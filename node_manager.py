#!/usr/bin/env python3
"""Interactive lightweight NAT node manager for two isolated Xray HY2 services."""

from __future__ import annotations

import datetime as dt
import getpass
import hashlib
import json
import os
import platform
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


VERSION = "0.2.0"
XRAY_VERSION = "26.7.28"
ROOT = Path("/etc/xray-nat-node-manager")
STATE = ROOT / "state.json"
SECRETS = ROOT / "secrets.json"
AGENT_CONFIG = Path("/etc/xui-agent/config.json")
AGENT_STATE = Path("/var/lib/xui-agent/state.json")
AGENT_BINARY = Path("/usr/local/sbin/xui-agent")
XRAY_BINARY = Path("/usr/local/bin/xray")
BACKUP_ROOT = Path("/var/backups/xray-nat-node-manager")
SERVICE_SPECS = {
    "direct": {
        "name": "xray-hy2-direct",
        "config": Path("/etc/xray-hy2-direct/config.json"),
        "api_port": 10085,
        "tag": "hy2-direct-in",
        "email": "hy2-direct",
    },
    "relay": {
        "name": "xray-hy2-relay",
        "config": Path("/etc/xray-hy2-relay/config.json"),
        "api_port": 10086,
        "tag": "hy2-relay-in",
        "email": "hy2-relay",
    },
}


class InstallError(RuntimeError):
    pass


def run(argv: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def parse_os_release(content: str) -> dict[str, str]:
    result = {}
    for line in content.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"').strip("'")
    return result


def detect_system(os_release_path: Path = Path("/etc/os-release")) -> dict[str, str]:
    release = parse_os_release(os_release_path.read_text(encoding="utf-8"))
    os_id = release.get("ID", "").lower()
    if os_id == "alpine":
        return {"os": "alpine", "init": "openrc"}
    if os_id in {"debian", "ubuntu"}:
        return {"os": os_id, "init": "systemd"}
    raise InstallError(f"不支持的系统：{os_id or 'unknown'}")


def require_root_supported() -> dict[str, str]:
    if os.geteuid() != 0:
        raise InstallError("请使用 root 运行")
    system = detect_system()
    commands = ["openssl"]
    commands += ["rc-service", "rc-update"] if system["init"] == "openrc" else ["systemctl"]
    for command in commands:
        if shutil.which(command) is None:
            raise InstallError(f"缺少命令：{command}")
    return system


def prompt(text: str, default: str | None = None, *, secret: bool = False) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = getpass.getpass(f"{text}{suffix}: ") if secret else input(f"{text}{suffix}: ")
    value = value.strip()
    if not value and default is not None:
        return default
    if not value:
        raise InstallError(f"{text}不能为空")
    return value


def prompt_port(text: str, default: int) -> int:
    value = int(prompt(text, str(default)))
    if not 1 <= value <= 65535:
        raise InstallError(f"端口超出范围：{value}")
    return value


def yes_no(text: str, default: bool = False) -> bool:
    mark = "Y/n" if default else "y/N"
    value = input(f"{text} [{mark}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "1", "是"}


def stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_atomic(path: Path, content: str | bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, candidate = tempfile.mkstemp(prefix=".node-manager-", dir=path.parent)
    try:
        binary = isinstance(content, bytes)
        with os.fdopen(fd, "wb" if binary else "w", encoding=None if binary else "utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(candidate, mode)
        os.replace(candidate, path)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def copy_atomic(source: Path, path: Path, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, candidate = tempfile.mkstemp(prefix=".node-manager-copy-", dir=path.parent)
    os.close(fd)
    try:
        shutil.copyfile(source, candidate)
        os.chmod(candidate, mode)
        os.replace(candidate, path)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def json_write(path: Path, value: object, mode: int = 0o600) -> None:
    write_atomic(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n", mode)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def xray_asset_name() -> str:
    machine = platform.machine().lower()
    mapping = {"x86_64": "64", "amd64": "64", "aarch64": "arm64-v8a", "arm64": "arm64-v8a"}
    if machine not in mapping:
        raise InstallError(f"不支持的 CPU 架构：{machine}")
    return f"Xray-linux-{mapping[machine]}.zip"


def download_xray(version: str, destination: Path) -> None:
    api = f"https://api.github.com/repos/XTLS/Xray-core/releases/tags/v{version}"
    request = urllib.request.Request(api, headers={"User-Agent": f"xray-nat-node-manager/{VERSION}"})
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.load(response)
    name = xray_asset_name()
    asset = next((item for item in release.get("assets", []) if item.get("name") == name), None)
    if asset is None:
        raise InstallError(f"官方发布中找不到 {name}")
    expected = str(asset.get("digest") or "")
    if not expected.startswith("sha256:"):
        raise InstallError("GitHub API 未提供官方 SHA-256，拒绝安装")
    with tempfile.TemporaryDirectory() as directory:
        archive_path = Path(directory) / name
        digest = hashlib.sha256()
        with urllib.request.urlopen(asset["browser_download_url"], timeout=120) as response:
            with archive_path.open("wb") as archive_handle:
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
                    archive_handle.write(chunk)
        if digest.hexdigest() != expected.removeprefix("sha256:"):
            raise InstallError("Xray 下载文件 SHA-256 不匹配")
        with zipfile.ZipFile(archive_path) as package:
            member = next((item for item in package.namelist() if Path(item).name == "xray"), None)
            if member is None:
                raise InstallError("官方压缩包中没有 xray")
            with package.open(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
    os.chmod(destination, 0o755)


def quic_settings() -> dict:
    return {
        "congestion": "bbr",
        "bbrProfile": "standard",
        "debug": False,
        "disablePathMTUDiscovery": False,
        "initConnectionReceiveWindow": 20 * 1024 * 1024,
        "maxConnectionReceiveWindow": 20 * 1024 * 1024,
        "initStreamReceiveWindow": 8 * 1024 * 1024,
        "maxStreamReceiveWindow": 8 * 1024 * 1024,
        "keepAlivePeriod": 15,
        "maxIdleTimeout": 30,
        "maxIncomingStreams": 1024,
    }


def hy2_config(*, domain: str, port: int, cert: str, key: str, auth: str,
               obfs_password: str, spec: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["StatsService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [
            {
                "tag": spec["tag"],
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "hysteria",
                "settings": {"version": 2, "clients": [{"auth": auth, "email": spec["email"]}]},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"]},
                "streamSettings": {
                    "network": "hysteria",
                    "security": "tls",
                    "hysteriaSettings": {"version": 2, "udpIdleTimeout": 60},
                    "finalmask": {
                        "udp": [{"type": "salamander", "settings": {"password": obfs_password}}],
                        "quicParams": quic_settings(),
                    },
                    "tlsSettings": {
                        "serverName": domain,
                        "minVersion": "1.2",
                        "maxVersion": "1.3",
                        "alpn": ["h3"],
                        "certificates": [{"certificateFile": cert, "keyFile": key, "usage": "encipherment"}],
                    },
                },
            },
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": spec["api_port"],
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "inboundTag": [spec["tag"]], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "blocked"},
            ],
        },
    }


def openrc_service(name: str, config: Path) -> str:
    return f'''#!/sbin/openrc-run
name="{name}"
description="Xray HY2 managed by xray-nat-node-manager"
command="{XRAY_BINARY}"
command_args="run -c {config}"
command_background="yes"
pidfile="/run/{name}.pid"
output_log="/var/log/{name}.log"
error_log="/var/log/{name}.log"
depend() {{ need net; after firewall; }}
'''


def agent_openrc() -> str:
    return f'''#!/sbin/openrc-run
name="xui-agent"
description="Lightweight 3x-ui compatible node agent"
command="{AGENT_BINARY}"
command_args="-config {AGENT_CONFIG}"
command_background="yes"
pidfile="/run/xui-agent.pid"
output_log="/var/log/xui-agent.log"
error_log="/var/log/xui-agent.log"
depend() {{ need net; after firewall; }}
'''


def systemd_service(name: str, config: Path) -> str:
    return f'''[Unit]
Description=Xray HY2 managed by xray-nat-node-manager ({name})
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart={XRAY_BINARY} run -c {config}
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
'''


def agent_systemd() -> str:
    return f'''[Unit]
Description=Lightweight 3x-ui compatible node agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart={AGENT_BINARY} -config {AGENT_CONFIG}
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
'''


def service_file(system: dict[str, str], name: str) -> Path:
    if system["init"] == "openrc":
        return Path("/etc/init.d") / name
    return Path("/etc/systemd/system") / f"{name}.service"


def service_definition(system: dict[str, str], name: str, config: Path | None = None) -> str:
    if system["init"] == "openrc":
        return agent_openrc() if name == "xui-agent" else openrc_service(name, config)
    return agent_systemd() if name == "xui-agent" else systemd_service(name, config)


def service_argv(system: dict[str, str], name: str, action: str) -> list[str]:
    if system["init"] == "openrc":
        return [shutil.which("rc-service") or "/sbin/rc-service", name, action]
    return [shutil.which("systemctl") or "/bin/systemctl", action, name]


def service_enable_argv(system: dict[str, str], name: str) -> list[str]:
    if system["init"] == "openrc":
        return [shutil.which("rc-update") or "/sbin/rc-update", "add", name, "default"]
    return [shutil.which("systemctl") or "/bin/systemctl", "enable", name]


def service_daemon_reload(system: dict[str, str]) -> None:
    if system["init"] == "systemd":
        run([shutil.which("systemctl") or "/bin/systemctl", "daemon-reload"])


def make_agent_cert(domain: str) -> tuple[str, str]:
    ROOT.mkdir(parents=True, exist_ok=True)
    cert = ROOT / "agent.crt"
    key = ROOT / "agent.key"
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "825", "-nodes",
        "-subj", f"/CN={domain}", "-addext", f"subjectAltName=DNS:{domain}",
        "-keyout", str(key), "-out", str(cert),
    ])
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    return str(cert), str(key)


def validate_cert_paths(cert: str, key: str) -> None:
    if not Path(cert).is_file() or not Path(key).is_file():
        raise InstallError("TLS 证书或私钥文件不存在")
    result = run(["openssl", "x509", "-in", cert, "-noout"], check=False, capture=True)
    if result.returncode != 0:
        raise InstallError("TLS 证书无法解析")


def backup_paths(paths: list[Path]) -> Path:
    target = BACKUP_ROOT / stamp()
    target.mkdir(parents=True, mode=0o700)
    manifest = []
    for path in paths:
        record = {"path": str(path), "existed": path.exists()}
        manifest.append(record)
        if not path.exists():
            continue
        relative = str(path).lstrip("/")
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if path.is_dir():
            shutil.copytree(path, destination, dirs_exist_ok=True)
        else:
            shutil.copy2(path, destination)
    json_write(target / "manifest.json", manifest)
    return target


def remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def restore_backup(target: Path, system: dict[str, str]) -> None:
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    for name in [spec["name"] for spec in SERVICE_SPECS.values()] + ["xui-agent"]:
        run(service_argv(system, name, "stop"), check=False, capture=True)
    for record in manifest:
        path = Path(record["path"])
        remove_path(path)
        if not record["existed"]:
            continue
        source = target / str(path).lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, path)
        else:
            shutil.copy2(source, path)
    service_daemon_reload(system)
    for name in [spec["name"] for spec in SERVICE_SPECS.values()] + ["xui-agent"]:
        if service_file(system, name).exists():
            run(service_argv(system, name, "start"), check=False, capture=True)


def validate_xray(configs: list[Path]) -> None:
    for config in configs:
        result = run([str(XRAY_BINARY), "run", "-test", "-c", str(config)], check=False, capture=True)
        if result.returncode != 0:
            raise InstallError(f"Xray 拒绝配置 {config}:\n{result.stdout}")


def check_port_conflicts(ports: list[tuple[int, str]]) -> None:
    seen = set()
    for port, protocol in ports:
        key = (port, protocol)
        if key in seen:
            raise InstallError(f"重复监听：{protocol}/{port}")
        seen.add(key)


def collect_install_answers() -> dict:
    domain = prompt("节点域名")
    direct_internal = prompt_port("HY2 直连内部 UDP 端口", 5201)
    direct_external = prompt_port("HY2 直连外部 UDP 端口", 45066)
    relay_internal = prompt_port("HY2 中转内部 UDP 端口", 24443)
    relay_external = prompt_port("HY2 中转外部 UDP 端口", 58350)
    agent_internal = prompt_port("Agent 内部 TCP 端口", 5201)
    agent_external = prompt_port("Agent 外部 TCP 端口", 45066)
    check_port_conflicts([(direct_internal, "udp"), (relay_internal, "udp"), (agent_internal, "tcp")])
    cert = prompt("HY2 TLS 完整证书路径", "/etc/ssl/node/fullchain.pem")
    key = prompt("HY2 TLS 私钥路径", "/etc/ssl/node/key.pem")
    validate_cert_paths(cert, key)
    return {
        "domain": domain,
        "cert": cert,
        "key": key,
        "ports": {
            "direct_internal_udp": direct_internal,
            "direct_external_udp": direct_external,
            "relay_internal_udp": relay_internal,
            "relay_external_udp": relay_external,
            "agent_internal_tcp": agent_internal,
            "agent_external_tcp": agent_external,
        },
    }


def install_all() -> None:
    system = require_root_supported()
    if STATE.exists() and not yes_no("检测到已有安装，是否覆盖并先备份", False):
        return
    answers = collect_install_answers()
    packaged_agent = Path(__file__).resolve().parent / "assets" / xray_asset_for_agent()
    if not packaged_agent.is_file():
        raise InstallError(f"安装包缺少 Agent：{packaged_agent}")

    managed = [
        ROOT, AGENT_CONFIG.parent, AGENT_STATE.parent, XRAY_BINARY, AGENT_BINARY,
        service_file(system, "xui-agent"),
    ]
    for spec in SERVICE_SPECS.values():
        managed += [spec["config"].parent, service_file(system, spec["name"])]
    backup = backup_paths(managed)
    print(f"备份：{backup}")

    candidate_fd, candidate_name = tempfile.mkstemp(prefix="xray-", dir="/tmp")
    os.close(candidate_fd)
    candidate_xray = Path(candidate_name)
    try:
        download_xray(XRAY_VERSION, candidate_xray)
        copy_atomic(candidate_xray, XRAY_BINARY, 0o755)

        credentials = {
            "agent_token": secrets.token_hex(32),
            "direct_auth": secrets.token_hex(24),
            "direct_obfs_password": secrets.token_hex(24),
            "relay_auth": secrets.token_hex(24),
            "relay_obfs_password": secrets.token_hex(24),
        }
        configs = []
        for role, spec in SERVICE_SPECS.items():
            port = answers["ports"][f"{role}_internal_udp"]
            config = hy2_config(
                domain=answers["domain"], port=port, cert=answers["cert"], key=answers["key"],
                auth=credentials[f"{role}_auth"], obfs_password=credentials[f"{role}_obfs_password"], spec=spec,
            )
            json_write(spec["config"], config)
            write_atomic(service_file(system, spec["name"]), service_definition(system, spec["name"], spec["config"]), 0o755 if system["init"] == "openrc" else 0o644)
            configs.append(spec["config"])
        validate_xray(configs)

        copy_atomic(packaged_agent, AGENT_BINARY, 0o755)
        agent_cert, agent_key = make_agent_cert(answers["domain"])
        services = []
        for role, spec in SERVICE_SPECS.items():
            services.append({
                "name": spec["name"], "binary": str(XRAY_BINARY), "configPath": str(spec["config"]),
                "apiEndpoint": f"127.0.0.1:{spec['api_port']}",
                "restartCommand": service_argv(system, spec["name"], "restart"),
                "statusCommand": service_argv(system, spec["name"], "status"),
                "ignoreTags": ["api"], "default": role == "direct",
            })
        agent = {
            "listen": f"0.0.0.0:{answers['ports']['agent_internal_tcp']}",
            "token": credentials["agent_token"],
            "panelGuid": secrets.token_hex(16),
            "statePath": str(AGENT_STATE),
            "tlsCertFile": agent_cert,
            "tlsKeyFile": agent_key,
            "services": services,
        }
        json_write(AGENT_CONFIG, agent)
        write_atomic(service_file(system, "xui-agent"), service_definition(system, "xui-agent"), 0o755 if system["init"] == "openrc" else 0o644)
        service_daemon_reload(system)
        AGENT_STATE.parent.mkdir(parents=True, exist_ok=True)
        run([str(AGENT_BINARY), "-config", str(AGENT_CONFIG), "-adopt"])
        run([str(AGENT_BINARY), "-config", str(AGENT_CONFIG), "-check"])

        for spec in SERVICE_SPECS.values():
            run(service_enable_argv(system, spec["name"]), check=False)
            run(service_argv(system, spec["name"], "restart"))
            run(service_argv(system, spec["name"], "status"))
        run(service_enable_argv(system, "xui-agent"), check=False)
        run(service_argv(system, "xui-agent", "restart"))
        run(service_argv(system, "xui-agent", "status"))

        ROOT.mkdir(parents=True, exist_ok=True)
        json_write(SECRETS, credentials)
        answers["installed_at"] = stamp()
        answers["xray_version"] = XRAY_VERSION
        answers["system"] = system
        answers["agent_sha256"] = sha256(packaged_agent)
        json_write(STATE, answers)
        print("安装完成。请在 NAT 面板添加以下映射：")
        show_mapping(answers)
        print(f"敏感凭据只保存在：{SECRETS}")
    except Exception:
        print(f"安装失败，正在恢复：{backup}", file=sys.stderr)
        restore_backup(backup, system)
        raise
    finally:
        candidate_xray.unlink(missing_ok=True)


def xray_asset_for_agent() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "xui-agent-linux-amd64"
    if machine in {"aarch64", "arm64"}:
        return "xui-agent-linux-arm64"
    raise InstallError(f"Agent 不支持的 CPU 架构：{machine}")


def show_mapping(state: dict | None = None) -> None:
    state = state or json.loads(STATE.read_text(encoding="utf-8"))
    ports = state["ports"]
    print(f"  UDP {ports['direct_external_udp']} -> UDP {ports['direct_internal_udp']}  (HY2 直连)")
    print(f"  UDP {ports['relay_external_udp']} -> UDP {ports['relay_internal_udp']}  (HY2 美国中转落地)")
    print(f"  TCP {ports['agent_external_tcp']} -> TCP {ports['agent_internal_tcp']}  (xui-agent)")


def hy2_uri(role: str) -> str:
    state = json.loads(STATE.read_text(encoding="utf-8"))
    credentials = json.loads(SECRETS.read_text(encoding="utf-8"))
    external = state["ports"][f"{role}_external_udp"]
    query = urllib.parse.urlencode({
        "sni": state["domain"], "insecure": "0", "alpn": "h3", "obfs": "salamander",
        "obfs-password": credentials[f"{role}_obfs_password"],
    })
    auth = urllib.parse.quote(credentials[f"{role}_auth"], safe="")
    return f"hysteria2://{auth}@{state['domain']}:{external}/?{query}"


def status() -> None:
    system = require_root_supported()
    for name in [spec["name"] for spec in SERVICE_SPECS.values()] + ["xui-agent"]:
        result = run(service_argv(system, name, "status"), check=False, capture=True)
        print(f"{name}: {'started' if result.returncode == 0 else 'stopped/error'}")
    if XRAY_BINARY.exists():
        result = run([str(XRAY_BINARY), "version"], check=False, capture=True)
        print(result.stdout.splitlines()[0] if result.stdout else "Xray version unknown")


def print_links() -> None:
    if not STATE.exists() or not SECRETS.exists():
        raise InstallError("尚未完成安装")
    print("直连：", hy2_uri("direct"))
    print("中转落地（提供给美国出站）：", hy2_uri("relay"))


def menu() -> None:
    actions = {
        "1": ("全新安装/重装", install_all),
        "2": ("查看服务状态", status),
        "3": ("查看 NAT 映射", show_mapping),
        "4": ("显示节点链接（包含敏感凭据）", print_links),
    }
    while True:
        print(f"\nXray NAT 节点管理器 v{VERSION}")
        for key, (label, _) in actions.items():
            print(f" {key}. {label}")
        print(" 0. 退出")
        choice = input("请选择: ").strip()
        if choice == "0":
            return
        action = actions.get(choice)
        if action is None:
            print("无效选择")
            continue
        try:
            action[1]()
        except (InstallError, OSError, subprocess.SubprocessError, urllib.error.URLError, ValueError) as exc:
            print(f"操作失败：{exc}", file=sys.stderr)


if __name__ == "__main__":
    menu()
