#!/usr/bin/env python3
"""Interactive lightweight NAT node manager for two isolated Xray HY2 services."""

from __future__ import annotations

import datetime as dt
import getpass
import hashlib
import io
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


VERSION = "0.3.7"
XRAY_VERSION = "26.7.28"
ACME_VERSION = "3.1.4"
ACME_ARCHIVE_SHA256 = "e5f8e187bbf5251e0cd8891f2622daab9850366bd17bea9f92c2fe2ee091fd32"
ROOT = Path("/etc/xray-nat-node-manager")
STATE = ROOT / "state.json"
SECRETS = ROOT / "secrets.json"
AGENT_CONFIG = Path("/etc/xui-agent/config.json")
AGENT_STATE = Path("/var/lib/xui-agent/state.json")
AGENT_BINARY = Path("/usr/local/sbin/xui-agent")
XRAY_BINARY = Path("/usr/local/bin/xray")
BACKUP_ROOT = Path("/var/backups/xray-nat-node-manager")
ACME_HOME = Path("/opt/acme.sh")
ACME_CONFIG_HOME = Path("/etc/acme.sh")
ACME_CERT_HOME = Path("/var/lib/acme.sh/certs")
ACME_RELOAD = Path("/usr/local/sbin/xray-nat-node-manager-cert-reload")
BBR_SYSCTL_CONFIG = Path("/etc/sysctl.d/99-xray-nat-node-manager-bbr.conf")
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


def run(argv: list[str], *, check: bool = True, capture: bool = False,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        env=env,
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
    commands = ["openssl", "sysctl"]
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


def prompt_port(text: str) -> int:
    value = int(prompt(text))
    if not 1 <= value <= 65535:
        raise InstallError(f"端口超出范围：{value}")
    return value


def normalize_node_identity(value: str) -> str:
    value = value.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InstallError(f"节点域名无效：{value}") from exc
    labels = domain.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if len(domain) > 253 or len(labels) < 2 or any(not label_pattern.fullmatch(label) for label in labels):
        raise InstallError(f"节点域名无效：{value}")
    return domain


def is_ip_identity(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def uri_host(value: str) -> str:
    return f"[{value}]" if ":" in value else value


def detect_public_ip() -> str | None:
    for url in ("https://api.ipify.org", "https://api64.ipify.org"):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": f"xray-nat-node-manager/{VERSION}"})
            with urllib.request.urlopen(request, timeout=8) as response:
                value = response.read(128).decode("ascii").strip()
            address = ipaddress.ip_address(value)
            if address.is_global:
                return str(address)
        except (OSError, UnicodeError, ValueError, urllib.error.URLError):
            continue
    return None


def collect_node_identity() -> str:
    print("\n[1/6] 节点地址")
    detected_ip = detect_public_ip()
    if detected_ip:
        print(f"检测到公网出口 IP：{detected_ip}")
    print(" 1. 使用节点域名（推荐）")
    if detected_ip:
        print(f" 2. 使用检测到的 IP：{detected_ip}")
        print(" 3. 手动填写公网入口 IP")
    else:
        print(" 2. 手动填写公网入口 IP")
    choice = prompt("请选择", "1")
    if choice == "1":
        identity = normalize_node_identity(prompt("节点域名"))
        if is_ip_identity(identity):
            raise InstallError("这里请选择并填写域名；使用 IP 请返回选择 IP 选项")
        return identity
    manual_ip_choice = "3" if detected_ip else "2"
    if choice == "2" and detected_ip:
        if not yes_no("检测值可能只是出口 IP，确认它也是本机可接收连接的公网入口 IP", False):
            raise InstallError("请确认公网入口 IP，或改用节点域名")
        return detected_ip
    if choice == manual_ip_choice:
        identity = normalize_node_identity(prompt("公网入口 IP"))
        if not is_ip_identity(identity):
            raise InstallError("公网入口 IP 必须是 IPv4 或 IPv6 地址")
        return identity
    raise InstallError("无效的节点地址方式")


def certificate_method_label(method: str) -> str:
    return {
        "cloudflare": "Cloudflare DNS-01 自动申请（无需端口）",
        "http": "HTTP-01 自动申请（公网 TCP 80）",
        "alpn": "TLS-ALPN-01 自动申请（公网 TCP 443）",
        "existing": "使用已有公网可信证书",
    }[method]


def collect_network_answers() -> dict:
    print("\n[2/6] 端口方式")
    print(" 1. 端口映射（NAT：分别设置内部端口和外部端口）")
    print(" 2. 无端口映射（公网机：监听端口就是公网端口）")
    choice = prompt("请选择", "1")
    if choice not in {"1", "2"}:
        raise InstallError("无效的端口方式")
    return {"mode": "mapped" if choice == "1" else "direct"}


def collect_service_ports(label: str, protocol: str, network: dict) -> tuple[int, int]:
    if network["mode"] == "mapped":
        internal = prompt_port(f"{label}内部 {protocol} 端口")
        external = prompt_port(f"{label}外部公网 {protocol} 端口")
        return internal, external
    port = prompt_port(f"{label}{protocol} 端口")
    return port, port


def collect_tls_answers(identity: str, network: dict) -> dict:
    print("\n[3/6] TLS 证书")
    if is_ip_identity(identity):
        print(" 1. HTTP-01 自动申请（公网 TCP 80）")
        print(" 2. TLS-ALPN-01 自动申请（公网 TCP 443）")
        print(" 3. 使用已有公网可信 IP 证书")
        choice = prompt("请选择", "1")
        methods = {"1": "http", "2": "alpn", "3": "existing"}
    else:
        print(" 1. Cloudflare DNS 自动申请（推荐，无需端口）")
        print(" 2. HTTP-01 自动申请（需要公网 TCP 80）")
        print(" 3. 使用已有公网可信证书")
        choice = prompt("请选择", "1")
        methods = {"1": "cloudflare", "2": "http", "3": "existing"}
    method = methods.get(choice)
    if method is None:
        raise InstallError("无效的证书方式")

    result = {"method": method}
    if method == "existing":
        cert = prompt("TLS 完整证书路径", "/etc/ssl/node/fullchain.pem")
        key = prompt("TLS 私钥路径", "/etc/ssl/node/key.pem")
        validate_cert_paths(cert, key, identity)
        result.update({"cert": cert, "key": key})
        return result
    if method == "cloudflare":
        print("\nCloudflare Token 获取方法：")
        print("  1. 打开 https://dash.cloudflare.com/profile/api-tokens")
        print("  2. 创建自定义 Token（不要使用 Global API Key）")
        print("  3. 权限：Zone > DNS > Edit")
        print("  4. Zone Resources：Include > Specific zone > 选择当前域名所在区域")
        print("  5. 在该 Zone 的 Overview 页面右侧复制 Zone ID")
        print("  6. 接下来先粘贴 Token，再粘贴 Zone ID；两项均隐藏输入")
        token = prompt("Cloudflare API Token（隐藏输入）", secret=True)
        if re.fullmatch(r"[0-9a-fA-F]{32}", token):
            raise InstallError("这里需要 API Token；你粘贴的看起来是 Zone ID")
        if len(token) < 20 or any(character.isspace() for character in token):
            raise InstallError("Cloudflare API Token 格式无效")
        zone_id = prompt("Cloudflare Zone ID（隐藏输入，32 位）", secret=True)
        if not re.fullmatch(r"[0-9a-fA-F]{32}", zone_id):
            if zone_id.startswith("cfut_"):
                raise InstallError("这里需要 Zone ID；你粘贴的看起来是 API Token")
            raise InstallError("Cloudflare Zone ID 应为 32 位十六进制字符")
        result["cf_zone_id"] = zone_id.lower()
        result["_cf_token"] = token
    else:
        external = 80 if method == "http" else 443
        if network["mode"] == "mapped":
            internal = prompt_port("ACME 内部 TCP 监听端口")
            if not yes_no(f"确认 NAT 已映射公网 TCP {external} -> 内部 TCP {internal}", False):
                raise InstallError("自动申请证书前必须完成 ACME TCP 端口映射")
        else:
            internal = external
            print(f"  此验证方式固定使用公网 TCP {external}，本机也将监听 TCP {internal}")
        result.update({"external_tcp": external, "internal_tcp": internal})
    result["email"] = prompt("Let's Encrypt 账户邮箱（可留空）", "")
    return result


def yes_no(text: str, default: bool = False) -> bool:
    mark = "Y/n" if default else "y/N"
    value = input(f"{text} [{mark}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "1", "是"}


def sysctl_value(name: str) -> str | None:
    result = run(["sysctl", "-n", name], check=False, capture=True)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def linux_tcp_bbr_status() -> dict[str, str | None]:
    return {
        "congestion_control": sysctl_value("net.ipv4.tcp_congestion_control"),
        "available": sysctl_value("net.ipv4.tcp_available_congestion_control"),
        "default_qdisc": sysctl_value("net.core.default_qdisc"),
    }


def linux_tcp_bbr_enabled(status: dict[str, str | None]) -> bool:
    return status["congestion_control"] == "bbr"


def restore_bbr_runtime(status: dict[str, str | None]) -> None:
    for name, key in (
        ("net.core.default_qdisc", "default_qdisc"),
        ("net.ipv4.tcp_congestion_control", "congestion_control"),
    ):
        value = status.get(key)
        if value:
            run(["sysctl", "-w", f"{name}={value}"], check=False, capture=True)


def enable_linux_tcp_bbr(config_path: Path = BBR_SYSCTL_CONFIG) -> dict[str, str | None]:
    before = linux_tcp_bbr_status()
    available = (before.get("available") or "").split()
    if "bbr" not in available and shutil.which("modprobe"):
        run(["modprobe", "tcp_bbr"], check=False, capture=True)
        available = (sysctl_value("net.ipv4.tcp_available_congestion_control") or "").split()
    if "bbr" not in available:
        raise InstallError("当前内核未提供 TCP BBR；NAT/LXC 可能需要服务商在宿主机开启")

    existed = config_path.exists()
    old_content = config_path.read_bytes() if existed else None
    old_mode = config_path.stat().st_mode & 0o777 if existed else 0o644
    content = (
        "# Managed by xray-nat-node-manager\n"
        "net.core.default_qdisc=fq\n"
        "net.ipv4.tcp_congestion_control=bbr\n"
    )
    try:
        write_atomic(config_path, content, 0o644)
        result = run(["sysctl", "-p", str(config_path)], check=False, capture=True)
        after = linux_tcp_bbr_status()
        if result.returncode != 0 or not linux_tcp_bbr_enabled(after):
            detail = (result.stdout or "sysctl 未能应用配置").strip()
            raise InstallError(detail)
        return after
    except (InstallError, OSError, subprocess.SubprocessError):
        if old_content is None:
            config_path.unlink(missing_ok=True)
        else:
            write_atomic(config_path, old_content, old_mode)
        restore_bbr_runtime(before)
        raise


def check_linux_tcp_bbr() -> None:
    print("\n[0/6] Linux TCP BBR")
    status = linux_tcp_bbr_status()
    if linux_tcp_bbr_enabled(status):
        print(f"Linux TCP BBR：已开启（default_qdisc={status['default_qdisc'] or 'unknown'}）")
        print("提示：这是 TCP BBR；HY2 使用独立的 QUIC BBR。")
        return
    current = status["congestion_control"] or "unknown"
    print(f"Linux TCP BBR：未开启（当前：{current}）")
    if not yes_no("是否现在开启 Linux TCP BBR", True):
        print("已跳过 Linux TCP BBR，继续安装。")
        return
    try:
        enabled = enable_linux_tcp_bbr()
    except InstallError as exc:
        print(f"Linux TCP BBR 开启失败：{exc}")
        print("已恢复原设置并继续安装；这不影响 HY2 的 QUIC BBR。")
        return
    print(f"Linux TCP BBR：已开启（default_qdisc={enabled['default_qdisc'] or 'unknown'}）")
    print("配置已保存到 /etc/sysctl.d/99-xray-nat-node-manager-bbr.conf")
    print("提示：这是 TCP BBR；HY2 使用独立的 QUIC BBR。")


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


def validate_cert_paths(cert: str, key: str, identity: str) -> None:
    if not Path(cert).is_file() or not Path(key).is_file():
        raise InstallError("TLS 证书或私钥文件不存在")
    result = run(["openssl", "x509", "-in", cert, "-noout"], check=False, capture=True)
    if result.returncode != 0:
        raise InstallError("TLS 证书无法解析")
    if run(["openssl", "x509", "-in", cert, "-noout", "-checkend", "0"], check=False, capture=True).returncode != 0:
        raise InstallError("TLS 证书已经过期")
    try:
        decoded = ssl._ssl._test_decode_cert(cert)
        san_kind = "IP Address" if is_ip_identity(identity) else "DNS"
        if not any(kind == san_kind for kind, _ in decoded.get("subjectAltName", ())):
            raise ssl.CertificateError("required SAN type is missing")
        ssl.match_hostname(decoded, identity)
    except (OSError, ValueError, ssl.CertificateError) as exc:
        kind = "IP" if is_ip_identity(identity) else "域名"
        raise InstallError(f"TLS 证书的 SAN 不包含节点{kind}：{identity}") from exc
    cert_public = run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"], check=False, capture=True)
    key_public = run(["openssl", "pkey", "-in", key, "-pubout"], check=False, capture=True)
    if cert_public.returncode != 0 or key_public.returncode != 0:
        raise InstallError("TLS 私钥无法解析")
    if cert_public.stdout.strip() != key_public.stdout.strip():
        raise InstallError("TLS 证书与私钥不匹配")


def safe_extract_tar(archive: bytes, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        members = package.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if target != root and root not in target.parents:
                raise InstallError("acme.sh 压缩包包含不安全路径")
            if member.issym() or member.islnk():
                raise InstallError("acme.sh 压缩包包含链接，拒绝安装")
        package.extractall(destination, members=members)
    directories = [path for path in destination.iterdir() if path.is_dir()]
    if len(directories) != 1 or not (directories[0] / "acme.sh").is_file():
        raise InstallError("acme.sh 压缩包结构无效")
    return directories[0]


def acme_command(config_home: Path = ACME_CONFIG_HOME, cert_home: Path = ACME_CERT_HOME) -> list[str]:
    return [str(ACME_HOME / "acme.sh"), "--home", str(ACME_HOME),
            "--config-home", str(config_home), "--cert-home", str(cert_home)]


def ensure_cron_running(system: dict[str, str]) -> None:
    if system["init"] == "openrc":
        run([shutil.which("rc-update") or "/sbin/rc-update", "add", "crond", "default"], check=False)
        run([shutil.which("rc-service") or "/sbin/rc-service", "crond", "start"])
    else:
        systemctl = shutil.which("systemctl") or "/bin/systemctl"
        run([systemctl, "enable", "cron"], check=False)
        run([systemctl, "start", "cron"])


def install_acme_client(system: dict[str, str], email: str) -> None:
    url = f"https://github.com/acmesh-official/acme.sh/archive/refs/tags/{ACME_VERSION}.tar.gz"
    request = urllib.request.Request(url, headers={"User-Agent": f"xray-nat-node-manager/{VERSION}"})
    with urllib.request.urlopen(request, timeout=120) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != ACME_ARCHIVE_SHA256:
        raise InstallError("acme.sh 下载文件 SHA-256 不匹配")
    with tempfile.TemporaryDirectory(prefix="acme-install-", dir="/tmp") as directory:
        source = safe_extract_tar(archive, Path(directory))
        argv = [str(source / "acme.sh"), "--install", "--home", str(ACME_HOME),
                "--config-home", str(ACME_CONFIG_HOME), "--cert-home", str(ACME_CERT_HOME),
                "--no-profile"]
        if email:
            argv += ["--email", email]
        run(argv)
    if not (ACME_HOME / "acme.sh").is_file():
        raise InstallError("acme.sh 安装后入口不存在")
    ACME_CONFIG_HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ACME_CONFIG_HOME, 0o700)
    ensure_cron_running(system)


def certificate_reload_script(system: dict[str, str]) -> str:
    names = [spec["name"] for spec in SERVICE_SPECS.values()] + ["xui-agent"]
    if system["init"] == "openrc":
        body = "\n".join(
            f'[ ! -x /etc/init.d/{name} ] || /sbin/rc-service {name} restart' for name in names
        )
    else:
        body = "\n".join(
            f'/bin/systemctl cat {name}.service >/dev/null 2>&1 && /bin/systemctl try-restart {name}.service || true'
            for name in names
        )
    return f"#!/bin/sh\nset -eu\n{body}\n"


def acme_validation_args(identity: str, tls: dict) -> list[str]:
    method = tls["method"]
    if method == "cloudflare":
        validation = ["--dns", "dns_cf"]
    elif method == "http":
        validation = ["--standalone", "--httpport", str(tls["internal_tcp"])]
    elif method == "alpn":
        validation = ["--alpn", "--tlsport", str(tls["internal_tcp"])]
    else:
        raise InstallError(f"不支持的自动证书方式：{method}")
    result = ["--issue", *validation, "-d", identity, "--keylength", "ec-256"]
    if is_ip_identity(identity):
        result += ["--certificate-profile", "shortlived"]
    return result


def managed_certificate_paths(identity: str) -> tuple[Path, Path]:
    safe_name = identity.replace(":", "_")
    directory = ROOT / "certs" / safe_name
    return directory / "fullchain.pem", directory / "privkey.pem"


def state_without_secrets(answers: dict) -> dict:
    state = json.loads(json.dumps(answers))
    state["tls"].pop("_cf_token", None)
    state["tls"]["token_configured"] = answers["tls"]["method"] == "cloudflare"
    return state


def issue_certificate(system: dict[str, str], identity: str, tls: dict) -> tuple[str, str]:
    install_acme_client(system, tls.get("email", ""))
    environment = os.environ.copy()
    token = tls.get("_cf_token")
    if token:
        environment["CF_Token"] = token
        environment["CF_Zone_ID"] = tls["cf_zone_id"]
    issue_args = acme_validation_args(identity, tls)
    with tempfile.TemporaryDirectory(prefix="acme-staging-", dir="/tmp") as directory:
        staging = Path(directory)
        run([*acme_command(staging / "config", staging / "certs"), "--server", "letsencrypt_test",
             *issue_args], env=environment)
    run([*acme_command(), "--server", "letsencrypt", *issue_args], env=environment)

    cert, key = managed_certificate_paths(identity)
    cert.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_atomic(ACME_RELOAD, certificate_reload_script(system), 0o755)
    run([*acme_command(), "--install-cert", "-d", identity, "--ecc",
         "--fullchain-file", str(cert), "--key-file", str(key),
         "--reloadcmd", str(ACME_RELOAD)], env=environment)
    os.chmod(cert, 0o644)
    os.chmod(key, 0o600)
    for path in ACME_CONFIG_HOME.rglob("*"):
        if path.is_file() and path.name.endswith(".conf"):
            os.chmod(path, 0o600)
    validate_cert_paths(str(cert), str(key), identity)
    return str(cert), str(key)


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


def validate_install_ports(answers: dict) -> None:
    ports = answers["ports"]
    tls = answers["tls"]
    check_port_conflicts([
        (ports["direct_internal_udp"], "udp"),
        (ports["relay_internal_udp"], "udp"),
        (ports["agent_internal_tcp"], "tcp"),
    ])
    check_port_conflicts([
        (ports["direct_external_udp"], "udp"),
        (ports["relay_external_udp"], "udp"),
        (ports["agent_external_tcp"], "tcp"),
    ])
    if tls.get("internal_tcp") == ports["agent_internal_tcp"]:
        raise InstallError(f"ACME 与 Agent 不能共用内部 TCP 端口：{ports['agent_internal_tcp']}")
    if tls.get("external_tcp") == ports["agent_external_tcp"]:
        raise InstallError(f"ACME 与 Agent 不能共用外部 TCP 端口：{ports['agent_external_tcp']}")


def collect_install_answers() -> dict:
    domain = collect_node_identity()
    network = collect_network_answers()
    tls = collect_tls_answers(domain, network)

    print("\n[4/6] HY2 直连端口")
    direct_internal, direct_external = collect_service_ports("HY2 直连", "UDP", network)

    print("\n[5/6] HY2 中转落地端口")
    relay_internal, relay_external = collect_service_ports("HY2 中转落地", "UDP", network)

    print("\n[6/6] Agent 管理端口")
    agent_internal, agent_external = collect_service_ports("Agent 管理", "TCP", network)
    answers = {
        "domain": domain,
        "network": network,
        "tls": tls,
        "cert": tls.get("cert"),
        "key": tls.get("key"),
        "ports": {
            "direct_internal_udp": direct_internal,
            "direct_external_udp": direct_external,
            "relay_internal_udp": relay_internal,
            "relay_external_udp": relay_external,
            "agent_internal_tcp": agent_internal,
            "agent_external_tcp": agent_external,
        },
    }
    validate_install_ports(answers)
    return answers


def show_install_summary(answers: dict) -> None:
    print("\n即将安装：")
    print(f"  节点身份：{answers['domain']}")
    print(f"  TLS 证书：{certificate_method_label(answers['tls']['method'])}")
    if answers["cert"]:
        print(f"  证书路径：{answers['cert']}")
    show_mapping(answers)


def review_install_answers(answers: dict) -> bool:
    while True:
        show_install_summary(answers)
        print("\n 1. 确认并开始安装")
        print(" 2. 修改 HY2 直连端口")
        print(" 3. 修改 HY2 中转端口")
        print(" 4. 修改 Agent 管理端口")
        print(" 0. 取消")
        choice = prompt("请选择", "1")
        if choice == "1":
            return True
        if choice == "0":
            return False
        old_ports = answers["ports"].copy()
        if choice == "2":
            internal, external = collect_service_ports("HY2 直连", "UDP", answers["network"])
            answers["ports"]["direct_internal_udp"] = internal
            answers["ports"]["direct_external_udp"] = external
        elif choice == "3":
            internal, external = collect_service_ports("HY2 中转落地", "UDP", answers["network"])
            answers["ports"]["relay_internal_udp"] = internal
            answers["ports"]["relay_external_udp"] = external
        elif choice == "4":
            internal, external = collect_service_ports("Agent 管理", "TCP", answers["network"])
            answers["ports"]["agent_internal_tcp"] = internal
            answers["ports"]["agent_external_tcp"] = external
        else:
            print("无效选择")
            continue
        try:
            validate_install_ports(answers)
        except InstallError as exc:
            answers["ports"] = old_ports
            print(f"端口修改无效：{exc}")


def install_all() -> None:
    system = require_root_supported()
    check_linux_tcp_bbr()
    if STATE.exists() and not yes_no("检测到已有安装，是否覆盖并先备份", False):
        return
    answers = collect_install_answers()
    if not review_install_answers(answers):
        print("已取消，未修改系统")
        return
    packaged_agent = Path(__file__).resolve().parent / "assets" / xray_asset_for_agent()
    if not packaged_agent.is_file():
        raise InstallError(f"安装包缺少 Agent：{packaged_agent}")

    managed = [
        ROOT, AGENT_CONFIG.parent, AGENT_STATE.parent, XRAY_BINARY, AGENT_BINARY,
        service_file(system, "xui-agent"), ACME_RELOAD,
        Path("/etc/crontabs/root"), Path("/var/spool/cron/crontabs/root"),
    ]
    if answers["tls"]["method"] != "existing":
        managed += [ACME_HOME, ACME_CONFIG_HOME, ACME_CERT_HOME]
    for spec in SERVICE_SPECS.values():
        managed += [spec["config"].parent, service_file(system, spec["name"])]
    backup = backup_paths(managed)
    print(f"备份：{backup}")

    candidate_fd, candidate_name = tempfile.mkstemp(prefix="xray-", dir="/tmp")
    os.close(candidate_fd)
    candidate_xray = Path(candidate_name)
    try:
        if answers["tls"]["method"] != "existing":
            answers["cert"], answers["key"] = issue_certificate(system, answers["domain"], answers["tls"])
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
            "tlsCertFile": answers["cert"],
            "tlsKeyFile": answers["key"],
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
        json_write(STATE, state_without_secrets(answers))
        print("安装完成。端口配置：")
        show_mapping(answers)
        show_agent_setup(answers)
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
    mapped = (state.get("network") or {}).get("mode", "mapped") == "mapped"
    if mapped:
        print("  请在 NAT 面板保留以下映射：")
        print(f"  UDP {ports['direct_external_udp']} -> UDP {ports['direct_internal_udp']}  (HY2 直连)")
        print(f"  UDP {ports['relay_external_udp']} -> UDP {ports['relay_internal_udp']}  (HY2 美国中转落地)")
        print(f"  TCP {ports['agent_external_tcp']} -> TCP {ports['agent_internal_tcp']}  (xui-agent)")
    else:
        print(f"  UDP {ports['direct_internal_udp']}  (HY2 直连，内外相同)")
        print(f"  UDP {ports['relay_internal_udp']}  (HY2 美国中转落地，内外相同)")
        print(f"  TCP {ports['agent_internal_tcp']}  (xui-agent，内外相同)")
    tls = state.get("tls") or {}
    if tls.get("external_tcp"):
        if mapped:
            print(f"  TCP {tls['external_tcp']} -> TCP {tls['internal_tcp']}  (ACME 自动续期，必须保留)")
        else:
            print(f"  TCP {tls['internal_tcp']}  (ACME 自动续期验证，公网端口固定)")


def show_agent_setup(state: dict | None = None, *, include_token: bool = False) -> None:
    state = state or json.loads(STATE.read_text(encoding="utf-8"))
    print("\n3x-ui Agent 设置：")
    print("  协议：https")
    print(f"  主机（不含 https://）：{state['domain']}")
    print(f"  端口：{state['ports']['agent_external_tcp']}")
    print("  基础路径：/")
    print("  TLS 校验：标准验证（verify；不要选择固定指纹或跳过验证）")
    if include_token:
        credentials = json.loads(SECRETS.read_text(encoding="utf-8"))
        print(f"  Token：{credentials['agent_token']}")
    else:
        print("  Token：安装完成后在菜单选择“显示 Agent 接入信息”查看")


def hy2_uri(role: str) -> str:
    state = json.loads(STATE.read_text(encoding="utf-8"))
    credentials = json.loads(SECRETS.read_text(encoding="utf-8"))
    external = state["ports"][f"{role}_external_udp"]
    query = urllib.parse.urlencode({
        "sni": state["domain"], "insecure": "0", "alpn": "h3", "obfs": "salamander",
        "obfs-password": credentials[f"{role}_obfs_password"],
    })
    auth = urllib.parse.quote(credentials[f"{role}_auth"], safe="")
    return f"hysteria2://{auth}@{uri_host(state['domain'])}:{external}/?{query}"


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


def print_agent_setup() -> None:
    if not STATE.exists() or not SECRETS.exists():
        raise InstallError("尚未完成安装")
    show_agent_setup(include_token=True)


def menu() -> None:
    actions = {
        "1": ("全新安装/重装", install_all),
        "2": ("查看服务状态", status),
        "3": ("查看端口配置/映射", show_mapping),
        "4": ("显示节点链接（包含敏感凭据）", print_links),
        "5": ("显示 Agent 接入信息（包含敏感凭据）", print_agent_setup),
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
