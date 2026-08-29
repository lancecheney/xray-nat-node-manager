#!/usr/bin/env python3
"""Interactive lightweight NAT node manager for isolated Xray node services."""

from __future__ import annotations

import datetime as dt
import concurrent.futures
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
import socket
import ssl
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path


VERSION = "0.7.4"
XRAY_VERSION = "26.7.28"
NEXTTRACE_VERSION = "1.7.3"
ACME_VERSION = "3.1.4"
ACME_ARCHIVE_SHA256 = "e5f8e187bbf5251e0cd8891f2622daab9850366bd17bea9f92c2fe2ee091fd32"
ROOT = Path("/etc/xray-nat-node-manager")
STATE = ROOT / "state.json"
SECRETS = ROOT / "secrets.json"
AGENT_CONFIG = Path("/etc/xui-agent/config.json")
AGENT_STATE = Path("/var/lib/xui-agent/state.json")
AGENT_BINARY = Path("/usr/local/sbin/xui-agent")
XRAY_BINARY = Path("/usr/local/bin/xray")
NEXTTRACE_BINARY = Path("/usr/local/bin/nexttrace")
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
        "label": "HY2 直连",
        "protocol": "hy2",
        "port_protocol": "UDP",
        "uses_tls_cert": True,
    },
    "relay": {
        "name": "xray-hy2-relay",
        "config": Path("/etc/xray-hy2-relay/config.json"),
        "api_port": 10086,
        "tag": "hy2-relay-in",
        "email": "hy2-relay",
        "label": "HY2 中转落地（供中转接入）",
        "protocol": "hy2",
        "port_protocol": "UDP",
        "uses_tls_cert": True,
    },
    "reality": {
        "name": "xray-vless-reality",
        "config": Path("/etc/xray-vless-reality/config.json"),
        "api_port": 10087,
        "tag": "vless-reality-in",
        "email": "vless-reality",
        "label": "VLESS + Reality",
        "protocol": "reality",
        "port_protocol": "TCP",
        "uses_tls_cert": False,
    },
}
REALITY_FALLBACK_TARGETS = (
    "www.kernel.org",
    "www.debian.org",
    "www.python.org",
    "www.cht.com.tw",
    "cht.com.tw",
    "www.swedishhost.se",
)
REALITY_SERVER_NAME_ALIASES = {
    "www.kernel.org": ["cdn.kernel.org", "kernel.org", "www.kernel.org"],
    "www.cht.com.tw": ["www.cht.com.tw", "cht.com.tw"],
    "cht.com.tw": ["www.cht.com.tw", "cht.com.tw"],
}
REALITY_DOMAIN_BLOCKLIST = (
    "cloudflare.com", "apple.com", "microsoft.com",
)
REALITY_SUSPICIOUS_LABELS = (
    "proxy", "vpn", "vless", "xray", "hysteria", "hy2", "trojan",
)

PROVINCE_ROUTE_CODES = {
    "北京": "bj", "天津": "tj", "河北": "he", "山西": "sx", "内蒙古": "nm",
    "辽宁": "ln", "吉林": "jl", "黑龙江": "hl", "上海": "sh", "江苏": "js",
    "浙江": "zj", "安徽": "ah", "福建": "fj", "江西": "jx", "山东": "sd",
    "河南": "ha", "湖北": "hb", "湖南": "hn", "广东": "gd", "广西": "gx",
    "海南": "hi", "重庆": "cq", "四川": "sc", "贵州": "gz", "云南": "yn",
    "西藏": "xz", "陕西": "sn", "甘肃": "gs", "青海": "qh", "宁夏": "nx",
    "新疆": "xj",
}
ROUTE_CARRIERS = (
    ("ct", "中国电信"),
    ("cu", "中国联通"),
    ("cm", "中国移动"),
)
ROUTE_CARRIER_LABELS = dict(ROUTE_CARRIERS)
ROUTE_LINES = {
    "ct": (
        ("4809", "CN2", "China Telecom Next Generation"),
        ("4134", "163", "ChinaNet 骨干网"),
        ("4812", "上海省网", "中国电信上海接入网"),
    ),
    "cu": (
        ("9929", "9929", "中国联通精品网"),
        ("10099", "CUG", "China Unicom Global"),
        ("4837", "4837/169", "China Unicom 169 骨干网"),
        ("140979", "上海省网", "中国联通上海 FuTe IDC 接入网"),
    ),
    "cm": (
        ("58807", "CMIN2", "China Mobile International N2"),
        ("58453", "CMI", "China Mobile International"),
        ("9808", "CMNET", "中国移动骨干网"),
        ("56041", "浙江省网", "中国移动浙江接入网"),
    ),
}
INTERNATIONAL_ROUTE_ASNS = {
    "ct": frozenset({"4809"}),
    "cu": frozenset({"9929", "10099"}),
    "cm": frozenset({"58807", "58453"}),
}
INTERNATIONAL_ROUTE_ASN_SET = frozenset(
    asn for asns in INTERNATIONAL_ROUTE_ASNS.values() for asn in asns
)
DOMESTIC_ROUTE_ASNS = frozenset(
    asn
    for carrier, lines in ROUTE_LINES.items()
    for asn, _, _ in lines
    if asn not in INTERNATIONAL_ROUTE_ASNS[carrier]
)
UNKNOWN_GEO_LABELS = {
    "", "unknown", "未知", "网络故障", "network error", "anycast",
}
NEXTTRACE_SHA256 = {
    "nexttrace-tiny_linux_amd64": "52b4a69aa2108332f53ca2e73ffdb2937cb6cf80a6f1730765fe2209ca720f7d",
    "nexttrace-tiny_linux_arm64": "10c8a06c9f516b737c82a2c7ce6571e3a1165bf420805b508f384af277f31147",
}


class InstallError(RuntimeError):
    pass


def run(argv: list[str], *, check: bool = True, capture: bool = False,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        env=env,
        cwd=cwd,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def sanitize_acme_output(output: str) -> str:
    lines = []
    in_certificate = False
    hidden_markers = (
        "ACCOUNT_THUMBPRINT=", "Adding TXT value:", "Removing txt:",
        "Le_OrderFinalize=", "Le_LinkCert=",
    )
    for line in output.splitlines():
        if "-----BEGIN CERTIFICATE-----" in line:
            in_certificate = True
            continue
        if "-----END CERTIFICATE-----" in line:
            in_certificate = False
            continue
        if in_certificate or any(marker in line for marker in hidden_markers):
            continue
        line = re.sub(r"cfut_[A-Za-z0-9_-]+", "cfut_[redacted]", line)
        line = re.sub(r"(CF_(?:Token|Key|Email)=)[^ ]+", r"\1[redacted]", line)
        if line.strip():
            lines.append(line)
    return "\n".join(lines[-20:])


def run_acme_step(argv: list[str], label: str, *, env: dict[str, str] | None = None,
                  cwd: str | Path | None = None) -> subprocess.CompletedProcess:
    print(f"{label}...", flush=True)
    result = run(argv, check=False, capture=True, env=env, cwd=cwd)
    if result.returncode != 0:
        detail = sanitize_acme_output(result.stdout)
        raise InstallError(f"{label}失败" + (f":\n{detail}" if detail else ""))
    print(f"{label}：完成")
    return result


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


def prompt_port(text: str, default: int | None = None) -> int:
    value = int(prompt(text, str(default) if default is not None else None))
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


def collect_node_identity(current: str | None = None) -> str:
    print("\n[1/3] 节点地址")
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
        default_domain = current if current and not is_ip_identity(current) else None
        identity = normalize_node_identity(prompt("节点域名", default_domain))
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
    print("\n[2/3] 端口方式")
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
    print("\n[3/3] TLS 证书")
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


def qdisc_display(status: dict[str, str | None]) -> str:
    return status.get("default_qdisc") or "宿主机未暴露（NAT/LXC 常见）"


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
    print("\n[0/3] Linux TCP BBR")
    status = linux_tcp_bbr_status()
    if linux_tcp_bbr_enabled(status):
        print(f"Linux TCP BBR：已开启（default_qdisc={qdisc_display(status)}）")
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
    print(f"Linux TCP BBR：已开启（default_qdisc={qdisc_display(enabled)}）")
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


def nexttrace_asset_name() -> str:
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
    }
    if machine not in mapping:
        raise InstallError(f"NextTrace 不支持的 CPU 架构：{machine}")
    return f"nexttrace-tiny_linux_{mapping[machine]}"


def download_nexttrace(destination: Path) -> None:
    name = nexttrace_asset_name()
    expected = NEXTTRACE_SHA256[name]
    url = (
        "https://github.com/nxtrace/NTrace-core/releases/download/"
        f"v{NEXTTRACE_VERSION}/{name}"
    )
    digest = hashlib.sha256()
    request = urllib.request.Request(
        url, headers={"User-Agent": f"xray-nat-node-manager/{VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        with destination.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                output.write(chunk)
    if digest.hexdigest() != expected:
        destination.unlink(missing_ok=True)
        raise InstallError("NextTrace 下载文件 SHA-256 不匹配")
    os.chmod(destination, 0o755)


def ensure_nexttrace() -> Path:
    existing = shutil.which("nexttrace")
    if existing:
        return Path(existing)
    if os.geteuid() != 0:
        raise InstallError("未安装 NextTrace；请使用 root 运行以自动安装官方 tiny 版")
    print("未检测到 NextTrace，正在安装官方 tiny 版（校验 SHA-256）...")
    fd, candidate_name = tempfile.mkstemp(prefix="nexttrace-", dir="/tmp")
    os.close(fd)
    candidate = Path(candidate_name)
    try:
        download_nexttrace(candidate)
        copy_atomic(candidate, NEXTTRACE_BINARY, 0o755)
    finally:
        candidate.unlink(missing_ok=True)
    print(f"NextTrace 已安装：{NEXTTRACE_BINARY}")
    return NEXTTRACE_BINARY


def province_route_targets(value: str) -> list[tuple[str, str, str]]:
    province = value.strip()
    code = PROVINCE_ROUTE_CODES.get(province)
    if code is None:
        raise InstallError(
            "省份/直辖市不匹配；请严格输入以下名称之一：\n"
            + "、".join(PROVINCE_ROUTE_CODES)
        )
    return [
        (carrier, label, f"{code}-{carrier}-v4.ip.zstaticcdn.com")
        for carrier, label in ROUTE_CARRIERS
    ]


def route_test_targets(value: str) -> list[tuple[str | None, str, str]]:
    target = value.strip()
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return province_route_targets(target)
    if address.version != 4:
        raise InstallError("当前轻量测试仅支持 IPv4")
    return [(None, "自定义 IP", str(address))]


def trace_rtt_ms(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Go 的 time.Duration 在 JSON 中以纳秒整数输出。
        return float(value) / 1_000_000
    if isinstance(value, str):
        match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*(ns|us|µs|ms|s)?", value)
        if not match:
            return None
        number = float(match.group(1))
        return number * {"ns": 0.000001, "us": 0.001, "µs": 0.001, "ms": 1, "s": 1000}.get(
            match.group(2) or "ms", 1,
        )
    return None


def trace_hop_ip(hop: dict) -> str | None:
    address = hop.get("Address") or hop.get("address")
    if isinstance(address, str):
        value = address.rsplit(":", 1)[0] if address.count(":") == 1 else address
    elif isinstance(address, dict):
        value = address.get("IP") or address.get("ip")
    else:
        value = None
    if not value:
        geo = hop.get("Geo") or hop.get("geo") or {}
        value = geo.get("ip") if isinstance(geo, dict) else None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def trace_hop_geo(hop: dict) -> dict:
    geo = hop.get("Geo") or hop.get("geo") or {}
    return geo if isinstance(geo, dict) else {}


def trace_hop_asn(hop: dict) -> str | None:
    asns = trace_hop_asns(hop)
    return asns[0] if asns else None


def trace_hop_asns(hop: dict) -> list[str]:
    geo = trace_hop_geo(hop)
    result = []

    def add(value: object) -> None:
        value = str(value)
        for asn in re.findall(r"\bAS\s*(\d{2,10})\b", value, re.IGNORECASE):
            if asn not in result:
                result.append(asn)

    # asnumber 常是纯数字，Router/Owner/Hostname 则通常带 AS 前缀。
    raw_asn = geo.get("asnumber")
    if raw_asn is not None:
        match = re.search(r"\d{2,10}", str(raw_asn))
        if match:
            result.append(match.group(0))
    router = geo.get("router")
    add(router)
    add(hop.get("Hostname") or hop.get("hostname") or "")
    for field in ("owner", "isp", "whois", "domain", "prefix"):
        add(geo.get(field) or "")

    text = json.dumps(router, ensure_ascii=False) if router is not None else ""
    text = f"{text} {json.dumps(geo, ensure_ascii=False)}".upper()
    # NextTrace 的 CN2-Global/CN2-BackBone 可能只出现在 Router 标签里。
    inferred = (
        ("CN2", "4809"), ("9929", "9929"), ("CUG", "10099"),
        ("4837", "4837"), ("CMIN2", "58807"), ("CMI", "58453"),
        ("CMNET", "9808"),
    )
    for label, asn in inferred:
        if label == "CMI" and "CMIN2" in text:
            continue
        if label in text and asn not in result:
            result.append(asn)
    return result


def trace_path_asns(hops: list[dict]) -> list[str]:
    return [asn for asn, _ in trace_path_entries(hops)]


def trace_path_entries(hops: list[dict]) -> list[tuple[str, dict]]:
    entries = []
    for hop in hops:
        for asn in trace_hop_asns(hop):
            if not entries or entries[-1][0] != asn:
                entries.append((asn, hop))
    return entries


def visible_route_path_asns(hops: list[dict]) -> list[str]:
    """Return only confirmed international or non-China route segments."""
    path = []
    for asn, hop in trace_path_entries(hops):
        if asn in INTERNATIONAL_ROUTE_ASN_SET:
            path.append(asn)
            continue
        if asn in DOMESTIC_ROUTE_ASNS:
            continue
        location = normalized_hop_location(hop)
        if location and location[0] != "CN":
            path.append(asn)
    return path


def successful_trace_hops(payload: dict) -> list[dict]:
    groups = payload.get("Hops") or payload.get("hops") or []
    result = []
    for group in groups:
        candidates = group if isinstance(group, list) else [group]
        usable = [hop for hop in candidates if isinstance(hop, dict) and hop.get("Success", hop.get("success", True))]
        if not usable:
            continue
        result.append(min(usable, key=lambda hop: trace_rtt_ms(hop.get("RTT", hop.get("rtt"))) or float("inf")))
    return result


def route_line(carrier: str, hops: list[dict]) -> tuple[str, str, str]:
    path = visible_route_path_asns(hops)
    matches = []
    seen = set()
    for asn in path:
        metadata = asn_line_metadata(asn)
        if metadata and asn in INTERNATIONAL_ROUTE_ASN_SET and asn not in seen:
            matches.append(metadata)
            seen.add(asn)
    if not matches:
        return "未识别", "未看到该运营商的典型国际骨干 ASN", " → ".join(f"AS{item}" for item in path) or "无已识别国际路径"
    code = "+".join(item[1] for item in matches)
    name = " + ".join(f"{ROUTE_CARRIER_LABELS[item[0]]} {item[2]}" for item in matches)
    return code, name, " → ".join(f"AS{item}" for item in path)


def route_line_any(hops: list[dict]) -> tuple[str, str, str]:
    path = visible_route_path_asns(hops)
    matches = []
    seen = set()
    for asn in path:
        metadata = asn_line_metadata(asn)
        if metadata and asn in INTERNATIONAL_ROUTE_ASN_SET and asn not in seen:
            matches.append(metadata)
            seen.add(asn)
    as_path = " → ".join(f"AS{item}" for item in path) or "无已识别国际路径"
    if not matches:
        return "未识别", "未看到典型三网国际骨干 ASN", as_path
    return (
        "+".join(item[1] for item in matches),
        " + ".join(f"{ROUTE_CARRIER_LABELS[item[0]]} {item[2]}" for item in matches),
        as_path,
    )


def asn_line_metadata(asn: str) -> tuple[str, str, str] | None:
    for carrier, label in ROUTE_CARRIERS:
        for known_asn, code, name in ROUTE_LINES[carrier]:
            if known_asn == asn:
                return carrier, code, name
    return None


def format_asn_line(asn: str, metadata: tuple[str, str, str] | None = None) -> str:
    metadata = metadata or asn_line_metadata(asn)
    if not metadata:
        return f"AS{asn}"
    carrier, code, _ = metadata
    return f"{ROUTE_CARRIER_LABELS[carrier]} {code}（AS{asn}）"


def format_transit_asn(asn: str) -> str:
    metadata = asn_line_metadata(asn)
    if not metadata:
        return f"AS{asn}"
    if asn in INTERNATIONAL_ROUTE_ASNS[metadata[0]]:
        return format_asn_line(asn, metadata)
    return ROUTE_CARRIER_LABELS[metadata[0]]


def route_transit(carrier: str, hops: list[dict]) -> str:
    path = trace_path_asns(hops)
    target_asns = {item[0] for item in ROUTE_LINES[carrier]}
    target_positions = [index for index, asn in enumerate(path) if asn in target_asns]
    if not target_positions:
        return "未能确认目标运营商 ASN，无法判定借道"
    # 以目标运营商最后一个已识别 ASN 为边界，避免目标网内出现跨网回程时
    # 把中途的其他运营商 ASN 静默掉。
    last_target = max(target_positions)
    seen = []
    for asn in path[:last_target]:
        metadata = asn_line_metadata(asn)
        if metadata and metadata[0] != carrier and asn not in seen:
            seen.append(asn)
    if not seen:
        return "未发现跨运营商借道证据"
    target_asn = path[last_target]
    target_metadata = asn_line_metadata(target_asn)
    target_label = (
        format_asn_line(target_asn, target_metadata)
        if target_asn in INTERNATIONAL_ROUTE_ASN_SET
        else f"{ROUTE_CARRIER_LABELS[carrier]} 目标"
    )
    borrowed = [format_transit_asn(asn) for asn in seen]
    return f"检测到借道：{'、'.join(borrowed)} → {target_label}"


def normalized_hop_location(hop: dict) -> tuple[str, str] | None:
    geo = trace_hop_geo(hop)
    country_en = str(geo.get("country_en") or "").strip()
    country = str(geo.get("country") or country_en).strip()
    if country.lower() in UNKNOWN_GEO_LABELS and country_en.lower() in UNKNOWN_GEO_LABELS:
        return None
    province = str(geo.get("prov") or geo.get("prov_en") or "").strip()
    combined = re.sub(r"[\s_-]+", "", f"{country_en}{country}{province}").lower()
    special = (
        (("hongkong", "香港"), "HK", "香港"),
        (("macao", "macau", "澳门"), "MO", "澳门"),
        (("taiwan", "台湾"), "TW", "台湾"),
    )
    for needles, key, label in special:
        if any(needle in combined for needle in needles):
            return key, label
    if country_en.lower() in {"cn", "china", "mainland china"} or country in {"中国", "中国大陆"}:
        return "CN", "中国大陆"
    key = country_en.casefold() or country.casefold()
    return key, country or country_en


def route_detour(hops: list[dict], destination_key: str = "CN") -> str:
    located = []
    for hop in hops:
        address = trace_hop_ip(hop)
        if address is None or not ipaddress.ip_address(address).is_global:
            continue
        location = normalized_hop_location(hop)
        rtt = trace_rtt_ms(hop.get("RTT", hop.get("rtt")))
        if location and rtt is not None:
            located.append((location[0], location[1], rtt))
    if len(located) < 2:
        return "无法判断（公开地理跳点不足）"

    prefix = located[:5]
    # 起点附近通常 RTT 最低；用它比“首个 GeoIP 标签”更能抵抗首跳误标。
    source_key = prefix[0][0]
    # 首个公开跳点才是起点；只有它明显低 RTT 且后续地区重复时，才视为孤立 GeoIP 误标。
    if len(prefix) >= 3 and sum(item[0] == source_key for item in prefix) == 1:
        second = prefix[1]
        if prefix[0][2] <= 3 and prefix[0][2] + 15 < second[2] and sum(item[0] == second[0] for item in prefix) >= 2:
            source_key = second[0]
    source_rtt = min(item[2] for item in located if item[0] == source_key)
    candidates: dict[str, list[tuple[str, float, int]]] = {}
    for index, (key, label, rtt) in enumerate(located):
        if key not in {source_key, destination_key}:
            candidates.setdefault(key, []).append((label, rtt, index))

    credible = []
    regional = []
    ignored = 0
    for candidate_key, samples in candidates.items():
        minimum = min(item[1] for item in samples)
        enough_latency = minimum >= 10 and minimum - source_rtt >= 8
        nearby_pair = any(
            right[2] - left[2] <= 2
            for left, right in zip(samples, samples[1:])
        )
        if len(samples) >= 2 and nearby_pair and enough_latency:
            item = (samples[0][0], minimum, len(samples))
            if (source_key, destination_key, candidate_key) == ("singapore", "CN", "HK"):
                regional.append(item)
            else:
                credible.append(item)
        else:
            ignored += len(samples)
    if credible:
        detail = "、".join(f"{label}（{count} 跳，最低 {rtt:.1f} ms）" for label, rtt, count in credible)
        if regional:
            detail += "；另经 " + "、".join(f"{label}（区域中转）" for label, _, _ in regional)
        return f"疑似绕路：经 {detail}；请结合完整路由复核"
    if regional:
        detail = "、".join(f"{label}（{count} 跳）" for label, _, count in regional)
        return f"经过 {detail}；属于可见的区域中转，暂不判定为绕路"
    suffix = f"；已忽略 {ignored} 个孤立或低 RTT 的 GeoIP 标签" if ignored else ""
    return f"未发现可信绕路证据{suffix}"


def run_route_trace(binary: Path, target: str) -> dict:
    argv = [
        str(binary), "-4", "-q", "1", "--parallel-requests", "1",
        "-m", "25", "-n", "--json", "--no-color", target,
    ]
    try:
        result = subprocess.run(
            argv, check=False, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=50,
        )
    except subprocess.TimeoutExpired as exc:
        raise InstallError(f"NextTrace 测试超时：{target}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"退出码 {result.returncode}"
        raise InstallError(f"NextTrace 测试失败：{detail}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise InstallError("NextTrace 未返回有效 JSON；请更新 NextTrace 后重试") from exc
    if not isinstance(payload, dict):
        raise InstallError("NextTrace 返回格式异常")
    return payload


def summarize_route_trace(carrier: str | None, payload: dict) -> dict[str, str]:
    hops = successful_trace_hops(payload)
    if carrier is None:
        line, name, as_path = route_line_any(hops)
    else:
        line, name, as_path = route_line(carrier, hops)
    latency = trace_rtt_ms(hops[-1].get("RTT", hops[-1].get("rtt"))) if hops else None
    reason = ((payload.get("StopReason") or payload.get("stop_reason") or {}).get("reason") or "")
    latency_label = f"{latency:.1f} ms" if latency is not None else "无响应"
    if latency is not None and reason and reason != "destination_reached":
        latency_label += "（最后响应跳）"
    if carrier is None:
        destination = normalized_hop_location(hops[-1]) if hops and reason == "destination_reached" else None
        detour = (
            route_detour(hops, destination[0])
            if destination else "无法判断（目标地理位置不可用或未到达）"
        )
        destination_carrier = None
        if hops:
            for last_asn in reversed(trace_hop_asns(hops[-1])):
                metadata = asn_line_metadata(last_asn)
                if metadata:
                    destination_carrier = metadata[0]
                    break
        transit = (
            route_transit(destination_carrier, hops)
            if destination_carrier else "自定义 IP 未能确认目标运营商，无法判定借道"
        )
    else:
        detour = route_detour(hops)
        transit = route_transit(carrier, hops)
    return {
        "line": line,
        "name": name,
        "as_path": as_path,
        "latency": latency_label,
        "detour": detour,
        "transit": transit,
    }


def test_single_province_route() -> None:
    print("\n单节点线路/延迟测试（IPv4）")
    print("可输入省级简称（浙江、上海、黑龙江）或直接输入目标 IPv4。")
    print("中文严格匹配且不带“省/市”；IPv4 不校验归属地或运营商。")
    value = prompt("省份/直辖市/自治区简称或目标 IPv4")
    targets = route_test_targets(value)
    binary = ensure_nexttrace()
    if targets[0][0] is None:
        print(f"\n正在直接测试 {targets[0][2]}；每跳仅 1 次探测，请稍候...")
    else:
        print(f"\n正在测试 {value.strip()} 电信、联通、移动；每跳仅 1 次探测，请稍候...")
    print("GeoIP 仅作辅助；绕路结论会忽略孤立或不符合 RTT 的离谱标签。")
    for carrier, label, target in targets:
        try:
            summary = summarize_route_trace(carrier, run_route_trace(binary, target))
            print(f"\n{label}  目标：{target}")
            print(f"  线路：{summary['line']}｜{summary['name']}")
            print(f"  延迟：{summary['latency']}")
            print(f"  路径：{summary['as_path']}")
            print(f"  绕路：{summary['detour']}")
            print(f"  借道：{summary['transit']}")
        except (InstallError, OSError, subprocess.SubprocessError) as exc:
            print(f"\n{label}  测试失败：{exc}")


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


def reality_config(*, port: int, target: str, target_port: int, server_names: list[str],
                   client_id: str, private_key: str, public_key: str, short_id: str,
                   spider_x: str, spec: dict) -> dict:
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
                "protocol": "vless",
                "settings": {
                    "clients": [{
                        "id": client_id,
                        "email": spec["email"],
                        "flow": "xtls-rprx-vision",
                    }],
                    "decryption": "none",
                    "encryption": "none",
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"]},
                "streamSettings": {
                    "network": "tcp",
                    "tcpSettings": {
                        "acceptProxyProtocol": False,
                        "header": {"type": "none"},
                    },
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": f"{target}:{target_port}",
                        "xver": 0,
                        "serverNames": server_names,
                        "privateKey": private_key,
                        "minClientVer": "1.0.0",
                        "maxClientVer": "",
                        "maxTimeDiff": 0,
                        "shortIds": [short_id],
                        "settings": {
                            "publicKey": public_key,
                            "fingerprint": "chrome",
                            "serverName": "",
                            "spiderX": spider_x,
                        },
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


def generate_reality_key_pair() -> tuple[str, str]:
    result = run([str(XRAY_BINARY), "x25519"], check=False, capture=True)
    if result.returncode != 0:
        raise InstallError(f"生成 Reality 密钥失败：\n{result.stdout}")
    private_match = re.search(r"(?:Private key|PrivateKey):\s*(\S+)", result.stdout, re.IGNORECASE)
    public_match = re.search(
        r"(?:Password(?: \(PublicKey\))?|Public key|PublicKey):\s*(\S+)",
        result.stdout,
        re.IGNORECASE,
    )
    if not private_match or not public_match:
        raise InstallError("无法识别 Xray 生成的 Reality 密钥")
    return private_match.group(1), public_match.group(1)


def reality_scan_ipv4(identity: str) -> str | None:
    try:
        address = ipaddress.ip_address(identity)
        return str(address) if address.version == 4 and address.is_global else None
    except ValueError:
        pass
    try:
        addresses = socket.getaddrinfo(identity, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    for item in addresses:
        address = ipaddress.ip_address(item[4][0])
        if address.is_global:
            return str(address)
    return None


def reality_scan_network(address: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{address}/27", strict=False)


def reality_domain_allowed(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    if "*" in domain:
        return False
    try:
        normalize_node_identity(domain)
    except InstallError:
        return False
    if any(domain == suffix or domain.endswith(f".{suffix}") for suffix in REALITY_DOMAIN_BLOCKLIST):
        return False
    labels = set(domain.split("."))
    return not labels.intersection(REALITY_SUSPICIOUS_LABELS)


def certificate_dns_names(certificate_pem: bytes) -> list[str]:
    result = subprocess.run(
        [shutil.which("openssl") or "/usr/bin/openssl", "x509", "-noout", "-ext", "subjectAltName"],
        input=certificate_pem,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        return []
    output = result.stdout.decode("utf-8", "replace")
    domains = []
    for value in re.findall(r"DNS:([^,\s]+)", output):
        domain = value.lower().rstrip(".")
        if reality_domain_allowed(domain) and domain not in domains:
            domains.append(domain)
    return domains


def ensure_reality_probe_support() -> None:
    openssl = shutil.which("openssl") or "/usr/bin/openssl"
    result = subprocess.run(
        [openssl, "s_client", "-help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = result.stdout.decode("utf-8", "replace")
    required = ("-tls1_3", "-alpn", "-verify_hostname")
    if not all(option in output for option in required):
        raise InstallError("系统 OpenSSL 不支持 Reality 选优所需的 TLS 1.3/H2/域名校验，请先升级 OpenSSL")


def openssl_tls_probe(address: str, *, domain: str | None = None,
                      verify_hostname: bool = False, timeout: float = 4.0) -> tuple[str, float] | None:
    openssl = shutil.which("openssl") or "/usr/bin/openssl"
    argv = [
        openssl, "s_client", "-connect", f"{address}:443",
        "-tls1_3", "-alpn", "h2", "-showcerts",
    ]
    if domain:
        argv.extend(["-servername", domain])
    if verify_hostname:
        argv.extend(["-verify_hostname", domain, "-verify_return_error"])
    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = result.stdout.decode("utf-8", "replace")
    tls13 = re.search(r"Protocol(?: version)?\s*:\s*TLSv1\.3", output)
    h2 = re.search(r"ALPN protocol\s*:\s*h2\b", output, re.IGNORECASE)
    if result.returncode != 0 or not tls13 or not h2:
        return None
    if verify_hostname and not (
            "Verify return code: 0 (ok)" in output or "Verification: OK" in output):
        return None
    return output, (time.monotonic() - started) * 1000


def scan_reality_ip(address: str, timeout: float = 4.0) -> list[tuple[str, float]]:
    probe = openssl_tls_probe(address, timeout=timeout)
    if probe is None:
        return []
    output, elapsed_ms = probe
    certificate = re.search(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        output.encode("utf-8"),
        re.DOTALL,
    )
    if certificate is None:
        return []
    domains = certificate_dns_names(certificate.group(0) + b"\n")
    return [(domain, elapsed_ms) for domain in domains]


def resolve_public_ipv4s(domain: str) -> list[str]:
    try:
        addresses = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    result = []
    for item in addresses:
        address = str(ipaddress.ip_address(item[4][0]))
        if ipaddress.ip_address(address).is_global and address not in result:
            result.append(address)
    return result


def measure_reality_candidate(domain: str, address: str, *, source: str,
                              rounds: int = 3, timeout: float = 4.0) -> dict | None:
    samples = []
    for _ in range(rounds):
        probe = openssl_tls_probe(
            address, domain=domain, verify_hostname=True, timeout=timeout,
        )
        if probe is None:
            return None
        samples.append(probe[1])
    median = statistics.median(samples)
    jitter = max(samples) - min(samples)
    return {
        "target": domain,
        "address": address,
        "source": source,
        "median_ms": median,
        "max_ms": max(samples),
        "score": median + jitter,
    }


def nearby_reality_candidates(address: str) -> tuple[ipaddress.IPv4Network, list[tuple[str, str]]]:
    network = reality_scan_network(address)
    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(scan_reality_ip, str(candidate)): str(candidate)
            for candidate in network.hosts()
        }
        for future in concurrent.futures.as_completed(futures):
            candidate_ip = futures[future]
            try:
                domains = future.result()
            except Exception:
                continue
            for domain, elapsed_ms in domains:
                if candidate_ip in resolve_public_ipv4s(domain):
                    findings.append((domain, candidate_ip, elapsed_ms))
    findings.sort(key=lambda item: item[2])
    deduplicated = []
    for domain, candidate_ip, _ in findings:
        if all(existing[0] != domain for existing in deduplicated):
            deduplicated.append((domain, candidate_ip))
    return network, deduplicated[:5]


def select_reality_target(identity: str, *, scan_nearby: bool) -> tuple[dict, ipaddress.IPv4Network | None]:
    ensure_reality_probe_support()
    scan_address = reality_scan_ipv4(identity)
    network = None
    candidates = []
    if scan_nearby and scan_address:
        network, nearby = nearby_reality_candidates(scan_address)
        candidates.extend((domain, address, "附近 /27") for domain, address in nearby)
    existing_domains = {candidate[0] for candidate in candidates}
    for domain in REALITY_FALLBACK_TARGETS:
        if domain in existing_domains:
            continue
        candidates.extend(
            (domain, address, "成熟域名回退")
            for address in resolve_public_ipv4s(domain)[:2]
        )

    measured = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for domain, address, source in candidates:
            futures.append(executor.submit(
                measure_reality_candidate, domain, address, source=source,
            ))
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception:
                continue
            if result is not None:
                measured.append(result)
    if not measured:
        raise InstallError("没有找到同时通过证书验证、TLS 1.3、H2 和三轮稳定性检查的 Reality 目标")
    measured.sort(key=lambda item: item["score"])
    return measured[0], network


def collect_reality_target(identity: str) -> dict:
    print("\n[Reality] 自动选择伪装目标")
    print("  默认：XTLS Vision、Chrome 指纹、最低客户端版本 1.0.0")
    scan_address = reality_scan_ipv4(identity)
    allow_scan = False
    if scan_address:
        network = reality_scan_network(scan_address)
        print(f"  可扫描节点入口附近：{network}（32 个地址，TCP 443）")
        print("  提醒：官方不建议在云服务器大范围扫描；这里只扫描最小 /27，仍可能触发服务商风控。")
        allow_scan = yes_no("是否允许本机执行这次受限扫描", True)
    else:
        print("  无法确定公网 IPv4，将只测试内置成熟域名。")
    selected, network = select_reality_target(identity, scan_nearby=allow_scan)
    result = run(
        [str(XRAY_BINARY), "tls", "ping", f"{selected['target']}:443"],
        check=False, capture=True,
    )
    if (result.returncode != 0 or "Handshake succeeded" not in result.stdout
            or "TLS 1.3" not in result.stdout):
        raise InstallError(f"Xray 对 Reality 目标的最终 TLS 检查失败：{selected['target']}:443")
    print(
        f"  已选择：{selected['target']}:443"
        f"（{selected['source']}，三轮 TLS 中位 {selected['median_ms']:.0f} ms，"
        f"最慢 {selected['max_ms']:.0f} ms）"
    )
    print("  已验证：证书与域名匹配、TLS 1.3、H2；客户端所在网络可达性仍需实际连接确认。")
    return {
        "target": selected["target"],
        "target_port": 443,
        "server_names": REALITY_SERVER_NAME_ALIASES.get(
            selected["target"], [selected["target"]],
        ),
        "source": selected["source"],
        "scan_network": str(network) if network else None,
        "median_ms": round(selected["median_ms"], 1),
        "max_ms": round(selected["max_ms"], 1),
    }


def openrc_service(name: str, config: Path) -> str:
    return f'''#!/sbin/openrc-run
name="{name}"
description="Xray node managed by xray-nat-node-manager"
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
Description=Xray node managed by xray-nat-node-manager ({name})
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


def service_disable_argv(system: dict[str, str], name: str) -> list[str]:
    if system["init"] == "openrc":
        return [shutil.which("rc-update") or "/sbin/rc-update", "del", name, "default"]
    return [shutil.which("systemctl") or "/bin/systemctl", "disable", name]


def service_daemon_reload(system: dict[str, str]) -> None:
    if system["init"] == "systemd":
        run([shutil.which("systemctl") or "/bin/systemctl", "daemon-reload"])


def dns_san_matches(pattern: str, hostname: str) -> bool:
    hostname = normalize_node_identity(hostname)
    pattern = pattern.strip().rstrip(".").lower()
    if "*" not in pattern:
        try:
            return pattern.encode("idna").decode("ascii") == hostname
        except UnicodeError:
            return False
    if not pattern.startswith("*.") or pattern.count("*") != 1:
        return False
    try:
        suffix = normalize_node_identity(pattern[2:])
    except InstallError:
        return False
    labels = hostname.split(".")
    suffix_labels = suffix.split(".")
    return len(labels) == len(suffix_labels) + 1 and labels[1:] == suffix_labels


def certificate_san_matches(decoded: dict, identity: str) -> bool:
    sans = decoded.get("subjectAltName", ())
    if is_ip_identity(identity):
        expected = ipaddress.ip_address(identity)
        for kind, value in sans:
            if kind != "IP Address":
                continue
            try:
                if ipaddress.ip_address(value) == expected:
                    return True
            except ValueError:
                continue
        return False
    return any(kind == "DNS" and dns_san_matches(value, identity) for kind, value in sans)


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
        if not certificate_san_matches(decoded, identity):
            raise ssl.CertificateError("required identity is missing from SAN")
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
        try:
            package.extractall(destination, members=members, filter="data")
        except TypeError:
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
        rc_update = shutil.which("rc-update") or "/sbin/rc-update"
        rc_service = shutil.which("rc-service") or "/sbin/rc-service"
        run([rc_update, "add", "crond", "default"], check=False, capture=True)
        status = run([rc_service, "crond", "status"], check=False, capture=True)
        if status.returncode != 0:
            run([rc_service, "crond", "start"], capture=True)
    else:
        systemctl = shutil.which("systemctl") or "/bin/systemctl"
        run([systemctl, "enable", "cron"], check=False, capture=True)
        status = run([systemctl, "is-active", "cron"], check=False, capture=True)
        if status.returncode != 0:
            run([systemctl, "start", "cron"], capture=True)


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
        run_acme_step(argv, "安装证书工具", cwd=source)
    if not (ACME_HOME / "acme.sh").is_file():
        raise InstallError("acme.sh 安装后入口不存在")
    ACME_CONFIG_HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ACME_CONFIG_HOME, 0o700)
    ensure_cron_running(system)


def certificate_reload_script(system: dict[str, str]) -> str:
    names = [spec["name"] for spec in SERVICE_SPECS.values() if spec["uses_tls_cert"]] + ["xui-agent"]
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
        staging_config = staging / "config"
        staging_certs = staging / "certs"
        staging_config.mkdir(mode=0o700)
        staging_certs.mkdir(mode=0o700)
        run_acme_step(
            [*acme_command(staging_config, staging_certs), "--server", "letsencrypt_test", *issue_args],
            "Let's Encrypt 测试验证", env=environment,
        )
    run_acme_step(
        [*acme_command(), "--server", "letsencrypt", *issue_args],
        "Let's Encrypt 正式证书申请", env=environment,
    )

    cert, key = managed_certificate_paths(identity)
    cert.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_atomic(ACME_RELOAD, certificate_reload_script(system), 0o755)
    run_acme_step(
        [*acme_command(), "--install-cert", "-d", identity, "--ecc",
         "--fullchain-file", str(cert), "--key-file", str(key),
         "--reloadcmd", str(ACME_RELOAD)],
        "安装证书并配置自动续期", env=environment,
    )
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


def restore_backup(target: Path, system: dict[str, str], services: list[str] | None = None) -> None:
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    service_names = services if services is not None else [
        spec["name"] for spec in SERVICE_SPECS.values()
    ] + ["xui-agent"]
    for name in service_names:
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
    for name in service_names:
        if service_file(system, name).exists():
            run(service_argv(system, name, "start"), check=False, capture=True)


def validate_xray(configs: list[Path]) -> None:
    for config in configs:
        result = run([str(XRAY_BINARY), "run", "-test", "-c", str(config)], check=False, capture=True)
        if result.returncode != 0:
            raise InstallError(f"Xray 拒绝配置 {config}:\n{result.stdout}")


def load_state() -> dict:
    if not STATE.is_file():
        raise InstallError("尚未完成基础设置；请先选择 1. 基础设置")
    state = json.loads(STATE.read_text(encoding="utf-8"))
    state.setdefault("ports", {})
    return state


def load_secrets() -> dict:
    if not SECRETS.is_file():
        return {}
    return json.loads(SECRETS.read_text(encoding="utf-8"))


def role_is_configured(state: dict, role: str) -> bool:
    ports = state.get("ports") or {}
    internal_key, external_key = role_port_keys(role)
    return all(key in ports for key in (internal_key, external_key))


def role_port_keys(role: str) -> tuple[str, str]:
    protocol = SERVICE_SPECS[role]["port_protocol"].lower()
    return f"{role}_internal_{protocol}", f"{role}_external_{protocol}"


def agent_is_configured(state: dict) -> bool:
    ports = state.get("ports") or {}
    return all(key in ports for key in ("agent_internal_tcp", "agent_external_tcp"))


def configured_roles(state: dict) -> list[str]:
    return [role for role in SERVICE_SPECS if role_is_configured(state, role)]


def validate_component_ports(state: dict, *, role: str | None = None,
                             internal: int, external: int, protocol: str) -> None:
    ports = state.get("ports") or {}
    protocol = protocol.lower()
    for other, spec in SERVICE_SPECS.items():
        if other == role or spec["port_protocol"].lower() != protocol or not role_is_configured(state, other):
            continue
        other_internal, other_external = role_port_keys(other)
        if ports[other_internal] == internal:
            raise InstallError(
                f"内部 {protocol.upper()} 端口已被 {spec['label']} 使用：{internal}"
            )
        if ports[other_external] == external:
            raise InstallError(
                f"外部 {protocol.upper()} 端口已被 {spec['label']} 使用：{external}"
            )
    if protocol == "tcp":
        if role != "agent" and agent_is_configured(state):
            if ports["agent_internal_tcp"] == internal:
                raise InstallError(f"内部 TCP 端口已被 Agent 使用：{internal}")
            if ports["agent_external_tcp"] == external:
                raise InstallError(f"外部 TCP 端口已被 Agent 使用：{external}")
        tls = state.get("tls") or {}
        if tls.get("internal_tcp") == internal:
            raise InstallError(f"该节点与 ACME 不能共用内部 TCP 端口：{internal}")
        if tls.get("external_tcp") == external:
            raise InstallError(f"该节点与 ACME 不能共用外部 TCP 端口：{external}")


def collect_base_answers() -> dict:
    domain = collect_node_identity()
    network = collect_network_answers()
    tls = collect_tls_answers(domain, network)
    return {
        "domain": domain,
        "network": network,
        "tls": tls,
        "cert": tls.get("cert"),
        "key": tls.get("key"),
        "ports": {},
    }


def show_base_summary(answers: dict, title: str = "即将完成基础设置：") -> None:
    print(f"\n{title}")
    print(f"  节点身份：{answers['domain']}")
    print(f"  端口方式：{'端口映射（NAT）' if answers['network']['mode'] == 'mapped' else '无端口映射（公网机）'}")
    print(f"  TLS 证书：{certificate_method_label(answers['tls']['method'])}")
    if answers.get("cert"):
        print(f"  证书路径：{answers['cert']}")


def validate_tls_ports(state: dict, tls: dict) -> None:
    internal = tls.get("internal_tcp")
    external = tls.get("external_tcp")
    if internal is None or external is None:
        return
    ports = state.get("ports") or {}
    if role_is_configured(state, "reality"):
        reality_internal, reality_external = role_port_keys("reality")
        if ports[reality_internal] == internal:
            raise InstallError(f"ACME 内部 TCP 端口已被 VLESS + Reality 使用：{internal}")
        if ports[reality_external] == external:
            raise InstallError(f"ACME 外部 TCP 端口已被 VLESS + Reality 使用：{external}")
    if agent_is_configured(state):
        if ports["agent_internal_tcp"] == internal:
            raise InstallError(f"ACME 内部 TCP 端口已被 Agent 使用：{internal}")
        if ports["agent_external_tcp"] == external:
            raise InstallError(f"ACME 外部 TCP 端口已被 Agent 使用：{external}")


def refresh_tls_consumers(system: dict[str, str], state: dict, credentials: dict) -> None:
    configs = []
    roles = []
    for role in ("direct", "relay"):
        if not role_is_configured(state, role):
            continue
        spec = SERVICE_SPECS[role]
        internal_key, _ = role_port_keys(role)
        auth = credentials.get(f"{role}_auth")
        obfs_password = credentials.get(f"{role}_obfs_password")
        if not auth or not obfs_password:
            raise InstallError(f"{spec['label']} 缺少原有凭据，无法安全更新证书")
        config = hy2_config(
            domain=state["domain"], port=state["ports"][internal_key],
            cert=state["cert"], key=state["key"], auth=auth,
            obfs_password=obfs_password, spec=spec,
        )
        json_write(spec["config"], config)
        configs.append(spec["config"])
        roles.append(role)
    validate_xray(configs)
    for role in roles:
        name = SERVICE_SPECS[role]["name"]
        run(service_argv(system, name, "restart"))
        run(service_argv(system, name, "status"))
    if agent_is_configured(state):
        refresh_agent(system, state, credentials)


def modify_base(system: dict[str, str], state: dict) -> None:
    show_base_summary(state, "当前基础设置：")
    print("  现有节点端口、凭据和 Agent Token 将保持不变。")
    if not yes_no("是否修改节点域名和 TLS 证书", False):
        print("已取消，未修改基础设置")
        return

    domain = collect_node_identity(state.get("domain"))
    tls = collect_tls_answers(domain, state["network"])
    validate_tls_ports(state, tls)
    updated = json.loads(json.dumps(state))
    updated["domain"] = domain
    updated["tls"] = tls
    updated["cert"] = tls.get("cert")
    updated["key"] = tls.get("key")
    show_base_summary(updated)
    if not yes_no("确认修改域名和证书", True):
        print("已取消，未修改系统")
        return

    credentials = load_secrets()
    managed = [
        ROOT, ACME_RELOAD,
        Path("/etc/crontabs/root"), Path("/var/spool/cron/crontabs/root"),
    ]
    rollback_services = []
    for role in ("direct", "relay"):
        if role_is_configured(state, role):
            managed.append(SERVICE_SPECS[role]["config"].parent)
            rollback_services.append(SERVICE_SPECS[role]["name"])
    if agent_is_configured(state):
        managed += [AGENT_CONFIG.parent, AGENT_STATE.parent]
        rollback_services.append("xui-agent")
    if tls["method"] != "existing":
        managed += [ACME_HOME, ACME_CONFIG_HOME, ACME_CERT_HOME]
    backup = backup_paths(managed)
    print(f"备份：{backup}")
    try:
        if tls["method"] != "existing":
            updated["cert"], updated["key"] = issue_certificate(system, domain, tls)
        updated["tls"] = state_without_secrets({"tls": tls})["tls"]
        updated["updated_at"] = stamp()
        refresh_tls_consumers(system, updated, credentials)
        json_write(SECRETS, credentials)
        json_write(STATE, updated)
        print("节点域名和 TLS 证书修改完成。")
        show_mapping(updated)
    except Exception:
        print(f"基础设置修改失败，正在恢复：{backup}", file=sys.stderr)
        restore_backup(backup, system, rollback_services)
        raise


def setup_base() -> None:
    system = require_root_supported()
    if STATE.exists():
        modify_base(system, load_state())
        return
    check_linux_tcp_bbr()
    answers = collect_base_answers()
    show_base_summary(answers)
    if not yes_no("确认保存基础设置", True):
        print("已取消，未修改系统")
        return

    managed = [
        ROOT, XRAY_BINARY, ACME_RELOAD,
        Path("/etc/crontabs/root"), Path("/var/spool/cron/crontabs/root"),
    ]
    if answers["tls"]["method"] != "existing":
        managed += [ACME_HOME, ACME_CONFIG_HOME, ACME_CERT_HOME]
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
        ROOT.mkdir(parents=True, exist_ok=True)
        json_write(SECRETS, {})
        answers["installed_at"] = stamp()
        answers["xray_version"] = XRAY_VERSION
        answers["system"] = system
        json_write(STATE, state_without_secrets(answers))
        print("基础设置完成。接下来请选择 2 创建需要的节点，再选择 5 设置 Agent。")
        show_mapping(answers)
    except Exception:
        print(f"基础设置失败，正在恢复：{backup}", file=sys.stderr)
        restore_backup(backup, system, [])
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


def agent_services(state: dict, system: dict[str, str]) -> list[dict]:
    roles = configured_roles(state)
    services = []
    for index, role in enumerate(roles):
        spec = SERVICE_SPECS[role]
        services.append({
            "name": spec["name"],
            "binary": str(XRAY_BINARY),
            "configPath": str(spec["config"]),
            "apiEndpoint": f"127.0.0.1:{spec['api_port']}",
            "restartCommand": service_argv(system, spec["name"], "restart"),
            "statusCommand": service_argv(system, spec["name"], "status"),
            "ignoreTags": ["api"],
            "default": index == 0,
        })
    return services


def agent_credentials(credentials: dict) -> tuple[str, str]:
    existing = {}
    if AGENT_CONFIG.is_file():
        try:
            existing = json.loads(AGENT_CONFIG.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
    token = credentials.get("agent_token") or existing.get("token") or secrets.token_hex(32)
    panel_guid = credentials.get("agent_panel_guid") or existing.get("panelGuid") or secrets.token_hex(16)
    credentials["agent_token"] = token
    credentials["agent_panel_guid"] = panel_guid
    return token, panel_guid


def build_agent_config(state: dict, credentials: dict, system: dict[str, str]) -> dict:
    if not agent_is_configured(state):
        raise InstallError("尚未设置 Agent 端口")
    services = agent_services(state, system)
    if not services:
        raise InstallError("请先选择 2 至少创建一个节点，再设置 Agent")
    token, panel_guid = agent_credentials(credentials)
    return {
        "listen": f"0.0.0.0:{state['ports']['agent_internal_tcp']}",
        "token": token,
        "panelGuid": panel_guid,
        "statePath": str(AGENT_STATE),
        "tlsCertFile": state["cert"],
        "tlsKeyFile": state["key"],
        "services": services,
    }


def write_validated_agent_config(config: dict) -> None:
    AGENT_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".xui-agent-candidate-", suffix=".json", dir=AGENT_CONFIG.parent)
    os.close(fd)
    candidate = Path(name)
    try:
        json_write(candidate, config)
        run([str(AGENT_BINARY), "-config", str(candidate), "-check"])
        os.replace(candidate, AGENT_CONFIG)
    finally:
        candidate.unlink(missing_ok=True)


def refresh_agent(system: dict[str, str], state: dict, credentials: dict) -> None:
    config = build_agent_config(state, credentials, system)
    write_validated_agent_config(config)
    AGENT_STATE.parent.mkdir(parents=True, exist_ok=True)
    run([str(AGENT_BINARY), "-config", str(AGENT_CONFIG), "-adopt"])
    run([str(AGENT_BINARY), "-config", str(AGENT_CONFIG), "-check"])
    run(service_argv(system, "xui-agent", "restart"))
    run(service_argv(system, "xui-agent", "status"))


def create_node() -> None:
    system = require_root_supported()
    state = load_state()
    credentials = load_secrets()
    print("\n创建节点：")
    print(" 1. HY2 直连节点")
    print(" 2. HY2 中转落地节点（供中转接入）")
    print(" 3. VLESS + Reality 节点")
    choice = prompt("请选择", "1")
    role = {"1": "direct", "2": "relay", "3": "reality"}.get(choice)
    if role is None:
        raise InstallError("无效的节点类型")
    spec = SERVICE_SPECS[role]
    label = spec["label"]
    if role_is_configured(state, role):
        print(f"{label} 节点已经创建。后续入站和客户端请在 3x-ui 总面板调整。")
        print("公网外部端口映射仍需在 NAT 服务商后台管理。")
        return
    if spec["protocol"] == "hy2" and any(
            role_is_configured(state, other)
            for other in ("direct", "relay") if other != role):
        print("提示：两条 HY2 使用独立服务，内部 UDP 端口不能相同。")
    print(f"\n[{label}] 端口")
    port_protocol = spec["port_protocol"]
    internal, external = collect_service_ports(label, port_protocol, state["network"])
    validate_component_ports(
        state, role=role, internal=internal, external=external, protocol=port_protocol,
    )
    if state["network"]["mode"] == "mapped":
        print(f"  需要 NAT 映射：{port_protocol} {external} -> {port_protocol} {internal}")
    else:
        print(f"  公网监听：{port_protocol} {internal}")
    reality_target = None
    if spec["protocol"] == "reality":
        reality_target = collect_reality_target(state["domain"])
    if not yes_no(f"确认设置 {label}", True):
        print("已取消，未修改节点")
        return

    service_preexisted = service_file(system, spec["name"]).exists()
    managed = [spec["config"].parent, service_file(system, spec["name"]), STATE, SECRETS]
    rollback_services = [spec["name"]]
    if agent_is_configured(state):
        managed += [AGENT_CONFIG, AGENT_STATE.parent]
        rollback_services.append("xui-agent")
    backup = backup_paths(managed)
    print(f"备份：{backup}")
    try:
        if spec["protocol"] == "hy2":
            credentials.setdefault(f"{role}_auth", secrets.token_hex(24))
            credentials.setdefault(f"{role}_obfs_password", secrets.token_hex(24))
            config = hy2_config(
                domain=state["domain"], port=internal, cert=state["cert"], key=state["key"],
                auth=credentials[f"{role}_auth"],
                obfs_password=credentials[f"{role}_obfs_password"], spec=spec,
            )
        else:
            if not credentials.get("reality_private_key") or not credentials.get("reality_public_key"):
                private_key, public_key = generate_reality_key_pair()
                credentials["reality_private_key"] = private_key
                credentials["reality_public_key"] = public_key
            credentials.setdefault("reality_client_id", str(uuid.uuid4()))
            credentials.setdefault("reality_short_id", secrets.token_hex(8))
            credentials.setdefault("reality_spider_x", f"/{secrets.token_hex(8)}")
            target = reality_target["target"]
            target_port = reality_target["target_port"]
            state["reality"] = reality_target
            config = reality_config(
                port=internal, target=target, target_port=target_port,
                server_names=reality_target["server_names"],
                client_id=credentials["reality_client_id"],
                private_key=credentials["reality_private_key"],
                public_key=credentials["reality_public_key"],
                short_id=credentials["reality_short_id"],
                spider_x=credentials["reality_spider_x"], spec=spec,
            )
        json_write(spec["config"], config)
        validate_xray([spec["config"]])
        write_atomic(
            service_file(system, spec["name"]),
            service_definition(system, spec["name"], spec["config"]),
            0o755 if system["init"] == "openrc" else 0o644,
        )
        service_daemon_reload(system)
        run(service_enable_argv(system, spec["name"]), check=False)
        run(service_argv(system, spec["name"], "restart"))
        run(service_argv(system, spec["name"], "status"))
        internal_key, external_key = role_port_keys(role)
        state["ports"][internal_key] = internal
        state["ports"][external_key] = external
        state["updated_at"] = stamp()
        json_write(SECRETS, credentials)
        json_write(STATE, state)
        if agent_is_configured(state):
            refresh_agent(system, state, credentials)
        print(f"{label} 节点创建完成。")
        print("请选择 3. 查看节点连接，按需显示敏感链接。")
    except Exception:
        print(f"节点创建失败，正在恢复：{backup}", file=sys.stderr)
        if not service_preexisted:
            run(service_disable_argv(system, spec["name"]), check=False, capture=True)
        restore_backup(backup, system, rollback_services)
        raise


def configure_agent() -> None:
    system = require_root_supported()
    state = load_state()
    if not configured_roles(state):
        raise InstallError("请先选择 2 至少创建一个节点，再设置 Agent")
    credentials = load_secrets()
    if agent_is_configured(state) and not yes_no("Agent 已存在，是否修改端口并保留现有 Token", False):
        return
    print("\n[Agent] 管理端口")
    internal, external = collect_service_ports("Agent 管理", "TCP", state["network"])
    validate_component_ports(
        state, role="agent", internal=internal, external=external, protocol="tcp",
    )
    if state["network"]["mode"] == "mapped":
        print(f"  需要 NAT 映射：TCP {external} -> TCP {internal}")
    else:
        print(f"  公网监听：TCP {internal}")
    if not yes_no("确认设置 Agent", True):
        print("已取消，未修改 Agent")
        return

    packaged_agent = Path(__file__).resolve().parent / "assets" / xray_asset_for_agent()
    if not packaged_agent.is_file():
        raise InstallError(f"安装包缺少 Agent：{packaged_agent}")
    service_preexisted = service_file(system, "xui-agent").exists()
    managed = [AGENT_CONFIG.parent, AGENT_STATE.parent, AGENT_BINARY,
               service_file(system, "xui-agent"), STATE, SECRETS]
    backup = backup_paths(managed)
    print(f"备份：{backup}")
    try:
        state["ports"]["agent_internal_tcp"] = internal
        state["ports"]["agent_external_tcp"] = external
        copy_atomic(packaged_agent, AGENT_BINARY, 0o755)
        write_atomic(
            service_file(system, "xui-agent"), service_definition(system, "xui-agent"),
            0o755 if system["init"] == "openrc" else 0o644,
        )
        service_daemon_reload(system)
        run(service_enable_argv(system, "xui-agent"), check=False)
        refresh_agent(system, state, credentials)
        state["agent_sha256"] = sha256(packaged_agent)
        state["updated_at"] = stamp()
        json_write(SECRETS, credentials)
        json_write(STATE, state)
        print("Agent 设置完成。")
        show_agent_setup(state)
        show_host_setup(state)
    except Exception:
        print(f"Agent 设置失败，正在恢复：{backup}", file=sys.stderr)
        if not service_preexisted:
            run(service_disable_argv(system, "xui-agent"), check=False, capture=True)
        restore_backup(backup, system, ["xui-agent"])
        raise


def show_mapping(state: dict | None = None) -> None:
    state = state or load_state()
    ports = state.get("ports") or {}
    mapped = (state.get("network") or {}).get("mode", "mapped") == "mapped"
    components = []
    for role, spec in SERVICE_SPECS.items():
        if not role_is_configured(state, role):
            continue
        internal_key, external_key = role_port_keys(role)
        components.append((
            spec["port_protocol"], ports[internal_key], ports[external_key], spec["label"],
        ))
    if agent_is_configured(state):
        components.append(("TCP", ports["agent_internal_tcp"], ports["agent_external_tcp"], "xui-agent"))
    if components and mapped:
        print("  请在 NAT 面板保留以下映射：")
    for protocol, internal, external, label in components:
        if mapped:
            print(f"  {protocol} {external} -> {protocol} {internal}  ({label})")
        else:
            print(f"  {protocol} {internal}  ({label}，内外相同)")
    if not components:
        print("  尚未创建节点或设置 Agent 端口。")
    tls = state.get("tls") or {}
    if tls.get("external_tcp"):
        if mapped:
            print(f"  TCP {tls['external_tcp']} -> TCP {tls['internal_tcp']}  (ACME 自动续期，必须保留)")
        else:
            print(f"  TCP {tls['internal_tcp']}  (ACME 自动续期验证，公网端口固定)")


def show_agent_setup(state: dict | None = None, *, include_token: bool = False) -> None:
    state = state or load_state()
    if not agent_is_configured(state):
        raise InstallError("尚未设置 Agent；请选择 5. 设置 Agent")
    print("\n3x-ui 添加节点设置（总面板 -> 节点 -> 添加节点）：")
    print("  说明：这里配置节点的 Agent 管理连接，不是 VLESS/HY2/Reality 的主机。")
    print("  协议：https")
    print(f"  地址（不含 https://）：{state['domain']}")
    external = state["ports"]["agent_external_tcp"]
    internal = state["ports"]["agent_internal_tcp"]
    print(f"  端口（Agent 外部公网 TCP 端口）：{external}")
    if (state.get("network") or {}).get("mode", "mapped") == "mapped":
        print(f"  NAT 面板映射：外部 TCP {external} -> 内部 TCP {internal}")
        print("  提醒：添加节点表单填 Agent 外部公网端口，不要填内部监听端口。")
    print("  基础路径：/")
    print("  TLS 校验：标准验证（verify；不要选择固定指纹或跳过验证）")
    if include_token:
        credentials = json.loads(SECRETS.read_text(encoding="utf-8"))
        print(f"  Token：{credentials['agent_token']}")
    else:
        print("  Token：安装完成后在菜单选择“显示 Agent 接入信息”查看")


def show_host_setup(state: dict | None = None) -> None:
    state = state or load_state()
    if (state.get("network") or {}).get("mode", "mapped") != "mapped":
        return
    if not agent_is_configured(state):
        return
    roles = configured_roles(state)
    if not roles:
        return
    print("\n端口映射模式提醒：请在 3x-ui 总面板的主机设置中填写节点对外连接信息：")
    print("  说明：这里填写的是 VLESS/HY2/Reality 节点主机，不是 Agent 管理连接。")
    print("  选择入站后 -> 添加/编辑主机，使用各服务的外部公网地址和端口。")
    for role in roles:
        spec = SERVICE_SPECS[role]
        internal_key, external_key = role_port_keys(role)
        internal = state["ports"][internal_key]
        external = state["ports"][external_key]
        print(f"  {spec['label']}：")
        print(f"    地址：{state['domain']}:{external}")
        print(f"    端口：{external}")
        print(
            f"    NAT 映射：外部 {spec['port_protocol']} {external}"
            f" -> 内部 {spec['port_protocol']} {internal}"
        )


def hy2_uri(role: str) -> str:
    state = load_state()
    if not role_is_configured(state, role):
        raise InstallError("该节点尚未设置")
    credentials = load_secrets()
    _, external_key = role_port_keys(role)
    external = state["ports"][external_key]
    query = urllib.parse.urlencode({
        "sni": state["domain"], "insecure": "0", "alpn": "h3", "obfs": "salamander",
        "obfs-password": credentials[f"{role}_obfs_password"],
    })
    auth = urllib.parse.quote(credentials[f"{role}_auth"], safe="")
    return f"hysteria2://{auth}@{uri_host(state['domain'])}:{external}/?{query}"


def reality_uri() -> str:
    state = load_state()
    if not role_is_configured(state, "reality"):
        raise InstallError("VLESS + Reality 节点尚未创建")
    credentials = load_secrets()
    _, external_key = role_port_keys("reality")
    target = state["reality"]["target"]
    query = urllib.parse.urlencode({
        "encryption": "none",
        "flow": "xtls-rprx-vision",
        "security": "reality",
        "sni": target,
        "fp": "chrome",
        "pbk": credentials["reality_public_key"],
        "sid": credentials["reality_short_id"],
        "type": "tcp",
        "headerType": "none",
        "spx": credentials.get("reality_spider_x", "/"),
    })
    return (
        f"vless://{credentials['reality_client_id']}@{uri_host(state['domain'])}:"
        f"{state['ports'][external_key]}?{query}#VLESS-Reality"
    )


def status() -> None:
    system = require_root_supported()
    state = load_state()
    names = [SERVICE_SPECS[role]["name"] for role in configured_roles(state)]
    if agent_is_configured(state):
        names.append("xui-agent")
    if not names:
        print("尚未创建节点或设置 Agent。")
    for name in names:
        result = run(service_argv(system, name, "status"), check=False, capture=True)
        print(f"{name}: {'started' if result.returncode == 0 else 'stopped/error'}")
    if XRAY_BINARY.exists():
        result = run([str(XRAY_BINARY), "version"], check=False, capture=True)
        print(result.stdout.splitlines()[0] if result.stdout else "Xray version unknown")


def print_links() -> None:
    if not STATE.exists() or not SECRETS.exists():
        raise InstallError("尚未完成基础设置")
    state = load_state()
    roles = configured_roles(state)
    if not roles:
        raise InstallError("尚未创建节点；请选择 2. 创建节点")
    if "direct" in roles:
        print("HY2 直连：", hy2_uri("direct"))
    if "relay" in roles:
        print("HY2 中转落地（供中转接入）：", hy2_uri("relay"))
    if "reality" in roles:
        print("VLESS + Reality：", reality_uri())


def print_agent_setup() -> None:
    if not STATE.exists() or not SECRETS.exists():
        raise InstallError("尚未完成基础设置")
    show_agent_setup(include_token=True)


def show_status_and_mapping() -> None:
    status()
    show_mapping()


def menu() -> None:
    actions = {
        "1": ("基础设置/修改域名证书", setup_base),
        "2": ("创建节点", create_node),
        "3": ("查看节点连接（包含敏感凭据）", print_links),
        "4": ("查看服务状态/端口映射", show_status_and_mapping),
        "5": ("设置 Agent", configure_agent),
        "6": ("查看 Agent 接入信息（包含敏感凭据）", print_agent_setup),
        "7": ("单节点三网线路/延迟测试", test_single_province_route),
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
