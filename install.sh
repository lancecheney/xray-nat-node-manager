#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

# Keep this in sync with VERSION in node_manager.py.
MANAGER_VERSION="0.7.6"
update_requested=false
if [ "${1:-}" = "--update" ]; then
  update_requested=true
fi
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$update_requested" = false ]; }; then
  echo "用法：$0 [--update]" >&2
  exit 2
fi

install_dir=/usr/local/lib/xray-nat-node-manager
installed_manager=$install_dir/node_manager.py

installed_manager_version() {
  [ -f "$installed_manager" ] || return 0
  sed -n 's/^VERSION = "\([^"]*\)"/\1/p' "$installed_manager" | head -n 1
}

dependencies_ready() {
  command -v python3 >/dev/null 2>&1 \
    && command -v openssl >/dev/null 2>&1 \
    && command -v socat >/dev/null 2>&1 \
    && (command -v crond >/dev/null 2>&1 || command -v cron >/dev/null 2>&1) \
    && [ -r /etc/ssl/certs/ca-certificates.crt ]
}

if [ "$update_requested" = false ] \
    && [ -x /usr/local/sbin/node-manager ] \
    && [ -f "$installed_manager" ] \
    && [ -d "$install_dir/assets" ] \
    && [ "$(installed_manager_version)" = "$MANAGER_VERSION" ] \
    && dependencies_ready; then
  exec /usr/local/sbin/node-manager
fi

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Running the raw script does not provide the manager or packaged Agent
# binaries. In that case, bootstrap the complete public repository first.
if [ ! -f "$base_dir/node_manager.py" ] || [ ! -d "$base_dir/assets" ]; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "远程安装需要 curl" >&2
    exit 1
  fi
  bootstrap_dir=$(mktemp -d /tmp/xray-nat-node-manager.XXXXXX)
  trap 'rm -rf -- "$bootstrap_dir"' EXIT
  curl -fsSL \
    https://github.com/lancecheney/xray-nat-node-manager/archive/refs/heads/main.tar.gz \
    -o "$bootstrap_dir/source.tar.gz"
  tar -xzf "$bootstrap_dir/source.tar.gz" -C "$bootstrap_dir"
  sh "$bootstrap_dir/xray-nat-node-manager-main/install.sh" "$@"
  exit
fi

if [ ! -r /etc/os-release ]; then
  echo "无法识别系统：缺少 /etc/os-release" >&2
  exit 1
fi

. /etc/os-release
case "${ID:-}" in
  alpine)
    apk add --no-cache python3 openssl ca-certificates dcron socat
    ;;
  debian|ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends python3 openssl ca-certificates cron socat
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    ;;
  *)
    echo "仅支持 Alpine、Debian、Ubuntu；当前：${ID:-unknown}" >&2
    exit 1
    ;;
esac

install -d -m 0755 "$install_dir/assets"
install -m 0755 "$base_dir/node_manager.py" "$installed_manager"

for asset in "$base_dir"/assets/xui-agent-linux-*; do
  [ -f "$asset" ] || continue
  install -m 0755 "$asset" "$install_dir/assets/$(basename "$asset")"
done

ln -sf /usr/local/lib/xray-nat-node-manager/node_manager.py /usr/local/sbin/node-manager
echo "安装完成，正在启动 node-manager"
exec /usr/local/sbin/node-manager
