#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

if [ ! -r /etc/os-release ]; then
  echo "无法识别系统：缺少 /etc/os-release" >&2
  exit 1
fi

. /etc/os-release
case "${ID:-}" in
  alpine)
    apk add --no-cache python3 openssl ca-certificates
    ;;
  debian|ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends python3 openssl ca-certificates
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    ;;
  *)
    echo "仅支持 Alpine、Debian、Ubuntu；当前：${ID:-unknown}" >&2
    exit 1
    ;;
esac

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -m 0755 /usr/local/lib/xray-nat-node-manager/assets
install -m 0755 "$base_dir/node_manager.py" /usr/local/lib/xray-nat-node-manager/node_manager.py

for asset in "$base_dir"/assets/xui-agent-linux-*; do
  [ -f "$asset" ] || continue
  install -m 0755 "$asset" "/usr/local/lib/xray-nat-node-manager/assets/$(basename "$asset")"
done

ln -sf /usr/local/lib/xray-nat-node-manager/node_manager.py /usr/local/sbin/node-manager
echo "安装完成，运行：node-manager"
