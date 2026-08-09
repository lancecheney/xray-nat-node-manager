#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行" >&2
  exit 1
fi

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -m 0755 /usr/local/lib/xray-nat-node-manager/assets
install -m 0755 "$base_dir/node_manager.py" /usr/local/lib/xray-nat-node-manager/node_manager.py

for asset in "$base_dir"/assets/xui-agent-linux-*; do
  [ -f "$asset" ] || continue
  install -m 0755 "$asset" "/usr/local/lib/xray-nat-node-manager/assets/$(basename "$asset")"
done

ln -sf /usr/local/lib/xray-nat-node-manager/node_manager.py /usr/local/sbin/node-manager
echo "安装完成，运行：node-manager"
