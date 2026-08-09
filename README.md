# Xray NAT Node Manager

面向轻量 NAT/LXC 的交互式命令行安装器。它安装官方 Xray，创建两个相互隔离的 Xray Hysteria 2 服务，并安装轻量 `xui-agent`：

- HY2 直连：客户端直接进入新节点。
- HY2 中转落地：美国入口通过第二条 HY2 进入新节点。
- 两条线路使用不同的内部端口、认证、Salamander 密码、服务、配置、日志和统计 API。
- QUIC 拥塞控制固定为 BBR `standard`，窗口沿用已验证的 8/20 MiB。

## 当前范围

- 支持 Alpine + OpenRC、Debian/Ubuntu + systemd，安装命令与菜单完全相同。
- 支持 `x86_64`；仓库加入 arm64 Agent 后也支持 `aarch64`。
- 需要事先准备域名对应的有效 TLS 完整证书与私钥。
- NAT 面板映射和 DNS 记录必须由用户在服务商后台完成。
- 首版不会自动修改美国 3x-ui；安装完成后会输出美国出站所需的中转 HY2 链接。

## 安装

把整个仓库上传到新机器，然后执行：

```sh
chmod +x install.sh node_manager.py
./install.sh
node-manager
```

选择 `1. 全新安装/重装`，按提示填写域名、证书路径以及内外端口。

安装生成的凭据仅保存在新机器：

```text
/etc/xray-nat-node-manager/secrets.json
```

权限为 `0600`。只有菜单中的“显示节点链接”会显示完整凭据。

## 安全设计

- 仓库不包含实际 Token、UUID、认证、混淆密码或证书私钥。
- Xray 从 `XTLS/Xray-core` 官方 GitHub Release 下载，并验证 GitHub API 提供的 SHA-256。
- 写入配置后先执行相同 Xray 二进制的 `run -test`，通过后才启动服务。
- 安装前备份到 `/var/backups/xray-nat-node-manager/`。
- 安装、校验或启动任一步骤失败时，自动恢复安装前文件并尝试恢复原服务。
- 每条 HY2 使用独立认证；不要让直连和中转共用认证。

## 测试

```sh
python3 -m unittest -v
```
