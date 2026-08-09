# Xray NAT Node Manager

面向轻量 NAT/LXC 的交互式命令行安装器。它安装官方 Xray，创建两个相互隔离的 Xray Hysteria 2 服务，并安装轻量 `xui-agent`：

- HY2 直连：客户端直接进入新节点。
- HY2 中转落地：美国入口通过第二条 HY2 进入新节点。
- 两条线路使用不同的内部端口、认证、Salamander 密码、服务、配置、日志和统计 API。
- QUIC 拥塞控制固定为 BBR `standard`，窗口沿用已验证的 8/20 MiB。

## 当前范围

- 支持 Alpine + OpenRC、Debian/Ubuntu + systemd，安装命令与菜单完全相同。
- 支持 `x86_64`；仓库加入 arm64 Agent 后也支持 `aarch64`。
- 支持 Cloudflare DNS-01 无端口自动申请、HTTP-01/TLS-ALPN-01 端口验证，以及已有公网可信证书。
- 全新安装开始时先检测 Linux TCP BBR；已开启会直接显示状态，未开启则询问是否启用。配置写入独立的 `/etc/sysctl.d/99-xray-nat-node-manager-bbr.conf`，不会重复追加 `/etc/sysctl.conf`。
- 节点身份可以填写域名或 IP；IP 证书使用 Let’s Encrypt `shortlived` 配置并必须保留自动续期验证端口，通常建议使用域名和 DNS-01。
- NAT 面板映射和 DNS 记录必须由用户在服务商后台完成。
- 首版不会自动修改美国 3x-ui；安装完成后会输出美国出站所需的中转 HY2 链接。

## 安装

使用 root 在新机器执行一条命令：

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/lancecheney/xray-nat-node-manager/main/install.sh)
```

脚本会下载完整安装包、安装必要依赖并自动进入 `node-manager` 交互菜单。选择 `1. 全新安装/重装` 后，程序会先明确选择“使用域名 / 检测 IP / 手动 IP”，域名为推荐默认项；随后选择“端口映射”或“无端口映射”。HY2 与 Agent 的业务端口都必须手动填写；NAT 映射模式分别填写内部监听端口和外部公网端口，无映射模式只填写一个端口。最终汇总页可以单独修改直连、中转或 Agent 端口，不需要全部重填。

在节点地址问题之前，程序会显示 `[0/6] Linux TCP BBR`。判断以 `net.ipv4.tcp_congestion_control` 的实时值为准，不使用可能漏报内核内置功能的 `lsmod | grep bbr`。如果 NAT/LXC 无权修改宿主内核，程序会恢复原配置、说明原因并继续安装。Linux TCP BBR 只影响 TCP；HY2 使用的是 Xray 内部独立配置的 QUIC BBR `standard`。

## TLS 与自动续期

- 域名默认推荐 Cloudflare DNS-01，不需要公网 80/443；API Token 使用隐藏输入。
- Cloudflare 流程会显示官方 Token 创建入口，并要求只授予当前 Zone 的 `Zone > DNS > Edit`；随后先隐藏输入 Token，再隐藏输入该 Zone Overview 页面中的 32 位 Zone ID，避免误贴 Token 时显示在终端。不要使用 Global API Key。
- HTTP-01 的公网验证端口固定为 TCP 80；NAT 模式可将它映射到手动填写的内部 TCP 端口。
- IP 证书还可使用 TLS-ALPN-01，其公网验证端口固定为 TCP 443；NAT 模式可映射到其他内部 TCP 端口。
- 自动申请使用固定并校验 SHA-256 的 `acme.sh 3.1.4`，先通过 Let’s Encrypt 测试环境，再申请正式证书。
- 两套 HY2 与 `xui-agent` 共用同一份证书；续期后同时重启三个服务。
- Cloudflare Token 由 `acme.sh` 保存在节点本地的 `0600` 配置中，不写入节点状态、链接或安装日志。
- 安装完成会输出 3x-ui Agent 所需的主机、外部端口、基础路径和 HTTPS 设置；公网证书应使用标准 `verify` 校验，不再固定证书指纹。Token 需通过菜单中的敏感信息选项主动显示。

也可以克隆或上传整个仓库后执行：

```sh
chmod +x install.sh node_manager.py
./install.sh
```

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

## Agent 源码与可复现构建

`agent/` 包含随安装器分发的 `xui-agent 0.1.2` 完整 Go 源码。仓库中的 Linux 二进制使用 Go 1.26.5、关闭 CGO 并启用 `-trimpath` 构建：

```sh
cd agent

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -buildvcs=false -trimpath -ldflags='-s -w' \
  -o ../assets/xui-agent-linux-amd64 .

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -buildvcs=false -trimpath -ldflags='-s -w' \
  -o ../assets/xui-agent-linux-arm64 .
```

当前发布文件的 SHA-256：

```text
6e348045154449fb24cf0e8522740ebcd447c2746e440410189e6557db4d8c85  xui-agent-linux-amd64
f860d178a75c4ca48a9902d58767ba472a295e141454268c5958ef31865a492b  xui-agent-linux-arm64
```

## 测试

```sh
python3 -m unittest -v

cd agent
go test ./...
```

本项目使用 [MIT License](LICENSE)。
