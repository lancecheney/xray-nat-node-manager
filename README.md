# Xray NAT Node Manager

面向轻量 NAT/LXC 主机的交互式 Xray 节点管理器。它负责安装官方 Xray、创建相互隔离的节点服务，并可安装 `xui-agent` 接入 3x-ui 总面板。

支持的节点类型：

- HY2 直连：客户端直接进入本机节点。
- HY2 中转落地：供中转服务器接入，不绑定特定入口或国家。
- VLESS + Reality：TCP/RAW、XTLS Vision、Chrome 指纹和独立 Reality 密钥。

每个节点使用独立的认证、配置、日志、服务和统计 API。HY2 的 QUIC 拥塞控制固定为 BBR `standard`，窗口沿用保守的 8/20 MiB 设置。

## 支持范围

- Alpine + OpenRC、Debian/Ubuntu + systemd。
- `x86_64`；仓库同时提供 `aarch64` 的 Agent 二进制。
- Cloudflare DNS-01、HTTP-01、TLS-ALPN-01，以及已有公网可信证书。
- 节点身份可以填写域名或 IP；IP 证书使用 Let’s Encrypt `shortlived` 配置，并必须保留自动续期验证端口。
- NAT 端口映射和 DNS 记录需要在服务商后台配置，脚本不会代替用户修改 3x-ui 总面板。

## 安装、启动与更新

使用 root 执行普通命令：

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/lancecheney/xray-nat-node-manager/main/install.sh)
```

普通命令会先下载几 KB 的安装脚本，然后比较远端脚本版本和本地管理器版本：

| 情况 | 行为 |
| --- | --- |
| 首次安装 | 下载完整源码包，安装缺失依赖，复制管理器和 Agent，进入菜单 |
| 版本不同 | 下载完整源码包，先更新管理器和 Agent，再只补齐缺失依赖 |
| 版本一致、依赖完整 | 直接启动本地管理器，不下载完整源码、不执行包管理器 |
| 版本一致、依赖缺失 | 只安装缺失依赖，不重新下载源码 |

安装后的日常启动也可以直接使用：

```sh
node-manager
# 或
/usr/local/sbin/node-manager
```

如果需要强制重新下载当前版本，可使用：

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/lancecheney/xray-nat-node-manager/main/install.sh) --update
```

也可以克隆或上传仓库后执行：

```sh
chmod +x install.sh node_manager.py
./install.sh
```

安装脚本只会在依赖缺失时安装 `python3`、`openssl`、`ca-certificates`、`cron/dcron` 和 `socat`。

临时下载目录会在安装流程结束时清理；系统依赖、节点配置、凭据和服务不会因退出菜单而卸载或删除。

## 菜单与首次配置

```text
1. 基础设置/修改域名证书
2. 创建节点
3. 查看节点连接（包含敏感凭据）
4. 查看服务状态/端口映射
5. 设置 Agent
6. 查看 Agent 接入信息（包含敏感凭据）
7. 单节点三网线路/延迟测试
0. 退出
```

推荐流程：

1. 选择 `1` 完成 BBR、节点地址、端口方式和 TLS 证书设置。
2. 选择 `2` 创建 HY2 直连、HY2 中转落地或 VLESS + Reality。
3. 选择 `5` 设置 Agent；随后可在 `6` 查看 3x-ui 的 Agent 接入信息。
4. 选择 `3` 查看节点链接，或选择 `4` 查看服务状态和映射关系。

再次选择 `1` 可以修改节点域名和 TLS 证书。现有节点端口、凭据和 Agent Token 会保留，端口映射方式不会在修改流程中重选。

### NAT 端口与 3x-ui 主机设置

两类设置不要混淆：

- `3x-ui 总面板 → 节点 → 添加节点`：填写 Agent 管理连接，包括 HTTPS、节点域名、Agent 外部公网 TCP 端口、基础路径、TLS 校验和 Token。
- `3x-ui 总面板 → 节点 → 添加/编辑主机`：填写 VLESS/HY2/Reality 节点主机的公网地址和外部服务端口，不填写 Agent 内部端口。

在 NAT 模式下，服务商后台的映射形如：

```text
外部 TCP/UDP 端口 → 内部 TCP/UDP 端口
```

脚本只有在 NAT 映射模式且 Agent 已配置后，才会显示“添加/编辑主机”的外部端口提醒。公网模式或未设置 Agent 时不显示该提醒。

### 节点与端口

- 两个 HY2 节点是独立 Xray 服务，不能共用同一个内部 UDP 端口；它们的认证、配置、日志和统计相互独立。
- VLESS Reality 使用 TCP，HY2 使用 UDP，因此可以使用相同的端口数字，但 NAT 面板必须分别建立 TCP 和 UDP 映射。
- NAT 映射关系和公网 DNS 记录由用户在服务商后台完成。

## 单节点线路与延迟测试

菜单 `7` 是只读的轻量回程测试，每跳只发送一次探测，实际命令为：

```sh
nexttrace -4 -q 1 --parallel-requests 1 -m 25 -n --json --no-color TARGET
```

输入方式：

- 输入 `浙江`、`上海`、`黑龙江` 等不带“省/市”的简称，依次测试电信、联通、移动目标。
- 中文严格匹配；`浙江省`、错字或其他不在注册表中的文字会拒绝。
- 输入 IPv4 时只测试该地址，不校验归属地、运营商、公网或私网属性；IPv6 不在当前范围内。
- 输入目标后会询问“每个目标测试次数”，默认 `1`，允许 `1–5` 次；省份模式最多顺序测试 15 条轨迹。
- 多次测试按顺序执行，不做硬件检测或并发探测，以减少 NAT/LXC 主机的 CPU、带宽和 ICMP 配额压力。每跳仍只发送一次探测。
- 测试次数大于 1 时，延迟显示中位数、成功次数和样本范围；线路和绕路取中位延迟对应的代表性路径，任一次确认借道都会保留“（借道）”标记。

输出重点是国际段：

```text
线路：CN2（借道）｜中国电信 China Telecom Next Generation
延迟：93.9 ms
路径：AS4809
绕路：未发现可信绕路证据
```

- `线路`只显示已识别的国际骨干，例如 CN2、9929、CUG、CMI、CMIN2。
- `路径`只显示国际或境外段 ASN；国内接入、省网和国内骨干不列出。
- 发现跨运营商借道时，在线路代码后加 `（借道）`，不再单独占一行。
- 线路、借道和绕路都是基于可见跳点的推断，不等同于完整 BGP 结论。
- GeoIP 只作辅助。单个孤立标签或与 RTT 不匹配的标签会被忽略；新加坡→香港→上海这类常见区域中转不会直接判为绕路。

省级目标来自 [oneclickvirt/nt3 的 31 省级路由注册表](https://github.com/oneclickvirt/nt3/blob/main/model/snapshot/province-routes.json)。首次测试若缺少 NextTrace，脚本会从 [NTrace-core 官方发布](https://github.com/nxtrace/NTrace-core/releases)安装固定版本 `nexttrace-tiny v1.7.3`，并校验仓库内记录的官方 SHA-256。

## TLS 证书与 Reality

### 证书申请

- 默认推荐 Cloudflare DNS-01，不要求公网 80/443；Token 使用隐藏输入。
- Cloudflare Token 只需当前 Zone 的 `Zone > DNS > Edit` 权限；不要使用 Global API Key。
- HTTP-01 固定使用公网 TCP 80；NAT 模式可以映射到手动填写的内部 TCP 端口。
- TLS-ALPN-01 固定使用公网 TCP 443；NAT 模式可以映射到其他内部 TCP 端口。
- 也可以使用已有公网可信证书；公网证书校验使用标准 CA `verify`，不固定指纹、不跳过校验。
- 自动申请使用固定并校验 SHA-256 的 `acme.sh 3.1.4`，先通过 Let’s Encrypt 测试环境，再申请正式证书。
- 两套 HY2 和 `xui-agent` 共用同一份证书；续期后会重启使用该证书的服务。Reality 不使用这份 TLS 证书。
- 域名证书和 Cloudflare Token 保存在本机受限文件中；Token 不写入节点状态、链接或安装日志。

### VLESS Reality

脚本不要求手填伪装目标。它会先解析当前节点入口 IPv4，在用户确认后扫描其所在的最小 `/27`（32 个地址、仅 TCP 443），并检查：

- TLS 1.3、H2、证书主机名和证书链；
- DNS 与扫描 IP 的一致性；
- 三轮握手稳定性和目标可达性。

扫描不合格时才使用内置的成熟域名集合；不会自动扩大到 `/24`，也不会把扫描 IP 固定成 Reality `target`。云服务器主动扫描可能触发服务商风控，因此扫描前必须确认范围。

默认 Reality 参数：

- `flow=xtls-rprx-vision`
- Chrome 指纹
- 独立 UUID、X25519 密钥、Short ID 和 SpiderX
- `minClientVer=1.0.0`

服务器侧验证不能代替客户端实测；创建完成后仍需从实际客户端网络测试连接。

## Linux BBR

全新安装开始时会显示 `[0/3] Linux TCP BBR`：

- 以 `net.ipv4.tcp_congestion_control` 的实时值判断是否已启用；
- 配置写入 `/etc/sysctl.d/99-xray-nat-node-manager-bbr.conf`，不会重复追加 `/etc/sysctl.conf`；
- NAT/LXC 无权修改宿主内核时，会恢复配置、说明原因并继续安装；
- Linux TCP BBR 只影响 TCP，HY2 使用的是 Xray 内部 QUIC BBR `standard`。

## 安全、校验与回滚

- 仓库不包含实际 Token、UUID、认证、混淆密码或证书私钥。
- Xray 从 [`XTLS/Xray-core` 官方 GitHub Release](https://github.com/XTLS/Xray-core/releases) 下载，并验证 GitHub API 提供的 SHA-256。
- 安装前备份到 `/var/backups/xray-nat-node-manager/`；凭据保存在 `/etc/xray-nat-node-manager/secrets.json`，权限为 `0600`。
- 配置写入临时文件后，先用同一个 Xray 二进制执行 `run -test`，通过后才替换并启动服务。
- 更新和证书变更使用原子写入；校验或启动失败时恢复备份并尝试恢复原服务。
- 每条 HY2 使用独立认证；不要让直连和中转共用认证。
- 不要把菜单 `3`、菜单 `6` 中显示的链接或 Token 发到聊天和公开日志中。

## Agent 源码与可复现构建

`agent/` 包含随安装器分发的 `xui-agent 0.1.2` Go 源码。仓库中的 Linux 二进制使用 Go 1.26.5、关闭 CGO 并启用 `-trimpath` 构建：

```sh
cd agent

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -buildvcs=false -trimpath -ldflags='-s -w' \
  -o ../assets/xui-agent-linux-amd64 .

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -buildvcs=false -trimpath -ldflags='-s -w' \
  -o ../assets/xui-agent-linux-arm64 .
```

当前发布文件 SHA-256：

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
