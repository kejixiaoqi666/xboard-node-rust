# Xboard Node Rust v0.1.0-preview.15

这一版延续 preview.14 的功能内容，并修正 systemd 发布验收在最后一次流量上报仍处于发送阶段时过早停机造成的时序误报。服务会先等待真实回执进入可核对状态，再执行停止；未知交付仍会失败而不会被隐藏。产品仍是给 Xboard 使用的 Linux 节点后端：面板管理套餐与用户，Rust 程序负责 VPS 上的认证、转发、限制、计数和上报。默认控制层和协议服务端均为 Rust。

## 新增与补齐

- **协议**：VMess AEAD、AnyTLS、Hysteria2、TUIC；Shadowsocks 扩展到 18 种方法；Vision UDP/MUX/XUDP；REALITY 的 ML-KEM、HRR 与可选 ML-DSA。
- **传输与复用**：WebSocket、HTTP Upgrade、HTTP/2、gRPC，SMUX/Yamux/H2MUX、Xray Mux.Cool/XUDP；内置 Rust v2ray-plugin 及可选外部 SIP003 插件。
- **路由与 DNS**：本地规则集、GeoIP/GeoSite、SOCKS5 UDP、HTTP CONNECT/VLESS/Trojan/SS 出站和多层代理链；DoT/DoH/DoQ 与显式 bootstrap。上游失败不会自动变成直连，加密 DNS 失败不会自动使用系统明文解析。
- **多节点与运维**：单进程静态 fleet、多面板、机器节点发现、独立状态与上报队列；在线 IP/连接数、Linux 资源和机器状态、本地健康接口、JSON 日志、原 Go YAML 导入。
- **证书**：file/content/self、ACME HTTP-01 和 Cloudflare DNS-01；证书轮换接入实际候选生成，申请失败保留上一份成功状态。
- **生命周期与计费**：凭据撤销唤醒阻塞连接，嵌套任务停止后再保存计数；插件未就绪时响应停机并回收子进程；健康及证书监听由任务所有权管理；拒绝含糊的面板 ACK。
- **配置恢复**：每个节点持久保存最后一次成功的面板配置/用户源快照。重启时只有在没有活动快照且面板连接失败或返回 5xx 才会做身份校验后的本地恢复；鉴权、解码、身份不匹配或损坏缓存不会激活，面板恢复后会覆盖旧缓存。

用户共享限速、来源 IP 名额、成功转发载荷计数和停止预算。单进程最多 64 节点；协议用户数、缓存和复用上限见 [中文介绍](README.md) / [English](README.en.md)。这些上限不是承载量测量。

## 安装与升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
xboard-rust update --version v0.1.0-preview.15
```

Linux AMD64/ARM64 静态 musl 包、一键管理脚本、SHA256SUMS、第三方许可及分架构互通/安装/systemd 报告随发行版提供。原服务不会自动迁移；接入、YAML 导入和多节点见 [安装指南](docs/INSTALL_ZH.md)。

## 验证范围

发行流程检查准确源码的普通回归与严格 lint、固定版本官方 sing-box/Xray、35 节点实际生产入口的 TCP/UDP 与计数，以及真实 Linux 安装/启停/升级/回退；preview.15 还等待 durable 流量批次从发送阶段得到真实回执，再验证 systemd 停止，未知交付仍明确失败。该版本的 AMD64/ARM64 结果以对应 GitHub Actions 运行记录为准。真实 Flash 计费仍引用 preview.12 的独立隐藏节点证据，未把本版的发布门禁误写成新的 Flash 业务验收。具体范围与最终 SHA 见 [验证入口](docs/VALIDATION_ZH.md)。

## 明确边界

不宣称完整上游字段兼容、公网最大承载量、长期生产稳定性、吞吐提升或抗探测效果。HTTP-01 使用本地 Pebble；Cloudflare DNS-01 使用本地 mock，未据此声称生产 DNS/公共 CA 已验收。

面板没有通用批次去重时，HTTP 结果未知的流量批次需人工对账；周期存档后的强杀/断电尾部仍可能丢失。配置缓存只桥接面板不可达窗口，不保存 Token、面板地址或未知流量 ACK，也不声明断电零丢失。旧 VMess AlterID、二进制 SRS、远程规则集下载、gRPC multiMode 和 Brutal 等未支持设置明确拒绝。

English: Preview.15 carries the preview.14 feature set and hardens the systemd release gate so it waits for a real traffic acknowledgement before stopping while still failing on an unknown delivery. The exact-source official-client, actual Linux fleet, installer and service results are recorded in the tag workflow. Flash billing remains the separate preview.12 evidence; this release does not claim a new Flash run. Production DNS/public CA, full upstream parity, WAN capacity and long-term stability are not claimed; unknown acknowledgements and unsaved crash-tail boundaries remain explicit.
