# Xboard Node Rust v0.1.0-preview.12

这一版补齐此前列出的主要协议、传输、路由、DNS、多节点和证书模块。它仍是给 Xboard 使用的 Linux 节点后端：面板管理套餐与用户，Rust 程序负责 VPS 上的认证、转发、限制、计数和上报。默认控制层和协议服务端均为 Rust。

## 新增与补齐

- **协议**：VMess AEAD、AnyTLS、Hysteria2、TUIC；Shadowsocks 扩展到 18 种方法；Vision UDP/MUX/XUDP；REALITY 的 ML-KEM、HRR 与可选 ML-DSA。
- **传输与复用**：WebSocket、HTTP Upgrade、HTTP/2、gRPC，SMUX/Yamux/H2MUX、Xray Mux.Cool/XUDP；内置 Rust v2ray-plugin 及可选外部 SIP003 插件。
- **路由与 DNS**：本地规则集、GeoIP/GeoSite、SOCKS5 UDP、HTTP CONNECT/VLESS/Trojan/SS 出站和多层代理链；DoT/DoH/DoQ 与显式 bootstrap。上游失败不会自动变成直连，加密 DNS 失败不会自动使用系统明文解析。
- **多节点与运维**：单进程静态 fleet、多面板、机器节点发现、独立状态与上报队列；在线 IP/连接数、Linux 资源和机器状态、本地健康接口、JSON 日志、原 Go YAML 导入。
- **证书**：file/content/self、ACME HTTP-01 和 Cloudflare DNS-01；证书轮换接入实际候选生成，申请失败保留上一份成功状态。
- **生命周期与计费**：凭据撤销唤醒阻塞连接，嵌套任务停止后再保存计数；插件未就绪时响应停机并回收子进程；健康及证书监听由任务所有权管理；拒绝含糊的面板 ACK。

用户共享限速、来源 IP 名额、成功转发载荷计数和停止预算。单进程最多 64 节点；协议用户数、缓存和复用上限见 [中文介绍](README.md) / [English](README.en.md)。这些上限不是承载量测量。

## 安装与升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
xboard-rust update --version v0.1.0-preview.12
```

Linux AMD64/ARM64 静态 musl 包、一键管理脚本、SHA256SUMS、第三方许可及分架构互通/安装/systemd 报告随发行版提供。原服务不会自动迁移；接入、YAML 导入和多节点见 [安装指南](docs/INSTALL_ZH.md)。

## 验证范围

发行流程检查准确源码的普通回归与严格 lint、固定版本官方 sing-box/Xray、35 节点实际生产入口的 TCP/UDP 与计数，以及真实 Linux 安装/启停/升级/回退；这些门在最终 tag [Actions 37154037856](https://github.com/kejixiaoqi666/xboard-node-rust/actions/runs/37154037856) 全部通过，AMD64/ARM64 的 systemd 报告各含 88 个案例。真实 Flash 计费使用隐藏节点与专用用户通过，分别核对原始载荷和面板倍率后的用户流量、在线记录、正常停止和重启不重放；该业务证据绑定前一份候选构建，最终 tag 另行通过精确停止路径验收。具体范围与最终 SHA 见 [验证入口](docs/VALIDATION_ZH.md)。

## 明确边界

不宣称完整上游字段兼容、公网最大承载量、长期生产稳定性、吞吐提升或抗探测效果。HTTP-01 使用本地 Pebble；Cloudflare DNS-01 使用本地 mock，未据此声称生产 DNS/公共 CA 已验收。

面板没有通用批次去重时，HTTP 结果未知的流量批次需人工对账；周期存档后的强杀/断电尾部仍可能丢失。重启要重新拉取面板配置。旧 VMess AlterID、二进制 SRS、远程规则集下载、gRPC multiMode 和 Brutal 等未支持设置明确拒绝。

English: This preview adds VMess, AnyTLS, Hysteria2, TUIC, broader Shadowsocks support, transports/multiplexing, routing and encrypted DNS, proxy chains, a single-process fleet, machine discovery, observations, YAML import and certificate integration. The default server and controller are Rust. The exact-source official-client, actual Linux fleet, installer and service gates passed for final tag `ef0355843693c3e4738d028c8af7ab5c0f0228ce` in Actions 37154037856. Hidden Flash billing passed on the preceding isolated candidate build; see the linked validation record for the exact commit and SHA scope. Production DNS/public CA, full upstream parity, WAN capacity and long-term stability are not claimed; unknown acknowledgements and unsaved crash-tail boundaries remain explicit.
