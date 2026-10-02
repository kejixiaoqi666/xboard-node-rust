# Xboard Node Rust v0.1.0-preview.3

本版继续补齐 Rust 原生网络能力：自定义路由、DNS 和 SOCKS5 TCP 上游。保留 preview.2 的 TCP/UDP、文件 TLS、共享限速、来源 IP 限制、持久流量统计及一键安装管理。

## 新增功能

- 按域名、域名后缀、IPv4/IPv6 CIDR、目标端口、TCP/UDP、来源 IP/端口匹配路由；支持直连、阻断及 SOCKS5 TCP（可用用户名/密码）。
- 支持面板 `routes`、`custom_route_rules` 和受限 `custom_routes`；结构化规则保留原版 OR 含义，原始规则支持组合条件，首条命中生效。
- 本地 `runtime.json` 可设置 DNS 服务器、UDP/TCP、TCP-only、静态 hosts、IPv4/IPv6 策略、超时和共享 TTL 缓存。
- DNS 结果先经过路由检查，实际连接使用同一个 IP；指定 DNS 失败时不回退系统 DNS，UDP 命中代理不会偷偷直连。
- 面板路由变化预检查通过后更换数据进程；错误配置保留原服务和路由。仅用户变化继续热更新。DNS 本地配置变化需重启服务。
- 新增真实安装后 DNS 缓存/过期、截断转 TCP、静态 hosts、NXDOMAIN、认证 SOCKS5、路由更新、错误候选保留、来源端口规则验证；继续运行旧版 TCP/TLS/UDP、流量、安装/升级/双向回退回归。

## 安装和升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
# 已安装：
xboard-rust update
```

Linux AMD64/ARM64 静态包、SHA-256、构建信息、精确依赖许可和安装/systemd 测试报告随附件提供。详细配置见 [中文首页](https://github.com/kejixiaoqi666/xboard-node-rust#路由与-dns-怎么用) 和 [English README](https://github.com/kejixiaoqi666/xboard-node-rust/blob/main/README.en.md)。

## 当前边界

仍是预览版。REALITY/Vision、mux/XUDP、其他协议和传输、GeoIP/GeoSite/正则/规则集、其他代理出站、SOCKS5 UDP、代理链、DoH/DoT、单进程多节点、在线 IP 上报和 ACME 尚未迁完。SOCKS5 服务器目前填写 IP；域名由本节点解析，SOCKS5 凭据需要可信链路。结构化规则任一匹配组生效；不默认加入私网阻断规则。Rust JSON 与原 Go YAML 不直接互换。

回退 preview.1/2 前，删除本版新增 DNS/路由/出站配置，并使用旧版支持的用户限制。升级/回退保留当前流量状态，不回滚计费。未落盘强杀尾部、未知上报对账和真实面板计费仍有原有边界；回环验证不代表公网最大吞吐或长期生产稳定性。

English: Adds native domain/IP/port/source routing, custom UDP/TCP DNS with shared TTL caching and hosts, and authenticated SOCKS5 TCP outbounds. The routed IP is pinned for I/O; unsupported UDP proxying fails without direct fallback. Invalid route candidates retain the old running child. Structured panel rules preserve upstream OR semantics. Tests exercise real installed Linux binaries, DNS fixtures, proxy forwarding and prior lifecycle/accounting behavior. Full protocol parity, encrypted DNS, production billing reconciliation, WAN capacity and long-term stability remain unclaimed. See the English README for exact configuration and bounds.
