# Xboard Node Rust v0.1.0-preview.7

补上 **普通 VLESS REALITY UDP** 和 **多记录 ClientHello 认证**。TCP/Vision、文件 TLS、共享限制、路由/DNS、持久流量统计、一键安装与管理继续保留。

## 本版变化

- 普通 VLESS 的 UDP 使用既有认证、路由、限速、来源 IP 名额和计数。两端移除 flow、关闭 mux/XUDP；Vision UDP 和 mux/XUDP 仍明确拒绝。固定官方 Xray v26.3.27 验收使用 `XRAY_CONE_DISABLED=true`，避免默认 cone 转成 XUDP。
- ClientHello 可分在最多 16 个 TLS 记录，握手消息最多 16 KiB；重组消息用于认证与 TLS transcript，固定站点收到原始记录边界。握手仍受 10 秒总时限控制；单记录共享缓冲路径避免新增重组拷贝，不宣称整体性能提升。
- 官方客户端 ClientHello 被实际拆成六个记录，重复普通 TCP、TLS1.2/1.3、双向 DIRECT、真实内层 HRR、缺 flow/错 UUID/短 ID 拒绝和不带 Vision 的矩阵。
- AMD64/ARM64 实际安装的 Rust ELF 验证 UDP IPv4/域名/IPv6、1/37/8000 字节、错误 UUID、阻断路由、Vision 用户拒绝普通 UDP、活跃关联停服与重连。双向有效载荷各 24188 字节，与模拟面板已确认报告与本地待报队列精确对账，TLS/VLESS/SOCKS 封装和拒绝包不计入。
- 每架构 18 个安装器和 57 个实际 systemd 案例，保留实际 preview.1 二进制升级及双向回退、配置与原生计数身份校验。服务端保持全 Rust，官方 Xray 仅为测试客户端。

## 安装与升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
# 已安装：
xboard-rust update --version v0.1.0-preview.7
```

提供 AMD64/ARM64 静态 Linux 包、SHA256SUMS、确切源码来源、第三方许可、安装/systemd JSON 报告。详见[中文首页](https://github.com/kejixiaoqi666/xboard-node-rust)和[English README](https://github.com/kejixiaoqi666/xboard-node-rust/blob/main/README.en.md)。

## 当前边界

仍是预览版。REALITY 外层需要 TLS1.3/X25519 固定站点和非 HRR ServerHello；KeyUpdate/PQ/外层 HRR、Vision UDP、mux/XUDP、其他协议/传输、规则集、加密 DNS、其他代理出站/代理链、SOCKS5 UDP、多节点、在线 IP 上报、ACME、原 Go YAML 导入尚未迁完。

官方 SOCKS 客户端丢弃空包且使用8192字节缓冲，本轮不声称 REALITY 空包/65507字节极限已验证；保留的空包/最大包回归是文件 TLS。认证前固定站点转发不走用户 SOCKS5 路由、不算用户代理流量。DIRECT 仍用有界 Tokio 复制。未证明零拷贝、低 CPU、抗探测、公网最大承载、真实面板计费或长期生产稳定性。周期落盘不保证强杀/断电尾部零丢失。

回退 preview.6 前停止 REALITY UDP/多记录 ClientHello；回退 preview.5 或更早还须改为旧版支持的 TLS/VLESS；preview.3 或更早移除 Vision flow，preview.1/2 移除新 DNS/路由/出站配置。升级/回退保留当前流量状态，不撤销计费。

English: Adds ordinary VLESS REALITY UDP without Vision/mux/XUDP and bounded multi-record ClientHello authentication, preserving the mirror's original wire. Official-client installed AMD64/ARM64 tests cover six-record TCP/Vision/DIRECT/inner-HRR, UDP IPv4/domain/IPv6, negative identity/flow/routes, active shutdown/reconnection and exact 24188-byte payload counters per direction. Each architecture includes 18 installer and 57 systemd cases. Zero/maximum REALITY datagrams, full protocol parity, outer KeyUpdate/PQ/HRR, zero-copy, WAN capacity and production billing/stability are not claimed.
