# Xboard Node Rust v0.1.0-preview.8

补上 **REALITY 外层客户端 KeyUpdate**。客户端更新会话密钥后可继续传输；请求双向更新时，Rust 服务端会先应答再使用新发送密钥。保留 preview.7 的普通 REALITY UDP、多记录 ClientHello、Vision TCP、路由/DNS、限制与持久计数。

## 本版变化

- 两个合法请求值均支持；收发流量密钥独立轮换，记录序号从零重新开始。应答由旧密钥加密，已加密待发数据保持原有顺序，后续数据使用新密钥。
- KeyUpdate 可跨记录分片，但总消息固定五字节并须在记录边界结束；非法长度/请求值、交错消息、旧密钥数据和未通知的密钥变更拒绝。
- 应答会在应用只读取时主动发送并 flush；发送或 flush 受阻时停止进一步读取，避免响应堆积。
- 三密码套件、HKDF 独立向量、反复轮换、碎片、发送顺序、半关闭、部分写入、背压和 WriteZero 回归。
- 每架构 18 个安装器、59 个实际 systemd 案例。新增官方 Xray v26.3.27 完成真实握手后，由回环测试记录适配器注入三次 KeyUpdate（其中一次分为五记录），核对两次请求应答和双向各 98,340 字节内容一致；非法请求在连接目标前拒绝。未声称未经修改的官方客户端会主动发出 KeyUpdate。
- 服务端保持全 Rust。官方 Xray 与 Python cryptography 仅测试使用，临时测试密钥不进入发行包或报告。

## 安装与升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
xboard-rust update --version v0.1.0-preview.8
```

附 AMD64/ARM64 静态 Linux 包、校验、源码来源和许可、安装/systemd 报告。详见[中文首页](https://github.com/kejixiaoqi666/xboard-node-rust)及[English README](https://github.com/kejixiaoqi666/xboard-node-rust/blob/main/README.en.md)。

## 当前边界

仍是预览版。尚不主动定时发起密钥更新；REALITY 外层 PQ/HRR、Vision UDP、mux/XUDP、其他协议/传输、规则集、加密 DNS、其他代理出站/代理链、SOCKS5 UDP、多节点、在线 IP 上报、ACME、原 Go YAML 导入尚未迁完。固定站点仍需 TLS1.3/X25519 和非 HRR ServerHello。

REALITY 空包/65,507 字节极限、公网最大承载、真实面板计费及长期生产稳定性尚未验证；本轮不宣称吞吐、CPU/内存改善或抗探测能力。周期存档仍有强杀/断电尾部丢失窗口。

回退 preview.7 需避免客户端 KeyUpdate；回退 preview.6 还需避免 REALITY UDP/多记录 ClientHello；更旧版本使用对应已支持配置。升级/回退保留当前流量状态，不撤销计费。

English: Adds peer-initiated outer REALITY TLS 1.3 KeyUpdate with independent directional secrets, reset sequences, bounded fragmentation and requested responses in the correct old/new-key order. Read-only applications flush responses and pause reads under backpressure. Installed AMD64/ARM64 tests use the official Xray handshake plus a loopback test record adapter, not an unmodified client initiating KeyUpdate: three updates, two responses, five-record fragmentation, 98,340 equal payload bytes per direction and invalid-update refusal before origin connect. Each architecture has 18 installer and 59 systemd cases. Proactive updates, PQ/outer HRR, Vision UDP/mux, full parity and production/performance guarantees remain outside this release.
