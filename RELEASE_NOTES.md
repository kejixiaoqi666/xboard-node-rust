# Xboard Node Rust v0.1.0-preview.4

增加 **VLESS Vision TCP + 文件 TLS 1.3**，保持现有 Rust 控制/数据层、路由、DNS、SOCKS5 TCP、UDP、共享限速、来源 IP 名额、持久计数及一键安装管理。

## 本版变化

- 面板 `flow=xtls-rprx-vision` 映射到用户认证；缺失/错误 flow、未知 addons、明文 Vision、Vision UDP 明确拒绝。
- Rust 填充/去填充、内层 TLS 1.3 双向 DIRECT 切换；普通 TCP 和 TLS 1.2 保留外层 TLS。TLS 记录边界隔离，防止预读吞掉直通数据。
- 独立审查后修复类 TLS 尾部被扣留、close_notify 等待 TCP FIN、HRR 阻止最终 TLS1.3 检测等问题，保留针对性回归。
- 保持既有的有效载荷计数和共享限速。HTTPS 有效载荷包含内层 TLS 记录，排除 Vision 填充和外层 TLS 开销；不是文件明文大小。
- 双架构实际安装验收使用固定官方 Xray v26.3.27 客户端：普通 TCP、内层 TLS1.3 双向 DIRECT、TLS1.2、线上字节捕获证明的 HRR、缺 flow/错 UUID 不连接目标。客户端仅用于测试，不随服务器交付。
- Vision 模块窄提取自 MIT 许可的 cfal/shoes，保留确切来源提交、文件摘要和原许可；未引入完整 shoes 服务或自定义 TLS 加密实现。

## 安装与升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
# 已安装：
xboard-rust update
```

Linux AMD64/ARM64 静态 musl 包、SHA-256、构建元数据、精确第三方许可和安装/systemd 测试报告随附件提供。Vision 字段示例、客户端要求及路由/DNS 见[中文首页](https://github.com/kejixiaoqi666/xboard-node-rust)与[English README](https://github.com/kejixiaoqi666/xboard-node-rust/blob/main/README.en.md)。

## 当前边界

仍是预览版。REALITY、Vision UDP、mux/XUDP、其他协议/传输、GeoIP/GeoSite/规则集、加密 DNS、其他代理出站/代理链/SOCKS5 UDP、单进程多节点、在线 IP 上报、自动 ACME 和原 Go YAML 导入仍待迁移。DIRECT 使用有界 Tokio 复制，不宣称内核 splice/零拷贝、最大承载或更低 CPU 的性能结果。

回退 preview.3 或更早版本前，去掉面板和客户端 Vision flow；回退 preview.1/2 还须移除新版路由/DNS/出站并采用旧版支持的限制。程序升级/回退保留当前流量状态，不撤销计费。未落盘强杀尾部、未知上报对账和真实面板计费仍有既有边界；回环测试不代表公网最大吞吐或长期生产稳定性。

English: Adds native VLESS Vision TCP over file TLS 1.3: padding/unpadding, bidirectional inner-TLS-1.3 direct switching, ordinary TCP/TLS1.2 compatibility, strict flow enforcement, and preserved routing/shared limits/durable payload counters. Pinned official Xray client acceptance exercises installed AMD64/ARM64 Rust servers, real HRR and authorization negatives. The server does not require Xray. REALITY, Vision UDP, full upstream parity, production billing reconciliation, zero-copy and performance improvements remain unclaimed.
