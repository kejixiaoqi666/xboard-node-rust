# Xboard Node Rust v0.1.0-preview.17

这一版延续 preview.16 的协议、传输、路由、DNS、fleet、证书和持久流量队列能力，重点补齐节点侧在线状态和流量审计的可解释性。默认控制层和协议服务端均为 Rust，不需要 Go、Xray 或外部 sing-box 服务端。

## 新增与补齐

- **在线审计**：区分逻辑会话数、活跃用户数、全局去重源 IP、用户/IP 关系数和跨用户复用出口证据。
- **多节点新鲜度**：fleet 健康接口在 `node_activity` 下保留每个节点的审计结果，并在 `node_activity_sample_unix` 记录最后一次有效采样时间。
- **样本校验**：拒绝同一用户重复源 IP，标准化 IPv4-mapped IPv6；非法样本不会发往 Xboard，也不会覆盖上一份有效审计。
- **流量结果审计**：按 `[上传, 下载]` 方向累计 `collected`、`acknowledged`、`uncertain` 和 `not_sent` 字节，并记录最后批次 ID 与结果。
- **ACK 失败证据**：流量持久落盘后，即使内核 ACK 失败，已采集字节仍会保留在本地审计和 outbox 中，不会伪装成已确认计费。
- **协议兼容**：保持 Xboard 原有 `alive`、`online` 和 `traffic` 字段，不要求面板立即理解新的本地 `/metrics` 审计字段。

## 安装与升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
xboard-rust update --version v0.1.0-preview.17
```

Linux AMD64/ARM64 静态 musl 包、一键管理脚本、SHA256SUMS、第三方许可及分架构互通/安装/systemd 报告随发行版提供。原服务不会自动迁移；接入、YAML 导入和多节点见 [安装指南](docs/INSTALL_ZH.md)。

## 验证范围

本版本地通过 workspace 测试、严格 Clippy、release 构建、格式和差异检查；GitHub Actions 对 AMD64/ARM64 通过源码回归、官方 sing-box/Xray 互通、静态构建、安装器和 systemd 生命周期。真实 Flash 计费仍引用 preview.12 的独立隐藏节点证据，未把本版发布门禁误写成新的面板业务验收。具体范围与 SHA 见 [验证入口](docs/VALIDATION_ZH.md)。

## 明确边界

不宣称完整上游字段兼容、公网最大承载量、长期生产稳定性、吞吐提升或抗探测效果。面板没有通用批次去重时，HTTP 结果未知的流量批次仍需人工对账；周期存档后的强杀/断电尾部仍可能丢失。生产 DNS、公共 CA、真实面板最终计费和多 VPS 面板侧全局负载仍需独立验收。

English: Preview.17 keeps the preview.16 protocol and operations surface and adds precise node-side activity audits, per-node sample freshness, directional traffic outcome counters and durable evidence when a kernel acknowledgement fails. The Xboard `alive`, `online` and `traffic` fields remain compatible. AMD64/ARM64 source, client, installer and service gates passed in the tag workflow. Full upstream parity, final panel billing, WAN capacity, production DNS/CA and long-term stability remain outside this release claim.
