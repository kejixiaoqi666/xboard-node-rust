# Xboard Node Rust v0.1.0-preview.2

在首个独立 Rust 预览版上补齐 UDP、用户共享限速和来源 IP 名额，继续沿用一键安装和 systemd 管理。

## 本版内容

- VLESS/Trojan TCP 与协议内 UDP；IPv4、IPv6、系统域名解析、文件 TLS。Trojan UDP 支持一个关联访问多个目标，VLESS UDP 使用固定目标。
- 用户 `speed_limit` 以十进制 Mbps 设置；所有连接的上传加下载共用预算，重连不刷新额度。0 表示不限速，突发额度为一秒、最小 64 KiB。
- `device_limit` 限制本节点每个用户同时活跃的不同来源 IP；同 IP 多连接共用名额，最后一条连接结束时释放。它不识别物理设备，也不是跨节点计数。
- 用户政策热更新：已有连接采用新限速；降低 IP 名额时保留已有连接，拒绝超额新来源。删除后的迟到握手不会覆盖已有会话最后观察到的限制。
- 修复异步 TLS 发送背压下尾部数据可能滞留的问题，使用真实 Rustls 流与 512 字节传输缓冲区作 TCP/UDP 回归。
- Xboard 单节点 REST 同步、WS 重同步提示、原子用户更新、候选配置校验和数据层恢复。
- 有效载荷计数、原生持久快照/采集回执、有界存储工作及持久待报队列。
- Linux AMD64/ARM64 静态 musl 包，发行与包内文件 SHA-256、构建元数据、源码绑定及第三方许可说明。
- 交互菜单、安装/配置/升级/程序回退、systemd 启停/状态/日志、停机队列查看和保留数据的卸载。
- 两架构实际安装与 systemd 测试：TCP/TLS/UDP 回显、域名/IPv6、空包及 65,507 字节大包、双连接双向共享限速、IP 名额及热更新，另用已公开 preview.1 实际程序验证升级和双向回退。报告与计时 JSON 随附件提供。

安装：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
```

## 当前边界

这是预览版，尚未迁完 REALITY/Vision、mux/XUDP、其他协议和传输、完整路由/DNS、单进程多节点、在线 IP 面板上报和自动 ACME。UDP 每个关联最多 64 个目标，全节点最多 1,024 个 UDP 关联，无成功载荷活动 60 秒后释放；这些上限不是已测承载能力。Rust JSON 与原 Go YAML 不直接互换。未落盘强杀尾部、未知上报对账和实际面板计费仍有明确边界。升级/回退保留当前流量状态，不回滚计费。回退 preview.1 前，面板需使用旧版支持的配置（含零限速和零设备限制）。

English: This preview adds VLESS/Trojan UDP, aggregate per-user rate budgets, active source-IP admission and live policy changes. Real TLS backpressure regressions prevent buffered response tails from stalling. Linux AMD64/ARM64 assets include installer/service tests and timing measurements, including upgrade/rollback with the actual preview.1 binary. IP admission counts source IPs on this node, not physical devices or cross-node totals. REALITY/Vision, mux and other protocols, full routing/DNS, multinode and ACME remain in progress. Production billing reconciliation, WAN capacity and long-term stability are not claimed. See [English README](https://github.com/kejixiaoqi666/xboard-node-rust/blob/main/README.en.md) for details.
