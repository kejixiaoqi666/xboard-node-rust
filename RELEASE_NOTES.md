# Xboard Node Rust v0.1.0-preview.1

首个独立 Rust 节点预览版，延续 xbord-node-v3 的迁移工作，提供默认 Rust 控制层与协议数据层、一键安装及管理入口。

## 本版内容

- VLESS TCP、VLESS 文件 TLS、Trojan 文件 TLS；控制和协议进程使用同一份 Rust 可执行文件。
- Xboard 单节点 REST 同步、WS 重同步提示、原子用户更新、候选配置校验和数据层恢复。
- 有效载荷计数、原生持久快照/采集回执、有界存储工作及持久待报队列。
- Linux AMD64/ARM64 静态 musl 包，发行与包内文件 SHA-256、构建元数据、源码绑定及第三方许可说明。
- 交互菜单、安装/配置/升级/程序回退、systemd 启停/状态/日志、停机队列查看和保留数据的卸载。
- 安装器离线文件检查与全新 systemd 安装测试，包含真实 TCP/TLS 转发和启动失败回退；测试结果 JSON 随附件提供。

安装：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
```

## 当前边界

这是预览版，尚未迁完 REALITY/Vision、UDP、其他协议、限速/设备/IP、完整路由/DNS、单进程多节点和自动 ACME。Rust JSON 与原 Go YAML 不直接互换。未落盘强杀尾部、未知上报对账和实际面板计费仍有明确边界。升级/回退保留当前流量状态，不回滚计费。

English: First standalone Rust preview for Xboard nodes, with static Linux AMD64/ARM64 assets and an installer/service manager. VLESS/Trojan TCP and file TLS are supported. Full upstream feature parity, production billing reconciliation, WAN capacity and long-term stability are not claimed. See the bilingual README for supported features and limits.
