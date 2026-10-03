# Xboard Node Rust v0.1.0-preview.9

补上 **REALITY 外层服务端自动密钥轮换**：长连接持续传输时，服务端按加密记录数量换用下一代发送密钥，客户端收到更新后继续传输。保留 preview.8 客户端 KeyUpdate 应答、普通 REALITY UDP、多记录 ClientHello、Vision TCP、路由/DNS、限制和持久计数。

## 本版变化

- 默认每代发送密钥最多 1,048,576 个非 KeyUpdate 记录；`tls_settings.key_update_after_records` 支持整数 16–1,048,576，0 和超界配置拒绝。更新消息另占一个旧密钥记录。
- 单次写入跨阈值也按记录切开，已加密数据、旧密钥更新消息、新密钥数据保持顺序；部分写入和背压不会重复发送。关闭通知同样遵守预算，与客户端请求应答合并处理。
- 主动消息使用 `update_not_requested`，不强制客户端同时轮换发送密钥；两个方向独立。空闲连接无定时器，只在下一次数据/关闭通知需要发送时触发。Vision 切入 DIRECT 后不再走这一外层记录路径。
- 三密码套件、默认/低阈值、大写入、反复轮换、半关闭、部分写入、异步背压、WriteZero、配置映射和非法值回归。
- 每架构 18 个安装器、60 个实际 systemd 案例。新增阈值 16、未经修改的官方 Xray v26.3.27 客户端：测试旁路只观察、原样转发密文，验证至少三次服务端主动更新、每代记录预算及双向各 262,240 字节完整回传。保留上版三次 peer 更新注入、两次应答、五记录分片、非法更新拒绝及 UDP/Vision 回归。
- 服务端全 Rust，未增加运行时依赖；官方 Xray 与 Python cryptography 仅用于测试。临时测试密钥不进入发行包或报告。

## 安装与升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
xboard-rust update --version v0.1.0-preview.9
```

附 AMD64/ARM64 静态 Linux 包、校验、源码来源和许可、安装/systemd 报告。详见[中文首页](https://github.com/kejixiaoqi666/xboard-node-rust)及[English README](https://github.com/kejixiaoqi666/xboard-node-rust/blob/main/README.en.md)。

## 当前边界

仍是预览版。REALITY 外层 PQ/HRR、Vision UDP、mux/XUDP、其他协议/传输、规则集、加密 DNS、其他代理出站/代理链、SOCKS5 UDP、多节点、在线 IP 上报、ACME、原 Go YAML 导入尚未迁完。固定站点仍需 TLS1.3/X25519 和非 HRR ServerHello。

REALITY 空包/65,507 字节极限、公网最大承载、真实面板计费及长期生产稳定性尚未验证；本轮不宣称吞吐、CPU/内存改善或抗探测能力。周期存档仍有强杀/断电尾部丢失窗口。

回退 preview.8 或更早版本前删除 `key_update_after_records` 字段；旧程序拒绝未知字段。回退 preview.7 还需避免客户端 KeyUpdate，preview.6 还需避免 REALITY UDP/多记录 ClientHello。升级/回退保留当前流量状态，不撤销计费。

English: Adds server-initiated outer REALITY TLS 1.3 write-key rotation by a bounded record budget, default 1,048,576 and configurable from 16 to 1,048,576. Large batches split at the boundary; pending ciphertext, old-key KeyUpdate and new-key data/close remain ordered under partial writes and backpressure. No idle timer or forced peer write-key change. Installed AMD64/ARM64 tests forward ciphertext unchanged to an unmodified official Xray client, observe at least three automatic updates and echo 262,240 equal payload bytes per direction. Retains peer-update, UDP and Vision regressions; 18 installer and 60 systemd cases per architecture. Vision DIRECT bypasses this outer record path. Remove the new configuration field before downgrading. PQ/outer HRR, full parity, production billing, WAN capacity and performance guarantees remain outside this release.
