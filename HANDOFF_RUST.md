# 开发与交接入口

先读 [中文首页](README.md)、[安装指南](docs/INSTALL_ZH.md) 和 [验证入口](docs/VALIDATION_ZH.md)，再核对当前提交、工作区差异和对应版本的 Release 报告。历史 benchmark 只证明它们绑定的历史源码与二进制。

## 当前结构

默认服务端由一个 Rust 进程运行控制层与协议数据层。简单配置启动一个节点，fleet 可运行多个面板的固定节点，机器配置可发现、增加与移除节点。每个节点使用独立状态目录与流量队列，整个进程最多 64 个活动节点。

| 模块 | 职责 |
| --- | --- |
| node-core / node-panel | 配置与用户、面板 wire、REST/ETag/WS、严格业务 ACK 与观测上报 |
| node-kernel | 实际候选配置、预检查、内置任务或显式外部程序、热更新与失败恢复 |
| node-native / node-session | 协议入口、共享限制/计数/预算/取消、控制 socket 与持久快照 |
| node-vision / node-reality | Vision 与 REALITY 的 TLS/认证实现 |
| node-extended / node-quic | VMess/AnyTLS、传输与复用；Hysteria2/TUIC |
| node-outbound | 路由、规则数据、DNS、TCP/UDP 上游与代理链 |
| node-admin | 原 Go YAML 导入、私密引用、证书、日志与健康设置 |
| node-runtime | 单节点/fleet/机器入口、证书挂接、生命周期、持久上报与健康汇总 |

来源、许可和修改记录留在各模块内。默认路径不需要 Go、Xray 或外部 sing-box 服务端。外部 SIP003 插件是管理员明确配置的额外程序；官方客户端只用于测试，不随发行包附带。

## 验证和发行

```bash
cargo fmt -- --check
cargo test --workspace --locked -j 2 -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -j 2 -- -D warnings
```

发行工作流固定准确源码，在 Linux AMD64/ARM64 分别运行普通回归、严格检查、固定 SHA 官方客户端、静态 musl 构建、35 节点生产入口的 TCP/UDP 与计数检查，以及安装器和 systemd 生命周期。手动 QA 默认不创建 Release，标签流程在所有门通过后创建草稿。

发布前核对两架构包内 BUILDINFO 的 commit、源文件与实际 ELF SHA，再核对报告和公开下载。代码测试、模拟面板、真实 Flash 业务和公开文件校验分别记录。不要把 --check、systemd active 或 HTTP 200 当作计费验收。

`v0.1.0-preview.12` 最终 tag 已绑定提交 `ef0355843693c3e4738d028c8af7ab5c0f0228ce`，双架构发行门和安装器/systemd 报告见 [Actions 37154037856](https://github.com/kejixiaoqi666/xboard-node-rust/actions/runs/37154037856)。包内 `BUILDINFO.json`、`SHA256SUMS` 和三类安装/协议报告必须与同一提交配套使用。隐藏 Flash 真实计费也已用该最终 tag 的 AMD64 包复验通过：在线/IP/资源观测、TCP/UDP、倍率计费、正常停止和重启不重放均为 PASS。Flash 结果只证明隔离面板、实际 Rust embedded runtime 和回环 TCP/UDP 业务，不替代 WAN 容量或长期稳定性验收。

## 保留的边界

当前接口与协议范围见首页，不宣称全部上游字段兼容、公网最大承载量或长期生产稳定性。Cloudflare DNS-01 使用本地 mock，HTTP-01 使用本地 Pebble；它们不能替代生产 DNS/公共 CA 验收。

成功配置快照保存在内存中，进程重启需要重新拉取面板；计数、采集回执和上报队列独立持久保存。没有通用批次去重时，未知上报必须对账；周期存档仍有未保存的强杀/断电尾部窗口。回退程序保留当前计费状态，不回滚已上报流量。

公开仓库不携带本机账本、真实凭据、生产配置或测试客户端。接手者在自己的项目目录记录状态，并沿用当次授权确定远端对象。
