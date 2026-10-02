# Rust 原生协议数据层

本文记录前一轮 rn3 的冻结协议验证结果。preview.2 已增加 UDP、共享限速和来源 IP 限制，当前支持范围与发行测试见 [项目首页](../README.md)；流量语义见 [流量统计与持久队列](RUST_TRAFFIC_ZH.md)。下文 rn3 的范围、二进制哈希与资源数字仅属于该历史片段。

本片段把此前仍由 Go 执行的已支持协议数据层迁入 Rust workspace，新增 `crates/node-native`。控制层、协议解析、认证、TLS 和 TCP 转发都由同一份 `xboard-node-rust` 二进制执行；默认配置无需 sing-box、xray 或 `xbord-native-users` 服务端。仍以控制/数据两个 Rust 进程隔离故障，用户只需提供一个程序文件。

最终 rn3 版本已在 Windows 通过 87 项、Linux ARM64 通过 93 项 workspace release 测试，fmt 与严格 clippy 通过。内置 Rust 数据层的真实客户端、用户更新、TLS、四类控制故障、生命周期及 FD 耗尽验证通过。执行输入绑定 54 文件清单，SHA-256 为 `b016fea6175279bf66303ae3ccabadd5f416ea6953e463370acb22e71094a1c1`；当前二进制为 4,069,304 字节，SHA-256 为 `e89a4fdbe80575551b8d4900f8affa283a63c0f8f3d78db5b4a7af2f9ec66665`。

## 范围与实现

- VLESS TCP：版本 0、16 字节 UUID 认证、IPv4/IPv6/域名地址、直接出站；非空 addons、UDP、mux、Vision 尚未支持，明确拒绝。
- Trojan TCP：SHA-224 密码摘要认证、CRLF 边界、IPv4/IPv6/域名地址、直接出站；要求文件 TLS，UDP/fallback 尚未接入。
- TLS：Rustls 加载文件证书及私钥，按同一 Rust 数据层处理连接；客户端验收需验证证书链与主机名。
- 用户快照：完整校验重复身份/凭据后 ArcSwap 一次发布。认证后保留用户字符串身份，重排和删除不把旧连接变成其他用户；删除后拒绝新认证，已有连接可继续。
- TCP 转发：Tokio 双向异步拷贝，保留半关闭语义和数据背压；TLS/协议握手及目标连接有超时。JoinSet 同时约束活跃连接和未回收的完成条目，最多 16,384；每轮分批回收。这只是资源保护上限，不是已证明的承载能力。TCP/Unix 监听的临时受理错误会异步退避，已有转发及关停仍能继续。
- 用户控制：复用私有 framed JSON 协议、SHA-256 事务及缺失确认后的摘要核实。服务端串行操作，整个控制请求两秒超时，不在原子用户发布与摘要提交之间 await。
- 生命周期：控制任务先停止，再回收连接任务。监听/TLS/协议变更仍走完整重启；不确定状态从上次成功快照恢复。

协议解析独立按公开格式实现。Trojan 数据结构来源为 [官方协议说明](https://trojan-gfw.github.io/trojan/protocol)，VLESS 格式与 [Xray-core 编码定义](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go) 对照。新增 Rust crate 不编译或链接先前 Go 内核。Rustls/ring 等基础依赖沿用 Rust 生态库，不要求 Go 工具链；项目实现为 Rust，不宣称操作系统或所有密码学底层均由 Rust 编写。

## 使用

```bash
cargo build -p node-runtime --release --locked
./target/release/xboard-node-rust --config examples/runtime-rust.json --check
read -rsp 'Panel token: ' XBORD_PANEL_TOKEN
printf '\n'
export XBORD_PANEL_TOKEN
./target/release/xboard-node-rust --config examples/runtime-rust.json
```

先修改 HTTPS 面板、machine/node ID、Token 环境变量名称及独立短状态目录。`--check` 只校验运行设置，不证明面板或协议可用。

默认不填写 `singbox_executable`，控制程序自动以自己的绝对路径启动 Rust `run`/`check` 子模式，并启用用户原生更新。这个字段只为旧外部内核方式保留；明确填写时才使用指定外部程序。旧官方内核例子另在 `examples/runtime-rust-external.json`，不再是默认路线。

完整默认运行目前要求 Unix，实际目标为 Linux ARM64；Windows 可编译控制程序和原生协议模块并运行相关测试，但尚未实现该平台的原生控制 socket。原 Go 源码/安装入口及历史过渡包保留，不作为新 Rust 模式的运行依赖。

## 验证与后续

新增回归覆盖分片/coalesced 协议头、非法版本/命令/扩展、所有截断长度、域名/IPv6 类型、重复凭据、1000 次并发认证表替换、移除用户后旧认证身份、TCP 半关闭后返回响应，以及 Unix 控制帧/摘要/端口变更和 socket 权限。

Linux 验收使用官方 sing-box 1.14.0 作为测试客户端和旧模式对照；客户端不属于 Rust 节点运行依赖。每个原生夹具启动时确认配置不含外部二进制，并核对数据层与控制层是同一个 Rust ELF。最终 m2 的结果：

| 检查 | 结果 |
| --- | --- |
| VLESS / VLESS TLS / Trojan TLS | 各 64/64 既有连接响应完成，32 个保留用户和 32 个已移除用户的旧连接身份保留 |
| 跨更新传输 | 各 2 MiB 数据与预期逐字节相同，跨首个实际观察的认证发布点 |
| 用户变更 | 新凭据可用、旧凭据的新连接被拒绝、保留凭据可用；用户排序变化不重启 |
| TLS | 正确证书链/主机名可访问，错误主机名拒绝 |
| 控制故障 | 丢确认、拒绝、未知状态、卡住四类通过；丢确认和未知状态均先确认真实操作已执行 |
| TCP / 生命周期 | 256 条连接保持 10 秒并完成响应；1,024 次 256 KiB 请求、并发 8，正文全部一致；崩溃恢复、监听变更、卡住面板时退出与回收通过 |
| FD 资源耗尽 | 仅新 Rust 子进程设为 64FD，两轮达到 64；已有两条连接回显一致，排队 Unix status 在释放后返回，新认证恢复，FD 回到 11；第二轮排队控制请求时 SIGTERM 退出约 4ms 且 socket 清理 |

一万用户、30 秒同步空闲窗口中，控制层 RSS 中位数为 7,052 KiB（约 6.89 MiB），Rust 数据层为 4,548 KiB（约 4.44 MiB），分别 2/1 个线程。控制层记录 0.03 秒 CPU，数据层 0 个 CPU tick；100Hz 计时粒度及短观察不能解释为真实 CPU 使用量为零。一万/两万用户 6 次更新期间，控制层 VmHWM 13,568 KiB，进程组采样 RSS 峰值 32,480 KiB。

对照的全功能官方服务端同窗口 RSS 57,180 KiB，更新组采样峰值 166,604 KiB；功能范围不同，不能用这个数字证明完整 Go/Rust 节点的优劣。组 RSS 包含共享页和临时检查进程，采样方式是扫描 `/proc` 后休眠 10ms，不是固定 10ms 采样，也不保证捕获所有瞬时峰值。`cycles.committed` 为客户端业务验证完成时间，非内部事务提交时刻；2 MiB 只验证首个发布点重叠，不代表跨所有六次更新。

独立复审发现并修复了任务回收上限和 TCP/Unix 临时受理错误退出的问题；rn3 源码与测试脚本的静态复审无未解决 blocker/P1/P2。旧 rn1 m1 PASS 保留，但最终验收仅使用 rn3 m2 与 fd3。FD 实验由受控限制、已满 FD 计数及排队请求推断资源受理路径，未通过 syscall trace 捕获 errno；不证明系统 ENFILE、16K 实际承载或长期压力稳定性。

机器可读完整结果在 [rust-native-kernel-20261002.json](../benchmarks/results/rust-native-kernel-20261002.json)。Rust GNU 二进制需要 Linux ARM64、glibc 2.39+ 与 libgcc_s；原版安装脚本不自动切换到本程序。

新增 Rust 数据层遵循现有 MPL-2.0。之前独立的 Go 过渡内核及其 GPL 上游许可证保留为历史方案，不链接进此二进制。正式 Rust 全功能迁移仍未完成：计费/可靠上报、限速、设备/IP 控制、REALITY/其他协议、路由/DNS策略、多节点和持久恢复继续按清单推进。本片段将“现有支持范围的数据层”迁至 Rust，不等于已经达到原 Go 节点的全部能力。
