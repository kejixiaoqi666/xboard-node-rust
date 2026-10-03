# Native SIP003 / WS plugin 只读审查

记录时间：2026-10-03 UTC。审查范围是主集成的 `node-native/src/plugin.rs`、`lib.rs`、`config.rs`，连同必要的 control、SS UDP owner 和 extended mux helper。没有改动被审查生产实现，没有把静态推导当作 Unix 实跑。

## P1-01：插件启动期间未响应停止，失败路径没有显式 join UDP

位置：`crates/node-native/src/lib.rs:339`、`:363`；`crates/node-native/src/plugin.rs:11`、`:55`。

`serve_udp` 在 `Process::start(...).await?` 前已经启动公共 UDP listener。`Process::start` 的 readiness 最长等待 15 秒，仅观察 child exit 和 public TCP，没有读取 `external_stop`；节点停止 future 在此之后才建立。一个仍存活但迟迟未 bind public TCP 的插件会让启动中的节点忽略停止，直到 readiness 成功或 15 秒超时。

若插件 spawn/readiness 失败，`?` 直接退出 `serve`。SS UDP owner 的 Drop 仅 abort，没有 await；公共 UDP 可能已处理经过认证的 payload，而正常 `udp.shutdown().await` 与最终 `traffic.checkpoint(true)` 都位于主循环后的清理，启动失败时不会执行。这里缺少停止/启动回滚的确定性 worker 与计费 barrier。

建议：让 startup 在持有 Process owner 的内部响应节点 watch，取消时 stop + wait 子进程；把 UDP 开始接收推迟到插件 readiness 成功之后，或在每个启动错误分支显式 shutdown + join 已启动 UDP、保存已发生流量后再返回。不要简单 drop 一段正在启动子进程的 future 来代替 wait。

建议验收：增加“child 存活但不绑定 public port，在收到 stop 后有界返回”的 Unix case；启动失败返回之后立即检查 private/public TCP、raw UDP、control socket 均释放。现有 pre-ready exit case 覆盖部分回滚，但不覆盖停止中的 readiness。

## P1-02：外层连接直接 abort 会跳过 mux 子 worker 的 join

位置：`crates/node-native/src/lib.rs:428`、`:500`。必要证明源为 `crates/node-extended/src/mux/xudp/mod.rs` 的 `serve_plugin_mux`：只有函数收到取消并走退出逻辑，才执行 `jobs.abort_all()` 后逐个 `join_next().await`。

quiesce 与最终 stop 都先发送 `protocol_stop_tx=true`，紧接着 `connections.abort_all()` 并等待外层 JoinSet。直接 abort 会 drop `serve_plugin_mux`、H2/AnyTLS 等嵌套协议 future，跳过其显式 join。内层 JoinSet 的 Drop 能发出 abort，不能同步等待这些已 spawn 的 worker 完成；仅等待外层连接完成不能证明嵌套 payload writer 已退场。随后执行 final checkpoint 的路径因此缺少确定的无 writer barrier。

建议：先通知协议停止，让有子 worker 的协议 future 在有界 grace 内完成自己的 cancel + join，再等待外层连接。对超过 grace 的连接单独处理，确保有子任务的入口仍能收回并 join 它们；不要把 outer JoinSet 的完成当作 nested JoinSet 已完成。

建议验收：在实际 WS plugin mux/H2/AnyTLS carrier 中保留活动逻辑流，发 node stop；native 返回前检查逻辑 handler Drop、active lease、listener shared budget 已归零/归还，随后读取 durable quiesced snapshot，确认返回后不再发生 payload 写入或 counter 更新。

## 未发现 P0/P1 的接线

- WS 解帧后进入 `serve_plugin_mux`；每个逻辑 stream 的 handler 再调用原生 SS 解密、认证和计费，外层 WS/mux 头没有进入业务计数器。mux=0 直接进入同一 SS decoder。UDP 是公共原生 SS UDP socket，未声称 UDP over WS。
- 原生 WS 的 Context.source 取自真实 accepted TCP peer，handler 逐层保留该值。外部 SIP003 的 peer 是 private loopback，因此 config 对每个用户明确要求 `device_limit==0`；热 replace 重新 decode 全配置，也不会绕过这一约束。
- 外部插件只允许 SS，且与 builtin transport/TLS 互斥；plugin_mux 只允许 SS+WS。transport + REALITY/Vision 不支持的组合明确拒绝。
- 插件 binary 要求绝对普通文件，argument/options 有长度和 NUL 边界；命令不经 shell/PATH 解析，敏感 options/arguments 的 Debug 被遮蔽。子进程设置 private Unix process group；正常 stop 先 TERM，再在 2 秒后 KILL + wait，公共/private endpoint 按 SIP003 区分。
- 完整认证 profile 来自完成 SS 解密的原 Snapshot；当前 identity 与 auth watch 由 native 路径重新检查，换凭据不会按相同 ID 误绑定到新密码。

## 审查源码 SHA256

这些 SHA 绑定上述静态 findings。后续主集成修改后需要复查，不宣称对后来的源码继续成立。

| 文件 | SHA256 |
|---|---|
| `crates/node-native/src/plugin.rs` | `3f65752d2ad37c4a3c84290eb111a2dae173e9732c11c5024a33e5f31f877d19` |
| `crates/node-native/src/lib.rs` | `56d4f1b1084b7881908ccd7071892d1f948229af01f1b658e12bed675dd7c8af` |
| `crates/node-native/src/config.rs` | `adc165ec4bdcf285501e91842132ccaef5366f6257f0d3670f2977b60143c444` |
| `crates/node-native/src/control.rs` | `88ce98458ab0978972f5a2fe9e90f3471a7df59a791154de58f5df07e413fb34` |
| `crates/node-native/src/shadowsocks/udp.rs` | `298d3fa1f2216a27bd9b08f7a6f81c0ad7850ebffc7907301b45a255ee2f2e8c` |
| `crates/node-extended/src/mux/xudp/mod.rs` | `da4ff9d06098636af75275b003fe9253c12a63b2a85f227de315270e4131a61a` |
| `crates/node-extended/src/sip003.rs` | `a33b59eba07b2486ef16c320155c8d003e00e61752c352e04e498cb6feebf5ed` |

Unix 实际 SIP003 三个业务 case 和四个官方配置入口 case 仍由主集成/CI 执行。此审查没有新增编译，没有改写第一/二阶段 scoped Windows 通过记录。
