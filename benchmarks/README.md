# 性能基线

此目录用于保存 Go 参考实现与 Rust 实现的同条件基准，不保存生产凭据、真实用户数据或真实面板 Token。

## 必测指标

- 常驻 RSS；
- CPU 使用率；
- 堆分配次数和字节数；
- 活跃连接数；
- 目标吞吐；
- P50/P95/P99 延迟；
- WebSocket 重连次数；
- 面板报告延迟和失败率；
- 配置热更新成功/回滚次数。

## 比较规则

先建立 Go 基线，再运行 Rust。协议、内核、用户数、连接数、吞吐、日志级别、运行时间和资源限制必须一致。测试结果必须保存命令、commit、环境和原始输出；单次结果不得作为发布依据。

## 本轮 Rust 优化前后比较

2026-10-02 的测试比较同一 Rust 单节点程序的优化前后版本，尚不是 Go/Rust 差分。结果见 [性能与稳定性记录](../docs/RUST_PERFORMANCE_ZH.md)。保留旧二进制和旧源码包，不通过 reset/stash 改写工作树建立基线。

### 无变化同步的堆分配

```bash
cargo bench -p node-runtime --bench cached_poll --locked -- 1 100
cargo bench -p node-runtime --bench cached_poll --locked -- 10000 100
```

同一份 `cached_poll.rs` 在优化前后各测三次。第一次应用和缓存预热不计入测量，100 次配置/用户双 304 返回均需 `Unchanged`。使用计数分配器；输出累计分配次数、累计字节与平均耗时。计数包含同进程的回环 HTTP 夹具，它仍会复制响应数据，不能把累计分配字节当作常驻内存，也不能用该测试证明协议吞吐。

### 可执行程序、实际资源与 TCP

`runtime_lab.py` 仅用于 Linux `/proc` 环境。需提供实验控制程序、相同的 sing-box、已有且匹配域名的有效证书，以及全新的输出目录；不会下载内核、复制证书或修改系统服务。

```bash
python3 benchmarks/runtime_lab.py \
  --baseline /absolute/path/old-xboard-node-rust \
  --optimized /absolute/path/new-xboard-node-rust \
  --singbox /absolute/path/sing-box \
  --domain lab.example.com \
  --certificate-dir /absolute/path/existing-certificate \
  --output /absolute/path/new-lab-result \
  --sample-seconds 12 --trials 3 --wss
```

- 使用合成认证与用户数据、回环 HTTPS 面板和真实 VLESS 客户端；证书校验正常开启。
- 1 和 10000 个用户各测三组，交替运行优化前后程序；每组预热后采样 12 秒，轮询间隔 1 秒。
- 分别记录控制程序与协议内核的 RSS、线程及 CPU ticks。CPU 按一颗核计算；低于 tick 分辨率的样本不能解释为真正零消耗。
- 第一组各保持 256 条真实代理连接 3 秒，逐条核对 HTTP 内容。随后以并发 8、32 个 256 KiB 请求测三轮传输；回环结果受 Python 夹具和共享宿主负载影响。
- 优化版执行面板请求中途内核退出/恢复和 HTTPS 请求卡住时 SIGTERM；使用真实业务成功判断恢复，不以发现新 PID 代替就绪。
- `--wss` 增加有效 TLS 的真实 WSS 推送、其他节点过滤、32 次大用户提示、REST 权威用户替换、强制断线重连和关闭清理。只在程序自己的 mount namespace 中绑定 hosts 映射，需具备 Linux mount/unshare 权限；结束后核对全局 hosts 哈希。
- 每个测试程序使用自己的 session/process group；失败时对本次进程组有界 TERM/KILL，不操作其他节点。

`result.json` 的整体 `PASS` 才表示全部所选步骤完成。部分 case 输出、监听存在或一次转发成功均不能替代整体结果。256 条连接通过只能证明该档位；无法给出最大并发、公网速率、长期稳定性或生产面板兼容性。
