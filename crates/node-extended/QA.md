# node-extended 本地互通验收（2026-10-03，第一阶段冻结）

本 crate 提供经过认证后的 VMess AEAD、AnyTLS v2、WebSocket、H2MUX 和 XUDP 编解码；所有业务 payload 经过 `node-session::Host`。TLS/REALITY、监听器、路由、限速和持久化计费由调用方提供。

验证环境为 Windows Rust，使用独立临时 workspace，未修改共享 Cargo.lock。固定官方 sing-box v1.14.2 的二进制 SHA 在测试内再次校验，测试不会自行下载客户端。证据在 `tests/evidence/stage1/`；`verification.json` 记录冻结源文件 SHA256。后续源文件变化需要单独的新验收记录。

| 验证 | 结果 |
|---|---|
| `cargo clippy -p node-extended --all-targets -- -D warnings` | PASS |
| 默认 `cargo test -p node-extended` | 109 单元 + 12 payload/session 集成测试 PASS；官方客户端及微基准默认 ignored |
| 官方 sing-box 完整矩阵 | 14 场景 PASS |
| release 认证微基准 | 256 用户，10000 次无效认证；派生表构建 432µs，总计 13433µs，均值 1.34µs/扫描；仅为此机器本地测量 |

官方场景：VMess AES128GCM、ChaCha20Poly1305、none 各 TCP/UDP；两个 AEAD 套件的 global padding + authenticated length；VMess WebSocket；VMess H2MUX 无 padding/有 padding；VMess XUDP；AnyTLS v2 TLS + UoT；VLESS plain H2MUX、plain XUDP、TLS padded H2MUX、TLS XUDP 测试载体。

每场景实际发送 3×22000 字节 TCP 及 19 字节 UDP，验证回传一致、Host 双向总数严格等于 66019（不含协议头/padding），取消后 Host 活动流/UDP 为 0，listener 字节/会话 permit 全部归还。VLESS 测试载体只验证入口与 mux 线协议；生产 VLESS 解码仍属于 node-native，不将 fixture 当作整个生产数据面的验收。

调用约定：

- 一个 listener 保存一份 `Config`，每连接 clone；`vmess_replay`、`authentication`、`shared_budget` 的 Arc 都须共享。`Config::validate_users` 用于启动前上限验证，`prepare_users` 可在启动或热更新时预热；每次握手仍从 Host 取得最新 immutable Arc 快照，新快照自动刷新派生表。缓存只保留当前表及在途握手持有的旧表。
- VMess 最大 256 用户，无效 AuthID 至多 256 个 cached AES block 解密；AnyTLS 最大 65536 用户，SHA256 HashMap 查找，单个密码最多 4096 字节。
- 握手最长 10 秒、frame 最长 65535 字节；所有 mux 连接共用最多 1024 逻辑会话与 8MiB payload 队列。物理 listener 并发连接由调用方限制。该 payload 预算不是整个进程 RSS 上限，编解码缓冲和有界控制帧另有 frame/消息数量限制。
- H2 接收窗口每连接保守预留 65535 字节，入场留出一个发送 chunk 的余量。发送 DATA 的 permit 保存在 Bytes owner 内，直到 h2 最后引用释放才归还。AnyTLS/XUDP 入出 payload 共用同一预算；连接退出不会关闭全局 semaphore。
- VLESS command=3 不携带 port/address：写 `[0,0]` ACK 后进入 `serve_xudp`。command=1 的 `sp.mux.sing-box.arpa:444`：写 ACK 后进入 `serve_h2mux`。

第一阶段明确边界：

- VMess 仅 AEAD 认证（alterId=0）。每方向 AEAD 最多 65536 个 chunk，计数耗尽会关闭连接，避免 16bit nonce 重复；不是无限时长/无限字节的单连接承诺。
- H2MUX 已验证；第一阶段 smux/yamux 尚未实现。XUDP 接收带 GlobalID 的 New 帧，但第一阶段尚未实现跨 transport 的 GlobalID 会话复绑。
- AnyTLS v2 padding scheme 同步、SynAck、心跳、TCP 与 UoT v1/v2 已实现；官方客户端本次验证 v2/UoT，v1 UoT 仅本地编解码覆盖。
- 官方矩阵还未在 Linux 此 crate 目录独立执行；parent 的统一 CI/生产计费验收另行报告。测试 Host 是可审计的 payload 计数替身，不能代替持久化账单、数据库或真实节点验收。

本轮曾发现 `h2 max_send_buffer_size(1)` 导致逐 byte 发送并耗尽 VMess 帧计数，已改成 16384，真正硬上限由 Bytes owner 的共享 permit 保证。修复后完整矩阵重新通过。Windows 官方客户端主动终止时会记录 socket 10053 / WebSocket closed；这些退出发生在 payload 对账成功之后，未被当成互通失败或掩盖失败。

上游仅复用 shoes MIT 编解码/crypto helper，固定 revision `60ed3838b346268615c81e4eace4e15e717da23e`。完整许可和原始源文件 SHA 在 `LICENSE-shoes-MIT` 与 `UPSTREAM.json`，未导入 upstream TUN/mobile/FFI/listener 运行时，crypto 使用 ring 与 RustCrypto AES，不引入 AWS-LC。

## 第二阶段冻结（2026-10-03）

第二阶段补齐 SMUX v1、Yamux、非零 XUDP GlobalID 跨 TCP 连接复绑、HTTPUpgrade、HTTP/2 与 gRPC Tun 传输，以及原生 v2ray-plugin WS 的外层 Mux.Cool 适配。Shadowsocks 的 18 种原版方法在 node-core/node-native 中实现，必要的 crypto helper 在 vendor/shadowsocks/crypto，保留上游 MIT 许可与原始 SHA。所有新增代理业务数据仍经过 Host 或 native 共享 routed_datagram；Header、padding、protobuf/gRPC 和 mux 控制帧不计为业务流量。

| 验证 | 结果 |
|---|---|
| node-extended 默认测试 | 112 单元 + 12 payload/session + 2 transport + 5 GlobalID + 1 multiplex policy 集成测试 PASS |
| node-extended clippy 全 targets，`-D warnings` | PASS |
| 官方 sing-box v1.14.2 扩展矩阵 | 37 场景 PASS |
| 官方 Xray v26.3.27 GlobalID | 2 个物理连接复用 1 个 Host UDP 通道，35 字节双向精确对账 PASS |
| native Shadowsocks 默认测试 | 11 PASS，覆盖全部 18 方法、131072 字节多帧 TCP/半关闭、UDP 空包/8000 字节、重放、换身份、同 ID 换凭据撤销 |
| native Shadowsocks clippy 全 targets，`-D warnings` | PASS |
| 官方 sing-box Shadowsocks | 20 场景 PASS：18 方法 TCP/UDP + AES128GCM WS plugin mux=1/mux=0 |

扩展矩阵包含第一阶段所有场景，并增加 VMess/VLESS fixture 的 SMUX/Yamux 无 padding/有 padding；VMess/VLESS fixture 的 HTTPUpgrade plain/TLS、gRPC plain/TLS、HTTP/2 TLS；Host/method 匹配；SMUX/Yamux 超过初始窗口的大数据流。35 个普通场景每方向精确等于 66019 字节，2 个流控场景为 3×524288 TCP + UDP19，每方向 1572883 字节。每场景取消后 Host 活动数为零，共享 8MiB payload 与 1024 session permit 全部归还。SS 20 场景每方向都是 66019 字节，监听器和逻辑 worker 均已 join。WS plugin 场景的 UDP 走正常 Shadowsocks UDP socket，未把它称为 UDP over WebSocket。

GlobalID 缓存随 listener Config clone 共享；键为非零 8 字节 ID、完整认证 User 的 SHA256 和规范化来源 IP，相同 IP 的 TCP 临时源端口变化可复绑，跨用户/换密码/换 UUID/不同来源 IP 隔离。复绑先中断并等待旧读取 worker，再启动新 worker；自然 EOF 暂停 30 秒，无背景 pump。`Config.xudp_sessions.prune_users(&new_profiles)` 必须在发布热认证快照后调用，及时释放暂停的失效 profile；listener 关闭且 carrier 全部 join 后调用 `clear_idle()`。发生 Host 错误/撤销时移除绑定，不能重复使用已关闭通道。

`Config.multiplex_enabled=false` 在读取或占用会话预算前拒绝 VMess mux command、H2MUX/SMUX/Yamux、XUDP 与 WS plugin mux 入口。GlobalID 暂停缓存的认证检查与发布位于同一把 registry 锁下，异步 Host 入场期间的热撤销不能在 prune 后重新缓存旧 profile。

SIP003 helper 只构造明确绝对路径二进制的环境契约：公共 SS_REMOTE_HOST/PORT、private loopback SS_LOCAL_HOST/PORT、原始 SS_PLUGIN_OPTIONS。运行时负责 spawn、readiness、退出与 wait；本次未运行独立外部插件二进制。原生 v2ray-plugin 默认 mux=1 和 mux=0 已由官方 sing-box 客户端验证，不需要导入 Go 内核。WS 支持配置 Host 精确匹配；HTTPUpgrade 支持 host/path；HTTP/2 支持 hosts/path prefix/method；gRPC 只支持未压缩 Tun 字节流（protobuf field 1）。HTTP/2/gRPC 每个逻辑流交给 StreamHandler，非“只收第一流”。

SS 用户边界：AES2022 的 EIH 支持最多 65536 用户；旧 AEAD 最多 256 用户；none、旧 stream、ChaCha2022 无可识别多用户 MAC/EIH，明确只允许一个用户。ChaCha2022 只使用用户 PSK，不能拼成 AES2022 的 server:user 复合密钥。官方方法：none、aes-128/192/256-gcm、chacha20-ietf-poly1305、xchacha20-ietf-poly1305、2022-blake3-aes-128/256-gcm、2022-blake3-chacha20-poly1305、aes-128/192/256-ctr、aes-128/192/256-cfb、rc4-md5、chacha20-ietf、xchacha20。

本地 native SS idle TCP/UDP 测试保留旧客户端连接，更新同一名称的密码并通知认证 watch，在 1 秒上限内关闭原会话、归还活跃 lease；分别覆盖旧 AEAD、AES2022 EIH 与 ChaCha2022。UDP 随后用新密码从同一源 socket 成功重新入场，旧 Snapshot 的完整 profile 不会误绑定到新密码。

本阶段证据在 `tests/evidence/stage2/`；verification.json 记录每个最终 owned 产品源文件、测试源、上游记录、客户端、独立 Cargo.lock 和原始日志 SHA256。失败历史保留：旧 WS plugin 未解外层默认 Mux.Cool 的 Auth 失败（已修复并重测），以及同步中间 parent 快照的编译失败；它们不被覆盖成成功。

三个官方 fixture 共用 `tests/clients-lock.json`，固定 sing-box v1.14.2 和 Xray v26.3.27 的 Windows x64/Linux amd64/Linux arm64 归档及独立二进制 SHA。`tests/fetch_clients.py` 验证官方 release digest 或 Xray .dgst，提取指定普通文件并独立核验二进制；Rust fixture 在执行前再次检查 SHA 和版本。固定 Linux 客户端已下载并校验，尚未执行 Linux 互通时不记为协议 PASS。

新增 `node-native/tests/plugin_process.rs` 通过当前 Rust test binary 充当真实 SIP003 外部进程，四个业务 case 检查实际 env、private/public listener、延迟 readiness、退出与停止后的 wait/端口清理，以及“真实子进程永不 ready、stop 后 3 秒内等待退出且 UDP 在 ready 前未暴露”。`native_plugin_transport.rs` 经 `config::decode → run_embedded` 验证 plain/TLS 与默认 mux=1/mux=0 四场景；默认 mux=1 保留第三条客户端流直到 native stop，随后验证断流、TCP/UDP/control 释放，并从真实 durable checkpoint 读取每方向 66019。两测试文件显式 `cfg(unix)`，本次 Windows 执行均为 0 tests，Unix 实跑结果由主集成补充，当前记为 PENDING。helper child 的普通空运行不算业务验收。

SIP003/停机只读审查曾发现两个 P1，完整原始 findings 和绑定源码 SHA 保存在 `tests/evidence/reviews/native-plugin-20261003.md`。主集成随后补了 stop-aware startup、UDP delayed start、协议 grace join 和 payload barrier；窄静态复核认为原触发路径已移除，Unix实际运行仍待验证。新增 fixture 与复核的当前 SHA 在 `tests/evidence/stage2/unix-fixture-addendum.json`；它是 stage2 Windows 冻结之后的补充，不改写旧日志的通过范围。

范围边界仍明确：本次为 Windows 本地原生 SS/独立 codec fixture 互通；生产配置入口、Linux/musl、TLS/REALITY 文件接线、数据库持久计费与真实奥地利 Flash 节点验收由主集成单独报告。外部 SIP003 插件实际 Unix 生命周期与统一入口仍 PENDING；独立第三方 SIP003 插件二进制互通仍 UNVERIFIED。SMUX v2 未实现；gRPC 不支持压缩/任意 RPC schema；VMess alterId=0 和每方向 65536 AEAD chunk 上限保持。
