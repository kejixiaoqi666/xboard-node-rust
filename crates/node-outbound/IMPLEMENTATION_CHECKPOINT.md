# Outbound / routing / DNS 实施恢复点

状态：实现和公开 API 已冻结；最后一轮完整隔离测试 **23 PASS** 的证据保留，其中包含真实官方 sing-box 服务端互通、Geo 自动发现、source Geo、同文件多 selector 预算和 native server 域名反序列化。此次只补固定客户端校验、许可与针对性回归，没有重跑既有 9/23 业务。生产和 Linux 双架构官方互通仍待根验收。

2026-10-04 后续冻结（UTC 2026-10-03T16:47:39Z）：

- `Network::udp_destination` 仅测试调用，最小加 `#[cfg(test)]`；原未调用的 `Network::udp_open` 已删除，产品仍用 `udp_plan_for` / `udp_channel`，无路由语义变化。network.rs SHA：`c8d88b5b7d8a61d32e3080e354f30f645f7d42c7475bc37cf87e9fb6a8f05547`。
- `session_integration.rs` 新增 watch 可重入回归：真实 duplex 读写同时阻塞，真实 changed() 返回 Ready 前再次通知，32 轮未变 profile 双通知，最后同 ID 密码替换唤醒/拒绝读写并清空 lease/activity。针对性 Session **98457** / chunk **3acc69**：**1 PASS**，68 filtered；原 9 PASS 独立保留。当前测试文件 SHA：`dd001bb8216d329c7e574ba71f25786731a1bdf478ae505107a6fab6d3d60480`。
- node-quic `tests/support/pinned_client.rs` 按 OS/ARCH 固定 Windows x86_64、Linux x86_64/aarch64 v1.14.2 binary SHA；先以 16KiB 缓冲校验不超过 256MiB 的常规文件，再运行版本和测试。环境变量只选择路径，不接受可变 expected SHA。Outbound 官方 fixture 复用该检查器，`clients-lock.json` 和 fetch 脚本新增 linux-arm64 固定 archive/executable SHA。
- 修改校验器后的官方 Windows fixture：QUIC Session **60392** / **8c4313**，四模式 **1 PASS**；Outbound Session **21380** / **7c4925**，真实服务端与串联 **1 PASS**。Linux fixture 在本代理没有运行，不能写作 Linux PASS。
- 唯一顺序 lint 链，全部 `-j 2 -D warnings`：native lib/tests **e4d960 PASS**，QUIC isolated all-targets **53422 / 9d7afa PASS**，Outbound isolated all-targets **54513c PASS**。owned rustfmt check / diff check **f11826 PASS**。
- 保留两次失败尝试：QUIC Session **74228 / 38f567** 的 E0624（调用私有 hash_provider method）已改为公开 TLS13 common.hash_provider 字段；Outbound **e1541e** 的 target 名 proxy_wire 错写，修正为 proxy-wire。两者后续实际 fixture 均通过；这是工具输出摘要，原 transcript chunk 保留，不伪造完整日志。
- Outbound 自写代码交付 `LICENSE` MIT 全文与 `NOTICE.md`，Shadowsocks 独立依赖保留 vendor 原许可；QUIC 保留 MPL 声明，并交付本地 MPL `LICENSE`、逐字 MIT `LICENSE-SHOES`、逐文件 `UPSTREAM.json` 和 `NOTICE.md`。shoes HEAD 核对为 `60ed3838b346268615c81e4eace4e15e717da23e`；Salamander 不归为该提交的改编。
- root 生产文件仅只读审查，完整 SHA 和边界保存在 `VERIFICATION.json.root_source_review`。已发现的 RateStream Ready 二次 eager poll 问题由 root 修复，新回归通过；最新 Services 持有 OwnedTask，正常 join 有界，超时 abort+await，Drop abort。没有新增确认缺陷；Unix 生命周期只做源码审查，本代理没有执行 Unix代码。

进程状态：**60392 / 21380 / 98457 / 53422** 均已退出 0，本代理没有 pending 编译或测试会话。当前公开 API 无新增变化。

后续 native SessionHost 业务验收：新增 `../node-native/src/session_integration.rs`，当前 Windows 真实 socket **9 PASS**（Session 99718）。覆盖TCP/UDP计数、VLESS UDP framing/auth排除、共享rate/device、删除与同ID UUID/password变化、挂起代理握手撤销、真实USER/PASS SOCKS5 UDP回程/cache/取消，以及完整8MiB和1024 association permits恢复。第一次 Session 71894 为 **8 PASS / 1 FAIL**，真实挂起SOCKS握手热更不能立即取消；根修复整个Host admission watch后最终9项通过。保留该失败，不以最新PASS覆盖历史证据。

按根后续授权删除无产品调用的 `Network::udp_open`，唯一隔离fixture调用改为 `udp_plan_for`；Session 99718再次完整 **23 PASS**，官方互通5.36秒。Outbound lint随后独立 chunk `345e0d` PASS；native lint在该链曾发现根owned session.rs/config.rs两处写法问题，失败证据保留。根修复后最终 native lib/tests clippy **e4d960 PASS**。

QUIC 协议源码已冻结：`../node-quic/tests/VERIFICATION.json` 和 `../node-quic/tests/clients-lock.json` 保存原 Hysteria2/TUIC/Salamander/0RTT 与官方客户端证据。此次按根新增授权修改的是客户端 pin/fetch fixture 与许可来源文件，协议产品源码未变。

文件归属与交付：

- `../node-core/src/routing.rs`：native schema、bounded regex、逻辑和用户/inbound 路由、Source/GeoIP/GeoSite loader、checksum/原子替换、Xray 翻译、`discover_geo_rulesets`。
- `../node-native/src/network.rs`：共享 resolver、UDP/TCP/DoT/DoH/DoQ、固定首次获准出站标签、显式 bootstrap 域名解析、BoxStream 和 UDP plan/channel API。
- `../node-native/src/network_tests.rs`：保留旧三个回归，新增代理失败不得 direct 回退和代理域名必须使用配置 hosts 的真实 TCP 回归。
- `Cargo.toml`、`src/lib.rs`、`src/tls.rs`、`src/stream.rs`、`src/udp.rs`：所有 Rust 出站和有界 TCP/UDP 串联。
- `tests/proxy_wire.rs`：独立官方 sing-box 服务端 SOCKS/HTTP/VLESS/Trojan、六种 SS 方法和多跳 TCP/UDP。
- `tests/network_wire.rs`：直接编译生产 Network 源码的五种真实 DNS fixture、cache、CA/SNI 拒绝和 IP 阻断。
- `tests/routing_extended.rs`：逻辑/regex/metadata、Geo protobuf、SHA 原子替换、Xray 转换、bounds。
- `tests/isolated/Cargo.toml` 与 `tests/corecheck/Cargo.toml`：独立 workspace，避免写共享 root lock。它们的 lock/target 都在 ignore 内。

最终接口：

- `Graph::new` / `Graph::with_resolver` / `Graph::connect(tag, SocketAddr)` / `Graph::udp_open(tag, SocketAddr)`。
- `Datagram::send` / `receive_packet()->Packet { payload, source, private permit }`；兼容 receive(buffer) 要求 65535 字节。
- 1024 顶层 UDP associations，64 targets/层，8 层 detour，128 并发发送，全局 8 MiB 发送封装 + Packet + partial frame 内存。原生 socket 等待不分配，半 TCP 帧存在 channel 中，取消读取后可续读。中途取消写入使该 TCP UDP channel 失效。
- `Network::connect_for(address,port,source,user,inbound_tag)`。
- `Network::udp_plan_for(...)->UdpPlan {destination,outbound_tag}` + `Network::udp_channel(&plan)`；根缓存需以完整 plan 为键。
- `from_node_with_rulesets(node, &[RuleSet])`、`translate_rule(raw, sets)`、`discover_geo_rulesets(node,&Path)`、`install_ruleset_atomic`。
- `RuleSet { tag, kind="local", format Source|Geoip|Geosite, path, sha256, selector }`。同一文件多国家共享一次 bounded 读取；Geo selector 校验后输出显式 SHA snapshot。source Geo 使用 source_ip_rule_set，并仅接受纯 IP matcher，避免拿目标 IP 判断来源。

实际执行证据：

1. 完整命令：设置 SHA 校验的 `SING_BOX_BIN`，`cargo test -j 2 --manifest-path crates/node-outbound/tests/isolated/Cargo.toml -- --include-ignored --nocapture`。最终 Session **35374** 完成退出 0：2 UDP unit + 3 DNS/OS + 5 old-routing + 3 proxy（含官方）+ 10 routing = **23 PASS**。此前 Session 22309 为 19 PASS；新增四项已在最终 23 项中验证。
2. 官方互通单独 Session **32046** 退出 0，5.57 秒；完整 Session **35374** 中再跑退出 0，5.65 秒。官方 v1.14.2 SHA 见 node-quic/tests/clients-lock.json。Windows binary 已运行；Linux binary 只核验 SHA，Linux 执行由 root CI 完成。
3. Outbound `cargo clippy -j 2 --manifest-path .../tests/isolated/Cargo.toml --all-targets -- -D warnings` 在最终 Session **46444** 退出 0；原依赖 vendor sm4 lifetime 警告已由 root 修复，本轮无警告。
4. 同一 Session **46444** 顺序执行 `CARGO_TARGET_DIR=.../node-outbound/tests/isolated/target cargo clippy -j 2 --manifest-path .../tests/corecheck/Cargo.toml -- -D warnings`，退出 0，覆盖最终 Geo/source/server-domain 代码。

进程回收：旧 **34239 / 80847 / 53094 / 77969** 全部退出 0；延迟读取 **43360 / 42886 / 34493 / 1515** 全部退出 0。未限制 jobs 的 QA **56012** 按根并发约束主动 Ctrl-C 回收退出 1，再以唯一 `-j 2` 链运行成功。最终 **35374 / 46444** 均已完成，不存在本代理未回收编译链。

源文件冻结：`SOURCE_SHA256.json` 记录 owned 产品源码、manifest、测试和 README 的 SHA-256，排除恢复点与验证记录自身以避免循环引用。详细公开签名已在 README 的 API 段列出。

待 root 最终验收：Linux x86_64/aarch64 官方 ignored fixture 互通、完整 workspace/parity 和发布门。原 node-native Network 新回归由根 suite 执行，结果以根的实际证据为准。源 Geo、自动发现、同文件 17 MiB 双 selector 和本代理 SessionHost 业务正反例已有上述 PASS 证据。

明确格式边界：source JSON 支持网络/域名/IP/端口与逻辑字段；remote/binary SRS、process/sniff/balancer、Vision/Reality/WS 等出站附加传输会拒绝。HTTP CONNECT 自身不承载原生 UDP；其 TCP 可承载内层 Trojan/VLESS UDP。没有静默 direct fallback，没有外部 Go 内核，没有提交/push/发布。
