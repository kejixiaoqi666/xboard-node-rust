# 验证入口与证据范围

验证按层区分：源码回归、独立官方客户端互通、实际 Linux 程序、真实面板业务。构建成功、服务启动、HTTP 200 或解析器测试不能代替下一层。当前介绍对应 preview.16 预发布版；最终发布状态和执行结果以匹配该版本的 Release 报告为准。

## 普通回归与静态检查

```bash
cargo fmt -- --check
cargo test --workspace --locked -j 2 -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -j 2 -- -D warnings
```

Unix 专用测试在 Windows 会显示零个测试，不能计入通过。被 `ignore` 的客户端/CA 测试也不计入普通通过数。

## 固定官方客户端

下载工具核对官方归档校验、源码中固定的归档 SHA 与独立二进制 SHA。客户端是测试依赖，不随 Rust 服务端分发。`linux-amd64` 可替换为 `linux-arm64`：

```bash
python3 crates/node-extended/tests/fetch_clients.py \
  --client sing-box --platform linux-amd64 --output /tmp/xbr-clients/sing-box
python3 crates/node-extended/tests/fetch_clients.py \
  --client xray --platform linux-amd64 --output /tmp/xbr-clients/xray
export SING_BOX_TEST_CLIENT=/tmp/xbr-clients/sing-box
export SING_BOX_BIN="$SING_BOX_TEST_CLIENT"
export XRAY_TEST_CLIENT=/tmp/xbr-clients/xray
cargo test -p node-extended --test official_clients -j 2 -- --ignored --nocapture
cargo test -p node-quic --test loopback -j 2 -- --ignored --nocapture
cargo test -p node-outbound --test proxy_wire -j 2 -- --ignored --nocapture
cargo test -p node-native --lib -j 2 all_eighteen_methods_official -- --ignored --nocapture
cargo test -p node-native --test native_plugin_transport -j 2 -- --ignored --nocapture
cargo test -p node-native --test plugin_process -j 2 -- --nocapture
```

| 模块 | 实际检查的内容 | 入口 |
| --- | --- | --- |
| Extended | VMess、AnyTLS、四种传输、SMUX/Yamux/H2MUX、padding、XUDP GlobalID、撤销及预算归还 | [QA](../crates/node-extended/QA.md)、[阶段记录](../crates/node-extended/tests/evidence/stage2/verification.json) |
| QUIC | Hysteria2/TUIC TCP/UDP、Salamander、fragment、0-RTT 认证、停止/重放 | [记录](../crates/node-quic/tests/VERIFICATION.json) |
| Routing/outbound | 实际 TCP/UDP 代理和多层链、规则集/Geo 数据、加密 DNS 及无明文降级 | [测试](../crates/node-outbound/tests/) |
| 原生接入 | SessionHost 计数/限速/IP/凭据撤销；Unix SIP003 子进程与 WS 插件入口 | [会话测试](../crates/node-native/src/session_integration.rs)、[Unix 入口](../crates/node-native/tests/) |
| 面板/配置 | 13 项真实 HTTP 观测/ACK 契约；NodeSpec→实际 builder→原生 decoder | [观测](../crates/node-panel/tests/telemetry_contract.rs)、[配置](../crates/node-kernel/tests/full_parity_config.rs) |
| Runtime | 304 后证书轮换、失败恢复、真实机器健康汇总和监听回收 | [接入](../crates/node-runtime/tests/administration_integration.rs)、[健康](../crates/node-runtime/tests/health_fleet.rs) |

## REALITY 与证书

REALITY 的完整 TLS mirror 验收需要固定 CPython 3.12/OpenSSL 3.5 和 Xray，见 [REALITY_FIXTURE.md](../crates/node-reality/tests/REALITY_FIXTURE.md)。它涵盖 X25519、ML-KEM、HRR、ML-DSA 和负例。普通全量测试没有自动执行该忽略项；安装后的 REALITY/Vision 验收由实际 Linux 程序测试另行记录。

ACME HTTP-01 使用实际本地 Pebble CA：见 [PEBBLE_FIXTURE.md](../crates/node-admin/tests/PEBBLE_FIXTURE.md)。Cloudflare DNS-01 的记录创建、所有权和清理由本地 mock 验证；没有用这份证据宣称已访问生产 DNS 或公共 CA。

## Linux 发行与真实计费

[发行工作流](../.github/workflows/release.yml)分别在 AMD64 和 ARM64 运行源码检查、官方客户端、静态 ELF 构建、安装器与 systemd 生命周期。公开报告保留架构、源码/二进制/归档 SHA；不同版本的结果不能直接转用。

真实面板验收使用独立隐藏节点和专用测试用户，检查实际转发字节、节点原始计数、倍率后的用户计费、在线记录及正常重启。凭据、真实用户资料和生产配置不进入公开报告。面板缺少批次去重时的未知上报仍需要人工对账；周期存档后的强杀尾部、WAN 最大承载量和长期稳定性保持明确边界。

### v0.1.0-preview.16 的精确结果

预发布 tag `v0.1.0-preview.16` 的发布门禁将绑定本次 tag workflow；除 preview.15 已通过的双架构源码、官方客户端、35 节点生产入口、安装器和 systemd 检查外，新增 `traffic-status` 摘要状态机的 10 项回归。该摘要只整理本地持久队列，不访问面板，也不替操作员判断未知 ACK。真实 Flash 计费仍引用下方 preview.12 的独立记录。

### v0.1.0-preview.15 的精确结果

预发布 tag `v0.1.0-preview.15` 精确绑定提交 `eb7fa212891ae2661842617aab8877e693910d8e`。GitHub Actions [37187398702](https://github.com/kejixiaoqi666/xboard-node-rust/actions/runs/37187398702) 在 AMD64 和 ARM64 均通过源码回归、clippy、固定 SHA 的官方 sing-box/Xray 互通、35 节点生产入口、静态 musl 构建、安装器和 systemd 生命周期。systemd 测试在停止前等待 durable 流量批次的真实回执；仍为 `uncertain` 会保持失败，不自动猜测面板是否已处理。发布资产包括两架构压缩包、SHA256SUMS、安装器及分架构互通/安装/systemd 机器结果。该版本没有新增 Flash 真实计费运行，计费证据仍是下方 preview.12 的独立记录。

### v0.1.0-preview.14 的精确结果

预发布 tag `v0.1.0-preview.14` 精确绑定提交 `437241d3a34c337915008d9b8faf3ecacf75ea7d`。GitHub Actions [37181124382](https://github.com/kejixiaoqi666/xboard-node-rust/actions/runs/37181124382) 在 AMD64 和 ARM64 均通过源码回归、clippy、固定 SHA 的官方 sing-box/Xray 互通、35 节点生产入口、静态 musl 构建、安装器和 systemd 生命周期。生产入口收尾增加了有界等待：最后一个协议案例完成后，只有真实面板 ACK 清空 durable `flight` 才会停机；仍为 `uncertain` 会使门禁失败。该版本没有新增 Flash 真实计费运行，计费证据仍是下方 preview.12 的独立记录。

### v0.1.0-preview.12 的精确结果

最终预发布 tag `v0.1.0-preview.12` 精确绑定提交 `ef0355843693c3e4738d028c8af7ab5c0f0228ce`。GitHub Actions [37154037856](https://github.com/kejixiaoqi666/xboard-node-rust/actions/runs/37154037856) 在 AMD64 和 ARM64 均通过源码回归、clippy、固定 SHA 的官方 sing-box/Xray 互通、35 节点生产入口、静态 musl 构建、安装器和 systemd 生命周期；systemd 报告各含 88 个案例。对应最终包的 SHA256 为：

| 架构 | ELF SHA256 | 发行包 SHA256 |
| --- | --- | --- |
| Linux AMD64 | `7bd025404c2fa8cf3c4fb7f478f7e8612baadd3b45190a0efef04ca1324627a0` | `cb1ba61a17dcba844da7e7f9d750aa49ea54c48b404167601bc31b535d7724ca` |
| Linux ARM64 | `f38772c647b8118ca1da2ae53c578badafc713f8e40ece2455192323850944c4` | `eec134456a06b99566d203d8e9ae9cac7f78a3000f2e4a980eb76fa46d0605b7` |

独立的奥地利 Flash 隐藏实验节点已使用最终 tag `v0.1.0-preview.12`（提交 `ef0355843693c3e4738d028c8af7ab5c0f0228ce`，AMD64 ELF SHA256 `7bd025404c2fa8cf3c4fb7f478f7e8612baadd3b45190a0efef04ca1324627a0`）完成真实业务验收：在线/IP/资源观测、TCP/UDP 实际转发、节点原始计数、倍率计费、正常停止清理和重启不重放均为 PASS。倍率 2 的专用用户验证原始每方向 69,000 字节计为 138,000；重启后新增每方向 4,157 字节的批次也正确计费，结束时没有待报或不确定批次。该结果只覆盖自有隔离面板和回环业务，不能推导公网容量、长期运行或生产 DNS/公共 CA 结论。
