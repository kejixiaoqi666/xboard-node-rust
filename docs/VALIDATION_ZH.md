# 验证入口与证据范围

验证按层区分：源码回归、独立官方客户端互通、实际 Linux 程序、真实面板业务。构建成功、服务启动、HTTP 200 或解析器测试不能代替下一层。当前介绍对应 preview.12 候选版；最终发布状态和执行结果以匹配该版本的 Release 报告为准。

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
