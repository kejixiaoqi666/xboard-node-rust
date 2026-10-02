# Linux ARM64 构建与美国服务器测试

观察日期：2026-10-02（北京时间）。这是 Rust 单节点实验版本的服务器构建与隔离验证记录，完整迁移进度见 [RUST_MIGRATION_ZH.md](RUST_MIGRATION_ZH.md)。

## 构建对象

| 项目 | 本次使用的版本或位置 |
| --- | --- |
| 测试机器 | 159.195.12.237，Debian 13，aarch64 |
| 独立目录 | /opt/xbord-rust-lab/20261002-build-01 |
| Rust | 1.98.1，Cargo.lock 锁定依赖 |
| 程序 | bin/xboard-node-rust，6,623,160 字节 |
| 二进制 SHA-256 | c15e942ad2c001050f2d3111d1ca76c762a0fd45f297b8a2a07663187174b8f6 |
| 对应构建源码包 SHA-256 | 02c25bbfea10ce32b8e1cfea503e5a87edaa238261dce6940564bcab3d4407a2 |
| 协议内核 | 官方 sing-box 1.14.0，linux/arm64 |

输出是 Linux ARM64 GNU 可执行文件，动态依赖 libc、libm、libgcc_s；最高引用的 glibc 版本符号为 GLIBC_2.39。这份构建适用于本次 Debian 13 测试机及满足这些依赖的 ARM64 环境。其他 CPU 架构和较旧 glibc 环境需要另行构建。

构建使用独立 Cargo 缓存和 target 目录、两项并行编译任务及 nice 10 优先级。测试未安装或修改 systemd 服务、网站配置、生产节点配置、系统 DNS 或防火墙。

## 执行结果

| 验证 | 结果 |
| --- | --- |
| cargo build -p node-runtime --release --locked | PASS |
| cargo test --workspace --release --locked | 68 passed；真实协议集成项默认 ignored |
| 显式 real_singbox 测试 | 1 passed |
| cargo fmt --all -- --check | PASS |
| cargo clippy --workspace --all-targets --all-features --locked -- -D warnings | PASS |
| 编译后的程序检查 | 以下 9 项 PASS |

1. `--help` 可用。
2. `--check` 无须 token，不联系面板，不创建内核状态。
3. 程序从 HTTPS 夹具取得配置和用户，启动真实内核；token 未出现在内核环境中，目录为 0700、候选文件为 0600。
4. 真实 sing-box VLESS 客户端通过节点取得 HTTP 目标响应。
5. 304 响应保持原内核 PID，无多余重启。
6. 同端口替换用户后，新用户可访问，旧用户不可访问。
7. 下发未实现的非零限速时，拒绝候选并保留现有有效配置。
8. 对本次测试内核发送 SIGKILL 后，程序恢复内核，真实客户端重新取得目标响应。
9. 对 Rust 程序发送 SIGTERM 后正常退出，子进程已回收，候选文件已清理，监听已释放。

程序检查使用标准 TLS 校验；测试 HTTPS 服务读取已有证书，证书和私钥没有复制进构建包。仅给这个进程设置 CONNECT 代理，将对应域名映射到回环夹具；没有修改 DNS 或生产网站。面板凭据和用户 UUID 均为合成测试数据。

第一次程序检查因脚本只查看主线程的子进程列表而超时；实际程序已完成同步。脚本修正为检查所有线程后，独立重跑通过。第一次失败日志保留，没有作为成功证据。

## 使用构建包

解压 ARM64 运行包，编辑 `runtime.example.json` 中的面板地址、machine_id/node_id、sing-box 绝对路径和独立状态目录。将 token 放入配置指定的环境变量后运行：

```bash
./bin/xboard-node-rust --config runtime.example.json --check
./bin/xboard-node-rust --config runtime.example.json
```

运行包包含 Rust 程序和示例配置；sing-box 需要单独提供。本次验证使用 [官方 sing-box 1.14.0](https://github.com/SagerNet/sing-box/releases/tag/v1.14.0)。同端口更新仍为有短暂中断的 stop/start，当前成功快照尚未跨 Rust 进程重启持久保存。

## 尚未覆盖

真实生产面板、WSS 在服务器上的端到端验证、VLESS/Trojan 的客户端 TLS 验收、流量计费与可靠上报、限制执行、完整协议/路由兼容、多节点、长时间运行及 Go/Rust 同负载性能对比均未在本次验收中完成。

所有原始证据保存在本地 `.Codex/evidence/us-arm64/` 及相关 `us-*.json` 中。服务器构建和诊断目录保留，测试进程与回环服务在测试结束后停止。
