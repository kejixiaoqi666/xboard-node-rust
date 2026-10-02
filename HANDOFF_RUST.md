# 开发接续入口

这是 `xboard-node-rust` 的独立公开源码仓库。先读 [README](README.md)、[安装指南](docs/INSTALL_ZH.md) 和 [迁移清单](docs/RUST_MIGRATION_ZH.md)，再核对当前提交与工作区差异。

默认服务端路径全部为 Rust，当前支持范围和未完成功能由首页列出。`docs/RUST_*.md` 与 `benchmarks/results/` 保留迁移过程中的历史测量；它们绑定各自的历史源码/二进制，不自动成为新发行版的验收。完整 Go 基线和历史外部内核仍在来源仓库，本仓库不分发该 Go 服务端。

检查入口：

```bash
cargo fmt --all -- --check
cargo test --workspace --locked -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

发行入口为 `.github/workflows/release.yml`：按标签 checkout，编译两个 Linux musl 架构，执行安装文件流程及全新 systemd/真实 TCP/TLS 测试，打包许可文件，再创建草稿 Release。人工回读附件、测试与标签 commit 后公开 Release。仓库源码、CI 结果、安装结果、真实面板兼容是不同证据范围。

接下来仍需实现和验证限速/设备/IP、真实计费对账、其他协议与路由、多节点和主控制配置持久恢复。不要把 installer 的配置 `--check` 或 systemd active 当作这些业务验收；升级测试里的 fixture 版本只改发行标签、复用同一程序，不能证明任意未来数据迁移。

公开仓库不携带本机 `.Codex` 账本、真实凭据或生产配置。后续执行者应在自己的项目目录记录工作状态，并依据用户当次授权确定部署对象。
