# Xboard Node Rust

[中文](README.md) · [English](README.en.md) · [Releases](https://github.com/kejixiaoqi666/xboard-node-rust/releases)

A Rust node backend for Xboard. It runs on a Linux VPS, synchronizes node configuration and users with the panel, authenticates clients, forwards supported proxy traffic, and reports collected payload counters.

This project continues the Rust migration of [xbord-node-v3](https://github.com/xiaofujie369/xbord-node-v3). **`v0.1.0-preview.1` is a preview with a limited protocol and feature set.** It includes a standalone Rust server and an installer. Full upstream parity is still in progress.

## Install

Run in a root Bash shell on a Linux AMD64/ARM64 VPS with systemd:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
```

The installer selects the latest published release with an asset for your architecture, including previews. It verifies archive and internal file checksums, asks for the HTTPS panel root URL, node ID, machine ID or legacy node type, and a hidden token. Runtime assets are built with static musl; Rust and a Go server are not needed on the VPS.

Recommended systems: Debian 12/13 and Ubuntu 22.04/24.04. The installer can install missing download utilities on Debian/Ubuntu. It does not change firewall settings or other node services.

After installation, `xboard-rust` opens the management menu. Use an actual client to verify the node; an active systemd service is only a process check.

## Supported today

| Capability | Scope |
| --- | --- |
| VLESS | TCP, UUID authentication; optional file TLS |
| Trojan | TCP authentication and file TLS |
| Panel synchronization | Xboard v2 machine or v1 legacy REST; one explicitly configured node |
| WebSocket | Trusted-origin checks, reconnect and node-specific resync hints; REST remains authoritative |
| User updates | Atomic authentication snapshots; already authenticated connections survive user-only updates |
| Lifecycle | Configuration preflight, recoverable data-process replacement and coordinated shutdown |
| Accounting | Successful payload bytes per stable user identity; durable snapshots, receipts and pending batches |
| Deployment | AMD64/ARM64 archives, checksums, systemd, private credentials, update/rollback and uninstall |

The control and data plane use the same Rust executable in separate processes. Default installation does not depend on Go, Xray, or an external sing-box server.

Not yet migrated: REALITY/Vision, UDP/mux, VMess, Shadowsocks, AnyTLS, TUIC, Hysteria2, non-TCP transports, custom routes/outbounds/DNS, rate/device/IP enforcement, multiple nodes/panels in one process, and automatic ACME. Unsupported nonzero limits/settings are explicitly rejected. The Rust runtime JSON is not interchangeable with the original Go YAML.

For TLS, provide local certificate/key files and set the corresponding panel `cert_mode=file`, `cert_file`, and `key_file`. Existing certificate tooling handles issuance and renewal.

## Manage

```bash
xboard-rust                  # menu
xboard-rust configure        # update panel/node settings with private backups
xboard-rust update           # latest published asset; retains config and traffic state
xboard-rust rollback         # previous program, only with matching declared state format
xboard-rust start
xboard-rust stop
xboard-rust restart
xboard-rust status
xboard-rust logs
xboard-rust check            # local runtime settings only
xboard-rust version
xboard-rust traffic-status   # stop the service first
xboard-rust uninstall        # remove service/entries; preserve config, credentials and state
```

Configuration is at `/etc/xboard-node-rust/runtime.json`. Credentials are stored separately in `/etc/xboard-node-rust/panel.env` with mode 0600, read by systemd without sourcing a shell script. State is at `/var/lib/xboard-node-rust/`; verified programs are under `/usr/local/lib/xboard-node-rust/releases/`.

Install/update options include `--version TAG`, `--token-file FILE`, `--token-env NAME`, `--yes`, `--no-start`, and offline `--package FILE --checksums FILE`. `--root ABSOLUTE_PATH` stages files without controlling host systemd. HTTP panel URLs are permitted only for literal loopback test addresses. See `bash install.sh --help` and the [Chinese installation guide](docs/INSTALL_ZH.md).

Startup failure during a version switch restores the previous program link and attempts to restart the previous service. This does not reverse panel billing or restore historical traffic state. Cross-format state migrations need explicit release instructions.

## Validation and limits

The retained migration baseline passed Rust formatting, serial workspace tests and strict clippy. Linux ARM64 baseline evidence covers real protocol/TLS connections, user updates, recovery, payload accounting and durability. Those historical GNU binary hashes do not identify the new musl release files.

Release builds separately verify AMD64/ARM64 compilation, installer lifecycle, private permissions, archive rejection, configuration retention, program rollback, and a fresh systemd installation with a synthetic loopback panel and real VLESS/Trojan TCP/TLS payload forwarding. `installer-tests-*.json` and `systemd-tests-*.json` accompany the release assets.

Unpersisted crash-tail bytes can still be lost; periodic checkpoints do not guarantee zero loss on power failure. Ambiguous report delivery pauses the batch until reconciled. API acceptance does not prove billing-database reconciliation. The tests do not establish maximum TCP capacity, WAN speed or long-running production stability.

## Build

Pinned Rust `1.98.1`, locked dependencies:

```bash
cargo build -p node-runtime --release --locked
cargo fmt --all -- --check
cargo test --workspace --locked -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Windows module builds/tests are supported; the default native runtime requires Unix sockets. Linux is the release deployment platform. Local panel fixtures may explicitly set `allow_loopback_http=true`; remote HTTP is still rejected and the default remains HTTPS.

## License

[MPL-2.0](LICENSE), with upstream attribution retained and no added commercial-use or purpose restrictions. Runtime archives include exact dependency, Rust toolchain and relevant static-library notices. See [NOTICE.md](NOTICE.md).
