# Xboard Node Rust

[中文](README.md) · [English](README.en.md) · [Releases](https://github.com/kejixiaoqi666/xboard-node-rust/releases)

A Rust node backend for Xboard. It runs on a Linux VPS, synchronizes node configuration and users with the panel, authenticates clients, forwards supported proxy traffic, and reports collected payload counters.

This project continues the Rust migration of [xbord-node-v3](https://github.com/xiaofujie369/xbord-node-v3). **`v0.1.0-preview.3` adds domain/IP/port routing, custom DNS and SOCKS5 TCP outbounds** to the existing TCP/UDP, shared per-user rate limits and source-IP admission. It includes a standalone Rust server and an installer. Full upstream parity is still in progress.

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
| UDP | VLESS fixed destinations and Trojan multiple destinations; IPv4, IPv6, system domain resolution and file TLS |
| User rate limits | Decimal Mbps, shared across every connection and both payload directions; 0 means unlimited |
| Device/source-IP limits | Distinct active source IPs per user on this node; same-IP connections share one slot; 0 means unlimited |
| Panel synchronization | Xboard v2 machine or v1 legacy REST; one explicitly configured node |
| WebSocket | Trusted-origin checks, reconnect and node-specific resync hints; REST remains authoritative |
| User updates | Atomic authentication snapshots; already authenticated connections survive user-only updates |
| Lifecycle | Configuration preflight, recoverable data-process replacement and coordinated shutdown |
| Accounting | Successful payload bytes per stable user identity; durable snapshots, receipts and pending batches |
| Deployment | AMD64/ARM64 archives, checksums, systemd, private credentials, update/rollback and uninstall |

The control and data plane use the same Rust executable in separate processes. Default installation does not depend on Go, Xray, or an external sing-box server.

`speed_limit=8` means a shared 1,000,000 payload bytes/second budget across upload, download and all connections for that user, with one second of burst credit and a 64 KiB minimum burst. Reconnecting does not reset the shared budget. Only payload bytes are counted, not total network-interface traffic.

`device_limit=2` admits two distinct active source IPs on this node. Devices behind the same public IP share one slot; this is not physical device identification or a cross-node limit. The last connection from an IP releases its slot. User-only policy updates retain authenticated sessions: rate changes apply to them, while lowering IP limits blocks new sources without disconnecting existing ones. Removed users cannot authenticate again; established sessions retain their last observed rate.

UDP associations close after 60 seconds without successful payload activity. Each association tracks at most 64 destination endpoints, with at most 1,024 UDP associations on the node. These are resource bounds, not benchmarked capacity claims.

Not yet migrated: REALITY/Vision, mux/XUDP, VMess, Shadowsocks, AnyTLS, TUIC, Hysteria2, other transports, GeoIP/GeoSite, regex/rule sets, other proxy outbounds, encrypted DNS, multiple nodes/panels in one process, online-IP reporting to the panel, and automatic ACME. Unsupported settings are explicitly rejected. Native Rust mode enforces supported user limits; the optional legacy external adapter still rejects nonzero limits and native routing/DNS options. The Rust runtime JSON is not interchangeable with the original Go YAML.

For TLS, provide local certificate/key files and set the corresponding panel `cert_mode=file`, `cert_file`, and `key_file`. Existing certificate tooling handles issuance and renewal.

## Routing and DNS

Routes can send selected traffic directly, block it, or use a SOCKS5 TCP upstream. They affect client proxy traffic, not the controller's Xboard connection.

Merge this `dns` field into `/etc/xboard-node-rust/runtime.json`, retaining existing panel/node fields and backing up the file first:

```json
{
  "dns": {
    "servers": ["1.1.1.1:53", "8.8.8.8:53"],
    "tcp_only": false,
    "strategy": "prefer_ipv4",
    "timeout_ms": 3000,
    "cache_size": 1024,
    "hosts": {"internal.example.com": ["192.0.2.10"]}
  }
}
```

Replace example addresses, then run `xboard-rust check` and `xboard-rust restart`. Server addresses support IPv4 and `[IPv6]:port`. With no custom servers, resolution uses the OS. Custom servers use UDP with TCP fallback for truncated replies, or TCP exclusively when `tcp_only=true`. There is no fallback to OS DNS when custom resolution fails. Explicit hosts take priority. Strategies are `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, and `ipv6_only`; they filter/sort domain answers, not literal client IP destinations.

The shared custom cache respects TTL, capped at 300 seconds for positive and 30 seconds for negative answers. `cache_size` counts responses; 0 disables caching. OS caching remains OS-managed. Bounds: 8 servers, 4,096 hosts, 32 returned IPs, 256 simultaneous network lookups per data process; overload fails. Timeout range: 100–10,000 ms, with a separate overall TCP handshake/connect deadline.

These fields belong to the **panel node response**, not `runtime.json`. Your panel must provide an interface that emits them; this project does not add a panel UI:

```json
{
  "custom_outbounds": [
    {"tag": "upstream", "protocol": "socks", "settings": {
      "server": "192.0.2.20", "server_port": 1080
    }}
  ],
  "custom_routes": [
    {"domain_suffix": ["blocked.example"], "outbound": "block"},
    {"ip_cidr": ["10.0.0.0/8"], "outbound": "block"},
    {"domain": ["proxy.example"], "network": ["tcp"], "outbound": "upstream"}
  ]
}
```

SOCKS5 servers currently require an IP. Optional `username` and `password` must appear together; SOCKS5 does not encrypt these credentials, so use a trusted link. The exact IP checked by the local route policy is used for direct I/O or sent to SOCKS5. UDP selecting a proxy is rejected rather than bypassing the proxy. VLESS UDP pins its destination for the association; Trojan UDP evaluates each datagram, closing the association on a blocked destination or resolution failure.

Precedence is `custom_route_rules`, then `custom_routes`, then `routes`; first matching rule wins, default direct. No implicit private-network block is added in this preview. Configure explicit CIDRs when needed.

| Input | Supported semantics |
| --- | --- |
| `routes` | Suffix domains including `*.example.com`, or CIDRs in `match`; `direct`, `block`/`reject`, or `proxy` with an outbound tag in `action_value` |
| `custom_route_rules` | Preserves upstream **OR** across `domains`, `domain_suffixes`, `ip_cidrs`, `ports`, `networks`, `source_cidrs`, `source_ports`; skips `disabled=true` |
| Structured actions | `direct`, `block`, or `route`; only `route` uses `action.target` |
| `custom_routes` | `domain`, `domain_suffix`, `ip_cidr`, `port`, `port_range`, `network`, `source_ip_cidr`, `source_port`, `source_port_range`, `outbound`; address predicates OR, combined with port/network/source groups using AND; no predicates matches all |
| Values | Port numbers or `80:90`/`80-90` ranges; case-insensitive domains with terminal dots normalized and label-boundary suffix matching |

Bounds: 4,096 compiled rules, 16,384 match values, 256 outbounds. Valid panel routing changes replace the native child and disconnect its sessions; invalid candidates preserve the prior child. User-only updates remain hot. Local DNS changes require a service restart. Before downgrading to preview.1/2, remove new routing/outbound/DNS fields and use that version's supported limits.

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

Startup failure during a version switch restores the previous program link and attempts to restart the previous service. This does not reverse panel billing or restore historical traffic state. Rollback to preview.1 requires settings supported by that version, including zero rate/device limits and TCP; cross-version tests use this common configuration. Cross-format state migrations need explicit release instructions.

## Validation and limits

The retained migration baseline passed Rust formatting, serial workspace tests and strict clippy. Linux ARM64 baseline evidence covers real protocol/TLS connections, user updates, recovery, payload accounting and durability. Those historical GNU binary hashes do not identify the new musl release files.

Release builds separately verify AMD64/ARM64 compilation, installer lifecycle, private permissions, archive rejection, configuration retention and rollback. A fresh systemd installation uses a synthetic loopback panel and real TCP/TLS/UDP echoes, including IPv4, domain and IPv6 targets, zero-length and 65,507-byte datagrams. It measures bidirectional shared limits across two connections and checks live IP/rate policy changes without restarting either process. Upgrade and two-way rollback use the actual published preview.1 binary and retain configuration and native counter identity. `installer-tests-*.json` and `systemd-tests-*.json` accompany the release assets and measurements.

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
