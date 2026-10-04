# Installation and operation

[中文](INSTALL_ZH.md) · [English](INSTALL_EN.md) · [Project](../README.en.md)

Use a Linux AMD64 or ARM64 VPS with Bash, systemd and root access. Release binaries are static musl builds; Rust is not required on the VPS. Prepare your panel URL, node ID and token, plus the machine ID for the v2 API. The panel must provide fields supported by the [capability table](../README.en.md#implemented-capabilities).

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
xboard-rust
```

The installer hides token input and stores it in a separate mode-0600 file. HTTPS panel certificates are verified. Plain HTTP is permitted only for literal loopback addresses in explicit local tests. It does not open firewall ports or change another node service. File certificates should be in a readable location such as `/etc/ssl` or `/etc/letsencrypt`, because the installed service protects home directories.

## Fixed release and unattended installation

```bash
curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/v0.1.0-preview.13/install.sh -o install.sh
bash install.sh install --version v0.1.0-preview.13
```

For unattended installation, create a private token file using your editor, then run:

```bash
bash install.sh install --yes \
  --panel https://panel.example.com --node-id 7 --machine-id 1 \
  --token-file /root/panel-token
```

For the legacy API, replace `--machine-id` with the panel's `--node-type`, such as `vless`. They are mutually exclusive. Do not put a real token directly in the command line. `--no-start` installs/configures without starting the service; changes to a running installation first stop its previous process.

## Offline installation

Download the archive for the VPS architecture, `SHA256SUMS` and `install.sh` from the same release.

```bash
bash install.sh install \
  --package xboard-node-rust-linux-amd64.tar.gz --checksums SHA256SUMS
```

Use `linux-arm64` for ARM64. The installer verifies archive and per-file hashes, project/version metadata and ELF architecture; unsafe paths, links and incomplete manifests are rejected. `--root /absolute/staging/path` stages files without controlling the host's systemd and implies `--no-start`.

## Management

```bash
xboard-rust configure
xboard-rust update
xboard-rust update --version v0.1.0-preview.13
xboard-rust rollback
xboard-rust start
xboard-rust stop
xboard-rust restart
xboard-rust status
xboard-rust logs
xboard-rust check
xboard-rust version
xboard-rust traffic-status  # stop first
xboard-rust uninstall
```

Configuration changes retain private backups. Failed local startup restores the previous program/configuration and attempts to restart it. A local check does not prove successful proxying or correct panel billing. Rollback changes the program and keeps current counters/outbox state; already billed traffic is not rolled back. Uninstallation retains configuration, credentials, state and historical releases.

After a node has successfully synchronized, the runtime also keeps its panel configuration and user source snapshot in `state_dir/runtime-snapshot.json`. If the process restarts before the panel is reachable, it can restore that snapshot only when there is no active in-memory snapshot and the panel request fails at the transport layer or returns HTTP 5xx. The cache is bound to the node and panel identity, stored with private file handling, and does not contain the Token or panel URL. Authentication, decoding, identity-mismatch and corrupted-cache failures stay fail-closed; a reachable panel replaces the cache with its new authoritative snapshot.

## Multiple nodes and YAML migration

See [runtime-fleet.json](../examples/runtime-fleet.json) for two node controllers sharing one Rust process. Fill in real panel IDs and use a distinct absolute `state_dir` for each node. The installer handles a single fixed node; advanced configurations can replace that runtime configuration after an offline check.

```bash
xboard-node-rust --config /etc/xboard-node-rust/runtime.json --check
xboard-node-rust --import-go-yaml /path/config.yml \
  --output /etc/xboard-node-rust/fleet.json \
  --secrets-output /etc/xboard-node-rust/private.json \
  --original-cwd /original/absolute/working-directory
xboard-node-rust --config /etc/xboard-node-rust/fleet.json \
  --secrets /etc/xboard-node-rust/private.json --check
```

The typed importer handles supported certificate, route/outbound, interval, logging, health and machine-discovery settings and rejects unknown/unmapped fields. Secrets are stored as references, not copied into public fleet JSON. `--check` does not contact panels, issue certificates or start listeners.

If a pending traffic batch becomes `uncertain`, stop the node and compare it with the actual panel record before resolving its delivery state. The panel has no universal batch deduplication API. See [accounting boundaries](../README.en.md#limits-credentials-and-accounting) and [validation](VALIDATION_ZH.md).
