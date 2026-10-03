# 来源与许可 / Source and licensing

Xboard Node Rust is a Rust migration of the node backend maintained in
[xiaofujie369/xbord-node-v3](https://github.com/xiaofujie369/xbord-node-v3),
with [cedar2025/xboard-node](https://github.com/cedar2025/xboard-node) as its upstream reference.
The retained baseline is `7893713344d301b07978c2c1e84d848181b20e39`.
Existing authors' rights and notices remain applicable. New Rust modules and the installer are provided under MPL-2.0, as declared by the crate manifests and [LICENSE](LICENSE).

本项目是 Xboard 节点后端的 Rust 迁移，保留上游来源和 MPL-2.0 许可。没有额外加入限制商业使用、用户数量或用途的条款；使用和分发仍须遵守 MPL-2.0 与实际第三方依赖的许可。

Selected Vision, REALITY and extended protocol codecs reference or adapt [cfal/shoes](https://github.com/cfal/shoes), commit `60ed3838b346268615c81e4eace4e15e717da23e`, copyright (c) 2021-2023 Alex Lau, MIT. The narrow adaptation excludes the full shoes runtime, original listeners, TUN and mobile/FFI interfaces. Its original notices and per-file provenance are retained in `crates/node-vision/LICENSE` + `UPSTREAM.json`, `crates/node-reality/LICENSE` + `UPSTREAM.json`, `crates/node-extended/LICENSE-shoes-MIT` + `UPSTREAM.json`, and `crates/node-quic/LICENSE-SHOES` + `UPSTREAM.json` + `NOTICE.md`. The QUIC provenance separates referenced Hysteria2/TUIC algorithms from its independently written Salamander implementation. Runtime archives include these notices. Full upstream feature parity is not claimed.

The default controller and data plane are Rust workspace crates. `crates/node-outbound` is an independently written MIT module and retains its own LICENSE/NOTICE. Other local code follows its crate license declarations, including adapted MIT sections. The historical Go transition kernel is not included or required by this repository. Its separate historical artifacts remain in the original project and retain their own licenses.

The pinned MIT `shadowsocks` 1.24.0 source in `vendor/shadowsocks`, copyright (c) 2017 Y.T. CHUNG, retains its original LICENSE and provenance. Its UDP cipher cache compares key contents with an equality-consistent total ordering and a 4,096-entry capacity. UDP and client TCP padding is initialized before encryption to prevent stale/uninitialized memory disclosure. See `vendor/shadowsocks/UPSTREAM.json`.

`vendor/shadowsocks/crypto` pins the MIT `shadowsocks-crypto` 0.6.2 source, revision `86dbc757`, copyright (c) 2020 寧靜. LICENSE and UPSTREAM.json preserve exact original archive/file hashes and local adaptations. The local fork adds AES-192-GCM and XChaCha20-Poly1305 integration through existing RustCrypto primitives and retains the other cipher implementations. No custom cipher or cryptographic-security claim is made.

Each runtime release contains `third-party-notices.tar.gz`, collected from the exact normal Cargo dependency tree, workspace MIT notices/provenance and Rust toolchain notices; static Linux builds also include the build system's musl/GCC notices. Dependency license expressions remain in Cargo metadata. Official sing-box and Xray binaries are separately downloaded, SHA-pinned interoperability test clients and are not bundled with the default Rust server. External SIP003 plugins are supplied separately by administrators and retain their own licenses. This notice is an attribution document, not a new license or a declaration that all upstream features have been ported.
