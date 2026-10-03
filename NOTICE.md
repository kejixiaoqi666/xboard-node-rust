# 来源与许可 / Source and licensing

Xboard Node Rust is a Rust migration of the node backend maintained in
[xiaofujie369/xbord-node-v3](https://github.com/xiaofujie369/xbord-node-v3),
with [cedar2025/xboard-node](https://github.com/cedar2025/xboard-node) as its upstream reference.
The retained baseline is `7893713344d301b07978c2c1e84d848181b20e39`.
Existing authors' rights and notices remain applicable. New Rust modules and the installer are provided under MPL-2.0, as declared by the crate manifests and [LICENSE](LICENSE).

本项目是 Xboard 节点后端的 Rust 迁移，保留上游来源和 MPL-2.0 许可。没有额外加入限制商业使用、用户数量或用途的条款；使用和分发仍须遵守 MPL-2.0 与实际第三方依赖的许可。

Vision data-stream modules in `crates/node-vision` and the narrow REALITY server engine in `crates/node-reality` are adapted from [cfal/shoes](https://github.com/cfal/shoes), commit `60ed3838b346268615c81e4eace4e15e717da23e`, copyright (c) 2021-2023 Alex Lau, under MIT. Each crate retains its upstream license and file provenance. File TLS uses rustls; the REALITY subset uses ring and x25519-dalek, removes upstream secret debug output, and does not include the full shoes runtime. Runtime archives retain both MIT notices alongside dependency notices. REALITY TCP compatible-client acceptance is recorded by the matching release test reports; full upstream parity is not claimed.

Default server code consists of the `node-core`, `node-panel`, `node-kernel`, `node-native` and `node-runtime` Rust crates. The historical Go transition kernel is not included or required by this repository. Its separate historical artifacts remain in the original project and retain their own licenses.

The pinned MIT `shadowsocks` 1.24.0 source in `vendor/shadowsocks` retains its original LICENSE and provenance. Its UDP cipher cache is patched to compare key contents with an equality-consistent total ordering, and its capacity is reduced to 4,096. UDP and client TCP padding is initialized before encryption to prevent stale/uninitialized memory disclosure. See `vendor/shadowsocks/UPSTREAM.json`. Cryptographic primitives remain the library's implementations.

Each runtime release contains `third-party-notices.tar.gz`, collected from the exact normal Cargo dependency tree and Rust toolchain notices; static Linux builds also include the build system's musl/GCC notices. Dependency license expressions remain in Cargo metadata. This notice is an attribution document, not a new license or a declaration that all upstream features have been ported.
