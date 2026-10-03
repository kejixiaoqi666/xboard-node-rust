# node-quic 来源与许可

本 crate 的本地实现依 `Cargo.toml` 和本目录 `LICENSE` 中的 MPL-2.0 提供。
Hysteria2/TUIC 帧格式、认证流程和 SendStream/RecvStream 适配曾参考
[cfal/shoes](https://github.com/cfal/shoes) 的固定提交
`60ed3838b346268615c81e4eace4e15e717da23e`，并在本模块接口上重新实现。
逐文件参考范围、原始 Git blob SHA-256 和本地改动在 `UPSTREAM.json` 中记录。

该参考代码原作者为 Copyright (c) 2021-2023 Alex Lau <github@alau.ca>，
依 MIT 提供；原许可全文逐字保留在 `LICENSE-SHOES`。
分发包含相应代码的源码或二进制时，应同时保留该作者和许可通知。
MPL-2.0 声明不删除参考材料原有的 MIT 许可或通知。

实际参考的 shoes 文件只有 `src/hysteria2_server.rs`、
`src/tuic_server.rs` 与 `src/quic_stream.rs`；没有导入整个 shoes crate、
其全局路由器或静态用户配置。多用户快照、node-session Host、认证期限、
取消树、帧边界和全局资源预算均由本模块实现。

`src/obfs.rs` 的 Salamander 实现依据 Hysteria2 公布的协议说明编写；
上述 shoes 提交中不含 Salamander 实现，因此没有将其归为 shoes 改编文件。
QUIC/TLS/HTTP3 和密码学分别使用 Quinn、rustls、h3/h3-quinn、Ring 和
blake2 的库实现；其依赖许可保留在根发行包按实际 Cargo 依赖树生成的通知中。

官方 sing-box 仅作为另行下载并校验 SHA-256 的互通测试进程。
其二进制不纳入本 crate 源码或发布包；版本和平台哈希位于
`tests/clients-lock.json`。
