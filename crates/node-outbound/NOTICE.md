# node-outbound 来源与许可

`node-outbound` 的图路由、SOCKS5/HTTP CONNECT/VLESS/Trojan 握手、UDP 状态机、
串联和资源预算实现由 xboard-node-rust contributors 编写，依本目录
`LICENSE` 中的 MIT 许可提供。本 crate 没有导入 shoes 的出站实现或运行时。

Shadowsocks TCP/UDP 加密和报文封装调用项目已有的 `shadowsocks` 1.24.0
依赖，不在本 crate 中复制密码学实现。该依赖的原作者为
Copyright (c) 2017 Y. T. CHUNG <zonyitoo@gmail.com>，许可为 MIT；
原许可和固定来源保存在 `../../vendor/shadowsocks/LICENSE` 与
`../../vendor/shadowsocks/UPSTREAM.json`，crypto 子依赖另有对应许可和来源记录。
分发包含该依赖的二进制时应同时保留这些通知。

`node-core`、`node-session` 等工作区依赖及 crates.io 依赖各自的许可继续适用。
本 crate 的 MIT 声明不改变这些依赖或工作区其他文件的许可。
发行包依赖通知由根打包流程按实际 Cargo 依赖树收集。

官方 sing-box 仅作为另行下载并校验 SHA-256 的互通测试进程。
其二进制不纳入本 crate 源码或发布包；测试锁定记录位于
`../node-quic/tests/clients-lock.json`。
