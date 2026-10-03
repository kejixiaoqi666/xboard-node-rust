# 更新记录

## v0.1.0-preview.11

- 修复 GitHub 发行列表乱序时，一键安装/更新的 `latest` 选到旧版的问题。分页读取全部发行记录，过滤草稿、非法标签、无发布时间和缺少当前架构附件的记录，再按发布时间及发行 ID 选择。
- 新增实际安装器函数的乱序、架构过滤、无有效候选、分页及固定版本分支回归。保留全部 18 项安装生命周期与 88 项服务用例。
- 保留 preview.10 的五种 Shadowsocks TCP/UDP 与其他协议能力；本补丁不扩大协议、性能或生产计费声明。

## v0.1.0-preview.10

- Add native Shadowsocks TCP/UDP for aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305 and 2022-blake3-aes-128/256-gcm.
- Preserve original Go UUID-to-2022-key conversion and reject derived-key collisions; integrate hot users, shared TCP/UDP limits, routing and payload counters.
- Bound handshake concurrency, UDP queues/associations/peers and replay windows; join datagram writers before final accounting checkpoints.
- Vendor pinned MIT framing with initialized TCP/UDP padding, value-based UDP cache keys and a 4,096-entry cap, retaining source and license notices.
- Add genuine installed Xray interoperability and independent AEAD negative tests; keep existing protocol and installer regression coverage.

## v0.1.0-preview.9

- REALITY 外层发送密钥按记录预算自动轮换，默认 1,048,576，可配置 16–1,048,576。无定时器，接收密钥不受主动轮换影响。
- 大写入在阈值处分片，KeyUpdate 使用旧密钥排在已加密数据后，新数据/关闭通知使用新密钥；与客户端请求应答共用轮换路径。
- 新增三套件、默认/低阈值、反复轮换、部分写入、异步背压、关闭通知、配置映射和非法值回归。
- 新增实际安装服务端与未经修改的官方 Xray 客户端回归：阈值 16，密文原样转发，仅观察至少三次自动更新；双向各 262,240 字节完整回传。保留 peer KeyUpdate 注入、UDP、Vision 与安装管理回归。
- 无吞吐、CPU/RSS、公网承载或完整功能迁移的新增声明。

## v0.1.0-preview.8

- 支持 REALITY 外层客户端 KeyUpdate：独立收发密钥、序号重置、请求应答和固定长度分片；保留未知消息拒绝。
- 应答在旧发送密钥下排在已加密数据后，后续数据使用新密钥；只读应用也主动 flush，背压时不继续读取。
- 新增标准 HKDF 向量、三密码套件轮换、非法/交错/旧密钥拒绝、顺序/半关闭及背压回归；实际 Linux 使用官方握手加回环记录适配器验证。
- 修正路由测试等待条件，仅本次请求新增精确 SOCKS5 目标才通过。

## v0.1.0-preview.2 — 2026-10-03

增加原生 VLESS/Trojan UDP、用户双向共享限速、不同来源 IP 名额及用户策略热更新。支持 IPv4/IPv6、系统域名解析、零长度和 65,507 字节数据包；预算跨连接保留，取消不留下未来欠额，最后一条连接结束后释放 IP 名额。

修复 TLS 发送背压下尾部未刷出的停等问题，以及删除用户后迟到握手用旧政策覆盖共享限速的问题。加入真实 Rustls 背压回归、删除边界测试和两架构 systemd 限速/IP/UDP 实测；使用已公开 preview.1 实际二进制验证升级及双向回退。

## v0.1.0-preview.1 — 2026-10-02

首次独立仓库发布：保留已实现的 Rust 节点内核，增加可校验的 AMD64/ARM64 发行包、一键安装与菜单、凭据分离、systemd 管理、配置备份、升级/程序回退和保留数据的卸载。

当前公开节点能力为 VLESS/Trojan TCP、文件 TLS、单节点 Xboard 同步、用户热更新、流量采集及持久队列。完整原版功能仍在迁移。
