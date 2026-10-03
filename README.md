# Xboard Node Rust

[中文](README.md) · [English](README.en.md) · [下载](https://github.com/kejixiaoqi666/xboard-node-rust/releases) · [安装与管理](docs/INSTALL_ZH.md)

**在 Linux VPS 上运行的 Xboard 节点后端，用 Rust 实现配置同步、代理协议、用户限制和流量上报。**

你在面板管理用户、套餐和节点；这个程序负责 VPS 上的认证与转发。它可以接入现有 Xboard，也可以根据本地配置独立运行。从 [xbord-node-v3](https://github.com/xiaofujie369/xbord-node-v3) 的迁移工作继续开发，项目名称与一键安装入口保持不变。

本次 `v0.1.0-preview.12` 候选版补齐此前列出的协议、传输、路由、DNS、多节点和证书模块。默认服务端包含 Rust 控制层和数据层，不需要 Go、Xray 或外部 sing-box 服务端。**新增功能不等于已经证明完整上游兼容、最大承载量或长期生产稳定性。** 验证记录与明确边界见下文。

![程序怎样工作](docs/assets/architecture.svg)

## 第一次使用，先看这里

1. 在 Xboard 面板创建节点，选择协议、端口并获取节点凭据。
2. 在 VPS 安装本程序，填写面板地址、节点 ID、机器 ID或旧 API 类型及 Token。
3. 用面板生成的订阅配置实际客户端，验证连接与流量统计。
4. 运行 `xboard-rust` 管理启停、更新、日志和回退。

程序不是面板，也不会为你购买 VPS、注册域名或自动生成所有客户端订阅。面板和客户端需要支持你选择的协议及字段。

## 一键安装

支持 Linux AMD64 / ARM64、Bash、systemd 和 root 权限。发行包采用静态 musl 构建，无需在服务器安装 Rust。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
```

安装器分页读取 GitHub 发行记录，按发布时间选择有对应文件的最新已发布版，下载后校验 SHA-256。Token 隐藏输入，保存在本机权限为 0600 的独立文件。安装后运行：

```bash
xboard-rust
```

菜单包含安装、更新、配置、回退、启动、停止、重启、状态、日志、版本和卸载。高级部署、离线安装、YAML 导入和多节点见[安装指南](docs/INSTALL_ZH.md)。正在使用的旧服务不会被安装器自动迁移或停掉。

## 现在有哪些能力

| 类别 | 实现内容 | 使用边界 |
| --- | --- | --- |
| VLESS / Trojan | TCP、UDP、IPv4/IPv6、域名目标、文件 TLS | Trojan 要求 TLS；VLESS 可用明文、TLS 或 REALITY |
| Vision / REALITY | Vision TCP/UDP；MUX/XUDP；REALITY X25519/ML-KEM-768、HRR、可选 ML-DSA-65、KeyUpdate | REALITY 使用一个配置的 SNI；支持范围以固定版本客户端验收为准 |
| VMess | AEAD 认证、AES-128-GCM / ChaCha20-Poly1305 / none；TCP、UDP、复用 | 每监听最多 256 用户；旧 AlterID 认证没有迁移；每方向 65,536 帧后关闭，避免重用 nonce |
| Shadowsocks | 18 种加密方法、TCP/UDP、2022 AES/ChaCha、多用户和重放检查 | 各类方法的用户上限不同，见下方 |
| AnyTLS | TLS、padding scheme、多流 TCP、UoT v2 UDP | 必须配置 TLS；逻辑会话共用监听器预算 |
| Hysteria2 | QUIC、HTTP/3 认证、TCP/UDP、Salamander | v2；cubic / new_reno / bbr；需要 TLS |
| TUIC | QUIC、UUID/密码、TCP/UDP、native/QUIC stream UDP、可选 0-RTT | v5；0-RTT 仍校验新连接的 exporter 认证与重放状态 |
| TCP 传输 | WebSocket、HTTP Upgrade、HTTP/2、gRPC | VLESS / VMess / Trojan；路径、Host、服务名明确校验；不叠加 Vision/REALITY |
| 复用 | Xray Mux.Cool / XUDP GlobalID；Sing SMUX / Yamux / H2MUX、padding | 默认共享 8 MiB 数据预算、1,024 逻辑会话；可禁用或调低会话上限 |
| SS 插件 | 内置 Rust v2ray-plugin WebSocket（默认 mux=1 或 mux=0）、文件 TLS；外部 SIP003 | 外部插件需要明确的绝对可执行路径；是管理员选择的额外程序 |
| 路由 | 域名、正则、CIDR、端口、源 IP/端口、用户、入站、逻辑组合/反转 | 按顺序匹配；代理失败不会自动降级直连 |
| 规则数据 | 本地 source JSON 规则集、V2Ray GeoIP/GeoSite `.dat`、选择器、SHA-256 校验与原子更新 | 不下载远程规则集；不接受二进制 SRS |
| 出站 | direct / block、SOCKS5、HTTP CONNECT、VLESS、Trojan、SS，多层 detour | TCP/UDP 依协议能力转发；带认证的 SOCKS5 UDP 可复用关联 |
| DNS | hosts、缓存、UDP/TCP、DoT、DoH、DoQ、显式 bootstrap | 加密 DNS 验证证书；失败不偷偷回退到系统明文解析 |
| 用户限制 | 共享限速、来源 IP 名额、热更新、凭据撤销 | 删除用户或同 ID 更换 UUID/密码后，旧会话停止；改速率不强制断开 |
| 面板同步 | v2 machine / v1 UniProxy、REST、ETag、WebSocket 重同步提示 | 推送只触发重新读取权威配置；HTTP 200 本身不代表业务确认 |
| 多节点 | 单进程静态 fleet、多面板、机器节点发现、独立状态/计费队列 | 全进程最多 64 节点；失败节点独立重试；拒绝目录重叠与身份重复 |
| 观测 | 在线 IP、连接数、Linux CPU/内存/磁盘、机器状态、本地健康接口 | 健康汇总真实叶子状态；部分节点未就绪返回 503；观测上报不携带流量增量 |
| 证书 | file / content / self、ACME HTTP-01、Cloudflare DNS-01、申请/续期/恢复 | 失败保留旧证书；HTTP-01 需要域名验证能访问节点；详见本地 CA 与生产验证边界 |
| 运维 | JSON 日志、离线检查、持久流量快照、待报队列、升级/回退 | 回退程序保留当前计费状态；不回滚已经上报的流量 |

## Shadowsocks 怎么配置

下面是**面板下发的节点字段**，不是安装器填写的本地运行配置：

```json
{"protocol":"shadowsocks","server_port":8388,"cipher":"aes-128-gcm","tls":0}
```

| 方法 | 用户密码与服务端密钥 | 每监听用户上限 |
| --- | --- | --- |
| `aes-128/192/256-gcm`、`chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305` | 用户 `uuid` 原文；不设置 `server_key` | 256 |
| `2022-blake3-aes-128/256-gcm` | `server_key` 是 Base64 的 16/32 字节密钥；用户按原版转换规则生成密钥 | 65,536 |
| `2022-blake3-chacha20-poly1305` | 用户按 32 字节规则转换；不设置 `server_key` | 1 |
| `none`、AES-128/192/256 CTR 与 CFB、`rc4-md5`、`chacha20-ietf`、`xchacha20` | 用户 `uuid` 原文；不设置 `server_key` | 1 |

2022 用户转换保持原版语义：把 `uuid` 的 UTF-8 字节复制到 16/32 字节零填充数组，超长截断，再 Base64 编码。AES2022 客户端密码采用 `server_key:用户密钥`；ChaCha2022 只用用户密钥。不同 UUID 转换成相同密钥时，节点拒绝该配置。

TCP 与原生加密 UDP 使用同一端口。内置 v2ray-plugin 只包装 TCP；UDP 仍使用同端口普通 SS 加密报文。面板字段示例：

```json
{"plugin":"v2ray-plugin","plugin_opts":"server;mode=websocket;path=/ss;host=node.example.com;mux=1"}
```

使用 `tls` 插件选项时需要配置文件证书。其他插件可把 `plugin` 设为 VPS 上可执行文件的绝对路径，`plugin_opts` 交给 SIP003 子进程；启动必须通过就绪检查，插件退出会使该节点失败并重新恢复，停机回收私有进程组。SIP003 标准转发不保留客户端原 IP，因此外部插件要求 `device_limit=0`；需要来源 IP 限制时使用内置 v2ray-plugin。

## 流量、限速和数据恢复

流量统计的是**成功转发的有效载荷**。认证头、地址、协议帧、填充、外层 TLS/QUIC 开销不计入；访问 HTTPS 时，内层 TLS 数据本身属于转发载荷。它不等于网卡总流量，也不等于下载文件的明文大小。

`speed_limit=8` 表示同一用户所有连接上传加下载共用约 1,000,000 字节/秒，允许一秒突发，最小额度 64 KiB。`device_limit=2` 限制本节点同时活跃的两个来源 IP，不能识别同一路由器后的物理设备，也不是多个节点间的全局限制。

计数按用户身份归属并持久存档，采集到待报队列后使用冻结批次上报。若连接中断导致无法确定面板是否接收，批次进入 `uncertain`，**不会盲目重发造成重复计费**。需要在面板核对对应批次后使用 `--traffic-resolve` 标记 delivered 或 not-delivered。面板自身没有通用批次去重接口，因此本项目不宣称端到端 exactly-once。

正常停止会先停止转发、回收会话、保存计数并清理在线记录。强制结束时仍有最后一次存档之后的尾部窗口；没有宣称掉电零损失或强杀无尾差。升级和回退只切换程序，保留当前计费状态。

## 多节点和迁移

简单 fleet 在 `nodes` 中放入多份运行配置，各节点使用不同 `state_dir`；`embedded=true` 把数据层放在同一个 Rust 进程里。旧单节点配置可继续使用独立 Rust 数据进程模式。高级 fleet 支持多面板、实例健康汇总、自动机器发现、证书和自定义路由。

原版 YAML 可通过离线导入生成类型明确的配置及独立凭据引用：

```bash
xboard-node-rust --import-go-yaml /path/config.yml \
  --output /etc/xboard-node-rust/fleet.json \
  --secrets-output /etc/xboard-node-rust/private.json \
  --original-cwd /原程序的绝对工作目录
xboard-node-rust --config /etc/xboard-node-rust/fleet.json \
  --secrets /etc/xboard-node-rust/private.json --check
```

导入不会替你运行旧 Go 内核。`xray` 配置标签映射到支持的 Rust 能力；未知字段、未映射选项、冲突的目录或监听身份会明确拒绝。`--check` 是离线配置检查，不代表面板可达、证书申请成功或协议可用。配置路径与具体功能见[安装指南](docs/INSTALL_ZH.md)。

## Vision 怎么用

Vision 是 VLESS 的一种数据流方式，现已接入 TCP、UDP 和复用链路。连接开始时使用填充；目标连接符合支持的 TLS 1.3 特征后，可切换为直接传送已经加密的内层 TLS 数据，减少一层重复加密。普通 TCP 和内层 TLS 1.2 仍通过外层 TLS 传送。它不代替证书，也不保证任何网络环境下的速度、可达性或隐蔽性。

面板下发的**节点配置**需要包含以下字段；这不是完整的本地 `runtime.json`：

```json
{
  "protocol": "vless",
  "network": "tcp",
  "tls": 1,
  "flow": "xtls-rprx-vision",
  "server_name": "node.example.com",
  "cert_config": {
    "cert_mode": "file",
    "cert_file": "/etc/letsencrypt/live/node.example.com/fullchain.pem",
    "key_file": "/etc/letsencrypt/live/node.example.com/privkey.pem"
  }
}
```

替换为 VPS 上实际的证书路径和域名。面板需能下发这些字段；客户端也要设置 VLESS、TCP、TLS、相同 UUID、正确证书域名和 `xtls-rprx-vision`。外层协商 TLS 1.3；缺少/不匹配的 flow、未知 addons或明文 Vision 会被拒绝，不会退成普通 VLESS。

Vision 继续使用已有的路由、共享限速、来源 IP 名额和持久计数。有效载荷指传给目标服务的数据：访问 HTTPS 时包含内层 TLS 记录，排除 VLESS/Vision 填充和外层 TLS 开销，并不等于网页或文件的明文大小。当前实现使用有界 Tokio 复制，**没有宣称实现内核 splice/零拷贝或提高了最大吞吐**。

回退到 preview.3 或更早版本前，先在面板去掉 Vision flow，并同步修改客户端；程序回退保留当前流量状态。客户端需要重连，已有连接不能跨版本保持。

## REALITY 怎么用

REALITY 是已支持的 VLESS 连接方式，可搭配 Vision。服务端使用 X25519 密钥、短 ID 和允许的服务器名称认证连接；不需要给节点配置证书文件。普通 TLS 访问或认证未通过的连接只会转发到管理员配置的固定目标站点，不会获得代理转发权限。这不保证公网可达性、隐蔽性或性能。

先在已安装节点上生成一对密钥：

```bash
/usr/local/lib/xboard-node-rust/current/bin/xboard-node-rust generate-reality-keypair
```

命令输出 `private_key` 和 `public_key`。私钥填在面板的服务端配置里，公钥提供给客户端；不要把私钥放进客户端订阅。以下是**面板下发的节点配置字段**，需要与你的面板实际支持的配置界面对应；不是完整的本地 `runtime.json`：

```json
{
  "protocol": "vless",
  "network": "tcp",
  "tls": 2,
  "flow": "xtls-rprx-vision",
  "server_name": "www.example.com",
  "tls_settings": {
    "private_key": "替换为生成的私钥",
    "public_key": "替换为对应公钥，也可省略此服务端校验字段",
    "short_id": "1234567890abcdef",
    "server_name": "www.example.com",
    "dest": "www.example.com:443",
    "max_time_diff": 300000
  }
}
```

示例域名是占位符，替换成从 VPS 可连接、支持 TLS 1.3 和 X25519 的实际目标站点。`server_name` 是唯一允许的客户端 SNI；`dest` 是固定转发目标，可填写域名或 IP 加端口，IPv6 使用 `[地址]:端口`。省略 `dest` 时使用 `server_name` 和 `server_port`（默认 443）。外层 `server_name` 若提供，必须与内部一致；REALITY 不与 `cert_config` 混用。客户端通常填写 VLESS、TCP、REALITY、相同 UUID、公钥、短 ID、服务器名称，以及 `xtls-rprx-vision`。Xray v26.3.27 的客户端公钥字段可用 `password`；其他客户端请按其界面字段填写。

`short_id` 接受偶数长度的十六进制字符串（0–16 个字符），或最多 16 个这样的字符串组成的列表；短于 16 字符时向右补零。省略或空字符串表示允许空短 ID。`max_time_diff` 为毫秒，默认 300000，最大 3600000；0 表示关闭时间差检查。可用三字节数组 `min_client_version` / `max_client_version` 限制客户端版本；VPS 和客户端的时间应正确。服务端可省略 `public_key`；若填写则必须对应私钥。

本版接入 **VLESS REALITY TCP、UDP、Vision 和 MUX/XUDP**。面板与客户端的 flow 要一致；普通 VLESS 与 Vision 使用不同的数据流格式。REALITY 认证后，代理有效载荷继续经过目标路由、共享限速、来源 IP 限制和持久计数。固定目标站点的认证前转发使用同一有界 DNS 解析器，然后直接连接，不走用户的代理出站规则，也不算入用户代理流量。目标配置变化会更换数据进程并断开连接。

ClientHello 可以分成最多 16 个 TLS 记录，重组后的握手消息最多 16 KiB；认证使用重组消息，固定目标站点仍收到原始记录。完整单记录走共享缓冲快速路径，未据此宣称整体性能提升。固定目标须完成支持的 TLS 1.3 握手；支持直接 ServerHello，以及协商组发生变化的 HRR（X25519、P-256、X25519MLKEM768）。客户端新 key share、认证、cookie 与两次 ClientHello 的 transcript 都重新核验；不支持的握手只能转发目标站点或拒绝。可选 tls_settings.mldsa65_seed 使用 generate-reality-mldsa65 生成的 32 字节签名 seed，客户端设置对应验证公钥，不能把 seed 当作客户端公钥。外层客户端 KeyUpdate 已支持 `update_not_requested` / `update_requested`：每方向独立派生新密钥并归零记录序号；请求应答使用旧发送密钥，后续数据使用新密钥。KeyUpdate 可分片但总消息固定 5 字节且必须在记录边界结束；非法值、交错消息及未知握手后消息拒绝。发送受阻时暂停继续读取，应答会主动 flush，不需要应用先发送数据。服务端现在按发送的加密记录数主动轮换，更新消息使用 `update_not_requested`，不会要求客户端同时换钥匙。`tls_settings.key_update_after_records` 默认为 1048576，可设置为 16–1048576；0、超界或非整数配置拒绝。这个数量是每代发送密钥下的非 KeyUpdate 记录上限，更新消息额外占用一个旧密钥记录；单次大写入跨阈值时也会按记录切开。只在下一次需要发送数据或关闭通知时轮换，空闲连接没有定时器；接收密钥继续由客户端更新控制。Vision 切入 DIRECT 后的数据不再使用这一外层 TLS 记录机制；**内层** TLS HRR 已有实际客户端回归。握手总时限 10 秒，镜像握手最多 16 个记录/64 KiB，认证前转发最长 300 秒；记录和缓冲都有上限，超限关闭。转发由节点连接任务持有，服务停止会一起取消。这些是实现边界，不是承载能力或抗探测证明。

回退 preview.8 或更早版本前，先删除新增的 `key_update_after_records` 配置字段；旧版仍拒绝未知字段，且不会主动按记录轮换。回退 preview.7 还需避免客户端 KeyUpdate。

回退 preview.6 前应停止使用 REALITY UDP 和多记录 ClientHello 客户端；旧程序不会自动转换这些能力。回退到 preview.5 或更早版本前，需要先把面板和客户端改为对应旧版支持的文件 TLS 或普通 VLESS；只切换程序版本不会自动转换 REALITY 配置。

## 验证和当前边界

验证分为普通源码测试、固定版本官方客户端互通、Linux 可执行文件/安装生命周期，以及隔离的真实面板计费。每一级保留自己的报告，构建成功、服务 active 或 HTTP 200 不替代下一层验收。

- 普通测试覆盖热更新/失败恢复、payload 计数、限速/IP、撤销和资源释放；Unix 插件与监听测试只在 Linux 执行。
- sing-box v1.14.2 与 Xray v26.3.27 是验收客户端，按官方发行包与独立二进制 SHA 固定；不打包进服务端。
- ACME 使用 Pebble 本地 CA 实际申请、续期和失败恢复；Cloudflare API 使用本地 mock 验证记录归属与清理。生产公共 CA / DNS 变更没有借此被宣称已验收。
- 详细命令和记录见 [验证索引](docs/VALIDATION_ZH.md)。后续源码修改会使旧 SHA 证明只覆盖原版本。

仍有明确范围：没有完整上游每个字段/协议/内核优化的对等承诺；不支持远程规则集/SRS、gRPC multiMode、VMess 旧 AlterID、Brutal、客户端连接池的服务端参数。复用的 `protocol` / `padding` 描述客户端协商，服务端接收支持的三种协议及两种 padding 格式；`enabled` 和 `max_streams` 执行接收端策略。

默认资源边界包含每进程 64 节点、每节点有界连接/握手/逻辑会话、8 MiB UDP/复用排队数据与 64 个 UDP 目标。上限是拒绝或回收策略，不能当作最大吞吐测量。新功能的内存、CPU、WAN 承载量和长期稳定性需要在实际负载下继续测量，没有用“Rust”替代测试结论。

## 开发和开源许可

```bash
cargo test --workspace --locked -j 2
cargo clippy --workspace --all-targets --all-features --locked -j 2 -- -D warnings
cargo build -p node-runtime --release --locked -j 2
```

项目使用 **MPL-2.0**，保留原作者和第三方许可；没有另加商业使用、用户数或用途限制。Vision、REALITY 与部分协议帧来自固定版本 MIT 上游；改动和来源记录随源码、发行包与依赖通知交付。见 [LICENSE](LICENSE) 和 [NOTICE.md](NOTICE.md)。
