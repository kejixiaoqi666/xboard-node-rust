# 原生出站、DNS 与路由

`node-outbound` 把协议握手、TLS 和 UDP 封装留在流量统计边界之外。`Graph::connect` 返回 `node_session::BoxStream`；Host 继续负责当前用户授权、限速、持久计数和取消。支持 direct、SOCKS5、HTTP CONNECT、VLESS、Trojan、Shadowsocks TCP；支持 direct、SOCKS5 UDP、VLESS UDP、Trojan UDP 和 Shadowsocks UDP。Shadowsocks 使用仓库固定的 Rust 库及其密码套件，不调用外部内核。

出站的 `detour` 指向外层代理。准备时拒绝不存在的标签、循环、block 跳点和超过 8 层的链。SOCKS/SS 的原生 UDP 可以逐层套在支持 UDP 的外层代理上；Trojan/VLESS 的 UDP 通过 TCP 流传输，因此外层也可以使用 HTTP CONNECT。HTTP CONNECT 自身的原生 UDP、以及 SOCKS/SS 原生 UDP 经 HTTP 的组合会明确返回 Unsupported。TCP 重试只使用首次获准的出站标签；UDP 握手失败不会切换成 direct。

代理地址可以写为 `server` IP 或域名；域名也可用 `server_domain` 表示。域名出站要求显式 `Resolver`，生产 Network 会使用同一份 hosts、DNS 缓存、查询限额和加密 DNS 配置。代理不会自行重新调用系统 DNS。TLS 默认验证证书和主机名，可配置 `server_name`、本地 `ca_file`、ALPN；`insecure` 只有明确设置时才启用。

生产 Network 提供 `connect_for(address, port, source, user, inbound_tag)`、`udp_plan_for(...)` 和 `udp_channel(&UdpPlan)`。先获得 `UdpPlan { destination, outbound_tag }`，再以该完整键复用 UDP channel，避免每包重新认证。VLESS UDP 流固定到一个目标；各层最多保存 64 个实际发送目标，回包需通过源地址验证。

根集成使用以下公开签名；`Network` 是 node-native 内部类型，`Address` 是其原生 IP/域名地址枚举。

```rust
// node_core::routing
pub fn from_node(node: &NodeSpec) -> Result<(Route, Vec<Outbound>), ConfigError>;
pub fn from_node_with_rulesets(node: &NodeSpec, sets: &[RuleSet])
    -> Result<(Route, Vec<Outbound>), ConfigError>;
pub fn discover_geo_rulesets(node: &NodeSpec, directory: &Path)
    -> Result<Vec<RuleSet>, ConfigError>;
pub fn translate_rule(raw: &serde_json::Value, sets: &[RuleSet])
    -> Result<Rule, ConfigError>;
pub fn install_ruleset_atomic(set: &RuleSet, data: &[u8]) -> Result<(), ConfigError>;
// Policy::select_with 的额外参数
pub struct MatchMeta<'a> { pub user: Option<&'a str>, pub inbound_tag: Option<&'a str> }

// node_outbound
pub fn Graph::new(outbounds: &[Outbound]) -> io::Result<Graph>;
pub fn Graph::with_resolver(outbounds: &[Outbound], resolver: Arc<dyn Resolver>)
    -> io::Result<Graph>;
pub async fn Graph::connect(&self, tag: &str, destination: SocketAddr)
    -> io::Result<node_session::BoxStream>;
pub async fn Graph::udp_open(&self, tag: &str, destination: SocketAddr)
    -> io::Result<Arc<dyn Datagram>>;
pub struct UdpPlan { pub destination: SocketAddr, pub outbound_tag: String }
pub struct Packet { pub payload: Vec<u8>, pub source: SocketAddr /* private memory permit */ }
// Resolver: async resolve(&self, name: &str) -> io::Result<Vec<IpAddr>>
// Datagram: async send(&self, payload: &[u8], destination: SocketAddr) -> io::Result<()>
//           async receive_packet(&self) -> io::Result<Packet>
//           async receive(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>

// node_native::network::Network
pub fn Network::new(route: &Route, outbounds: &[Outbound], dns: Option<&DnsConfig>)
    -> Result<Network, Error>;
pub async fn Network::connect_for(&self, address: &Address, port: u16,
    source: SocketAddr, user: &str, inbound_tag: &str)
    -> Result<node_session::BoxStream, Error>;
pub async fn Network::udp_plan_for(&self, address: &Address, port: u16,
    source: SocketAddr, user: &str, inbound_tag: &str) -> Result<UdpPlan, Error>;
pub async fn Network::udp_channel(&self, plan: &UdpPlan) -> Result<Arc<dyn Datagram>, Error>;
```

`Datagram::receive_packet` 返回 `Packet { payload, source }`；内部的全局内存 permit 会随 Packet 丢弃而释放。等待 native UDP socket 的 future 不分配包缓冲区，TCP 的半帧解析状态存在 channel 内，取消后可以继续读取。全部 UDP 发送封装、已返回 Packet 和未完成流帧共享 8 MiB 限额，顶层 association 最多 1024 个，发送并发最多 128。兼容方法 `receive(&mut buffer)` 要求 buffer 至少 65535 字节。TCP UDP 发送被中途取消后会使该 channel 失效，避免后续帧接在半帧之后。

DNS 的 `upstreams` 支持 udp、tcp、tls、https、quic。每个 upstream 指定 `address` 作为 bootstrap IP，tls/https/quic 还必须指定 `server_name`，可指定 `ca_file`；https 可指定自定义 path。DNS 配置不产生隐含的明文或系统 resolver 回退。旧 `servers`、`tcp_only`、hosts、IP 家族优先级保持原语义。查询最多 256 个并发，缓存有界，正 TTL 最大 300 秒，负 TTL 最大 30 秒。

路由支持精确域名、后缀、关键词、Rust regex、CIDR、端口范围、TCP/UDP、来源 IP/端口、user、inbound、invert 和逻辑 and/or。旧面板结构化 match 条件保持 OR；native default rule 的地址条件 OR，端口、来源和其他条件 AND。Xray field rule 和 servers/vnext 出站配置可通过 `from_node_with_rulesets` 转换。无法实施的 sniff/process/balancer、Vision/Reality/WS 等出站附加传输会明确拒绝。

本地 `rule_set` 接受 `source`（sing-box JSON v1–v5 支持的网络/域名/IP/端口字段）、`geoip` 和 `geosite`（V2Ray protobuf）。每项必须提供 tag、path 和文件 SHA-256；geoip/geosite 还需要 selector，例如 `cn`、`!cn` 或 `category-ads-all@ads`。总文件最多 32 MiB、64 个集、200000 条目；regex 最多 256 个，单式最多 4096 字节并限制编译内存。远程和 binary SRS 格式不被当成已实现功能，配置会拒绝。更新使用 `install_ruleset_atomic`，先验证 SHA 并完整解析/编译，再写同目录临时文件并原子替换。现有 Policy 保留自己的旧快照。

`discover_geo_rulesets` 只在实际路由引用 `geoip:` / `geosite:` 时读取显式 `geo_data_dir` 的 geoip.dat / geosite.dat。缺目录、文件、国家或 attribute，损坏 protobuf，超过文件/条目限额都会拒绝；同一文件的多个 selector 共用一个有界快照。发现结果包含绝对路径和内容 SHA，随后加载时重新校验 SHA，文件变化不能绕过已生成配置。`source_ip_rule_set` 是内部来源 IP 集引用，必须指向纯 IP matcher，并以连接来源 IP 匹配。

隔离测试从 `tests/isolated/Cargo.toml` 运行；固定官方客户端由 `../node-quic/tests/fetch_clients.ps1` 下载并按 `clients-lock.json` 校验。设置 `SING_BOX_BIN` 后使用 `cargo test --manifest-path crates/node-outbound/tests/isolated/Cargo.toml -- --include-ignored --nocapture` 执行官方服务端互通。测试覆盖五种真实 DNS 传输、错误 CA/SNI、缓存、固定目标、官方 SOCKS/HTTP/VLESS/Trojan 和六种 SS 方法、两级/三级 TCP/UDP 链、半帧取消恢复，以及规则集 checksum/原子更新。

格式依据：[V2Ray 地理数据 protobuf](https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto)、[sing-box source rule-set](https://sing-box.sagernet.org/configuration/rule-set/source-format/)、[sing-box headless rule](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)。实现没有引入上游全局路由器或静态用户。
