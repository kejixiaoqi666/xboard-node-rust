//! Native outgoing transports. Negotiation bytes stay outside payload accounting.
use async_trait::async_trait;
use node_core::routing::{Outbound, OutboundTls};
use node_session::BoxStream;
use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpStream;
mod stream;
mod tls;
mod udp;
pub use tls::tls_client_config;

#[async_trait]
pub trait Datagram: Send + Sync {
    async fn send(&self, payload: &[u8], destination: SocketAddr) -> io::Result<()>;
    /// Waiting futures allocate no caller buffers. Returned packets and partial
    /// stream frames retain a permit from the graph's global 8 MiB budget.
    async fn receive_packet(&self) -> io::Result<Packet>;
    async fn receive(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if buffer.len() < 65535 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP receive requires a full 65535-byte buffer",
            ));
        }
        let packet = self.receive_packet().await?;
        buffer[..packet.payload.len()].copy_from_slice(&packet.payload);
        Ok((packet.payload.len(), packet.source))
    }
}
pub struct Packet {
    pub payload: Vec<u8>,
    pub source: SocketAddr,
    pub(crate) _permit: tokio::sync::OwnedSemaphorePermit,
}
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>>;
}
pub struct UdpRoute {
    pub destination: SocketAddr,
    pub outbound_tag: String,
    pub channel: Arc<dyn Datagram>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UdpPlan {
    pub destination: SocketAddr,
    pub outbound_tag: String,
}
pub struct Graph {
    outbounds: BTreeMap<String, Prepared>,
    associations: Arc<tokio::sync::Semaphore>,
    framing: Arc<tokio::sync::Semaphore>,
    sends: Arc<tokio::sync::Semaphore>,
    resolver: Option<Arc<dyn Resolver>>,
}
struct Prepared {
    config: Outbound,
    tls: Option<Arc<rustls::ClientConfig>>,
    ss: Option<shadowsocks::config::ServerConfig>,
}
type UdpFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Arc<dyn Datagram>>> + Send + 'a>>;
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn server(outbound: &Outbound) -> io::Result<SocketAddr> {
    Ok(SocketAddr::new(
        outbound
            .server
            .ok_or_else(|| invalid("missing proxy server"))?,
        outbound
            .server_port
            .ok_or_else(|| invalid("missing proxy port"))?,
    ))
}
fn context() -> shadowsocks::context::SharedContext {
    shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local)
}
impl Graph {
    pub fn new(outbounds: &[Outbound]) -> io::Result<Self> {
        Self::prepare(outbounds, None)
    }
    pub fn with_resolver(outbounds: &[Outbound], resolver: Arc<dyn Resolver>) -> io::Result<Self> {
        Self::prepare(outbounds, Some(resolver))
    }
    fn prepare(outbounds: &[Outbound], resolver: Option<Arc<dyn Resolver>>) -> io::Result<Self> {
        if outbounds.is_empty() || outbounds.len() > 256 {
            return Err(invalid("invalid outbound count"));
        }
        let mut prepared = BTreeMap::new();
        for outbound in outbounds {
            outbound
                .validate()
                .map_err(|_| invalid("invalid outbound configuration"))?;
            let tls = outbound.tls.as_ref().map(tls::prepare).transpose()?;
            if outbound.server_domain.is_some() && resolver.is_none() {
                return Err(invalid("proxy domain requires an explicit resolver"));
            }
            let ss = if outbound.kind == "shadowsocks" {
                Some(
                    shadowsocks::config::ServerConfig::new(
                        SocketAddr::new(
                            outbound.server.unwrap_or(IpAddr::from([127, 0, 0, 1])),
                            outbound.server_port.unwrap_or(1),
                        ),
                        outbound.password.as_deref().unwrap_or_default(),
                        outbound
                            .method
                            .as_deref()
                            .unwrap_or_default()
                            .parse()
                            .map_err(|_| invalid("invalid Shadowsocks method"))?,
                    )
                    .map_err(|_| invalid("invalid Shadowsocks credentials"))?,
                )
            } else {
                None
            };
            if prepared
                .insert(
                    outbound.tag.clone(),
                    Prepared {
                        config: outbound.clone(),
                        tls,
                        ss,
                    },
                )
                .is_some()
            {
                return Err(invalid("duplicate outbound tag"));
            }
        }
        let graph = Self {
            outbounds: prepared,
            associations: Arc::new(tokio::sync::Semaphore::new(1024)),
            framing: Arc::new(tokio::sync::Semaphore::new(8 * 1024 * 1024)),
            sends: Arc::new(tokio::sync::Semaphore::new(128)),
            resolver,
        };
        for (tag, hop) in &graph.outbounds {
            if hop.config.kind != "block" {
                graph.chain(tag)?;
            }
        }
        Ok(graph)
    }
    pub async fn connect(&self, tag: &str, destination: SocketAddr) -> io::Result<BoxStream> {
        if destination.port() == 0 {
            return Err(invalid("invalid target port"));
        }
        tokio::time::timeout(Duration::from_secs(10), self.tcp(tag, destination))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy connection timed out"))?
    }
    pub async fn udp_open(
        &self,
        tag: &str,
        destination: SocketAddr,
    ) -> io::Result<Arc<dyn Datagram>> {
        if destination.port() == 0 {
            return Err(invalid("invalid target port"));
        }
        let slot = self.associations.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "UDP association limit reached")
        })?;
        let inner = tokio::time::timeout(Duration::from_secs(10), self.udp_for(tag, destination))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "UDP proxy association timed out")
            })??;
        Ok(Arc::new(udp::Bounded {
            inner,
            _slot: slot,
            framing: self.framing.clone(),
            sends: self.sends.clone(),
        }))
    }
    fn chain(&self, tag: &str) -> io::Result<Vec<&Prepared>> {
        let mut path = Vec::new();
        let mut seen = HashSet::new();
        let mut tag = tag;
        loop {
            let hop = self
                .outbounds
                .get(tag)
                .ok_or_else(|| invalid("unknown outbound detour"))?;
            if seen.len() >= 8 || !seen.insert(tag) {
                return Err(invalid("outbound cycle or chain too deep"));
            }
            if hop.config.kind == "block" {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "blocked outbound",
                ));
            }
            if hop.config.kind != "direct" {
                path.push(hop);
            }
            if let Some(next) = &hop.config.detour {
                tag = next;
            } else {
                break;
            }
        }
        path.reverse();
        Ok(path)
    }
    async fn tcp(&self, tag: &str, destination: SocketAddr) -> io::Result<BoxStream> {
        let path = self.chain(tag)?;
        let endpoint = if let Some(hop) = path.first() {
            self.endpoint(hop).await?
        } else {
            destination
        };
        let socket = TcpStream::connect(endpoint).await?;
        socket.set_nodelay(true)?;
        let mut stream: BoxStream = Box::new(socket);
        for (index, hop) in path.iter().enumerate() {
            let target = if let Some(next) = path.get(index + 1) {
                self.endpoint(next).await?
            } else {
                destination
            };
            stream = self.secure(hop, stream).await?;
            stream = match hop.config.kind.as_str() {
                "socks" => {
                    stream::socks(&mut stream, &hop.config, 1, target).await?;
                    stream
                }
                "http" => {
                    stream::http(&mut stream, &hop.config, target).await?;
                    stream
                }
                "vless" => stream::vless(stream, &hop.config, 1, target).await?,
                "trojan" => {
                    stream::trojan(&mut stream, &hop.config, 1, target).await?;
                    stream
                }
                "shadowsocks" => Box::new(
                    shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream::from_stream(
                        context(),
                        stream,
                        hop.ss
                            .as_ref()
                            .ok_or_else(|| invalid("missing Shadowsocks configuration"))?,
                        target,
                    ),
                ),
                _ => return Err(unsupported("unknown TCP proxy transport")),
            };
        }
        Ok(stream)
    }
    async fn endpoint(&self, hop: &Prepared) -> io::Result<SocketAddr> {
        if let Some(name) = &hop.config.server_domain {
            let resolver = self
                .resolver
                .as_ref()
                .ok_or_else(|| invalid("missing explicit proxy resolver"))?;
            let ips = resolver.resolve(name).await?;
            let ip = ips
                .into_iter()
                .find(|ip| !ip.is_unspecified() && !ip.is_multicast())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "proxy domain has no usable address",
                    )
                })?;
            Ok(SocketAddr::new(
                ip,
                hop.config
                    .server_port
                    .ok_or_else(|| invalid("missing proxy port"))?,
            ))
        } else {
            server(&hop.config)
        }
    }
    async fn secure(&self, hop: &Prepared, stream: BoxStream) -> io::Result<BoxStream> {
        if let Some(config) = &hop.tls {
            let setting = hop
                .config
                .tls
                .as_ref()
                .ok_or_else(|| invalid("missing TLS setting"))?;
            let name = if let Some(name) = setting
                .server_name
                .as_ref()
                .or(hop.config.server_domain.as_ref())
            {
                rustls::pki_types::ServerName::try_from(name.clone())
                    .map_err(|_| invalid("invalid TLS server name"))?
            } else {
                rustls::pki_types::ServerName::IpAddress(
                    hop.config
                        .server
                        .ok_or_else(|| invalid("missing proxy IP"))?
                        .into(),
                )
            };
            Ok(Box::new(
                tokio_rustls::TlsConnector::from(config.clone())
                    .connect(name, stream)
                    .await?,
            ))
        } else {
            Ok(stream)
        }
    }
    fn udp_for<'a>(&'a self, tag: &'a str, destination: SocketAddr) -> UdpFuture<'a> {
        Box::pin(async move {
            let hop = self
                .outbounds
                .get(tag)
                .ok_or_else(|| invalid("unknown outbound tag"))?;
            let result: Arc<dyn Datagram> = match hop.config.kind.as_str() {
                "block" => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "blocked UDP outbound",
                    ));
                }
                "direct" => {
                    if let Some(tag) = &hop.config.detour {
                        return self.udp_for(tag, destination).await;
                    }
                    Arc::new(udp::Direct::bind(destination, self.framing.clone()).await?)
                }
                "socks" => {
                    let proxy = self.endpoint(hop).await?;
                    let mut control = if let Some(tag) = &hop.config.detour {
                        self.tcp(tag, proxy).await?
                    } else {
                        let tcp = TcpStream::connect(proxy).await?;
                        tcp.set_nodelay(true)?;
                        Box::new(tcp) as BoxStream
                    };
                    control = self.secure(hop, control).await?;
                    let mut relay = stream::socks(
                        &mut control,
                        &hop.config,
                        3,
                        SocketAddr::new(
                            if proxy.is_ipv4() {
                                IpAddr::from([0, 0, 0, 0])
                            } else {
                                IpAddr::from([0u16; 8])
                            },
                            0,
                        ),
                    )
                    .await?;
                    if relay.ip().is_unspecified() {
                        relay.set_ip(proxy.ip());
                    }
                    if relay.port() == 0 || relay.ip().is_multicast() {
                        return Err(invalid("invalid SOCKS UDP relay"));
                    }
                    let lower = if let Some(tag) = &hop.config.detour {
                        self.udp_for(tag, relay).await?
                    } else {
                        Arc::new(udp::Direct::bind(relay, self.framing.clone()).await?)
                            as Arc<dyn Datagram>
                    };
                    Arc::new(udp::Socks::new(control, lower, relay))
                }
                "shadowsocks" => {
                    let proxy = self.endpoint(hop).await?;
                    let lower = if let Some(tag) = &hop.config.detour {
                        self.udp_for(tag, proxy).await?
                    } else {
                        Arc::new(udp::Direct::bind(proxy, self.framing.clone()).await?)
                            as Arc<dyn Datagram>
                    };
                    Arc::new(udp::Shadowsocks::new(
                        lower,
                        proxy,
                        hop.ss
                            .as_ref()
                            .ok_or_else(|| invalid("missing Shadowsocks configuration"))?
                            .clone(),
                    )?)
                }
                "vless" | "trojan" => {
                    let proxy = self.endpoint(hop).await?;
                    let tcp = if let Some(tag) = &hop.config.detour {
                        self.tcp(tag, proxy).await?
                    } else {
                        let tcp = TcpStream::connect(proxy).await?;
                        tcp.set_nodelay(true)?;
                        Box::new(tcp) as BoxStream
                    };
                    let mut tcp = self.secure(hop, tcp).await?;
                    let vless = hop.config.kind == "vless";
                    if vless {
                        tcp = stream::vless(tcp, &hop.config, 2, destination).await?;
                    } else {
                        stream::trojan(&mut tcp, &hop.config, 3, "0.0.0.0:0".parse().unwrap())
                            .await?;
                    }
                    Arc::new(udp::Stream::new(
                        tcp,
                        vless,
                        destination,
                        self.framing.clone(),
                    ))
                }
                "http" => {
                    return Err(unsupported(
                        "HTTP CONNECT carries TCP only; native UDP cannot traverse this hop",
                    ));
                }
                _ => return Err(unsupported("unknown UDP proxy transport")),
            };
            Ok(result)
        })
    }
}
