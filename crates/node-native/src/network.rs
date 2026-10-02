//! Shared bounded resolver and routing, pinned to the exact IP used for I/O.
use crate::{Error, protocol::Address};
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use node_core::routing::{self, DnsConfig, IpStrategy, Outbound, Policy, Route};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub(crate) struct Network {
    policy: Policy,
    resolver: Option<TokioResolver>,
    dns: DnsConfig,
    hosts: BTreeMap<String, Vec<IpAddr>>,
    queries: Arc<tokio::sync::Semaphore>,
    os: OnceLock<Result<crate::os_dns::OsResolver, std::io::Error>>,
}
impl Network {
    pub fn new(
        route: &Route,
        outbounds: &[Outbound],
        dns: Option<&DnsConfig>,
    ) -> Result<Self, Error> {
        let dns = dns.cloned().unwrap_or_default();
        dns.validate().map_err(|_| Error::Config)?;
        let resolver = if dns.servers.is_empty() {
            None
        } else {
            let servers = dns
                .servers
                .iter()
                .map(|s| {
                    let mut server = if dns.tcp_only {
                        NameServerConfig::tcp(s.ip())
                    } else {
                        NameServerConfig::udp_and_tcp(s.ip())
                    };
                    for c in &mut server.connections {
                        c.port = s.port();
                    }
                    server
                })
                .collect();
            let mut builder = Resolver::builder_with_config(
                ResolverConfig::from_name_servers(servers),
                TokioRuntimeProvider::default(),
            );
            let opts = builder.options_mut();
            opts.timeout = Duration::from_millis(dns.timeout_ms);
            opts.attempts = 1;
            opts.num_concurrent_reqs = 2;
            opts.cache_size = dns.cache_size;
            opts.use_hosts_file = ResolveHosts::Never;
            opts.positive_max_ttl = Some(Duration::from_secs(300));
            opts.negative_max_ttl = Some(Duration::from_secs(30));
            opts.ip_strategy = match dns.strategy {
                IpStrategy::Ipv4Only => LookupIpStrategy::Ipv4Only,
                IpStrategy::Ipv6Only => LookupIpStrategy::Ipv6Only,
                _ => LookupIpStrategy::Ipv4AndIpv6,
            };
            Some(builder.build().map_err(|_| Error::Config)?)
        };
        let hosts = dns
            .hosts
            .iter()
            .map(|(name, ips)| (routing::normalize_domain(name), ips.clone()))
            .collect();
        Ok(Self {
            policy: Policy::new(route, outbounds).map_err(|_| Error::Config)?,
            resolver,
            dns,
            hosts,
            queries: Arc::new(tokio::sync::Semaphore::new(256)),
            os: OnceLock::new(),
        })
    }
    #[cfg(test)]
    pub fn direct() -> Self {
        Self::new(
            &Route::default(),
            &[Outbound::plain("direct", "direct")],
            None,
        )
        .unwrap()
    }

    pub async fn resolve(&self, address: &Address) -> Result<(Option<String>, Vec<IpAddr>), Error> {
        let Address::Domain(name) = address else {
            let Address::Ip(ip) = address else {
                unreachable!()
            };
            return Ok((None, vec![routing::canonical(*ip)]));
        };
        if !routing::valid_domain(name) {
            return Err(Error::Protocol);
        }
        let name = routing::normalize_domain(name);
        let mut ips = if let Some(ips) = self.hosts.get(&name) {
            ips.clone()
        } else {
            let permit = Arc::clone(&self.queries)
                .try_acquire_owned()
                .map_err(|_| Error::Limited)?;
            tokio::time::timeout(Duration::from_millis(self.dns.timeout_ms), async {
                if let Some(resolver) = &self.resolver {
                    let _permit = permit;
                    // Absolute query, no OS search suffix or fallback to the system resolver.
                    Ok::<_, Error>(
                        resolver
                            .lookup_ip(format!("{name}."))
                            .await
                            .map_err(|_| Error::Dns)?
                            .iter()
                            .take(32)
                            .collect(),
                    )
                } else {
                    let resolver = self
                        .os
                        .get_or_init(crate::os_dns::OsResolver::new)
                        .as_ref()
                        .map_err(|_| Error::Dns)?;
                    resolver
                        .submit(name.clone(), permit)?
                        .await
                        .map_err(|_| Error::Dns)?
                }
            })
            .await
            .map_err(|_| Error::Dns)??
        };
        ips.iter_mut().for_each(|ip| *ip = routing::canonical(*ip));
        ips.retain(|ip| match self.dns.strategy {
            IpStrategy::Ipv4Only => ip.is_ipv4(),
            IpStrategy::Ipv6Only => ip.is_ipv6(),
            _ => true,
        });
        ips.sort_by_key(|ip| match self.dns.strategy {
            IpStrategy::PreferIpv6 => ip.is_ipv4(),
            _ => ip.is_ipv6(),
        });
        let mut unique = Vec::with_capacity(ips.len());
        for ip in ips {
            if !unique.contains(&ip) {
                unique.push(ip);
            }
        }
        if unique.is_empty() {
            return Err(Error::Dns);
        }
        Ok((Some(name), unique))
    }

    pub async fn connect(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
    ) -> Result<TcpStream, Error> {
        let (domain, ips) = self.resolve(address).await?;
        let mut error = Error::Blocked;
        for ip in ips {
            let outbound = self
                .policy
                .select(domain.as_deref(), ip, port, "tcp", source);
            let destination = SocketAddr::new(ip, port);
            let result = match outbound.kind.as_str() {
                "block" => continue,
                "direct" => {
                    tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(destination))
                        .await
                        .map_err(|_| Error::Protocol)
                        .and_then(|r| r.map_err(Error::Io))
                }
                "socks" => {
                    tokio::time::timeout(Duration::from_secs(3), socks(outbound, destination))
                        .await
                        .map_err(|_| Error::Protocol)
                        .and_then(|r| r)
                }
                _ => return Err(Error::Unsupported),
            };
            match result {
                Ok(stream) => return Ok(stream),
                Err(e) => error = e,
            }
        }
        Err(error)
    }

    pub async fn udp_destination(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
    ) -> Result<SocketAddr, Error> {
        let (domain, ips) = self.resolve(address).await?;
        for ip in ips {
            match self
                .policy
                .select(domain.as_deref(), ip, port, "udp", source)
                .kind
                .as_str()
            {
                "block" => continue,
                "direct" => return Ok(SocketAddr::new(ip, port)),
                // Never silently bypass a requested proxy for UDP.
                _ => return Err(Error::Unsupported),
            }
        }
        Err(Error::Blocked)
    }
}

async fn socks(outbound: &Outbound, destination: SocketAddr) -> Result<TcpStream, Error> {
    let mut stream = TcpStream::connect(SocketAddr::new(
        outbound.server.ok_or(Error::Config)?,
        outbound.server_port.ok_or(Error::Config)?,
    ))
    .await?;
    let method = if outbound.username.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut pair = [0; 2];
    stream.read_exact(&mut pair).await?;
    if pair != [5, method] {
        return Err(Error::Protocol);
    }
    if let (Some(user), Some(password)) = (&outbound.username, &outbound.password) {
        let mut auth = vec![1, user.len() as u8];
        auth.extend(user.as_bytes());
        auth.push(password.len() as u8);
        auth.extend(password.as_bytes());
        stream.write_all(&auth).await?;
        stream.read_exact(&mut pair).await?;
        if pair != [1, 0] {
            return Err(Error::Protocol);
        }
    }
    let mut request = vec![5, 1, 0];
    match destination.ip() {
        IpAddr::V4(ip) => {
            request.push(1);
            request.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(4);
            request.extend(ip.octets());
        }
    }
    request.extend(destination.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    if reply[..3] != [5, 0, 0] {
        return Err(Error::Protocol);
    }
    let size = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let n = stream.read_u8().await? as usize;
            if n == 0 {
                return Err(Error::Protocol);
            }
            n
        }
        _ => return Err(Error::Protocol),
    };
    let mut bound = [0; 257];
    stream.read_exact(&mut bound[..size + 2]).await?;
    Ok(stream)
}
