//! Shared bounded resolver and routing, pinned to the exact IP used for I/O.
use crate::{Error, protocol::Address};
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use node_core::routing::{self, DnsConfig, DnsTransport, IpStrategy, Outbound, Policy, Route};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::Duration,
};

pub(crate) struct Network {
    policy: Policy,
    graph: node_outbound::Graph,
    resolver: Arc<NetworkResolver>,
}
struct NetworkResolver {
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
        let resolver = if dns.servers.is_empty() && dns.upstreams.is_empty() {
            None
        } else {
            let mut servers: Vec<_> = dns
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
            for upstream in &dns.upstreams {
                let name = upstream.server_name.as_deref().unwrap_or_default();
                let mut server = match upstream.transport {
                    DnsTransport::Udp => {
                        if dns.tcp_only {
                            NameServerConfig::tcp(upstream.address.ip())
                        } else {
                            NameServerConfig::udp(upstream.address.ip())
                        }
                    }
                    DnsTransport::Tcp => NameServerConfig::tcp(upstream.address.ip()),
                    DnsTransport::Tls => {
                        NameServerConfig::tls(upstream.address.ip(), Arc::<str>::from(name))
                    }
                    DnsTransport::Https => NameServerConfig::https(
                        upstream.address.ip(),
                        Arc::<str>::from(name),
                        upstream.path.as_deref().map(Arc::<str>::from),
                    ),
                    DnsTransport::Quic => {
                        NameServerConfig::quic(upstream.address.ip(), Arc::<str>::from(name))
                    }
                };
                for connection in &mut server.connections {
                    connection.port = upstream.address.port();
                }
                servers.push(server);
            }
            let mut builder = Resolver::builder_with_config(
                ResolverConfig::from_name_servers(servers),
                TokioRuntimeProvider::default(),
            );
            if dns.upstreams.iter().any(|u| {
                matches!(
                    u.transport,
                    DnsTransport::Tls | DnsTransport::Https | DnsTransport::Quic
                )
            }) {
                let paths = dns
                    .upstreams
                    .iter()
                    .filter_map(|u| u.ca_file.as_deref())
                    .collect::<Vec<_>>();
                builder = builder.with_tls_config(
                    node_outbound::tls_client_config(&paths).map_err(|_| Error::Config)?,
                );
            }
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
        let resolver = Arc::new(NetworkResolver {
            resolver,
            dns,
            hosts,
            queries: Arc::new(tokio::sync::Semaphore::new(256)),
            os: OnceLock::new(),
        });
        Ok(Self {
            policy: Policy::new(route, outbounds).map_err(|_| Error::Config)?,
            graph: node_outbound::Graph::with_resolver(outbounds, resolver.clone())
                .map_err(|_| Error::Config)?,
            resolver,
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
        self.resolver.lookup(address).await
    }

    pub async fn connect_for(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
        user: &str,
        inbound_tag: &str,
    ) -> Result<node_session::BoxStream, Error> {
        self.connect_with(
            address,
            port,
            source,
            routing::MatchMeta {
                user: Some(user),
                inbound_tag: Some(inbound_tag),
            },
        )
        .await
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn udp_open_for(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
        user: &str,
        inbound_tag: &str,
    ) -> Result<node_outbound::UdpRoute, Error> {
        self.udp_with(
            address,
            port,
            source,
            routing::MatchMeta {
                user: Some(user),
                inbound_tag: Some(inbound_tag),
            },
        )
        .await
    }
    pub async fn udp_plan_for(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
        user: &str,
        inbound_tag: &str,
    ) -> Result<node_outbound::UdpPlan, Error> {
        self.udp_plan(
            address,
            port,
            source,
            routing::MatchMeta {
                user: Some(user),
                inbound_tag: Some(inbound_tag),
            },
        )
        .await
    }
    pub async fn udp_channel(
        &self,
        plan: &node_outbound::UdpPlan,
    ) -> Result<Arc<dyn node_outbound::Datagram>, Error> {
        self.graph
            .udp_open(&plan.outbound_tag, plan.destination)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::Unsupported {
                    Error::Unsupported
                } else {
                    Error::Io(e)
                }
            })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn connect(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
    ) -> Result<node_session::BoxStream, Error> {
        self.connect_with(address, port, source, routing::MatchMeta::default())
            .await
    }
    async fn connect_with(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
        meta: routing::MatchMeta<'_>,
    ) -> Result<node_session::BoxStream, Error> {
        let (domain, ips) = self.resolve(address).await?;
        let mut error = Error::Blocked;
        let mut admitted_tag = None;
        for ip in ips {
            let outbound =
                self.policy
                    .select_with(domain.as_deref(), ip, port, "tcp", source, meta);
            let destination = SocketAddr::new(ip, port);
            if outbound.kind == "block" {
                continue;
            }
            if let Some(tag) = admitted_tag {
                if tag != outbound.tag {
                    continue;
                }
            } else {
                admitted_tag = Some(outbound.tag.as_str());
            }
            let result = self
                .graph
                .connect(&outbound.tag, destination)
                .await
                .map_err(Error::Io);
            match result {
                Ok(stream) => return Ok(stream),
                Err(e) => error = e,
            }
        }
        Err(error)
    }
    async fn udp_with(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
        meta: routing::MatchMeta<'_>,
    ) -> Result<node_outbound::UdpRoute, Error> {
        let plan = self.udp_plan(address, port, source, meta).await?;
        let channel = self.udp_channel(&plan).await?;
        Ok(node_outbound::UdpRoute {
            destination: plan.destination,
            outbound_tag: plan.outbound_tag,
            channel,
        })
    }
    async fn udp_plan(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
        meta: routing::MatchMeta<'_>,
    ) -> Result<node_outbound::UdpPlan, Error> {
        let (domain, ips) = self.resolve(address).await?;
        for ip in ips {
            let outbound =
                self.policy
                    .select_with(domain.as_deref(), ip, port, "udp", source, meta);
            if outbound.kind == "block" {
                continue;
            }
            let destination = SocketAddr::new(ip, port);
            return Ok(node_outbound::UdpPlan {
                destination,
                outbound_tag: outbound.tag.clone(),
            });
        }
        Err(Error::Blocked)
    }
    #[cfg(test)]
    pub async fn udp_destination(
        &self,
        address: &Address,
        port: u16,
        source: SocketAddr,
    ) -> Result<SocketAddr, Error> {
        let (domain, ips) = self.resolve(address).await?;
        for ip in ips {
            let outbound = self
                .policy
                .select(domain.as_deref(), ip, port, "udp", source);
            match outbound.kind.as_str() {
                "block" => continue,
                "direct" if outbound.detour.is_none() => return Ok(SocketAddr::new(ip, port)),
                _ => return Err(Error::Unsupported),
            }
        }
        Err(Error::Blocked)
    }
}
#[async_trait::async_trait]
impl node_outbound::Resolver for NetworkResolver {
    async fn resolve(&self, name: &str) -> std::io::Result<Vec<IpAddr>> {
        self.lookup(&Address::Domain(name.to_owned()))
            .await
            .map(|(_, ips)| ips)
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "proxy DNS resolution failed")
            })
    }
}
impl NetworkResolver {
    async fn lookup(&self, address: &Address) -> Result<(Option<String>, Vec<IpAddr>), Error> {
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
}
