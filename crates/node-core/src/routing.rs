//! Bounded native routing schema. Structured panel match groups retain Go's OR semantics.
use crate::{ConfigError, NodeSpec};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
};

fn invalid() -> ConfigError {
    ConfigError::KernelRejected("invalid or unsupported routing/DNS configuration".into())
}
fn direct() -> String {
    "direct".into()
}
fn timeout() -> u64 {
    3000
}
fn cache() -> u64 {
    1024
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub servers: Vec<SocketAddr>,
    #[serde(default)]
    pub tcp_only: bool,
    #[serde(default)]
    pub strategy: IpStrategy,
    #[serde(default)]
    pub hosts: BTreeMap<String, Vec<IpAddr>>,
    #[serde(default = "timeout")]
    pub timeout_ms: u64,
    #[serde(default = "cache")]
    pub cache_size: u64,
}
impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: vec![],
            tcp_only: false,
            strategy: IpStrategy::default(),
            hosts: BTreeMap::new(),
            timeout_ms: timeout(),
            cache_size: cache(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpStrategy {
    #[default]
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

impl DnsConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.servers.len() > 8
            || self
                .servers
                .iter()
                .any(|s| s.port() == 0 || s.ip().is_unspecified() || s.ip().is_multicast())
            || !(100..=10000).contains(&self.timeout_ms)
            || self.cache_size > 65536
            || self.hosts.len() > 4096
            || (self.tcp_only && self.servers.is_empty())
        {
            return Err(invalid());
        }
        let mut names = HashSet::new();
        for (name, ips) in &self.hosts {
            if !valid_domain(name)
                || !names.insert(normalize_domain(name))
                || ips.is_empty()
                || ips.len() > 32
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

pub fn normalize_domain(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}
pub fn valid_domain(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip.into()),
        _ => ip,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Outbound {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
impl Outbound {
    pub fn plain(tag: &str, kind: &str) -> Self {
        Self {
            tag: tag.into(),
            kind: kind.into(),
            server: None,
            server_port: None,
            username: None,
            password: None,
        }
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.tag.is_empty()
            || self.tag.len() > 128
            || !self
                .tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(invalid());
        }
        match self.kind.as_str() {
            "direct" | "block"
                if self.server.is_none()
                    && self.server_port.is_none()
                    && self.username.is_none()
                    && self.password.is_none() =>
            {
                Ok(())
            }
            "socks"
                if self
                    .server
                    .is_some_and(|ip| !ip.is_unspecified() && !ip.is_multicast())
                    && self.server_port.is_some_and(|p| p != 0)
                    && self.username.is_some() == self.password.is_some()
                    && [&self.username, &self.password]
                        .iter()
                        .all(|v| v.as_ref().is_none_or(|s| !s.is_empty() && s.len() <= 255)) =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default = "direct", rename = "final")]
    pub final_outbound: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}
impl Default for Route {
    fn default() -> Self {
        Self {
            final_outbound: direct(),
            rules: vec![],
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub outbound: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port_range: Vec<String>,
}

#[derive(Clone, Debug)]
struct Cidr {
    ip: IpAddr,
    prefix: u32,
}
impl Cidr {
    fn parse(s: &str) -> Result<Self, ConfigError> {
        let (ip, prefix) = s.split_once('/').ok_or_else(invalid)?;
        let mut ip: IpAddr = ip.parse().map_err(|_| invalid())?;
        let mut prefix: u32 = prefix.parse().map_err(|_| invalid())?;
        if prefix > if ip.is_ipv4() { 32 } else { 128 } {
            return Err(invalid());
        }
        if let IpAddr::V6(v6) = ip
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            if prefix < 96 {
                return Err(invalid());
            }
            ip = v4.into();
            prefix -= 96;
        }
        Ok(Self { ip, prefix })
    }
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, canonical(ip)) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                (u32::from(a) ^ u32::from(b))
                    .checked_shr(32 - self.prefix)
                    .unwrap_or(0)
                    == 0
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                (u128::from(a) ^ u128::from(b))
                    .checked_shr(128 - self.prefix)
                    .unwrap_or(0)
                    == 0
            }
            _ => false,
        }
    }
}
fn ranges(single: &[u16], ranges: &[String]) -> Result<Vec<(u16, u16)>, ConfigError> {
    let mut result: Vec<_> = single.iter().map(|p| (*p, *p)).collect();
    for s in ranges {
        let (a, b) = s.split_once(['-', ':']).unwrap_or((s, s));
        result.push((
            a.trim().parse().map_err(|_| invalid())?,
            b.trim().parse().map_err(|_| invalid())?,
        ));
    }
    if result.iter().any(|(a, b)| *a == 0 || b < a) {
        return Err(invalid());
    }
    Ok(result)
}

pub struct Policy {
    rules: Vec<CompiledRule>,
    final_outbound: usize,
    pub outbounds: Vec<Outbound>,
}
struct CompiledRule {
    rule: Rule,
    cidrs: Vec<Cidr>,
    sources: Vec<Cidr>,
    ports: Vec<(u16, u16)>,
    source_ports: Vec<(u16, u16)>,
    outbound: usize,
}
impl Policy {
    pub fn new(route: &Route, outbounds: &[Outbound]) -> Result<Self, ConfigError> {
        if outbounds.is_empty() || outbounds.len() > 256 || route.rules.len() > 4096 {
            return Err(invalid());
        }
        let mut tags = BTreeMap::new();
        for (i, outbound) in outbounds.iter().enumerate() {
            outbound.validate()?;
            if tags.insert(outbound.tag.as_str(), i).is_some() {
                return Err(invalid());
            }
        }
        let final_outbound = *tags
            .get(route.final_outbound.as_str())
            .ok_or_else(invalid)?;
        let mut rules = vec![];
        let mut entries = 0;
        for raw in &route.rules {
            entries += raw.domain.len()
                + raw.domain_suffix.len()
                + raw.ip_cidr.len()
                + raw.port.len()
                + raw.port_range.len()
                + raw.network.len()
                + raw.source_ip_cidr.len()
                + raw.source_port.len()
                + raw.source_port_range.len();
            if entries > 16384
                || raw
                    .domain
                    .iter()
                    .chain(&raw.domain_suffix)
                    .any(|s| !valid_domain(s))
                || raw
                    .network
                    .iter()
                    .any(|s| !matches!(s.as_str(), "tcp" | "udp"))
            {
                return Err(invalid());
            }
            let mut rule = raw.clone();
            rule.domain
                .iter_mut()
                .chain(&mut rule.domain_suffix)
                .for_each(|s| *s = normalize_domain(s));
            rules.push(CompiledRule {
                cidrs: raw
                    .ip_cidr
                    .iter()
                    .map(|s| Cidr::parse(s))
                    .collect::<Result<_, _>>()?,
                sources: raw
                    .source_ip_cidr
                    .iter()
                    .map(|s| Cidr::parse(s))
                    .collect::<Result<_, _>>()?,
                ports: ranges(&raw.port, &raw.port_range)?,
                source_ports: ranges(&raw.source_port, &raw.source_port_range)?,
                outbound: *tags.get(raw.outbound.as_str()).ok_or_else(invalid)?,
                rule,
            });
        }
        Ok(Self {
            rules,
            final_outbound,
            outbounds: outbounds.to_vec(),
        })
    }
    /// The caller resolves once and evaluates each actual candidate IP before connecting it.
    pub fn select(
        &self,
        domain: Option<&str>,
        ip: IpAddr,
        port: u16,
        network: &str,
        source: SocketAddr,
    ) -> &Outbound {
        fn has_port(ranges: &[(u16, u16)], p: u16) -> bool {
            ranges.is_empty() || ranges.iter().any(|(a, b)| (*a..=*b).contains(&p))
        }
        for r in &self.rules {
            let address_empty =
                r.rule.domain.is_empty() && r.rule.domain_suffix.is_empty() && r.cidrs.is_empty();
            let domain_match = domain.is_some_and(|s| {
                r.rule.domain.iter().any(|d| s == d)
                    || r.rule.domain_suffix.iter().any(|d| {
                        s == d
                            || s.strip_suffix(d)
                                .is_some_and(|prefix| prefix.ends_with('.'))
                    })
            });
            if (address_empty || domain_match || r.cidrs.iter().any(|c| c.contains(ip)))
                && has_port(&r.ports, port)
                && has_port(&r.source_ports, source.port())
                && (r.sources.is_empty() || r.sources.iter().any(|c| c.contains(source.ip())))
                && (r.rule.network.is_empty() || r.rule.network.iter().any(|n| n == network))
            {
                return &self.outbounds[r.outbound];
            }
        }
        &self.outbounds[self.final_outbound]
    }
}

pub fn from_node(node: &NodeSpec) -> Result<(Route, Vec<Outbound>), ConfigError> {
    let mut outbounds = vec![Outbound::plain("direct", "direct")];
    if !node.routes.is_empty()
        || !node.custom_routes.is_empty()
        || !node.custom_route_rules.is_empty()
        || !node.custom_outbounds.is_empty()
    {
        outbounds.push(Outbound::plain("block", "block"));
    }
    for o in &node.custom_outbounds {
        if o.proxy_tag.as_deref().is_some_and(|s| !s.is_empty()) {
            return Err(invalid());
        }
        let mut settings = if o.settings.is_null() {
            serde_json::Map::new()
        } else {
            o.settings.as_object().ok_or_else(invalid)?.clone()
        };
        if settings.contains_key("tag") || settings.contains_key("type") {
            return Err(invalid());
        }
        settings.insert("tag".into(), o.tag.clone().into());
        settings.insert("type".into(), o.protocol.clone().into());
        outbounds.push(serde_json::from_value(settings.into()).map_err(|_| invalid())?);
    }
    let mut route = Route::default();
    for custom in &node.custom_route_rules {
        if custom.disabled {
            continue;
        }
        let outbound = match custom.action.action_type.as_str() {
            "direct" | "block" if custom.action.target.as_deref().is_none_or(str::is_empty) => {
                custom.action.action_type.clone()
            }
            "route" => custom.action.target.clone().ok_or_else(invalid)?,
            _ => return Err(invalid()),
        };
        let m = &custom.matches;
        let mut groups = vec![];
        if !m.domains.is_empty() {
            groups.push(Rule {
                domain: m.domains.clone(),
                ..Default::default()
            });
        }
        if !m.domain_suffixes.is_empty() {
            groups.push(Rule {
                domain_suffix: m.domain_suffixes.clone(),
                ..Default::default()
            });
        }
        if !m.ip_cidrs.is_empty() {
            groups.push(Rule {
                ip_cidr: m.ip_cidrs.clone(),
                ..Default::default()
            });
        }
        if !m.ports.is_empty() {
            groups.push(Rule {
                port_range: m.ports.clone(),
                ..Default::default()
            });
        }
        if !m.networks.is_empty() {
            groups.push(Rule {
                network: m.networks.clone(),
                ..Default::default()
            });
        }
        if !m.source_cidrs.is_empty() {
            groups.push(Rule {
                source_ip_cidr: m.source_cidrs.clone(),
                ..Default::default()
            });
        }
        if !m.source_ports.is_empty() {
            groups.push(Rule {
                source_port_range: m.source_ports.clone(),
                ..Default::default()
            });
        }
        if groups.is_empty() {
            return Err(invalid());
        }
        for mut r in groups {
            r.outbound = outbound.clone();
            route.rules.push(r);
        }
    }
    for raw in &node.custom_routes {
        route
            .rules
            .push(serde_json::from_value(raw.clone()).map_err(|_| invalid())?);
    }
    for panel in &node.routes {
        if panel.matches.is_empty() {
            continue;
        }
        let outbound = match panel.action.as_str() {
            "direct" | "block" | "reject" if panel.action_value.is_empty() => {
                if panel.action == "direct" {
                    "direct"
                } else {
                    "block"
                }
                .to_owned()
            }
            "proxy" if !panel.action_value.is_empty() => panel.action_value.clone(),
            _ => return Err(invalid()),
        };
        let mut domains = Rule {
            outbound: outbound.clone(),
            ..Default::default()
        };
        let mut ips = Rule {
            outbound,
            ..Default::default()
        };
        for s in &panel.matches {
            let s = s.trim().trim_start_matches("*.");
            if s.contains('/') {
                ips.ip_cidr.push(s.into());
            } else {
                domains.domain_suffix.push(s.into());
            }
        }
        if !domains.domain_suffix.is_empty() {
            route.rules.push(domains);
        }
        if !ips.ip_cidr.is_empty() {
            route.rules.push(ips);
        }
    }
    Policy::new(&route, &outbounds)?;
    Ok((route, outbounds))
}
