//! Bounded native routing schema. Structured panel match groups retain Go's OR semantics.
use crate::{ConfigError, NodeSpec};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
};

const RULESET_BYTES: u64 = 32 * 1024 * 1024;
const RULESET_ENTRIES: usize = 200_000;
const MAX_REGEX: usize = 256;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<DnsUpstream>,
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
            upstreams: vec![],
            tcp_only: false,
            strategy: IpStrategy::default(),
            hosts: BTreeMap::new(),
            timeout_ms: timeout(),
            cache_size: cache(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsUpstream {
    pub transport: DnsTransport,
    /// An explicit bootstrap IP prevents encrypted resolver setup from
    /// silently falling back to a different system DNS service.
    pub address: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
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
        if self.servers.len() + self.upstreams.len() > 8
            || self
                .servers
                .iter()
                .any(|s| s.port() == 0 || s.ip().is_unspecified() || s.ip().is_multicast())
            || !(100..=10000).contains(&self.timeout_ms)
            || self.cache_size > 65536
            || self.hosts.len() > 4096
            || (self.tcp_only && self.servers.is_empty() && self.upstreams.is_empty())
        {
            return Err(invalid());
        }
        for server in &self.upstreams {
            let encrypted = matches!(
                server.transport,
                DnsTransport::Tls | DnsTransport::Https | DnsTransport::Quic
            );
            if server.address.port() == 0
                || server.address.ip().is_unspecified()
                || server.address.ip().is_multicast()
                || (encrypted && !server.server_name.as_deref().is_some_and(valid_domain))
                || (!encrypted && (server.server_name.is_some() || server.ca_file.is_some()))
                || (server.path.is_some() && server.transport != DnsTransport::Https)
                || server.path.as_ref().is_some_and(|p| {
                    !p.starts_with('/') || p.len() > 1024 || p.chars().any(char::is_control)
                })
                || server.ca_file.as_deref().is_some_and(|p| !valid_path(p))
            {
                return Err(invalid());
            }
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

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct Outbound {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTls>,
    #[serde(default, alias = "proxy_tag", skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum ProxyAddress {
    Ip(IpAddr),
    Domain(String),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundWire {
    tag: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    server: Option<ProxyAddress>,
    #[serde(default)]
    server_domain: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    tls: Option<OutboundTls>,
    #[serde(default, alias = "proxy_tag")]
    detour: Option<String>,
}
impl<'de> Deserialize<'de> for Outbound {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = OutboundWire::deserialize(deserializer)?;
        let (server, server_domain) = match raw.server {
            Some(ProxyAddress::Ip(ip)) => (Some(ip), raw.server_domain),
            Some(ProxyAddress::Domain(name)) => {
                if raw.server_domain.is_some() {
                    return Err(serde::de::Error::custom("duplicate proxy server domain"));
                }
                (None, Some(name))
            }
            None => (None, raw.server_domain),
        };
        Ok(Self {
            tag: raw.tag,
            kind: raw.kind,
            server,
            server_domain,
            server_port: raw.server_port,
            username: raw.username,
            password: raw.password,
            uuid: raw.uuid,
            method: raw.method,
            tls: raw.tls,
            detour: raw.detour,
        })
    }
}
impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound")
            .field("tag", &self.tag)
            .field("kind", &self.kind)
            .field("server", &self.server)
            .field("server_port", &self.server_port)
            .field("detour", &self.detour)
            .finish_non_exhaustive()
    }
}
fn enabled() -> bool {
    true
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutboundTls {
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
}
impl Outbound {
    pub fn plain(tag: &str, kind: &str) -> Self {
        Self {
            tag: tag.into(),
            kind: kind.into(),
            server: None,
            server_domain: None,
            server_port: None,
            username: None,
            password: None,
            uuid: None,
            method: None,
            tls: None,
            detour: None,
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
        if self
            .detour
            .as_deref()
            .is_some_and(|tag| tag.is_empty() || tag.len() > 128 || tag == self.tag)
            || self.tls.as_ref().is_some_and(|tls| {
                !tls.enabled
                    || tls.server_name.as_deref().is_some_and(|s| !valid_domain(s))
                    || tls.ca_file.as_deref().is_some_and(|p| !valid_path(p))
                    || tls.alpn.len() > 8
                    || tls
                        .alpn
                        .iter()
                        .any(|p| p.is_empty() || p.len() > 255 || !p.is_ascii())
            })
        {
            return Err(invalid());
        }
        let server = (self
            .server
            .is_some_and(|ip| !ip.is_unspecified() && !ip.is_multicast())
            && self.server_domain.is_none()
            || self.server.is_none() && self.server_domain.as_deref().is_some_and(valid_domain))
            && self.server_port.is_some_and(|p| p != 0);
        let no_protocol_credentials = self.uuid.is_none() && self.method.is_none();
        match self.kind.as_str() {
            "direct" | "block"
                if self.server.is_none()
                    && self.server_domain.is_none()
                    && self.server_port.is_none()
                    && self.username.is_none()
                    && self.password.is_none()
                    && no_protocol_credentials
                    && self.tls.is_none()
                    && (self.kind == "direct" || self.detour.is_none()) =>
            {
                Ok(())
            }
            "socks" | "http"
                if server
                    && self.username.is_some() == self.password.is_some()
                    && no_protocol_credentials
                    && [&self.username, &self.password]
                        .iter()
                        .all(|v| v.as_ref().is_none_or(|s| !s.is_empty() && s.len() <= 255)) =>
            {
                Ok(())
            }
            "vless"
                if server
                    && self.uuid.as_deref().is_some_and(valid_uuid)
                    && self.password.is_none()
                    && self.username.is_none()
                    && self.method.is_none() =>
            {
                Ok(())
            }
            "trojan"
                if server
                    && self
                        .password
                        .as_deref()
                        .is_some_and(|p| !p.is_empty() && p.len() <= 4096)
                    && self.username.is_none()
                    && no_protocol_credentials =>
            {
                Ok(())
            }
            "shadowsocks"
                if server
                    && self.password.as_deref().is_some_and(|p| {
                        (!p.is_empty()
                            || matches!(self.method.as_deref(), Some("none" | "plain" | "table")))
                            && p.len() <= 4096
                    })
                    && self.method.as_deref().is_some_and(ss_method)
                    && self.username.is_none()
                    && self.uuid.is_none()
                    && self.tls.is_none() =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}
pub fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn valid_path(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control)
}
fn ss_method(s: &str) -> bool {
    if matches!(
        s,
        "none"
            | "plain"
            | "table"
            | "rc4-md5"
            | "rc4"
            | "chacha20-ietf"
            | "chacha20-ietf-poly1305"
            | "xchacha20-ietf-poly1305"
            | "sm4-gcm"
            | "sm4-ccm"
            | "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305"
            | "2022-blake3-chacha8-poly1305"
    ) {
        return true;
    }
    let mut parts = s.splitn(3, '-');
    let algorithm = parts.next();
    let bits = parts.next();
    let mode = parts.next();
    matches!(algorithm, Some("aes" | "camellia"))
        && matches!(bits, Some("128" | "192" | "256"))
        && matches!(
            mode,
            Some("ctr" | "cfb" | "cfb1" | "cfb8" | "cfb128" | "ofb")
        )
        || algorithm == Some("aes")
            && matches!(bits, Some("128" | "256"))
            && matches!(mode, Some("gcm" | "ccm" | "gcm-siv"))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default = "direct", rename = "final")]
    pub final_outbound: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<RuleSet>,
}
impl Default for Route {
    fn default() -> Self {
        Self {
            final_outbound: direct(),
            rules: vec![],
            rule_set: vec![],
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub outbound: String,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
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
    pub source_ip_rule_set: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port_range: Vec<String>,
}

fn local() -> String {
    "local".into()
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetFormat {
    Source,
    Geoip,
    Geosite,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub tag: String,
    #[serde(default = "local", rename = "type")]
    pub kind: String,
    pub format: RuleSetFormat,
    pub path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
}

fn validate_ruleset(set: &RuleSet) -> Result<(), ConfigError> {
    if set.kind != "local"
        || set.tag.is_empty()
        || set.tag.len() > 128
        || !valid_path(&set.path)
        || set.sha256.len() != 64
        || !set.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || (set.format == RuleSetFormat::Source && set.selector.is_some())
        || (set.format != RuleSetFormat::Source
            && !set
                .selector
                .as_deref()
                .is_some_and(|s| !s.is_empty() && s.len() <= 128 && s.is_ascii()))
    {
        return Err(invalid());
    }
    Ok(())
}
fn verify_ruleset(set: &RuleSet, data: &[u8]) -> Result<(), ConfigError> {
    validate_ruleset(set)?;
    if data.len() as u64 > RULESET_BYTES
        || format!("{:x}", Sha256::digest(data)) != set.sha256.to_ascii_lowercase()
    {
        return Err(invalid());
    }
    Ok(())
}
fn read_ruleset(set: &RuleSet) -> Result<Vec<u8>, ConfigError> {
    validate_ruleset(set)?;
    let file = File::open(&set.path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > RULESET_BYTES {
        return Err(invalid());
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    file.take(RULESET_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| invalid())?;
    verify_ruleset(set, &data)?;
    Ok(data)
}

/// Install a complete, checksum verified snapshot. Parse/compile failures leave
/// the prior file intact; running policies keep their immutable old snapshot.
pub fn install_ruleset_atomic(set: &RuleSet, data: &[u8]) -> Result<(), ConfigError> {
    verify_ruleset(set, data)?;
    compile_ruleset(set, data, &mut CompileBudget::default())?;
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = Path::new(&set.path);
    let parent = path.parent().ok_or_else(invalid)?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(invalid)?;
    let temp = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|_| invalid())?;
    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })()
    .map_err(|_| invalid());
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRuleset {
    version: u8,
    rules: Vec<serde_json::Value>,
}
fn source_rule(mut value: serde_json::Value) -> Result<Rule, ConfigError> {
    let map = value.as_object_mut().ok_or_else(invalid)?;
    for field in [
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
        "port",
        "port_range",
        "network",
        "source_ip_cidr",
        "source_ip_rule_set",
        "source_port",
        "source_port_range",
        "user",
        "inbound",
        "rule_set",
    ] {
        if let Some(v) = map.get_mut(field)
            && !v.is_array()
        {
            *v = serde_json::Value::Array(vec![v.take()]);
        }
    }
    if let Some(v) = map.get_mut("rules") {
        let children = v.as_array_mut().ok_or_else(invalid)?;
        for child in children {
            *child = serde_json::to_value(source_rule(child.take())?).map_err(|_| invalid())?;
        }
    }
    serde_json::from_value(value).map_err(|_| invalid())
}
fn compile_ruleset(
    set: &RuleSet,
    data: &[u8],
    budget: &mut CompileBudget,
) -> Result<Arc<Matcher>, ConfigError> {
    verify_ruleset(set, data)?;
    let raw = match set.format {
        RuleSetFormat::Source => {
            let document: SourceRuleset = serde_json::from_slice(data).map_err(|_| invalid())?;
            if !(1..=5).contains(&document.version)
                || document.rules.is_empty()
                || document.rules.len() > RULESET_ENTRIES
            {
                return Err(invalid());
            }
            document
                .rules
                .into_iter()
                .map(source_rule)
                .collect::<Result<Vec<_>, _>>()?
        }
        RuleSetFormat::Geoip | RuleSetFormat::Geosite => vec![parse_geo(set, data)?],
    };
    let empty = BTreeMap::new();
    Ok(Arc::new(Matcher::Any(
        raw.iter()
            .map(|r| compile_rule(r, &empty, budget, 0, true))
            .collect::<Result<_, _>>()?,
    )))
}

// V2Ray GeoIPList/GeoSiteList protobuf wire reader. No generated object tree:
// each length is checked against a checksum-bound 32 MiB input slice first.
enum ProtoValue<'a> {
    Number(u64),
    Bytes(&'a [u8]),
    Other,
}
fn varint(data: &[u8], pos: &mut usize) -> Result<u64, ConfigError> {
    let mut n = 0;
    for shift in (0..70).step_by(7) {
        let b = *data.get(*pos).ok_or_else(invalid)?;
        *pos += 1;
        if shift == 63 && b > 1 {
            return Err(invalid());
        }
        n |= ((b & 127) as u64) << shift;
        if b & 128 == 0 {
            return Ok(n);
        }
    }
    Err(invalid())
}
fn proto_fields(data: &[u8]) -> Result<Vec<(u32, ProtoValue<'_>)>, ConfigError> {
    let mut pos = 0;
    let mut fields = Vec::new();
    while pos < data.len() {
        let tag = varint(data, &mut pos)?;
        let number = u32::try_from(tag >> 3).map_err(|_| invalid())?;
        if number == 0 || fields.len() >= RULESET_ENTRIES {
            return Err(invalid());
        }
        let value = match tag & 7 {
            0 => ProtoValue::Number(varint(data, &mut pos)?),
            2 => {
                let len = usize::try_from(varint(data, &mut pos)?).map_err(|_| invalid())?;
                let end = pos.checked_add(len).ok_or_else(invalid)?;
                let bytes = data.get(pos..end).ok_or_else(invalid)?;
                pos = end;
                ProtoValue::Bytes(bytes)
            }
            1 | 5 => {
                pos = pos
                    .checked_add(if tag & 7 == 1 { 8 } else { 4 })
                    .ok_or_else(invalid)?;
                if pos > data.len() {
                    return Err(invalid());
                }
                ProtoValue::Other
            }
            _ => return Err(invalid()),
        };
        fields.push((number, value));
    }
    Ok(fields)
}
fn proto_text(data: &[u8]) -> Result<&str, ConfigError> {
    std::str::from_utf8(data).map_err(|_| invalid())
}
fn parse_geo(set: &RuleSet, data: &[u8]) -> Result<Rule, ConfigError> {
    let selector = set.selector.as_deref().ok_or_else(invalid)?;
    let (selector, requested_invert) = selector
        .strip_prefix('!')
        .map_or((selector, false), |s| (s, true));
    if requested_invert && set.format != RuleSetFormat::Geoip {
        return Err(invalid());
    }
    let (code, attribute) = selector
        .split_once('@')
        .map_or((selector, None), |(c, a)| (c, Some(a)));
    if code.is_empty()
        || attribute == Some("")
        || (attribute.is_some() && set.format == RuleSetFormat::Geoip)
    {
        return Err(invalid());
    }
    let mut selected = None;
    for (number, value) in proto_fields(data)? {
        if number != 1 {
            continue;
        }
        let ProtoValue::Bytes(bytes) = value else {
            return Err(invalid());
        };
        let fields = proto_fields(bytes)?;
        let name = fields
            .iter()
            .find_map(|(n, v)| {
                if *n == 1 {
                    if let ProtoValue::Bytes(b) = v {
                        Some(*b)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or_else(invalid)?;
        if !proto_text(name)?.eq_ignore_ascii_case(code) {
            continue;
        }
        if selected.is_some() {
            return Err(invalid());
        }
        let mut rule = Rule::default();
        let mut count = 0;
        for (number, value) in fields {
            if number == 3 && set.format == RuleSetFormat::Geoip {
                if let ProtoValue::Number(v) = value {
                    rule.invert = v != 0;
                } else {
                    return Err(invalid());
                }
            } else if number == 2 {
                count += 1;
                if count > RULESET_ENTRIES {
                    return Err(invalid());
                }
                let ProtoValue::Bytes(bytes) = value else {
                    return Err(invalid());
                };
                if set.format == RuleSetFormat::Geoip {
                    let mut ip = None;
                    let mut prefix = 0u64;
                    for (n, v) in proto_fields(bytes)? {
                        match (n, v) {
                            (1, ProtoValue::Bytes(b)) => {
                                ip = Some(match b.len() {
                                    4 => {
                                        IpAddr::from(<[u8; 4]>::try_from(b).map_err(|_| invalid())?)
                                    }
                                    16 => IpAddr::from(
                                        <[u8; 16]>::try_from(b).map_err(|_| invalid())?,
                                    ),
                                    _ => return Err(invalid()),
                                })
                            }
                            (2, ProtoValue::Number(p)) => prefix = p,
                            _ => {}
                        }
                    }
                    let ip = ip.ok_or_else(invalid)?;
                    rule.ip_cidr.push(format!("{ip}/{prefix}"));
                } else {
                    let mut kind = 0;
                    let mut text = None;
                    let mut attributes = Vec::new();
                    for (n, v) in proto_fields(bytes)? {
                        match (n, v) {
                            (1, ProtoValue::Number(t)) => kind = t,
                            (2, ProtoValue::Bytes(b)) => text = Some(proto_text(b)?.to_owned()),
                            (3, ProtoValue::Bytes(b)) => {
                                let mut key = None;
                                let mut enabled = false;
                                for (n, v) in proto_fields(b)? {
                                    match (n, v) {
                                        (1, ProtoValue::Bytes(b)) => {
                                            key = Some(proto_text(b)?.to_owned())
                                        }
                                        (2, ProtoValue::Number(v)) => enabled = v != 0,
                                        (3, ProtoValue::Number(v)) => enabled = v != 0,
                                        _ => {}
                                    }
                                }
                                if enabled {
                                    attributes.push(key.ok_or_else(invalid)?)
                                }
                            }
                            _ => {}
                        }
                    }
                    if attribute
                        .is_some_and(|a| !attributes.iter().any(|s| s.eq_ignore_ascii_case(a)))
                    {
                        continue;
                    }
                    let text = text.ok_or_else(invalid)?;
                    match kind {
                        0 => rule.domain_keyword.push(text),
                        1 => rule.domain_regex.push(text),
                        2 => rule.domain_suffix.push(text),
                        3 => rule.domain.push(text),
                        _ => return Err(invalid()),
                    }
                }
            }
        }
        if rule.ip_cidr.is_empty()
            && rule.domain.is_empty()
            && rule.domain_suffix.is_empty()
            && rule.domain_keyword.is_empty()
            && rule.domain_regex.is_empty()
        {
            return Err(invalid());
        }
        rule.invert ^= requested_invert;
        selected = Some(rule);
    }
    selected.ok_or_else(invalid)
}

#[derive(Clone, Debug)]
struct Cidr {
    ip: IpAddr,
    prefix: u32,
}
impl Cidr {
    fn parse(s: &str) -> Result<Self, ConfigError> {
        let (ip, prefix) = s.split_once('/').unwrap_or((s, ""));
        let mut ip: IpAddr = ip.parse().map_err(|_| invalid())?;
        let mut prefix: u32 = if prefix.is_empty() {
            if ip.is_ipv4() { 32 } else { 128 }
        } else {
            prefix.parse().map_err(|_| invalid())?
        };
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
            if a.trim().is_empty() {
                1
            } else {
                a.trim().parse().map_err(|_| invalid())?
            },
            if b.trim().is_empty() {
                u16::MAX
            } else {
                b.trim().parse().map_err(|_| invalid())?
            },
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
    matcher: Arc<Matcher>,
    outbound: usize,
}
enum Matcher {
    Any(Vec<Arc<Matcher>>),
    Logical {
        children: Vec<Arc<Matcher>>,
        and: bool,
        invert: bool,
    },
    Default(Box<DefaultMatcher>),
}
struct DefaultMatcher {
    domain: Vec<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    regex: Vec<Regex>,
    cidrs: Vec<Cidr>,
    sources: Vec<Cidr>,
    source_sets: Vec<Arc<Matcher>>,
    ports: Vec<(u16, u16)>,
    source_ports: Vec<(u16, u16)>,
    network: Vec<String>,
    sets: Vec<Arc<Matcher>>,
    user: Vec<String>,
    inbound: Vec<String>,
    invert: bool,
}
#[derive(Clone, Copy, Default)]
pub struct MatchMeta<'a> {
    pub user: Option<&'a str>,
    pub inbound_tag: Option<&'a str>,
}
struct MatchInput<'a> {
    domain: Option<&'a str>,
    ip: IpAddr,
    port: u16,
    network: &'a str,
    source: SocketAddr,
    meta: MatchMeta<'a>,
}
impl Matcher {
    fn ip_only(&self) -> bool {
        match self {
            Self::Any(rules) => !rules.is_empty() && rules.iter().all(|r| r.ip_only()),
            Self::Logical { children, .. } => {
                !children.is_empty() && children.iter().all(|r| r.ip_only())
            }
            Self::Default(r) => {
                !r.cidrs.is_empty()
                    && r.domain.is_empty()
                    && r.suffix.is_empty()
                    && r.keyword.is_empty()
                    && r.regex.is_empty()
                    && r.sources.is_empty()
                    && r.source_sets.is_empty()
                    && r.ports.is_empty()
                    && r.source_ports.is_empty()
                    && r.network.is_empty()
                    && r.sets.is_empty()
                    && r.user.is_empty()
                    && r.inbound.is_empty()
            }
        }
    }
    fn matches(&self, m: &MatchInput<'_>) -> bool {
        fn port(ranges: &[(u16, u16)], p: u16) -> bool {
            ranges.is_empty() || ranges.iter().any(|(a, b)| (*a..=*b).contains(&p))
        }
        match self {
            Self::Any(rules) => rules.iter().any(|r| r.matches(m)),
            Self::Logical {
                children,
                and,
                invert,
            } => {
                (if *and {
                    children.iter().all(|r| r.matches(m))
                } else {
                    children.iter().any(|r| r.matches(m))
                }) ^ *invert
            }
            Self::Default(default) => {
                let DefaultMatcher {
                    domain,
                    suffix,
                    keyword,
                    regex,
                    cidrs,
                    sources,
                    source_sets,
                    ports,
                    source_ports,
                    network,
                    sets,
                    user,
                    inbound,
                    invert,
                } = &**default;
                let address_empty = domain.is_empty()
                    && suffix.is_empty()
                    && keyword.is_empty()
                    && regex.is_empty()
                    && cidrs.is_empty();
                let domain_match = m.domain.is_some_and(|s| {
                    domain.iter().any(|d| s == d)
                        || suffix.iter().any(|d| {
                            if d.starts_with('.') {
                                s.ends_with(d)
                            } else {
                                s == d || s.strip_suffix(d).is_some_and(|p| p.ends_with('.'))
                            }
                        })
                        || keyword.iter().any(|d| s.contains(d))
                        || regex.iter().any(|r| r.is_match(s))
                });
                ((address_empty || domain_match || cidrs.iter().any(|c| c.contains(m.ip)))
                    && port(ports, m.port)
                    && port(source_ports, m.source.port())
                    && ((sources.is_empty() && source_sets.is_empty())
                        || sources.iter().any(|c| c.contains(m.source.ip()))
                        || source_sets.iter().any(|r| {
                            r.matches(&MatchInput {
                                domain: None,
                                ip: m.source.ip(),
                                port: m.port,
                                network: m.network,
                                source: m.source,
                                meta: m.meta,
                            })
                        }))
                    && (network.is_empty() || network.iter().any(|n| n == m.network))
                    && (sets.is_empty() || sets.iter().any(|r| r.matches(m)))
                    && (user.is_empty()
                        || m.meta.user.is_some_and(|u| user.iter().any(|s| s == u)))
                    && (inbound.is_empty()
                        || m.meta
                            .inbound_tag
                            .is_some_and(|u| inbound.iter().any(|s| s == u))))
                    ^ *invert
            }
        }
    }
}
#[derive(Default)]
struct CompileBudget {
    entries: usize,
    regex: usize,
    nodes: usize,
}
fn compile_rule(
    raw: &Rule,
    sets: &BTreeMap<String, Arc<Matcher>>,
    budget: &mut CompileBudget,
    depth: usize,
    headless: bool,
) -> Result<Arc<Matcher>, ConfigError> {
    budget.nodes += 1;
    if depth > 8 || budget.nodes > RULESET_ENTRIES || (headless && !raw.outbound.is_empty()) {
        return Err(invalid());
    }
    let entries = raw.domain.len()
        + raw.domain_suffix.len()
        + raw.domain_keyword.len()
        + raw.domain_regex.len()
        + raw.ip_cidr.len()
        + raw.port.len()
        + raw.port_range.len()
        + raw.network.len()
        + raw.source_ip_cidr.len()
        + raw.source_ip_rule_set.len()
        + raw.source_port.len()
        + raw.source_port_range.len()
        + raw.rule_set.len()
        + raw.user.len()
        + raw.inbound.len();
    budget.entries = budget.entries.checked_add(entries).ok_or_else(invalid)?;
    if budget.entries > RULESET_ENTRIES {
        return Err(invalid());
    }
    if raw.rule_type.as_deref() == Some("logical") {
        if entries != 0
            || raw.rules.is_empty()
            || raw.rules.len() > 4096
            || !matches!(raw.mode.as_deref(), Some("and" | "or"))
        {
            return Err(invalid());
        }
        let children = raw
            .rules
            .iter()
            .map(|r| compile_rule(r, sets, budget, depth + 1, true))
            .collect::<Result<_, _>>()?;
        return Ok(Arc::new(Matcher::Logical {
            children,
            and: raw.mode.as_deref() == Some("and"),
            invert: raw.invert,
        }));
    }
    if !matches!(raw.rule_type.as_deref(), None | Some("default"))
        || raw.mode.is_some()
        || !raw.rules.is_empty()
        || raw.domain.iter().any(|s| !valid_domain(s))
        || raw
            .domain_suffix
            .iter()
            .any(|s| !valid_domain(s.strip_prefix('.').unwrap_or(s)))
        || raw
            .user
            .iter()
            .chain(&raw.inbound)
            .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
        || raw
            .domain_keyword
            .iter()
            .any(|s| s.is_empty() || s.len() > 253 || !s.is_ascii())
        || raw
            .network
            .iter()
            .any(|s| !matches!(s.as_str(), "tcp" | "udp"))
    {
        return Err(invalid());
    }
    let mut regex = Vec::new();
    for pattern in &raw.domain_regex {
        budget.regex += 1;
        if budget.regex > MAX_REGEX || pattern.len() > 4096 {
            return Err(invalid());
        }
        regex.push(
            RegexBuilder::new(pattern)
                .size_limit(256 * 1024)
                .dfa_size_limit(64 * 1024)
                .build()
                .map_err(|_| invalid())?,
        );
    }
    let source_sets = raw
        .source_ip_rule_set
        .iter()
        .map(|tag| {
            sets.get(tag)
                .filter(|set| set.ip_only())
                .cloned()
                .ok_or_else(invalid)
        })
        .collect::<Result<_, _>>()?;
    Ok(Arc::new(Matcher::Default(Box::new(DefaultMatcher {
        domain: raw.domain.iter().map(|s| normalize_domain(s)).collect(),
        suffix: raw
            .domain_suffix
            .iter()
            .map(|s| normalize_domain(s))
            .collect(),
        keyword: raw
            .domain_keyword
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        regex,
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
        source_sets,
        ports: ranges(&raw.port, &raw.port_range)?,
        source_ports: ranges(&raw.source_port, &raw.source_port_range)?,
        network: raw.network.clone(),
        sets: raw
            .rule_set
            .iter()
            .map(|tag| sets.get(tag).cloned().ok_or_else(invalid))
            .collect::<Result<_, _>>()?,
        user: raw.user.clone(),
        inbound: raw.inbound.clone(),
        invert: raw.invert,
    }))))
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
        // Reject dangling detours, cycles and overly deep chains during preparation.
        for outbound in outbounds {
            let mut seen = HashSet::new();
            let mut current = outbound;
            while let Some(next) = &current.detour {
                if seen.len() >= 8 || !seen.insert(current.tag.as_str()) {
                    return Err(invalid());
                }
                current = &outbounds[*tags.get(next.as_str()).ok_or_else(invalid)?];
                if current.kind == "block" {
                    return Err(invalid());
                }
            }
        }
        if route.rule_set.len() > 64 {
            return Err(invalid());
        }
        let mut sets = BTreeMap::new();
        let mut files: BTreeMap<(String, String), Arc<[u8]>> = BTreeMap::new();
        let mut bytes = 0u64;
        let mut budget = CompileBudget::default();
        for set in &route.rule_set {
            let key = (set.path.clone(), set.sha256.to_ascii_lowercase());
            let data = if let Some(data) = files.get(&key) {
                data.clone()
            } else {
                let data: Arc<[u8]> = read_ruleset(set)?.into();
                bytes += data.len() as u64;
                files.insert(key, data.clone());
                data
            };
            if bytes > RULESET_BYTES || sets.contains_key(&set.tag) {
                return Err(invalid());
            }
            let matcher = compile_ruleset(set, &data, &mut budget)?;
            sets.insert(set.tag.clone(), matcher);
        }
        let mut rules = vec![];
        let initial_entries = budget.entries;
        for raw in &route.rules {
            let matcher = compile_rule(raw, &sets, &mut budget, 0, false)?;
            if budget.entries - initial_entries > 16384 {
                return Err(invalid());
            }
            rules.push(CompiledRule {
                matcher,
                outbound: *tags.get(raw.outbound.as_str()).ok_or_else(invalid)?,
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
        self.select_with(domain, ip, port, network, source, MatchMeta::default())
    }
    pub fn select_with(
        &self,
        domain: Option<&str>,
        ip: IpAddr,
        port: u16,
        network: &str,
        source: SocketAddr,
        meta: MatchMeta<'_>,
    ) -> &Outbound {
        let normalized = domain.map(normalize_domain);
        let input = MatchInput {
            domain: normalized.as_deref(),
            ip,
            port,
            network,
            source,
            meta,
        };
        for r in &self.rules {
            if r.matcher.matches(&input) {
                return &self.outbounds[r.outbound];
            }
        }
        &self.outbounds[self.final_outbound]
    }
}

fn strings(value: Option<&serde_json::Value>) -> Result<Vec<String>, ConfigError> {
    match value {
        None => Ok(vec![]),
        Some(serde_json::Value::String(s)) => Ok(vec![s.clone()]),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(invalid))
            .collect(),
        _ => Err(invalid()),
    }
}
fn geo_tag(value: &str, format: RuleSetFormat, sets: &[RuleSet]) -> Result<String, ConfigError> {
    sets.iter()
        .find(|set| {
            set.format == format
                && (set.tag == value
                    || set.selector.as_deref().is_some_and(|s| {
                        s.eq_ignore_ascii_case(value.split_once(':').map_or(value, |(_, s)| s))
                    }))
        })
        .map(|set| set.tag.clone())
        .ok_or_else(invalid)
}
/// Translate the supported Xray field-rule subset to the same native matcher.
/// Process/sniff/balancer fields are rejected, rather than silently discarded.
pub fn translate_rule(raw: &serde_json::Value, sets: &[RuleSet]) -> Result<Rule, ConfigError> {
    let map = raw.as_object().ok_or_else(invalid)?;
    if !map.contains_key("outboundTag") {
        return expand_native_geo(source_rule(raw.clone())?, sets);
    }
    if map.keys().any(|s| {
        !matches!(
            s.as_str(),
            "type"
                | "outboundTag"
                | "domain"
                | "ip"
                | "port"
                | "network"
                | "source"
                | "sourcePort"
                | "user"
                | "inboundTag"
        )
    }) || !matches!(
        map.get("type").and_then(|v| v.as_str()),
        None | Some("field")
    ) {
        return Err(invalid());
    }
    let mut rule = Rule {
        outbound: map
            .get("outboundTag")
            .and_then(|v| v.as_str())
            .ok_or_else(invalid)?
            .to_owned(),
        ..Default::default()
    };
    for value in strings(map.get("domain"))? {
        if let Some(s) = value.strip_prefix("full:") {
            rule.domain.push(s.into());
        } else if let Some(s) = value.strip_prefix("domain:") {
            rule.domain_suffix.push(s.into());
        } else if let Some(s) = value.strip_prefix("keyword:") {
            rule.domain_keyword.push(s.into());
        } else if let Some(s) = value.strip_prefix("regexp:") {
            rule.domain_regex.push(s.into());
        } else if value.starts_with("geosite:") {
            rule.rule_set
                .push(geo_tag(&value, RuleSetFormat::Geosite, sets)?);
        } else {
            rule.domain_keyword.push(value);
        }
    }
    for value in strings(map.get("ip"))? {
        if value.starts_with("geoip:") {
            rule.rule_set
                .push(geo_tag(&value, RuleSetFormat::Geoip, sets)?);
        } else {
            rule.ip_cidr.push(value);
        }
    }
    for value in strings(map.get("source"))? {
        if value.starts_with("geoip:") {
            rule.source_ip_rule_set
                .push(geo_tag(&value, RuleSetFormat::Geoip, sets)?);
        } else {
            rule.source_ip_cidr.push(value);
        }
    }
    for (field, result) in [
        ("port", &mut rule.port_range),
        ("sourcePort", &mut rule.source_port_range),
    ] {
        if let Some(value) = map.get(field) {
            let value = if let Some(n) = value.as_u64() {
                n.to_string()
            } else {
                value.as_str().ok_or_else(invalid)?.to_owned()
            };
            result.extend(value.split(',').map(|s| s.trim().to_owned()));
        }
    }
    rule.network = strings(map.get("network"))?
        .iter()
        .flat_map(|s| s.split(',').map(|s| s.trim().to_owned()))
        .collect();
    rule.user = strings(map.get("user"))?;
    rule.inbound = strings(map.get("inboundTag"))?;
    if !rule.rule_set.is_empty()
        && (!rule.domain.is_empty()
            || !rule.domain_suffix.is_empty()
            || !rule.domain_keyword.is_empty()
            || !rule.domain_regex.is_empty()
            || !rule.ip_cidr.is_empty())
    {
        let address = Rule {
            domain: std::mem::take(&mut rule.domain),
            domain_suffix: std::mem::take(&mut rule.domain_suffix),
            domain_keyword: std::mem::take(&mut rule.domain_keyword),
            domain_regex: std::mem::take(&mut rule.domain_regex),
            ip_cidr: std::mem::take(&mut rule.ip_cidr),
            ..Default::default()
        };
        let sets = Rule {
            rule_set: std::mem::take(&mut rule.rule_set),
            ..Default::default()
        };
        let address_or = Rule {
            rule_type: Some("logical".into()),
            mode: Some("or".into()),
            rules: vec![address, sets],
            ..Default::default()
        };
        let outbound = std::mem::take(&mut rule.outbound);
        return Ok(Rule {
            outbound,
            rule_type: Some("logical".into()),
            mode: Some("and".into()),
            rules: vec![address_or, rule],
            ..Default::default()
        });
    }
    Ok(rule)
}
fn combine_geo_address(mut rule: Rule, geos: Vec<String>) -> Rule {
    if geos.is_empty() {
        return rule;
    }
    let address = Rule {
        domain: std::mem::take(&mut rule.domain),
        domain_suffix: std::mem::take(&mut rule.domain_suffix),
        domain_keyword: std::mem::take(&mut rule.domain_keyword),
        domain_regex: std::mem::take(&mut rule.domain_regex),
        ip_cidr: std::mem::take(&mut rule.ip_cidr),
        ..Default::default()
    };
    let mut children = vec![];
    if !address.domain.is_empty()
        || !address.domain_suffix.is_empty()
        || !address.domain_keyword.is_empty()
        || !address.domain_regex.is_empty()
        || !address.ip_cidr.is_empty()
    {
        children.push(address)
    }
    children.push(Rule {
        rule_set: geos,
        ..Default::default()
    });
    let address = Rule {
        rule_type: Some("logical".into()),
        mode: Some("or".into()),
        rules: children,
        ..Default::default()
    };
    let outbound = std::mem::take(&mut rule.outbound);
    let invert = rule.invert;
    rule.invert = false;
    Rule {
        outbound,
        invert,
        rule_type: Some("logical".into()),
        mode: Some("and".into()),
        rules: vec![address, rule],
        ..Default::default()
    }
}
fn expand_native_geo(mut rule: Rule, sets: &[RuleSet]) -> Result<Rule, ConfigError> {
    if rule.rule_type.as_deref() == Some("logical") {
        rule.rules = rule
            .rules
            .into_iter()
            .map(|r| expand_native_geo(r, sets))
            .collect::<Result<_, _>>()?;
        return Ok(rule);
    }
    let mut geos = vec![];
    for values in [&mut rule.domain, &mut rule.domain_suffix] {
        let mut regular = vec![];
        for value in std::mem::take(values) {
            if value.starts_with("geosite:") {
                geos.push(geo_tag(&value, RuleSetFormat::Geosite, sets)?)
            } else {
                regular.push(value)
            }
        }
        *values = regular;
    }
    let mut ips = vec![];
    for value in std::mem::take(&mut rule.ip_cidr) {
        if value.starts_with("geoip:") {
            geos.push(geo_tag(&value, RuleSetFormat::Geoip, sets)?)
        } else {
            ips.push(value)
        }
    }
    rule.ip_cidr = ips;
    let mut sources = vec![];
    for value in std::mem::take(&mut rule.source_ip_cidr) {
        if value.starts_with("geoip:") {
            rule.source_ip_rule_set
                .push(geo_tag(&value, RuleSetFormat::Geoip, sets)?)
        } else {
            sources.push(value)
        }
    }
    rule.source_ip_cidr = sources;
    Ok(combine_geo_address(rule, geos))
}
fn xray_outbound(
    kind: &str,
    settings: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>, ConfigError> {
    let key = if kind == "vless" { "vnext" } else { "servers" };
    if settings.len() != 1 {
        return Err(invalid());
    }
    let servers = settings
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(invalid)?;
    if servers.len() != 1 {
        return Err(invalid());
    }
    let server = servers[0].as_object().ok_or_else(invalid)?;
    let address = server
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(invalid)?;
    let port = server
        .get("port")
        .and_then(|v| v.as_u64())
        .filter(|p| *p > 0 && *p <= 65535)
        .ok_or_else(invalid)?;
    let mut result = serde_json::Map::new();
    if address.parse::<IpAddr>().is_ok() {
        result.insert("server".into(), address.into());
    } else if valid_domain(address) {
        result.insert("server_domain".into(), address.into());
    } else {
        return Err(invalid());
    }
    result.insert("server_port".into(), port.into());
    let mut allowed = vec!["address", "port"];
    match kind {
        "socks" | "http" | "vless" => {
            allowed.push("users");
            let users = server
                .get("users")
                .map(|v| v.as_array().ok_or_else(invalid))
                .transpose()?;
            if let Some(users) = users {
                if users.len() > 1 || kind == "vless" && users.is_empty() {
                    return Err(invalid());
                }
                if let Some(user) = users.first() {
                    let user = user.as_object().ok_or_else(invalid)?;
                    if kind == "vless" {
                        if user.keys().any(|s| {
                            !matches!(s.as_str(), "id" | "encryption" | "flow" | "level" | "email")
                        }) || user
                            .get("encryption")
                            .is_some_and(|v| v.as_str() != Some("none"))
                            || user.get("flow").is_some_and(|v| v.as_str() != Some(""))
                        {
                            return Err(invalid());
                        }
                        result.insert("uuid".into(), user.get("id").cloned().ok_or_else(invalid)?);
                    } else {
                        if user
                            .keys()
                            .any(|s| !matches!(s.as_str(), "user" | "pass" | "level" | "email"))
                        {
                            return Err(invalid());
                        }
                        result.insert(
                            "username".into(),
                            user.get("user").cloned().ok_or_else(invalid)?,
                        );
                        result.insert(
                            "password".into(),
                            user.get("pass").cloned().ok_or_else(invalid)?,
                        );
                    }
                    if user.get("level").is_some_and(|v| v.as_u64() != Some(0))
                        || user.get("email").is_some_and(|v| {
                            !v.as_str()
                                .is_some_and(|s| s.len() <= 256 && !s.chars().any(char::is_control))
                        })
                    {
                        return Err(invalid());
                    }
                }
            } else if kind == "vless" {
                return Err(invalid());
            }
        }
        "trojan" | "shadowsocks" => {
            allowed.extend(["password", "level", "email"]);
            if server.get("level").is_some_and(|v| v.as_u64() != Some(0))
                || server.get("email").is_some_and(|v| {
                    !v.as_str()
                        .is_some_and(|s| s.len() <= 256 && !s.chars().any(char::is_control))
                })
            {
                return Err(invalid());
            }
            result.insert(
                "password".into(),
                server.get("password").cloned().ok_or_else(invalid)?,
            );
            if kind == "shadowsocks" {
                allowed.push("method");
                result.insert(
                    "method".into(),
                    server.get("method").cloned().ok_or_else(invalid)?,
                );
            }
        }
        _ => return Err(invalid()),
    }
    if server.keys().any(|s| !allowed.contains(&s.as_str())) {
        return Err(invalid());
    }
    Ok(result)
}
/// Expand legacy Geo references into checksum-bound local snapshots before
/// native config generation. No network access or fallback country matching.
pub fn discover_geo_rulesets(
    node: &NodeSpec,
    directory: &Path,
) -> Result<Vec<RuleSet>, ConfigError> {
    fn collect<'a>(
        values: impl IntoIterator<Item = &'a String>,
        references: &mut std::collections::BTreeSet<String>,
    ) -> Result<(), ConfigError> {
        for value in values {
            if value.starts_with("geoip:") || value.starts_with("geosite:") {
                if value.len() > 128
                    || value.len() <= value.find(':').ok_or_else(invalid)? + 1
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_:!@.".contains(&b))
                {
                    return Err(invalid());
                }
                references.insert(value.to_ascii_lowercase());
                if references.len() > 64 {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
    fn walk(
        value: &serde_json::Value,
        references: &mut std::collections::BTreeSet<String>,
        depth: usize,
    ) -> Result<(), ConfigError> {
        if depth > 8 {
            return Err(invalid());
        }
        let map = value.as_object().ok_or_else(invalid)?;
        for key in [
            "domain",
            "domain_suffix",
            "ip",
            "ip_cidr",
            "source",
            "source_ip_cidr",
            "rule_set",
            "source_ip_rule_set",
        ] {
            let values = strings(map.get(key))?;
            collect(&values, references)?;
        }
        if let Some(children) = map.get("rules") {
            for child in children.as_array().ok_or_else(invalid)? {
                walk(child, references, depth + 1)?;
            }
        }
        Ok(())
    }
    let mut references = std::collections::BTreeSet::new();
    for route in &node.routes {
        let values = route
            .matches
            .iter()
            .map(|s| s.trim().trim_start_matches("*.").to_owned())
            .collect::<Vec<_>>();
        collect(&values, &mut references)?;
    }
    for rule in &node.custom_routes {
        walk(rule, &mut references, 0)?;
    }
    for rule in &node.custom_route_rules {
        if !rule.disabled {
            let m = &rule.matches;
            collect(
                m.domains
                    .iter()
                    .chain(&m.domain_suffixes)
                    .chain(&m.ip_cidrs)
                    .chain(&m.source_cidrs),
                &mut references,
            )?;
        }
    }
    if references.is_empty() {
        return Ok(vec![]);
    }
    let directory = directory
        .canonicalize()
        .map_err(|_| ConfigError::KernelRejected("missing Geo data directory".into()))?;
    if !directory.is_dir() {
        return Err(invalid());
    }
    let mut files: BTreeMap<String, Arc<[u8]>> = BTreeMap::new();
    let mut total = 0u64;
    let mut budget = CompileBudget::default();
    let mut result = Vec::new();
    for reference in references {
        let (prefix, selector) = reference.split_once(':').ok_or_else(invalid)?;
        let format = if prefix == "geoip" {
            RuleSetFormat::Geoip
        } else {
            RuleSetFormat::Geosite
        };
        let path = directory.join(if prefix == "geoip" {
            "geoip.dat"
        } else {
            "geosite.dat"
        });
        let path = path.to_str().ok_or_else(invalid)?.to_owned();
        let data = if let Some(data) = files.get(&path) {
            data.clone()
        } else {
            let file = File::open(&path)
                .map_err(|_| ConfigError::KernelRejected("missing Geo data file".into()))?;
            let metadata = file.metadata().map_err(|_| invalid())?;
            if !metadata.is_file()
                || metadata.len() > RULESET_BYTES
                || total.checked_add(metadata.len()).ok_or_else(invalid)? > RULESET_BYTES
            {
                return Err(invalid());
            }
            let mut data = Vec::with_capacity(metadata.len() as usize);
            file.take(RULESET_BYTES + 1)
                .read_to_end(&mut data)
                .map_err(|_| invalid())?;
            total += data.len() as u64;
            if total > RULESET_BYTES {
                return Err(invalid());
            }
            let data: Arc<[u8]> = data.into();
            files.insert(path.clone(), data.clone());
            data
        };
        let set = RuleSet {
            tag: reference.clone(),
            kind: local(),
            format,
            path,
            sha256: format!("{:x}", Sha256::digest(&data)),
            selector: Some(selector.to_owned()),
        };
        compile_ruleset(&set, &data, &mut budget)?;
        result.push(set);
    }
    Ok(result)
}
pub fn from_node(node: &NodeSpec) -> Result<(Route, Vec<Outbound>), ConfigError> {
    from_node_with_rulesets(node, &[])
}
pub fn from_node_with_rulesets(
    node: &NodeSpec,
    sets: &[RuleSet],
) -> Result<(Route, Vec<Outbound>), ConfigError> {
    let mut outbounds = vec![Outbound::plain("direct", "direct")];
    if !node.routes.is_empty()
        || !node.custom_routes.is_empty()
        || !node.custom_route_rules.is_empty()
        || !node.custom_outbounds.is_empty()
    {
        outbounds.push(Outbound::plain("block", "block"));
    }
    for o in &node.custom_outbounds {
        let mut settings = if o.settings.is_null() {
            serde_json::Map::new()
        } else {
            o.settings.as_object().ok_or_else(invalid)?.clone()
        };
        let kind = match o.protocol.as_str() {
            "freedom" => "direct",
            "blackhole" => "block",
            s => s,
        };
        if settings.contains_key("servers") || settings.contains_key("vnext") {
            settings = xray_outbound(kind, settings)?;
        } else if kind == "block" && settings.get("response").is_some() {
            if settings.len() != 1
                || settings.get("response") != Some(&serde_json::json!({"type":"none"}))
            {
                return Err(invalid());
            }
            settings.clear();
        }
        if let Some(serde_json::Value::String(server)) = settings.get("server")
            && server.parse::<IpAddr>().is_err()
        {
            if settings.contains_key("server_domain") || !valid_domain(server) {
                return Err(invalid());
            }
            let server = server.clone();
            settings.remove("server");
            settings.insert("server_domain".into(), server.into());
        }
        if settings.contains_key("tag") || settings.contains_key("type") {
            return Err(invalid());
        }
        settings.insert("tag".into(), o.tag.clone().into());
        settings.insert("type".into(), kind.into());
        if let Some(tag) = o.proxy_tag.as_ref().filter(|s| !s.is_empty()) {
            if settings.contains_key("detour") || settings.contains_key("proxy_tag") {
                return Err(invalid());
            }
            settings.insert("detour".into(), tag.clone().into());
        }
        outbounds.push(serde_json::from_value(settings.into()).map_err(|_| invalid())?);
    }
    let mut route = Route {
        rule_set: sets.to_vec(),
        ..Route::default()
    };
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
        let domains = m
            .domains
            .iter()
            .filter(|s| !s.starts_with("geosite:"))
            .cloned()
            .collect::<Vec<_>>();
        let suffixes = m
            .domain_suffixes
            .iter()
            .filter(|s| !s.starts_with("geosite:"))
            .cloned()
            .collect::<Vec<_>>();
        let ips = m
            .ip_cidrs
            .iter()
            .filter(|s| !s.starts_with("geoip:"))
            .cloned()
            .collect::<Vec<_>>();
        let sources = m
            .source_cidrs
            .iter()
            .filter(|s| !s.starts_with("geoip:"))
            .cloned()
            .collect::<Vec<_>>();
        let geo = m
            .domains
            .iter()
            .chain(&m.domain_suffixes)
            .filter(|s| s.starts_with("geosite:"))
            .map(|s| geo_tag(s, RuleSetFormat::Geosite, sets))
            .chain(
                m.ip_cidrs
                    .iter()
                    .filter(|s| s.starts_with("geoip:"))
                    .map(|s| geo_tag(s, RuleSetFormat::Geoip, sets)),
            )
            .collect::<Result<Vec<_>, _>>()?;
        let source_geo = m
            .source_cidrs
            .iter()
            .filter(|s| s.starts_with("geoip:"))
            .map(|s| geo_tag(s, RuleSetFormat::Geoip, sets))
            .collect::<Result<Vec<_>, _>>()?;
        if !geo.is_empty() {
            groups.push(Rule {
                rule_set: geo,
                ..Default::default()
            });
        }
        if !source_geo.is_empty() {
            groups.push(Rule {
                source_ip_rule_set: source_geo,
                ..Default::default()
            });
        }
        if !domains.is_empty() {
            groups.push(Rule {
                domain: domains,
                ..Default::default()
            });
        }
        if !suffixes.is_empty() {
            groups.push(Rule {
                domain_suffix: suffixes,
                ..Default::default()
            });
        }
        if !ips.is_empty() {
            groups.push(Rule {
                ip_cidr: ips,
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
        if !sources.is_empty() {
            groups.push(Rule {
                source_ip_cidr: sources,
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
        route.rules.push(translate_rule(raw, &route.rule_set)?);
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
        let mut geo = Rule {
            outbound: outbound.clone(),
            ..Default::default()
        };
        let mut ips = Rule {
            outbound,
            ..Default::default()
        };
        for s in &panel.matches {
            let s = s.trim().trim_start_matches("*.");
            if s.starts_with("geoip:") {
                geo.rule_set.push(geo_tag(s, RuleSetFormat::Geoip, sets)?);
            } else if s.starts_with("geosite:") {
                geo.rule_set.push(geo_tag(s, RuleSetFormat::Geosite, sets)?);
            } else if let Ok(ip) = s.parse::<IpAddr>() {
                let ip = canonical(ip);
                ips.ip_cidr
                    .push(format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }));
            } else if s.contains('/') {
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
        if !geo.rule_set.is_empty() {
            route.rules.push(geo);
        }
    }
    Policy::new(&route, &outbounds)?;
    Ok((route, outbounds))
}
