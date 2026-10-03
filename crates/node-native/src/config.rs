use crate::{Error, auth::Snapshot};
use node_core::routing::{DnsConfig, Outbound, Policy, Route};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, net::IpAddr, path::Path, sync::Arc};

pub const MAX_CONFIG: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub enabled: bool,
    #[serde(default)]
    pub reality: Option<node_core::reality::Settings>,
    #[serde(default)]
    pub certificate_path: String,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub speed_limit: i64,
    #[serde(default)]
    pub device_limit: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inbound {
    #[serde(rename = "type")]
    kind: String,
    tag: String,
    listen: IpAddr,
    listen_port: u16,
    #[serde(default)]
    tls: Option<Tls>,
    users: Vec<User>,
    #[serde(default)]
    method: Option<node_core::shadowsocks::Cipher>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    quic: Option<Quic>,
    #[serde(default)]
    extended: Option<Extended>,
    #[serde(default)]
    transport: Option<Transport>,
    #[serde(default)]
    plugin: Option<Plugin>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Log {
    level: String,
    timestamp: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    dns: Option<DnsConfig>,
    inbounds: Vec<Inbound>,
    outbounds: Vec<Outbound>,
    route: Route,
    log: Log,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Trojan,
    Shadowsocks,
    Vmess,
    AnyTls,
    Hysteria2,
    Tuic,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default = "default_early_data")]
    pub max_early_data: usize,
    #[serde(default)]
    pub plugin_mux: bool,
}
fn default_early_data() -> usize {
    2048
}
#[derive(Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plugin {
    pub binary: std::path::PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub options: Option<String>,
}
impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("binary", &self.binary)
            .field("options", &"[REDACTED]")
            .finish()
    }
}
impl Plugin {
    fn validate(&self) -> Result<(), Error> {
        if !self.binary.is_absolute()
            || !std::fs::symlink_metadata(&self.binary).is_ok_and(|meta| meta.is_file())
            || self.arguments.len() > 64
            || self
                .arguments
                .iter()
                .any(|arg| arg.len() > 4096 || arg.contains('\0'))
            || self
                .options
                .as_ref()
                .is_some_and(|options| options.len() > 16384 || options.contains('\0'))
        {
            return Err(Error::Config);
        }
        Ok(())
    }
    pub fn sip003(&self) -> node_extended::sip003::Sip003Config {
        node_extended::sip003::Sip003Config {
            binary: self.binary.clone(),
            arguments: self
                .arguments
                .iter()
                .map(std::ffi::OsString::from)
                .collect(),
            options: self.options.as_ref().map(std::ffi::OsString::from),
        }
    }
}
impl Transport {
    fn validate(&self, protocol: Protocol, tls: Option<&Tls>) -> Result<(), Error> {
        if !matches!(self.kind.as_str(), "ws" | "httpupgrade" | "http2" | "grpc")
            || !(matches!(
                protocol,
                Protocol::Vless | Protocol::Vmess | Protocol::Trojan
            ) || protocol == Protocol::Shadowsocks && self.kind == "ws")
            || self.plugin_mux && !(protocol == Protocol::Shadowsocks && self.kind == "ws")
            || tls.is_some_and(|tls| tls.reality.is_some())
            || self.max_early_data > 2048
            || self.path.as_ref().is_some_and(|path| {
                !path.starts_with('/') || path.len() > 2048 || path.chars().any(char::is_control)
            })
            || self.hosts.len() > 16
            || self.host.iter().chain(self.hosts.iter()).any(|host| {
                host.is_empty()
                    || host.len() > 253
                    || !host.is_ascii()
                    || host.chars().any(|c| c.is_control() || c.is_whitespace())
            })
            || self.method.as_ref().is_some_and(|method| {
                method.is_empty()
                    || method.len() > 16
                    || !method.bytes().all(|c| c.is_ascii_uppercase())
            })
            || self.kind != "http2" && (!self.hosts.is_empty() || self.method.is_some())
            || self.kind != "grpc" && self.service_name.is_some()
            || self.kind == "grpc"
                && self.service_name.as_ref().is_none_or(|service| {
                    service.len() > 128
                        || !service
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
                })
            || self.kind != "ws" && self.max_early_data != 2048
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    pub fn websocket(&self) -> node_extended::websocket::WebSocketConfig {
        node_extended::websocket::WebSocketConfig {
            path: self.path.clone(),
            host: self.host.clone(),
            max_early_data: self.max_early_data,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Quic {
    #[serde(default)]
    pub obfs_password: Option<String>,
    #[serde(default = "default_congestion")]
    pub congestion_control: String,
    #[serde(default)]
    pub allow_0rtt: bool,
    #[serde(default = "default_udp")]
    pub enable_udp: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Extended {
    pub vmess_security: String,
    pub padding_scheme: Option<node_core::StringOrArray>,
    pub max_sessions: Option<usize>,
    pub multiplex_enabled: Option<bool>,
}
impl Extended {
    pub fn config(&self) -> Result<node_extended::Config, Error> {
        let mut config = node_extended::Config {
            vmess_security: match self.vmess_security.as_str() {
                "" | "any" | "auto" => node_extended::vmess::Security::Any,
                "aes-128-gcm" => node_extended::vmess::Security::Aes128Gcm,
                "chacha20-poly1305" => node_extended::vmess::Security::ChaCha20Poly1305,
                "none" => node_extended::vmess::Security::None,
                _ => return Err(Error::Config),
            },
            ..Default::default()
        };
        if let Some(enabled) = self.multiplex_enabled {
            config.multiplex_enabled = enabled;
        }
        if let Some(max) = self.max_sessions {
            if max == 0 || max > 1024 {
                return Err(Error::Config);
            }
            config.max_sessions = max;
        }
        if let Some(scheme) = &self.padding_scheme {
            let text = match scheme {
                node_core::StringOrArray::String(value) => value.clone(),
                node_core::StringOrArray::Array(values) => values.join("\n"),
            };
            if text.len() > 16384 {
                return Err(Error::Config);
            }
            config.anytls_padding = Arc::new(
                node_extended::anytls::anytls_padding::PaddingFactory::new(text.as_bytes())
                    .map_err(|_| Error::Config)?,
            );
        }
        Ok(config)
    }
}
fn default_congestion() -> String {
    "cubic".into()
}
fn default_udp() -> bool {
    true
}
impl Default for Quic {
    fn default() -> Self {
        Self {
            obfs_password: None,
            congestion_control: default_congestion(),
            allow_0rtt: false,
            enable_udp: true,
        }
    }
}
impl Quic {
    fn validate(&self, protocol: Protocol) -> Result<(), Error> {
        if !matches!(
            self.congestion_control.as_str(),
            "cubic" | "new_reno" | "bbr"
        ) || self
            .obfs_password
            .as_ref()
            .is_some_and(|p| p.is_empty() || p.len() > 1024 || protocol != Protocol::Hysteria2)
            || self.allow_0rtt && protocol != Protocol::Tuic
        {
            return Err(Error::Config);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base {
    pub dns: Option<DnsConfig>,
    pub route: Route,
    pub outbounds: Vec<Outbound>,
    pub protocol: Protocol,
    pub tag: String,
    pub listen: IpAddr,
    pub port: u16,
    pub tls: Option<Tls>,
    pub shadowsocks: Option<node_core::shadowsocks::Settings>,
    pub quic: Option<Quic>,
    pub extended: Option<Extended>,
    pub transport: Option<Transport>,
    pub plugin: Option<Plugin>,
    log: Log,
}

pub struct Candidate {
    pub base: Base,
    pub auth: Arc<Snapshot>,
    pub digest: String,
}

pub fn read_candidate(path: &Path) -> Result<Candidate, Error> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| Error::Config)?;
    if !path.is_absolute() || !meta.is_file() || meta.len() > MAX_CONFIG as u64 {
        return Err(Error::Config);
    }
    let data = read_bounded(path, MAX_CONFIG)?;
    decode(&data)
}

pub fn decode(data: &[u8]) -> Result<Candidate, Error> {
    if data.len() > MAX_CONFIG {
        return Err(Error::Config);
    }
    let mut config: Config = serde_json::from_slice(data).map_err(|_| Error::Config)?;
    if config.inbounds.len() != 1
        || !matches!(
            config.log.level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic"
        )
    {
        return Err(Error::Unsupported);
    }
    Policy::new(&config.route, &config.outbounds).map_err(|_| Error::Config)?;
    if let Some(dns) = &config.dns {
        dns.validate().map_err(|_| Error::Config)?;
    }
    let inbound = config.inbounds.pop().ok_or(Error::Config)?;
    if inbound.tag.is_empty() || inbound.listen_port == 0 {
        return Err(Error::Config);
    }
    let protocol = match inbound.kind.as_str() {
        "vless" => Protocol::Vless,
        "trojan" => Protocol::Trojan,
        "shadowsocks" => Protocol::Shadowsocks,
        "vmess" => Protocol::Vmess,
        "anytls" => Protocol::AnyTls,
        "hysteria2" => Protocol::Hysteria2,
        "tuic" => Protocol::Tuic,
        _ => return Err(Error::Unsupported),
    };
    if matches!(
        protocol,
        Protocol::Trojan | Protocol::AnyTls | Protocol::Hysteria2 | Protocol::Tuic
    ) && inbound.tls.is_none()
    {
        return Err(Error::Unsupported);
    }
    if let Some(tls) = &inbound.tls {
        if !tls.enabled {
            return Err(Error::Config);
        }
        if let Some(reality) = &tls.reality {
            if protocol != Protocol::Vless
                || !tls.certificate_path.is_empty()
                || !tls.key_path.is_empty()
                || tls
                    .server_name
                    .as_deref()
                    .is_some_and(|s| s != reality.server_name)
            {
                return Err(Error::Unsupported);
            }
            reality.validate().map_err(|_| Error::Config)?;
            crate::reality_config(reality)?;
        } else if !Path::new(&tls.certificate_path).is_absolute()
            || !Path::new(&tls.key_path).is_absolute()
        {
            return Err(Error::Config);
        }
    }
    let shadowsocks = if protocol == Protocol::Shadowsocks {
        if inbound.tls.is_some()
            && !inbound
                .transport
                .as_ref()
                .is_some_and(|transport| transport.kind == "ws")
        {
            return Err(Error::Unsupported);
        }
        let settings = node_core::shadowsocks::Settings {
            method: inbound.method.ok_or(Error::Config)?,
            password: inbound.password,
        };
        settings.validate().map_err(|_| Error::Config)?;
        Some(settings)
    } else {
        if inbound.method.is_some() || inbound.password.is_some() {
            return Err(Error::Unsupported);
        }
        None
    };
    let quic = if matches!(protocol, Protocol::Hysteria2 | Protocol::Tuic) {
        let settings = inbound.quic.unwrap_or_default();
        settings.validate(protocol)?;
        Some(settings)
    } else {
        if inbound.quic.is_some() {
            return Err(Error::Config);
        }
        None
    };
    let extended = if matches!(
        protocol,
        Protocol::Vmess
            | Protocol::AnyTls
            | Protocol::Vless
            | Protocol::Trojan
            | Protocol::Shadowsocks
    ) {
        let settings = inbound.extended.unwrap_or_default();
        settings.config()?;
        Some(settings)
    } else {
        if inbound.extended.is_some() {
            return Err(Error::Config);
        }
        None
    };
    if let Some(transport) = &inbound.transport {
        transport.validate(protocol, inbound.tls.as_ref())?;
    }
    if let Some(plugin) = &inbound.plugin {
        plugin.validate()?;
        if protocol != Protocol::Shadowsocks
            || inbound.transport.is_some()
            || inbound.tls.is_some()
            || inbound.users.iter().any(|user| user.device_limit != 0)
        {
            return Err(Error::Unsupported);
        }
    }
    let mut auth = Snapshot::new(protocol, inbound.users)?;
    if let Some(settings) = &shadowsocks {
        auth.configure_shadowsocks(settings)?;
    }
    let auth = Arc::new(auth);
    if auth.has_vision() && (inbound.tls.is_none() || inbound.transport.is_some()) {
        return Err(Error::Unsupported);
    }
    Ok(Candidate {
        base: Base {
            dns: config.dns,
            route: config.route,
            outbounds: config.outbounds,
            protocol,
            tag: inbound.tag,
            listen: inbound.listen,
            port: inbound.listen_port,
            tls: inbound.tls,
            shadowsocks,
            quic,
            extended,
            transport: inbound.transport,
            plugin: inbound.plugin,
            log: config.log,
        },
        auth,
        digest: format!("{:x}", Sha256::digest(data)),
    })
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| Error::Config)?
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| Error::Config)?;
    if data.len() > limit {
        return Err(Error::Config);
    }
    Ok(data)
}

pub fn tls_config(tls: Option<&Tls>) -> Result<Option<Arc<rustls::ServerConfig>>, Error> {
    let Some(tls) = tls else {
        return Ok(None);
    };
    if tls.reality.is_some() {
        return Ok(None);
    }
    let cert_data = read_bounded(Path::new(&tls.certificate_path), 1024 * 1024)?;
    let key_data = read_bounded(Path::new(&tls.key_path), 1024 * 1024)?;
    let certificates: Vec<_> = CertificateDer::pem_slice_iter(&cert_data)
        .collect::<Result<_, _>>()
        .map_err(|_| Error::Tls)?;
    let key = PrivateKeyDer::from_pem_slice(&key_data).map_err(|_| Error::Tls)?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error::Tls)?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|_| Error::Tls)?;
    Ok(Some(Arc::new(config)))
}
