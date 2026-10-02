use crate::{Error, auth::Snapshot};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, net::IpAddr, path::Path, sync::Arc};

pub const MAX_CONFIG: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub enabled: bool,
    pub certificate_path: String,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Log {
    level: String,
    timestamp: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outbound {
    #[serde(rename = "type")]
    kind: String,
    tag: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    #[serde(rename = "final")]
    final_outbound: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    inbounds: Vec<Inbound>,
    outbounds: Vec<Outbound>,
    route: Route,
    log: Log,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Trojan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base {
    pub protocol: Protocol,
    pub tag: String,
    pub listen: IpAddr,
    pub port: u16,
    pub tls: Option<Tls>,
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
        || config.outbounds.len() != 1
        || config.outbounds[0].kind != "direct"
        || config.outbounds[0].tag != "direct"
        || config.route.final_outbound != "direct"
        || !matches!(
            config.log.level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic"
        )
    {
        return Err(Error::Unsupported);
    }
    let inbound = config.inbounds.pop().ok_or(Error::Config)?;
    if inbound.tag.is_empty() || inbound.listen_port == 0 {
        return Err(Error::Config);
    }
    let protocol = match inbound.kind.as_str() {
        "vless" => Protocol::Vless,
        "trojan" => Protocol::Trojan,
        _ => return Err(Error::Unsupported),
    };
    if protocol == Protocol::Trojan && inbound.tls.is_none() {
        return Err(Error::Unsupported);
    }
    if let Some(tls) = &inbound.tls
        && (!tls.enabled
            || !Path::new(&tls.certificate_path).is_absolute()
            || !Path::new(&tls.key_path).is_absolute())
    {
        return Err(Error::Config);
    }
    let auth = Arc::new(Snapshot::new(protocol, inbound.users)?);
    Ok(Candidate {
        base: Base {
            protocol,
            tag: inbound.tag,
            listen: inbound.listen,
            port: inbound.listen_port,
            tls: inbound.tls,
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
