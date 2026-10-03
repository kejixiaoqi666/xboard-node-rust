//! Bounded REALITY panel/native settings; private material is redacted in Debug.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub private_key: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub short_id: ShortIds,
    #[serde(default)]
    pub dest: Option<String>,
    pub server_name: String,
    #[serde(default = "port")]
    pub server_port: u16,
    #[serde(default = "age")]
    pub max_time_diff: u64,
    /// Maximum non-KeyUpdate records sent with one application traffic key.
    #[serde(default = "key_update_records")]
    pub key_update_after_records: u64,
    #[serde(default)]
    pub min_client_version: Option<[u8; 3]>,
    #[serde(default)]
    pub max_client_version: Option<[u8; 3]>,
}
pub const MAX_KEY_UPDATE_RECORDS: u64 = 1 << 20;
pub const MIN_KEY_UPDATE_RECORDS: u64 = 16;
fn key_update_records() -> u64 {
    MAX_KEY_UPDATE_RECORDS
}
fn port() -> u16 {
    443
}
fn age() -> u64 {
    300_000
}
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealitySettings")
            .field("private_key", &"[REDACTED]")
            .field("server_name", &self.server_name)
            .field("dest", &self.dest)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ShortIds {
    One(String),
    Many(Vec<String>),
}
impl Default for ShortIds {
    fn default() -> Self {
        Self::One(String::new())
    }
}
impl ShortIds {
    pub fn values(&self) -> Vec<&str> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(s) => s.iter().map(String::as_str).collect(),
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        let valid_key =
            |s: &str| s.len() == 43 && URL_SAFE_NO_PAD.decode(s).is_ok_and(|b| b.len() == 32);
        if !valid_key(&self.private_key)
            || self.public_key.as_deref().is_some_and(|s| !valid_key(s))
            || !crate::routing::valid_domain(&self.server_name)
            || self.server_port == 0
            || self.max_time_diff > 3_600_000
            || !(MIN_KEY_UPDATE_RECORDS..=MAX_KEY_UPDATE_RECORDS)
                .contains(&self.key_update_after_records)
            || self
                .min_client_version
                .zip(self.max_client_version)
                .is_some_and(|(a, b)| a > b)
        {
            return Err("invalid REALITY settings");
        }
        let ids = self.short_id.values();
        if ids.is_empty()
            || ids.len() > 16
            || ids.iter().any(|s| {
                s.len() > 16 || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit())
            })
        {
            return Err("invalid REALITY short IDs");
        }
        self.endpoint()?;
        Ok(())
    }
    pub fn endpoint(&self) -> Result<(String, u16), &'static str> {
        let s = self.dest.as_deref().unwrap_or(&self.server_name);
        if s.is_empty() || s.trim() != s || s.len() > 300 {
            return Err("invalid REALITY destination");
        }
        if let Ok(a) = s.parse::<SocketAddr>() {
            if a.port() == 0 {
                return Err("invalid REALITY destination");
            }
            return Ok((a.ip().to_string(), a.port()));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok((ip.to_string(), self.server_port));
        }
        let (host, port) = match s.rsplit_once(':') {
            Some((h, p)) => (
                h,
                p.parse::<u16>()
                    .map_err(|_| "invalid REALITY destination")?,
            ),
            None => (s, self.server_port),
        };
        if port == 0 || !crate::routing::valid_domain(host) {
            return Err("invalid REALITY destination");
        }
        Ok((host.to_string(), port))
    }
}
