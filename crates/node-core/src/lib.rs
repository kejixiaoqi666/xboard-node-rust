use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod traffic;
pub use traffic::{MAX_TRAFFIC_ROWS, TrafficSnapshot};
pub mod routing;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("invalid server port: {0}")]
    InvalidPort(u16),
    #[error("invalid user delta action: {0}")]
    InvalidDeltaAction(String),
    #[error("empty user UUID for id {0}")]
    EmptyUserUuid(i64),
    #[error("duplicate user id: {0}")]
    DuplicateUserId(i64),
    #[error("config serialization failed: {0}")]
    Serialization(String),
    #[error("kernel candidate rejected: {0}")]
    KernelRejected(String),
}

mod state;
pub use state::{AppliedSnapshot, ApplyResult, RuntimeState};

const SUPPORTED_PROTOCOLS: &[&str] = &[
    "anytls",
    "http",
    "hysteria",
    "hysteria2",
    "naive",
    "shadowsocks",
    "socks",
    "trojan",
    "tuic",
    "vless",
    "vmess",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSpec {
    pub protocol: String,
    #[serde(default)]
    pub listen_ip: Option<String>,
    pub server_port: u16,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "networkSettings")]
    pub network_settings: Value,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    #[serde(default)]
    pub kernel_type: Option<String>,
    #[serde(default)]
    pub kernel_log_level: Option<String>,
    #[serde(default)]
    pub custom_outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub custom_routes: Vec<Value>,
    #[serde(default)]
    pub custom_route_rules: Vec<CustomRouteRule>,
    #[serde(default)]
    pub cert_config: Option<Value>,
    #[serde(default)]
    pub auto_tls: bool,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default, rename = "plugin_opts")]
    pub plugin_opt: Option<String>,
    #[serde(default)]
    pub server_key: Option<String>,
    #[serde(default)]
    pub tls: i32,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default)]
    pub tls_settings: Value,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub version: i32,
    #[serde(default)]
    pub up_mbps: i32,
    #[serde(default)]
    pub down_mbps: i32,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, rename = "obfs-password")]
    pub obfs_password: Option<String>,
    #[serde(default)]
    pub congestion_control: Option<String>,
    #[serde(default)]
    pub padding_scheme: Option<StringOrArray>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub traffic_pattern: Option<String>,
    #[serde(default)]
    pub multiplex: Option<MultiplexConfig>,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
}

impl NodeSpec {
    pub fn new(protocol: impl Into<String>, server_port: u16) -> Self {
        Self {
            protocol: protocol.into(),
            listen_ip: None,
            server_port,
            network: None,
            network_settings: Value::Null,
            routes: vec![],
            kernel_type: None,
            kernel_log_level: None,
            custom_outbounds: vec![],
            custom_routes: vec![],
            custom_route_rules: vec![],
            cert_config: None,
            auto_tls: false,
            domain: None,
            cipher: None,
            plugin: None,
            plugin_opt: None,
            server_key: None,
            tls: 0,
            flow: None,
            decryption: None,
            tls_settings: Value::Null,
            host: None,
            server_name: None,
            version: 0,
            up_mbps: 0,
            down_mbps: 0,
            obfs: None,
            obfs_password: None,
            congestion_control: None,
            padding_scheme: None,
            transport: None,
            traffic_pattern: None,
            multiplex: None,
            accept_proxy_protocol: false,
        }
    }
    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = Some(server_name.into());
        self
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        let protocol = self.protocol.trim().to_ascii_lowercase();
        if !SUPPORTED_PROTOCOLS.contains(&protocol.as_str()) {
            return Err(ConfigError::UnsupportedProtocol(self.protocol.clone()));
        }
        if self.server_port == 0 {
            return Err(ConfigError::InvalidPort(self.server_port));
        }
        Ok(())
    }
    pub fn config_hash(&self) -> Result<String, ConfigError> {
        self.validate()?;
        let canonical =
            serde_json::to_vec(self).map_err(|e| ConfigError::Serialization(e.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(canonical)))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum StringOrArray {
    String(String),
    Array(Vec<String>),
}
impl StringOrArray {
    pub fn as_str(&self) -> String {
        match self {
            Self::String(v) => v.clone(),
            Self::Array(v) => v.join("\n"),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    #[serde(default)]
    pub id: i64,
    #[serde(default, rename = "match")]
    pub matches: Vec<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub action_value: String,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConfig {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub settings: Value,
    #[serde(default)]
    pub proxy_tag: Option<String>,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRouteRule {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, rename = "match")]
    pub matches: RouteMatch,
    pub action: RouteAction,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub domain_suffixes: Vec<String>,
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub source_cidrs: Vec<String>,
    #[serde(default)]
    pub source_ports: Vec<String>,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAction {
    #[serde(default, rename = "type")]
    pub action_type: String,
    #[serde(default)]
    pub target: Option<String>,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MultiplexConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub max_connections: i32,
    #[serde(default)]
    pub min_streams: i32,
    #[serde(default)]
    pub max_streams: i32,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub brutal: Option<BrutalConfig>,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrutalConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub up_mbps: i32,
    #[serde(default)]
    pub down_mbps: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSpec {
    pub id: i64,
    pub uuid: String,
    #[serde(default)]
    pub speed_limit: i64,
    #[serde(default)]
    pub device_limit: i64,
}
impl UserSpec {
    pub fn new(id: i64, uuid: impl Into<String>) -> Self {
        Self {
            id,
            uuid: uuid.into(),
            speed_limit: 0,
            device_limit: 0,
        }
    }
    pub fn with_limits(mut self, speed_limit: i64, device_limit: i64) -> Self {
        self.speed_limit = speed_limit;
        self.device_limit = device_limit;
        self
    }
}
pub fn user_hash(users: &[UserSpec]) -> String {
    let mut ordered = users.to_vec();
    ordered.sort_by_key(|u| u.id);
    let mut digest = Sha256::new();
    for user in &ordered {
        digest.update(user.id.to_le_bytes());
        digest.update(user.uuid.as_bytes());
        digest.update(user.speed_limit.to_le_bytes());
        digest.update(user.device_limit.to_le_bytes());
    }
    format!("{:x}", digest.finalize())
}
pub fn apply_user_delta(
    current: Vec<UserSpec>,
    action: &str,
    delta: Vec<UserSpec>,
) -> Result<Vec<UserSpec>, ConfigError> {
    let mut users = current;
    match action {
        "add" => {
            for user in delta {
                if user.uuid.trim().is_empty() {
                    return Err(ConfigError::EmptyUserUuid(user.id));
                }
                if let Some(existing) = users.iter_mut().find(|e| e.id == user.id) {
                    *existing = user;
                } else {
                    users.push(user);
                }
            }
        }
        "remove" => users.retain(|existing| !delta.iter().any(|removed| removed.id == existing.id)),
        _ => return Err(ConfigError::InvalidDeltaAction(action.to_owned())),
    };
    let mut ids = std::collections::HashSet::with_capacity(users.len());
    for user in &users {
        if user.uuid.trim().is_empty() {
            return Err(ConfigError::EmptyUserUuid(user.id));
        }
        if !ids.insert(user.id) {
            return Err(ConfigError::DuplicateUserId(user.id));
        }
    }
    Ok(users)
}
