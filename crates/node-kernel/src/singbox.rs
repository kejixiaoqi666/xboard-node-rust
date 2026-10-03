use crate::KernelError;
use node_core::{NodeSpec, UserSpec};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use std::io::Write;

#[derive(Clone, Debug, Default)]
pub struct SingBoxConfigBuilder {
    native: bool,
    dns: Option<node_core::routing::DnsConfig>,
}

impl SingBoxConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    /// Emit limits only for the embedded Rust kernel that enforces them.
    pub fn native() -> Self {
        Self {
            native: true,
            dns: None,
        }
    }
    pub fn with_dns(mut self, dns: Option<node_core::routing::DnsConfig>) -> Self {
        self.dns = dns;
        self
    }

    pub fn build(&self, node: &NodeSpec, users: &[UserSpec]) -> Result<Value, KernelError> {
        serde_json::to_value(self.serializable(node, users)?)
            .map_err(|e| KernelError::Prepare(format!("encode sing-box config: {e}")))
    }

    /// Encode directly from validated, borrowed users without a full JSON tree.
    pub fn write_json<W: Write>(
        &self,
        writer: W,
        node: &NodeSpec,
        users: &[UserSpec],
    ) -> Result<(), KernelError> {
        serde_json::to_writer(writer, &self.serializable(node, users)?)
            .map_err(|e| KernelError::Prepare(format!("encode sing-box config: {e}")))
    }

    pub(crate) fn serializable<'a>(
        &self,
        node: &'a NodeSpec,
        users: &'a [UserSpec],
    ) -> Result<SingBoxConfig<'a>, KernelError> {
        node.validate()
            .map_err(|e| KernelError::Invalid(e.to_string()))?;
        if !matches!(node.protocol.as_str(), "vless" | "trojan")
            && !(self.native && node.protocol == "shadowsocks")
        {
            return Err(KernelError::Invalid(format!(
                "sing-box tracer supports only vless/trojan, got {}",
                node.protocol
            )));
        }
        // Explicitly reject features this experimental adapter cannot enforce.
        // Comparing the supported subset also guards future NodeSpec additions.
        let ss = if node.protocol == "shadowsocks" {
            let method: node_core::shadowsocks::Cipher = serde_json::from_value(json!(node.cipher))
                .map_err(|_| KernelError::Invalid("unsupported Shadowsocks cipher".into()))?;
            let settings = node_core::shadowsocks::Settings {
                method,
                password: node.server_key.clone(),
            };
            settings
                .validate()
                .map_err(|_| KernelError::Invalid("invalid Shadowsocks server key".into()))?;
            if users.len() > method.max_users() {
                return Err(KernelError::Invalid(
                    "Shadowsocks user limit exceeded".into(),
                ));
            }
            let mut keys = std::collections::HashSet::new();
            for user in users {
                if user.uuid.len() > 1024
                    || !keys.insert(node_core::shadowsocks::user_password(method, &user.uuid))
                {
                    return Err(KernelError::Invalid(
                        "duplicate or oversized Shadowsocks credential".into(),
                    ));
                }
            }
            Some(settings)
        } else {
            None
        };
        let mut supported = NodeSpec::new(&node.protocol, node.server_port);
        supported.listen_ip = node.listen_ip.clone();
        supported.network = node.network.clone();
        supported.kernel_type = node.kernel_type.clone();
        supported.kernel_log_level = node.kernel_log_level.clone();
        supported.tls = node.tls;
        supported.cert_config = node.cert_config.clone();
        supported.server_name = node.server_name.clone();
        if self.native && ss.is_some() {
            supported.cipher = node.cipher.clone();
            supported.server_key = node.server_key.clone();
        }
        if self.native {
            supported.flow = node.flow.clone();
            if node.tls == 2 {
                supported.tls_settings = node.tls_settings.clone();
            }
            supported.routes = node.routes.clone();
            supported.custom_routes = node.custom_routes.clone();
            supported.custom_route_rules = node.custom_route_rules.clone();
            supported.custom_outbounds = node.custom_outbounds.clone();
        }
        if let Some(dns) = &self.dns {
            if !self.native {
                return Err(KernelError::Invalid(
                    "custom DNS requires the native Rust kernel".into(),
                ));
            }
            dns.validate()
                .map_err(|e| KernelError::Invalid(e.to_string()))?;
        }
        if node != &supported
            || node
                .network
                .as_deref()
                .is_some_and(|network| network != "tcp")
            || node
                .kernel_type
                .as_deref()
                .is_some_and(|kernel| !matches!(kernel, "sing-box" | "singbox"))
            || node.kernel_log_level.as_deref().is_some_and(|level| {
                !matches!(
                    level,
                    "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic"
                )
            })
        {
            return Err(KernelError::Invalid(
                "node contains options not supported by the Rust adapter".into(),
            ));
        }
        if !self.native
            && users
                .iter()
                .any(|user| user.speed_limit != 0 || user.device_limit != 0)
        {
            return Err(KernelError::Invalid(
                "speed/device enforcement is not implemented".into(),
            ));
        }
        let tls = match node.tls {
            0 if matches!(node.protocol.as_str(), "vless" | "shadowsocks")
                && node.cert_config.is_none()
                && node.server_name.is_none() =>
            {
                None
            }
            1 => {
                let cert = node
                    .cert_config
                    .as_ref()
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        KernelError::Invalid("TLS requires file certificate configuration".into())
                    })?;
                let mode = cert
                    .get("cert_mode")
                    .or_else(|| cert.get("mode"))
                    .and_then(Value::as_str);
                let path = |key| {
                    cert.get(key)
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                };
                let (Some(certificate), Some(key)) = (path("cert_file"), path("key_file")) else {
                    return Err(KernelError::Invalid(
                        "TLS certificate/key paths are required".into(),
                    ));
                };
                if mode != Some("file")
                    || !std::path::Path::new(certificate).is_absolute()
                    || !std::path::Path::new(key).is_absolute()
                {
                    return Err(KernelError::Invalid(
                        "only TLS with absolute certificate/key file paths is supported".into(),
                    ));
                }
                let mut tls = json!({"enabled":true,"certificate_path":certificate,"key_path":key});
                if let Some(name) = &node.server_name {
                    tls["server_name"] = json!(name);
                }
                Some(tls)
            }
            2 if self.native && node.protocol == "vless" && node.cert_config.is_none() => {
                let settings: node_core::reality::Settings =
                    serde_json::from_value(node.tls_settings.clone())
                        .map_err(|_| KernelError::Invalid("invalid REALITY settings".into()))?;
                settings
                    .validate()
                    .map_err(|_| KernelError::Invalid("invalid REALITY settings".into()))?;
                if node
                    .server_name
                    .as_deref()
                    .is_some_and(|s| s != settings.server_name)
                {
                    return Err(KernelError::Invalid(
                        "conflicting REALITY server names".into(),
                    ));
                }
                Some(json!({"enabled":true,"server_name":settings.server_name,"reality":settings}))
            }
            _ => {
                return Err(KernelError::Invalid(
                    "unsupported TLS mode or incompatible certificate/REALITY settings".into(),
                ));
            }
        };
        let flow = node.flow.as_deref().filter(|flow| !flow.is_empty());
        if flow.is_some_and(|flow| flow != "xtls-rprx-vision")
            || flow.is_some()
                && (!self.native || node.protocol != "vless" || !matches!(node.tls, 1 | 2))
        {
            return Err(KernelError::Invalid(
                "Vision requires native VLESS with file TLS or REALITY".into(),
            ));
        }
        let mut ids = std::collections::HashSet::with_capacity(users.len());
        let vless = node.protocol == "vless";
        let mut uuid_keys =
            std::collections::HashSet::with_capacity(if vless { users.len() } else { 0 });
        let mut passwords =
            std::collections::HashSet::with_capacity(if vless { 0 } else { users.len() });
        for user in users {
            if user.speed_limit < 0
                || user.device_limit < 0
                || u64::try_from(user.speed_limit)
                    .ok()
                    .and_then(|n| n.checked_mul(125_000))
                    .is_none()
                || u32::try_from(user.device_limit).is_err()
            {
                return Err(KernelError::Invalid("invalid speed/device policy".into()));
            }
            if user.uuid.trim().is_empty() {
                return Err(KernelError::Invalid(format!(
                    "empty user UUID for id {}",
                    user.id
                )));
            }
            if !ids.insert(user.id) {
                return Err(KernelError::Invalid(format!(
                    "duplicate user id {}",
                    user.id
                )));
            }
            if vless {
                let key = uuid_key(&user.uuid).ok_or_else(|| {
                    KernelError::Invalid(format!("invalid user UUID for id {}", user.id))
                })?;
                if !uuid_keys.insert(key) {
                    return Err(KernelError::Invalid("duplicate user credential".into()));
                }
            } else if !passwords.insert(user.uuid.as_str()) {
                return Err(KernelError::Invalid("duplicate user credential".into()));
            }
        }
        let (route, outbounds) =
            node_core::routing::from_node(node).map_err(|e| KernelError::Invalid(e.to_string()))?;
        Ok(SingBoxConfig {
            dns: self.dns.clone(),
            inbounds: [Inbound {
                listen: node.listen_ip.as_deref().unwrap_or("::"),
                listen_port: node.server_port,
                tag: if node.protocol == "vless" {
                    "vless-in"
                } else if node.protocol == "shadowsocks" {
                    "shadowsocks-in"
                } else {
                    "trojan-in"
                },
                tls,
                method: ss.as_ref().map(|s| s.method.name()),
                password: ss.as_ref().and(node.server_key.as_deref()),
                kind: &node.protocol,
                users: Users {
                    users,
                    vless: node.protocol == "vless",
                    flow,
                    native: self.native,
                    shadowsocks: ss.as_ref().map(|s| s.method),
                },
            }],
            log: Log {
                level: node.kernel_log_level.as_deref().unwrap_or("info"),
                timestamp: true,
            },
            outbounds,
            route,
        })
    }
}

// Field order matches the original serde_json::Value encoding, including the
// historical string form of user IDs. Only the small TLS object is owned.
#[derive(Serialize)]
pub(crate) struct SingBoxConfig<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<node_core::routing::DnsConfig>,
    inbounds: [Inbound<'a>; 1],
    log: Log<'a>,
    outbounds: Vec<node_core::routing::Outbound>,
    route: node_core::routing::Route,
}

#[derive(Serialize)]
struct Inbound<'a> {
    listen: &'a str,
    listen_port: u16,
    tag: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(rename = "type")]
    kind: &'a str,
    users: Users<'a>,
}

#[derive(Serialize)]
struct Log<'a> {
    level: &'a str,
    timestamp: bool,
}

struct Users<'a> {
    users: &'a [UserSpec],
    flow: Option<&'a str>,
    vless: bool,
    native: bool,
    shadowsocks: Option<node_core::shadowsocks::Cipher>,
}

impl Serialize for Users<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.users.len()))?;
        for user in self.users {
            sequence.serialize_element(&User {
                user,
                flow: self.flow,
                vless: self.vless,
                native: self.native,
                shadowsocks: self.shadowsocks,
            })?;
        }
        sequence.end()
    }
}

struct User<'a> {
    user: &'a UserSpec,
    flow: Option<&'a str>,
    vless: bool,
    native: bool,
    shadowsocks: Option<node_core::shadowsocks::Cipher>,
}

impl Serialize for User<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if self.native && self.user.device_limit > 0 {
            map.serialize_entry("device_limit", &self.user.device_limit)?;
        }
        if let Some(flow) = self.flow {
            map.serialize_entry("flow", flow)?;
        }
        map.serialize_entry("name", &UserName(self.user.id))?;
        if self.native && self.user.speed_limit > 0 {
            map.serialize_entry("speed_limit", &self.user.speed_limit)?;
        }
        map.serialize_entry(
            if self.vless { "uuid" } else { "password" },
            &match self.shadowsocks {
                Some(method) => node_core::shadowsocks::user_password(method, &self.user.uuid),
                None => std::borrow::Cow::Borrowed(self.user.uuid.as_str()),
            },
        )?;
        map.end()
    }
}

struct UserName(i64);

impl Serialize for UserName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

fn uuid_key(value: &str) -> Option<[u8; 16]> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|&index| bytes[index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit());
    if !valid {
        return None;
    }
    let mut hex = bytes.iter().copied().filter(|byte| *byte != b'-');
    let nibble = |byte: u8| {
        if byte.is_ascii_digit() {
            byte - b'0'
        } else {
            byte.to_ascii_lowercase() - b'a' + 10
        }
    };
    let mut key = [0u8; 16];
    for byte in &mut key {
        *byte = (nibble(hex.next()?) << 4) | nibble(hex.next()?);
    }
    Some(key)
}
