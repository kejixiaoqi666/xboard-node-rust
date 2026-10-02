use crate::KernelError;
use node_core::{NodeSpec, UserSpec};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use std::io::Write;

#[derive(Clone, Debug, Default)]
pub struct SingBoxConfigBuilder;

impl SingBoxConfigBuilder {
    pub fn new() -> Self {
        Self
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
        if !matches!(node.protocol.as_str(), "vless" | "trojan") {
            return Err(KernelError::Invalid(format!(
                "sing-box tracer supports only vless/trojan, got {}",
                node.protocol
            )));
        }
        // Explicitly reject features this experimental adapter cannot enforce.
        // Comparing the supported subset also guards future NodeSpec additions.
        let mut supported = NodeSpec::new(&node.protocol, node.server_port);
        supported.listen_ip = node.listen_ip.clone();
        supported.network = node.network.clone();
        supported.kernel_type = node.kernel_type.clone();
        supported.kernel_log_level = node.kernel_log_level.clone();
        supported.tls = node.tls;
        supported.cert_config = node.cert_config.clone();
        supported.server_name = node.server_name.clone();
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
        if users
            .iter()
            .any(|user| user.speed_limit != 0 || user.device_limit != 0)
        {
            return Err(KernelError::Invalid(
                "speed/device enforcement is not implemented".into(),
            ));
        }
        let tls = match node.tls {
            0 if node.protocol == "vless"
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
            _ => {
                return Err(KernelError::Invalid(
                    "unsupported TLS mode; Trojan requires TLS and REALITY is pending".into(),
                ));
            }
        };
        let mut ids = std::collections::HashSet::with_capacity(users.len());
        let vless = node.protocol == "vless";
        let mut uuid_keys =
            std::collections::HashSet::with_capacity(if vless { users.len() } else { 0 });
        let mut passwords =
            std::collections::HashSet::with_capacity(if vless { 0 } else { users.len() });
        for user in users {
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
        Ok(SingBoxConfig {
            inbounds: [Inbound {
                listen: node.listen_ip.as_deref().unwrap_or("::"),
                listen_port: node.server_port,
                tag: if node.protocol == "vless" {
                    "vless-in"
                } else {
                    "trojan-in"
                },
                tls,
                kind: &node.protocol,
                users: Users {
                    users,
                    vless: node.protocol == "vless",
                },
            }],
            log: Log {
                level: node.kernel_log_level.as_deref().unwrap_or("info"),
                timestamp: true,
            },
            outbounds: [Outbound {
                tag: "direct",
                kind: "direct",
            }],
            route: Route {
                final_outbound: "direct",
            },
        })
    }
}

// Field order matches the original serde_json::Value encoding, including the
// historical string form of user IDs. Only the small TLS object is owned.
#[derive(Serialize)]
pub(crate) struct SingBoxConfig<'a> {
    inbounds: [Inbound<'a>; 1],
    log: Log<'a>,
    outbounds: [Outbound; 1],
    route: Route,
}

#[derive(Serialize)]
struct Inbound<'a> {
    listen: &'a str,
    listen_port: u16,
    tag: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<Value>,
    #[serde(rename = "type")]
    kind: &'a str,
    users: Users<'a>,
}

#[derive(Serialize)]
struct Log<'a> {
    level: &'a str,
    timestamp: bool,
}

#[derive(Serialize)]
struct Outbound {
    tag: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
struct Route {
    #[serde(rename = "final")]
    final_outbound: &'static str,
}

struct Users<'a> {
    users: &'a [UserSpec],
    vless: bool,
}

impl Serialize for Users<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.users.len()))?;
        for user in self.users {
            sequence.serialize_element(&User {
                user,
                vless: self.vless,
            })?;
        }
        sequence.end()
    }
}

struct User<'a> {
    user: &'a UserSpec,
    vless: bool,
}

impl Serialize for User<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("name", &UserName(self.user.id))?;
        map.serialize_entry(
            if self.vless { "uuid" } else { "password" },
            &self.user.uuid,
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
