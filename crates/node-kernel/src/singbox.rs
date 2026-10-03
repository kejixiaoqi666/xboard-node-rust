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
    rule_sets: Vec<node_core::routing::RuleSet>,
    geo_data_dir: Option<std::path::PathBuf>,
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
            rule_sets: Vec::new(),
            geo_data_dir: None,
        }
    }
    pub fn with_dns(mut self, dns: Option<node_core::routing::DnsConfig>) -> Self {
        self.dns = dns;
        self
    }
    pub fn with_rule_sets(mut self, sets: Vec<node_core::routing::RuleSet>) -> Self {
        self.rule_sets = sets;
        self
    }
    pub fn with_geo_data_dir(mut self, directory: Option<std::path::PathBuf>) -> Self {
        self.geo_data_dir = directory;
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
        if node.protocol == "vmess" && users.len() > 256 {
            return Err(KernelError::Invalid(
                "VMess authentication is limited to 256 users per listener".into(),
            ));
        }
        let transport = if self.native {
            native_transport(node)?
        } else {
            None
        };
        let plugin = if self.native {
            native_plugin(node)?
        } else {
            None
        };
        let extended = if self.native {
            native_extended(node)?
        } else {
            None
        };
        if !matches!(node.protocol.as_str(), "vless" | "trojan")
            && !(self.native
                && matches!(
                    node.protocol.as_str(),
                    "shadowsocks" | "vmess" | "anytls" | "hysteria2" | "tuic"
                ))
        {
            return Err(KernelError::Invalid(format!(
                "unsupported kernel protocol: {}",
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
            if node.plugin.is_some() {
                supported.plugin = node.plugin.clone();
                supported.plugin_opt = node.plugin_opt.clone();
            }
            supported.multiplex = node.multiplex.clone();
            if transport.is_some() {
                supported.network_settings = node.network_settings.clone();
            }
            if node.protocol == "vmess" {
                supported.cipher = node.cipher.clone();
            }
            if node.protocol == "anytls" {
                supported.padding_scheme = node.padding_scheme.clone();
            }
            if matches!(node.protocol.as_str(), "hysteria2" | "tuic") {
                supported.version = node.version;
                supported.congestion_control = node.congestion_control.clone();
                if node.protocol == "hysteria2" {
                    supported.obfs = node.obfs.clone();
                    supported.obfs_password = node.obfs_password.clone();
                }
                if node.version != 0 && node.version != if node.protocol == "tuic" { 5 } else { 2 }
                    || node
                        .obfs
                        .as_deref()
                        .is_some_and(|kind| kind != "salamander")
                    || node.obfs.is_some() != node.obfs_password.is_some()
                {
                    return Err(KernelError::Invalid(
                        "invalid QUIC version/obfuscation".into(),
                    ));
                }
            }
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
                .is_some_and(|network| network != "tcp" && transport.is_none())
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
        let mandatory_tls = matches!(node.protocol.as_str(), "anytls" | "hysteria2" | "tuic");
        let plugin_tls = node.plugin.as_deref() == Some("v2ray-plugin")
            && plugin_options(node)?.remove("tls").is_some();
        let tls_mode =
            if (mandatory_tls && node.cert_config.is_some() || plugin_tls) && node.tls == 0 {
                1
            } else {
                node.tls
            };
        if plugin.is_some() && users.iter().any(|user| user.device_limit > 0) {
            return Err(KernelError::Invalid("external SIP003 does not preserve client IP; device limits require native v2ray-plugin transport".into()));
        }
        let tls = match tls_mode {
            0 if matches!(node.protocol.as_str(), "vless" | "shadowsocks" | "vmess")
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
        let vless = matches!(node.protocol.as_str(), "vless" | "vmess" | "tuic");
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
        let mut sets = self.rule_sets.clone();
        if let Some(directory) = &self.geo_data_dir {
            sets.extend(
                node_core::routing::discover_geo_rulesets(node, directory)
                    .map_err(|e| KernelError::Invalid(e.to_string()))?,
            );
        }
        let (route, outbounds) = node_core::routing::from_node_with_rulesets(node, &sets)
            .map_err(|e| KernelError::Invalid(e.to_string()))?;
        Ok(SingBoxConfig {
            dns: self.dns.clone(),
            inbounds: [Inbound {
                listen: node.listen_ip.as_deref().unwrap_or("::"),
                listen_port: node.server_port,
                tag: match node.protocol.as_str() {
                    "vless" => "vless-in",
                    "vmess" => "vmess-in",
                    "shadowsocks" => "shadowsocks-in",
                    "anytls" => "anytls-in",
                    "hysteria2" => "hysteria2-in",
                    "tuic" => "tuic-in",
                    _ => "trojan-in",
                },
                tls,
                method: ss.as_ref().map(|s| s.method.name()),
                password: ss.as_ref().and(node.server_key.as_deref()),
                quic: if self.native && matches!(node.protocol.as_str(), "hysteria2" | "tuic") {
                    Some(
                        json!({"obfs_password":node.obfs_password,"congestion_control":node.congestion_control.as_deref().unwrap_or("cubic")}),
                    )
                } else {
                    None
                },
                extended,
                transport,
                plugin,
                kind: &node.protocol,
                users: Users {
                    users,
                    vless: matches!(node.protocol.as_str(), "vless" | "vmess" | "tuic"),
                    tuic: node.protocol == "tuic",
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
    #[serde(skip_serializing_if = "Option::is_none")]
    quic: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<Value>,
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
    tuic: bool,
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
                tuic: self.tuic,
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
    tuic: bool,
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
        if self.tuic {
            map.serialize_entry("password", &self.user.uuid)?;
        }
        map.end()
    }
}

struct UserName(i64);

impl Serialize for UserName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

fn native_transport(node: &NodeSpec) -> Result<Option<Value>, KernelError> {
    if let Some(plugin) = &node.plugin {
        if node.protocol != "shadowsocks"
            || node
                .network
                .as_deref()
                .is_some_and(|network| network != "tcp")
            || !node.network_settings.is_null()
        {
            return Err(KernelError::Invalid(
                "SIP003 requires Shadowsocks TCP without separate network settings".into(),
            ));
        }
        if plugin != "v2ray-plugin" {
            return Ok(None);
        }
        let mut options = plugin_options(node)?;
        for flag in ["server", "tls"] {
            if let Some(value) = options.remove(flag)
                && !value.is_empty()
            {
                return Err(KernelError::Invalid(
                    "plugin flag must not have a value".into(),
                ));
            }
        }
        if options
            .remove("mode")
            .is_some_and(|mode| mode != "websocket")
        {
            return Err(KernelError::Invalid(
                "native v2ray-plugin supports WebSocket mode".into(),
            ));
        }
        let multiplex = match options.remove("mux").as_deref() {
            None | Some("1") => true,
            Some("0") => false,
            _ => {
                return Err(KernelError::Invalid(
                    "v2ray-plugin mux must be 0 or 1".into(),
                ));
            }
        };
        let mut transport = json!({"type":"ws","plugin_mux":multiplex});
        if let Some(path) = options.remove("path") {
            transport["path"] = json!(path);
        }
        if let Some(host) = options.remove("host") {
            transport["host"] = json!(host);
        }
        if !options.is_empty() {
            return Err(KernelError::Invalid("unsupported native v2ray-plugin options; use explicit external SIP003 executable for other plugins".into()));
        }
        return Ok(Some(transport));
    }
    let kind = match node.network.as_deref().unwrap_or("tcp") {
        "tcp" => return Ok(None),
        "ws" => "ws",
        "httpupgrade" => "httpupgrade",
        "h2" | "http" | "http2" => "http2",
        "grpc" => "grpc",
        _ => return Err(KernelError::Invalid("unsupported native transport".into())),
    };
    if !matches!(node.protocol.as_str(), "vless" | "vmess" | "trojan")
        || node.tls == 2
        || node.flow.as_deref().is_some_and(|flow| !flow.is_empty())
    {
        return Err(KernelError::Invalid(
            "transport incompatible with protocol or Vision/REALITY".into(),
        ));
    }
    let mut settings = if node.network_settings.is_null() {
        serde_json::Map::new()
    } else {
        node.network_settings
            .as_object()
            .cloned()
            .ok_or_else(|| KernelError::Invalid("transport settings require an object".into()))?
    };
    let mut result = json!({"type":kind});
    if kind == "grpc" {
        let service = settings
            .remove("serviceName")
            .or_else(|| settings.remove("service_name"))
            .unwrap_or(json!(""));
        if !service.is_string() {
            return Err(KernelError::Invalid("invalid gRPC service name".into()));
        }
        result["service_name"] = service;
        for option in ["multiMode", "multi_mode"] {
            if let Some(value) = settings.remove(option)
                && value != json!(false)
            {
                return Err(KernelError::Invalid(
                    "gRPC multiMode requires an unsupported wire format".into(),
                ));
            }
        }
    } else {
        if let Some(path) = settings.remove("path") {
            if !path.is_string() {
                return Err(KernelError::Invalid("invalid transport path".into()));
            }
            result["path"] = path;
        }
        let mut host = settings.remove("host");
        if let Some(headers) = settings.remove("headers") {
            let mut headers = headers
                .as_object()
                .cloned()
                .ok_or_else(|| KernelError::Invalid("invalid transport headers".into()))?;
            let header = headers.remove("Host").or_else(|| headers.remove("host"));
            if !headers.is_empty() || host.is_some() && header.is_some() {
                return Err(KernelError::Invalid(
                    "unsupported or duplicate transport headers".into(),
                ));
            }
            if header.is_some() {
                host = header;
            }
        }
        if let Some(host) = host {
            if kind == "http2" {
                result["hosts"] = if host.is_string() {
                    json!([host])
                } else {
                    host
                };
            } else {
                if !host.is_string() {
                    return Err(KernelError::Invalid("transport requires one Host".into()));
                }
                result["host"] = host;
            }
        }
        if kind == "http2"
            && let Some(method) = settings.remove("method")
        {
            result["method"] = method;
        }
        if kind == "ws" {
            if let Some(early) = settings
                .remove("maxEarlyData")
                .or_else(|| settings.remove("max_early_data"))
            {
                result["max_early_data"] = early;
            }
            if let Some(header) = settings
                .remove("early_data_header_name")
                .or_else(|| settings.remove("earlyDataHeaderName"))
                && header != json!("Sec-WebSocket-Protocol")
            {
                return Err(KernelError::Invalid(
                    "unsupported WebSocket early-data header".into(),
                ));
            }
        }
    }
    if !settings.is_empty() {
        return Err(KernelError::Invalid("unsupported transport options".into()));
    }
    Ok(Some(result))
}

fn plugin_options(
    node: &NodeSpec,
) -> Result<std::collections::BTreeMap<String, String>, KernelError> {
    let text = node.plugin_opt.as_deref().unwrap_or("");
    if text.len() > 16384 || text.contains('\0') {
        return Err(KernelError::Invalid("invalid plugin options".into()));
    }
    let mut options = std::collections::BTreeMap::new();
    for part in text.split(';').filter(|part| !part.is_empty()) {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        if name.is_empty() || options.insert(name.into(), value.into()).is_some() {
            return Err(KernelError::Invalid("duplicate plugin options".into()));
        }
    }
    Ok(options)
}
fn native_plugin(node: &NodeSpec) -> Result<Option<Value>, KernelError> {
    let Some(binary) = &node.plugin else {
        return Ok(None);
    };
    if binary == "v2ray-plugin" {
        return Ok(None);
    }
    if node.protocol != "shadowsocks"
        || !std::path::Path::new(binary).is_absolute()
        || node.tls != 0
        || node.cert_config.is_some()
    {
        return Err(KernelError::Invalid(
            "external SIP003 needs an absolute executable and Shadowsocks without separate TLS"
                .into(),
        ));
    }
    Ok(Some(json!({"binary":binary,"options":node.plugin_opt})))
}
fn native_extended(node: &NodeSpec) -> Result<Option<Value>, KernelError> {
    if !matches!(
        node.protocol.as_str(),
        "vmess" | "anytls" | "vless" | "trojan" | "shadowsocks"
    ) {
        if node.multiplex.is_some() {
            return Err(KernelError::Invalid(
                "multiplex settings are incompatible with this protocol".into(),
            ));
        }
        return Ok(None);
    }
    let mut settings = json!({"vmess_security":if node.protocol=="vmess" {node.cipher.as_deref().unwrap_or("any")}else{"any"},"padding_scheme":node.padding_scheme});
    if let Some(mux) = &node.multiplex {
        if mux.max_connections != 0
            || mux.min_streams != 0
            || mux.max_streams < 0
            || mux.max_streams > 1024
            || mux
                .brutal
                .as_ref()
                .is_some_and(|b| b.enabled || b.up_mbps != 0 || b.down_mbps != 0)
            || mux
                .protocol
                .as_deref()
                .is_some_and(|p| !matches!(p, "smux" | "yamux" | "h2mux"))
        {
            return Err(KernelError::Invalid(
                "unsupported inbound multiplex pool/brutal settings; max_streams supports 1..1024"
                    .into(),
            ));
        }
        settings["multiplex_enabled"] = json!(mux.enabled);
        if mux.max_streams > 0 {
            settings["max_sessions"] = json!(mux.max_streams);
        }
    }
    Ok(Some(settings))
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
