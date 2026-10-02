use crate::PanelError;
use node_core::NodeSpec;
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseConfig {
    #[serde(default)]
    pub push_interval: u64,
    #[serde(default)]
    pub pull_interval: u64,
}

pub struct PanelNodeConfig {
    pub spec: NodeSpec,
    pub node_id: Option<u32>,
    pub base_config: Option<BaseConfig>,
}

/// Separate the panel wire metadata from the kernel model. Preserve strict unknown-field checks.
pub fn decode_node_config(mut value: Value) -> Result<PanelNodeConfig, PanelError> {
    let object = value.as_object_mut().ok_or(PanelError::Decode)?;
    let node_id = match object.remove("node_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) => Some(id.parse::<u32>().map_err(|_| PanelError::Decode)?),
        Some(id) => Some(serde_json::from_value::<u32>(id).map_err(|_| PanelError::Decode)?),
    };
    let base_config = match object.remove("base_config") {
        None | Some(Value::Null) => None,
        Some(mut base) => {
            if let Some(fields) = base.as_object_mut() {
                for key in ["push_interval", "pull_interval"] {
                    normalize_integer(fields.get_mut(key))?;
                }
            }
            Some(serde_json::from_value(base).map_err(|_| PanelError::Decode)?)
        }
    };
    // Go's wire struct sends empty default strings and nil slices/maps.
    for key in [
        "listen_ip",
        "network",
        "kernel_type",
        "kernel_log_level",
        "domain",
        "cipher",
        "plugin",
        "plugin_opts",
        "server_key",
        "flow",
        "decryption",
        "host",
        "server_name",
        "obfs",
        "obfs-password",
        "congestion_control",
        "transport",
        "traffic_pattern",
    ] {
        if object.get(key) == Some(&Value::String(String::new())) {
            object.remove(key);
        }
    }
    for key in [
        "routes",
        "custom_outbounds",
        "custom_routes",
        "custom_route_rules",
    ] {
        if object.get(key) == Some(&Value::Null) {
            object.remove(key);
        }
    }
    for key in ["networkSettings", "tls_settings"] {
        if object
            .get(key)
            .is_some_and(|v| v.as_object().is_some_and(serde_json::Map::is_empty))
        {
            object.remove(key);
        }
    }
    for key in ["server_port", "tls", "version", "up_mbps", "down_mbps"] {
        normalize_integer(object.get_mut(key))?;
    }
    if let Some(Value::String(protocol)) = object.get_mut("protocol") {
        *protocol = protocol.trim().to_ascii_lowercase();
    }
    let spec: NodeSpec = serde_json::from_value(value).map_err(|_| PanelError::Decode)?;
    spec.validate().map_err(|_| PanelError::Decode)?;
    Ok(PanelNodeConfig {
        spec,
        node_id,
        base_config,
    })
}

fn normalize_integer(value: Option<&mut Value>) -> Result<(), PanelError> {
    if let Some(value @ Value::String(_)) = value {
        let number = value
            .as_str()
            .unwrap()
            .parse::<i64>()
            .map_err(|_| PanelError::Decode)?;
        *value = Value::from(number);
    }
    Ok(())
}
