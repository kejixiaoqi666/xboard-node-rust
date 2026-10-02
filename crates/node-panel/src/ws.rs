use crate::PanelError;
use node_core::{NodeSpec, UserSpec};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Envelope {
    event: String,
    #[serde(default)]
    data: Value,
}
#[derive(Debug, Deserialize)]
struct ConfigData {
    config: Value,
    #[serde(default)]
    node_id: Option<u32>,
}
#[derive(Debug, Deserialize)]
struct UsersData {
    users: Vec<PanelUser>,
    #[serde(default)]
    node_id: Option<u32>,
}
#[derive(Debug, Deserialize)]
struct DeltaData {
    action: String,
    users: Vec<PanelUser>,
    #[serde(default)]
    node_id: Option<u32>,
}
#[derive(Debug, Deserialize)]
struct DevicesData {
    users: std::collections::BTreeMap<i64, Vec<String>>,
    #[serde(default)]
    node_id: Option<u32>,
}
#[derive(Debug, Deserialize)]
struct PanelUser {
    id: i64,
    uuid: String,
    #[serde(default)]
    speed_limit: i64,
    #[serde(default)]
    device_limit: i64,
}
impl PanelUser {
    fn into_core(self) -> UserSpec {
        UserSpec {
            id: self.id,
            uuid: self.uuid,
            speed_limit: self.speed_limit,
            device_limit: self.device_limit,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum WsEvent {
    Config {
        node_id: Option<u32>,
        config: Box<NodeSpec>,
    },
    Users {
        node_id: Option<u32>,
        users: Vec<UserSpec>,
    },
    UserDelta {
        node_id: Option<u32>,
        action: String,
        users: Vec<UserSpec>,
    },
    Devices {
        node_id: Option<u32>,
        users: std::collections::BTreeMap<i64, Vec<String>>,
    },
}

pub fn parse_ws_message(bytes: &[u8]) -> Result<Option<WsEvent>, PanelError> {
    if bytes.len() > 10 * 1024 * 1024 {
        return Err(PanelError::TooLarge);
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| PanelError::Decode)?;
    let event = match envelope.event.as_str() {
        "sync.config" => {
            let data: ConfigData =
                serde_json::from_value(envelope.data).map_err(|_| PanelError::Decode)?;
            let wire = crate::decode_node_config(data.config)?;
            if data.node_id.is_some() && wire.node_id.is_some() && data.node_id != wire.node_id {
                return Err(PanelError::Decode);
            }
            Some(WsEvent::Config {
                node_id: data.node_id.or(wire.node_id),
                config: Box::new(wire.spec),
            })
        }
        "sync.users" => {
            let data: UsersData =
                serde_json::from_value(envelope.data).map_err(|_| PanelError::Decode)?;
            Some(WsEvent::Users {
                node_id: data.node_id,
                users: data.users.into_iter().map(PanelUser::into_core).collect(),
            })
        }
        "sync.user.delta" => {
            let data: DeltaData =
                serde_json::from_value(envelope.data).map_err(|_| PanelError::Decode)?;
            if data.action != "add" && data.action != "remove" {
                return Err(PanelError::Decode);
            }
            Some(WsEvent::UserDelta {
                node_id: data.node_id,
                action: data.action,
                users: data.users.into_iter().map(PanelUser::into_core).collect(),
            })
        }
        "sync.devices" => {
            let data: DevicesData =
                serde_json::from_value(envelope.data).map_err(|_| PanelError::Decode)?;
            Some(WsEvent::Devices {
                node_id: data.node_id,
                users: data.users,
            })
        }
        _ => None,
    };
    Ok(event)
}
