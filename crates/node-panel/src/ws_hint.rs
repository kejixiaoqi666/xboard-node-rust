use crate::PanelError;
use serde::Deserialize;

/// Runtime notifications carry identity only; payloads are fetched from REST.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsHint {
    pub node_id: Option<u32>,
}

#[derive(Deserialize)]
pub(crate) struct EventName {
    pub event: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NodeId {
    Number(u32),
    Text(String),
}
impl NodeId {
    fn value(self) -> Result<u32, PanelError> {
        match self {
            Self::Number(id) => Ok(id),
            Self::Text(id) => id.parse().map_err(|_| PanelError::Decode),
        }
    }
}
#[derive(Default, Deserialize)]
struct Identity {
    #[serde(default)]
    node_id: Option<NodeId>,
}
#[derive(Default, Deserialize)]
struct HintData {
    #[serde(default)]
    node_id: Option<NodeId>,
    #[serde(default)]
    config: Option<Identity>,
}
#[derive(Deserialize)]
struct HintEnvelope {
    #[serde(default)]
    data: HintData,
}

pub fn parse_ws_hint(bytes: &[u8]) -> Result<Option<WsHint>, PanelError> {
    if bytes.len() > 10 * 1024 * 1024 {
        return Err(PanelError::TooLarge);
    }
    let name: EventName = serde_json::from_slice(bytes).map_err(|_| PanelError::Decode)?;
    if !matches!(
        name.event.as_str(),
        "sync.config" | "sync.users" | "sync.user.delta" | "sync.devices"
    ) {
        return Ok(None);
    }
    // Unknown payload fields are skipped by serde instead of building large Values/Vecs.
    let envelope: HintEnvelope = serde_json::from_slice(bytes).map_err(|_| PanelError::Decode)?;
    let outer = envelope.data.node_id.map(NodeId::value).transpose()?;
    let inner = if name.event == "sync.config" {
        envelope
            .data
            .config
            .and_then(|config| config.node_id)
            .map(NodeId::value)
            .transpose()?
    } else {
        None
    };
    if outer.is_some() && inner.is_some() && outer != inner {
        return Err(PanelError::Decode);
    }
    Ok(Some(WsHint {
        node_id: outer.or(inner),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_keep_target_identity_and_ignore_non_authoritative_payload() {
        assert_eq!(
            parse_ws_hint(
                br#"{"event":"sync.users","data":{"node_id":7,"users":[{"anything":"ignored"}]}}"#
            )
            .unwrap(),
            Some(WsHint { node_id: Some(7) })
        );
        assert_eq!(
            parse_ws_hint(br#"{"event":"sync.config","data":{"config":{"node_id":"7"}}}"#).unwrap(),
            Some(WsHint { node_id: Some(7) })
        );
        assert!(
            parse_ws_hint(
                br#"{"event":"sync.config","data":{"node_id":7,"config":{"node_id":8}}}"#
            )
            .is_err()
        );
        assert_eq!(
            parse_ws_hint(br#"{"event":"heartbeat","data":[]}"#).unwrap(),
            None
        );
        assert_eq!(
            parse_ws_hint(br#"{"event":"auth.success","data":[]}"#).unwrap(),
            None
        );
        assert!(parse_ws_hint(b"broken-json").is_err());
    }
}
