use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_TRAFFIC_ROWS: usize = 512;

/// Unacknowledged payload bytes, frozen until the controller durably collects them.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrafficSnapshot {
    pub epoch: String,
    pub sequence: u64,
    pub traffic: BTreeMap<String, [u64; 2]>,
}

impl TrafficSnapshot {
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("serializable traffic snapshot"))
        )
    }
    pub fn validate(&self) -> bool {
        self.epoch.len() == 32
            && self.epoch.bytes().all(|b| b.is_ascii_hexdigit())
            && self.sequence > 0
            && !self.traffic.is_empty()
            && self.traffic.len() <= MAX_TRAFFIC_ROWS
            && self.traffic.iter().all(|(id, bytes)| {
                !id.is_empty()
                    && id.len() <= 128
                    && !id.chars().any(char::is_control)
                    && *bytes != [0, 0]
            })
    }
}
