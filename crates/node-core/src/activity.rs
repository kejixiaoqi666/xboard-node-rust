//! A measured snapshot of active authenticated source IPs; no credentials.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivitySnapshot {
    pub alive: BTreeMap<i64, Vec<String>>,
    pub online: BTreeMap<i64, u32>,
    pub sessions: u64,
}
impl ActivitySnapshot {
    pub fn validate(&self) -> bool {
        self.alive.len() <= 65536
            && self.online.len() == self.alive.len()
            && self.alive.iter().all(|(id, ips)| {
                *id > 0
                    && self
                        .online
                        .get(id)
                        .is_some_and(|sessions| *sessions as usize >= ips.len())
                    && ips.iter().all(|ip| ip.parse::<std::net::IpAddr>().is_ok())
            })
            && self.alive.values().map(Vec::len).sum::<usize>() <= 65536
            && self
                .online
                .values()
                .map(|count| u64::from(*count))
                .sum::<u64>()
                == self.sessions
    }
}
