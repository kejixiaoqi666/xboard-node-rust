//! A measured snapshot of active authenticated source IPs; no credentials.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivitySnapshot {
    pub alive: BTreeMap<i64, Vec<String>>,
    pub online: BTreeMap<i64, u32>,
    pub sessions: u64,
}

/// A local-only, credential-free explanation of an activity sample.
///
/// `sessions` is the logical connection count reported by the kernel. The
/// other counters deliberately use different names and units so callers do
/// not mistake connections for users or source IPs. The per-user map keeps the
/// exact relationship for users with a session or source-IP observation,
/// available to the localhost health endpoint without sending it to the panel
/// wire format.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityUserAudit {
    pub sessions: u32,
    pub source_ips: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityAudit {
    pub tracked_users: u32,
    pub online_users: u32,
    pub unique_source_ips: u32,
    pub user_source_ip_pairs: u32,
    pub reused_source_ip_pairs: u32,
    pub sessions: u64,
    pub users: BTreeMap<i64, ActivityUserAudit>,
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
                    && unique_ip_list(ips)
            })
            && self.alive.values().map(Vec::len).sum::<usize>() <= 65536
            && self
                .online
                .values()
                .map(|count| u64::from(*count))
                .sum::<u64>()
                == self.sessions
    }

    /// Derive precise local counters from one validated sample.
    ///
    /// `None` means the source sample violates the same bounds used by the
    /// panel reporter.  Cross-user source-IP reuse is retained as a metric;
    /// it is common behind NAT and must not be treated as duplicate sessions.
    pub fn audit(&self) -> Option<ActivityAudit> {
        if !self.validate() {
            return None;
        }
        let mut source_ips = BTreeSet::<IpAddr>::new();
        let mut users = BTreeMap::new();
        let mut user_source_ip_pairs = 0_u32;
        let mut online_users = 0_u32;
        for (id, ips) in &self.alive {
            let sessions = *self.online.get(id)?;
            let source_count = u32::try_from(ips.len()).ok()?;
            user_source_ip_pairs = user_source_ip_pairs.checked_add(source_count)?;
            online_users = online_users.checked_add(u32::from(sessions > 0))?;
            for ip in ips {
                source_ips.insert(canonical_ip(ip.parse().ok()?));
            }
            if sessions > 0 || source_count > 0 {
                users.insert(
                    *id,
                    ActivityUserAudit {
                        sessions,
                        source_ips: source_count,
                    },
                );
            }
        }
        let unique_source_ips = u32::try_from(source_ips.len()).ok()?;
        Some(ActivityAudit {
            tracked_users: u32::try_from(self.online.len()).ok()?,
            online_users,
            unique_source_ips,
            user_source_ip_pairs,
            reused_source_ip_pairs: user_source_ip_pairs.saturating_sub(unique_source_ips),
            sessions: self.sessions,
            users,
        })
    }
}

fn unique_ip_list(ips: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    ips.iter().all(|ip| {
        ip.parse::<IpAddr>()
            .is_ok_and(|parsed| seen.insert(canonical_ip(parsed)))
    })
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}
