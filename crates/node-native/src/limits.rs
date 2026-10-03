//! Shared per-user payload budget and distinct active source-IP admission.
#![cfg_attr(not(any(unix, test)), allow(dead_code))]
use crate::{Error, auth::Users};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub bytes_per_second: u64,
    pub devices: u32,
}

impl Policy {
    pub fn new(speed_mbps: i64, devices: i64) -> Result<Self, Error> {
        Ok(Self {
            bytes_per_second: u64::try_from(speed_mbps)
                .ok()
                .and_then(|n| n.checked_mul(125_000))
                .ok_or(Error::Config)?,
            devices: u32::try_from(devices).map_err(|_| Error::Config)?,
        })
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

pub(crate) struct Registry {
    accounts: Mutex<HashMap<Arc<str>, Arc<Account>>>,
    users: Option<Users>,
    auth_changes: tokio::sync::watch::Sender<u64>,
}
impl Default for Registry {
    fn default() -> Self {
        let (auth_changes, _) = tokio::sync::watch::channel(0);
        Self {
            accounts: Mutex::default(),
            users: None,
            auth_changes,
        }
    }
}

#[derive(Default)]
struct Account {
    ips: Mutex<HashMap<IpAddr, usize>>,
    bucket: tokio::sync::Mutex<Bucket>,
    last_speed: std::sync::atomic::AtomicU64,
    last_devices: std::sync::atomic::AtomicU32,
}

impl Registry {
    pub fn new(users: Users) -> Self {
        Self {
            accounts: Mutex::default(),
            users: Some(users),
            ..Self::default()
        }
    }
    pub fn subscribe_auth(&self) -> tokio::sync::watch::Receiver<u64> {
        self.auth_changes.subscribe()
    }
    pub fn notify_users_changed(&self) {
        self.auth_changes
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }
    pub fn activity(&self) -> node_core::ActivitySnapshot {
        let registry = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        let mut result = node_core::ActivitySnapshot::default();
        for (name, account) in registry.iter() {
            let Ok(id) = name.parse::<i64>() else {
                continue;
            };
            if id <= 0 {
                continue;
            }
            let ips = account.ips.lock().unwrap_or_else(|e| e.into_inner());
            if ips.is_empty() {
                continue;
            }
            let sessions = ips.values().sum::<usize>();
            result.sessions = result.sessions.saturating_add(sessions as u64);
            let mut addresses: Vec<_> = ips.keys().map(ToString::to_string).collect();
            addresses.sort_unstable();
            result
                .online
                .insert(id, u32::try_from(sessions).unwrap_or(u32::MAX));
            result.alive.insert(id, addresses);
        }
        result
    }
    pub fn acquire(
        self: &Arc<Self>,
        name: Arc<str>,
        ip: IpAddr,
        policy: Policy,
    ) -> Result<Lease, Error> {
        let ip = canonical_ip(ip);
        // Lock ordering is always registry then account; no lock crosses await.
        let mut registry = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if registry.len() >= 65536
            && let Some(users) = &self.users
        {
            let snapshot = users.load();
            registry.retain(|name, account| {
                snapshot.policy(name).is_some()
                    || !account
                        .ips
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .is_empty()
            });
        }
        if registry.len() >= 65536 && !registry.contains_key(&name) {
            return Err(Error::Limited);
        }
        let existing = registry.get(&name).cloned();
        let observed = self
            .users
            .as_ref()
            .and_then(|users| users.load().policy(&name));
        // Authentication may have completed before a policy change/removal,
        // while the remaining request header arrived later. A stale handshake
        // must not overwrite an existing user's most recently observed limits.
        let policy = if self.users.is_some() {
            observed
                .or_else(|| {
                    existing.as_ref().map(|account| Policy {
                        bytes_per_second: account
                            .last_speed
                            .load(std::sync::atomic::Ordering::Acquire),
                        devices: account
                            .last_devices
                            .load(std::sync::atomic::Ordering::Acquire),
                    })
                })
                .unwrap_or(policy)
        } else {
            policy
        };
        let account = registry.entry(Arc::clone(&name)).or_default().clone();
        let mut ips = account.ips.lock().unwrap_or_else(|e| e.into_inner());
        if !ips.contains_key(&ip) && policy.devices > 0 && ips.len() >= policy.devices as usize {
            return Err(Error::Limited);
        }
        let count = ips.entry(ip).or_default();
        *count = count.checked_add(1).ok_or(Error::Limited)?;
        account.last_speed.store(
            policy.bytes_per_second,
            std::sync::atomic::Ordering::Release,
        );
        account
            .last_devices
            .store(policy.devices, std::sync::atomic::Ordering::Release);
        drop(ips);
        drop(registry);
        Ok(Lease { name, ip, account })
    }
}

pub(crate) struct Lease {
    name: Arc<str>,
    ip: IpAddr,
    account: Arc<Account>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut ips = self.account.ips.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = ips.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                ips.remove(&self.ip);
            }
        }
        // Keep the shared budget across reconnects. Otherwise reconnecting
        // would replenish the burst and bypass the user's aggregate limit.
    }
}

impl Lease {
    pub async fn charge(&self, bytes: usize, users: &Users) {
        if bytes == 0 {
            return;
        }
        let speed = || {
            use std::sync::atomic::Ordering;
            if let Some(policy) = users.load().policy(&self.name) {
                self.account
                    .last_devices
                    .store(policy.devices, Ordering::Release);
                self.account
                    .last_speed
                    .store(policy.bytes_per_second, Ordering::Release);
                policy.bytes_per_second
            } else {
                // Removed users cannot authenticate again; existing sessions
                // retain their last observed rate rather than becoming unlimited.
                self.account.last_speed.load(Ordering::Acquire)
            }
        };
        if speed() == 0 {
            return;
        }
        // FIFO access shares one budget across directions/connections. Sleep is
        // cancellable; a cancelled waiter does not leave future token debt.
        let mut bucket = self.account.bucket.lock().await;
        loop {
            let delay = bucket.take(bytes, speed(), Instant::now());
            if delay.is_zero() {
                return;
            }
            // Existing sessions observe policy changes without reconnecting.
            tokio::time::sleep(delay.min(Duration::from_millis(100))).await;
        }
    }
}

struct Bucket {
    speed: u64,
    tokens: f64,
    last: Instant,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            speed: 0,
            tokens: 0.0,
            last: Instant::now(),
        }
    }
}

impl Bucket {
    fn take(&mut self, bytes: usize, speed: u64, now: Instant) -> Duration {
        if speed == 0 {
            self.speed = 0;
            self.last = now;
            return Duration::ZERO;
        }
        // Match upstream units/burst: Mbps -> decimal bytes/s, one second of
        // credit with a 64 KiB floor. Large UDP packets still fit in one claim.
        let capacity = (speed as f64).max(65536.0);
        if self.speed == 0 {
            self.tokens = capacity;
        } else {
            self.tokens = (self.tokens
                + now.duration_since(self.last).as_secs_f64() * self.speed as f64)
                .min(capacity);
        }
        self.last = now;
        self.speed = speed;
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            Duration::ZERO
        } else {
            Duration::from_secs_f64(((bytes as f64 - self.tokens) / speed as f64).max(0.000001))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn users(speed: i64) -> Users {
        let config = crate::tests::config(
            serde_json::json!([{"name":"7","uuid":"00000000-0000-4000-8000-000000000007","speed_limit":speed}]),
        );
        Arc::new(arc_swap::ArcSwap::from(
            crate::config::decode(config.to_string().as_bytes())
                .unwrap()
                .auth,
        ))
    }

    #[tokio::test(start_paused = true)]
    async fn shared_rate_survives_reconnect_and_cancelled_waiters() {
        let users = users(1);
        let registry = Arc::new(Registry::new(Arc::clone(&users)));
        let policy = Policy::new(1, 0).unwrap();
        let lease = registry
            .acquire("7".into(), "127.0.0.1".parse().unwrap(), policy)
            .unwrap();
        lease.charge(125_000, &users).await;
        drop(lease);
        let lease = registry
            .acquire("7".into(), "127.0.0.1".parse().unwrap(), policy)
            .unwrap();
        let started = Instant::now();
        let mut charge = Box::pin(lease.charge(12_500, &users));
        tokio::select! { _=&mut charge => panic!("reconnect replenished the budget"), _=tokio::time::sleep(Duration::from_millis(10))=>{} }
        drop(charge);
        lease.charge(12_500, &users).await;
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() <= Duration::from_millis(110));
    }

    #[tokio::test(start_paused = true)]
    async fn aggregate_directions_share_budget_and_hot_unlimited_policy_wakes_waiter() {
        let users = users(1);
        let registry = Arc::new(Registry::new(Arc::clone(&users)));
        let policy = Policy::new(1, 0).unwrap();
        let a = registry
            .acquire("7".into(), "127.0.0.1".parse().unwrap(), policy)
            .unwrap();
        let b = registry
            .acquire("7".into(), "127.0.0.2".parse().unwrap(), policy)
            .unwrap();
        a.charge(125_000, &users).await;
        let started = Instant::now();
        tokio::join!(a.charge(62_500, &users), b.charge(62_500, &users));
        assert!(started.elapsed() >= Duration::from_secs(1));
        let unlimited = self::users(0);
        let change = async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            users.store(unlimited.load_full());
        };
        let started = Instant::now();
        tokio::join!(a.charge(125_000, &users), change);
        assert!(started.elapsed() <= Duration::from_millis(101));
    }

    #[tokio::test(start_paused = true)]
    async fn deleted_user_stale_handshake_cannot_reset_last_observed_limits() {
        let users = users(0);
        let registry = Arc::new(Registry::new(Arc::clone(&users)));
        let stale = Policy::new(0, 0).unwrap();
        let lease = registry
            .acquire("7".into(), "127.0.0.1".parse().unwrap(), stale)
            .unwrap();
        let limited = crate::tests::config(serde_json::json!([{
            "name":"7", "uuid":"00000000-0000-4000-8000-000000000007", "speed_limit":1, "device_limit":1
        }]));
        users.store(
            crate::config::decode(limited.to_string().as_bytes())
                .unwrap()
                .auth,
        );
        lease.charge(125_000, &users).await;
        users.store(
            crate::config::decode(
                crate::tests::config(serde_json::json!([]))
                    .to_string()
                    .as_bytes(),
            )
            .unwrap()
            .auth,
        );
        let late = registry
            .acquire("7".into(), "127.0.0.1".parse().unwrap(), stale)
            .unwrap();
        assert!(
            registry
                .acquire("7".into(), "127.0.0.2".parse().unwrap(), stale)
                .is_err()
        );
        let started = Instant::now();
        late.charge(12_500, &users).await;
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() <= Duration::from_millis(101));
    }
    #[test]
    fn units_invalid_values_and_aggregate_bucket() {
        assert_eq!(Policy::new(8, 2).unwrap().bytes_per_second, 1_000_000);
        for (speed, devices) in [(-1, 0), (0, -1), (i64::MAX, 0), (0, i64::MAX)] {
            assert!(Policy::new(speed, devices).is_err());
        }
        let mut bucket = Bucket::default();
        let now = Instant::now();
        assert!(bucket.take(125_000, 125_000, now).is_zero());
        assert_eq!(
            bucket.take(12_500, 125_000, now),
            Duration::from_millis(100)
        );
        assert!(
            bucket
                .take(12_500, 125_000, now + Duration::from_millis(100))
                .is_zero()
        );
        assert!(
            !bucket
                .take(1, 125_000, now + Duration::from_millis(100))
                .is_zero()
        );
    }
    #[test]
    fn device_gate_counts_unique_ips_and_releases_last_reference() {
        let registry = Arc::new(Registry::default());
        let name: Arc<str> = "7".into();
        let policy = Policy::new(0, 1).unwrap();
        let a = registry
            .acquire(name.clone(), "127.0.0.1".parse().unwrap(), policy)
            .unwrap();
        let b = registry
            .acquire(name.clone(), "::ffff:127.0.0.1".parse().unwrap(), policy)
            .unwrap();
        assert!(
            registry
                .acquire(name.clone(), "127.0.0.2".parse().unwrap(), policy)
                .is_err()
        );
        drop(a);
        assert!(
            registry
                .acquire(name.clone(), "127.0.0.2".parse().unwrap(), policy)
                .is_err()
        );
        drop(b);
        let c = registry
            .acquire(name, "127.0.0.2".parse().unwrap(), policy)
            .unwrap();
        drop(c);
        assert!(
            registry
                .accounts
                .lock()
                .unwrap()
                .values()
                .all(|account| account.ips.lock().unwrap().is_empty())
        );
    }
    #[test]
    fn independent_users_and_policy_lowering_keep_established_leases() {
        let registry = Arc::new(Registry::default());
        let a = registry
            .acquire("7".into(), "127.0.0.1".parse().unwrap(), Policy::default())
            .unwrap();
        let b = registry
            .acquire("7".into(), "127.0.0.2".parse().unwrap(), Policy::default())
            .unwrap();
        let limit = Policy::new(0, 1).unwrap();
        assert!(
            registry
                .acquire("7".into(), "127.0.0.3".parse().unwrap(), limit)
                .is_err()
        );
        assert!(
            registry
                .acquire("7".into(), "127.0.0.1".parse().unwrap(), limit)
                .is_ok()
        );
        assert!(
            registry
                .acquire("8".into(), "127.0.0.3".parse().unwrap(), limit)
                .is_ok()
        );
        drop((a, b));
        assert!(
            registry
                .accounts
                .lock()
                .unwrap()
                .values()
                .all(|account| account.ips.lock().unwrap().is_empty())
        );
    }
}
