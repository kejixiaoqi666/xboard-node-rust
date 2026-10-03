//! Derive credentials once per immutable Host snapshot, without retaining historical passwords.
use crate::{Protocol, vmess::wire};
use node_session::User;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
};

/// VMess AuthIDs contain random bytes, so invalid authentication requires a scan.
/// Limit the scan to 256 cached AES block decryptions per connection.
pub const MAX_VMESS_USERS: usize = 256;
pub const MAX_ANYTLS_USERS: usize = 65536;
const MAX_PASSWORD_BYTES: usize = 4096;

pub(crate) fn validate_users(protocol: Protocol, users: &[User]) -> io::Result<()> {
    let max = match protocol {
        Protocol::Vmess => MAX_VMESS_USERS,
        Protocol::AnyTls => MAX_ANYTLS_USERS,
    };
    if users.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{protocol:?} user snapshot exceeds supported limit {max}"),
        ));
    }
    if protocol == Protocol::AnyTls
        && users.iter().any(|u| {
            u.password
                .as_ref()
                .is_some_and(|p| p.len() > MAX_PASSWORD_BYTES)
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AnyTLS password exceeds 4096 bytes",
        ));
    }
    Ok(())
}

pub(crate) struct VmessSnapshot {
    pub users: Arc<[User]>,
    pub keys: Vec<(usize, wire::AuthIdCipher)>,
}
pub(crate) struct AnyTlsSnapshot {
    pub users: Arc<[User]>,
    pub hashes: HashMap<[u8; 32], usize>,
}

#[derive(Default)]
pub struct AuthenticationCache {
    vmess: Mutex<Option<Arc<VmessSnapshot>>>,
    anytls: Mutex<Option<Arc<AnyTlsSnapshot>>>,
}
impl AuthenticationCache {
    pub(crate) fn vmess(&self, users: Arc<[User]>) -> io::Result<Arc<VmessSnapshot>> {
        let mut current = self
            .vmess
            .lock()
            .map_err(|_| io::Error::other("VMess authentication cache lock poisoned"))?;
        if let Some(cached) = current.as_ref()
            && Arc::ptr_eq(&cached.users, &users)
        {
            return Ok(cached.clone());
        }
        validate_users(Protocol::Vmess, &users)?;
        let keys = users
            .iter()
            .enumerate()
            .filter_map(|(index, user)| {
                user.uuid
                    .map(|uuid| (index, wire::AuthIdCipher::new(wire::instruction_key(&uuid))))
            })
            .collect();
        let snapshot = Arc::new(VmessSnapshot { users, keys });
        *current = Some(snapshot.clone());
        Ok(snapshot)
    }
    pub(crate) fn anytls(&self, users: Arc<[User]>) -> io::Result<Arc<AnyTlsSnapshot>> {
        let mut current = self
            .anytls
            .lock()
            .map_err(|_| io::Error::other("AnyTLS authentication cache lock poisoned"))?;
        if let Some(cached) = current.as_ref()
            && Arc::ptr_eq(&cached.users, &users)
        {
            return Ok(cached.clone());
        }
        validate_users(Protocol::AnyTls, &users)?;
        let mut hashes = HashMap::with_capacity(users.len());
        for (index, user) in users.iter().enumerate() {
            if let Some(password) = &user.password {
                let digest = ring::digest::digest(&ring::digest::SHA256, password.as_bytes());
                let hash: [u8; 32] = digest.as_ref().try_into().expect("SHA256 length");
                hashes.entry(hash).or_insert(index);
            }
        }
        let snapshot = Arc::new(AnyTlsSnapshot { users, hashes });
        *current = Some(snapshot.clone());
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn users(count: usize) -> Arc<[User]> {
        (0..count)
            .map(|i| User {
                name: format!("user-{i}").into(),
                uuid: Some((i as u128).to_be_bytes()),
                password: Some(format!("test-only-password-{i}").into()),
            })
            .collect::<Vec<_>>()
            .into()
    }
    #[test]
    fn snapshots_reuse_derived_tables_and_release_old_credentials() {
        let cache = AuthenticationCache::default();
        let first = users(2);
        let weak = Arc::downgrade(&first);
        let v1 = cache.vmess(first.clone()).unwrap();
        let a1 = cache.anytls(first.clone()).unwrap();
        assert!(Arc::ptr_eq(&v1, &cache.vmess(first.clone()).unwrap()));
        assert!(Arc::ptr_eq(&a1, &cache.anytls(first.clone()).unwrap()));
        let presented: [u8; 32] =
            ring::digest::digest(&ring::digest::SHA256, b"test-only-password-1")
                .as_ref()
                .try_into()
                .unwrap();
        assert_eq!(a1.hashes.get(&presented), Some(&1));
        let revoked: Arc<[User]> = Arc::from([]);
        assert!(cache.vmess(revoked.clone()).unwrap().keys.is_empty());
        assert!(cache.anytls(revoked).unwrap().hashes.is_empty());
        drop(v1);
        drop(a1);
        drop(first);
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn user_limits_reject_hot_updates_before_deriving_keys() {
        let cache = AuthenticationCache::default();
        let vmess = users(MAX_VMESS_USERS + 1);
        assert!(cache.vmess(vmess.clone()).is_err());
        assert!(cache.vmess.lock().unwrap().is_none());
        assert!(
            crate::Config::default()
                .validate_users(Protocol::Vmess, &vmess)
                .is_err()
        );
        let anytls = users(MAX_ANYTLS_USERS + 1);
        assert!(cache.anytls(anytls).is_err());
        assert!(cache.anytls.lock().unwrap().is_none());
    }
    #[test]
    #[ignore = "local release-build authentication microbenchmark"]
    fn vmess_cached_invalid_auth_benchmark() {
        let cache = AuthenticationCache::default();
        let started = std::time::Instant::now();
        let snapshot = cache.vmess(users(MAX_VMESS_USERS)).unwrap();
        let build = started.elapsed();
        let started = std::time::Instant::now();
        let attempts = 10000;
        for _ in 0..attempts {
            assert!(
                !snapshot
                    .keys
                    .iter()
                    .any(|(_, cipher)| cipher
                        .validate(std::hint::black_box(&[0; 16]), 1_800_000_000))
            );
        }
        eprintln!(
            "VMess cached invalid-auth scan: users={}, attempts={attempts}, build_us={}, total_us={}, mean_us={:.2}",
            MAX_VMESS_USERS,
            build.as_micros(),
            started.elapsed().as_micros(),
            started.elapsed().as_secs_f64() * 1_000_000.0 / attempts as f64
        );
    }
}
