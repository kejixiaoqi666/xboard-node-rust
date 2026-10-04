use node_core::{AppliedSnapshot, NodeSpec, UserSpec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const CACHE_FILE: &str = "runtime-snapshot.json";
const CACHE_VERSION: u32 = 1;
const MAX_CACHE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub(crate) enum CacheError {
    Storage,
    Decode,
    Mismatch,
    Invalid,
    TooLarge,
}

#[derive(Clone)]
pub(crate) struct SnapshotCache {
    directory: PathBuf,
    node_id: u32,
    identity_hash: String,
}

#[derive(Clone)]
pub(crate) struct CachedSnapshot {
    pub source_config: NodeSpec,
    pub users: Vec<UserSpec>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskSnapshot {
    version: u32,
    node_id: u32,
    identity_hash: String,
    source_config: NodeSpec,
    users: Vec<UserSpec>,
}

impl SnapshotCache {
    pub(crate) fn new(directory: PathBuf, node_id: u32, identity: &str) -> Self {
        Self {
            directory,
            node_id,
            identity_hash: hash_identity(identity),
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.join(CACHE_FILE)
    }

    pub(crate) fn load(&self) -> Result<Option<CachedSnapshot>, CacheError> {
        let path = self.path();
        if !path.exists() {
            return Ok(None);
        }
        node_admin::storage::check_private(&path).map_err(|_| CacheError::Storage)?;
        let data = node_admin::storage::read_bounded(&path, MAX_CACHE_BYTES)
            .map_err(|_| CacheError::Storage)?;
        let disk: DiskSnapshot = serde_json::from_slice(&data).map_err(|_| CacheError::Decode)?;
        if disk.version != CACHE_VERSION
            || disk.node_id != self.node_id
            || disk.identity_hash != self.identity_hash
        {
            return Err(CacheError::Mismatch);
        }
        AppliedSnapshot::new(disk.source_config.clone(), disk.users.clone())
            .map_err(|_| CacheError::Invalid)?;
        Ok(Some(CachedSnapshot {
            source_config: disk.source_config,
            users: disk.users,
        }))
    }

    pub(crate) fn store(
        &self,
        source_config: &NodeSpec,
        users: &[UserSpec],
    ) -> Result<(), CacheError> {
        AppliedSnapshot::new(source_config.clone(), users.to_vec())
            .map_err(|_| CacheError::Invalid)?;
        let disk = DiskSnapshot {
            version: CACHE_VERSION,
            node_id: self.node_id,
            identity_hash: self.identity_hash.clone(),
            source_config: source_config.clone(),
            users: users.to_vec(),
        };
        let data = serde_json::to_vec(&disk).map_err(|_| CacheError::Decode)?;
        if data.len() as u64 > MAX_CACHE_BYTES {
            return Err(CacheError::TooLarge);
        }
        node_admin::storage::atomic_private(&self.path(), &data).map_err(|_| CacheError::Storage)
    }
}

fn hash_identity(identity: &str) -> String {
    format!("{:x}", Sha256::digest(identity.as_bytes()))
}
