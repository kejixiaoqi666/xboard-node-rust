//! Validate an entire fleet before any listener or report writer is started.
use crate::{RuntimeConfig, RuntimeError};
use serde::Deserialize;
use std::{
    collections::HashSet,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetConfig {
    pub version: u32,
    pub nodes: Vec<RuntimeConfig>,
}
impl FleetConfig {
    pub fn validate(&mut self) -> Result<(), RuntimeError> {
        if self.version != 1 || self.nodes.is_empty() || self.nodes.len() > 64 {
            return Err(RuntimeError::Config);
        }
        let mut identities = HashSet::new();
        let mut directories: HashSet<PathBuf> = HashSet::new();
        for config in &mut self.nodes {
            config.embedded = true;
            config.validate()?;
            let auth = match config.machine_id {
                Some(machine) => node_panel::Auth::machine("validation", machine, config.node_id),
                None => node_panel::Auth::legacy(
                    "validation",
                    config.node_id,
                    config.node_type.clone().unwrap_or_default(),
                ),
            };
            let panel = if config.allow_loopback_http {
                node_panel::Panel::new_for_test(&config.panel_url, auth)
            } else {
                node_panel::Panel::new(&config.panel_url, auth)
            }
            .map_err(|_| RuntimeError::Config)?;
            let directory = state_identity(&config.state_dir)?;
            if !identities.insert(panel.traffic_identity())
                || directories
                    .iter()
                    .any(|held| held.starts_with(&directory) || directory.starts_with(held))
            {
                return Err(RuntimeError::Config);
            }
            directories.insert(directory);
        }
        Ok(())
    }
}
pub fn state_identity(path: &Path) -> Result<PathBuf, RuntimeError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(RuntimeError::Config);
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        suffix.push(ancestor.file_name().ok_or(RuntimeError::Config)?);
        ancestor = ancestor.parent().ok_or(RuntimeError::Config)?;
    }
    let mut identity = ancestor.canonicalize().map_err(|_| RuntimeError::Config)?;
    for name in suffix.into_iter().rev() {
        identity.push(name);
    }
    Ok(identity)
}

/// One capacity and ownership boundary for static and discovered nodes.
#[derive(Default)]
pub struct Claims(Mutex<(HashSet<String>, HashSet<PathBuf>)>);
pub struct Claim {
    owner: Arc<Claims>,
    identity: String,
    directory: PathBuf,
}
impl Claims {
    pub fn acquire(
        self: &Arc<Self>,
        identity: String,
        directory: &Path,
    ) -> Result<Claim, RuntimeError> {
        let directory = state_identity(directory)?;
        let mut held = self.0.lock().map_err(|_| RuntimeError::Worker)?;
        if held.0.len() >= 64
            || held.0.contains(&identity)
            || held
                .1
                .iter()
                .any(|path| path.starts_with(&directory) || directory.starts_with(path))
        {
            return Err(RuntimeError::Config);
        }
        held.0.insert(identity.clone());
        held.1.insert(directory.clone());
        Ok(Claim {
            owner: self.clone(),
            identity,
            directory,
        })
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if let Ok(mut held) = self.owner.0.lock() {
            held.0.remove(&self.identity);
            held.1.remove(&self.directory);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn static_and_discovered_claims_share_capacity_and_release_exact_owners() {
        let owner = Arc::new(Claims::default());
        let base = std::env::temp_dir();
        let mut held = Vec::new();
        for id in 0..64 {
            held.push(
                owner
                    .acquire(
                        format!("panel-{id}"),
                        &base.join(format!("fleet-test-{id}")),
                    )
                    .unwrap(),
            );
        }
        assert!(
            owner
                .acquire("other".into(), &base.join("fleet-test-other"))
                .is_err()
        );
        let one = held.remove(0);
        drop(one);
        assert!(
            owner
                .acquire("panel-1".into(), &base.join("new-directory"))
                .is_err()
        );
        assert!(
            owner
                .acquire("new-panel".into(), &base.join("fleet-test-1"))
                .is_err()
        );
        assert!(
            owner
                .acquire("nested".into(), &base.join("fleet-test-1/certs"))
                .is_err()
        );
        assert!(owner.acquire("parent".into(), &base).is_err());
        let replacement = owner
            .acquire("panel-0".into(), &base.join("fleet-test-0"))
            .unwrap();
        drop(replacement);
        drop(held);
        assert!(
            owner
                .acquire("panel-1".into(), &base.join("fleet-test-1"))
                .is_ok()
        );
    }
}
