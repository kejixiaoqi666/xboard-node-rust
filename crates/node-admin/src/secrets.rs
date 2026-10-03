use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret values deliberately have no Display implementation and redact Debug.
#[derive(Clone, Default, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);
impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

pub trait SecretResolver: Send + Sync {
    fn get(&self, name: &str) -> Option<Secret>;
}
#[derive(Default)]
pub struct EnvSecrets;
impl SecretResolver for EnvSecrets {
    fn get(&self, name: &str) -> Option<Secret> {
        valid_env_name(name)
            .then(|| std::env::var(name).ok())
            .flatten()
            .map(Secret::new)
    }
}

/// A migration never writes secrets implicitly. The CLI may explicitly write this
/// plan to a private JSON file, which is also a process-local SecretResolver.
#[derive(Default)]
pub struct SecretPlan {
    values: BTreeMap<String, Secret>,
}
impl fmt::Debug for SecretPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPlan")
            .field("environment_names", &self.names())
            .finish()
    }
}
impl Serialize for SecretPlan {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.names().serialize(serializer)
    }
}
impl SecretResolver for SecretPlan {
    fn get(&self, name: &str) -> Option<Secret> {
        self.values
            .get(name)
            .cloned()
            .or_else(|| EnvSecrets.get(name))
    }
}
impl SecretPlan {
    pub fn names(&self) -> Vec<&str> {
        self.values.keys().map(String::as_str).collect()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    pub fn insert(&mut self, name: String, value: Secret) -> Result<(), &'static str> {
        if !valid_env_name(&name) {
            return Err("invalid secret environment name");
        }
        if self
            .values
            .get(&name)
            .is_some_and(|old| old.expose() != value.expose())
        {
            return Err("conflicting secret environment name");
        }
        self.values.insert(name, value);
        Ok(())
    }
    /// Create-only: an existing secret file is never overwritten during import.
    pub fn write_private_json(&self, path: &Path) -> std::io::Result<()> {
        let exposed: BTreeMap<_, _> = self.values.iter().map(|(k, v)| (k, v.expose())).collect();
        let mut bytes = serde_json::to_vec(&exposed).map_err(std::io::Error::other)?;
        let result = crate::storage::create_private(path, &bytes);
        bytes.zeroize();
        result
    }
    pub fn read_private_json(path: &Path) -> std::io::Result<Self> {
        crate::storage::check_private(path)?;
        let mut bytes = crate::storage::read_bounded(path, 4 * 1024 * 1024)?;
        let parsed: Result<BTreeMap<String, Secret>, _> = serde_json::from_slice(&bytes);
        bytes.zeroize();
        let values = parsed.map_err(|_| std::io::Error::other("invalid secret store JSON"))?;
        if values.keys().any(|key| !valid_env_name(key)) {
            return Err(std::io::Error::other(
                "invalid secret store environment name",
            ));
        }
        Ok(Self { values })
    }
}
pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && (name.as_bytes()[0].is_ascii_alphabetic() || name.starts_with('_'))
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
