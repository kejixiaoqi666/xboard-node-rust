use crate::{ConfigError, NodeSpec, UserSpec, apply_user_delta};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedSnapshot {
    pub config: NodeSpec,
    pub users: Vec<UserSpec>,
}

impl AppliedSnapshot {
    /// Validate an owned snapshot without duplicating its user list.
    pub fn new(config: NodeSpec, users: Vec<UserSpec>) -> Result<Self, ConfigError> {
        config.validate()?;
        validate_users(&users)?;
        Ok(Self { config, users })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyResult {
    Applied,
    Unchanged,
}

/// Pure control-plane state. The caller MUST supply a transactional kernel adapter:
/// a callback error must leave the existing listener and users operational.
/// This type cannot roll back side effects performed by an arbitrary callback.
pub struct RuntimeState {
    applied: AppliedSnapshot,
    last_known_good: AppliedSnapshot,
}

impl RuntimeState {
    pub fn new(config: NodeSpec, users: Vec<UserSpec>) -> Result<Self, ConfigError> {
        let applied = AppliedSnapshot::new(config, users)?;
        Ok(Self {
            last_known_good: applied.clone(),
            applied,
        })
    }

    pub fn applied(&self) -> &AppliedSnapshot {
        &self.applied
    }

    pub fn last_known_good(&self) -> &AppliedSnapshot {
        &self.last_known_good
    }

    pub fn apply_config<F>(
        &mut self,
        config: NodeSpec,
        transactional_apply: F,
    ) -> Result<ApplyResult, ConfigError>
    where
        F: FnOnce(&AppliedSnapshot) -> Result<(), String>,
    {
        config.validate()?;
        if config == self.applied.config {
            return Ok(ApplyResult::Unchanged);
        }
        let candidate = AppliedSnapshot {
            config,
            users: self.applied.users.clone(),
        };
        transactional_apply(&candidate).map_err(ConfigError::KernelRejected)?;
        self.commit(candidate);
        Ok(ApplyResult::Applied)
    }

    pub fn apply_users<F>(
        &mut self,
        action: &str,
        delta: Vec<UserSpec>,
        transactional_apply: F,
    ) -> Result<ApplyResult, ConfigError>
    where
        F: FnOnce(&AppliedSnapshot) -> Result<(), String>,
    {
        let users = apply_user_delta(self.applied.users.clone(), action, delta)?;
        if users == self.applied.users {
            return Ok(ApplyResult::Unchanged);
        }
        let candidate = AppliedSnapshot {
            config: self.applied.config.clone(),
            users,
        };
        transactional_apply(&candidate).map_err(ConfigError::KernelRejected)?;
        self.commit(candidate);
        Ok(ApplyResult::Applied)
    }

    pub fn replace_users<F>(
        &mut self,
        users: Vec<UserSpec>,
        transactional_apply: F,
    ) -> Result<ApplyResult, ConfigError>
    where
        F: FnOnce(&AppliedSnapshot) -> Result<(), String>,
    {
        validate_users(&users)?;
        if users == self.applied.users {
            return Ok(ApplyResult::Unchanged);
        }
        let candidate = AppliedSnapshot {
            config: self.applied.config.clone(),
            users,
        };
        transactional_apply(&candidate).map_err(ConfigError::KernelRejected)?;
        self.commit(candidate);
        Ok(ApplyResult::Applied)
    }

    fn commit(&mut self, candidate: AppliedSnapshot) {
        self.last_known_good = candidate.clone();
        self.applied = candidate;
    }
}

fn validate_users(users: &[UserSpec]) -> Result<(), ConfigError> {
    let mut ids = std::collections::HashSet::with_capacity(users.len());
    for user in users {
        if user.uuid.trim().is_empty() {
            return Err(ConfigError::EmptyUserUuid(user.id));
        }
        if !ids.insert(user.id) {
            return Err(ConfigError::DuplicateUserId(user.id));
        }
    }
    Ok(())
}
