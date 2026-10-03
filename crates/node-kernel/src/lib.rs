use node_core::{AppliedSnapshot, ConfigError, NodeSpec, UserSpec};
use thiserror::Error;

mod embedded;
mod process;
pub use embedded::{EmbeddedLauncher, EmbeddedWorker};
mod traffic_control;
mod user_control;
pub use process::{ProcessCandidate, ProcessKernel, ProcessKernelConfig};
mod singbox;
pub use singbox::SingBoxConfigBuilder;
mod singbox_process;
pub use singbox_process::{SingBoxProcessKernel, SingBoxProcessKernelConfig};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelStatus {
    Ready,
    Stopped,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KernelError {
    #[error("candidate preparation failed: {0}")]
    Prepare(String),
    #[error("candidate activation failed: {0}")]
    Activate(String),
    #[error("rollback failed: {0}")]
    Rollback(String),
    #[error("invalid candidate: {0}")]
    Invalid(String),
}

pub trait KernelAdapter {
    type Candidate;
    fn name(&self) -> &'static str;
    fn prepare(
        &self,
        config: &NodeSpec,
        users: &[UserSpec],
    ) -> Result<Self::Candidate, KernelError>;
    fn activate(&self, candidate: Self::Candidate) -> Result<(), KernelError>;
    fn rollback(&self) -> Result<(), KernelError>;
    fn status(&self) -> KernelStatus;
}

pub struct KernelManager<K: KernelAdapter> {
    kernel: K,
    applied: AppliedSnapshot,
    last_known_good: AppliedSnapshot,
    status: KernelStatus,
}

impl<K: KernelAdapter> KernelManager<K> {
    pub fn new(config: NodeSpec, users: Vec<UserSpec>, kernel: K) -> Result<Self, ConfigError> {
        config.validate()?;
        let runtime = node_core::RuntimeState::new(config, users)?;
        let applied = runtime.applied().clone();
        Ok(Self {
            kernel,
            applied: applied.clone(),
            last_known_good: applied,
            status: KernelStatus::Stopped,
        })
    }

    pub fn applied(&self) -> &AppliedSnapshot {
        &self.applied
    }
    pub fn last_known_good(&self) -> &AppliedSnapshot {
        &self.last_known_good
    }
    pub fn status(&self) -> KernelStatus {
        if self.status == KernelStatus::Ready {
            self.kernel.status()
        } else {
            self.status
        }
    }
    pub fn kernel(&self) -> &K {
        &self.kernel
    }

    pub fn start(&mut self) -> Result<(), KernelError> {
        let candidate = self
            .kernel
            .prepare(&self.applied.config, &self.applied.users)?;
        if let Err(error) = self.kernel.activate(candidate) {
            let _ = self.kernel.rollback();
            return Err(error);
        }
        self.status = KernelStatus::Ready;
        Ok(())
    }

    pub fn apply(&mut self, config: NodeSpec, users: Vec<UserSpec>) -> Result<(), KernelError> {
        config
            .validate()
            .map_err(|e| KernelError::Invalid(e.to_string()))?;
        node_core::RuntimeState::new(config.clone(), users.clone())
            .map_err(|e| KernelError::Invalid(e.to_string()))?;
        if self.status() == KernelStatus::Ready
            && self.applied.config == config
            && self.applied.users == users
        {
            return Ok(());
        }
        let candidate = self.kernel.prepare(&config, &users)?;
        if let Err(error) = self.kernel.activate(candidate) {
            let rollback_error = self.kernel.rollback().err();
            return match rollback_error {
                Some(err) => Err(KernelError::Rollback(err.to_string())),
                None => Err(error),
            };
        }
        self.applied = AppliedSnapshot { config, users };
        self.last_known_good = self.applied.clone();
        self.status = KernelStatus::Ready;
        Ok(())
    }
}
