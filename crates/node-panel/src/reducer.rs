use crate::WsEvent;
use node_core::{ConfigError, RuntimeState};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReduceResult {
    Applied,
    Unchanged,
    Stale,
    Ignored,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReduceError {
    #[error("state apply failed: {0}")]
    State(#[from] ConfigError),
}

pub struct ControlPlaneReducer {
    runtime: RuntimeState,
    target_node_id: Option<u32>,
    last_sequence: u64,
    devices: BTreeMap<i64, Vec<String>>,
}
impl ControlPlaneReducer {
    pub fn new(runtime: RuntimeState, target_node_id: Option<u32>) -> Self {
        Self {
            runtime,
            target_node_id,
            last_sequence: 0,
            devices: BTreeMap::new(),
        }
    }
    pub fn runtime(&self) -> &RuntimeState {
        &self.runtime
    }
    pub fn devices(&self) -> &BTreeMap<i64, Vec<String>> {
        &self.devices
    }
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
    pub fn apply<F>(
        &mut self,
        sequence: u64,
        event: WsEvent,
        transactional_apply: F,
    ) -> Result<ReduceResult, ReduceError>
    where
        F: FnOnce(&node_core::AppliedSnapshot) -> Result<(), String>,
    {
        if sequence <= self.last_sequence {
            return Ok(ReduceResult::Stale);
        }
        let node_id = match &event {
            WsEvent::Config { node_id, .. }
            | WsEvent::Users { node_id, .. }
            | WsEvent::UserDelta { node_id, .. }
            | WsEvent::Devices { node_id, .. } => *node_id,
        };
        // A node-scoped reducer must not guess ownership of an untagged event.
        if self.target_node_id.is_some() && self.target_node_id != node_id {
            return Ok(ReduceResult::Ignored);
        }
        let result = match event {
            WsEvent::Config { config, .. } => {
                self.runtime.apply_config(*config, transactional_apply)?
            }
            WsEvent::Users { users, .. } => {
                self.runtime.replace_users(users, transactional_apply)?
            }
            WsEvent::UserDelta { action, users, .. } => {
                self.runtime
                    .apply_users(&action, users, transactional_apply)?
            }
            WsEvent::Devices { users, .. } => {
                self.devices = users;
                self.last_sequence = sequence;
                return Ok(ReduceResult::Applied);
            }
        };
        self.last_sequence = sequence;
        Ok(match result {
            node_core::ApplyResult::Applied => ReduceResult::Applied,
            node_core::ApplyResult::Unchanged => ReduceResult::Unchanged,
        })
    }
}
