use node_core::{NodeSpec, UserSpec};
use node_kernel::{KernelAdapter, KernelError, KernelManager, KernelStatus};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Fake {
    state: Arc<Mutex<FakeState>>,
}
#[derive(Default)]
struct FakeState {
    active: Option<(NodeSpec, Vec<UserSpec>)>,
    prepared: usize,
    activated: usize,
    rolled_back: usize,
    fail_prepare: bool,
    fail_activate: bool,
}
impl KernelAdapter for Fake {
    type Candidate = (NodeSpec, Vec<UserSpec>);
    fn name(&self) -> &'static str {
        "fake"
    }
    fn prepare(
        &self,
        config: &NodeSpec,
        users: &[UserSpec],
    ) -> Result<Self::Candidate, KernelError> {
        let mut s = self.state.lock().unwrap();
        s.prepared += 1;
        if s.fail_prepare {
            return Err(KernelError::Prepare("rejected".into()));
        }
        Ok((config.clone(), users.to_vec()))
    }
    fn activate(&self, candidate: Self::Candidate) -> Result<(), KernelError> {
        let mut s = self.state.lock().unwrap();
        s.activated += 1;
        if s.fail_activate {
            return Err(KernelError::Activate("not ready".into()));
        }
        s.active = Some(candidate);
        Ok(())
    }
    fn rollback(&self) -> Result<(), KernelError> {
        self.state.lock().unwrap().rolled_back += 1;
        Ok(())
    }
    fn status(&self) -> KernelStatus {
        KernelStatus::Ready
    }
}

fn manager(fake: &Fake) -> KernelManager<Fake> {
    KernelManager::new(
        NodeSpec::new("vless", 443),
        vec![UserSpec::new(1, "one")],
        fake.clone(),
    )
    .unwrap()
}

#[test]
fn activation_commits_only_after_prepare_and_activate() {
    let fake = Fake {
        state: Arc::new(Mutex::new(FakeState::default())),
    };
    let mut manager = manager(&fake);
    manager
        .apply(NodeSpec::new("trojan", 8443), vec![UserSpec::new(2, "two")])
        .unwrap();
    assert_eq!(manager.status(), KernelStatus::Ready);
    assert_eq!(manager.applied().config.server_port, 8443);
    let s = fake.state.lock().unwrap();
    assert_eq!((s.prepared, s.activated, s.rolled_back), (1, 1, 0));
}

#[test]
fn prepare_or_activate_failure_preserves_snapshot_and_rolls_back() {
    let fake = Fake {
        state: Arc::new(Mutex::new(FakeState {
            fail_activate: true,
            ..Default::default()
        })),
    };
    let mut manager = manager(&fake);
    let err = manager
        .apply(NodeSpec::new("trojan", 8443), vec![])
        .unwrap_err();
    assert!(matches!(err, KernelError::Activate(_)));
    assert_eq!(manager.applied().config.server_port, 443);
    assert_eq!(fake.state.lock().unwrap().rolled_back, 1);
}
