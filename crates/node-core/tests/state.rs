use node_core::{ApplyResult, ConfigError, NodeSpec, RuntimeState, UserSpec};

fn valid() -> NodeSpec {
    NodeSpec::new("vless", 443).with_server_name("one.example")
}

#[test]
fn failed_candidate_never_overwrites_applied_or_last_known_good() {
    let mut state = RuntimeState::new(valid(), vec![UserSpec::new(1, "u1")]).unwrap();
    let before = state.applied().clone();
    let candidate = NodeSpec::new("vless", 8443).with_server_name("two.example");
    let err = state.apply_config(candidate, |_| Err("bind failed".to_string()));
    assert!(matches!(err, Err(ConfigError::KernelRejected(_))));
    assert_eq!(state.applied(), &before);
    assert_eq!(state.last_known_good(), &before);
}

#[test]
fn accepted_candidate_updates_applied_and_good_together() {
    let mut state = RuntimeState::new(valid(), vec![UserSpec::new(1, "u1")]).unwrap();
    let next = NodeSpec::new("vless", 8443).with_server_name("two.example");
    assert_eq!(
        state.apply_config(next.clone(), |_| Ok(())).unwrap(),
        ApplyResult::Applied
    );
    assert_eq!(state.applied().config, next);
    assert_eq!(state.applied(), state.last_known_good());
}

#[test]
fn unchanged_candidate_does_not_touch_kernel() {
    let mut state = RuntimeState::new(valid(), vec![UserSpec::new(1, "u1")]).unwrap();
    assert_eq!(
        state
            .apply_config(valid(), |_| panic!("must not apply"))
            .unwrap(),
        ApplyResult::Unchanged
    );
}

#[test]
fn invalid_candidate_does_not_touch_kernel() {
    let mut state = RuntimeState::new(valid(), vec![UserSpec::new(1, "u1")]).unwrap();
    assert!(matches!(
        state.apply_config(NodeSpec::new("bad", 443), |_| panic!("must not apply")),
        Err(ConfigError::UnsupportedProtocol(_))
    ));
}

#[test]
fn failed_user_delta_preserves_applied_state() {
    let mut state = RuntimeState::new(valid(), vec![UserSpec::new(1, "u1")]).unwrap();
    let before = state.applied().clone();
    assert!(matches!(
        state.apply_users(
            "add",
            vec![UserSpec::new(2, "u2")],
            |_| Err("failed".into())
        ),
        Err(ConfigError::KernelRejected(_))
    ));
    assert_eq!(state.applied(), &before);
}

#[test]
fn invalid_user_delta_preserves_applied_state_and_never_calls_kernel() {
    let mut state = RuntimeState::new(valid(), vec![UserSpec::new(1, "u1")]).unwrap();
    let before = state.applied().clone();
    assert!(matches!(
        state.apply_users("replace", vec![], |_| panic!("must not apply")),
        Err(ConfigError::InvalidDeltaAction(_))
    ));
    assert_eq!(state.applied(), &before);
}

#[test]
fn user_add_then_remove_flows_through_applied_state() {
    let mut state = RuntimeState::new(valid(), vec![UserSpec::new(1, "u1")]).unwrap();
    assert_eq!(
        state
            .apply_users("add", vec![UserSpec::new(2, "u2")], |_| Ok(()))
            .unwrap(),
        ApplyResult::Applied
    );
    assert_eq!(state.applied().users.len(), 2);
    assert_eq!(
        state
            .apply_users("remove", vec![UserSpec::new(2, "ignored")], |_| Ok(()))
            .unwrap(),
        ApplyResult::Applied
    );
    assert_eq!(state.applied().users, vec![UserSpec::new(1, "u1")]);
}
