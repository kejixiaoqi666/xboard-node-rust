use node_core::{NodeSpec, RuntimeState, UserSpec};
use node_panel::{ControlPlaneReducer, ReduceResult, WsEvent};
use std::collections::BTreeMap;

fn initial() -> RuntimeState {
    RuntimeState::new(NodeSpec::new("vless", 443), vec![UserSpec::new(1, "one")]).unwrap()
}

#[test]
fn reducer_applies_ordered_config_users_delta_and_devices_once() {
    let mut reducer = ControlPlaneReducer::new(initial(), Some(7));
    let config = WsEvent::Config {
        node_id: Some(7),
        config: Box::new(NodeSpec::new("trojan", 8443)),
    };
    assert_eq!(
        reducer.apply(10, config, |_| Ok(())),
        Ok(ReduceResult::Applied)
    );
    let users = WsEvent::Users {
        node_id: Some(7),
        users: vec![UserSpec::new(2, "two")],
    };
    assert_eq!(
        reducer.apply(11, users, |_| Ok(())),
        Ok(ReduceResult::Applied)
    );
    let delta = WsEvent::UserDelta {
        node_id: Some(7),
        action: "add".into(),
        users: vec![UserSpec::new(3, "three")],
    };
    assert_eq!(
        reducer.apply(12, delta, |_| Ok(())),
        Ok(ReduceResult::Applied)
    );
    let mut devices = BTreeMap::new();
    devices.insert(3, vec!["198.51.100.10".into()]);
    assert_eq!(
        reducer.apply(
            13,
            WsEvent::Devices {
                node_id: Some(7),
                users: devices
            },
            |_| Ok(())
        ),
        Ok(ReduceResult::Applied)
    );
    assert_eq!(reducer.last_sequence(), 13);
    assert_eq!(reducer.runtime().applied().config.server_port, 8443);
    assert_eq!(reducer.runtime().applied().users.len(), 2);
    assert_eq!(reducer.devices().get(&3).unwrap()[0], "198.51.100.10");
    assert_eq!(
        reducer.apply(
            13,
            WsEvent::Devices {
                node_id: Some(7),
                users: BTreeMap::new()
            },
            |_| Ok(())
        ),
        Ok(ReduceResult::Stale)
    );
}

#[test]
fn reducer_does_not_commit_kernel_or_sequence_on_failure_or_wrong_node() {
    let mut reducer = ControlPlaneReducer::new(initial(), Some(7));
    let wrong = WsEvent::Config {
        node_id: Some(8),
        config: Box::new(NodeSpec::new("trojan", 8443)),
    };
    assert_eq!(
        reducer.apply(1, wrong, |_| panic!("wrong node must not call kernel")),
        Ok(ReduceResult::Ignored)
    );
    let candidate = WsEvent::Config {
        node_id: Some(7),
        config: Box::new(NodeSpec::new("trojan", 8443)),
    };
    assert!(
        reducer
            .apply(2, candidate, |_| Err("kernel rejected".into()))
            .is_err()
    );
    assert_eq!(reducer.last_sequence(), 0);
    assert_eq!(reducer.runtime().applied().config.server_port, 443);
}
