use node_core::{ConfigError, NodeSpec, UserSpec};

#[test]
fn normalizes_and_hashes_equivalent_specs_identically() {
    let a = NodeSpec::new("vless", 443).with_server_name("example.com");
    let b = NodeSpec::new("vless", 443).with_server_name("example.com");
    assert_eq!(a.config_hash().unwrap(), b.config_hash().unwrap());
}

#[test]
fn rejects_invalid_protocol_and_port_before_apply() {
    let bad_protocol = NodeSpec::new("unknown", 443);
    assert!(matches!(
        bad_protocol.validate(),
        Err(ConfigError::UnsupportedProtocol(_))
    ));

    let bad_port = NodeSpec::new("vless", 0);
    assert!(matches!(
        bad_port.validate(),
        Err(ConfigError::InvalidPort(0))
    ));
}

#[test]
fn user_delta_is_idempotent_and_does_not_duplicate_users() {
    let users = vec![UserSpec::new(7, "u7")];
    let updated =
        node_core::apply_user_delta(users.clone(), "add", vec![UserSpec::new(7, "u7-new")])
            .unwrap();
    assert_eq!(updated, vec![UserSpec::new(7, "u7-new")]);
    let removed =
        node_core::apply_user_delta(updated, "remove", vec![UserSpec::new(7, "ignored")]).unwrap();
    assert!(removed.is_empty());
}

#[test]
fn rejects_unknown_delta_action() {
    let err = node_core::apply_user_delta(Vec::new(), "replace-all", Vec::new()).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidDeltaAction(_)));
}
