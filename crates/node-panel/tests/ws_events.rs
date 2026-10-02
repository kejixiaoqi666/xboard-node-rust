use node_panel::{WsEvent, parse_ws_message};

#[test]
fn parses_config_and_user_delta_events_with_node_routing() {
    let config = br#"{"event":"sync.config","data":{"node_id":7,"config":{"protocol":"vless","server_port":443,"network":"ws"}}}"#;
    match parse_ws_message(config).unwrap().unwrap() {
        WsEvent::Config { node_id, config } => {
            assert_eq!(node_id, Some(7));
            assert_eq!(config.server_port, 443);
            assert_eq!(config.network.as_deref(), Some("ws"));
        }
        other => panic!("unexpected event: {other:?}"),
    }

    let delta = br#"{"event":"sync.user.delta","data":{"node_id":7,"action":"add","users":[{"id":9,"uuid":"u","speed_limit":10,"device_limit":2}]}}"#;
    match parse_ws_message(delta).unwrap().unwrap() {
        WsEvent::UserDelta {
            node_id,
            action,
            users,
        } => {
            assert_eq!(node_id, Some(7));
            assert_eq!(action, "add");
            assert_eq!(users[0].id, 9);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn rejects_malformed_or_oversized_ws_messages_and_ignores_unknown_events() {
    assert!(parse_ws_message(br#"{"event":"sync.config","data":{}}"#).is_err());
    assert!(parse_ws_message(br#"not-json"#).is_err());
    let unknown = br#"{"event":"server.future","data":{"secret":"never logged"}}"#;
    assert!(parse_ws_message(unknown).unwrap().is_none());
    let oversized = vec![b'x'; 10 * 1024 * 1024 + 1];
    assert!(parse_ws_message(&oversized).is_err());
}
