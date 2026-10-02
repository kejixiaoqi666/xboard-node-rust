use node_panel::{Auth, WsClient, decode_node_config, parse_ws_message};
use serde_json::json;
use std::time::Duration;

#[test]
fn go_wire_metadata_empty_defaults_and_numeric_strings_are_supported() {
    let wire = decode_node_config(json!({
        "node_id":"7","protocol":"VLESS","server_port":"443","listen_ip":"","network":"",
        "networkSettings":null,"routes":null,"tls":"0","tls_settings":{},
        "base_config":{"pull_interval":"30","push_interval":60}
    }))
    .unwrap();
    assert_eq!(wire.node_id, Some(7));
    assert_eq!(wire.spec.protocol, "vless");
    assert_eq!(wire.spec.server_port, 443);
    assert!(wire.spec.listen_ip.is_none());
    assert!(wire.spec.network.is_none());
    assert!(wire.spec.routes.is_empty());
    assert_eq!(wire.base_config.unwrap().pull_interval, 30);
}

#[test]
fn wire_metadata_does_not_hide_unknown_options_or_wrong_types() {
    for value in [
        json!({"protocol":"vless","server_port":443,"base_config":{},"future_limit":1}),
        json!({"protocol":"vless","server_port":443,"base_config":{"future_setting":1}}),
        json!({"protocol":"vless","server_port":"invalid"}),
        json!({"protocol":"vless","server_port":443,"node_id":-1}),
    ] {
        assert!(decode_node_config(value).is_err());
    }
}

#[test]
fn ws_config_accepts_wire_metadata_and_checks_node_ownership() {
    let value = json!({"event":"sync.config","data":{"config":{"node_id":7,"protocol":"vless","server_port":443,"base_config":{"pull_interval":30}}}});
    assert!(matches!(
        parse_ws_message(&serde_json::to_vec(&value).unwrap()).unwrap(),
        Some(node_panel::WsEvent::Config {
            node_id: Some(7),
            ..
        })
    ));
    let value = json!({"event":"sync.config","data":{"node_id":8,"config":{"node_id":7,"protocol":"vless","server_port":443}}});
    assert!(parse_ws_message(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn handshake_ws_endpoints_cannot_forward_credentials_to_a_different_origin() {
    for endpoint in [
        "wss://other.example/ws",
        "wss://panel.example:9443/ws",
        "ws://panel.example/ws",
        "wss://panel.example/ws?token=extra",
    ] {
        assert!(
            WsClient::for_panel(
                "https://panel.example",
                endpoint,
                Auth::machine("fixture", 1, 7),
                Duration::from_secs(1),
                Duration::from_secs(10)
            )
            .is_err()
        );
    }
    assert!(
        WsClient::for_panel(
            "https://panel.example",
            "wss://panel.example/ws",
            Auth::machine("fixture", 1, 7),
            Duration::from_secs(1),
            Duration::from_secs(10)
        )
        .is_ok()
    );
}
