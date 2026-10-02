#![recursion_limit = "256"]

use node_core::{NodeSpec, StringOrArray};

#[test]
fn decodes_representative_xboard_config_without_dropping_runtime_fields() {
    let raw = serde_json::json!({
        "protocol":"vless", "listen_ip":"0.0.0.0", "server_port":443,
        "network":"ws", "networkSettings":{"path":"/edge","headers":{"Host":"edge.example"}},
        "routes":[{"id":1,"match":["ads"],"action":"block","action_value":""}],
        "kernel_type":"xray", "kernel_log_level":"warn",
        "custom_outbounds":[{"tag":"proxy","protocol":"freedom","settings":{},"proxy_tag":"direct"}],
        "custom_routes":[{"type":"field","outboundTag":"proxy"}],
        "custom_route_rules":[{"name":"rule-1","disabled":false,"match":{"domains":["example.com"]},"action":{"type":"proxy","target":"proxy"}}],
        "auto_tls":false, "domain":"edge.example", "cipher":"aes-128-gcm", "plugin":"", "plugin_opts":"",
        "server_key":"private-key-reference", "tls":2, "flow":"xtls-rprx-vision", "decryption":"none",
        "tls_settings":{"server_name":"edge.example","reality":{"enabled":true}}, "host":"edge.example",
        "server_name":"edge.example", "version":2, "up_mbps":100, "down_mbps":200,
        "obfs":"salamander", "obfs-password":"obfs-secret-reference", "congestion_control":"bbr",
        "padding_scheme":["1-10"], "transport":"tcp", "traffic_pattern":"",
        "multiplex":{"enabled":true,"protocol":"smux","max_connections":4,"min_streams":1,"max_streams":8,"padding":true,"brutal":{"enabled":true,"up_mbps":10,"down_mbps":20}},
        "accept_proxy_protocol":true
    });
    let spec: NodeSpec =
        serde_json::from_value(raw).expect("full representative config must decode");
    assert_eq!(spec.protocol, "vless");
    assert_eq!(spec.listen_ip.as_deref(), Some("0.0.0.0"));
    assert_eq!(spec.network.as_deref(), Some("ws"));
    assert_eq!(spec.tls, 2);
    assert_eq!(spec.custom_outbounds.len(), 1);
    assert_eq!(spec.routes.len(), 1);
    assert_eq!(spec.tls_settings["server_name"], "edge.example");
    assert_eq!(
        spec.padding_scheme
            .as_ref()
            .map(StringOrArray::as_str)
            .as_deref(),
        Some("1-10")
    );
    assert!(
        spec.multiplex
            .as_ref()
            .unwrap()
            .brutal
            .as_ref()
            .unwrap()
            .enabled
    );
    assert!(spec.accept_proxy_protocol);
}

#[test]
fn representative_config_rejects_unmapped_fields() {
    let raw = serde_json::json!({"protocol":"vless","server_port":443,"future_panel_field":true});
    assert!(serde_json::from_value::<NodeSpec>(raw).is_err());
}
