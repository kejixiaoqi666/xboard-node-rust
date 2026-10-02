use node_core::{NodeSpec, UserSpec};
use node_kernel::{KernelError, SingBoxConfigBuilder};
use serde_json::Value;

fn user(id: i64, uuid: &str) -> UserSpec {
    UserSpec::new(id, uuid)
}

#[test]
fn builds_vless_inbound_with_users_and_direct_outbound() {
    let config = SingBoxConfigBuilder::new()
        .build(
            &NodeSpec::new("vless", 443),
            &[user(7, "00000000-0000-4000-8000-000000000007")],
        )
        .unwrap();
    assert_eq!(config["inbounds"][0]["type"], "vless");
    assert_eq!(config["inbounds"][0]["listen_port"], 443);
    assert_eq!(
        config["inbounds"][0]["users"][0]["uuid"],
        "00000000-0000-4000-8000-000000000007"
    );
    assert_eq!(
        config["outbounds"][0],
        serde_json::json!({"type":"direct","tag":"direct"})
    );
}

#[test]
fn unsupported_protocol_and_empty_uuid_are_rejected_before_config_generation() {
    assert!(matches!(
        SingBoxConfigBuilder::new().build(&NodeSpec::new("wireguard", 443), &[]),
        Err(KernelError::Invalid(_))
    ));
    assert!(matches!(
        SingBoxConfigBuilder::new().build(&NodeSpec::new("vless", 443), &[user(2, "uuid")]),
        Err(KernelError::Invalid(_))
    ));
}

#[test]
fn generated_config_is_json_and_has_no_panel_auth_fields() {
    let mut node = NodeSpec::new("trojan", 8443);
    node.tls = 1;
    node.cert_config = Some(
        serde_json::json!({"cert_mode":"file", "cert_file":std::env::temp_dir().join("test-cert.pem"), "key_file":std::env::temp_dir().join("test-key.pem")}),
    );
    let config = SingBoxConfigBuilder::new()
        .build(&node, &[user(1, "00000000-0000-4000-8000-000000000001")])
        .unwrap();
    let encoded = serde_json::to_vec(&config).unwrap();
    let _: Value = serde_json::from_slice(&encoded).unwrap();
    assert!(encoded.windows(5).all(|w| w != b"token"));
    assert_eq!(config["inbounds"][0]["tls"]["enabled"], true);
}

#[test]
fn duplicate_credentials_are_rejected_before_output_including_uuid_case_aliases() {
    let mut output = Vec::new();
    let users = [
        user(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        user(2, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ];
    let error = SingBoxConfigBuilder::new()
        .write_json(&mut output, &NodeSpec::new("vless", 443), &users)
        .unwrap_err();
    assert!(matches!(error, KernelError::Invalid(_)));
    assert!(output.is_empty());
    let mut node = NodeSpec::new("trojan", 8443);
    node.tls = 1;
    node.cert_config = Some(
        serde_json::json!({"cert_mode":"file","cert_file":std::env::temp_dir().join("test-cert.pem"),"key_file":std::env::temp_dir().join("test-key.pem")}),
    );
    assert!(
        SingBoxConfigBuilder::new()
            .write_json(
                &mut output,
                &node,
                &[user(1, "same-password"), user(2, "same-password")]
            )
            .is_err()
    );
    assert!(output.is_empty());
}

#[test]
fn unimplemented_tls_routes_and_limits_cannot_be_silently_dropped() {
    let mut tls = NodeSpec::new("vless", 443);
    tls.tls = 2;
    assert!(SingBoxConfigBuilder::new().build(&tls, &[]).is_err());
    let mut route = NodeSpec::new("vless", 443);
    route
        .custom_routes
        .push(serde_json::json!({"action":"reject"}));
    assert!(SingBoxConfigBuilder::new().build(&route, &[]).is_err());
    let mut limited = user(1, "00000000-0000-4000-8000-000000000001");
    limited.speed_limit = 10;
    assert!(
        SingBoxConfigBuilder::new()
            .build(&NodeSpec::new("vless", 443), &[limited])
            .is_err()
    );
    assert!(
        SingBoxConfigBuilder::new()
            .build(&NodeSpec::new("trojan", 443), &[])
            .is_err()
    );
}

#[test]
fn streamed_vless_and_trojan_match_complete_legacy_config_bytes() {
    for protocol in ["vless", "trojan"] {
        let mut node = NodeSpec::new(protocol, 8443);
        node.listen_ip = Some("127.0.0.1".into());
        node.kernel_log_level = Some("warn".into());
        let credential = if protocol == "vless" {
            "00000000-0000-4000-8000-000000000007"
        } else {
            "password with \"quotes\", \\ slash and 中文"
        };
        let mut expected_inbound = serde_json::json!({
            "type": protocol, "tag": format!("{protocol}-in"),
            "listen": "127.0.0.1", "listen_port": 8443,
            "users": [{"name": "7", if protocol == "vless" { "uuid" } else { "password" }: credential}]
        });
        if protocol == "trojan" {
            node.tls = 1;
            let certificate = std::env::temp_dir().join("stream-test-cert.pem");
            let key = std::env::temp_dir().join("stream-test-key.pem");
            node.cert_config =
                Some(serde_json::json!({"mode":"file", "cert_file": certificate, "key_file": key}));
            node.server_name = Some("example.test".into());
            expected_inbound["tls"] = serde_json::json!({"enabled":true, "certificate_path":certificate,
                "key_path":key, "server_name":"example.test"});
        }
        let expected = serde_json::json!({
            "log": {"level":"warn", "timestamp":true}, "inbounds":[expected_inbound],
            "outbounds":[{"type":"direct", "tag":"direct"}], "route":{"final":"direct"}
        });
        let users = [user(7, credential)];
        let builder = SingBoxConfigBuilder::new();
        let mut encoded = Vec::new();
        builder.write_json(&mut encoded, &node, &users).unwrap();
        assert_eq!(encoded, serde_json::to_vec(&expected).unwrap());
        assert_eq!(builder.build(&node, &users).unwrap(), expected);
        assert_eq!(users[0].uuid, credential);
    }
}

#[test]
fn invalid_streamed_config_never_writes_and_output_errors_propagate() {
    struct RefusesOutput;
    impl std::io::Write for RefusesOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected write failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let builder = SingBoxConfigBuilder::new();
    let node = NodeSpec::new("vless", 443);
    let mut encoded = Vec::new();
    assert!(matches!(
        builder.write_json(&mut encoded, &node, &[user(1, "invalid")]),
        Err(KernelError::Invalid(_))
    ));
    assert!(encoded.is_empty());
    assert!(matches!(
        builder.write_json(
            RefusesOutput,
            &node,
            &[user(1, "00000000-0000-4000-8000-000000000001")]
        ),
        Err(KernelError::Prepare(_))
    ));
}
