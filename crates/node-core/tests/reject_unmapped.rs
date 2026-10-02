use node_core::NodeSpec;

#[test]
fn full_rust_model_accepts_mapped_tls_settings() {
    let raw = r#"{"protocol":"vless","server_port":443,"tls_settings":{"reality":{"private_key":"test"}}}"#;
    assert!(serde_json::from_str::<NodeSpec>(raw).is_ok());
}
