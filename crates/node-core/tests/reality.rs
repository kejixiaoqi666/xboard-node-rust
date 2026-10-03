use node_core::reality::Settings;
use serde_json::json;
fn base() -> serde_json::Value {
    json!({"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","server_name":"example.test","short_id":["1234","5678"],"dest":"[::1]:8443"})
}
#[test]
fn panel_reality_settings_are_bounded_and_private_debug_is_redacted() {
    let settings: Settings = serde_json::from_value(base()).unwrap();
    settings.validate().unwrap();
    assert_eq!(settings.endpoint().unwrap(), ("::1".into(), 8443));
    assert!(!format!("{settings:?}").contains(&settings.private_key));
    for (key, value) in [
        ("private_key", json!("bad")),
        ("short_id", json!(["1"])),
        ("short_id", json!([])),
        ("dest", json!("example.test:0")),
        ("server_name", json!("bad/path")),
        ("max_time_diff", json!(3_600_001)),
    ] {
        let mut v = base();
        v[key] = value;
        let s: Settings = serde_json::from_value(v).unwrap();
        assert!(s.validate().is_err());
    }
    let mut v = base();
    v["unsupported_security"] = json!(true);
    assert!(serde_json::from_value::<Settings>(v).is_err());
}
