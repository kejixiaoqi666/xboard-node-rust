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

#[test]
fn key_update_budget_defaults_and_rejects_disable_overflow_and_wrong_types() {
    use node_core::reality::{MAX_KEY_UPDATE_RECORDS, MIN_KEY_UPDATE_RECORDS};
    assert_eq!(
        serde_json::from_value::<Settings>(base())
            .unwrap()
            .key_update_after_records,
        MAX_KEY_UPDATE_RECORDS
    );
    for count in [MIN_KEY_UPDATE_RECORDS, MAX_KEY_UPDATE_RECORDS] {
        let mut value = base();
        value["key_update_after_records"] = json!(count);
        let settings: Settings = serde_json::from_value(value).unwrap();
        settings.validate().unwrap();
        assert_eq!(
            serde_json::to_value(settings).unwrap()["key_update_after_records"],
            count
        );
    }
    for count in [0, 15, MAX_KEY_UPDATE_RECORDS + 1, u64::MAX] {
        let mut value = base();
        value["key_update_after_records"] = json!(count);
        assert!(
            serde_json::from_value::<Settings>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for count in [json!(-1), json!(16.5), json!("16"), json!(null)] {
        let mut value = base();
        value["key_update_after_records"] = count;
        assert!(serde_json::from_value::<Settings>(value).is_err());
    }
}
