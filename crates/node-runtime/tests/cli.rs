#[path = "../../../tests/support/mod.rs"]
mod support;
use serde_json::json;
use std::process::Command;

#[test]
fn check_validates_settings_without_a_token_or_external_side_effects() {
    let dir = support::TestDir::new();
    let config = dir.0.join("runtime.json");
    std::fs::write(
        &config,
        json!({
            "panel_url":"https://panel.example.com","token_env":"XBORD_CLI_FIXTURE_MISSING_TOKEN",
            "node_id":7,"machine_id":1,"singbox_executable":dir.0.join("not-installed-kernel.exe"),
            "state_dir":dir.0.join("not-created-state"),"poll_seconds":30
        })
        .to_string(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_xboard-node-rust"))
        .arg("--config")
        .arg(&config)
        .arg("--check")
        .env_remove("XBORD_CLI_FIXTURE_MISSING_TOKEN")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("compatibility not tested"));
    assert!(!dir.0.join("not-created-state").exists());
}

#[test]
fn malformed_config_and_oversized_input_have_bounded_redacted_errors() {
    let dir = support::TestDir::new();
    let path = dir.0.join("bad.json");
    for bytes in [
        b"{\"token\":\"fixture-secret-do-not-log\"}".to_vec(),
        vec![b'x'; 65537],
    ] {
        std::fs::write(&path, bytes).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_xboard-node-rust"))
            .arg("--config")
            .arg(&path)
            .arg("--check")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("fixture-secret-do-not-log"));
        assert!(error.len() < 256);
    }
}

#[test]
fn native_mode_settings_are_explicit_and_unix_only() {
    let dir = support::TestDir::new();
    let path = dir.0.join("native.json");
    std::fs::write(
        &path,
        json!({
            "panel_url":"https://panel.example.com","token_env":"XBORD_CLI_FIXTURE_MISSING_TOKEN",
            "node_id":7,"machine_id":1,"singbox_executable":dir.0.join("native-kernel"),
            "state_dir":dir.0.join("not-created-state"),"native_user_updates":true
        })
        .to_string(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_xboard-node-rust"))
        .arg("--config")
        .arg(path)
        .arg("--check")
        .env_remove("XBORD_CLI_FIXTURE_MISSING_TOKEN")
        .output()
        .unwrap();
    assert_eq!(output.status.success(), cfg!(unix));
    assert!(!dir.0.join("not-created-state").exists());
}

#[test]
fn omitted_external_kernel_selects_builtin_rust_without_files_or_token() {
    let dir = support::TestDir::new();
    let path = dir.0.join("builtin.json");
    std::fs::write(&path,json!({"panel_url":"https://panel.example.com","token_env":"XBORD_CLI_FIXTURE_MISSING_TOKEN","node_id":7,"machine_id":1,"state_dir":dir.0.join("unused-state")}).to_string()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_xboard-node-rust"))
        .args(["--config", path.to_str().unwrap(), "--check"])
        .env_remove("XBORD_CLI_FIXTURE_MISSING_TOKEN")
        .output()
        .unwrap();
    assert_eq!(output.status.success(), cfg!(unix));
    assert!(!dir.0.join("unused-state").exists());
}
