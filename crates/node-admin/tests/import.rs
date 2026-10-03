use node_admin::{ImportError, SecretPlan, import_go_yaml};
use std::path::Path;
fn source() -> std::path::PathBuf {
    std::env::temp_dir().join("go-import-source/config.yml")
}
const PANEL: &str = "panel:\n  url: https://panel.example.test\n  token: panel-top-secret\n  node_id: 2\n  node_type: vless\n";
#[test]
fn plaintext_tokens_are_planned_and_never_serialized_or_debugged() {
    let imported = import_go_yaml(PANEL, &source()).unwrap();
    let encoded = serde_json::to_string(&imported).unwrap();
    assert!(!encoded.contains("panel-top-secret"));
    assert!(!format!("{imported:?}").contains("panel-top-secret"));
    assert!(encoded.contains("token_env"));
    assert_eq!(imported.secrets.names().len(), 1);
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("secrets.json");
    imported.secrets.write_private_json(&path).unwrap();
    assert!(imported.secrets.write_private_json(&path).is_err());
    let reloaded = SecretPlan::read_private_json(&path).unwrap();
    assert_eq!(reloaded.names(), imported.secrets.names());
}
#[test]
fn token_env_is_preserved_without_reading_process_environment() {
    let input = PANEL.replace("token: panel-top-secret", "token_env: PANEL_TOKEN");
    let imported = import_go_yaml(&input, &source()).unwrap();
    assert!(imported.secrets.is_empty());
    assert_eq!(imported.fleet.nodes[0].runtime["token_env"], "PANEL_TOKEN");
}
#[test]
fn relative_paths_use_original_go_working_directory_and_default_state_uses_source_location() {
    let temporary = tempfile::tempdir().unwrap();
    let working = temporary.path().join("go-cwd");
    let source = temporary.path().join("configuration/config.yml");
    let input = format!(
        "{PANEL}kernel: {{config_dir: local-state, geo_data_dir: ../geodata, custom_config: kernel.json}}\ncert: {{cert_mode: file, cert_file: cert.pem, key_file: key.pem}}\nlog: {{output: application.log}}\n"
    );
    let imported =
        node_admin::import_go_yaml_with_working_directory(&input, &source, &working).unwrap();
    let node = &imported.fleet.nodes[0];
    assert_eq!(node.kernel.config_dir, working.join("local-state"));
    assert_eq!(node.kernel.geo_data_dir, temporary.path().join("geodata"));
    assert_eq!(node.kernel.custom_config, Some(working.join("kernel.json")));
    assert_eq!(node.cert.cert_file, Some(working.join("cert.pem")));
    assert_eq!(
        std::path::PathBuf::from(&node.log.output),
        working.join("application.log")
    );
    let default =
        node_admin::import_go_yaml_with_working_directory(PANEL, &source, &working).unwrap();
    assert_eq!(
        default.fleet.nodes[0].kernel.config_dir,
        source.parent().unwrap()
    );
}
#[test]
fn fleet_inherits_true_go_defaults_and_reordering_preserves_ids() {
    let input = "node: {pull_interval: 17, track_interval: 7}\nws: {backoff_max: 90}\nlog: {level: warn}\nkernel: {config_dir: /do-not-inherit}\ninstances:\n  - panel: {url: 'https://one.example.test', token_env: ONE, node_id: 1, node_type: vless}\n  - panel: {url: 'https://two.example.test', token_env: TWO, node_id: 2, node_type: trojan}\n    node: {pull_interval: 23}\n";
    let imported = import_go_yaml(input, &source()).unwrap();
    let nodes = &imported.fleet.nodes;
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].intervals.pull_interval, 17);
    assert_eq!(nodes[1].intervals.pull_interval, 23);
    assert_eq!(nodes[0].intervals.track_interval, 7);
    assert_eq!(nodes[1].websocket.backoff_max, 90);
    assert_eq!(nodes[1].log.level, "warn");
    assert_ne!(nodes[0].kernel.config_dir, Path::new("/do-not-inherit"));
    assert_ne!(nodes[0].kernel.config_dir, nodes[1].kernel.config_dir);
    let suffix = input.split("instances:\n").nth(1).unwrap();
    let chunks: Vec<_> = suffix
        .split("  - panel:")
        .filter(|s| !s.is_empty())
        .collect();
    let reversed = format!(
        "{}instances:\n  - panel:{}  - panel:{}",
        input.split("instances:\n").next().unwrap(),
        chunks[1],
        chunks[0]
    );
    let again = import_go_yaml(&reversed, &source()).unwrap();
    assert_eq!(nodes[0].id, again.fleet.nodes[1].id);
    assert_eq!(
        nodes[0].kernel.config_dir,
        again.fleet.nodes[1].kernel.config_dir
    );
}
#[test]
fn multinode_overrides_replace_cert_and_keep_geodata_inheritance() {
    let input = "panel: {url: 'https://one.example.test', token_env: ONE}\nkernel: {config_dir: /nodes}\ncert: {cert_mode: self, domain: inherited.example.test}\nnodes:\n  - node_id: 7\n    node_type: vless\n  - node_id: 8\n    node_type: trojan\n    kernel: {config_dir: /other, log_level: info}\n    cert: {cert_mode: none}\n";
    let imported = import_go_yaml(input, &source()).unwrap();
    let nodes = &imported.fleet.nodes;
    assert_eq!(nodes[0].kernel.config_dir, Path::new("/nodes/node-7"));
    assert_eq!(nodes[0].kernel.geo_data_dir, Path::new("/nodes"));
    assert_eq!(nodes[1].kernel.config_dir, Path::new("/other"));
    assert_eq!(nodes[1].kernel.geo_data_dir, Path::new("/other"));
    assert_eq!(nodes[1].cert.mode(), "none");
    assert!(nodes[1].cert.domain.is_empty());
    assert_ne!(nodes[0].id, nodes[1].id);
}
#[test]
fn unknown_fields_gc_and_negative_intervals_are_explicit_errors_without_secret_values() {
    for tail in [
        "node: {mispelled: 12}",
        "runtime: {gogc: 50}",
        "runtime: {gomemlimit: 30MiB}",
        "node: {pull_interval: -1}",
        "cert: {key_content: hidden, cert_mode: invalid}",
    ] {
        let error = import_go_yaml(&format!("{PANEL}{tail}\n"), &source()).unwrap_err();
        assert!(!error.to_string().contains("panel-top-secret"));
        assert!(!error.to_string().contains("hidden"));
    }
    assert!(matches!(
        import_go_yaml(&format!("{PANEL}forgotten: 3"), &source()),
        Err(ImportError::Unmapped(_))
    ));
}
#[test]
fn same_or_nested_state_directories_and_duplicate_bindings_are_rejected() {
    for (first, second) in [("/shared", "/shared"), ("/shared", "/shared/subdir")] {
        let input = format!(
            "instances:\n - panel: {{url: 'https://one.example.test', token_env: ONE, node_id: 1, node_type: vless}}\n   kernel: {{config_dir: {first}}}\n - panel: {{url: 'https://two.example.test', token_env: TWO, node_id: 2, node_type: vless}}\n   kernel: {{config_dir: {second}}}\n"
        );
        assert!(matches!(
            import_go_yaml(&input, &source()),
            Err(ImportError::Conflict(_))
        ));
    }
    let input = "panel: {url: 'https://one.example.test', token_env: ONE}\nnodes: [{node_id: 1, node_type: vless}, {node_id: 1, node_type: trojan}]";
    assert!(matches!(
        import_go_yaml(input, &source()),
        Err(ImportError::Conflict(_))
    ));
}
#[test]
fn machines_are_templates_and_discovered_nodes_get_distinct_directories() {
    let input = "panel: {url: 'https://panel.example.test'}\nmachine: {machine_id: 19, token_env: MACHINE_TOKEN}\nnode: {push_interval: 31}\n";
    let imported = import_go_yaml(input, &source()).unwrap();
    assert!(imported.fleet.nodes.is_empty());
    let machine = &imported.fleet.machines[0];
    assert_eq!(machine.machine_id, 19);
    assert_eq!(machine.token_env, "MACHINE_TOKEN");
    let one = machine.expand(2, "vless").unwrap();
    let two = machine.expand(3, "trojan").unwrap();
    assert_ne!(one.kernel.config_dir, two.kernel.config_dir);
    assert_eq!(one.runtime["machine_id"], 19);
    assert_eq!(one.runtime["token_env"], "MACHINE_TOKEN");
    assert_eq!(one.cert.cert_dir, Some(one.kernel.config_dir.join("certs")));
    assert!(
        import_go_yaml(
            &format!("{input}nodes: [{{node_id: 3, node_type: vless}}]"),
            &source()
        )
        .is_err()
    );
}
#[test]
fn standalone_mapping_preserves_routes_network_and_obfs_without_public_credentials() {
    let input = "standalone:\n enabled: true\n node:\n  protocol: hysteria2\n  server_port: 443\n  listen_ip: '::'\n  network_settings: {path: /ws}\n  obfs_password: obfs-secret\n  tls: 1\n  padding_scheme: 'stop=8'\n  routes: [{id: 2, match: [example.test], action: block}]\n users: [{id: 1, uuid: user-secret, speed_limit: 33, device_limit: 2}]\ncert: {cert_mode: self, domain: node.example.test}\n";
    let imported = import_go_yaml(input, &source()).unwrap();
    let public = serde_json::to_string(&imported.fleet).unwrap();
    assert!(!public.contains("obfs-secret"));
    assert!(!public.contains("user-secret"));
    let snapshot = imported.fleet.nodes[0]
        .standalone
        .as_ref()
        .unwrap()
        .resolve(&imported.secrets)
        .unwrap();
    assert_eq!(snapshot.node.network_settings["path"], "/ws");
    assert_eq!(snapshot.node.obfs_password.as_deref(), Some("obfs-secret"));
    assert_eq!(snapshot.users[0].speed_limit, 33);
    assert_eq!(snapshot.node.routes.len(), 1);
}
#[test]
fn dns_and_custom_outbound_secrets_are_references_and_runtime_features_are_mandatory() {
    let input = format!(
        "{PANEL}cert: {{cert_mode: dns, domain: '*.example.test', dns_provider: cloudflare, dns_env: {{CF_API_TOKEN: cloudflare-secret}}}}\nkernel:\n custom_outbound: [{{type: socks, server: proxy.example.test, password: proxy-secret}}]\n"
    );
    let imported = import_go_yaml(&input, &source()).unwrap();
    let public = serde_json::to_string(&imported.fleet).unwrap();
    for secret in ["cloudflare-secret", "proxy-secret", "panel-top-secret"] {
        assert!(!public.contains(secret));
    }
    assert!(imported.fleet.validate_runtime_features(&[]).is_err());
    let features: Vec<_> = imported
        .fleet
        .required_runtime_features
        .iter()
        .map(String::as_str)
        .collect();
    imported.fleet.validate_runtime_features(&features).unwrap();
    assert_eq!(
        imported.fleet.nodes[0]
            .kernel
            .resolve_custom_outbound(&imported.secrets)
            .unwrap()[0]["password"],
        "proxy-secret"
    );
}
