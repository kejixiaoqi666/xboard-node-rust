use node_admin::certificate::CertificateError;
use node_admin::{CertConfig, CertificateManager, Secret};
use std::fs;
#[tokio::test]
async fn self_signed_is_valid_for_ten_years_and_reused_until_due() {
    let temporary = tempfile::tempdir().unwrap();
    let manager = CertificateManager::default();
    let cfg = CertConfig {
        cert_mode: "self".into(),
        domain: "node.example.test".into(),
        ..Default::default()
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let files = manager
        .ensure_at(&cfg, temporary.path(), now, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(files.not_after_unix, now + 10 * 365 * 86400);
    assert_eq!(files.next_renew_unix, files.not_after_unix - 30 * 86400);
    let again = manager
        .ensure_at(&cfg, temporary.path(), now + 86400, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(files, again);
    let renewed = manager
        .ensure_at(&cfg, temporary.path(), files.next_renew_unix + 1, false)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(files.generation, renewed.generation);
    assert!(files.cert.exists());
    assert!(files.key.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [
            &files.cert,
            &files.key,
            &temporary.path().join("certs/current.json"),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
#[tokio::test]
async fn file_and_content_modes_validate_matching_keys_and_preserve_previous_commit_on_failure() {
    let source = tempfile::tempdir().unwrap();
    let manager = CertificateManager::default();
    let self_cfg = CertConfig {
        cert_mode: "self".into(),
        domain: "file.example.test".into(),
        ..Default::default()
    };
    let generated = manager
        .ensure(&self_cfg, source.path())
        .await
        .unwrap()
        .unwrap();
    let target = tempfile::tempdir().unwrap();
    let mut cfg = CertConfig {
        cert_mode: "file".into(),
        domain: self_cfg.domain.clone(),
        cert_file: Some(generated.cert.clone()),
        key_file: Some(generated.key.clone()),
        ..Default::default()
    };
    let loaded = manager.ensure(&cfg, target.path()).await.unwrap().unwrap();
    assert_eq!(
        fs::read(&loaded.cert).unwrap(),
        fs::read(&generated.cert).unwrap()
    );
    assert_eq!(
        manager.ensure(&cfg, target.path()).await.unwrap().unwrap(),
        loaded
    );
    let other = tempfile::tempdir().unwrap();
    let wrong = manager
        .ensure(&self_cfg, other.path())
        .await
        .unwrap()
        .unwrap();
    cfg.key_file = Some(wrong.key);
    assert!(matches!(
        manager.ensure(&cfg, target.path()).await,
        Err(CertificateError::Material)
    ));
    assert_eq!(
        manager.read_current(&cfg, target.path()).unwrap().unwrap(),
        loaded
    );
    let content_target = tempfile::tempdir().unwrap();
    cfg.cert_mode = "content".into();
    cfg.cert_content = Secret::new(fs::read_to_string(&generated.cert).unwrap());
    cfg.key_content = Secret::new(fs::read_to_string(&generated.key).unwrap());
    let serialized = serde_json::to_string(&cfg).unwrap();
    assert!(!serialized.contains("PRIVATE KEY"));
    assert!(!format!("{cfg:?}").contains("PRIVATE KEY"));
    let content = manager
        .ensure(&cfg, content_target.path())
        .await
        .unwrap()
        .unwrap();
    cfg.key_content = Secret::new("bad-private-key");
    assert!(manager.ensure(&cfg, content_target.path()).await.is_err());
    assert_eq!(
        manager
            .read_current(&cfg, content_target.path())
            .unwrap()
            .unwrap(),
        content
    );
}
#[tokio::test]
async fn locks_exclude_a_second_issuer_and_non_tls_mode_never_creates_state() {
    use fs2::FileExt;
    let temporary = tempfile::tempdir().unwrap();
    let manager = CertificateManager::default();
    let cfg = CertConfig {
        cert_mode: "self".into(),
        ..Default::default()
    };
    manager.ensure(&cfg, temporary.path()).await.unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(temporary.path().join("certs/.certificate.lock"))
        .unwrap();
    file.lock_exclusive().unwrap();
    assert!(matches!(
        manager.renew(&cfg, temporary.path()).await,
        Err(CertificateError::Busy)
    ));
    FileExt::unlock(&file).unwrap();
    let absent = temporary.path().join("absent");
    assert!(
        manager
            .ensure(&CertConfig::default(), &absent)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!absent.exists());
}
#[tokio::test]
async fn original_go_flat_files_are_adopted_and_corrupt_pointer_fails_closed() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let manager = CertificateManager::default();
    let cfg = CertConfig {
        cert_mode: "self".into(),
        domain: "legacy.example.test".into(),
        ..Default::default()
    };
    let original = manager.ensure(&cfg, source.path()).await.unwrap().unwrap();
    let legacy_dir = target.path().join("certs");
    fs::create_dir_all(&legacy_dir).unwrap();
    fs::copy(&original.cert, legacy_dir.join("cert.pem")).unwrap();
    fs::copy(&original.key, legacy_dir.join("key.pem")).unwrap();
    let imported = manager.ensure(&cfg, target.path()).await.unwrap().unwrap();
    assert_eq!(
        fs::read(&imported.cert).unwrap(),
        fs::read(&original.cert).unwrap()
    );
    assert_eq!(
        fs::read(&imported.key).unwrap(),
        fs::read(&original.key).unwrap()
    );
    assert!(legacy_dir.join("cert.pem").exists());
    assert!(legacy_dir.join("key.pem").exists());
    fs::write(legacy_dir.join("current.json"), b"corrupt").unwrap();
    assert!(matches!(
        manager.renew(&cfg, target.path()).await,
        Err(CertificateError::Storage)
    ));
    assert!(imported.cert.exists());
    assert!(imported.key.exists());
}
#[test]
fn mode_priority_and_acme_security_match_intended_contract() {
    let mut cfg = CertConfig::default();
    assert_eq!(cfg.mode(), "none");
    cfg.cert_file = Some("cert.pem".into());
    cfg.key_file = Some("key.pem".into());
    assert_eq!(cfg.mode(), "file");
    cfg.cert_content = Secret::new("cert");
    cfg.key_content = Secret::new("key");
    assert_eq!(cfg.mode(), "content");
    cfg.auto_tls = true;
    assert_eq!(cfg.mode(), "http");
    cfg.domain = "*.example.test".into();
    assert!(cfg.validate().is_err());
    cfg.cert_mode = "dns".into();
    assert!(cfg.validate().is_ok());
    cfg.acme_directory = Some("http://remote.example.test/directory".into());
    cfg.allow_loopback_acme_http = true;
    assert!(cfg.validate().is_err());
    cfg.acme_directory = Some("http://localhost:1234/directory".into());
    assert!(cfg.validate().is_ok());
    let alias: CertConfig =
        serde_json::from_str("{\"mode\":\"self\",\"domain\":\"node.test\"}").unwrap();
    assert_eq!(alias.mode(), "self");
    let both: CertConfig =
        serde_json::from_str("{\"mode\":\"http\",\"cert_mode\":\" SELF \"}").unwrap();
    assert_eq!(both.mode(), "self");
}
