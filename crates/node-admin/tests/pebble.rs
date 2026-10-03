//! Actual ACME interoperability gate. Ignored without a local Pebble process.
//! Pebble must use this HTTP listener's port and PEBBLE_VA_NOSLEEP=1. Do not set
//! PEBBLE_VA_ALWAYS_VALID: this test must exercise real HTTP-01 validation.
use node_admin::{CertConfig, CertificateManager, ChallengeStore};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use tokio::{net::TcpListener, sync::watch};

#[tokio::test]
#[ignore = "requires a local Pebble CA and its local root certificate"]
async fn pebble_http_issuance_renewal_recovery_and_failure_retains_old_pair() {
    let directory =
        std::env::var("XBOARD_PEBBLE_DIRECTORY").expect("local Pebble directory URL required");
    let url = url::Url::parse(&directory).unwrap();
    assert_eq!(url.scheme(), "https");
    assert!(
        matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")),
        "test forbids production/non-loopback CAs"
    );
    let root =
        PathBuf::from(std::env::var("XBOARD_PEBBLE_CA").expect("local Pebble root PEM required"));
    let port: u16 = std::env::var("XBOARD_PEBBLE_HTTP_PORT")
        .unwrap_or_else(|_| "5002".into())
        .parse()
        .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let listener_v6 = TcpListener::bind(("::1", port)).await.unwrap();
    let store = ChallengeStore::default();
    let server_store = store.clone();
    let (shutdown, mut receiver) = watch::channel(false);
    let server =
        tokio::spawn(async move { server_store.serve_listener(listener, &mut receiver).await });
    let server_store_v6 = store.clone();
    let mut receiver_v6 = shutdown.subscribe();
    let server_v6 = tokio::spawn(async move {
        server_store_v6
            .serve_listener(listener_v6, &mut receiver_v6)
            .await
    });
    let state = tempfile::tempdir().unwrap();
    let manager = CertificateManager::new(store.clone());
    let cfg = CertConfig {
        cert_mode: "http".into(),
        domain: "localhost".into(),
        email: "test@example.test".into(),
        http_port: port,
        acme_directory: Some(directory),
        acme_ca_file: Some(root),
        challenge_timeout_seconds: Some(30),
        ..Default::default()
    };
    let first = manager
        // Force the captured request time into a previous second: validation
        // must use issuance completion time for the new certificate notBefore.
        .ensure_at(
            &cfg,
            state.path(),
            time::OffsetDateTime::now_utc().unix_timestamp() - 2,
            false,
        )
        .await
        .expect("actual Pebble HTTP-01 issuance must succeed")
        .unwrap();
    assert!(first.cert.exists() && first.key.exists());
    assert!(first.next_renew_unix < first.not_after_unix);
    let accounts = state.path().join("certs/accounts");
    let files: Vec<_> = std::fs::read_dir(&accounts)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    let account_before = Sha256::digest(std::fs::read(&files[0]).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let unchanged = manager.ensure(&cfg, state.path()).await.unwrap().unwrap();
    assert_eq!(first, unchanged);
    let restarted = CertificateManager::new(store);
    assert_eq!(
        restarted.ensure(&cfg, state.path()).await.unwrap().unwrap(),
        first
    );
    let second = restarted
        .renew(&cfg, state.path())
        .await
        .expect("actual Pebble ACME renewal must succeed")
        .unwrap();
    assert_ne!(first.generation, second.generation);
    assert_eq!(
        account_before,
        Sha256::digest(std::fs::read(&files[0]).unwrap())
    );
    assert!(first.cert.exists());
    assert!(first.key.exists());
    // Changing to a closed loopback CA makes issuance fail without touching the
    // previously committed pair or returning a false successful renewal.
    let closed = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let failing = CertConfig {
        acme_directory: Some(format!("https://127.0.0.1:{closed_port}/dir")),
        challenge_timeout_seconds: Some(2),
        ..cfg.clone()
    };
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            restarted.renew(&failing, state.path())
        )
        .await
        .unwrap()
        .is_err()
    );
    assert_eq!(
        restarted.read_current(&cfg, state.path()).unwrap().unwrap(),
        second
    );
    shutdown.send(true).unwrap();
    server.await.unwrap().unwrap();
    server_v6.await.unwrap().unwrap();
}
