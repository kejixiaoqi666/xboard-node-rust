use super::*;
use arc_swap::ArcSwap;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID_A: &str = "00000000-0000-4000-8000-000000000100";
const UUID_B: &str = "00000000-0000-4000-8000-000000000200";

#[test]
fn reality_key_update_budget_survives_controller_to_engine_mapping() {
    assert_eq!(
        node_core::reality::MAX_KEY_UPDATE_RECORDS,
        node_reality::MAX_KEY_UPDATE_RECORDS
    );
    assert_eq!(
        node_core::reality::MIN_KEY_UPDATE_RECORDS,
        node_reality::MIN_KEY_UPDATE_RECORDS
    );
    let mut settings: node_core::reality::Settings = serde_json::from_value(json!({
        "private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "server_name":"example.test"
    }))
    .unwrap();
    assert_eq!(
        reality_config(&settings).unwrap().key_update_after_records,
        node_reality::MAX_KEY_UPDATE_RECORDS
    );
    settings.key_update_after_records = 16;
    assert_eq!(
        reality_config(&settings).unwrap().key_update_after_records,
        16
    );
    settings.key_update_after_records = 0;
    assert!(reality_config(&settings).is_err());
}

pub(super) fn config(users: Value) -> Value {
    json!({"log":{"level":"error","timestamp":true},"inbounds":[{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":12345,"users":users}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})
}
fn snapshot(id: &str, key: &str) -> auth::Users {
    Arc::new(ArcSwap::from(
        config::decode(
            config(json!([{"name":id,"uuid":key}]))
                .to_string()
                .as_bytes(),
        )
        .unwrap()
        .auth,
    ))
}

#[test]
fn accept_failure_policy_preserves_recoverable_connections() {
    use std::io::{Error, ErrorKind};
    for kind in [
        ErrorKind::ConnectionAborted,
        ErrorKind::ConnectionReset,
        ErrorKind::Interrupted,
        ErrorKind::WouldBlock,
        ErrorKind::TimedOut,
        ErrorKind::OutOfMemory,
    ] {
        assert!(accept_retry_delay(&Error::from(kind)).is_some());
    }
    assert!(accept_retry_delay(&Error::from(ErrorKind::InvalidInput)).is_none());
    #[cfg(target_os = "linux")]
    {
        for code in [23, 24, 64, 71, 92, 95, 100, 101, 105, 112, 113] {
            assert_eq!(
                accept_retry_delay(&Error::from_raw_os_error(code)),
                Some(Duration::from_millis(100))
            );
        }
        // EBADF / EINVAL / ENOTSOCK indicate an unusable listener.
        for code in [9, 22, 88] {
            assert!(accept_retry_delay(&Error::from_raw_os_error(code)).is_none());
        }
    }
}
fn vless(port: u16) -> Vec<u8> {
    let mut data = vec![0];
    data.extend(auth::uuid(UUID_A).unwrap());
    data.extend([0, 1]);
    data.extend(port.to_be_bytes());
    data.extend([1, 127, 0, 0, 1]);
    data
}

#[test]
fn entire_candidate_rejects_duplicates_and_unsupported_fields() {
    for users in [
        json!([{"name":"100","uuid":UUID_A},{"name":"200","uuid":UUID_A.to_uppercase()}]),
        json!([{"name":"100","uuid":UUID_A},{"name":"100","uuid":UUID_B}]),
        json!([{"name":"100","uuid":"invalid"}]),
        json!([{"name":"100","uuid":UUID_A,"flow":"xtls-rprx-vision"}]),
    ] {
        assert!(config::decode(config(users).to_string().as_bytes()).is_err());
    }
    let mut value = config(json!([]));
    value["inbounds"][0]["transport"] = json!({"type":"quic-unsupported"});
    assert!(config::decode(value.to_string().as_bytes()).is_err());
    let mut value = config(json!([]));
    value["outbounds"][0]["type"] = json!("socks");
    assert!(config::decode(value.to_string().as_bytes()).is_err());
    assert!(config::decode(&vec![b' '; config::MAX_CONFIG + 1]).is_err());
}

#[test]
fn concurrent_publication_keeps_stable_identity_and_removal() {
    let users = snapshot("100", UUID_A);
    let mut threads = Vec::new();
    for _ in 0..8 {
        let users = Arc::clone(&users);
        threads.push(std::thread::spawn(move || {
            for _ in 0..1024 {
                assert_eq!(
                    &*users.load().vless(&auth::uuid(UUID_A).unwrap()).unwrap(),
                    "100"
                );
            }
        }));
    }
    for index in 0..1000 {
        let entries = if index % 2 == 0 {
            json!([{"name":"200","uuid":UUID_B},{"name":"100","uuid":UUID_A}])
        } else {
            json!([{"name":"100","uuid":UUID_A}])
        };
        users.store(
            config::decode(config(entries).to_string().as_bytes())
                .unwrap()
                .auth,
        );
    }
    for thread in threads {
        thread.join().unwrap();
    }
    let authenticated = users.load().vless(&auth::uuid(UUID_A).unwrap()).unwrap();
    users.store(
        config::decode(config(json!([])).to_string().as_bytes())
            .unwrap()
            .auth,
    );
    assert!(users.load().vless(&auth::uuid(UUID_A).unwrap()).is_none());
    assert_eq!(&*authenticated, "100");
}

#[tokio::test]
async fn fragmented_vless_preserves_coalesced_payload() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let users = snapshot("100", UUID_A);
    let writer = tokio::spawn(async move {
        let mut wire = vless(443);
        wire.extend(b"payload must not be consumed by the header");
        for part in wire.chunks(3) {
            client.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    let request = protocol::handshake(&mut server, config::Protocol::Vless, &users)
        .await
        .unwrap();
    assert_eq!(&*request.user, "100");
    assert_eq!(request.port, 443);
    assert!(matches!(request.address, protocol::Address::Ip(_)));
    let mut body = Vec::new();
    server.read_to_end(&mut body).await.unwrap();
    writer.await.unwrap();
    assert_eq!(body, b"payload must not be consumed by the header");
}

#[tokio::test]
async fn invalid_vless_version_command_and_addons_never_pass() {
    let users = snapshot("100", UUID_A);
    for (offset, value) in [(0, 1), (17, 1), (18, 4)] {
        let mut header = vless(443);
        header[offset] = value;
        assert!(
            protocol::handshake(&mut header.as_slice(), config::Protocol::Vless, &users)
                .await
                .is_err()
        );
    }
    let mut header = vless(443);
    header[1] ^= 1;
    assert!(
        protocol::handshake(&mut header.as_slice(), config::Protocol::Vless, &users)
            .await
            .is_err()
    );
    for size in 0..vless(443).len() {
        let header = vless(443);
        assert!(
            protocol::handshake(&mut &header[..size], config::Protocol::Vless, &users)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn vless_domain_and_ipv6_wire_types_are_distinct() {
    let users = snapshot("100", UUID_A);
    let mut base = vless(443);
    base.truncate(21);
    let mut domain = base.clone();
    domain.extend([2, 9]);
    domain.extend(b"localhost");
    let request = protocol::handshake(&mut domain.as_slice(), config::Protocol::Vless, &users)
        .await
        .unwrap();
    assert!(matches!(request.address,protocol::Address::Domain(name) if name=="localhost"));
    base.push(3);
    base.extend(std::net::Ipv6Addr::LOCALHOST.octets());
    let request = protocol::handshake(&mut base.as_slice(), config::Protocol::Vless, &users)
        .await
        .unwrap();
    assert!(
        matches!(request.address,protocol::Address::Ip(ip) if ip==std::net::Ipv6Addr::LOCALHOST)
    );
}

#[tokio::test]
async fn trojan_fragmented_authentication_keeps_identity_after_removal() {
    let password = "热更新-Ω-\"\\";
    let users = Arc::new(ArcSwap::from_pointee(
        auth::Snapshot::new(
            config::Protocol::Trojan,
            vec![config::User {
                name: "100".into(),
                uuid: None,
                password: Some(password.into()),
                flow: None,
                speed_limit: 0,
                device_limit: 0,
            }],
        )
        .unwrap(),
    ));
    let (mut client, mut server) = tokio::io::duplex(64);
    let server_users = Arc::clone(&users);
    let task = tokio::spawn(async move {
        protocol::handshake(&mut server, config::Protocol::Trojan, &server_users)
            .await
            .unwrap()
    });
    let key = auth::trojan_key(password);
    for chunk in key.chunks(7) {
        client.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
    }
    // Let the parser authenticate, then block waiting for the request remainder.
    tokio::task::yield_now().await;
    users.store(Arc::new(
        auth::Snapshot::new(config::Protocol::Trojan, Vec::new()).unwrap(),
    ));
    client
        .write_all(&[13, 10, 1, 1, 127, 0, 0, 1, 1, 187, 13, 10])
        .await
        .unwrap();
    let request = task.await.unwrap();
    assert_eq!(&*request.user, "100");
    assert_eq!(request.port, 443);
    let mut wire = key.to_vec();
    wire.extend([13, 10, 1, 1, 127, 0, 0, 1, 1, 187, 13, 10]);
    assert!(
        protocol::handshake(&mut wire.as_slice(), config::Protocol::Trojan, &users)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn slow_metadata_storage_does_not_block_cancellation_or_forward_late_payload() {
    // This runtime has one async thread, matching the production executor.
    // A storage writer owns the same registry mutex during fsync.
    let traffic = Arc::new(traffic::Traffic::new("a".repeat(32)));
    let locked_traffic = Arc::clone(&traffic);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        locked_traffic.with_metadata_locked_for_test(|| {
            entered_tx.send(()).unwrap();
            // Bound even a failing regression so it cannot hang the test run.
            let _ = release_rx.recv_timeout(Duration::from_secs(3));
        });
    });
    entered_rx.await.unwrap();
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut client, server) = tokio::io::duplex(1024);
    let mut wire = vless(target.local_addr().unwrap().port());
    wire.extend(b"must never forward after cancellation");
    client.write_all(&wire).await.unwrap();
    let users = snapshot("100", UUID_A);
    let proxy = tokio::spawn(async move {
        connection(
            server,
            config::Protocol::Vless,
            &users,
            &traffic,
            "127.0.0.1".parse().unwrap(),
            &Arc::new(limits::Registry::default()),
            &Arc::new(tokio::sync::Semaphore::new(1024)),
        )
        .await
    });
    let started = std::time::Instant::now();
    let (mut outbound, _) = tokio::time::timeout(Duration::from_millis(500), target.accept())
        .await
        .unwrap()
        .unwrap();
    // Poll the reservation while the mutex is still held, then cancel it.
    tokio::task::yield_now().await;
    proxy.abort();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), proxy)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled()
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    let mut payload = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(100),
        outbound.read_to_end(&mut payload),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(payload.is_empty());
    release_tx.send(()).unwrap();
    tokio::task::spawn_blocking(move || holder.join().unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn tcp_half_close_retains_reverse_payload() {
    for enabled in [true, false] {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request until EOF");
            stream
                .write_all(b"response after half close")
                .await
                .unwrap();
        });
        let (mut client, server) = tokio::io::duplex(1024);
        let users = snapshot("100", UUID_A);
        let traffic = Arc::new(traffic::Traffic::new_with_enabled("a".repeat(32), enabled));
        let connection_traffic = Arc::clone(&traffic);
        let proxy = tokio::spawn(async move {
            connection(
                server,
                config::Protocol::Vless,
                &users,
                &connection_traffic,
                "127.0.0.1".parse().unwrap(),
                &Arc::new(limits::Registry::default()),
                &Arc::new(tokio::sync::Semaphore::new(1024)),
            )
            .await
            .unwrap()
        });
        let mut request = vless(port);
        request.extend(b"request until EOF");
        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response,
            [&[0, 0][..], b"response after half close"].concat()
        );
        proxy.await.unwrap();
        origin.await.unwrap();
        if enabled {
            assert_eq!(
                traffic.snapshot().unwrap().unwrap().traffic["100"],
                [17, 25]
            );
        } else {
            assert!(traffic.snapshot().unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn vision_addons_match_authenticated_user_for_tcp_udp_and_mux() {
    let users = Arc::new(ArcSwap::from_pointee(
        auth::Snapshot::new(
            config::Protocol::Vless,
            vec![config::User {
                name: "100".into(),
                uuid: Some(UUID_A.into()),
                password: None,
                flow: Some("xtls-rprx-vision".into()),
                speed_limit: 0,
                device_limit: 0,
            }],
        )
        .unwrap(),
    ));
    for (addons, command, accept) in [
        (
            [vec![10, 16], b"xtls-rprx-vision".to_vec()].concat(),
            1,
            true,
        ),
        (vec![], 1, false),
        (
            [vec![10, 16], b"xtls-rprx-vision".to_vec()].concat(),
            2,
            true,
        ),
        (
            [vec![10, 16], b"xtls-rprx-vision".to_vec(), vec![16, 1]].concat(),
            1,
            false,
        ),
        (vec![10, 255], 1, false),
    ] {
        let mut frame = vec![0];
        frame.extend(auth::uuid(UUID_A).unwrap());
        frame.push(addons.len() as u8);
        frame.extend(addons);
        frame.push(command);
        frame.extend([0, 80, 1, 127, 0, 0, 1]);
        let result =
            protocol::handshake(&mut frame.as_slice(), config::Protocol::Vless, &users).await;
        assert_eq!(result.is_ok(), accept);
        if let Ok(request) = result {
            assert_eq!(request.vision_uuid, auth::uuid(UUID_A));
        }
    }
}
