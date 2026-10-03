mod support;
use node_extended::{Config, Protocol};
use node_session::Host;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

#[tokio::test]
async fn anytls_v2_multiple_tcp_streams_payload_accounting_and_cancel_join() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let host = TestHost::new();
        let server_host = host.clone();
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let (cancel, rx) = watch::channel(false);
        let server = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            Config::default(),
            Box::new(server),
            peer(),
            server_host,
            Some(rx),
        ));
        anytls_auth(&mut client).await;
        let (cmd, _, _) = read_frame(&mut client).await;
        assert_eq!(cmd, 6);
        let (cmd, _, bytes) = read_frame(&mut client).await;
        assert_eq!(cmd, 10);
        assert_eq!(bytes, b"v=2");
        for id in 1..=3 {
            frame(&mut client, 1, id, &[]).await;
            let mut request = vec![1, 127, 0, 0, 1, 0, 80];
            request.extend_from_slice(b"logical TCP payload");
            frame(&mut client, 2, id, &request).await;
        }
        let mut payloads = 0;
        while payloads < 3 {
            let (cmd, _, bytes) = read_frame(&mut client).await;
            match cmd {
                7 => assert!(bytes.is_empty()),
                2 => {
                    assert_eq!(bytes, b"logical TCP payload");
                    payloads += 1;
                }
                _ => panic!("unexpected cmd {cmd}"),
            }
        }
        assert_eq!(host.totals(), (57, 57));
        assert_eq!(host.active.load(Ordering::SeqCst), 3);
        frame(&mut client, 8, 42, &[]).await;
        assert_eq!(read_frame(&mut client).await, (9, 42, vec![]));
        cancel.send(true).unwrap();
        server.await.unwrap().unwrap();
        assert_eq!(host.active.load(Ordering::SeqCst), 0);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn anytls_uot_v2_connect_and_multi_destination_payload_only() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for connected in [0u8, 1] {
            let host = TestHost::new();
            let (mut client, server) = tokio::io::duplex(1 << 20);
            let (cancel, rx) = watch::channel(false);
            let server = tokio::spawn(node_extended::serve(
                Protocol::AnyTls,
                Config::default(),
                Box::new(server),
                peer(),
                host.clone(),
                Some(rx),
            ));
            anytls_auth(&mut client).await;
            let _ = read_frame(&mut client).await;
            let _ = read_frame(&mut client).await;
            frame(&mut client, 1, 1, &[]).await;
            let magic = b"sp.v2.udp-over-tcp.arpa";
            let mut request = vec![3, magic.len() as u8];
            request.extend_from_slice(magic);
            request.extend_from_slice(&[0, 0, connected, 1, 127, 0, 0, 1, 0, 53]);
            if connected == 0 {
                request.extend_from_slice(&[0, 127, 0, 0, 1, 0, 53]);
            }
            request.extend_from_slice(&[0, 6]);
            request.extend_from_slice(b"packet");
            frame(&mut client, 2, 1, &request).await;
            assert_eq!(read_frame(&mut client).await, (7, 1, vec![]));
            let mut response = vec![];
            let want = if connected == 0 { 15 } else { 8 };
            while response.len() < want {
                let (cmd, id, data) = read_frame(&mut client).await;
                assert_eq!((cmd, id), (2, 1));
                response.extend_from_slice(&data);
            }
            assert_eq!(&response[response.len() - 6..], b"packet");
            assert_eq!(host.totals(), (6, 6));
            cancel.send(true).unwrap();
            server.await.unwrap().unwrap();
            assert_eq!(host.active.load(Ordering::SeqCst), 0);
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn anytls_hot_user_revocation_is_checked_on_stream_admission() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = TestHost::new();
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            Config::default(),
            Box::new(server),
            peer(),
            host.clone(),
            None,
        ));
        anytls_auth(&mut client).await;
        let _ = read_frame(&mut client).await;
        let _ = read_frame(&mut client).await;
        *host.users.write().unwrap() = Arc::from([]);
        frame(&mut client, 1, 1, &[]).await;
        frame(&mut client, 2, 1, &[1, 127, 0, 0, 1, 0, 80]).await;
        let (cmd, _, err) = read_frame(&mut client).await;
        assert_eq!(cmd, 7);
        assert!(!err.is_empty());
        assert_eq!(host.totals(), (0, 0));
        assert_eq!(host.active.load(Ordering::SeqCst), 0);
        drop(client);
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn xudp_udp_domains_multiple_sessions_payload_only_and_cancel() {
    use node_extended::mux::xudp::frame::{
        FrameMetadata, FrameOption, SessionStatus, TargetNetwork,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let host = TestHost::new();
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let (cancel, rx) = watch::channel(false);
        let user = host.users()[0].clone();
        let server = tokio::spawn(node_extended::mux::serve_xudp(
            Box::new(server),
            user,
            peer(),
            host.clone(),
            Config::default(),
            Some(rx),
        ));
        // Raw independent NEW frames include GlobalID, domain destinations and fragmented writes.
        for id in [7u16, 9] {
            let domain = b"dns.example";
            let mut metadata = vec![];
            metadata.extend_from_slice(&id.to_be_bytes());
            metadata.extend_from_slice(&[1, 1, 2, 0, 53, 2, domain.len() as u8]);
            metadata.extend_from_slice(domain);
            metadata.extend_from_slice(&[0; 8]);
            client.write_u16(metadata.len() as u16).await.unwrap();
            for byte in metadata {
                client.write_u8(byte).await.unwrap();
            }
            client.write_u16(5).await.unwrap();
            client.write_all(b"xudp!").await.unwrap();
        }
        for _ in 0..2 {
            let len = client.read_u16().await.unwrap();
            let mut bytes = bytes::BytesMut::new();
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.resize(2 + len as usize, 0);
            client.read_exact(&mut bytes[2..]).await.unwrap();
            let metadata = FrameMetadata::decode(&mut bytes).unwrap().unwrap();
            assert_eq!(metadata.status, SessionStatus::Keep);
            assert!(metadata.option.has_data());
            assert_eq!(metadata.network, Some(TargetNetwork::Udp));
            assert_eq!(client.read_u16().await.unwrap(), 5);
            let mut b = [0; 5];
            client.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"xudp!");
        }
        assert_eq!(host.totals(), (10, 10));
        cancel.send(true).unwrap();
        server.await.unwrap().unwrap();
        assert_eq!(host.active.load(Ordering::SeqCst), 0);
        let _ = FrameOption::new();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn malformed_xudp_metadata_is_error_without_panic_or_host_admission() {
    let host = TestHost::new();
    let (mut client, server) = tokio::io::duplex(64);
    let user = host.users()[0].clone();
    let task = tokio::spawn(node_extended::mux::serve_xudp(
        Box::new(server),
        user,
        peer(),
        host.clone(),
        Config::default(),
        None,
    ));
    client.write_all(&[0, 5, 0, 1, 1, 0, 2]).await.unwrap();
    drop(client);
    assert!(task.await.unwrap().is_err());
    assert_eq!(host.totals(), (0, 0));
}
#[tokio::test]
async fn websocket_path_early_data_binary_payload_and_ping() {
    use base64::Engine;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let mut server = node_extended::websocket::accept(
                Box::new(server),
                node_extended::websocket::WebSocketConfig {
                    path: Some("/proxy".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let mut bytes = [0; 10];
            server.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"earlyhello");
            server.write_all(&bytes).await.unwrap();
            server.flush().await.unwrap();
        });
        let mut request = "ws://localhost/proxy".into_client_request().unwrap();
        request.headers_mut().insert(
            "sec-websocket-protocol",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(b"early")
                .parse()
                .unwrap(),
        );
        let (mut ws, _) = tokio_tungstenite::client_async(request, client)
            .await
            .unwrap();
        ws.send(Message::Ping(bytes::Bytes::from_static(b"probe")))
            .await
            .unwrap();
        ws.send(Message::Binary(bytes::Bytes::from_static(b"hello")))
            .await
            .unwrap();
        let mut got_pong = false;
        loop {
            match ws.next().await.unwrap().unwrap() {
                Message::Pong(_) => got_pong = true,
                Message::Binary(b) => {
                    assert_eq!(&b[..], b"earlyhello");
                    break;
                }
                _ => (),
            }
        }
        assert!(got_pong);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

struct SlowHost(Arc<TestHost>, Arc<std::sync::atomic::AtomicUsize>);
#[async_trait::async_trait]
impl Host for SlowHost {
    fn users(&self) -> Arc<[node_session::User]> {
        self.0.users()
    }
    async fn connect(
        &self,
        _: &node_session::User,
        _: std::net::SocketAddr,
        _: &node_session::Destination,
    ) -> std::io::Result<node_session::BoxStream> {
        self.1.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
    async fn datagram(
        &self,
        user: &node_session::User,
        peer: std::net::SocketAddr,
    ) -> std::io::Result<Arc<dyn node_session::Datagram>> {
        self.0.datagram(user, peer).await
    }
}
#[tokio::test]
async fn anytls_session_limit_and_shared_byte_queue_fail_closed_and_join() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for flood in [false, true] {
            let host = TestHost::new();
            let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let slow = Arc::new(SlowHost(host.clone(), entered.clone()));
            let (mut client, server) = tokio::io::duplex(1 << 20);
            let config = Config {
                max_sessions: 2,
                max_frame: 512,
                max_queued_bytes: 1024,
                ..Default::default()
            };
            let server = tokio::spawn(node_extended::serve(
                Protocol::AnyTls,
                config,
                Box::new(server),
                peer(),
                slow,
                None,
            ));
            anytls_auth(&mut client).await;
            let _ = read_frame(&mut client).await;
            let _ = read_frame(&mut client).await;
            frame(&mut client, 1, 1, &[]).await;
            if flood {
                frame(&mut client, 2, 1, &[1, 127, 0, 0, 1, 0, 80]).await;
                while entered.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
                for _ in 0..3 {
                    frame(&mut client, 2, 1, &[8; 512]).await;
                }
            } else {
                frame(&mut client, 1, 2, &[]).await;
                frame(&mut client, 1, 3, &[]).await;
            }
            let (cmd, _, error) = read_frame(&mut client).await;
            assert_eq!(cmd, 5);
            assert!(!error.is_empty());
            assert!(server.await.unwrap().is_err());
            assert_eq!(host.totals(), (0, 0));
            assert_eq!(host.active.load(Ordering::SeqCst), 0);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn two_connections_share_payload_budget_and_cancel_returns_only_owned_permits() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = TestHost::new();
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let slow = Arc::new(SlowHost(host.clone(), entered.clone()));
        let config = Config {
            max_sessions: 2,
            max_frame: 512,
            max_queued_bytes: 1024,
            ..Default::default()
        };
        let shared = config.shared_budget.clone();
        let (mut client1, server1) = tokio::io::duplex(65536);
        let (cancel1, rx1) = watch::channel(false);
        let job1 = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            config.clone(),
            Box::new(server1),
            peer(),
            slow.clone(),
            Some(rx1),
        ));
        let (mut client2, server2) = tokio::io::duplex(65536);
        let (cancel2, rx2) = watch::channel(false);
        let job2 = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            config.clone(),
            Box::new(server2),
            peer(),
            slow.clone(),
            Some(rx2),
        ));
        let mut blocked_payload = vec![1, 127, 0, 0, 1, 0, 80];
        blocked_payload.extend_from_slice(&[42; 256]);
        for client in [&mut client1, &mut client2] {
            anytls_auth(client).await;
            let _ = read_frame(client).await;
            let _ = read_frame(client).await;
            frame(client, 1, 1, &[]).await;
            frame(client, 2, 1, &blocked_payload).await;
        }
        while entered.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(shared.available_sessions(), Some(0));
        assert_eq!(shared.available_bytes(), Some(1024 - 2 * 263));
        frame(&mut client2, 2, 1, &[99; 512]).await;
        assert_eq!(read_frame(&mut client2).await.0, 5); // Alert, then close offender.
        assert!(job2.await.unwrap().is_err());
        assert_eq!(shared.available_sessions(), Some(1));
        assert_eq!(shared.available_bytes(), Some(1024 - 263));
        cancel1.send(true).unwrap();
        job1.await.unwrap().unwrap();
        assert_eq!(shared.available_bytes(), Some(1024));
        assert_eq!(shared.available_sessions(), Some(2));
        drop(cancel2);
        // A subsequent connection proves one connection did not close the shared semaphore.
        let (mut client3, server3) = tokio::io::duplex(65536);
        let (cancel3, rx3) = watch::channel(false);
        let job3 = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            config,
            Box::new(server3),
            peer(),
            slow,
            Some(rx3),
        ));
        anytls_auth(&mut client3).await;
        let _ = read_frame(&mut client3).await;
        let _ = read_frame(&mut client3).await;
        frame(&mut client3, 1, 1, &[]).await;
        frame(&mut client3, 2, 1, &blocked_payload).await;
        while entered.load(Ordering::SeqCst) != 3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(shared.available_bytes(), Some(761));
        cancel3.send(true).unwrap();
        job3.await.unwrap().unwrap();
        assert_eq!(shared.available_bytes(), Some(1024));
        assert_eq!(shared.available_sessions(), Some(2));
        assert_eq!(host.totals(), (0, 0));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn two_connections_share_logical_session_ceiling() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = TestHost::new();
        let config = Config {
            max_sessions: 1,
            max_frame: 512,
            max_queued_bytes: 1024,
            ..Default::default()
        };
        let shared = config.shared_budget.clone();
        let (mut client1, server1) = tokio::io::duplex(65536);
        let (cancel, rx) = watch::channel(false);
        let job1 = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            config.clone(),
            Box::new(server1),
            peer(),
            host.clone(),
            Some(rx),
        ));
        anytls_auth(&mut client1).await;
        let _ = read_frame(&mut client1).await;
        let _ = read_frame(&mut client1).await;
        frame(&mut client1, 1, 1, &[]).await;
        while shared.available_sessions() != Some(0) {
            tokio::task::yield_now().await;
        }
        let (mut client2, server2) = tokio::io::duplex(65536);
        let job2 = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            config,
            Box::new(server2),
            peer(),
            host,
            None,
        ));
        anytls_auth(&mut client2).await;
        let _ = read_frame(&mut client2).await;
        let _ = read_frame(&mut client2).await;
        frame(&mut client2, 1, 1, &[]).await;
        assert_eq!(read_frame(&mut client2).await.0, 5);
        assert!(job2.await.unwrap().is_err());
        assert_eq!(shared.available_sessions(), Some(0));
        cancel.send(true).unwrap();
        job1.await.unwrap().unwrap();
        assert_eq!(shared.available_sessions(), Some(1));
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn anytls_syn_before_settings_sends_alert_and_auth_reads_current_users() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = TestHost::new();
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            Config::default(),
            Box::new(server),
            peer(),
            host.clone(),
            None,
        ));
        client
            .write_all(ring::digest::digest(&ring::digest::SHA256, PASSWORD.as_bytes()).as_ref())
            .await
            .unwrap();
        client.write_u16(0).await.unwrap();
        frame(&mut client, 1, 1, &[]).await;
        assert_eq!(read_frame(&mut client).await.0, 5);
        assert!(task.await.unwrap().is_err());
        *host.users.write().unwrap() = Arc::from([]);
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(node_extended::serve(
            Protocol::AnyTls,
            Config::default(),
            Box::new(server),
            peer(),
            host.clone(),
            None,
        ));
        client
            .write_all(ring::digest::digest(&ring::digest::SHA256, PASSWORD.as_bytes()).as_ref())
            .await
            .unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(host.totals(), (0, 0));
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn xudp_mux_tcp_payload_is_forwarded_and_end_releases_host() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = TestHost::new();
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let (cancel, rx) = watch::channel(false);
        let task = tokio::spawn(node_extended::mux::serve_xudp(
            Box::new(server),
            host.users()[0].clone(),
            peer(),
            host.clone(),
            Config::default(),
            Some(rx),
        ));
        client
            .write_all(&[
                0, 12, 0, 7, 1, 1, 1, 0, 80, 1, 127, 0, 0, 1, 0, 3, b't', b'c', b'p',
            ])
            .await
            .unwrap();
        let len = client.read_u16().await.unwrap();
        let mut metadata = vec![0; len as usize];
        client.read_exact(&mut metadata).await.unwrap();
        assert_eq!(&metadata[..4], &[0, 7, 2, 1]);
        assert_eq!(client.read_u16().await.unwrap(), 3);
        let mut data = [0; 3];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"tcp");
        assert_eq!(host.totals(), (3, 3));
        client.write_all(&[0, 4, 0, 7, 3, 0]).await.unwrap();
        while host.active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
        cancel.send(true).unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn websocket_frame_limit_and_fragmented_binary_are_enforced() {
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::{
        Message,
        protocol::frame::{
            Frame,
            coding::{Data, OpCode},
        },
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut stream = node_extended::websocket::accept(
                Box::new(server),
                node_extended::websocket::WebSocketConfig {
                    max_frame: 64,
                    max_early_data: 0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let mut message = [0; 6];
            stream.read_exact(&mut message).await.unwrap();
            assert_eq!(&message, b"abcdef");
            let mut more = [0; 1];
            stream.read(&mut more).await
        });
        let (mut client, _) = tokio_tungstenite::client_async("ws://localhost/", client)
            .await
            .unwrap();
        client
            .send(Message::Frame(Frame::message(
                bytes::Bytes::from_static(b"abc"),
                OpCode::Data(Data::Binary),
                false,
            )))
            .await
            .unwrap();
        client
            .send(Message::Frame(Frame::message(
                bytes::Bytes::from_static(b"def"),
                OpCode::Data(Data::Continue),
                true,
            )))
            .await
            .unwrap();
        client
            .send(Message::Binary(bytes::Bytes::from(vec![0; 65])))
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
    })
    .await
    .unwrap();
}
