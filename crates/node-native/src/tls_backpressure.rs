//! Real rustls streams with a tiny transport buffer reproduce ciphertext
//! backpressure: the target waits for a second request instead of closing.
use crate::{auth, config::Protocol, limits, traffic};
use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

const USER: &str = "00000000-0000-4000-8000-000000000007";

async fn streams() -> (
    tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
    tokio_rustls::server::TlsStream<crate::vision::RecordIo<tokio::io::DuplexStream>>,
) {
    let cert = CertificateDer::from(TEST_CERT.to_vec());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(TEST_KEY.to_vec())),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (a, b) = tokio::io::duplex(512);
    let client = tokio_rustls::TlsConnector::from(Arc::new(client));
    let server = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let (a, b) = tokio::join!(
        client.connect(ServerName::try_from("localhost").unwrap(), a),
        server.accept(crate::vision::RecordIo::new(b))
    );
    (a.unwrap(), b.unwrap())
}

fn users(protocol: Protocol) -> auth::Users {
    Arc::new(ArcSwap::from_pointee(
        auth::Snapshot::new(
            protocol,
            vec![crate::config::User {
                name: "7".into(),
                uuid: (protocol == Protocol::Vless).then(|| USER.into()),
                password: (protocol == Protocol::Trojan).then(|| USER.into()),
                flow: None,
                speed_limit: 0,
                device_limit: 0,
            }],
        )
        .unwrap(),
    ))
}

#[tokio::test]
async fn tls_tcp_response_flushes_tail_while_origin_waits_for_next_request() {
    let test = async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let response = vec![0x63; 8192];
        let expected = response.clone();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), b'A');
            stream.write_all(&response).await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), b'B');
            stream.write_all(b"C").await.unwrap();
        });
        let (mut client, server) = streams().await;
        let users = users(Protocol::Vless);
        let registry = Arc::new(limits::Registry::new(Arc::clone(&users)));
        let proxy = tokio::spawn(async move {
            crate::connection(
                server,
                Protocol::Vless,
                &users,
                &Arc::new(traffic::Traffic::new_with_enabled("b".repeat(32), false)),
                "127.0.0.1".parse().unwrap(),
                &registry,
                &Arc::new(tokio::sync::Semaphore::new(1)),
            )
            .await
        });
        let mut header = vec![0];
        header.extend(auth::uuid(USER).unwrap());
        header.extend([0, 1]);
        header.extend(port.to_be_bytes());
        header.extend([1, 127, 0, 0, 1]);
        client.write_all(&header).await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0);
        client.write_all(b"A").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = vec![0; expected.len()];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, expected);
        client.write_all(b"B").await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), b'C');
        client.shutdown().await.unwrap();
        origin.await.unwrap();
        proxy.await.unwrap().unwrap();
    };
    tokio::time::timeout(Duration::from_secs(3), test)
        .await
        .unwrap();
}

#[tokio::test]
async fn tls_udp_frame_flushes_tail_without_waiting_for_another_datagram() {
    let test = async {
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut bytes = [0; 8192];
            for _ in 0..2 {
                let (size, source) = origin.recv_from(&mut bytes).await.unwrap();
                origin.send_to(&bytes[..size], source).await.unwrap();
            }
        });
        let (mut client, server) = streams().await;
        let users = users(Protocol::Trojan);
        let registry = Arc::new(limits::Registry::new(Arc::clone(&users)));
        let proxy = tokio::spawn(async move {
            crate::connection(
                server,
                Protocol::Trojan,
                &users,
                &Arc::new(traffic::Traffic::new_with_enabled("c".repeat(32), false)),
                "127.0.0.1".parse().unwrap(),
                &registry,
                &Arc::new(tokio::sync::Semaphore::new(1)),
            )
            .await
        });
        let mut handshake = auth::trojan_key(USER).to_vec();
        handshake.extend([13, 10, 3, 1, 0, 0, 0, 0, 0, 0, 13, 10]);
        client.write_all(&handshake).await.unwrap();
        client.flush().await.unwrap();
        for size in [8192_u16, 0] {
            let body = vec![0x73; size as usize];
            let mut header = vec![1, 127, 0, 0, 1];
            header.extend(port.to_be_bytes());
            header.extend(size.to_be_bytes());
            header.extend(b"\r\n");
            client.write_all(&header).await.unwrap();
            client.write_all(&body).await.unwrap();
            client.flush().await.unwrap();
            let mut reply_header = vec![0; header.len()];
            client.read_exact(&mut reply_header).await.unwrap();
            assert_eq!(reply_header, header);
            let mut reply = vec![0; body.len()];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, body);
        }
        client.shutdown().await.unwrap();
        echo.await.unwrap();
        proxy.await.unwrap().unwrap();
    };
    tokio::time::timeout(Duration::from_secs(3), test)
        .await
        .unwrap();
}

// Self-signed localhost-only test identity, generated for this fixture. This
// key is public test material and never used by the runtime or a live service.
const TEST_CERT: &[u8] = &[
    48, 130, 1, 184, 48, 130, 1, 93, 160, 3, 2, 1, 2, 2, 20, 96, 2, 65, 247, 41, 73, 187, 131, 235,
    195, 122, 23, 34, 169, 149, 195, 163, 0, 163, 87, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2,
    48, 20, 49, 18, 48, 16, 6, 3, 85, 4, 3, 12, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 48,
    30, 23, 13, 50, 54, 49, 48, 48, 50, 49, 54, 48, 51, 49, 57, 90, 23, 13, 51, 54, 48, 57, 50, 57,
    49, 54, 48, 51, 49, 57, 90, 48, 20, 49, 18, 48, 16, 6, 3, 85, 4, 3, 12, 9, 108, 111, 99, 97,
    108, 104, 111, 115, 116, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72,
    206, 61, 3, 1, 7, 3, 66, 0, 4, 66, 140, 82, 24, 41, 87, 197, 9, 119, 152, 216, 185, 205, 186,
    173, 214, 228, 202, 100, 45, 68, 67, 240, 42, 128, 216, 122, 78, 129, 149, 84, 143, 135, 219,
    52, 15, 9, 219, 77, 235, 115, 107, 112, 221, 216, 93, 69, 235, 72, 146, 136, 105, 246, 59, 225,
    117, 54, 138, 222, 73, 190, 159, 73, 124, 163, 129, 140, 48, 129, 137, 48, 29, 6, 3, 85, 29,
    14, 4, 22, 4, 20, 144, 231, 165, 20, 49, 111, 155, 107, 38, 68, 234, 209, 82, 178, 173, 96,
    117, 169, 226, 26, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 144, 231, 165, 20, 49,
    111, 155, 107, 38, 68, 234, 209, 82, 178, 173, 96, 117, 169, 226, 26, 48, 20, 6, 3, 85, 29, 17,
    4, 13, 48, 11, 130, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 48, 12, 6, 3, 85, 29, 19, 1,
    1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 19, 6, 3, 85,
    29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3,
    2, 3, 73, 0, 48, 70, 2, 33, 0, 157, 84, 18, 239, 139, 201, 48, 114, 140, 184, 124, 20, 215, 90,
    149, 115, 240, 220, 89, 134, 32, 168, 124, 38, 102, 135, 119, 46, 188, 191, 98, 171, 2, 33, 0,
    244, 160, 149, 89, 207, 158, 116, 177, 124, 62, 25, 95, 10, 225, 195, 20, 12, 14, 44, 211, 133,
    240, 72, 140, 49, 36, 213, 184, 203, 110, 177, 60,
];

const TEST_KEY: &[u8] = &[
    48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3,
    1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 248, 72, 186, 51, 218, 31, 127, 162, 141, 222, 185, 254,
    44, 219, 42, 113, 28, 153, 43, 171, 246, 76, 90, 136, 247, 187, 181, 189, 197, 173, 98, 129,
    161, 68, 3, 66, 0, 4, 66, 140, 82, 24, 41, 87, 197, 9, 119, 152, 216, 185, 205, 186, 173, 214,
    228, 202, 100, 45, 68, 67, 240, 42, 128, 216, 122, 78, 129, 149, 84, 143, 135, 219, 52, 15, 9,
    219, 77, 235, 115, 107, 112, 221, 216, 93, 69, 235, 72, 146, 136, 105, 246, 59, 225, 117, 54,
    138, 222, 73, 190, 159, 73, 124,
];

#[tokio::test]
async fn vision_tls_backpressure_preserves_payload_and_half_close() {
    let test = async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut body = Vec::new();
            socket.read_to_end(&mut body).await.unwrap();
            socket.write_all(&body).await.unwrap();
            socket.shutdown().await.unwrap();
            body
        });
        let users = Arc::new(ArcSwap::from_pointee(
            auth::Snapshot::new(
                Protocol::Vless,
                vec![crate::config::User {
                    name: "7".into(),
                    uuid: Some(USER.into()),
                    password: None,
                    flow: Some("xtls-rprx-vision".into()),
                    speed_limit: 0,
                    device_limit: 0,
                }],
            )
            .unwrap(),
        ));
        let traffic = Arc::new(traffic::Traffic::new("vision-test-epoch".into()));
        let registry = Arc::new(limits::Registry::new(Arc::clone(&users)));
        let (mut client, server) = streams().await;
        let native = {
            let users = Arc::clone(&users);
            let traffic = Arc::clone(&traffic);
            tokio::spawn(async move {
                let network = crate::network::Network::direct();
                let slots = Arc::new(tokio::sync::Semaphore::new(1));
                crate::connection_tls(
                    server,
                    Protocol::Vless,
                    crate::ConnectionContext {
                        users: &users,
                        traffic: &traffic,
                        source: "127.0.0.1:12345".parse().unwrap(),
                        limits: &registry,
                        udp_slots: &slots,
                        network: &network,
                    },
                )
                .await
            })
        };
        let mut header = vec![0];
        header.extend(auth::uuid(USER).unwrap());
        let flow = b"xtls-rprx-vision";
        header.extend([18, 10, 16]);
        header.extend(flow);
        header.push(1);
        header.extend(port.to_be_bytes());
        header.extend([1, 127, 0, 0, 1]);
        client.write_all(&header).await.unwrap();
        client.flush().await.unwrap();
        let (tcp, session) = client.into_inner();
        let mut client = node_vision::VisionStream::new_client(
            tcp,
            rustls::Connection::Client(session),
            auth::uuid(USER).unwrap(),
        );
        let payload = b"bounded-Vision-TLS-payload".repeat(4096);
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut actual = vec![0; payload.len()];
        client.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, payload);
        assert_eq!(origin.await.unwrap(), payload);
        native.await.unwrap().unwrap();
        let counters = traffic.snapshot().unwrap().unwrap().traffic["7"];
        assert_eq!(counters, [payload.len() as u64, payload.len() as u64]);
    };
    tokio::time::timeout(Duration::from_secs(15), test)
        .await
        .unwrap();
}

#[tokio::test]
async fn vision_partial_tls_tail_and_close_notify_without_tcp_fin_are_forwarded() {
    let test = async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
            body
        });
        let users = Arc::new(ArcSwap::from_pointee(
            auth::Snapshot::new(
                Protocol::Vless,
                vec![crate::config::User {
                    name: "7".into(),
                    uuid: Some(USER.into()),
                    password: None,
                    flow: Some("xtls-rprx-vision".into()),
                    speed_limit: 0,
                    device_limit: 0,
                }],
            )
            .unwrap(),
        ));
        let (mut client, server) = streams().await;
        let native = tokio::spawn(async move {
            let traffic = Arc::new(traffic::Traffic::new("d".repeat(32)));
            let limits = Arc::new(limits::Registry::new(Arc::clone(&users)));
            let slots = Arc::new(tokio::sync::Semaphore::new(1));
            let network = crate::network::Network::direct();
            crate::connection_tls(
                server,
                Protocol::Vless,
                crate::ConnectionContext {
                    users: &users,
                    traffic: &traffic,
                    source: "127.0.0.1:1".parse().unwrap(),
                    limits: &limits,
                    udp_slots: &slots,
                    network: &network,
                },
            )
            .await
            .unwrap();
            traffic.snapshot().unwrap().unwrap().traffic["7"]
        });
        let uuid = auth::uuid(USER).unwrap();
        let mut header = vec![0];
        header.extend(uuid);
        header.extend([18, 10, 16]);
        header.extend(b"xtls-rprx-vision");
        header.push(1);
        header.extend(port.to_be_bytes());
        header.extend([1, 127, 0, 0, 1]);
        client.write_all(&header).await.unwrap();
        client.flush().await.unwrap();
        // UUID and padding header can span different TLS records.
        let payload = b"tail-is-payload\x16\x03\x03";
        let mut frame = uuid.to_vec();
        frame.push(0);
        frame.extend((payload.len() as u16).to_be_bytes());
        frame.extend([0, 0]);
        frame.extend(payload);
        for part in frame.chunks(3) {
            client.write_all(part).await.unwrap();
            client.flush().await.unwrap();
        }
        client.get_mut().1.send_close_notify();
        client.flush().await.unwrap();
        // Keep TCP write side open: authenticated TLS EOF must reach origin now.
        let mut prefix = [0; 18];
        client.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix[..2], [0, 0]);
        assert_eq!(prefix[2..], uuid);
        let mut padding = [0; 5];
        client.read_exact(&mut padding).await.unwrap();
        let size = u16::from_be_bytes([padding[1], padding[2]]) as usize;
        let mut body = vec![0; size];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(body, payload);
        assert_eq!(origin.await.unwrap(), payload);
        assert_eq!(native.await.unwrap(), [payload.len() as u64; 2]);
    };
    tokio::time::timeout(Duration::from_secs(10), test)
        .await
        .unwrap();
}
