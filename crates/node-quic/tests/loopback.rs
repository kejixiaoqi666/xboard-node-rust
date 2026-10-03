//! Wire-level tests use actual Quinn connections and HTTP/3 requests. The mock
//! host observes only application payload, just like the production bridge.
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use node_quic::{Config, CongestionControl, ProtocolKind, SalamanderConfig};
use node_session::{BoxStream, Datagram, Destination, Host, User};
#[path = "support/pinned_client.rs"]
mod pinned_client;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, watch},
    task::JoinHandle,
    time::timeout,
};

#[derive(Default)]
struct Counts {
    upload: AtomicU64,
    download: AtomicU64,
}
struct MockHost {
    users: Arc<RwLock<Arc<[User]>>>,
    counts: HashMap<String, Arc<Counts>>,
    admitted: Mutex<Vec<(String, Destination)>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    udp_users: Mutex<Vec<String>>,
}
impl MockHost {
    fn new() -> Arc<Self> {
        let users: Arc<[User]> = vec![
            user("alice", 1, "alice-password"),
            user("bob", 2, "bob-password"),
        ]
        .into();
        let counts = users
            .iter()
            .map(|u| (u.name.to_string(), Arc::new(Counts::default())))
            .collect();
        Arc::new(Self {
            users: Arc::new(RwLock::new(users)),
            counts,
            admitted: Mutex::new(Vec::new()),
            workers: Mutex::new(Vec::new()),
            udp_users: Mutex::new(Vec::new()),
        })
    }
    fn count(&self, name: &str) -> (u64, u64) {
        let c = &self.counts[name];
        (
            c.upload.load(Ordering::Relaxed),
            c.download.load(Ordering::Relaxed),
        )
    }
    fn revoke(&self, name: &str) {
        let current = self.users();
        *self.users.write().unwrap() = current
            .iter()
            .filter(|u| u.name.as_ref() != name)
            .cloned()
            .collect::<Vec<_>>()
            .into();
    }
}
impl Drop for MockHost {
    fn drop(&mut self) {
        for worker in self.workers.get_mut().unwrap().drain(..) {
            worker.abort();
        }
    }
}
fn user(name: &str, id: u8, password: &str) -> User {
    User {
        name: name.into(),
        uuid: Some([id; 16]),
        password: Some(password.into()),
    }
}

#[async_trait]
impl Host for MockHost {
    fn users(&self) -> Arc<[User]> {
        self.users.read().unwrap().clone()
    }
    async fn connect(
        &self,
        user: &User,
        _peer: SocketAddr,
        target: &Destination,
    ) -> io::Result<BoxStream> {
        if !self.users().iter().any(|u| u == user) || target.host == "blocked.invalid" {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
        }
        self.admitted
            .lock()
            .unwrap()
            .push((user.name.to_string(), target.clone()));
        let (client, mut echo) = tokio::io::duplex(64 * 1024);
        self.workers.lock().unwrap().push(tokio::spawn(async move {
            let mut buffer = vec![0; 8192];
            while let Ok(n) = echo.read(&mut buffer).await {
                if n == 0 {
                    break;
                }
                if echo.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
            }
            let _ = echo.shutdown().await;
        }));
        Ok(Box::new(Counted {
            inner: client,
            counts: self.counts[user.name.as_ref()].clone(),
        }))
    }
    async fn datagram(&self, user: &User, _peer: SocketAddr) -> io::Result<Arc<dyn Datagram>> {
        if !self.users().iter().any(|u| u == user) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "revoked"));
        }
        self.udp_users.lock().unwrap().push(user.name.to_string());
        let (tx, rx) = mpsc::channel(64);
        Ok(Arc::new(MockDatagram {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            counts: self.counts[user.name.as_ref()].clone(),
            users: self.users.clone(),
            user: user.clone(),
        }))
    }
}
struct Counted {
    inner: tokio::io::DuplexStream,
    counts: Arc<Counts>,
}
impl AsyncRead for Counted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let start = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.counts
                .download
                .fetch_add((buf.filled().len() - start) as u64, Ordering::Relaxed);
        }
        result
    }
}
impl AsyncWrite for Counted {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = result {
            this.counts.upload.fetch_add(n as u64, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
struct MockDatagram {
    tx: mpsc::Sender<(Vec<u8>, Destination)>,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, Destination)>>,
    counts: Arc<Counts>,
    users: Arc<RwLock<Arc<[User]>>>,
    user: User,
}
#[async_trait]
impl Datagram for MockDatagram {
    async fn send(&self, payload: &[u8], target: &Destination) -> io::Result<usize> {
        if !self.users.read().unwrap().iter().any(|u| u == &self.user)
            || target.host == "blocked.invalid"
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
        }
        self.tx
            .send((payload.to_vec(), target.clone()))
            .await
            .map_err(|_| io::Error::other("closed"))?;
        self.counts
            .upload
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(payload.len())
    }
    async fn receive(&self, buffer: &mut [u8]) -> io::Result<(usize, Destination)> {
        assert!(
            buffer.len() >= 65535,
            "codec must provide a complete UDP receive buffer"
        );
        let (payload, target) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::other("closed"))?;
        buffer[..payload.len()].copy_from_slice(&payload);
        self.counts
            .download
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok((payload.len(), target))
    }
}

struct TestServer {
    handle: node_quic::Handle,
    stop: watch::Sender<bool>,
    client: quinn::ClientConfig,
}
impl TestServer {
    async fn new(
        kind: ProtocolKind,
        host: Arc<MockHost>,
        obfs: Option<&str>,
        cc: CongestionControl,
        early: bool,
    ) -> Self {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = generated.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h3".to_vec()];
        client.enable_early_data = early;
        let client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client).unwrap(),
        ));
        let mut config = Config::new(kind, "127.0.0.1:0".parse().unwrap(), Arc::new(tls));
        config.obfs = obfs.map(|p| SalamanderConfig { password: p.into() });
        config.congestion_control = cc;
        config.allow_0rtt = early;
        let (stop, rx) = watch::channel(false);
        let handle = node_quic::bind(config, host, rx).await.unwrap();
        Self {
            handle,
            stop,
            client,
        }
    }
    async fn connect(&self, obfs: Option<&str>) -> (quinn::Endpoint, quinn::Connection) {
        let mut endpoint = if let Some(secret) = obfs {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                node_quic::wrap_salamander(socket, secret.into()).unwrap(),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap()
        } else {
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap()
        };
        endpoint.set_default_client_config(self.client.clone());
        let connection = timeout(
            Duration::from_secs(5),
            endpoint
                .connect(self.handle.local_addr, "localhost")
                .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        (endpoint, connection)
    }
    async fn shutdown(self) {
        self.stop.send(true).unwrap();
        timeout(Duration::from_secs(12), self.handle.task)
            .await
            .expect("listener shutdown must join all tasks")
            .unwrap()
            .unwrap();
    }
}

async fn hy_auth(connection: &quinn::Connection, password: &str) -> (u16, JoinHandle<()>) {
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .unwrap();
    let keep_alive = send.clone();
    let task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        drop(keep_alive);
    });
    let req = http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", "ignored-client-padding")
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    if response.status().as_u16() == 233 {
        assert_eq!(response.headers()["Hysteria-CC-RX"], "auto");
    }
    (response.status().as_u16(), task)
}
async fn tuic_auth(connection: &quinn::Connection, user: &User, bad: bool) -> [u8; 32] {
    let uuid = user.uuid.unwrap();
    let mut token = [0; 32];
    connection
        .export_keying_material(
            &mut token,
            &uuid,
            user.password.as_ref().unwrap().as_bytes(),
        )
        .unwrap();
    let mut stream = connection.open_uni().await.unwrap();
    let mut frame = vec![5, 0];
    frame.extend_from_slice(&uuid);
    frame.extend_from_slice(if bad { &[0; 32] } else { &token });
    stream.write_all(&frame).await.unwrap();
    stream.finish().unwrap();
    token
}
fn put_varint(b: &mut BytesMut, n: usize) {
    if n < 64 {
        b.put_u8(n as u8);
    } else {
        b.put_u16(n as u16 | 0x4000);
    }
}
fn take_varint(b: &[u8], offset: &mut usize) -> usize {
    let first = b[*offset];
    *offset += 1;
    let width = 1usize << (first >> 6);
    let mut n = (first & 63) as usize;
    for _ in 1..width {
        n = (n << 8) | b[*offset] as usize;
        *offset += 1;
    }
    n
}
fn put_address(b: &mut BytesMut, target: &Destination) {
    b.put_u8(0);
    b.put_u8(target.host.len() as u8);
    b.extend_from_slice(target.host.as_bytes());
    b.put_u16(target.port);
}
async fn tcp(
    connection: &quinn::Connection,
    kind: ProtocolKind,
    target: &Destination,
    payload: &[u8],
) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut header = BytesMut::new();
    match kind {
        ProtocolKind::Hysteria2 => {
            header.extend_from_slice(&[0x44, 0x01]);
            let address = format!("{}:{}", target.host, target.port);
            put_varint(&mut header, address.len());
            header.extend_from_slice(address.as_bytes());
            header.put_u8(3);
            header.extend_from_slice(&[9, 8, 7]);
        }
        ProtocolKind::Tuic => {
            header.extend_from_slice(&[5, 1]);
            put_address(&mut header, target);
        }
    }
    header.extend_from_slice(payload);
    send.write_all(&header).await.unwrap();
    send.finish().unwrap();
    if kind == ProtocolKind::Hysteria2 {
        let mut response = [0; 3];
        recv.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0, 0, 0]);
    }
    timeout(Duration::from_secs(4), recv.read_to_end(64 * 1024))
        .await
        .unwrap()
        .unwrap()
}
fn hy_packet(
    assoc: u32,
    id: u16,
    index: u8,
    total: u8,
    target: &Destination,
    payload: &[u8],
) -> Bytes {
    let mut b = BytesMut::new();
    b.put_u32(assoc);
    b.put_u16(id);
    b.put_u8(index);
    b.put_u8(total);
    let address = format!("{}:{}", target.host, target.port);
    put_varint(&mut b, address.len());
    b.extend_from_slice(address.as_bytes());
    b.extend_from_slice(payload);
    b.freeze()
}
fn tuic_packet(
    assoc: u16,
    id: u16,
    index: u8,
    total: u8,
    target: Option<&Destination>,
    payload: &[u8],
) -> Bytes {
    let mut b = BytesMut::new();
    b.extend_from_slice(&[5, 2]);
    b.put_u16(assoc);
    b.put_u16(id);
    b.put_u8(total);
    b.put_u8(index);
    b.put_u16(payload.len() as u16);
    if let Some(target) = target {
        put_address(&mut b, target)
    } else {
        b.put_u8(0xff);
    }
    b.extend_from_slice(payload);
    b.freeze()
}
fn decode_tuic(b: &[u8]) -> (u16, u8, u8, Destination, usize) {
    assert_eq!(&b[..2], &[5, 2]);
    let assoc = u16::from_be_bytes([b[2], b[3]]);
    let total = b[6];
    let index = b[7];
    let mut offset = 10;
    let target = match b[offset] {
        0 => {
            offset += 1;
            let n = b[offset] as usize;
            offset += 1;
            let host = String::from_utf8(b[offset..offset + n].to_vec()).unwrap();
            offset += n;
            let port = u16::from_be_bytes([b[offset], b[offset + 1]]);
            offset += 2;
            Destination::new(host, port).unwrap()
        }
        0xff => {
            offset += 1;
            Destination::new("none.test", 1).unwrap()
        }
        _ => panic!("unexpected test address"),
    };
    (assoc, index, total, target, offset)
}
async fn read_udp(
    connection: &quinn::Connection,
    kind: ProtocolKind,
    expected_assoc: u32,
) -> (Destination, Vec<u8>) {
    let mut fragments: Vec<Option<Vec<u8>>> = Vec::new();
    let mut target = None;
    loop {
        let b = timeout(Duration::from_secs(4), connection.read_datagram())
            .await
            .unwrap()
            .unwrap();
        if b.as_ref() == [5, 4] {
            continue;
        }
        let (assoc, index, total, address, offset) = if kind == ProtocolKind::Hysteria2 {
            let assoc = u32::from_be_bytes(b[..4].try_into().unwrap());
            let index = b[6];
            let total = b[7];
            let mut offset = 8;
            let n = take_varint(&b, &mut offset);
            let address = std::str::from_utf8(&b[offset..offset + n]).unwrap();
            offset += n;
            let (host, port) = address.rsplit_once(':').unwrap();
            (
                assoc,
                index,
                total,
                Destination::new(host.trim_matches(['[', ']']), port.parse().unwrap()).unwrap(),
                offset,
            )
        } else {
            let (assoc, index, total, address, offset) = decode_tuic(&b);
            (assoc as u32, index, total, address, offset)
        };
        assert_eq!(assoc, expected_assoc);
        if index == 0 {
            target = Some(address);
        }
        if fragments.is_empty() {
            fragments = (0..total).map(|_| None).collect();
        }
        fragments[index as usize] = Some(b[offset..].to_vec());
        if fragments.iter().all(Option::is_some) {
            return (
                target.unwrap(),
                fragments.into_iter().flat_map(Option::unwrap).collect(),
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hysteria_h3_multiplayer_tcp_udp_payload_counters_and_bad_auth() {
    let host = MockHost::new();
    let server = TestServer::new(
        ProtocolKind::Hysteria2,
        host.clone(),
        None,
        CongestionControl::Cubic,
        false,
    )
    .await;
    let (endpoint, conn) = server.connect(None).await;
    let (status, driver) = hy_auth(&conn, "alice-password").await;
    assert_eq!(status, 233);
    let target = Destination::new("example.test", 443).unwrap();
    let payload = b"alice tcp payload";
    assert_eq!(
        tcp(&conn, ProtocolKind::Hysteria2, &target, payload).await,
        payload
    );
    let udp_target = Destination::new("udp.test", 53).unwrap();
    let udp_payload = vec![42; 5000];
    for i in (0..5).rev() {
        conn.send_datagram(hy_packet(
            19,
            99,
            i,
            5,
            &udp_target,
            &udp_payload[i as usize * 1000..(i as usize + 1) * 1000],
        ))
        .unwrap();
    }
    let (source, response) = read_udp(&conn, ProtocolKind::Hysteria2, 19).await;
    assert_eq!(source, udp_target);
    assert_eq!(response, udp_payload);
    assert_eq!(
        host.count("alice"),
        ((payload.len() + 5000) as u64, (payload.len() + 5000) as u64)
    );
    let (bob_endpoint, bob) = server.connect(None).await;
    let (status, bob_driver) = hy_auth(&bob, "bob-password").await;
    assert_eq!(status, 233);
    assert_eq!(
        tcp(&bob, ProtocolKind::Hysteria2, &target, b"bob").await,
        b"bob"
    );
    assert_eq!(host.count("bob"), (3, 3));
    let (bad_endpoint, bad) = server.connect(None).await;
    let (status, bad_driver) = hy_auth(&bad, "wrong-password").await;
    assert_eq!(status, 404);
    bad.send_datagram(hy_packet(55, 0, 0, 1, &udp_target, b"unauthenticated"))
        .unwrap();
    assert_eq!(*host.udp_users.lock().unwrap(), vec!["alice"]);
    conn.close(0u32.into(), b"done");
    bob.close(0u32.into(), b"done");
    bad.close(0u32.into(), b"done");
    driver.abort();
    bob_driver.abort();
    bad_driver.abort();
    drop(endpoint);
    drop(bob_endpoint);
    drop(bad_endpoint);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tuic_multiplayer_tcp_native_stream_udp_fragment_and_replay_rejection() {
    let host = MockHost::new();
    let server = TestServer::new(
        ProtocolKind::Tuic,
        host.clone(),
        None,
        CongestionControl::Bbr,
        true,
    )
    .await;
    let alice = host.users()[0].clone();
    let (endpoint, conn) = server.connect(None).await;
    let token = tuic_auth(&conn, &alice, false).await;
    let target = Destination::new("tuic.test", 443).unwrap();
    assert_eq!(
        tcp(&conn, ProtocolKind::Tuic, &target, b"tuic payload").await,
        b"tuic payload"
    );
    let target = Destination::new("udp.test", 53).unwrap();
    let payload = vec![7; 5000];
    for i in (0..5).rev() {
        conn.send_datagram(tuic_packet(
            42,
            15,
            i,
            5,
            if i == 0 { Some(&target) } else { None },
            &payload[i as usize * 1000..(i as usize + 1) * 1000],
        ))
        .unwrap();
    }
    let (source, response) = read_udp(&conn, ProtocolKind::Tuic, 42).await;
    assert_eq!(source, target);
    assert_eq!(response, payload);
    // Each fragmented command gets its own unidirectional stream. Reassembly
    // must persist across streams, unlike the known upstream temporary-cache bug.
    for i in (0..2).rev() {
        let mut stream = conn.open_uni().await.unwrap();
        stream
            .write_all(&tuic_packet(
                43,
                22,
                i,
                2,
                if i == 0 { Some(&target) } else { None },
                if i == 0 { b"first" } else { b"second" },
            ))
            .await
            .unwrap();
        stream.finish().unwrap();
    }
    let mut response = timeout(Duration::from_secs(4), conn.accept_uni())
        .await
        .unwrap()
        .unwrap();
    let data = response.read_to_end(1000).await.unwrap();
    let (assoc, index, total, source, offset) = decode_tuic(&data);
    assert_eq!((assoc, index, total), (43, 0, 1));
    assert_eq!(source, target);
    assert_eq!(&data[offset..], b"firstsecond");
    let (bob_endpoint, bob) = server.connect(None).await;
    let bob_user = host.users()[1].clone();
    tuic_auth(&bob, &bob_user, false).await;
    assert_eq!(tcp(&bob, ProtocolKind::Tuic, &target, b"bob").await, b"bob");
    assert_eq!(host.count("bob"), (3, 3));
    // Replay the first connection's exporter token on a distinct TLS connection.
    let (bad_endpoint, bad) = server.connect(None).await;
    let mut auth = bad.open_uni().await.unwrap();
    let mut frame = vec![5, 0];
    frame.extend_from_slice(&alice.uuid.unwrap());
    frame.extend_from_slice(&token);
    auth.write_all(&frame).await.unwrap();
    auth.finish().unwrap();
    timeout(Duration::from_secs(3), bad.closed())
        .await
        .expect("cross-connection replay must close");
    assert_eq!(host.count("alice"), (5023, 5023));
    assert_eq!(host.admitted.lock().unwrap().len(), 2);
    conn.close(0u32.into(), b"done");
    bob.close(0u32.into(), b"done");
    drop(endpoint);
    drop(bob_endpoint);
    drop(bad_endpoint);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn salamander_real_quic_and_live_user_rotation() {
    let host = MockHost::new();
    let server = TestServer::new(
        ProtocolKind::Hysteria2,
        host.clone(),
        Some("salamander-secret"),
        CongestionControl::NewReno,
        false,
    )
    .await;
    let (endpoint, conn) = server.connect(Some("salamander-secret")).await;
    let (status, driver) = hy_auth(&conn, "alice-password").await;
    assert_eq!(status, 233);
    let target = Destination::new("obfs.test", 443).unwrap();
    assert_eq!(
        tcp(&conn, ProtocolKind::Hysteria2, &target, b"obfuscated").await,
        b"obfuscated"
    );
    host.revoke("alice");
    let (new_endpoint, new_conn) = server.connect(Some("salamander-secret")).await;
    let (status, new_driver) = hy_auth(&new_conn, "alice-password").await;
    assert_eq!(status, 404);
    timeout(Duration::from_secs(7), conn.closed())
        .await
        .expect("revoked live connection must close on periodic check");
    assert_eq!(host.count("alice"), (10, 10));
    new_conn.close(0u32.into(), b"done");
    driver.abort();
    new_driver.abort();
    drop(endpoint);
    drop(new_endpoint);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_shutdown_joins_stalled_handshake_and_payload_tasks() {
    let host = MockHost::new();
    let server = TestServer::new(
        ProtocolKind::Tuic,
        host.clone(),
        None,
        CongestionControl::Cubic,
        false,
    )
    .await;
    let (endpoint, conn) = server.connect(None).await;
    let mut stalled = conn.open_uni().await.unwrap();
    stalled.write_all(&[5, 0]).await.unwrap();
    server.shutdown().await;
    timeout(Duration::from_secs(2), conn.closed())
        .await
        .unwrap();
    assert!(host.admitted.lock().unwrap().is_empty());
    drop(endpoint);
}

struct OfficialClient {
    child: std::process::Child,
    socks: u16,
    log: std::path::PathBuf,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tuic_actual_0rtt_resume_buffers_payload_until_fresh_exporter_auth() {
    let host = MockHost::new();
    let server = TestServer::new(
        ProtocolKind::Tuic,
        host.clone(),
        None,
        CongestionControl::Cubic,
        true,
    )
    .await;
    let (endpoint, first) = server.connect(None).await;
    let alice = host.users()[0].clone();
    let old_token = tuic_auth(&first, &alice, false).await;
    let target = Destination::new("early.test", 443).unwrap();
    assert_eq!(
        tcp(&first, ProtocolKind::Tuic, &target, b"ticket").await,
        b"ticket"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    first.close(0u32.into(), b"resume");
    let (resumed, accepted) = endpoint
        .connect(server.handle.local_addr, "localhost")
        .unwrap()
        .into_0rtt()
        .expect("a real TLS resumption ticket must enable 0-RTT");
    let (mut send, mut recv) = resumed.open_bi().await.unwrap();
    let mut packet = BytesMut::from(&[5, 1][..]);
    put_address(&mut packet, &target);
    packet.extend_from_slice(b"early payload");
    send.write_all(&packet).await.unwrap();
    send.finish().unwrap();
    assert!(
        timeout(Duration::from_secs(3), accepted).await.unwrap(),
        "server must accept negotiated TUIC early data"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        host.count("alice"),
        (6, 6),
        "early payload cannot cross the Host boundary before auth"
    );
    tuic_auth(&resumed, &alice, false).await;
    assert_eq!(
        timeout(Duration::from_secs(3), recv.read_to_end(1000))
            .await
            .unwrap()
            .unwrap(),
        b"early payload"
    );
    assert_eq!(host.count("alice"), (19, 19));
    tokio::time::sleep(Duration::from_millis(100)).await;
    resumed.close(0u32.into(), b"done");
    let (replay, accepted) = endpoint
        .connect(server.handle.local_addr, "localhost")
        .unwrap()
        .into_0rtt()
        .expect("second resumption ticket");
    let mut authentication = replay.open_uni().await.unwrap();
    let mut frame = vec![5, 0];
    frame.extend_from_slice(&alice.uuid.unwrap());
    frame.extend_from_slice(&old_token);
    authentication.write_all(&frame).await.unwrap();
    authentication.finish().unwrap();
    let _ = timeout(Duration::from_secs(3), accepted).await.unwrap();
    timeout(Duration::from_secs(3), replay.closed())
        .await
        .expect("replayed early auth must fail exporter binding");
    assert_eq!(host.count("alice"), (19, 19));
    drop(endpoint);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_tuic_udp_and_tcp_expire_within_ten_seconds() {
    let host = MockHost::new();
    let server = TestServer::new(
        ProtocolKind::Tuic,
        host.clone(),
        None,
        CongestionControl::Cubic,
        false,
    )
    .await;
    let (endpoint, connection) = server.connect(None).await;
    let target = Destination::new("unauth.test", 53).unwrap();
    connection
        .send_datagram(tuic_packet(1, 1, 0, 1, Some(&target), b"must not relay"))
        .unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    let mut frame = BytesMut::from(&[5, 1][..]);
    put_address(&mut frame, &target);
    frame.extend_from_slice(b"must not relay");
    send.write_all(&frame).await.unwrap();
    timeout(Duration::from_secs(11), connection.closed())
        .await
        .expect("unauthenticated connection has a 10 second total handshake/auth deadline");
    assert!(host.admitted.lock().unwrap().is_empty());
    assert!(host.udp_users.lock().unwrap().is_empty());
    assert_eq!(host.count("alice"), (0, 0));
    drop(endpoint);
    server.shutdown().await;
}
impl Drop for OfficialClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn official_client(
    server: &TestServer,
    kind: ProtocolKind,
    user: &User,
    mode: &str,
    obfs: Option<&str>,
    bad: bool,
) -> OfficialClient {
    let binary = pinned_client::binary();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let socks = listener.local_addr().unwrap().port();
    drop(listener);
    let output =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/official-interop");
    std::fs::create_dir_all(&output).unwrap();
    let id = format!("{:?}-{}-{}-{}", kind, mode, socks, user.name);
    let config_file = output.join(format!("{id}.json"));
    let log = output.join(format!("{id}.log"));
    let password = if bad {
        "wrong-password"
    } else {
        user.password.as_ref().unwrap().as_ref()
    };
    let protocol = match kind {
        ProtocolKind::Hysteria2 => {
            let obfs = obfs
                .map(|password| {
                    format!(",\"obfs\":{{\"type\":\"salamander\",\"password\":\"{password}\"}}")
                })
                .unwrap_or_default();
            format!("\"type\":\"hysteria2\",\"password\":\"{password}\"{obfs}")
        }
        ProtocolKind::Tuic => {
            let id = user.uuid.unwrap();
            let hex = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let uuid = format!(
                "{}-{}-{}-{}-{}",
                &hex[..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..]
            );
            format!(
                "\"type\":\"tuic\",\"uuid\":\"{uuid}\",\"password\":\"{password}\",\"udp_relay_mode\":\"{mode}\",\"congestion_control\":\"cubic\",\"zero_rtt_handshake\":true"
            )
        }
    };
    let config = format!(
        r#"{{"log":{{"level":"debug"}},"inbounds":[{{"type":"socks","listen":"127.0.0.1","listen_port":{socks}}}],"outbounds":[{{{protocol},"server":"127.0.0.1","server_port":{},"tls":{{"enabled":true,"server_name":"localhost","insecure":true,"alpn":["h3"]}}}}]}}"#,
        server.handle.local_addr.port()
    );
    std::fs::write(&config_file, config).unwrap();
    let log_file = std::fs::File::create(&log).unwrap();
    let mut command = std::process::Command::new(binary);
    command
        .args(["run", "-c"])
        .arg(config_file)
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone().unwrap())
        .stderr(log_file);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().unwrap();
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", socks))
            .await
            .is_ok()
        {
            return OfficialClient { child, socks, log };
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "official client exited {status}: {}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("official client did not bind SOCKS; see {}", log.display());
}

async fn socks_command(
    client: &OfficialClient,
    command: u8,
) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", client.socks)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS greeting rejected"));
    }
    stream
        .write_all(if command == 3 {
            &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]
        } else {
            &[5, 1, 0, 1, 127, 0, 0, 1, 0x30, 0x39]
        })
        .await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[1] != 0 {
        return Err(io::Error::other("SOCKS request rejected"));
    }
    let ip = match header[3] {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            std::net::IpAddr::V4(b.into())
        }
        4 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            std::net::IpAddr::V6(b.into())
        }
        _ => return Err(io::Error::other("unexpected SOCKS bound address")),
    };
    let port = stream.read_u16().await?;
    let ip = if ip.is_unspecified() {
        "127.0.0.1".parse().unwrap()
    } else {
        ip
    };
    Ok((stream, SocketAddr::new(ip, port)))
}

async fn official_tcp(client: &OfficialClient, payload: &[u8]) {
    let (mut stream, _) = timeout(Duration::from_secs(8), socks_command(client, 1))
        .await
        .expect("official SOCKS CONNECT timed out")
        .unwrap_or_else(|e| {
            panic!(
                "{e}: {}",
                std::fs::read_to_string(&client.log).unwrap_or_default()
            )
        });
    stream.write_all(payload).await.unwrap();
    let mut response = vec![0; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await
        .expect("official TCP payload timed out")
        .unwrap();
    assert_eq!(response, payload);
    let _ = stream.shutdown().await;
}
async fn official_udp(client: &OfficialClient, payload: &[u8], host: &MockHost) {
    let (_association, remote) = timeout(Duration::from_secs(5), socks_command(client, 3))
        .await
        .unwrap()
        .unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut frame = vec![0, 0, 0, 1, 127, 0, 0, 1, 0x30, 0x39];
    frame.extend_from_slice(payload);
    socket.send_to(&frame, remote).await.unwrap();
    let mut response = vec![0; 65535];
    let (n, _) = timeout(Duration::from_secs(8), socket.recv_from(&mut response))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "official UDP timed out: boundary={:?} sessions={:?} remote={remote} log={}",
                host.count("alice"),
                host.udp_users.lock().unwrap(),
                std::fs::read_to_string(&client.log).unwrap_or_default()
            )
        })
        .unwrap();
    assert_eq!(&response[..3], &[0, 0, 0]);
    assert_eq!(response[3], 1);
    assert_eq!(&response[4..8], &[127, 0, 0, 1]);
    assert_eq!(&response[8..10], &[0x30, 0x39]);
    assert_eq!(&response[10..n], payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SHA-verified official sing-box v1.14.2, SING_BOX_BIN"]
async fn official_sing_box_hysteria_salamander_tuic_native_and_quic_clients() {
    for (kind, mode, obfs) in [
        (ProtocolKind::Hysteria2, "native", None),
        (ProtocolKind::Hysteria2, "native", Some("salamander-secret")),
        (ProtocolKind::Tuic, "native", None),
        (ProtocolKind::Tuic, "quic", None),
    ] {
        let host = MockHost::new();
        let server =
            TestServer::new(kind, host.clone(), obfs, CongestionControl::Cubic, true).await;
        let alice = host.users()[0].clone();
        let bob = host.users()[1].clone();
        let client = official_client(&server, kind, &alice, mode, obfs, false).await;
        // sing-box's pinned Hysteria implementation caps its own UDP input at
        // 4096 bytes. 3000 bytes still exercises genuine QUIC fragmentation.
        official_tcp(&client, b"official client tcp payload").await;
        official_udp(&client, &vec![17; 3000], &host).await;
        assert_eq!(
            host.count("alice"),
            (3027, 3027),
            "only payload contributes to counters"
        );
        let bob_client = official_client(&server, kind, &bob, mode, obfs, false).await;
        official_tcp(&bob_client, b"bob payload").await;
        assert_eq!(host.count("bob"), (11, 11));
        let bad = official_client(&server, kind, &alice, mode, obfs, true).await;
        let denied = timeout(Duration::from_secs(5), async {
            let (mut stream, _) = socks_command(&bad, 1).await?;
            stream.write_all(b"must not relay").await?;
            let mut response = [0; 14];
            stream.read_exact(&mut response).await?;
            Ok::<(), io::Error>(())
        })
        .await;
        assert!(
            !matches!(denied, Ok(Ok(_))),
            "bad auth must not admit official client TCP"
        );
        assert_eq!(host.admitted.lock().unwrap().len(), 2);
        eprintln!(
            "official sing-box 1.14.2 PASS kind={kind:?} mode={mode} salamander={} alice=3027/3027 bob=11/11",
            obfs.is_some()
        );
        drop(bad);
        drop(bob_client);
        drop(client);
        server.shutdown().await;
    }
}
