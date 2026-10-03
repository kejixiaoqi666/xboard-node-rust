//! Independent official sing-box client matrix. Explicit opt-in, never downloads.
//! SING_BOX_TEST_CLIENT must point at the SHA-verified v1.14.2 binary.
#[path = "support/clients.rs"]
mod clients;
mod support;
use node_extended::{Config, Protocol};
use node_session::Host;
use serde_json::{Value, json};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
    task::JoinSet,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};

#[derive(Clone, Copy)]
enum Carrier {
    Native(Protocol),
    VlessFixture,
}
impl From<Protocol> for Carrier {
    fn from(protocol: Protocol) -> Self {
        Self::Native(protocol)
    }
}

struct Client(Child);
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn command(binary: &Path) -> Command {
    let command = Command::new(binary);
    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;
        let mut command = command;
        command.creation_flags(0x08000000);
        command
    };
    command
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
#[allow(clippy::too_many_arguments)] // Test-only carrier, transport and cancellation fixture.
async fn serve_listener(
    listener: TcpListener,
    protocol: Carrier,
    tls: Option<TlsAcceptor>,
    websocket: bool,
    transport: Option<Value>,
    host: Arc<TestHost>,
    mut cancel: watch::Receiver<bool>,
    config: Config,
) -> io::Result<()> {
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel.changed() => break,
            result = listener.accept() => {
                let (stream, peer) = result?; let tls = tls.clone(); let host = host.clone(); let config = config.clone(); let cancel = cancel.clone(); let transport=transport.clone();
                jobs.spawn(async move {
                    let mut stream: node_session::BoxStream = if let Some(tls) = tls {
                        Box::new(tokio::time::timeout(Duration::from_secs(10), tls.accept(stream)).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test TLS timeout"))??)
                    } else { Box::new(stream) };
                    if websocket { stream = node_extended::websocket::accept(stream, node_extended::websocket::WebSocketConfig { path: Some("/proxy".into()),host:transport.as_ref().and_then(|transport|transport["headers"]["Host"].as_str()).map(str::to_owned), ..Default::default() }).await?; }
                    if let Some(transport)=transport {
                        match transport["type"].as_str() {
                            Some("httpupgrade")=>stream=node_extended::httpupgrade::accept(stream,node_extended::httpupgrade::HttpUpgradeConfig{path:Some("/proxy".into()),host:transport["host"].as_str().map(str::to_owned),..Default::default()}).await?,
                            Some("http")|Some("grpc")=> {
                                let handler=Arc::new(FixtureHandler{protocol,peer,host,config:config.clone(),cancel:cancel.clone()});
                                return if transport["type"]=="http" {
                                    node_extended::http2::serve(stream,node_extended::http2::Http2Config{path:Some("/proxy".into()),hosts:transport["host"].as_array().map(|hosts|hosts.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default(),method:transport["method"].as_str().map(str::to_owned)},handler,config,Some(cancel)).await
                                } else {
                                    node_extended::grpc::serve(stream,node_extended::grpc::GrpcConfig{service_name:"proxy".into()},handler,config,Some(cancel)).await
                                };
                            },
                            _=>(),
                        }
                    }
                    match protocol {
                        Carrier::Native(protocol) => node_extended::serve(protocol, config, stream, peer, host, Some(cancel)).await,
                        Carrier::VlessFixture => vless_fixture(stream, peer, host, config, cancel).await,
                    }
                });
            },
            job = jobs.join_next(), if !jobs.is_empty() => {
                if let Some(Ok(Err(error))) = job { eprintln!("protocol connection: {error}"); }
            },
        }
    }
    if tokio::time::timeout(Duration::from_secs(5), async {
        while jobs.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "test listener workers did not finish on cancellation",
        ));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires SHA-verified Xray v26.3.27 client in XRAY_TEST_CLIENT"]
async fn xray_nonzero_global_id_reuses_udp_host_after_carrier_disconnect() {
    let binary = PathBuf::from(std::env::var_os("XRAY_TEST_CLIENT").expect("set XRAY_TEST_CLIENT"));
    let mut file = std::fs::File::open(&binary).unwrap();
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut chunk = [0; 65536];
    loop {
        let size = std::io::Read::read(&mut file, &mut chunk).unwrap();
        if size == 0 {
            break;
        }
        digest.update(&chunk[..size]);
    }
    let actual: String = digest
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(actual, clients::expected_binary_sha256("xray"));
    let version = command(&binary).arg("version").output().unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).contains("Xray 26.3.27"));
    let host = TestHost::new();
    let config = Config::default();
    let budget = config.shared_budget.clone();
    let globals = config.xudp_sessions.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let socks_port = port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (kill, kill_rx) = watch::channel(0u64);
    let (stop, mut stop_rx) = watch::channel(false);
    let server = {
        let host = host.clone();
        let accepted = accepted.clone();
        let completed = completed.clone();
        tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                    _=stop_rx.changed()=>break,
                    incoming=listener.accept()=> {
                        let (mut network,peer)=incoming.unwrap();accepted.fetch_add(1,Ordering::SeqCst);let host=host.clone();let config=config.clone();let cancel=stop_rx.clone();let mut killed=kill_rx.clone();let _=*killed.borrow_and_update();let completed=completed.clone();
                        jobs.spawn(async move {
                            let (mut bridge,protocol)=tokio::io::duplex(65536);
                            let forwarding=async {tokio::select! {_=killed.changed()=>{},_=tokio::io::copy_bidirectional(&mut network,&mut bridge)=>{}}drop(network);drop(bridge);};
                            let (result,())=tokio::join!(vless_fixture(Box::new(protocol),peer,host,config,cancel),forwarding);completed.fetch_add(1,Ordering::SeqCst);result
                        });
                    },
                    _=jobs.join_next(),if !jobs.is_empty()=>(),
                }
            }
            if tokio::time::timeout(Duration::from_secs(5), async {
                while jobs.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                jobs.abort_all();
                while jobs.join_next().await.is_some() {}
                panic!("Xray fixture worker cancellation failed");
            }
        })
    };
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("xray.json");
    let log_path = directory.path().join("xray.log");
    let client_config = json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":server_port,"users":[{"id":UUID_TEXT,"encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"},"mux":{"enabled":true,"concurrency":1,"xudpConcurrency":1,"xudpProxyUDP443":"allow"}}]});
    std::fs::write(&file, serde_json::to_vec(&client_config).unwrap()).unwrap();
    let log = std::fs::File::create(&log_path).unwrap();
    let mut client = Client(
        command(&binary)
            .args(["run", "-c"])
            .arg(&file)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", socks_port)).await.is_ok() {
            break;
        }
        if client.0.try_wait().unwrap().is_some() {
            panic!(
                "Xray did not start: {}",
                std::fs::read_to_string(&log_path).unwrap()
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut auth = [0; 2];
    control.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 4];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let endpoint = read_socks_addr(&mut control, reply[3]).await.unwrap();
    let endpoint = SocketAddr::new("127.0.0.1".parse().unwrap(), endpoint.port());
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (index, payload) in [
        b"first-xray-global".as_slice(),
        b"second-xray-global".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        if index == 1 {
            kill.send(1).unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while completed.load(Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                host.active.load(Ordering::SeqCst),
                1,
                "idle GlobalID must preserve its Host channel after EOF"
            );
        }
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x75];
        packet.extend_from_slice(payload);
        udp.send_to(&packet, endpoint).await.unwrap();
        let mut returned = [0; 1024];
        let result =
            tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut returned)).await;
        let (size, _) = result
            .unwrap_or_else(|_| {
                panic!(
                    "Xray carrier {index} UDP timeout: {}",
                    std::fs::read_to_string(&log_path).unwrap()
                )
            })
            .unwrap();
        assert_eq!(&returned[..size], packet);
        assert_eq!(
            globals.cached_sessions(),
            1,
            "official Xray must provide a nonzero stable GlobalID"
        );
        assert_eq!(
            host.active.load(Ordering::SeqCst),
            1,
            "rebind must reuse the original Host UDP channel"
        );
    }
    assert!(accepted.load(Ordering::SeqCst) >= 2);
    assert_eq!(host.totals(), (35, 35));
    stop.send(true).unwrap();
    drop(client);
    server.await.unwrap();
    assert_eq!(host.active.load(Ordering::SeqCst), 0);
    assert_eq!(globals.cached_sessions(), 0);
    assert_eq!(budget.available_bytes(), Some(8 * 1024 * 1024));
    assert_eq!(budget.available_sessions(), Some(1024));
    println!(
        "official Xray v26.3.27 nonzero XUDP GlobalID: two physical carriers, one Host UDP channel; up=35 down=35; all workers joined"
    );
}
struct FixtureHandler {
    protocol: Carrier,
    peer: SocketAddr,
    host: Arc<TestHost>,
    config: Config,
    cancel: watch::Receiver<bool>,
}
#[async_trait::async_trait]
impl node_extended::http2::StreamHandler for FixtureHandler {
    async fn serve(&self, stream: node_session::BoxStream) -> io::Result<()> {
        match self.protocol {
            Carrier::Native(protocol) => {
                node_extended::serve(
                    protocol,
                    self.config.clone(),
                    stream,
                    self.peer,
                    self.host.clone(),
                    Some(self.cancel.clone()),
                )
                .await
            }
            Carrier::VlessFixture => {
                vless_fixture(
                    stream,
                    self.peer,
                    self.host.clone(),
                    self.config.clone(),
                    self.cancel.clone(),
                )
                .await
            }
        }
    }
}
// A deliberately small test carrier: production VLESS decoding remains in node-native.
async fn vless_fixture(
    mut stream: node_session::BoxStream,
    peer: SocketAddr,
    host: Arc<TestHost>,
    config: Config,
    cancel: watch::Receiver<bool>,
) -> io::Result<()> {
    if stream.read_u8().await? != 0 {
        return Err(io::Error::other("VLESS test version"));
    }
    let mut uuid = [0; 16];
    stream.read_exact(&mut uuid).await?;
    let user = host
        .users()
        .iter()
        .find(|u| u.uuid == Some(uuid))
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "VLESS test auth"))?;
    let addons = stream.read_u8().await?;
    let mut addon_bytes = vec![0; addons as usize];
    stream.read_exact(&mut addon_bytes).await?;
    let command = stream.read_u8().await?;
    if command == 3 {
        // MUX has no address/port fields in VLESS (same as VMess).
        stream.write_all(&[0, 0]).await?;
        stream.flush().await?;
        return node_extended::mux::serve_xudp(stream, user, peer, host, config, Some(cancel))
            .await;
    }
    let port = stream.read_u16().await?;
    let destination = match stream.read_u8().await? {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await?;
            node_session::Destination::new(std::net::Ipv4Addr::from(ip).to_string(), port)?
        }
        3 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            node_session::Destination::new(std::net::Ipv6Addr::from(ip).to_string(), port)?
        }
        2 => {
            let len = stream.read_u8().await?;
            let mut host = vec![0; len as usize];
            stream.read_exact(&mut host).await?;
            node_session::Destination::new(
                String::from_utf8(host).map_err(io::Error::other)?,
                port,
            )?
        }
        _ => return Err(io::Error::other("VLESS test address")),
    };
    stream.write_all(&[0, 0]).await?;
    stream.flush().await?;
    if command == 1
        && destination.host == node_extended::mux::MUX_HOST
        && destination.port == node_extended::mux::MUX_PORT
    {
        node_extended::mux::serve_h2mux(stream, user, peer, host, config, Some(cancel)).await
    } else if command == 1 {
        let remote = host.connect(&user, peer, &destination).await?;
        node_session::relay(stream, remote).await
    } else {
        Err(io::Error::other(
            "test fixture supports TCP and MUX commands",
        ))
    }
}
async fn socks_connect(port: u16, destination_port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS greeting failed"));
    }
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&destination_port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut response = [0; 4];
    stream.read_exact(&mut response).await?;
    if response[1] != 0 {
        return Err(io::Error::other(format!(
            "SOCKS TCP status {}",
            response[1]
        )));
    }
    read_socks_addr(&mut stream, response[3]).await?;
    Ok(stream)
}
async fn read_socks_addr(stream: &mut TcpStream, kind: u8) -> io::Result<SocketAddr> {
    let host = match kind {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        3 => {
            let n = stream.read_u8().await?;
            let mut b = vec![0; n as usize];
            stream.read_exact(&mut b).await?;
            String::from_utf8(b).map_err(io::Error::other)?
        }
        _ => return Err(io::Error::other("bad SOCKS reply address")),
    };
    let port = stream.read_u16().await?;
    format!(
        "{}:{port}",
        if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        }
    )
    .parse()
    .map_err(io::Error::other)
}
async fn tcp_payload(socks_port: u16, destination_port: u16, payload: &[u8]) -> io::Result<()> {
    let mut stream = socks_connect(socks_port, destination_port).await?;
    stream.write_all(payload).await?;
    let mut echo = vec![0; payload.len()];
    stream.read_exact(&mut echo).await?;
    if echo != payload {
        return Err(io::Error::other("TCP payload mismatch"));
    }
    stream.shutdown().await?;
    Ok(())
}
async fn udp_payload(socks_port: u16, payload: &[u8]) -> io::Result<()> {
    let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting).await?;
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut response = [0; 4];
    control.read_exact(&mut response).await?;
    if response[1] != 0 {
        return Err(io::Error::other("SOCKS UDP associate failed"));
    }
    let endpoint = read_socks_addr(&mut control, response[3]).await?;
    let endpoint = if endpoint.ip().is_unspecified() {
        SocketAddr::new("127.0.0.1".parse().unwrap(), endpoint.port())
    } else {
        endpoint
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1, 0, 53];
    packet.extend_from_slice(payload);
    socket.send_to(&packet, endpoint).await?;
    let mut echo = vec![0; 65535];
    let (len, _) = socket.recv_from(&mut echo).await?;
    if len < payload.len() || echo[len - payload.len()..len] != *payload {
        return Err(io::Error::other("UDP payload mismatch"));
    }
    Ok(())
}
fn tls() -> TlsAcceptor {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.cert.der().to_vec())],
            PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut server = server;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(server))
}
async fn case(
    binary: &Path,
    label: &str,
    protocol: impl Into<Carrier>,
    mut outbound: Value,
    ws: bool,
    use_tls: bool,
    udp: bool,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let socks_port = port();
    let host = TestHost::new();
    let server_config = Config::default();
    let budget = server_config.shared_budget.clone();
    let (cancel, receiver) = watch::channel(false);
    let server = tokio::spawn(serve_listener(
        listener,
        protocol.into(),
        if use_tls { Some(tls()) } else { None },
        ws,
        outbound.get("transport").cloned(),
        host.clone(),
        receiver,
        server_config,
    ));
    outbound["server"] = json!("127.0.0.1");
    outbound["server_port"] = json!(server_port);
    outbound["tag"] = json!("proxy");
    let config = json!({"log":{"level":"error","timestamp":false},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],"outbounds":[outbound],"route":{"final":"proxy"}});
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("client.json");
    let log_path = directory.path().join("client.log");
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let log = std::fs::File::create(&log_path).unwrap();
    let mut process = Client(
        command(binary)
            .args(["run", "-c"])
            .arg(&file)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", socks_port)).await.is_ok() {
            break;
        }
        if process.0.try_wait().unwrap().is_some() {
            panic!(
                "{label}: official client did not start: {}",
                std::fs::read_to_string(&log_path).unwrap()
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let payload_size = if label.contains("flow-window") {
        524288
    } else {
        22000
    };
    let payload: Vec<u8> = (0..payload_size).map(|i| (i % 251) as u8).collect();
    for destination in [443u16, 8443, 8080] {
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            tcp_payload(socks_port, destination, &payload),
        )
        .await;
        if !matches!(result, Ok(Ok(()))) {
            panic!(
                "{label} TCP failed: {result:?}; client: {}",
                std::fs::read_to_string(&log_path).unwrap()
            );
        }
    }
    if udp {
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            udp_payload(socks_port, b"official-client-udp"),
        )
        .await;
        if !matches!(result, Ok(Ok(()))) {
            panic!(
                "{label} UDP failed: {result:?}; client: {}",
                std::fs::read_to_string(&log_path).unwrap()
            );
        }
    }
    let bytes = 3 * payload.len() as u64 + if udp { 19 } else { 0 };
    assert_eq!(
        host.totals(),
        (bytes, bytes),
        "{label}: framing/padding leaked into Host payload"
    );
    drop(process);
    cancel.send(true).unwrap();
    server.await.unwrap().unwrap();
    assert_eq!(
        host.active.load(Ordering::SeqCst),
        0,
        "{label}: session task leaked"
    );
    assert_eq!(
        budget.available_bytes(),
        Some(8 * 1024 * 1024),
        "{label}: listener byte permit leaked"
    );
    assert_eq!(
        budget.available_sessions(),
        Some(1024),
        "{label}: listener session permit leaked"
    );
    println!(
        "official sing-box v1.14.2 {label}: TCP 3x{}{}; Host totals={:?}; active=0",
        payload.len(),
        if udp { " + UDP19" } else { "" },
        host.totals()
    );
}

#[tokio::test]
#[ignore = "requires SHA-verified official v1.14.2 client in SING_BOX_TEST_CLIENT"]
async fn singbox_vmess_anytls_websocket_h2mux_xudp_matrix() {
    let binary =
        PathBuf::from(std::env::var_os("SING_BOX_TEST_CLIENT").expect("set SING_BOX_TEST_CLIENT"));
    let expected = clients::expected_binary_sha256("sing-box");
    let mut file = std::fs::File::open(&binary).unwrap();
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut chunk = [0u8; 65536];
    loop {
        let count = std::io::Read::read(&mut file, &mut chunk).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    let actual: String = digest
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        actual, expected,
        "official client does not match immutable v1.14.2 binary"
    );
    let version = command(&binary).arg("version").output().unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).contains("sing-box version 1.14.2"));
    for security in ["aes-128-gcm", "chacha20-poly1305", "none"] {
        case(&binary, &format!("vmess-{security}"), Protocol::Vmess, json!({"type":"vmess","uuid":UUID_TEXT,"security":security,"alter_id":0,"global_padding":true,"authenticated_length":false}), false, false, true).await;
    }
    for security in ["aes-128-gcm", "chacha20-poly1305"] {
        case(&binary, &format!("vmess-{security}-authenticated-length"), Protocol::Vmess, json!({"type":"vmess","uuid":UUID_TEXT,"security":security,"alter_id":0,"global_padding":true,"authenticated_length":true}), false, false, true).await;
    }
    case(&binary, "vmess-websocket", Protocol::Vmess, json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"transport":{"type":"ws","path":"/proxy"}}), true, false, true).await;
    case(&binary,"vmess-websocket-host",Protocol::Vmess,json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"transport":{"type":"ws","path":"/proxy","headers":{"Host":"example.test"}}}),true,false,true).await;
    case(&binary,"vmess-httpupgrade-host",Protocol::Vmess,json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"transport":{"type":"httpupgrade","path":"/proxy","host":"example.test"}}),false,false,true).await;
    case(&binary,"vmess-http2-host-method",Protocol::Vmess,json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"transport":{"type":"http","path":"/proxy","host":["example.test"],"method":"PUT"},"tls":{"enabled":true,"server_name":"localhost","insecure":true}}),false,true,true).await;
    for carrier in [Carrier::Native(Protocol::Vmess), Carrier::VlessFixture] {
        let carrier_label = match carrier {
            Carrier::Native(_) => "vmess",
            Carrier::VlessFixture => "vless-fixture",
        };
        for transport in ["httpupgrade", "grpc", "http"] {
            for use_tls in [false, true] {
                if transport == "http" && !use_tls {
                    continue;
                }
                let mut outbound = match carrier {
                    Carrier::Native(_) => {
                        json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0})
                    }
                    Carrier::VlessFixture => {
                        json!({"type":"vless","uuid":UUID_TEXT,"packet_encoding":"xudp"})
                    }
                };
                outbound["transport"] = if transport == "grpc" {
                    json!({"type":"grpc","service_name":"proxy"})
                } else {
                    json!({"type":transport,"path":"/proxy"})
                };
                if use_tls {
                    outbound["tls"] =
                        json!({"enabled":true,"server_name":"localhost","insecure":true});
                }
                case(
                    &binary,
                    &format!(
                        "{carrier_label}-{transport}-{}",
                        if use_tls { "tls" } else { "plain" }
                    ),
                    carrier,
                    outbound,
                    false,
                    use_tls,
                    true,
                )
                .await;
            }
        }
    }
    case(&binary, "vmess-h2mux", Protocol::Vmess, json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"multiplex":{"enabled":true,"protocol":"h2mux","max_connections":1}}), false, false, true).await;
    case(&binary, "vmess-h2mux-padding", Protocol::Vmess, json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"multiplex":{"enabled":true,"protocol":"h2mux","max_connections":1,"padding":true}}), false, false, true).await;
    for mux in ["smux", "yamux"] {
        case(&binary,&format!("vmess-{mux}-flow-window"),Protocol::Vmess,json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"multiplex":{"enabled":true,"protocol":mux,"max_connections":1}}),false,false,true).await;
        for padding in [false, true] {
            case(&binary, &format!("vmess-{mux}-padding-{padding}"), Protocol::Vmess, json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"multiplex":{"enabled":true,"protocol":mux,"max_connections":1,"padding":padding}}), false, false, true).await;
        }
    }
    case(&binary, "vmess-xudp", Protocol::Vmess, json!({"type":"vmess","uuid":UUID_TEXT,"security":"aes-128-gcm","alter_id":0,"packet_encoding":"xudp"}), false, false, true).await;
    case(&binary, "anytls-v2-uot", Protocol::AnyTls, json!({"type":"anytls","password":PASSWORD,"tls":{"enabled":true,"server_name":"localhost","insecure":true}}), false, true, true).await;
    for use_tls in [false, true] {
        let mut h2 = json!({"type":"vless","uuid":UUID_TEXT,"multiplex":{"enabled":true,"protocol":"h2mux","max_connections":1,"padding":use_tls}});
        let mut xudp = json!({"type":"vless","uuid":UUID_TEXT,"packet_encoding":"xudp"});
        if use_tls {
            let tls = json!({"enabled":true,"server_name":"localhost","insecure":true});
            h2["tls"] = tls.clone();
            xudp["tls"] = tls;
        }
        case(
            &binary,
            &format!(
                "vless-{}-h2mux-fixture",
                if use_tls { "tls-padding" } else { "plain" }
            ),
            Carrier::VlessFixture,
            h2,
            false,
            use_tls,
            true,
        )
        .await;
        for mux in ["smux", "yamux"] {
            let mut outbound = json!({"type":"vless","uuid":UUID_TEXT,"multiplex":{"enabled":true,"protocol":mux,"max_connections":1,"padding":use_tls}});
            if use_tls {
                outbound["tls"] = json!({"enabled":true,"server_name":"localhost","insecure":true});
            }
            case(
                &binary,
                &format!(
                    "vless-{}-{mux}-fixture",
                    if use_tls { "tls-padding" } else { "plain" }
                ),
                Carrier::VlessFixture,
                outbound,
                false,
                use_tls,
                true,
            )
            .await;
        }
        case(
            &binary,
            &format!(
                "vless-{}-xudp-fixture",
                if use_tls { "tls" } else { "plain" }
            ),
            Carrier::VlessFixture,
            xudp,
            false,
            use_tls,
            true,
        )
        .await;
    }
}
