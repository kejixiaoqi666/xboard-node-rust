//! Exercise the production Network source with minimal crate error/address
//! adapters, so isolated builds never write the root workspace lockfile.
#![allow(dead_code)]
#[derive(Debug)]
enum Error {
    Config,
    Protocol,
    Dns,
    Blocked,
    Unsupported,
    Limited,
    Io(std::io::Error),
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
mod protocol {
    #[derive(Clone)]
    pub enum Address {
        Ip(std::net::IpAddr),
        Domain(String),
    }
}
#[path = "../../node-native/src/network.rs"]
mod network;
#[path = "../../node-native/src/os_dns.rs"]
mod os_dns;
use network::Network;
use node_core::routing::*;
use protocol::Address;
use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
fn response(query: &[u8]) -> io::Result<Vec<u8>> {
    if query.len() < 17 || query[4..6] != [0, 1] {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut end = 12;
    while query.get(end).is_some_and(|n| *n != 0) {
        let n = query[end] as usize;
        if n > 63 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        end += 1 + n;
    }
    end += 5;
    if end > query.len() || query[end - 4..end] != [0, 1, 0, 1] {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut answer = query[..end].to_vec();
    answer[2..4].copy_from_slice(&[0x81, 0x80]);
    answer[6..8].copy_from_slice(&[0, 1]);
    answer[8..12].fill(0);
    answer.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 2]);
    Ok(answer)
}
async fn framed<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    count: Arc<AtomicUsize>,
) -> io::Result<()> {
    loop {
        let n = stream.read_u16().await? as usize;
        if n > 65535 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = vec![0; n];
        stream.read_exact(&mut bytes).await?;
        let answer = response(&bytes)?;
        count.fetch_add(1, Ordering::SeqCst);
        stream.write_u16(answer.len() as u16).await?;
        stream.write_all(&answer).await?;
        stream.flush().await?;
    }
}
async fn https<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    count: Arc<AtomicUsize>,
) -> io::Result<()> {
    let mut connection = h2::server::handshake(stream)
        .await
        .map_err(io::Error::other)?;
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            request=connection.accept()=>{let Some(request)=request else{break};let(request,mut send)=request.map_err(io::Error::other)?;let count=count.clone();tasks.spawn(async move{
                assert_eq!(request.method(),http::Method::POST);assert_eq!(request.uri().path(),"/custom-dns-query");let mut body=request.into_body();let mut query=vec![];while let Some(bytes)=body.data().await{let bytes=bytes.map_err(io::Error::other)?;body.flow_control().release_capacity(bytes.len()).map_err(io::Error::other)?;query.extend(bytes);if query.len()>65535{return Err(io::ErrorKind::InvalidData.into())}}
                let answer=response(&query)?;count.fetch_add(1,Ordering::SeqCst);let response=http::Response::builder().status(200).header("content-type","application/dns-message").header("content-length",answer.len()).body(()).unwrap();let mut stream=send.send_response(response,false).map_err(io::Error::other)?;stream.send_data(bytes::Bytes::from(answer),true).map_err(io::Error::other)?;Ok::<_,io::Error>(())
            });},
            value=tasks.join_next(),if !tasks.is_empty()=>{value.unwrap().unwrap()?;}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
struct Fixture {
    address: SocketAddr,
    ca: String,
    count: Arc<AtomicUsize>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl Fixture {
    async fn new(transport: DnsTransport) -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "target/dns-wire-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let path = dir.join("certificate.pem");
        std::fs::write(&path, certificate.cert.pem()).unwrap();
        let ca = path.to_string_lossy().into();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        tls.alpn_protocols = match transport {
            DnsTransport::Tls => vec![b"dot".to_vec()],
            DnsTransport::Https => vec![b"h2".to_vec()],
            DnsTransport::Quic => vec![b"doq".to_vec()],
            _ => vec![],
        };
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let (stop, mut receiver) = watch::channel(false);
        let (address, task) = match transport {
            DnsTransport::Udp => {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let address = socket.local_addr().unwrap();
                let task = tokio::spawn(async move {
                    let mut bytes = vec![0; 65535];
                    loop {
                        tokio::select! {_ = receiver.changed()=>break,result=socket.recv_from(&mut bytes)=>{let(n,source)=result.unwrap();let answer=response(&bytes[..n]).unwrap();observed.fetch_add(1,Ordering::SeqCst);socket.send_to(&answer,source).await.unwrap();}}
                    }
                });
                (address, task)
            }
            DnsTransport::Quic => {
                let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
                let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
                let endpoint =
                    quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
                let address = endpoint.local_addr().unwrap();
                let task = tokio::spawn(async move {
                    let mut tasks = JoinSet::new();
                    loop {
                        tokio::select! {_ = receiver.changed()=>break,incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break};let count=observed.clone();tasks.spawn(async move{let Ok(connection)=incoming.await else{return};while let Ok((mut send,mut recv))=connection.accept_bi().await{let mut size=[0;2];recv.read_exact(&mut size).await.unwrap();let mut bytes=vec![0;u16::from_be_bytes(size) as usize];recv.read_exact(&mut bytes).await.unwrap();assert_eq!(&bytes[..2],&[0,0],"RFC9250 DoQ transaction ID must be zero");let answer=response(&bytes).unwrap();count.fetch_add(1,Ordering::SeqCst);send.write_all(&(answer.len() as u16).to_be_bytes()).await.unwrap();send.write_all(&answer).await.unwrap();send.finish().unwrap();}});},_ = tasks.join_next(),if !tasks.is_empty()=>{}}
                    }
                    endpoint.close(0u32.into(), b"done");
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    endpoint.wait_idle().await;
                });
                (address, task)
            }
            _ => {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
                let task = tokio::spawn(async move {
                    let mut tasks = JoinSet::new();
                    loop {
                        tokio::select! {_ = receiver.changed()=>break,accepted=listener.accept()=>{let(stream,_)=accepted.unwrap();let acceptor=acceptor.clone();let count=observed.clone();tasks.spawn(async move{if transport==DnsTransport::Tcp{let _=framed(stream,count).await;}else if let Ok(stream)=acceptor.accept(stream).await{if transport==DnsTransport::Https{let _=https(stream,count).await;}else{let _=framed(stream,count).await;}}});},_ = tasks.join_next(),if !tasks.is_empty()=>{}}
                    }
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                });
                (address, task)
            }
        };
        Self {
            address,
            ca,
            count,
            stop,
            task,
        }
    }
    fn dns(&self, transport: DnsTransport) -> DnsConfig {
        let encrypted = matches!(
            transport,
            DnsTransport::Tls | DnsTransport::Https | DnsTransport::Quic
        );
        DnsConfig {
            upstreams: vec![DnsUpstream {
                transport,
                address: self.address,
                server_name: encrypted.then(|| "localhost".into()),
                path: (transport == DnsTransport::Https).then(|| "/custom-dns-query".into()),
                ca_file: encrypted.then(|| self.ca.clone()),
            }],
            strategy: IpStrategy::Ipv4Only,
            timeout_ms: 2000,
            ..Default::default()
        }
    }
    async fn shutdown(self) {
        self.stop.send(true).unwrap();
        timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_network_real_udp_tcp_dot_doh_doq_cache_and_pinned_route() {
    for transport in [
        DnsTransport::Udp,
        DnsTransport::Tcp,
        DnsTransport::Tls,
        DnsTransport::Https,
        DnsTransport::Quic,
    ] {
        let fixture = Fixture::new(transport).await;
        let mut route = Route::default();
        route.rules.push(Rule {
            outbound: "block".into(),
            ip_cidr: vec!["127.0.0.2/32".into()],
            ..Default::default()
        });
        let network = Network::new(
            &route,
            &[
                Outbound::plain("direct", "direct"),
                Outbound::plain("block", "block"),
            ],
            Some(&fixture.dns(transport)),
        )
        .unwrap();
        for _ in 0..2 {
            let (name, ips) = network
                .resolve(&Address::Domain("FiXtUrE.TEST.".into()))
                .await
                .unwrap_or_else(|e| panic!("{transport:?} resolve: {e:?}"));
            assert_eq!(name.as_deref(), Some("fixture.test"));
            assert_eq!(ips, vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()]);
        }
        assert_eq!(
            fixture.count.load(Ordering::SeqCst),
            1,
            "{transport:?} must use bounded DNS cache"
        );
        assert!(matches!(
            network
                .connect(
                    &Address::Domain("fixture.test".into()),
                    443,
                    "127.0.0.1:1000".parse().unwrap()
                )
                .await,
            Err(Error::Blocked)
        ));
        assert!(matches!(
            network
                .udp_plan_for(
                    &Address::Domain("fixture.test".into()),
                    53,
                    "127.0.0.1:1000".parse().unwrap(),
                    "",
                    "",
                )
                .await,
            Err(Error::Blocked)
        ));
        drop(network);
        fixture.shutdown().await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_dns_rejects_wrong_name_and_untrusted_ca_without_plaintext_fallback() {
    for transport in [DnsTransport::Tls, DnsTransport::Https, DnsTransport::Quic] {
        let fixture = Fixture::new(transport).await;
        for wrong_name in [true, false] {
            let mut dns = fixture.dns(transport);
            if wrong_name {
                dns.upstreams[0].server_name = Some("other.test".into())
            } else {
                dns.upstreams[0].ca_file = None
            }
            let network = Network::new(
                &Route::default(),
                &[Outbound::plain("direct", "direct")],
                Some(&dns),
            )
            .unwrap();
            assert!(matches!(
                network
                    .resolve(&Address::Domain("fixture.test".into()))
                    .await,
                Err(Error::Dns)
            ));
        }
        assert_eq!(fixture.count.load(Ordering::SeqCst), 0);
        fixture.shutdown().await;
    }
}
