//! Opt-in real pinned Xray client and real local OpenSSL TLS mirror.
//! This exercises the same mirror_handshake API called by node-native.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use node_reality::{
    CryptoTlsStream, MirrorFlight, RealityServerConfig, RealityServerConnection,
    feed_reality_server_connection, mirror_handshake, mldsa65_verify_key, public_key_from_private,
};
use std::{
    io,
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    net::{TcpListener, TcpStream},
    process::Command,
    time::timeout,
};

const USER: &str = "9d154f47-780a-4bfb-bcaa-a603a5b38ca6";
const USER_BYTES: [u8; 16] = [
    0x9d, 0x15, 0x4f, 0x47, 0x78, 0x0a, 0x4b, 0xfb, 0xbc, 0xaa, 0xa6, 0x03, 0xa5, 0xb3, 0x8c, 0xa6,
];
const PAYLOAD: &[u8] = b"REALITY real-client record fixture\0\xff0123456789";

fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Capture<S> {
    stream: S,
    read: Arc<Mutex<Vec<u8>>>,
    write: Arc<Mutex<Vec<u8>>>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Capture<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.read
                .lock()
                .unwrap()
                .extend_from_slice(&buf.filled()[start..]);
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Capture<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.write.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn record<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).await?;
    let n = u16::from_be_bytes([header[3], header[4]]) as usize;
    if n == 0 || n > 16640 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut result = header.to_vec();
    result.resize(5 + n, 0);
    stream.read_exact(&mut result[5..]).await?;
    Ok(result)
}

fn summaries(data: &[u8]) -> Vec<serde_json::Value> {
    let mut data = data;
    let mut out = Vec::new();
    while data.len() >= 5 {
        let n = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < n + 5 {
            break;
        }
        let r = &data[..n + 5];
        let mut v = serde_json::json!({"type":r[0],"length":r.len(),"sha256":digest(r)});
        if r[0] == 22 && r.len() > 44 && r[5] == 2 {
            v["retry"] = serde_json::json!(
                node_reality::classify_server_hello(r)
                    .is_ok_and(|k| k == node_reality::MirrorHello::Retry)
            );
            let ext = 44 + r[43] as usize + 3;
            if r.len() > ext + 2 {
                let mut p = ext + 2;
                while p + 4 <= r.len() {
                    let id = u16::from_be_bytes([r[p], r[p + 1]]);
                    let m = u16::from_be_bytes([r[p + 2], r[p + 3]]) as usize;
                    p += 4;
                    if p + m > r.len() {
                        break;
                    }
                    if id == 51 && m >= 2 {
                        v["key_share_group"] =
                            serde_json::json!(u16::from_be_bytes([r[p], r[p + 1]]));
                        v["key_share_extension_length"] = serde_json::json!(m);
                    }
                    p += m;
                }
            }
        }
        out.push(v);
        data = &data[n + 5..];
    }
    out
}

async fn case(
    xray: &PathBuf,
    python: &PathBuf,
    group: &str,
    mldsa: bool,
    wrong_verify: bool,
    fragment_retry: bool,
) -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = temp.path().join("cert.pem");
    let key_path = temp.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.signing_key.serialize_pem())?;
    let mut mirror = Command::new(python)
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/openssl_mirror.py"))
        .args([
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--group",
            group,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let line = BufReader::new(mirror.stdout.take().unwrap())
        .lines()
        .next_line()
        .await?
        .ok_or_else(|| io::Error::other("mirror failed"))?;
    let mirror_info: serde_json::Value = serde_json::from_str(&line).unwrap();
    let mirror_port = mirror_info["mirror"][1].as_u64().unwrap() as u16;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let node_port = listener.local_addr()?.port();
    let fragment_count = Arc::new(AtomicUsize::new(0));
    let mut proxy_task = None;
    let client_port = if fragment_retry {
        let proxy = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = proxy.local_addr()?.port();
        let count = fragment_count.clone();
        proxy_task = Some(tokio::spawn(async move {
            let (peer, _) = proxy.accept().await?;
            let upstream = TcpStream::connect(("127.0.0.1", node_port)).await?;
            let (mut from_peer, mut to_peer) = tokio::io::split(peer);
            let (mut from_node, mut to_node) = tokio::io::split(upstream);
            let upload = async {
                let mut hellos = 0;
                loop {
                    let r = record(&mut from_peer).await?;
                    if r[0] == 22 && r.get(5) == Some(&1) {
                        hellos += 1;
                    }
                    if hellos == 2 && r[0] == 22 && r.get(5) == Some(&1) {
                        let mut begin = 5;
                        for end in [6, 7, 8, 44, 60, r.len()] {
                            let mut fragment = r[..3].to_vec();
                            fragment.extend_from_slice(&((end - begin) as u16).to_be_bytes());
                            fragment.extend_from_slice(&r[begin..end]);
                            to_node.write_all(&fragment).await?;
                            begin = end;
                        }
                        count.store(6, Ordering::Relaxed);
                    } else {
                        to_node.write_all(&r).await?;
                    }
                    to_node.flush().await?;
                }
                #[allow(unreachable_code)]
                Ok::<_, io::Error>(())
            };
            let download = async {
                tokio::io::copy(&mut from_node, &mut to_peer).await?;
                Ok::<_, io::Error>(())
            };
            tokio::try_join!(upload, download)?;
            Ok::<_, io::Error>(())
        }));
        port
    } else {
        node_port
    };
    let inbound = TcpListener::bind(("127.0.0.1", 0)).await?;
    let inbound_port = inbound.local_addr()?.port();
    drop(inbound);
    // Deliberately public fixture keys; no production material is read or printed.
    let private = [0x11; 32];
    let seed = URL_SAFE_NO_PAD.encode([0x22; 32]);
    let verify = mldsa65_verify_key(&if wrong_verify {
        URL_SAFE_NO_PAD.encode([0x23; 32])
    } else {
        seed.clone()
    })?;
    let mut reality = serde_json::json!({"serverName":"localhost","password":URL_SAFE_NO_PAD.encode(public_key_from_private(private)),"shortId":"1234","fingerprint":"chrome"});
    if mldsa {
        reality["mldsa65Verify"] = serde_json::json!(verify);
    }
    let config = serde_json::json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":inbound_port,"protocol":"http"}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":client_port,"users":[{"id":USER,"encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":reality}}]});
    let config_path = temp.path().join("xray.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap())?;
    let mut client = Command::new(xray)
        .args(["run", "-c", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let peer = timeout(Duration::from_secs(5), async {
        loop {
            match TcpStream::connect(("127.0.0.1", inbound_port)).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .map_err(|_| io::Error::other("Xray HTTP listener timeout"))?;
    let client_read = Arc::new(Mutex::new(Vec::new()));
    let client_write = Arc::new(Mutex::new(Vec::new()));
    let mirror_read = Arc::new(Mutex::new(Vec::new()));
    let mirror_write = Arc::new(Mutex::new(Vec::new()));
    let cr = client_read.clone();
    let cw = client_write.clone();
    let mr = mirror_read.clone();
    let mw = mirror_write.clone();
    let server = async {
        let (stream, _) = listener.accept().await?;
        let mut stream = Capture {
            stream,
            read: cr,
            write: cw,
        };
        let hello = record(&mut stream).await?;
        let mut session = RealityServerConnection::new(RealityServerConfig {
            private_key: private,
            short_ids: vec![[0x12, 0x34, 0, 0, 0, 0, 0, 0]],
            server_name: "localhost".into(),
            max_time_diff: Some(300000),
            min_client_version: None,
            max_client_version: None,
            cipher_suites: Vec::new(),
            key_update_after_records: 1 << 20,
        })?;
        if mldsa {
            session.configure_mldsa65(&seed)?;
        }
        session.validate_client_hello(&hello)?;
        let mut dest = Capture {
            stream: TcpStream::connect(("127.0.0.1", mirror_port)).await?,
            read: mr,
            write: mw,
        };
        dest.write_all(&hello).await?;
        dest.flush().await?;
        let MirrorFlight::Ready(records) =
            mirror_handshake(&mut session, &mut stream, &mut dest).await?
        else {
            return Err(io::Error::other("unexpected mirror fallback"));
        };
        session.build_server_response(records)?;
        drop(dest);
        let mut output = Vec::new();
        while session.is_handshaking() {
            while session.wants_write() {
                output.clear();
                session.write_tls(&mut output)?;
                stream.write_all(&output).await?;
            }
            stream.flush().await?;
            let record = record(&mut stream).await?;
            feed_reality_server_connection(&mut session, &record)?;
            session.process_new_packets()?;
        }
        let mut stream = CryptoTlsStream::new(stream, session);
        let mut vless = [0; 26];
        stream.read_exact(&mut vless).await?;
        assert_eq!(vless[0], 0);
        assert_eq!(&vless[1..17], &USER_BYTES);
        assert_eq!(vless[17], 0);
        assert_eq!(&vless[18..], &[1, 0, 9, 1, 127, 0, 0, 1]);
        stream.write_all(&[0, 0]).await?;
        stream.flush().await?;
        let mut bytes = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut bytes).await?;
        assert_eq!(bytes, PAYLOAD);
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok::<_, io::Error>(())
    };
    let request = async {
        let mut peer = peer;
        peer.write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
            .await?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut b = [0];
            peer.read_exact(&mut b).await?;
            header.push(b[0]);
            if header.len() > 4096 {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        if !header.starts_with(b"HTTP/1.1 200") {
            return Err(io::Error::other("Xray rejected tunnel"));
        }
        peer.write_all(PAYLOAD).await?;
        let mut echo = vec![0; PAYLOAD.len()];
        peer.read_exact(&mut echo).await?;
        assert_eq!(echo, PAYLOAD);
        Ok::<_, io::Error>(())
    };
    let outcome = match timeout(Duration::from_secs(12), async {
        tokio::try_join!(server, request)
    })
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::other("real-client handshake timeout")),
    };
    client.kill().await?;
    mirror.kill().await?;
    if let Some(task) = proxy_task {
        task.abort();
        let _ = task.await;
    }
    let success = outcome.is_ok();
    println!(
        "{}",
        serde_json::json!({"group":group,"mldsa":mldsa,"wrong_verify":wrong_verify,"success":success,"fragmented_retry_records":fragment_count.load(Ordering::Relaxed),
        "client_to_node":summaries(&client_read.lock().unwrap()),"node_to_client":summaries(&client_write.lock().unwrap()),
        "mirror_to_node":summaries(&mirror_read.lock().unwrap()),"node_to_mirror":summaries(&mirror_write.lock().unwrap()),
        "real_client":"Xray v26.3.27","mirror":mirror_info,"payload_bytes":PAYLOAD.len(),"error":outcome.as_ref().err().map(|e|e.to_string())})
    );
    if wrong_verify {
        assert!(!success, "wrong ML-DSA verification key accepted");
        assert_eq!(
            outcome.unwrap_err().to_string(),
            "expected TLS handshake content type"
        );
        let received = summaries(&client_read.lock().unwrap());
        assert_eq!(received.last().unwrap()["type"], 23);
        assert_eq!(received.last().unwrap()["length"], 24); // authenticated encrypted TLS alert
        return Ok(());
    }
    outcome?;
    if fragment_retry {
        assert_eq!(fragment_count.load(Ordering::Relaxed), 6);
    }
    let node_records = summaries(&client_write.lock().unwrap());
    let expected_group = match group {
        "X25519" => 29,
        "prime256v1" => 23,
        _ => 4588,
    };
    let selected = node_records.iter().rev().find(|r| r["type"] == 22).unwrap();
    assert_eq!(selected["key_share_group"], expected_group);
    if group == "prime256v1" {
        assert!(node_records.iter().any(|r| r["retry"] == true));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires pinned official Xray and CPython 3.12/OpenSSL 3.5 loopback fixture"]
async fn pinned_xray_classic_hybrid_mldsa_and_real_outer_hrr() {
    let xray = PathBuf::from(std::env::var_os("NODE_REALITY_XRAY").expect("NODE_REALITY_XRAY"));
    let python =
        PathBuf::from(std::env::var_os("NODE_REALITY_PYTHON").expect("NODE_REALITY_PYTHON"));
    assert!(xray.is_absolute() && python.is_absolute());
    // Platform-specific pinned release binary; other architectures need their exact verified digest.
    if cfg!(windows) {
        assert_eq!(
            digest(&std::fs::read(&xray).unwrap()),
            "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1"
        );
    }
    let seed = URL_SAFE_NO_PAD.encode([0x22; 32]);
    let derived = Command::new(&xray)
        .args(["mldsa65", "-i", &seed])
        .output()
        .await
        .unwrap();
    assert!(derived.status.success());
    let output = String::from_utf8(derived.stdout).unwrap();
    let official = output
        .lines()
        .find_map(|line| line.strip_prefix("Verify: "))
        .unwrap();
    assert_eq!(official, mldsa65_verify_key(&seed).unwrap());
    println!(
        "{}",
        serde_json::json!({"mldsa65_public_key_matches_official":true,"public_key_sha256":digest(official.as_bytes())})
    );
    for (group, mldsa, wrong_verify, fragment_retry) in [
        ("X25519", false, false, false),
        ("X25519MLKEM768", false, false, false),
        ("X25519MLKEM768", true, false, false),
        ("X25519MLKEM768", true, true, false),
        ("prime256v1", false, false, false),
        ("prime256v1", true, false, false),
        ("prime256v1", true, false, true),
    ] {
        case(&xray, &python, group, mldsa, wrong_verify, fragment_retry)
            .await
            .unwrap();
    }
}
