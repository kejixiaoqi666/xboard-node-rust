//! Bounded REALITY acceptance. Mirror forwarding stays in the listener's task.
use crate::{ConnectionContext, Error, config::Protocol, protocol, vision};
use bytes::Bytes;
use node_core::reality::Settings;
use node_reality::{CryptoTlsStream, RealityServerConnection};
use std::{io, net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout_at},
};

const MAX_RECORD: usize = 16_640;
const MAX_MIRROR_BYTES: usize = 65_536;

async fn record<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Bytes> {
    let mut header = [0; 5];
    s.read_exact(&mut header).await?;
    let n = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[1] != 3 || n == 0 || n > MAX_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TLS record",
        ));
    }
    let mut data = vec![0; n + 5];
    data[..5].copy_from_slice(&header);
    s.read_exact(&mut data[5..]).await?;
    Ok(data.into())
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn length(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn vector(&mut self) -> Option<&'a [u8]> {
        let n = self.length()?;
        self.take(n)
    }
}

// Exactly one complete ClientHello, one hostname and a TLS 1.3 offer.
fn client_name(data: &[u8]) -> Option<&str> {
    if data.len() < 9 || data[0] != 22 || data[5] != 1 {
        return None;
    }
    let n = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | data[8] as usize;
    if n + 9 != data.len() {
        return None;
    }
    let mut c = Cursor(&data[9..]);
    c.take(34)?;
    let n = c.byte()? as usize;
    c.take(n)?;
    let suites = c.vector()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return None;
    }
    let n = c.byte()? as usize;
    c.take(n)?;
    let extensions = c.vector()?;
    if !c.0.is_empty() {
        return None;
    }
    let mut e = Cursor(extensions);
    let mut name = None;
    let mut tls13 = false;
    let mut seen = std::collections::BTreeSet::new();
    while !e.0.is_empty() {
        let id = e.length()?;
        if !seen.insert(id) {
            return None;
        }
        let value = e.vector()?;
        if id == 0 {
            let mut v = Cursor(value);
            let list = v.vector()?;
            if !v.0.is_empty() {
                return None;
            }
            let mut list = Cursor(list);
            if list.byte()? != 0 {
                return None;
            }
            name = Some(std::str::from_utf8(list.vector()?).ok()?);
            if !list.0.is_empty() {
                return None;
            }
        } else if id == 43 {
            let mut v = Cursor(value);
            let n = v.byte()? as usize;
            let versions = v.take(n)?;
            if !v.0.is_empty() || !n.is_multiple_of(2) {
                return None;
            }
            tls13 = versions.as_chunks::<2>().0.iter().any(|v| v == &[3, 4]);
        }
    }
    name.filter(|n| tls13 && node_core::routing::valid_domain(n))
}

fn server_tls13(data: &[u8]) -> bool {
    fn check(data: &[u8]) -> Option<()> {
        if data.len() < 9 || data[0] != 22 || data[5] != 2 {
            return None;
        }
        let n = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | data[8] as usize;
        if n + 9 != data.len() {
            return None;
        }
        let mut c = Cursor(&data[9..]);
        c.take(2)?;
        let random = c.take(32)?;
        const HRR: [u8; 32] = [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ];
        if random == HRR {
            return None;
        }
        let n = c.byte()? as usize;
        c.take(n)?;
        c.take(3)?;
        let mut e = Cursor(c.vector()?);
        if !c.0.is_empty() {
            return None;
        }
        let mut version = false;
        while !e.0.is_empty() {
            let id = e.length()?;
            let v = e.vector()?;
            if id == 43 {
                if version || v != [3, 4] {
                    return None;
                }
                version = true;
            }
        }
        version.then_some(())
    }
    check(data).is_some()
}

async fn fallback<S: AsyncRead + AsyncWrite + Unpin>(
    mut client: S,
    mut mirror: TcpStream,
    records: Vec<Bytes>,
) -> Result<(), Error> {
    // Fixed maximum lifetime; no detached forwarding survives service shutdown.
    timeout_at(Instant::now() + Duration::from_secs(300), async {
        for r in records {
            client.write_all(&r).await?;
        }
        client.flush().await?;
        tokio::io::copy_bidirectional(&mut client, &mut mirror).await?;
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| Error::Protocol)??;
    Ok(())
}

pub(super) async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut client: S,
    settings: &Settings,
    context: ConnectionContext<'_>,
) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let accepted = timeout_at(deadline, async {
        let hello = record(&mut client).await?;
        let (host, port) = settings.endpoint().map_err(|_| Error::Config)?;
        let address = host
            .parse::<IpAddr>()
            .map(protocol::Address::Ip)
            .unwrap_or_else(|_| protocol::Address::Domain(host));
        let (_, ips) = context.network.resolve(&address).await?;
        let mut mirror = None;
        for ip in ips {
            if let Ok(Ok(s)) =
                tokio::time::timeout(Duration::from_secs(3), TcpStream::connect((ip, port))).await
            {
                mirror = Some(s);
                break;
            }
        }
        let mut mirror =
            mirror.ok_or_else(|| Error::Io(io::ErrorKind::ConnectionRefused.into()))?;
        mirror.write_all(&hello).await?;
        mirror.flush().await?;
        let mut session = RealityServerConnection::new(crate::reality_config(settings)?)?;
        let valid_name =
            client_name(&hello).is_some_and(|n| n.eq_ignore_ascii_case(&settings.server_name));
        if !valid_name || session.validate_client_hello(&hello).is_err() {
            return Ok::<_, Error>(Err((client, mirror, Vec::new())));
        }
        let mut records = Vec::new();
        let mut total = 0;
        for _ in 0..16 {
            let r = record(&mut mirror).await?;
            total += r.len();
            if total > MAX_MIRROR_BYTES {
                return Err(Error::Protocol);
            }
            let bad = records.is_empty() && !server_tls13(&r);
            records.push(r);
            if bad {
                return Ok(Err((client, mirror, records)));
            }
            if records.len() >= 6 || (records.len() >= 3 && records[2].len() > 512) {
                break;
            }
        }
        if records.len() < 3
            || records[1].as_ref() != [20, 3, 3, 0, 1, 1]
            || records[2..].iter().any(|r| r[0] != 23)
        {
            return Err(Error::Protocol);
        }
        drop(mirror);
        session.build_server_response(records)?;
        let mut writes = Vec::with_capacity(4096);
        let mut total = 0;
        while session.is_handshaking() {
            while session.wants_write() {
                writes.clear();
                let n = session.write_tls(&mut writes)?;
                if n == 0 {
                    return Err(Error::Protocol);
                }
                client.write_all(&writes).await?;
            }
            client.flush().await?;
            let r = record(&mut client).await?;
            total += r.len();
            if total > MAX_MIRROR_BYTES {
                return Err(Error::Protocol);
            }
            node_reality::feed_reality_server_connection(&mut session, &r)?;
            session.process_new_packets()?;
        }
        Ok(Ok((session, client)))
    })
    .await
    .map_err(|_| Error::Protocol)??;
    let (session, client) = match accepted {
        Ok(pair) => pair,
        Err((client, mirror, records)) => return fallback(client, mirror, records).await,
    };
    let mut stream = CryptoTlsStream::new(vision::RecordIo::new(client), session);
    let deadline = Instant::now() + Duration::from_secs(10);
    let request = timeout_at(
        deadline,
        protocol::handshake(&mut stream, Protocol::Vless, context.users),
    )
    .await
    .map_err(|_| Error::Protocol)??;
    if request.command != protocol::Command::Tcp {
        return Err(Error::Unsupported);
    }
    if let Some(uuid) = request.vision_uuid {
        timeout_at(deadline, stream.flush())
            .await
            .map_err(|_| Error::Protocol)??;
        let (transport, session) = stream.into_inner();
        let stream =
            node_vision::VisionStream::new_server(transport.into_inner()?, session, uuid, &[])?;
        crate::connection_authenticated(stream, Protocol::Vless, request, true, deadline, context)
            .await
    } else {
        crate::connection_authenticated(stream, Protocol::Vless, request, false, deadline, context)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    fn hello(name: &str) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7; 32]);
        body.push(32);
        body.extend([0; 32]);
        body.extend([0, 2, 0x13, 1, 1, 0]);
        let mut sni = vec![0];
        sni.extend((name.len() as u16).to_be_bytes());
        sni.extend(name.as_bytes());
        let mut value = Vec::new();
        value.extend((sni.len() as u16).to_be_bytes());
        value.extend(sni);
        let mut extensions = vec![0, 0];
        extensions.extend((value.len() as u16).to_be_bytes());
        extensions.extend(value);
        extensions.extend([0, 43, 0, 3, 2, 3, 4]);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let n = body.len();
        let mut record = vec![22, 3, 1];
        record.extend(((n + 4) as u16).to_be_bytes());
        record.extend([1, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
        record.extend(body);
        record
    }
    #[test]
    fn strict_client_hello_rejects_truncation_and_duplicate_extensions() {
        let h = hello("localhost");
        assert_eq!(client_name(&h), Some("localhost"));
        for n in 0..h.len() {
            assert_eq!(client_name(&h[..n]), None);
        }
        let mut duplicate = h.clone();
        duplicate.extend([0, 43, 0, 3, 2, 3, 4]);
        assert_eq!(client_name(&duplicate), None);
        let mut no13 = h;
        let last = no13.len() - 1;
        no13[last] = 3;
        assert_eq!(client_name(&no13), None);
    }
    #[tokio::test]
    async fn excessive_record_is_rejected_before_body_read() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[22, 3, 3, 255, 255]).await.unwrap();
        assert_eq!(
            record(&mut b).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[tokio::test]
    async fn unknown_auth_stays_in_owned_task_and_forwards_only_fixed_mirror() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let h = hello("localhost");
        let expected = h.clone();
        let mirror = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut input = vec![0; expected.len()];
            s.read_exact(&mut input).await.unwrap();
            assert_eq!(input, expected);
            s.write_all(b"fixed-mirror-response").await.unwrap();
            let mut data = [0; 4];
            s.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            s.write_all(b"pong").await.unwrap();
        });
        let settings:Settings=serde_json::from_value(serde_json::json!({"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","server_name":"localhost","dest":address.to_string(),"short_id":"1234"})).unwrap();
        let users = Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::auth::Snapshot::new(Protocol::Vless, Vec::new()).unwrap(),
        ));
        let traffic = Arc::new(crate::traffic::Traffic::new_with_enabled(
            "a".repeat(32),
            false,
        ));
        let limits = Arc::new(crate::limits::Registry::default());
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let network = crate::network::Network::direct();
        let (mut peer, inbound) = tokio::io::duplex(4096);
        let work = async {
            connection(
                inbound,
                &settings,
                ConnectionContext {
                    users: &users,
                    traffic: &traffic,
                    source: address,
                    limits: &limits,
                    udp_slots: &slots,
                    network: &network,
                },
            )
            .await
        };
        let exercise = async {
            peer.write_all(&h).await.unwrap();
            let mut answer = [0; 21];
            peer.read_exact(&mut answer).await.unwrap();
            assert_eq!(&answer, b"fixed-mirror-response");
            peer.write_all(b"ping").await.unwrap();
            let mut pong = [0; 4];
            peer.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");
            peer.shutdown().await.unwrap();
        };
        let (result, ()) = tokio::join!(work, exercise);
        result.unwrap();
        mirror.await.unwrap();
    }
}
