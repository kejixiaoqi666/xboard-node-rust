//! VLESS length packets and Trojan UDP-over-stream associations.
use crate::{
    Error,
    config::Protocol,
    protocol::{self, Address, Request},
    traffic::Counter,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};

const MAX_DATAGRAM: usize = 65507;
const IDLE: Duration = Duration::from_secs(60);

struct Packet {
    address: Address,
    port: u16,
    payload: Vec<u8>,
}

async fn packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    protocol: Protocol,
    fixed: &(Address, u16),
) -> Result<Option<Packet>, Error> {
    let first = match reader.read_u8().await {
        Ok(first) => first,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let (address, port, size) = match protocol {
        Protocol::Vless => {
            let size = ((first as usize) << 8) | reader.read_u8().await? as usize;
            (fixed.0.clone(), fixed.1, size)
        }
        Protocol::Shadowsocks
        | Protocol::Vmess
        | Protocol::AnyTls
        | Protocol::Hysteria2
        | Protocol::Tuic => return Err(Error::Unsupported),
        Protocol::Trojan => {
            let address = protocol::address(reader, first, 3, 4).await?;
            let port = reader.read_u16().await?;
            let size = reader.read_u16().await? as usize;
            if reader.read_u16().await? != 0x0d0a {
                return Err(Error::Protocol);
            }
            (address, port, size)
        }
    };
    if size > MAX_DATAGRAM || port == 0 {
        return Err(Error::Protocol);
    }
    let mut payload = vec![0; size];
    reader.read_exact(&mut payload).await?;
    Ok(Some(Packet {
        address,
        port,
        payload,
    }))
}

fn header(protocol: Protocol, source: SocketAddr, size: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(23);
    if protocol == Protocol::Trojan {
        match source.ip() {
            IpAddr::V4(ip) => {
                header.push(1);
                header.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                header.push(4);
                header.extend(ip.octets());
            }
        }
        header.extend(source.port().to_be_bytes());
    }
    header.extend((size as u16).to_be_bytes());
    if protocol == Protocol::Trojan {
        header.extend([13, 10]);
    }
    header
}

async fn write_payload<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
    counter: Option<&Arc<Counter>>,
) -> Result<(), Error> {
    let mut offset = 0;
    while offset < body.len() {
        let size = writer.write(&body[offset..]).await?;
        if size == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
        }
        if let Some(counter) = counter {
            counter.add(1, size);
        }
        offset += size;
    }
    Ok(())
}

pub(crate) async fn relay<S: AsyncRead + AsyncWrite + Unpin>(
    inbound: S,
    request: Request,
    protocol: Protocol,
    datagram: Arc<dyn node_session::Datagram>,
    counter: Option<Arc<Counter>>,
) -> Result<(), Error> {
    let fixed = (request.address, request.port);
    let last = Mutex::new(Instant::now());
    let (mut reader, mut writer) = tokio::io::split(inbound);
    let send = async {
        // Poll continuously: cancelling a partially parsed inbound frame would
        // lose its boundary. The enclosing select only ends the whole session.
        while let Some(packet) = packet(&mut reader, protocol, &fixed).await? {
            let host = match packet.address {
                Address::Ip(ip) => ip.to_string(),
                Address::Domain(name) => name,
            };
            let target = node_session::Destination::new(host, packet.port)?;
            datagram.send(&packet.payload, &target).await?;
            *last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        }
        Ok::<_, Error>(())
    };
    let receive = async {
        let mut buffer = vec![0; 65536];
        loop {
            let (size, source) = datagram.receive(&mut buffer).await?;
            let source = SocketAddr::new(
                source.host.parse().map_err(|_| Error::Protocol)?,
                source.port,
            );
            writer.write_all(&header(protocol, source, size)).await?;
            write_payload(&mut writer, &buffer[..size], counter.as_ref()).await?;
            writer.flush().await?;
            *last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        }
    };
    let idle = async {
        loop {
            let deadline = *last.lock().unwrap_or_else(|e| e.into_inner()) + IDLE;
            tokio::time::sleep_until(deadline).await;
            if Instant::now() >= *last.lock().unwrap_or_else(|e| e.into_inner()) + IDLE {
                return Ok(());
            }
        }
    };
    tokio::select! {result=send=>result,result=receive=>result,result=idle=>result}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Users;
    use crate::{auth, config, limits, traffic};
    use arc_swap::ArcSwap;
    use tokio::net::UdpSocket;
    const UUID: &str = "00000000-0000-4000-8000-000000000007";

    fn users(protocol: Protocol) -> Users {
        Arc::new(ArcSwap::from_pointee(
            auth::Snapshot::new(
                protocol,
                vec![config::User {
                    name: "7".into(),
                    uuid: (protocol == Protocol::Vless).then(|| UUID.into()),
                    password: (protocol == Protocol::Trojan).then(|| UUID.into()),
                    flow: None,
                    speed_limit: 0,
                    device_limit: 0,
                }],
            )
            .unwrap(),
        ))
    }

    async fn roundtrip(protocol: Protocol) {
        let origin = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = origin.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut body = vec![0; 65536];
            for _ in 0..3 {
                let (size, peer) = origin.recv_from(&mut body).await.unwrap();
                // A reply from an unrequested source port must never enter the
                // client's stream or payload accounting.
                let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                attacker.send_to(b"unsolicited", peer).await.unwrap();
                origin.send_to(&body[..size], peer).await.unwrap();
            }
        });
        let users = users(protocol);
        let traffic = Arc::new(traffic::Traffic::new_with_enabled("d".repeat(32), true));
        let registry = Arc::new(limits::Registry::new(Arc::clone(&users)));
        let (mut client, server) = tokio::io::duplex(4096);
        let connection_traffic = Arc::clone(&traffic);
        let proxy = tokio::spawn(async move {
            crate::connection(
                server,
                protocol,
                &users,
                &connection_traffic,
                "127.0.0.1".parse().unwrap(),
                &registry,
                &Arc::new(tokio::sync::Semaphore::new(1024)),
            )
            .await
        });
        let mut handshake = match protocol {
            Protocol::Vless => {
                let mut bytes = vec![0];
                bytes.extend(auth::uuid(UUID).unwrap());
                bytes.extend([0, 2]);
                bytes.extend(target.port().to_be_bytes());
                bytes.extend([1, 127, 0, 0, 1]);
                bytes
            }
            Protocol::Shadowsocks
            | Protocol::Vmess
            | Protocol::AnyTls
            | Protocol::Hysteria2
            | Protocol::Tuic => unreachable!("other protocols use their own codec"),
            Protocol::Trojan => {
                let mut bytes = auth::trojan_key(UUID).to_vec();
                bytes.extend([13, 10, 3, 1, 0, 0, 0, 0, 0, 0, 13, 10]);
                bytes
            }
        };
        client.write_all(&handshake).await.unwrap();
        handshake.clear();
        if protocol == Protocol::Vless {
            let mut ack = [0; 2];
            client.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, [0, 0]);
        }
        let mut total = 0;
        for size in [0, 37, MAX_DATAGRAM] {
            let body = vec![0x95; size];
            let frame_header = header(protocol, target, size);
            let frame = [frame_header.as_slice(), body.as_slice()].concat();
            // Tiny writes also exercise partially received headers/payloads.
            // Read on a separate split half so large frames cannot deadlock the
            // bounded duplex buffer while the UDP echo is returning.
            let (mut read, mut write) = tokio::io::split(&mut client);
            let send = async {
                for part in frame.chunks(31) {
                    write.write_all(part).await.unwrap();
                }
            };
            let recv = async {
                packet(
                    &mut read,
                    protocol,
                    &(Address::Ip(target.ip()), target.port()),
                )
                .await
                .unwrap()
                .unwrap()
            };
            let (_, reply) = tokio::join!(send, recv);
            assert_eq!(reply.payload, body);
            assert_eq!(reply.port, target.port());
            total += size as u64;
        }
        drop(client);
        proxy.await.unwrap().unwrap();
        echo.await.unwrap();
        assert_eq!(
            traffic.snapshot().unwrap().unwrap().traffic["7"],
            [total, total]
        );
    }

    #[tokio::test]
    async fn vless_udp_fragmentation_zero_large_payload_and_source_filtering() {
        tokio::time::timeout(Duration::from_secs(5), roundtrip(Protocol::Vless))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn trojan_udp_fragmentation_zero_large_payload_and_source_filtering() {
        tokio::time::timeout(Duration::from_secs(5), roundtrip(Protocol::Trojan))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn trojan_udp_one_association_multiple_peers_domain_and_ipv6() {
        let test = async {
            let origins = [
                UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                UdpSocket::bind("[::1]:0").await.unwrap(),
            ];
            let targets: Vec<_> = origins
                .iter()
                .map(|socket| socket.local_addr().unwrap())
                .collect();
            let mut echoes = Vec::new();
            for origin in origins {
                echoes.push(tokio::spawn(async move {
                    let mut body = [0; 128];
                    for _ in 0..2 {
                        let (size, peer) = origin.recv_from(&mut body).await.unwrap();
                        origin.send_to(&body[..size], peer).await.unwrap();
                    }
                }));
            }
            let users = users(Protocol::Trojan);
            let registry = Arc::new(limits::Registry::new(Arc::clone(&users)));
            let traffic = Arc::new(traffic::Traffic::new_with_enabled("e".repeat(32), true));
            let (mut client, server) = tokio::io::duplex(4096);
            let connection_traffic = Arc::clone(&traffic);
            let proxy = tokio::spawn(async move {
                crate::connection(
                    server,
                    Protocol::Trojan,
                    &users,
                    &connection_traffic,
                    "127.0.0.1".parse().unwrap(),
                    &registry,
                    &Arc::new(tokio::sync::Semaphore::new(1024)),
                )
                .await
            });
            let mut handshake = auth::trojan_key(UUID).to_vec();
            handshake.extend([13, 10, 3, 1, 0, 0, 0, 0, 0, 0, 13, 10]);
            client.write_all(&handshake).await.unwrap();
            let mut total = 0;
            // Cycle back through the same endpoints, exercising reuse as well
            // as two IPv4 ports and a native IPv6 destination in one session.
            for index in 0..6 {
                let target = targets[index % targets.len()];
                let body = vec![index as u8; 13 + index];
                let mut frame = if index % targets.len() == 1 {
                    let mut frame = vec![3, 9];
                    frame.extend(b"localhost");
                    frame.extend(target.port().to_be_bytes());
                    frame.extend((body.len() as u16).to_be_bytes());
                    frame.extend(b"\r\n");
                    frame
                } else {
                    header(Protocol::Trojan, target, body.len())
                };
                frame.extend(&body);
                client.write_all(&frame).await.unwrap();
                let reply = packet(
                    &mut client,
                    Protocol::Trojan,
                    &(Address::Ip(target.ip()), target.port()),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(reply.payload, body);
                assert_eq!(reply.port, target.port());
                match reply.address {
                    Address::Ip(ip) => assert_eq!(ip, target.ip()),
                    Address::Domain(_) => panic!("reply must identify the actual origin"),
                }
                total += body.len() as u64;
            }
            drop(client);
            proxy.await.unwrap().unwrap();
            for echo in echoes {
                echo.await.unwrap();
            }
            assert_eq!(
                traffic.snapshot().unwrap().unwrap().traffic["7"],
                [total, total]
            );
        };
        tokio::time::timeout(Duration::from_secs(5), test)
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn idle_udp_association_closes_and_releases_device_lease() {
        let users = users(Protocol::Vless);
        let registry = Arc::new(limits::Registry::new(Arc::clone(&users)));
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let connection_slots = Arc::clone(&slots);
        let connection_registry = Arc::clone(&registry);
        let (mut client, server) = tokio::io::duplex(4096);
        let proxy = tokio::spawn(async move {
            crate::connection(
                server,
                Protocol::Vless,
                &users,
                &Arc::new(traffic::Traffic::new_with_enabled("f".repeat(32), false)),
                "127.0.0.1".parse().unwrap(),
                &connection_registry,
                &connection_slots,
            )
            .await
        });
        let mut handshake = vec![0];
        handshake.extend(auth::uuid(UUID).unwrap());
        handshake.extend([0, 2, 0, 53, 1, 127, 0, 0, 1]);
        client.write_all(&handshake).await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0);
        tokio::task::yield_now().await;
        assert_eq!(slots.available_permits(), 0);
        tokio::time::advance(IDLE + Duration::from_secs(1)).await;
        proxy.await.unwrap().unwrap();
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(
            client.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert!(
            registry
                .acquire(
                    Arc::from("7"),
                    "127.0.0.2".parse().unwrap(),
                    limits::Policy::new(0, 1).unwrap()
                )
                .is_ok()
        );
    }
    #[tokio::test]
    async fn invalid_udp_lengths_truncation_and_trojan_crlf_are_rejected() {
        let fixed = (Address::Ip("127.0.0.1".parse().unwrap()), 53);
        for bytes in [vec![255, 255], vec![0], vec![0, 2, 7]] {
            assert!(
                packet(&mut bytes.as_slice(), Protocol::Vless, &fixed)
                    .await
                    .is_err()
            );
        }
        let mut bytes = header(Protocol::Trojan, "127.0.0.1:53".parse().unwrap(), 0);
        *bytes.last_mut().unwrap() = 0;
        assert!(
            packet(&mut bytes.as_slice(), Protocol::Trojan, &fixed)
                .await
                .is_err()
        );
        assert!(
            packet(&mut &[][..], Protocol::Vless, &fixed)
                .await
                .unwrap()
                .is_none()
        );
    }
}
