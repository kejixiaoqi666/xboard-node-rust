//! VMess AEAD authentication and payload framing, adapted from shoes' MIT codecs.
mod crc32;
mod fnv1a;
mod md5;
mod sha2;
mod typed;
pub(crate) mod wire;
use crate::io_adapter::{PacketReader, PacketStream, PacketWriter};
use node_session::{BoxStream, Destination, Host, User};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::SystemTime,
};
use tokio::{io::AsyncReadExt, sync::watch};
pub use wire::Security;

#[derive(Default)]
pub struct ReplayCache(Mutex<HashMap<[u8; 16], u64>>);
impl ReplayCache {
    fn admit(&self, auth: [u8; 16], now: u64) -> io::Result<()> {
        let mut ids = self
            .0
            .lock()
            .map_err(|_| io::Error::other("replay lock poisoned"))?;
        ids.retain(|_, admitted| now.saturating_sub(*admitted) <= 240);
        if ids.contains_key(&auth) {
            return Err(crate::invalid("VMess auth ID replay"));
        }
        if ids.len() >= 65536 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VMess replay cache at capacity",
            ));
        }
        ids.insert(auth, now);
        Ok(())
    }
}
struct Admission {
    user: User,
    target: Option<Destination>,
    command: u8,
    reader: wire::Reader<tokio::io::ReadHalf<BoxStream>>,
    writer: wire::Writer<tokio::io::WriteHalf<BoxStream>>,
}
async fn authenticate(
    mut stream: BoxStream,
    host: &dyn Host,
    config: &crate::Config,
) -> io::Result<Admission> {
    let mut auth = [0; 16];
    stream.read_exact(&mut auth).await?;
    // Take a fresh snapshot after the first authentication bytes arrive.
    let snapshot = config.authentication.vmess(host.users())?;
    let now = SystemTime::UNIX_EPOCH
        .elapsed()
        .map_err(io::Error::other)?
        .as_secs();
    let mut matched = None;
    for (index, cipher) in &snapshot.keys {
        if cipher.validate(&auth, now) {
            matched = Some((snapshot.users[*index].clone(), cipher.instruction_key));
            break;
        }
    }
    let (user, instruction_key) = matched.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VMess authentication failed",
        )
    })?;
    let mut encrypted_len = [0; 18];
    stream.read_exact(&mut encrypted_len).await?;
    let mut nonce = [0; 8];
    stream.read_exact(&mut nonce).await?;
    let len = wire::open_header_length(&instruction_key, &auth, &nonce, &mut encrypted_len)?;
    if !(42..=316).contains(&len) {
        return Err(crate::invalid("VMess header length out of bounds"));
    }
    let mut body = vec![0; len + 16];
    stream.read_exact(&mut body).await?;
    wire::open_header(&instruction_key, &auth, &nonce, &mut body)?;
    body.truncate(len);
    let header = wire::Header::decode(&body)?;
    if config.vmess_security != Security::Any && config.vmess_security != header.security {
        return Err(crate::invalid("VMess cipher is disabled"));
    }
    config.vmess_replay.admit(auth, now)?;
    let (read, write) = tokio::io::split(stream);
    let response_iv: [u8; 16] = sha2::compute_sha256(&header.iv)[..16]
        .try_into()
        .expect("SHA256 size");
    let response_key: [u8; 16] = sha2::compute_sha256(&header.key)[..16]
        .try_into()
        .expect("SHA256 size");
    let request_codec = wire::BodyCodec::new(
        header.security,
        header.key,
        header.iv,
        header.key,
        header.iv,
        header.options,
        config.max_frame,
    )?;
    // The authenticated-length key and nonce use request key/IV in both directions (Xray convention).
    let response_codec = wire::BodyCodec::new(
        header.security,
        response_key,
        response_iv,
        header.key,
        header.iv,
        header.options,
        config.max_frame,
    )?;
    let prefix = wire::response_header(header.response, &response_key, &response_iv)?;
    Ok(Admission {
        user,
        target: header.target,
        command: header.command,
        reader: wire::Reader::new(read, request_codec),
        writer: wire::Writer::new(write, response_codec, prefix),
    })
}
pub(crate) async fn serve(
    stream: BoxStream,
    peer: SocketAddr,
    host: Arc<dyn Host>,
    config: crate::Config,
    mut cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    let admission = tokio::select! {
        biased;
        _ = crate::cancelled(&mut cancel) => return Ok(()),
        result = tokio::time::timeout(config.handshake_timeout, authenticate(stream, host.as_ref(), &config)) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VMess handshake timed out"))??,
    };
    let Admission {
        user,
        target,
        command,
        mut reader,
        mut writer,
    } = admission;
    if command == 3
        || command == 1
            && target.as_ref().is_some_and(|target| {
                target.host == crate::mux::MUX_HOST && target.port == crate::mux::MUX_PORT
            })
    {
        config.require_multiplex()?;
    }
    match command {
        1 => {
            let target = target.ok_or_else(|| crate::invalid("VMess missing destination"))?;
            let client: BoxStream = Box::new(PacketStream::new(
                reader,
                writer,
                (config.max_frame.saturating_sub(80)).clamp(1, 8192),
            ));
            if target.host == crate::mux::MUX_HOST && target.port == crate::mux::MUX_PORT {
                crate::mux::serve_h2mux(client, user, peer, host, config, cancel).await
            } else {
                tokio::select! {
                    _ = crate::cancelled(&mut cancel) => Ok(()),
                    result = async { let remote = host.connect(&user, peer, &target).await?; node_session::relay(client, remote).await } => result,
                }
            }
        }
        2 => {
            let target = target.ok_or_else(|| crate::invalid("VMess missing UDP destination"))?;
            let datagram = tokio::select! { _ = crate::cancelled(&mut cancel) => return Ok(()), result = host.datagram(&user, peer) => result? };
            let upstream = async {
                while let Some(packet) = reader.read_packet().await? {
                    if datagram.send(&packet, &target).await? != packet.len() {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP send"));
                    }
                }
                Ok::<(), io::Error>(())
            };
            let downstream = async {
                let mut payload = vec![0; config.max_frame.saturating_sub(80)];
                loop {
                    let (len, _) = datagram.receive(&mut payload).await?;
                    if len > payload.len() {
                        return Err(crate::invalid("host returned oversized datagram"));
                    }
                    writer.write_packet(&payload[..len]).await?;
                    writer.flush().await?;
                }
            };
            tokio::select! { _ = crate::cancelled(&mut cancel) => Ok(()), result = upstream => result, result = downstream => result }
        }
        3 => {
            let client: BoxStream = Box::new(PacketStream::new(
                reader,
                writer,
                (config.max_frame.saturating_sub(80)).clamp(1, 8192),
            ));
            crate::mux::serve_xudp(client, user, peer, host, config, cancel).await
        }
        _ => Err(crate::invalid("VMess command not supported")),
    }
}

#[cfg(test)]
#[path = "../../tests/support/mod.rs"]
mod test_support;
#[cfg(test)]
mod admission_tests {
    use super::test_support as support;
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use tokio::io::AsyncWriteExt;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], data: &mut Vec<u8>) {
        LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key).unwrap())
            .seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(nonce).unwrap(),
                Aad::from(aad),
                data,
            )
            .unwrap();
    }
    fn request(timestamp: u64, uuid: [u8; 16], advertised_len: Option<u16>) -> Vec<u8> {
        let key = wire::instruction_key(&uuid);
        let mut auth = [0; 16];
        auth[..8].copy_from_slice(&timestamp.to_be_bytes());
        auth[8..12].copy_from_slice(&[2, 3, 4, 5]);
        let crc = crc32::crc32c(&auth[..12]);
        auth[12..].copy_from_slice(&crc.to_be_bytes());
        let auth_key = sha2::kdf(&key, &[b"AES Auth ID Encryption"]);
        aes::Aes128::new_from_slice(&auth_key[..16])
            .unwrap()
            .encrypt_block((&mut auth).into());
        let unique = [9; 8];
        let mut clear = vec![0; 38];
        clear[0] = 1;
        clear[1..17].fill(4);
        clear[17..33].fill(7);
        clear[33] = 17;
        clear[34] = 13;
        clear[35] = 3;
        clear[37] = 1;
        clear.extend_from_slice(&[0, 80, 1, 127, 0, 0, 1]);
        let mut checksum = fnv1a::Fnv1aHasher::new();
        checksum.write(&clear);
        clear.extend_from_slice(&checksum.finish().to_be_bytes());
        let mut length = advertised_len
            .unwrap_or(clear.len() as u16)
            .to_be_bytes()
            .to_vec();
        let k = sha2::kdf(&key, &[b"VMess Header AEAD Key_Length", &auth, &unique]);
        let iv = sha2::kdf(&key, &[b"VMess Header AEAD Nonce_Length", &auth, &unique]);
        seal(&k[..16], &iv[..12], &auth, &mut length);
        let k = sha2::kdf(&key, &[b"VMess Header AEAD Key", &auth, &unique]);
        let iv = sha2::kdf(&key, &[b"VMess Header AEAD Nonce", &auth, &unique]);
        seal(&k[..16], &iv[..12], &auth, &mut clear);
        let mut request = auth.to_vec();
        request.extend_from_slice(&length);
        request.extend_from_slice(&unique);
        request.extend_from_slice(&clear);
        request
    }
    async fn admission(
        bytes: &[u8],
        host: &dyn Host,
        config: &crate::Config,
    ) -> io::Result<Admission> {
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(bytes).await.unwrap();
        authenticate(Box::new(server), host, config).await
    }
    #[tokio::test]
    async fn fresh_users_replay_timestamp_and_length_admission() {
        let host = support::TestHost::new();
        let config = crate::Config::default();
        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
        let valid = request(now, support::UUID, None);
        assert!(admission(&valid, host.as_ref(), &config).await.is_ok());
        let result = admission(&valid, host.as_ref(), &config.clone()).await;
        assert!(matches!(result, Err(ref e) if e.to_string().contains("replay")));
        assert!(
            admission(
                &request(now - 300, support::UUID, None),
                host.as_ref(),
                &config
            )
            .await
            .is_err()
        );
        assert!(
            admission(&request(now, [0; 16], None), host.as_ref(), &config)
                .await
                .is_err()
        );
        assert!(
            admission(
                &request(now, support::UUID, Some(65535)),
                host.as_ref(),
                &config
            )
            .await
            .is_err()
        );
        *host.users.write().unwrap() = Arc::from([]);
        assert!(
            admission(&valid, host.as_ref(), &crate::Config::default())
                .await
                .is_err()
        );
        assert_eq!(host.totals(), (0, 0));
    }
    #[tokio::test]
    async fn partial_handshake_deadline_and_cancel_are_bounded() {
        let host = support::TestHost::new();
        let (_client, server) = tokio::io::duplex(1024);
        let config = crate::Config {
            handshake_timeout: std::time::Duration::from_millis(30),
            ..Default::default()
        };
        assert_eq!(
            serve(
                Box::new(server),
                support::peer(),
                host.clone(),
                config,
                None
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        let (_client, server) = tokio::io::duplex(1024);
        let (_tx, rx) = watch::channel(true);
        assert!(
            serve(
                Box::new(server),
                support::peer(),
                host,
                crate::Config::default(),
                Some(rx)
            )
            .await
            .is_ok()
        );
    }
}
