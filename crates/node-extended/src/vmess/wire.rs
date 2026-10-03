use super::{
    crc32,
    fnv1a::Fnv1aHasher,
    md5::{compute_md5, create_chacha_key},
    sha2,
};
use crate::io_adapter::{PacketReader, PacketWriter};
use aes::{
    Aes128,
    cipher::{BlockDecrypt, KeyInit},
};
use async_trait::async_trait;
use bytes::Bytes;
use digest::XofReader;
use node_session::Destination;
use rand::Rng;
use ring::aead::{AES_128_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use shake::{
    Shake128,
    digest::{ExtendableOutput, Update},
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    Any,
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}
fn aead(security: Security, key: &[u8]) -> io::Result<LessSafeKey> {
    let key = match security {
        Security::Aes128Gcm => UnboundKey::new(&AES_128_GCM, key),
        Security::ChaCha20Poly1305 => UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(key)),
        _ => return Err(crate::invalid("no AEAD for selected cipher")),
    }
    .map_err(|_| crate::invalid("invalid AEAD key"))?;
    Ok(LessSafeKey::new(key))
}
fn nonce(bytes: &[u8]) -> io::Result<Nonce> {
    Nonce::try_assume_unique_for_key(bytes).map_err(|_| crate::invalid("invalid AEAD nonce"))
}
pub fn instruction_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut input = Vec::with_capacity(52);
    input.extend_from_slice(uuid);
    input.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    compute_md5(&input)
}
pub struct AuthIdCipher {
    pub instruction_key: [u8; 16],
    aes: Aes128,
}
impl AuthIdCipher {
    pub fn new(instruction_key: [u8; 16]) -> Self {
        let key = sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        Self {
            instruction_key,
            aes: Aes128::new_from_slice(&key[..16]).expect("AES128 key length"),
        }
    }
    pub fn validate(&self, auth: &[u8; 16], now: u64) -> bool {
        let mut clear = *auth;
        self.aes.decrypt_block((&mut clear).into());
        crc32::crc32c(&clear[..12])
            == u32::from_be_bytes(clear[12..].try_into().expect("fixed size"))
            && now.abs_diff(u64::from_be_bytes(
                clear[..8].try_into().expect("fixed size"),
            )) <= 120
    }
}
pub fn open_header_length(
    key: &[u8; 16],
    auth: &[u8; 16],
    unique: &[u8; 8],
    data: &mut [u8; 18],
) -> io::Result<usize> {
    let secret = sha2::kdf(key, &[b"VMess Header AEAD Key_Length", auth, unique]);
    let iv = sha2::kdf(key, &[b"VMess Header AEAD Nonce_Length", auth, unique]);
    let clear = aead(Security::Aes128Gcm, &secret[..16])?
        .open_in_place(nonce(&iv[..12])?, Aad::from(auth), data)
        .map_err(|_| crate::invalid("VMess header length authentication failed"))?;
    Ok(u16::from_be_bytes(
        clear
            .try_into()
            .map_err(|_| crate::invalid("invalid VMess header length"))?,
    ) as usize)
}
pub fn open_header(
    key: &[u8; 16],
    auth: &[u8; 16],
    unique: &[u8; 8],
    data: &mut [u8],
) -> io::Result<()> {
    let secret = sha2::kdf(key, &[b"VMess Header AEAD Key", auth, unique]);
    let iv = sha2::kdf(key, &[b"VMess Header AEAD Nonce", auth, unique]);
    aead(Security::Aes128Gcm, &secret[..16])?
        .open_in_place(nonce(&iv[..12])?, Aad::from(auth), data)
        .map_err(|_| crate::invalid("VMess header authentication failed"))?;
    Ok(())
}
pub struct Header {
    pub iv: [u8; 16],
    pub key: [u8; 16],
    pub response: u8,
    pub options: u8,
    pub security: Security,
    pub command: u8,
    pub target: Option<Destination>,
}
impl Header {
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 42 || bytes[0] != 1 {
            return Err(crate::invalid("invalid VMess header version or length"));
        }
        let checked = bytes.len() - 4;
        let mut fnv = Fnv1aHasher::new();
        fnv.write(&bytes[..checked]);
        if fnv.finish() != u32::from_be_bytes(bytes[checked..].try_into().expect("checksum size")) {
            return Err(crate::invalid("VMess header checksum mismatch"));
        }
        let options = bytes[34];
        if options & !0x1d != 0 || (options & 8 != 0 && options & 4 == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VMess stream options {options:#x}"),
            ));
        }
        if bytes[36] != 0 {
            return Err(crate::invalid("VMess reserved field is not zero"));
        }
        let security = match bytes[35] & 15 {
            3 => Security::Aes128Gcm,
            4 => Security::ChaCha20Poly1305,
            5 => Security::None,
            _ => return Err(crate::invalid("unsupported VMess cipher")),
        };
        if options & 1 == 0 && !(options == 0 && security == Security::None && bytes[37] != 2) {
            return Err(crate::invalid("VMess raw stream requires none/TCP or MUX"));
        }
        if options & 0x10 != 0 && security == Security::None {
            return Err(crate::invalid("authenticated length requires AEAD"));
        }
        let mut pos = 38;
        let mut take = |n: usize| -> io::Result<&[u8]> {
            if pos + n > checked {
                return Err(crate::invalid("truncated VMess destination"));
            }
            let s = &bytes[pos..pos + n];
            pos += n;
            Ok(s)
        };
        let command = bytes[37];
        let target = if command == 3 {
            None
        } else {
            if !matches!(command, 1 | 2) {
                return Err(crate::invalid("unsupported VMess command"));
            }
            let port = u16::from_be_bytes(take(2)?.try_into().expect("port size"));
            let host = match take(1)?[0] {
                1 => Ipv4Addr::from(<[u8; 4]>::try_from(take(4)?).expect("IPv4 size")).to_string(),
                3 => {
                    Ipv6Addr::from(<[u8; 16]>::try_from(take(16)?).expect("IPv6 size")).to_string()
                }
                2 => {
                    let n = take(1)?[0] as usize;
                    String::from_utf8(take(n)?.to_vec())
                        .map_err(|_| crate::invalid("VMess domain is not UTF-8"))?
                }
                _ => return Err(crate::invalid("invalid VMess address type")),
            };
            Some(Destination::new(host, port)?)
        };
        if pos + (bytes[35] >> 4) as usize != checked {
            return Err(crate::invalid("invalid VMess header padding length"));
        }
        Ok(Self {
            iv: bytes[1..17].try_into().expect("IV size"),
            key: bytes[17..33].try_into().expect("key size"),
            response: bytes[33],
            options,
            security,
            command,
            target,
        })
    }
}
pub fn response_header(response: u8, key: &[u8; 16], iv: &[u8; 16]) -> io::Result<Vec<u8>> {
    let length_key = sha2::kdf(key, &[b"AEAD Resp Header Len Key"]);
    let length_iv = sha2::kdf(iv, &[b"AEAD Resp Header Len IV"]);
    let body_key = sha2::kdf(key, &[b"AEAD Resp Header Key"]);
    let body_iv = sha2::kdf(iv, &[b"AEAD Resp Header IV"]);
    let mut prefix = vec![0, 4];
    aead(Security::Aes128Gcm, &length_key[..16])?
        .seal_in_place_append_tag(nonce(&length_iv[..12])?, Aad::empty(), &mut prefix)
        .map_err(|_| crate::invalid("response length sealing failed"))?;
    let mut body = vec![response, 0, 0, 0];
    aead(Security::Aes128Gcm, &body_key[..16])?
        .seal_in_place_append_tag(nonce(&body_iv[..12])?, Aad::empty(), &mut body)
        .map_err(|_| crate::invalid("response sealing failed"))?;
    prefix.extend_from_slice(&body);
    Ok(prefix)
}
pub struct BodyCodec {
    key: Option<LessSafeKey>,
    length_key: Option<LessSafeKey>,
    iv: [u8; 16],
    length_iv: [u8; 16],
    count: u32,
    length_count: u32,
    mask: Option<super::typed::VmessReader>,
    padding: bool,
    raw: bool,
    max: usize,
}
impl BodyCodec {
    pub fn new(
        security: Security,
        key: [u8; 16],
        iv: [u8; 16],
        length_key: [u8; 16],
        length_iv: [u8; 16],
        options: u8,
        max: usize,
    ) -> io::Result<Self> {
        let body_key = if security == Security::None {
            None
        } else {
            Some(aead(security, &key)?)
        };
        let length_key = if options & 0x10 == 0 {
            None
        } else {
            Some(aead(
                security,
                &sha2::kdf(&length_key, &[b"auth_len"])[..16],
            )?)
        };
        let mask = if options & 4 != 0 {
            let mut shake = Shake128::default();
            shake.update(&iv);
            Some(shake.finalize_xof())
        } else {
            None
        };
        Ok(Self {
            key: body_key,
            length_key,
            iv,
            length_iv,
            count: 0,
            length_count: 0,
            mask,
            padding: options & 8 != 0,
            raw: options & 1 == 0,
            max,
        })
    }
    fn nonce(iv: &[u8; 16], count: &mut u32) -> io::Result<Nonce> {
        // Fail closed before the 16-bit protocol counter would reuse an AEAD nonce.
        if *count > u16::MAX as u32 {
            return Err(crate::invalid("VMess AEAD nonce counter exhausted"));
        }
        let mut bytes: [u8; 12] = iv[..12].try_into().expect("nonce size");
        bytes[..2].copy_from_slice(&(*count as u16).to_be_bytes());
        *count += 1;
        nonce(&bytes)
    }
    fn next_mask(&mut self) -> u16 {
        let mut b = [0; 2];
        if let Some(r) = &mut self.mask {
            r.read(&mut b);
        }
        u16::from_be_bytes(b)
    }
    fn padding(&mut self) -> usize {
        if self.padding {
            (self.next_mask() % 64) as usize
        } else {
            0
        }
    }
    pub async fn read<R: AsyncRead + Unpin + Send>(
        &mut self,
        r: &mut R,
    ) -> io::Result<Option<Bytes>> {
        if self.raw {
            let mut bytes = vec![0; self.max.min(8192)];
            let len = r.read(&mut bytes).await?;
            bytes.truncate(len);
            return Ok(if len == 0 {
                None
            } else {
                Some(Bytes::from(bytes))
            });
        }
        let length_size = if self.length_key.is_some() { 18 } else { 2 };
        let mut length = vec![0; length_size];
        let first = r.read(&mut length[..1]).await?;
        if first == 0 {
            return Ok(None);
        }
        r.read_exact(&mut length[1..]).await?;
        let padding = self.padding();
        let len = if let Some(key) = &self.length_key {
            let clear = key
                .open_in_place(
                    Self::nonce(&self.length_iv, &mut self.length_count)?,
                    Aad::empty(),
                    &mut length,
                )
                .map_err(|_| crate::invalid("VMess length authentication failed"))?;
            (u16::from_be_bytes(
                clear
                    .try_into()
                    .map_err(|_| crate::invalid("bad authenticated length"))?,
            ) as usize)
                .checked_add(16)
                .ok_or_else(|| crate::invalid("length overflow"))?
        } else {
            (u16::from_be_bytes(length[..2].try_into().expect("length size")) ^ self.next_mask())
                as usize
        };
        let tag = if self.key.is_some() { 16 } else { 0 };
        if len > self.max || len < padding + tag {
            return Err(crate::invalid("invalid VMess frame length or padding"));
        }
        let mut frame = vec![0; len];
        r.read_exact(&mut frame).await?;
        let payload_len = if let Some(key) = &self.key {
            key.open_in_place(
                Self::nonce(&self.iv, &mut self.count)?,
                Aad::empty(),
                &mut frame[..len - padding],
            )
            .map_err(|_| crate::invalid("VMess body authentication failed"))?
            .len()
        } else {
            len - padding
        };
        if payload_len == 0 {
            return Ok(None);
        }
        frame.truncate(payload_len);
        Ok(Some(Bytes::from(frame)))
    }
    pub async fn write<W: AsyncWrite + Unpin + Send>(
        &mut self,
        w: &mut W,
        payload: &[u8],
    ) -> io::Result<()> {
        if self.raw {
            return w.write_all(payload).await;
        }
        let padding = self.padding();
        let tag = if self.key.is_some() { 16 } else { 0 };
        let size = payload
            .len()
            .checked_add(padding + tag)
            .ok_or_else(|| crate::invalid("frame size overflow"))?;
        if size > self.max {
            return Err(crate::invalid("VMess datagram exceeds frame limit"));
        }
        let mut encoded_len = if self.length_key.is_some() {
            ((size - 16) as u16).to_be_bytes().to_vec()
        } else {
            ((size as u16) ^ self.next_mask()).to_be_bytes().to_vec()
        };
        if let Some(key) = &self.length_key {
            key.seal_in_place_append_tag(
                Self::nonce(&self.length_iv, &mut self.length_count)?,
                Aad::empty(),
                &mut encoded_len,
            )
            .map_err(|_| crate::invalid("VMess length sealing failed"))?;
        }
        let mut frame = payload.to_vec();
        if let Some(key) = &self.key {
            key.seal_in_place_append_tag(
                Self::nonce(&self.iv, &mut self.count)?,
                Aad::empty(),
                &mut frame,
            )
            .map_err(|_| crate::invalid("VMess body sealing failed"))?;
        }
        let prior = frame.len();
        frame.resize(size, 0);
        if padding != 0 {
            rand::rng().fill_bytes(&mut frame[prior..]);
        }
        w.write_all(&encoded_len).await?;
        w.write_all(&frame).await
    }
}
pub struct Reader<R> {
    inner: R,
    codec: BodyCodec,
}
impl<R> Reader<R> {
    pub fn new(inner: R, codec: BodyCodec) -> Self {
        Self { inner, codec }
    }
}
#[async_trait]
impl<R: AsyncRead + Unpin + Send> PacketReader for Reader<R> {
    async fn read_packet(&mut self) -> io::Result<Option<Bytes>> {
        self.codec.read(&mut self.inner).await
    }
}
pub struct Writer<W> {
    inner: W,
    codec: BodyCodec,
    prefix: Vec<u8>,
}
impl<W> Writer<W> {
    pub fn new(inner: W, codec: BodyCodec, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            codec,
            prefix,
        }
    }
}
#[async_trait]
impl<W: AsyncWrite + Unpin + Send> PacketWriter for Writer<W> {
    async fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        if !self.prefix.is_empty() {
            self.inner.write_all(&self.prefix).await?;
            self.prefix.clear();
        }
        self.codec.write(&mut self.inner, payload).await
    }
    async fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }
    async fn finish(&mut self) -> io::Result<()> {
        self.write_packet(&[]).await?;
        self.inner.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn malformed_padding_and_corrupt_eof_tag_fail_closed() {
        let (mut input, mut output) = tokio::io::duplex(1024);
        let mut reader = BodyCodec::new(
            Security::Aes128Gcm,
            [4; 16],
            [7; 16],
            [4; 16],
            [7; 16],
            1,
            65535,
        )
        .unwrap();
        input.write_all(&[0, 1, 0]).await.unwrap();
        assert!(reader.read(&mut output).await.is_err());
        let mut encrypted = Vec::new();
        // Independently seal an EOF packet and corrupt its tag: zero payload is not an authentication bypass.
        let key = aead(Security::Aes128Gcm, &[4; 16]).unwrap();
        let mut iv: [u8; 12] = [7; 12];
        iv[..2].fill(0);
        key.seal_in_place_append_tag(nonce(&iv).unwrap(), Aad::empty(), &mut encrypted)
            .unwrap();
        encrypted[15] ^= 1;
        let (mut input, mut output) = tokio::io::duplex(1024);
        input.write_u16(16).await.unwrap();
        input.write_all(&encrypted).await.unwrap();
        let mut reader = BodyCodec::new(
            Security::Aes128Gcm,
            [4; 16],
            [7; 16],
            [4; 16],
            [7; 16],
            1,
            65535,
        )
        .unwrap();
        assert!(reader.read(&mut output).await.is_err());
        let mut underflow = BodyCodec::new(
            Security::Aes128Gcm,
            [4; 16],
            [7; 16],
            [4; 16],
            [7; 16],
            13,
            65535,
        )
        .unwrap();
        let padding = underflow.padding();
        let mask = underflow.next_mask();
        let (mut input, mut output) = tokio::io::duplex(1024);
        input
            .write_u16(mask ^ padding.saturating_sub(1) as u16)
            .await
            .unwrap();
        let mut reader = BodyCodec::new(
            Security::Aes128Gcm,
            [4; 16],
            [7; 16],
            [4; 16],
            [7; 16],
            13,
            65535,
        )
        .unwrap();
        assert!(reader.read(&mut output).await.is_err());
    }
    #[test]
    fn aead_nonce_reuse_is_refused_at_counter_wrap() {
        let mut codec = BodyCodec::new(
            Security::Aes128Gcm,
            [4; 16],
            [7; 16],
            [4; 16],
            [7; 16],
            1,
            65535,
        )
        .unwrap();
        codec.count = 65535;
        assert!(BodyCodec::nonce(&codec.iv, &mut codec.count).is_ok());
        assert!(BodyCodec::nonce(&codec.iv, &mut codec.count).is_err());
    }
}
