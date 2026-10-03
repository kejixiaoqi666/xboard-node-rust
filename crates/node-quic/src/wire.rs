//! Hysteria 2 and TUIC v5 framing. Only decoded payload crosses node-session.
use bytes::{Buf, BufMut, Bytes, BytesMut};
use node_session::Destination;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const MAX_PAYLOAD: usize = 65_507;
pub(crate) const MAX_ADDRESS: usize = 2048;
pub(crate) const MAX_PADDING: usize = 4096;

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) async fn varint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let width = 1usize << (first >> 6);
    let mut value = (first & 63) as u64;
    for _ in 1..width {
        value = (value << 8) | r.read_u8().await? as u64;
    }
    Ok(value)
}

pub(crate) fn put_varint(out: &mut BytesMut, v: u64) {
    if v < 64 {
        out.put_u8(v as u8);
    } else if v < 16384 {
        out.put_u16(v as u16 | 0x4000);
    } else if v < (1 << 30) {
        out.put_u32(v as u32 | 0x8000_0000);
    } else {
        out.put_u64(v | 0xc000_0000_0000_0000);
    }
}

fn take_varint(b: &mut Bytes) -> io::Result<u64> {
    if b.is_empty() {
        return Err(invalid("missing varint"));
    }
    let first = b.get_u8();
    let width = 1usize << (first >> 6);
    if b.len() < width - 1 {
        return Err(invalid("truncated varint"));
    }
    let mut value = (first & 63) as u64;
    for _ in 1..width {
        value = (value << 8) | b.get_u8() as u64;
    }
    Ok(value)
}

pub(crate) fn destination(s: &str) -> io::Result<Destination> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| invalid("address requires port"))?;
    let host = if host.starts_with('[') {
        host.strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| invalid("invalid IPv6 address"))?
    } else {
        host
    };
    Destination::new(host, port.parse().map_err(|_| invalid("invalid port"))?)
        .map_err(|_| invalid("invalid destination"))
}

pub(crate) fn address_string(d: &Destination) -> String {
    if d.host.contains(':') {
        format!("[{}]:{}", d.host, d.port)
    } else {
        format!("{}:{}", d.host, d.port)
    }
}

pub(crate) async fn hysteria_tcp<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Destination> {
    if varint(r).await? != 0x401 {
        return Err(invalid("unknown Hysteria stream"));
    }
    let len = varint(r).await? as usize;
    if len == 0 || len > MAX_ADDRESS {
        return Err(invalid("invalid address length"));
    }
    let mut address = vec![0; len];
    r.read_exact(&mut address).await?;
    let target = destination(
        std::str::from_utf8(&address).map_err(|_| invalid("invalid address encoding"))?,
    )?;
    let padding = varint(r).await? as usize;
    if padding > MAX_PADDING {
        return Err(invalid("excessive padding"));
    }
    let mut scratch = [0u8; 256];
    let mut left = padding;
    while left > 0 {
        let n = left.min(scratch.len());
        r.read_exact(&mut scratch[..n]).await?;
        left -= n;
    }
    Ok(target)
}

pub(crate) async fn tuic_address<R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<Option<Destination>> {
    let host = match r.read_u8().await? {
        0xff => return Ok(None),
        0 => {
            let n = r.read_u8().await? as usize;
            if n == 0 || n > 253 {
                return Err(invalid("invalid domain length"));
            }
            let mut b = vec![0; n];
            r.read_exact(&mut b).await?;
            String::from_utf8(b).map_err(|_| invalid("invalid domain encoding"))?
        }
        1 => {
            let mut b = [0; 4];
            r.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        2 => {
            let mut b = [0; 16];
            r.read_exact(&mut b).await?;
            Ipv6Addr::from(b).to_string()
        }
        _ => return Err(invalid("invalid TUIC address type")),
    };
    Destination::new(host, r.read_u16().await?)
        .map(Some)
        .map_err(|_| invalid("invalid destination"))
}

fn take_address(b: &mut Bytes) -> io::Result<Option<Destination>> {
    if b.is_empty() {
        return Err(invalid("missing address"));
    }
    let host = match b.get_u8() {
        0xff => return Ok(None),
        0 => {
            if b.is_empty() {
                return Err(invalid("missing domain length"));
            }
            let n = b.get_u8() as usize;
            if n == 0 || n > 253 || b.len() < n + 2 {
                return Err(invalid("invalid domain"));
            }
            String::from_utf8(b.split_to(n).to_vec())
                .map_err(|_| invalid("invalid domain encoding"))?
        }
        1 => {
            if b.len() < 6 {
                return Err(invalid("truncated IPv4 address"));
            }
            let mut ip = [0; 4];
            b.copy_to_slice(&mut ip);
            Ipv4Addr::from(ip).to_string()
        }
        2 => {
            if b.len() < 18 {
                return Err(invalid("truncated IPv6 address"));
            }
            let mut ip = [0; 16];
            b.copy_to_slice(&mut ip);
            Ipv6Addr::from(ip).to_string()
        }
        _ => return Err(invalid("invalid TUIC address type")),
    };
    if b.len() < 2 {
        return Err(invalid("missing port"));
    }
    Destination::new(host, b.get_u16())
        .map(Some)
        .map_err(|_| invalid("invalid destination"))
}

fn put_address(b: &mut BytesMut, target: Option<&Destination>) {
    let Some(target) = target else {
        b.put_u8(0xff);
        return;
    };
    match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            b.put_u8(1);
            b.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            b.put_u8(2);
            b.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            b.put_u8(0);
            b.put_u8(target.host.len() as u8);
            b.extend_from_slice(target.host.as_bytes());
        }
    }
    b.put_u16(target.port);
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Mode {
    Hysteria,
    TuicNative,
    TuicStream,
}

pub(crate) struct Packet {
    pub assoc: u32,
    pub id: u16,
    pub total: u8,
    pub index: u8,
    pub target: Option<Destination>,
    pub payload: Bytes,
    pub mode: Mode,
}

impl Packet {
    pub fn validate(&self) -> io::Result<()> {
        if self.total == 0 || self.index >= self.total || self.payload.len() > MAX_PAYLOAD {
            return Err(invalid("invalid UDP fragment"));
        }
        if self.index == 0 && self.target.is_none() {
            return Err(invalid("first fragment requires address"));
        }
        Ok(())
    }
}

pub(crate) fn hysteria_packet(mut b: Bytes) -> io::Result<Packet> {
    if b.len() < 9 {
        return Err(invalid("short Hysteria datagram"));
    }
    let assoc = b.get_u32();
    let id = b.get_u16();
    let mut index = b.get_u8();
    let total = b.get_u8();
    if total == 1 {
        index = 0;
    } // The specification makes this field irrelevant for single packets.
    let len = take_varint(&mut b)? as usize;
    if len == 0 || len > MAX_ADDRESS || b.len() < len {
        return Err(invalid("invalid UDP address length"));
    }
    let address = b.split_to(len);
    let target = destination(
        std::str::from_utf8(&address).map_err(|_| invalid("invalid address encoding"))?,
    )?;
    let p = Packet {
        assoc,
        id,
        total,
        index,
        target: Some(target),
        payload: b,
        mode: Mode::Hysteria,
    };
    p.validate()?;
    Ok(p)
}

pub(crate) fn tuic_packet(mut b: Bytes, mode: Mode) -> io::Result<Packet> {
    if b.len() < 11 || b[0] != 5 || b[1] != 2 {
        return Err(invalid("invalid TUIC packet"));
    }
    b.advance(2);
    let assoc = b.get_u16() as u32;
    let id = b.get_u16();
    let total = b.get_u8();
    let index = b.get_u8();
    let len = b.get_u16() as usize;
    let target = take_address(&mut b)?;
    if len != b.len() {
        return Err(invalid("TUIC payload length mismatch"));
    }
    let p = Packet {
        assoc,
        id,
        total,
        index,
        target,
        payload: b,
        mode,
    };
    p.validate()?;
    Ok(p)
}

pub(crate) async fn tuic_stream_packet<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Packet> {
    let assoc = r.read_u16().await? as u32;
    let id = r.read_u16().await?;
    let total = r.read_u8().await?;
    let index = r.read_u8().await?;
    let len = r.read_u16().await? as usize;
    if len > MAX_PAYLOAD {
        return Err(invalid("excessive UDP size"));
    }
    let target = tuic_address(r).await?;
    let mut payload = vec![0; len];
    r.read_exact(&mut payload).await?;
    let p = Packet {
        assoc,
        id,
        total,
        index,
        target,
        payload: payload.into(),
        mode: Mode::TuicStream,
    };
    p.validate()?;
    Ok(p)
}

pub(crate) fn encode_packet(p: &Packet) -> Bytes {
    let mut b = BytesMut::new();
    match p.mode {
        Mode::Hysteria => {
            b.put_u32(p.assoc);
            b.put_u16(p.id);
            b.put_u8(p.index);
            b.put_u8(p.total);
            if let Some(target) = &p.target {
                let address = address_string(target);
                put_varint(&mut b, address.len() as u64);
                b.extend_from_slice(address.as_bytes());
            } else {
                put_varint(&mut b, 0);
            }
        }
        Mode::TuicNative | Mode::TuicStream => {
            b.extend_from_slice(&[5, 2]);
            b.put_u16(p.assoc as u16);
            b.put_u16(p.id);
            b.put_u8(p.total);
            b.put_u8(p.index);
            b.put_u16(p.payload.len() as u16);
            put_address(&mut b, p.target.as_ref());
        }
    }
    b.extend_from_slice(&p.payload);
    b.freeze()
}

pub(crate) fn split_packet(
    assoc: u32,
    id: u16,
    target: Destination,
    payload: Bytes,
    mode: Mode,
    mtu: usize,
) -> io::Result<Vec<Bytes>> {
    let first = encode_packet(&Packet {
        assoc,
        id,
        total: 1,
        index: 0,
        target: Some(target.clone()),
        payload: Bytes::new(),
        mode,
    });
    let later = encode_packet(&Packet {
        assoc,
        id,
        total: 1,
        index: 1,
        target: if mode == Mode::Hysteria {
            Some(target.clone())
        } else {
            None
        },
        payload: Bytes::new(),
        mode,
    });
    let first_cap = mtu
        .checked_sub(first.len())
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid("MTU cannot fit address"))?;
    let later_cap = mtu
        .checked_sub(later.len())
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid("MTU cannot fit packet"))?;
    let total = 1 + payload.len().saturating_sub(first_cap).div_ceil(later_cap);
    if total > 255 || payload.len() > MAX_PAYLOAD {
        return Err(invalid("too many UDP fragments"));
    }
    let mut result = Vec::with_capacity(total);
    let mut offset = 0;
    for index in 0..total {
        let len = (if index == 0 { first_cap } else { later_cap }).min(payload.len() - offset);
        result.push(encode_packet(&Packet {
            assoc,
            id,
            total: total as u8,
            index: index as u8,
            target: if index == 0 || mode == Mode::Hysteria {
                Some(target.clone())
            } else {
                None
            },
            payload: payload.slice(offset..offset + len),
            mode,
        }));
        offset += len;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addresses_and_fragment_headers() {
        for host in ["example.test", "127.0.0.1", "::1"] {
            let d = Destination::new(host, 53).unwrap();
            assert_eq!(destination(&address_string(&d)).unwrap(), d);
            for mode in [Mode::Hysteria, Mode::TuicNative] {
                let parts =
                    split_packet(9, 7, d.clone(), Bytes::from(vec![1; 5000]), mode, 1200).unwrap();
                assert!(parts.len() > 1);
                for (i, b) in parts.iter().enumerate() {
                    assert!(b.len() <= 1200);
                    let p = if mode == Mode::Hysteria {
                        hysteria_packet(b.clone())
                    } else {
                        tuic_packet(b.clone(), mode)
                    }
                    .unwrap();
                    assert_eq!(p.index as usize, i);
                    assert_eq!(p.total as usize, parts.len());
                }
            }
        }
    }
    #[test]
    fn malformed_datagrams_are_bounded() {
        for len in 0..80 {
            let b = Bytes::from(vec![255; len]);
            assert!(hysteria_packet(b.clone()).is_err());
            assert!(tuic_packet(b, Mode::TuicNative).is_err());
        }
    }
}
