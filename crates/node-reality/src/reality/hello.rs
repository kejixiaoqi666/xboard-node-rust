//! Bounded, exact TLS 1.3 hello parsing for the REALITY outer handshake.
//! X25519, final FIPS-203 X25519MLKEM768 (4588), and P-256 are accepted.
use std::{collections::BTreeMap, io};

pub const X25519: u16 = 29;
pub const SECP256R1: u16 = 23;
pub const X25519_MLKEM768: u16 = 4588;
pub const MLKEM_PUBLIC_LEN: usize = 1184;
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;
pub const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unsupported TLS 1.3 hello",
    )
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let (v, rest) = self.0.split_at_checked(n).ok_or_else(invalid)?;
        self.0 = rest;
        Ok(v)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> io::Result<u16> {
        let v = self.take(2)?;
        Ok(u16::from_be_bytes([v[0], v[1]]))
    }
    fn vector(&mut self) -> io::Result<&'a [u8]> {
        let n = self.word()? as usize;
        self.take(n)
    }
    fn short_vector(&mut self) -> io::Result<&'a [u8]> {
        let n = self.byte()? as usize;
        self.take(n)
    }
}

fn handshake(record: &[u8], kind: u8) -> io::Result<&[u8]> {
    if record.len() < 9
        || record.len() > 16_389
        || record[0] != 22
        || record[1] != 3
        || !(1..=3).contains(&record[2])
        || record[5] != kind
        || u16::from_be_bytes([record[3], record[4]]) as usize != record.len() - 5
        || ((record[6] as usize) << 16 | (record[7] as usize) << 8 | record[8] as usize)
            != record.len() - 9
    {
        return Err(invalid());
    }
    Ok(&record[5..])
}

fn extensions<'a>(c: &mut Cursor<'a>) -> io::Result<BTreeMap<u16, &'a [u8]>> {
    let mut rest = Cursor(c.vector()?);
    if !c.0.is_empty() {
        return Err(invalid());
    }
    let mut out = BTreeMap::new();
    while !rest.0.is_empty() {
        let id = rest.word()?;
        if out.insert(id, rest.vector()?).is_some() {
            return Err(invalid());
        }
    }
    Ok(out)
}

#[derive(Clone)]
pub(crate) struct ClientHello<'a> {
    pub handshake: &'a [u8],
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub suites: Vec<u16>,
    pub groups: Vec<u16>,
    pub shares: BTreeMap<u16, &'a [u8]>,
    pub extensions: BTreeMap<u16, &'a [u8]>,
}

fn words(data: &[u8]) -> io::Result<Vec<u16>> {
    if data.is_empty() || !data.len().is_multiple_of(2) {
        return Err(invalid());
    }
    Ok(data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .collect())
}

pub(crate) fn parse_client(record: &[u8]) -> io::Result<ClientHello<'_>> {
    let handshake = handshake(record, 1)?;
    let mut c = Cursor(&handshake[4..]);
    if c.word()? != 0x0303 {
        return Err(invalid());
    }
    let random = c.take(32)?;
    let session_id = c.short_vector()?;
    if session_id.len() != 32 {
        return Err(invalid());
    }
    let suites = words(c.vector()?)?;
    if c.short_vector()? != [0] {
        return Err(invalid());
    }
    let extensions = extensions(&mut c)?;
    let mut versions = Cursor(extensions.get(&43).ok_or_else(invalid)?);
    if !words(versions.short_vector()?)?.contains(&0x0304) || !versions.0.is_empty() {
        return Err(invalid());
    }
    let mut groups = Cursor(extensions.get(&10).ok_or_else(invalid)?);
    let groups_out = words(groups.vector()?)?;
    if !groups.0.is_empty() {
        return Err(invalid());
    }
    let mut shares = BTreeMap::new();
    let mut outer = Cursor(extensions.get(&51).ok_or_else(invalid)?);
    let mut values = Cursor(outer.vector()?);
    if !outer.0.is_empty() {
        return Err(invalid());
    }
    while !values.0.is_empty() {
        let group = values.word()?;
        let value = values.vector()?;
        if value.is_empty() || !groups_out.contains(&group) || shares.insert(group, value).is_some()
        {
            return Err(invalid());
        }
        if (group == X25519 && value.len() != 32)
            || (group == X25519_MLKEM768 && value.len() != MLKEM_PUBLIC_LEN + 32)
            || (group == SECP256R1 && (value.len() != 65 || value[0] != 4))
        {
            return Err(invalid());
        }
    }
    // The server does not implement PSK/resumption or 0-RTT; fail closed.
    if extensions.contains_key(&41) || extensions.contains_key(&42) {
        return Err(invalid());
    }
    Ok(ClientHello {
        handshake,
        random,
        session_id,
        suites,
        groups: groups_out,
        shares,
        extensions,
    })
}

impl ClientHello<'_> {
    /// REALITY auth prefers a separate X25519 key, exactly as pinned Xray.
    pub fn auth_public(&self) -> io::Result<[u8; 32]> {
        let data = self
            .shares
            .get(&X25519)
            .copied()
            .or_else(|| {
                self.shares
                    .get(&X25519_MLKEM768)
                    .map(|v| &v[MLKEM_PUBLIC_LEN..])
            })
            .ok_or_else(invalid)?;
        data.try_into().map_err(|_| invalid())
    }
}

pub(crate) struct ServerHello<'a> {
    pub handshake: &'a [u8],
    pub session_id: &'a [u8],
    pub suite: u16,
    pub group: u16,
    pub retry: bool,
    pub cookie: Option<&'a [u8]>,
}

pub(crate) fn parse_server(record: &[u8]) -> io::Result<ServerHello<'_>> {
    let handshake = handshake(record, 2)?;
    let mut c = Cursor(&handshake[4..]);
    if c.word()? != 0x0303 {
        return Err(invalid());
    }
    let retry = c.take(32)? == HRR_RANDOM;
    let session_id = c.short_vector()?;
    if session_id.len() != 32 {
        return Err(invalid());
    }
    let suite = c.word()?;
    if ![0x1301, 0x1302, 0x1303].contains(&suite) || c.byte()? != 0 {
        return Err(invalid());
    }
    let extensions = extensions(&mut c)?;
    if extensions.get(&43).copied() != Some([3, 4].as_slice())
        || extensions
            .keys()
            .any(|k| ![43, 51, 44].contains(k) || (!retry && *k == 44))
    {
        return Err(invalid());
    }
    let mut share = Cursor(extensions.get(&51).ok_or_else(invalid)?);
    let group = share.word()?;
    if ![X25519, X25519_MLKEM768, SECP256R1].contains(&group) {
        return Err(invalid());
    }
    if !retry {
        let key = share.vector()?;
        let expected = match group {
            X25519 => 32,
            SECP256R1 => 65,
            _ => MLKEM_CIPHERTEXT_LEN + 32,
        };
        if key.len() != expected || (group == SECP256R1 && key.first() != Some(&4)) {
            return Err(invalid());
        }
    }
    if !share.0.is_empty() {
        return Err(invalid());
    }
    let cookie = extensions.get(&44).copied();
    if let Some(cookie) = cookie {
        let mut v = Cursor(cookie);
        if v.vector()?.is_empty() || !v.0.is_empty() {
            return Err(invalid());
        }
    }
    Ok(ServerHello {
        handshake,
        session_id,
        suite,
        group,
        retry,
        cookie,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorHello {
    Server,
    Retry,
}

/// Reject malformed, duplicate-extension or unsupported-group mirror hellos.
pub fn classify_server_hello(record: &[u8]) -> io::Result<MirrorHello> {
    Ok(if parse_server(record)?.retry {
        MirrorHello::Retry
    } else {
        MirrorHello::Server
    })
}
