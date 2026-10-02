use std::io::{Error, ErrorKind, Result};
pub struct ParsedServerHello {
    pub cipher_suite: u16,
    pub is_tls13: bool,
}
fn invalid() -> Error {
    ErrorKind::InvalidData.into()
}
pub fn parse_server_hello(record: &[u8]) -> Result<ParsedServerHello> {
    if record.len() < 47 || record[..3] != [22, 3, 3] || record[5] != 2 {
        return Err(invalid());
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let message_len =
        usize::from(record[6]) * 65536 + usize::from(record[7]) * 256 + usize::from(record[8]);
    if record_len + 5 != record.len() || message_len + 9 != record.len() || record[9..11] != [3, 3]
    {
        return Err(invalid());
    }
    // RFC 8446 HelloRetryRequest must not enable direct mode.
    if is_hello_retry_request(record) {
        return Err(invalid());
    }
    let sid = record[43] as usize;
    let mut pos = 44 + sid;
    if sid > 32 || pos + 3 > record.len() {
        return Err(invalid());
    }
    let cipher_suite = u16::from_be_bytes([record[pos], record[pos + 1]]);
    if record[pos + 2] != 0 {
        return Err(invalid());
    }
    pos += 3;
    let mut is_tls13 = false;
    if pos < record.len() {
        if pos + 2 > record.len() {
            return Err(invalid());
        }
        let n = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
        pos += 2;
        if pos + n != record.len() {
            return Err(invalid());
        }
        while pos < record.len() {
            if pos + 4 > record.len() {
                return Err(invalid());
            }
            let kind = u16::from_be_bytes([record[pos], record[pos + 1]]);
            let n = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
            pos += 4;
            if pos + n > record.len() {
                return Err(invalid());
            }
            if kind == 43 {
                if n != 2 {
                    return Err(invalid());
                }
                is_tls13 = record[pos..pos + 2] == [3, 4];
            }
            pos += n;
        }
    }
    Ok(ParsedServerHello {
        cipher_suite,
        is_tls13,
    })
}

const HRR: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub fn is_hello_retry_request(record: &[u8]) -> bool {
    record.len() >= 43 && record[5] == 2 && record[11..43] == HRR
}
