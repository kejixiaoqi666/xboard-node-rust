//! In-task, bounded mirror exchange. The caller supplies its handshake deadline.
use super::{
    RealityServerConnection,
    hello::{MirrorHello, classify_server_hello},
};
use bytes::Bytes;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CCS: &[u8] = &[20, 3, 3, 0, 1, 1];
const MAX_BYTES: usize = 65_536;
const MAX_RECORDS: usize = 16;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid REALITY mirror flight")
}

async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Bytes> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).await?;
    let n = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[1] != 3 || !(1..=3).contains(&header[2]) || n == 0 || n > 16_640 {
        return Err(invalid());
    }
    let mut out = vec![0; 5 + n];
    out[..5].copy_from_slice(&header);
    stream.read_exact(&mut out[5..]).await?;
    Ok(out.into())
}

pub enum MirrorFlight {
    /// Template records after the validated ServerHello, including optional CCS.
    Ready(Vec<Bytes>),
    /// Untouched records to replay before forwarding the fixed mirror.
    Forward(Vec<Bytes>),
}

/// Called after authenticating ClientHello1 and forwarding it to the fixed mirror.
/// One HRR is supported, for X25519, X25519MLKEM768, or P-256. Incompatible first
/// mirror hellos are returned intact for fallback. Invalid authenticated retries
/// fail closed. There is no spawned task or detached forwarding here.
pub async fn mirror_handshake<C, M>(
    session: &mut RealityServerConnection,
    client: &mut C,
    mirror: &mut M,
) -> io::Result<MirrorFlight>
where
    C: AsyncRead + AsyncWrite + Unpin,
    M: AsyncRead + AsyncWrite + Unpin,
{
    let first = read_record(mirror).await?;
    let mut total = first.len();
    let mut records = vec![first];
    let kind = match classify_server_hello(&records[0]) {
        Ok(kind) => kind,
        Err(_) => return Ok(MirrorFlight::Forward(records)),
    };
    if kind == MirrorHello::Retry {
        if session.observe_hello_retry_request(&records[0]).is_err() {
            return Ok(MirrorFlight::Forward(records));
        }
        client.write_all(&records[0]).await?;
        client.flush().await?;
        let mut wire = Vec::new();
        let mut handshake = Vec::new();
        let mut first_client = read_record(client).await?;
        if first_client.as_ref() == CCS {
            mirror.write_all(&first_client).await?;
            first_client = read_record(client).await?;
        }
        wire.push(first_client);
        for _ in 0..MAX_RECORDS {
            let current = wire.last().ok_or_else(invalid)?;
            if current[0] != 22 || handshake.len() + current.len() - 5 > 16_384 {
                return Err(invalid());
            }
            total += current.len();
            if total > MAX_BYTES {
                return Err(invalid());
            }
            handshake.extend_from_slice(&current[5..]);
            if handshake[0] != 1 {
                return Err(invalid());
            }
            if handshake.len() >= 4 {
                let n = 4
                    + ((handshake[1] as usize) << 16
                        | (handshake[2] as usize) << 8
                        | handshake[3] as usize);
                if n > 16_384 || handshake.len() > n {
                    return Err(invalid());
                }
                if handshake.len() == n {
                    break;
                }
            }
            if wire.len() == MAX_RECORDS {
                return Err(invalid());
            }
            wire.push(read_record(client).await?);
        }
        let mut canonical = vec![22, 3, 3];
        canonical.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        canonical.extend_from_slice(&handshake);
        session.validate_retry_client_hello(&canonical)?;
        for record in wire {
            mirror.write_all(&record).await?;
        }
        mirror.flush().await?;
        let mut next = read_record(mirror).await?;
        if next.as_ref() == CCS {
            client.write_all(&next).await?;
            client.flush().await?;
            next = read_record(mirror).await?;
        }
        total += next.len();
        if classify_server_hello(&next)? != MirrorHello::Server {
            return Err(invalid());
        }
        records = vec![next];
    }
    let mut encrypted = 0;
    for _ in 1..MAX_RECORDS {
        let current = read_record(mirror).await?;
        total += current.len();
        if total > MAX_BYTES {
            return Err(invalid());
        }
        if current.as_ref() == CCS && records.len() == 1 {
            records.push(current);
            continue;
        }
        if current[0] != 23 || current[1..3] != [3, 3] || current.len() < 22 {
            return Err(invalid());
        }
        encrypted += 1;
        let combined = encrypted == 1 && current.len() > 512;
        records.push(current);
        if combined || encrypted == 4 {
            return Ok(MirrorFlight::Ready(records));
        }
    }
    Err(invalid())
}
