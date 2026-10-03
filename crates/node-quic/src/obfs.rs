//! Salamander packet obfuscation from the public Hysteria 2 wire specification.
//! It is not an authentication layer; QUIC still authenticates every packet.
use blake2::{Blake2b, Digest, digest::consts::U32};
use quinn::{
    AsyncUdpSocket, Runtime, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use rand::{RngCore, rngs::OsRng};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[derive(Clone)]
pub struct SalamanderConfig {
    pub password: Arc<str>,
}

struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Arc<str>,
}

impl fmt::Debug for SalamanderSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderSocket").finish_non_exhaustive()
    }
}

fn key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hash = Blake2b::<U32>::new();
    hash.update(password.as_bytes());
    hash.update(salt);
    hash.finalize().into()
}

/// Wrap a socket before handing it to Quinn. Also usable by integration clients.
/// Secret values never appear in Debug output. GSO is disabled because each
/// QUIC packet requires its own salt; GRO packets are decoded individually.
pub fn wrap_salamander(
    socket: std::net::UdpSocket,
    password: Arc<str>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    if password.len() < 4 || password.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Salamander password length must be 4..4096 bytes",
        ));
    }
    socket.set_nonblocking(true)?;
    Ok(Arc::new(SalamanderSocket {
        inner: quinn::TokioRuntime.wrap_udp_socket(socket)?,
        password,
    }))
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn try_send(&self, t: &Transmit<'_>) -> io::Result<()> {
        let stride = t.segment_size.unwrap_or(t.contents.len()).max(1);
        for content in t.contents.chunks(stride) {
            let mut packet = vec![0; content.len() + 8];
            OsRng.fill_bytes(&mut packet[..8]);
            let mask = key(&self.password, &packet[..8]);
            for (i, b) in content.iter().enumerate() {
                packet[i + 8] = *b ^ mask[i % 32];
            }
            self.inner.try_send(&Transmit {
                destination: t.destination,
                ecn: t.ecn,
                contents: &packet,
                segment_size: None,
                src_ip: t.src_ip,
            })?;
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // A malformed datagram cannot force a busy loop in a single poll.
        for _ in 0..16 {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => n,
            };
            let mut accepted = 0;
            for i in 0..n {
                let len = meta[i].len;
                let stride = meta[i].stride.max(1);
                let mut out = 0;
                for input in (0..len).step_by(stride) {
                    let end = (input + stride).min(len);
                    if end - input <= 8 {
                        continue;
                    }
                    let mask = key(&self.password, &bufs[i][input..input + 8]);
                    for j in 0..end - input - 8 {
                        bufs[i][out + j] = bufs[i][input + 8 + j] ^ mask[j % 32];
                    }
                    out += end - input - 8;
                }
                if out == 0 {
                    continue;
                }
                meta[i].len = out;
                meta[i].stride = stride.saturating_sub(8).max(1);
                if accepted != i {
                    // Preserve one RecvMeta per buffer; this is rare and only
                    // needed when another datagram in this batch was empty.
                    let decoded = bufs[i][..out].to_vec();
                    bufs[accepted][..out].copy_from_slice(&decoded);
                    meta[accepted] = meta[i];
                }
                accepted += 1;
            }
            if accepted > 0 {
                return Poll::Ready(Ok(accepted));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blake2b_256_is_not_truncated_512() {
        // Digest output length is part of Blake2's initialization, as required
        // by the official Go blake2b.Sum256 implementation.
        let digest = key("test-key", &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(digest.len(), 32);
        let mut hash = blake2::Blake2b512::new();
        hash.update(b"test-key");
        hash.update([0, 1, 2, 3, 4, 5, 6, 7]);
        assert_ne!(digest.as_slice(), &hash.finalize()[..32]);
    }
}
