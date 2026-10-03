//! VLESS Vision stream, adapted from MIT-licensed cfal/shoes.
// Internal reference parser helpers are retained for the stream and regression tests.
#![allow(dead_code)]
mod server_hello;
mod sync_adapter;
mod tls_deframer;
mod tls_fuzzy_deframer;
mod tls_handshake_util;
mod vision_filter;
mod vision_pad;
mod vision_stream;
mod vision_unpad;
pub use vision_stream::VisionStream;
mod util {
    pub fn allocate_vec(size: usize) -> Vec<u8> {
        vec![0; size]
    }
}
pub mod crypto {
    use std::io::{self, BufRead, Read, Write};
    pub enum CryptoConnection {
        Rustls(Box<rustls::Connection>),
        Reality(Box<node_reality::RealityServerConnection>),
    }
    impl From<rustls::Connection> for CryptoConnection {
        fn from(c: rustls::Connection) -> Self {
            Self::Rustls(Box::new(c))
        }
    }
    impl From<node_reality::RealityServerConnection> for CryptoConnection {
        fn from(c: node_reality::RealityServerConnection) -> Self {
            Self::Reality(Box::new(c))
        }
    }
    pub struct State {
        bytes: usize,
        closed: bool,
    }
    pub enum Reader<'a> {
        Rustls(rustls::Reader<'a>),
        Reality(node_reality::RealityReader<'a>),
    }
    impl Read for Reader<'_> {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            match self {
                Self::Rustls(r) => r.read(b),
                Self::Reality(r) => r.read(b),
            }
        }
    }
    impl BufRead for Reader<'_> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            match self {
                Self::Rustls(r) => r.fill_buf(),
                Self::Reality(r) => r.fill_buf(),
            }
        }
        fn consume(&mut self, n: usize) {
            match self {
                Self::Rustls(r) => r.consume(n),
                Self::Reality(r) => r.consume(n),
            }
        }
    }
    pub enum Writer<'a> {
        Rustls(rustls::Writer<'a>),
        Reality(node_reality::RealityWriter<'a>),
    }
    impl Write for Writer<'_> {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            match self {
                Self::Rustls(w) => w.write(b),
                Self::Reality(w) => w.write(b),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            match self {
                Self::Rustls(w) => w.flush(),
                Self::Reality(w) => w.flush(),
            }
        }
    }
    impl State {
        pub fn plaintext_bytes_to_read(&self) -> usize {
            self.bytes
        }
        pub fn peer_has_closed(&self) -> bool {
            self.closed
        }
    }
    impl CryptoConnection {
        pub fn is_server(&self) -> bool {
            match self {
                Self::Rustls(c) => matches!(c.as_ref(), rustls::Connection::Server(_)),
                Self::Reality(_) => true,
            }
        }
        pub fn is_client(&self) -> bool {
            !self.is_server()
        }
        pub fn read_tls(&mut self, io: &mut dyn Read) -> io::Result<usize> {
            match self {
                Self::Rustls(c) => c.read_tls(io),
                Self::Reality(c) => c.read_tls(io),
            }
        }
        pub fn write_tls(&mut self, io: &mut dyn Write) -> io::Result<usize> {
            match self {
                Self::Rustls(c) => c.write_tls(io),
                Self::Reality(c) => c.write_tls(io),
            }
        }
        pub fn process_new_packets(&mut self) -> io::Result<State> {
            match self {
                Self::Rustls(c) => {
                    let s = c.process_new_packets().map_err(io::Error::other)?;
                    Ok(State {
                        bytes: s.plaintext_bytes_to_read(),
                        closed: s.peer_has_closed(),
                    })
                }
                Self::Reality(c) => {
                    let s = c.process_new_packets()?;
                    Ok(State {
                        bytes: s.plaintext_bytes_to_read(),
                        closed: c.peer_has_closed(),
                    })
                }
            }
        }
        pub fn wants_write(&self) -> bool {
            match self {
                Self::Rustls(c) => c.wants_write(),
                Self::Reality(c) => c.wants_write(),
            }
        }
        pub fn wants_read(&self) -> bool {
            match self {
                Self::Rustls(c) => c.wants_read(),
                Self::Reality(c) => c.wants_read(),
            }
        }
        pub fn send_close_notify(&mut self) {
            match self {
                Self::Rustls(c) => c.send_close_notify(),
                Self::Reality(c) => c.send_close_notify(),
            }
        }
        pub fn reader(&mut self) -> Reader<'_> {
            match self {
                Self::Rustls(c) => Reader::Rustls(c.reader()),
                Self::Reality(c) => Reader::Reality(c.reader()),
            }
        }
        pub fn writer(&mut self) -> Writer<'_> {
            match self {
                Self::Rustls(c) => Writer::Rustls(c.writer()),
                Self::Reality(c) => Writer::Reality(c.writer()),
            }
        }
    }
    pub fn feed_crypto_connection(c: &mut CryptoConnection, data: &[u8]) -> io::Result<()> {
        let mut rd = io::Cursor::new(data);
        while rd.position() < data.len() as u64 {
            if c.read_tls(&mut rd)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(())
    }
}
