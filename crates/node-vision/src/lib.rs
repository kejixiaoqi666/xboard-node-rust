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
mod crypto {
    pub type CryptoConnection = rustls::Connection;
    pub fn feed_crypto_connection(
        connection: &mut CryptoConnection,
        data: &[u8],
    ) -> std::io::Result<()> {
        use std::io::Cursor;
        let mut cursor = Cursor::new(data);
        while cursor.position() < data.len() as u64 {
            if connection.read_tls(&mut cursor)? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(())
    }
}
