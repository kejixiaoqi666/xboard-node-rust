//! Narrow MIT-licensed REALITY server engine adapted from fixed cfal/shoes source.
#![allow(dead_code)]
mod buf_reader;
mod reality;
mod slide_buffer;
mod stream;
mod sync_adapter;
pub use reality::*;
pub use stream::CryptoTlsStream;
mod util {
    pub fn allocate_vec(size: usize) -> Vec<u8> {
        vec![0; size]
    }
}
