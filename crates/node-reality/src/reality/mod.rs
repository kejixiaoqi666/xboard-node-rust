mod common;
mod hello;
#[cfg(test)]
mod hello_tests;
mod mirror;
mod reality_aead;
mod reality_auth;
mod reality_certificate;
mod reality_cipher_suite;
mod reality_io_state;
mod reality_reader_writer;
mod reality_records;
mod reality_server_connection;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;
pub use hello::{MirrorHello, classify_server_hello};
pub use mirror::{MirrorFlight, mirror_handshake};
pub use reality_certificate::{generate_mldsa65_keypair, mldsa65_verify_key};
pub use reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
pub use reality_server_connection::{
    MAX_KEY_UPDATE_RECORDS, MIN_KEY_UPDATE_RECORDS, RealityServerConfig, RealityServerConnection,
    feed_reality_server_connection,
};
pub use reality_util::{decode_private_key, decode_public_key, decode_short_id, generate_keypair};
pub fn public_key_from_private(key: [u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(key)).to_bytes()
}
pub use reality_reader_writer::{RealityReader, RealityWriter};
