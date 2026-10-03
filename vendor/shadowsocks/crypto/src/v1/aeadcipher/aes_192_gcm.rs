//! AES192-GCM wire compatibility; ring has no AES192-GCM primitive, so this
//! method uses the existing RustCrypto AES/GCM implementation.
use aes_gcm::{
    aead::{consts::U12, AeadInPlace, KeyInit},
    AesGcm, Nonce, Tag,
};
type Cipher = AesGcm<aes::Aes192, U12>;
pub struct Aes192Gcm(Cipher);
impl Aes192Gcm {
    pub fn new(key: &[u8]) -> Self {
        Self(Cipher::new_from_slice(key).expect("AES192 key length"))
    }
    pub fn key_size() -> usize {
        24
    }
    pub fn nonce_size() -> usize {
        12
    }
    pub fn tag_size() -> usize {
        16
    }
    pub fn encrypt(&self, nonce: &[u8], packet: &mut [u8]) {
        let (payload, out_tag) = packet.split_at_mut(packet.len() - 16);
        let tag = self
            .0
            .encrypt_in_place_detached(Nonce::from_slice(nonce), &[], payload)
            .expect("AES192-GCM sealing");
        out_tag.copy_from_slice(&tag);
    }
    pub fn decrypt(&self, nonce: &[u8], packet: &mut [u8]) -> bool {
        if packet.len() < 16 || nonce.len() != 12 {
            return false;
        }
        let (payload, tag) = packet.split_at_mut(packet.len() - 16);
        self.0
            .decrypt_in_place_detached(Nonce::from_slice(nonce), &[], payload, Tag::from_slice(tag))
            .is_ok()
    }
}
