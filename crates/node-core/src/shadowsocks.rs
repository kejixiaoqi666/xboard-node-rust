//! Explicit native Shadowsocks subset and original panel user-key conversion.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Cipher {
    #[serde(rename = "aes-128-gcm")]
    Aes128,
    #[serde(rename = "aes-256-gcm")]
    Aes256,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128V2,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256V2,
}
impl Cipher {
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128 => "aes-128-gcm",
            Self::Aes256 => "aes-256-gcm",
            Self::Chacha20 => "chacha20-ietf-poly1305",
            Self::Aes128V2 => "2022-blake3-aes-128-gcm",
            Self::Aes256V2 => "2022-blake3-aes-256-gcm",
        }
    }
    pub fn key_len(self) -> usize {
        if matches!(self, Self::Aes128 | Self::Aes128V2) {
            16
        } else {
            32
        }
    }
    pub fn is_v2(self) -> bool {
        matches!(self, Self::Aes128V2 | Self::Aes256V2)
    }
    pub fn max_users(self) -> usize {
        if self.is_v2() { 65536 } else { 256 }
    }
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub method: Cipher,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksSettings")
            .field("method", &self.method)
            .field("password", &"[REDACTED]")
            .finish()
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.method.is_v2() {
            let encoded = self.password.as_deref().ok_or("missing server key")?;
            if encoded.len() != 4 * self.method.key_len().div_ceil(3) {
                return Err("invalid server key length");
            }
            let key = STANDARD.decode(encoded).map_err(|_| "invalid server key")?;
            if key.len() != self.method.key_len() {
                return Err("invalid server key length");
            }
        } else if self.password.is_some() {
            return Err("traditional multi-user mode has no server key");
        }
        Ok(())
    }
}
/// Mirrors original Go: copy UTF-8 UUID bytes into a zero-filled fixed key.
pub fn user_password(method: Cipher, uuid: &str) -> Cow<'_, str> {
    if !method.is_v2() {
        return Cow::Borrowed(uuid);
    }
    let mut key = vec![0; method.key_len()];
    let n = uuid.len().min(key.len());
    key[..n].copy_from_slice(&uuid.as_bytes()[..n]);
    Cow::Owned(STANDARD.encode(key))
}
