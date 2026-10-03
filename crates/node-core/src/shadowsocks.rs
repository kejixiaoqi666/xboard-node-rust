//! Native Shadowsocks methods and original panel user-key conversion.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Cipher {
    #[serde(rename = "none", alias = "plain")]
    None,
    #[serde(rename = "aes-128-gcm")]
    Aes128,
    #[serde(rename = "aes-192-gcm")]
    Aes192,
    #[serde(rename = "aes-256-gcm")]
    Aes256,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20,
    #[serde(rename = "xchacha20-ietf-poly1305", alias = "xchacha20-poly1305")]
    Xchacha20,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128V2,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256V2,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Chacha20V2,
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
    #[serde(rename = "aes-192-ctr")]
    Aes192Ctr,
    #[serde(rename = "aes-256-ctr")]
    Aes256Ctr,
    #[serde(rename = "aes-128-cfb")]
    Aes128Cfb,
    #[serde(rename = "aes-192-cfb")]
    Aes192Cfb,
    #[serde(rename = "aes-256-cfb")]
    Aes256Cfb,
    #[serde(rename = "rc4-md5")]
    Rc4Md5,
    #[serde(rename = "chacha20-ietf")]
    Chacha20Stream,
    #[serde(rename = "xchacha20")]
    Xchacha20Stream,
}
impl Cipher {
    pub const ALL: [Self; 18] = [
        Self::None,
        Self::Aes128,
        Self::Aes192,
        Self::Aes256,
        Self::Chacha20,
        Self::Xchacha20,
        Self::Aes128V2,
        Self::Aes256V2,
        Self::Chacha20V2,
        Self::Aes128Ctr,
        Self::Aes192Ctr,
        Self::Aes256Ctr,
        Self::Aes128Cfb,
        Self::Aes192Cfb,
        Self::Aes256Cfb,
        Self::Rc4Md5,
        Self::Chacha20Stream,
        Self::Xchacha20Stream,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes128 => "aes-128-gcm",
            Self::Aes192 => "aes-192-gcm",
            Self::Aes256 => "aes-256-gcm",
            Self::Chacha20 => "chacha20-ietf-poly1305",
            Self::Xchacha20 => "xchacha20-ietf-poly1305",
            Self::Aes128V2 => "2022-blake3-aes-128-gcm",
            Self::Aes256V2 => "2022-blake3-aes-256-gcm",
            Self::Chacha20V2 => "2022-blake3-chacha20-poly1305",
            Self::Aes128Ctr => "aes-128-ctr",
            Self::Aes192Ctr => "aes-192-ctr",
            Self::Aes256Ctr => "aes-256-ctr",
            Self::Aes128Cfb => "aes-128-cfb",
            Self::Aes192Cfb => "aes-192-cfb",
            Self::Aes256Cfb => "aes-256-cfb",
            Self::Rc4Md5 => "rc4-md5",
            Self::Chacha20Stream => "chacha20-ietf",
            Self::Xchacha20Stream => "xchacha20",
        }
    }
    pub fn key_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128 | Self::Aes128V2 | Self::Aes128Ctr | Self::Aes128Cfb | Self::Rc4Md5 => 16,
            Self::Aes192 | Self::Aes192Ctr | Self::Aes192Cfb => 24,
            _ => 32,
        }
    }
    pub fn is_v2(self) -> bool {
        matches!(self, Self::Aes128V2 | Self::Aes256V2 | Self::Chacha20V2)
    }
    /// AES2022 supports encrypted identity headers; ChaCha2022 has no EIH.
    pub fn uses_identity_header(self) -> bool {
        matches!(self, Self::Aes128V2 | Self::Aes256V2)
    }
    pub fn is_authenticated(self) -> bool {
        self.is_v2()
            || matches!(
                self,
                Self::Aes128 | Self::Aes192 | Self::Aes256 | Self::Chacha20 | Self::Xchacha20
            )
    }
    pub fn max_users(self) -> usize {
        if self.uses_identity_header() {
            65536
        } else if self.is_authenticated() && self != Self::Chacha20V2 {
            256
        } else {
            1
        }
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
        if self.method.uses_identity_header() {
            let encoded = self.password.as_deref().ok_or("missing server key")?;
            validate_user_key(self.method, encoded)?;
        } else if self.password.is_some() {
            return Err("method has no server identity key; configure the user key instead");
        }
        Ok(())
    }
}
pub fn validate_user_key(method: Cipher, encoded: &str) -> Result<(), &'static str> {
    if !method.is_v2() {
        return Ok(());
    }
    if encoded.len() != 4 * method.key_len().div_ceil(3) {
        return Err("invalid 2022 key length");
    }
    let key = STANDARD.decode(encoded).map_err(|_| "invalid 2022 key")?;
    if key.len() != method.key_len() {
        return Err("invalid 2022 key length");
    }
    Ok(())
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
