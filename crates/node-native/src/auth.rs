use crate::{
    Error,
    config::{Protocol, User},
};
use arc_swap::ArcSwap;
use sha2::{Digest, Sha224};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub struct Snapshot {
    vless: HashMap<[u8; 16], Arc<str>>,
    trojan: HashMap<[u8; 56], Arc<str>>,
    policies: HashMap<Arc<str>, crate::limits::Policy>,
}

impl Snapshot {
    pub fn new(protocol: Protocol, users: Vec<User>) -> Result<Self, Error> {
        let mut snapshot = Self {
            vless: HashMap::new(),
            trojan: HashMap::new(),
            policies: HashMap::new(),
        };
        let mut names = HashSet::with_capacity(users.len());
        for user in users {
            if user.name.is_empty()
                || user.name.len() > 128
                || user.name.chars().any(char::is_control)
                || !names.insert(user.name.clone())
                || user.flow.as_ref().is_some_and(|flow| !flow.is_empty())
            {
                return Err(Error::Auth);
            }
            let policy = crate::limits::Policy::new(user.speed_limit, user.device_limit)?;
            let name: Arc<str> = user.name.into();
            snapshot.policies.insert(Arc::clone(&name), policy);
            match protocol {
                Protocol::Vless => {
                    if user.password.is_some() {
                        return Err(Error::Auth);
                    }
                    let key = uuid(user.uuid.as_deref().ok_or(Error::Auth)?).ok_or(Error::Auth)?;
                    if snapshot.vless.insert(key, name).is_some() {
                        return Err(Error::Auth);
                    }
                }
                Protocol::Trojan => {
                    if user.uuid.is_some() {
                        return Err(Error::Auth);
                    }
                    let password = user.password.ok_or(Error::Auth)?;
                    if password.is_empty() {
                        return Err(Error::Auth);
                    }
                    if snapshot
                        .trojan
                        .insert(trojan_key(&password), name)
                        .is_some()
                    {
                        return Err(Error::Auth);
                    }
                }
            }
        }
        Ok(snapshot)
    }
    pub fn vless(&self, key: &[u8; 16]) -> Option<Arc<str>> {
        self.vless.get(key).cloned()
    }
    pub fn trojan(&self, key: &[u8; 56]) -> Option<Arc<str>> {
        self.trojan.get(key).cloned()
    }
    pub fn policy(&self, name: &str) -> Option<crate::limits::Policy> {
        self.policies.get(name).copied()
    }
}

pub type Users = Arc<ArcSwap<Snapshot>>;

pub fn uuid(value: &str) -> Option<[u8; 16]> {
    if value.len() != 36 {
        return None;
    }
    let mut bytes = [0u8; 16];
    let mut offset = 0;
    let mut nibble = None;
    for (index, c) in value.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if c != b'-' {
                return None;
            }
            continue;
        }
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        match nibble.take() {
            Some(high) => {
                bytes[offset] = high * 16 + digit;
                offset += 1;
            }
            None => nibble = Some(digit),
        }
    }
    Some(bytes)
}

pub fn trojan_key(password: &str) -> [u8; 56] {
    let digest = Sha224::digest(password.as_bytes());
    let mut key = [0u8; 56];
    const HEX: &[u8] = b"0123456789abcdef";
    for (index, byte) in digest.iter().enumerate() {
        key[index * 2] = HEX[(byte >> 4) as usize];
        key[index * 2 + 1] = HEX[(byte & 15) as usize];
    }
    key
}
