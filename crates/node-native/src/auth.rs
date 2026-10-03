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
    vision: HashSet<Arc<str>>,
    pub(crate) shadowsocks: Option<Arc<crate::shadowsocks::Credentials>>,
    ss_pending: Vec<(Arc<str>, String)>,
    profiles: Arc<[node_session::User]>,
    profile_indices: HashMap<Arc<str>, usize>,
}

impl Snapshot {
    pub fn new(protocol: Protocol, users: Vec<User>) -> Result<Self, Error> {
        if users.len()
            > if protocol == Protocol::Vmess {
                node_extended::MAX_VMESS_USERS
            } else {
                node_extended::MAX_ANYTLS_USERS
            }
        {
            return Err(Error::Config);
        }
        let mut snapshot = Self {
            vless: HashMap::new(),
            trojan: HashMap::new(),
            policies: HashMap::new(),
            vision: HashSet::new(),
            shadowsocks: None,
            ss_pending: Vec::new(),
            profiles: Arc::from([]),
            profile_indices: HashMap::new(),
        };
        let mut names = HashSet::with_capacity(users.len());
        let mut profiles = Vec::with_capacity(users.len());
        for user in users {
            if user.name.is_empty()
                || user.name.len() > 128
                || user.name.chars().any(char::is_control)
                || !names.insert(user.name.clone())
                || user
                    .flow
                    .as_deref()
                    .is_some_and(|flow| !matches!(flow, "" | "xtls-rprx-vision"))
                || protocol != Protocol::Vless
                    && user.flow.as_ref().is_some_and(|flow| !flow.is_empty())
            {
                return Err(Error::Auth);
            }
            let policy = crate::limits::Policy::new(user.speed_limit, user.device_limit)?;
            let name: Arc<str> = user.name.into();
            let profile = node_session::User {
                name: Arc::clone(&name),
                uuid: user.uuid.as_deref().and_then(uuid),
                password: user.password.as_deref().map(Arc::from),
            };
            if user.flow.as_deref() == Some("xtls-rprx-vision") {
                snapshot.vision.insert(Arc::clone(&name));
            }
            snapshot.policies.insert(Arc::clone(&name), policy);
            match protocol {
                Protocol::Vless | Protocol::Vmess => {
                    if user.password.is_some() {
                        return Err(Error::Auth);
                    }
                    let key = uuid(user.uuid.as_deref().ok_or(Error::Auth)?).ok_or(Error::Auth)?;
                    if snapshot.vless.insert(key, name).is_some() {
                        return Err(Error::Auth);
                    }
                }
                Protocol::Shadowsocks => {
                    if user.uuid.is_some() {
                        return Err(Error::Auth);
                    }
                    let password = user.password.ok_or(Error::Auth)?;
                    if password.is_empty() || password.len() > 1024 {
                        return Err(Error::Auth);
                    }
                    snapshot.ss_pending.push((name, password));
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
                Protocol::AnyTls | Protocol::Hysteria2 | Protocol::Tuic => {
                    let password = user.password.ok_or(Error::Auth)?;
                    if password.is_empty()
                        || password.len() > 1024
                        || protocol == Protocol::Tuic && profile.uuid.is_none()
                        || protocol != Protocol::Tuic && user.uuid.is_some()
                        || snapshot
                            .trojan
                            .insert(trojan_key(&password), name)
                            .is_some()
                    {
                        return Err(Error::Auth);
                    }
                }
            }
            snapshot
                .profile_indices
                .insert(Arc::clone(&profile.name), profiles.len());
            profiles.push(profile);
        }
        snapshot.profiles = profiles.into();
        Ok(snapshot)
    }
    #[cfg_attr(not(any(unix, test)), allow(dead_code))]
    pub(crate) fn profiles(&self) -> Arc<[node_session::User]> {
        Arc::clone(&self.profiles)
    }
    #[cfg_attr(not(any(unix, test)), allow(dead_code))]
    pub(crate) fn contains_profile(&self, user: &node_session::User) -> bool {
        self.profile_indices
            .get(&user.name)
            .is_some_and(|index| self.profiles.get(*index) == Some(user))
    }
    pub(crate) fn profile(&self, name: &str) -> Option<node_session::User> {
        self.profile_indices
            .get(name)
            .and_then(|index| self.profiles.get(*index))
            .cloned()
    }
    pub(crate) fn configure_shadowsocks(
        &mut self,
        settings: &node_core::shadowsocks::Settings,
    ) -> Result<(), Error> {
        self.shadowsocks = Some(Arc::new(crate::shadowsocks::Credentials::new(
            settings,
            std::mem::take(&mut self.ss_pending),
        )?));
        Ok(())
    }
    pub fn has_vision(&self) -> bool {
        !self.vision.is_empty()
    }
    pub fn vision(&self, name: &str) -> bool {
        self.vision.contains(name)
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
