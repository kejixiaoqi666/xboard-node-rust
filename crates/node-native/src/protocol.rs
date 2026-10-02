//! Independent TCP wire implementation based on public VLESS/Trojan formats.
use crate::{Error, auth::Users, config::Protocol};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Ip(IpAddr),
    Domain(String),
}
pub struct Request {
    pub user: Arc<str>,
    pub vision_uuid: Option<[u8; 16]>,
    pub policy: crate::limits::Policy,
    pub address: Address,
    pub port: u16,
    pub command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

pub(crate) async fn address<R: AsyncRead + Unpin>(
    reader: &mut R,
    kind: u8,
    domain: u8,
    ipv6: u8,
) -> Result<Address, Error> {
    match kind {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            Ok(Address::Ip(Ipv4Addr::from(bytes).into()))
        }
        n if n == ipv6 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            Ok(Address::Ip(Ipv6Addr::from(bytes).into()))
        }
        n if n == domain => {
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                return Err(Error::Protocol);
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).await?;
            let name = String::from_utf8(bytes).map_err(|_| Error::Protocol)?;
            if name.len() > 253
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.'))
            {
                return Err(Error::Protocol);
            }
            Ok(Address::Domain(name))
        }
        _ => Err(Error::Protocol),
    }
}

pub async fn handshake<R: AsyncRead + Unpin>(
    reader: &mut R,
    protocol: Protocol,
    users: &Users,
) -> Result<Request, Error> {
    match protocol {
        Protocol::Vless => {
            if reader.read_u8().await? != 0 {
                return Err(Error::Protocol);
            }
            let mut key = [0; 16];
            reader.read_exact(&mut key).await?;
            let snapshot = users.load();
            let user = snapshot.vless(&key).ok_or(Error::Auth)?;
            let policy = snapshot.policy(&user).ok_or(Error::Auth)?;
            let vision = snapshot.vision(&user);
            drop(snapshot);
            let length = reader.read_u8().await? as usize;
            let mut addons = vec![0; length];
            reader.read_exact(&mut addons).await?;
            // The supported protobuf Addons has only field 1 (Flow). Unknown
            // extensions and mismatched per-user flows fail before connecting.
            let flow = b"xtls-rprx-vision";
            if vision {
                if addons.len() != flow.len() + 2
                    || addons[..2] != [10, flow.len() as u8]
                    || addons[2..] != *flow
                {
                    return Err(Error::Unsupported);
                }
            } else if !addons.is_empty() {
                return Err(Error::Unsupported);
            }
            let command = match reader.read_u8().await? {
                1 => Command::Tcp,
                2 => Command::Udp,
                _ => return Err(Error::Unsupported),
            };
            if vision && command != Command::Tcp {
                return Err(Error::Unsupported);
            }
            let port = reader.read_u16().await?;
            let kind = reader.read_u8().await?;
            let address = address(reader, kind, 2, 3).await?;
            if port == 0 {
                return Err(Error::Protocol);
            }
            Ok(Request {
                vision_uuid: vision.then_some(key),
                user,
                policy,
                address,
                port,
                command,
            })
        }
        Protocol::Trojan => {
            let mut key = [0; 56];
            reader.read_exact(&mut key).await?;
            let snapshot = users.load();
            let user = snapshot.trojan(&key).ok_or(Error::Auth)?;
            let policy = snapshot.policy(&user).ok_or(Error::Auth)?;
            drop(snapshot);
            if reader.read_u16().await? != 0x0d0a {
                return Err(Error::Unsupported);
            }
            let command = match reader.read_u8().await? {
                1 => Command::Tcp,
                3 => Command::Udp,
                _ => return Err(Error::Unsupported),
            };
            let kind = reader.read_u8().await?;
            let address = address(reader, kind, 3, 4).await?;
            let port = reader.read_u16().await?;
            if port == 0 && command == Command::Tcp || reader.read_u16().await? != 0x0d0a {
                return Err(Error::Protocol);
            }
            Ok(Request {
                vision_uuid: None,
                user,
                policy,
                address,
                port,
                command,
            })
        }
    }
}
