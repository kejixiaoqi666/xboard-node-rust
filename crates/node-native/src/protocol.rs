//! Independent TCP wire implementation based on public VLESS/Trojan formats.
use crate::{Error, auth::Users, config::Protocol};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt};

pub enum Address {
    Ip(IpAddr),
    Domain(String),
}
pub struct Request {
    pub user: Arc<str>,
    pub address: Address,
    pub port: u16,
}

async fn address<R: AsyncRead + Unpin>(
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
            let user = users.load().vless(&key).ok_or(Error::Auth)?;
            // Nonempty addons may carry flow/extension behavior we do not implement.
            if reader.read_u8().await? != 0 || reader.read_u8().await? != 1 {
                return Err(Error::Unsupported);
            }
            let port = reader.read_u16().await?;
            let kind = reader.read_u8().await?;
            let address = address(reader, kind, 2, 3).await?;
            if port == 0 {
                return Err(Error::Protocol);
            }
            Ok(Request {
                user,
                address,
                port,
            })
        }
        Protocol::Trojan => {
            let mut key = [0; 56];
            reader.read_exact(&mut key).await?;
            let user = users.load().trojan(&key).ok_or(Error::Auth)?;
            if reader.read_u16().await? != 0x0d0a || reader.read_u8().await? != 1 {
                return Err(Error::Unsupported);
            }
            let kind = reader.read_u8().await?;
            let address = address(reader, kind, 3, 4).await?;
            let port = reader.read_u16().await?;
            if port == 0 || reader.read_u16().await? != 0x0d0a {
                return Err(Error::Protocol);
            }
            Ok(Request {
                user,
                address,
                port,
            })
        }
    }
}
