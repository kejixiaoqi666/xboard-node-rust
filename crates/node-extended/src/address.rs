//! Small address representation used by the upstream wire codecs.
use node_session::Destination;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::io::{AsyncRead, AsyncReadExt};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Hostname(String),
}
impl Address {
    pub fn from(s: &str) -> io::Result<Self> {
        if s.is_empty() || s.len() > 253 || s.chars().any(char::is_control) {
            return Err(crate::invalid("invalid hostname"));
        }
        Ok(match s.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Self::Ipv4(ip),
            Ok(IpAddr::V6(ip)) => Self::Ipv6(ip),
            Err(_) => Self::Hostname(s.into()),
        })
    }
}
impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4(ip) => ip.fmt(f),
            Self::Ipv6(ip) => ip.fmt(f),
            Self::Hostname(h) => h.fmt(f),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetLocation {
    address: Address,
    port: u16,
}
impl NetLocation {
    pub fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }
    pub fn address(&self) -> &Address {
        &self.address
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn destination(&self) -> io::Result<Destination> {
        Destination::new(self.address.to_string(), self.port)
    }
    pub fn from_destination(d: &Destination) -> io::Result<Self> {
        Ok(Self::new(Address::from(&d.host)?, d.port))
    }
}
pub async fn read_location<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> io::Result<NetLocation> {
    let kind = r.read_u8().await?;
    let host = match kind {
        1 => {
            let mut b = [0; 4];
            r.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0; 16];
            r.read_exact(&mut b).await?;
            Ipv6Addr::from(b).to_string()
        }
        3 => {
            let len = r.read_u8().await? as usize;
            if len == 0 || len > 253 {
                return Err(crate::invalid("invalid domain length"));
            }
            let mut b = vec![0; len];
            r.read_exact(&mut b).await?;
            String::from_utf8(b).map_err(|_| crate::invalid("domain is not UTF-8"))?
        }
        _ => return Err(crate::invalid("unsupported SOCKS address")),
    };
    Ok(NetLocation::new(Address::from(&host)?, r.read_u16().await?))
}
pub async fn read_socks<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> io::Result<Destination> {
    read_location(r).await?.destination()
}
