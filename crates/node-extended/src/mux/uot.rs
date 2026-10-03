//! SagerNet UoT v1/v2 and sing-mux packet-address framing.
use node_session::{BoxStream, Datagram, Destination};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
pub const UOT_V1: &str = "sp.udp-over-tcp.arpa";
pub const UOT_V2: &str = "sp.v2.udp-over-tcp.arpa";
#[derive(Clone)]
pub enum Mode {
    Connected(Destination),
    UotAddress,
    SocksAddress,
}
pub async fn relay(
    mut stream: BoxStream,
    datagram: Arc<dyn Datagram>,
    mode: Mode,
    max_frame: usize,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let send = async {
        loop {
            let target = match &mode {
                Mode::Connected(d) => d.clone(),
                Mode::UotAddress => read_uot_address(&mut reader).await?,
                Mode::SocksAddress => crate::address::read_socks(&mut reader).await?,
            };
            let len = reader.read_u16().await? as usize;
            if len > max_frame {
                return Err(crate::invalid("UoT datagram exceeds frame limit"));
            }
            let mut payload = vec![0; len];
            reader.read_exact(&mut payload).await?;
            if datagram.send(&payload, &target).await? != len {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP send"));
            }
        }
    };
    let receive = async {
        let mut payload = vec![0; max_frame];
        loop {
            let (len, source) = datagram.receive(&mut payload).await?;
            if len > max_frame {
                return Err(crate::invalid("host returned oversized datagram"));
            }
            match &mode {
                Mode::Connected(_) => (),
                Mode::UotAddress => writer.write_all(&encode_uot_address(&source)?).await?,
                Mode::SocksAddress => {
                    let mut address = bytes::BytesMut::new();
                    super::h2mux::h2mux_protocol::encode_socks_address(
                        &mut address,
                        &crate::address::NetLocation::from_destination(&source)?,
                    )?;
                    writer.write_all(&address).await?;
                }
            }
            writer.write_u16(len as u16).await?;
            writer.write_all(&payload[..len]).await?;
            writer.flush().await?;
        }
    };
    tokio::select! { result = send => result, result = receive => result }
}
async fn read_uot_address<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Destination> {
    let kind = r.read_u8().await?;
    let host = match kind {
        0 => {
            let mut b = [0; 4];
            r.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        1 => {
            let mut b = [0; 16];
            r.read_exact(&mut b).await?;
            Ipv6Addr::from(b).to_string()
        }
        2 => {
            let n = r.read_u8().await? as usize;
            if n == 0 || n > 253 {
                return Err(crate::invalid("invalid UoT hostname length"));
            }
            let mut b = vec![0; n];
            r.read_exact(&mut b).await?;
            String::from_utf8(b).map_err(|_| crate::invalid("invalid UoT domain"))?
        }
        _ => return Err(crate::invalid("unsupported UoT address kind")),
    };
    Destination::new(host, r.read_u16().await?)
}
fn encode_uot_address(d: &Destination) -> io::Result<Vec<u8>> {
    let mut address = Vec::with_capacity(260);
    match d.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            address.push(0);
            address.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            address.push(1);
            address.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if d.host.len() > 253 {
                return Err(crate::invalid("domain too long"));
            }
            address.extend_from_slice(&[2, d.host.len() as u8]);
            address.extend_from_slice(d.host.as_bytes());
        }
    }
    address.extend_from_slice(&d.port.to_be_bytes());
    Ok(address)
}
