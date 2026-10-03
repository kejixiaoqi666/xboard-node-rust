use crate::{BoxStream, Outbound, invalid};
use base64::Engine;
use sha2::{Digest, Sha224};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub(crate) fn address(destination: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(19);
    match destination.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(destination.port().to_be_bytes());
    bytes
}
pub(crate) fn parse_address(bytes: &[u8]) -> io::Result<(SocketAddr, usize)> {
    let (ip, n) = match bytes.first() {
        Some(1) => (
            IpAddr::from(
                <[u8; 4]>::try_from(
                    bytes
                        .get(1..5)
                        .ok_or_else(|| invalid("short IPv4 address"))?,
                )
                .map_err(|_| invalid("invalid IPv4 address"))?,
            ),
            5,
        ),
        Some(4) => (
            IpAddr::from(
                <[u8; 16]>::try_from(
                    bytes
                        .get(1..17)
                        .ok_or_else(|| invalid("short IPv6 address"))?,
                )
                .map_err(|_| invalid("invalid IPv6 address"))?,
            ),
            17,
        ),
        Some(3) => {
            return Err(crate::unsupported(
                "proxy returned a domain instead of the pinned target IP",
            ));
        }
        _ => return Err(invalid("invalid address type")),
    };
    let port = u16::from_be_bytes(
        bytes
            .get(n..n + 2)
            .ok_or_else(|| invalid("short address port"))?
            .try_into()
            .map_err(|_| invalid("invalid port"))?,
    );
    Ok((
        SocketAddr::new(node_core::routing::canonical(ip), port),
        n + 2,
    ))
}
pub(crate) async fn read_address<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
) -> io::Result<SocketAddr> {
    let kind = stream.read_u8().await?;
    let n = match kind {
        1 => 6,
        4 => 18,
        3 => {
            return Err(crate::unsupported(
                "proxy returned a domain instead of the pinned target IP",
            ));
        }
        _ => return Err(invalid("invalid proxy address type")),
    };
    let mut bytes = [0; 19];
    bytes[0] = kind;
    stream.read_exact(&mut bytes[1..n + 1]).await?;
    Ok(parse_address(&bytes[..n + 1])?.0)
}
pub(crate) async fn socks(
    stream: &mut BoxStream,
    outbound: &Outbound,
    command: u8,
    target: SocketAddr,
) -> io::Result<SocketAddr> {
    let method = if outbound.username.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, method] {
        return Err(invalid("SOCKS method rejected"));
    }
    if let (Some(user), Some(password)) = (&outbound.username, &outbound.password) {
        let mut auth = vec![1, user.len() as u8];
        auth.extend(user.as_bytes());
        auth.push(password.len() as u8);
        auth.extend(password.as_bytes());
        stream.write_all(&auth).await?;
        stream.read_exact(&mut reply).await?;
        if reply != [1, 0] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS authentication rejected",
            ));
        }
    }
    let mut request = vec![5, command, 0];
    request.extend(address(target));
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut header = [0; 3];
    stream.read_exact(&mut header).await?;
    if header != [5, 0, 0] {
        return Err(invalid("SOCKS request rejected"));
    }
    // CONNECT's bound address is informational, and may legally be a domain.
    if command == 1 {
        let kind = stream.read_u8().await?;
        let n = match kind {
            1 => 4,
            4 => 16,
            3 => {
                let n = stream.read_u8().await? as usize;
                if n == 0 {
                    return Err(invalid("empty SOCKS bound domain"));
                }
                n
            }
            _ => return Err(invalid("invalid SOCKS bound address")),
        };
        let mut bound = [0; 257];
        stream.read_exact(&mut bound[..n + 2]).await?;
        Ok(target)
    } else {
        read_address(stream).await
    }
}
pub(crate) async fn http(
    stream: &mut BoxStream,
    outbound: &Outbound,
    target: SocketAddr,
) -> io::Result<()> {
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let (Some(user), Some(password)) = (&outbound.username, &outbound.password) {
        if user.contains(':') || user.chars().chain(password.chars()).any(char::is_control) {
            return Err(invalid("invalid HTTP proxy credentials"));
        }
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut header = Vec::with_capacity(256);
    loop {
        if header.len() >= 8192 {
            return Err(invalid("HTTP CONNECT response too large"));
        }
        header.push(stream.read_u8().await?);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text =
        std::str::from_utf8(&header).map_err(|_| invalid("invalid HTTP CONNECT response"))?;
    let mut status = text
        .split("\r\n")
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || !status
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .is_some_and(|n| (200..300).contains(&n))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP CONNECT rejected",
        ));
    }
    Ok(())
}
pub(crate) async fn trojan(
    stream: &mut BoxStream,
    outbound: &Outbound,
    command: u8,
    target: SocketAddr,
) -> io::Result<()> {
    let password = outbound
        .password
        .as_deref()
        .ok_or_else(|| invalid("missing Trojan password"))?;
    let mut request = format!("{:x}\r\n", Sha224::digest(password)).into_bytes();
    request.push(command);
    request.extend(address(target));
    request.extend(b"\r\n");
    stream.write_all(&request).await?;
    stream.flush().await
}
pub(crate) async fn vless(
    mut stream: BoxStream,
    outbound: &Outbound,
    command: u8,
    target: SocketAddr,
) -> io::Result<BoxStream> {
    let uuid = outbound
        .uuid
        .as_ref()
        .ok_or_else(|| invalid("missing VLESS UUID"))?
        .replace('-', "");
    let mut request = vec![0];
    for i in (0..32).step_by(2) {
        request.push(
            u8::from_str_radix(&uuid[i..i + 2], 16).map_err(|_| invalid("invalid VLESS UUID"))?,
        )
    }
    request.extend([0, command]);
    request.extend(target.port().to_be_bytes());
    match target.ip() {
        IpAddr::V4(ip) => {
            request.push(1);
            request.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(3);
            request.extend(ip.octets());
        }
    }
    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(Box::new(VlessResponse {
        stream,
        header: [0; 257],
        read: 0,
        total: 2,
        ready: false,
    }))
}
// Strip the response lazily: waiting for it before writing the first payload
// would deadlock lazy server implementations and multi-hop chains.
struct VlessResponse {
    stream: BoxStream,
    header: [u8; 257],
    read: usize,
    total: usize,
    ready: bool,
}
impl AsyncRead for VlessResponse {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while !self.ready {
            let this = &mut *self;
            let mut header = ReadBuf::new(&mut this.header[this.read..this.total]);
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut header))?;
            let n = header.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.read += n;
            if this.read == this.total {
                if this.header[0] != 0 {
                    return Poll::Ready(Err(invalid("invalid VLESS response version")));
                }
                this.total = 2 + this.header[1] as usize;
                this.ready = this.read == this.total;
            }
        }
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for VlessResponse {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
