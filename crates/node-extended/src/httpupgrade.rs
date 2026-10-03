//! V2Ray HTTPUpgrade: HTTP/1.1 negotiation followed by an unframed byte stream.
use node_session::BoxStream;
use std::{io, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug)]
pub struct HttpUpgradeConfig {
    pub path: Option<String>,
    pub host: Option<String>,
    pub handshake_timeout: Duration,
    pub max_header_bytes: usize,
}
impl Default for HttpUpgradeConfig {
    fn default() -> Self {
        Self {
            path: None,
            host: None,
            handshake_timeout: Duration::from_secs(10),
            max_header_bytes: 16384,
        }
    }
}
pub async fn accept(mut stream: BoxStream, config: HttpUpgradeConfig) -> io::Result<BoxStream> {
    if config.handshake_timeout.is_zero()
        || config.handshake_timeout > Duration::from_secs(10)
        || config.max_header_bytes < 256
        || config.max_header_bytes > 65535
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid HTTPUpgrade limits",
        ));
    }
    tokio::time::timeout(config.handshake_timeout, async {
        // Reading only through the delimiter preserves a pipelined protocol
        // handshake in the caller's stream without a second parser buffer.
        let mut head = Vec::with_capacity(1024);
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() == config.max_header_bytes { return Err(crate::invalid("HTTPUpgrade headers exceed limit")); }
            head.push(stream.read_u8().await?);
        }
        validate(&head, &config)?;
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n").await?;
        stream.flush().await?;
        Ok(stream)
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTPUpgrade handshake timed out"))?
}
fn validate(head: &[u8], config: &HttpUpgradeConfig) -> io::Result<()> {
    let text = std::str::from_utf8(head)
        .map_err(|_| crate::invalid("invalid HTTPUpgrade header bytes"))?;
    let mut lines = text.split("\r\n");
    let mut request = lines.next().unwrap_or_default().split(' ');
    if request.next() != Some("GET") {
        return Err(crate::invalid("HTTPUpgrade requires GET"));
    }
    let target = request
        .next()
        .ok_or_else(|| crate::invalid("missing HTTPUpgrade path"))?;
    if request.next() != Some("HTTP/1.1")
        || request.next().is_some()
        || !target.starts_with('/')
        || config
            .path
            .as_deref()
            .is_some_and(|path| target.split('?').next() != Some(path))
    {
        return Err(crate::invalid("HTTPUpgrade path or version mismatch"));
    }
    let (mut host, mut connection, mut upgrade) = (None, false, false);
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| crate::invalid("malformed HTTPUpgrade header"))?;
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| crate::invalid("invalid HTTPUpgrade header name"))?;
        let value = value.trim();
        http::header::HeaderValue::from_str(value)
            .map_err(|_| crate::invalid("invalid HTTPUpgrade header value"))?;
        match name.as_str() {
            "host" => {
                if host.replace(value).is_some() {
                    return Err(crate::invalid("duplicate HTTPUpgrade Host"));
                }
            }
            "connection" => {
                connection |= value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
            }
            "upgrade" => upgrade |= value.eq_ignore_ascii_case("websocket"),
            "sec-websocket-key" => {
                return Err(crate::invalid("WebSocket request is not HTTPUpgrade"));
            }
            "transfer-encoding" => {
                return Err(crate::invalid("HTTPUpgrade request body is forbidden"));
            }
            "content-length" if value != "0" => {
                return Err(crate::invalid("HTTPUpgrade request body is forbidden"));
            }
            _ => (),
        }
    }
    if !connection
        || !upgrade
        || host.is_none()
        || config
            .host
            .as_deref()
            .is_some_and(|expected| host != Some(expected))
    {
        return Err(crate::invalid("HTTPUpgrade host or upgrade mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn pipelined_protocol_bytes_survive_upgrade() {
        let (server, mut client) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            let mut stream = accept(
                Box::new(server),
                HttpUpgradeConfig {
                    path: Some("/proxy".into()),
                    host: Some("example.test".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let mut payload = [0; 7];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"payload");
        });
        client.write_all(b"GET /proxy HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\npayload").await.unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(client.read_u8().await.unwrap());
        }
        assert!(response.starts_with(b"HTTP/1.1 101 "));
        task.await.unwrap();
    }
    #[test]
    fn rejects_real_websocket_body_and_duplicate_host() {
        for extra in [
            "Sec-WebSocket-Key: key\r\n",
            "Content-Length: 1\r\n",
            "Host: duplicate.test\r\n",
        ] {
            let head = format!(
                "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\n{extra}\r\n"
            );
            assert!(validate(head.as_bytes(), &Default::default()).is_err());
        }
    }
}
