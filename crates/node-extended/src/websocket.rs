//! RFC6455 transport adapter, including V2Ray/Xray header early data.
//! No background pump: dropping the stream drops all protocol work.
use base64::Engine;
use bytes::Bytes;
use futures::{Sink, Stream, ready};
use node_session::BoxStream;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
        protocol::WebSocketConfig as WireConfig,
    },
};

#[derive(Clone, Debug)]
pub struct WebSocketConfig {
    pub path: Option<String>,
    pub host: Option<String>,
    pub handshake_timeout: Duration,
    pub max_frame: usize,
    pub max_early_data: usize,
}
impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: None,
            host: None,
            handshake_timeout: Duration::from_secs(10),
            max_frame: 65535,
            max_early_data: 2048,
        }
    }
}
#[allow(clippy::result_large_err)] // The tungstenite handshake callback fixes ErrorResponse's type.
pub async fn accept(stream: BoxStream, config: WebSocketConfig) -> io::Result<BoxStream> {
    if config.max_frame == 0
        || config.max_frame > 65535
        || config.max_early_data > config.max_frame
        || config.handshake_timeout.is_zero()
        || config.handshake_timeout > Duration::from_secs(10)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid WebSocket limits",
        ));
    }
    let early = Arc::new(Mutex::new(Bytes::new()));
    let callback_data = early.clone();
    let path = config.path.clone();
    let host = config.host.clone();
    let limit = config.max_early_data;
    let callback = move |request: &Request,
                         mut response: Response|
          -> Result<Response, ErrorResponse> {
        let reject = |status: http::StatusCode| {
            let mut response =
                ErrorResponse::new(Some("invalid WebSocket transport request".into()));
            *response.status_mut() = status;
            response
        };
        if let Some(path) = &path
            && request.uri().path() != path.split('?').next().unwrap_or(path)
        {
            return Err(reject(http::StatusCode::NOT_FOUND));
        }
        if let Some(host) = &host {
            let mut values = request.headers().get_all(http::header::HOST).iter();
            if values.next().and_then(|value| value.to_str().ok()) != Some(host.as_str())
                || values.next().is_some()
            {
                return Err(reject(http::StatusCode::BAD_REQUEST));
            }
        }
        if let Some(value) = request.headers().get(http::header::SEC_WEBSOCKET_PROTOCOL) {
            let encoded = value
                .to_str()
                .map_err(|_| reject(http::StatusCode::BAD_REQUEST))?;
            if encoded.len() > limit.saturating_mul(4).div_ceil(3) + 4 || encoded.contains(',') {
                return Err(reject(http::StatusCode::BAD_REQUEST));
            }
            let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
                .map_err(|_| reject(http::StatusCode::BAD_REQUEST))?;
            if payload.len() > limit {
                return Err(reject(http::StatusCode::BAD_REQUEST));
            }
            *callback_data
                .lock()
                .map_err(|_| reject(http::StatusCode::INTERNAL_SERVER_ERROR))? =
                Bytes::from(payload);
            response
                .headers_mut()
                .insert(http::header::SEC_WEBSOCKET_PROTOCOL, value.clone());
        }
        Ok(response)
    };
    let wire = WireConfig::default()
        .read_buffer_size(8192)
        .write_buffer_size(0)
        .max_write_buffer_size(config.max_frame + 128)
        .max_message_size(Some(config.max_frame))
        .max_frame_size(Some(config.max_frame));
    let ws = tokio::time::timeout(
        config.handshake_timeout,
        tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(wire)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket upgrade timed out"))?
    .map_err(io::Error::other)?;
    let data = early
        .lock()
        .map_err(|_| io::Error::other("early data lock poisoned"))?
        .clone();
    Ok(Box::new(Adapter {
        ws,
        data,
        pending_write: None,
        eof: false,
        max_write: config.max_frame.min(16384),
    }))
}
struct Adapter {
    ws: WebSocketStream<BoxStream>,
    data: Bytes,
    pending_write: Option<usize>,
    eof: bool,
    max_write: usize,
}
impl AsyncRead for Adapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.data.is_empty() {
                let count = self.data.len().min(output.remaining());
                output.put_slice(&self.data[..count]);
                self.data = self.data.slice(count..);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => self.data = data,
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                    ready!(Pin::new(&mut self.ws).poll_flush(cx)).map_err(io::Error::other)?;
                }
                Some(Ok(Message::Close(_))) | None => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(crate::invalid(
                        "WebSocket proxy transport requires binary frames",
                    )));
                }
                Some(Ok(_)) => (),
                Some(Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            }
        }
    }
}
impl AsyncWrite for Adapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.eof {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket closed",
            )));
        }
        if let Some(count) = self.pending_write {
            ready!(Pin::new(&mut self.ws).poll_flush(cx)).map_err(io::Error::other)?;
            self.pending_write = None;
            return Poll::Ready(Ok(count));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.ws).poll_ready(cx)).map_err(io::Error::other)?;
        let count = data.len().min(self.max_write);
        Pin::new(&mut self.ws)
            .start_send(Message::Binary(Bytes::copy_from_slice(&data[..count])))
            .map_err(io::Error::other)?;
        self.pending_write = Some(count);
        ready!(Pin::new(&mut self.ws).poll_flush(cx)).map_err(io::Error::other)?;
        self.pending_write = None;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}
