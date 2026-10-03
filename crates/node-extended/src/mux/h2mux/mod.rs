mod h2mux_padding;
pub mod h2mux_protocol;
mod h2mux_stream;
use bytes::Bytes;
use h2mux_padding::H2MuxPaddingStream;
use h2mux_protocol::SessionRequest;
pub(crate) use h2mux_stream::H2MuxStream;
use node_session::{BoxStream, Host, User};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{sync::watch, task::JoinSet};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MuxProtocol {
    Smux = 0,
    Yamux = 1,
    H2Mux = 2,
}
impl MuxProtocol {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Smux),
            1 => Some(Self::Yamux),
            2 => Some(Self::H2Mux),
            _ => None,
        }
    }
}

pub async fn serve(
    mut stream: BoxStream,
    user: User,
    peer: SocketAddr,
    host: Arc<dyn Host>,
    config: crate::Config,
    mut cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    config.require_multiplex()?;
    config.validate()?;
    let request = tokio::select! {
        _ = crate::cancelled(&mut cancel) => return Ok(()),
        result = tokio::time::timeout(config.handshake_timeout, SessionRequest::decode(&mut stream)) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mux negotiation timed out"))??,
    };
    let stream: BoxStream = if request.padding {
        Box::new(H2MuxPaddingStream::new(stream))
    } else {
        stream
    };
    match request.protocol {
        MuxProtocol::Smux => {
            return super::stream_mux::serve(
                stream,
                super::stream_mux::Kind::Smux,
                user,
                peer,
                host,
                config,
                cancel,
            )
            .await;
        }
        MuxProtocol::Yamux => {
            return super::stream_mux::serve(
                stream,
                super::stream_mux::Kind::Yamux,
                user,
                peer,
                host,
                config,
                cancel,
            )
            .await;
        }
        MuxProtocol::H2Mux => (),
    }
    let listener_budget = config
        .shared_budget
        .bind(config.max_queued_bytes, config.max_sessions)?;
    // HTTP/2 starts with a 65535-byte connection window, even when a smaller
    // initial stream window is advertised. Reserve that whole receive queue
    // across all carriers before admitting this connection.
    // Leave space for at least one send chunk rather than letting idle H2
    // connections reserve the whole pool and prevent every response.
    let _receive_permit =
        listener_budget.reserve_receive_window(65535, config.max_frame.min(16384))?;
    let builder = &mut h2::server::Builder::new();
    builder
        .initial_window_size(config.max_frame.min(65535) as u32)
        .initial_connection_window_size(65535)
        .max_frame_size(config.max_frame.max(16384) as u32)
        .max_concurrent_streams(config.max_sessions as u32)
        .max_header_list_size(8192)
        // The threshold can be exceeded by one DATA call; each DATA owns its
        // exact byte permit until h2 releases it, so the shared budget remains
        // the hard bound rather than this per-stream throughput setting.
        .max_send_buffer_size(16384);
    let mut connection = tokio::select! {
        _ = crate::cancelled(&mut cancel) => return Ok(()),
        result = tokio::time::timeout(config.handshake_timeout, builder.handshake::<_, Bytes>(stream)) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "h2mux handshake timed out"))?.map_err(io::Error::other)?,
    };
    let mut jobs = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = crate::cancelled(&mut cancel) => { connection.abrupt_shutdown(h2::Reason::NO_ERROR); break Ok(()); },
            job = jobs.join_next(), if !jobs.is_empty() => { if let Some(Err(err)) = job && !err.is_cancelled() { break Err(io::Error::other(err)); } },
            incoming = connection.accept() => match incoming {
                Some(Ok((request, mut response))) => {
                    if jobs.len() >= config.max_sessions { response.send_reset(h2::Reason::REFUSED_STREAM); continue; }
                    let session_permit = match listener_budget.session() { Ok(permit) => permit, Err(_) => { response.send_reset(h2::Reason::REFUSED_STREAM); continue; } };
                    let host = host.clone(); let user = user.clone(); let config = config.clone();
                    jobs.spawn(async move { let _session_permit = session_permit; handle_stream(request, response, user, peer, host, config).await });
                },
                Some(Err(err)) => break Err(io::Error::other(err)),
                None => break Ok(()),
            },
        }
    };
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    result
}
async fn handle_stream(
    request: http::Request<h2::RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
    user: User,
    peer: SocketAddr,
    host: Arc<dyn Host>,
    config: crate::Config,
) -> io::Result<()> {
    let head = http::Response::builder()
        .status(200)
        .body(())
        .map_err(io::Error::other)?;
    let send = response
        .send_response(head, false)
        .map_err(io::Error::other)?;
    let budget = config
        .shared_budget
        .bind(config.max_queued_bytes, config.max_sessions)?;
    let stream = H2MuxStream::new(
        send,
        request.into_body(),
        config.max_frame.min(16384),
        budget.bytes,
    );
    super::handle_payload(
        Box::new(stream),
        crate::SessionContext {
            user,
            peer,
            host,
            config,
        },
    )
    .await
}
