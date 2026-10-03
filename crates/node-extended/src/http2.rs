//! HTTP/2 DATA transport with one owned driver and bounded logical streams.
use async_trait::async_trait;
use bytes::Bytes;
use node_session::BoxStream;
use std::{io, sync::Arc};
use tokio::{sync::watch, task::JoinSet};

#[async_trait]
pub trait StreamHandler: Send + Sync {
    async fn serve(&self, stream: BoxStream) -> io::Result<()>;
}
#[derive(Clone, Debug, Default)]
pub struct Http2Config {
    pub path: Option<String>,
    pub hosts: Vec<String>,
    pub method: Option<String>,
}
#[derive(Clone)]
pub(crate) enum Mode {
    Http(Http2Config),
    Grpc(crate::grpc::GrpcConfig),
}

pub async fn serve(
    stream: BoxStream,
    transport: Http2Config,
    handler: Arc<dyn StreamHandler>,
    config: crate::Config,
    cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    serve_mode(stream, Mode::Http(transport), handler, config, cancel).await
}
pub(crate) async fn serve_mode(
    stream: BoxStream,
    mode: Mode,
    handler: Arc<dyn StreamHandler>,
    config: crate::Config,
    mut cancel: Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    config.validate()?;
    let budget = config
        .shared_budget
        .bind(config.max_queued_bytes, config.max_sessions)?;
    let _receive = budget.reserve_receive_window(65535, config.max_frame.min(16384))?;
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(config.max_frame.min(65535) as u32)
        .initial_connection_window_size(65535)
        .max_concurrent_streams(config.max_sessions as u32)
        .max_header_list_size(16384)
        .max_send_buffer_size(16384);
    let mut connection = tokio::select! {
        _ = crate::cancelled(&mut cancel) => return Ok(()),
        result = tokio::time::timeout(config.handshake_timeout,builder.handshake::<_,Bytes>(stream)) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut,"HTTP/2 handshake timed out"))?.map_err(io::Error::other)?,
    };
    let mut jobs = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = crate::cancelled(&mut cancel) => { connection.abrupt_shutdown(h2::Reason::NO_ERROR); break Ok(()); },
            job = jobs.join_next(), if !jobs.is_empty() => { if let Some(Err(error))=job && !error.is_cancelled() {break Err(io::Error::other(error));} },
            incoming = connection.accept() => match incoming {
                Some(Ok((request,mut response))) => {
                    if !valid_request(&request,&mode) {
                        let head=match http::Response::builder().status(404).body(()) {Ok(head)=>head,Err(error)=>break Err(io::Error::other(error))};
                        if let Err(error)=response.send_response(head,true) {break Err(io::Error::other(error));} continue;
                    }
                    let session = match budget.session() {Ok(permit)=>permit,Err(_)=>{response.send_reset(h2::Reason::REFUSED_STREAM);continue;}};
                    let handler=handler.clone(); let config=config.clone(); let mode=mode.clone(); let byte_budget=budget.bytes.clone();
                    jobs.spawn(async move {
                        let _session=session;
                        let mut head=http::Response::builder().status(200).header("cache-control","no-store");
                        if matches!(mode,Mode::Grpc(_)) {head=head.header("content-type","application/grpc").header("trailer","grpc-status");}
                        let send=response.send_response(head.body(()).map_err(io::Error::other)?,false).map_err(io::Error::other)?;
                        let stream=crate::mux::h2mux::H2MuxStream::new(send,request.into_body(),config.max_frame.min(16384),byte_budget.clone());
                        let stream:BoxStream=match mode {Mode::Http(_)=>Box::new(stream),Mode::Grpc(_)=>crate::grpc::wrap(Box::new(stream.with_grpc_trailers()),config.max_frame,byte_budget)};
                        handler.serve(stream).await
                    });
                },
                Some(Err(error)) => break Err(io::Error::other(error)),
                None => break Ok(()),
            }
        }
    };
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    result
}
fn valid_request(request: &http::Request<h2::RecvStream>, mode: &Mode) -> bool {
    match mode {
        Mode::Http(config) => {
            config
                .path
                .as_deref()
                .is_none_or(|path| request.uri().path().starts_with(path))
                && config
                    .method
                    .as_deref()
                    .is_none_or(|method| request.method().as_str() == method)
                && (config.hosts.is_empty()
                    || request.uri().authority().is_some_and(|authority| {
                        config.hosts.iter().any(|host| host == authority.as_str())
                    }))
        }
        Mode::Grpc(config) => {
            request.method() == http::Method::POST
                && request.uri().path() == format!("/{}/Tun", config.service_name)
                && request
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.starts_with("application/grpc"))
        }
    }
}
