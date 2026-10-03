//! Multiplexed payload sessions over already-authenticated streams.
pub mod h2mux;
mod stream_mux;
pub(crate) mod uot;
pub mod xudp;
pub use xudp::serve_plugin_mux;
pub const MUX_HOST: &str = "sp.mux.sing-box.arpa";
pub const MUX_PORT: u16 = 444;
pub use h2mux::serve as serve_h2mux;
/// The shared Sing multiplex negotiation accepts H2MUX, SMUX v1 and YAMUX.
pub use h2mux::serve as serve_mux;
pub use xudp::serve as serve_xudp;

pub(crate) async fn handle_payload(
    mut stream: node_session::BoxStream,
    context: crate::SessionContext,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let crate::SessionContext {
        user,
        peer,
        host,
        config,
    } = context;
    let deadline = tokio::time::Instant::now() + config.handshake_timeout;
    enum Admission {
        Tcp(node_session::BoxStream),
        Udp(std::sync::Arc<dyn node_session::Datagram>, uot::Mode),
    }
    let admitted = tokio::time::timeout_at(deadline, async {
        let request = h2mux::h2mux_protocol::StreamRequest::decode_async(&mut stream).await?;
        let admission = if request.is_udp() {
            let datagram = host.datagram(&user, peer).await?;
            let mode = if request.packet_addr {
                uot::Mode::SocksAddress
            } else {
                uot::Mode::Connected(request.destination.destination()?)
            };
            Admission::Udp(datagram, mode)
        } else {
            if request.packet_addr {
                return Err(crate::invalid("mux packet addressing on TCP"));
            }
            Admission::Tcp(
                host.connect(&user, peer, &request.destination.destination()?)
                    .await?,
            )
        };
        stream.write_all(&[0]).await?;
        stream.flush().await?;
        Ok::<_, std::io::Error>(admission)
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "mux stream admission timed out",
        )
    })?;
    match admitted {
        Ok(Admission::Tcp(remote)) => node_session::relay(stream, remote).await,
        Ok(Admission::Udp(datagram, mode)) => {
            uot::relay(stream, datagram, mode, config.max_frame).await
        }
        Err(error) => {
            let _ =
                tokio::time::timeout_at(deadline, stream.write_all(b"\x01\x10admission failed"))
                    .await;
            Err(error)
        }
    }
}
