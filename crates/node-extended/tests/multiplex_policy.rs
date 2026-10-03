mod support;
use node_extended::{Config, mux};
use node_session::Host;
use std::{
    io,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

#[tokio::test]
async fn disabled_mux_rejects_every_carrier_before_waiting_for_wire_data() {
    struct Handler;
    #[async_trait::async_trait]
    impl node_extended::http2::StreamHandler for Handler {
        async fn serve(&self, _: node_session::BoxStream) -> io::Result<()> {
            panic!("disabled plugin admitted a payload stream")
        }
    }
    let host = support::TestHost::new();
    let user = host.users()[0].clone();
    let config = Config {
        multiplex_enabled: false,
        ..Default::default()
    };
    // Keep each client half open and silent. A disabled listener must reject
    // immediately, rather than enter the mux negotiation or create workers.
    let (_client, server) = tokio::io::duplex(1024);
    let error = tokio::time::timeout(
        Duration::from_millis(100),
        mux::serve_h2mux(
            Box::new(server),
            user.clone(),
            support::peer(),
            host.clone(),
            config.clone(),
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    let (_client, server) = tokio::io::duplex(1024);
    let error = tokio::time::timeout(
        Duration::from_millis(100),
        mux::serve_xudp(
            Box::new(server),
            user,
            support::peer(),
            host.clone(),
            config.clone(),
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    let (_client, server) = tokio::io::duplex(1024);
    let error = tokio::time::timeout(
        Duration::from_millis(100),
        mux::serve_plugin_mux(Box::new(server), Arc::new(Handler), config.clone(), None),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(host.totals(), (0, 0));
    assert_eq!(host.active.load(Ordering::SeqCst), 0);
    assert_eq!(config.shared_budget.available_sessions(), None);
}
