use node_core::{NodeSpec, RuntimeState};
use node_panel::{Auth, ControlPlaneReducer, ReduceResult, WsClient, WsClientError, WsEvent};
use std::time::Duration;

#[test]
fn websocket_rejects_prepopulated_query_and_fragment() {
    for base in [
        "wss://example.org/ws?token=stale",
        "wss://example.org/ws#fragment",
        "wss://example.org/ws?x=1",
    ] {
        assert!(matches!(
            WsClient::new(
                base,
                Auth::machine("placeholder", 2, 7),
                Duration::from_millis(1),
                Duration::from_secs(1)
            ),
            Err(WsClientError::InsecureUrl)
        ));
    }
}

#[test]
fn machine_reducer_rejects_untagged_events() {
    let runtime = RuntimeState::new(NodeSpec::new("vless", 443), vec![]).unwrap();
    let mut reducer = ControlPlaneReducer::new(runtime, Some(7));
    assert_eq!(
        reducer.apply(
            1,
            WsEvent::Config {
                node_id: None,
                config: Box::new(NodeSpec::new("trojan", 8443))
            },
            |_| panic!("untagged event must not reach kernel")
        ),
        Ok(ReduceResult::Ignored)
    );
    assert_eq!(reducer.last_sequence(), 0);
    assert_eq!(reducer.runtime().applied().config.server_port, 443);
}
