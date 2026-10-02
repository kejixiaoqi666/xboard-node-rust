use node_panel::{Auth, WsBackoff, WsClient, WsClientError};
use std::time::Duration;

#[test]
fn websocket_url_requires_tls_and_never_places_token_in_path() {
    let client = WsClient::new(
        "wss://panel.example/ws",
        Auth::machine("secret", 2, 7),
        Duration::from_millis(10),
        Duration::from_secs(1),
    )
    .unwrap();
    let url = client.authenticated_url_for_test().unwrap();
    assert_eq!(url.scheme(), "wss");
    assert_eq!(url.path(), "/ws");
    assert!(url.query().unwrap().contains("token=secret"));
    assert!(!url.path().contains("secret"));
    assert!(matches!(
        WsClient::new(
            "ws://panel.example/ws",
            Auth::machine("secret", 2, 7),
            Duration::from_millis(10),
            Duration::from_secs(1)
        ),
        Err(WsClientError::InsecureUrl)
    ));
}

#[test]
fn websocket_backoff_is_bounded_and_resets_after_stable_connection() {
    let mut backoff = WsBackoff::new(Duration::from_millis(100), Duration::from_secs(1));
    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    assert_eq!(backoff.next_delay(), Duration::from_millis(200));
    assert_eq!(backoff.next_delay(), Duration::from_millis(400));
    assert_eq!(backoff.next_delay(), Duration::from_millis(800));
    assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    backoff.reset();
    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
}
