use node_panel::{Auth, Fetch, Panel, PanelError, Report, ResourceUse, User};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn serve_once(response: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let read = stream.read(&mut buf).await.unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..read]);
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&bytes[..end]);
                let len: usize = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + len {
                    break;
                }
            }
        }
        stream.write_all(response.as_bytes()).await.unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (format!("http://{addr}"), handle)
}

fn auth() -> Auth {
    Auth::machine("test-secret", 42, 7)
}

#[tokio::test]
async fn handshake_is_post_with_body_auth_and_no_url_secret() {
    let (base, request) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 89\r\nConnection: close\r\n\r\n{\"websocket\":{\"enabled\":true,\"ws_url\":\"wss://example/ws\"},\"settings\":{\"push_interval\":5}}" ).await;
    let panel = Panel::new_for_test(&base, auth()).unwrap();
    let result = panel.handshake().await.unwrap();
    assert!(result.websocket.enabled);
    let req = request.await.unwrap();
    assert!(req.starts_with("POST /api/v2/server/handshake HTTP/1.1"));
    assert!(!req.lines().next().unwrap().contains("test-secret"));
    assert!(req.contains("\"token\":\"test-secret\""));
    assert!(req.contains("\"machine_id\":42"));
    assert!(req.contains("\"node_id\":7"));
}

#[tokio::test]
async fn report_shape_matches_go_and_http_error_does_not_echo_secret() {
    let (base, request) = serve_once(
        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"data\":true}",
    )
    .await;
    let panel = Panel::new_for_test(&base, auth()).unwrap();
    let mut traffic = BTreeMap::new();
    traffic.insert(9, [12, 34]);
    panel
        .report(Report {
            traffic,
            alive: BTreeMap::new(),
            online: BTreeMap::new(),
            cpu: 1.5,
            mem: ResourceUse {
                total: 100,
                used: 25,
            },
            swap: ResourceUse {
                total: 200,
                used: 0,
            },
            disk: ResourceUse {
                total: 300,
                used: 3,
            },
            metrics: BTreeMap::new(),
        })
        .await
        .unwrap();
    let raw = request.await.unwrap();
    assert!(raw.starts_with("POST /api/v2/server/report HTTP/1.1"));
    let payload: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(
        payload,
        json!({"token":"test-secret", "machine_id":42, "node_id":7,
        "traffic":{"9":[12,34]}, "status":{"cpu":1.5,"mem":{"total":100,"used":25},
        "swap":{"total":200,"used":0},"disk":{"total":300,"used":3}}})
    );
}

#[tokio::test]
async fn etag_304_and_malformed_data_preserve_cache() {
    let (base, req) = serve_once("HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Length: 50\r\nConnection: close\r\n\r\n{\"users\":[{\"id\":9,\"uuid\":\"good\",\"speed_limit\":4}]}" ).await;
    let mut panel = Panel::new_for_test(&base, auth()).unwrap();
    assert!(matches!(panel.users().await.unwrap(), Fetch::Modified(_)));
    req.await.unwrap();
    assert_eq!(panel.user_etag(), None);
    panel.accept_users();
    assert_eq!(panel.user_etag(), Some("\"v1\""));
    let (base, req) =
        serve_once("HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    panel.set_test_base(&base);
    assert!(matches!(panel.users().await.unwrap(), Fetch::NotModified));
    assert!(req.await.unwrap().contains("if-none-match: \"v1\""));
    let (base, req) = serve_once("HTTP/1.1 200 OK\r\nETag: \"bad\"\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"users\":1}" ).await;
    panel.set_test_base(&base);
    assert!(panel.users().await.is_err());
    req.await.unwrap();
    assert_eq!(panel.user_etag(), Some("\"v1\""));
}

#[tokio::test]
async fn oversize_and_secret_error_body_are_rejected_safely() {
    let (base, req) = serve_once("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 30\r\nConnection: close\r\n\r\ntest-secret-should-not-be-logged" ).await;
    let mut panel = Panel::new_for_test(&base, auth()).unwrap();
    let err = panel.users().await.unwrap_err();
    assert!(!err.to_string().contains("test-secret"));
    req.await.unwrap();
    let (base, req) =
        serve_once("HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\nConnection: close\r\n\r\n{}")
            .await;
    panel.set_test_base(&base);
    assert!(matches!(
        panel.users().await.unwrap_err(),
        PanelError::TooLarge
    ));
    req.await.unwrap();
}

#[test]
fn users_reject_unknown_fields_to_avoid_dropping_limits() {
    assert!(serde_json::from_str::<User>(r#"{"id":1,"uuid":"x","new_limit":1}"#).is_err());
}

#[test]
fn production_requires_https() {
    assert!(Panel::new("http://example.com", auth()).is_err());
    assert!(Panel::new("https://example.com", auth()).is_ok());
    assert!(Panel::new("https://example.com/prefix", auth()).is_err());
    assert!(Panel::new_for_test("http://example.com", auth()).is_err());
}

#[tokio::test]
async fn traffic_ack_failure_and_connection_failure_have_distinct_retry_semantics() {
    use node_panel::ReportOutcome;
    let traffic = BTreeMap::from([(100, [17, 31])]);
    for (response, expected) in [
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"data\":true}",
            ReportOutcome::Acknowledged,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{\"data\":false}",
            ReportOutcome::Uncertain,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\n<html>login</html>",
            ReportOutcome::Uncertain,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            ReportOutcome::Uncertain,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{\"error\":true}",
            ReportOutcome::Uncertain,
        ),
        // Server may already have committed the traffic before closing/erroring.
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n{}",
            ReportOutcome::Uncertain,
        ),
        (
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ReportOutcome::Uncertain,
        ),
        ("", ReportOutcome::Uncertain),
    ] {
        let (base, captured) = serve_once(response).await;
        let panel = Panel::new_for_test(&base, auth()).unwrap();
        assert!(!panel.traffic_identity().contains("test-secret"));
        assert_eq!(panel.report_traffic(&traffic).await, expected);
        let raw = captured.await.unwrap();
        assert!(raw.starts_with("POST /api/v2/server/report HTTP/1.1"));
        let payload: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(
            payload,
            json!({"token":"test-secret","machine_id":42,"node_id":7,"traffic":{"100":[17,31]}})
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let panel = Panel::new_for_test(&base, auth()).unwrap();
    assert_eq!(panel.report_traffic(&traffic).await, ReportOutcome::NotSent);
}

#[tokio::test]
async fn handshake_allows_legacy_empty_settings_array() {
    let (base, request) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 45\r\nConnection: close\r\n\r\n{\"websocket\":{\"enabled\":false},\"settings\":[]}").await;
    let panel = Panel::new_for_test(&base, auth()).unwrap();
    let handshake = panel.handshake().await.unwrap();
    assert!(!handshake.websocket.enabled);
    assert_eq!(handshake.settings, serde_json::json!({}));
    request.await.unwrap();
}
