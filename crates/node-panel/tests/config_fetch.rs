use node_panel::{Auth, Fetch, Panel, PanelError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn serve(
    body: &str,
    status: &str,
    etag: Option<&str>,
) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nETag: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
        etag.unwrap_or("")
    );
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0_u8; 4096];
        let count = stream.read(&mut bytes).await.unwrap();
        stream.write_all(response.as_bytes()).await.unwrap();
        String::from_utf8_lossy(&bytes[..count]).into_owned()
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn config_fetch_follows_go_machine_path_and_conditional_etag() {
    let (base, first) = serve(
        r#"{"protocol":"vless","server_port":443}"#,
        "200 OK",
        Some("\"v1\""),
    )
    .await;
    let mut panel = Panel::new_for_test(&base, Auth::machine("placeholder", 42, 7)).unwrap();
    let Fetch::Modified(config) = panel.config().await.unwrap() else {
        panic!("expected config")
    };
    assert_eq!(config.server_port, 443);
    assert_eq!(panel.config_etag(), None);
    assert_eq!(panel.pending_config_etag(), Some("\"v1\""));
    panel.accept_config();
    assert_eq!(panel.config_etag(), Some("\"v1\""));
    let request = first.await.unwrap();
    assert!(request.starts_with("GET /api/v2/server/config?"));
    assert!(request.contains("machine_id=42"));
    let (base, second) = serve("", "304 Not Modified", None).await;
    panel.set_test_base(&base);
    assert!(matches!(panel.config().await.unwrap(), Fetch::NotModified));
    assert!(
        second
            .await
            .unwrap()
            .to_ascii_lowercase()
            .contains("if-none-match: \"v1\"")
    );
}

#[tokio::test]
async fn malformed_or_unknown_config_does_not_advance_etag() {
    let (base, first) = serve(
        r#"{"protocol":"vless","server_port":443}"#,
        "200 OK",
        Some("\"good\""),
    )
    .await;
    let mut panel = Panel::new_for_test(&base, Auth::legacy("placeholder", 7, "vless")).unwrap();
    assert!(matches!(panel.config().await.unwrap(), Fetch::Modified(_)));
    assert_eq!(panel.config_etag(), None);
    panel.accept_config();
    assert_eq!(panel.config_etag(), Some("\"good\""));
    assert!(
        first
            .await
            .unwrap()
            .starts_with("GET /api/v1/server/UniProxy/config?")
    );
    for body in [
        r#"{"protocol":"vless","server_port":443,"future_limit":1}"#,
        r#"{"protocol":"vless","server_port":0}"#,
    ] {
        let (base, req) = serve(body, "200 OK", Some("\"bad\"")).await;
        panel.set_test_base(&base);
        assert!(matches!(panel.config().await, Err(PanelError::Decode)));
        req.await.unwrap();
        assert_eq!(panel.config_etag(), Some("\"good\""));
    }
}
