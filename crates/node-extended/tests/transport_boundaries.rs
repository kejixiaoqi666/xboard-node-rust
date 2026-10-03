use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[tokio::test]
async fn websocket_accepts_matching_host_and_rejects_other_hosts_before_protocol() {
    for (host, accepted) in [("example.test", true), ("other.test", false)] {
        let (server, client) = tokio::io::duplex(8192);
        let task = tokio::spawn(node_extended::websocket::accept(
            Box::new(server),
            node_extended::websocket::WebSocketConfig {
                host: Some("example.test".into()),
                ..Default::default()
            },
        ));
        let request = format!("ws://{host}/proxy").into_client_request().unwrap();
        let response = tokio_tungstenite::client_async(request, client).await;
        assert_eq!(response.is_ok(), accepted);
        assert_eq!(task.await.unwrap().is_ok(), accepted);
    }
}
#[tokio::test]
async fn grpc_split_headers_and_payload_do_not_count_frame_bytes_as_application() {
    struct Echo;
    #[async_trait::async_trait]
    impl node_extended::http2::StreamHandler for Echo {
        async fn serve(&self, mut stream: node_session::BoxStream) -> std::io::Result<()> {
            let mut payload = [0; 7];
            stream.read_exact(&mut payload).await?;
            assert_eq!(&payload, b"payload");
            stream.write_all(&payload).await?;
            stream.shutdown().await
        }
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, client) = tokio::io::duplex(65536);
        let config = node_extended::Config::default();
        let budget = config.shared_budget.clone();
        let (stop, rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(node_extended::grpc::serve(
            Box::new(server),
            node_extended::grpc::GrpcConfig::default(),
            Arc::new(Echo),
            config,
            Some(rx),
        ));
        let (mut client, driver) = h2::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(driver);
        let request = http::Request::builder()
            .method("POST")
            .uri("http://example.test/TunService/Tun")
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let (response, mut send) = client.send_request(request, false).unwrap();
        let wire = b"\0\0\0\0\x09\x0a\x07payload";
        for &byte in wire {
            send.send_data(bytes::Bytes::copy_from_slice(&[byte]), false)
                .unwrap();
        }
        send.send_data(bytes::Bytes::new(), true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let mut receive = response.into_body();
        let mut returned = Vec::new();
        while let Some(data) = receive.data().await {
            let data = data.unwrap();
            returned.extend_from_slice(&data);
            receive.flow_control().release_capacity(data.len()).unwrap();
        }
        assert_eq!(returned, wire);
        assert_eq!(
            receive.trailers().await.unwrap().unwrap()["grpc-status"],
            "0"
        );
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
        driver.abort();
        let _ = driver.await;
        assert_eq!(budget.available_bytes(), Some(8 * 1024 * 1024));
        assert_eq!(budget.available_sessions(), Some(1024));
    })
    .await
    .unwrap();
}
