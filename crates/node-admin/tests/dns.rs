use node_admin::{
    Secret,
    dns::{CloudflareProvider, DnsProvider, DnsRecord},
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn fake_api(
    responses: Vec<serde_json::Value>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                data.extend_from_slice(&chunk[..n]);
                assert!(data.len() < 65536);
                if let Some(header_end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&data[..header_end]).unwrap();
                    let length = headers
                        .split("\r\n")
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|value| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if data.len() >= header_end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(data).unwrap());
            let body = response.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
        requests
    });
    (format!("http://{address}/client/v4/"), handle)
}
#[tokio::test]
async fn cloudflare_zone_discovery_adds_only_challenge_txt_and_cleans_only_owned_record_id() {
    let (endpoint, api) = fake_api(vec![
        json!({"success":true,"result":[]}),
        json!({"success":true,"result":[{"id":"zone-example"}]}),
        json!({"success":true,"result":{"id":"record-owned"}}),
        json!({"success":true,"result":{"id":"record-owned"}}),
    ])
    .await;
    let provider =
        CloudflareProvider::with_endpoint(Secret::new("fixture-token"), None, &endpoint).unwrap();
    let record = DnsRecord {
        name: "_acme-challenge.node.example.test".into(),
        value: "A".repeat(43),
    };
    let lease = provider.present(&record).await.unwrap();
    assert_eq!(lease.zone_id, "zone-example");
    assert_eq!(lease.record_id, "record-owned");
    provider.cleanup(&lease).await.unwrap();
    let requests = api.await.unwrap();
    assert!(requests[0].starts_with("GET /client/v4/zones?name=node.example.test"));
    assert!(requests[1].starts_with("GET /client/v4/zones?name=example.test"));
    assert!(requests[2].starts_with("POST /client/v4/zones/zone-example/dns_records "));
    assert!(requests[2].contains("\"type\":\"TXT\""));
    assert!(requests[2].contains(&record.name));
    assert!(
        requests[3].starts_with("DELETE /client/v4/zones/zone-example/dns_records/record-owned ")
    );
    assert!(requests.iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token")
    }));
}
#[tokio::test]
async fn cloudflare_api_error_body_is_never_forwarded_to_logs_or_errors() {
    let (endpoint,api)=fake_api(vec![json!({"success":false,"result":null,"errors":[{"message":"fixture-secret credential rejected"}]})]).await;
    let provider = CloudflareProvider::with_endpoint(
        Secret::new("fixture-secret"),
        Some("known-zone".into()),
        &endpoint,
    )
    .unwrap();
    let error = provider
        .present(&DnsRecord {
            name: "_acme-challenge.node.example.test".into(),
            value: "A".repeat(43),
        })
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("fixture-secret"));
    api.await.unwrap();
}
