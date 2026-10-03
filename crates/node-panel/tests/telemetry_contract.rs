//! HTTP contracts from the captured current Flash source, not client round trips.
//! Source: xbord-node-v3/.Codex/evidence/full-parity-20261003/flash-current-source.json
//! SHA256: 166cb98900ec8bdde40b41ef1163c197bb194ef4a1412fb51129bb15f73abca9
//! UniProxyController push/alive/status; V2 ServerController report;
//! MachineController nodes/status; ServerService processAlive/processOnline.
use node_core::ActivitySnapshot;
use node_panel::{Auth, Panel, PanelError, Report, ReportOutcome, ResourceUse};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const TOKEN: &str = "contract fixture +& only";
const LIMIT: usize = 64 * 1024;

#[derive(Debug)]
struct Request {
    target: String,
    body: Value,
    content_type: String,
}

#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
}
impl Reply {
    fn json(body: Value) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
        }
    }
    fn raw(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
}

struct Server {
    base: String,
    task: Option<JoinHandle<Vec<Request>>>,
}
impl Server {
    async fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::with_capacity(replies.len());
            for reply in replies {
                let (mut stream, _) = timeout(Duration::from_secs(3), listener.accept())
                    .await
                    .expect("panel did not send the expected HTTP request")
                    .unwrap();
                requests.push(
                    timeout(Duration::from_secs(3), request(&mut stream))
                        .await
                        .expect("incomplete HTTP request"),
                );
                let response = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    reply.status,
                    reply.body.len(),
                    reply.body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            requests
        });
        Self {
            base,
            task: Some(task),
        }
    }
    fn panel(&self, machine: bool) -> Panel {
        let auth = if machine {
            Auth::machine(TOKEN, 42, 7)
        } else {
            Auth::legacy(TOKEN, 7, "vless")
        };
        Panel::new_for_test(&self.base, auth).unwrap()
    }
    async fn finish(mut self) -> Vec<Request> {
        timeout(Duration::from_secs(3), self.task.take().unwrap())
            .await
            .expect("HTTP fixture did not stop")
            .unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn request(stream: &mut TcpStream) -> Request {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 2048];
    let (head_end, length) = loop {
        let count = stream.read(&mut buffer).await.unwrap();
        assert_ne!(count, 0, "closed before HTTP headers");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(
            bytes.len() <= LIMIT,
            "fixture request exceeds bounded storage"
        );
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&bytes[..end]).unwrap();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .expect("POST must have Content-Length");
            assert!(end + 4 + length <= LIMIT);
            break (end, length);
        }
    };
    while bytes.len() < head_end + 4 + length {
        let count = stream.read(&mut buffer).await.unwrap();
        assert_ne!(count, 0, "closed before JSON body");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= LIMIT);
    }
    let head = std::str::from_utf8(&bytes[..head_end]).unwrap();
    let mut line = head.lines().next().unwrap().split_whitespace();
    assert_eq!(line.next(), Some("POST"));
    let target = line.next().unwrap().to_owned();
    assert_eq!(line.next(), Some("HTTP/1.1"));
    let content_type = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_owned())
        })
        .unwrap();
    Request {
        target,
        body: serde_json::from_slice(&bytes[head_end + 4..head_end + 4 + length]).unwrap(),
        content_type,
    }
}

fn legacy_request(request: &Request, path: &str, body: Value) {
    let url = reqwest::Url::parse(&format!("http://fixture{}", request.target)).unwrap();
    assert_eq!(url.path(), path);
    let query: BTreeMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    assert_eq!(
        query,
        BTreeMap::from([
            ("token".into(), TOKEN.into()),
            ("node_id".into(), "7".into()),
            ("node_type".into(), "vless".into()),
        ])
    );
    assert_eq!(request.content_type, "application/json");
    assert_eq!(request.body, body);
}

fn machine_request(request: &Request, path: &str, body: Value) {
    assert_eq!(request.target, path, "machine credentials belong in JSON");
    assert_eq!(request.content_type, "application/json");
    let mut expected = body.as_object().unwrap().clone();
    expected.extend([
        ("token".into(), json!(TOKEN)),
        ("machine_id".into(), json!(42)),
        ("node_id".into(), json!(7)),
    ]);
    assert_eq!(request.body, Value::Object(expected));
}

fn activity() -> ActivitySnapshot {
    ActivitySnapshot {
        alive: BTreeMap::from([
            (7, vec!["192.0.2.7".into(), "2001:db8::7".into()]),
            (9, vec![]),
        ]),
        // processOnline stores logical connections, not the number of IPs.
        online: BTreeMap::from([(7, 5), (9, 0)]),
        sessions: 5,
    }
}
fn status() -> Value {
    json!({"cpu":12.5,"mem":{"total":8192,"used":2048},
        "swap":{"total":4096,"used":0},"disk":{"total":65536,"used":16384}})
}
fn metrics() -> Value {
    json!({"uptime":123,"active_connections":5,"total_users":2,"active_users":1,
        "inbound_speed":321,"outbound_speed":654,"kernel_status":true})
}
fn report() -> Report {
    Report {
        traffic: BTreeMap::from([(7, [123, 456])]),
        alive: activity().alive,
        online: activity().online,
        cpu: 12.5,
        mem: ResourceUse {
            total: 8192,
            used: 2048,
        },
        swap: ResourceUse {
            total: 4096,
            used: 0,
        },
        disk: ResourceUse {
            total: 65536,
            used: 16384,
        },
        metrics: serde_json::from_value(metrics()).unwrap(),
    }
}

#[tokio::test]
async fn legacy_push_has_raw_user_traffic_map_and_query_auth() {
    let server = Server::start(vec![Reply::json(
        json!({"data":true,"code":0,"message":"success"}),
    )])
    .await;
    let traffic = BTreeMap::from([(7, [123, 456]), (9, [0, 8192])]);
    assert_eq!(
        server.panel(false).report_traffic(&traffic).await,
        ReportOutcome::Acknowledged
    );
    let requests = server.finish().await;
    legacy_request(
        &requests[0],
        "/api/v1/server/UniProxy/push",
        json!({"7":[123,456],"9":[0,8192]}),
    );
}

#[tokio::test]
async fn legacy_alive_sends_distinct_ip_map_including_departed_user_zero_row() {
    let server = Server::start(vec![Reply::json(json!({"data":true}))]).await;
    server
        .panel(false)
        .report_activity(&activity())
        .await
        .unwrap();
    let requests = server.finish().await;
    legacy_request(
        &requests[0],
        "/api/v1/server/UniProxy/alive",
        json!({"7":["192.0.2.7","2001:db8::7"],"9":[]}),
    );
}

#[tokio::test]
async fn legacy_status_uses_raw_resource_body_and_current_success_envelope() {
    let server = Server::start(vec![Reply::json(
        json!({"data":true,"code":0,"message":"success"}),
    )])
    .await;
    server
        .panel(false)
        .report_status(status(), metrics())
        .await
        .unwrap();
    let requests = server.finish().await;
    legacy_request(&requests[0], "/api/v1/server/UniProxy/status", status());
}

#[tokio::test]
async fn machine_observations_keep_activity_status_metrics_and_body_auth() {
    let server = Server::start(vec![Reply::json(json!({"data":true}))]).await;
    server
        .panel(true)
        .report_observations(&activity(), status(), metrics())
        .await
        .unwrap();
    let requests = server.finish().await;
    machine_request(
        &requests[0],
        "/api/v2/server/report",
        json!({
            "alive":{"7":["192.0.2.7","2001:db8::7"],"9":[]},
            "online":{"7":5,"9":0},"status":status(),"metrics":metrics()
        }),
    );
}

#[tokio::test]
async fn machine_split_reports_preserve_clear_rows_without_fake_traffic() {
    let server = Server::start(vec![Reply::json(json!({"data":true})); 2]).await;
    let panel = server.panel(true);
    let cleared = ActivitySnapshot {
        alive: BTreeMap::from([(7, vec![]), (9, vec![])]),
        online: BTreeMap::from([(7, 0), (9, 0)]),
        sessions: 0,
    };
    panel.report_activity(&cleared).await.unwrap();
    panel.report_status(status(), metrics()).await.unwrap();
    let requests = server.finish().await;
    machine_request(
        &requests[0],
        "/api/v2/server/report",
        json!({"alive":{"7":[],"9":[]},"online":{"7":0,"9":0}}),
    );
    machine_request(
        &requests[1],
        "/api/v2/server/report",
        json!({"status":status(),"metrics":metrics()}),
    );
}

#[tokio::test]
async fn machine_nodes_reads_node_metadata_and_accepts_empty_inventory() {
    let server = Server::start(vec![
        Reply::json(
            json!({"nodes":[{"id":7,"type":"vless","name":"fixture one"},
            {"id":9,"type":"hysteria","name":"fixture two"}],
            "base_config":{"push_interval":15,"pull_interval":30}}),
        ),
        Reply::json(json!({"nodes":[],"base_config":{"push_interval":15,"pull_interval":30}})),
    ])
    .await;
    let panel = server.panel(true);
    let nodes = panel.machine_nodes().await.unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| (node.id, node.kind.as_str(), node.name.as_str()))
            .collect::<Vec<_>>(),
        [(7, "vless", "fixture one"), (9, "hysteria", "fixture two")]
    );
    assert!(panel.machine_nodes().await.unwrap().is_empty());
    for request in server.finish().await {
        machine_request(&request, "/api/v2/server/machine/nodes", json!({}));
    }
}

#[tokio::test]
async fn machine_status_is_machine_load_not_node_report_or_node_configuration() {
    let server = Server::start(vec![Reply::json(json!({"data":true})); 2]).await;
    let panel = server.panel(true);
    let mut machine_load = status();
    machine_load["net"] = json!({"in_speed":1234.5,"out_speed":6789.0});
    panel.machine_status(machine_load.clone()).await.unwrap();
    panel.report_status(status(), metrics()).await.unwrap();
    let requests = server.finish().await;
    machine_request(&requests[0], "/api/v2/server/machine/status", machine_load);
    machine_request(
        &requests[1],
        "/api/v2/server/report",
        json!({"status":status(),"metrics":metrics()}),
    );
    assert_ne!(requests[0].target, requests[1].target);
}

#[tokio::test]
async fn machine_only_apis_refuse_legacy_auth_before_network_io() {
    let panel = Panel::new_for_test("http://127.0.0.1:1", Auth::legacy(TOKEN, 7, "vless")).unwrap();
    assert!(matches!(panel.machine_nodes().await, Err(PanelError::Auth)));
    assert!(matches!(
        panel.machine_status(status()).await,
        Err(PanelError::Auth)
    ));
}

#[tokio::test]
async fn machine_nodes_refuses_invalid_inventory_and_server_rejection() {
    let replies = vec![
        Reply::json(json!({"data":{"nodes":[]}})),
        Reply::json(json!({"nodes":[{"id":0,"type":"vless"}]})),
        Reply::json(json!({"nodes":[{"id":7,"type":"vless"},{"id":7,"type":"tuic"}]})),
        Reply::json(json!({"nodes":[{"id":7,"type":""}]})),
        Reply::json(json!({"nodes":[{"id":"7","type":"vless"}]})),
        Reply::raw(403, "{\"message\":\"machine disabled\"}"),
    ];
    let server = Server::start(replies.clone()).await;
    let panel = server.panel(true);
    for _ in &replies {
        assert!(panel.machine_nodes().await.is_err());
    }
    assert_eq!(server.finish().await.len(), replies.len());
}

#[tokio::test]
async fn current_machine_combined_report_ack_is_checked_as_well_as_http_status() {
    let server = Server::start(vec![Reply::json(json!({"data":true}))]).await;
    server.panel(true).report(report()).await.unwrap();
    let requests = server.finish().await;
    machine_request(
        &requests[0],
        "/api/v2/server/report",
        json!({
            "traffic":{"7":[123,456]},"alive":{"7":["192.0.2.7","2001:db8::7"],"9":[]},
            "online":{"7":5,"9":0},"status":status(),"metrics":metrics()
        }),
    );
}

fn bad_acks() -> Vec<Reply> {
    vec![
        Reply::json(json!({})),
        Reply::json(json!({"data":false})),
        Reply::json(json!({"data":"true"})),
        Reply::json(json!({"data":true,"code":1})),
        Reply::json(json!({"data":true,"message":42})),
        Reply::json(json!({"data":true,"unexpected":"ambiguous"})),
        Reply::json(json!([{"data":true}])),
        Reply::raw(200, "<html>login</html>"),
        Reply::raw(204, ""),
        Reply::raw(503, "{\"data\":true}"),
    ]
}

#[tokio::test]
async fn bad_acks_never_mark_submitted_traffic_as_acknowledged() {
    for machine in [false, true] {
        let replies = bad_acks();
        let server = Server::start(replies.clone()).await;
        let panel = server.panel(machine);
        for reply in &replies {
            let outcome = panel
                .report_traffic(&BTreeMap::from([(7, [123, 456])]))
                .await;
            assert_eq!(
                outcome,
                ReportOutcome::Uncertain,
                "status={} body={}",
                reply.status,
                reply.body
            );
        }
        assert_eq!(
            server.finish().await.len(),
            replies.len(),
            "no retry of possibly billed traffic"
        );
    }
}

#[tokio::test]
async fn bad_acks_are_rejected_by_every_machine_telemetry_entry_point() {
    let replies = bad_acks();
    let server = Server::start(
        replies
            .iter()
            .flat_map(|reply| vec![reply.clone(); 5])
            .collect(),
    )
    .await;
    let panel = server.panel(true);
    let mut violations = Vec::new();
    for reply in &replies {
        let results = [
            panel.report_activity(&activity()).await,
            panel.report_status(status(), metrics()).await,
            panel.machine_status(status()).await,
            panel
                .report_observations(&activity(), status(), metrics())
                .await,
            panel.report(report()).await,
        ];
        for (name, result) in [
            "activity",
            "status",
            "machine_status",
            "observations",
            "report",
        ]
        .into_iter()
        .zip(results)
        {
            if result.is_ok() {
                violations.push(format!("{name}: HTTP {} {}", reply.status, reply.body));
            }
        }
    }
    assert_eq!(server.finish().await.len(), replies.len() * 5);
    assert!(
        violations.is_empty(),
        "bad ACK was accepted: {}",
        violations.join("; ")
    );
}

#[tokio::test]
async fn bad_acks_are_rejected_by_legacy_alive_and_status_entry_points() {
    let replies = bad_acks();
    let server = Server::start(
        replies
            .iter()
            .flat_map(|reply| vec![reply.clone(); 2])
            .collect(),
    )
    .await;
    let panel = server.panel(false);
    for reply in &replies {
        assert!(
            panel.report_activity(&activity()).await.is_err(),
            "alive accepted {}",
            reply.body
        );
        assert!(
            panel.report_status(status(), metrics()).await.is_err(),
            "status accepted {}",
            reply.body
        );
    }
    assert_eq!(server.finish().await.len(), replies.len() * 2);
}
