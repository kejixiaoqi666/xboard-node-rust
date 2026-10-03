use node_runtime::{RuntimeConfig, RuntimeMetrics, administration::PreparedNode, health_fleet};
use serde_json::{Value, json};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

fn node(instance: &str, id: u32, port: u16) -> PreparedNode {
    let runtime_json = json!({
        "panel_url":"https://panel.invalid", "token_env":"HEALTH_FIXTURE_TOKEN",
        "node_id":id, "node_type":"vless",
        "state_dir":std::env::temp_dir().join(format!("health-fixture-{id}")),
    });
    let runtime: RuntimeConfig = serde_json::from_value(runtime_json.clone()).unwrap();
    let mut prepared = PreparedNode::simple(runtime);
    prepared.settings = Some(
        serde_json::from_value(json!({
            "instance_id":instance,"id":format!("health-node-{id}"),"runtime":runtime_json,
            "intervals":{},"websocket":{},"kernel":{},"log":{},"cert":{},
            "standalone":null,"health_port":port,
        }))
        .unwrap(),
    );
    prepared
}

async fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn request(port: u16, path: &str) -> Option<(u16, Value)> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .ok()?;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.ok()?;
        let response = std::str::from_utf8(&bytes).ok()?;
        let (headers, body) = response.split_once("\r\n\r\n")?;
        let status = headers.split_whitespace().nth(1)?.parse().ok()?;
        Some((status, serde_json::from_str(body).ok()?))
    })
    .await
    .ok()
    .flatten()
}

async fn wait_response(port: u16, path: &str, matches: impl Fn(u16, &Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if let Some((status, body)) = request(port, path).await
                && matches(status, &body)
            {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("health endpoint did not reach the expected state")
}

#[test]
fn shared_port_requires_one_instance_and_unique_metric_ids() {
    let mut nodes = vec![
        node("instance-a", 7, 32001),
        node("instance-a", 8, 32001),
        node("instance-b", 7, 32002),
    ];
    health_fleet::validate(&nodes).unwrap();
    let groups = health_fleet::prepare(&mut nodes);
    assert_eq!(
        groups.iter().map(|group| group.port).collect::<Vec<_>>(),
        vec![32001, 32002]
    );
    assert!(
        nodes
            .iter()
            .all(|node| node.settings.as_ref().unwrap().health_port == 0)
    );
    assert!(health_fleet::prepare(&mut nodes).is_empty());

    let different_instances = [node("instance-a", 7, 32001), node("instance-b", 8, 32001)];
    assert!(
        health_fleet::validate(&different_instances)
            .unwrap_err()
            .to_string()
            .contains("different instances")
    );
    let repeated_id = [node("instance-a", 7, 32001), node("instance-a", 7, 32001)];
    assert!(
        health_fleet::validate(&repeated_id)
            .unwrap_err()
            .to_string()
            .contains("duplicate node ID")
    );
    assert!(health_fleet::validate(&[node("", 7, 32001)]).is_err());
    let mut disabled = [node("instance-a", 7, 0), node("instance-b", 7, 0)];
    health_fleet::validate(&disabled).unwrap();
    assert!(health_fleet::prepare(&mut disabled).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_aggregates_live_nodes_and_releases_port_on_shutdown() {
    let port = free_port().await;
    let mut nodes = [node("instance-a", 7, port), node("instance-a", 8, port)];
    let first = Arc::clone(&nodes[0].health);
    let second = Arc::clone(&nodes[1].health);
    first.update(
        true,
        &RuntimeMetrics {
            sync_attempts: 3,
            applied: 2,
            traffic_reports: 1,
            ..Default::default()
        },
        Some(4),
    );
    second.update(
        true,
        &RuntimeMetrics {
            sync_attempts: 5,
            applied: 4,
            traffic_reports: 2,
            ..Default::default()
        },
        Some(7),
    );
    health_fleet::validate(&nodes).unwrap();
    let group = health_fleet::prepare(&mut nodes).pop().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(group.run(rx));

    wait_response(port, "/healthz", |status, body| {
        status == 200 && body["ready"] == true
    })
    .await;
    let metrics = wait_response(port, "/metrics", |status, body| {
        status == 200 && body["nodes"] == 2
    })
    .await;
    assert_eq!(metrics["ready_nodes"], 2);
    assert_eq!(metrics["desired_nodes"], 2);
    assert_eq!(metrics["rejected_nodes"], 0);
    assert_eq!(metrics["sessions"], 11);
    assert_eq!(metrics["metrics"]["sync_attempts"], 8);
    assert_eq!(metrics["metrics"]["applied"], 6);
    assert_eq!(metrics["metrics"]["traffic_reports"], 3);
    assert_eq!(metrics["node_metrics"]["7"]["applied"], 2);
    assert_eq!(metrics["node_metrics"]["8"]["applied"], 4);
    assert_eq!(metrics["node_metrics"].as_object().unwrap().len(), 2);

    second.update(
        false,
        &RuntimeMetrics {
            sync_attempts: 9,
            failed: 1,
            ..Default::default()
        },
        Some(1),
    );
    wait_response(port, "/healthz", |status, body| {
        status == 503 && body["ready"] == false
    })
    .await;
    let metrics = wait_response(port, "/metrics", |status, body| {
        status == 200 && body["ready_nodes"] == 1
    })
    .await;
    assert_eq!(metrics["sessions"], 5);
    assert_eq!(metrics["metrics"]["sync_attempts"], 12);
    assert_eq!(metrics["node_metrics"]["8"]["failed"], 1);

    second.update(true, &RuntimeMetrics::default(), Some(0));
    wait_response(port, "/healthz", |status, _| status == 200).await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("shutdown must release the health port");
    drop(rebound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_stop_channel_and_aborted_owner_release_the_listener() {
    for abort in [false, true] {
        let port = free_port().await;
        let mut nodes = [node("instance-a", 7, port)];
        nodes[0]
            .health
            .update(true, &RuntimeMetrics::default(), Some(0));
        let group = health_fleet::prepare(&mut nodes).pop().unwrap();
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(group.run(rx));
        wait_response(port, "/healthz", |status, _| status == 200).await;
        if abort {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            drop(stop);
            tokio::time::timeout(Duration::from_secs(4), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        // An aborted Server task releases its socket when the executor processes
        // cancellation. Bound the observation instead of assuming synchronous drop.
        let rebound = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                    break listener;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled owner must release the health port");
        drop(rebound);
    }
}

#[tokio::test]
async fn direct_preparation_still_rejects_conflicts_before_listening() {
    let port = free_port().await;
    for mut nodes in [
        vec![node("instance-a", 7, port), node("instance-a", 7, port)],
        vec![node("instance-a", 7, port), node("instance-b", 8, port)],
    ] {
        let group = health_fleet::prepare(&mut nodes).pop().unwrap();
        let (_stop, rx) = watch::channel(false);
        assert!(group.run(rx).await.is_err());
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.is_ok());
    }
}
