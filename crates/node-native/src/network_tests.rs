use crate::{Error, network::Network, protocol::Address};
use node_core::routing::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn dns_hosts_are_pinned_to_routed_ip_and_never_re_resolved_for_connect() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let mut dns = DnsConfig::default();
    dns.hosts.insert(
        "Origin.TEST.".into(),
        vec!["127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap()],
    );
    let r = Route {
        rules: vec![Rule {
            outbound: "block".into(),
            ip_cidr: vec!["127.0.0.2/32".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let n = Network::new(
        &r,
        &[
            Outbound::plain("direct", "direct"),
            Outbound::plain("block", "block"),
        ],
        Some(&dns),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.unwrap();
        let mut b = [0; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"test");
        s.write_all(b"done").await.unwrap();
    });
    let mut stream = n
        .connect(
            &Address::Domain("origin.test".into()),
            port,
            "127.0.0.1:9000".parse().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stream.peer_addr().unwrap().ip().to_string(), "127.0.0.1");
    stream.write_all(b"test").await.unwrap();
    let mut response = [0; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"done");
    task.await.unwrap();
}

#[tokio::test]
async fn blocked_literal_and_dns_answer_do_not_open_origin_or_udp_socket() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let mut dns = DnsConfig::default();
    dns.hosts
        .insert("blocked.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    let r = Route {
        final_outbound: "block".into(),
        rules: vec![],
    };
    let n = Network::new(&r, &[Outbound::plain("block", "block")], Some(&dns)).unwrap();
    for address in [
        Address::Ip("127.0.0.1".parse().unwrap()),
        Address::Domain("blocked.test".into()),
    ] {
        assert!(matches!(
            n.connect(&address, port, "127.0.0.1:9000".parse().unwrap())
                .await,
            Err(Error::Blocked)
        ));
        assert!(matches!(
            n.udp_destination(&address, port, "127.0.0.1:9000".parse().unwrap())
                .await,
            Err(Error::Blocked)
        ));
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), origin.accept())
            .await
            .is_err()
    );
}

#[test]
fn changed_routes_or_dns_require_a_new_native_base() {
    let original = crate::tests::config(serde_json::json!([]));
    let baseline = crate::config::decode(original.to_string().as_bytes()).unwrap();
    let mut changed = original.clone();
    changed["route"]["rules"] =
        serde_json::json!([{"outbound":"direct","domain":["example.test"]}]);
    assert_ne!(
        baseline.base,
        crate::config::decode(changed.to_string().as_bytes())
            .unwrap()
            .base
    );
    changed = original;
    changed["dns"] = serde_json::json!({"hosts":{"example.test":["127.0.0.1"]}});
    assert_ne!(
        baseline.base,
        crate::config::decode(changed.to_string().as_bytes())
            .unwrap()
            .base
    );
}
