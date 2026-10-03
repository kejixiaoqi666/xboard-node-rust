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
    // The sole 127.0.0.1 listener accepting this payload proves the selected
    // candidate; a boxed proxy stream does not expose an underlying peer IP.
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
        ..Default::default()
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

#[tokio::test]
async fn proxy_failure_cannot_fall_back_to_a_direct_dns_candidate() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut outbound = Outbound::plain("proxy", "socks");
    outbound.server = Some(proxy.local_addr().unwrap().ip());
    outbound.server_port = Some(proxy.local_addr().unwrap().port());
    let denied = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 255]).await.unwrap();
        }
    });
    let mut dns = DnsConfig::default();
    dns.hosts.insert(
        "route.test".into(),
        vec!["127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap()],
    );
    let route = Route {
        rules: vec![Rule {
            outbound: "proxy".into(),
            ip_cidr: vec!["127.0.0.2/32".into()],
            user: vec!["alice".into()],
            inbound: vec!["node-test".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let network = Network::new(
        &route,
        &[Outbound::plain("direct", "direct"), outbound],
        Some(&dns),
    )
    .unwrap();
    let source = "10.1.2.3:1000".parse().unwrap();
    let target = Address::Domain("route.test".into());
    assert!(
        network
            .connect_for(
                &target,
                origin.local_addr().unwrap().port(),
                source,
                "alice",
                "node-test"
            )
            .await
            .is_err()
    );
    assert!(
        network
            .udp_open_for(&target, 53, source, "alice", "node-test")
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), origin.accept())
            .await
            .is_err()
    );
    denied.await.unwrap();
}

#[tokio::test]
async fn proxy_server_domain_uses_the_same_explicit_hosts_resolver() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        stream.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [5, 1, 0, 1, 203, 0, 113, 6, 1, 187]);
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
        stream.write_all(b"proof").await.unwrap();
    });
    let mut outbound = Outbound::plain("proxy", "socks");
    outbound.server_domain = Some("bootstrap.invalid".into());
    outbound.server_port = Some(port);
    let mut dns = DnsConfig::default();
    dns.hosts.insert(
        "bootstrap.invalid".into(),
        vec!["127.0.0.1".parse().unwrap()],
    );
    dns.hosts
        .insert("origin.test".into(), vec!["203.0.113.6".parse().unwrap()]);
    let network = Network::new(
        &Route {
            final_outbound: "proxy".into(),
            ..Default::default()
        },
        &[outbound],
        Some(&dns),
    )
    .unwrap();
    let mut stream = network
        .connect_for(
            &Address::Domain("origin.test".into()),
            443,
            "10.1.2.3:1000".parse().unwrap(),
            "alice",
            "node-test",
        )
        .await
        .unwrap();
    stream.write_all(b"payload").await.unwrap();
    let mut response = [0; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"proof");
    task.await.unwrap();
}
