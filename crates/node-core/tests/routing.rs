use node_core::{NodeSpec, routing::*};
use serde_json::json;

fn policy(rules: serde_json::Value) -> Policy {
    Policy::new(
        &serde_json::from_value(json!({"final":"direct","rules":rules})).unwrap(),
        &[
            Outbound::plain("direct", "direct"),
            Outbound::plain("block", "block"),
        ],
    )
    .unwrap()
}
fn selected(
    p: &Policy,
    domain: Option<&str>,
    ip: &str,
    port: u16,
    network: &str,
    source: &str,
) -> String {
    p.select(
        domain,
        ip.parse().unwrap(),
        port,
        network,
        source.parse().unwrap(),
    )
    .kind
    .clone()
}

#[test]
fn raw_rules_combine_address_or_with_port_network_and_source_constraints() {
    let p = policy(
        json!([{"outbound":"block", "domain_suffix":["Example.COM."], "ip_cidr":["192.0.2.0/24"],
        "port_range":["80:90"], "network":["tcp"], "source_ip_cidr":["10.0.0.0/8"], "source_port_range":["1000-2000"]}]),
    );
    assert_eq!(
        selected(
            &p,
            Some("a.example.com"),
            "203.0.113.1",
            80,
            "tcp",
            "10.1.1.1:1500"
        ),
        "block"
    );
    assert_eq!(
        selected(&p, None, "192.0.2.4", 90, "tcp", "10.1.1.1:1500"),
        "block"
    );
    for (name, ip, port, net, source) in [
        (
            Some("badexample.com"),
            "203.0.113.1",
            80,
            "tcp",
            "10.1.1.1:1500",
        ),
        (
            Some("example.com"),
            "203.0.113.1",
            91,
            "tcp",
            "10.1.1.1:1500",
        ),
        (
            Some("example.com"),
            "203.0.113.1",
            80,
            "udp",
            "10.1.1.1:1500",
        ),
        (
            Some("example.com"),
            "203.0.113.1",
            80,
            "tcp",
            "11.1.1.1:1500",
        ),
        (
            Some("example.com"),
            "203.0.113.1",
            80,
            "tcp",
            "10.1.1.1:999",
        ),
    ] {
        assert_eq!(selected(&p, name, ip, port, net, source), "direct");
    }
}

#[test]
fn ipv6_cidr_boundaries_and_mapped_ipv4_cannot_bypass_rules() {
    let p = policy(json!([{"outbound":"block", "ip_cidr":["2001:db8::/32","127.0.0.1/32"]}]));
    for ip in ["2001:db8:ffff::1", "::ffff:127.0.0.1"] {
        assert_eq!(selected(&p, None, ip, 443, "tcp", "[::1]:9000"), "block");
    }
    assert_eq!(
        selected(&p, None, "2001:db9::1", 443, "tcp", "[::1]:9000"),
        "direct"
    );
    let p = policy(json!([{"outbound":"block", "ip_cidr":["0.0.0.0/0","::/0"]}]));
    assert_eq!(
        selected(&p, None, "2001:db9::1", 443, "tcp", "[::1]:9000"),
        "block"
    );
    assert_eq!(
        selected(&p, None, "127.1.2.3", 443, "tcp", "[::1]:9000"),
        "block"
    );
}

#[test]
fn panel_structured_or_and_priority_are_preserved() {
    let node:NodeSpec=serde_json::from_value(json!({"protocol":"vless","server_port":443,
      "custom_route_rules":[{"match":{"domains":["allow.test"],"ports":["8443"]},"action":{"type":"direct"}}],
      "custom_routes":[{"outbound":"block"}],
      "routes":[{"match":["*.allow.test"],"action":"block"}]})).unwrap();
    let (r, o) = from_node(&node).unwrap();
    let p = Policy::new(&r, &o).unwrap();
    assert_eq!(
        selected(
            &p,
            Some("allow.test"),
            "1.1.1.1",
            80,
            "tcp",
            "127.0.0.1:2000"
        ),
        "direct"
    );
    assert_eq!(
        selected(
            &p,
            Some("another.test"),
            "1.1.1.1",
            8443,
            "tcp",
            "127.0.0.1:2000"
        ),
        "direct"
    );
    assert_eq!(
        selected(
            &p,
            Some("sub.allow.test"),
            "1.1.1.1",
            80,
            "tcp",
            "127.0.0.1:2000"
        ),
        "block"
    );
}

#[test]
fn unsupported_routes_dns_and_credentials_are_rejected_before_activation() {
    for raw in [
        json!({"outbound":"missing"}),
        json!({"outbound":"block","ip_cidr":["geoip:cn"]}),
        json!({"outbound":"block","domain_suffix":["geosite:cn"]}),
        json!({"outbound":"block","port_range":["90-80"]}),
        json!({"outbound":"block","port":[0]}),
        json!({"outbound":"block","ip_cidr":["::ffff:127.0.0.1/32"]}),
        json!({"outbound":"block","network":["quic"]}),
    ] {
        let mut node = NodeSpec::new("vless", 443);
        node.custom_routes.push(raw);
        assert!(from_node(&node).is_err());
    }
    assert!(
        serde_json::from_value::<Rule>(json!({"outbound":"block","domain_regex":[".*"]})).is_err()
    );
    let mut dns = DnsConfig::default();
    dns.validate().unwrap();
    dns.hosts
        .insert("EXAMPLE.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    dns.hosts
        .insert("example.test.".into(), vec!["127.0.0.2".parse().unwrap()]);
    assert!(dns.validate().is_err());
    let mut o = Outbound::plain("proxy", "socks");
    o.server = Some("127.0.0.1".parse().unwrap());
    o.server_port = Some(1080);
    o.validate().unwrap();
    o.username = Some("user".into());
    assert!(o.validate().is_err());
}

#[test]
fn panel_bare_ips_block_literal_and_resolved_destinations_including_mapped_ipv4() {
    let mut node = NodeSpec::new("vless", 443);
    node.routes =
        serde_json::from_value(json!([{"match":["127.0.0.1","2001:db8::1"],"action":"block"}]))
            .unwrap();
    let (r, o) = from_node(&node).unwrap();
    let p = Policy::new(&r, &o).unwrap();
    for ip in ["127.0.0.1", "::ffff:127.0.0.1", "2001:db8::1"] {
        for name in [None, Some("resolved.test")] {
            assert_eq!(
                selected(&p, name, ip, 443, "tcp", "127.0.0.1:9000"),
                "block"
            );
        }
    }
    assert_eq!(
        selected(&p, None, "127.0.0.2", 443, "tcp", "127.0.0.1:9000"),
        "direct"
    );
}
