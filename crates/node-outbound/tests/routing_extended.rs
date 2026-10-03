use node_core::routing::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
fn outbounds() -> Vec<Outbound> {
    vec![
        Outbound::plain("direct", "direct"),
        Outbound::plain("block", "block"),
    ]
}
fn selected(policy: &Policy, name: Option<&str>, ip: &str, port: u16) -> String {
    policy
        .select(
            name,
            ip.parse().unwrap(),
            port,
            "tcp",
            "10.1.2.3:1500".parse().unwrap(),
        )
        .kind
        .clone()
}
fn file() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/ruleset-fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(format!(
        "set-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn spec(
    path: &std::path::Path,
    bytes: &[u8],
    format: RuleSetFormat,
    selector: Option<&str>,
) -> RuleSet {
    RuleSet {
        tag: "fixture".into(),
        kind: "local".into(),
        format,
        path: path.to_string_lossy().into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        selector: selector.map(str::to_owned),
    }
}
#[test]
fn regex_keyword_logical_inversion_and_old_address_or_semantics() {
    let route:Route=serde_json::from_value(json!({"rules":[{"type":"logical","mode":"and","outbound":"block","rules":[{"domain_regex":["^api[0-9]+\\.example\\.test$"],"domain_keyword":["special"],"ip_cidr":["192.0.2.0/24"]},{"source_ip_cidr":["10.0.0.0/8"],"port_range":["4000:"]}]}]})).unwrap();
    let policy = Policy::new(&route, &outbounds()).unwrap();
    for (name, ip) in [
        (Some("API12.Example.TEST."), "203.0.113.9"),
        (Some("special.test"), "203.0.113.9"),
        (None, "192.0.2.9"),
    ] {
        assert_eq!(selected(&policy, name, ip, 4430), "block")
    }
    assert_eq!(
        selected(&policy, Some("api.test"), "203.0.113.9", 4430),
        "direct"
    );
    assert_eq!(
        selected(&policy, Some("api12.example.test"), "203.0.113.9", 80),
        "direct"
    );
    let inverted: Route = serde_json::from_value(
        json!({"rules":[{"outbound":"block","domain_suffix":[".example.test"],"invert":true}]}),
    )
    .unwrap();
    let policy = Policy::new(&inverted, &outbounds()).unwrap();
    assert_eq!(
        selected(&policy, Some("child.example.test"), "1.1.1.1", 80),
        "direct"
    );
    assert_eq!(
        selected(&policy, Some("example.test"), "1.1.1.1", 80),
        "block"
    );
}
#[test]
fn verified_atomic_ruleset_update_keeps_live_snapshot_and_bad_update_keeps_file() {
    let path = file();
    let first = br#"{"version":5,"rules":[{"domain_suffix":"old.test","port_range":":443"}]}"#;
    let set = spec(&path, first, RuleSetFormat::Source, None);
    install_ruleset_atomic(&set, first).unwrap();
    let mut route = Route {
        rules: vec![Rule {
            outbound: "block".into(),
            rule_set: vec!["fixture".into()],
            ..Default::default()
        }],
        rule_set: vec![set],
        ..Default::default()
    };
    let old = Policy::new(&route, &outbounds()).unwrap();
    let next=br#"{"version":3,"rules":[{"type":"logical","mode":"or","rules":[{"domain":"new.test"},{"ip_cidr":"198.51.100.4"}]}]}"#;
    route.rule_set[0] = spec(&path, next, RuleSetFormat::Source, None);
    install_ruleset_atomic(&route.rule_set[0], next).unwrap();
    let new = Policy::new(&route, &outbounds()).unwrap();
    assert_eq!(selected(&old, Some("old.test"), "1.1.1.1", 80), "block");
    assert_eq!(selected(&new, Some("old.test"), "1.1.1.1", 80), "direct");
    assert_eq!(selected(&new, Some("new.test"), "1.1.1.1", 80), "block");
    assert_eq!(selected(&new, None, "198.51.100.4", 80), "block");
    let malformed = br#"{"version":3,"rules":[{"process_name":["curl"]}]}"#;
    let bad = spec(&path, malformed, RuleSetFormat::Source, None);
    assert!(install_ruleset_atomic(&bad, malformed).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), next);
    let mut wrong = route.rule_set[0].clone();
    wrong.sha256 = "00".repeat(32);
    assert!(install_ruleset_atomic(&wrong, next).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), next);
}
fn varint(mut n: u64) -> Vec<u8> {
    let mut bytes = vec![];
    while n >= 128 {
        bytes.push(n as u8 | 128);
        n >>= 7;
    }
    bytes.push(n as u8);
    bytes
}
fn data(field: u64, bytes: &[u8]) -> Vec<u8> {
    [
        varint(field << 3 | 2),
        varint(bytes.len() as u64),
        bytes.to_vec(),
    ]
    .concat()
}
fn number(field: u64, n: u64) -> Vec<u8> {
    [varint(field << 3), varint(n)].concat()
}
#[test]
fn v2ray_geoip_geosite_wire_formats_selectors_attributes_ipv6_and_truncation() {
    let cidr = [data(1, &[192, 0, 2, 0]), number(2, 24)].concat();
    let cidr6 = [
        data(
            1,
            &"2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().octets(),
        ),
        number(2, 32),
    ]
    .concat();
    let bytes = data(
        1,
        &[data(1, b"TEST"), data(2, &cidr), data(2, &cidr6)].concat(),
    );
    let path = file();
    let set = spec(&path, &bytes, RuleSetFormat::Geoip, Some("test"));
    install_ruleset_atomic(&set, &bytes).unwrap();
    let route = Route {
        rule_set: vec![set],
        rules: vec![Rule {
            outbound: "block".into(),
            rule_set: vec!["fixture".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let p = Policy::new(&route, &outbounds()).unwrap();
    assert_eq!(selected(&p, None, "::ffff:192.0.2.4", 80), "block");
    assert_eq!(selected(&p, None, "2001:db8::1", 80), "block");
    assert_eq!(selected(&p, None, "192.0.3.1", 80), "direct");
    let attribute = [data(1, b"ads"), number(2, 1)].concat();
    let domain = [number(1, 2), data(2, b"ads.test"), data(3, &attribute)].concat();
    let full = [number(1, 3), data(2, b"full.test")].concat();
    let bytes = data(
        1,
        &[data(1, b"TEST"), data(2, &domain), data(2, &full)].concat(),
    );
    let path = file();
    let set = spec(&path, &bytes, RuleSetFormat::Geosite, Some("test@ads"));
    install_ruleset_atomic(&set, &bytes).unwrap();
    let route = Route {
        rule_set: vec![set],
        rules: route.rules,
        ..Default::default()
    };
    let p = Policy::new(&route, &outbounds()).unwrap();
    assert_eq!(selected(&p, Some("sub.ads.test"), "1.1.1.1", 80), "block");
    assert_eq!(selected(&p, Some("full.test"), "1.1.1.1", 80), "direct");
    for n in 0..bytes.len() {
        let truncated = &bytes[..n];
        let set = spec(&path, truncated, RuleSetFormat::Geosite, Some("test@ads"));
        assert!(
            install_ruleset_atomic(&set, truncated).is_err(),
            "accepted truncated protobuf at {n}"
        );
    }
}
#[test]
fn bounded_regex_unknown_fields_dangling_sets_and_detour_cycles_fail_before_use() {
    for raw in [
        json!({"domain_regex":["("]}),
        json!({"rule_set":["missing"]}),
        json!({"type":"logical","mode":"xor","rules":[{}]}),
        json!({"domain_regex":vec![".*";257]}),
    ] {
        let mut rule: Rule = serde_json::from_value(raw).unwrap();
        rule.outbound = "block".into();
        assert!(
            Policy::new(
                &Route {
                    rules: vec![rule],
                    ..Default::default()
                },
                &outbounds()
            )
            .is_err()
        )
    }
    assert!(
        serde_json::from_value::<RuleSet>(
            json!({"tag":"s","type":"remote","format":"binary","path":"x","sha256":"00"})
        )
        .is_err()
    );
    let mut a = Outbound::plain("a", "direct");
    a.detour = Some("b".into());
    let mut b = Outbound::plain("b", "direct");
    b.detour = Some("a".into());
    assert!(
        Policy::new(
            &Route {
                final_outbound: "a".into(),
                ..Default::default()
            },
            &[a, b]
        )
        .is_err()
    );
}
#[test]
fn xray_outbound_nested_settings_detour_domain_bootstrap_and_user_inbound_routes() {
    let node:node_core::NodeSpec=serde_json::from_value(json!({"protocol":"vless","server_port":443,"custom_outbounds":[
        {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"proxy.test","port":1080,"users":[{"user":"fixture","pass":"fixture-password"}]}]}},
        {"tag":"inner","protocol":"vless","proxy_tag":"proxy","settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"00112233-4455-6677-8899-aabbccddeeff","encryption":"none"}]}]}}
    ],"custom_routes":[{"type":"field","outboundTag":"inner","domain":["full:exact.test","regexp:^api[0-9]+\\.test$"],"network":"tcp,udp","port":"443,8000-9000","source":["10.0.0.0/8"],"sourcePort":"1000-2000","user":["alice"],"inboundTag":["node-test"]}]})).unwrap();
    let (route, outbounds) = from_node(&node).unwrap();
    assert_eq!(
        outbounds
            .iter()
            .find(|o| o.tag == "proxy")
            .unwrap()
            .server_domain
            .as_deref(),
        Some("proxy.test")
    );
    assert_eq!(
        outbounds
            .iter()
            .find(|o| o.tag == "inner")
            .unwrap()
            .detour
            .as_deref(),
        Some("proxy")
    );
    let p = Policy::new(&route, &outbounds).unwrap();
    assert_eq!(
        p.select_with(
            Some("exact.test"),
            "1.1.1.1".parse().unwrap(),
            443,
            "tcp",
            "10.1.1.1:1500".parse().unwrap(),
            MatchMeta {
                user: Some("alice"),
                inbound_tag: Some("node-test")
            }
        )
        .tag,
        "inner"
    );
    for meta in [
        MatchMeta {
            user: Some("bob"),
            inbound_tag: Some("node-test"),
        },
        MatchMeta {
            user: Some("alice"),
            inbound_tag: Some("other"),
        },
        MatchMeta::default(),
    ] {
        assert_eq!(
            p.select_with(
                Some("api12.test"),
                "1.1.1.1".parse().unwrap(),
                443,
                "udp",
                "10.1.1.1:1500".parse().unwrap(),
                meta
            )
            .tag,
            "direct"
        )
    }
    let mut unsupported = node.clone();
    unsupported.custom_routes[0]["protocol"] = json!(["tls"]);
    assert!(from_node(&unsupported).is_err());
    unsupported = node;
    unsupported.custom_outbounds[1].settings["vnext"][0]["users"][0]["flow"] =
        json!("xtls-rprx-vision");
    assert!(from_node(&unsupported).is_err());
}
#[test]
fn xray_geo_and_regular_address_groups_remain_or_with_metadata_and() {
    let path = file();
    let bytes = br#"{"version":3,"rules":[{"domain_suffix":["geo.test"]}]}"#;
    let set = spec(&path, bytes, RuleSetFormat::Source, None);
    install_ruleset_atomic(&set, bytes).unwrap();
    let geo_bytes = data(
        1,
        &[
            data(1, b"TEST"),
            data(2, &[number(1, 2), data(2, b"geo.test")].concat()),
        ]
        .concat(),
    );
    let geo_path = file();
    let set = spec(&geo_path, &geo_bytes, RuleSetFormat::Geosite, Some("test"));
    install_ruleset_atomic(&set, &geo_bytes).unwrap();
    let mut node = node_core::NodeSpec::new("vless", 443);
    node.custom_routes = vec![
        json!({"type":"field","outboundTag":"block","domain":["full:regular.test","geosite:test"],"port":"443"}),
    ];
    let (route, outbounds) = from_node_with_rulesets(&node, &[set]).unwrap();
    let p = Policy::new(&route, &outbounds).unwrap();
    for name in ["regular.test", "sub.geo.test"] {
        assert_eq!(selected(&p, Some(name), "1.1.1.1", 443), "block");
        assert_eq!(selected(&p, Some(name), "1.1.1.1", 80), "direct");
    }
    assert_eq!(selected(&p, Some("none.test"), "1.1.1.1", 443), "direct");
}

fn geoip_fixture(countries: &[&str]) -> Vec<u8> {
    countries
        .iter()
        .flat_map(|country| {
            data(
                1,
                &[
                    data(1, country.as_bytes()),
                    data(2, &[data(1, &[192, 0, 2, 0]), number(2, 24)].concat()),
                ]
                .concat(),
            )
        })
        .collect()
}

#[test]
fn geo_data_directory_discovery_validates_selectors_and_freezes_content_checksum() {
    let directory = file();
    std::fs::create_dir_all(&directory).unwrap();
    let geoip = geoip_fixture(&["TEST", "OTHER"]);
    let geosite = data(
        1,
        &[
            data(1, b"TEST"),
            data(
                2,
                &[
                    number(1, 2),
                    data(2, b"geo.test"),
                    data(3, &[data(1, b"ads"), number(2, 1)].concat()),
                ]
                .concat(),
            ),
        ]
        .concat(),
    );
    std::fs::write(directory.join("geoip.dat"), &geoip).unwrap();
    std::fs::write(directory.join("geosite.dat"), &geosite).unwrap();
    let mut node = node_core::NodeSpec::new("vless", 443);
    node.custom_routes = vec![
        json!({"type":"field","outboundTag":"block","domain":["geosite:test@ads"],"source":["geoip:test"]}),
        json!({"outbound":"block","ip_cidr":["geoip:other"],"port":443}),
    ];
    let sets = discover_geo_rulesets(&node, &directory).unwrap();
    assert_eq!(sets.len(), 3);
    assert!(
        sets.iter()
            .all(|set| std::path::Path::new(&set.path).is_absolute())
    );
    for set in &sets {
        let bytes = if set.format == RuleSetFormat::Geoip {
            &geoip
        } else {
            &geosite
        };
        assert_eq!(set.sha256, format!("{:x}", Sha256::digest(bytes)));
    }
    let (route, outbounds) = from_node_with_rulesets(&node, &sets).unwrap();
    let policy = Policy::new(&route, &outbounds).unwrap();
    assert_eq!(
        selected(&policy, Some("sub.geo.test"), "192.0.2.1", 443),
        "block"
    );
    assert_eq!(
        selected(&policy, Some("other.test"), "203.0.113.1", 443),
        "direct"
    );

    let mut unknown = node.clone();
    unknown.custom_routes = vec![json!({"outbound":"block","source_ip_cidr":["geoip:missing"]})];
    assert!(discover_geo_rulesets(&unknown, &directory).is_err());
    assert!(discover_geo_rulesets(&node, &directory.join("missing")).is_err());
    std::fs::write(
        directory.join("geoip.dat"),
        geoip_fixture(&["TEST", "OTHER", "NEW"]),
    )
    .unwrap();
    assert!(Policy::new(&route, &outbounds).is_err());
    let next = discover_geo_rulesets(&node, &directory).unwrap();
    assert!(next.iter().any(|set| set.format == RuleSetFormat::Geoip
        && !sets.iter().any(|old| old.sha256 == set.sha256)));
    std::fs::write(directory.join("geosite.dat"), &geosite[..geosite.len() - 1]).unwrap();
    assert!(discover_geo_rulesets(&node, &directory).is_err());
    let empty = node_core::NodeSpec::new("vless", 443);
    assert!(
        discover_geo_rulesets(&empty, &directory.join("unused-missing"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn native_and_xray_source_geo_match_source_ip_and_preserve_source_or_address_and() {
    let path = file();
    let bytes = geoip_fixture(&["TEST"]);
    let set = spec(&path, &bytes, RuleSetFormat::Geoip, Some("test"));
    install_ruleset_atomic(&set, &bytes).unwrap();
    for raw in [
        json!({"outbound":"block","domain":["target.test"],"source_ip_cidr":["geoip:test","10.0.0.0/8"]}),
        json!({"type":"field","outboundTag":"block","domain":["full:target.test"],"source":["geoip:test","10.0.0.0/8"]}),
    ] {
        let mut node = node_core::NodeSpec::new("vless", 443);
        node.custom_routes = vec![raw];
        let (route, outbounds) =
            from_node_with_rulesets(&node, std::slice::from_ref(&set)).unwrap();
        let policy = Policy::new(&route, &outbounds).unwrap();
        let route_for = |domain, ip: &str, source: &str| {
            policy
                .select(
                    Some(domain),
                    ip.parse().unwrap(),
                    443,
                    "tcp",
                    source.parse().unwrap(),
                )
                .kind
                .as_str()
        };
        assert_eq!(
            route_for("target.test", "203.0.113.1", "192.0.2.9:1500"),
            "block"
        );
        assert_eq!(
            route_for("target.test", "203.0.113.1", "10.1.2.3:1500"),
            "block"
        );
        assert_eq!(
            route_for("target.test", "192.0.2.9", "203.0.113.1:1500"),
            "direct"
        );
        assert_eq!(
            route_for("other.test", "203.0.113.1", "192.0.2.9:1500"),
            "direct"
        );
    }
    let wrong = Route {
        rule_set: vec![set],
        rules: vec![Rule {
            outbound: "block".into(),
            source_ip_rule_set: vec!["missing".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(Policy::new(&wrong, &outbounds()).is_err());
}

#[test]
fn geo_multiple_selectors_share_one_bounded_file_snapshot() {
    let directory = file();
    std::fs::create_dir_all(&directory).unwrap();
    let mut bytes = geoip_fixture(&["TEST", "OTHER"]);
    // A legal unknown protobuf field makes duplicate accounting exceed 32 MiB
    // while the single shared file remains under the aggregate loader limit.
    bytes.extend(data(99, &vec![0; 17 * 1024 * 1024]));
    std::fs::write(directory.join("geoip.dat"), &bytes).unwrap();
    let mut node = node_core::NodeSpec::new("vless", 443);
    node.custom_routes = vec![json!({"outbound":"block","ip_cidr":["geoip:test","geoip:other"]})];
    let sets = discover_geo_rulesets(&node, &directory).unwrap();
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0].path, sets[1].path);
    assert_eq!(sets[0].sha256, sets[1].sha256);
    let (route, outbounds) = from_node_with_rulesets(&node, &sets).unwrap();
    let policy = Policy::new(&route, &outbounds).unwrap();
    assert_eq!(selected(&policy, None, "192.0.2.1", 443), "block");
    assert_eq!(selected(&policy, None, "203.0.113.1", 443), "direct");
}

#[test]
fn native_outbound_domains_are_explicit_and_conflicting_address_forms_fail() {
    let domain: Outbound = serde_json::from_value(
        json!({"tag":"proxy","type":"socks","server":"proxy.test","server_port":1080}),
    )
    .unwrap();
    assert!(domain.server.is_none());
    assert_eq!(domain.server_domain.as_deref(), Some("proxy.test"));
    domain.validate().unwrap();
    let literal: Outbound = serde_json::from_value(
        json!({"tag":"proxy","type":"socks","server":"127.0.0.1","server_port":1080}),
    )
    .unwrap();
    assert_eq!(literal.server, Some("127.0.0.1".parse().unwrap()));
    assert!(literal.server_domain.is_none());
    assert!(serde_json::from_value::<Outbound>(json!({"tag":"proxy","type":"socks","server":"proxy.test","server_domain":"other.test","server_port":1080})).is_err());
    assert!(serde_json::from_value::<Outbound>(json!({"tag":"proxy","type":"socks","server":"proxy.test","server_port":1080,"transport":{"type":"ws"}})).is_err());
}
