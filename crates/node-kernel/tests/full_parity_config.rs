//! Exercise the panel model -> production builder -> production native decoder.
//! Wire interoperability is covered separately by node-quic/node-extended/node-outbound.
use node_core::routing::{DnsConfig, MatchMeta, Policy, RuleSet, RuleSetFormat};
use node_core::{MultiplexConfig, NodeSpec, OutboundConfig, StringOrArray, UserSpec};
use node_kernel::SingBoxConfigBuilder;
use node_native::{
    auth,
    config::{Candidate, Protocol, decode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const UUID7: &str = "00000000-0000-4000-8000-000000000007";
const UUID9: &str = "00000000-0000-4000-8000-000000000009";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "xboard-full-parity-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn source(&self, tag: &str, bytes: &[u8]) -> RuleSet {
        let path = self.path(&format!("{tag}.json"));
        std::fs::write(&path, bytes).unwrap();
        RuleSet {
            tag: tag.into(),
            kind: "local".into(),
            format: RuleSetFormat::Source,
            path: path.to_str().unwrap().into(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            selector: None,
        }
    }
    fn node(&self, protocol: &str) -> NodeSpec {
        let mut node = NodeSpec::new(protocol, 18443);
        node.listen_ip = Some("127.0.0.1".into());
        if matches!(protocol, "trojan" | "anytls" | "hysteria2" | "tuic") {
            self.tls(&mut node);
        }
        if protocol == "shadowsocks" {
            node.cipher = Some("aes-128-gcm".into());
        }
        node
    }
    fn tls(&self, node: &mut NodeSpec) {
        // decode validates absolute references; loading certificates and handshakes
        // have their own real TLS/QUIC interoperability fixtures.
        node.tls = 1;
        node.cert_config = Some(json!({"cert_mode":"file",
            "cert_file":self.path("cert.pem"),"key_file":self.path("key.pem")}));
        node.server_name = Some("fixture.test".into());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(self.0.parent(), Some(std::env::temp_dir().as_path()));
        assert!(
            self.0
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("xboard-full-parity-config-")
        );
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn users() -> [UserSpec; 2] {
    [
        UserSpec::new(7, UUID7).with_limits(1, 2),
        UserSpec::new(9, UUID9).with_limits(3, 1),
    ]
}

fn generated(
    builder: &SingBoxConfigBuilder,
    node: &NodeSpec,
    users: &[UserSpec],
) -> (Value, Candidate) {
    let mut bytes = Vec::new();
    builder
        .write_json(&mut bytes, node, users)
        .unwrap_or_else(|error| panic!("{} {:?}: {error}", node.protocol, node.network));
    let value = builder.build(node, users).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        value,
        "streamed and object paths differ"
    );
    let candidate = decode(&bytes).unwrap_or_else(|error| {
        panic!(
            "native rejected generated {} {:?}: {error}; config={value}",
            node.protocol, node.network
        )
    });
    assert_eq!(
        candidate.base.listen,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(candidate.base.port, 18443);
    assert_eq!(
        candidate.auth.policy("7").unwrap().bytes_per_second,
        125_000
    );
    assert_eq!(
        candidate.auth.policy("7").unwrap().devices,
        users[0].device_limit as u32
    );
    if users.len() > 1 {
        assert_eq!(
            candidate.auth.policy("9").unwrap().bytes_per_second,
            375_000
        );
        assert_eq!(
            candidate.auth.policy("9").unwrap().devices,
            users[1].device_limit as u32
        );
    }
    (value, candidate)
}

fn reject(builder: &SingBoxConfigBuilder, node: &NodeSpec) {
    let mut bytes = Vec::new();
    assert!(
        builder.write_json(&mut bytes, node, &users()).is_err(),
        "unsupported options were accepted: {node:?}"
    );
    assert!(
        bytes.is_empty(),
        "failed configuration wrote a partial candidate"
    );
}

fn selected(policy: &Policy, domain: &str, source: &str, user: &str, inbound: &str) -> String {
    policy
        .select_with(
            Some(domain),
            "203.0.113.10".parse().unwrap(),
            443,
            "tcp",
            source.parse().unwrap(),
            MatchMeta {
                user: Some(user),
                inbound_tag: Some(inbound),
            },
        )
        .tag
        .clone()
}

#[test]
fn all_new_tcp_transports_are_reachable_from_nodespec_and_native_decode() {
    let fixture = Fixture::new();
    let builder = SingBoxConfigBuilder::native();
    for protocol in ["vless", "vmess", "trojan"] {
        for network in ["ws", "httpupgrade", "h2", "http", "http2", "grpc"] {
            let mut node = fixture.node(protocol);
            node.network = Some(network.into());
            node.network_settings = match network {
                "ws" => json!({"path":"/bridge","headers":{"Host":"wire.fixture.test"},
                    "maxEarlyData":512,"earlyDataHeaderName":"Sec-WebSocket-Protocol"}),
                "httpupgrade" => json!({"path":"/bridge","host":"wire.fixture.test"}),
                "grpc" => json!({"serviceName":"fixture.bridge","multiMode":false}),
                _ => {
                    json!({"path":"/bridge","host":["one.fixture.test","two.fixture.test"],"method":"PUT"})
                }
            };
            let (_, candidate) = generated(&builder, &node, &users());
            let transport = candidate.base.transport.unwrap();
            assert_eq!(
                transport.kind,
                match network {
                    "h2" | "http" => "http2",
                    network => network,
                }
            );
            if network == "grpc" {
                assert_eq!(transport.service_name.as_deref(), Some("fixture.bridge"));
            } else {
                assert_eq!(transport.path.as_deref(), Some("/bridge"));
            }
            if matches!(network, "h2" | "http" | "http2") {
                assert_eq!(transport.hosts, ["one.fixture.test", "two.fixture.test"]);
                assert_eq!(transport.method.as_deref(), Some("PUT"));
            } else if network != "grpc" {
                assert_eq!(transport.host.as_deref(), Some("wire.fixture.test"));
            }
            if network == "ws" {
                assert_eq!(transport.max_early_data, 512);
            }
            if protocol == "trojan" {
                assert_eq!(
                    candidate.auth.trojan(&auth::trojan_key(UUID7)).as_deref(),
                    Some("7")
                );
            } else {
                assert_eq!(
                    candidate.auth.vless(&auth::uuid(UUID7).unwrap()).as_deref(),
                    Some("7")
                );
            }
        }
    }
}

#[test]
fn vmess_security_and_anytls_padding_survive_the_builder_decoder_boundary() {
    let fixture = Fixture::new();
    let builder = SingBoxConfigBuilder::native();
    for security in ["any", "auto", "aes-128-gcm", "chacha20-poly1305", "none"] {
        let mut node = fixture.node("vmess");
        node.cipher = Some(security.into());
        let (_, candidate) = generated(&builder, &node, &users());
        assert_eq!(candidate.base.protocol, Protocol::Vmess);
        assert_eq!(candidate.base.extended.unwrap().vmess_security, security);
    }
    for scheme in [
        StringOrArray::String("stop=2\n0=30-30\n1=100-200".into()),
        StringOrArray::Array(vec!["stop=2".into(), "0=30-30".into(), "1=100-200".into()]),
    ] {
        let mut node = fixture.node("anytls");
        node.padding_scheme = Some(scheme.clone());
        let (_, candidate) = generated(&builder, &node, &users());
        assert_eq!(candidate.base.protocol, Protocol::AnyTls);
        let extended = candidate.base.extended.unwrap();
        assert_eq!(extended.padding_scheme, Some(scheme));
        extended.config().unwrap();
        assert_eq!(
            candidate.auth.trojan(&auth::trojan_key(UUID9)).as_deref(),
            Some("9")
        );
    }
}

#[test]
fn tuic_hysteria2_versions_congestion_obfuscation_and_multiuser_auth_are_generated() {
    let fixture = Fixture::new();
    let builder = SingBoxConfigBuilder::native();
    for protocol in ["hysteria2", "tuic"] {
        for congestion in ["cubic", "new_reno", "bbr"] {
            let mut node = fixture.node(protocol);
            node.version = if protocol == "tuic" { 5 } else { 2 };
            node.congestion_control = Some(congestion.into());
            if protocol == "hysteria2" {
                node.obfs = Some("salamander".into());
                node.obfs_password = Some("fixture salamander secret".into());
            }
            let (value, candidate) = generated(&builder, &node, &users());
            assert_eq!(
                candidate.base.protocol,
                if protocol == "tuic" {
                    Protocol::Tuic
                } else {
                    Protocol::Hysteria2
                }
            );
            let quic = candidate.base.quic.unwrap();
            assert_eq!(quic.congestion_control, congestion);
            assert_eq!(quic.obfs_password, node.obfs_password);
            assert!(quic.enable_udp);
            assert!(
                !quic.allow_0rtt,
                "replay-prone early data must not be enabled by omission"
            );
            for (index, (id, credential)) in [("7", UUID7), ("9", UUID9)].into_iter().enumerate() {
                assert_eq!(
                    candidate
                        .auth
                        .trojan(&auth::trojan_key(credential))
                        .as_deref(),
                    Some(id)
                );
                assert_eq!(value["inbounds"][0]["users"][index]["password"], credential);
                if protocol == "tuic" {
                    assert_eq!(value["inbounds"][0]["users"][index]["uuid"], credential);
                } else {
                    assert!(value["inbounds"][0]["users"][index].get("uuid").is_none());
                }
            }
        }
    }
}

#[test]
fn inbound_multiplex_switch_and_stream_cap_are_reachable_for_each_supported_protocol() {
    let fixture = Fixture::new();
    let builder = SingBoxConfigBuilder::native();
    for protocol in ["vless", "vmess", "trojan", "shadowsocks", "anytls"] {
        for mux_protocol in ["smux", "yamux", "h2mux"] {
            for enabled in [false, true] {
                let mut node = fixture.node(protocol);
                node.multiplex = Some(MultiplexConfig {
                    enabled,
                    protocol: Some(mux_protocol.into()),
                    max_streams: 64,
                    padding: true,
                    ..Default::default()
                });
                let (_, candidate) = generated(&builder, &node, &users());
                let settings = candidate.base.extended.unwrap().config().unwrap();
                assert_eq!(settings.multiplex_enabled, enabled);
                assert_eq!(settings.max_sessions, 64);
            }
        }
    }
}

#[test]
fn shadowsocks_v2ray_plugin_builds_native_websocket_mux_and_tls_from_nodespec() {
    let fixture = Fixture::new();
    let builder = SingBoxConfigBuilder::native();
    for mux in [0, 1] {
        for tls in [false, true] {
            let mut node = fixture.node("shadowsocks");
            node.plugin = Some("v2ray-plugin".into());
            node.plugin_opt = Some(format!(
                "server;mode=websocket;path=/plugin;host=wire.fixture.test;mux={mux}{}",
                if tls { ";tls" } else { "" }
            ));
            if tls {
                fixture.tls(&mut node);
                node.tls = 0;
            }
            let (_, candidate) = generated(&builder, &node, &users());
            assert_eq!(candidate.base.protocol, Protocol::Shadowsocks);
            assert!(
                candidate.base.plugin.is_none(),
                "native plugin must not require an executable"
            );
            assert_eq!(candidate.base.tls.is_some(), tls);
            let transport = candidate.base.transport.unwrap();
            assert_eq!(transport.kind, "ws");
            assert_eq!(transport.path.as_deref(), Some("/plugin"));
            assert_eq!(transport.host.as_deref(), Some("wire.fixture.test"));
            assert_eq!(transport.plugin_mux, mux == 1);
        }
    }
}

#[test]
fn explicit_external_sip003_reference_and_options_are_preserved_and_device_limit_rejected() {
    let fixture = Fixture::new();
    let builder = SingBoxConfigBuilder::native();
    let mut node = fixture.node("shadowsocks");
    // An actual absolute executable file is required by native decode. It is not launched here.
    let executable = std::env::current_exe().unwrap();
    node.plugin = Some(executable.to_str().unwrap().into());
    node.plugin_opt = Some("server;obfs=http;obfs-host=wire.fixture.test".into());
    let users = [UserSpec::new(7, UUID7).with_limits(1, 0)];
    let (_, candidate) = generated(&builder, &node, &users);
    assert!(candidate.base.transport.is_none());
    let plugin = candidate.base.plugin.unwrap();
    assert_eq!(plugin.binary, executable);
    assert_eq!(plugin.options, node.plugin_opt);
    reject(&builder, &node);
}

#[test]
fn local_source_ruleset_is_loaded_from_builder_config_and_rejects_changed_content() {
    let fixture = Fixture::new();
    let bytes = br#"{"version":4,"rules":[{"domain_regex":["(^|\\.)blocked\\.fixture\\.test$"],"network":["tcp"],"port":[443]}]}"#;
    let set = fixture.source("source-fixture", bytes);
    let mut node = fixture.node("vless");
    node.custom_routes.push(json!({"outbound":"block","rule_set":["source-fixture"],"user":["7"],"inbound":["vless-in"]}));
    let builder = SingBoxConfigBuilder::native().with_rule_sets(vec![set.clone()]);
    let (value, candidate) = generated(&builder, &node, &users());
    assert_eq!(value["route"]["rule_set"][0]["sha256"], set.sha256);
    assert_eq!(
        candidate.base.route.rule_set.as_slice(),
        std::slice::from_ref(&set)
    );
    let policy = Policy::new(&candidate.base.route, &candidate.base.outbounds).unwrap();
    assert_eq!(
        selected(
            &policy,
            "cdn.blocked.fixture.test",
            "192.0.2.7:1234",
            "7",
            "vless-in"
        ),
        "block"
    );
    assert_eq!(
        selected(
            &policy,
            "cdn.blocked.fixture.test",
            "192.0.2.7:1234",
            "9",
            "vless-in"
        ),
        "direct"
    );
    assert_eq!(
        selected(
            &policy,
            "allowed.fixture.test",
            "192.0.2.7:1234",
            "7",
            "vless-in"
        ),
        "direct"
    );
    std::fs::write(&set.path, br#"{"version":4,"rules":[]}"#).unwrap();
    assert!(
        decode(&serde_json::to_vec(&value).unwrap()).is_err(),
        "SHA mismatch admitted new configuration"
    );
    reject(&builder, &node);
    assert_eq!(
        selected(
            &policy,
            "cdn.blocked.fixture.test",
            "192.0.2.7:1234",
            "7",
            "vless-in"
        ),
        "block",
        "existing policy lost its frozen snapshot"
    );
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 128 {
        bytes.push(value as u8 | 128);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}
fn field(number: u64, value: &[u8]) -> Vec<u8> {
    [
        varint(number << 3 | 2),
        varint(value.len() as u64),
        value.to_vec(),
    ]
    .concat()
}
fn number(field: u64, value: u64) -> Vec<u8> {
    [varint(field << 3), varint(value)].concat()
}
fn geo_files(fixture: &Fixture) -> (Vec<u8>, Vec<u8>) {
    // V2Ray common.proto: GeoIPList.entry, country_code, CIDR.ip/prefix;
    // GeoSiteList.entry, Domain.RootDomain, Attribute.key/bool_value.
    let cidr = [field(1, &[192, 0, 2, 0]), number(2, 24)].concat();
    let geoip = field(1, &[field(1, b"TEST"), field(2, &cidr)].concat());
    let attribute = [field(1, b"ads"), number(2, 1)].concat();
    let domain = [
        number(1, 2),
        field(2, b"ads.fixture.test"),
        field(3, &attribute),
    ]
    .concat();
    let geosite = field(1, &[field(1, b"TEST"), field(2, &domain)].concat());
    std::fs::write(fixture.path("geoip.dat"), &geoip).unwrap();
    std::fs::write(fixture.path("geosite.dat"), &geosite).unwrap();
    (geoip, geosite)
}

#[test]
fn geo_directory_discovers_referenced_country_attribute_source_ip_and_merges_explicit_sets() {
    let fixture = Fixture::new();
    let (geoip, geosite) = geo_files(&fixture);
    let set = fixture.source(
        "explicit-source",
        br#"{"version":4,"rules":[{"domain":["source.fixture.test"]}]}"#,
    );
    let mut node = fixture.node("vless");
    node.custom_routes = vec![
        json!({"type":"field","outboundTag":"block","domain":["geosite:test@ads"],"source":["geoip:test"],
            "user":["7"],"inboundTag":["vless-in"],"network":"tcp","port":"443"}),
        json!({"outbound":"block","rule_set":["explicit-source"]}),
    ];
    let builder = SingBoxConfigBuilder::native()
        .with_geo_data_dir(Some(fixture.0.clone()))
        .with_rule_sets(vec![set]);
    let (value, candidate) = generated(&builder, &node, &users());
    assert_eq!(candidate.base.route.rule_set.len(), 3);
    for set in &candidate.base.route.rule_set {
        assert!(Path::new(&set.path).is_absolute());
        if set.format == RuleSetFormat::Geoip {
            assert_eq!(set.selector.as_deref(), Some("test"));
            assert_eq!(set.sha256, format!("{:x}", Sha256::digest(&geoip)));
        } else if set.format == RuleSetFormat::Geosite {
            assert_eq!(set.selector.as_deref(), Some("test@ads"));
            assert_eq!(set.sha256, format!("{:x}", Sha256::digest(&geosite)));
        }
    }
    let policy = Policy::new(&candidate.base.route, &candidate.base.outbounds).unwrap();
    assert_eq!(
        selected(
            &policy,
            "cdn.ads.fixture.test",
            "192.0.2.7:1234",
            "7",
            "vless-in"
        ),
        "block"
    );
    assert_eq!(
        selected(
            &policy,
            "cdn.ads.fixture.test",
            "198.51.100.7:1234",
            "7",
            "vless-in"
        ),
        "direct"
    );
    assert_eq!(
        selected(
            &policy,
            "cdn.ads.fixture.test",
            "192.0.2.7:1234",
            "9",
            "vless-in"
        ),
        "direct"
    );
    assert_eq!(
        selected(
            &policy,
            "source.fixture.test",
            "198.51.100.7:1234",
            "9",
            "other-in"
        ),
        "block"
    );
    std::fs::write(fixture.path("geoip.dat"), [0xff]).unwrap();
    assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    reject(&builder, &node);
    geo_files(&fixture);
    let mut unknown = node.clone();
    unknown.custom_routes[0]["domain"] = json!(["geosite:absent@ads"]);
    reject(&builder, &unknown);
    reject(&SingBoxConfigBuilder::native(), &node);
}

#[test]
fn xray_outbound_chain_metadata_and_encrypted_dns_are_generated_and_decoded() {
    let fixture = Fixture::new();
    let mut node = fixture.node("vless");
    node.custom_outbounds = vec![
        OutboundConfig {
            tag: "entry".into(),
            protocol: "socks".into(),
            proxy_tag: None,
            settings: json!({"servers":[{"address":"proxy.fixture.test","port":1080,"users":[{"user":"fixture","pass":"password"}]}]}),
        },
        OutboundConfig {
            tag: "exit".into(),
            protocol: "vless".into(),
            proxy_tag: Some("entry".into()),
            settings: json!({"vnext":[{"address":"exit.fixture.test","port":443,"users":[{"id":UUID7,"encryption":"none"}]}]}),
        },
    ];
    node.custom_routes.push(
        json!({"type":"field","outboundTag":"exit","domain":["domain:example.test"],
        "network":"tcp","port":"443","user":["7"],"inboundTag":["vless-in"]}),
    );
    let dns: DnsConfig = serde_json::from_value(json!({
        "upstreams":[{"transport":"tls","address":"127.0.0.1:853","server_name":"dns.fixture.test","ca_file":fixture.path("dns-ca.pem")},
            {"transport":"https","address":"127.0.0.1:8443","server_name":"dns.fixture.test","path":"/private-query","ca_file":fixture.path("dns-ca.pem")},
            {"transport":"quic","address":"127.0.0.1:8853","server_name":"dns.fixture.test","ca_file":fixture.path("dns-ca.pem")}],
        "hosts":{"proxy.fixture.test":["192.0.2.10"],"exit.fixture.test":["192.0.2.20"]}
    })).unwrap();
    let (_, candidate) = generated(
        &SingBoxConfigBuilder::native().with_dns(Some(dns.clone())),
        &node,
        &users(),
    );
    assert_eq!(candidate.base.dns, Some(dns));
    let exit = candidate
        .base
        .outbounds
        .iter()
        .find(|outbound| outbound.tag == "exit")
        .unwrap();
    assert_eq!(exit.detour.as_deref(), Some("entry"));
    assert_eq!(exit.server_domain.as_deref(), Some("exit.fixture.test"));
    assert_eq!(exit.uuid.as_deref(), Some(UUID7));
    let policy = Policy::new(&candidate.base.route, &candidate.base.outbounds).unwrap();
    assert_eq!(
        selected(
            &policy,
            "cdn.example.test",
            "198.51.100.1:1234",
            "7",
            "vless-in"
        ),
        "exit"
    );
    assert_eq!(
        selected(
            &policy,
            "cdn.example.test",
            "198.51.100.1:1234",
            "9",
            "vless-in"
        ),
        "direct"
    );
}

#[test]
fn unsupported_transport_mux_and_quic_options_fail_before_writing_candidates() {
    let fixture = Fixture::new();
    let builder = SingBoxConfigBuilder::native();
    for (network, settings) in [
        ("kcp", json!({})),
        ("ws", json!({"path":"/","future_wire_option":true})),
        ("grpc", json!({"serviceName":"fixture","multiMode":true})),
    ] {
        let mut node = fixture.node("vless");
        node.network = Some(network.into());
        node.network_settings = settings;
        reject(&builder, &node);
    }
    for mux in [
        MultiplexConfig {
            max_connections: 1,
            ..Default::default()
        },
        MultiplexConfig {
            min_streams: 1,
            ..Default::default()
        },
        MultiplexConfig {
            max_streams: 1025,
            ..Default::default()
        },
        MultiplexConfig {
            protocol: Some("unknown-wire".into()),
            ..Default::default()
        },
    ] {
        let mut node = fixture.node("vless");
        node.multiplex = Some(mux);
        reject(&builder, &node);
    }
    let mut tuic = fixture.node("tuic");
    tuic.version = 4;
    reject(&builder, &tuic);
    let mut hysteria = fixture.node("hysteria2");
    hysteria.version = 1;
    reject(&builder, &hysteria);
    hysteria.version = 2;
    hysteria.obfs = Some("salamander".into());
    reject(&builder, &hysteria);
    let mut plugin = fixture.node("shadowsocks");
    plugin.plugin = Some("v2ray-plugin".into());
    plugin.plugin_opt = Some("mode=quic".into());
    reject(&builder, &plugin);
    let mut stock = fixture.node("vless");
    stock.network = Some("ws".into());
    reject(&SingBoxConfigBuilder::new(), &stock);
}
