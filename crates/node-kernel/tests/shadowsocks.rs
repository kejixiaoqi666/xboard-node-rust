use node_core::{
    NodeSpec, UserSpec,
    shadowsocks::{Cipher, user_password},
};
use node_kernel::SingBoxConfigBuilder;

#[test]
fn native_all_cipher_configs_preserve_user_names_limits_and_original_password_conversion() {
    for method in [
        Cipher::Aes128,
        Cipher::Aes256,
        Cipher::Chacha20,
        Cipher::Aes128V2,
        Cipher::Aes256V2,
    ] {
        let mut node = NodeSpec::new("shadowsocks", 8443);
        node.cipher = Some(method.name().into());
        if method.is_v2() {
            node.server_key = Some(user_password(method, "server-key").into_owned());
        }
        let users = [
            UserSpec::new(7, "user-first-key").with_limits(8, 2),
            UserSpec::new(8, "user-second-key"),
        ];
        let builder = SingBoxConfigBuilder::native();
        let json = builder.build(&node, &users).unwrap();
        let inbound = &json["inbounds"][0];
        assert_eq!(inbound["type"], "shadowsocks");
        assert_eq!(inbound["tag"], "shadowsocks-in");
        assert_eq!(inbound["method"], method.name());
        assert_eq!(inbound["users"][0]["name"], "7");
        assert_eq!(inbound["users"][0]["speed_limit"], 8);
        assert_eq!(inbound["users"][0]["device_limit"], 2);
        assert_eq!(
            inbound["users"][0]["password"],
            user_password(method, "user-first-key").as_ref()
        );
        assert!(inbound["users"][0].get("uuid").is_none());
        let mut bytes = Vec::new();
        builder.write_json(&mut bytes, &node, &users).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            json
        );
        assert!(SingBoxConfigBuilder::new().build(&node, &users).is_err());
    }
}
#[test]
fn native_rejects_uuid_prefix_collisions_unknown_cipher_and_bounded_classic_users() {
    let mut node = NodeSpec::new("shadowsocks", 8443);
    node.cipher = Some(Cipher::Aes128V2.name().into());
    node.server_key = Some(user_password(Cipher::Aes128V2, "server-key").into_owned());
    let builder = SingBoxConfigBuilder::native();
    let users = [
        UserSpec::new(7, "0123456789012345-a"),
        UserSpec::new(8, "0123456789012345-b"),
    ];
    let mut out = Vec::new();
    assert!(builder.write_json(&mut out, &node, &users).is_err());
    assert!(out.is_empty());
    node.cipher = Some("2022-blake3-chacha20-poly1305".into());
    assert!(builder.build(&node, &[]).is_err());
    node.cipher = Some("aes-128-gcm".into());
    node.server_key = None;
    let users = (0..257)
        .map(|n| UserSpec::new(n, format!("password-{n}")))
        .collect::<Vec<_>>();
    assert!(builder.build(&node, &users[..256]).is_ok());
    assert!(builder.build(&node, &users).is_err());
}
