use base64::{Engine, engine::general_purpose::STANDARD};
use node_core::shadowsocks::{Cipher, Settings, user_password};

#[test]
fn original_go_conversion_is_utf8_byte_copy_zero_fill_and_truncate() {
    for method in [Cipher::Aes128V2, Cipher::Aes256V2] {
        for text in [
            "abc",
            "中文密钥测试中文密钥测试中文密钥测试",
            "0123456789012345678901234567890123456789",
        ] {
            let result = STANDARD
                .decode(user_password(method, text).as_ref())
                .unwrap();
            let n = text.len().min(method.key_len());
            assert_eq!(result.len(), method.key_len());
            assert_eq!(&result[..n], &text.as_bytes()[..n]);
            assert!(result[n..].iter().all(|x| *x == 0));
        }
    }
    for method in [Cipher::Aes128, Cipher::Aes256, Cipher::Chacha20] {
        assert_eq!(user_password(method, "raw password"), "raw password");
    }
}
#[test]
fn key_validation_and_redacted_debug_have_explicit_subset() {
    for method in [Cipher::Aes128V2, Cipher::Aes256V2] {
        let key = STANDARD.encode(vec![42; method.key_len()]);
        let settings = Settings {
            method,
            password: Some(key.clone()),
        };
        settings.validate().unwrap();
        assert!(!format!("{settings:?}").contains(&key));
        for password in [
            None,
            Some("bad".into()),
            Some(STANDARD.encode(vec![0; method.key_len() - 1])),
            Some(format!("{key}:{key}")),
        ] {
            assert!(Settings { method, password }.validate().is_err());
        }
    }
    assert!(
        Settings {
            method: Cipher::Aes128,
            password: Some("unneeded".into())
        }
        .validate()
        .is_err()
    );
    for name in [
        "none",
        "aes-128-cfb",
        "2022-blake3-chacha20-poly1305",
        "unknown",
    ] {
        assert!(serde_json::from_value::<Cipher>(serde_json::json!(name)).is_err());
    }
}
