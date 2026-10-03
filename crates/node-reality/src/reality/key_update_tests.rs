//! Wire-level rotation, framing and output-order regressions.
use super::*;

fn connection(cs: CipherSuite) -> RealityServerConnection {
    RealityServerConnection::new(RealityServerConfig {
        private_key: [0; 32],
        short_ids: vec![[0; 8]],
        server_name: "localhost".into(),
        max_time_diff: None,
        min_client_version: None,
        max_client_version: None,
        cipher_suites: vec![cs],
    })
    .unwrap()
    .complete_with_secrets_for_test(cs, secret(cs, 0), secret(cs, 1))
    .unwrap()
}
fn secret(cs: CipherSuite, seed: u8) -> Vec<u8> {
    (0..cs.digest_algorithm().output_len())
        .map(|n| seed.wrapping_add(n as u8))
        .collect()
}
fn record(cs: CipherSuite, secret: &[u8], seq: u64, body: &[u8], kind: u8) -> Vec<u8> {
    let (key, iv) = derive_traffic_keys(secret, cs).unwrap();
    let key = AeadKey::new(cs, &key).unwrap();
    let mut plain = body.to_vec();
    plain.push(kind);
    let n = plain.len() + 16;
    let header = [23, 3, 3, (n >> 8) as u8, n as u8];
    let mut out = header.to_vec();
    out.extend(key.seal(&plain, &iv, seq, &header).unwrap());
    out
}
fn feed(s: &mut RealityServerConnection, data: &[u8]) -> io::Result<()> {
    feed_reality_server_connection(s, data)?;
    s.process_new_packets().map(|_| ())
}
fn decrypt_first(cs: CipherSuite, secret: &[u8], seq: u64, wire: &mut Vec<u8>) -> (u8, Vec<u8>) {
    let n = u16::from_be_bytes([wire[3], wire[4]]) as usize;
    let mut r: Vec<_> = wire.drain(..n + 5).collect();
    let (key, iv) = derive_traffic_keys(secret, cs).unwrap();
    let key = AeadKey::new(cs, &key).unwrap();
    let mut seq = seq;
    let (kind, plain) = RecordDecryptor::new(&key, &iv, &mut seq)
        .decrypt_record_in_place(&mut r[5..], n as u16)
        .unwrap();
    (kind, plain.to_vec())
}

#[test]
fn traffic_update_matches_independent_hmac_vectors() {
    // Python standard-library HMAC over the RFC 8446 HkdfLabel; no
    // production derivation function used to calculate these expected values.
    for (cs, expected) in [
        (
            CipherSuite::AES_128_GCM_SHA256,
            "2cecd0a17506ef5fa73edc062d6e7b5397cf074ec1b4d8f99a120772932f0b45",
        ),
        (
            CipherSuite::AES_256_GCM_SHA384,
            "401331b63e9d59f202e8f041042d9516f4cd7fa2e2ee14631d3b49fc340d7af37fc2c0c9f252d8036f81ec5b85cbe5db",
        ),
        (
            CipherSuite::CHACHA20_POLY1305_SHA256,
            "2cecd0a17506ef5fa73edc062d6e7b5397cf074ec1b4d8f99a120772932f0b45",
        ),
    ] {
        let got = update_traffic_secret(&secret(cs, 0), cs).unwrap();
        assert_eq!(
            got.iter().map(|v| format!("{v:02x}")).collect::<String>(),
            expected
        );
        assert!(update_traffic_secret(&[0; 31], cs).is_err());
    }
}
#[test]
fn repeated_peer_rotation_preserves_application_data_all_suites() {
    for cs in DEFAULT_CIPHER_SUITES {
        let mut s = connection(*cs);
        let mut current = secret(*cs, 0);
        for _ in 0..8 {
            let mut wire = record(*cs, &current, 0, b"before", 23);
            wire.extend(record(*cs, &current, 1, &[24, 0, 0, 1, 0], 22));
            current = update_traffic_secret(&current, *cs).unwrap();
            wire.extend(record(*cs, &current, 0, b"after", 23));
            feed(&mut s, &wire).unwrap();
            let mut body = [0; 11];
            s.reader().read_exact(&mut body).unwrap();
            assert_eq!(&body, b"beforeafter");
            assert!(!s.wants_write());
            // Next generation starts after its first data record already read.
            let ku = record(*cs, &current, 1, &[24, 0, 0, 1, 0], 22);
            feed(&mut s, &ku).unwrap();
            current = update_traffic_secret(&current, *cs).unwrap();
        }
    }
}
#[test]
fn fragmented_key_update_ends_at_record_boundary() {
    let cs = CipherSuite::AES_128_GCM_SHA256;
    let initial = secret(cs, 0);
    for cut in 1..5 {
        let mut s = connection(cs);
        let ku = [24, 0, 0, 1, 1];
        feed(&mut s, &record(cs, &initial, 0, &ku[..cut], 22)).unwrap();
        assert!(!s.wants_write());
        let mut tail = record(cs, &initial, 1, &ku[cut..], 22);
        tail.extend(record(
            cs,
            &update_traffic_secret(&initial, cs).unwrap(),
            0,
            b"data",
            23,
        ));
        // TCP-byte fragmentation is independent of TLS handshake fragmentation.
        for byte in tail {
            feed(&mut s, &[byte]).unwrap();
        }
        let mut body = [0; 4];
        s.reader().read_exact(&mut body).unwrap();
        assert_eq!(&body, b"data");
        assert!(s.wants_write());
    }
}
#[test]
fn malformed_interleaved_and_unannounced_rotation_fail_permanently() {
    let cs = CipherSuite::AES_128_GCM_SHA256;
    let initial = secret(cs, 0);
    for data in [
        vec![24, 0, 0, 1, 2],
        vec![24, 0, 0, 2, 0],
        vec![4, 0, 0, 1, 0],
        vec![24, 0, 0, 1, 0, 24],
        vec![],
    ] {
        let mut s = connection(cs);
        assert!(feed(&mut s, &record(cs, &initial, 0, &data, 22)).is_err());
        assert!(s.process_new_packets().is_err());
        assert!(s.write_tls(&mut Vec::new()).is_err());
    }
    for kind in [23, 21] {
        let mut s = connection(cs);
        feed(&mut s, &record(cs, &initial, 0, &[24, 0], 22)).unwrap();
        assert!(feed(&mut s, &record(cs, &initial, 1, &[1, 0], kind)).is_err());
    }
    let mut s = connection(cs);
    assert!(
        feed(
            &mut s,
            &record(
                cs,
                &update_traffic_secret(&initial, cs).unwrap(),
                0,
                b"skip",
                23
            )
        )
        .is_err()
    );
    let mut s = connection(cs);
    feed(&mut s, &record(cs, &initial, 0, &[24, 0, 0, 1, 0], 22)).unwrap();
    assert!(feed(&mut s, &record(cs, &initial, 1, b"stale", 23)).is_err());
}
#[test]
fn response_uses_old_write_key_then_new_data_sequence_zero() {
    for cs in DEFAULT_CIPHER_SUITES {
        let mut s = connection(*cs);
        let read = secret(*cs, 0);
        let write = secret(*cs, 1);
        s.writer().write_all(b"already-encrypted").unwrap();
        struct Block;
        impl Write for Block {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::WouldBlock.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            s.write_tls(&mut Block).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        feed(&mut s, &record(*cs, &read, 0, &[24, 0, 0, 1, 1], 22)).unwrap();
        s.writer().write_all(b"new-data").unwrap();
        let mut wire = Vec::new();
        s.write_tls(&mut wire).unwrap();
        assert_eq!(
            decrypt_first(*cs, &write, 0, &mut wire),
            (23, b"already-encrypted".to_vec())
        );
        assert_eq!(
            decrypt_first(*cs, &write, 1, &mut wire),
            (22, vec![24, 0, 0, 1, 0])
        );
        assert_eq!(
            decrypt_first(
                *cs,
                &update_traffic_secret(&write, *cs).unwrap(),
                0,
                &mut wire
            ),
            (23, b"new-data".to_vec())
        );
        assert!(wire.is_empty());
        assert!(!s.wants_write());
    }
}
#[test]
fn requests_coalesce_before_write_and_close_uses_updated_key() {
    let cs = CipherSuite::AES_128_GCM_SHA256;
    let mut s = connection(cs);
    let mut read = secret(cs, 0);
    let write = secret(cs, 1);
    for _ in 0..100 {
        feed(&mut s, &record(cs, &read, 0, &[24, 0, 0, 1, 1], 22)).unwrap();
        read = update_traffic_secret(&read, cs).unwrap();
    }
    assert!(s.ciphertext_write_buf.is_empty());
    assert!(s.key_update_response_pending);
    s.send_close_notify();
    let mut wire = Vec::new();
    s.write_tls(&mut wire).unwrap();
    assert_eq!(
        decrypt_first(cs, &write, 0, &mut wire),
        (22, vec![24, 0, 0, 1, 0])
    );
    assert_eq!(
        decrypt_first(
            cs,
            &update_traffic_secret(&write, cs).unwrap(),
            0,
            &mut wire
        ),
        (21, vec![1, 0])
    );
    assert!(wire.is_empty());
}
