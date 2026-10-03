use super::{
    CipherSuite,
    hello::*,
    reality_auth::{derive_auth_key, perform_ecdh},
    reality_server_connection::{HandshakeState, RealityServerConfig, RealityServerConnection},
    reality_tls13_messages::construct_server_hello_for_group,
};
use ml_kem::{
    MlKem768,
    kem::{Kem, KeyExport},
};
use ring::{aead, digest};

fn vector(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out
}
fn extension(id: u16, data: &[u8]) -> Vec<u8> {
    let mut out = id.to_be_bytes().to_vec();
    out.extend(vector(data));
    out
}
fn record(message: &[u8]) -> Vec<u8> {
    let mut out = vec![22, 3, 3];
    out.extend(vector(message));
    out
}
fn hello(shares: &[(u16, Vec<u8>)], sid: &[u8], random: &[u8; 32], sni: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend(random);
    body.push(32);
    body.extend(sid);
    body.extend(vector(&[0x13, 1, 0x13, 2, 0x13, 3]));
    body.extend([1, 0]);
    let mut extensions = extension(43, &[2, 3, 4]);
    extensions.extend(extension(10, &vector(&[0, 29, 0x11, 0xec, 0, 23])));
    extensions.extend(extension(0, sni));
    let mut key_shares = Vec::new();
    for (g, k) in shares {
        key_shares.extend(g.to_be_bytes());
        key_shares.extend(vector(k));
    }
    extensions.extend(extension(51, &vector(&key_shares)));
    body.extend(vector(&extensions));
    let n = body.len();
    let mut message = vec![1, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    message.extend(body);
    record(&message)
}
fn config() -> RealityServerConfig {
    RealityServerConfig {
        private_key: [0x22; 32],
        short_ids: vec![[0x12, 0x34, 0, 0, 0, 0, 0, 0]],
        server_name: "localhost".into(),
        max_time_diff: None,
        min_client_version: None,
        max_client_version: None,
        cipher_suites: Vec::new(),
        key_update_after_records: 1 << 20,
    }
}
fn authenticate(mut hello: Vec<u8>) -> Vec<u8> {
    let parsed = parse_client(&hello).unwrap();
    let key = derive_auth_key(
        &perform_ecdh(&config().private_key, &parsed.auth_public().unwrap()).unwrap(),
        &parsed.random[..20],
        b"REALITY",
    )
    .unwrap();
    let nonce: aead::Nonce = aead::Nonce::try_assume_unique_for_key(&parsed.random[20..]).unwrap();
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
    let mut plain = vec![26, 3, 27, 0, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 0, 0, 0];
    key.seal_in_place_append_tag(nonce, aead::Aad::from(&hello[5..]), &mut plain)
        .unwrap();
    hello[44..76].copy_from_slice(&plain);
    hello
}
fn xkey() -> Vec<u8> {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x11; 32]))
        .as_bytes()
        .to_vec()
}
fn first() -> Vec<u8> {
    authenticate(hello(
        &[(X25519, xkey())],
        &[0; 32],
        &[0x42; 32],
        b"fixed-sni",
    ))
}
fn hrr(sid: &[u8], group: u16) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend(HRR_RANDOM);
    body.push(32);
    body.extend(sid);
    body.extend([0x13, 2, 0]);
    let mut ext = extension(43, &[3, 4]);
    ext.extend(extension(51, &group.to_be_bytes()));
    body.extend(vector(&ext));
    let n = body.len();
    let mut msg = vec![2, 0, (n >> 8) as u8, n as u8];
    msg.extend(body);
    record(&msg)
}
fn prepared() -> (RealityServerConnection, Vec<u8>, Vec<u8>) {
    let first = first();
    let mut session = RealityServerConnection::new(config()).unwrap();
    session.validate_client_hello(&first).unwrap();
    let initial = parse_client(&first).unwrap();
    let retry = hrr(initial.session_id, SECP256R1);
    session.observe_hello_retry_request(&retry).unwrap();
    let private = ring::agreement::EphemeralPrivateKey::generate(
        &ring::agreement::ECDH_P256,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let share = private.compute_public_key().unwrap().as_ref().to_vec();
    let second = hello(
        &[(SECP256R1, share)],
        initial.session_id,
        &initial.random.try_into().unwrap(),
        b"fixed-sni",
    );
    (session, retry, second)
}

#[test]
fn hybrid_only_authentication_and_classical_preference_match_xray() {
    let (_dk, ek) = MlKem768::generate_keypair();
    let mut hybrid = ek.to_bytes().to_vec();
    hybrid.extend(xkey());
    let first = authenticate(hello(
        &[(X25519_MLKEM768, hybrid.clone())],
        &[0; 32],
        &[0x42; 32],
        b"fixed-sni",
    ));
    let mut session = RealityServerConnection::new(config()).unwrap();
    session.validate_client_hello(&first).unwrap();
    // The hybrid classical half may differ. A separate X25519 share wins for auth.
    hybrid[MLKEM_PUBLIC_LEN..].fill(0x55);
    let both = authenticate(hello(
        &[(X25519_MLKEM768, hybrid), (X25519, xkey())],
        &[0; 32],
        &[0x42; 32],
        b"fixed-sni",
    ));
    RealityServerConnection::new(config())
        .unwrap()
        .validate_client_hello(&both)
        .unwrap();
}

#[test]
fn retry_transcript_uses_hrr_suite_hash_and_preserves_original_auth() {
    let (mut session, retry, second) = prepared();
    let original = first();
    let first_auth = match &session.handshake_state {
        HandshakeState::ClientHelloValidated { info } => info.auth_key,
        _ => panic!(),
    };
    session.validate_retry_client_hello(&second).unwrap();
    let HandshakeState::ClientHelloValidated { info } = &session.handshake_state else {
        panic!()
    };
    let hash = digest::digest(&digest::SHA384, &original[5..]);
    let mut expected = vec![254, 0, 0, 48];
    expected.extend(hash.as_ref());
    expected.extend(&retry[5..]);
    assert_eq!(info.transcript_prefix, expected);
    assert_eq!(info.auth_key, first_auth);
    assert_eq!(info.client_hello_handshake, &second[5..]);
    assert_eq!(info.cipher_suite, CipherSuite::AES_256_GCM_SHA384);
    assert!(session.observe_hello_retry_request(&retry).is_err());
    assert!(session.validate_retry_client_hello(&second).is_err());
}

#[test]
fn retry_identity_changes_fail_before_response() {
    for offset in [11usize, 44, 78] {
        let (mut session, _, mut second) = prepared();
        second[offset] ^= 1;
        assert!(session.validate_retry_client_hello(&second).is_err());
        assert!(!session.wants_write());
    }
    let (mut session, _, second) = prepared();
    let parsed = parse_client(&second).unwrap();
    let changed = hello(
        &[(SECP256R1, parsed.shares[&SECP256R1].to_vec())],
        parsed.session_id,
        &parsed.random.try_into().unwrap(),
        b"other-sni",
    );
    assert!(session.validate_retry_client_hello(&changed).is_err());
}

#[test]
fn invalid_retry_already_offered_group_and_repeated_hrr_are_rejected() {
    let first = first();
    let mut session = RealityServerConnection::new(config()).unwrap();
    session.validate_client_hello(&first).unwrap();
    let sid = parse_client(&first).unwrap().session_id;
    assert!(
        session
            .observe_hello_retry_request(&hrr(sid, X25519))
            .is_err()
    );
    let mut bad = hrr(sid, SECP256R1);
    bad[44] ^= 1;
    assert!(session.observe_hello_retry_request(&bad).is_err());
}

#[test]
fn invalid_hybrid_encoding_is_rejected_without_output() {
    let mut share = vec![0xff; MLKEM_PUBLIC_LEN];
    share.extend(xkey());
    let first = authenticate(hello(
        &[(X25519_MLKEM768, share)],
        &[0; 32],
        &[0x42; 32],
        b"fixed-sni",
    ));
    let mut session = RealityServerConnection::new(config()).unwrap();
    session.validate_client_hello(&first).unwrap();
    let server = construct_server_hello_for_group(
        &[0x33; 32],
        parse_client(&first).unwrap().session_id,
        0x1301,
        X25519_MLKEM768,
        &vec![0; 1120],
    )
    .unwrap();
    assert!(
        session
            .build_server_response(vec![record(&server).into()])
            .is_err()
    );
    assert!(!session.wants_write());
    assert!(session.process_new_packets().is_err());
}

#[tokio::test]
async fn outer_hrr_reassembles_fragmented_client_hello2_in_owned_future() {
    use super::{MirrorFlight, mirror_handshake};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, mut peer) = tokio::io::duplex(4096);
    let (mut mirror, mut destination) = tokio::io::duplex(4096);
    let (_, retry, second) = prepared();
    let parsed = parse_client(&second).unwrap();
    let sh = construct_server_hello_for_group(
        &[0x33; 32],
        parsed.session_id,
        0x1302,
        SECP256R1,
        parsed.shares[&SECP256R1],
    )
    .unwrap();
    let mut session = RealityServerConnection::new(config()).unwrap();
    session.validate_client_hello(&first()).unwrap();
    let mut wire = Vec::new();
    let mut begin = 5;
    for end in [6, 7, 8, 44, 60, second.len()] {
        wire.extend([22, 3, 3]);
        wire.extend(vector(&second[begin..end]));
        begin = end;
    }
    let mirror_expected = wire.clone();
    let peer_work = async {
        let mut received = vec![0; retry.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, retry);
        peer.write_all(&[20, 3, 3, 0, 1, 1]).await.unwrap();
        peer.write_all(&wire).await.unwrap();
        let mut ccs = [0; 6];
        peer.read_exact(&mut ccs).await.unwrap();
        assert_eq!(ccs, [20, 3, 3, 0, 1, 1]);
    };
    let mirror_work = async {
        destination.write_all(&retry).await.unwrap();
        destination.write_all(&[20, 3, 3, 0, 1, 1]).await.unwrap();
        let mut client_ccs = [0; 6];
        destination.read_exact(&mut client_ccs).await.unwrap();
        assert_eq!(client_ccs, [20, 3, 3, 0, 1, 1]);
        let mut received = vec![0; mirror_expected.len()];
        destination.read_exact(&mut received).await.unwrap();
        assert_eq!(received, mirror_expected);
        destination.write_all(&record(&sh)).await.unwrap();
        for n in [23usize, 384, 95, 69] {
            let mut encrypted = vec![23, 3, 3];
            encrypted.extend(vector(&vec![0; n]));
            destination.write_all(&encrypted).await.unwrap();
        }
    };
    let work = async {
        mirror_handshake(&mut session, &mut client, &mut mirror)
            .await
            .unwrap()
    };
    let (flight, (), ()) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::join!(work, peer_work, mirror_work)
    })
    .await
    .unwrap();
    let MirrorFlight::Ready(records) = flight else {
        panic!("valid retry fell back")
    };
    assert_eq!(records.len(), 5);
    session.build_server_response(records).unwrap();
    assert!(session.wants_write());
}

#[tokio::test]
async fn outer_mirror_wait_and_incomplete_retry_can_be_cancelled() {
    use super::mirror_handshake;
    use tokio::io::AsyncWriteExt;
    let (mut client, _peer) = tokio::io::duplex(128);
    let (mut mirror, mut destination) = tokio::io::duplex(128);
    let mut session = RealityServerConnection::new(config()).unwrap();
    session.validate_client_hello(&first()).unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            mirror_handshake(&mut session, &mut client, &mut mirror)
        )
        .await
        .is_err()
    );
    let (_, retry, _) = prepared();
    destination.write_all(&retry).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            mirror_handshake(&mut session, &mut client, &mut mirror)
        )
        .await
        .is_err()
    );
}

#[test]
fn strict_hello_rejects_every_truncation_and_invalid_vector_lengths() {
    let hello = first();
    for n in 0..hello.len() {
        assert!(parse_client(&hello[..n]).is_err());
    }
    let mut extra = hello.clone();
    extra.push(0);
    assert!(parse_client(&extra).is_err());
    let mut odd = hello;
    odd[77] ^= 1;
    assert!(parse_client(&odd).is_err());
    let valid = hrr(&[0x55; 32], SECP256R1);
    for n in 0..valid.len() {
        assert!(parse_server(&valid[..n]).is_err());
    }
}

#[test]
fn mldsa_certificate_binds_both_hellos_and_first_extension() {
    use super::reality_certificate::generate_certificate;
    use ml_dsa::{Keypair, MlDsa65, Signature, SigningKey, Verifier};
    use ring::{hmac, signature::KeyPair};
    let key = SigningKey::<MlDsa65>::from_seed(&[0x23; 32].into());
    let (cert, ed) =
        generate_certificate(&[0x22; 32], "localhost", Some(&key), b"CH2", b"SH2").unwrap();
    let (_, x509) = x509_parser::parse_x509_certificate(cert.der()).unwrap();
    let ext = &x509.extensions()[0];
    // 0.0 is encoded as one zero octet; x509-parser's display collapses this OID.
    assert_eq!(ext.oid.as_bytes(), &[0]);
    assert_eq!(ext.value.len(), 3309);
    let signature = Signature::<MlDsa65>::try_from(ext.value).unwrap();
    let mut context = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, &[0x22; 32]));
    context.update(ed.public_key().as_ref());
    context.update(b"CH2");
    context.update(b"SH2");
    key.verifying_key()
        .verify(context.sign().as_ref(), &signature)
        .unwrap();
    let mut changed = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, &[0x22; 32]));
    changed.update(ed.public_key().as_ref());
    changed.update(b"CH1");
    changed.update(b"SH2");
    assert!(
        key.verifying_key()
            .verify(changed.sign().as_ref(), &signature)
            .is_err()
    );
}
