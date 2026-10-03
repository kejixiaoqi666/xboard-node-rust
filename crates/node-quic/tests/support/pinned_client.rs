//! Only fixed, reviewed official binaries may be executed by wire fixtures.
use std::{io::Read, path::PathBuf};

pub fn binary() -> PathBuf {
    let expected = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "7bbef1dea9189ee12799ae834ea4b4658355da25c47a21ad8804904c0ccd9410",
        ("linux", "x86_64") => "fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8",
        ("linux", "aarch64") => "b8610f45abb7e967e195264383f5cbd20fba7821a3c37e3a8c4c5ab6cad28eac",
        platform => {
            panic!("official sing-box v1.14.2 has no reviewed fixture pin for {platform:?}")
        }
    };
    let binary = PathBuf::from(
        std::env::var_os("SING_BOX_BIN")
            .expect("set SING_BOX_BIN to the pinned official sing-box v1.14.2 binary"),
    );
    let file = std::fs::File::open(&binary).expect("open official fixture binary");
    const MAX_BINARY: u64 = 256 * 1024 * 1024;
    let metadata = file.metadata().unwrap();
    assert!(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= MAX_BINARY,
        "official fixture must be a bounded regular executable file"
    );
    let mut reader = file.take(MAX_BINARY + 1);
    // SHA256 is supplied by the same existing rustls/ring crypto provider.
    let mut hash = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("fixed TLS13 suite")
        .common
        .hash_provider
        .start();
    let mut buffer = [0u8; 16 * 1024];
    let mut length = 0;
    loop {
        let size = reader
            .read(&mut buffer)
            .expect("hash official fixture binary");
        if size == 0 {
            break;
        }
        length += size as u64;
        assert!(
            length <= MAX_BINARY,
            "fixture changed beyond its size limit"
        );
        hash.update(&buffer[..size]);
    }
    let digest = hash.finish();
    let actual = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        actual, expected,
        "official fixture binary SHA256 mismatch for current OS/architecture"
    );
    let version = std::process::Command::new(&binary)
        .arg("version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("sing-box version 1.14.2"));
    binary
}
