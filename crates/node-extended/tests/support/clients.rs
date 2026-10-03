//! Strict binary pins shared by codec and native integration fixtures.
pub fn expected_binary_sha256(client: &str) -> String {
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "windows-amd64",
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        other => panic!("no official {client} binary pin for {other:?}"),
    };
    let lock: serde_json::Value =
        serde_json::from_str(include_str!("../clients-lock.json")).unwrap();
    lock["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["client"] == client && entry["platform"] == platform)
        .unwrap_or_else(|| panic!("missing {client} {platform} official pin"))["binary_sha256"]
        .as_str()
        .unwrap()
        .to_owned()
}
