# REALITY outer handshake evidence

The compatibility reference is official Xray **v26.3.27** (`d2758a0`, Go
1.26.1), which pins XTLS/REALITY `9234c772ba8f` and uTLS
`aa6edf4b11af`. `evidence/upstream.json` records the exact fetched source hashes.
The existing shoes MIT source attribution and full LICENSE remain intact.

This change implements:

- Authentication from a standalone X25519 share, or the final 32 bytes of a
  final-standard X25519MLKEM768 share when X25519 is absent. A separate X25519
  share takes precedence, as it does in the pinned official server.
- Final-standard hybrid group 4588: client key share `ML-KEM768 public[1184] ||
  X25519 public[32]`, server share `ML-KEM ciphertext[1088] || X25519 public[32]`,
  shared secret `ML-KEM secret[32] || ECDH secret[32]`. RustCrypto supplies ML-KEM;
  the existing dalek code supplies X25519. There are no handwritten primitives.
- Optional Xray-compatible ML-DSA-65 seed and public verify-key derivation. The
  first certificate extension is OID 0.0, containing the 3309-byte signature of
  `HMAC-SHA512(AuthKey, Ed25519Public || ClientHello || public ServerHello)`.
  RustCrypto supplies the signature. Signing seeds and intermediate decoded
  copies are zeroized, and Debug omits private material.
- One group-changing outer HRR for X25519, group 4588, or P-256. Authentication
  remains bound to CH1. CH2 must preserve the authenticated identity, cipher
  offers and all extensions except key_share, cookie and zero-valued padding.
  A cookie, when present, must match exactly. Repeated HRR, unoffered groups,
  duplicate extensions, invalid lengths, PSK and early data fail closed.
- RFC 8446 transcript replacement
  `message_hash(Hash(CH1)) || HRR || CH2 || SH2`. P-256 is supplied by Ring and
  provides a real group-changing HRR with the pinned Chrome client. The pinned
  official REALITY interception path only accepts X25519/hybrid ServerHello;
  P-256 interception and bounded HRR are explicit extensions to that behavior.

The combined HRR + ML-DSA fixture found a pinned uTLS compatibility detail:
at Xray's `VerifyPeerCertificate`, public `HandshakeState.ServerHello.Raw` still
contains the HRR, while public `Hello.Raw` contains CH2. Its internal TLS state
already uses SH2. This server signs CH2 + HRR for that extra certificate signature
and still uses the complete RFC transcript through SH2 for CertificateVerify and
Finished. The successful actual client test confirms this behavior for the
fixed version only; compatibility with clients that update that public slot
earlier is not claimed.

The public key-tool APIs are `node_reality::generate_mldsa65_keypair() ->
io::Result<(String, String)>` (secret seed, public verify key) and
`node_reality::mldsa65_verify_key(&str) -> io::Result<String>`. The generator
draws an independent 32-byte seed from `OsRng`, encodes it as unpadded base64url,
and reuses the strict derivation routine. Returned seeds are intentionally
secret; temporary raw and encoded copies are zeroized.

## Running the real local fixture

`xray.rs` is ignored in the default suite. It runs the exported
`mirror_handshake` API used by `node-native`, finishes TLS with the official Xray
process, checks the authenticated VLESS UUID and TCP request, and exchanges a
46-byte binary payload through Xray's HTTP CONNECT inbound. It does not start
the controller, bill traffic, or claim installed-server/WAN acceptance.

The mirror is an actual local OpenSSL 3.5 TLS 1.3 server, listening only on
`127.0.0.1` with an ephemeral port. The fixture pins CPython 3.12 / 64-bit layout
and uses a fixture-only OpenSSL group-selection adapter. That Python code is
never linked into the Rust server. All subprocesses and proxy tasks are stopped
after their cases. No production CA, DNS provider or remote node is accessed.

Official Windows asset:
`https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip`

- Archive SHA256:
  `d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad`
- Executable SHA256:
  `15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1`

```powershell
$env:NODE_REALITY_XRAY = 'C:/absolute/verified/xray.exe'
$env:NODE_REALITY_PYTHON = 'C:/absolute/python-3.12-with-openssl-3.5/python.exe'
cargo test -p node-reality --test xray -- --ignored --nocapture
```

The real test covers classic X25519, hybrid, hybrid plus ML-DSA, rejection of a
wrong ML-DSA verify key after the authenticated encrypted TLS alert, real P-256
HRR with and without ML-DSA, and ML-DSA HRR with CH2 split across six actual TLS
records. It also compares the Rust derived ML-DSA public key against official
`xray mldsa65 -i` output without printing the seed. JSON record evidence records
each TLS header/length/group and SHA256; it contains no production credentials.

`evidence/validation.json` describes the checks that actually ran and hashes the
checked source. The local engine suite is separate from the parent's Linux
whole-workspace and installed-server gates. Windows native scoped tests can
report warnings in unrelated in-progress root modules; only node-reality's
isolated all-target Clippy result is claimed by this evidence.

## Explicit limits

This is not every TLS 1.3 feature. Cookie-only HRR, a second HRR, accepted ECH,
TLS resumption/PSK, 0-RTT, draft Kyber groups, other outer groups, or fragmented
mirror ServerHello are not intercepted. An incompatible initial mirror hello
is replayed intact before the existing fixed-mirror forwarding path. Invalid
authenticated retries are closed. ClientHello reassembly has a 16-record /
16KiB bound; mirror exchange has a 64KiB bound and runs in the caller's owned
future under its handshake deadline. RustCrypto's ML-KEM/ML-DSA packages state
that their implementations have not been independently audited; this fixture
proves interoperability and regression behavior, not an independent crypto
audit.
