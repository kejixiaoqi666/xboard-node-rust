# Certificate interoperability fixture

`pebble.rs` is a real ACME HTTP-01 lifecycle gate, ignored by the ordinary suite.
It requires an isolated loopback [Pebble](https://github.com/letsencrypt/pebble)
instance. It does not request production certificates or call Cloudflare.

Use the upstream test TLS certificate/key and `test/certs/pebble.minica.pem` from
the same Pebble release. Bind the CA and management listener to loopback. Set its
`httpPort` to a free port shared with the test, e.g. 5009. The Rust fixture binds
both 127.0.0.1 and ::1 because Pebble may choose the first localhost DNS address.
Set `PEBBLE_VA_NOSLEEP=1`, `PEBBLE_AUTHZREUSE=0`, `PEBBLE_WFE_NONCEREJECT=0`, and
`PEBBLE_VA_ALWAYS_VALID=0`. Never bypass challenge validation.

After starting the isolated CA, run:

```sh
XBOARD_PEBBLE_DIRECTORY=https://localhost:14009/dir \
XBOARD_PEBBLE_CA=/absolute/path/pebble.minica.pem \
XBOARD_PEBBLE_HTTP_PORT=5009 \
cargo test -p node-admin --test pebble -- --ignored --nocapture
```

The test rejects any non-loopback CA URL. It checks initial issuance, forced
renewal, unchanged account credentials, process-local manager recreation,
retention of old version files, and failure against a closed local CA port
without changing the last committed certificate pair. Unix checks also require
the private account file to have mode 0600. The ordinary suite verifies mode
selection, file/key matching, content mode, renewal scheduling, exclusive locks,
strict challenge serving, and a loopback mock of Cloudflare zone discovery,
TXT creation, owned-record cleanup, and redacted API failures.
The first issuance deliberately uses an earlier captured request timestamp so
the notBefore check also covers issuance crossing a wall-clock second boundary.

The module uses `instant-acme` 0.8.5 and `rcgen` 0.14 with the ring backend.
Certificate/key generations and account credentials are written privately;
`current.json` switches to a complete generation only after both files are
validated and synced. Renewals are requested by calling `ensure` repeatedly.
Valid legacy Go `cert.pem`/`key.pem` files are adopted into the version store,
and a malformed committed pointer fails closed instead of being ignored.
The caller owns the HTTP listener and the policy for keeping an active old
certificate when `ensure` reports an issuance failure. DNS cancellation cleanup
is bounded and best effort while the Tokio runtime remains available.

# Configuration import contract

`import_go_yaml` uses the current process working directory for explicit relative
Go paths. `import_go_yaml_with_working_directory` accepts the original Go process
working directory when migrating from another location. Only the default
`config_dir` derives from the source YAML location, matching the original loader.
Multi-instance inheritance and whole-block per-node certificate replacement
follow the Go source, and duplicate/nested state directories fail validation.

`FleetConfig.required_runtime_features` must be checked before launching nodes.
The runtime receives baseline JSON plus typed node, WS, kernel, logging,
certificate, health, standalone and machine template data. Go GC settings,
unknown fields, unsupported provider configuration and inactive ambiguous
settings fail explicitly. Machine discovery itself is the runtime's task.

Panel/machine tokens, inline certificate/key material, DNS credentials,
standalone snapshots and custom kernel JSON are moved into `SecretPlan`.
Public serialization and Debug show references only. A caller may explicitly
write a new private JSON secret store; the create-only API never overwrites an
existing store. The plan/store resolves saved values first and named process
environment references second. `StandaloneRef::resolve` and
`KernelSettings::resolve_custom_*` retrieve typed private input for the runtime.
The imported fleet itself is not proof that those runtime features are supported.

Verified locally on 2026-10-03 with the official Pebble v2.10.1 Windows artifact.
Archive SHA256 (matched to GitHub release asset digest):
`2539f3903302d75f897522b23b1b52b3300f5f992245f13d3bdf3967cf23af6d`.
The Linux permission assertions require the Linux CI/integration run as well.
