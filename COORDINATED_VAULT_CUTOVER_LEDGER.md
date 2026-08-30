# Rust-client coordinated vault cutover ledger

Concept branch: `codex/coordinated-vault-rust-cutover`

Implementation commits: `a66ff0e9`, `b62eab1f`

Concept pull request: [lpm-dev/rust-client#671](https://github.com/lpm-dev/rust-client/pull/671)

Related merged pull requests:

- App: [lpm-dev/lpm-vault#17](https://github.com/lpm-dev/lpm-vault/pull/17)
- Server: [tolgaergin/a-package-manager#155](https://github.com/tolgaergin/a-package-manager/pull/155)

| ID | Source | Category | Location | Claim | Evidence | Disposition | Coverage | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| COR-007B / SEC-SYNC-001B-RUST | correctness audit and security audit | Correctness and security | `crates/lpm-vault/src/sync/{envelope,http,personal,org}.rs` | The Rust client verified the response HMAC but did not bind a successful personal or organization response to one request, vault, scope, crypto version, or payload digest. It also did not send the protocol-v2 request nonce required for strict server interoperability. | Before the production change, focused regressions failed because the client emitted no nonce and accepted signed cross-vault, replayed-nonce, scope, canonical organization slug, envelope-version, server-version, non-positive-version, payload-digest, partial-payload, and crypto-downgrade substitutions. The shared implementation now generates 32 random bytes as 43-character unpadded base64url, preserves the 10 MiB body cap and HMAC verification, deserializes each success once, and validates every binding before decryption or success return. | Verified | Cross-language payload-digest fixture; nonce wire-format and header capture; personal and organization success envelopes; substitution, replay, downgrade, missing-binding, partial-payload, migration, HMAC, and bounded-response regressions | `a66ff0e9` | Included in [#671](https://github.com/lpm-dev/rust-client/pull/671) |
| COR-008 / TEST-SYNC-001 | primary post-fix CI review | Correctness | `tests/workflows/tests/{support/mock_registry.rs,env_vault.rs,cross_command_flows.rs}` | Workflow mock servers returned signed v1-shaped personal and organization sync responses, so the strict v2 client rejected ten macOS workflow tests before they reached their intended assertions. | The macOS workspace job ran 13,573 tests and failed ten vault workflows with `authenticated sync envelope version is missing or unsupported`. A focused local run of `env_pull_overwrites_local_state_with_remote_environments` reproduced the same failure. The shared workflow responder now echoes the request nonce and binds the vault, scope, server version, crypto version, and payload digest; personal and organization fixtures now use protocol-v2 associated-data encryption. | Verified | Full `env_vault` workflow target (85 passed) and focused cross-machine stateful push/pull round trip (1 passed) | `b62eab1f` | Included in [#671](https://github.com/lpm-dev/rust-client/pull/671) |

## Performance analysis

Envelope validation is linear in the signed response size. The payload digest streams the domain, two big-endian lengths, and the two UTF-8 fields directly into SHA-256 without building a concatenated buffer. A successful body is deserialized once into the shared response type. The existing 10 MiB response cap remains in force before parsing, and the boxed success variant keeps the HTTP result enum small.

## Verification

- `cargo test -p lpm-vault --locked`: 204 passed, 2 intentionally ignored.
- `cargo clippy -p lpm-vault --all-targets --all-features --locked -- -D warnings`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy -p lpm-workflows --all-targets --locked -- -D warnings`: passed after the workflow fixture correction.
- `cargo test -p lpm-workflows --test env_vault --locked`: 85 passed after reproducing the pre-fix envelope-version failure locally.
- `cargo test -p lpm-workflows --test cross_command_flows flow_env_push_pull_cross_machine_round_trip --locked -- --exact`: passed.
- The broad workspace test run reached the CLI suite with 4,958 passed, 4 unrelated process-global environment races, and 8 ignored. The four failures all passed when rerun in isolation; the matching filter produced 5 passing tests because one filter also selected a neighboring negative case.
- Install-readiness was not run because no shared install path changed.

## Final totals

- Findings received for the Rust-client phase: 2.
- Findings verified and fixed: 2.
- Findings rejected with evidence: 0.
- Findings externally blocked: 0.
- Findings still pending: 0.
