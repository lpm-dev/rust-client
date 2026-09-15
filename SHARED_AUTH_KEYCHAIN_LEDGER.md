# Shared auth Keychain finding

| ID | Source | Category | Location | Claim | Evidence | Disposition | Coverage | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AUTH-RUST | Primary agent | Security | `crates/lpm-auth` macOS auth queries | Queries omitted the shared access group and Data Protection selection. | A query-scope regression failed before the native query change. | Verified | Scoped native queries, six migration/recovery cases, signed Rust/Swift interoperability | `c98b86eb` | Concept PR |

Totals: one direct finding, one verified and fixed, zero rejected, zero externally blocked findings, zero pending findings. Subagent findings received: zero.

The companion Vault finding and release dependencies are recorded in lpm-dev/lpm-vault#24.

## Validation

- Rust 1.94.0 workspace build, formatting, and all-target clippy with warnings denied.
- Fast workspace nextest: 6,307 passed, nine skipped.
- CLI unit tests, serial: 5,131 passed, ten ignored.
- CLI integration nextest: 99 passed.
- Repository shell, installer, benchmark-helper, and npm wrapper/release checks passed. Native fish execution was skipped because fish is unavailable.
- Signed native Keychain round trip and absent-item deletion passed.
- A signed Swift helper read Rust's synthetic credential, replaced it, and Rust read the replacement. Test credentials were deleted.

The native deletion test requires a signed bundle and provisioning profile. An unsigned test executable receives the expected missing-entitlement error, so this test runs in the signed opt-in suite.
