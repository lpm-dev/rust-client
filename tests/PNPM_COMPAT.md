# PNPM Compat

This ledger tracks pnpm source scenarios that are useful for hardening LPM's
behavioral contracts. A row means one of three things:

- `passing` — LPM has a matching contract test that runs normally.
- `blocked:<gap>` — the LPM contract is planned, but the test is ignored until
  that named gap lands.
- `wont-port:<reason>` — the source scenario is pnpm-specific or an intentional
  divergence for LPM.

The workflow-tier `pnpm_compat_ledger` test verifies this table against the
`pnpm_compat_*.rs` test files.

| area | source | scenario | lpm test | status | notes |
| --- | --- | --- | --- | --- | --- |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:1181` | Optional peer warning suppression | `optional_peer_dependency_missing_does_not_warn_or_install_peer` | `passing` | LPM contract: a missing optional peer is silent and is not installed. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:1230` | Required missing peer is warning-only by default | `required_peer_dependency_missing_warns_and_succeeds_without_strict_mode` | `passing` | LPM contract: default mode keeps pnpm-compatible warn-only behavior when auto-install is disabled. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:1246` | `strict-peer-dependencies` fails missing peers | `strict_peer_dependencies_cli_fails_when_required_peer_is_missing` | `passing` | CLI strict mode turns missing required-peer warnings into install failures. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:1246` | `strict-peer-dependencies` config fails missing peers | `strict_peer_dependencies_global_config_fails_when_required_peer_is_missing` | `passing` | Global config `strict-peer-dependencies = true` turns missing required-peer warnings into install failures. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:36` | Peer ranges conflict across consumers | `strict_peer_dependencies_config_fails_when_peer_ranges_conflict` | `passing` | `lpm.strictPeerDependencies` turns best-effort peer-conflict warnings into install failures. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:36` | Peer conflicts auto-select isolated layout | `peer_conflict_auto_isolates_default_linker_and_stays_up_to_date` | `passing` | Default linker auto-isolates when peer conflicts are detected and persists that decision for warm installs. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:36` | Explicit hoisted linker stays hoisted on peer conflict | `peer_conflict_respects_explicit_hoisted_linker` | `passing` | LPM contract: explicit linker selection wins over peer-conflict auto-isolation. |
