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
