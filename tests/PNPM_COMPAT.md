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
| peer | `core/types/src/peerDependencyIssues.ts:20` | Missing peer issue is structured for API consumers | `install_json_reports_missing_peer_issue` | `passing` | `lpm install --json` exposes missing peer warnings under `peer_issues.missing`. |
| peer | `core/types/src/peerDependencyIssues.ts:20` | Peer conflict issue is structured for API consumers | `install_json_reports_peer_conflict_issue` | `passing` | `lpm install --json` exposes both bad peer-version warnings and best-effort conflict reports under `peer_issues`. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:1246` | `strict-peer-dependencies` fails missing peers | `strict_peer_dependencies_cli_fails_when_required_peer_is_missing` | `passing` | CLI strict mode turns missing required-peer warnings into install failures. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:1246` | `strict-peer-dependencies` config fails missing peers | `strict_peer_dependencies_global_config_fails_when_required_peer_is_missing` | `passing` | Global config `strict-peer-dependencies = true` turns missing required-peer warnings into install failures. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:36` | Peer ranges conflict across consumers | `strict_peer_dependencies_config_fails_when_peer_ranges_conflict` | `passing` | `lpm.strictPeerDependencies` turns best-effort peer-conflict warnings into install failures. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:36` | Peer conflicts auto-select isolated layout | `peer_conflict_auto_isolates_default_linker_and_stays_up_to_date` | `passing` | Default linker auto-isolates when peer conflicts are detected and persists that decision for warm installs. |
| peer | `installing/deps-installer/test/install/peerDependencies.ts:36` | Explicit hoisted linker stays hoisted on peer conflict | `peer_conflict_respects_explicit_hoisted_linker` | `passing` | LPM contract: explicit linker selection wins over peer-conflict auto-isolation. |
| catalog | `installing/deps-installer/src/install/extendInstallOptions.ts:338` | `catalogMode` defaults to manual | `default_catalog_mode_saves_raw_range_when_catalog_range_matches` | `passing` | LPM contract: absent `lpm.catalogMode` keeps the existing raw `lpm install <pkg>` save policy. |
| catalog | `installing/deps-installer/src/install/index.ts:791` | Manual catalog mode does not auto-save catalog references | `manual_catalog_mode_saves_raw_range_when_catalog_range_matches` | `passing` | LPM contract: `lpm.catalogMode = "manual"` saves the resolved raw range even when a default catalog entry matches. |
| catalog | `installing/deps-installer/test/catalogs.ts:1404` | Prefer catalog mode saves matching deps through the catalog | `prefer_catalog_mode_saves_catalog_reference_when_catalog_range_matches` | `passing` | LPM contract: `lpm.catalogMode = "prefer"` saves `catalog:` when the resolved version satisfies the default catalog entry. |
| catalog | `installing/deps-installer/test/catalogs.ts:1312` | Strict catalog mode saves matching deps through the catalog | `strict_catalog_mode_saves_catalog_reference_when_catalog_range_matches` | `passing` | LPM contract: `lpm.catalogMode = "strict"` saves `catalog:` when the resolved version satisfies the default catalog entry. |
| catalog | `pnpm/test/saveCatalog.ts:58` | Explicit save-catalog flag saves deps through the default catalog | `install_catalog_flag_saves_default_catalog_reference_when_catalog_range_matches` | `passing` | LPM contract: `lpm install --catalog <pkg>` writes `catalog:` when the root default catalog entry satisfies the resolved version. |
| catalog | `pnpm/test/saveCatalog.ts:718` | Explicit named save-catalog flag saves deps through a named catalog | `install_named_catalog_flag_saves_named_catalog_reference_when_catalog_range_matches` | `passing` | LPM contract: `lpm install --catalog=<name> <pkg>` writes `catalog:<name>` when that catalog entry satisfies the resolved version. |
| catalog | `installing/deps-installer/test/catalogs.ts:1437` | Strict catalog mode rejects direct ranges outside the catalog | `strict_catalog_mode_rejects_direct_range_outside_catalog` | `passing` | LPM contract: strict mode fails before committing `package.json` when the requested version does not satisfy the default catalog entry. |
| catalog | `installing/deps-installer/test/catalogs.ts:1437` | Forced catalog save rejects direct ranges outside the catalog | `install_catalog_flag_rejects_direct_range_outside_catalog` | `passing` | LPM contract: `lpm install --catalog <pkg@range>` fails before committing `package.json` when the requested version does not satisfy the default catalog entry. |
| catalog | `catalogs/resolver/src/resolveFromCatalog.ts:68` | Forced catalog save rejects missing catalog entries | `install_named_catalog_flag_rejects_missing_entry_before_manifest_commit` | `passing` | LPM contract: unlike pnpm's `--save-catalog-name`, LPM's `--catalog=<name>` does not create catalog entries; it fails before committing `package.json` when the named catalog lacks the package. |
| catalog | `patching/commands/CHANGELOG.md:717` | Strict catalog mode only allows packages from the catalog | `strict_catalog_mode_rejects_package_missing_from_default_catalog` | `passing` | LPM contract: strict mode rejects `lpm install <pkg>` when the root default catalog has no entry for that package. |
| catalog | `installing/deps-installer/test/catalogs.ts:1463` | Prefer catalog mode warns and falls back to direct ranges on mismatch | `prefer_catalog_mode_warns_and_saves_direct_range_when_catalog_mismatches` | `passing` | LPM contract: prefer mode keeps the direct user spec when it does not satisfy the default catalog entry. |
