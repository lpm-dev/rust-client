//! Coverage matrix **v2** — depth + scenario metrics.
//!
//! v1 (`coverage_audit_baseline.rs`) tracks surface-level coverage and
//! an accounted JSON contract status per row. That coarse metric
//! saturated at 97.8% workflow / 70% JSON during the 2026-05-14 coverage
//! push but doesn't reflect:
//!
//! - **Scenario depth.** A surface with 1 trivial test and one with 50
//!   thorough tests get the same v1 flag.
//! - **Failure-mode coverage.** Which of the surface's *known* failure
//!   modes are actually exercised by tests, and which are gaps?
//! - **JSON contract depth.** "Locked via insta snapshot" vs "checked
//!   one field semantically" vs "test calls --json but never reads
//!   the envelope" are distinct in v2.
//!
//! ## Schema
//!
//! v2 is **opt-in per surface**. Surfaces with no entry here are
//! treated as v2-unpopulated; the reminder test in
//! `coverage_audit_v2.rs` emits a backfill punch list so missing rows
//! are visible in CI output without failing the build.
//!
//! ## How to populate a row
//!
//! 1. Read the surface's workflow test file end-to-end.
//! 2. Count distinct scenarios (one test fn = ~one scenario; sub-cases
//!    inside `#[test]` count individually if asserting independent
//!    contracts).
//! 3. List the failure modes that ARE tested by name.
//! 4. List the failure modes that are KNOWN but not tested — the gap.
//!    See `private/test-gaps-strategic-audit.md` for the
//!    by-category gap inventory.
//! 5. Set `json_contract_depth` based on what the test file does:
//!    - `None` — surface doesn't emit `--json`, OR tests don't read
//!      the envelope.
//!    - `SemanticAsserts` — tests check specific fields via
//!      `envelope["field"]` matches.
//!    - `InstaSnapshot` — full envelope locked via
//!      `insta::assert_json_snapshot!`.
//!
//! Failure-mode names are free-text but stable: pick a noun phrase
//! that names the failure, e.g. `"SIGKILL mid-install"`, not
//! `"interrupted install"`. The strict-equality dedup in the audit
//! tests treats different wordings as different gaps.

#![allow(dead_code)] // Re-exported via #[path] from the audit test.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JsonContractDepth {
    /// Surface emits no `--json`, or tests do not read the envelope.
    None,
    /// Tests assert on specific fields (`envelope["field"] == ...`)
    /// but don't snapshot the full envelope shape.
    SemanticAsserts,
    /// Full envelope locked via `insta::assert_json_snapshot!`.
    InstaSnapshot,
}

#[derive(Debug)]
pub struct SurfaceV2 {
    /// Must match `SurfaceBaseline::id` in `coverage_audit_baseline.rs`.
    pub id: u16,
    /// Distinct test scenarios for this surface. Count `#[test]` fns
    /// in the surface's workflow file plus any in shared files
    /// (`json_output.rs`, etc.) that target this surface.
    pub scenarios: u32,
    /// Optional per-file breakdown of the scenario count for shared
    /// test files (`json_output.rs`, `tools.rs`, `auth_lifecycle.rs`,
    /// `run.rs`, `env_local.rs`, etc.). Each tuple is
    /// `(file_path_relative_to_repo_root, count_targeting_this_surface)`.
    ///
    /// When this is empty (`&[]`), the row is treated as "all
    /// scenarios live in the surface's primary test file" — fine
    /// for dedicated files like `cache.rs` or `audit.rs`. For
    /// surfaces that share a file with other surfaces, populating
    /// this lets the reminder reports check that
    /// `sum(scenarios_by_file) == scenarios` — drift here means
    /// the file got new tests that nobody attributed to a row.
    ///
    /// Schema integrity test:
    /// `v2_scenarios_by_file_sum_matches_scenarios_when_populated`
    /// enforces the sum invariant for rows that have populated the
    /// breakdown.
    pub scenarios_by_file: &'static [(&'static str, u32)],
    /// Failure modes the test suite actually exercises.
    pub failure_modes_tested: &'static [&'static str],
    /// Failure modes that are known to be relevant for this surface
    /// but are NOT currently tested. Lift these into
    /// `failure_modes_tested` as coverage grows.
    pub failure_modes_known: &'static [&'static str],
    /// How deeply is the `--json` envelope contract pinned?
    pub json_contract_depth: JsonContractDepth,
    /// ISO-8601 date this row was last validated against the source.
    /// Catches bit-rot: if a row hasn't been re-audited in a long
    /// time and the test file has churned, the row's data is suspect.
    /// The reminder report sorts by oldest so the next session knows
    /// what to recheck. Format: `"YYYY-MM-DD"`.
    pub last_audited_at: &'static str,
}

/// Cross-command flow: a named multi-command sequence that real users
/// chain together. Single-command tests don't catch state-consistency
/// bugs between commands; the flow inventory below is the missing
/// dimension v1 doesn't track at all.
#[derive(Debug)]
pub struct CrossCommandFlow {
    pub name: &'static str,
    /// Commands in execution order, e.g. `["lpm migrate npm", "lpm install", "lpm audit"]`.
    pub commands: &'static [&'static str],
    /// Is there an integration test that runs this full sequence?
    pub tested: bool,
    /// Test file (workflow tier) when `tested == true`.
    pub test_file: Option<&'static str>,
    /// What this flow catches that single-command tests can't.
    pub catches: &'static str,
}

// ─── Surface v2 data ──────────────────────────────────────────────────
//
// Backfill landed in two passes. The eight strategic-audit anchor rows
// (id 12 install, 15 install --filter, 22 add, 63 audit --fail-on,
// 64 audit --secrets, 67 rebuild, 71 approve-scripts interactive,
// 77 patch) are the depth-rich examples. Every other v1-covered
// surface follows the same schema with scenario / failure-mode arrays
// derived from the test fns actually shipped in `tests/workflows/tests/`.
// Rows with `JsonContractDepth::None` are intentionally non-JSON
// surfaces; every JSON-capable surface has either semantic assertions
// or a snapshot row.

pub const SURFACES_V2: &[SurfaceV2] = &[
    // ── id 1: lpm info <pkg> ──
    SurfaceV2 {
        id: 1,
        scenarios: 1,
        failure_modes_tested: &[
            "subcommand --version flag accepted without panic",
            "scoped name canonicalization in envelope",
            "version metadata included for requested version",
        ],
        failure_modes_known: &[
            "registry 404 on package lookup",
            "registry returns malformed packument (mid-parse)",
            "untrusted certificate on registry origin",
            "version range syntax fed to --version flag",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/json_output.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 2: lpm search <query> ──
    SurfaceV2 {
        id: 2,
        scenarios: 3,
        failure_modes_tested: &[
            "no-matches warn and exit zero",
            "long-description truncation in human output",
            "compact download-count formatting",
            "JSON envelope single-result snapshot",
        ],
        failure_modes_known: &[
            "registry 5xx mid-batch",
            "query containing special / regex characters",
            "partial response truncation mid-stream",
            "search across paginated result sets",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/search.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 3: lpm quality <pkg> ──
    SurfaceV2 {
        id: 3,
        scenarios: 2,
        failure_modes_tested: &[
            "human output groups checks",
            "failed-detail-only rendering",
            "JSON envelope shape snapshot",
        ],
        failure_modes_known: &[
            "registry returns malformed quality response",
            "quality cache invalidation across publishes",
            "missing-package quality lookup",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/quality.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 4: lpm whoami ──
    SurfaceV2 {
        id: 4,
        scenarios: 7,
        failure_modes_tested: &[
            "JSON envelope required fields",
            "session recovery from refresh token only",
            "whoami envelope shape locked under refresh-only session (snapshot)",
            "refresh-only logout does not rehydrate",
            "invalid access token + valid refresh recovers + normalizes store",
            "malformed session expiry metadata triggers refresh",
            "env token precedence over refreshable stored session",
            "CLI token precedence over env + stored session",
        ],
        failure_modes_known: &[
            "expired access + expired refresh fall-through",
            "keychain locked on read",
            "stale session marker after rotation",
            "whoami while another login is mid-flight",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[
            ("tests/workflows/tests/json_output.rs", 1),
            ("tests/workflows/tests/auth_lifecycle.rs", 6),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 5: lpm health ──
    SurfaceV2 {
        id: 5,
        scenarios: 2,
        failure_modes_tested: &[
            "happy-path required fields",
            "unhealthy reporting on registry failure",
        ],
        failure_modes_known: &[
            "registry timeout mid-check (no partial-state reporting)",
            "DNS failure propagation to envelope",
            "TLS handshake failure surfacing",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/json_output.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 6: lpm download <pkg> ──
    SurfaceV2 {
        id: 6,
        scenarios: 1,
        failure_modes_tested: &[
            "version flag canonicalization",
            "output dir resolution (path traversal containment)",
            "JSON envelope success + package + path fields",
        ],
        failure_modes_known: &[
            "registry returns invalid tarball bytes",
            "concurrent download of same package",
            "disk full mid-extraction",
            "registry follows untrusted same-origin redirect",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/download.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 7: lpm resolve <pkgs> ──
    SurfaceV2 {
        id: 7,
        scenarios: 3,
        failure_modes_tested: &[
            "missing packages preflight fails before network",
            "bare scoped package defaults to latest",
            "scoped@version separator parsing (last @ wins)",
        ],
        failure_modes_known: &[
            "cyclic dependency graph terminates cleanly",
            "unresolvable version constraint diagnostics",
            "registry network timeout per-package",
            "mixed scoped + unscoped multi-package query",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/resolve.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 8: lpm outdated ──
    SurfaceV2 {
        id: 8,
        scenarios: 7,
        failure_modes_tested: &[
            "missing package.json fails clearly",
            "empty deps emits empty JSON envelope",
            "non-lpm packages reported by default",
            "registry-only-lpm filtering",
            "newer version detection",
            "matched-latest zero count",
            "JSON envelope snapshot (one outdated)",
        ],
        failure_modes_known: &[
            "registry version no longer published",
            "concurrent outdated check",
            "pre-release handling strategy",
            "outdated against private registry under .npmrc routing",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/outdated.rs", 7)],
        last_audited_at: "2026-05-14",
    },
    // ── id 9: lpm doctor ──
    SurfaceV2 {
        id: 9,
        scenarios: 9,
        failure_modes_tested: &[
            "envelope shape (json_output)",
            "doctor_list envelope shape",
            "each entry has required fields",
            "filter by code returns single entry",
            "filter by code typo nonzero + single JSON envelope",
            "filter by category returns subset",
            "manifest-compat codes surfaced",
            "well-known codes pinned",
            "every runtime-emitted code is in the catalog",
        ],
        failure_modes_known: &[
            "doctor on read-only home",
            "corrupted store metadata",
            "concurrent doctor + install",
            "doctor against partial node_modules tree",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/json_output.rs", 1),
            ("tests/workflows/tests/doctor_list.rs", 8),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 10: lpm doctor --fix ──
    SurfaceV2 {
        id: 10,
        scenarios: 4,
        failure_modes_tested: &[
            "gitattributes created when lockfile exists without it",
            "binary lockfile regenerated when toml present",
            "non-fix mode does not mutate",
            "JSON envelope carries fixes-applied array",
        ],
        failure_modes_known: &[
            "recovery under partial corruption",
            "disk full during cleanup",
            "concurrent fix + install lock contention",
            "fix on a project whose package.json is intentionally exotic",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/doctor_fix.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 11: lpm init ──
    SurfaceV2 {
        id: 11,
        scenarios: 2,
        failure_modes_tested: &[
            "yes + json uses profile username + creates gitattributes",
            "fallback to literal username when whoami unavailable",
        ],
        failure_modes_known: &[
            "overwriting existing package.json",
            "Unicode in project name",
            "concurrent init in same directory",
            "init under a directory whose parent is not a git repo",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/init.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 12: lpm install (bare, lockfile fast-path) ──
    SurfaceV2 {
        id: 12,
        scenarios: 54,
        failure_modes_tested: &[
            "lockfile-missing (regenerate from package.json)",
            "save-policy (caret, exact, tilde)",
            "workspace:* root symlink",
            "workspace:^ resolution",
            "transitive hoisting",
            "peer dependency not auto-installed",
            "optional dependency failure isolation",
            "SHA-512 integrity verification roundtrip",
            "registry 404 on tarball fetch",
            "registry returns valid metadata but missing tarball",
            "declared-integrity mismatch (Verdaccio tier)",
            "ghost-transitive fail-closed under --offline",
            "workspace ghost-transitive fails closed with actionable error (non-offline path)",
            "warns when LPM_RESOLVER=pubgrub + auto-install-peers under --json",
            "silent when LPM_RESOLVER=pubgrub + auto-install-peers off",
            "silent when default resolver + auto-install-peers on (no warning regression)",
        ],
        failure_modes_known: &[
            "concurrent install on same project (lock contention)",
            "SIGKILL mid-install (partial state recovery)",
            "network drop mid-tarball download (retry behavior)",
            "disk full during extraction",
            "permission denied on node_modules path",
            "tarball zip-slip via symlink entry",
            "tarball zip-slip via absolute path",
            "tarball entries with Unicode normalization tricks",
            "tarball entries with hard links to system files",
            "tarball entries with device files or FIFOs",
            "registry returns malformed JSON (mid-parse panic vs graceful)",
            "registry returns bytes that match declared integrity but rewrite package.json",
            "registry response truncated mid-stream",
            "store dir is read-only at start of install",
            "user CTRL-C between download and link phase",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[
            ("tests/workflows/tests/install.rs", 21),
            ("tests/workflows/tests/install_real_registry.rs", 14),
            ("tests/workflows/tests/install_overrides.rs", 7),
            ("tests/workflows/tests/install_patches.rs", 12),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 13: lpm install <pkg> (add-and-install) ──
    SurfaceV2 {
        id: 13,
        scenarios: 14,
        failure_modes_tested: &[
            "single-package install via mock registry",
            "caret-resolved range saved (not wildcard)",
            "existing dep bare reinstall does not churn",
            "explicit range beats project-config save-prefix",
            "exact pin via --exact",
            "tilde range via --tilde",
            "tilde range via project save-prefix=~",
            "wildcard save-prefix rejected",
            "contradictory save flags rejected",
            "JSON envelope with one installed package matches snapshot",
            "lockfile content matches snapshot after install <pkg>",
            "JSON output contains installed package list",
            "honors project lpm.toml save-prefix=~ when adding new dep",
            "rejects project lpm.toml save-prefix=* (wildcard)",
        ],
        failure_modes_known: &[
            "registry 404 mid-install",
            "partial lockfile-write rollback under crash",
            "concurrent add on same project",
            "save-prefix from CLI overriding malformed lpm.toml",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/install.rs", 14)],
        last_audited_at: "2026-05-14",
    },
    // ── id 14: lpm install --offline ──
    SurfaceV2 {
        id: 14,
        scenarios: 10,
        failure_modes_tested: &[
            "offline with store succeeds",
            "offline empty-fingerprints emit null in envelope",
            "offline without lockfile fails",
            "offline reruns workspace member BFS expansion",
            "offline mixed-registry + file dep uses lockfile fast-path",
            "offline install capability round-trip end-to-end",
            "offline handles F9-deduped workspace member",
            "offline workspace ghost-transitive after manifest edit fails closed",
            "offline refuses pre-r25 v1 lockfile under auto-install-peers",
            "offline accepts pre-r25 v1 lockfile when auto-install-peers off",
        ],
        failure_modes_known: &[
            "store partially populated (missing tarball)",
            "cache corruption during offline read",
            "network drop interrupts offline reload",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/install.rs", 9),
            (
                "tests/workflows/tests/install_offline_capability_roundtrip.rs",
                1,
            ),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 15: lpm install --filter / -w (workspace) ──
    SurfaceV2 {
        id: 15,
        scenarios: 10,
        failure_modes_tested: &[
            "--filter exact name selects only matched member",
            "--filter glob expands across members",
            "-w mutates only workspace root",
            "--filter + -w mutual exclusion",
            "empty-match without --fail-if-no-match exits 0",
            "empty-match with --fail-if-no-match exits non-zero",
        ],
        failure_modes_known: &[
            "filter against a 100+ member workspace (resolver scaling)",
            "filter with circular workspace deps",
            "filter when a member has unresolvable workspace:^ range",
            "filter with workspace:*-keyed devDependencies",
            "concurrent install --filter A and --filter B on same workspace",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/install.rs", 10)],
        last_audited_at: "2026-05-14",
    },
    // ── id 16: lpm install -g (global) ──
    SurfaceV2 {
        id: 16,
        scenarios: 8,
        failure_modes_tested: &[
            "install -g without args fails or no-ops",
            "validator accepts --allow-new",
            "validator accepts --min-release-age",
            "validator accepts --ignore-provenance-drift",
            "validator accepts --policy=allow",
            "validator accepts --triage + --auto-build",
            "validator accepts --yolo",
            "validator still rejects --yes",
        ],
        failure_modes_known: &[
            "concurrent install -g same package",
            "permission denied on shim path",
            "PATH update visibility race",
            "package in-use during update (Windows EBUSY)",
            "shim repair after upstream binary rename",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/install_global_security.rs", 8)],
        last_audited_at: "2026-05-14",
    },
    // ── id 17: lpm install --policy / --yolo ──
    SurfaceV2 {
        id: 17,
        scenarios: 8,
        failure_modes_tested: &[
            "--policy + --yolo mutual exclusion at parse time",
            "--policy + --triage mutual exclusion at parse time",
            "--yolo + --triage mutual exclusion at parse time",
            "invalid --policy value rejected",
            "invalid --policy value under --json emits error envelope on stdout",
            "default policy blocks postinstall scripts",
            "--policy=allow accepted at parse time",
            "--yolo accepted at parse time",
        ],
        failure_modes_known: &[
            "--policy=deny actual script blocking end-to-end (vs install-time)",
            "--policy=triage routing decisions for amber/red",
            "--yolo + sandbox actually disables sandbox enforcement",
            "policy override via package.json > lpm > scriptPolicy",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/install_policy.rs", 8)],
        last_audited_at: "2026-05-14",
    },
    // ── id 18: lpm install --strict-integrity / provenance / cooldown ──
    SurfaceV2 {
        id: 18,
        scenarios: 14,
        failure_modes_tested: &[
            "approved attestation dropped blocks install",
            "ignore-provenance-drift per-package unblocks",
            "ignore-provenance-drift --all unblocks",
            "publisher identity changed blocks",
            "legitimate release bump does not drift",
            "--allow-new alone does not bypass drift",
            "attestation-fetch failure does not falsely block",
            "drift does not block project with no approvals",
            "min-release-age CLI override blocks fresh package",
            "--allow-new bypasses cooldown CLI override",
            "global config min-release-age overrides default",
            "package.json min-release-age overrides global",
            "explicit version pin does not bypass cooldown",
            "freshness cache invalidates on lpm-linker flip",
        ],
        failure_modes_known: &[
            "registry serves different bytes on retry",
            "attestation envelope partial-valid (signature good, claims wrong)",
            "concurrent install vs provenance fetch race",
            "cooldown override interaction with --offline path",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/install.rs", 6),
            ("tests/workflows/tests/install_provenance.rs", 8),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 19: lpm uninstall <pkg> (project) ──
    SurfaceV2 {
        id: 19,
        scenarios: 8,
        failure_modes_tested: &[
            "without package args fails with clear message",
            "last dependency leaves empty deps object",
            "removes devDependency in same pass",
            "drops lpm.lock entirely after removal",
            "unknown package warns and exits zero",
            "after real install removes isolated symlink",
            "after real install removes hoisted directory",
            "JSON envelope (one removal) snapshot",
        ],
        failure_modes_known: &[
            "partial symlink removal on SIGKILL",
            "package locked by running process (Windows EBUSY)",
            "concurrent uninstall same pkg",
            "uninstall while a postinstall script is still running",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/uninstall.rs", 8)],
        last_audited_at: "2026-05-14",
    },
    // ── id 20: lpm uninstall -g (global) ──
    SurfaceV2 {
        id: 20,
        scenarios: 1,
        failure_modes_tested: &["unknown package matches global-remove error path"],
        failure_modes_known: &[
            "permission denied on shim unlink",
            "concurrent global uninstall on same shim",
            "partial shim removal recovery on crash",
            "uninstall -g of package still referenced by an open shell",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/global.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 21: lpm uninstall --filter / -w ──
    SurfaceV2 {
        id: 21,
        scenarios: 5,
        failure_modes_tested: &[
            "filter removes only from targeted member",
            "workspace root removes from root only",
            "filter typo without fail-flag exits zero",
            "filter typo with fail-flag exits nonzero",
            "-w + --filter together rejected by clap",
        ],
        failure_modes_known: &[
            "circular workspace dep during uninstall",
            "filter glob with overlapping selectors",
            "uninstall --filter on a member whose lockfile diverges from root",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/uninstall.rs", 5)],
        last_audited_at: "2026-05-14",
    },
    // ── id 22: lpm add (npm + source) ──
    SurfaceV2 {
        id: 22,
        scenarios: 12,
        failure_modes_tested: &[
            "source package add into auto-detected dir",
            "npm package add into project root",
            "path-traversal dest-escape rejected (`../foo` target)",
            "non-interactive mode requires explicit path",
            "ask interactively when path missing in TTY",
        ],
        failure_modes_known: &[
            "tarball zip-slip via symlink entries (source pkg path)",
            "tarball with absolute paths in package/ entries",
            "Unicode normalization in destination path",
            "destination resolves outside CWD via symlink chain",
            "destination is a read-only mount",
            "overwriting existing files without --force prompts in non-TTY",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/add.rs", 12)],
        last_audited_at: "2026-05-14",
    },
    // ── id 23: lpm remove (alias rm, source pkg) ──
    SurfaceV2 {
        id: 23,
        scenarios: 2,
        failure_modes_tested: &[
            "JSON cleans source package paths + editor links",
            "rm alias warns + exits zero when no files match",
        ],
        failure_modes_known: &[
            "symlink outside project (containment check)",
            "permission denied on source path",
            "remove of a source package while VSCode has the file open",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/remove.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 24: lpm upgrade (bare) ──
    SurfaceV2 {
        id: 24,
        scenarios: 14,
        failure_modes_tested: &[
            "missing package.json fails clearly",
            "zero upgraded when lpm dep already at latest",
            "skips npm packages by default",
            "dry-run does not mutate manifest or lockfile",
            "writes new range to manifest + lockfile",
            "rewrites minified manifest JSON",
            "yes mode no-candidates emits legacy success envelope",
            "yes mode writes manifest when not dry-run",
            "default in no-TTY matches yes output",
            "interactive + JSON hard error",
            "interactive + yes hard error",
            "yes marks install-scripts in JSON",
            "yes marks peer violation in JSON",
            "yes install-failure restores manifest",
            "dry-run JSON envelope (one candidate) snapshot",
        ],
        failure_modes_known: &[
            "registry version no longer published mid-upgrade",
            "concurrent upgrade on same project",
            "upgrade across a deprecated → renamed package transition",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/upgrade.rs", 14)],
        last_audited_at: "2026-05-14",
    },
    // ── id 25: lpm upgrade --major ──
    SurfaceV2 {
        id: 25,
        scenarios: 4,
        failure_modes_tested: &[
            "major in interactive mode hard error",
            "yes jumps to latest major version",
            "yes dry-run envelope (one candidate) snapshot",
            "yes dry-run full-enrichment smoke",
        ],
        failure_modes_known: &[
            "ambiguous pre-release majors (2.0.0-rc vs 2.0.0)",
            "policy change between major versions",
            "major bump that drops a sub-dependency entirely",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/upgrade.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 26: lpm upgrade --interactive ──
    SurfaceV2 {
        id: 26,
        scenarios: 1,
        failure_modes_tested: &[
            "interactive + JSON hard error",
            "JSON error envelope shape on -i+--json mutual-exclusion",
        ],
        failure_modes_known: &[
            "interactive walk under TTY (PTY-driven)",
            "user CTRL-C mid-prompt",
            "terminal resize mid-render",
            "interactive in non-TTY environment falls back to batch",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/upgrade.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 27: lpm publish (LPM, default) ──
    SurfaceV2 {
        id: 27,
        scenarios: 5,
        failure_modes_tested: &[
            "dry-run validates package",
            "without package.json fails",
            "without name fails",
            "accepts target flags",
            "publishes to mock registry",
        ],
        failure_modes_known: &[
            "incomplete OIDC setup error path",
            "registry 403 auth fail (real bearer rejected)",
            "attestation missing required claim",
            "publish while a freshly rotated token is propagating",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/publish.rs", 5)],
        last_audited_at: "2026-05-14",
    },
    // ── id 28: lpm publish --npm ──
    SurfaceV2 {
        id: 28,
        scenarios: 1,
        failure_modes_tested: &["npm dry-run resolves npm target in JSON envelope"],
        failure_modes_known: &[
            "npm 401 token expired",
            "npm rate-limit 429",
            "registry serves tarball instead of metadata",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/publish.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 29: lpm publish --github ──
    SurfaceV2 {
        id: 29,
        scenarios: 1,
        failure_modes_tested: &["github dry-run resolves github target in JSON envelope"],
        failure_modes_known: &[
            "github 403 insufficient permissions",
            "repository not found",
            "concurrent multi-publish race",
            "GHCR vs GitHub Packages routing mismatch",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/publish.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 30: lpm publish --gitlab ──
    SurfaceV2 {
        id: 30,
        scenarios: 1,
        failure_modes_tested: &["gitlab dry-run resolves gitlab target in JSON envelope"],
        failure_modes_known: &[
            "gitlab 401 token-format wrong",
            "group registry vs project registry routing",
            "concurrent publish to same project ID",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/publish.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 31: lpm publish --publish-registry <URL> ──
    SurfaceV2 {
        id: 31,
        scenarios: 1,
        failure_modes_tested: &[
            "custom registry URL surfaces in JSON envelope (registry-url + resolved name)",
        ],
        failure_modes_known: &[
            "untrusted certificate on custom registry",
            "custom registry returns malformed PUT response",
            "custom registry requires unsupported auth scheme",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/publish.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 32: lpm publish --dry-run ──
    SurfaceV2 {
        id: 32,
        scenarios: 4,
        failure_modes_tested: &[
            "dry-run validates package",
            "publishes to mock registry (live path)",
            "github + gitlab together yields two targets",
            "check mode shows quality",
        ],
        failure_modes_known: &[
            "dry-run with missing lpm.config.json",
            "dry-run rejects local version label",
            "dry-run against a registry the user has never logged in to",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/publish.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 33: lpm publish --check ──
    SurfaceV2 {
        id: 33,
        scenarios: 2,
        failure_modes_tested: &["check mode shows quality", "accepts target flags"],
        failure_modes_known: &[
            "quality score below threshold messaging",
            "missing required fields in lpm.config.json",
            "check during a stale-token rotation window",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/publish.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 34: lpm login (LPM default) ──
    SurfaceV2 {
        id: 34,
        scenarios: 3,
        failure_modes_tested: &[
            "env token precedence over refreshable session",
            "CLI token precedence over env + stored session",
            "logout prevents startup session rehydration",
        ],
        failure_modes_known: &[
            "registry returns invalid token format",
            "keychain locked on read",
            "OIDC issuer unreachable",
            "login on a host that has no keychain (Linux without libsecret)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/auth_lifecycle.rs", 2),
            ("tests/workflows/tests/json_output.rs", 1),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 35: lpm login --npm ──
    SurfaceV2 {
        id: 35,
        scenarios: 4,
        failure_modes_tested: &[
            "env token precedence over stored custom registry token",
            "authenticated install attaches bearer on every registry request",
            "--json without --token emits error envelope (directs user to npmjs.com tokens)",
            "--json with --token stores fallback token",
            "--json with NPM_TOKEN stores fallback token",
        ],
        failure_modes_known: &[
            "NPM 401 invalid credentials",
            ".npmrc merge strategy with existing entries",
            "npm OTP prompt under non-TTY",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/auth_lifecycle.rs", 3),
            ("tests/workflows/tests/npmrc.rs", 1),
        ],
        last_audited_at: "2026-05-29",
    },
    // ── id 36: lpm login --github / --gitlab ──
    SurfaceV2 {
        id: 36,
        scenarios: 7,
        failure_modes_tested: &[
            "OIDC setup snippet contract (cli-binary)",
            "login --github --json without --token emits error envelope (directs to github.com tokens)",
            "login --gitlab --json without --token emits error envelope (directs to gitlab.com tokens)",
            "login --github --json with --token stores fallback token",
            "login --gitlab --json with --token stores fallback token",
            "login --github --json with gh auth avoids storing copied token",
            "login --gitlab --json with glab auth avoids storing copied token",
        ],
        failure_modes_known: &[
            "github device-flow timeout awaiting user approval",
            "gitlab PAT expiry warning",
            "OIDC issuer DNS failure mid-flow",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/auth_lifecycle.rs", 6),
            ("crates/lpm-cli/tests/oidc_setup_snippet_contract.rs", 1),
        ],
        last_audited_at: "2026-05-29",
    },
    // ── id 37: lpm login --login-registry <URL> ──
    SurfaceV2 {
        id: 37,
        scenarios: 3,
        failure_modes_tested: &[
            "env token precedence over stored custom registry token (no tracking mutation)",
            "malformed custom registry entry does not break primary session",
            "login --login-registry --json without --token emits error envelope",
        ],
        failure_modes_known: &[
            "custom registry challenges unsupported auth scheme",
            "token scope mismatch on custom registry",
            "multi-registry token storage cross-talk",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/auth_lifecycle.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 38: lpm logout ──
    SurfaceV2 {
        id: 38,
        scenarios: 3,
        failure_modes_tested: &[
            "logout prevents startup session rehydration",
            "logout --json envelope carries success=true",
            "logout skips browser-pairing revocation without refresh token",
            "logout clears recent token validation marker",
        ],
        failure_modes_known: &[
            "logout-persists-across-restart guarantee",
            "partial logout on permission denied",
            "logout while a publish is mid-flight",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/auth_lifecycle.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 39: lpm logout --revoke / --all ──
    SurfaceV2 {
        id: 39,
        scenarios: 4,
        failure_modes_tested: &[
            "refresh-only logout-all clears everything + does not rehydrate",
            "logout-all clears lpm + external registry state",
            "logout-all --json envelope carries success=true",
            "logout-all normalizes malformed custom registry tracking + clears file-backed tokens",
            "logout-registry clears only targeted custom-registry state",
        ],
        failure_modes_known: &[
            "revoke fails on network error but local deletion succeeds",
            "all flag with selective removal ambiguity",
            "revoke during a CI-managed token rotation",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/auth_lifecycle.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 40: lpm token-rotate ──
    SurfaceV2 {
        id: 40,
        scenarios: 1,
        failure_modes_tested: &["replaces stored session token + expiry metadata"],
        failure_modes_known: &[
            "rotation fails mid-store (partial-state recovery)",
            "concurrent rotation on same registry",
            "rotation during active publish",
            "rotation against a registry that returns 5xx",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/token_rotate.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 41: lpm setup ci npmrc (.npmrc CI gen) ──
    SurfaceV2 {
        id: 41,
        scenarios: 4,
        failure_modes_tested: &[
            "default writes scoped registry line to .npmrc",
            "removed --proxy flag is rejected before .npmrc write",
            "legacy proxy config is ignored",
            "JSON envelope carries path + content + flag state",
        ],
        failure_modes_known: &[
            "CI platform unknown exit code",
            "malformed OIDC issuer URL",
            ".npmrc write permission denied",
            "setup against an .npmrc that already has conflicting scoped entries",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/setup_ci.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 42: lpm setup local ──
    SurfaceV2 {
        id: 42,
        scenarios: 2,
        failure_modes_tested: &[
            "writes scoped config + gitignore + read-only token",
            "removed --proxy flag is rejected before token request",
        ],
        failure_modes_known: &[
            ".npmrc path is symlink outside project",
            "concurrent setup local writes",
            "backup file creation on overwrite",
            "setup local when project root is a git submodule",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/setup_local.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 43: lpm config get ──
    SurfaceV2 {
        id: 43,
        scenarios: 1,
        failure_modes_tested: &["JSON returns existing value"],
        failure_modes_known: &[
            "nonexistent key error",
            "config file parse error",
            "symlink config path",
            "get of a key with embedded JSON-special characters",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/config.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 44: lpm config set ──
    SurfaceV2 {
        id: 44,
        scenarios: 1,
        failure_modes_tested: &[
            "writes value into isolated home",
            "--json envelope carries success + action + key + value",
        ],
        failure_modes_known: &[
            "invalid JSON value rejected",
            "config file permission denied on write",
            "concurrent config writes (last-writer-wins vs lock)",
            "set on a key that violates a typed schema",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/config.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 45: lpm config delete ──
    SurfaceV2 {
        id: 45,
        scenarios: 1,
        failure_modes_tested: &[
            "removes existing key + preserves other entries",
            "--json envelope carries success + action + key + existed",
        ],
        failure_modes_known: &[
            "delete last key (file removed vs left empty)",
            "permission denied on file",
            "concurrent delete + set on same key",
            "delete of a nonexistent key (idempotent vs error)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/config.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 46: lpm config list ──
    SurfaceV2 {
        id: 46,
        scenarios: 1,
        failure_modes_tested: &["JSON envelope reports all keys"],
        failure_modes_known: &[
            "empty config file returns empty object",
            "config file with comments (JSON5 vs strict JSON)",
            "list under a HOME that points to a non-writable mount",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/config.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 47: lpm cache clean [subcat] ──
    SurfaceV2 {
        id: 47,
        scenarios: 5,
        failure_modes_tested: &[
            "blanket removes all three subcategories",
            "subcat-specific clean (only that subcat)",
            "unknown subcategory helpful error",
            "JSON envelope reports per-subcategory freed bytes",
            "idempotent clean on empty cache",
        ],
        failure_modes_known: &[
            "permission denied on cache dir",
            "concurrent clean + install",
            "partial clean on SIGKILL recovery",
            "clean under a HOME whose cache dir is a bind-mount",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/cache.rs", 5)],
        last_audited_at: "2026-05-14",
    },
    // ── id 48: lpm cache path [subcat] ──
    SurfaceV2 {
        id: 48,
        scenarios: 4,
        failure_modes_tested: &[
            "without subcategory prints cache root",
            "metadata subcategory prints metadata dir",
            "unknown subcategory helpful error",
            "JSON envelope shape is stable",
        ],
        failure_modes_known: &[
            "symlink loop in cache path",
            "tilde / $HOME expansion edge cases",
            "cache root override via env var",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/cache.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 49: lpm store verify ──
    SurfaceV2 {
        id: 49,
        scenarios: 3,
        failure_modes_tested: &[
            "empty store reports zero entries",
            "passes on valid v1 entry",
            "flags corrupted v1 entry without package.json",
        ],
        failure_modes_known: &[
            "concurrent verify + install lock contention",
            "partial verification on SIGKILL recovery",
            "store locked by another process",
            "verify of v2 entries (when v2 layout ships)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/store.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 50: lpm store path ──
    SurfaceV2 {
        id: 50,
        scenarios: 2,
        failure_modes_tested: &["prints store root", "JSON envelope carries path"],
        failure_modes_known: &[
            "symlink store path",
            "package-not-in-store error",
            "store root override via env var",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/store.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 51: lpm cache prune ──
    SurfaceV2 {
        id: 51,
        scenarios: 7,
        failure_modes_tested: &[
            "dry-run with no registry succeeds without mutation",
            "apply with no registry degrades to tombstone-only",
            "apply with explicit project succeeds with no v2 store",
            "dry-run does not mutate the project registry",
            "apply drops stale registry entries under exclusive lock",
            "apply with corrupt registry does not wipe the store",
            "back-to-back apply releases the store lock",
        ],
        failure_modes_known: &[
            "permission denied on cache dir",
            "concurrent prune + install",
            "partial prune on SIGKILL recovery",
            "prune across a store dir whose backing FS is full",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/cache_prune.rs", 7)],
        last_audited_at: "2026-05-14",
    },
    // ── id 52: lpm store clean ──
    SurfaceV2 {
        id: 52,
        scenarios: 3,
        failure_modes_tested: &[
            "empty store reports idempotent success",
            "wipes v1 + v2 directories",
            "unknown action fails with helpful message",
        ],
        failure_modes_known: &[
            "permission denied on store dir",
            "concurrent clean + symlink update from active install",
            "package active in node_modules (won't unlink)",
            "clean across mixed-permission entries",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/store.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 53: lpm global list ──
    SurfaceV2 {
        id: 53,
        scenarios: 2,
        failure_modes_tested: &[
            "empty manifest succeeds with no-packages message",
            "JSON envelope on empty manifest carries empty packages array",
        ],
        failure_modes_known: &[
            "global dir permission denied read",
            "global store corruption",
            "concurrent list + update",
            "list against a global dir on a network-mounted FS",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/global.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 54: lpm global list --outdated ──
    SurfaceV2 {
        id: 54,
        scenarios: 1,
        failure_modes_tested: &["empty manifest succeeds with empty set"],
        failure_modes_known: &[
            "registry timeout mid-outdated check",
            "cache stale versions",
            "concurrent list + install -g",
            "outdated against a global pin that no longer resolves",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/global.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 55: lpm global bin ──
    SurfaceV2 {
        id: 55,
        scenarios: 2,
        failure_modes_tested: &[
            "prints isolated global bin directory",
            "JSON envelope carries path",
        ],
        failure_modes_known: &[
            "shim dir not in PATH (user remediation message)",
            "bin path uses symlinks (loop check)",
            "Windows: bin path with backslashes vs forward slashes",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/global.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 56: lpm global path <pkg> ──
    SurfaceV2 {
        id: 56,
        scenarios: 2,
        failure_modes_tested: &[
            "unknown package fails with helpful message",
            "unknown package under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "package path symlink outside global dir (containment check)",
            "global store corrupted entry",
            "path of a package installed via cargo-install fallback",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/global.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 57: lpm global remove ──
    SurfaceV2 {
        id: 57,
        scenarios: 1,
        failure_modes_tested: &["unknown package fails with helpful message"],
        failure_modes_known: &[
            "permission denied shim unlink",
            "concurrent global remove + install -g",
            "partial removal on crash",
            "remove of a package whose shim was hand-edited",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/global.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 58: lpm global update ──
    SurfaceV2 {
        id: 58,
        scenarios: 2,
        failure_modes_tested: &[
            "dry-run on empty manifest succeeds without writing",
            "unknown package fails with helpful message",
        ],
        failure_modes_known: &[
            "package in-use EBUSY on Windows",
            "update rollback on failure",
            "concurrent update same package",
            "update across a major-version jump (provenance drift)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/global.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 59: lpm trust diff ──
    SurfaceV2 {
        id: 59,
        scenarios: 5,
        failure_modes_tested: &[
            "no snapshot reports no-prior-state (human)",
            "reports added binding against snapshot",
            "reports removed binding when manifest dropped an entry",
            "reports changed binding when integrity drifts",
            "without package.json fails with helpful message",
        ],
        failure_modes_known: &[
            "trust file corrupted",
            "concurrent diff + approve",
            "diff with empty trust file",
            "diff after a `lpm rebuild --policy=allow` widened the trust set",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/trust.rs", 5)],
        last_audited_at: "2026-05-14",
    },
    // ── id 60: lpm trust prune ──
    SurfaceV2 {
        id: 60,
        scenarios: 4,
        failure_modes_tested: &[
            "dry-run reports stale entries without mutation",
            "--yes removes stale entries + preserves active ones",
            "no-stale-entries reports success without mutation",
            "without lockfile fails with helpful message",
        ],
        failure_modes_known: &[
            "permission denied on trust file",
            "concurrent prune + rebuild",
            "recovery on partial prune (snapshot rollback)",
            "prune against a workspace where some members have stale + others fresh entries",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/trust.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 61: lpm pool ──
    SurfaceV2 {
        id: 61,
        scenarios: 2,
        failure_modes_tested: &[
            "human output formats revenue summary + package rows",
            "JSON envelope snapshot",
        ],
        failure_modes_known: &[
            "pool with cycles (orphaned members)",
            "pool with circular workspace deps",
            "pool stats for a project with zero pooled deps",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/pool.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 62: lpm audit (bare) ──
    SurfaceV2 {
        id: 62,
        scenarios: 7,
        failure_modes_tested: &[
            "help lists fail-on policies on separate lines",
            "empty lockfile reports no packages + exits zero",
            "clean dep with empty OSV response exits zero",
            "high vuln under default policy exits nonzero",
            "private package without license does not emit no-license flag",
            "JSON envelope (one vuln) snapshot",
            "audit without node_modules helpful error",
        ],
        failure_modes_known: &[
            "OSV returns malformed JSON",
            "OSV times out partway through workspace audit",
            "audit on lockfile with packages registry no longer serves",
            "audit when behavioral analysis cache is corrupt",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/audit.rs", 7)],
        last_audited_at: "2026-05-14",
    },
    // ── id 63: lpm audit --fail-on=<policy> ──
    SurfaceV2 {
        id: 63,
        scenarios: 6,
        failure_modes_tested: &[
            "--fail-on=vuln triggers on OSV vuln",
            "--fail-on=behavior does not trigger on vuln alone",
            "--fail-on=all triggers on either",
            "OSV empty response → exit 0",
            "OSV mock returns one vuln → JSON envelope shape",
        ],
        failure_modes_known: &[
            "OSV returns malformed JSON",
            "OSV returns 5xx mid-batch",
            "OSV times out partway through a workspace audit",
            "audit on lockfile with packages the registry no longer serves",
            "audit when behavioral analysis cache is corrupt",
            "audit reports a finding for a package no longer installed",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/audit.rs", 6)],
        last_audited_at: "2026-05-14",
    },
    // ── id 64: lpm audit --secrets ──
    SurfaceV2 {
        id: 64,
        scenarios: 4,
        failure_modes_tested: &[
            "clean node_modules → no findings",
            "Stripe sk_live_… pattern detected",
            "AWS AKIA… pattern detected",
            "no node_modules → helpful error",
        ],
        failure_modes_known: &[
            "secret in JSON / YAML / TOML / .env file (not just .js)",
            "multi-line secret with line continuation",
            "secret in comment (false-positive surface)",
            "high-entropy random string adjacent to recognizable prefix",
            "secret in node_modules/<pkg>/.git/ subdir (should skip .git)",
            "binary file containing pattern-shaped bytes",
            "scoped @org/pkg dir (test only covers unscoped)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/audit.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 65: lpm query <selector> ──
    SurfaceV2 {
        id: 65,
        scenarios: 6,
        failure_modes_tested: &[
            "eval tag selector",
            "intersection selector requires both tags",
            "union selector includes either tag",
            "invalid selector syntax helpful error",
            "no-match human output indicates zero",
            "JSON envelope carries matched array",
        ],
        failure_modes_known: &[
            "selector syntax error diagnostics quality",
            "empty selector result handling",
            "circular workspace query",
            "selector against a 1000+ package transitive tree (perf)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/query.rs", 6)],
        last_audited_at: "2026-05-14",
    },
    // ── id 66: lpm query --count / --assert-none / --format mermaid ──
    SurfaceV2 {
        id: 66,
        scenarios: 3,
        failure_modes_tested: &[
            "count mode emits tag counts grouped by severity",
            "assert-none exits zero when match-set empty",
            "assert-none exits nonzero when at least one matches",
        ],
        failure_modes_known: &[
            "mermaid rendering on cyclic dep graph",
            "mermaid output for a 100+ package selection",
            "count under a registry-only-lpm filter",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/query.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 67: lpm rebuild (bare, trusted-only) ──
    SurfaceV2 {
        id: 67,
        scenarios: 20,
        failure_modes_tested: &[
            "deny policy: default selector filters to trusted only",
            "allow policy widens to every scripted package",
            "triage policy: greens auto-execute, ambers/reds block",
            "version-diff card surfaces on update",
            "trusted entries bypass scriptHash check",
            "Rich-form trustedDependencies surfaces approved pkg as trusted (cross-flow #6)",
        ],
        failure_modes_known: &[
            "rebuild during a concurrent install",
            "script writes outside sandbox (FS write denial test exists but limited)",
            "script attempts network egress under strict-sandbox",
            "script triggers SIGSEGV / SIGABRT mid-execution",
            "script holds open a long-running daemon (kill-tree behavior)",
            "script reads parent process env that wasn't scrubbed",
            "Windows AppContainer sandbox network denial (no test today)",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[
            ("tests/workflows/tests/rebuild.rs", 11),
            ("tests/workflows/tests/triage_install_lifecycle.rs", 3),
            ("tests/workflows/tests/cross_command_flows.rs", 1),
            ("tests/workflows/tests/approve_scripts.rs", 5),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 68: lpm rebuild --all ──
    SurfaceV2 {
        id: 68,
        scenarios: 4,
        failure_modes_tested: &[
            "allow policy widens to every scripted package",
            "deny skips all packages + keeps legacy pointer",
            "strict + sandbox-log suppresses strict banner under log-only",
            "triage default build points at approve-scripts for blocked",
        ],
        failure_modes_known: &[
            "concurrent rebuild --all + install",
            "partial rebuild on SIGKILL recovery (resume vs restart)",
            "rebuild --all across a workspace where some members have script-policy overrides",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/rebuild.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 69: lpm rebuild --policy=allow / --yolo ──
    SurfaceV2 {
        id: 69,
        scenarios: 2,
        failure_modes_tested: &[
            "allow policy dry-run envelope snapshot",
            "allow via CLI override or yolo alias also widens",
        ],
        failure_modes_known: &[
            "yolo with network egress (sandbox actually off)",
            "malicious script containment verification under yolo",
            "yolo + cross-platform sandbox parity (macOS vs Windows AppContainer)",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/rebuild.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 70: lpm rebuild --policy=triage / --triage ──
    SurfaceV2 {
        id: 70,
        scenarios: 5,
        failure_modes_tested: &[
            "triage policy does not widen beyond greens",
            "triage default dry-run filter keeps only green-promoted",
            "triage dry-run all-labels-green with promotion suffix",
            "triage default build points at approve-scripts for blocked",
            "triage JSON separates streams",
        ],
        failure_modes_known: &[
            "concurrent triage + user input via stdin",
            "triage with 100+ packages (scaling of layer-1/2/3 gates)",
            "triage without advisor + --auto-build keeps amber blocked",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/rebuild.rs", 5)],
        last_audited_at: "2026-05-14",
    },
    // ── id 71: lpm approve-scripts (interactive) ──
    SurfaceV2 {
        id: 71,
        scenarios: 2,
        failure_modes_tested: &[
            "non-TTY without --yes / --list / <pkg> fails with helpful alternatives",
            "--json in non-TTY emits failure envelope on stdout (finding #73)",
        ],
        failure_modes_known: &[
            "PTY-driven interactive walk (q to quit, v to view, a to approve)",
            "interactive walk: user interrupts with Ctrl-C mid-package",
            "interactive walk: terminal resize mid-render",
            "diff card rendering when prior approval exists",
            "approve-scripts on a project where the lockfile differs from the build-state.json",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("crates/lpm-cli/tests/approve_scripts_interactive_tty.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 72: lpm approve-scripts --list ──
    SurfaceV2 {
        id: 72,
        scenarios: 6,
        failure_modes_tested: &[
            "list dry-run silent no-op with uniform dry-run flag",
            "list surfaces exact added line on script-hash drift",
            "list JSON emits structured version-diff on script-hash drift",
            "list surfaces gained behavioral tags when tags-only drift",
            "list JSON emits gained-arrays on behavioral tag drift",
            "list filters already-approved packages after --yes",
        ],
        failure_modes_known: &[
            "list with no pending scripts (output shape)",
            "permission denied on approval file",
            "list across a workspace where each member has different pending sets",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/approve_scripts.rs", 6)],
        last_audited_at: "2026-05-14",
    },
    // ── id 73: lpm approve-scripts --yes ──
    SurfaceV2 {
        id: 73,
        scenarios: 4,
        failure_modes_tested: &[
            "yes dry-run does not mutate package.json + JSON carries flag",
            "yes JSON emits exactly one valid JSON payload on stdout",
            "yes JSON with no state file emits clean error JSON on stdout",
            "empty blocked-set envelope carries dry-run flag",
        ],
        failure_modes_known: &[
            "approve during lockfile divergence (build-state mismatch)",
            "concurrent approve + rebuild",
            "yes on a workspace where members disagree on policy",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/approve_scripts.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 74: lpm approve-scripts <pkg> ──
    SurfaceV2 {
        id: 74,
        scenarios: 3,
        failure_modes_tested: &[
            "named dry-run does not mutate package.json",
            "<pkg> --json envelope carries dry_run + approved_count",
            "specific-pkg arg for already-approved emits friendly error",
            "first-time review emits null version-diff + no card",
        ],
        failure_modes_known: &[
            "approval with missing package in lockfile",
            "approval of source package",
            "approval of a package that has multiple installed versions",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/approve_scripts.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 75: lpm approve-scripts --global ──
    SurfaceV2 {
        id: 75,
        scenarios: 5,
        failure_modes_tested: &[
            "global yes dry-run does not mutate trust file + JSON carries flag",
            "global named dry-run does not mutate trust file",
            "global named dry-run preserves pre-seeded trust file byte-equal",
            "global list JSON carries dry-run flag on both axes",
            "global yes dry-run JSON omits next-step",
        ],
        failure_modes_known: &[
            "global approval conflict (multi-project)",
            "permission denied on global approval dir",
            "global approval surviving an `lpm cache clean trust` (legacy state)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/approve_scripts.rs", 3),
            ("tests/workflows/tests/install_global_security.rs", 2),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 76: lpm approve-scripts --dry-run ──
    SurfaceV2 {
        id: 76,
        scenarios: 2,
        failure_modes_tested: &[
            "global yes live JSON carries next-step origins",
            "list JSON stays parseable with version-diff enrichment",
        ],
        failure_modes_known: &[
            "dry-run with missing approval file",
            "dry-run exit-code semantics vs live (finding #73)",
            "dry-run that would have promoted nothing (output shape)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/approve_scripts.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 77: lpm patch <key> ──
    SurfaceV2 {
        id: 77,
        scenarios: 3,
        failure_modes_tested: &[
            "extract path + breadcrumb",
            "rejects range keys (e.g., react@^18.0.0)",
            "missing-store package → helpful error",
        ],
        failure_modes_known: &[
            "patch source has read-only mount",
            "patch dir already has uncommitted changes",
            "patch chunk attempts file rename (DEFERRED_SURFACES.md #7)",
            "concurrent patch on same package@version",
            "patch survives store gc / cache prune",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/patch.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 78: lpm patch-commit <dir> ──
    SurfaceV2 {
        id: 78,
        scenarios: 3,
        failure_modes_tested: &[
            "writes patch file + updates manifest",
            "fails on no changes",
            "fails on binary change",
        ],
        failure_modes_known: &[
            "untracked patch files in git",
            "permission denied on patch dir",
            "concurrent patch-commit",
            "patch-commit when the source dir was moved between extract and commit",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/patch.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 79: lpm filter <expr> ──
    SurfaceV2 {
        id: 79,
        scenarios: 11,
        failure_modes_tested: &[
            "exact name selects only that member",
            "glob matches multiple members",
            "forward closure includes dependencies",
            "reverse closure includes dependents",
            "exclusion removes matched packages",
            "no-match without fail-flag exits zero",
            "no-match with fail-flag exits nonzero",
            "JSON envelope carries selected names + count",
            "JSON envelope includes trace entries",
            "outside workspace fails with helpful message",
            "explain mode renders per-package trace",
        ],
        failure_modes_known: &[
            "circular workspace filter",
            "filter on 100+ member workspace (scaling)",
            "filter combining glob + dependency-of in the same expr",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/filter.rs", 11)],
        last_audited_at: "2026-05-14",
    },
    // ── id 80: lpm deploy <out> --filter ──
    SurfaceV2 {
        id: 80,
        scenarios: 7,
        failure_modes_tested: &[
            "dry-run writes nothing to output dir",
            "dry-run JSON envelope carries resolved plan",
            "filter matching multiple members fails",
            "filter matching zero members fails",
            "into workspace directory rejected",
            "into non-empty dir without force rejected",
            "outside workspace context fails",
        ],
        failure_modes_known: &[
            "deploy nonexistent member error",
            "concurrent deploy same output dir",
            "deploy with circular members",
            "deploy across a member with workspace:^ pointing outside the closure",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/deploy.rs", 7)],
        last_audited_at: "2026-05-14",
    },
    // ── id 81: lpm plugin list / update ──
    SurfaceV2 {
        id: 81,
        scenarios: 2,
        failure_modes_tested: &[
            "list JSON reports installed versions + known latest versions",
            "update JSON reports zero updates when no plugins are installed",
        ],
        failure_modes_known: &[
            "plugin registry unavailable",
            "version mismatch between installed + registry",
            "malformed plugin registry response",
            "update under offline mode",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/plugin.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 82: lpm skills list/install/validate/clean ──
    SurfaceV2 {
        id: 82,
        scenarios: 9,
        failure_modes_tested: &[
            "list on fresh project reports no skills installed",
            "list groups by package + counts files",
            "list JSON envelope carries per-package arrays",
            "validate accepts a well-formed skill",
            "validate flags skill exceeding size limit in output",
            "validate with no skills dir succeeds quietly",
            "clean removes skills directory + reports count",
            "clean on empty project is idempotent",
            "unknown action fails with helpful message",
        ],
        failure_modes_known: &[
            "skills validate never exits non-zero (finding #72)",
            "malformed skill manifest (parse error path)",
            "concurrent skills clean + install",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/skills.rs", 9)],
        last_audited_at: "2026-05-14",
    },
    // ── id 83: lpm run <script> ──
    SurfaceV2 {
        id: 83,
        scenarios: 14,
        // 14 single-script run tests in `run.rs`. `--filter / --all /
        // --affected` cases live in id 84 — see partition there.
        failure_modes_tested: &[
            "executes script and succeeds",
            "script output reaches stdout",
            "forwards exit code from failing script",
            "missing script fails with error",
            "without package.json fails",
            "multiple scripts execute all",
            "executes pre + post hooks",
            "aborts if pre hook fails",
            "passes extra args after `--` separator",
            "respects task dependencies from lpm.json",
            "loads dotenv file",
            "loads env-mode file",
            "cache hit replays output",
            "--no-cache skips cache",
        ],
        failure_modes_known: &[
            "race with concurrent runs of the same script",
            "partial script execution (SIGKILL mid-script)",
            "symlink traversal in script path",
            "script that spawns a long-lived daemon (kill-tree behavior)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/run.rs", 14)],
        last_audited_at: "2026-05-14",
    },
    // ── id 84: lpm run --filter / --all / --affected ──
    SurfaceV2 {
        id: 84,
        scenarios: 7,
        failure_modes_tested: &[
            "multi-task JSON has task array",
            "parallel executes independent tasks",
            "--filter executes only matched members",
            "--all executes in every member",
            "--affected with no changes executes in zero members",
            "filter typo without fail-flag exits zero",
            "filter typo with fail-flag exits nonzero",
        ],
        failure_modes_known: &[
            "cross-workspace dependency ordering under --affected",
            "filter with no matches under --fail-if-no-match",
            "partial failure recovery in parallel runs",
            "--affected base ref pointing at a missing commit",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/run.rs", 7)],
        last_audited_at: "2026-05-14",
    },
    // ── id 85: lpm exec <file> ──
    SurfaceV2 {
        id: 85,
        scenarios: 3,
        failure_modes_tested: &[
            "loads dotenv + forwards args",
            "missing file fails before runtime execution",
            "missing file under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "file permission denied",
            "symlink escape in exec path",
            "exec under sandbox / strict-egress mode",
            "exec of a file with shebang resolving to an absent interpreter",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/exec.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 86: lpm dlx <pkg> ──
    SurfaceV2 {
        id: 86,
        scenarios: 2,
        failure_modes_tested: &[
            "cache hit executes cached binary + refreshes TTL",
            "malformed spec under --json emits error envelope (resolver range parse error)",
        ],
        failure_modes_known: &[
            "cache corruption recovery",
            "race condition cache evict mid-exec",
            "missing package in cache (cold path)",
            "dlx of a package whose entrypoint shells out",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/dlx.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 87: lpm lint ──
    SurfaceV2 {
        id: 87,
        scenarios: 5,
        failure_modes_tested: &[
            "filter typo without fail-flag exits zero",
            "filter typo with fail-flag exits nonzero",
            "filter typo JSON envelope shape",
            "--affected with no changes prints specific success message",
            "--all outside workspace errors clearly",
        ],
        failure_modes_known: &[
            "tool spawn failure (binary missing)",
            "permission denied on tool path",
            "cross-platform tool availability (oxlint not built for arch)",
            "lint --all on a workspace where one member has a broken config",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/tools.rs", 5)],
        last_audited_at: "2026-05-14",
    },
    // ── id 88: lpm fmt (write) ──
    SurfaceV2 {
        id: 88,
        scenarios: 3,
        failure_modes_tested: &[
            "filter typo without fail-flag exits zero",
            "filter typo with fail-flag exits nonzero",
            "filter typo JSON envelope shape",
        ],
        failure_modes_known: &[
            "concurrent fmt + cache prune",
            "partial write recovery on crash",
            "symlink target write",
            "fmt on a file whose encoding is not UTF-8",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/tools.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 89: lpm fmt --check ──
    SurfaceV2 {
        id: 89,
        scenarios: 1,
        failure_modes_tested: &["--check flag accepted alongside --filter"],
        failure_modes_known: &[
            "read-only filesystem (still reports diff cleanly)",
            "permission denied on file",
            "cross-platform line endings (CRLF vs LF)",
            "check on a file whose declared dialect mismatches biome's expectation",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/tools.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 90: lpm check ──
    SurfaceV2 {
        id: 90,
        scenarios: 11,
        failure_modes_tested: &[
            "workspace JSON emits valid envelope per member",
            "doctor emits typescript-healthy when local tsc resolves",
            "doctor emits typescript-unavailable when declared but not installed",
            "doctor emits typescript-unavailable when dep not declared",
            "doctor emits no-typescript-check when no tsconfig",
            "doctor emits per-member typescript checks in workspace",
            "check preflight errors when no tsconfig + no explicit target",
            "check preflight skips when user passes explicit project",
            "check preflight errors when typescript not installed/declared",
            "check preflight errors when typescript declared but not installed",
            "unsupported tool pin emits warning on tool command",
        ],
        failure_modes_known: &[
            "tsc not on PATH at runtime",
            "typechecking timeout (cancellation behavior)",
            "memory exhaustion in tsc on large projects",
            "tsc version mismatch between members",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/tools.rs", 1),
            ("tests/workflows/tests/check_typescript.rs", 10),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 91: lpm test ──
    SurfaceV2 {
        id: 91,
        scenarios: 7,
        failure_modes_tested: &[
            "filter typo with fail-flag exits nonzero",
            "filter typo JSON envelope shape",
            "multi-member watch rejected with count",
            "filter one-member with watch hands off to single-package",
            "zero-member watch rejects with nothing-to-watch",
            "workspace JSON emits valid envelope per member",
            "double-dash still forwards recognized flags to runner",
        ],
        failure_modes_known: &[
            "test timeout handling per member",
            "concurrent test isolation under --all",
            "flaky test detection (retry policy)",
            "test runner not installed in member's node_modules",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/tools.rs", 7)],
        last_audited_at: "2026-05-14",
    },
    // ── id 92: lpm bench ──
    SurfaceV2 {
        id: 92,
        scenarios: 3,
        failure_modes_tested: &[
            "multi-member watch rejected with count",
            "filter one-member with watch hands off to single-package",
            "no-runner error envelope on stdout under --json",
        ],
        failure_modes_known: &[
            "benchmark timeout handling",
            "resource exhaustion during bench",
            "cross-platform timing variance",
            "bench against a member with no bench script",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/tools.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 93: lpm ci ──
    //
    SurfaceV2 {
        id: 93,
        scenarios: 3,
        failure_modes_tested: &[
            "missing lockfile fails as a frozen install",
            "matching frozen lockfile replays without rewriting lockfiles",
            "JSON success envelope remains parseable without rewriting lpm.lock",
        ],
        failure_modes_known: &[
            "strict peer failure under frozen replay",
            "offline frozen replay with missing store entries",
            "root lifecycle failure before dependency replay",
            "workspace importer snapshots",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/ci.rs", 1),
            ("tests/workflows/tests/frozen_lockfile.rs", 2),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 94: lpm setup ci github-actions ──
    SurfaceV2 {
        id: 94,
        scenarios: 2,
        failure_modes_tested: &[
            "uses project vault id + requested env name",
            "unknown-platform error envelope on stdout under --json (shared dispatcher with id 95)",
        ],
        failure_modes_known: &[
            "malformed vault config",
            "concurrent workflow setup",
            "token expiry mid-setup",
            "setup against a workflow file the user has hand-edited",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/ci.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 95: lpm setup ci gitlab ──
    SurfaceV2 {
        id: 95,
        scenarios: 4,
        failure_modes_tested: &[
            "gitlab emits id-tokens block + authorization command",
            "gitlab with --env-flag threads the env name",
            "unknown platform fails with helpful message",
            "unknown-platform error envelope on stdout under --json",
            "without platform arg fails with usage message",
        ],
        failure_modes_known: &[
            "gitlab API unavailable",
            "malformed OIDC config",
            "concurrent gitlab setup",
            "gitlab CI YAML already contains conflicting id_tokens stanza",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/ci.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 96: lpm env init ──
    SurfaceV2 {
        id: 96,
        scenarios: 2,
        failure_modes_tested: &[
            "vault initialization happens implicitly on first `env set`",
            "explicit `env init --json` envelope carries environments[] + actions[]",
        ],
        failure_modes_known: &[
            "concurrent env init from two CLIs",
            "storage quota exceeded on init",
            "init in an already-initialized vault (idempotent vs error)",
            "init under a HOME with restricted permissions",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_local.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 97: lpm env ls / list ──
    SurfaceV2 {
        id: 97,
        scenarios: 1,
        failure_modes_tested: &[
            "list JSON envelope carries keys",
            "list JSON envelope shape locked (snapshot)",
        ],
        failure_modes_known: &[
            "symlink in env path",
            "permission denied on env file",
            "case-collision in key names on case-insensitive FS",
            "list under an env that was deleted by a concurrent CLI",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/env_local.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 98: lpm env set / get / delete ──
    SurfaceV2 {
        id: 98,
        scenarios: 6,
        failure_modes_tested: &[
            "set persists key/value + get reveals",
            "get without --reveal masks the value",
            "delete removes key",
            "set without pairs fails with usage message",
            "set with --env flag scopes to named environment",
            "unknown action lists available subcommands",
        ],
        failure_modes_known: &[
            "concurrent set on same key",
            "race condition between delete + set",
            "set with Unicode key name (normalization)",
            "set of a value larger than the vault's size cap",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_local.rs", 6)],
        last_audited_at: "2026-05-14",
    },
    // ── id 99: lpm env import / export / print / copy ──
    SurfaceV2 {
        id: 99,
        scenarios: 4,
        failure_modes_tested: &[
            "import from dotenv populates vault (envelope: success + imported count)",
            "export writes dotenv with all keys (envelope: success + exported count)",
            "print streams keys to stdout",
            "copy duplicates environment into target (envelope: success)",
        ],
        failure_modes_known: &[
            "malformed import file (helpful diagnostics)",
            "circular reference in export",
            "import overwrites existing without --force",
            "copy across two pair-bound vaults on the same machine",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_local.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 100: lpm env diff / validate / check ──
    SurfaceV2 {
        id: 100,
        scenarios: 4,
        failure_modes_tested: &[
            "diff local-vs-local reports added/removed/changed keys",
            "validate reports missing keys against dotenv-example",
            "validate without dotenv-example fails with helpful message",
            "check without lpm.json env schema fails with helpful message",
        ],
        failure_modes_known: &[
            "validation error propagation across nested schemas",
            "malformed schema in lpm.json",
            "diff between local + remote (cloud-bound path)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_local.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 101: lpm env push / pull (cloud) ──
    SurfaceV2 {
        id: 101,
        scenarios: 10,
        failure_modes_tested: &[
            "pull overwrites local state with remote environments",
            "cross-machine push→pull plaintext byte-equality under shared wrapping key (flow #7)",
            "pull-oidc writes env file with sorted + quoted values",
            "pull-oidc uses LPM_OIDC_TOKEN canonical + ignores CI_JOB_JWT_V2",
            "pull-oidc gitlab envelope shape locked (snapshot)",
            "pull-oidc uses github-actions runtime token",
            "pull-oidc partial github signal token-only falls through",
            "pull-oidc partial github signal url-only falls through",
            "pull-oidc surfaces github runtime request failures",
            "pull-oidc rejects github runtime responses without value",
            "pull-oidc surfaces exchange-error hint",
        ],
        failure_modes_known: &[
            "network failure mid-sync (partial-state recovery)",
            "concurrent push + pull on same env",
            "push to a vault whose org membership was revoked between auth + write",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[
            ("tests/workflows/tests/env_vault.rs", 9),
            ("tests/workflows/tests/cross_command_flows.rs", 1),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 102: lpm env share ──
    SurfaceV2 {
        id: 102,
        scenarios: 2,
        failure_modes_tested: &[
            "share --force fails before vault or network access",
            "share --force under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "empty vault refusal under --json",
            "not logged in under --json",
            "org version conflict with pull-then-retry remediation",
            "sharing-key rotation-required refusal",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_vault.rs", 2)],
        last_audited_at: "2026-06-11",
    },
    // ── id 103: lpm env pair ──
    SurfaceV2 {
        id: 103,
        scenarios: 9,
        failure_modes_tested: &[
            "uppercases code + approves browser pairing",
            "refresh-only session pair then unpair reuses normalized session",
            "pair then logout revokes pairings + blocks future commands",
            "surfaces expired-code error",
            "rejects non-pending session status",
            "rejects malformed browser key",
            "pair without auth under --json emits error envelope on stdout",
            "refuses to wrap when stdin is not a TTY and --yes is absent",
            "renders browser key fingerprint, device label, match number, --yes audit warning before approving",
        ],
        failure_modes_known: &[
            "pairing token expiry mid-flow",
            "network timeout mid-pair",
            "concurrent pair from two devices using same code",
            "pair after a logout-all on a refresh-backed session",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_vault.rs", 9)],
        last_audited_at: "2026-05-20",
    },
    // ── id 104: lpm env unpair ──
    SurfaceV2 {
        id: 104,
        scenarios: 5,
        failure_modes_tested: &[
            "requires session-based login",
            "pair → unpair → logout on refresh-backed session keeps normalized state",
            "pair → unpair → logout-all on refresh-backed session clears auth state",
            "unpair blocks future vault commands",
            "unpair without auth under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "concurrent unpair operations",
            "orphaned local state cleanup after unpair",
            "unpair while a push/pull is mid-flight",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/env_vault.rs", 4),
            ("tests/workflows/tests/env_local.rs", 1),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 105: lpm env connect / status / log / rotate-key / list-remote ──
    SurfaceV2 {
        id: 105,
        scenarios: 5,
        failure_modes_tested: &[
            "connect --json success envelope carries success + status + platform",
            "status --json success envelope carries success + count + platforms",
            "log without vault under --json emits error envelope on stdout",
            "rotate-key without vault under --json emits error envelope on stdout",
            "list-remote without auth under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "connect network failure after auth",
            "status response with malformed platform entries",
            "audit log pagination cursor handling",
            "rotate-key push conflict",
            "list-remote org route with multiple vaults",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_vault.rs", 5)],
        last_audited_at: "2026-06-11",
    },
    // ── id 106: lpm env oidc allow ──
    SurfaceV2 {
        id: 106,
        scenarios: 7,
        failure_modes_tested: &[
            "missing repo emits JSON error",
            "allow then list shows policy + escrow success",
            "emits JSON response",
            "warns when escrow upload fails",
            "allow + list on refresh-backed session then logout-all clears auth state",
            "warns on refresh-backed session then logout clears auth state",
            "canonicalizes env aliases before storing policy",
        ],
        failure_modes_known: &[
            "malformed OIDC claim",
            "JWT signature mismatch",
            "allow against a vault the user lacks admin rights to",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_vault.rs", 7)],
        last_audited_at: "2026-05-14",
    },
    // ── id 107: lpm env oidc list ──
    SurfaceV2 {
        id: 107,
        scenarios: 2,
        failure_modes_tested: &["without vault emits JSON error", "emits JSON response"],
        failure_modes_known: &[
            "vault unavailable mid-list",
            "malformed config response from vault",
            "list across a vault with 100+ allowed identities",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_vault.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 108: lpm env oidc pull ──
    SurfaceV2 {
        id: 108,
        scenarios: 1,
        failure_modes_tested: &["exchange-error emits JSON error"],
        failure_modes_known: &[
            "token expiry handling mid-exchange",
            "provider error propagation into JSON envelope",
            "exchange against an unsupported OIDC provider issuer",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/env_vault.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 109: lpm dev ──
    //
    // KEEP_NONE rationale: `lpm dev` boots a long-running orchestrator
    // (HTTPS server, tunnel, dashboard) and streams progress / logs to
    // stdout for the developer. A single JSON envelope on the same
    // surface would either be emitted at startup (before useful info
    // exists) or held until shutdown (defeating the long-running
    // contract). Parse-time errors (clap-level help) go through the
    // human formatter intentionally — `lpm dev --help` is for humans
    // reading at a terminal, not for machine consumers. Not a gap.
    SurfaceV2 {
        id: 109,
        scenarios: 1,
        failure_modes_tested: &["dev help emits command usage + flags"],
        failure_modes_known: &[
            "dev server start failure (port in use)",
            "TLS certificate generation failure",
            "dev under a HOME without write permission on .lpm/dev",
            "dev on a machine missing the bundled runtime binary",
        ],
        json_contract_depth: JsonContractDepth::None,
        scenarios_by_file: &[("tests/workflows/tests/dev_tunnel.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 110: lpm dev --tunnel / --https / --network ──
    //
    // KEEP_NONE rationale: same surface shape as id 109 — long-running
    // orchestrator with streaming stdout, no envelope contract. The
    // tunnel / https / network flags layer additional services into
    // the same `lpm dev` process; their failure modes (tunnel session
    // expiry, TLS cert generation failure, port-in-use) surface
    // mid-stream and don't fit the single-envelope shape. Not a gap.
    SurfaceV2 {
        id: 110,
        scenarios: 1,
        failure_modes_tested: &["dev help surfaces --tunnel / --https / --network in flag list"],
        failure_modes_known: &[
            "tunnel service unavailable mid-bind",
            "https flag without local CA installed",
            "network flag binding to a privileged port (Unix EACCES)",
            "tunnel + https together (interaction matrix)",
        ],
        json_contract_depth: JsonContractDepth::None,
        scenarios_by_file: &[("tests/workflows/tests/dev_tunnel.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 111: lpm cert status / trust / uninstall / generate ──
    SurfaceV2 {
        id: 111,
        scenarios: 4,
        failure_modes_tested: &[
            "status JSON reports absent CA + project cert",
            "trust JSON generates CA + installs into isolated test store",
            "uninstall JSON removes trust store entry but keeps CA files",
            "generate JSON regenerates when requested host is missing",
        ],
        failure_modes_known: &[
            "CA key permissions check on multi-user systems",
            "concurrent cert ops on same store",
            "certificate trust-chain validation on Windows + Linux stores",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/cert.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 112: lpm graph (tree default) ──
    SurfaceV2 {
        id: 112,
        scenarios: 4,
        failure_modes_tested: &[
            "--depth truncates JSON format",
            "--depth truncates HTML stats summary",
            "stats max-depth matches flag input",
            "bare graph --json without lockfile emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "graph cycle detection in tree output",
            "malformed lockfile parsing (graceful diagnostics)",
            "graph on a workspace with circular members",
            "graph against a fully hoisted vs isolated layout",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/graph.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 113: lpm graph --format json ──
    SurfaceV2 {
        id: 113,
        scenarios: 2,
        failure_modes_tested: &[
            "--format json envelope matches snapshot",
            "html writes human-readable size",
        ],
        failure_modes_known: &[
            "graph JSON serialization mismatch on prerelease versions",
            "missing transitive edges in JSON",
            "JSON output for a 1000+ package transitive tree (perf)",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/graph.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 114: lpm graph --format html ──
    SurfaceV2 {
        id: 114,
        scenarios: 4,
        failure_modes_tested: &[
            "html writes to .lpm dir + respects --no-open",
            "--no-open without --html warns + prints to stdout",
            "--no-open warning suppressed under global --json flag",
            "missing-lockfile under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "file write permission denied",
            "concurrent HTML generation",
            "HTML rendering for large graphs (>1000 nodes)",
            "HTML output written to a path that already exists as a directory",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/graph.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 115: lpm graph --format dot / mermaid / stats ──
    SurfaceV2 {
        id: 115,
        scenarios: 4,
        failure_modes_tested: &[
            "--format dot emits valid dot syntax to stdout",
            "--format mermaid emits valid mermaid syntax to stdout",
            "stats max-depth matches flag input",
            "missing-lockfile under --json emits error envelope on stdout (all 3 formats)",
        ],
        failure_modes_known: &[
            "unsupported --format value error path",
            "graph-too-large for mermaid (rendering fail under viewer)",
            "dot output piped through `graphviz -Tsvg` parity (extern tool)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/graph.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 116: lpm graph --why <pkg> ──
    SurfaceV2 {
        id: 116,
        scenarios: 7,
        failure_modes_tested: &[
            "--why human output shows override trace",
            "--why JSON output includes applied overrides",
            "--why JSON output returns empty overrides when no state file",
            "--why human output shows patch trace",
            "--why JSON output includes applied patches",
            "--why JSON output returns empty applied-patches when no state file",
            "--why includes original integrity in human + JSON",
        ],
        failure_modes_known: &[
            "missing dependency in graph (helpful error)",
            "circular dependency path terminates cleanly",
            "--why for a package present in multiple workspace members at different versions",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/graph.rs", 7)],
        last_audited_at: "2026-05-14",
    },
    // ── id 117: lpm ports list / all / inspect / kill / reset ──
    SurfaceV2 {
        id: 117,
        scenarios: 43,
        failure_modes_tested: &[
            "list JSON reports free + in-use services",
            "list human renders table + slim completion",
            "kill JSON reports already-free for unused port",
            "kill human reports already-free with slim completion",
            "ports all JSON includes visible live listener",
            "default project list falls back to cwd-rooted listeners when no services exist",
            "bare port inspect JSON reports visible live listener",
            "range kill JSON with --yes reports empty free range",
            "range kill JSON without --yes requires confirmation before termination",
            "range kill JSON with --yes terminates a live listener process",
            "range kill candidates dedupe duplicate port rows by PID",
            "reset JSON clears only current-project overrides",
            "bare number parses as port inspect, not PID kill",
            "all command and --all flag parse as system-wide list",
            "PID kill requires explicit --pid",
            "inclusive range kill target parses",
            "descending range kill target is rejected",
            "macOS/BSD lsof parser dedupes dual-stack same PID/port",
            "macOS/BSD lsof parser reads IPv6 and wildcard addresses",
            "macOS/BSD ps parser preserves full command",
            "Linux /proc TCP parser reads IPv4/IPv6 listeners and ignores non-listeners",
            "Linux /proc process parser reads cmdline/stat/socket inode",
            "Windows TCP helper decodes ports and addresses",
            "Windows process helper reads image names, FILETIME, and PID+creation identity",
            "Windows IP Helper live-listener test covers current process",
            "cwd project discovery finds nearest manifest and framework",
            "cwd project discovery cache hits avoid repeated walks for the same cwd",
            "unsupported platform listener discovery returns empty cleanly",
            "ports.toml project override cleanup preserves unrelated projects",
            "ports.toml atomic write creates parent directories",
        ],
        failure_modes_known: &[
            "port binding race condition between list + kill",
            "concurrent operations across projects on same port",
            "kill of a port held by a process the user lacks privilege to signal",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[
            ("crates/lpm-cli/src/commands/ports.rs", 6),
            ("crates/lpm-runner/src/ports.rs", 26),
            ("tests/workflows/tests/ports.rs", 11),
        ],
        last_audited_at: "2026-06-01",
    },
    // ── id 118: lpm tunnel <port> (start) ──
    SurfaceV2 {
        id: 118,
        scenarios: 2,
        failure_modes_tested: &[
            "tunnel help emits action summary",
            "tunnel <port> without auth under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "tunnel service connection failure",
            "port already in use",
            "tunnel session expiry mid-stream",
            "tunnel under a HOME that has never been paired",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/dev_tunnel.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 119: lpm tunnel claim / unclaim / list / domains ──
    SurfaceV2 {
        id: 119,
        scenarios: 3,
        failure_modes_tested: &[
            "claim without auth fails with clear message",
            "claim without auth under --json emits error envelope on stdout",
            "list without auth under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "domain already claimed",
            "concurrent claim operations",
            "domain DNS propagation timing",
            "unclaim of a domain that was force-released server-side",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/dev_tunnel.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 120: lpm tunnel inspect / replay / log ──
    SurfaceV2 {
        id: 120,
        scenarios: 2,
        failure_modes_tested: &[
            "action enumeration is reachable via tunnel help",
            "inspect without auth under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "tunnel session expired (inspect/replay error path)",
            "concurrent inspection access on same session",
            "log rotation behavior under long sessions",
            "replay against a request whose body bytes have been GC'd server-side",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/dev_tunnel.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 121: lpm migrate (auto-detect npm/yarn/pnpm/bun) ──
    SurfaceV2 {
        id: 121,
        scenarios: 16,
        failure_modes_tested: &[
            "npm creates lockfile",
            "npm creates backup",
            "yarn creates lockfile",
            "pnpm creates lockfile",
            "pnpm translates overrides to lpm section",
            "pnpm overrides conflict aborts before any write",
            "pnpm overrides dry-run reports translation count",
            "pnpm translates patches to lpm section",
            "pnpm patches conflict aborts before any write",
            "pnpm patches rewrites pnpm path for non-canonical source",
            "pnpm patches directory path aborts",
            "bun creates lockfile",
            "yes alone does not overwrite existing lockfile",
            "without package.json fails",
            "refuses overwrite without force",
            "npm lockfile contains packages",
        ],
        failure_modes_known: &[
            "malformed source lockfile (mid-parse)",
            "concurrent migration on same project",
            "partial recovery on interrupt",
            "migrate from a lockfile format the toolchain does not understand",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/migrate.rs", 16)],
        last_audited_at: "2026-05-14",
    },
    // ── id 122: lpm migrate --rollback ──
    SurfaceV2 {
        id: 122,
        scenarios: 1,
        failure_modes_tested: &[
            "rollback restores original",
            "--json envelope carries success + rollback flag + restored_files[]",
        ],
        failure_modes_known: &[
            "rollback without backup",
            "partial rollback recovery",
            "rollback after manual lockfile edits since the backup",
            "rollback under a workspace where some members migrated + others didn't",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/migrate.rs", 1)],
        last_audited_at: "2026-05-14",
    },
    // ── id 123: lpm migrate --dry-run ──
    SurfaceV2 {
        id: 123,
        scenarios: 3,
        failure_modes_tested: &[
            "dry-run does not write lockfile",
            "pnpm overrides dry-run reports translation count",
            "dry-run JSON output (json_output.rs)",
        ],
        failure_modes_known: &[
            "dry-run accuracy vs actual mismatch",
            "symlink handling in dry-run",
            "dry-run against an already-migrated project (no-op shape)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("tests/workflows/tests/migrate.rs", 2),
            ("tests/workflows/tests/json_output.rs", 1),
        ],
        last_audited_at: "2026-05-14",
    },
    // ── id 124: lpm migrate --ci / --no-npmrc ──
    SurfaceV2 {
        id: 124,
        scenarios: 4,
        failure_modes_tested: &[
            "--ci generates workflow template file",
            "--ci --json envelope carries success=true alongside file emission",
            "without --ci does not generate workflow file",
            "--no-npmrc skips npmrc creation",
            "default creates npmrc unless --no-npmrc",
        ],
        failure_modes_known: &[
            "--ci against an unknown CI platform",
            "--no-npmrc cleanup on error mid-write",
            "--ci + --no-npmrc interaction matrix",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/migrate.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 125: lpm vault open / update / version ──
    SurfaceV2 {
        id: 125,
        scenarios: 5,
        failure_modes_tested: &[
            "open on non-macos fails with unsupported message",
            "open on non-macos under --json emits error envelope on stdout",
            "bare defaults to open + fails on non-macos",
            "update on non-macos fails with unsupported message",
            "version on non-macos fails with unsupported message",
            "unknown action fails with helpful message",
            "unknown action under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "macos-only happy paths (open / update / version, no test today)",
            "vault unlock race on macos",
            "vault under a HOME mounted from a network share",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/vault.rs", 5)],
        last_audited_at: "2026-05-14",
    },
    // ── id 126: lpm self-update ──
    SurfaceV2 {
        id: 126,
        scenarios: 2,
        failure_modes_tested: &[
            "cache hit with matching latest reports up-to-date",
            "recent failure short-circuits with backoff error",
        ],
        failure_modes_known: &[
            "update download failure mid-stream",
            "permission denied on binary replace",
            "platform-specific binary mismatch (arch vs OS)",
            "self-update during an active install (binary held open)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/self_update.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 127: lpm internal-update-check (hidden) ──
    //
    // KEEP_NONE rationale: this is a hidden, fire-and-forget background
    // updater spawned by the parent `lpm` process. Its only side effect
    // is refreshing `<HOME>/.lpm/.update-cache.json`; it is INTENTIONALLY
    // silent on stdout/stderr so the parent's user-facing output isn't
    // polluted by a background subprocess's chatter. Adding an envelope
    // would either leak into the parent's piped output or require the
    // parent to filter it out — both defeat the "silent background
    // worker" contract. Not a gap.
    SurfaceV2 {
        id: 127,
        scenarios: 2,
        failure_modes_tested: &[
            "hidden command exits zero even offline",
            "command is hidden from help",
        ],
        failure_modes_known: &[
            "cache corruption recovery",
            "staleness detection failure",
            "internal-update-check fires during a slow `lpm install` (background race)",
        ],
        json_contract_depth: JsonContractDepth::None,
        scenarios_by_file: &[("tests/workflows/tests/dev_tunnel.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 128: lpm swift-registry ──
    SurfaceV2 {
        id: 128,
        scenarios: 4,
        failure_modes_tested: &[
            "swift-registry help works",
            "--force flag accepted at parse time",
            "setup-with-mock smoke",
            "--json envelope carries success field",
        ],
        failure_modes_known: &[
            "swift toolchain unavailable",
            "certificate trust failure in xcode integration",
            "swift-registry login on a machine without swift installed",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/swift.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 129: lpm mcp setup / remove / status ──
    SurfaceV2 {
        id: 129,
        scenarios: 4,
        failure_modes_tested: &[
            "status on fresh home succeeds",
            "status JSON envelope is valid JSON",
            "remove without name fails with helpful message",
            "unknown action lists valid subcommands",
        ],
        failure_modes_known: &[
            "editor config permission denied",
            "malformed MCP config",
            "concurrent setup + status",
            "setup against an editor that doesn't ship MCP support",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/mcp.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 130: lpm use node@<v> ──
    SurfaceV2 {
        id: 130,
        scenarios: 3,
        failure_modes_tested: &[
            "install unsupported runtime fails before network call",
            "install without runtime prefix fails with usage",
            "use --pin without spec under --json emits error envelope on stdout",
        ],
        failure_modes_known: &[
            "node download network failure",
            "architecture mismatch detection (arm64 vs x86_64)",
            "checksum mismatch on downloaded runtime",
            "use of a runtime version no longer hosted upstream",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/use.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 131: lpm use --list ──
    SurfaceV2 {
        id: 131,
        scenarios: 4,
        failure_modes_tested: &[
            "list on empty runtime succeeds with empty set",
            "JSON envelope reports empty versions on fresh home",
            "no-args falls through to list path",
            "list with unsupported runtime filter fails cleanly",
        ],
        failure_modes_known: &[
            "symlink in runtime path",
            "permission denied on runtime dir",
            "list under a HOME whose runtime dir is corrupted",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/use.rs", 4)],
        last_audited_at: "2026-05-14",
    },
    // ── id 132: lpm completions <shell> ──
    //
    // KEEP_NONE rationale: this surface emits a shell completion
    // script (bash function, zsh _lpm definition, fish/PowerShell
    // equivalents) on stdout, intended to be `eval`d or written to a
    // completion-load path. A JSON envelope would defeat the contract
    // — the user can't pipe `{"success": true, "script": "_lpm() {..."}`
    // into `~/.zshrc`. Error paths (invalid shell value) are clap-level
    // and rejected before main() runs; clap's `value_enum` rejection
    // can't be intercepted by the LpmError → envelope handler without
    // a much larger refactor. Not a gap. See finding #76 for the broader
    // clap-vs-envelope routing story.
    SurfaceV2 {
        id: 132,
        scenarios: 3,
        failure_modes_tested: &[
            "zsh stdout uses lpm bin name + lists live commands",
            "bash emits bash completion script",
            "invalid shell rejected by clap",
        ],
        failure_modes_known: &[
            "shell not found in PATH (post-install hook scenario)",
            "completion lag vs clap evolution",
            "completions for fish / powershell (not yet supported)",
        ],
        json_contract_depth: JsonContractDepth::None,
        scenarios_by_file: &[("tests/workflows/tests/completions.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 133: lpm schema lpm.json ──
    SurfaceV2 {
        id: 133,
        scenarios: 2,
        failure_modes_tested: &[
            "emits valid JSON schema to stdout",
            "with --out writes to file + silences stdout",
        ],
        failure_modes_known: &[
            "schema generation from struct mismatch (drift)",
            "out path permission denied",
            "schema output for an unknown kind (helpful error)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/schema.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 134: lpm schema lpm.config.json ──
    SurfaceV2 {
        id: 134,
        scenarios: 2,
        failure_modes_tested: &[
            "emits hand-authored schema with $id",
            "unknown kind fails with helpful message",
        ],
        failure_modes_known: &[
            "schema drift vs committed version",
            "out flag file writing under read-only FS",
            "schema parity with the runtime parser for lpm.config.json",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/schema.rs", 2)],
        last_audited_at: "2026-05-14",
    },
    // ── id 135: lpm strict-ssl warning (cross-cmd installer warning) ──
    SurfaceV2 {
        id: 135,
        scenarios: 3,
        failure_modes_tested: &[
            "strict-ssl=false emits loud warning with source citation",
            "strict-ssl=false emits warning even in --json mode",
            "no strict-ssl setting emits no warning",
        ],
        failure_modes_known: &[
            "false-positive on custom CA chain",
            "suppression flag (NODE_TLS_REJECT_UNAUTHORIZED) ignored",
            "warning interaction with --offline + .npmrc routing",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/install.rs", 3)],
        last_audited_at: "2026-05-14",
    },
    // ── id 136: lpm install pnpm migration warnings ──
    //
    // Carved out of id 12 during the 2026-05-14 v2 partition pass.
    // These tests exercise install's cross-tool-input behavior: when a
    // project still carries pnpm-shaped `overrides` / `patches` blocks
    // and `lpm migrate` either hasn't run, has partially translated,
    // or has diverged from the lpm-section state, install should
    // either warn loudly (with --json suppression) or stay silent when
    // the lpm-side already covers the same keys/paths. Folding these
    // under id 12 would have inflated id 12's failure_modes_tested
    // list with cross-tool concerns that have no bearing on the
    // lockfile fast-path.
    SurfaceV2 {
        id: 136,
        scenarios: 8,
        failure_modes_tested: &[
            "warns when pnpm overrides dropped during migration",
            "pnpm overrides warning silenced under --json",
            "warns when pnpm and lpm override targets diverge",
            "pnpm overrides warning silent when lpm side covers same keys",
            "warns when pnpm patches dropped during migration",
            "pnpm patches warning silent when lpm side covers same paths",
            "warns when pnpm and lpm patch paths diverge",
            "pnpm patches warning silenced under --json",
        ],
        failure_modes_known: &[
            "warning when pnpm-lock.yaml is malformed mid-parse",
            "warning interaction with --offline (no migration source)",
            "warning suppression precedence (env var vs --json vs lpm.toml)",
            "warning surface when both overrides AND patches diverge in same install",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/install.rs", 8)],
        last_audited_at: "2026-05-14",
    },
    // ── id 137: lpm install linker validation (LPM_LINKER) ──
    //
    // Carved out of id 12 during the 2026-05-14 v2 partition pass.
    // These tests exercise install's config-validation contract for
    // the LPM_LINKER env var + --linker CLI flag: unknown values are
    // rejected loudly at the earliest practical surface (clap parse,
    // env normalization, or sync fast-lane). Also covers the
    // freshness-cache invalidation contract: flipping the linker
    // value between runs must invalidate the install-hash so the next
    // install actually re-links rather than skipping under up-to-date.
    SurfaceV2 {
        id: 137,
        scenarios: 6,
        failure_modes_tested: &[
            "rejects unknown LPM_LINKER value with loud error",
            "--linker CLI flag rejects unknown value at clap parse",
            "migrate honors LPM_LINKER env when invoking install pipeline",
            "install invalidates freshness cache on LPM_LINKER flip",
            "invalid LPM_LINKER surfaces through sync fast-lane (not just slow path)",
            "LPM_LINKER env rejects unknown value loudly at normalization",
        ],
        failure_modes_known: &[
            "concurrent installs with different LPM_LINKER values racing on the cache",
            "LPM_LINKER set to a future-only value (forward-compat error UX)",
            "linker flip mid-install (SIGHUP between resolve and link)",
            "LPM_LINKER honoring across workspace member install (per-member override)",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/install.rs", 6)],
        last_audited_at: "2026-05-14",
    },
    // ── id 138: lpm bundle ──
    SurfaceV2 {
        id: 138,
        scenarios: 3,
        failure_modes_tested: &[
            "single-package bundle reuses seeded managed rolldown engine",
            "workspace bundle emits per-member JSON envelope",
            "fail-if-no-match turns filter typos into non-zero exit",
        ],
        failure_modes_known: &[
            "workspace watch selection rejects multi-member fan-out",
            "spawn failure when node is unavailable on PATH",
            "engine prewarm failure surfaces exit_code null with error in workspace JSON envelope",
            "cold managed rolldown install path without seeded cache",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[("tests/workflows/tests/bundle.rs", 3)],
        last_audited_at: "2026-05-25",
    },
    // ── id 139: lpm pack ──
    SurfaceV2 {
        id: 139,
        scenarios: 3,
        failure_modes_tested: &[
            "single-package pack runs the project-local tsdown binary with forwarded flags",
            "workspace pack emits per-member JSON envelope",
            "fail-if-no-match turns filter typos into non-zero exit",
        ],
        failure_modes_known: &[
            "workspace watch selection rejects multi-member fan-out",
            "tsdown missing from the reachable node_modules/.bin chain",
            "spawn failure when node is unavailable on PATH",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/pack.rs", 3)],
        last_audited_at: "2026-05-25",
    },
    // ── id 140: lpm catalog list --unused ──
    SurfaceV2 {
        id: 140,
        scenarios: 1,
        failure_modes_tested: &[
            "unused default catalog entries reported",
            "unused named catalog entries reported",
            "JSON envelope count and entries snapshot",
        ],
        failure_modes_known: &[
            "pnpm-workspace.yaml-only unused catalog entries",
            "workspace member reference keeps root catalog entry live",
            "malformed package.json catalog shape",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/pnpm_compat_catalog.rs", 1)],
        last_audited_at: "2026-05-28",
    },
    // ── id 141: lpm catalog show --resolved ──
    SurfaceV2 {
        id: 141,
        scenarios: 1,
        failure_modes_tested: &[
            "resolved catalog snapshot reports catalog name",
            "resolved catalog snapshot reports package specifier and version",
            "resolved catalog snapshot reports consumer reference shape",
            "JSON envelope count and entries snapshot",
        ],
        failure_modes_known: &[
            "missing lockfile",
            "lockfile without catalog snapshot",
            "stale lockfile catalog snapshot after manifest drift",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/pnpm_compat_catalog.rs", 1)],
        last_audited_at: "2026-05-28",
    },
    // ── id 142: lpm patch-remove <selector> ──
    SurfaceV2 {
        id: 142,
        scenarios: 7,
        failure_modes_tested: &[
            "exact key removes manifest entry and deletes unshared patch file",
            "bare-name selector requires a unique patched version",
            "shared patch file is retained",
            "dry-run leaves manifest and patch file untouched",
            "parent-escape patch path is never deleted",
            "workflow exact pin removes manifest entry and patch file",
            "workflow dry-run preserves manifest entry and patch file",
        ],
        failure_modes_known: &[
            "permission denied while rewriting package.json",
            "permission denied while deleting a patch file",
            "concurrent patch-remove invocations on the same package.json",
            "workspace member patch-remove routed from a non-root cwd",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("crates/lpm-cli/src/commands/patch.rs", 5),
            ("tests/workflows/tests/patch.rs", 2),
        ],
        last_audited_at: "2026-05-29",
    },
    // ── id 143: lpm sbom ──
    SurfaceV2 {
        id: 143,
        scenarios: 6,
        failure_modes_tested: &[
            "CycloneDX output includes lockfile dependency graph",
            "CycloneDX output includes local package metadata",
            "CycloneDX output includes patch metadata",
            "SPDX output includes dependency relationships",
            "--output writes the SBOM to a file without stdout JSON",
            "scoped npm package names render valid purls",
        ],
        failure_modes_known: &[
            "missing lpm.lock error",
            "registry metadata fetch failure under --registry-metadata",
            "provenance attestation verification rejection under --registry-metadata",
            "duplicate name/version packages from distinct sources in one lockfile",
            "permission denied writing --output file",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[
            ("crates/lpm-cli/src/commands/sbom.rs", 3),
            ("tests/workflows/tests/sbom.rs", 3),
        ],
        last_audited_at: "2026-05-29",
    },
    // ── id 144: lpm proxy status / list / start / stop ──
    SurfaceV2 {
        id: 144,
        scenarios: 70,
        failure_modes_tested: &[
            "status/list JSON reports absent daemon with clean stderr",
            "status human reports absent daemon on stderr with empty stdout",
            "stop JSON reports not-stopped when daemon is absent",
            "start --detach starts a background control daemon",
            "start --detach JSON reports running daemon with clean stderr",
            "install/uninstall dry-run reports persistent service plan with clean stdout/stderr",
            "install rejects privileged ports for user-scoped Unix services",
            "uninstall rejects listener flags",
            "service install renders launchd/systemd/Windows launcher definitions from resolved listener args",
            "foreground control daemon start/status/stop round-trip",
            "plain HTTP listener routes registered host and forwards method/path/body",
            "HTTPS listener routes registered host with project certificate",
            "HTTP redirect listener redirects registered host without open redirect fallback",
            "route registry rejects duplicate/conflicting hosts and prunes dead owners",
            "line-JSON control protocol round-trips register/status/release requests",
            "Unix socket daemon register/list/stop lifecycle",
            "daemon IPC rejects cross-lease duplicate host registration",
            "Windows named-pipe name normalization and ACL construction",
            "IPC disconnect-backed lease cleanup",
            "daemon-side cert mint/refresh from route registration",
            "WebSocket/HMR upgrade bytes tunnel through the proxy",
            "low-port permission-denied bind errors include elevation/high-port hint",
            "lpm dev auto-starts a detached HTTPS proxy daemon when local-domain config needs one",
            "lpm dev refuses a control-only daemon before route registration",
            "lpm dev releases proxy route lease when the service exits",
            "lpm dev writes/removes managed hosts-file block for non-localhost host",
            "lpm dev aborts non-interactive non-localhost host without hosts-file consent",
            "two concurrent lpm dev projects share one proxy daemon/TLS listener",
            "two concurrent lpm dev projects reject duplicate host registration through the shared daemon",
        ],
        failure_modes_known: &[
            "Windows named-pipe runtime behavior on Windows CI",
            "privileged default 443/80 binding with elevation helper",
            "live launchd/systemd/Scheduled-Task install/uninstall runtime behavior",
        ],
        json_contract_depth: JsonContractDepth::SemanticAsserts,
        scenarios_by_file: &[
            ("crates/lpm-proxy/src/lib.rs", 38),
            ("crates/lpm-cli/src/commands/proxy.rs", 11),
            ("crates/lpm-cli/tests/proxy_status_contract.rs", 14),
            ("tests/workflows/tests/local_domains.rs", 7),
        ],
        last_audited_at: "2026-06-01",
    },
    // ── id 145: lpm hosts clean ──
    SurfaceV2 {
        id: 145,
        scenarios: 13,
        failure_modes_tested: &[
            "removes multiple LPM-managed hosts-file blocks while preserving unmanaged lines",
            "writes a first-use hosts backup before cleanup",
            "requires `--yes` for non-interactive mutation",
            "leaves the hosts file unchanged when consent is missing",
            "rejects malformed unterminated LPM-managed blocks",
            "privileged helper path mutates the target hosts file without creating a root-owned backup",
            "privileged helper path removes one managed block without creating a root-owned backup",
            "privileged helper path cleans all managed blocks without creating a root-owned backup",
            "internal hosts-file helper rejects invalid block ids",
            "internal hosts-file helper rejects hosts with whitespace",
            "internal hosts-file helper rejects hosts with path separators",
            "privileged helper re-exec argument vector preserves the hidden helper contract",
            "Windows elevated helper argument quoting preserves spaces, quotes, and trailing backslashes",
        ],
        failure_modes_known: &[
            "live privileged /etc/hosts cleanup on Unix with sudo prompt",
            "real Windows hosts cleanup through Administrator/UAC path",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[
            ("crates/lpm-runner/src/local_domains.rs", 6),
            ("crates/lpm-cli/src/commands/hosts.rs", 5),
            ("tests/workflows/tests/hosts.rs", 2),
        ],
        last_audited_at: "2026-06-01",
    },
    SurfaceV2 {
        id: 146,
        scenarios: 4,
        failure_modes_tested: &[
            "posts npm-compatible payload to stage endpoint",
            "rewrites lpm.dev package name to npm name inside attachment",
            "preserves provenance fields in version payload",
            "blocks implicit latest when npm has a higher stable version",
            "missing npm token fails before upload",
        ],
        failure_modes_known: &[
            "Sigstore signing failure under --provenance",
            "package metadata 404 for missing npm package",
            "published duplicate version rejected before upload",
            "prerelease without explicit tag rejected before upload",
            "stage publish network timeout after metadata succeeds",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/stage.rs", 4)],
        last_audited_at: "2026-06-04",
    },
    SurfaceV2 {
        id: 147,
        scenarios: 1,
        failure_modes_tested: &["dry-run performs no npm registry requests"],
        failure_modes_known: &[
            "dry-run with --provenance avoids Sigstore network",
            "dry-run reports quality gate failure under JSON",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/stage.rs", 1)],
        last_audited_at: "2026-06-04",
    },
    SurfaceV2 {
        id: 148,
        scenarios: 3,
        failure_modes_tested: &[
            "filtered list returns JSON envelope",
            "list fetches second page when first page is full",
            "global --registry is rejected in favor of --npm-registry",
        ],
        failure_modes_known: &[
            "version/range package filter rejected",
            "empty list renders stable human output",
            "registry returns malformed pagination response",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/stage.rs", 3)],
        last_audited_at: "2026-06-04",
    },
    SurfaceV2 {
        id: 149,
        scenarios: 1,
        failure_modes_tested: &["stage view returns JSON envelope for a valid UUID"],
        failure_modes_known: &[
            "invalid stage UUID rejected before network",
            "registry 404 for stage id",
            "registry returns malformed stage detail",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/stage.rs", 1)],
        last_audited_at: "2026-06-04",
    },
    SurfaceV2 {
        id: 150,
        scenarios: 1,
        failure_modes_tested: &["approve sends supplied OTP to approve endpoint"],
        failure_modes_known: &[
            "web-auth challenge retry path",
            "invalid stage UUID rejected before network",
            "registry rejects OTP",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/stage.rs", 1)],
        last_audited_at: "2026-06-04",
    },
    SurfaceV2 {
        id: 151,
        scenarios: 1,
        failure_modes_tested: &["reject sends supplied OTP to delete endpoint"],
        failure_modes_known: &[
            "web-auth challenge retry path",
            "invalid stage UUID rejected before network",
            "registry rejects OTP",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/stage.rs", 1)],
        last_audited_at: "2026-06-04",
    },
    SurfaceV2 {
        id: 152,
        scenarios: 1,
        failure_modes_tested: &[
            "download writes tarball using manifest-derived filename and JSON envelope",
        ],
        failure_modes_known: &[
            "invalid stage UUID rejected before network",
            "registry returns invalid tarball bytes",
            "output filename collision with existing file",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/stage.rs", 1)],
        last_audited_at: "2026-06-04",
    },
    SurfaceV2 {
        id: 153,
        scenarios: 6,
        failure_modes_tested: &[
            "lockfile-only fetch works without package.json",
            "fetch does not link node_modules or rewrite lpm.lock",
            "fetch-warmed store enables offline frozen install",
            "store cache hit avoids repeated tarball download",
            "missing integrity hard-errors before store write",
            "integrity mismatch hard-errors before store write",
            "platform option skips incompatible lockfile entries",
            "JSON envelope reports lockfile fetch counts",
        ],
        failure_modes_known: &[
            "remote tarball source fetch path",
            "git source surfaced as unsupported lockfile fetch input",
            "v2 object cache hit verified under default store layout",
            "parallel fetch cancellation after one package fails",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/fetch.rs", 6)],
        last_audited_at: "2026-06-13",
    },
    SurfaceV2 {
        id: 154,
        scenarios: 5,
        failure_modes_tested: &[
            "report-only tidy exits 1 on unused dependency and phantom import findings",
            "report-only tidy leaves package.json unchanged",
            "script-used dev dependency is not reported unused",
            "JSON envelope reports unused and phantom findings",
            "tidy --fix removes unused dependencies and reconciles lpm.lock/node_modules",
            "tidy --fix reports peerDependencies without removing them",
            "lpm.toml [tidy] ignore-unused and ignore-phantom suppress configured findings",
        ],
        failure_modes_known: &[
            "workspace-recursive tidy target selection",
            "invalid [tidy] ignore glob diagnostics",
            "rollback after install failure restores lpm.lock/lpm.lockb snapshots",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/tidy.rs", 5)],
        last_audited_at: "2026-06-13",
    },
    SurfaceV2 {
        id: 155,
        scenarios: 1,
        failure_modes_tested: &[
            "configured extension appears with command, mode, on-error, timeout, and events",
            "JSON envelope is snapshot-pinned",
        ],
        failure_modes_known: &[
            "disabled extension is omitted from active list",
            "invalid policy config surfaces as command error",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/policy_extensions.rs", 1)],
        last_audited_at: "2026-06-28",
    },
    SurfaceV2 {
        id: 156,
        scenarios: 1,
        failure_modes_tested: &[
            "configured extension contributes enabled, report, and enforce counters",
            "JSON envelope is snapshot-pinned",
        ],
        failure_modes_known: &[
            "multiple extensions with mixed modes",
            "report-only warning diagnostics in status output",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/policy_extensions.rs", 1)],
        last_audited_at: "2026-06-28",
    },
    SurfaceV2 {
        id: 157,
        scenarios: 1,
        failure_modes_tested: &[
            "unavailable extension command exits nonzero",
            "JSON diagnostics envelope is snapshot-pinned",
        ],
        failure_modes_known: &[
            "doctor scoped to one extension",
            "invalid extension name diagnostics",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/policy_extensions.rs", 1)],
        last_audited_at: "2026-06-28",
    },
    SurfaceV2 {
        id: 158,
        scenarios: 1,
        failure_modes_tested: &[
            "synthetic package candidate is sent to the named extension",
            "warn decisions are returned in the JSON envelope",
            "JSON envelope is snapshot-pinned",
        ],
        failure_modes_known: &[
            "missing --package validation",
            "extension block decision exit semantics",
        ],
        json_contract_depth: JsonContractDepth::InstaSnapshot,
        scenarios_by_file: &[("tests/workflows/tests/policy_extensions.rs", 1)],
        last_audited_at: "2026-06-28",
    },
];

// ─── Cross-command flow inventory ─────────────────────────────────────
//
// Every entry below describes a real-user multi-command sequence.
// `tested: false` flags a gap that a single-command test cannot catch.

pub const CROSS_COMMAND_FLOWS: &[CrossCommandFlow] = &[
    CrossCommandFlow {
        name: "migrate → install → audit",
        commands: &["lpm migrate npm", "lpm install", "lpm audit"],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "migration produces a lockfile that audit can read; behavioral analysis fires on \
                  installed packages, not on a synthesized lockfile-only inventory.",
    },
    CrossCommandFlow {
        name: "install → patch → install (patch persistence)",
        commands: &[
            "lpm install",
            "lpm patch <key>",
            "lpm patch-commit <dir>",
            "lpm install",
        ],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "second install must re-apply the patch from disk + invalidate the original \
                  store integrity in favor of the patched binding.",
    },
    CrossCommandFlow {
        name: "add → install → graph (cross-member dep visible)",
        commands: &[
            "lpm add @scope/pkg --filter member-a",
            "lpm install",
            "lpm graph --filter member-a",
        ],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "graph sees the freshly added dep without a manual lockfile refresh; \
                  filter resolves the just-added member correctly.",
    },
    CrossCommandFlow {
        name: "install → upgrade --major → audit (re-audit upgraded version)",
        commands: &["lpm install", "lpm upgrade --major", "lpm audit"],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "audit refreshes vuln data against the new major version, not the cached \
                  pre-upgrade response.",
    },
    CrossCommandFlow {
        name: "token-rotate → publish (new token authenticates)",
        commands: &["lpm token-rotate", "lpm publish --dry-run --check"],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "rotation invalidates the previously-stored bearer; the next publish call \
                  picks up the new token from the same storage path.",
    },
    CrossCommandFlow {
        name: "install → rebuild → approve-scripts → rebuild (approval lifecycle)",
        commands: &[
            "lpm install",
            "lpm rebuild",
            "lpm approve-scripts --yes",
            "lpm rebuild",
        ],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "first rebuild reports the blocked set; approve-scripts unblocks; second \
                  rebuild actually executes the previously-blocked scripts.",
    },
    CrossCommandFlow {
        name: "env push → env pull on a different machine (round-trip)",
        commands: &[
            "lpm env push --env=staging",
            // (different machine / fresh HOME)
            "lpm env pair <code>",
            "lpm env pull --env=staging",
            "lpm env get API_KEY --reveal",
        ],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "round-trip encryption: the pulled value matches the pushed value byte-for-byte \
                  after device-key wrap/unwrap.",
    },
    CrossCommandFlow {
        name: "install -g <pkg> → run shimmed binary → uninstall -g",
        commands: &[
            "lpm install -g some-cli",
            "some-cli --version",
            "lpm uninstall -g some-cli",
        ],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "shim repair + PATH integration end-to-end. The cli-binary survivor probes the \
                  shim creation; this flow probes the user-visible PATH consequence.",
    },
    CrossCommandFlow {
        name: "publish --dry-run --check → publish (real)",
        commands: &["lpm publish --dry-run --check", "lpm publish"],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "every concern --check surfaces (quality, OIDC eligibility, registry routing) \
                  must match what the real publish actually does — no surprise on the second run.",
    },
    CrossCommandFlow {
        name: "doctor --fix → install (post-fix install succeeds)",
        commands: &["lpm doctor --fix --yes", "lpm install"],
        tested: true,
        test_file: Some("tests/workflows/tests/cross_command_flows.rs"),
        catches: "the fixes doctor applied actually produce a healthy state for install; \
                  install does not re-trigger the same fixable issues.",
    },
];
