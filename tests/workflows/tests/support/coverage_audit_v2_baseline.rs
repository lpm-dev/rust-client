//! Coverage matrix **v2** — depth + scenario metrics.
//!
//! v1 (`coverage_audit_baseline.rs`) tracks binary "does any test exist
//! for this surface" flags. That metric saturated at 97.8% workflow /
//! 70% JSON during the 2026-05-14 coverage push but doesn't reflect:
//!
//! - **Scenario depth.** A surface with 1 trivial test and one with 50
//!   thorough tests get the same v1 flag.
//! - **Failure-mode coverage.** Which of the surface's *known* failure
//!   modes are actually exercised by tests, and which are gaps?
//! - **JSON contract depth.** "Locked via insta snapshot" vs "checked
//!   one field semantically" vs "test calls --json but never reads
//!   the envelope" all flip the same v1 `json_contract: true` bit.
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
    /// Failure modes the test suite actually exercises.
    pub failure_modes_tested: &'static [&'static str],
    /// Failure modes that are known to be relevant for this surface
    /// but are NOT currently tested. Lift these into
    /// `failure_modes_tested` as coverage grows.
    pub failure_modes_known: &'static [&'static str],
    /// How deeply is the `--json` envelope contract pinned?
    pub json_contract_depth: JsonContractDepth,
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
// Pre-populated rows: 8 high-value surfaces, chosen to demonstrate the
// schema across the risk categories from
// `private/test-gaps-strategic-audit.md`. Extend session-by-session.

pub const SURFACES_V2: &[SurfaceV2] = &[
    // ── id 12: lpm install (bare, lockfile fast-path) ──
    SurfaceV2 {
        id: 12,
        scenarios: 50,
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
        tested: false,
        test_file: None,
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
        tested: false,
        test_file: None,
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
        tested: false,
        test_file: None,
        catches: "graph sees the freshly added dep without a manual lockfile refresh; \
                  filter resolves the just-added member correctly.",
    },
    CrossCommandFlow {
        name: "install → upgrade --major → audit (re-audit upgraded version)",
        commands: &["lpm install", "lpm upgrade --major", "lpm audit"],
        tested: false,
        test_file: None,
        catches: "audit refreshes vuln data against the new major version, not the cached \
                  pre-upgrade response.",
    },
    CrossCommandFlow {
        name: "token-rotate → publish (new token authenticates)",
        commands: &["lpm token-rotate", "lpm publish --dry-run --check"],
        tested: false,
        test_file: None,
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
        tested: false,
        test_file: None,
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
        tested: false,
        test_file: None,
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
        tested: false,
        test_file: None,
        catches: "shim repair + PATH integration end-to-end. The cli-binary survivor probes the \
                  shim creation; this flow probes the user-visible PATH consequence.",
    },
    CrossCommandFlow {
        name: "publish --dry-run --check → publish (real)",
        commands: &["lpm publish --dry-run --check", "lpm publish"],
        tested: false,
        test_file: None,
        catches: "every concern --check surfaces (quality, OIDC eligibility, registry routing) \
                  must match what the real publish actually does — no surprise on the second run.",
    },
    CrossCommandFlow {
        name: "doctor --fix → install (post-fix install succeeds)",
        commands: &["lpm doctor --fix --yes", "lpm install"],
        tested: false,
        test_file: None,
        catches: "the fixes doctor applied actually produce a healthy state for install; \
                  install does not re-trigger the same fixable issues.",
    },
];
