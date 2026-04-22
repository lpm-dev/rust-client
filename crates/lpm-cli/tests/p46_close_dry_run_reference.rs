//! Phase 46 close-out Chunk 3 — reference-fixture integration tests
//! for `lpm approve-builds --dry-run`.
//!
//! The contract (from the Chunk 3 signoff + §11 P9 close-out scope):
//!
//! > Preview decisions without mutating state. In project mode,
//! > `package.json`'s `trustedDependencies` stays untouched. In
//! > global mode, `~/.lpm/global/trusted-dependencies.json` stays
//! > untouched. The review flow runs normally; only the write step
//! > is skipped. JSON envelopes carry `"dry_run": true`.
//!
//! The tests here exercise both project and global mutation surfaces
//! end-to-end through subprocess invocation of `lpm-rs`. The contract
//! at each mutation site is **byte-equality of the would-be-mutated
//! file before and after the command**, PLUS `"dry_run": true` on
//! the JSON envelope — a pre-fix binary (without Chunk 3's
//! short-circuits) fails these.
//!
//! ## Why subprocess and not direct library calls
//!
//! Same rationale as the P6/P7 reference fixtures: real
//! stdout/stderr separation, real CLI-to-`run_global` dispatch
//! through `main.rs`, real env isolation via `LPM_HOME`. Critically,
//! the byte-equal assertion MUST observe what `run_global`'s
//! atomic-write path produces on disk; a direct library call
//! bypasses the whole-binary contract.
//!
//! ## Coverage map (per signoff)
//!
//! - Project `--yes --dry-run --json`: `package.json` byte-equal,
//!   JSON has `"dry_run": true`.
//! - Project `<pkg> --dry-run --json`: `package.json` byte-equal,
//!   JSON has `"dry_run": true`.
//! - Project `--list --dry-run`: accepted silently, no mutation.
//! - Global `--yes --global --dry-run --json`:
//!   `trusted-dependencies.json` byte-equal (or absent before AND
//!   after), JSON has `"dry_run": true`.
//! - Global `<pkg> --global --dry-run --json`: same.
//!
//! The interactive walks (both project and global) are not
//! subprocess-testable without a TTY; their dry-run short-circuit
//! is pinned by source-level audit in the Chunk 3 patch plus the
//! unit-level tests of the project-mode `run`'s `--yes` path
//! (existing `approve_builds_yes_*` tests).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Harness (mirrors P6/P7 shape; duplicated intentionally — see
//    P6 fixture's commentary on why per-file harness duplication is
//    the established pattern) ─────────────────────────────────────

fn run_lpm(cwd: &Path, home: &Path, args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let output = Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .env("LPM_HOME", home.join(".lpm"))
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn lpm-rs");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stdout, stderr)
}

// ── Project-mode fixture helpers ────────────────────────────────

/// Write a project `package.json` with no `trustedDependencies`.
/// First-time review scenario: the approver has no prior bindings,
/// so the diff surface is empty and `approve-builds` is purely
/// mutating (pre-fix) or purely previewing (post-fix).
fn write_project_package_json(project: &Path) {
    fs::write(
        project.join("package.json"),
        r#"{
    "name": "p46-close-dryrun-fixture",
    "version": "0.0.1"
}
"#,
    )
    .unwrap();
}

/// Synthesize `<project>/.lpm/build-state.json` with one blocked
/// entry. Enough to drive `lpm approve-builds` through the
/// mutation path; the specific fields match the post-P7 shape.
fn write_blocked_build_state(project: &Path, name: &str, version: &str) {
    fs::create_dir_all(project.join(".lpm")).unwrap();
    let body = format!(
        r#"{{
    "state_version": 1,
    "blocked_set_fingerprint": "sha256-fixture-stable",
    "captured_at": "2026-04-22T00:00:00Z",
    "blocked_packages": [
        {{
            "name": "{name}",
            "version": "{version}",
            "integrity": "sha512-fixture-skip-verify",
            "script_hash": "sha256-fixture-script-hash",
            "phases_present": ["postinstall"],
            "binding_drift": false,
            "static_tier": "green",
            "published_at": "2026-04-22T00:00:00Z"
        }}
    ]
}}"#
    );
    fs::write(project.join(".lpm").join("build-state.json"), body).unwrap();
}

// ── Global-mode fixture helpers ─────────────────────────────────

/// Write a minimal `<home>/.lpm/global/manifest.toml` with one
/// globally-installed top-level package. Matches the on-disk shape
/// produced by `lpm_global::write_for`.
fn write_global_manifest(home: &Path, top_level: &str, top_level_version: &str) {
    let global_root = home.join(".lpm").join("global");
    fs::create_dir_all(&global_root).unwrap();
    let toml = format!(
        r#"schema_version = 1

[packages.{top_level}]
saved_spec = "^1"
resolved = "{top_level_version}"
integrity = "sha512-fixture-top-level"
source = "upstream-npm"
installed_at = "2026-04-22T00:00:00Z"
root = "installs/{top_level}@{top_level_version}"
commands = []
"#
    );
    fs::write(global_root.join("manifest.toml"), toml).unwrap();
}

/// Seed a per-install `build-state.json` under the global install
/// root, with one blocked package. The aggregator reads this to
/// populate the global blocked set that `approve-builds --global`
/// iterates over.
fn write_global_install_blocked_state(
    home: &Path,
    top_level: &str,
    top_level_version: &str,
    blocked_name: &str,
    blocked_version: &str,
) {
    let install_lpm = home
        .join(".lpm")
        .join("global")
        .join("installs")
        .join(format!("{top_level}@{top_level_version}"))
        .join(".lpm");
    fs::create_dir_all(&install_lpm).unwrap();
    let body = format!(
        r#"{{
    "state_version": 1,
    "blocked_set_fingerprint": "sha256-fixture-stable",
    "captured_at": "2026-04-22T00:00:00Z",
    "blocked_packages": [
        {{
            "name": "{blocked_name}",
            "version": "{blocked_version}",
            "integrity": "sha512-fixture-skip-verify",
            "script_hash": "sha256-fixture-script-hash",
            "phases_present": ["postinstall"],
            "binding_drift": false,
            "static_tier": "green"
        }}
    ]
}}"#
    );
    fs::write(install_lpm.join("build-state.json"), body).unwrap();
}

/// Path to the global trust file. Absence before the test is the
/// baseline; the byte-equal contract asserts it's still absent
/// after a dry-run invocation (or still carries the pre-seeded
/// contents if we chose to seed one).
fn global_trust_path(home: &Path) -> PathBuf {
    home.join(".lpm")
        .join("global")
        .join("trusted-dependencies.json")
}

struct Fixture {
    _tmpdir: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmpdir = tempfile::tempdir().unwrap();
        let home = tmpdir.path().to_path_buf();
        let project = home.join("project");
        fs::create_dir_all(&project).unwrap();
        Fixture {
            _tmpdir: tmpdir,
            home,
            project,
        }
    }
}

// ── Project-mode tests ─────────────────────────────────────────

/// Ship criterion — project `--yes --dry-run --json`: the bulk path
/// must not mutate `package.json`, and the JSON envelope must carry
/// `"dry_run": true` so agents can detect the mode. Pre-fix, the
/// `write_back` call at `approve_builds.rs:368` fires
/// unconditionally; this test fails on a pre-fix binary.
#[test]
fn p46_close_chunk3_project_yes_dry_run_does_not_mutate_package_json_and_json_carries_flag() {
    let fx = Fixture::new();
    write_project_package_json(&fx.project);
    write_blocked_build_state(&fx.project, "some-blocked-pkg", "1.0.0");

    let pkg_json_path = fx.project.join("package.json");
    let before = fs::read(&pkg_json_path).unwrap();

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-builds", "--yes", "--dry-run"],
    );

    assert!(
        status.success(),
        "--yes --dry-run --json must exit 0. stdout={stdout}"
    );

    let after = fs::read(&pkg_json_path).unwrap();
    assert_eq!(
        before, after,
        "package.json must be byte-equal before and after --yes --dry-run — \
         pre-fix, the write_back call at approve_builds.rs:368 mutates \
         the manifest"
    );

    // JSON envelope must surface the dry-run mode so agents can
    // distinguish preview from live-write.
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid JSON on stdout");
    assert_eq!(
        parsed["dry_run"].as_bool(),
        Some(true),
        "JSON envelope must carry `dry_run: true` under --dry-run. envelope={parsed}"
    );
    assert_eq!(
        parsed["approved_count"].as_u64(),
        Some(1),
        "the would-approve count matches the blocked set — pre-fix and \
         post-fix must agree on this number; only mutation differs"
    );
    // The `--yes` warning message must clearly indicate this is a
    // preview, not a live bulk-approve. Agents parsing warnings
    // rely on the text shape.
    let warnings = parsed["warnings"].as_array().expect("warnings array");
    let first_msg = warnings
        .first()
        .and_then(|w| w.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        first_msg.contains("DRY RUN"),
        "--yes warning must reframe as DRY RUN under --dry-run. \
         warning={first_msg}"
    );
}

/// Ship criterion — project `<pkg> --dry-run --json`: the direct-
/// approve path must not mutate `package.json`. Pre-fix, the
/// `write_back` call at `approve_builds.rs:289` fires after the
/// user confirms (or under --json, auto-confirms).
#[test]
fn p46_close_chunk3_project_named_dry_run_does_not_mutate_package_json() {
    let fx = Fixture::new();
    write_project_package_json(&fx.project);
    write_blocked_build_state(&fx.project, "some-blocked-pkg", "1.0.0");

    let pkg_json_path = fx.project.join("package.json");
    let before = fs::read(&pkg_json_path).unwrap();

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-builds", "some-blocked-pkg", "--dry-run"],
    );

    assert!(status.success(), "exit 0 expected. stdout={stdout}");

    let after = fs::read(&pkg_json_path).unwrap();
    assert_eq!(
        before, after,
        "package.json must be byte-equal before and after <pkg> --dry-run"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["dry_run"].as_bool(), Some(true));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));
}

/// Compatibility — project `--list --dry-run`: silent no-op.
/// `--list` is already read-only, and the signoff says `--dry-run`
/// on top of it is a no-op (accept silently). This pins that
/// `--list --dry-run` doesn't error and doesn't mutate.
#[test]
fn p46_close_chunk3_project_list_dry_run_is_silent_no_op() {
    let fx = Fixture::new();
    write_project_package_json(&fx.project);
    write_blocked_build_state(&fx.project, "some-blocked-pkg", "1.0.0");

    let pkg_json_path = fx.project.join("package.json");
    let before = fs::read(&pkg_json_path).unwrap();

    // Plain `--list --json` without `--dry-run`: the envelope must
    // carry `"dry_run": false` as the regression baseline for the
    // universal contract below.
    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-builds", "--list"],
    );
    assert!(status.success(), "plain --list --json must succeed");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        parsed["dry_run"].as_bool(),
        Some(false),
        "plain --list --json must carry `dry_run: false` for schema uniformity — \
         agents read `envelope.dry_run` without branching on mode. envelope={parsed}"
    );

    // Same path with `--dry-run`: envelope flips to `true`; no
    // mutation. Upgraded from a basic exit-code-only assertion
    // to prove the universal dry_run contract holds on read-only
    // paths too.
    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-builds", "--list", "--dry-run"],
    );
    assert!(
        status.success(),
        "--list --dry-run --json must succeed (dry-run is a no-op on an \
         already-read-only command, but the envelope still reflects the mode)"
    );
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        parsed["dry_run"].as_bool(),
        Some(true),
        "--list --dry-run --json envelope must carry `dry_run: true` — \
         the help text (main.rs) + the command-level doc comments \
         (approve_builds.rs) promise agents can detect dry-run \
         uniformly; this assertion is the enforcement. envelope={parsed}"
    );

    let after = fs::read(&pkg_json_path).unwrap();
    assert_eq!(before, after, "`--list` never mutates, dry-run or not");
}

/// Empty-blocked-set envelope carries `dry_run` too. The
/// `effective_state.blocked_packages.is_empty()` branch in
/// [`run`] emits its own short-circuit envelope; this test pins
/// that it conforms to the universal dry_run schema.
#[test]
fn p46_close_chunk3_project_empty_blocked_set_json_carries_dry_run_flag() {
    let fx = Fixture::new();
    write_project_package_json(&fx.project);
    // Write a build-state with an empty blocked_packages array to
    // reach the short-circuit branch.
    fs::create_dir_all(fx.project.join(".lpm")).unwrap();
    fs::write(
        fx.project.join(".lpm").join("build-state.json"),
        r#"{
    "state_version": 1,
    "blocked_set_fingerprint": "sha256-empty",
    "captured_at": "2026-04-22T00:00:00Z",
    "blocked_packages": []
}"#,
    )
    .unwrap();

    // Two invocations: dry-run off and on. Both exit 0 with a
    // "nothing to approve" JSON envelope; only the dry_run field
    // differs.
    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-builds", "--yes"],
    );
    assert!(status.success());
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["blocked_count"].as_u64(), Some(0));
    assert_eq!(parsed["dry_run"].as_bool(), Some(false));

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-builds", "--yes", "--dry-run"],
    );
    assert!(status.success());
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["blocked_count"].as_u64(), Some(0));
    assert_eq!(
        parsed["dry_run"].as_bool(),
        Some(true),
        "empty-set envelope must carry dry_run: true too — the short-\
         circuit at approve_builds.rs emits its own inline envelope \
         separate from print_summary; both must conform to the \
         universal contract. envelope={parsed}"
    );
}

// ── Global-mode tests ──────────────────────────────────────────

/// Ship criterion — global `--yes --global --dry-run --json`: the
/// aggregate-bulk path must not mutate
/// `~/.lpm/global/trusted-dependencies.json`. Pre-fix, the
/// `lpm_global::trusted_deps::write_for` call inside
/// `run_global_bulk_yes` fires unconditionally. This test fails on
/// a pre-fix binary.
#[test]
fn p46_close_chunk3_global_yes_dry_run_does_not_mutate_trust_file_and_json_carries_flag() {
    let fx = Fixture::new();
    write_global_manifest(&fx.home, "some-top-level", "1.0.0");
    write_global_install_blocked_state(
        &fx.home,
        "some-top-level",
        "1.0.0",
        "some-blocked-pkg",
        "2.0.0",
    );

    let trust_path = global_trust_path(&fx.home);
    // The trust file is absent in the fresh-fixture state —
    // `lpm_global::trusted_deps::read_for` returns default under
    // missing-file (§ trusted_deps.rs read_at). Under `--dry-run`
    // the write is skipped, so the file MUST stay absent.
    assert!(
        !trust_path.exists(),
        "pre-condition: trust file must not exist before the test"
    );

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-builds", "--global", "--yes", "--dry-run"],
    );

    assert!(
        status.success(),
        "--yes --global --dry-run --json must exit 0. stdout={stdout}"
    );

    assert!(
        !trust_path.exists(),
        "trusted-dependencies.json must stay absent under --dry-run — \
         pre-fix, `write_for` in run_global_bulk_yes creates the file"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid JSON on stdout");
    assert_eq!(
        parsed["dry_run"].as_bool(),
        Some(true),
        "global envelope must carry `dry_run: true` too"
    );
    assert_eq!(parsed["scope"].as_str(), Some("global"));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));
    let warnings = parsed["warnings"].as_array().expect("warnings array");
    assert!(
        warnings
            .first()
            .and_then(|w| w.as_str())
            .map(|s| s.contains("DRY RUN"))
            .unwrap_or(false),
        "global --yes warning must reframe as DRY RUN. warnings={warnings:?}"
    );
}

/// Ship criterion — global `<pkg> --global --dry-run --json`: the
/// named-approve path must not mutate the global trust file.
/// Pre-fix, the `write_for` call in `run_global_named` fires
/// unconditionally.
#[test]
fn p46_close_chunk3_global_named_dry_run_does_not_mutate_trust_file() {
    let fx = Fixture::new();
    write_global_manifest(&fx.home, "some-top-level", "1.0.0");
    write_global_install_blocked_state(
        &fx.home,
        "some-top-level",
        "1.0.0",
        "some-blocked-pkg",
        "2.0.0",
    );

    let trust_path = global_trust_path(&fx.home);
    assert!(
        !trust_path.exists(),
        "pre-condition: trust file absent on fresh fixture"
    );

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &[
            "--json",
            "approve-builds",
            "--global",
            "some-blocked-pkg@2.0.0",
            "--dry-run",
        ],
    );

    assert!(status.success(), "exit 0 expected. stdout={stdout}");

    assert!(
        !trust_path.exists(),
        "trusted-dependencies.json must stay absent under --dry-run <pkg> --global"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["dry_run"].as_bool(), Some(true));
    assert_eq!(parsed["scope"].as_str(), Some("global"));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));
    // Sanity: the matched package identity carries through so
    // agents can see which candidate would have been approved.
    let approved = parsed["approved"].as_array().expect("approved array");
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0]["name"].as_str(), Some("some-blocked-pkg"));
    assert_eq!(approved[0]["version"].as_str(), Some("2.0.0"));
}

/// Control — global `<pkg> --global --dry-run` against a pre-seeded
/// trust file: the file must stay byte-equal to its seeded contents,
/// proving the dry-run short-circuit protects existing state as
/// well as the fresh-file case above.
#[test]
fn p46_close_chunk3_global_named_dry_run_preserves_pre_seeded_trust_file_byte_equal() {
    let fx = Fixture::new();
    write_global_manifest(&fx.home, "some-top-level", "1.0.0");
    write_global_install_blocked_state(
        &fx.home,
        "some-top-level",
        "1.0.0",
        "some-blocked-pkg",
        "2.0.0",
    );

    // Pre-seed the trust file with an unrelated entry so byte-equal
    // is a meaningful assertion (mutation would rewrite this).
    let trust_path = global_trust_path(&fx.home);
    let seeded = r#"{
  "schema_version": 1,
  "trusted": {
    "unrelated@9.9.9": {
      "integrity": "sha512-pre-seeded",
      "script_hash": "sha256-pre-seeded"
    }
  }
}
"#;
    fs::write(&trust_path, seeded).unwrap();
    let before = fs::read(&trust_path).unwrap();

    let (status, _stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &[
            "--json",
            "approve-builds",
            "--global",
            "some-blocked-pkg@2.0.0",
            "--dry-run",
        ],
    );

    assert!(status.success(), "exit 0 expected");

    let after = fs::read(&trust_path).unwrap();
    assert_eq!(
        before, after,
        "pre-seeded trusted-dependencies.json must be byte-equal under \
         --dry-run — pre-fix, `write_for` rewrites it with the new binding"
    );
}

/// Universal-contract enforcement for the global `--list --json`
/// envelope: `print_global_list` emits `dry_run` uniformly so
/// agents can read the flag without branching on which approve-
/// builds subcommand produced the output. Mirrors the project-
/// side assertion in the project `--list` test above.
#[test]
fn p46_close_chunk3_global_list_json_carries_dry_run_flag_on_both_axes() {
    let fx = Fixture::new();
    write_global_manifest(&fx.home, "some-top-level", "1.0.0");
    write_global_install_blocked_state(
        &fx.home,
        "some-top-level",
        "1.0.0",
        "some-blocked-pkg",
        "2.0.0",
    );

    // Plain `--list --global --json`: dry_run: false baseline.
    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-builds", "--global", "--list"],
    );
    assert!(status.success());
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["scope"].as_str(), Some("global"));
    assert_eq!(
        parsed["dry_run"].as_bool(),
        Some(false),
        "plain `--list --global --json` must carry `dry_run: false` \
         for schema uniformity. envelope={parsed}"
    );

    // `--dry-run` on top: flag flips to true.
    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &[
            "--json",
            "approve-builds",
            "--global",
            "--list",
            "--dry-run",
        ],
    );
    assert!(status.success());
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["scope"].as_str(), Some("global"));
    assert_eq!(
        parsed["dry_run"].as_bool(),
        Some(true),
        "`--list --global --dry-run --json` envelope must carry \
         `dry_run: true`. envelope={parsed}"
    );
}
