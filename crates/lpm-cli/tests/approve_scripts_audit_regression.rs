//! **Phase 32 Phase 4 audit regressions — CLI-level (subprocess-driven).**
//!
//! These tests spawn the actual `lpm-rs` binary as a child process and
//! drive `approve-scripts` end-to-end against on-disk fixtures. They are
//! the regression suite for the three findings in the Phase 4 audit:
//!
//! - **D-impl-1**: legacy `["esbuild"]` → after `approve-scripts --yes` and
//!   another install, esbuild MUST still be honored (not re-blocked).
//! - **D-impl-2**: `approve-scripts --list` MUST filter persisted state
//!   against current trust — already-approved entries are not in the output.
//! - **D-impl-3**: `approve-scripts --yes --json` MUST emit exactly one
//!   valid JSON object on stdout (no warning lines on stdout).
//!
//! The unit-level tests in `commands::approve_scripts::tests::*` cover the
//! behavior at the function-call level. These tests are the CLI-level gate:
//! they verify the END-TO-END contract that agents and `JSON.parse` rely on,
//! using the actual binary build with the actual tracing subscriber, the
//! actual stdout/stderr separation, and the actual command-line parser.
//!
//! Cargo automatically sets `CARGO_BIN_EXE_lpm-rs` for binary integration
//! tests, so the binary is always built+available before these tests run.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Spawn the lpm-rs binary in `cwd` with the given args. Returns
/// (status, stdout, stderr) — always captures both streams.
fn run_lpm(cwd: &Path, args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let output = Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .env("HOME", cwd) // isolate from real ~/.lpm
        .env("NO_COLOR", "1") // no ANSI escapes in stdout/stderr
        // Disable update check + telemetry that could pollute output
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        // Disable any tracing override the host environment may have set
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn lpm-rs");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stdout, stderr)
}

/// Strip ANSI escapes from a captured stream so assertions are stable
/// even when `NO_COLOR=1` doesn't reach every code path.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            // ANSI CSI sequence: ESC [ ... <final byte 0x40-0x7e>
            i += 2;
            while i < bytes.len() {
                let b = bytes[i];
                i += 1;
                if (0x40..=0x7e).contains(&b) {
                    break;
                }
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Build a synthetic project at `dir` with the given package.json content.
fn write_project(dir: &Path, package_json: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("package.json"), package_json).unwrap();
}

/// Write a `.lpm/build-state.json` containing the given blocked entries.
/// Each entry is `(name, version, integrity, script_hash)`.
fn write_build_state(dir: &Path, entries: &[(&str, &str, &str, &str)]) {
    let lpm_dir = dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    let blocked: Vec<serde_json::Value> = entries
        .iter()
        .map(|(name, version, integrity, script_hash)| {
            serde_json::json!({
                "name": name,
                "version": version,
                "integrity": integrity,
                "script_hash": script_hash,
                "phases_present": ["postinstall"],
                "binding_drift": false
            })
        })
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "blocked_set_fingerprint": "sha256-cli-test",
        "captured_at": "2026-04-11T00:00:00Z",
        "blocked_packages": blocked,
    });
    std::fs::write(
        lpm_dir.join("build-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

fn read_manifest(dir: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(dir.join("package.json")).unwrap()).unwrap()
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-cli-audit-regression")
        .join(format!("{name}.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── D-impl-1 — legacy `@*` preserve key honored after upgrade ──

/// **Phase 4 audit Finding 1 (D-impl-1) — CLI level.**
///
/// Reproduces the audit's end-to-end repro:
///   1. Start with `trustedDependencies: ["esbuild"]`
///   2. Persist a build-state with `sharp` blocked (esbuild not in state)
///   3. Run `approve-scripts --yes` — sharp gets approved, esbuild becomes `@*`
///   4. Persist a NEW build-state with esbuild blocked too
///   5. Run `approve-scripts --list --json`
///
/// Pre-fix step 5 returned esbuild in the blocked array because the `@*`
/// preserve key never satisfied `matches_strict`. Post-fix it's filtered
/// out via the LegacyNameOnly path.
#[test]
fn cli_legacy_array_upgrade_preserves_esbuild_after_subsequent_install() {
    let dir = project_dir("d-impl-1-cli");
    write_project(
        &dir,
        r#"{
  "name": "d-impl-1-cli",
  "version": "0.0.0",
  "lpm": { "trustedDependencies": ["esbuild"] }
}"#,
    );
    write_build_state(
        &dir,
        &[("sharp", "0.32.1", "sha512-sharp-int", "sha256-sharp-h")],
    );

    // Step 1: --yes approves sharp, upgrades esbuild to @*
    let (status, _stdout, _stderr) = run_lpm(&dir, &["approve-scripts", "--yes"]);
    assert!(status.success(), "first approve-scripts --yes must succeed");

    let manifest = read_manifest(&dir);
    let td = &manifest["lpm"]["trustedDependencies"];
    assert!(td.is_object(), "must be Rich form after upgrade");
    let map = td.as_object().unwrap();
    assert!(
        map.contains_key("esbuild@*"),
        "esbuild must be preserved as the @* sentinel"
    );
    assert!(
        map.contains_key("sharp@0.32.1"),
        "sharp must be in the rich form"
    );

    // Step 2: simulate a new install that captures esbuild as blocked.
    write_build_state(
        &dir,
        &[
            (
                "esbuild",
                "0.25.1",
                "sha512-esbuild-int",
                "sha256-esbuild-h",
            ),
            ("sharp", "0.32.1", "sha512-sharp-int", "sha256-sharp-h"),
        ],
    );

    // Step 3: --list --json should show esbuild as NOT blocked (covered
    // by @*) and sharp as NOT blocked (covered by the rich entry).
    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "approve-scripts", "--list"]);
    assert!(
        status.success(),
        "approve-scripts --list --json failed. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&stdout)).unwrap_or_else(|e| {
            panic!("stdout is not valid JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        });
    assert_eq!(
        parsed["blocked_count"].as_u64(),
        Some(0),
        "post-fix: nothing should be blocked. JSON: {parsed:#?}"
    );
}

// ── D-impl-2 — approve-scripts filters persisted state through current trust ──

/// **Phase 4 audit Finding 2 (D-impl-2) — CLI level.** Reproduces the
/// audit's `--list --json` repro: install captures esbuild as blocked,
/// `approve-scripts --yes` approves it, and the next `approve-scripts --list`
/// (without re-installing) MUST NOT report esbuild as still blocked.
#[test]
fn cli_list_filters_already_approved_packages_after_yes() {
    let dir = project_dir("d-impl-2-list");
    write_project(&dir, r#"{"name": "d-impl-2-list", "version": "0.0.0"}"#);
    write_build_state(
        &dir,
        &[(
            "esbuild",
            "0.25.1",
            "sha512-esbuild-int",
            "sha256-esbuild-h",
        )],
    );

    // Approve esbuild.
    let (status, _, stderr) = run_lpm(&dir, &["approve-scripts", "--yes"]);
    assert!(status.success(), "yes must succeed. stderr={stderr}");

    // Now --list --json — the persisted state still says esbuild is
    // blocked, but the manifest covers it.
    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "approve-scripts", "--list"]);
    assert!(
        status.success(),
        "list --json failed. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&stdout)).expect("stdout must be valid JSON");
    assert_eq!(
        parsed["blocked_count"].as_u64(),
        Some(0),
        "esbuild must be filtered out by current trust. JSON: {parsed:#?}"
    );
    assert_eq!(
        parsed["blocked"].as_array().map(|a| a.len()),
        Some(0),
        "blocked array must be empty"
    );
}

/// **Phase 4 audit Finding 2 (D-impl-2) — CLI level.** When the user
/// explicitly names a package that's already approved, the binary must
/// emit an "already approved" error rather than silently re-approving.
#[test]
fn cli_specific_pkg_arg_for_already_approved_emits_friendly_error() {
    let dir = project_dir("d-impl-2-pkg");
    write_project(
        &dir,
        r#"{
  "name": "d-impl-2-pkg",
  "version": "0.0.0",
  "lpm": {
    "trustedDependencies": {
      "esbuild@0.25.1": {
        "integrity": "sha512-esbuild-int",
        "scriptHash": "sha256-esbuild-h"
      }
    }
  }
}"#,
    );
    write_build_state(
        &dir,
        &[(
            "esbuild",
            "0.25.1",
            "sha512-esbuild-int",
            "sha256-esbuild-h",
        )],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["approve-scripts", "esbuild"]);
    assert!(
        !status.success(),
        "asking to approve an already-approved package must error. stdout={stdout} stderr={stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    let combined_clean = strip_ansi(&combined);
    assert!(
        combined_clean.contains("already approved"),
        "expected an 'already approved' message; combined output:\n{combined_clean}"
    );
}

// ── D-impl-3 — --yes --json emits exactly one valid JSON payload ──

/// **Phase 4 audit Finding 3 (D-impl-3) — CLI level.** This is the most
/// important regression test in this file: the audit reproduced this with
/// a live `cargo run` invocation and `JSON.parse` choked on a WARN line
/// at the start of stdout. The fix routes the global tracing subscriber
/// to stderr. This test asserts the contract end-to-end.
#[test]
fn cli_yes_json_emits_exactly_one_valid_json_payload_on_stdout() {
    let dir = project_dir("d-impl-3-json-purity");
    write_project(
        &dir,
        r#"{"name": "d-impl-3-json-purity", "version": "0.0.0"}"#,
    );
    write_build_state(&dir, &[("esbuild", "0.25.1", "sha512-int", "sha256-h")]);

    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "approve-scripts", "--yes"]);
    assert!(
        status.success(),
        "yes --json must succeed. stdout={stdout} stderr={stderr}"
    );

    // Stdout MUST be exactly one valid JSON object. Strip ANSI just in
    // case NO_COLOR didn't reach the JSON encoder.
    let stdout_clean = strip_ansi(&stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_clean).unwrap_or_else(|e| {
        panic!(
            "stdout is not valid JSON: {e}\n\
             stdout (first 500 chars):\n{}\n\
             stderr (first 500 chars):\n{}",
            stdout_clean.chars().take(500).collect::<String>(),
            stderr.chars().take(500).collect::<String>(),
        )
    });

    // Sanity: the parsed JSON has the expected shape. SCHEMA_VERSION
    // bumped to 2 in Phase 46 P2 Chunk 3 (`static_tier`) and to 3 in
    // Phase 46 P7 Chunk 4 (`version_diff`) — see approve_scripts.rs
    // constants.
    assert_eq!(parsed["schema_version"].as_u64(), Some(3));
    assert_eq!(parsed["command"].as_str(), Some("approve-scripts"));
    assert_eq!(parsed["mode"].as_str(), Some("yes"));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));

    // The structured warning IS in the JSON payload (the triple-emission
    // contract — JSON warnings field is one of the three).
    let warnings = parsed["warnings"]
        .as_array()
        .expect("warnings must be a JSON array");
    assert!(
        warnings
            .iter()
            .any(|w| w["code"].as_str() == Some("yes_blanket_approve")),
        "warnings array must include the yes_blanket_approve entry, got: {warnings:#?}"
    );

    // Stderr MUST contain the WARN line (this is where the tracing
    // subscriber writes after the audit fix).
    let stderr_clean = strip_ansi(&stderr);
    assert!(
        stderr_clean.contains("blanket-approves"),
        "stderr must contain the WARN line; got:\n{stderr_clean}"
    );

    // CRITICAL: stdout must NOT contain the WARN text. This is the
    // exact corruption the audit caught. If a future change re-routes
    // tracing to stdout this assertion fires immediately.
    assert!(
        !stdout_clean.contains("WARN"),
        "stdout must NOT contain the WARN tracing line — that's the audit-caught bug. \
         stdout:\n{stdout_clean}"
    );
    assert!(
        !stdout_clean.contains("blanket-approves"),
        "stdout must NOT contain the warning prose. stdout:\n{stdout_clean}"
    );
}

/// **Phase 4 audit Finding 3 (D-impl-3) — generalized.** The contract is
/// stronger than just `--yes --json`: ANY `--json` invocation must produce
/// exactly one JSON payload on stdout regardless of what tracing emits.
/// This test exercises `--list --json` with state that triggers no
/// warnings AT ALL — the subscriber-to-stdout bug would have shown up
/// here too if a tracing call existed at the empty-blocked-set path.
#[test]
fn cli_list_json_emits_exactly_one_valid_json_payload_on_stdout() {
    let dir = project_dir("d-impl-3-list-purity");
    write_project(&dir, r#"{"name": "list-purity", "version": "0.0.0"}"#);
    write_build_state(&dir, &[("esbuild", "0.25.1", "sha512-i", "sha256-h")]);

    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "approve-scripts", "--list"]);
    assert!(
        status.success(),
        "list --json must succeed. stdout={stdout} stderr={stderr}"
    );
    let stdout_clean = strip_ansi(&stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_clean)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nstdout:\n{stdout_clean}"));
    assert_eq!(parsed["schema_version"].as_u64(), Some(3));
    assert!(!stdout_clean.contains("WARN"));
}

/// **Phase 4 audit Finding 3 (D-impl-3) — error path.** Verify error
/// JSON also lands on stdout cleanly (errors should follow the same
/// contract).
#[test]
fn cli_yes_json_with_no_state_file_emits_clean_error_json_on_stdout() {
    let dir = project_dir("d-impl-3-error-purity");
    write_project(&dir, r#"{"name": "error-purity", "version": "0.0.0"}"#);
    // No state file — error path

    let (status, stdout, _stderr) = run_lpm(&dir, &["--json", "approve-scripts", "--yes"]);
    assert!(
        !status.success(),
        "missing state file must produce a non-zero exit"
    );
    let stdout_clean = strip_ansi(&stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_clean)
        .unwrap_or_else(|e| panic!("error JSON should still parse: {e}\nstdout:\n{stdout_clean}"));
    // The error JSON shape (already in lpm-cli's error path)
    assert_eq!(parsed["success"].as_bool(), Some(false));
}
