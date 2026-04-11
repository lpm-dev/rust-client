//! **Phase 32 Phase 5 — overrides end-to-end regression suite (CLI level).**
//!
//! These tests spawn the actual `lpm-rs` binary as a child process and
//! drive override-related code paths against on-disk fixtures. They
//! are the regression suite for the Phase 5 spec acceptance criteria:
//!
//! - **Fail-closed parsing.** Invalid overrides in `package.json` are
//!   a hard error at install entry, not a silent no-op. The error
//!   message names the offending key and the validation failure.
//! - **`lpm graph --why` decoration.** When an override is applied
//!   during a fresh install, the persisted `.lpm/overrides-state.json`
//!   is loaded by the graph command and the apply trace appears in
//!   both human and JSON output.
//! - **`.lpm/overrides-state.json` lifecycle.** The state file is
//!   created on first install with overrides, deleted when overrides
//!   are removed, and the fingerprint changes when the override set
//!   changes.
//!
//! These mirror the structure of `approve_builds_audit_regression.rs`:
//! a `run_lpm` helper that captures stdout/stderr from a real binary
//! invocation, plus filesystem fixtures that exercise the install
//! pipeline without needing a live registry.
//!
//! **Why subprocess tests?** The unit tests in
//! `commands::install::tests::*` and the resolver-crate tests cover
//! the parser/lookup/IR at the function-call level. These tests are
//! the CLI-level gate: they verify the END-TO-END contract that
//! agents and `JSON.parse` rely on, including stdout/stderr separation
//! and the actual command-line parser dispatch.

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
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn lpm-rs");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stdout, stderr)
}

/// Strip ANSI escapes from a captured stream so assertions are stable.
/// UTF-8 safe — iterates `chars()` and skips CSI sequences without
/// re-encoding bytes individually (the byte-level approach used by
/// older test helpers corrupts multi-byte UTF-8 like `→`).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            // Consume the `[` and the rest of the CSI sequence up to
            // and including the final byte (0x40..=0x7e).
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn write_project(dir: &Path, package_json: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("package.json"), package_json).unwrap();
}

/// Seed a fake but well-formed entry in `<HOME>/.lpm/store/v1/`.
/// `lpm install --offline` checks `PackageStore::has_package` for every
/// locked package, which in turn checks for `package.json` + `.integrity`
/// inside the version directory. Tests that exercise the offline branch
/// against a non-empty fixture must seed at least one package this way
/// or the install will hard-error with "package not in global store"
/// before reaching the override-state lifecycle code under test.
///
/// `name` may be unscoped (e.g. `lodash`) or scoped — scoped names get
/// the same `/` → `+` rewrite the store applies internally.
fn seed_store_package(home: &Path, name: &str, version: &str) {
    let safe_name = name.replace(['/', '\\'], "+");
    let dir = home
        .join(".lpm")
        .join("store")
        .join("v1")
        .join(format!("{safe_name}@{version}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
    std::fs::write(dir.join(".integrity"), "sha512-fixture").unwrap();
}

/// Write a synthetic `lpm.lock` containing the given package entries.
/// Each entry is `(name, version, dependencies)`.
fn write_lockfile(dir: &Path, entries: &[(&str, &str, &[&str])]) {
    let pkgs: Vec<String> = entries
        .iter()
        .map(|(name, version, deps)| {
            let deps_block = if deps.is_empty() {
                String::new()
            } else {
                let inner = deps
                    .iter()
                    .map(|d| format!("\"{d}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("\ndependencies = [{inner}]")
            };
            format!(
                r#"[[packages]]
name = "{name}"
version = "{version}"{deps_block}
"#
            )
        })
        .collect();
    let toml = format!(
        r#"[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

{}
"#,
        pkgs.join("\n")
    );
    std::fs::write(dir.join("lpm.lock"), toml).unwrap();
}

/// Write a synthetic `.lpm/overrides-state.json` capturing one applied
/// override for `(package, from, to, via_parent)`. Used by the
/// `lpm graph --why` tests so they don't need to drive a real install.
fn write_overrides_state(
    dir: &Path,
    fingerprint: &str,
    parsed: &[(&str, &str)],
    applied: &[(&str, &str, &str, Option<&str>)],
) {
    let lpm_dir = dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    let parsed_json: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(key, target)| {
            serde_json::json!({
                "raw_key": key,
                "source": "lpm.overrides",
                "selector": { "kind": "name", "name": key },
                "target": target,
            })
        })
        .collect();
    let applied_json: Vec<serde_json::Value> = applied
        .iter()
        .map(|(pkg, from, to, via)| {
            serde_json::json!({
                "raw_key": pkg,
                "source": "lpm.overrides",
                "package": pkg,
                "from_version": from,
                "to_version": to,
                "via_parent": via,
            })
        })
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": fingerprint,
        "captured_at": "2026-04-11T00:00:00Z",
        "parsed": parsed_json,
        "applied": applied_json,
    });
    std::fs::write(
        lpm_dir.join("overrides-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-overrides-phase5-regression")
        .join(format!("{name}.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── Acceptance Criterion #1: fail-closed parsing ─────────────────────

/// **Phase 5 acceptance criterion: fail-closed parsing.** Multi-segment
/// path selectors must be a HARD ERROR at install entry, not a silent
/// no-op or a warning. The error message must name the offending key.
#[test]
fn cli_install_rejects_multi_segment_path_selector() {
    let dir = project_dir("multi-segment-path");
    write_project(
        &dir,
        r#"{
  "name": "multi-segment-path",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": {
    "overrides": {
      "a>b>c": "1.0.0"
    }
  }
}"#,
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "multi-segment path must error. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("a>b>c"),
        "error message must name the offending key. combined:\n{combined}"
    );
}

/// **Phase 5 acceptance criterion: fail-closed parsing.** An invalid
/// target version is a HARD ERROR. The error must name the offending
/// override key.
#[test]
fn cli_install_rejects_invalid_target_version() {
    let dir = project_dir("invalid-target");
    write_project(
        &dir,
        r#"{
  "name": "invalid-target",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": {
    "overrides": {
      "lodash": "not-a-version-or-range"
    }
  }
}"#,
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "invalid target must error. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("lodash"),
        "error message must name the offending key. combined:\n{combined}"
    );
}

/// **Phase 5 acceptance criterion: fail-closed parsing.** An invalid
/// range in the selector half is a HARD ERROR.
#[test]
fn cli_install_rejects_invalid_range_in_selector() {
    let dir = project_dir("invalid-range");
    write_project(
        &dir,
        r#"{
  "name": "invalid-range",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": {
    "overrides": {
      "lodash@???": "1.0.0"
    }
  }
}"#,
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "invalid range must error. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("???") || combined.contains("invalid"),
        "error message must surface the validation failure. combined:\n{combined}"
    );
}

// ── Acceptance Criterion #2: `lpm graph --why` decoration ────────────

/// **Phase 5 acceptance criterion: `lpm why` shows the override
/// trace.** When `.lpm/overrides-state.json` records an applied
/// override for a package, `lpm graph --why pkg` decorates the
/// rendered output with the from→to summary.
#[test]
fn cli_graph_why_shows_override_trace_in_human_output() {
    let dir = project_dir("why-human-trace");
    write_project(
        &dir,
        r#"{
  "name": "why-human-trace",
  "version": "0.0.0",
  "dependencies": {
    "lodash": "^4.17.0"
  }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.20", &[])]);
    write_overrides_state(
        &dir,
        "sha256-test-fp",
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", None)],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["graph", "--why", "lodash"]);
    assert!(
        status.success(),
        "graph --why must succeed. stdout={stdout} stderr={stderr}"
    );
    let stdout_clean = strip_ansi(&stdout);
    assert!(
        stdout_clean.contains("Overrides applied to this package"),
        "human output must show override section. stdout:\n{stdout_clean}"
    );
    assert!(
        stdout_clean.contains("4.17.21 → 4.17.20"),
        "human output must show from→to. stdout:\n{stdout_clean}"
    );
    assert!(
        stdout_clean.contains("lpm.overrides.lodash"),
        "human output must reference source. stdout:\n{stdout_clean}"
    );
}

/// **Phase 5 acceptance criterion: `lpm why` shows the override
/// trace.** The JSON form of `lpm graph --why` must include an
/// `applied_overrides` array populated from `.lpm/overrides-state.json`.
#[test]
fn cli_graph_why_json_includes_applied_overrides() {
    let dir = project_dir("why-json-trace");
    write_project(
        &dir,
        r#"{
  "name": "why-json-trace",
  "version": "0.0.0",
  "dependencies": {
    "lodash": "^4.17.0"
  }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.20", &[])]);
    write_overrides_state(
        &dir,
        "sha256-test-fp",
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", Some("debug"))],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "graph", "--why", "lodash"]);
    assert!(
        status.success(),
        "graph --why --json must succeed. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&stdout)).unwrap_or_else(|e| {
            panic!("stdout is not valid JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        });
    let arr = parsed["applied_overrides"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "applied_overrides should have one entry");
    assert_eq!(arr[0]["package"].as_str().unwrap(), "lodash");
    assert_eq!(arr[0]["from_version"].as_str().unwrap(), "4.17.21");
    assert_eq!(arr[0]["to_version"].as_str().unwrap(), "4.17.20");
    assert_eq!(arr[0]["via_parent"].as_str().unwrap(), "debug");
}

/// **Phase 5 acceptance criterion: graceful absence.** When no
/// overrides state file exists, `lpm graph --why --json` still
/// succeeds and emits an empty `applied_overrides` array.
#[test]
fn cli_graph_why_json_empty_overrides_when_no_state_file() {
    let dir = project_dir("why-no-state");
    write_project(
        &dir,
        r#"{
  "name": "why-no-state",
  "version": "0.0.0",
  "dependencies": {
    "lodash": "^4.17.0"
  }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.20", &[])]);
    // Intentionally no overrides-state.json.

    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "graph", "--why", "lodash"]);
    assert!(
        status.success(),
        "graph --why --json must succeed without state file. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout)).unwrap();
    let arr = parsed["applied_overrides"].as_array().unwrap();
    assert!(arr.is_empty(), "applied_overrides should be empty");
}

// ── Acceptance Criterion #3: state file lifecycle (offline parity) ───
//
// **Audit finding (2026-04-12, GPT-5.4 end-to-end audit).** The first
// pass of Phase 5 wired override fingerprint/state lifecycle handling
// only into the ONLINE install branch. The `--offline` branch returned
// before reaching that code, which produced three silent-failure
// modes:
//
//   1. Stale state file not deleted when the user removes all overrides
//   2. Fingerprint mismatch silently accepted (lockfile fast path
//      shadows the user's override edits)
//   3. State file not created on first offline install with overrides
//      (`lpm graph --why` then has no trace to load)
//
// The previous "state lifecycle" test in this file was a no-op: it
// staged an empty-deps fixture (which hits the no-deps short-circuit
// before reaching the offline branch at all) and explicitly avoided
// asserting any post-condition. It always passed regardless of whether
// the bug existed.
//
// The three tests below stage NON-EMPTY offline fixtures (deps backed
// by a seeded `~/.lpm/store/` entry so `try_lockfile_fast_path` returns
// Some) and assert the actual contract.

/// **Audit fix #1.** Stale state + non-empty deps + EMPTY current
/// override set → offline install must HARD ERROR.
///
/// Rationale: the lockfile was produced by a resolution that DID
/// apply overrides. Removing the override declaration in offline
/// mode would silently install the old override-pinned versions
/// instead of the user's new natural versions, because offline mode
/// cannot re-resolve. The safe behavior is to refuse and tell the
/// user to run online so the lockfile can be regenerated against
/// the new (empty) override set.
///
/// Pre-fix: the offline branch returned without reaching the
/// fingerprint check, completed the install with stale resolutions,
/// AND left the stale `.lpm/overrides-state.json` on disk, making
/// `lpm graph --why` surface ghost override traces.
#[test]
fn cli_offline_install_hard_errors_when_overrides_removed_with_prior_state() {
    let dir = project_dir("offline-overrides-removed");
    write_project(
        &dir,
        r#"{
  "name": "offline-overrides-removed",
  "version": "0.0.0",
  "dependencies": {
    "lodash": "^4.17.0"
  }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&dir, "lodash", "4.17.20");
    write_overrides_state(
        &dir,
        "sha256-stale-fp",
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", None)],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "offline install MUST hard error when overrides were removed but the lockfile \
         still reflects them (audit fix #1). stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error message should mention overrides/fingerprint. combined:\n{combined}"
    );
    assert!(
        combined.contains("online") || combined.contains("re-resolve"),
        "error message should tell the user how to recover (run online). combined:\n{combined}"
    );
}

/// **Audit fix #2.** Stale state with fingerprint X + non-empty deps +
/// CURRENT overrides whose fingerprint is Y (different) → offline
/// install must HARD ERROR. Offline mode cannot re-resolve, so a
/// silent fast path here would mean the user's override edits are
/// silently ignored.
#[test]
fn cli_offline_install_hard_errors_on_fingerprint_mismatch() {
    let dir = project_dir("offline-fingerprint-mismatch");
    write_project(
        &dir,
        r#"{
  "name": "offline-fingerprint-mismatch",
  "version": "0.0.0",
  "dependencies": {
    "lodash": "^4.17.0"
  },
  "lpm": {
    "overrides": {
      "lodash": "5.0.0"
    }
  }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&dir, "lodash", "4.17.20");
    // Persisted fingerprint deliberately differs from what the
    // current `lpm.overrides` set will produce.
    write_overrides_state(
        &dir,
        "sha256-totally-different-fp-from-current",
        &[("lodash", "4.17.20")],
        &[],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "offline install with fingerprint mismatch MUST hard error (audit fix #2). \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error message should mention overrides/fingerprint. combined:\n{combined}"
    );
}

/// **Audit fix #2 (variant).** No persisted state file + non-empty
/// deps + CURRENT non-empty overrides → offline install must HARD
/// ERROR. We can't prove the lockfile was generated with the same
/// override set, so the safe behavior is to refuse.
#[test]
fn cli_offline_install_hard_errors_when_overrides_exist_but_no_state_file() {
    let dir = project_dir("offline-no-prior-state");
    write_project(
        &dir,
        r#"{
  "name": "offline-no-prior-state",
  "version": "0.0.0",
  "dependencies": {
    "lodash": "^4.17.0"
  },
  "lpm": {
    "overrides": {
      "lodash": "4.17.20"
    }
  }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&dir, "lodash", "4.17.20");
    // Intentionally no overrides-state.json — we have overrides in
    // package.json but the previous install (online) never recorded
    // a fingerprint we can verify against.

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "offline install with overrides but no recorded state MUST hard error (audit fix #3). \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error message should mention overrides/fingerprint. combined:\n{combined}"
    );
}

/// **Positive case.** Stale state + non-empty deps + CURRENT overrides
/// with the SAME fingerprint → offline install succeeds AND preserves
/// the existing state file.
#[test]
fn cli_offline_install_succeeds_when_fingerprint_matches() {
    let dir = project_dir("offline-fp-match");
    // Reproduce the install pipeline's fingerprint locally so the
    // fixture and the binary agree on the canonical SHA-256. The
    // simplest way is to call OverrideSet::parse here and pull the
    // fingerprint out, but lpm-resolver isn't a dev-dep of this test.
    // Instead: stage the override set in `package.json`, run a dummy
    // first install ONLINE-like — actually, just run the binary once
    // to stage the state file, then run --offline a second time.
    //
    // Easier still: don't stage a state file at all on the first run,
    // run --offline EXPECTING failure (no recorded fingerprint), then
    // fix the fixture by writing a state file with the right
    // fingerprint via a helper that mirrors the resolver's hash. Since
    // we don't have access to the resolver, mirror its canonical
    // serialization here.
    write_project(
        &dir,
        r#"{
  "name": "offline-fp-match",
  "version": "0.0.0",
  "dependencies": {
    "lodash": "^4.17.0"
  },
  "lpm": {
    "overrides": {
      "lodash": "4.17.20"
    }
  }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&dir, "lodash", "4.17.20");
    // Compute the canonical fingerprint for the single-entry override
    // set `{"lodash": "4.17.20"}`. Mirrors `lpm_resolver::overrides::compute_fingerprint`.
    let fingerprint = phase5_fingerprint(&[("lpm.overrides", "lodash", "4.17.20")]);
    write_overrides_state(
        &dir,
        &fingerprint,
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", None)],
    );

    let state_path = dir.join(".lpm").join("overrides-state.json");
    assert!(state_path.exists());

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        status.success(),
        "offline install with matching fingerprint should succeed. stdout={stdout} stderr={stderr}"
    );
    assert!(
        state_path.exists(),
        "state file should be preserved when fingerprints match"
    );
}

/// Mirror of `lpm_resolver::overrides::compute_fingerprint`. The
/// canonical encoding is one line per entry, sorted ASCII, fed
/// through SHA-256 with `\n` after each line. Each line is
/// `{source}|{raw_key}|{selector}|{target}`.
///
/// **MUST stay in sync** with `compute_fingerprint` in
/// `crates/lpm-resolver/src/overrides.rs`. If that function changes,
/// these tests will fail loudly because the binary's fingerprint won't
/// match the test fixture's, and the assertion above will catch it.
fn phase5_fingerprint(entries: &[(&str, &str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut canonical: Vec<String> = entries
        .iter()
        .map(|(source, key, target)| format!("{source}|{key}|name:{key}|{target}"))
        .collect();
    canonical.sort();
    let mut hasher = Sha256::new();
    for line in &canonical {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256-{:x}", hasher.finalize())
}
