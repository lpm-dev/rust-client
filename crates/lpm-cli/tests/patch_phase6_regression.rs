//! **Phase 32 Phase 6 — `lpm patch` end-to-end regression suite (CLI level).**
//!
//! These tests spawn the actual `lpm-rs` binary as a child process and
//! drive `lpm patch`, `lpm patch-commit`, `lpm install`, and
//! `lpm graph --why` against on-disk fixtures. They are the regression
//! suite for the Phase 6 spec acceptance criteria:
//!
//! - **`lpm patch <key>` extracts a clean staging copy** of the store
//!   package and prints (in human + JSON) where the staging dir lives.
//! - **`lpm patch-commit <staging>` writes `patches/<key>.patch`** plus
//!   updates `package.json :: lpm.patchedDependencies` with the patch
//!   path and the original integrity baseline.
//! - **`lpm install` applies patches automatically** after the linker
//!   pass. Drift, fuzzy hunks, missing patch files, and internal-file
//!   tampering attempts are HARD install errors.
//! - **`lpm install --offline` hard-errors on patch fingerprint drift**
//!   (mirror of the Phase 5 overrides offline contract).
//! - **`lpm install --json` surfaces `applied_patches`.**
//! - **`lpm graph --why` decorates** with the patch trace from
//!   `.lpm/patch-state.json`.
//! - **JSON contracts are stable** — the F-V12 stream-separation
//!   contract holds for every `--json` patch path.
//!
//! These mirror the structure of `overrides_phase5_regression.rs`: a
//! `run_lpm` helper that captures stdout/stderr from a real binary
//! invocation, plus filesystem fixtures that exercise the install
//! pipeline without needing a live registry.
//!
//! **Why subprocess tests?** The unit tests in
//! `crate::patch_engine::tests::*` cover the parser, generator,
//! classifier, and apply loop at the function-call level. These tests
//! are the CLI-level gate: they verify the END-TO-END contract that
//! agents and `JSON.parse` rely on, including stdout/stderr separation
//! and the actual command-line parser dispatch.

use std::path::{Path, PathBuf};
use std::process::Command;

// ── Helpers ──────────────────────────────────────────────────────────

/// Spawn the lpm-rs binary in `cwd` with the given args. Returns
/// (status, stdout, stderr) — always captures both streams.
fn run_lpm(cwd: &Path, args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let output = Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .env("HOME", cwd) // isolate from real ~/.lpm
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

/// Strip ANSI escape sequences. UTF-8-safe (iterates `chars()`).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
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
/// Includes `package.json`, an `index.js`, and the `.integrity`
/// sentinel. Returns the integrity string the engine will read back.
fn seed_store_package(home: &Path, name: &str, version: &str, files: &[(&str, &str)]) -> String {
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
    for (rel, content) in files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
    }
    let integrity = format!("sha512-fixture-{name}-{version}");
    std::fs::write(dir.join(".integrity"), &integrity).unwrap();
    integrity
}

/// Write a synthetic `lpm.lock` containing the given package entries.
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

/// Mirror of `patch_state::compute_fingerprint` so test fixtures and
/// the binary agree on the canonical hash. Same byte-domain-separator
/// pattern as the real impl.
fn phase6_fingerprint(entries: &[(&str, &str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut keys: Vec<&(&str, &str, &str)> = entries.iter().collect();
    keys.sort_by(|a, b| a.0.cmp(b.0));
    let mut h = Sha256::new();
    for (k, path, integrity) in keys {
        h.update(k.as_bytes());
        h.update(b"\x00");
        h.update(path.as_bytes());
        h.update(b"\x00");
        h.update(integrity.as_bytes());
        h.update(b"\x01");
    }
    format!("sha256-{:x}", h.finalize())
}

/// One applied-patch hit, in test-helper terms.
/// Tuple shape: (name, version, patch_path, locations, modified, added, deleted).
type AppliedTuple<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a [&'a str],
    usize,
    usize,
    usize,
);

/// Write a synthetic `.lpm/patch-state.json` capturing the given patch
/// state. Used by both the offline-drift tests and the
/// `lpm graph --why` decoration tests.
fn write_patch_state(
    dir: &Path,
    fingerprint: &str,
    parsed: &[(&str, &str, &str, &str)],
    applied: &[AppliedTuple<'_>],
) {
    let lpm_dir = dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    let parsed_json: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(raw_key, name, version, path)| {
            serde_json::json!({
                "raw_key": raw_key,
                "name": name,
                "version": version,
                "path": path,
                "original_integrity": "sha512-fixture",
            })
        })
        .collect();
    let applied_json: Vec<serde_json::Value> = applied
        .iter()
        .map(
            |(name, version, patch_path, locations, modified, added, deleted)| {
                serde_json::json!({
                    "raw_key": format!("{name}@{version}"),
                    "name": name,
                    "version": version,
                    "patch_path": patch_path,
                    "locations": locations.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    "files_modified": modified,
                    "files_added": added,
                    "files_deleted": deleted,
                })
            },
        )
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": fingerprint,
        "captured_at": "2026-04-12T00:00:00Z",
        "parsed": parsed_json,
        "applied": applied_json,
    });
    std::fs::write(
        lpm_dir.join("patch-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-patch-phase6-regression")
        .join(format!("{name}.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── 1. `lpm patch <key>` extracts the staging dir ────────────────────

#[test]
fn cli_patch_extracts_to_temp_dir_with_breadcrumb() {
    let dir = project_dir("patch-extracts");
    write_project(
        &dir,
        r#"{
  "name": "patch-extracts",
  "version": "0.0.0"
}"#,
    );
    seed_store_package(
        &dir,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'")],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "patch", "lodash@4.17.21"]);
    assert!(
        status.success(),
        "patch must succeed. stdout={stdout} stderr={stderr}"
    );

    // F-V12 contract: stdout in --json mode is valid JSON.
    let parsed: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout))
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nstdout:\n{stdout}"));
    assert!(parsed["success"].as_bool().unwrap());
    assert_eq!(parsed["name"].as_str().unwrap(), "lodash");
    assert_eq!(parsed["version"].as_str().unwrap(), "4.17.21");
    let staging_dir_str = parsed["staging_dir"].as_str().unwrap();
    let staging_dir = PathBuf::from(staging_dir_str);

    // The package files were copied to the staging dir.
    let pkg_dir = staging_dir.join("node_modules").join("lodash");
    assert!(
        pkg_dir.join("package.json").exists(),
        "package.json must exist in staging"
    );
    assert!(
        pkg_dir.join("index.js").exists(),
        "index.js must exist in staging"
    );

    // The breadcrumb is at the staging root.
    let breadcrumb = staging_dir.join(".lpm-patch.json");
    assert!(breadcrumb.exists(), "breadcrumb file must exist");
    let bc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&breadcrumb).unwrap()).unwrap();
    assert_eq!(bc["name"].as_str().unwrap(), "lodash");
    assert_eq!(bc["version"].as_str().unwrap(), "4.17.21");
    assert_eq!(bc["key"].as_str().unwrap(), "lodash@4.17.21");

    // Internal sentinels are NOT in the staging copy.
    assert!(
        !pkg_dir.join(".integrity").exists(),
        ".integrity must be filtered from staging"
    );

    let _ = std::fs::remove_dir_all(&staging_dir);
}

#[test]
fn cli_patch_fails_when_package_not_in_store() {
    let dir = project_dir("patch-no-store");
    write_project(
        &dir,
        r#"{
  "name": "patch-no-store",
  "version": "0.0.0"
}"#,
    );
    // Intentionally no seeded store entry.

    let (status, stdout, stderr) = run_lpm(&dir, &["patch", "lodash@4.17.21"]);
    assert!(
        !status.success(),
        "patch must fail when store has no copy. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("not in the global store") || combined.contains("Run `lpm install"),
        "error must explain how to recover. combined:\n{combined}"
    );
}

#[test]
fn cli_patch_rejects_range_keys() {
    let dir = project_dir("patch-range-key");
    write_project(
        &dir,
        r#"{
  "name": "patch-range-key",
  "version": "0.0.0"
}"#,
    );
    seed_store_package(&dir, "lodash", "4.17.21", &[("a.js", "x")]);

    // Range selectors are reserved for Phase 6.1 — must be rejected.
    let (status, stdout, stderr) = run_lpm(&dir, &["patch", "lodash@^4.17.0"]);
    assert!(
        !status.success(),
        "patch with caret range must fail. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("range version") || combined.contains("Phase 6.1"),
        "error must mention range / Phase 6.1. combined:\n{combined}"
    );
}

// ── 2. `lpm patch-commit` writes patch + updates manifest ────────────

#[test]
fn cli_patch_commit_writes_patch_file_and_updates_manifest() {
    let dir = project_dir("patch-commit-flow");
    write_project(
        &dir,
        r#"{
  "name": "patch-commit-flow",
  "version": "0.0.0"
}"#,
    );
    let integrity = seed_store_package(
        &dir,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'\n")],
    );

    // Step 1: extract.
    let (s1, stdout1, stderr1) = run_lpm(&dir, &["--json", "patch", "lodash@4.17.21"]);
    assert!(
        s1.success(),
        "extract failed: stdout={stdout1} stderr={stderr1}"
    );
    let parsed1: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout1)).unwrap();
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    // Step 2: edit a file.
    let edit_target = staging.join("node_modules/lodash/index.js");
    std::fs::write(&edit_target, "module.exports = 'PATCHED'\n").unwrap();

    // Step 3: commit.
    let (s2, stdout2, stderr2) =
        run_lpm(&dir, &["--json", "patch-commit", staging.to_str().unwrap()]);
    assert!(
        s2.success(),
        "patch-commit failed. stdout={stdout2} stderr={stderr2}"
    );

    // F-V12: stdout is valid JSON.
    let parsed2: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout2)).unwrap();
    assert!(parsed2["success"].as_bool().unwrap());
    assert_eq!(parsed2["name"].as_str().unwrap(), "lodash");
    assert_eq!(parsed2["version"].as_str().unwrap(), "4.17.21");
    assert_eq!(parsed2["files_changed"].as_u64().unwrap(), 1);
    assert!(parsed2["insertions"].as_u64().unwrap() >= 1);
    assert!(parsed2["deletions"].as_u64().unwrap() >= 1);
    assert_eq!(parsed2["original_integrity"].as_str().unwrap(), integrity);

    // The patch file is on disk.
    let patch_file = dir.join("patches/lodash@4.17.21.patch");
    assert!(patch_file.exists(), "patch file must exist");
    let patch_text = std::fs::read_to_string(&patch_file).unwrap();
    assert!(patch_text.contains("--- a/index.js"));
    assert!(patch_text.contains("+++ b/index.js"));
    assert!(patch_text.contains("-module.exports = 'orig'"));
    assert!(patch_text.contains("+module.exports = 'PATCHED'"));

    // package.json contains the new entry.
    let pkg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("package.json")).unwrap()).unwrap();
    assert_eq!(
        pkg["lpm"]["patchedDependencies"]["lodash@4.17.21"]["path"]
            .as_str()
            .unwrap(),
        "patches/lodash@4.17.21.patch"
    );
    assert_eq!(
        pkg["lpm"]["patchedDependencies"]["lodash@4.17.21"]["originalIntegrity"]
            .as_str()
            .unwrap(),
        integrity
    );

    // The staging dir was cleaned up.
    assert!(
        !staging.exists(),
        "patch-commit should clean up the staging dir"
    );
}

#[test]
fn cli_patch_commit_fails_on_no_changes() {
    let dir = project_dir("patch-commit-no-changes");
    write_project(
        &dir,
        r#"{
  "name": "patch-commit-no-changes",
  "version": "0.0.0"
}"#,
    );
    seed_store_package(&dir, "lodash", "4.17.21", &[("index.js", "x\n")]);

    let (_, stdout1, _) = run_lpm(&dir, &["--json", "patch", "lodash@4.17.21"]);
    let parsed1: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout1)).unwrap();
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    // Don't edit anything. Commit must fail.
    let (status, stdout, stderr) = run_lpm(&dir, &["patch-commit", staging.to_str().unwrap()]);
    assert!(
        !status.success(),
        "patch-commit with no changes must fail. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("no changes detected"),
        "error must mention 'no changes detected'. combined:\n{combined}"
    );
}

#[test]
fn cli_patch_commit_fails_on_binary_change() {
    let dir = project_dir("patch-commit-binary");
    write_project(
        &dir,
        r#"{
  "name": "patch-commit-binary",
  "version": "0.0.0"
}"#,
    );
    seed_store_package(&dir, "lodash", "4.17.21", &[("logo.txt", "hello\n")]);

    let (_, stdout1, _) = run_lpm(&dir, &["--json", "patch", "lodash@4.17.21"]);
    let parsed1: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout1)).unwrap();
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    // Replace with a binary file.
    std::fs::write(
        staging.join("node_modules/lodash/logo.txt"),
        b"hello\x00binary",
    )
    .unwrap();

    let (status, stdout, stderr) = run_lpm(&dir, &["patch-commit", staging.to_str().unwrap()]);
    assert!(
        !status.success(),
        "patch-commit must reject binary edits. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("binary"),
        "error must mention 'binary'. combined:\n{combined}"
    );
}

// ── 3. `lpm install` applies patches ─────────────────────────────────

/// Build a fixture project with a patch already declared in
/// `package.json`, the patch file at `patches/<key>.patch`, a lockfile
/// entry, a seeded store entry, AND a pre-staged `patch-state.json`
/// with the matching fingerprint.
///
/// Pre-staging the state file is required because the install pipeline
/// hard-errors in `--offline` mode if the patches map fingerprint
/// doesn't match the persisted state. Tests that exercise the apply
/// pass need to bypass that drift gate by faking the prior state to
/// match.
///
/// Returns the project dir, the patch fingerprint that the install
/// pipeline will compute, and the integrity string from the seeded
/// store.
fn build_install_fixture(
    name: &str,
    pkg_name: &str,
    pkg_version: &str,
    store_files: &[(&str, &str)],
    patch_text: &str,
) -> (PathBuf, String, String) {
    let dir = project_dir(name);
    let integrity = seed_store_package(&dir, pkg_name, pkg_version, store_files);

    let patch_rel = format!("patches/{pkg_name}@{pkg_version}.patch");
    std::fs::create_dir_all(dir.join("patches")).unwrap();
    std::fs::write(dir.join(&patch_rel), patch_text).unwrap();

    write_project(
        &dir,
        &format!(
            r#"{{
  "name": "{name}",
  "version": "0.0.0",
  "dependencies": {{ "{pkg_name}": "^{pkg_version}" }},
  "lpm": {{
    "patchedDependencies": {{
      "{pkg_name}@{pkg_version}": {{
        "path": "{patch_rel}",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(&dir, &[(pkg_name, pkg_version, &[])]);
    let key = format!("{pkg_name}@{pkg_version}");
    let fp = phase6_fingerprint(&[(&key, &patch_rel, &integrity)]);

    // Pre-stage the patch state file with the matching fingerprint so
    // the offline drift gate accepts the install.
    write_patch_state(&dir, &fp, &[(&key, pkg_name, pkg_version, &patch_rel)], &[]);
    (dir, fp, integrity)
}

#[test]
fn cli_install_applies_patch_after_link_isolated() {
    let original = "module.exports = 'orig'\n";
    let patched = "module.exports = 'PATCHED'\n";
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-module.exports = 'orig'\n+module.exports = 'PATCHED'\n";
    let (dir, _fp, _integrity) = build_install_fixture(
        "install-applies-patch",
        "lodash",
        "4.17.21",
        &[("index.js", original)],
        patch_text,
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        status.success(),
        "install must succeed. stdout={stdout} stderr={stderr}"
    );

    // The canonical isolated location must contain the patched bytes.
    let nm_file = dir.join("node_modules/.lpm/lodash@4.17.21/node_modules/lodash/index.js");
    assert!(nm_file.exists(), "linked file must exist");
    assert_eq!(
        std::fs::read_to_string(&nm_file).unwrap(),
        patched,
        "patch must be applied to the linked tree"
    );
}

#[test]
fn cli_install_is_idempotent_with_patches() {
    let original = "a\nb\nc\n";
    let patched = "a\nB\nc\n";
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n";
    let (dir, _, _) = build_install_fixture(
        "install-idempotent",
        "lodash",
        "4.17.21",
        &[("index.js", original)],
        patch_text,
    );

    // First install.
    let (s1, _, _) = run_lpm(&dir, &["install", "--offline"]);
    assert!(s1.success());

    // Second install (idempotency check).
    let (s2, stdout2, stderr2) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        s2.success(),
        "second install must succeed. stdout={stdout2} stderr={stderr2}"
    );

    // Bytes unchanged after second pass.
    let nm_file = dir.join("node_modules/.lpm/lodash@4.17.21/node_modules/lodash/index.js");
    assert_eq!(std::fs::read_to_string(&nm_file).unwrap(), patched);
}

#[test]
fn cli_install_fails_on_drift() {
    // Author the patch against integrity X, then mutate the seeded
    // .integrity file so the live store reports integrity Y. Install
    // must hard-error.
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-orig\n+patched\n";
    let (dir, _, _) = build_install_fixture(
        "install-drift",
        "lodash",
        "4.17.21",
        &[("index.js", "orig\n")],
        patch_text,
    );

    // Mutate .integrity in the store after the fixture was built.
    let store_integrity = dir.join(".lpm/store/v1/lodash@4.17.21/.integrity");
    std::fs::write(&store_integrity, "sha512-different-from-recorded").unwrap();

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "drift must hard-error. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("drift"),
        "error must mention 'drift'. combined:\n{combined}"
    );
    assert!(
        combined.contains("lodash"),
        "error must name the package. combined:\n{combined}"
    );
}

#[test]
fn cli_install_fails_on_missing_patch_file() {
    let dir = project_dir("install-missing-patch");
    let integrity = seed_store_package(&dir, "lodash", "4.17.21", &[("index.js", "x\n")]);
    let patch_rel = "patches/missing.patch";
    write_project(
        &dir,
        &format!(
            r#"{{
  "name": "install-missing-patch",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "{patch_rel}",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    // Intentionally do not create patches/missing.patch.
    // Pre-stage matching state so the offline drift gate passes and
    // we reach the apply pass (where the missing-file check fires).
    let fp = phase6_fingerprint(&[("lodash@4.17.21", patch_rel, &integrity)]);
    write_patch_state(
        &dir,
        &fp,
        &[("lodash@4.17.21", "lodash", "4.17.21", patch_rel)],
        &[],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "missing patch file must hard-error. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("does not exist") || combined.contains("missing.patch"),
        "error must name the missing path. combined:\n{combined}"
    );
}

#[test]
fn cli_install_fails_on_fuzzy_hunk() {
    // Patch was authored against `apple\nbanana\ncherry\n` but the
    // store baseline is `alpha\nbravo\ncharlie\n`. Strict apply must
    // reject.
    let patch_text =
        "--- a/index.js\n+++ b/index.js\n@@ -1,3 +1,3 @@\n apple\n-banana\n+BANANA\n cherry\n";
    let (dir, _, _) = build_install_fixture(
        "install-fuzzy",
        "lodash",
        "4.17.21",
        &[("index.js", "alpha\nbravo\ncharlie\n")],
        patch_text,
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "fuzzy hunk must hard-error. stdout={stdout} stderr={stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("hunk failed") || combined.contains("regenerate"),
        "error must mention failed hunk / regenerate. combined:\n{combined}"
    );
}

// ── 4. Patches_changed gate (drift detection) ────────────────────────

/// **Patches_changed contract.** Run two installs back-to-back. The
/// first records a patch state file with fingerprint A; before the
/// second install, edit `package.json` to declare a different patch
/// path so the recomputed fingerprint is B. The install pipeline
/// detects the drift via `patches_changed` and — in offline mode —
/// hard-errors with a recoverable message (run online to re-resolve).
///
/// **Why structured signal:** the human-mode "Using lockfile" message
/// goes through `output::info` which writes to STDOUT via cliclack
/// (verified at install.rs:579 + output.rs:21). A stderr text-search
/// for that string would always succeed regardless of fast-path state,
/// giving false confidence. We assert on the exit status + the
/// `--offline` recovery message instead, which is the actual
/// user-visible contract for the patches_changed gate in offline
/// mode.
#[test]
fn cli_install_offline_hard_errors_when_patches_change_between_runs() {
    let dir = project_dir("install-patches-changed-between-runs");
    let integrity = seed_store_package(&dir, "lodash", "4.17.21", &[("index.js", "x\n")]);
    std::fs::create_dir_all(dir.join("patches")).unwrap();
    std::fs::write(
        dir.join("patches/v1.patch"),
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("patches/v2.patch"),
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+Y\n",
    )
    .unwrap();
    write_project(
        &dir,
        &format!(
            r#"{{
  "name": "install-patches-changed-between-runs",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "patches/v1.patch",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    // Pre-stage matching state for the v1 fingerprint so the first
    // (--offline) install passes the drift gate.
    let fp_v1 = phase6_fingerprint(&[("lodash@4.17.21", "patches/v1.patch", &integrity)]);
    write_patch_state(
        &dir,
        &fp_v1,
        &[("lodash@4.17.21", "lodash", "4.17.21", "patches/v1.patch")],
        &[],
    );

    // First install — should succeed with v1 applied.
    let (s1, stdout1, stderr1) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        s1.success(),
        "first offline install must succeed. stdout={stdout1} stderr={stderr1}"
    );

    // Now edit package.json to point at v2 — patches_changed fires.
    write_project(
        &dir,
        &format!(
            r#"{{
  "name": "install-patches-changed-between-runs",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "patches/v2.patch",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );

    let (s2, stdout2, stderr2) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !s2.success(),
        "second offline install with patches_changed MUST hard-error. \
         stdout={stdout2} stderr={stderr2}"
    );
    let combined = strip_ansi(&format!("{stdout2}{stderr2}"));
    assert!(
        combined.contains("patch") || combined.contains("fingerprint"),
        "error must mention patches/fingerprint. combined:\n{combined}"
    );
    assert!(
        combined.contains("online") || combined.contains("re-resolve"),
        "error must tell the user how to recover. combined:\n{combined}"
    );
}

// ── 5. Offline-mode hard-error on patch fingerprint drift ────────────

#[test]
fn cli_offline_install_hard_errors_on_patch_fingerprint_mismatch() {
    let dir = project_dir("offline-patch-fingerprint-mismatch");
    let integrity = seed_store_package(&dir, "lodash", "4.17.21", &[("index.js", "x\n")]);
    std::fs::create_dir_all(dir.join("patches")).unwrap();
    std::fs::write(
        dir.join("patches/lodash@4.17.21.patch"),
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n",
    )
    .unwrap();
    write_project(
        &dir,
        &format!(
            r#"{{
  "name": "offline-patch-mismatch",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    // Persisted fingerprint deliberately differs from what the
    // current lpm.patchedDependencies map will produce.
    write_patch_state(
        &dir,
        "sha256-completely-different-from-current",
        &[(
            "lodash@4.17.21",
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
        )],
        &[],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "offline install with patch fingerprint mismatch MUST hard-error. \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("patch") || combined.contains("fingerprint"),
        "error must mention patches/fingerprint. combined:\n{combined}"
    );
    assert!(
        combined.contains("online") || combined.contains("re-resolve"),
        "error must tell the user how to recover. combined:\n{combined}"
    );
}

#[test]
fn cli_offline_install_hard_errors_when_patches_exist_but_no_state_file() {
    let dir = project_dir("offline-patch-no-prior-state");
    let integrity = seed_store_package(&dir, "lodash", "4.17.21", &[("index.js", "x\n")]);
    std::fs::create_dir_all(dir.join("patches")).unwrap();
    std::fs::write(
        dir.join("patches/lodash@4.17.21.patch"),
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n",
    )
    .unwrap();
    write_project(
        &dir,
        &format!(
            r#"{{
  "name": "offline-patch-no-state",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    // No .lpm/patch-state.json — we have patches in package.json but
    // the previous (online) install never recorded a fingerprint we
    // can verify against. Offline mode must refuse.

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "offline install with patches but no recorded state MUST hard-error. \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("patch") || combined.contains("fingerprint"),
        "error must mention patches/fingerprint. combined:\n{combined}"
    );
}

#[test]
fn cli_offline_install_hard_errors_when_patches_removed_with_prior_state() {
    let dir = project_dir("offline-patches-removed");
    seed_store_package(&dir, "lodash", "4.17.21", &[("index.js", "x\n")]);
    write_project(
        &dir,
        r#"{
  "name": "offline-patches-removed",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    // The state file says we previously had a patch, but the manifest
    // no longer declares one. Offline cannot prove the lockfile is
    // safe, so it must refuse.
    write_patch_state(
        &dir,
        "sha256-prior-fingerprint",
        &[(
            "lodash@4.17.21",
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
        )],
        &[(
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
            &["node_modules/.lpm/lodash@4.17.21/node_modules/lodash"],
            1,
            0,
            0,
        )],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        !status.success(),
        "offline install with prior patch state but no current patches MUST hard-error. \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let combined = strip_ansi(&format!("{stdout}{stderr}"));
    assert!(
        combined.contains("patch") || combined.contains("fingerprint"),
        "error must mention patches/fingerprint. combined:\n{combined}"
    );
}

// ── 6. State file lifecycle: deletion when patches removed ───────────

#[test]
fn cli_install_deletes_patch_state_file_when_patches_removed_online() {
    // We can't actually run an online install in tests (no live
    // registry), but the deletion path runs after the offline branch
    // exits successfully too — so this test stages a state file and
    // then runs an empty-deps install (which short-circuits and
    // cleans up stale state files via the no-deps path... actually,
    // the no-deps short-circuit only handles overrides cleanup).
    //
    // Use the offline path with a fingerprint that matches the empty
    // patches map (sha256 of nothing).
    let dir = project_dir("delete-patch-state");
    seed_store_package(&dir, "lodash", "4.17.21", &[("index.js", "x\n")]);
    write_project(
        &dir,
        r#"{
  "name": "delete-patch-state",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    // Stage a state file matching the EMPTY current patches map. This
    // is contrived but exercises the cleanup path: the install
    // pipeline will see prior_patch_state.is_some() AND
    // current_patches.is_empty() AND fingerprint match, then take the
    // delete-stale-state branch in the no-deps cleanup.
    let empty_fp = phase6_fingerprint(&[]);
    write_patch_state(&dir, &empty_fp, &[], &[]);

    // The fingerprint matches (both empty), so install should succeed
    // and the state file should remain (because it's still consistent
    // with an empty current set... actually we DO delete it in this
    // case because current_patches.is_empty()).
    let (status, stdout, stderr) = run_lpm(&dir, &["install", "--offline"]);
    assert!(
        status.success(),
        "install must succeed when patch fingerprint matches empty. \
         stdout={stdout} stderr={stderr}"
    );
    // State file is deleted because current patches set is empty.
    let state_file = dir.join(".lpm/patch-state.json");
    assert!(
        !state_file.exists(),
        "state file should be deleted when current patches set is empty"
    );
}

// ── 7. JSON output stream contract (--json) ──────────────────────────

#[test]
fn cli_install_json_includes_applied_patches_field() {
    let original = "x\n";
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n";
    let (dir, _, _) = build_install_fixture(
        "install-json-applied",
        "lodash",
        "4.17.21",
        &[("index.js", original)],
        patch_text,
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "install", "--offline"]);
    assert!(
        status.success(),
        "install --json must succeed. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&stdout)).unwrap_or_else(|e| {
            panic!(
                "install --json stdout is not valid JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            )
        });
    let arr = parsed["applied_patches"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "applied_patches must contain one entry");
    assert_eq!(arr[0]["name"].as_str().unwrap(), "lodash");
    assert_eq!(arr[0]["version"].as_str().unwrap(), "4.17.21");
    assert_eq!(arr[0]["files_modified"].as_u64().unwrap(), 1);
}

// ── 8. `lpm graph --why` decoration ──────────────────────────────────

#[test]
fn cli_graph_why_shows_patch_trace_in_human_output() {
    let dir = project_dir("why-patch-human");
    write_project(
        &dir,
        r#"{
  "name": "why-patch-human",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    write_patch_state(
        &dir,
        "sha256-test-fp",
        &[(
            "lodash@4.17.21",
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
        )],
        &[(
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
            &["node_modules/.lpm/lodash@4.17.21/node_modules/lodash"],
            2,
            0,
            0,
        )],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["graph", "--why", "lodash"]);
    assert!(
        status.success(),
        "graph --why must succeed. stdout={stdout} stderr={stderr}"
    );
    let stdout_clean = strip_ansi(&stdout);
    assert!(
        stdout_clean.contains("Patches applied to this package"),
        "human output must include patches section. stdout:\n{stdout_clean}"
    );
    assert!(
        stdout_clean.contains("patches/lodash@4.17.21.patch"),
        "human output must reference the patch path. stdout:\n{stdout_clean}"
    );
}

#[test]
fn cli_graph_why_json_includes_applied_patches() {
    let dir = project_dir("why-patch-json");
    write_project(
        &dir,
        r#"{
  "name": "why-patch-json",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    write_patch_state(
        &dir,
        "sha256-test-fp",
        &[(
            "lodash@4.17.21",
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
        )],
        &[(
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
            &["node_modules/.lpm/lodash@4.17.21/node_modules/lodash"],
            2,
            0,
            0,
        )],
    );

    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "graph", "--why", "lodash"]);
    assert!(
        status.success(),
        "graph --why --json must succeed. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout))
        .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout:\n{stdout}"));
    let arr = parsed["applied_patches"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"].as_str().unwrap(), "lodash");
    assert_eq!(
        arr[0]["patch_path"].as_str().unwrap(),
        "patches/lodash@4.17.21.patch"
    );
    assert_eq!(arr[0]["files_modified"].as_u64().unwrap(), 2);
}

#[test]
fn cli_graph_why_json_empty_patches_when_no_state_file() {
    let dir = project_dir("why-patch-no-state");
    write_project(
        &dir,
        r#"{
  "name": "why-patch-no-state",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);
    // No patch-state.json.

    let (status, stdout, stderr) = run_lpm(&dir, &["--json", "graph", "--why", "lodash"]);
    assert!(
        status.success(),
        "graph --why --json must succeed without state. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout)).unwrap();
    let arr = parsed["applied_patches"].as_array().unwrap();
    assert!(arr.is_empty(), "applied_patches should be empty");
}

// ── 9. Audit fixes (2026-04-12 GPT-5.4 end-to-end audit) ─────────────
//
// Two findings from a live end-to-end run of the built binary that
// the unit + subprocess suites missed because they didn't assert the
// per-run summary contract on idempotent reruns or the integrity-hash
// surfacing in `lpm graph --why`.

/// **Audit finding (Medium): idempotent installs still report patches
/// as applied even when the rerun changed nothing.**
///
/// User-visible contract: a no-op idempotent rerun must NOT print
/// "Applied N patches" in human mode and must NOT include zero-op
/// entries in `--json` `applied_patches`. The state file (`.lpm/
/// patch-state.json`) should still record the patches as in effect
/// (so `lpm graph --why` keeps its provenance), but the per-run
/// summary describes work done THIS run, not "patches we considered".
///
/// Pre-fix repro: the second offline install printed
/// `Applied 1 patch:` with `0 files`, and the JSON `applied_patches`
/// array contained one entry with all-zero counts.
#[test]
fn cli_install_idempotent_rerun_reports_no_applied_patches_per_run() {
    let original = "x\n";
    let patched = "X\n";
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n";
    let (dir, _, _) = build_install_fixture(
        "install-idempotent-zero-op-report",
        "lodash",
        "4.17.21",
        &[("index.js", original)],
        patch_text,
    );

    // First install: actually applies the patch.
    let (s1, stdout1, stderr1) = run_lpm(&dir, &["--json", "install", "--offline"]);
    assert!(s1.success(), "first install must succeed: {stderr1}");
    let p1: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout1))
        .unwrap_or_else(|e| panic!("first install --json invalid: {e}\nstdout:\n{stdout1}"));
    let arr1 = p1["applied_patches"].as_array().unwrap();
    assert_eq!(
        arr1.len(),
        1,
        "first install should report one applied patch"
    );
    assert_eq!(arr1[0]["files_modified"].as_u64().unwrap(), 1);

    // Sanity: bytes are patched on disk.
    let nm_file = dir.join("node_modules/.lpm/lodash@4.17.21/node_modules/lodash/index.js");
    assert_eq!(std::fs::read_to_string(&nm_file).unwrap(), patched);

    // Second install: nothing to do (idempotent path). The JSON
    // `applied_patches` array MUST be empty — we did no work, we
    // shouldn't claim we did. The patch is still in effect on disk.
    let (s2, stdout2, stderr2) = run_lpm(&dir, &["--json", "install", "--offline"]);
    assert!(s2.success(), "second install must succeed: {stderr2}");
    let p2: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout2))
        .unwrap_or_else(|e| panic!("second install --json invalid: {e}\nstdout:\n{stdout2}"));
    let arr2 = p2["applied_patches"].as_array().unwrap();
    assert!(
        arr2.is_empty(),
        "no-op rerun must report empty applied_patches; got {arr2:?}"
    );

    // Bytes still patched on disk after the no-op rerun.
    assert_eq!(
        std::fs::read_to_string(&nm_file).unwrap(),
        patched,
        "no-op rerun must not corrupt the patched bytes"
    );

    // Third install in human mode: must NOT print "Applied N patches".
    let (s3, stdout3, _stderr3) = run_lpm(&dir, &["install", "--offline"]);
    assert!(s3.success());
    let stdout3_clean = strip_ansi(&stdout3);
    assert!(
        !stdout3_clean.contains("Applied 1 patch") && !stdout3_clean.contains("Applied 1 patches"),
        "no-op rerun human mode must NOT print 'Applied N patches'; got:\n{stdout3_clean}"
    );

    // The state file MUST still have the patch recorded so
    // `lpm graph --why` keeps its provenance after the no-op rerun.
    let state_file = dir.join(".lpm/patch-state.json");
    assert!(
        state_file.exists(),
        "state file must persist across no-op reruns"
    );
    let state_text = std::fs::read_to_string(&state_file).unwrap();
    let state: serde_json::Value = serde_json::from_str(&state_text).unwrap();
    let state_applied = state["applied"].as_array().unwrap();
    assert_eq!(
        state_applied.len(),
        1,
        "state file MUST preserve the apply trace across no-op reruns; got: {state_applied:?}"
    );
    assert_eq!(state_applied[0]["files_modified"].as_u64().unwrap(), 1);
}

/// **Audit finding (Low): patch provenance in graph output drops the
/// actual recorded integrity hash.**
///
/// User-visible contract: `lpm graph --why <pkg>` must surface the
/// `originalIntegrity` value from `.lpm/patch-state.json` so users can
/// verify the patch is bound to the expected store baseline. Pre-fix,
/// human output emitted the literal string "originalIntegrity recorded"
/// and JSON output omitted the field entirely.
#[test]
fn cli_graph_why_includes_original_integrity_in_human_and_json() {
    let dir = project_dir("why-includes-integrity");
    write_project(
        &dir,
        r#"{
  "name": "why-includes-integrity",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&dir, &[("lodash", "4.17.21", &[])]);

    // Recognizable integrity hash that will appear in output.
    let test_integrity = "sha512-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ";

    // Write a state file directly with the integrity field populated
    // on the applied hit.
    let lpm_dir = dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": "sha256-test",
        "captured_at": "2026-04-12T00:00:00Z",
        "parsed": [{
            "raw_key": "lodash@4.17.21",
            "name": "lodash",
            "version": "4.17.21",
            "path": "patches/lodash@4.17.21.patch",
            "original_integrity": test_integrity,
        }],
        "applied": [{
            "raw_key": "lodash@4.17.21",
            "name": "lodash",
            "version": "4.17.21",
            "patch_path": "patches/lodash@4.17.21.patch",
            "original_integrity": test_integrity,
            "locations": ["node_modules/.lpm/lodash@4.17.21/node_modules/lodash"],
            "files_modified": 1,
            "files_added": 0,
            "files_deleted": 0,
        }],
    });
    std::fs::write(
        lpm_dir.join("patch-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();

    // Human mode: must surface the integrity hash (possibly truncated)
    // and must NOT emit the literal "originalIntegrity recorded"
    // placeholder.
    let (s1, stdout1, stderr1) = run_lpm(&dir, &["graph", "--why", "lodash"]);
    assert!(
        s1.success(),
        "graph --why must succeed: {stdout1} {stderr1}"
    );
    let stdout1_clean = strip_ansi(&stdout1);
    assert!(
        !stdout1_clean.contains("originalIntegrity recorded"),
        "human output must NOT emit the literal placeholder; got:\n{stdout1_clean}"
    );
    // First 16 chars of the integrity hash should appear.
    assert!(
        stdout1_clean.contains("sha512-AbCdEfGh"),
        "human output must include the original integrity prefix; got:\n{stdout1_clean}"
    );

    // JSON mode: full integrity hash must be present in
    // applied_patches[0].original_integrity.
    let (s2, stdout2, _) = run_lpm(&dir, &["--json", "graph", "--why", "lodash"]);
    assert!(s2.success());
    let parsed: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout2)).unwrap();
    let arr = parsed["applied_patches"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0]["original_integrity"].as_str().unwrap(),
        test_integrity,
        "JSON output must include the full original_integrity hash"
    );
}
