//! Workflow tests for `lpm store verify` / `lpm store path` / `lpm store clean`.
//!
//! Covers the v1 store layout (`<HOME>/.lpm/store/v1/<safe>@<ver>/`) with
//! valid, empty, and corrupted entries. No registry, no network.

mod support;

use support::{TempProject, lpm};

fn store_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("store")
}

fn store_v1(project: &TempProject) -> std::path::PathBuf {
    store_root(project).join("v1")
}

/// Seed a single v1 store entry with a minimal package.json + one stub file.
/// Directory layout matches `PackageStore::package_dir`: scoped names use
/// `+` instead of `/`, version follows `@`.
fn seed_v1_entry(project: &TempProject, name: &str, version: &str, valid: bool) {
    let safe_name = name.replace(['/', '\\'], "+");
    let dir = store_v1(project).join(format!("{safe_name}@{version}"));
    std::fs::create_dir_all(&dir).expect("failed to create store entry dir");

    if valid {
        let pkg_json = serde_json::json!({
            "name": name,
            "version": version,
        });
        std::fs::write(dir.join("package.json"), pkg_json.to_string())
            .expect("failed to write package.json");
        std::fs::write(dir.join("index.js"), "module.exports = {}\n")
            .expect("failed to write index.js");
    }
    // !valid → directory exists but no package.json. Verify should flag
    // it as corrupted via the "missing package.json" branch.
}

// ─── path subcommand ──────────────────────────────────────────────────

#[test]
fn store_path_prints_store_root() {
    let project = TempProject::empty(r#"{"name":"store-path","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["store", "path"])
        .output()
        .expect("failed to run lpm store path");

    assert!(
        output.status.success(),
        "lpm store path failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = store_root(&project).display().to_string();
    assert_eq!(
        stdout.trim(),
        expected,
        "lpm store path must print the isolated store root, got: {stdout}\nexpected: {expected}",
    );
}

#[test]
fn store_path_json_envelope_carries_path() {
    let project = TempProject::empty(r#"{"name":"store-path","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "store", "path"])
        .output()
        .expect("failed to run lpm store path --json");

    assert!(output.status.success(), "lpm store path --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("store path --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    let path = envelope["path"].as_str().expect("path must be a string");
    assert_eq!(
        path,
        store_root(&project).display().to_string(),
        "store path --json must report the isolated store root",
    );
}

// ─── verify subcommand ────────────────────────────────────────────────

#[test]
fn store_verify_on_empty_store_reports_zero_entries() {
    let project = TempProject::empty(r#"{"name":"store-verify","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "store", "verify"])
        .output()
        .expect("failed to run lpm store verify --json");

    assert!(
        output.status.success(),
        "verify on empty store must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("verify --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["entries_verified"], serde_json::json!(0));
    assert_eq!(envelope["corrupted"], serde_json::json!(0));
}

#[test]
fn store_verify_passes_on_valid_v1_entry() {
    let project = TempProject::empty(r#"{"name":"store-verify","version":"1.0.0"}"#);
    seed_v1_entry(&project, "lodash", "4.17.21", true);

    let output = lpm(&project)
        .args(["--json", "store", "verify"])
        .output()
        .expect("failed to run lpm store verify --json");

    assert!(
        output.status.success(),
        "verify on valid entry must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("verify --json must be valid JSON: {e}\n---\n{stdout}"));

    let entries = envelope["entries_verified"]
        .as_u64()
        .expect("entries_verified must be u64");
    assert!(
        entries >= 1,
        "verify must report >=1 entries after seeding one, got {entries}\nenvelope: {envelope}",
    );
    assert_eq!(envelope["corrupted"], serde_json::json!(0));
}

#[test]
fn store_verify_human_uses_slim_status_lines() {
    let project = TempProject::empty(r#"{"name":"store-verify","version":"1.0.0"}"#);
    seed_v1_entry(&project, "lodash", "4.17.21", true);

    let output = lpm(&project)
        .args(["store", "verify"])
        .output()
        .expect("failed to run lpm store verify");

    assert!(
        output.status.success(),
        "verify on valid entry must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Verifying store integrity"),
        "store verify must report a slim phase line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Store verified ·"),
        "store verify must report a slim completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "store verify output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[test]
fn store_verify_flags_corrupted_v1_entry_without_package_json() {
    let project = TempProject::empty(r#"{"name":"store-verify","version":"1.0.0"}"#);
    seed_v1_entry(&project, "broken-pkg", "1.0.0", false);

    let output = lpm(&project)
        .args(["--json", "store", "verify"])
        .output()
        .expect("failed to run lpm store verify --json");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("verify --json must be valid JSON: {e}\n---\n{stdout}"));

    let corrupted = envelope["corrupted"]
        .as_u64()
        .expect("corrupted must be u64");
    assert!(
        corrupted >= 1,
        "verify must flag the missing-package.json entry as corrupted, got {corrupted}\nenvelope: {envelope}",
    );

    let issues = envelope["issues"]
        .as_array()
        .expect("issues must be an array");
    assert!(
        issues.iter().any(|i| i
            .as_str()
            .is_some_and(|s| s.contains("broken-pkg@1.0.0") && s.contains("package.json"))),
        "issues must mention the corrupted entry and the missing field, got: {issues:?}",
    );
}

// ─── clean subcommand ─────────────────────────────────────────────────

#[test]
fn store_clean_on_empty_store_reports_idempotent_success() {
    let project = TempProject::empty(r#"{"name":"store-clean","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "store", "clean"])
        .output()
        .expect("failed to run lpm store clean --json");

    assert!(
        output.status.success(),
        "clean on empty store must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("clean --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["removed_bytes"], serde_json::json!(0));
}

#[test]
fn store_clean_wipes_v1_and_v2_directories() {
    let project = TempProject::empty(r#"{"name":"store-clean","version":"1.0.0"}"#);

    seed_v1_entry(&project, "lodash", "4.17.21", true);

    // Also seed a v2 link entry shell so the v2 wipe path is exercised.
    let v2 = store_root(&project).join("v2");
    std::fs::create_dir_all(v2.join("links")).expect("failed to create v2/links");
    std::fs::write(v2.join("links/.placeholder"), b"x").expect("failed to seed v2 placeholder");

    let output = lpm(&project)
        .args(["--json", "store", "clean"])
        .output()
        .expect("failed to run lpm store clean --json");

    assert!(output.status.success(), "lpm store clean --json failed");

    assert!(
        !store_v1(&project).exists(),
        "v1 store dir must be removed after clean"
    );
    assert!(!v2.exists(), "v2 store dir must be removed after clean");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("clean --json must be valid JSON: {e}\n---\n{stdout}"));

    let removed = envelope["removed_bytes"]
        .as_u64()
        .expect("removed_bytes must be u64");
    assert!(
        removed > 0,
        "removed_bytes must reflect seeded content, got {removed}\nenvelope: {envelope}",
    );
    assert!(
        envelope["v1_path"].is_string(),
        "envelope must surface v1_path"
    );
    assert!(
        envelope["v2_path"].is_string(),
        "envelope must surface v2_path"
    );
}

#[test]
fn store_clean_human_uses_slim_completion() {
    let project = TempProject::empty(r#"{"name":"store-clean","version":"1.0.0"}"#);
    seed_v1_entry(&project, "lodash", "4.17.21", true);

    let output = lpm(&project)
        .args(["store", "clean"])
        .output()
        .expect("failed to run lpm store clean");

    assert!(
        output.status.success(),
        "store clean must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Wiped package store · freed "),
        "store clean must report a slim completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "store clean output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[test]
fn store_unknown_action_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"store-unknown","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["store", "no-such-action"])
        .output()
        .expect("failed to run lpm store bogus");

    assert!(
        !output.status.success(),
        "unknown store action must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("verify") && stderr.contains("clean") && stderr.contains("path"),
        "stderr must list valid actions, got:\n{stderr}"
    );
}
