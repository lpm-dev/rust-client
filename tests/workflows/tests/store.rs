//! Workflow tests for `lpm store verify` / `lpm store path` / `lpm store clean`.
//!
//! Covers the v1 store layout (`<HOME>/.lpm/store/v1/<safe>@<ver>/`) with
//! valid, empty, and corrupted entries. No registry, no network.

mod support;

use base64::Engine as _;
use base64::engine::general_purpose;
use sha2::{Digest, Sha512};
use support::{TempProject, lpm};

fn store_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("store")
}

fn store_v1(project: &TempProject) -> std::path::PathBuf {
    store_root(project).join("v1")
}

fn v1_entry_dir(project: &TempProject, name: &str, version: &str) -> std::path::PathBuf {
    let safe_name = name.replace(['/', '\\'], "+");
    store_v1(project).join(format!("{safe_name}@{version}"))
}

fn v2_sri_and_segment(seed: &[u8]) -> (String, String) {
    let digest: [u8; 64] = Sha512::digest(seed).into();
    let sri = format!("sha512-{}", general_purpose::STANDARD.encode(digest));
    let segment = format!("sha512-{}", hex::encode(digest));
    (sri, segment)
}

/// Seed a single v1 store entry with a minimal package.json + one stub file.
/// Directory layout matches `PackageStore::package_dir`: scoped names use
/// `+` instead of `/`, version follows `@`.
fn seed_v1_entry(project: &TempProject, name: &str, version: &str, valid: bool) {
    let dir = v1_entry_dir(project, name, version);
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

fn seed_v2_entry(project: &TempProject, name: &str, version: &str) {
    let (sri, segment) = v2_sri_and_segment(format!("{name}@{version}").as_bytes());
    let v2 = store_root(project).join("v2");
    let object_path = format!("objects/{segment}");
    let object_dir = v2.join(&object_path);
    std::fs::create_dir_all(&object_dir).expect("failed to create v2 object dir");
    std::fs::write(
        object_dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .expect("failed to write v2 object package.json");
    std::fs::write(object_dir.join(".integrity"), &sri)
        .expect("failed to write v2 object integrity");

    let link_key = format!("{name}@{version}+0123456789abcdef");
    let link_dir = v2.join("links").join(&link_key);
    let pkg_dir = link_dir.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).expect("failed to create v2 link package dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .expect("failed to write v2 link package.json");
    std::fs::write(pkg_dir.join("index.js"), "module.exports = {}\n")
        .expect("failed to write v2 link index.js");

    let sidecar = serde_json::json!({
        "schema": 1,
        "graph_key": link_key,
        "graph_key_digest_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "name": name,
        "version": version,
        "source_sri": sri,
        "object_path": object_path,
        "deps": [],
        "platform": {
            "os": "darwin",
            "cpu": "arm64",
            "libc": null
        },
        "created_at": "2026-05-31T08:00:00Z",
        "last_referenced_at": "2026-05-31T08:00:00Z"
    });
    std::fs::write(
        link_dir.join(".lpm-link-meta.json"),
        serde_json::to_vec_pretty(&sidecar).expect("sidecar JSON must serialize"),
    )
    .expect("failed to write v2 sidecar");
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
    seed_v2_entry(&project, "lodash", "4.17.21");

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
        stderr.contains("links 1 / objects 1"),
        "store verify must report v2 link/object counts, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Checked every referenced object hash"),
        "store verify must report the referenced-object check, got:\n{stderr}"
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

#[test]
fn store_verify_deep_fails_when_lockfile_is_unreadable() {
    let project = TempProject::empty(r#"{"name":"store-verify","version":"1.0.0"}"#);
    seed_v1_entry(&project, "deep-pkg", "1.0.0", true);
    project.write_file("lpm.lock", "this is not a valid lpm lockfile");

    let output = lpm(&project)
        .args(["--json", "store", "verify", "--deep"])
        .output()
        .expect("failed to run lpm store verify --deep --json");

    assert!(
        !output.status.success(),
        "deep verify must fail when its lockfile cross-check cannot be loaded\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("store verify --deep --json must emit JSON on failure: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(
        envelope["check_kind"],
        serde_json::json!("lockfile_marker_consistency")
    );
    let issues = envelope["issues"]
        .as_array()
        .expect("issues must be an array");
    assert!(
        issues
            .iter()
            .filter_map(|issue| issue.as_str())
            .any(|issue| issue.contains("lpm.lock") && issue.contains("unreadable")),
        "deep verify must explain that the lockfile could not be read: {envelope}",
    );
}

#[cfg(unix)]
#[test]
fn store_verify_deep_fix_fails_when_security_cache_cannot_be_written() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempProject::empty(r#"{"name":"store-verify","version":"1.0.0"}"#);
    seed_v1_entry(&project, "readonly-pkg", "1.0.0", true);

    let pkg_dir = v1_entry_dir(&project, "readonly-pkg", "1.0.0");
    let mut readonly = std::fs::metadata(&pkg_dir)
        .expect("read package dir metadata")
        .permissions();
    readonly.set_mode(0o555);
    std::fs::set_permissions(&pkg_dir, readonly).expect("make package dir readonly");

    let output = lpm(&project)
        .args(["--json", "store", "verify", "--deep", "--fix"])
        .output()
        .expect("failed to run lpm store verify --deep --fix --json");

    let mut writable = std::fs::metadata(&pkg_dir)
        .expect("read package dir metadata after verify")
        .permissions();
    writable.set_mode(0o755);
    std::fs::set_permissions(&pkg_dir, writable).expect("restore writable package dir");

    assert!(
        !output.status.success(),
        "deep verify --fix must fail when it cannot write the refreshed security cache\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("store verify --deep --fix --json must emit JSON on failure: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["securityMismatches"], serde_json::json!(1));
    assert_eq!(envelope["securityReanalyzed"], serde_json::json!(0));
    let issues = envelope["issues"]
        .as_array()
        .expect("issues must be an array");
    assert!(
        issues
            .iter()
            .filter_map(|issue| issue.as_str())
            .any(|issue| issue.contains("readonly-pkg@1.0.0")
                && issue.contains(".lpm-security.json")),
        "failed --fix must name the package and cache file that could not be written: {envelope}",
    );
}

#[test]
fn store_verify_fix_refreshes_security_cache_without_requiring_deep_flag() {
    let project = TempProject::empty(r#"{"name":"store-verify","version":"1.0.0"}"#);
    seed_v1_entry(&project, "cacheless-pkg", "1.0.0", true);

    let pkg_dir = v1_entry_dir(&project, "cacheless-pkg", "1.0.0");
    assert!(
        !pkg_dir.join(".lpm-security.json").exists(),
        "pre-condition: fixture starts without a security cache"
    );

    let output = lpm(&project)
        .args(["--json", "store", "verify", "--fix"])
        .output()
        .expect("failed to run lpm store verify --fix --json");

    assert!(
        output.status.success(),
        "store verify --fix should succeed when it can refresh the missing cache\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        pkg_dir.join(".lpm-security.json").exists(),
        "--fix must create the missing security cache even when --deep is omitted"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("store verify --fix --json must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["securityMismatches"], serde_json::json!(1));
    assert_eq!(envelope["securityReanalyzed"], serde_json::json!(1));
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
