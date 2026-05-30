//! Workflow tests for `lpm trust diff` and `lpm trust prune`.
//!
//! Pure manifest-and-snapshot operations: no registry, no network. Each
//! test seeds `package.json > lpm > trustedDependencies` plus (for diff)
//! `.lpm/trust-snapshot.json` and (for prune) `lpm.lock`, then asserts
//! the human + JSON outputs and the mutated manifest state.

mod support;

use serde_json::json;
use support::{TempProject, lpm};

fn write_pkg_with_trust(project: &TempProject, trusted: serde_json::Value) {
    let pkg = json!({
        "name": "trust-test",
        "version": "1.0.0",
        "lpm": {
            "trustedDependencies": trusted,
        },
    });
    project.write_file("package.json", &serde_json::to_string_pretty(&pkg).unwrap());
}

fn write_trust_snapshot(project: &TempProject, bindings: serde_json::Value) {
    let snapshot = json!({
        "schema_version": 1,
        "captured_at": "2026-05-01T00:00:00Z",
        "bindings": bindings,
    });
    project.write_file(
        ".lpm/trust-snapshot.json",
        &serde_json::to_string_pretty(&snapshot).unwrap(),
    );
}

fn write_lockfile(project: &TempProject, names_and_versions: &[(&str, &str)]) {
    let mut toml = String::from("[metadata]\nlockfile-version = 1\n");
    for (name, version) in names_and_versions {
        toml.push_str(&format!(
            "\n[[packages]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://lpm.dev\"\ndependencies = []\n"
        ));
    }
    project.write_file("lpm.lock", &toml);
}

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

// ─── lpm trust diff ───────────────────────────────────────────────────

#[test]
fn trust_diff_no_snapshot_reports_no_prior_state_human() {
    let project = TempProject::empty(r#"{"name":"trust-diff","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["trust", "diff"])
        .output()
        .expect("failed to run lpm trust diff");

    assert!(
        output.status.success(),
        "trust diff without snapshot must exit zero, got: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("no prior snapshot"),
        "expected 'no prior snapshot' messaging when .lpm/trust-snapshot.json is absent, got:\n{combined}"
    );
}

#[test]
fn trust_diff_reports_added_binding_against_snapshot() {
    let project = TempProject::empty(r#"{}"#);

    // Snapshot: only esbuild was trusted before
    write_trust_snapshot(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-e", "scriptHash": null } }),
    );
    // Current manifest: esbuild PLUS sharp (the addition we want to detect)
    write_pkg_with_trust(
        &project,
        json!({
            "esbuild@0.25.1": { "integrity": "sha512-e" },
            "sharp@0.33.0": { "integrity": "sha512-s" }
        }),
    );

    let output = lpm(&project)
        .args(["trust", "diff", "--json"])
        .output()
        .expect("failed to run lpm trust diff --json");

    assert!(
        output.status.success(),
        "trust diff --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("trust diff --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["command"], json!("trust diff"));
    assert_eq!(envelope["schema_version"], json!(1));
    assert_eq!(envelope["current_binding_count"], json!(2));

    let added = envelope["added"].as_array().expect("added must be array");
    assert_eq!(added.len(), 1, "exactly one addition expected: {envelope}");
    assert_eq!(added[0]["key"], json!("sharp@0.33.0"));

    let removed = envelope["removed"]
        .as_array()
        .expect("removed must be array");
    assert!(removed.is_empty(), "no removals expected: {envelope}");
}

#[test]
fn trust_diff_reports_removed_binding_when_manifest_dropped_an_entry() {
    let project = TempProject::empty(r#"{}"#);

    write_trust_snapshot(
        &project,
        json!({
            "esbuild@0.25.1": { "integrity": "sha512-e" },
            "sharp@0.33.0": { "integrity": "sha512-s" }
        }),
    );
    write_pkg_with_trust(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-e" } }),
    );

    let output = lpm(&project)
        .args(["trust", "diff", "--json"])
        .output()
        .expect("failed to run lpm trust diff --json");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("trust diff --json must be valid JSON: {e}\n---\n{stdout}"));

    let removed = envelope["removed"]
        .as_array()
        .expect("removed must be array");
    assert_eq!(removed.len(), 1, "exactly one removal expected: {envelope}");
    assert_eq!(removed[0]["key"], json!("sharp@0.33.0"));
}

#[test]
fn trust_diff_reports_changed_binding_when_integrity_drifts() {
    let project = TempProject::empty(r#"{}"#);

    write_trust_snapshot(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-OLD" } }),
    );
    write_pkg_with_trust(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-NEW" } }),
    );

    let output = lpm(&project)
        .args(["trust", "diff", "--json"])
        .output()
        .expect("failed to run lpm trust diff --json");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("trust diff --json must be valid JSON: {e}\n---\n{stdout}"));

    let changed = envelope["changed"]
        .as_array()
        .expect("changed must be array");
    assert_eq!(changed.len(), 1, "exactly one change expected: {envelope}");
    assert_eq!(changed[0]["key"], json!("esbuild@0.25.1"));
    assert_eq!(
        changed[0]["previous"]["integrity"],
        json!("sha512-OLD"),
        "previous integrity must be carried in the diff entry"
    );
    assert_eq!(
        changed[0]["current"]["integrity"],
        json!("sha512-NEW"),
        "current integrity must be carried in the diff entry"
    );
}

#[test]
fn trust_diff_human_output_uses_slim_sections() {
    let project = TempProject::empty(r#"{}"#);

    write_trust_snapshot(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-old", "scriptHash": "sha256-old" } }),
    );
    write_pkg_with_trust(
        &project,
        json!({
            "esbuild@0.25.1": { "integrity": "sha512-new", "scriptHash": "sha256-new" },
            "sharp@0.34.2": { "integrity": "sha512-s" }
        }),
    );

    let output = lpm(&project)
        .args(["trust", "diff"])
        .output()
        .expect("failed to run lpm trust diff");

    assert!(
        output.status.success(),
        "trust diff human failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("› Comparing trust ledger against last install snapshot"),
        "must show slim phase line; got:\n{combined}"
    );
    assert!(combined.contains("added\n  + sharp@0.34.2"));
    assert!(combined.contains("changed\n  ~ esbuild@0.25.1"));
    assert!(combined.contains("integrity"));
    assert!(combined.contains("sha512-old → sha512-new"));
    assert!(combined.contains("scriptHash"));
    assert!(combined.contains("sha256-old → sha256-new"));
    assert!(
        combined
            .contains("! 2 trust entries differ from the last install snapshot — lpm trust review"),
        "must show slim warning summary; got:\n{combined}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "trust diff output should not use bordered/cliclack glyphs; got:\n{combined}"
    );
}

#[test]
fn trust_diff_assert_none_exits_zero_when_diff_is_empty() {
    let project = TempProject::empty(r#"{}"#);

    write_trust_snapshot(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-e" } }),
    );
    write_pkg_with_trust(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-e" } }),
    );

    let output = lpm(&project)
        .args(["trust", "diff", "--assert-none"])
        .output()
        .expect("failed to run lpm trust diff --assert-none");

    assert!(
        output.status.success(),
        "trust diff --assert-none must exit 0 when no diff entries exist\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn trust_diff_assert_none_exits_nonzero_when_diff_entries_exist() {
    let project = TempProject::empty(r#"{}"#);

    write_trust_snapshot(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-e" } }),
    );
    write_pkg_with_trust(
        &project,
        json!({
            "esbuild@0.25.1": { "integrity": "sha512-e" },
            "sharp@0.33.0": { "integrity": "sha512-s" }
        }),
    );

    let output = lpm(&project)
        .args(["trust", "diff", "--assert-none"])
        .output()
        .expect("failed to run lpm trust diff --assert-none");

    assert!(
        !output.status.success(),
        "trust diff --assert-none must exit non-zero when diff entries exist"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("assertion failed")
            || stderr.contains("diff")
            || stderr.contains("matched"),
        "stderr must explain the assert-none failure, got:\n{stderr}"
    );
}

#[test]
fn trust_diff_without_package_json_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{}"#);
    // Remove the seeded package.json so the not-found branch fires.
    std::fs::remove_file(project.path().join("package.json")).expect("rm package.json");

    let output = lpm(&project)
        .args(["trust", "diff"])
        .output()
        .expect("failed to run lpm trust diff");

    assert!(
        !output.status.success(),
        "trust diff without package.json must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package.json"),
        "stderr must reference the missing manifest, got:\n{stderr}"
    );
}

// ─── lpm trust prune ──────────────────────────────────────────────────

#[test]
fn trust_prune_dry_run_reports_stale_but_does_not_mutate() {
    let project = TempProject::empty(r#"{}"#);

    write_pkg_with_trust(
        &project,
        json!({
            "esbuild@0.25.1": { "integrity": "sha512-e" },
            "removed-pkg@1.0.0": { "integrity": "sha512-r" }
        }),
    );
    write_lockfile(&project, &[("esbuild", "0.25.1")]);

    let before = std::fs::read_to_string(project.path().join("package.json"))
        .expect("read package.json before");

    let output = lpm(&project)
        .args(["trust", "prune", "--dry-run", "--json"])
        .output()
        .expect("failed to run lpm trust prune --dry-run --json");

    assert!(
        output.status.success(),
        "trust prune --dry-run failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("trust prune --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["dry_run"], json!(true), "dry_run must be true");
    assert_eq!(envelope["mutated"], json!(false), "mutated must be false");
    let stale = envelope["stale"].as_array().expect("stale must be array");
    assert_eq!(
        stale.len(),
        1,
        "exactly one stale entry expected: {envelope}"
    );
    assert_eq!(stale[0], json!("removed-pkg@1.0.0"));

    let after = std::fs::read_to_string(project.path().join("package.json"))
        .expect("read package.json after");
    assert_eq!(
        before, after,
        "dry-run must leave package.json byte-equal\nbefore:\n{before}\nafter:\n{after}",
    );
}

#[test]
fn trust_prune_human_dry_run_uses_slim_status_lines() {
    let project = TempProject::empty(r#"{}"#);

    write_pkg_with_trust(
        &project,
        json!({
            "esbuild@0.25.1": { "integrity": "sha512-e" },
            "removed-pkg@1.0.0": { "integrity": "sha512-r" }
        }),
    );
    write_lockfile(&project, &[("esbuild", "0.25.1")]);

    let output = lpm(&project)
        .args(["trust", "prune", "--dry-run"])
        .output()
        .expect("failed to run lpm trust prune --dry-run");

    assert!(
        output.status.success(),
        "trust prune --dry-run failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("› Pruning stale trust entries"),
        "must show slim phase line; got:\n{combined}"
    );
    assert!(combined.contains("stale\n  - removed-pkg@1.0.0"));
    assert!(
        combined.contains("✓ Dry run · 1 stale trust entry would be removed"),
        "must show dry-run completion; got:\n{combined}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "trust prune output should not use bordered/cliclack glyphs; got:\n{combined}"
    );
}

#[test]
fn trust_prune_yes_removes_stale_entries_and_preserves_active_ones() {
    let project = TempProject::empty(r#"{}"#);

    write_pkg_with_trust(
        &project,
        json!({
            "esbuild@0.25.1": { "integrity": "sha512-e" },
            "removed-pkg@1.0.0": { "integrity": "sha512-r" }
        }),
    );
    write_lockfile(&project, &[("esbuild", "0.25.1")]);

    let output = lpm(&project)
        .args(["trust", "prune", "--yes", "--json"])
        .output()
        .expect("failed to run lpm trust prune --yes --json");

    assert!(
        output.status.success(),
        "trust prune --yes failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("trust prune --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["mutated"], json!(true));
    assert_eq!(envelope["dry_run"], json!(false));

    let manifest_after = std::fs::read_to_string(project.path().join("package.json"))
        .expect("read package.json after");
    let pkg: serde_json::Value = serde_json::from_str(&manifest_after).expect("parse package.json");
    let trusted = pkg["lpm"]["trustedDependencies"]
        .as_object()
        .expect("trustedDependencies must remain an object");

    assert!(
        trusted.contains_key("esbuild@0.25.1"),
        "active entry must be preserved, got: {trusted:?}"
    );
    assert!(
        !trusted.contains_key("removed-pkg@1.0.0"),
        "stale entry must be pruned, got: {trusted:?}"
    );
}

#[test]
fn trust_prune_no_stale_entries_reports_success_without_mutation() {
    let project = TempProject::empty(r#"{}"#);

    write_pkg_with_trust(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-e" } }),
    );
    write_lockfile(&project, &[("esbuild", "0.25.1")]);

    let output = lpm(&project)
        .args(["trust", "prune", "--yes", "--json"])
        .output()
        .expect("failed to run lpm trust prune");

    assert!(output.status.success(), "trust prune with no stale failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("trust prune --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["mutated"], json!(false));
    let stale = envelope["stale"].as_array().expect("stale must be array");
    assert!(stale.is_empty(), "no stale entries expected: {envelope}");
}

#[test]
fn trust_prune_without_lockfile_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{}"#);
    write_pkg_with_trust(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-e" } }),
    );
    // No lpm.lock seeded.

    let output = lpm(&project)
        .args(["trust", "prune", "--yes"])
        .output()
        .expect("failed to run lpm trust prune");

    assert!(
        !output.status.success(),
        "trust prune without lockfile must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lpm.lock") || stderr.contains("lpm install"),
        "stderr must guide the user to run lpm install first, got:\n{stderr}"
    );
}
