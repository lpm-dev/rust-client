//! Workflow tests for project trust management.
//!
//! Pure manifest-and-snapshot operations: no registry, no network. Each
//! test seeds `package.json > lpm > trustedDependencies` plus (for diff)
//! `.lpm/trust-snapshot.json` and (for prune) `lpm.lock`, then asserts
//! the human + JSON outputs and the mutated manifest state.

mod support;

use serde_json::json;
use support::{TempProject, assertions, lpm, write_signed_unlock};

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
fn trust_diff_global_json_reports_added_binding_against_snapshot() {
    let project = TempProject::empty(r#"{}"#);

    write_trust_snapshot(
        &project,
        json!({ "esbuild@0.25.1": { "integrity": "sha512-e", "scriptHash": null } }),
    );
    write_pkg_with_trust(
        &project,
        json!({
            "esbuild@0.25.1": { "integrity": "sha512-e" },
            "sharp@0.33.0": { "integrity": "sha512-s" }
        }),
    );

    let output = lpm(&project)
        .args(["--json", "trust", "diff"])
        .output()
        .expect("failed to run lpm --json trust diff");

    assert!(
        output.status.success(),
        "global --json trust diff failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("lpm --json trust diff must emit one valid JSON document: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], json!(true));
    assert_eq!(envelope["command"], json!("trust diff"));
    assert_eq!(envelope["diff_count"], json!(1));
    assert_eq!(envelope["added"][0]["key"], json!("sharp@0.33.0"));
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
fn trust_diff_json_assert_none_failure_emits_single_diff_envelope() {
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
        .args(["--json", "trust", "diff", "--assert-none"])
        .output()
        .expect("failed to run lpm --json trust diff --assert-none");

    assert!(
        !output.status.success(),
        "global --json trust diff --assert-none must fail when entries exist"
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "assert-none failure must emit one valid JSON document on stdout: {e}\n---\n{stdout}"
        )
    });

    assert_eq!(envelope["success"], json!(false));
    assert_eq!(envelope["command"], json!("trust diff"));
    assert_eq!(envelope["assertion_failed"], json!(true));
    assert_eq!(envelope["error_code"], json!("trust_diff_assert_none"));
    assert_eq!(envelope["diff_count"], json!(1));
    assert_eq!(envelope["added"][0]["key"], json!("sharp@0.33.0"));
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
fn trust_prune_global_json_dry_run_reports_success_without_mutation() {
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
        .args(["--json", "trust", "prune", "--dry-run"])
        .output()
        .expect("failed to run lpm --json trust prune --dry-run");

    assert!(
        output.status.success(),
        "global --json trust prune --dry-run failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("lpm --json trust prune must emit one valid JSON document: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], json!(true));
    assert_eq!(envelope["command"], json!("trust prune"));
    assert_eq!(envelope["dry_run"], json!(true));
    assert_eq!(envelope["mutated"], json!(false));
    assert_eq!(envelope["stale_count"], json!(1));

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

#[cfg(unix)]
#[test]
fn trust_prune_does_not_follow_preplanted_manifest_temp_symlink() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(r#"{}"#);
    let external = tempfile::tempdir().unwrap();
    let sentinel = external.path().join("sentinel");
    let original = b"external sentinel";
    std::fs::write(&sentinel, original).unwrap();
    symlink(&sentinel, project.path().join("package.json.tmp")).unwrap();

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
    assert_eq!(std::fs::read(&sentinel).unwrap(), original);
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

// ─── lpm trust release-age-exclude ───────────────────────────────────

#[test]
fn trust_release_age_exclude_add_accepts_package_scope_and_exact_version_selectors() {
    let project = TempProject::empty(
        r#"{
  "name": "release-age-trust",
  "version": "1.0.0",
  "scripts": { "test": "vitest" },
  "lpm": { "minimumReleaseAge": 172800 }
}"#,
    );
    let selectors = ["react", "@company/*", "react@1.0.0"];
    let mut envelopes = Vec::with_capacity(selectors.len());

    for selector in selectors {
        let output = lpm(&project)
            .args(["--json", "trust", "release-age-exclude", "add", selector])
            .output()
            .expect("failed to add project release-age exclusion");
        assert!(
            output.status.success(),
            "project exclusion add failed for {selector}:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        envelopes.push(
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .expect("add output must be valid JSON"),
        );
    }

    insta::assert_json_snapshot!(envelopes, @r###"
    [
      {
        "success": true,
        "schema_version": 1,
        "command": "trust release-age-exclude",
        "scope": "project",
        "action": "add",
        "selector": "react",
        "changed": true,
        "exclusions": [
          "react"
        ]
      },
      {
        "success": true,
        "schema_version": 1,
        "command": "trust release-age-exclude",
        "scope": "project",
        "action": "add",
        "selector": "@company/*",
        "changed": true,
        "exclusions": [
          "react",
          "@company/*"
        ]
      },
      {
        "success": true,
        "schema_version": 1,
        "command": "trust release-age-exclude",
        "scope": "project",
        "action": "add",
        "selector": "react@1.0.0",
        "changed": true,
        "exclusions": [
          "react",
          "@company/*",
          "react@1.0.0"
        ]
      }
    ]
    "###);

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["lpm"]["minimumReleaseAgeExclude"],
        json!(["react", "@company/*", "react@1.0.0"])
    );
    assert_eq!(manifest["lpm"]["minimumReleaseAge"], json!(172800));
    assert_eq!(manifest["scripts"]["test"], json!("vitest"));

    let list = lpm(&project)
        .args(["--json", "trust", "release-age-exclude", "list"])
        .output()
        .expect("failed to list project release-age exclusions");
    assert!(list.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "schema_version": 1,
      "command": "trust release-age-exclude",
      "scope": "project",
      "action": "list",
      "changed": false,
      "exclusions": [
        "react",
        "@company/*",
        "react@1.0.0"
      ]
    }
    "###);
}

#[test]
fn trust_release_age_exclude_duplicate_add_is_a_byte_stable_noop() {
    let project = TempProject::empty(
        r#"{"name":"release-age-trust","version":"1.0.0","lpm":{"minimumReleaseAgeExclude":["react"]}}"#,
    );
    let path = project.path().join("package.json");
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["--json", "trust", "release-age-exclude", "add", "react"])
        .output()
        .expect("failed to repeat project release-age exclusion");

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["changed"], json!(false));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn trust_release_age_exclude_remove_matches_the_complete_selector_only() {
    let project = TempProject::empty(
        r#"{"name":"release-age-trust","version":"1.0.0","lpm":{"minimumReleaseAgeExclude":["react","react@1.0.0","@company/*"]}}"#,
    );

    let output = lpm(&project)
        .args([
            "--json",
            "trust",
            "release-age-exclude",
            "remove",
            "react@1.0.0",
        ])
        .output()
        .expect("failed to remove project release-age exclusion");

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "schema_version": 1,
      "command": "trust release-age-exclude",
      "scope": "project",
      "action": "remove",
      "selector": "react@1.0.0",
      "changed": true,
      "exclusions": [
        "react",
        "@company/*"
      ]
    }
    "###);
}

#[test]
fn trust_release_age_exclude_remove_last_selector_deletes_only_the_exclusion_field() {
    let project = TempProject::empty(
        r#"{"name":"release-age-trust","version":"1.0.0","lpm":{"minimumReleaseAge":172800,"minimumReleaseAgeExclude":["react"]}}"#,
    );

    let output = lpm(&project)
        .args(["trust", "release-age-exclude", "remove", "react"])
        .output()
        .expect("failed to remove final project release-age exclusion");

    assert!(output.status.success());
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["lpm"]["minimumReleaseAge"], json!(172800));
    assert!(manifest["lpm"].get("minimumReleaseAgeExclude").is_none());
}

#[test]
fn trust_release_age_exclude_rejects_ranges_without_mutating_the_manifest() {
    let project = TempProject::empty(
        r#"{"name":"release-age-trust","version":"1.0.0","lpm":{"minimumReleaseAgeExclude":["react"]}}"#,
    );
    let path = project.path().join("package.json");
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["trust", "release-age-exclude", "add", "react@^1.0.0"])
        .output()
        .expect("failed to run invalid project release-age exclusion");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exact semantic version"),
        "error must explain exact-version selectors: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn trust_release_age_exclude_rejects_a_malformed_existing_list_without_mutation() {
    let project = TempProject::empty(
        r#"{"name":"release-age-trust","version":"1.0.0","lpm":{"minimumReleaseAgeExclude":"react"}}"#,
    );
    let path = project.path().join("package.json");
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["trust", "release-age-exclude", "add", "lodash"])
        .output()
        .expect("failed to inspect malformed project release-age exclusions");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be an array of strings"),
        "error must identify the required list shape: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn trust_release_age_exclude_list_requires_a_project_manifest() {
    let project = TempProject::empty(r#"{}"#);
    std::fs::remove_file(project.path().join("package.json")).unwrap();

    let output = lpm(&project)
        .args(["trust", "release-age-exclude", "list"])
        .output()
        .expect("failed to list project release-age exclusions without a manifest");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires a package.json"),
        "error must identify the required manifest: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─── lpm trust lifecycle-scope ───────────────────────────────────────

#[test]
fn trust_lifecycle_scope_add_requires_security_approval_before_manifest_mutation() {
    let project = TempProject::empty(
        r#"{"name":"lifecycle-scope-trust","version":"1.0.0","lpm":{"minimumReleaseAge":86400}}"#,
    );
    let path = project.path().join("package.json");
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["--json", "trust", "lifecycle-scope", "add", "@company/*"])
        .output()
        .expect("failed to add lifecycle scope without approval");

    let envelope = assertions::assert_security_approval_required(&output);
    assert_eq!(
        envelope["error"]["requested_scopes"],
        json!(["trust-scope-widen"])
    );
    assert!(
        envelope["error"]["suggested_command"]
            .as_str()
            .is_some_and(|command| command.contains("trust-scope-widen")),
        "error must provide the lifecycle-scope unlock command: {envelope}"
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn trust_lifecycle_scope_add_and_list_write_only_project_scope_trust() {
    let project = TempProject::empty(
        r#"{
  "name": "lifecycle-scope-trust",
  "version": "1.0.0",
  "lpm": {
    "minimumReleaseAge": 86400,
    "scripts": { "autoBuild": false }
  }
}"#,
    );
    write_signed_unlock(&project, &["trust-scope-widen"]);

    let add = lpm(&project)
        .args(["--json", "trust", "lifecycle-scope", "add", "@company/*"])
        .output()
        .expect("failed to add project lifecycle scope");

    assert!(
        add.status.success(),
        "lifecycle scope add failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&add.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "schema_version": 1,
      "command": "trust lifecycle-scope",
      "scope": "project",
      "action": "add",
      "selector": "@company/*",
      "changed": true,
      "scopes": [
        "@company/*"
      ]
    }
    "###);

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["lpm"]["scripts"]["trustedScopes"],
        json!(["@company/*"])
    );
    assert_eq!(manifest["lpm"]["scripts"]["autoBuild"], json!(false));
    assert_eq!(manifest["lpm"]["minimumReleaseAge"], json!(86400));

    let list = lpm(&project)
        .args(["--json", "trust", "lifecycle-scope", "list"])
        .output()
        .expect("failed to list project lifecycle scopes");
    assert!(list.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "schema_version": 1,
      "command": "trust lifecycle-scope",
      "scope": "project",
      "action": "list",
      "changed": false,
      "scopes": [
        "@company/*"
      ]
    }
    "###);
}

#[test]
fn trust_lifecycle_scope_duplicate_add_is_a_byte_stable_noop() {
    let project = TempProject::empty(
        r#"{"name":"lifecycle-scope-trust","version":"1.0.0","lpm":{"scripts":{"trustedScopes":["@company/*"]}}}"#,
    );
    write_signed_unlock(&project, &["trust-scope-widen"]);
    let path = project.path().join("package.json");
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["--json", "trust", "lifecycle-scope", "add", "@company/*"])
        .output()
        .expect("failed to repeat project lifecycle scope");

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["changed"], json!(false));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn trust_lifecycle_scope_remove_matches_the_complete_scope_and_preserves_siblings() {
    let project = TempProject::empty(
        r#"{"name":"lifecycle-scope-trust","version":"1.0.0","lpm":{"minimumReleaseAge":86400,"scripts":{"autoBuild":false,"trustedScopes":["@company/*","@internal/*"]}}}"#,
    );

    let output = lpm(&project)
        .args(["--json", "trust", "lifecycle-scope", "remove", "@company/*"])
        .output()
        .expect("failed to remove project lifecycle scope");

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "schema_version": 1,
      "command": "trust lifecycle-scope",
      "scope": "project",
      "action": "remove",
      "selector": "@company/*",
      "changed": true,
      "scopes": [
        "@internal/*"
      ]
    }
    "###);

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["lpm"]["scripts"]["trustedScopes"],
        json!(["@internal/*"])
    );
    assert_eq!(manifest["lpm"]["scripts"]["autoBuild"], json!(false));
    assert_eq!(manifest["lpm"]["minimumReleaseAge"], json!(86400));
}

#[test]
fn trust_lifecycle_scope_remove_revokes_the_signed_scope_authorization() {
    let project = TempProject::empty(r#"{"name":"lifecycle-scope-trust","version":"1.0.0"}"#);
    write_signed_unlock(&project, &["trust-scope-widen"]);

    let add = lpm(&project)
        .args(["trust", "lifecycle-scope", "add", "@company/*"])
        .output()
        .expect("failed to add project lifecycle scope");
    assert!(add.status.success());

    std::fs::remove_dir_all(project.home().join(".lpm/security/unlocks")).unwrap();
    let approved_duplicate = lpm(&project)
        .args(["--json", "trust", "lifecycle-scope", "add", "@company/*"])
        .output()
        .expect("failed to check persisted lifecycle-scope authorization");
    assert!(
        approved_duplicate.status.success(),
        "persisted scope authorization must cover a duplicate add: {}",
        String::from_utf8_lossy(&approved_duplicate.stderr)
    );
    let duplicate_envelope: serde_json::Value =
        serde_json::from_slice(&approved_duplicate.stdout).unwrap();
    assert_eq!(duplicate_envelope["changed"], json!(false));

    let remove = lpm(&project)
        .args(["trust", "lifecycle-scope", "remove", "@company/*"])
        .output()
        .expect("failed to remove project lifecycle scope");
    assert!(remove.status.success());

    let re_add = lpm(&project)
        .args(["--json", "trust", "lifecycle-scope", "add", "@company/*"])
        .output()
        .expect("failed to check removed lifecycle-scope authorization");
    let envelope = assertions::assert_security_approval_required(&re_add);
    assert_eq!(
        envelope["error"]["requested_scopes"],
        json!(["trust-scope-widen"])
    );
}

#[test]
fn trust_lifecycle_scope_rejects_non_scope_and_malicious_selectors_without_mutation() {
    let project = TempProject::empty(r#"{"name":"lifecycle-scope-trust","version":"1.0.0"}"#);
    let path = project.path().join("package.json");
    let before = std::fs::read(&path).unwrap();

    for selector in [
        "react",
        "react@1.0.0",
        "@company/package",
        "@Company/*",
        "@company-evil/pkg/*",
        "@company/\n*",
    ] {
        let output = lpm(&project)
            .args(["trust", "lifecycle-scope", "add", selector])
            .output()
            .expect("failed to run invalid lifecycle scope add");
        assert!(
            !output.status.success(),
            "invalid lifecycle scope must fail: {selector:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("expected one lowercase npm scope"),
            "error must explain lifecycle scope syntax: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn trust_lifecycle_scope_rejects_a_malformed_existing_list_without_mutation() {
    let project = TempProject::empty(
        r#"{"name":"lifecycle-scope-trust","version":"1.0.0","lpm":{"scripts":{"trustedScopes":["@company/*",42]}}}"#,
    );
    let path = project.path().join("package.json");
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["trust", "lifecycle-scope", "add", "@internal/*"])
        .output()
        .expect("failed to inspect malformed project lifecycle scopes");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be an array of strings"),
        "error must identify the required list shape: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn trust_lifecycle_scope_list_requires_a_project_manifest() {
    let project = TempProject::empty(r#"{}"#);
    std::fs::remove_file(project.path().join("package.json")).unwrap();

    let output = lpm(&project)
        .args(["trust", "lifecycle-scope", "list"])
        .output()
        .expect("failed to list lifecycle scopes without a manifest");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires a package.json"),
        "error must identify the required manifest: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
