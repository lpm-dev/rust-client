//! Workflow tests for `lpm skills list / validate / clean`.
//!
//! Skills live under `<project>/.lpm/skills/<owner.pkg>/<name>.md`.
//! These tests cover the local-only management surfaces (list /
//! validate / clean); `install` requires a registry call that's
//! already exercised by integration tests at `tests/integration/`
//! and isn't repeated here.

mod support;

use support::{TempProject, lpm};

fn seed_skill(project: &TempProject, pkg: &str, name: &str, body: &str) {
    project.write_file(&format!(".lpm/skills/{pkg}/{name}.md"), body);
}

// ─── list ─────────────────────────────────────────────────────────────

#[test]
fn skills_list_on_fresh_project_reports_no_skills_installed() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["skills", "list"])
        .output()
        .expect("failed to run lpm skills list");

    assert!(output.status.success(), "skills list must succeed");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("No skills installed"),
        "stdout/stderr must indicate no skills on a fresh project, got:\n{combined}",
    );
}

#[test]
fn skills_list_groups_by_package_and_counts_files() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    seed_skill(&project, "alice.tools", "format-code", "# format-code\n");
    seed_skill(&project, "alice.tools", "lint-rules", "# lint-rules\n");
    seed_skill(&project, "bob.helpers", "deploy", "# deploy\n");

    let output = lpm(&project)
        .args(["skills", "list"])
        .output()
        .expect("failed to run lpm skills list");

    assert!(output.status.success(), "skills list must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("alice.tools") && stdout.contains("bob.helpers"),
        "list must group by package, got:\n{stdout}"
    );
    assert!(
        stdout.contains("format-code")
            && stdout.contains("lint-rules")
            && stdout.contains("deploy"),
        "list must show each skill name, got:\n{stdout}"
    );
    // `3 skill` may carry ANSI bold codes between the digit and the word
    // (owo_colors emits `\x1b[1m3\x1b[0m skill(s)` even with NO_COLOR=1).
    // Assert on a non-overlapping substring that's color-stable.
    assert!(
        stdout.contains("skill(s) across 2 package(s)"),
        "list must report total summary, got:\n{stdout}"
    );
}

#[test]
fn skills_list_json_envelope_carries_per_package_arrays() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    seed_skill(&project, "alice.tools", "format-code", "# format-code\n");
    seed_skill(&project, "alice.tools", "lint-rules", "# lint-rules\n");

    let output = lpm(&project)
        .args(["--json", "skills", "list"])
        .output()
        .expect("failed to run lpm skills list --json");

    assert!(output.status.success(), "skills list --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("skills list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    let pkg_skills = envelope["alice.tools"]
        .as_array()
        .expect("alice.tools must be an array of skills");
    assert_eq!(pkg_skills.len(), 2, "two skills expected: {envelope}");

    let names: Vec<&str> = pkg_skills
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    assert!(names.contains(&"format-code"));
    assert!(names.contains(&"lint-rules"));

    for skill in pkg_skills {
        assert!(
            skill["size"].as_u64().is_some(),
            "each entry must carry a size field, got: {skill}"
        );
    }
}

// ─── validate ─────────────────────────────────────────────────────────

#[test]
fn skills_validate_accepts_a_well_formed_skill() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    seed_skill(
        &project,
        "alice.tools",
        "ok",
        "# ok\n\nThis is a tiny skill description.\n",
    );

    let output = lpm(&project)
        .args(["skills", "validate"])
        .output()
        .expect("failed to run lpm skills validate");

    assert!(
        output.status.success(),
        "validate on a well-formed skill must succeed, got: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn skills_validate_flags_skill_exceeding_size_limit_in_output() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);

    // Source enforces a 15KB max per skill file. Write 20KB so the limit
    // fires deterministically.
    let oversized = "x".repeat(20 * 1024);
    seed_skill(&project, "alice.tools", "too-big", &oversized);

    let output = lpm(&project)
        .args(["skills", "validate"])
        .output()
        .expect("failed to run lpm skills validate");

    // NOTE (finding #72 in private/findings.md): validate always exits 0
    // even when errors exist. Assert on the error message instead of the
    // exit code; tighten this test once validate becomes fail-closed.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("15KB") || combined.contains("exceed") || combined.contains("limit"),
        "validate output must mention the size limit, got:\n{combined}",
    );
}

#[test]
fn skills_validate_with_no_skills_dir_succeeds_quietly() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["skills", "validate"])
        .output()
        .expect("failed to run lpm skills validate");

    assert!(
        output.status.success(),
        "validate on a project without .lpm/skills/ must succeed"
    );
}

// ─── clean ────────────────────────────────────────────────────────────

#[test]
fn skills_clean_removes_skills_directory_and_reports_count() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    seed_skill(&project, "alice.tools", "a", "# a\n");
    seed_skill(&project, "alice.tools", "b", "# b\n");
    seed_skill(&project, "bob.helpers", "c", "# c\n");

    assert!(
        project.file_exists(".lpm/skills/alice.tools/a.md"),
        "preconditions"
    );

    let output = lpm(&project)
        .args(["--json", "skills", "clean"])
        .output()
        .expect("failed to run lpm skills clean");

    assert!(output.status.success(), "skills clean must succeed");

    assert!(
        !project.path().join(".lpm/skills").exists(),
        ".lpm/skills/ must be removed after clean"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("skills clean --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["cleaned"], serde_json::json!(true));
    assert_eq!(
        envelope["files_removed"],
        serde_json::json!(3),
        "envelope must count removed files (3 skills): {envelope}",
    );
}

#[test]
fn skills_clean_on_empty_project_is_idempotent() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["skills", "clean"])
        .output()
        .expect("failed to run lpm skills clean");

    assert!(
        output.status.success(),
        "clean with no skills dir must succeed",
    );
}

// ─── unknown action ───────────────────────────────────────────────────

#[test]
fn skills_unknown_action_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["skills", "not-a-real-action"])
        .output()
        .expect("failed to run lpm skills bogus");

    assert!(
        !output.status.success(),
        "unknown skills action must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("list")
            && stderr.contains("install")
            && stderr.contains("validate")
            && stderr.contains("clean"),
        "stderr must list valid actions, got:\n{stderr}",
    );
}
