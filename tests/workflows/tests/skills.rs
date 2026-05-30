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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "skills list must not use cliclack gutter output, got:\n{stderr}",
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
        stdout.contains("@lpm.dev/alice.tools") && stdout.contains("@lpm.dev/bob.helpers"),
        "list must group by package, got:\n{stdout}"
    );
    assert!(
        stdout.contains("format-code.md")
            && stdout.contains("lint-rules.md")
            && stdout.contains("deploy.md"),
        "list must show each skill name, got:\n{stdout}"
    );
    // The package/skill report is stdout; the total summary is slim
    // status on stderr so callers can pipe the report without chatter.
    assert!(
        !stdout.contains("3 skills installed"),
        "summary belongs on stderr so stdout stays report-only, got:\n{stdout}"
    );
    assert!(
        !stdout.contains('\x1b'),
        "stdout must contain no ANSI escape under NO_COLOR=1, got:\n{stdout:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ 3 skills installed across 2 packages"),
        "summary must use a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "skills list must not use cliclack gutter output, got:\n{stderr}",
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
    // Validator gates: (a) YAML frontmatter required (content must
    // start with `---`), (b) total content length >= 100 chars,
    // (c) file size <= 15 KB. The pre-#72 test seeded a 40-char body
    // with no frontmatter and still passed because the validator
    // unconditionally returned Ok — the fix to fail-closed exposed
    // the fixture gap. Rebuild the skill with all three constraints
    // satisfied so we exercise the canonical happy path.
    seed_skill(
        &project,
        "alice.tools",
        "ok",
        &format!(
            "---\nname: ok\ndescription: A small but well-formed skill for the validate-happy-path test\n---\n\n{}",
            "well-formed body content. ".repeat(8),
        ),
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ 1 skill valid"),
        "validate must report a slim success line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "skills validate must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn skills_validate_rejects_skill_exceeding_size_limit() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);

    // Source enforces a 15KB max per skill file. Write 20KB so the limit
    // fires deterministically.
    let oversized = "x".repeat(20 * 1024);
    seed_skill(&project, "alice.tools", "too-big", &oversized);

    let output = lpm(&project)
        .args(["skills", "validate"])
        .output()
        .expect("failed to run lpm skills validate");

    // Contract: a non-empty error set must exit non-zero,
    // so CI gates that run `lpm skills validate` fail closed. The
    // exit code AND the surfaced message are both load-bearing —
    // exit-only would let a future regression scrub the per-skill
    // warning without notice, message-only is what the pre-fix test
    // settled for and let the 0-exit regression sit for a tranche.
    assert_eq!(
        output.status.code(),
        Some(1),
        "validate must exit 1 on size-limit violation (got code={:?}, \
         stdout={:?}, stderr={:?})",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("15KB") || combined.contains("exceed") || combined.contains("limit"),
        "validate output must surface the per-skill size-limit warning, got:\n{combined}",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "skills validate must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn skills_validate_json_reports_success_false_and_exits_non_zero_on_error() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);

    // 20KB skill file triggers the 15KB size-limit branch in
    // `validate_skills`. The JSON envelope must (a) carry
    // `success: false` so agents that parse stdout can branch on
    // failure, (b) keep the per-skill `errors` list intact, and
    // (c) exit non-zero so `$?`-style CI gates pick up the failure.
    let oversized = "x".repeat(20 * 1024);
    seed_skill(&project, "alice.tools", "too-big", &oversized);

    let output = lpm(&project)
        .args(["--json", "skills", "validate"])
        .output()
        .expect("failed to run lpm --json skills validate");

    assert_eq!(
        output.status.code(),
        Some(1),
        "--json validate must exit 1 alongside success=false; \
         got code={:?}, stdout={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json validate must emit one valid JSON envelope on stdout: {e}\n---\n{stdout}")
    });

    assert_eq!(
        envelope["success"],
        serde_json::json!(false),
        "envelope success must mirror error presence: {envelope}",
    );
    let errors = envelope["errors"]
        .as_array()
        .expect("envelope must carry an `errors` array");
    assert_eq!(
        errors.len(),
        1,
        "envelope must list the one size-limit error: {envelope}",
    );
    let error_text = errors[0]
        .as_str()
        .expect("each error entry must be a string");
    assert!(
        error_text.contains("15KB") || error_text.contains("limit"),
        "error text must name the violated limit, got {error_text:?}",
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! No .lpm/skills/ directory found"),
        "validate without a skills dir must use a slim warning, got:\n{stderr}",
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! No skills to clean"),
        "clean with no skills dir must use a slim warning, got:\n{stderr}",
    );
}

#[test]
fn skills_clean_human_removes_skills_directory_with_slim_completion() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    seed_skill(&project, "alice.tools", "a", "# a\n");
    seed_skill(&project, "alice.tools", "b", "# b\n");

    let output = lpm(&project)
        .args(["skills", "clean"])
        .output()
        .expect("failed to run lpm skills clean");

    assert!(output.status.success(), "skills clean must succeed");
    assert!(
        !project.path().join(".lpm/skills").exists(),
        ".lpm/skills/ must be removed after clean"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Skills cleaned · removed 2 files"),
        "clean must report a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "skills clean must not use cliclack gutter output, got:\n{stderr}",
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
