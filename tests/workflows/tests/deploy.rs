//! Workflow tests for `lpm deploy <output> --filter`.
//!
//! Deploy materializes one workspace member's production closure into an
//! external directory. The full happy-path also runs an install at the
//! output, which requires a mock registry; these workflow tests focus on
//! the validation/dispatch contracts that don't require network:
//!
//! - `--dry-run` writes nothing, surfaces the resolved plan
//! - filter must match exactly one member (zero or many → error)
//! - output dir must be outside the workspace
//! - output dir must be empty without `--force`
//! - human + JSON envelope shape for the dry-run path

mod support;

use support::{TempProject, lpm};

/// `lpm deploy` requires the output dir to be OUTSIDE the workspace. Use
/// the system temp area for that — every test gets a fresh tempdir.
fn external_output_dir() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("failed to create external output dir")
}

// ─── --dry-run path (no filesystem writes) ──────────────────────────────

#[test]
fn deploy_dry_run_writes_nothing_to_output_dir() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    // Snapshot output dir state before
    let entries_before: Vec<_> = std::fs::read_dir(out.path())
        .expect("read output dir")
        .collect();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy --dry-run");

    assert!(
        output.status.success(),
        "deploy --dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let entries_after: Vec<_> = std::fs::read_dir(out.path())
        .expect("read output dir")
        .collect();
    assert_eq!(
        entries_before.len(),
        entries_after.len(),
        "dry-run must not write any files to the output dir",
    );
}

#[test]
fn deploy_dry_run_json_envelope_carries_resolved_plan() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "--json",
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy --dry-run --json");

    assert!(
        output.status.success(),
        "deploy --dry-run --json must succeed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("deploy --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    assert_eq!(envelope["member"], serde_json::json!("@test/utils"));
    assert!(
        envelope["member_dir"].is_string(),
        "envelope must carry member_dir"
    );
    assert!(
        envelope["output_dir"].is_string(),
        "envelope must carry output_dir"
    );
}

#[test]
fn deploy_dry_run_human_output_uses_slim_ui() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy --dry-run");

    assert!(
        output.status.success(),
        "deploy --dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.trim().is_empty(),
        "human status output must stay off stdout; got:\n{stdout}"
    );
    assert!(
        stderr.contains("› Materializing production closure for @test/utils"),
        "stderr must show the slim deploy phase; got:\n{stderr}"
    );
    assert!(
        stderr.contains("output:") && stderr.contains("dry run:"),
        "stderr must show deploy details without a boxed prompt; got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · dry run complete"),
        "stderr must show the slim dry-run terminus; got:\n{stderr}"
    );
    assert!(
        !stderr.contains('│') && !stderr.contains('◇'),
        "dry-run status must not use cliclack's boxed gutter; got:\n{stderr}"
    );
}

#[test]
fn deploy_dry_run_human_output_applies_slim_color_roles_when_forced() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "--color=always",
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run colored lpm deploy --dry-run");

    assert!(
        output.status.success(),
        "colored deploy --dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\x1b[33m@test/utils")
            && stderr.contains("\x1b[2moutput:")
            && stderr.contains("\x1b[33m/")
            && stderr.contains("\x1b[32myes"),
        "deploy dry-run should color target/path/status and dim labels, got:\n{stderr:?}",
    );
}

// ─── filter must match exactly one member ──────────────────────────────

#[test]
fn deploy_filter_matching_multiple_members_fails() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/*",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy with multi-match filter");

    assert!(
        !output.status.success(),
        "deploy with multi-match filter must exit non-zero",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exactly one") || stderr.contains("multiple") || stderr.contains("3"),
        "stderr must explain the single-target requirement, got:\n{stderr}",
    );
}

#[test]
fn deploy_filter_matching_zero_members_fails() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "this-does-not-exist",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy with zero-match filter");

    assert!(
        !output.status.success(),
        "deploy with zero-match filter must exit non-zero",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no")
            || stderr.contains("zero")
            || stderr.contains("did not match")
            || stderr.contains("matched"),
        "stderr must explain the no-match condition, got:\n{stderr}",
    );
}

// ─── output dir safety ──────────────────────────────────────────────────

#[test]
fn deploy_into_workspace_directory_is_rejected() {
    let project = TempProject::from_fixture("workspace-monorepo");

    // Try to deploy INTO the workspace itself (a subdir). Deploy must
    // refuse to prevent overwriting the source.
    let inside_workspace = project.path().join("deploy-output");
    std::fs::create_dir_all(&inside_workspace).expect("create inside-workspace dir");

    let output = lpm(&project)
        .args([
            "deploy",
            inside_workspace.to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy into workspace");

    assert!(
        !output.status.success(),
        "deploy into the workspace tree must be rejected",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workspace") || stderr.contains("outside"),
        "stderr must explain the outside-workspace requirement, got:\n{stderr}",
    );
}

#[test]
fn deploy_into_nonempty_dir_without_force_is_rejected() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    // Seed a file in the output dir.
    std::fs::write(out.path().join("existing.txt"), b"hello").expect("seed existing file");

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy into non-empty dir");

    assert!(
        !output.status.success(),
        "deploy into non-empty dir without --force must be rejected",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not empty") || stderr.contains("--force") || stderr.contains("empty"),
        "stderr must explain the empty-dir requirement, got:\n{stderr}",
    );

    // The existing file must be untouched.
    let content = std::fs::read(out.path().join("existing.txt")).expect("read existing.txt");
    assert_eq!(content, b"hello", "existing file must not be modified");
}

#[test]
fn deploy_outside_workspace_context_fails() {
    // Bare project (no workspaces) — deploy makes no sense.
    let project = TempProject::empty(r#"{"name":"single","version":"1.0.0"}"#);
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "single",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy outside workspace");

    assert!(
        !output.status.success(),
        "deploy outside a workspace must exit non-zero",
    );
}
