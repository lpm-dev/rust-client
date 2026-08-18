mod support;

use support::assertions::parse_json_output;
use support::{
    LOCK_CONTENTION_MARKER_ENV, TempProject, lpm, lpm_spawnable, wait_for_lock_contention,
};

fn read_package_json(project: &TempProject, rel: &str) -> serde_json::Value {
    serde_json::from_str(&project.read_file(rel)).expect("package.json must be valid JSON")
}

fn run_git(project: &TempProject, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(project.path())
        .output()
        .unwrap_or_else(|error| panic!("failed to run git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[cfg(unix)]
fn write_git_hook(project: &TempProject, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    let relative = format!(".git/hooks/{name}");
    project.write_file(&relative, body);
    let path = project.path().join(relative);
    let mut permissions = std::fs::metadata(&path)
        .expect("read Git hook metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).expect("make Git hook executable");
}

fn redact_version_paths(json: &mut serde_json::Value) {
    json["plan"]["packages"][0]["path"] = serde_json::json!("[PROJECT]");
    json["plan"]["packages"][0]["manifest_path"] = serde_json::json!("[PACKAGE_JSON]");
    json["plan"]["files"][0]["path"] = serde_json::json!("[PACKAGE_JSON]");
}

fn initialized_git_project() -> TempProject {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "initial"]);
    project
}

#[test]
fn version_no_git_tag_updates_package_json_without_running_version_script() {
    let manifest = serde_json::json!({
        "name": "demo",
        "version": "1.2.3",
        "scripts": {
            "version": "node -e \"require('fs').writeFileSync('script-ran','yes')\""
        }
    })
    .to_string();
    let project = TempProject::empty(&manifest);

    let output = lpm(&project)
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .expect("failed to run lpm version");

    assert!(
        output.status.success(),
        "lpm version failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let package = read_package_json(&project, "package.json");
    assert_eq!(package["version"], "1.2.4");
    assert!(
        !project.file_exists("script-ran"),
        "built-in lpm version must win over a package.json version script"
    );
}

#[test]
fn version_recovers_an_interrupted_manifest_transaction_before_replanning() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_MANIFEST_WRITES", "1")
        .args(["version", "major", "--no-git-tag-version"])
        .output()
        .expect("run version with crash injection");
    assert!(!interrupted.status.success());

    let recovered = lpm(&project)
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .expect("run version after interrupted transaction");

    assert!(
        recovered.status.success(),
        "version did not recover before replanning\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.4"
    );
    assert!(
        !project
            .path()
            .join(".lpm/release-apply/journal.json")
            .exists()
    );
}

#[test]
fn version_no_git_retry_after_durable_commit_does_not_bump_twice() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_COMMIT", "1")
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .expect("interrupt version after durable commit");
    assert!(!interrupted.status.success());

    let recovered = lpm(&project)
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .expect("retry version after durable commit");

    assert!(
        recovered.status.success(),
        "version did not recover durable completion\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.4"
    );
}

#[test]
fn version_from_a_sibling_does_not_consume_another_members_completed_retry() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0"}"#,
    );
    let mut core_version = lpm(&project);
    core_version.current_dir(project.path().join("packages/core"));
    let interrupted = core_version
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_COMMIT", "1")
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .expect("interrupt core version after durable commit");
    assert!(!interrupted.status.success());

    let mut app_version = lpm(&project);
    app_version.current_dir(project.path().join("packages/app"));
    let output = app_version
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .expect("version sibling after core completion");

    assert!(
        output.status.success(),
        "sibling version was mistaken for core retry\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.0.1"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["version"],
        "1.0.1"
    );
}

#[test]
fn version_from_a_workspace_member_recovers_the_root_release_transaction() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.2.3"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"core":"^1.2.3"}}"#,
    );
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_MANIFEST_WRITES", "1")
        .args([
            "release", "apply", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .expect("interrupt root release apply");
    assert!(!interrupted.status.success());
    let mut command = lpm(&project);
    command.current_dir(project.path().join("packages/core"));

    let recovered = command
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .expect("run version from workspace member");

    assert!(
        recovered.status.success(),
        "member version did not recover the root transaction\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.4"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^1.2.3"
    );
}

#[test]
fn version_dry_run_json_reports_plan_without_mutating_manifest() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);

    let output = lpm(&project)
        .args([
            "version",
            "patch",
            "--dry-run",
            "--json",
            "--no-git-tag-version",
        ])
        .output()
        .expect("failed to run lpm version --json");

    assert!(
        output.status.success(),
        "lpm version --json failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut json = parse_json_output(&output.stdout);
    redact_version_paths(&mut json);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": true,
      "dry_run": true,
      "git_tag_version": false,
      "commit": null,
      "tag": null,
      "plan": {
        "success": true,
        "dry_run": true,
        "packages": [
          {
            "name": "demo",
            "path": "[PROJECT]",
            "manifest_path": "[PACKAGE_JSON]",
            "old_version": "1.2.3",
            "new_version": "1.2.4",
            "bump": "patch"
          }
        ],
        "dependency_updates": [],
        "files": [
          {
            "path": "[PACKAGE_JSON]",
            "changes": 1
          }
        ]
      }
    }
    "###);
    let package = read_package_json(&project, "package.json");
    assert_eq!(package["version"], "1.2.3");
}

#[test]
fn version_dry_run_plans_from_one_locked_manifest_generation() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock =
        lpm_common::acquire_exclusive_lock(&lock_path).expect("hold the project transaction lock");
    let marker_path = project.home().join("version-dry-run-lock-contention");
    let mut command = lpm_spawnable(&project);
    command.env(LOCK_CONTENTION_MARKER_ENV, &marker_path).args([
        "version",
        "minor",
        "--dry-run",
        "--json",
        "--no-git-tag-version",
    ]);
    let mut child = command.spawn().expect("spawn contending version dry-run");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    project.write_file("package.json", r#"{"name":"demo","version":"2.0.0"}"#);
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish version dry-run");
    assert!(
        output.status.success(),
        "version dry-run failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["plan"]["packages"][0]["old_version"], "2.0.0");
    assert_eq!(json["plan"]["packages"][0]["new_version"], "2.1.0");
}

#[test]
fn version_refuses_workspace_scope_drift_while_waiting_for_the_transaction_lock() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.2.3"}"#,
    );
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock =
        lpm_common::acquire_exclusive_lock(&lock_path).expect("hold workspace transaction lock");
    let marker_path = project.home().join("version-scope-drift-lock-contention");
    let mut command = lpm_spawnable(&project);
    command
        .current_dir(project.path().join("packages/core"))
        .env(LOCK_CONTENTION_MARKER_ENV, &marker_path)
        .args(["version", "patch", "--no-git-tag-version"]);
    let mut child = command.spawn().expect("spawn contending member version");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    project.write_file(
        "package.json",
        r#"{"name":"root","private":true,"version":"0.0.0"}"#,
    );
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish member version");
    assert!(
        !output.status.success(),
        "version accepted a project that left its locked workspace"
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.3"
    );
}

#[test]
fn version_creates_git_commit_and_tag_when_git_tag_version_is_enabled() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "initial"]);

    let output = lpm(&project)
        .args(["version", "minor", "--message", "release %s"])
        .output()
        .expect("failed to run lpm version");

    assert!(
        output.status.success(),
        "lpm version failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let package = read_package_json(&project, "package.json");
    assert_eq!(package["version"], "1.3.0");
    assert_eq!(
        run_git(&project, &["log", "-1", "--pretty=%s"]),
        "release 1.3.0"
    );
    assert_eq!(run_git(&project, &["tag", "--list", "v1.3.0"]), "v1.3.0");
}

#[test]
fn version_restores_manifest_and_index_when_signed_commit_fails() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "initial"]);
    let initial_head = run_git(&project, &["rev-parse", "HEAD"]);
    let missing_signer = project.path().join("missing-gpg-program");
    run_git(
        &project,
        &[
            "config",
            "gpg.program",
            missing_signer
                .to_str()
                .expect("temporary path must be UTF-8"),
        ],
    );
    run_git(&project, &["config", "commit.gpgSign", "true"]);

    let output = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("run version with unavailable commit signer");

    assert!(!output.status.success(), "signed commit must fail");
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.3",
        "version failure was not rolled back\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(run_git(&project, &["rev-parse", "HEAD"]), initial_head);
    assert!(run_git(&project, &["diff", "--cached", "--name-only"]).is_empty());
    assert!(run_git(&project, &["tag", "--list", "v1.2.4"]).is_empty());
}

#[test]
fn version_rolls_back_commit_when_tag_ref_is_locked() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "initial"]);
    let initial_head = run_git(&project, &["rev-parse", "HEAD"]);
    project.write_file(".git/refs/tags/v1.2.4.lock", "held by another Git process");

    let output = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("run version with a locked tag ref");

    assert!(!output.status.success(), "locked tag creation must fail");
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.3",
        "tag failure was not rolled back\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(run_git(&project, &["rev-parse", "HEAD"]), initial_head);
    assert!(run_git(&project, &["diff", "--cached", "--name-only"]).is_empty());
    assert!(run_git(&project, &["tag", "--list", "v1.2.4"]).is_empty());
}

#[test]
fn version_restores_commit_when_signed_tag_fails() {
    let project = initialized_git_project();
    let initial_head = run_git(&project, &["rev-parse", "HEAD"]);
    let missing_signer = project.path().join("missing-gpg-program");
    run_git(
        &project,
        &[
            "config",
            "gpg.program",
            missing_signer
                .to_str()
                .expect("temporary path must be UTF-8"),
        ],
    );
    run_git(&project, &["config", "tag.gpgSign", "true"]);

    let output = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("run version with unavailable tag signer");

    assert!(!output.status.success(), "signed tag must fail");
    assert_eq!(run_git(&project, &["rev-parse", "HEAD"]), initial_head);
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.3"
    );
    assert!(run_git(&project, &["diff", "--cached", "--name-only"]).is_empty());
    assert!(run_git(&project, &["tag", "--list", "v1.2.4"]).is_empty());
}

#[cfg(unix)]
#[test]
fn version_rejects_files_staged_by_pre_commit_hook_without_losing_them() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    project.write_file("notes.txt", "before\n");
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "."]);
    run_git(&project, &["commit", "-m", "initial"]);
    write_git_hook(
        &project,
        "pre-commit",
        "#!/bin/sh\nprintf 'from hook\\n' > notes.txt\ngit add -- notes.txt\n",
    );

    let output = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("run version with a staging pre-commit hook");

    assert!(
        !output.status.success(),
        "hook-expanded commit must be rejected"
    );
    assert_eq!(run_git(&project, &["log", "-1", "--pretty=%s"]), "initial");
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.3"
    );
    assert!(run_git(&project, &["diff", "--cached", "--name-only"]).is_empty());
    assert_eq!(run_git(&project, &["diff", "--name-only"]), "notes.txt");
    assert_eq!(project.read_file("notes.txt"), "from hook\n");
    assert!(run_git(&project, &["tag", "--list", "v1.2.4"]).is_empty());
}

#[cfg(unix)]
#[test]
fn version_does_not_tag_head_moved_by_post_commit_hook() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "initial"]);
    let initial_head = run_git(&project, &["rev-parse", "HEAD"]);
    write_git_hook(
        &project,
        "post-commit",
        &format!("#!/bin/sh\ngit update-ref HEAD {initial_head}\n"),
    );

    let output = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("run version with a HEAD-moving post-commit hook");

    assert!(!output.status.success(), "moved HEAD must not be tagged");
    assert_eq!(run_git(&project, &["rev-parse", "HEAD"]), initial_head);
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.3"
    );
    assert!(run_git(&project, &["diff", "--cached", "--name-only"]).is_empty());
    assert!(run_git(&project, &["tag", "--list", "v1.2.4"]).is_empty());
}

#[cfg(unix)]
#[test]
fn version_json_reports_the_commit_message_rewritten_by_hook() {
    let project = initialized_git_project();
    write_git_hook(
        &project,
        "commit-msg",
        "#!/bin/sh\nprintf 'hooked version subject\\n' > \"$1\"\n",
    );

    let output = lpm(&project)
        .args(["version", "patch", "--message", "requested %s", "--json"])
        .output()
        .expect("run version with a commit-msg hook");

    assert!(
        output.status.success(),
        "version failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["commit"], "hooked version subject");
    assert_eq!(
        run_git(&project, &["log", "-1", "--pretty=%s"]),
        "hooked version subject"
    );
    assert_eq!(run_git(&project, &["tag", "--list", "v1.2.4"]), "v1.2.4");
}

#[test]
fn version_recovers_an_interruption_after_staging_without_double_bumping() {
    let project = initialized_git_project();
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_VERSION_ABORT_AFTER_GIT_STAGE", "add")
        .args(["version", "patch"])
        .output()
        .expect("interrupt version after Git add");
    assert!(!interrupted.status.success());

    let recovered = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("recover version after Git add");

    assert!(
        recovered.status.success(),
        "version recovery failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.4"
    );
    assert_eq!(run_git(&project, &["rev-list", "--count", "HEAD"]), "2");
    assert_eq!(run_git(&project, &["tag", "--list", "v1.2.4"]), "v1.2.4");
    assert!(run_git(&project, &["diff", "--cached", "--name-only"]).is_empty());
}

#[test]
fn version_recovers_an_interruption_after_commit_without_double_bumping() {
    let project = initialized_git_project();
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_VERSION_ABORT_AFTER_GIT_STAGE", "commit")
        .args(["version", "patch"])
        .output()
        .expect("interrupt version after Git commit");
    assert!(!interrupted.status.success());

    let recovered = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("recover version after Git commit");

    assert!(
        recovered.status.success(),
        "version recovery failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.4"
    );
    assert_eq!(run_git(&project, &["rev-list", "--count", "HEAD"]), "2");
    assert_eq!(run_git(&project, &["tag", "--list", "v1.2.4"]), "v1.2.4");
}

#[test]
fn version_recognizes_an_interruption_after_tag_without_double_bumping() {
    let project = initialized_git_project();
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_VERSION_ABORT_AFTER_GIT_STAGE", "tag")
        .args(["version", "patch"])
        .output()
        .expect("interrupt version after Git tag");
    assert!(!interrupted.status.success());

    let recovered = lpm(&project)
        .args(["version", "patch", "--json"])
        .output()
        .expect("recover version after Git tag");

    assert!(
        recovered.status.success(),
        "version recovery failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.4"
    );
    assert_eq!(run_git(&project, &["rev-list", "--count", "HEAD"]), "2");
    assert_eq!(run_git(&project, &["tag", "--list", "v1.2.4"]), "v1.2.4");
    assert!(!project.file_exists(".lpm/release-apply/journal.json"));
    insta::assert_json_snapshot!(parse_json_output(&recovered.stdout), @r###"
    {
      "success": true,
      "recovered": true,
      "git_tag_version": true,
      "tag": "v1.2.4"
    }
    "###);
}

#[test]
fn version_from_a_clean_workspace_member_creates_its_commit_and_tag() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.2.3"}"#,
    );
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "."]);
    run_git(&project, &["commit", "-m", "initial"]);
    let mut command = lpm(&project);
    command.current_dir(project.path().join("packages/core"));

    let output = command
        .args(["version", "patch"])
        .output()
        .expect("run version from clean workspace member");

    assert!(
        output.status.success(),
        "member version failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.4"
    );
    assert_eq!(run_git(&project, &["tag", "--list", "v1.2.4"]), "v1.2.4");
}

#[test]
fn version_ignores_internal_publish_lock_files_when_the_git_tree_is_clean() {
    let project = initialized_git_project();
    project.write_file(".lpm/.publish.lock", "");
    project.write_file(".lpm/.publish.lock.writer-intent", "");
    project.write_file(".lpm/.publish.lock.writer-queue", "");

    let output = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("run version after a publish lock was created");

    assert!(
        output.status.success(),
        "internal publish lock made the Git tree appear dirty\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.4"
    );
}

#[test]
fn version_from_a_member_refuses_unrelated_staged_workspace_changes() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.2.3"}"#,
    );
    project.write_file("notes.txt", "initial");
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "."]);
    run_git(&project, &["commit", "-m", "initial"]);
    project.write_file("notes.txt", "staged sibling edit");
    run_git(&project, &["add", "notes.txt"]);
    let mut command = lpm(&project);
    command.current_dir(project.path().join("packages/core"));

    let output = command
        .args(["version", "patch"])
        .output()
        .expect("run member version with staged sibling edit");

    assert!(!output.status.success());
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.3"
    );
    assert_eq!(
        run_git(&project, &["diff", "--cached", "--name-only"]),
        "notes.txt"
    );
    assert!(run_git(&project, &["tag", "--list", "v1.2.4"]).is_empty());
}

#[test]
fn version_refuses_to_commit_when_git_tree_is_dirty() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "initial"]);
    project.write_file("README.md", "dirty\n");

    let output = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("failed to run lpm version");

    assert!(
        !output.status.success(),
        "dirty git tree must fail before mutation"
    );
    let package = read_package_json(&project, "package.json");
    assert_eq!(package["version"], "1.2.3");
}

#[test]
fn version_refuses_existing_target_tag_before_mutating_manifest() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "initial"]);
    run_git(&project, &["tag", "v1.2.4"]);

    let output = lpm(&project)
        .args(["version", "patch"])
        .output()
        .expect("failed to run lpm version");

    assert!(
        !output.status.success(),
        "existing target tag must fail before mutation"
    );
    let package = read_package_json(&project, "package.json");
    assert_eq!(package["version"], "1.2.3");
    assert_eq!(run_git(&project, &["log", "-1", "--pretty=%s"]), "initial");
}

#[test]
fn version_refuses_dash_prefixed_tag_before_mutating_manifest() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "initial"]);

    let output = lpm(&project)
        .args(["version", "patch", "--tag-prefix", "-"])
        .output()
        .expect("failed to run lpm version");

    assert!(
        !output.status.success(),
        "dash-prefixed tag should fail before mutation"
    );
    let package = read_package_json(&project, "package.json");
    assert_eq!(package["version"], "1.2.3");
    assert_eq!(run_git(&project, &["log", "-1", "--pretty=%s"]), "initial");
}
