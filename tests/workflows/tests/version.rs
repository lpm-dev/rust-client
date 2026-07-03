mod support;

use support::assertions::parse_json_output;
use support::{TempProject, lpm};

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

fn redact_version_paths(json: &mut serde_json::Value) {
    json["plan"]["packages"][0]["path"] = serde_json::json!("[PROJECT]");
    json["plan"]["packages"][0]["manifest_path"] = serde_json::json!("[PACKAGE_JSON]");
    json["plan"]["files"][0]["path"] = serde_json::json!("[PACKAGE_JSON]");
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
