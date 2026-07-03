mod support;

use support::assertions::parse_json_output;
use support::{TempProject, lpm};

fn workspace_project() -> TempProject {
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
    project
}

fn stale_workspace_project() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"2.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"core":"^1.2.3"}}"#,
    );
    project
}

fn read_package_json(project: &TempProject, rel: &str) -> serde_json::Value {
    serde_json::from_str(&project.read_file(rel)).expect("package.json must be valid JSON")
}

fn redact_release_paths(json: &mut serde_json::Value) {
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            let name = package["name"].as_str().unwrap_or("pkg").to_string();
            package["path"] = serde_json::json!(format!("[{name}]"));
            package["manifest_path"] = serde_json::json!(format!("[{name}/package.json]"));
        }
    }
    if let Some(updates) = json["dependency_updates"].as_array_mut() {
        for update in updates {
            let dependent = update["dependent"].as_str().unwrap_or("pkg").to_string();
            update["manifest_path"] = serde_json::json!(format!("[{dependent}/package.json]"));
        }
    }
    if let Some(files) = json["files"].as_array_mut() {
        for file in files {
            let path = file["path"].as_str().unwrap_or_default();
            let placeholder = if path.contains("/packages/core/") {
                "[core/package.json]"
            } else if path.contains("/packages/app/") {
                "[app/package.json]"
            } else {
                "[package.json]"
            };
            file["path"] = serde_json::json!(placeholder);
        }
    }
}

fn redact_publish_paths(json: &mut serde_json::Value) {
    if let Some(results) = json["results"].as_array_mut() {
        for result in results {
            let name = result["name"].as_str().unwrap_or("pkg").to_string();
            result["path"] = serde_json::json!(format!("[{name}]"));
        }
    }
}

#[test]
fn release_plan_json_reports_bumps_and_internal_dependent_updates() {
    let project = workspace_project();

    let output = lpm(&project)
        .args([
            "release", "plan", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .expect("failed to run lpm release plan");

    assert!(
        output.status.success(),
        "lpm release plan failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut json = parse_json_output(&output.stdout);
    redact_release_paths(&mut json);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": true,
      "dry_run": true,
      "packages": [
        {
          "name": "core",
          "path": "[core]",
          "manifest_path": "[core/package.json]",
          "old_version": "1.2.3",
          "new_version": "2.0.0",
          "bump": "major"
        }
      ],
      "dependency_updates": [
        {
          "dependent": "app",
          "dependency": "core",
          "section": "dependencies",
          "manifest_path": "[app/package.json]",
          "old_spec": "^1.2.3",
          "new_spec": "^2.0.0"
        }
      ],
      "files": [
        {
          "path": "[app/package.json]",
          "changes": 1
        },
        {
          "path": "[core/package.json]",
          "changes": 1
        }
      ]
    }
    "###);
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.3"
    );
}

#[test]
fn release_apply_updates_selected_package_and_internal_dependents() {
    let project = workspace_project();

    let output = lpm(&project)
        .args([
            "release", "apply", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .expect("failed to run lpm release apply");

    assert!(
        output.status.success(),
        "lpm release apply failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut json = parse_json_output(&output.stdout);
    redact_release_paths(&mut json);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": true,
      "dry_run": false,
      "packages": [
        {
          "name": "core",
          "path": "[core]",
          "manifest_path": "[core/package.json]",
          "old_version": "1.2.3",
          "new_version": "2.0.0",
          "bump": "major"
        }
      ],
      "dependency_updates": [
        {
          "dependent": "app",
          "dependency": "core",
          "section": "dependencies",
          "manifest_path": "[app/package.json]",
          "old_spec": "^1.2.3",
          "new_spec": "^2.0.0"
        }
      ],
      "files": [
        {
          "path": "[app/package.json]",
          "changes": 1
        },
        {
          "path": "[core/package.json]",
          "changes": 1
        }
      ]
    }
    "###);
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "2.0.0"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^2.0.0"
    );
}

#[test]
fn release_publish_dry_run_reports_dependency_order() {
    let project = workspace_project();

    let output = lpm(&project)
        .args([
            "release",
            "publish",
            "--all",
            "--dry-run",
            "--json",
            "--publish-registry",
            "https://registry.example.com",
        ])
        .output()
        .expect("failed to run lpm release publish");

    assert!(
        output.status.success(),
        "lpm release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut json = parse_json_output(&output.stdout);
    redact_publish_paths(&mut json);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": true,
      "dry_run": true,
      "packages": 2,
      "results": [
        {
          "name": "core",
          "version": "1.2.3",
          "path": "[core]",
          "status": "planned"
        },
        {
          "name": "app",
          "version": "1.0.0",
          "path": "[app]",
          "status": "planned"
        }
      ]
    }
    "###);
}

#[test]
fn release_publish_refuses_stale_internal_ranges_before_publish_starts() {
    let project = stale_workspace_project();

    let output = lpm(&project)
        .args([
            "release",
            "publish",
            "--all",
            "--dry-run",
            "--json",
            "--publish-registry",
            "https://registry.example.com",
        ])
        .output()
        .expect("failed to run lpm release publish");

    assert!(!output.status.success(), "stale internal range must fail");
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert_eq!(json["error_code"], "script");
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("does not accept current workspace version 2.0.0")
    );
}
