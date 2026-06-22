mod support;

use support::assertions::parse_json_output;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

#[test]
fn install_json_rejects_new_cli_arg_typosquat_before_manifest_mutation() {
    let project =
        TempProject::empty(r#"{"name":"typosquat-cli","version":"1.0.0","dependencies":{}}"#);

    let output = lpm(&project)
        .args(["install", "axois", "--json"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "typosquat install must fail before network\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], "typosquat_suspected");
    assert_eq!(json["error"]["findings"][0]["package"], "axois");
    assert_eq!(json["error"]["findings"][0]["similar_to"], "axios");
    assert_eq!(
        json["error"]["findings"][0]["technique"],
        "adjacent_transposition"
    );
    assert!(
        !project.read_file("package.json").contains("axois"),
        "guard must run before package.json is mutated"
    );

    let mut snapshot = json;
    snapshot["error"]["config_path"] = serde_json::json!("[PROJECT]/lpm.toml");
    insta::assert_json_snapshot!(snapshot, @r###"
        {
          "success": false,
          "error_code": "typosquat_suspected",
          "error": {
            "code": "TYPOSQUAT_SUSPECTED",
            "message": "suspicious package name 'axois' looks like 'axios'",
            "findings": [
              {
                "package": "axois",
                "similar_to": "axios",
                "technique": "adjacent_transposition",
                "source": "cli"
              }
            ],
            "config_path": "[PROJECT]/lpm.toml",
            "allow_example": "[[policy.typosquat.allow]]\npackage = \"axois\"\nsimilar-to = \"axios\"\nreason = \"Intentional package\"",
            "suggested_command": "lpm install axios"
          }
        }
        "###);
}

#[test]
fn install_json_rejects_manifest_direct_typosquat_before_lockfile_write() {
    let project = TempProject::empty(
        r#"{
            "name":"typosquat-manifest",
            "version":"1.0.0",
            "dependencies":{"axois":"^1.0.0"}
        }"#,
    );

    let output = lpm(&project)
        .args(["install", "--json"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "manifest typosquat must fail before resolver/network\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], "typosquat_suspected");
    assert_eq!(json["error"]["findings"][0]["package"], "axois");
    assert!(!project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_json_env_can_disable_manifest_typosquat_analysis() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("axois", "1.0.0");
    mock.with_package("axois", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-env-disabled",
            "version":"1.0.0",
            "dependencies":{"axois":"^1.0.0"}
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TYPOSQUAT_GUARD", "0")
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "env-disabled typosquat analysis should allow install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert!(project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_ci_replay_allows_suspicious_direct_dependency_already_locked() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("axois", "1.0.0");
    mock.with_package("axois", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-locked",
            "version":"1.0.0",
            "dependencies":{"axois":"^1.0.0"}
        }"#,
    );
    project.write_file(
        "lpm.toml",
        r#"[[policy.typosquat.allow]]
package = "axois"
similar-to = "axios"
reason = "fixture package name"
"#,
    );

    let first = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run initial lpm install");
    assert!(
        first.status.success(),
        "allow-listed install should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(project.file_exists("lpm.lock"));
    std::fs::remove_file(project.path().join("lpm.toml")).unwrap();

    let replay = lpm_with_registry(&project, &mock.url())
        .env("CI", "true")
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run CI replay install");

    assert!(
        replay.status.success(),
        "CI replay must not fail typosquat guard when direct dep is locked\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    let json = parse_json_output(&replay.stdout);
    assert_eq!(json["success"], true);
    assert_ne!(
        json.get("error_code"),
        Some(&serde_json::json!("typosquat_suspected"))
    );
}

#[test]
fn install_json_rejects_flag_name_after_dashdash() {
    let project =
        TempProject::empty(r#"{"name":"typosquat-flag","version":"1.0.0","dependencies":{}}"#);

    let output = lpm(&project)
        .args(["--json", "install", "--", "--legacy-peer-deps"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "flag-shaped package name must fail\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], "invalid_package_name");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|message| message.contains("command-line flag")),
        "error must explain flag-shaped package names: {json}"
    );
}

#[test]
fn add_json_rejects_new_source_package_typosquat_before_fetch() {
    let project =
        TempProject::empty(r#"{"name":"typosquat-add","version":"1.0.0","dependencies":{}}"#);

    let output = lpm(&project)
        .args(["add", "axois", "--json"])
        .output()
        .expect("failed to run lpm add");

    assert!(
        !output.status.success(),
        "source add typosquat must fail before fetch\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], "typosquat_suspected");
    assert_eq!(json["error"]["findings"][0]["package"], "axois");
}
