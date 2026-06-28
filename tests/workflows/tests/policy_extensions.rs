//! Workflow tests for install-time policy extensions.

mod support;

use support::assertions;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

const POLICY_PACKAGE: &str = "policy-pkg";
const POLICY_VERSION: &str = "1.0.0";

#[tokio::test]
async fn install_policy_extension_enforce_blocks_package_candidate_before_linking() {
    let mock = MockRegistry::start().await;
    mount_policy_package(&mock).await;
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "policy-extension-enforce",
  "version": "1.0.0",
  "dependencies": {{ "{POLICY_PACKAGE}": "{POLICY_VERSION}" }}
}}"#
    ));
    write_policy_extension_config(
        &project,
        &policy_extension_command(&[
            "--action",
            "block",
            "--name",
            POLICY_PACKAGE,
            "--version",
            POLICY_VERSION,
            "--code",
            "deny-list",
            "--reason",
            "matched local fixture feed",
        ]),
        "enforce",
        None,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run install with policy extension");

    assert!(
        !output.status.success(),
        "policy extension enforce mode must block install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("policy extension `fixture` blocked 1 package decision"),
        "human output must name the blocking extension; got:\n{combined}"
    );
    assert!(
        combined.contains("blocked by LPM policy extensions"),
        "error must explain the policy extension block; got:\n{combined}"
    );
    assert!(
        !project.file_exists("node_modules/policy-pkg/package.json"),
        "blocked package must not be linked"
    );
}

#[tokio::test]
async fn install_policy_extension_rejects_remote_tarball_url_dependency_before_download() {
    let mock = MockRegistry::start().await;
    mount_policy_package(&mock).await;
    let tarball_url = mock.tarball_url(POLICY_PACKAGE, POLICY_VERSION);
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "policy-extension-tarball-url",
  "version": "1.0.0",
  "dependencies": {{ "{POLICY_PACKAGE}": "{tarball_url}" }}
}}"#
    ));
    write_policy_extension_config(
        &project,
        &policy_extension_command(&["--action", "allow"]),
        "enforce",
        None,
    );

    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run install with policy extension");

    assert!(
        !output.status.success(),
        "policy extension install must reject tarball URL deps before download\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("do not support remote tarball URL dependency `policy-pkg`"),
        "error must explain the policy extension tarball URL limitation; got:\n{combined}"
    );
    assert_eq!(
        mock.tarball_request_count(POLICY_PACKAGE, POLICY_VERSION)
            .await,
        0,
        "remote tarball bytes must not be requested before policy extension evaluation"
    );
}

#[tokio::test]
async fn install_policy_extension_blocks_up_to_date_install_from_lockfile_candidates() {
    let mock = MockRegistry::start().await;
    mount_policy_package(&mock).await;
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "policy-extension-up-to-date",
  "version": "1.0.0",
  "dependencies": {{ "{POLICY_PACKAGE}": "{POLICY_VERSION}" }}
}}"#
    ));

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    write_policy_extension_config(
        &project,
        &policy_extension_command(&[
            "--action",
            "block",
            "--name",
            POLICY_PACKAGE,
            "--version",
            POLICY_VERSION,
            "--code",
            "deny-list",
            "--reason",
            "matched after warm install",
        ]),
        "enforce",
        None,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run warm install with policy extension");

    assert!(
        !output.status.success(),
        "up-to-date install must still run enforcing policy extensions\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("blocked by LPM policy extensions"),
        "warm policy block error must explain the policy extension block; got:\n{combined}"
    );
}

#[tokio::test]
async fn install_policy_extension_blocks_bare_up_to_date_fast_lane() {
    let mock = MockRegistry::start().await;
    mount_policy_package(&mock).await;
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "policy-extension-bare-fast-lane",
  "version": "1.0.0",
  "dependencies": {{ "{POLICY_PACKAGE}": "{POLICY_VERSION}" }}
}}"#
    ));

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    write_policy_extension_config(
        &project,
        &policy_extension_command(&[
            "--action",
            "block",
            "--name",
            POLICY_PACKAGE,
            "--version",
            POLICY_VERSION,
            "--code",
            "deny-list",
            "--reason",
            "matched before pre-clap fast lane exit",
        ]),
        "enforce",
        None,
    );

    let output = lpm(&project)
        .arg("install")
        .output()
        .expect("failed to run bare warm install with policy extension");

    assert!(
        !output.status.success(),
        "bare up-to-date install must not bypass enforcing policy extensions\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("blocked by LPM policy extensions"),
        "bare warm policy block error must explain the policy extension block; got:\n{combined}"
    );
}

#[tokio::test]
async fn install_policy_extension_report_mode_continues_and_reports_json_stats() {
    let mock = MockRegistry::start().await;
    mount_policy_package(&mock).await;
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "policy-extension-report",
  "version": "1.0.0",
  "dependencies": {{ "{POLICY_PACKAGE}": "{POLICY_VERSION}" }}
}}"#
    ));
    let request_log = project.path().join("policy-extension-request.json");
    write_policy_extension_config(
        &project,
        &policy_extension_command(&[
            "--action",
            "block",
            "--name",
            POLICY_PACKAGE,
            "--version",
            POLICY_VERSION,
            "--code",
            "report-only",
            "--reason",
            "reported by local fixture feed",
            "--log",
            request_log.to_str().expect("utf-8 temp path"),
        ]),
        "report",
        None,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run install with policy extension");

    assert!(
        output.status.success(),
        "report-mode policy extension must not block install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assertions::assert_in_node_modules(project.path(), POLICY_PACKAGE);

    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["timing"]["policy_extensions"]["enabled"], true);
    assert_eq!(
        envelope["timing"]["policy_extensions"]["configured_count"],
        1
    );
    assert_eq!(envelope["timing"]["policy_extensions"]["ran_count"], 1);
    assert_eq!(
        envelope["timing"]["policy_extensions"]["candidate_count"],
        1
    );
    assert_eq!(envelope["timing"]["policy_extensions"]["block_count"], 1);
    assert_eq!(
        envelope["timing"]["policy_extensions"]["extensions"][0]["mode"],
        "report"
    );
    assert_eq!(envelope["security"]["policy_extensions"]["enabled"], true);
    assert_eq!(
        envelope["security"]["policy_extensions"]["configured_count"],
        1
    );
    assert_eq!(envelope["security"]["policy_extensions"]["ran_count"], 1);

    let request: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&request_log).expect("read policy extension request log"),
    )
    .expect("request must be valid JSON");
    assert_eq!(request["schema_version"], 1);
    assert_eq!(request["event"], "package.candidate");
    assert_eq!(request["packages"][0]["name"], POLICY_PACKAGE);
    assert_eq!(request["packages"][0]["version"], POLICY_VERSION);
}

#[test]
fn install_no_dependencies_json_reports_policy_extension_stats() {
    let project =
        TempProject::empty(r#"{"name":"policy-extension-empty-install","version":"1.0.0"}"#);
    write_policy_extension_config(
        &project,
        &policy_extension_command(&["--action", "allow"]),
        "enforce",
        None,
    );

    let output = lpm(&project)
        .args(["install", "--json", "--timing"])
        .output()
        .expect("failed to run empty install with policy extension");

    assert!(
        output.status.success(),
        "empty install must succeed while reporting policy extension counters\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["no_dependencies"], true);
    assert_eq!(envelope["timing"]["policy_extensions"]["enabled"], true);
    assert_eq!(
        envelope["timing"]["policy_extensions"]["configured_count"],
        1
    );
    assert_eq!(envelope["timing"]["policy_extensions"]["ran_count"], 0);
    assert_eq!(
        envelope["timing"]["policy_extensions"]["candidate_count"],
        0
    );
    assert_eq!(envelope["security"]["policy_extensions"]["enabled"], true);
    assert_eq!(
        envelope["security"]["policy_extensions"]["configured_count"],
        1
    );
    assert_eq!(envelope["security"]["policy_extensions"]["ran_count"], 0);
}

#[test]
fn policy_list_json_reports_configured_extension() {
    let project = TempProject::empty(r#"{"name":"policy-list","version":"1.0.0"}"#);
    write_policy_extension_config(
        &project,
        &policy_extension_command(&["--action", "allow"]),
        "enforce",
        Some("block"),
    );

    let output = lpm(&project)
        .args(["policy", "list", "--json"])
        .output()
        .expect("failed to run lpm policy list");

    assert!(
        output.status.success(),
        "policy list must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = assertions::parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["enabled_count"], 1);
    assert_eq!(json["extensions"][0]["name"], "fixture");
    assert_eq!(json["extensions"][0]["mode"], "enforce");
    assert_eq!(json["extensions"][0]["on_error"], "block");
    assert_eq!(json["extensions"][0]["events"][0], "package.candidate");
    insta::assert_json_snapshot!(
        "policy_list_json_reports_configured_extension",
        normalize_policy_list_json(json)
    );
}

#[test]
fn policy_status_json_reports_configured_extension() {
    let project = TempProject::empty(r#"{"name":"policy-status","version":"1.0.0"}"#);
    write_policy_extension_config(
        &project,
        &policy_extension_command(&["--action", "allow"]),
        "enforce",
        None,
    );

    let output = lpm(&project)
        .args(["policy", "status", "--json"])
        .output()
        .expect("failed to run lpm policy status");

    assert!(
        output.status.success(),
        "policy status must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = assertions::parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["enabled"], true);
    assert_eq!(json["enabled_count"], 1);
    assert_eq!(json["enforce_count"], 1);
    assert_eq!(json["report_count"], 0);
    assert_eq!(json["no_failures"], true);
    insta::assert_json_snapshot!("policy_status_json_reports_configured_extension", json);
}

#[test]
fn policy_doctor_json_fails_when_extension_command_is_unavailable() {
    let project = TempProject::empty(r#"{"name":"policy-doctor","version":"1.0.0"}"#);
    write_policy_extension_config(
        &project,
        &[project
            .home()
            .join(".lpm")
            .join("missing-policy-extension")
            .display()
            .to_string()],
        "enforce",
        None,
    );

    let output = lpm(&project)
        .args(["policy", "doctor", "--json"])
        .output()
        .expect("failed to run lpm policy doctor");

    assert!(
        !output.status.success(),
        "policy doctor must fail when configured command is unavailable\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = assertions::parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["no_failures"], false);
    let diagnostics = json["diagnostics"]
        .as_array()
        .expect("diagnostics must be an array");
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic["code"] == "policy_extension_command_unavailable"
                && diagnostic["severity"] == "fail"
                && diagnostic["extension"] == "fixture"
        }),
        "policy doctor must emit command-unavailable diagnostic, got: {json}"
    );
    insta::assert_json_snapshot!(
        "policy_doctor_json_reports_unavailable_extension",
        normalize_policy_doctor_json(json)
    );
}

#[test]
fn policy_test_sends_package_candidate_to_named_extension() {
    let project = TempProject::empty(r#"{"name":"policy-test","version":"1.0.0"}"#);
    let request_log = project.path().join("policy-test-request.json");
    write_policy_extension_config(
        &project,
        &policy_extension_command(&[
            "--action",
            "warn",
            "--name",
            "react",
            "--version",
            "19.0.0",
            "--code",
            "fixture-warning",
            "--reason",
            "synthetic policy test",
            "--log",
            request_log.to_str().expect("utf-8 temp path"),
        ]),
        "enforce",
        None,
    );

    let output = lpm(&project)
        .args([
            "policy",
            "test",
            "fixture",
            "--package",
            "react@19.0.0",
            "--json",
        ])
        .output()
        .expect("failed to run lpm policy test");

    assert!(
        output.status.success(),
        "policy test must succeed for a valid extension response\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = assertions::parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["extension"], "fixture");
    assert_eq!(json["package"]["name"], "react");
    assert_eq!(json["package"]["version"], "19.0.0");
    assert_eq!(json["warn_count"], 1);
    assert_eq!(json["decisions"][0]["action"], "warn");
    insta::assert_json_snapshot!("policy_test_json_reports_warn_decision", json, {
        ".duration_ms" => "[DURATION]"
    });

    let request: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&request_log).expect("read policy test request log"),
    )
    .expect("request must be valid JSON");
    assert_eq!(request["event"], "package.candidate");
    assert_eq!(request["packages"][0]["name"], "react");
    assert_eq!(request["packages"][0]["version"], "19.0.0");
}

#[test]
fn doctor_json_includes_policy_extension_summary_code() {
    let project = TempProject::empty(r#"{"name":"policy-doctor-main","version":"1.0.0"}"#);
    write_policy_extension_config(
        &project,
        &policy_extension_command(&["--action", "allow"]),
        "enforce",
        None,
    );

    let output = lpm(&project)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor");

    let json = assertions::parse_json_output(&output.stdout);
    let checks = json["checks"].as_array().expect("checks must be an array");
    assert!(
        checks.iter().any(|check| {
            check["code"] == "policy_extensions_configured" && check["severity"] == "pass"
        }),
        "doctor must include policy extension summary check, got: {json}"
    );
}

async fn mount_policy_package(mock: &MockRegistry) {
    let tarball = make_tarball(POLICY_PACKAGE, POLICY_VERSION);
    mock.with_package(POLICY_PACKAGE, POLICY_VERSION, &tarball)
        .await;
}

fn policy_extension_command(args: &[&str]) -> Vec<String> {
    let mut command = Vec::with_capacity(args.len() + 1);
    command.push(
        assert_cmd::cargo::cargo_bin("workflows-policy-extension")
            .display()
            .to_string(),
    );
    command.extend(args.iter().map(|arg| (*arg).to_string()));
    command
}

fn write_policy_extension_config(
    project: &TempProject,
    command: &[String],
    mode: &str,
    on_error: Option<&str>,
) {
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).expect("create isolated lpm home");

    let mut extension = toml::map::Map::new();
    extension.insert(
        "command".to_string(),
        toml::Value::Array(command.iter().cloned().map(toml::Value::String).collect()),
    );
    extension.insert("mode".to_string(), toml::Value::String(mode.to_string()));
    if let Some(on_error) = on_error {
        extension.insert(
            "on-error".to_string(),
            toml::Value::String(on_error.to_string()),
        );
    }

    let mut extensions = toml::map::Map::new();
    extensions.insert("fixture".to_string(), toml::Value::Table(extension));

    let mut policy = toml::map::Map::new();
    policy.insert("extensions".to_string(), toml::Value::Table(extensions));

    let mut root = toml::map::Map::new();
    root.insert("policy".to_string(), toml::Value::Table(policy));

    std::fs::write(
        lpm_dir.join("config.toml"),
        toml::to_string_pretty(&toml::Value::Table(root)).expect("serialize policy config"),
    )
    .expect("write isolated policy extension config");
}

fn normalize_policy_list_json(mut json: serde_json::Value) -> serde_json::Value {
    if let Some(extensions) = json["extensions"].as_array_mut() {
        for extension in extensions {
            extension["command"] = serde_json::json!(["[POLICY_EXTENSION_FIXTURE]"]);
        }
    }
    json
}

fn normalize_policy_doctor_json(mut json: serde_json::Value) -> serde_json::Value {
    if let Some(diagnostics) = json["diagnostics"].as_array_mut() {
        for diagnostic in diagnostics {
            if diagnostic["code"] == "policy_extension_command_unavailable" {
                diagnostic["detail"] = serde_json::Value::String(
                    "`fixture` command unavailable: [MISSING_POLICY_EXTENSION]".to_string(),
                );
            }
        }
    }
    json
}
