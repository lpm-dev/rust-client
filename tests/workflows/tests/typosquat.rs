mod support;

use support::assertions::parse_json_output;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry, write_signed_typosquat_guard_posture};

fn enable_typosquat_guard(project: &TempProject) {
    lpm(project)
        .args(["config", "typosquat", "--set", "on"])
        .assert()
        .success();
}

#[tokio::test]
async fn install_default_allows_suspicious_package_name_without_approval() {
    let mock = MockRegistry::start().await;
    mock.with_package("axois", "1.0.0", &make_tarball("axois", "1.0.0"))
        .await;
    let project = TempProject::empty(r#"{"name":"default-guard","version":"1.0.0"}"#);

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "axois",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    assert!(project.file_exists("node_modules/axois/package.json"));
    assert!(project.read_file("package.json").contains("axois"));
}

#[test]
fn install_json_rejects_new_cli_arg_typosquat_before_manifest_mutation() {
    let project =
        TempProject::empty(r#"{"name":"typosquat-cli","version":"1.0.0","dependencies":{}}"#);

    enable_typosquat_guard(&project);

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
    assert_eq!(json["schema_version"], serde_json::json!(1));
    assert_eq!(json["error_code"], "typosquat_suspected");
    assert_eq!(json["error"]["findings"][0]["package"], "axois");
    assert_eq!(json["error"]["findings"][0]["similar_to"], "axios");
    assert_eq!(
        json["error"]["findings"][0]["technique"],
        "adjacent_transposition"
    );
    assert_eq!(json["next_steps"][0]["command"], "lpm install axios");
    assert!(
        !project.read_file("package.json").contains("axois"),
        "guard must run before package.json is mutated"
    );

    let mut snapshot = json;
    snapshot["error"]["config_path"] = serde_json::json!("[PROJECT]/lpm.toml");
    insta::assert_json_snapshot!(snapshot, @r###"
        {
          "schema_version": 1,
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
          },
          "next_steps": [
            {
              "description": "Install the suggested package",
              "command": "lpm install axios"
            }
          ]
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

    enable_typosquat_guard(&project);

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
async fn install_json_allows_manifest_alias_whose_local_name_resembles_target() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("vite", "1.0.0");
    mock.with_package("vite", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-alias",
            "version":"1.0.0",
            "dependencies":{"vite7":"npm:vite@1.0.0"}
        }"#,
    );

    enable_typosquat_guard(&project);

    let output = lpm_with_registry(&project, &mock.url())
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
        "an npm alias must analyze its canonical target rather than its local key\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert!(project.file_exists("lpm.lock"));
}

#[test]
fn install_json_rejects_manifest_alias_with_suspicious_registry_target() {
    let project = TempProject::empty(
        r#"{
            "name":"typosquat-alias-target",
            "version":"1.0.0",
            "dependencies":{"http-client":"npm:axois@1.0.0"}
        }"#,
    );

    enable_typosquat_guard(&project);

    let output = lpm(&project)
        .args(["install", "--json"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "a suspicious npm alias target must fail before resolver/network\nstdout: {}\nstderr: {}",
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

#[test]
fn install_json_force_floor_keeps_typosquat_guard_enabled_against_env_disable() {
    let project = TempProject::empty(
        r#"{
            "name":"typosquat-force-floor",
            "version":"1.0.0",
            "dependencies":{"axois":"^1.0.0"}
        }"#,
    );
    let config_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&config_dir).expect("create isolated LPM_HOME");
    std::fs::write(
        config_dir.join("config.toml"),
        "force-security-floor = true\n",
    )
    .expect("seed force floor config");

    enable_typosquat_guard(&project);

    let output = lpm(&project)
        .env("LPM_TYPOSQUAT_GUARD", "off")
        .args(["install", "--json"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "force floor must keep typosquat analysis enabled despite env override\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], "typosquat_suspected");
    assert_eq!(json["error"]["findings"][0]["package"], "axois");
}

#[tokio::test]
async fn install_json_global_config_can_disable_manifest_typosquat_analysis() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("axois", "1.0.0");
    mock.with_package("axois", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-config-disabled",
            "version":"1.0.0",
            "dependencies":{"axois":"^1.0.0"}
        }"#,
    );
    let config_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&config_dir).expect("create isolated LPM_HOME");
    std::fs::write(
        config_dir.join("config.toml"),
        "typosquat-guard = \"off\"\n",
    )
    .expect("seed global typosquat config");
    write_signed_typosquat_guard_posture(&project, "off");

    let output = lpm_with_registry(&project, &mock.url())
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
        "config-disabled typosquat analysis should allow install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert!(project.file_exists("lpm.lock"));
}

#[test]
fn install_json_global_config_off_requires_security_approval_after_approved_enable() {
    let project = TempProject::empty(
        r#"{
            "name":"typosquat-config-unapproved",
            "version":"1.0.0",
            "dependencies":{"axois":"^1.0.0"}
        }"#,
    );
    write_signed_typosquat_guard_posture(&project, "on");
    let config_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&config_dir).expect("create isolated LPM_HOME");
    std::fs::write(
        config_dir.join("config.toml"),
        "typosquat-guard = \"off\"\n",
    )
    .expect("seed global typosquat config");

    let output = lpm(&project)
        .args(["install", "--json"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "unapproved typosquat-guard off must require security approval\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], "security_approval_required");
}

#[tokio::test]
async fn install_json_allows_known_legitimate_prismjs_package() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("prismjs", "1.0.0");
    mock.with_package("prismjs", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-legitimate",
            "version":"1.0.0",
            "dependencies":{}
        }"#,
    );

    enable_typosquat_guard(&project);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "prismjs",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "legitimate prismjs install should pass typosquat guard\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert!(project.read_file("package.json").contains("prismjs"));
    assert!(project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_json_allows_exact_inquirer_package() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("inquirer", "1.0.0");
    mock.with_package("inquirer", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-inquirer-exact",
            "version":"1.0.0",
            "dependencies":{}
        }"#,
    );

    enable_typosquat_guard(&project);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "inquirer",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install inquirer");

    assert!(
        output.status.success(),
        "exact inquirer install should pass typosquat guard\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert!(project.read_file("package.json").contains("inquirer"));
    assert!(project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_json_allows_popular_clean_enquirer_package() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("enquirer", "1.0.0");
    mock.with_package("enquirer", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-enquirer-legitimate",
            "version":"1.0.0",
            "dependencies":{}
        }"#,
    );

    enable_typosquat_guard(&project);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "enquirer",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install enquirer");

    assert!(
        output.status.success(),
        "popular clean enquirer install should pass typosquat guard\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_ne!(
        json.get("error_code"),
        Some(&serde_json::json!("typosquat_suspected"))
    );
    assert!(project.read_file("package.json").contains("enquirer"));
    assert!(project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_json_allows_popular_clean_chat_package() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("chat", "1.0.0");
    mock.with_package("chat", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-chat-legitimate",
            "version":"1.0.0",
            "dependencies":{}
        }"#,
    );

    enable_typosquat_guard(&project);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "chat",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install chat");

    assert!(
        output.status.success(),
        "popular clean chat install should pass typosquat guard\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_ne!(
        json.get("error_code"),
        Some(&serde_json::json!("typosquat_suspected"))
    );
    assert!(project.read_file("package.json").contains("chat"));
    assert!(project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_json_allows_legitimate_fsevents_package() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("fsevents", "2.3.3");
    mock.with_package("fsevents", "2.3.3", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-fsevents-legitimate",
            "version":"1.0.0",
            "dependencies":{}
        }"#,
    );

    enable_typosquat_guard(&project);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "fsevents@2.3.3",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install fsevents");

    assert!(
        output.status.success(),
        "legitimate fsevents install should pass typosquat guard\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_ne!(
        json.get("error_code"),
        Some(&serde_json::json!("typosquat_suspected"))
    );
    assert!(project.read_file("package.json").contains("fsevents"));
    assert!(project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_json_allows_legitimate_short_serve_package() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("serve", "14.2.4");
    mock.with_package("serve", "14.2.4", &tarball).await;

    let project = TempProject::empty(
        r#"{
            "name":"typosquat-serve-legitimate",
            "version":"1.0.0",
            "dependencies":{}
        }"#,
    );

    enable_typosquat_guard(&project);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "serve@14.2.4",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install serve");

    assert!(
        output.status.success(),
        "legitimate short serve install should pass typosquat guard\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_ne!(
        json.get("error_code"),
        Some(&serde_json::json!("typosquat_suspected"))
    );
    assert!(project.read_file("package.json").contains("serve"));
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

    enable_typosquat_guard(&project);

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
