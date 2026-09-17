//! Install options must apply to both standalone and workspace package additions.

mod support;

use support::mock_registry::{MockRegistry, make_tarball, make_tarball_with_files};
use support::{TempProject, lpm, lpm_with_registry, write_signed_unlock_for};

fn project(workspace: bool, registry: &MockRegistry) -> (TempProject, &'static str) {
    let project = TempProject::empty(if workspace {
        r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#
    } else {
        r#"{"name":"consumer","version":"1.0.0"}"#
    });
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    let target = if workspace { "packages/web" } else { "." };
    if workspace {
        project.write_file(
            "packages/web/package.json",
            r#"{"name":"web","version":"1.0.0"}"#,
        );
    }
    (project, target)
}

fn add_command(
    project: &TempProject,
    registry: &MockRegistry,
    workspace: bool,
) -> assert_cmd::Command {
    let mut command = lpm_with_registry(project, &registry.url());
    command.args(["install", "--no-skills"]);
    if workspace {
        command.args(["--filter", "web"]);
    }
    command
}

async fn assert_offline_add_rejected_without_requests(workspace: bool) {
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            "option-probe",
            "1.0.0",
            &make_tarball("option-probe", "1.0.0"),
        )
        .await;
    let (project, target) = project(workspace, &registry);
    let manifest = format!("{target}/package.json");
    let before = project.read_file(&manifest);
    add_command(&project, &registry, workspace)
        .args(["option-probe@1.0.0", "--offline"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "offline installs do not accept package specs",
        ));
    assert_eq!(project.read_file(&manifest), before);
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn standalone_add_rejects_offline_before_network_or_mutation() {
    assert_offline_add_rejected_without_requests(false).await;
}

#[tokio::test]
async fn workspace_add_rejects_offline_before_network_or_mutation() {
    assert_offline_add_rejected_without_requests(true).await;
}

async fn assert_add_linker_override(workspace: bool) {
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            "option-probe",
            "1.0.0",
            &make_tarball("option-probe", "1.0.0"),
        )
        .await;
    let (project, target) = project(workspace, &registry);
    let linker = if workspace { "hoisted" } else { "isolated" };
    add_command(&project, &registry, workspace)
        .args([
            "option-probe@1.0.0",
            "--linker",
            linker,
            "--no-security-summary",
        ])
        .assert()
        .success();
    let hash = project.read_file(&format!("{target}/.lpm/install-hash"));
    assert!(
        hash.lines().any(|line| line == format!("l:{linker}")),
        "{hash}"
    );
}

#[tokio::test]
async fn standalone_add_applies_linker_override() {
    assert_add_linker_override(false).await;
}

#[tokio::test]
async fn workspace_add_applies_linker_override() {
    assert_add_linker_override(true).await;
}

async fn assert_add_strict_integrity(workspace: bool) {
    let registry = MockRegistry::start().await;
    for name in ["option-probe", "unsigned-archive"] {
        registry
            .with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
            .await;
    }
    let (project, target) = project(workspace, &registry);
    let manifest = format!("{target}/package.json");
    let mut contents: serde_json::Value =
        serde_json::from_str(&project.read_file(&manifest)).unwrap();
    contents["dependencies"] = serde_json::json!({
        "unsigned-archive": registry.tarball_url("unsigned-archive", "1.0.0")
    });
    project.write_file(&manifest, &contents.to_string());
    let before = project.read_file(&manifest);
    add_command(&project, &registry, workspace)
        .args([
            "option-probe@1.0.0",
            "--strict-integrity",
            "--no-security-summary",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--strict-integrity"));
    assert_eq!(project.read_file(&manifest), before);
    assert_eq!(
        registry
            .tarball_request_count("unsigned-archive", "1.0.0")
            .await,
        0
    );
    add_command(&project, &registry, workspace)
        .args(["option-probe@1.0.0", "--no-security-summary"])
        .assert()
        .success();
}

#[tokio::test]
async fn standalone_add_enforces_strict_integrity_before_archive_download() {
    assert_add_strict_integrity(false).await;
}

#[tokio::test]
async fn workspace_add_enforces_strict_integrity_before_archive_download() {
    assert_add_strict_integrity(true).await;
}

async fn assert_add_security_summary_opt_out(workspace: bool) {
    let registry = MockRegistry::start().await;
    let tarball = make_tarball_with_files(
        "option-probe",
        "1.0.0",
        &[(
            "danger.js",
            b"module.exports = eval(process.env.LPM_INPUT);\n",
        )],
    );
    registry
        .with_package("option-probe", "1.0.0", &tarball)
        .await;
    for suppress in [false, true] {
        let (project, _) = project(workspace, &registry);
        lpm(&project)
            .args(["config", "source-analysis", "--set", "true"])
            .assert()
            .success();
        let mut command = add_command(&project, &registry, workspace);
        command.arg("option-probe@1.0.0");
        if suppress {
            command.arg("--no-security-summary");
        }
        let output = command.output().unwrap();
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{text}");
        assert_eq!(text.contains("Security summary"), !suppress, "{text}");
        assert_eq!(text.contains("Capabilities"), !suppress, "{text}");
    }
}

#[tokio::test]
async fn standalone_add_honors_security_summary_opt_out() {
    assert_add_security_summary_opt_out(false).await;
}

#[tokio::test]
async fn workspace_add_honors_security_summary_opt_out() {
    assert_add_security_summary_opt_out(true).await;
}

async fn assert_add_auto_build(workspace: bool) {
    let registry = MockRegistry::start().await;
    for name in ["trusted-probe", "blocked-probe"] {
        registry.with_manifest_package(
            serde_json::json!({"name":name,"version":"1.0.0","scripts":{"postinstall":"node build.js"}}),
            &[("build.js", b"require('fs').writeFileSync('built.txt', 'ok');\n")],
        ).await;
    }
    for auto_build in [false, true] {
        let (project, target) = project(workspace, &registry);
        let manifest = format!("{target}/package.json");
        let mut contents: serde_json::Value =
            serde_json::from_str(&project.read_file(&manifest)).unwrap();
        contents["lpm"] = serde_json::json!({"trustedDependencies":["trusted-probe"]});
        project.write_file(&manifest, &contents.to_string());
        write_signed_unlock_for(
            &project,
            &project.path().join(target),
            &["sandbox-none", "trust-bulk-approve"],
        );
        let mut command = add_command(&project, &registry, workspace);
        command.args([
            "trusted-probe@1.0.0",
            "blocked-probe@1.0.0",
            "--no-sandbox",
            "--no-security-summary",
        ]);
        if auto_build {
            command.arg("--auto-build");
        }
        command.assert().success();
        assert_eq!(
            project.file_exists(&format!("{target}/node_modules/trusted-probe/built.txt")),
            auto_build
        );
        assert!(!project.file_exists(&format!("{target}/node_modules/blocked-probe/built.txt")));
    }
}

#[tokio::test]
async fn standalone_add_auto_build_runs_only_approved_scripts() {
    assert_add_auto_build(false).await;
}

#[tokio::test]
async fn workspace_add_auto_build_runs_only_approved_scripts() {
    assert_add_auto_build(true).await;
}
