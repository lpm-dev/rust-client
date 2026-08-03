mod support;

use support::mock_registry::{MockRegistry, make_tarball_with_files};
use support::{TempProject, lpm_with_registry};

#[tokio::test]
async fn install_jsr_specifier_fetches_folded_npm_package_from_jsr_registry() {
    let registry = MockRegistry::start().await;
    let tarball = make_tarball_with_files(
        "@jsr/std__path",
        "1.1.6",
        &[("index.js", b"exports.basename = () => 'ok';\n")],
    );
    registry
        .with_package("@jsr/std__path", "1.1.6", &tarball)
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "jsr-native-install",
  "version": "1.0.0",
  "dependencies": {
    "@std/path": "jsr:@std/path@1.1.6"
  }
}"#,
    );
    project.write_file(".npmrc", &format!("@jsr:registry={}\n", registry.url()));

    lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let installed = project.path().join("node_modules/@std/path/package.json");
    assert!(
        installed.exists(),
        "native jsr: dependency must install under the requested JSR alias"
    );
}

#[tokio::test]
async fn install_jsr_version_only_specifier_borrows_dependency_name() {
    let registry = MockRegistry::start().await;
    let tarball = make_tarball_with_files(
        "@jsr/std__path",
        "1.1.6",
        &[("index.js", b"exports.dirname = () => 'ok';\n")],
    );
    registry
        .with_package("@jsr/std__path", "1.1.6", &tarball)
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "jsr-version-only-install",
  "version": "1.0.0",
  "dependencies": {
    "@std/path": "jsr:1.1.6"
  }
}"#,
    );
    project.write_file(".npmrc", &format!("@jsr:registry={}\n", registry.url()));

    lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let installed = project.path().join("node_modules/@std/path/package.json");
    assert!(
        installed.exists(),
        "version-only jsr: dependency must resolve using the dependency key"
    );
}

#[tokio::test]
async fn install_workspace_member_semver_jsr_dependency_installs_alias_dependency() {
    let registry = MockRegistry::start().await;
    let tarball = make_tarball_with_files(
        "@jsr/std__path",
        "1.1.6",
        &[("index.js", b"exports.basename = () => 'from-jsr';\n")],
    );
    registry
        .with_package("@jsr/std__path", "1.1.6", &tarball)
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "jsr-workspace-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "app": "^1.0.0"
  }
}"#,
    );
    project.write_file(".npmrc", &format!("@jsr:registry={}\n", registry.url()));
    project.write_file(
        "packages/app/package.json",
        r#"{
  "name": "app",
  "version": "1.0.0",
  "main": "index.js",
  "dependencies": {
    "@std/path": "jsr:@std/path@1.1.6"
  }
}"#,
    );
    project.write_file(
        "packages/app/index.js",
        r#"module.exports = require("@std/path").basename()
"#,
    );

    lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let lockfile = lpm_lockfile::Lockfile::read_for_project(project.path())
        .expect("root lockfile projection should parse after install")
        .lockfile;
    let app = lockfile
        .packages
        .iter()
        .find(|package| package.name == "app")
        .expect("workspace member should be resolved from the seeded cache");
    assert!(
        app.dependencies.iter().any(|dep| dep == "@std/path@1.1.6"),
        "workspace member lockfile entry must retain the JSR local alias dependency; got {:?}",
        app.dependencies,
    );
    assert!(
        app.alias_dependencies
            .iter()
            .any(|[local, target]| local == "@std/path" && target == "@jsr/std__path"),
        "workspace member lockfile entry must map the JSR local alias to the npm.jsr.io package; got {:?}",
        app.alias_dependencies,
    );
    assert!(
        lockfile
            .packages
            .iter()
            .any(|package| package.name == "@jsr/std__path" && package.version == "1.1.6"),
        "normalized JSR target package must be resolved into the lockfile"
    );
}

#[test]
fn install_rejects_malformed_jsr_package_name_before_registry_fetch() {
    let project = TempProject::empty(
        r#"{
  "name": "jsr-malformed",
  "version": "1.0.0",
  "dependencies": {
    "@std/path": "jsr:@std/../path"
  }
}"#,
    );

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        !output.status.success(),
        "malformed jsr package name must fail before install"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid JSR package name") && stderr.contains("@std/../path"),
        "error must identify the malformed JSR package name; got:\n{stderr}"
    );
}
