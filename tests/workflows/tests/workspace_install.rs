//! Workflow contracts for recursive workspace installation.

mod support;

use support::{TempProject, lpm};

const INSTALL_FLAGS: &[&str] = &[
    "--no-security-summary",
    "--no-skills",
    "--no-editor-setup",
    "--no-audit-after-install",
];

fn workspace_project() -> TempProject {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{
  "name": "@fixture/core",
  "version": "1.0.0",
  "private": true
}"#,
    );
    project.write_file(
        "packages/web/package.json",
        r#"{
  "name": "@fixture/web",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@fixture/core": "workspace:*"
  }
}"#,
    );
    project.write_file(
        "packages/unrelated/package.json",
        r#"{
  "name": "@fixture/unrelated",
  "version": "1.0.0",
  "private": true
}"#,
    );
    project
}

fn assert_install_succeeded(output: &std::process::Output, context: &str) {
    assert!(
        output.status.success(),
        "{context}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_target_installed(project: &TempProject, relative_dir: &str) {
    let root = project.path().join(relative_dir);
    assert!(
        root.join("lpm.lock").is_file(),
        "{} should contain lpm.lock",
        root.display(),
    );
    assert!(
        root.join("node_modules").is_dir(),
        "{} should contain node_modules",
        root.display(),
    );
    assert!(
        root.join(".lpm/install-hash").is_file(),
        "{} should contain the install hash",
        root.display(),
    );
}

fn assert_target_not_installed(project: &TempProject, relative_dir: &str) {
    let root = project.path().join(relative_dir);
    assert!(
        !root.join("lpm.lock").exists(),
        "{} should not contain lpm.lock",
        root.display(),
    );
    assert!(
        !root.join("node_modules").exists(),
        "{} should not contain node_modules",
        root.display(),
    );
}

#[test]
fn install_recursive_installs_workspace_root_and_every_member() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run explicit recursive workspace install");

    assert_install_succeeded(&output, "explicit recursive install should succeed");
    for target in ["", "packages/core", "packages/web", "packages/unrelated"] {
        assert_target_installed(&project, target);
    }
}

#[test]
fn recursive_install_resolves_workspace_protocol_to_named_root_package() {
    let project = TempProject::empty(
        r#"{
  "name": "vitepress",
  "version": "1.5.0",
  "private": true
}"#,
    );
    project.write_file("pnpm-workspace.yaml", "packages:\n  - docs\n");
    project.write_file(
        "docs/package.json",
        r#"{
  "name": "docs",
  "version": "1.0.0",
  "private": true,
  "devDependencies": {
    "vitepress": "workspace:*"
  }
}"#,
    );

    let output = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install with a member depending on the workspace root");

    assert_install_succeeded(
        &output,
        "workspace protocol should resolve a named workspace root",
    );
    let linked_manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("docs/node_modules/vitepress/package.json"))
            .expect("linked workspace root should expose its package manifest");
    assert_eq!(
        (
            linked_manifest["name"].as_str(),
            linked_manifest["version"].as_str(),
        ),
        (Some("vitepress"), Some("1.5.0")),
    );
}

#[test]
fn recursive_short_flag_before_install_installs_the_workspace() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("-r")
        .arg("install")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive workspace install through the short flag");

    assert_install_succeeded(&output, "`lpm -r install` should succeed");
    for target in ["", "packages/core", "packages/web", "packages/unrelated"] {
        assert_target_installed(&project, target);
    }
}

#[test]
fn install_recursive_from_member_widens_to_the_owning_workspace() {
    let project = workspace_project();
    let output = lpm(&project)
        .current_dir(project.path().join("packages/web"))
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run explicit recursive install from a workspace member");

    assert_install_succeeded(
        &output,
        "explicit recursion from a member should install the owning workspace",
    );
    for target in ["", "packages/core", "packages/web", "packages/unrelated"] {
        assert_target_installed(&project, target);
    }
}

#[test]
fn install_recursive_filter_includes_workspace_dependency_closure() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(["--filter", "@fixture/web"])
        .args(INSTALL_FLAGS)
        .output()
        .expect("run filtered recursive workspace install");

    assert_install_succeeded(
        &output,
        "filtered recursion should install the selected member and its dependencies",
    );
    assert_target_installed(&project, "packages/core");
    assert_target_installed(&project, "packages/web");
    assert_target_not_installed(&project, "");
    assert_target_not_installed(&project, "packages/unrelated");
}

#[test]
fn recursive_filter_prod_excludes_dev_only_workspace_dependencies() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@fixture/core","version":"1.0.0","private":true}"#,
    );
    project.write_file(
        "packages/tooling/package.json",
        r#"{"name":"@fixture/tooling","version":"1.0.0","private":true}"#,
    );
    project.write_file(
        "packages/web/package.json",
        r#"{
  "name": "@fixture/web",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@fixture/core": "workspace:*"
  },
  "devDependencies": {
    "@fixture/tooling": "workspace:*"
  }
}"#,
    );

    let output = lpm(&project)
        .arg("install")
        .args(["--filter-prod", "@fixture/web"])
        .args(INSTALL_FLAGS)
        .output()
        .expect("run production-filtered recursive workspace install");

    assert_install_succeeded(
        &output,
        "production filtering should retain only production workspace dependencies",
    );
    assert_target_installed(&project, "packages/core");
    assert_target_installed(&project, "packages/web");
    assert_target_not_installed(&project, "");
    assert_target_not_installed(&project, "packages/tooling");
}

#[test]
fn bare_install_at_workspace_root_installs_root_and_every_member() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("install")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run default workspace-root install");

    assert_install_succeeded(&output, "workspace-root bare install should recurse");
    for target in ["", "packages/core", "packages/web", "packages/unrelated"] {
        assert_target_installed(&project, target);
    }
}

#[test]
fn no_recursive_at_workspace_root_installs_only_the_root() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("install")
        .arg("--no-recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run root-only workspace install");

    assert_install_succeeded(&output, "root-only workspace install should succeed");
    assert_target_installed(&project, "");
    for target in ["packages/core", "packages/web", "packages/unrelated"] {
        assert_target_not_installed(&project, target);
    }
}

#[test]
fn workspace_root_default_filter_includes_dependency_closure() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("install")
        .args(["--filter", "@fixture/web"])
        .args(INSTALL_FLAGS)
        .output()
        .expect("run default filtered workspace install");

    assert_install_succeeded(
        &output,
        "workspace-root default filter should install the selected dependency closure",
    );
    assert_target_installed(&project, "packages/core");
    assert_target_installed(&project, "packages/web");
    assert_target_not_installed(&project, "");
    assert_target_not_installed(&project, "packages/unrelated");
}

#[test]
fn pnpm_workspace_root_bare_install_recurses_by_default() {
    let project = TempProject::empty(
        r#"{
  "name": "pnpm-workspace-root",
  "version": "1.0.0",
  "private": true
}"#,
    );
    project.write_file("pnpm-workspace.yaml", "packages:\n  - packages/*\n");
    project.write_file(
        "packages/core/package.json",
        r#"{
  "name": "@fixture/core",
  "version": "1.0.0",
  "private": true
}"#,
    );

    let output = lpm(&project)
        .arg("install")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run pnpm-workspace root install");

    assert_install_succeeded(&output, "pnpm-workspace root install should recurse");
    assert_target_installed(&project, "");
    assert_target_installed(&project, "packages/core");
}

#[test]
fn bare_install_inside_member_remains_member_local() {
    let project = workspace_project();
    let output = lpm(&project)
        .current_dir(project.path().join("packages/web"))
        .arg("install")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run member-local bare install");

    assert_install_succeeded(&output, "bare install inside a member should succeed");
    assert_target_installed(&project, "packages/web");
    assert_target_not_installed(&project, "");
    assert_target_not_installed(&project, "packages/core");
    assert_target_not_installed(&project, "packages/unrelated");
}

#[test]
fn recursive_install_rejects_standalone_project() {
    let project = TempProject::empty(
        r#"{
  "name": "standalone",
  "version": "1.0.0",
  "private": true
}"#,
    );
    let output = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install outside a workspace");

    assert!(
        !output.status.success(),
        "standalone recursive install should fail\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires a workspace"),
        "error should explain the workspace requirement: {stderr}",
    );
}

#[test]
fn recursive_install_json_emits_one_workspace_envelope() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("--json")
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive workspace install with JSON output");

    assert_install_succeeded(&output, "recursive JSON install should succeed");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain one JSON value");
    assert_eq!(envelope["success"], true);
    assert_eq!(envelope["recursive"], true);
    assert_eq!(envelope["summary"]["total"], 4);
    assert_eq!(
        envelope["targets"]
            .as_array()
            .expect("targets should be an array")
            .len(),
        4,
    );

    envelope["workspace_root"] = serde_json::json!("<workspace>");
    envelope["duration_ms"] = serde_json::json!("<duration>");
    let canonical_workspace = std::fs::canonicalize(project.path())
        .expect("temporary workspace should canonicalize")
        .to_string_lossy()
        .into_owned();
    for target in envelope["targets"]
        .as_array_mut()
        .expect("targets should be an array")
    {
        let path = target["path"]
            .as_str()
            .expect("target path should be a string");
        let normalized = path.replacen(&canonical_workspace, "<workspace>", 1);
        target["path"] = serde_json::json!(normalized);
        target["duration_ms"] = serde_json::json!("<duration>");
    }

    insta::assert_json_snapshot!("recursive_install_workspace_envelope", envelope);
}

#[test]
fn recursive_install_runs_lifecycle_scripts_in_dependency_order() {
    let project = TempProject::empty(
        r#"{
  "name": "lifecycle-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "scripts": {
    "preinstall": "node record.js root"
  }
}"#,
    );
    project.write_file(
        "record.js",
        "require('fs').appendFileSync(process.argv[3] || 'lifecycle-order.txt', `${process.argv[2]}\\n`);\n",
    );
    project.write_file(
        "packages/core/package.json",
        r#"{
  "name": "@fixture/core",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "preinstall": "node ../../record.js core ../../lifecycle-order.txt"
  }
}"#,
    );
    project.write_file(
        "packages/web/package.json",
        r#"{
  "name": "@fixture/web",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@fixture/core": "workspace:*"
  },
  "scripts": {
    "preinstall": "node ../../record.js web ../../lifecycle-order.txt"
  }
}"#,
    );

    let output = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive workspace install with root lifecycle scripts");

    assert_install_succeeded(
        &output,
        "recursive install should run every selected root lifecycle",
    );
    assert_eq!(
        project.read_file("lifecycle-order.txt"),
        "core\nweb\nroot\n",
        "workspace lifecycle scripts should run dependencies before dependents and root",
    );
}

#[test]
fn recursive_install_stops_before_root_after_member_lifecycle_failure() {
    let project = TempProject::empty(
        r#"{
  "name": "failing-lifecycle-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "scripts": {
    "preinstall": "node record.js root"
  }
}"#,
    );
    project.write_file(
        "record.js",
        "require('fs').appendFileSync(process.argv[3] || 'lifecycle-order.txt', `${process.argv[2]}\\n`);\n",
    );
    project.write_file(
        "packages/core/package.json",
        r#"{
  "name": "@fixture/core",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "preinstall": "node ../../record.js core ../../lifecycle-order.txt"
  }
}"#,
    );
    project.write_file(
        "packages/web/package.json",
        r#"{
  "name": "@fixture/web",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@fixture/core": "workspace:*"
  },
  "scripts": {
    "preinstall": "node ../../record.js web ../../lifecycle-order.txt && node -e \"process.exit(23)\""
  }
}"#,
    );

    let output = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive workspace install with a failing member lifecycle");

    assert!(
        !output.status.success(),
        "member lifecycle failure should fail the recursive command\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        project.read_file("lifecycle-order.txt"),
        "core\nweb\n",
        "recursive install should stop before running the workspace root lifecycle",
    );
}

#[test]
fn recursive_install_preserves_member_trust_approval_gates() {
    let project = TempProject::empty(
        r#"{
  "name": "member-trust-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/trusted/package.json",
        r#"{
  "name": "@fixture/trusted",
  "version": "1.0.0",
  "private": true,
  "lpm": {
    "trustedDependencies": ["esbuild"]
  }
}"#,
    );

    let output = lpm(&project)
        .arg("install")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install with unapproved member trust");

    assert!(
        !output.status.success(),
        "recursive install must not bypass member trust approval\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Security approval required") && stderr.contains("trust-bulk-approve"),
        "member trust failure should retain the approval guidance: {stderr}",
    );
    assert_target_not_installed(&project, "");
    assert_target_not_installed(&project, "packages/trusted");
}
