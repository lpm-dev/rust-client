//! Workflow contracts for recursive workspace installation.

mod support;

use support::{TempProject, lpm, write_npm_firewall_global_config};

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

fn publish_directory_workspace(with_build_output: bool) -> TempProject {
    let project = TempProject::empty(
        r#"{
  "name": "publish-directory-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/library/package.json",
        r#"{
  "name": "@fixture/library",
  "version": "1.0.0",
  "publishConfig": { "directory": "build" }
}"#,
    );
    if with_build_output {
        project.write_file(
            "packages/library/build/package.json",
            r#"{
  "name": "@fixture/library",
  "version": "1.0.0",
  "main": "index.js"
}"#,
        );
        project.write_file(
            "packages/library/build/index.js",
            "module.exports = 'published';\n",
        );
    }
    project.write_file(
        "packages/app/package.json",
        r#"{
  "name": "@fixture/app",
  "version": "1.0.0",
  "private": true,
  "dependencies": { "@fixture/library": "workspace:*" }
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("link/directory dep resolves to a path outside the project tree"),
        "a declared workspace-root source is an expected cross-project link: {stderr}",
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
fn workspace_protocol_links_the_declared_publish_directory() {
    let project = publish_directory_workspace(true);

    let output = lpm(&project)
        .current_dir(project.path().join("packages/app"))
        .arg("install")
        .arg("--no-recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("install workspace package with publish directory");

    assert_install_succeeded(
        &output,
        "workspace dependency with publishConfig.directory should install",
    );
    assert_eq!(
        project.read_file("packages/app/node_modules/@fixture/library/index.js"),
        "module.exports = 'published';\n",
        "workspace dependency must expose the declared publish directory",
    );
}

#[test]
fn frozen_offline_replay_preserves_workspace_publish_directory_projection() {
    let project = publish_directory_workspace(true);
    let app_dir = project.path().join("packages/app");
    let initial = lpm(&project)
        .current_dir(&app_dir)
        .arg("install")
        .arg("--no-recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("install workspace package with publish directory");
    assert_install_succeeded(&initial, "initial workspace install should succeed");

    std::fs::remove_dir_all(app_dir.join("node_modules"))
        .expect("remove installed workspace layout before replay");
    std::fs::remove_dir_all(app_dir.join(".lpm"))
        .expect("remove materialization state before replay");

    let replay = lpm(&project)
        .current_dir(&app_dir)
        .args([
            "install",
            "--no-recursive",
            "--offline",
            "--frozen-lockfile",
        ])
        .args(INSTALL_FLAGS)
        .output()
        .expect("replay workspace publish directory from the lockfile");

    assert_install_succeeded(
        &replay,
        "frozen offline replay should preserve the workspace projection",
    );
    let link = app_dir.join("node_modules/@fixture/library");
    let link_metadata = std::fs::symlink_metadata(&link).unwrap_or_else(|error| {
        panic!(
            "frozen offline replay should recreate the workspace link at {}: {error}",
            link.display()
        )
    });
    assert!(
        link_metadata.file_type().is_symlink() || link_metadata.is_dir(),
        "replayed workspace entry should remain a directory link"
    );
    let replay_target = std::fs::read_link(&link)
        .unwrap_or_else(|error| panic!("read replayed workspace link target: {error}"));
    assert!(
        std::fs::metadata(&link).is_ok(),
        "replayed workspace link target should exist: {} -> {}",
        link.display(),
        replay_target.display()
    );
    assert_eq!(
        project.read_file("packages/app/node_modules/@fixture/library/index.js"),
        "module.exports = 'published';\n",
        "lockfile replay must expose the declared publish directory",
    );
}

#[test]
fn workspace_protocol_allows_a_publish_directory_before_build_output_exists() {
    let project = publish_directory_workspace(false);
    let app_dir = project.path().join("packages/app");
    let output = lpm(&project)
        .current_dir(&app_dir)
        .arg("install")
        .arg("--no-recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("install workspace package before its publish directory is built");

    assert_install_succeeded(
        &output,
        "workspace install should allow a not-yet-built publish directory",
    );

    #[cfg(unix)]
    {
        let link = app_dir.join("node_modules/@fixture/library");
        let metadata = std::fs::symlink_metadata(&link)
            .expect("workspace publish directory should have a dangling symlink");
        assert!(metadata.file_type().is_symlink());
        let target = std::fs::read_link(&link).expect("read workspace publish directory link");
        assert!(
            target.ends_with("library/build"),
            "workspace link should target the publish directory, got {}",
            target.display()
        );
        assert!(std::fs::metadata(link).is_err());
    }
}

#[test]
fn workspace_protocol_rejects_publish_directory_parent_traversal() {
    let project = TempProject::empty(
        r#"{
  "name": "invalid-publish-directory-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/library/package.json",
        r#"{
  "name": "@fixture/library",
  "version": "1.0.0",
  "publishConfig": { "directory": "../outside" }
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
  "name": "@fixture/app",
  "version": "1.0.0",
  "private": true,
  "dependencies": { "@fixture/library": "workspace:*" }
}"#,
    );

    let output = lpm(&project)
        .current_dir(project.path().join("packages/app"))
        .arg("install")
        .arg("--no-recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("install workspace package with invalid publish directory");

    assert!(
        !output.status.success(),
        "publish directory traversal must fail",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("publishConfig.directory") && stderr.contains("../outside"),
        "failure should identify the invalid publish directory: {stderr}",
    );
}

#[cfg(unix)]
#[test]
fn workspace_protocol_rejects_missing_publish_directory_through_symlink_escape() {
    let project = TempProject::empty(
        r#"{
  "name": "symlink-escape-publish-directory-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/library/package.json",
        r#"{
  "name": "@fixture/library",
  "version": "1.0.0",
  "publishConfig": { "directory": "projection/build" }
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
  "name": "@fixture/app",
  "version": "1.0.0",
  "private": true,
  "dependencies": { "@fixture/library": "workspace:*" }
}"#,
    );
    let outside = project.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create path outside the workspace package");
    std::os::unix::fs::symlink(&outside, project.path().join("packages/library/projection"))
        .expect("create publish-directory symlink escape");

    let output = lpm(&project)
        .current_dir(project.path().join("packages/app"))
        .arg("install")
        .arg("--no-recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("install workspace package through publish-directory symlink escape");

    assert!(!output.status.success(), "symlink escape must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("publishConfig.directory")
            && stderr.contains("resolves outside its package directory"),
        "failure should identify the publish-directory symlink escape: {stderr}",
    );
}

#[test]
fn member_install_does_not_install_workspace_root_dev_dependencies_transitively() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "devDependencies": {
    "build-only-package": "https://example.invalid/build-only-package.tgz"
  }
}"#,
    );
    project.write_file(
        "packages/member/package.json",
        r#"{
  "name": "workspace-member",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "workspace-root": "workspace:*"
  }
}"#,
    );

    let output = lpm(&project)
        .current_dir(project.path().join("packages/member"))
        .arg("install")
        .arg("--no-recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("install a member that consumes the workspace root");

    assert_install_succeeded(
        &output,
        "workspace-root devDependencies must not become member transitives",
    );
    let linked_manifest: serde_json::Value = serde_json::from_str(
        &project.read_file("packages/member/node_modules/workspace-root/package.json"),
    )
    .expect("linked workspace root should expose its package manifest");
    assert_eq!(linked_manifest["name"], "workspace-root");
}

#[test]
fn member_install_does_not_link_transitive_workspace_dev_dependencies() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/runtime/package.json",
        r#"{
  "name": "@fixture/runtime",
  "version": "1.0.0",
  "private": true,
  "devDependencies": {
    "@fixture/build-tool": "workspace:*"
  }
}"#,
    );
    project.write_file(
        "packages/build-tool/package.json",
        r#"{
  "name": "@fixture/build-tool",
  "version": "1.0.0",
  "private": true
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
  "name": "@fixture/app",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@fixture/runtime": "workspace:*"
  }
}"#,
    );

    let output = lpm(&project)
        .current_dir(project.path().join("packages/app"))
        .arg("install")
        .arg("--no-recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("install a member with a consumed workspace package");

    assert_install_succeeded(
        &output,
        "consumed workspace package devDependencies must not become transitives",
    );
    assert!(
        project
            .path()
            .join("packages/app/node_modules/@fixture/runtime")
            .exists(),
        "the direct workspace runtime dependency should be linked",
    );
    assert!(
        !project
            .path()
            .join("packages/app/node_modules/@fixture/build-tool")
            .exists(),
        "the consumed workspace package devDependency must not be linked",
    );
}

#[test]
fn repeated_recursive_install_fast_exits_members_with_a_shared_workspace_root() {
    let project = TempProject::empty(
        r#"{
  "name": "shared-workspace-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    for member in ["first", "second"] {
        project.write_file(
            &format!("packages/{member}/package.json"),
            &format!(
                r#"{{
  "name": "@fixture/{member}",
  "version": "1.0.0",
  "private": true,
  "dependencies": {{
    "shared-workspace-root": "workspace:*"
  }}
}}"#,
            ),
        );
    }

    let first = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run initial recursive install with a shared workspace root");
    assert_install_succeeded(&first, "initial recursive install should succeed");
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert!(
        !first_stderr.contains("incomplete or stale link entry"),
        "initial recursive install should keep the shared workspace-root snapshot stable: \
         {first_stderr}",
    );

    let second = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("rerun recursive install with a shared workspace root");
    assert_install_succeeded(&second, "repeated recursive install should succeed");

    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        !stderr.contains("incomplete or stale link entry"),
        "repeated recursive install should reuse the shared workspace-root link entry: {stderr}",
    );
    assert!(
        !stderr.contains("Using lockfile")
            && !stderr.contains("link/directory dep resolves to a path outside the project tree"),
        "repeated recursive install should finish before member resolution and linking: {stderr}",
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
fn repeated_recursive_json_install_reports_up_to_date_targets() {
    let project = workspace_project();
    let seed = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("seed recursive workspace install");
    assert_install_succeeded(&seed, "seed recursive install should succeed");

    let output = lpm(&project)
        .arg("--json")
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("rerun recursive workspace install with JSON output");
    assert_install_succeeded(&output, "repeated recursive JSON install should succeed");

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain one JSON value");
    assert_eq!(envelope["success"], true);
    assert_eq!(
        envelope["up_to_date"], true,
        "aggregate up_to_date should be true when every target fast-exits: {envelope}",
    );
    for target in envelope["targets"]
        .as_array()
        .expect("targets should be an array")
    {
        assert_eq!(
            target["up_to_date"], true,
            "every target should fast-exit on rerun: {target}",
        );
    }
}

#[test]
fn recursive_json_install_with_timing_reports_per_target_and_aggregate_phases() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("--json")
        .arg("install")
        .arg("--recursive")
        .arg("--timing")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive workspace install with timing telemetry");
    assert_install_succeeded(
        &output,
        "recursive JSON install with --timing should succeed",
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain one JSON value");
    let aggregate = envelope["timing"]
        .as_object()
        .expect("aggregate timing should be present with --timing");
    for phase in ["resolve_ms", "fetch_ms", "link_ms", "total_ms"] {
        assert!(
            aggregate.get(phase).is_some_and(serde_json::Value::is_u64),
            "aggregate timing should report {phase}: {envelope}",
        );
    }
    let targets = envelope["targets"]
        .as_array()
        .expect("targets should be an array");
    assert!(
        targets
            .iter()
            .any(|target| target["timing"].as_object().is_some()),
        "per-target timing should be embedded with --timing: {envelope}",
    );
}

#[test]
fn recursive_install_respects_workspace_concurrency_flag() {
    let project = workspace_project();
    let output = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .arg("--workspace-concurrency")
        .arg("1")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive workspace install with a concurrency cap");
    assert_install_succeeded(&output, "recursive install with --workspace-concurrency 1");
    for target in ["", "packages/core", "packages/web", "packages/unrelated"] {
        assert_target_installed(&project, target);
    }

    let rejected = lpm(&project)
        .arg("install")
        .arg("--recursive")
        .arg("--workspace-concurrency")
        .arg("0")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive workspace install with an invalid concurrency");
    assert!(
        !rejected.status.success(),
        "--workspace-concurrency 0 should be rejected at the CLI layer",
    );
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

// ─── Recursive workspace importer isolation ─────────────────────

use support::lpm_with_registry;
use support::mock_registry::{
    MockRegistry, compute_integrity, make_tarball, make_tarball_from_pkg_json,
};

async fn mount_registry_packages(mock: &MockRegistry, packages: &[(&str, &str)]) {
    let mut batch = Vec::with_capacity(packages.len());
    for (name, version) in packages {
        let tarball = make_tarball(name, version);
        mock.with_package(name, version, &tarball).await;
        let integrity = compute_integrity(&tarball);
        batch.push(serde_json::json!({
            "name": name,
            "dist-tags": { "latest": version },
            "versions": {
                *version: {
                    "name": name,
                    "version": version,
                    "dist": {
                        "tarball": format!("{}/tarballs/{name}/-/{name}-{version}.tgz", mock.url()),
                        "integrity": integrity,
                    },
                    "dependencies": {}
                }
            },
            "time": { *version: "2025-01-01T00:00:00.000Z" }
        }));
    }
    mock.with_batch_metadata(batch).await;
}

async fn mount_importer_context_packages(mock: &MockRegistry) {
    let parent_manifest = serde_json::json!({
        "name": "context-parent",
        "version": "1.0.0",
        "dependencies": {
            "context-child": "^1.0.0"
        }
    });
    let parent_tarball = make_tarball_from_pkg_json(parent_manifest, &[]);
    let child_v1_tarball = make_tarball("context-child", "1.0.0");
    let child_v11_tarball = make_tarball("context-child", "1.1.0");
    let parent_metadata = serde_json::json!({
        "name": "context-parent",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "context-parent",
                "version": "1.0.0",
                "dependencies": {
                    "context-child": "^1.0.0"
                },
                "dist": {
                    "tarball": mock.tarball_url("context-parent", "1.0.0"),
                    "integrity": compute_integrity(&parent_tarball)
                }
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    let child_metadata = serde_json::json!({
        "name": "context-child",
        "dist-tags": { "latest": "1.1.0" },
        "modified": "2099-01-01T00:00:00.000Z",
        "versions": {
            "1.0.0": {
                "name": "context-child",
                "version": "1.0.0",
                "dependencies": {},
                "dist": {
                    "tarball": mock.tarball_url("context-child", "1.0.0"),
                    "integrity": compute_integrity(&child_v1_tarball)
                }
            },
            "1.1.0": {
                "name": "context-child",
                "version": "1.1.0",
                "dependencies": {},
                "dist": {
                    "tarball": mock.tarball_url("context-child", "1.1.0"),
                    "integrity": compute_integrity(&child_v11_tarball)
                }
            }
        },
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z",
            "1.1.0": "2099-01-01T00:00:00.000Z"
        }
    });

    mock.with_package_metadata_and_tarballs(
        "context-parent",
        parent_metadata.clone(),
        &[("1.0.0", parent_tarball)],
    )
    .await;
    mock.with_package_metadata_and_tarballs(
        "context-child",
        child_metadata.clone(),
        &[("1.0.0", child_v1_tarball), ("1.1.0", child_v11_tarball)],
    )
    .await;
    mock.with_batch_metadata(vec![parent_metadata, child_metadata])
        .await;
}

fn peer_sensitive_workspace_project() -> TempProject {
    let project = TempProject::empty(
        r#"{
  "name": "peer-sensitive-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/with-runtime/package.json",
        r#"{
  "name": "@fixture/with-runtime",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "peer-plugin": "1.0.0",
    "peer-runtime": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/without-runtime/package.json",
        r#"{
  "name": "@fixture/without-runtime",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "peer-plugin": "1.0.0"
  }
}"#,
    );
    project
}

fn peer_sensitive_standalone_project(with_runtime: bool) -> TempProject {
    TempProject::empty(if with_runtime {
        r#"{
  "name": "peer-sensitive-standalone-with-runtime",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "peer-plugin": "1.0.0",
    "peer-runtime": "1.0.0"
  }
}"#
    } else {
        r#"{
  "name": "peer-sensitive-standalone-without-runtime",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "peer-plugin": "1.0.0"
  }
}"#
    })
}

async fn mount_peer_sensitive_workspace_packages(mock: &MockRegistry) {
    let plugin_manifest = serde_json::json!({
        "name": "peer-plugin",
        "version": "1.0.0",
        "peerDependencies": {
            "peer-runtime": "*"
        }
    });
    let plugin_tarball = make_tarball_from_pkg_json(plugin_manifest.clone(), &[]);
    let plugin_metadata = serde_json::json!({
        "name": "peer-plugin",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "peer-plugin",
                "version": "1.0.0",
                "peerDependencies": {
                    "peer-runtime": "*"
                },
                "dist": {
                    "tarball": mock.tarball_url("peer-plugin", "1.0.0"),
                    "integrity": compute_integrity(&plugin_tarball)
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });

    let runtime_v1_tarball = make_tarball("peer-runtime", "1.0.0");
    let runtime_v2_tarball = make_tarball("peer-runtime", "2.0.0");
    let runtime_metadata = serde_json::json!({
        "name": "peer-runtime",
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "1.0.0": {
                "name": "peer-runtime",
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url("peer-runtime", "1.0.0"),
                    "integrity": compute_integrity(&runtime_v1_tarball)
                },
                "dependencies": {}
            },
            "2.0.0": {
                "name": "peer-runtime",
                "version": "2.0.0",
                "dist": {
                    "tarball": mock.tarball_url("peer-runtime", "2.0.0"),
                    "integrity": compute_integrity(&runtime_v2_tarball)
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z",
            "2.0.0": "2025-01-01T00:00:00.000Z"
        }
    });

    mock.with_package_metadata_and_tarballs(
        "peer-plugin",
        plugin_metadata.clone(),
        &[("1.0.0", plugin_tarball)],
    )
    .await;
    mock.with_package_metadata_and_tarballs(
        "peer-runtime",
        runtime_metadata.clone(),
        &[("1.0.0", runtime_v1_tarball), ("2.0.0", runtime_v2_tarball)],
    )
    .await;
    mock.with_batch_metadata(vec![plugin_metadata, runtime_metadata])
        .await;
}

fn member_package_graph(project: &TempProject, member: &str) -> Vec<(String, String, Vec<String>)> {
    let lockfile = lpm_lockfile::Lockfile::read_fast(&project.path().join(member).join("lpm.lock"))
        .unwrap_or_else(|error| panic!("read {member}/lpm.lock: {error}"));
    lockfile
        .packages
        .into_iter()
        .map(|package| (package.name, package.version, package.peers))
        .collect()
}

fn member_package_version(project: &TempProject, member: &str, name: &str) -> String {
    member_package_graph(project, member)
        .into_iter()
        .find_map(|(package, version, _)| (package == name).then_some(version))
        .unwrap_or_else(|| panic!("{member}/lpm.lock should contain {name}"))
}

#[tokio::test]
async fn recursive_install_preserves_importer_local_peer_contexts_in_parallel() {
    let mock = MockRegistry::start().await;
    mount_peer_sensitive_workspace_packages(&mock).await;

    let standalone_with_runtime = peer_sensitive_standalone_project(true);
    let with_runtime_output = lpm_with_registry(&standalone_with_runtime, &mock.url())
        .arg("install")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run standalone install with a direct peer runtime");
    assert_install_succeeded(
        &with_runtime_output,
        "standalone install with a direct peer runtime should succeed",
    );
    let standalone_without_runtime = peer_sensitive_standalone_project(false);
    let without_runtime_output = lpm_with_registry(&standalone_without_runtime, &mock.url())
        .arg("install")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run standalone install without a direct peer runtime");
    assert_install_succeeded(
        &without_runtime_output,
        "standalone install without a direct peer runtime should succeed",
    );

    let expected_with_runtime = member_package_graph(&standalone_with_runtime, "");
    let expected_without_runtime = member_package_graph(&standalone_without_runtime, "");
    assert_ne!(
        expected_with_runtime, expected_without_runtime,
        "the fixture must produce distinct independent importer graphs",
    );

    for attempt in 1..=3 {
        let recursive = peer_sensitive_workspace_project();
        let recursive_output = lpm_with_registry(&recursive, &mock.url())
            .arg("install")
            .arg("--recursive")
            .args(INSTALL_FLAGS)
            .output()
            .unwrap_or_else(|error| panic!("run recursive install attempt {attempt}: {error}"));
        assert_install_succeeded(
            &recursive_output,
            &format!("recursive install attempt {attempt} should succeed"),
        );

        assert_eq!(
            member_package_graph(&recursive, "packages/with-runtime"),
            expected_with_runtime,
            "attempt {attempt} changed the importer graph that declares peer-runtime directly",
        );
        assert_eq!(
            member_package_graph(&recursive, "packages/without-runtime"),
            expected_without_runtime,
            "attempt {attempt} leaked another importer's direct peer into the peer-autoinstall graph",
        );
    }
}

#[tokio::test]
async fn recursive_install_keeps_each_member_lockfile_scoped_to_its_importer() {
    let mock = MockRegistry::start().await;
    mount_registry_packages(&mock, &[("shared-dep", "1.0.0"), ("web-only-dep", "2.0.0")]).await;

    let project = TempProject::empty(
        r#"{
  "name": "importer-scoped-root",
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
  "private": true,
  "dependencies": {
    "shared-dep": "^1.0.0"
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
    "shared-dep": "^1.0.0",
    "web-only-dep": "^2.0.0"
  }
}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install against the mock registry");
    assert_install_succeeded(&output, "recursive install should succeed");

    for member in ["packages/core", "packages/web"] {
        assert_target_installed(&project, member);
    }
    assert!(
        project
            .path()
            .join("packages/core/node_modules/shared-dep")
            .exists(),
        "core must link its shared dependency",
    );
    assert!(
        project
            .path()
            .join("packages/web/node_modules/web-only-dep")
            .exists(),
        "web must link its own dependency",
    );
    assert!(
        !project
            .path()
            .join("packages/core/node_modules/web-only-dep")
            .exists(),
        "core must not receive web's dependency from the shared resolution",
    );

    let core_lock = project.read_file("packages/core/lpm.lock");
    assert!(
        core_lock.contains("shared-dep"),
        "core lockfile must record its direct dependency: {core_lock}",
    );
    assert!(
        !core_lock.contains("web-only-dep"),
        "core lockfile must not leak web's dependency from the shared resolution: {core_lock}",
    );
    let web_lock = project.read_file("packages/web/lpm.lock");
    assert!(
        web_lock.contains("shared-dep") && web_lock.contains("web-only-dep"),
        "web lockfile must record both of its direct dependencies: {web_lock}",
    );
}

#[tokio::test]
async fn recursive_install_preserves_importer_local_overrides_with_shared_metadata() {
    let mock = MockRegistry::start().await;
    mount_importer_context_packages(&mock).await;
    let project = TempProject::empty(
        r#"{
  "name": "override-context-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/old/package.json",
        r#"{
  "name": "@fixture/old-override",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "context-parent": "1.0.0"
  },
  "lpm": {
    "minimumReleaseAgeExclude": ["context-child"],
    "overrides": {
      "context-child": "1.0.0"
    }
  }
}"#,
    );
    project.write_file(
        "packages/new/package.json",
        r#"{
  "name": "@fixture/new-override",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "context-parent": "1.0.0"
  },
  "lpm": {
    "minimumReleaseAgeExclude": ["context-child"],
    "overrides": {
      "context-child": "1.1.0"
    }
  }
}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install with importer-local overrides");
    assert_install_succeeded(&output, "recursive override install should succeed");

    assert_eq!(
        member_package_version(&project, "packages/old", "context-child"),
        "1.0.0",
    );
    assert_eq!(
        member_package_version(&project, "packages/new", "context-child"),
        "1.1.0",
    );
}

#[tokio::test]
async fn recursive_install_preserves_importer_local_release_age_policies_with_shared_metadata() {
    let mock = MockRegistry::start().await;
    mount_importer_context_packages(&mock).await;
    let project = TempProject::empty(
        r#"{
  "name": "release-age-context-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/unrestricted/package.json",
        r#"{
  "name": "@fixture/unrestricted",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "context-child": "^1.0.0"
  },
  "lpm": {
    "minimumReleaseAge": 86400,
    "minimumReleaseAgeExclude": ["context-child"]
  }
}"#,
    );
    project.write_file(
        "packages/cooldown/package.json",
        r#"{
  "name": "@fixture/cooldown",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "context-child": "^1.0.0"
  },
  "lpm": {
    "minimumReleaseAge": 86400
  }
}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install with importer-local release-age policies");
    assert_install_succeeded(&output, "recursive release-age install should succeed");

    assert_eq!(
        member_package_version(&project, "packages/unrestricted", "context-child"),
        "1.1.0",
    );
    assert_eq!(
        member_package_version(&project, "packages/cooldown", "context-child"),
        "1.0.0",
    );
}

#[tokio::test]
async fn recursive_install_commits_no_importer_when_root_firewall_blocks() {
    let mock = MockRegistry::start().await;
    mount_registry_packages(
        &mock,
        &[("member-allowed", "1.0.0"), ("root-blocked", "1.0.0")],
    )
    .await;
    mock.with_npm_firewall_allow_expected("member-allowed", "1.0.0", 0..=1)
        .await;
    mock.with_npm_firewall_block("root-blocked", "1.0.0").await;

    let project = TempProject::empty(
        r#"{
  "name": "firewall-ordered-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "root-blocked": "^1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/member/package.json",
        r#"{
  "name": "@fixture/member",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "member-allowed": "^1.0.0"
  }
}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");

    let output = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install with a blocked root dependency");

    assert!(
        !output.status.success(),
        "root firewall block must fail recursive install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("blocked by LPM npm firewall"),
        "recursive root error must retain firewall guidance: {combined}",
    );
    assert_target_not_installed(&project, "packages/member");
    assert_target_not_installed(&project, "");
    assert_eq!(
        mock.tarball_request_count("root-blocked", "1.0.0").await,
        0,
        "firewall must block the root tarball before resolve-ahead fetch overlap",
    );
}

#[tokio::test]
async fn recursive_firewall_preflight_does_not_launch_importer_local_tarball_waterfalls() {
    let mock = MockRegistry::start().await;
    mount_registry_packages(
        &mock,
        &[("member-allowed", "1.0.0"), ("root-allowed", "1.0.0")],
    )
    .await;
    mock.with_npm_firewall_allow("member-allowed", "1.0.0")
        .await;
    mock.with_npm_firewall_allow("root-allowed", "1.0.0").await;

    let project = TempProject::empty(
        r#"{
  "name": "firewall-waterfall-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "root-allowed": "^1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/member/package.json",
        r#"{
  "name": "@fixture/firewall-waterfall-member",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "member-allowed": "^1.0.0"
  }
}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_TIMING_DETAIL", "1")
        .env("LPM_FETCH_OVERLAP_MIN_SELECTED", "1")
        .arg("install")
        .arg("--recursive")
        .arg("--json")
        .arg("--timing")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install with importer-scoped firewall preflights");
    assert_install_succeeded(
        &output,
        "recursive firewall install should serialize importer-local materialization",
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("recursive install must emit JSON");
    let targets = report["targets"]
        .as_array()
        .expect("recursive report must contain targets");
    assert!(
        targets.iter().all(|target| {
            target["timing"]["detail"]["fetch"]["overlap"]["dispatched_count"].as_u64() == Some(0)
        }),
        "firewall-scoped importers must not launch competing tarball waterfalls: {report:#}"
    );
}

#[tokio::test]
async fn recursive_firewall_fetch_failure_commits_no_importer() {
    let mock = MockRegistry::start().await;
    mount_registry_packages(&mock, &[("member-allowed", "1.0.0")]).await;
    mock.with_full_package_metadata(
        "root-missing-tarball",
        "1.0.0",
        &[("1.0.0", serde_json::json!({}), None)],
    )
    .await;
    mock.with_npm_firewall_allow("member-allowed", "1.0.0")
        .await;
    mock.with_npm_firewall_allow("root-missing-tarball", "1.0.0")
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "firewall-fetch-failure-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "root-missing-tarball": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/member/package.json",
        r#"{
  "name": "@fixture/firewall-fetch-failure-member",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "member-allowed": "1.0.0"
  }
}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive firewall install with a missing root tarball");
    assert!(
        !output.status.success(),
        "recursive install must fail when an importer cannot materialize its graph\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert_target_not_installed(&project, "packages/member");
    assert_target_not_installed(&project, "");
}

#[tokio::test]
async fn warm_recursive_replay_preserves_each_importers_root_links_and_bin_shims() {
    let mock = MockRegistry::start().await;
    let shared_manifest = serde_json::json!({
        "name": "shared-tool",
        "version": "1.0.0",
        "bin": {
            "shared-tool": "cli.js"
        }
    });
    let shared_tarball = make_tarball_from_pkg_json(
        shared_manifest.clone(),
        &[("cli.js", b"#!/usr/bin/env node\n")],
    );
    let shared_metadata = serde_json::json!({
        "name": "shared-tool",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "shared-tool",
                "version": "1.0.0",
                "bin": {
                    "shared-tool": "cli.js"
                },
                "dist": {
                    "tarball": mock.tarball_url("shared-tool", "1.0.0"),
                    "integrity": compute_integrity(&shared_tarball)
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    let private_tarball = make_tarball("second-only", "1.0.0");
    let private_metadata = serde_json::json!({
        "name": "second-only",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "second-only",
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url("second-only", "1.0.0"),
                    "integrity": compute_integrity(&private_tarball)
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_package_metadata_and_tarballs(
        "shared-tool",
        shared_metadata.clone(),
        &[("1.0.0", shared_tarball)],
    )
    .await;
    mock.with_package_metadata_and_tarballs(
        "second-only",
        private_metadata.clone(),
        &[("1.0.0", private_tarball)],
    )
    .await;
    mock.with_batch_metadata(vec![shared_metadata, private_metadata])
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "warm-replay-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "shared-tool": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/first/package.json",
        r#"{
  "name": "@fixture/first",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "shared-tool": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/second/package.json",
        r#"{
  "name": "@fixture/second",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "shared-tool": "1.0.0",
    "second-only": "1.0.0"
  }
}"#,
    );

    let seed = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("seed importer-local lockfiles and store entries");
    assert_install_succeeded(&seed, "initial recursive install should succeed");

    for target in ["", "packages/first", "packages/second"] {
        let node_modules = project.path().join(target).join("node_modules");
        std::fs::remove_dir_all(&node_modules).unwrap_or_else(|error| {
            panic!(
                "remove {} before warm replay: {error}",
                node_modules.display()
            )
        });
    }

    let replay = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run warm recursive lockfile replay");
    assert_install_succeeded(&replay, "warm recursive replay should succeed");

    for target in ["", "packages/first", "packages/second"] {
        let node_modules = project.path().join(target).join("node_modules");
        assert!(
            node_modules.join("shared-tool/package.json").is_file()
                && node_modules.join(".bin/shared-tool").exists(),
            "{} must receive its own shared root link and bin shim",
            node_modules.display(),
        );
    }
    assert!(
        !project
            .path()
            .join("packages/first/node_modules/second-only")
            .exists(),
        "the first importer must not receive the second importer's private dependency",
    );
    assert!(
        project
            .path()
            .join("packages/second/node_modules/second-only/package.json")
            .is_file(),
        "the second importer must retain its private dependency",
    );
}

#[tokio::test]
async fn recursive_install_with_conflicting_member_specs_keeps_both_correct() {
    let mock = MockRegistry::start().await;
    mount_registry_packages(
        &mock,
        &[("contested-dep", "1.0.0"), ("contested-dep", "2.0.0")],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "conflicted-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/one/package.json",
        r#"{
  "name": "@fixture/one",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "contested-dep": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/two/package.json",
        r#"{
  "name": "@fixture/two",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "contested-dep": "2.0.0"
  }
}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .arg("--recursive")
        .args(INSTALL_FLAGS)
        .output()
        .expect("run recursive install with conflicting member specs");
    assert_install_succeeded(&output, "conflicting member specs should still install");

    let one_manifest: serde_json::Value = serde_json::from_str(
        &project.read_file("packages/one/node_modules/contested-dep/package.json"),
    )
    .expect("member one should link contested-dep");
    assert_eq!(one_manifest["version"], "1.0.0");
    let two_manifest: serde_json::Value = serde_json::from_str(
        &project.read_file("packages/two/node_modules/contested-dep/package.json"),
    )
    .expect("member two should link contested-dep");
    assert_eq!(two_manifest["version"], "2.0.0");
}
