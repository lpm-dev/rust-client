//! Workspace path selection and deployment contracts.
mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};

fn git(project: &TempProject, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(project.path())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn nested_workspace(core_path: &str) -> TempProject {
    let project = TempProject::empty(r#"{"name":"repository"}"#);
    project.write_file(
        "nested/package.json",
        r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
    );
    for (dir, name, dependencies) in [
        (core_path, "core", serde_json::json!({})),
        (
            "packages/app",
            "app",
            serde_json::json!({"core":"workspace:*"}),
        ),
        ("packages/spare", "spare", serde_json::json!({})),
    ] {
        project.write_file(&format!("nested/{dir}/package.json"), &serde_json::json!({"name":name,"version":"1.0.0","dependencies":dependencies,"scripts":{"check":"node -e \"require('fs').writeFileSync('ran.txt','yes')\""}}).to_string());
        project.write_file(&format!("nested/{dir}/index.js"), "before\n");
    }
    project.write_file("outside.txt", "before\n");
    git(&project, &["init", "-b", "main"]);
    git(&project, &["add", "."]);
    git(&project, &["commit", "-m", "initial"]);
    project
}

fn selection(project: &TempProject, expr: &str, extra: &[&str]) -> Vec<String> {
    let output = lpm(project)
        .current_dir(project.path().join("nested"))
        .args(["filter", expr])
        .args(extra)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut names = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn nested_workspace_git_filters_use_workspace_relative_paths() {
    for (changed, expected) in [
        ("nested/packages/core/index.js", vec!["core"]),
        ("outside.txt", vec![]),
        ("nested/package.json", vec!["app", "core", "spare"]),
    ] {
        let project = nested_workspace("packages/core");
        if changed.ends_with("package.json") {
            project.write_file(changed, r#"{"name":"root","private":true,"workspaces":["packages/*"],"description":"changed"}"#);
        } else {
            project.write_file(changed, "after\n");
        }
        assert_eq!(selection(&project, "[main]", &[]), expected, "{changed}");
        if changed.ends_with("index.js") {
            assert_eq!(selection(&project, "...[main]", &[]), ["app", "core"]);
        }
    }
}

#[test]
fn escaped_git_paths_keep_ignore_and_test_only_classification() {
    #[cfg(unix)]
    let filenames = [
        "src/quoted\".test.js",
        "src/ignored.js",
        "src/line\nbreak.test.js",
        "src/back\\slash.test.js",
    ]
    .as_slice();
    #[cfg(not(unix))]
    let filenames = ["src/changed.test.js", "src/ignored.js"].as_slice();
    for filename in filenames {
        let project = nested_workspace("packages/café");
        project.write_file(&format!("nested/packages/café/{filename}"), "before\n");
        git(&project, &["add", "."]);
        git(&project, &["commit", "-m", "add fixture"]);
        project.write_file(&format!("nested/packages/café/{filename}"), "after\n");
        let expected = if filename.ends_with("ignored.js") {
            vec![]
        } else {
            vec!["core"]
        };
        assert_eq!(
            selection(
                &project,
                "...[HEAD]",
                &[
                    "--changed-files-ignore-pattern",
                    "**/ignored.js",
                    "--test-pattern",
                    "**/*.test.js"
                ]
            ),
            expected,
            "{filename:?}"
        );
    }
}

#[test]
fn missing_git_base_fails_filters_and_affected_tasks() {
    let project = nested_workspace("packages/core");
    for args in [
        vec!["filter", "[missing-base]"],
        vec!["run", "check", "--affected", "--base", "missing-base"],
    ] {
        let output = lpm(&project)
            .current_dir(project.path().join("nested"))
            .args(&args)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    for member in ["core", "app", "spare"] {
        assert!(
            !project
                .path()
                .join(format!("nested/packages/{member}/ran.txt"))
                .exists()
        );
    }
}

async fn deploy(project: &TempProject, out: &std::path::Path, json: bool) -> std::process::Output {
    let registry = MockRegistry::start().await;
    let mut command = lpm_with_registry(project, &registry.url());
    if json {
        command.arg("--json");
    }
    let output = command
        .args(["deploy", out.to_str().unwrap(), "--filter", "app"])
        .output()
        .unwrap();
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty(),
        "local deployment must not fetch registry packages"
    );
    output
}

fn assert_no_env_paths(path: &std::path::Path) {
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        assert!(
            !entry.file_name().as_encoded_bytes().starts_with(b".env"),
            "leaked {}",
            entry.path().display()
        );
        if entry.file_type().unwrap().is_dir() {
            assert_no_env_paths(&entry.path());
        }
    }
}

#[tokio::test]
async fn deployment_excludes_all_env_prefixes_even_from_allowlists_and_local_dependencies() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file("packages/app/package.json",r#"{"name":"app","version":"1.0.0","files":["**/*",".env*"],"dependencies":{"shared":"workspace:*"}}"#);
    project.write_file(
        "packages/shared/package.json",
        r#"{"name":"shared","version":"1.0.0","files":["**/*",".env*"]}"#,
    );
    for member in ["app", "shared"] {
        project.write_file(
            &format!("packages/{member}/index.js"),
            "module.exports=1;\n",
        );
        for name in [
            ".env.staging",
            "nested/.env.customer-a",
            ".env.backups/secret.txt",
            ".env.example",
        ] {
            project.write_file(&format!("packages/{member}/{name}"), "secret\n");
        }
    }
    let out = tempfile::tempdir().unwrap();
    let output = deploy(&project, out.path(), false).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_env_paths(out.path());
    assert_eq!(project.read_file("packages/app/.env.staging"), "secret\n");
}

#[tokio::test]
async fn deployment_accepts_bom_manifests_without_changing_source_bytes() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    let manifest = "\u{feff}{\"name\":\"app\",\"version\":\"1.0.0\"}";
    project.write_file("packages/client/package.json", manifest);
    let out = tempfile::tempdir().unwrap();
    let output = deploy(&project, out.path(), false).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("packages/client/package.json"), manifest);
}

#[tokio::test]
async fn actual_deployment_emits_one_json_envelope() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0"}"#,
    );
    let out = tempfile::tempdir().unwrap();
    let output = deploy(&project, out.path(), true).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["success"], true);
    insta::assert_json_snapshot!("actual_deployment",envelope, {
        ".deployed.member_dir"=>"[MEMBER]", ".deployed.output_dir"=>"[OUTPUT]", ".duration_ms"=>"[DURATION]",
        ".copy_stats.bytes_copied"=>"[BYTES]"
    });
}

#[tokio::test]
async fn deployment_copies_named_root_and_peer_workspace_sources() {
    for peer_only in [false, true] {
        let root = r#"{"name":"root-provider","version":"1.0.0","private":true,"workspaces":["packages/*"],"files":["index.js"],"main":"index.js"}"#;
        let project = TempProject::empty(root);
        project.write_file("index.js", "module.exports='root';\n");
        let mut member = serde_json::json!({"name":"app","version":"1.0.0"});
        member[if peer_only {
            "peerDependencies"
        } else {
            "dependencies"
        }] = serde_json::json!({"root-provider":"workspace:*"});
        let member = member.to_string();
        project.write_file("packages/app/package.json", &member);
        let out = tempfile::tempdir().unwrap();
        let output = deploy(&project, out.path(), false).await;
        assert!(
            output.status.success(),
            "peer_only={peer_only}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let deployed: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(out.path().join("package.json")).unwrap(),
        )
        .unwrap();
        let spec = deployed[if peer_only {
            "peerDependencies"
        } else {
            "dependencies"
        }]["root-provider"]
            .as_str()
            .unwrap();
        let local = spec
            .strip_prefix("file:")
            .expect("deployment must retain a local source");
        let provider = out.path().join(local);
        assert!(provider.join("package.json").is_file());
        assert_eq!(
            std::fs::read_to_string(provider.join("index.js")).unwrap(),
            "module.exports='root';\n"
        );
        if !peer_only {
            assert!(
                out.path()
                    .join("node_modules/root-provider/package.json")
                    .is_file()
            );
        }
        assert_eq!(project.read_file("package.json"), root);
        assert_eq!(project.read_file("packages/app/package.json"), member);
    }
}

#[tokio::test]
async fn deployment_rewrites_local_edges_back_to_the_selected_package() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"shared":"workspace:*"}}"#,
    );
    project.write_file(
        "packages/shared/package.json",
        r#"{"name":"shared","version":"1.0.0","peerDependencies":{"app":"workspace:*"}}"#,
    );
    project.write_file("packages/app/index.js", "module.exports='app';\n");
    project.write_file(
        "packages/shared/index.js",
        "module.exports=require('app');\n",
    );
    let out = tempfile::tempdir().unwrap();
    let output = deploy(&project, out.path(), false).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let deployed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.path().join("package.json")).unwrap())
            .unwrap();
    let path = out.path().join(
        deployed["dependencies"]["shared"]
            .as_str()
            .unwrap()
            .strip_prefix("file:")
            .unwrap(),
    );
    let shared: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path.join("package.json")).unwrap()).unwrap();
    let peer = shared["peerDependencies"]["app"]
        .as_str()
        .unwrap()
        .strip_prefix("file:")
        .expect("workspace peer back-edge must point into deploy output");
    assert_eq!(
        std::fs::canonicalize(path.join(peer)).unwrap(),
        std::fs::canonicalize(out.path()).unwrap()
    );
    let lock = lpm_lockfile::Lockfile::read_fast(&out.path().join("lpm.lock")).unwrap();
    let app = lock
        .packages
        .iter()
        .find(|package| package.name == "app")
        .unwrap();
    let shared = lock
        .packages
        .iter()
        .find(|package| package.name == "shared")
        .unwrap();
    assert_eq!(app.source.as_deref(), Some("directory+."));
    assert_eq!(shared.peer_targets.get("app").copied(), app.instance_id);
    let output = std::process::Command::new("node")
        .current_dir(out.path())
        .args(["-e", "if(require('shared')!=='app')process.exit(1)"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn deployment_keeps_nested_provider_copies_disjoint_and_preserves_source_files() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"workspaces":["packages/*","packages/parent/child"]}"#,
    );
    project.write_file("packages/app/package.json",r#"{"name":"app","version":"1.0.0","dependencies":{"parent":"workspace:*","child":"workspace:*"}}"#);
    project.write_file(
        "packages/parent/package.json",
        r#"{"name":"parent","version":"1.0.0"}"#,
    );
    let child = r#"{"name":"child","version":"1.0.0"}"#;
    project.write_file("packages/parent/child/package.json", child);
    project.write_file(
        "packages/parent/child/index.js",
        "module.exports='child';\n",
    );
    let out = tempfile::tempdir().unwrap();
    let output = deploy(&project, out.path(), false).await;
    assert_eq!(
        project.read_file("packages/parent/child/package.json"),
        child,
        "copy must not overwrite a source hardlink"
    );
    assert_eq!(
        project.read_file("packages/parent/child/index.js"),
        "module.exports='child';\n"
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let deployed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.path().join("package.json")).unwrap())
            .unwrap();
    let paths = ["parent", "child"].map(|name| {
        out.path().join(
            deployed["dependencies"][name]
                .as_str()
                .unwrap()
                .strip_prefix("file:")
                .unwrap(),
        )
    });
    assert!(
        !paths[0].starts_with(&paths[1]) && !paths[1].starts_with(&paths[0]),
        "provider destinations must not overlap: {paths:?}"
    );
}

#[tokio::test]
async fn deployment_rejects_workspace_ranges_that_exclude_local_providers() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"shared":"workspace:^2.0.0"}}"#,
    );
    project.write_file(
        "packages/shared/package.json",
        r#"{"name":"shared","version":"1.0.0"}"#,
    );
    let out = tempfile::tempdir().unwrap();
    let output = deploy(&project, out.path(), false).await;
    assert!(
        !output.status.success(),
        "incompatible workspace version must not become a file dependency"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("2.0.0"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn scoped_workspace_version_requests_resolve_locally_before_registry_preflight() {
    let name = "@lpm.dev/acme.shared";
    for mode in ["manual", "strict"] {
        for suffix in ["", "@^1.0.0", "@1.0.0"] {
            let registry = MockRegistry::start().await;
            let project=TempProject::empty(&serde_json::json!({"name":"root","private":true,"workspaces":["packages/*"],"catalogs":{"default":{name:"^1.0.0"}},"lpm":{"catalogMode":mode}}).to_string());
            project.write_file(
                "packages/app/package.json",
                r#"{"name":"app","version":"1.0.0"}"#,
            );
            project.write_file(
                "packages/shared/package.json",
                &serde_json::json!({"name":name,"version":"1.0.0"}).to_string(),
            );
            let output = lpm_with_registry(&project, &registry.url())
                .env("LPM_TYPOSQUAT_GUARD", "0")
                .args([
                    "install",
                    &format!("{name}{suffix}"),
                    "--filter",
                    "app",
                    "--no-skills",
                    "--no-editor-setup",
                    "--no-security-summary",
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode} {suffix}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                project
                    .path()
                    .join("packages/app/node_modules/@lpm.dev/acme.shared/package.json")
                    .is_file()
            );
            assert!(
                registry
                    .server()
                    .received_requests()
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn moving_a_file_between_members_marks_both_members_changed() {
    let project = nested_workspace("packages/core");
    git(
        &project,
        &[
            "mv",
            "nested/packages/core/index.js",
            "nested/packages/spare/moved.js",
        ],
    );
    assert_eq!(selection(&project, "[main]", &[]), ["core", "spare"]);
}

#[tokio::test]
async fn deployment_preserves_workspace_self_reference_validation() {
    for section in [
        "dependencies",
        "peerDependencies",
        "optionalDependencies",
        "devDependencies",
    ] {
        let project =
            TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
        let mut manifest = serde_json::json!({"name":"app","version":"1.0.0"});
        manifest[section] = serde_json::json!({"app":"workspace:*"});
        let source = manifest.to_string();
        project.write_file("packages/app/package.json", &source);
        let registry = MockRegistry::start().await;
        let out = tempfile::tempdir().unwrap();
        let mut command = lpm_with_registry(&project, &registry.url());
        command.args(["deploy", out.path().to_str().unwrap(), "--filter", "app"]);
        if section == "devDependencies" {
            command.arg("--dev");
        }
        let output = command.output().unwrap();
        if section == "devDependencies" {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let deployed: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(out.path().join("package.json")).unwrap(),
            )
            .unwrap();
            assert!(
                deployed[section].get("app").is_none(),
                "dev self dependency must be omitted"
            );
        } else {
            assert!(
                !output.status.success(),
                "{section} self edge must be rejected"
            );
            assert!(String::from_utf8_lossy(&output.stderr).contains("depends on itself"));
        }
        assert_eq!(project.read_file("packages/app/package.json"), source);
        assert!(
            registry
                .server()
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn deployment_ignores_incidental_nested_manifests_when_pruning_a_source_lockfile() {
    let project = TempProject::empty(
        r#"{"name":"root-provider","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"root-provider":"workspace:*"}}"#,
    );
    project.write_file(
        "fixtures/broken/package.json",
        "{ intentionally malformed fixture",
    );
    lpm_lockfile::Lockfile::new()
        .write_all(&project.path().join("lpm.lock"))
        .unwrap();
    let out = tempfile::tempdir().unwrap();
    let output = deploy(&project, out.path(), false).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("fixtures/broken/package.json"),
        "{ intentionally malformed fixture"
    );
}

#[tokio::test]
async fn deployment_optional_dependencies_override_regular_declarations() {
    for (no_optional, copied_provider) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let project =
            TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
        let consumer_path = if copied_provider {
            "packages/provider/package.json"
        } else {
            "packages/app/package.json"
        };
        if copied_provider {
            project.write_file(
                "packages/app/package.json",
                r#"{"name":"app","version":"1.0.0","dependencies":{"provider":"workspace:*"}}"#,
            );
        }
        let source_name = if copied_provider { "provider" } else { "app" };
        let source=serde_json::json!({"name":source_name,"version":"1.0.0","dependencies":{"shared":"workspace:^2.0.0"},"optionalDependencies":{"shared":"workspace:*"}}).to_string();
        project.write_file(consumer_path, &source);

        project.write_file(
            "packages/shared/package.json",
            r#"{"name":"shared","version":"1.0.0"}"#,
        );
        let registry = MockRegistry::start().await;
        let out = tempfile::tempdir().unwrap();
        let mut command = lpm_with_registry(&project, &registry.url());
        command.args(["deploy", out.path().to_str().unwrap(), "--filter", "app"]);
        if no_optional {
            command.arg("--no-optional");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "no_optional={no_optional}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let deployed_path = if copied_provider {
            let root: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(out.path().join("package.json")).unwrap(),
            )
            .unwrap();
            out.path()
                .join(
                    root["dependencies"]["provider"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("file:")
                        .unwrap(),
                )
                .join("package.json")
        } else {
            out.path().join("package.json")
        };
        let deployed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(deployed_path).unwrap()).unwrap();
        assert!(deployed["dependencies"].get("shared").is_none());
        let lock = lpm_lockfile::Lockfile::read_fast(&out.path().join("lpm.lock")).unwrap();
        assert_eq!(
            lock.packages.iter().any(|package| package.name == "shared"),
            !no_optional
        );
        assert_eq!(project.read_file(consumer_path), source);
        assert!(
            registry
                .server()
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn forced_deployment_rejects_an_output_ancestor_of_the_workspace() {
    let project = TempProject::empty(r#"{"name":"fixture"}"#);
    let root = r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#;
    project.write_file("output/workspace/package.json", root);
    project.write_file(
        "output/workspace/packages/app/package.json",
        r#"{"name":"app","version":"1.0.0"}"#,
    );
    project.write_file("output/keep.txt", "outside workspace");
    let registry = MockRegistry::start().await;
    let output = lpm_with_registry(&project, &registry.url())
        .current_dir(project.path().join("output/workspace"))
        .args(["deploy", "..", "--filter", "app", "--force"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(project.read_file("output/workspace/package.json"), root);
    assert_eq!(project.read_file("output/keep.txt"), "outside workspace");
    assert!(String::from_utf8_lossy(&output.stderr).contains("overlaps"));
}

#[tokio::test]
async fn deployment_resolves_root_catalogs_in_members_and_copied_providers() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({"name":"catalog-fixture","version":"1.0.0","main":"index.js"}),
            &[("index.js", b"module.exports=1;\n")],
        )
        .await;
    let root = r#"{"name":"root","private":true,"workspaces":["packages/*"],"catalogs":{"shared":{"catalog-fixture":"1.0.0"}}}"#;
    let project = TempProject::empty(root);
    let app = r#"{"name":"app","version":"1.0.0","dependencies":{"shared":"workspace:*","catalog-fixture":"catalog:shared"}}"#;
    let shared = r#"{"name":"shared","version":"1.0.0","dependencies":{"catalog-fixture":"catalog:shared"}}"#;
    project.write_file("packages/app/package.json", app);
    project.write_file("packages/shared/package.json", shared);
    let out = tempfile::tempdir().unwrap();
    let output = lpm_with_registry(&project, &registry.url())
        .args(["deploy", out.path().to_str().unwrap(), "--filter", "app"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let deployed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.path().join("package.json")).unwrap())
            .unwrap();
    assert_eq!(deployed["dependencies"]["catalog-fixture"], "1.0.0");
    let shared_path = out.path().join(
        deployed["dependencies"]["shared"]
            .as_str()
            .unwrap()
            .strip_prefix("file:")
            .unwrap(),
    );
    let shared_doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(shared_path.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(shared_doc["dependencies"]["catalog-fixture"], "1.0.0");
    assert!(
        out.path()
            .join("node_modules/catalog-fixture/package.json")
            .is_file()
    );
    assert_eq!(project.read_file("package.json"), root);
    assert_eq!(project.read_file("packages/app/package.json"), app);
    assert_eq!(project.read_file("packages/shared/package.json"), shared);
}
