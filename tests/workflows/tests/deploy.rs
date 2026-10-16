//! Workflow tests for `lpm deploy <output> --filter`.
//!
//! Deploy materializes one workspace member's production closure into an
//! external directory. The full happy-path also runs an install at the
//! output, which requires a mock registry; these workflow tests focus on
//! the validation/dispatch contracts that don't require network:
//!
//! - `--dry-run` writes nothing, surfaces the resolved plan
//! - filter must match exactly one member (zero or many → error)
//! - output dir must be outside the workspace
//! - output dir must be empty without `--force`
//! - human + JSON envelope shape for the dry-run path

mod support;

use support::{TempProject, lpm};

/// `lpm deploy` requires the output dir to be OUTSIDE the workspace. Use
/// the system temp area for that — every test gets a fresh tempdir.
fn external_output_dir() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("failed to create external output dir")
}

// ─── --dry-run path (no filesystem writes) ──────────────────────────────

#[test]
fn deploy_dry_run_writes_nothing_to_output_dir() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    // Snapshot output dir state before
    let entries_before: Vec<_> = std::fs::read_dir(out.path())
        .expect("read output dir")
        .collect();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy --dry-run");

    assert!(
        output.status.success(),
        "deploy --dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let entries_after: Vec<_> = std::fs::read_dir(out.path())
        .expect("read output dir")
        .collect();
    assert_eq!(
        entries_before.len(),
        entries_after.len(),
        "dry-run must not write any files to the output dir",
    );
}

#[test]
fn deploy_dry_run_json_envelope_carries_resolved_plan() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "--json",
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy --dry-run --json");

    assert!(
        output.status.success(),
        "deploy --dry-run --json must succeed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("deploy --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    assert_eq!(envelope["member"], serde_json::json!("@test/utils"));
    assert!(
        envelope["member_dir"].is_string(),
        "envelope must carry member_dir"
    );
    assert!(
        envelope["output_dir"].is_string(),
        "envelope must carry output_dir"
    );
}

#[test]
fn deploy_dry_run_human_output_uses_slim_ui() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy --dry-run");

    assert!(
        output.status.success(),
        "deploy --dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.trim().is_empty(),
        "human status output must stay off stdout; got:\n{stdout}"
    );
    assert!(
        stderr.contains("› Materializing production closure for @test/utils"),
        "stderr must show the slim deploy phase; got:\n{stderr}"
    );
    assert!(
        stderr.contains("output:") && stderr.contains("dry run:"),
        "stderr must show deploy details without a boxed prompt; got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · dry run complete"),
        "stderr must show the slim dry-run terminus; got:\n{stderr}"
    );
    assert!(
        !stderr.contains('│') && !stderr.contains('◇'),
        "dry-run status must not use cliclack's boxed gutter; got:\n{stderr}"
    );
}

#[test]
fn deploy_dry_run_human_output_applies_slim_color_roles_when_forced() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "--color=always",
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run colored lpm deploy --dry-run");

    assert!(
        output.status.success(),
        "colored deploy --dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\x1b[33m@test/utils")
            && stderr.contains("\x1b[2moutput:")
            && stderr.contains("\x1b[33m/")
            && stderr.contains("\x1b[36m")
            && stderr.contains("\x1b[32myes")
            && stderr.contains("\x1b[32mproduction")
            && stderr.contains("\x1b[32mincluded"),
        "deploy dry-run should color target/path/status/count roles and dim labels, got:\n{stderr:?}",
    );
}

// ─── filter must match exactly one member ──────────────────────────────

#[test]
fn deploy_filter_matching_multiple_members_fails() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/*",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy with multi-match filter");

    assert!(
        !output.status.success(),
        "deploy with multi-match filter must exit non-zero",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exactly one") || stderr.contains("multiple") || stderr.contains("3"),
        "stderr must explain the single-target requirement, got:\n{stderr}",
    );
}

#[test]
fn deploy_filter_matching_zero_members_fails() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "this-does-not-exist",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy with zero-match filter");

    assert!(
        !output.status.success(),
        "deploy with zero-match filter must exit non-zero",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no")
            || stderr.contains("zero")
            || stderr.contains("did not match")
            || stderr.contains("matched"),
        "stderr must explain the no-match condition, got:\n{stderr}",
    );
}

// ─── output dir safety ──────────────────────────────────────────────────

#[test]
fn deploy_into_workspace_directory_is_rejected() {
    let project = TempProject::from_fixture("workspace-monorepo");

    // Try to deploy INTO the workspace itself (a subdir). Deploy must
    // refuse to prevent overwriting the source.
    let inside_workspace = project.path().join("deploy-output");
    std::fs::create_dir_all(&inside_workspace).expect("create inside-workspace dir");

    let output = lpm(&project)
        .args([
            "deploy",
            inside_workspace.to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy into workspace");

    assert!(
        !output.status.success(),
        "deploy into the workspace tree must be rejected",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workspace") || stderr.contains("outside"),
        "stderr must explain the outside-workspace requirement, got:\n{stderr}",
    );
}

#[test]
fn deploy_into_nonempty_dir_without_force_is_rejected() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let out = external_output_dir();

    // Seed a file in the output dir.
    std::fs::write(out.path().join("existing.txt"), b"hello").expect("seed existing file");

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "@test/utils",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy into non-empty dir");

    assert!(
        !output.status.success(),
        "deploy into non-empty dir without --force must be rejected",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not empty") || stderr.contains("--force") || stderr.contains("empty"),
        "stderr must explain the empty-dir requirement, got:\n{stderr}",
    );

    // The existing file must be untouched.
    let content = std::fs::read(out.path().join("existing.txt")).expect("read existing.txt");
    assert_eq!(content, b"hello", "existing file must not be modified");
}

#[test]
fn deploy_outside_workspace_context_fails() {
    // Bare project (no workspaces) — deploy makes no sense.
    let project = TempProject::empty(r#"{"name":"single","version":"1.0.0"}"#);
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "single",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm deploy outside workspace");

    assert!(
        !output.status.success(),
        "deploy outside a workspace must exit non-zero",
    );
}

#[tokio::test]
async fn deploy_excludes_registry_credentials_from_members_and_workspace_dependencies() {
    assert_deploy_excludes_credentials(&[".npmrc", ".netrc", "_netrc"]).await;
}

#[tokio::test]
async fn deploy_excludes_mixed_case_registry_credentials() {
    assert_deploy_excludes_credentials(&[".NpMrC", ".NeTrC", "_NeTrC"]).await;
}

async fn assert_deploy_excludes_credentials(credential_names: &[&str]) {
    use support::lpm_with_registry;
    use support::mock_registry::MockRegistry;
    for allowlist in [false, true] {
        let project =
            TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
        for member in ["app", "shared"] {
            let mut manifest =
                serde_json::json!({"name":member,"version":"1.0.0","main":"index.js"});
            if member == "app" {
                manifest["dependencies"] = serde_json::json!({"shared":"workspace:*"});
            }
            if allowlist {
                manifest["files"] = serde_json::json!([
                    "index.js",
                    credential_names[0],
                    credential_names[1],
                    credential_names[2],
                    "nested"
                ]);
            }
            project.write_file(
                &format!("packages/{member}/package.json"),
                &manifest.to_string(),
            );
            project.write_file(
                &format!("packages/{member}/index.js"),
                "module.exports = 1;\n",
            );
            for name in credential_names {
                for directory in ["", "nested/"] {
                    project.write_file(
                        &format!("packages/{member}/{directory}{name}"),
                        "private-fixture-credential\n",
                    );
                }
                #[cfg(unix)]
                {
                    let linked = project
                        .path()
                        .join(format!("packages/{member}/nested/linked/{name}"));
                    std::fs::create_dir_all(linked.parent().unwrap()).unwrap();
                    std::os::unix::fs::symlink(
                        project.path().join(format!("packages/{member}/{name}")),
                        linked,
                    )
                    .unwrap();
                }
            }
        }
        let registry = MockRegistry::start().await;
        let out = external_output_dir();
        let output = lpm_with_registry(&project, &registry.url())
            .args([
                "deploy",
                out.path().to_str().unwrap(),
                "--filter",
                "app",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        assert_deployment_has_no_registry_credentials(out.path());
        assert!(out.path().join("index.js").is_file());
        assert_eq!(
            project.read_file(&format!("packages/shared/{}", credential_names[0])),
            "private-fixture-credential\n"
        );
    }
}

#[tokio::test]
async fn a_committed_deploy_output_keeps_what_the_deploy_wrote_whatever_rules_outside_it_say() {
    use support::lpm_with_registry;
    use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_with_files};
    let package = "@lpm.dev/test.kept-pkg";
    let tarball = make_tarball_with_files(
        package,
        "1.0.0",
        &[("index.js", b"module.exports = 'kept';\n")],
    );
    let registry = MockRegistry::start().await;
    let metadata = serde_json::json!({
        "name": package,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "name": package,
            "version": "1.0.0",
            "main": "index.js",
            "dist": {
                "tarball": format!("{}{}", registry.url(), MockRegistry::tarball_path(package, "1.0.0")),
                "integrity": compute_integrity(&tarball),
            },
        }},
    });
    registry
        .with_package_metadata_and_tarballs(package, metadata, &[("1.0.0", tarball)])
        .await;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/app/package.json",
        &format!(
            r#"{{"name":"app","version":"1.0.0","main":"index.js","dependencies":{{"shared":"workspace:*","{package}":"1.0.0"}}}}"#
        ),
    );
    project.write_file("packages/app/index.js", "require('./dist/lib');\n");
    project.write_file("packages/app/dist/lib.js", "require('./build/x');\n");
    project.write_file("packages/app/dist/build/x.js", "require('shared');\n");
    project.write_file(
        "packages/shared/package.json",
        r#"{"name":"shared","version":"1.0.0","main":"index.js"}"#,
    );
    project.write_file("packages/shared/index.js", "module.exports = 1;\n");
    let deploy = |out: &std::path::Path| {
        let output = lpm_with_registry(&project, &registry.url())
            .args(["deploy", out.to_str().unwrap(), "--filter", "app"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // What the user adds to the output afterwards still follows their
        // rules.
        std::fs::write(out.join(".env"), "TOKEN=placeholder\n").unwrap();
        std::fs::write(out.join("dist/.env"), "TOKEN=placeholder\n").unwrap();
    };
    let scratch = external_output_dir();
    let global = scratch.path().join("gitconfig");
    let git = |directory: &std::path::Path, arguments: &[&str]| {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .env("GIT_CONFIG_GLOBAL", &global)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let check = |committed: &str, prefix: &str| {
        let committed: Vec<&str> = committed
            .lines()
            .filter_map(|path| path.strip_prefix(prefix))
            .collect();
        for kept in [
            ".gitignore",
            "index.js",
            "dist/lib.js",
            "dist/build/x.js",
            ".lpm/.gitignore",
        ] {
            assert!(committed.contains(&kept), "{kept}: {committed:#?}");
        }
        for payload in [
            "node_modules/shared",
            ".lpm/deploy-workspace/",
            ".lpm/store/",
        ] {
            assert!(
                committed.iter().any(|path| path.starts_with(payload)),
                "{payload}: {committed:#?}"
            );
        }
        for added in [".env", "dist/.env"] {
            assert!(!committed.contains(&added), "{added}: {committed:#?}");
        }
    };

    // The output inside a repository whose `.gitignore` names what a Node
    // project builds and installs.
    std::fs::write(&global, "").unwrap();
    let repository = scratch.path().join("repository");
    std::fs::create_dir_all(repository.join("deploy")).unwrap();
    git(&repository, &["init", "-q"]);
    std::fs::write(
        repository.join(".gitignore"),
        "node_modules/\ndist/\nbuild/\n.lpm/\n.env\n",
    )
    .unwrap();
    deploy(&repository.join("deploy/out"));
    git(&repository, &["add", "-A"]);
    check(&git(&repository, &["ls-files"]), "deploy/out/");

    // The output as a repository of its own, under a global excludes file.
    let excludes = scratch.path().join("excludes");
    std::fs::write(&excludes, "node_modules\ndist/\nbuild/\n.lpm/\n.env\n").unwrap();
    std::fs::write(
        &global,
        format!(
            "[core]\n\texcludesFile = {}\n",
            excludes.to_str().unwrap().replace('\\', "/")
        ),
    )
    .unwrap();
    let own = scratch.path().join("own");
    deploy(&own);
    git(&own, &["init", "-q"]);
    git(&own, &["add", "-A"]);
    check(&git(&own, &["ls-files"]), "");
}

#[tokio::test]
async fn a_deploy_output_git_commits_keeps_its_dependencies() {
    use support::lpm_with_registry;
    use support::mock_registry::MockRegistry;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","main":"index.js","dependencies":{"shared":"workspace:*"}}"#,
    );
    project.write_file("packages/app/index.js", "require('shared');\n");
    project.write_file(
        "packages/shared/package.json",
        r#"{"name":"shared","version":"1.0.0","main":"index.js"}"#,
    );
    project.write_file("packages/shared/index.js", "module.exports = 1;\n");
    let registry = MockRegistry::start().await;
    let out = external_output_dir();
    let output = lpm_with_registry(&project, &registry.url())
        .args(["deploy", out.path().to_str().unwrap(), "--filter", "app"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // A host that deploys what git pushes gets what `git add -A` stages.
    let git = |arguments: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(out.path())
            .args(arguments)
            .output()
            .expect("run git")
    };
    assert!(git(&["init", "-q"]).status.success());
    let offered = || {
        String::from_utf8_lossy(&git(&["ls-files", "--others", "--exclude-standard"]).stdout)
            .into_owned()
    };
    let check = |offered: &str| {
        assert!(
            offered.lines().any(|path| path == ".lpm/.gitignore"),
            "a clone would lose what keeps the dependencies committed:\n{offered}"
        );
        for payload in [".lpm/deploy-workspace/", ".lpm/store/"] {
            assert!(
                offered.lines().any(|path| path.starts_with(payload)),
                "{payload} is left out of git:\n{offered}"
            );
        }
        // Machine-local state stays out, and nothing committed names a path
        // on this machine.
        assert!(!offered.contains(".lpm/known-projects.json"), "{offered}");
        let local_paths = [
            out.path().to_path_buf(),
            std::fs::canonicalize(out.path()).unwrap(),
            std::fs::canonicalize(project.path()).unwrap(),
        ];
        for path in offered.lines().filter(|path| path.starts_with(".lpm/")) {
            let content = std::fs::read(out.path().join(path)).unwrap_or_default();
            let content = String::from_utf8_lossy(&content);
            for local in &local_paths {
                assert!(
                    !content.contains(&*local.to_string_lossy()),
                    "{path} names {}",
                    local.display()
                );
            }
        }
    };
    check(&offered());

    // A later command in the output keeps it that way.
    let later = lpm_with_registry(&project, &registry.url())
        .current_dir(out.path())
        .args(["config", "list"])
        .output()
        .unwrap();
    assert!(
        later.status.success(),
        "{}",
        String::from_utf8_lossy(&later.stderr)
    );
    check(&offered());

    // A clone keeps them committed.
    assert!(git(&["add", "-A"]).status.success());
    let committed = git(&[
        "-c",
        "user.name=deploy",
        "-c",
        "user.email=deploy@example.invalid",
        "commit",
        "-q",
        "-m",
        "deploy",
    ]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let clone = external_output_dir();
    let cloned = std::process::Command::new("git")
        .args(["clone", "-q"])
        .arg(out.path())
        .arg(clone.path().join("app"))
        .output()
        .unwrap();
    assert!(cloned.status.success());
    assert_eq!(
        std::fs::read_to_string(clone.path().join("app/.lpm/.gitignore")).unwrap(),
        std::fs::read_to_string(out.path().join(".lpm/.gitignore")).unwrap()
    );
}

fn assert_deployment_has_no_registry_credentials(directory: &std::path::Path) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        assert!(
            ![".npmrc", ".netrc", "_netrc"]
                .iter()
                .any(|denied| name.to_string_lossy().eq_ignore_ascii_case(denied)),
            "credential leaked: {}",
            entry.path().display()
        );
        if entry.file_type().unwrap().is_dir() {
            assert_deployment_has_no_registry_credentials(&entry.path());
        }
    }
}

/// A workspace whose `api` member depends on `util-pkg`, either of which can
/// have a `main` that a deploy's selection refuses.
#[cfg(unix)]
#[test]
fn deploy_selects_a_large_workspace_closure_within_a_small_descriptor_limit() {
    const PROVIDERS: usize = 150;
    let project = TempProject::empty(
        r#"{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    let dependencies = (0..PROVIDERS)
        .map(|index| format!(r#""p{index}":"workspace:*""#))
        .collect::<Vec<_>>()
        .join(",");
    project.write_file(
        "packages/app/package.json",
        &format!(r#"{{"name":"app","version":"1.0.0","dependencies":{{{dependencies}}}}}"#),
    );
    for index in 0..PROVIDERS {
        project.write_file(
            &format!("packages/p{index}/package.json"),
            &format!(r#"{{"name":"p{index}","version":"1.0.0","files":[]}}"#),
        );
    }
    let out = external_output_dir();

    // Fewer descriptors than the closure has packages.
    let output = support::lpm_from_path(&project, std::path::Path::new("/bin/sh"))
        .args(["-c", r#"ulimit -n 96 && exec "$0" "$@""#])
        .arg(assert_cmd::cargo::cargo_bin("lpm-rs"))
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "app",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run lpm deploy --dry-run");

    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn workspace_with_refusable_main(api_main: &str, util_main: &str) -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/api/package.json",
        &format!(
            r#"{{"name":"api","version":"1.0.0","main":"{api_main}","dependencies":{{"util-pkg":"workspace:*"}}}}"#
        ),
    );
    project.write_file("packages/api/index.js", "module.exports = 1;");
    project.write_file(
        "packages/util/package.json",
        &format!(r#"{{"name":"util-pkg","version":"1.0.0","main":"{util_main}"}}"#),
    );
    project.write_file("packages/util/index.js", "module.exports = 2;");
    project
}

#[test]
fn deploy_force_keeps_the_previous_output_when_the_member_s_files_are_refused() {
    let project = workspace_with_refusable_main("../escape.js", "index.js");
    let out = external_output_dir();
    std::fs::write(out.path().join("keep.txt"), "earlier deploy").unwrap();

    let output = lpm(&project)
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "api",
            "--force",
        ])
        .output()
        .expect("run lpm deploy --force");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("project-relative path"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(out.path().join("keep.txt")).unwrap(),
        "earlier deploy"
    );
}

#[test]
fn deploy_leaves_no_output_and_names_a_refused_workspace_provider() {
    let project = workspace_with_refusable_main("index.js", "../escape.js");
    let out = external_output_dir();

    let output = lpm(&project)
        .args(["deploy", out.path().to_str().unwrap(), "--filter", "api"])
        .output()
        .expect("run lpm deploy");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workspace provider \"util-pkg\"")
            && stderr.contains("project-relative path"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_dir(out.path()).unwrap().count(),
        0,
        "a refused deploy wrote to the output"
    );
}

#[test]
fn deploy_dry_run_reports_a_selection_the_deploy_would_refuse() {
    let project = workspace_with_refusable_main("index.js", "../escape.js");
    let out = external_output_dir();

    let output = lpm(&project)
        .args([
            "--json",
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "api",
            "--dry-run",
        ])
        .output()
        .expect("run lpm deploy --dry-run");

    assert!(!output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["success"], false, "{envelope}");
    assert!(
        envelope
            .to_string()
            .contains("workspace provider \\\"util-pkg\\\""),
        "{envelope}"
    );
}

#[tokio::test]
async fn deploy_refuses_a_private_key_publish_would_refuse_and_writes_nothing() {
    use support::lpm_with_registry;
    use support::mock_registry::MockRegistry;
    let project = workspace_with_refusable_main("index.js", "index.js");
    project.write_file(
        "packages/api/server.pem",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
    );
    project.write_file(
        "packages/util/certs/tls.key",
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----\n",
    );
    let registry = MockRegistry::start().await;
    let out = external_output_dir();
    std::fs::write(out.path().join("keep.txt"), "earlier deploy").unwrap();

    for dry_run in [false, true] {
        let mut arguments = vec![
            "--json",
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "api",
            "--force",
        ];
        if dry_run {
            arguments.push("--dry-run");
        }
        let output = lpm_with_registry(&project, &registry.url())
            .args(&arguments)
            .output()
            .unwrap();

        assert!(!output.status.success(), "dry run: {dry_run}");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
        assert_eq!(envelope["error"], "secret_scan_failed", "{envelope}");
        let found: Vec<(&str, &str, &str, &str)> = envelope["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|found| {
                (
                    found["package"].as_str().unwrap(),
                    found["directory"].as_str().unwrap(),
                    found["path"].as_str().unwrap(),
                    found["pattern"].as_str().unwrap(),
                )
            })
            .collect();
        let separator = std::path::MAIN_SEPARATOR_STR;
        assert_eq!(
            found,
            [
                (
                    "api",
                    &*format!("packages{separator}api"),
                    "server.pem",
                    "private_key_rsa"
                ),
                (
                    "util-pkg",
                    &*format!("packages{separator}util"),
                    "certs/tls.key",
                    "private_key_pkcs8"
                ),
            ],
            "{envelope}"
        );
        assert_eq!(
            std::fs::read_dir(out.path()).unwrap().count(),
            1,
            "a refused deploy changed the output"
        );
        assert_eq!(
            std::fs::read_to_string(out.path().join("keep.txt")).unwrap(),
            "earlier deploy"
        );
    }

    let human = lpm_with_registry(&project, &registry.url())
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "api",
            "--force",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(!human.status.success());
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(
        stderr.contains("RSA private key in server.pem")
            && stderr.contains("Deploy blocked")
            && stderr.contains("--allow-secrets"),
        "{stderr}"
    );

    let allowed = lpm_with_registry(&project, &registry.url())
        .args([
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "api",
            "--force",
            "--allow-secrets",
        ])
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(out.path().join("server.pem").is_file());
}

#[tokio::test]
async fn deploy_names_the_dependency_ignore_files_a_commit_of_the_output_would_obey() {
    use support::lpm_with_registry;
    use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_with_files};
    let package = "@lpm.dev/test.gi-pkg";
    let tarball = make_tarball_with_files(
        package,
        "1.0.0",
        &[
            (".gitignore", b"dist/\n"),
            ("dist/index.js", b"module.exports = 'from dist';\n"),
        ],
    );
    let registry = MockRegistry::start().await;
    let metadata = serde_json::json!({
        "name": package,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "name": package,
            "version": "1.0.0",
            "main": "dist/index.js",
            "dist": {
                "tarball": format!("{}{}", registry.url(), MockRegistry::tarball_path(package, "1.0.0")),
                "integrity": compute_integrity(&tarball),
            },
        }},
    });
    registry
        .with_package_metadata_and_tarballs(package, metadata, &[("1.0.0", tarball)])
        .await;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/app/package.json",
        &format!(r#"{{"name":"app","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#),
    );
    let out = external_output_dir();

    let output = lpm_with_registry(&project, &registry.url())
        .args([
            "--json",
            "deploy",
            out.path().to_str().unwrap(),
            "--filter",
            "app",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = support::assertions::parse_json_output(&output.stdout);
    let named: Vec<&str> = summary["dependency_ignore_files"]
        .as_array()
        .unwrap_or_else(|| panic!("{summary}"))
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    assert!(!named.is_empty(), "{summary}");
    for path in &named {
        assert!(
            out.path().join(path).is_file() && path.ends_with("/.gitignore"),
            "{path}"
        );
    }
    assert!(!named.contains(&".lpm/.gitignore"), "{summary}");
}
