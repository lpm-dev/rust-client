use super::{AvailableLpmPublishPreflight, read_package_json, workspace_project};
use crate::support::mock_registry::MockRegistry;
use crate::support::{TempProject, lpm, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn change(project: &TempProject, mode: &str, bump: &str) -> std::process::Output {
    lpm(project)
        .args([
            "release", mode, "--filter", "core", "--bump", bump, "--json",
        ])
        .output()
        .unwrap()
}

#[test]
fn release_rejects_catalog_ranges_that_exclude_the_planned_member_version() {
    for pnpm in [false, true] {
        for name in ["default", "shared"] {
            let project = workspace_project();
            let mut root = read_package_json(&project, "package.json");
            if pnpm {
                let yaml = if name == "default" {
                    "catalog:\n  core: '^1.2.3'\n"
                } else {
                    "catalogs:\n  shared:\n    core: '^1.2.3'\n"
                };
                project.write_file("pnpm-workspace.yaml", yaml);
            } else {
                root["catalogs"] = serde_json::json!({name:{"core":"^1.2.3"}});
                project.write_file("package.json", &root.to_string());
            }
            let reference = if name == "default" {
                "catalog:"
            } else {
                "catalog:shared"
            };
            project.write_file("packages/app/package.json", &serde_json::json!({"name":"app","version":"1.0.0","dependencies":{"core":reference}}).to_string());
            for mode in ["plan", "apply"] {
                let out = change(&project, mode, "major");
                assert!(
                    !out.status.success(),
                    "accepted stale catalog in {mode}: {out:?}"
                );
                assert_eq!(
                    read_package_json(&project, "packages/core/package.json")["version"],
                    "1.2.3"
                );
            }
            let out = change(&project, "apply", "patch");
            assert!(out.status.success(), "compatible catalog failed: {out:?}");
            assert_eq!(
                read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
                reference
            );
        }
    }
}

#[test]
fn release_allows_unselected_private_members_without_versions() {
    let project = workspace_project();
    project.write_file(
        "packages/site/package.json",
        r#"{"name":"site","private":true}"#,
    );
    for mode in ["plan", "apply"] {
        let out = change(&project, mode, "patch");
        assert!(
            out.status.success(),
            "unrelated private app blocked {mode}: {out:?}"
        );
    }
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.4"
    );
}

#[test]
fn release_updates_private_unversioned_dependents_without_adding_a_version() {
    let project = workspace_project();
    project.write_file(
        "packages/site/package.json",
        r#"{"name":"site","private":true,"dependencies":{"core":"^1.2.3"}}"#,
    );
    let out = change(&project, "apply", "major");
    assert!(out.status.success(), "{out:?}");
    let site = read_package_json(&project, "packages/site/package.json");
    assert_eq!(site["dependencies"]["core"], "^2.0.0");
    assert!(site.get("version").is_none());
}

#[tokio::test]
async fn release_publish_ignores_an_unrelated_private_member_without_a_version() {
    let project = workspace_project();
    project.write_file(
        "packages/site/package.json",
        r#"{"name":"site","private":true}"#,
    );
    project.write_file(
        "packages/core/lpm.json",
        r#"{"publish":{"lpm":{"name":"@lpm.dev/acme.core"}}}"#,
    );
    let registry = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .mount(registry.server())
        .await;
    let out = lpm_with_registry(&project, &registry.url())
        .args([
            "release",
            "publish",
            "--filter",
            "core",
            "--dry-run",
            "--lpm",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
}

#[test]
fn release_ignores_cycles_outside_the_selected_packages() {
    let project = workspace_project();
    project.write_file(
        "packages/a/package.json",
        r#"{"name":"a","version":"1.0.0","dependencies":{"b":"*"}}"#,
    );
    project.write_file(
        "packages/b/package.json",
        r#"{"name":"b","version":"1.0.0","dependencies":{"a":"*"}}"#,
    );
    let out = change(&project, "plan", "patch");
    assert!(out.status.success(), "{out:?}");
    let out = change(&project, "apply", "patch");
    assert!(out.status.success(), "{out:?}");
    let out = lpm(&project)
        .args([
            "release", "plan", "--filter", "missing", "--bump", "patch", "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "empty selection failed: {out:?}");
    let out = lpm(&project)
        .args(["release", "plan", "--all", "--bump", "patch", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "selected cycle was accepted");
}

#[test]
fn release_updates_root_dependency_ranges_without_bumping_the_root_version() {
    for versioned in [false, true] {
        let project = workspace_project();
        let mut root = read_package_json(&project, "package.json");
        if !versioned {
            root.as_object_mut().unwrap().remove("version");
            root.as_object_mut().unwrap().remove("name");
        }
        for section in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            root[section] = serde_json::json!({"core":"^1.2.3"});
        }
        project.write_file("package.json", &root.to_string());
        let out = change(&project, "apply", "major");
        assert!(out.status.success(), "{out:?}");
        let updated = read_package_json(&project, "package.json");
        for section in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            assert_eq!(updated[section]["core"], "^2.0.0");
        }
        assert_eq!(updated.get("version"), root.get("version"));
    }
}

#[test]
fn release_rejects_conflicting_change_entries_in_any_file_order() {
    for entries in [
        ["core major\n", "core patch\n"],
        ["core patch\n", "core major\n"],
        ["core 2.0.0\n", "core 3.0.0\n"],
    ] {
        let project = workspace_project();
        project.write_file(".lpm/changes/a", entries[0]);
        project.write_file(".lpm/changes/z", entries[1]);
        let out = change(&project, "plan", "patch");
        assert!(!out.status.success(), "accepted conflicting bumps: {out:?}");
        assert_eq!(
            read_package_json(&project, "packages/core/package.json")["version"],
            "1.2.3"
        );
    }
}

#[test]
fn release_previews_reject_plans_that_exceed_the_manifest_transaction_limit() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    for i in 0..129 {
        project.write_file(
            &format!("packages/p{i}/package.json"),
            &serde_json::json!({"name":format!("p{i}"),"version":"1.0.0"}).to_string(),
        );
    }
    for mode in [vec!["plan"], vec!["apply", "--dry-run"], vec!["apply"]] {
        let out = lpm(&project)
            .arg("release")
            .args(mode)
            .args(["--all", "--bump", "patch", "--json"])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "accepted impossible transaction preview: {out:?}"
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(json["error"].as_str().unwrap().contains("128"), "{json}");
        assert_eq!(
            read_package_json(&project, "packages/p0/package.json")["version"],
            "1.0.0"
        );
    }
}

#[tokio::test]
async fn release_publish_rejects_stale_catalog_ranges_before_remote_preflight() {
    let project = workspace_project();
    let mut root = read_package_json(&project, "package.json");
    root["catalogs"] = serde_json::json!({"default":{"core":"^1.2.3"}});
    project.write_file("package.json", &root.to_string());
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"2.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"core":"catalog:"}}"#,
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{"publish":{"lpm":{"name":"@lpm.dev/acme.app"}}}"#,
    );
    let registry = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"success":true,"packageExists":true})),
        )
        .mount(registry.server())
        .await;
    let out = lpm_with_registry(&project, &registry.url())
        .args([
            "release",
            "publish",
            "--filter",
            "app",
            "--dry-run",
            "--lpm",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "accepted stale published catalog: {out:?}"
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

#[cfg(unix)]
#[test]
fn release_refuses_replaced_roots_and_lock_directories_after_contention() {
    use crate::support::{LOCK_CONTENTION_MARKER_ENV, lpm_spawnable, wait_for_lock_contention};
    for replace_root in [false, true] {
        for mode in ["plan", "apply"] {
            let project = workspace_project();
            let root_manifest = project.read_file("package.json");
            let lock_path = lpm_common::project_install_lock(project.path());
            let held = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();
            let marker = project.home().join("release-lock-contention");
            let mut cmd = lpm_spawnable(&project);
            cmd.env(LOCK_CONTENTION_MARKER_ENV, &marker).args([
                "release", mode, "--filter", "core", "--bump", "patch", "--json",
            ]);
            let mut child = cmd.spawn().unwrap();
            wait_for_lock_contention(&mut child, &marker, &lock_path);
            if replace_root {
                std::fs::rename(project.path(), project.home().join("old-root")).unwrap();
                project.write_file("package.json", &root_manifest);
                project.write_file(
                    "packages/core/package.json",
                    r#"{"name":"core","version":"1.2.3"}"#,
                );
            } else {
                std::fs::rename(
                    project.path().join(".lpm"),
                    project.home().join("old-state"),
                )
                .unwrap();
                std::fs::create_dir(project.path().join(".lpm")).unwrap();
            }
            drop(held);
            let out = child.wait_with_output().unwrap();
            assert!(
                !out.status.success(),
                "{mode} accepted replacement (root={replace_root}): {out:?}"
            );
            assert_eq!(
                read_package_json(&project, "packages/core/package.json")["version"],
                "1.2.3"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn release_does_not_block_on_a_fifo_workspace_manifest() {
    use crate::support::lpm_spawnable;
    for unsafe_path in [
        "pnpm-workspace.yaml",
        "package.json",
        "packages/site/package.json",
    ] {
        for mode in ["plan", "apply"] {
            let project = workspace_project();
            project.write_file(unsafe_path, "{}");
            let manifest = project.path().join(unsafe_path);
            std::fs::remove_file(&manifest).unwrap();
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&manifest)
                    .status()
                    .unwrap()
                    .success()
            );
            let mut child = lpm_spawnable(&project)
                .args([
                    "release", mode, "--filter", "core", "--bump", "patch", "--json",
                ])
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let out = child.wait_with_output().unwrap();
                    panic!("release {mode} blocked on FIFO {unsafe_path}: {out:?}");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let out = child.wait_with_output().unwrap();
            assert!(!out.status.success(), "unsafe manifest accepted: {out:?}");
        }
    }
}

#[cfg(unix)]
#[test]
fn release_publish_never_runs_a_replaced_members_lifecycle() {
    use crate::support::lpm_spawnable;
    use std::os::unix::fs::symlink;
    let project = workspace_project();
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.2.3","scripts":{"prepack":"node pause.cjs"}}"#,
    );
    project.write_file("packages/core/pause.cjs", "const fs=require('fs');fs.writeFileSync('ready','');const end=Date.now()+15000;while(!fs.existsSync('resume')){if(Date.now()>end)process.exit(2);Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,20);}");
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("package.json"),
        r#"{"name":"app","version":"1.0.0","scripts":{"prepack":"node evil.cjs"}}"#,
    )
    .unwrap();
    std::fs::write(
        outside.path().join("evil.cjs"),
        "require('fs').writeFileSync('outside-ran','yes')",
    )
    .unwrap();
    let mut child = lpm_spawnable(&project)
        .args([
            "release",
            "publish",
            "--all",
            "--dry-run",
            "--lpm",
            "--yes",
            "--json",
        ])
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !project.file_exists("packages/core/ready") {
        if child.try_wait().unwrap().is_some() || std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!(
                "prepack did not reach pause: {:?}",
                child.wait_with_output()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::fs::rename(
        project.path().join("packages/app"),
        project.path().join("original-app"),
    )
    .unwrap();
    symlink(outside.path(), project.path().join("packages/app")).unwrap();
    project.write_file("packages/core/resume", "");
    let out = child.wait_with_output().unwrap();
    assert!(
        !outside.path().join("outside-ran").exists(),
        "outside lifecycle ran: {out:?}"
    );
    assert!(!out.status.success(), "replaced member accepted: {out:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn release_publish_handles_many_members_with_a_bounded_file_descriptor_budget() {
    use crate::support::lpm_spawnable;
    use std::os::unix::process::CommandExt;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    for index in 0..300 {
        project.write_file(
            &format!("packages/p{index}/package.json"),
            &serde_json::json!({"name":format!("@lpm.dev/acme.p{index}"),"version":"1.0.0"})
                .to_string(),
        );
    }
    let registry = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .mount(registry.server())
        .await;
    let mut cmd = lpm_spawnable(&project);
    cmd.env("LPM_REGISTRY_URL", registry.url()).args([
        "release",
        "publish",
        "--all",
        "--dry-run",
        "--ignore-scripts",
        "--lpm",
        "--json",
    ]);
    // SAFETY: only the child process limit changes; setrlimit is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 256,
                rlim_max: 256,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "release exhausted descriptors: {out:?}"
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["results"].as_array().unwrap().len(), 300);
}

#[tokio::test]
async fn release_publish_refreshes_its_generation_after_an_accepted_skills_manifest_update() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    for index in 0..8 {
        project.write_file(&format!("packages/p{index}/package.json"), &serde_json::json!({"name":format!("@lpm.dev/acme.p{index}"),"version":"1.0.0","files":["index.js"]}).to_string());
        project.write_file(
            &format!("packages/p{index}/index.js"),
            "module.exports = {};",
        );
    }
    project.write_file(
        "packages/p0/.lpm/skills/usage.md",
        "---\nname: usage\ndescription: Complete usage guidance\n---\n# Usage\nUse this package to load application configuration. Import the module, call its public methods, and handle returned errors.\n",
    );
    let registry = MockRegistry::start().await;
    registry.with_whoami("acme", "test@example.com").await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .mount(registry.server())
        .await;
    Mock::given(method("PUT"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"success":true,"message":"Package published"})),
        )
        .expect(8)
        .mount(registry.server())
        .await;
    let out = lpm_with_registry(&project, &registry.url())
        .env("RUST_LOG", "lpm_workspace::publish_name_scan=trace")
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--ignore-scripts",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        read_package_json(&project, "packages/p0/package.json")["files"],
        serde_json::json!(["index.js", ".lpm/skills"])
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let scans = stderr.matches("publish workspace name scan").count();
    assert!(
        (1..=2).contains(&scans),
        "expected one initial scan and at most one refresh, got {scans}: {stderr}"
    );
}

#[test]
fn release_change_files_have_aggregate_and_record_limits() {
    for records in [true, false] {
        let project = workspace_project();
        if records {
            project.write_file(".lpm/changes/many", &"core patch\n".repeat(100_001));
        } else {
            let content = format!("#{}", "x".repeat(16 * 1024 * 1024 - 1));
            for i in 0..5 {
                project.write_file(&format!(".lpm/changes/{i}"), &content);
            }
        }
        let out = change(&project, "plan", "patch");
        assert!(
            !out.status.success(),
            "accepted excess change data (records={records})"
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(json["error"].as_str().unwrap().contains("change"), "{json}");
    }
}

#[cfg(unix)]
#[test]
fn release_rejects_linked_change_directories_and_files() {
    use std::os::unix::fs::symlink;
    for directory in [false, true] {
        let project = workspace_project();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("entry"), "core major\n").unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        if directory {
            symlink(outside.path(), project.path().join(".lpm/changes")).unwrap();
        } else {
            std::fs::create_dir(project.path().join(".lpm/changes")).unwrap();
            symlink(
                outside.path().join("entry"),
                project.path().join(".lpm/changes/entry"),
            )
            .unwrap();
        }
        let out = change(&project, "apply", "patch");
        assert!(
            !out.status.success(),
            "accepted linked change input: {out:?}"
        );
        assert_eq!(
            read_package_json(&project, "packages/core/package.json")["version"],
            "1.2.3"
        );
    }
}

#[cfg(unix)]
#[test]
fn release_workspace_scan_caps_directory_entries() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    let packages = project.path().join("packages");
    std::fs::create_dir(&packages).unwrap();
    for i in 0..100_001 {
        std::fs::create_dir(packages.join(format!("p{i}"))).unwrap();
    }
    let out = lpm(&project)
        .args(["release", "plan", "--all", "--bump", "patch", "--json"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "accepted an excessive workspace scan"
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("100000"), "{json}");
}

#[cfg(unix)]
#[tokio::test]
async fn release_lifecycle_finds_member_tools_after_changing_directory() {
    use std::os::unix::fs::PermissionsExt;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file("packages/core/package.json", r#"{"name":"@lpm.dev/acme.core","version":"1.0.0","scripts":{"prepack":"cd src && release-local-builder"}}"#);
    project.write_file("packages/core/src/index.js", "module.exports = {};");
    project.write_file(
        "packages/core/node_modules/.bin/release-local-builder",
        "#!/bin/sh\nprintf built > tool-marker\n",
    );
    std::fs::set_permissions(
        project
            .path()
            .join("packages/core/node_modules/.bin/release-local-builder"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let registry = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .mount(registry.server())
        .await;
    let out = lpm_with_registry(&project, &registry.url())
        .args([
            "release",
            "publish",
            "--all",
            "--dry-run",
            "--lpm",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "local tool was not found after cd: {out:?}"
    );
    assert_eq!(project.read_file("packages/core/src/tool-marker"), "built");
}
