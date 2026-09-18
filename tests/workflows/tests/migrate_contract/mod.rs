use super::*;
use serde_json::json;

fn convert_only(project: &TempProject) {
    lpm(project)
        .args([
            "migrate",
            "--force",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
        ])
        .assert()
        .success();
}

#[test]
fn rollback_restores_a_peer_rule_only_manifest_translation() {
    let project = TempProject::from_fixture("migrate-pnpm");
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    package["pnpm"] = json!({"peerDependencyRules":{"ignoreMissing":["react"]}});
    let original = serde_json::to_string_pretty(&package).unwrap();
    project.write_file("package.json", &original);
    convert_only(&project);
    assert!(project.read_file("package.json").contains("\"lpm\""));
    lpm(&project)
        .args(["migrate", "--rollback"])
        .assert()
        .success();
    assert_eq!(project.read_file("package.json"), original);
}

#[test]
fn rollback_removes_a_newly_generated_ci_template() {
    let project = TempProject::from_fixture("migrate-npm");
    std::fs::create_dir_all(project.path().join(".github/workflows")).unwrap();
    lpm(&project)
        .args([
            "migrate",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--ci",
        ])
        .assert()
        .success();
    assert!(project.file_exists(".github/workflows/ci.lpm.yml"));
    lpm(&project)
        .args(["migrate", "--rollback"])
        .assert()
        .success();
    assert!(!project.file_exists(".github/workflows/ci.lpm.yml"));
}

#[test]
fn repeated_conversion_preserves_the_original_rollback_snapshot() {
    let project = TempProject::from_fixture("migrate-pnpm-overrides");
    let original = project.read_file("package.json");
    convert_only(&project);
    convert_only(&project);
    lpm(&project)
        .args(["migrate", "--rollback"])
        .assert()
        .success();
    assert_eq!(project.read_file("package.json"), original);
    assert!(!project.file_exists("lpm.lock"));
}

#[test]
fn rollback_rejects_dry_run_before_restoring_files() {
    let project = TempProject::from_fixture("migrate-npm");
    convert_only(&project);
    let lock = project.read_file("lpm.lock");
    let output = lpm(&project)
        .args(["migrate", "--rollback", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "contradictory rollback preview must be rejected"
    );
    assert_eq!(project.read_file("lpm.lock"), lock);
    assert!(project.file_exists(".lpm-migrate-manifest.json"));
}

#[test]
fn rollback_rejects_legacy_paths_outside_the_project() {
    for version in [None, Some(1), Some(99)] {
        let project = TempProject::empty("{}");
        let external = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(external.path(), "preserve outside bytes").unwrap();
        let mut manifest = json!({"backups":[],"created":[external.path()]});
        if let Some(version) = version {
            manifest["version"] = json!(version);
        }
        project.write_file(".lpm-migrate-manifest.json", &manifest.to_string());
        let output = lpm(&project)
            .args(["migrate", "--rollback"])
            .output()
            .unwrap();
        assert!(
            external.path().exists(),
            "legacy rollback removed an outside file: {version:?}"
        );
        assert!(
            !output.status.success(),
            "unsafe rollback manifest must be rejected"
        );
        assert_eq!(
            std::fs::read_to_string(external.path()).unwrap(),
            "preserve outside bytes"
        );
    }
}

#[cfg(unix)]
#[test]
fn migration_refuses_a_linked_backup_destination_without_outside_writes() {
    let project = TempProject::from_fixture("migrate-pnpm");
    let external = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(external.path(), "preserve outside bytes").unwrap();
    std::os::unix::fs::symlink(
        external.path(),
        project.path().join("pnpm-lock.yaml.backup"),
    )
    .unwrap();
    let output = lpm(&project)
        .args([
            "migrate",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
        ])
        .output()
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(external.path()).unwrap(),
        "preserve outside bytes"
    );
    assert!(!output.status.success());
    assert!(!project.file_exists("lpm.lock"));
}

#[test]
fn migration_rejects_a_malformed_yarn_lock_before_writing_files() {
    let project = TempProject::empty("{}");
    project.write_file("yarn.lock", "this is not a lockfile\n");
    let output = lpm(&project)
        .args([
            "migrate",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "malformed Yarn input must not become an empty success"
    );
    assert!(!project.file_exists("lpm.lock"));
    assert!(!project.file_exists("yarn.lock.backup"));
}

#[test]
fn bom_manifest_verification_runs_the_requested_test() {
    let project = TempProject::from_fixture("migrate-npm");
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    package["scripts"] = json!({"test":"exit 1"});
    project.write_file("package.json", &format!("\u{feff}{}", package));
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    let output = command
        .args(["migrate", "--no-install", "--no-npmrc", "--no-ci"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "BOM must not bypass the failing verification script"
    );
}

#[test]
fn bom_manifests_support_each_pnpm_translation() {
    for fixture in ["migrate-pnpm-overrides", "migrate-pnpm-patches"] {
        let project = TempProject::from_fixture(fixture);
        let original = project.read_file("package.json");
        project.write_file("package.json", &format!("\u{feff}{original}"));
        convert_only(&project);
        lpm(&project)
            .args(["migrate", "--rollback"])
            .assert()
            .success();
        assert_eq!(
            project.read_file("package.json"),
            format!("\u{feff}{original}")
        );
    }
}

#[test]
fn migration_json_keeps_verification_output_out_of_the_envelope() {
    let project = TempProject::from_fixture("migrate-npm");
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    package["scripts"] = json!({"test":"echo verification-output"});
    project.write_file("package.json", &package.to_string());
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    let output = command
        .args(["migrate", "--no-install", "--no-npmrc", "--no-ci", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&output.stdout);
    assert!(
        parsed.is_ok(),
        "migration stdout must contain one JSON envelope: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn move_patch_source(project: &TempProject) {
    let body = project.read_file("patches/ms@2.1.3.patch");
    std::fs::remove_file(project.path().join("patches/ms@2.1.3.patch")).unwrap();
    project.write_file("custom/ms.patch", &body);
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    package["pnpm"]["patchedDependencies"]["ms@2.1.3"] = json!("custom/ms.patch");
    project.write_file("package.json", &package.to_string());
}

#[test]
fn rollback_tracks_created_patches_before_verification_failure() {
    let project = TempProject::from_fixture("migrate-pnpm-patches");
    move_patch_source(&project);
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    package["scripts"] = json!({"test":"exit 1"});
    project.write_file("package.json", &package.to_string());
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    command
        .args(["migrate", "--no-install", "--no-npmrc", "--no-ci"])
        .assert()
        .failure();
    assert!(project.file_exists("patches/ms@2.1.3.patch"));
    lpm(&project)
        .args(["migrate", "--rollback"])
        .assert()
        .success();
    assert!(
        !project.file_exists("patches/ms@2.1.3.patch"),
        "rollback omitted a patch created before verification failed"
    );
    assert!(project.file_exists("custom/ms.patch"));
}

#[cfg(unix)]
#[test]
fn migration_validates_patch_destination_ancestors_before_backups() {
    let project = TempProject::from_fixture("migrate-pnpm-patches");
    move_patch_source(&project);
    std::fs::remove_dir(project.path().join("patches")).unwrap();
    let external = tempfile::tempdir().unwrap();
    let sentinel = external.path().join("ms@2.1.3.patch");
    std::fs::write(&sentinel, "outside-before").unwrap();
    std::os::unix::fs::symlink(external.path(), project.path().join("patches")).unwrap();
    let output = lpm(&project)
        .args([
            "migrate",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
        ])
        .output()
        .unwrap();
    assert!(
        !external.path().join("ms@2.1.3.patch.backup").exists(),
        "migration wrote a backup outside the project before rejecting the destination"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).unwrap(),
        "outside-before"
    );
    assert!(!output.status.success());
    assert!(!project.file_exists("pnpm-lock.yaml.backup"));
}

#[tokio::test]
async fn migration_reports_an_install_failure_as_failure() {
    let registry = support::mock_registry::MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{"name":"migration-host","version":"1.0.0","dependencies":{"missing-addon":"1.0.0"}}"#,
    );
    project.write_file("package-lock.json", r#"{"name":"migration-host","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"migration-host","version":"1.0.0","dependencies":{"missing-addon":"1.0.0"}}}}"#);
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    let output = support::lpm_with_registry(&project, &registry.url())
        .args([
            "migrate",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a failed install must not be reported as successful migration: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(project.file_exists(".lpm-migrate-manifest.json"));
}

#[test]
fn rollback_validates_the_entire_manifest_before_restoring_any_file() {
    let project = TempProject::empty("{}");
    project.write_file("original", "current");
    project.write_file("original.backup", "old");
    project.write_file(
        ".lpm-migrate-manifest.json",
        &json!({
            "version":2,
            "backups":[{"original":"original","backup":"original.backup"}],
            "created":["../outside"]
        })
        .to_string(),
    );
    lpm(&project)
        .args(["migrate", "--rollback"])
        .assert()
        .failure();
    assert_eq!(project.read_file("original"), "current");
    assert_eq!(project.read_file("original.backup"), "old");
}

#[test]
fn rollback_does_not_overwrite_a_hardlinked_outside_file() {
    let project = TempProject::empty("{}");
    let external = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(external.path(), "outside").unwrap();
    std::fs::hard_link(external.path(), project.path().join("original")).unwrap();
    project.write_file("original.backup", "old");
    project.write_file(
        ".lpm-migrate-manifest.json",
        &json!({
            "version":2,"backups":[{"original":"original","backup":"original.backup"}],"created":[]
        })
        .to_string(),
    );
    lpm(&project)
        .args(["migrate", "--rollback"])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(external.path()).unwrap(), "outside");
    assert_eq!(project.read_file("original"), "old");
}

#[test]
fn migration_refuses_to_replace_an_untracked_backup() {
    let project = TempProject::from_fixture("migrate-npm");
    project.write_file("package-lock.json.backup", "previous snapshot");
    lpm(&project)
        .args([
            "migrate",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
        ])
        .assert()
        .failure();
    assert_eq!(
        project.read_file("package-lock.json.backup"),
        "previous snapshot"
    );
    assert!(!project.file_exists("lpm.lock"));
}

#[cfg(unix)]
#[test]
fn migration_uses_the_selected_bun_binary_instead_of_older_sibling_text() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty("{}");
    project.write_file("bun.lock", r#"{"lockfileVersion":1,"packages":{}}"#);
    project.write_file("bun.lockb", "selected binary");
    let older = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    std::fs::File::open(project.path().join("bun.lock"))
        .unwrap()
        .set_modified(older)
        .unwrap();
    project.write_file("tools/bun", "#!/bin/sh\nprintf '%s' '{\"lockfileVersion\":1,\"packages\":{\"selected\":[\"selected@1.0.0\",\"\",{},\"sha512-YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==\"]}}'\n");
    std::fs::set_permissions(
        project.path().join("tools/bun"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut paths = vec![project.path().join("tools")];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    lpm(&project)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .args([
            "migrate",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
        ])
        .assert()
        .success();
    assert!(project.read_file("lpm.lock").contains("selected"));
}

#[test]
fn gitlab_template_prepares_every_isolated_job() {
    let project = TempProject::from_fixture("migrate-npm");
    project.write_file(".gitlab-ci.yml", "image: node:22\n");
    lpm(&project)
        .args([
            "migrate",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--ci",
        ])
        .assert()
        .success();
    let template = project.read_file(".gitlab-ci.lpm.yml");
    // GitLab runs this default setup inside each fresh job container.
    let setup = template
        .split("default:\n")
        .nth(1)
        .and_then(|tail| tail.split("\nstages:").next())
        .unwrap_or("");
    assert!(
        setup.contains("npm install -g @lpm-registry/cli"),
        "each job needs the CLI: {template}"
    );
    assert!(
        setup.contains("lpm install"),
        "each job needs its own dependency links: {template}"
    );
    assert!(
        !template.contains("artifacts:"),
        "node_modules links cannot transfer the external store"
    );
}

#[test]
fn verification_rejects_a_manifest_corrupted_by_the_build_script() {
    let project = TempProject::from_fixture("migrate-npm");
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    package["scripts"] = json!({"build":"echo invalid > package.json", "test":"echo test"});
    project.write_file("package.json", &package.to_string());
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    command
        .args(["migrate", "--no-install", "--no-npmrc", "--no-ci"])
        .assert()
        .failure();
}

#[test]
fn migration_json_reserves_stdout_for_install_hooks_and_cached_verification() {
    for cache in [false, true] {
        let project = TempProject::empty(&json!({"name":"empty","version":"1.0.0","scripts":{
            "postinstall":"echo install-output", "pretest":"echo pre-output", "test":"echo test-output && mkdir -p dist && echo built > dist/result", "posttest":"echo post-output"
        }}).to_string());
        project.write_file(
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"name":"empty","version":"1.0.0"}}}"#,
        );
        project.write_file(
            "lpm.json",
            &json!({"tasks":{"test":{"cache":cache,"outputs":["dist/**"],"inputs":["package.json","lpm.json"],"cacheEnv":[]}}}).to_string(),
        );
        for iteration in 0..2 {
            let mut command = lpm(&project);
            if iteration == 0 {
                configure_fake_node(&mut command, &project, "22.0.0");
            } else {
                reuse_fake_node(&mut command, &project);
            }
            let output = command
                .args(["migrate", "--force", "--no-npmrc", "--no-ci", "--json"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let value: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                    panic!(
                        "invalid JSON: {error}: {}",
                        String::from_utf8_lossy(&output.stdout)
                    )
                });
            insta::allow_duplicates! { insta::assert_json_snapshot!(value, @r#"
            {
              "success": true,
              "source": "npm",
              "source_version": 3,
              "package_count": 0,
              "integrity_count": 0,
              "skipped_count": 0,
              "warning_count": 0,
              "workspace_members": 0
            }
            "#); }
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("test-output"));
            if cache && iteration == 1 {
                assert!(stderr.contains("restored from cache"), "{stderr}");
            }
        }
    }
}

#[test]
fn migration_json_preserves_one_error_envelope_when_verification_fails() {
    let project = TempProject::from_fixture("migrate-npm");
    project.write_file("package.json", r#"{"name":"empty","scripts":{"pretest":"echo pre-output","test":"echo failure-output && exit 1"}}"#);
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    let output = command
        .args(["migrate", "--no-install", "--no-npmrc", "--no-ci", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(value["success"], false);
    assert!(String::from_utf8_lossy(&output.stderr).contains("failure-output"));
}

#[cfg(unix)]
#[test]
fn rollback_restores_restrictive_backup_permissions() {
    use std::os::unix::fs::PermissionsExt;
    for existing in [false, true] {
        let project = TempProject::empty("{}");
        project.write_file(".npmrc.backup", "private-registry-token");
        std::fs::set_permissions(
            project.path().join(".npmrc.backup"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        if existing {
            project.write_file(".npmrc", "public");
            std::fs::set_permissions(
                project.path().join(".npmrc"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        lpm(&project)
            .args(["migrate", "--rollback"])
            .assert()
            .success();
        assert_eq!(
            std::fs::metadata(project.path().join(".npmrc"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn verification_rejects_a_manifest_corrupted_by_postinstall() {
    let project = TempProject::empty(
        r#"{"name":"empty","version":"1.0.0","scripts":{"postinstall":"echo invalid > package.json","test":"echo test"}}"#,
    );
    project.write_file(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"":{"name":"empty","version":"1.0.0"}}}"#,
    );
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    let output = command
        .args(["migrate", "--no-npmrc", "--no-ci", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "invalid verification input must fail: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(project.file_exists(".lpm-migrate-manifest.json"));
}

#[cfg(unix)]
#[test]
fn rollback_rejects_special_files_without_waiting_for_a_writer() {
    for path in [".lpm-migrate-manifest.json", "original.backup", "original"] {
        let project = TempProject::empty("{}");
        project.write_file(
            ".lpm-migrate-manifest.json",
            &json!({"version":2,"backups":[{"original":"original","backup":"original.backup"}]})
                .to_string(),
        );
        project.write_file("original", "current");
        project.write_file("original.backup", "snapshot");
        std::fs::remove_file(project.path().join(path)).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(project.path().join(path))
                .status()
                .unwrap()
                .success()
        );
        lpm(&project)
            .timeout(std::time::Duration::from_secs(3))
            .args(["migrate", "--rollback"])
            .assert()
            .failure();
        if path != "original" {
            assert_eq!(project.read_file("original"), "current");
        }
    }
}

#[test]
fn migration_rejects_truncated_yarn_entries_and_keeps_valid_empty_lockfiles() {
    for source in ["thing@^1:\n", "thing@^1:\n  version \"1.0.0\"\ngarbage\n"] {
        let project = TempProject::empty("{}");
        project.write_file("yarn.lock", source);
        lpm(&project)
            .args([
                "migrate",
                "--no-install",
                "--skip-verify",
                "--no-npmrc",
                "--no-ci",
            ])
            .assert()
            .failure();
        assert!(!project.file_exists("lpm.lock"));
    }
    let project = TempProject::empty("{}");
    project.write_file("yarn.lock", "# yarn lockfile v1\n");
    convert_only(&project);
}

#[test]
fn verification_cannot_reuse_an_explicit_tasks_cache_for_a_different_package_script() {
    let project = TempProject::from_fixture("migrate-npm");
    project.write_file(
        "package.json",
        r#"{"name":"cache-verification","scripts":{"test":"exit 1"}}"#,
    );
    project.write_file(
        "lpm.json",
        &json!({"tasks":{"test":{
            "command":"mkdir -p dist && echo built > dist/result",
            "cache":true,"outputs":["dist/**"],"inputs":["package.json","lpm.json"],"cacheEnv":[]
        }}})
        .to_string(),
    );
    convert_only(&project);
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    command.args(["run", "test"]).assert().success();
    let mut warm = lpm(&project);
    reuse_fake_node(&mut warm, &project);
    let output = warm.args(["run", "test"]).output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cached"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut command = lpm(&project);
    reuse_fake_node(&mut command, &project);
    command
        .args([
            "migrate",
            "--force",
            "--no-install",
            "--no-npmrc",
            "--no-ci",
            "--json",
        ])
        .assert()
        .failure();
}

#[test]
fn migration_rejects_malformed_berry_and_bun_package_rows() {
    for (filename, content) in [
        (
            "yarn.lock",
            "__metadata:\n  version: 8\n\"addon@npm:1.0.0\":\n  resolution: addon@npm:1.0.0\n",
        ),
        (
            "yarn.lock",
            "__metadata:\n  version: 8\n\"addon@npm:1.0.0\": invalid\n",
        ),
        (
            "bun.lock",
            r#"{"lockfileVersion":1,"packages":{"addon":null}}"#,
        ),
        (
            "bun.lock",
            r#"{"lockfileVersion":1,"packages":{"addon":[]}}"#,
        ),
    ] {
        let project = TempProject::empty("{}");
        project.write_file(filename, content);
        lpm(&project)
            .args([
                "migrate",
                "--no-install",
                "--skip-verify",
                "--no-npmrc",
                "--no-ci",
            ])
            .assert()
            .failure();
        assert!(!project.file_exists("lpm.lock"));
    }
}

#[test]
fn migration_runs_root_install_scripts_and_propagates_their_failure() {
    let project = TempProject::empty(
        r#"{"name":"root-hooks","version":"1.0.0","scripts":{"postinstall":"echo root-hook > root-result && exit 1"}}"#,
    );
    project.write_file(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"":{"name":"root-hooks","version":"1.0.0"}}}"#,
    );
    let output = lpm(&project)
        .args([
            "migrate",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        project.file_exists("root-result"),
        "migration omitted the root install lifecycle"
    );
    assert!(!output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["success"], false);
}

#[test]
fn migration_preserves_real_bun_tuple_integrity_and_dependencies() {
    let project = TempProject::empty(r#"{"dependencies":{"parent":"1.0.0"}}"#);
    project.write_file(
        "bun.lock",
        r#"{"lockfileVersion":1,"packages":{
        "parent":["parent@1.0.0","",{"dependencies":{"child":"^2.0.0"}},"sha512-YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="],
        "child":["child@2.0.0","",{},"sha512-YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYg=="]
    }}"#,
    );
    convert_only(&project);
    let lock: toml::Value = toml::from_str(&project.read_file("lpm.lock")).unwrap();
    let parent = lock["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"].as_str() == Some("parent"))
        .unwrap();
    assert_eq!(
        parent["integrity"].as_str(),
        Some(
            "sha512-YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="
        )
    );
    assert_eq!(
        parent["dependencies"].as_array().unwrap(),
        &[toml::Value::String("child@2.0.0".into())]
    );
}

#[test]
fn migration_accepts_bun_text_comments_and_trailing_commas() {
    let project = TempProject::empty("{}");
    project.write_file("bun.lock", r#"{
        // Bun text lockfile
        "lockfileVersion": 1,
        "workspaces": {
            "": {
                "name": "example",
                "dependencies": {"addon": "^1.0.0",},
                "ignored": [true, null, 42, "text",],
            },
        },
        "packages": {
            "addon": ["addon@1.0.0", "", {}, "sha512-YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="],
        },
    }"#);
    convert_only(&project);
    assert!(project.read_file("lpm.lock").contains("addon"));
}

#[cfg(unix)]
#[test]
fn migration_parses_the_yarn_output_of_the_bun_binary_converter() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty("{}");
    project.write_file("bun.lockb", "binary fixture");
    project.write_file("tools/bun", "#!/bin/sh\ncat <<'LOCK'\n# yarn lockfile v1\n\"addon@1.0.0\":\n  version \"1.0.0\"\n  resolved \"https://registry.npmjs.org/addon/-/addon-1.0.0.tgz\"\n  integrity sha512-YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==\nLOCK\n");
    std::fs::set_permissions(
        project.path().join("tools/bun"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut paths = vec![project.path().join("tools")];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    lpm(&project)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .args([
            "migrate",
            "--no-install",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
        ])
        .assert()
        .success();
    assert!(project.read_file("lpm.lock").contains("addon"));
}

fn reuse_fake_node(command: &mut assert_cmd::Command, project: &TempProject) {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(project.home().join("fake-node-bin"))
        .chain(std::env::split_paths(&existing));
    command.env("PATH", std::env::join_paths(paths).unwrap());
}

#[test]
fn migration_resolves_bun_dependencies_from_their_nearest_package_location() {
    let project = TempProject::empty("{}");
    project.write_file(
        "bun.lock",
        r#"{"lockfileVersion":1,"packages":{
        "parent":["parent@1.0.0","","sha512-YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==",{"dependencies":{"child":"^1.0.0"}}],
        "parent/child":["child@1.0.0","","sha512-YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYg==",{}],
        "child":["child@2.0.0","","sha512-Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYw==",{}]
    }}"#,
    );
    convert_only(&project);
    let lock: toml::Value = toml::from_str(&project.read_file("lpm.lock")).unwrap();
    let parent = lock["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"].as_str() == Some("parent"))
        .unwrap();
    assert_eq!(
        parent["dependencies"].as_array().unwrap(),
        &[toml::Value::String("child@1.0.0".into())]
    );
}
