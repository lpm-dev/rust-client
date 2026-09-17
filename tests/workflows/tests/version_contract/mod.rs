use super::{read_package_json, run_git};
use crate::support::{
    LOCK_CONTENTION_MARKER_ENV, TempProject, lpm, lpm_spawnable, wait_for_lock_contention,
};

#[cfg(unix)]
#[test]
fn signed_version_commits_ignore_signature_display_configuration() {
    for fail_tag in [false, true] {
        let project = super::initialized_git_project();
        let key = project.home().join("signing-key");
        let output = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let allowed = project.home().join("allowed-signers");
        std::fs::write(
            &allowed,
            format!(
                "test@example.com {}",
                std::fs::read_to_string(key.with_extension("pub")).unwrap()
            ),
        )
        .unwrap();
        run_git(&project, &["config", "gpg.format", "ssh"]);
        run_git(
            &project,
            &["config", "user.signingkey", key.to_str().unwrap()],
        );
        run_git(
            &project,
            &[
                "config",
                "gpg.ssh.allowedSignersFile",
                allowed.to_str().unwrap(),
            ],
        );
        run_git(&project, &["config", "commit.gpgSign", "true"]);
        run_git(&project, &["config", "log.showSignature", "true"]);
        if fail_tag {
            project.write_file(".git/refs/tags/v1.2.4.lock", "held");
        }
        let out = lpm(&project)
            .args(["version", "patch", "--json"])
            .output()
            .unwrap();
        if fail_tag {
            assert!(!out.status.success());
            assert_eq!(
                read_package_json(&project, "package.json")["version"],
                "1.2.3"
            );
            assert_eq!(run_git(&project, &["rev-list", "--count", "HEAD"]), "1");
        } else {
            assert!(out.status.success(), "{out:?}");
            let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(json["commit"], "v1.2.4");
            assert_eq!(run_git(&project, &["tag", "--list", "v1.2.4"]), "v1.2.4");
        }
        assert!(!project.file_exists(".lpm/release-apply/journal.json"));
    }
}

fn member_project() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.2.3"}"#,
    );
    run_git(&project, &["init"]);
    run_git(&project, &["config", "user.email", "test@example.com"]);
    run_git(&project, &["config", "user.name", "Test User"]);
    run_git(&project, &["add", "."]);
    run_git(&project, &["commit", "-m", "initial"]);
    project
}

#[test]
fn nested_version_failure_restores_the_actual_manifest_index() {
    let project = member_project();
    let original = project.read_file("packages/core/package.json");
    run_git(
        &project,
        &["config", "gpg.program", "nonexistent-version-signer"],
    );
    run_git(&project, &["config", "commit.gpgSign", "true"]);
    let out = lpm(&project)
        .current_dir(project.path().join("packages/core"))
        .args(["version", "patch"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(project.read_file("packages/core/package.json"), original);
    assert_eq!(run_git(&project, &["diff", "--cached", "--name-only"]), "");
}

#[test]
fn nested_version_recovers_after_staging_without_dirtying_the_index() {
    let project = member_project();
    let out = lpm(&project)
        .current_dir(project.path().join("packages/core"))
        .env("LPM_INTERNAL_TEST_VERSION_ABORT_AFTER_GIT_STAGE", "add")
        .args(["version", "patch"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let out = lpm(&project)
        .current_dir(project.path().join("packages/core"))
        .args(["version", "patch"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.4"
    );
    assert_eq!(run_git(&project, &["diff", "--cached", "--name-only"]), "");
}

#[cfg(unix)]
#[test]
fn version_preserves_additional_commits_created_by_a_post_commit_hook() {
    let project = super::initialized_git_project();
    super::write_git_hook(
        &project,
        "post-commit",
        "#!/bin/sh\ngit -c core.hooksPath=/dev/null commit --allow-empty -m 'hook commit'\n",
    );
    let out = lpm(&project).args(["version", "patch"]).output().unwrap();
    assert!(!out.status.success());
    assert_eq!(
        run_git(&project, &["log", "-1", "--pretty=%s"]),
        "hook commit"
    );
    assert_eq!(run_git(&project, &["rev-list", "--count", "HEAD"]), "3");
    assert!(project.file_exists(".lpm/release-apply/journal.json"));
    assert_eq!(run_git(&project, &["tag", "--list", "v1.2.4"]), "");
}

#[cfg(unix)]
#[test]
fn version_preserves_a_commit_amended_by_a_post_commit_hook() {
    let project = super::initialized_git_project();
    super::write_git_hook(
        &project,
        "post-commit",
        "#!/bin/sh\nprintf 'hook content' > hook.txt\ngit add hook.txt\ngit -c core.hooksPath=/dev/null commit --amend -m 'amended hook commit'\n",
    );
    let out = lpm(&project).args(["version", "patch"]).output().unwrap();
    assert!(!out.status.success());
    assert_eq!(
        run_git(&project, &["log", "-1", "--pretty=%s"]),
        "amended hook commit"
    );
    assert_eq!(
        run_git(&project, &["show", "HEAD:hook.txt"]),
        "hook content"
    );
    assert!(project.file_exists(".lpm/release-apply/journal.json"));
}

#[cfg(unix)]
#[test]
fn version_refuses_a_merge_commit_created_by_a_hook() {
    let project = super::initialized_git_project();
    let old = run_git(&project, &["rev-parse", "HEAD"]);
    super::write_git_hook(
        &project,
        "post-commit",
        &format!(
            "#!/bin/sh\nside=$(printf side | git commit-tree {old}^{{tree}} -p {old})\nmerge=$(printf 'hook merge' | git commit-tree HEAD^{{tree}} -p {old} -p \"$side\")\ngit update-ref HEAD \"$merge\"\n"
        ),
    );
    let out = lpm(&project).args(["version", "patch"]).output().unwrap();
    assert!(
        !out.status.success(),
        "version accepted a hook-created merge"
    );
    assert_eq!(
        run_git(&project, &["log", "-1", "--pretty=%s"]),
        "hook merge"
    );
    assert!(project.file_exists(".lpm/release-apply/journal.json"));
    assert_eq!(run_git(&project, &["tag", "--list", "v1.2.4"]), "");
}

#[test]
fn release_updates_dependency_ranges_when_the_old_manifest_version_has_a_prefix() {
    let project = member_project();
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"v1.2.3"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"core":"^1.2.3"}}"#,
    );
    let out = lpm(&project)
        .args([
            "release", "apply", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "2.0.0"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^2.0.0"
    );
}

#[cfg(unix)]
#[test]
fn version_refuses_a_member_replaced_after_planning() {
    use std::os::unix::fs::PermissionsExt as _;
    let project = member_project();
    let shim_dir = project.home().join("git-shim");
    std::fs::create_dir(&shim_dir).unwrap();
    let shim = shim_dir.join("git");
    std::fs::write(&shim, "#!/bin/sh\nif [ \"$*\" = 'rev-parse --verify HEAD^{commit}' ]; then\n touch \"$VERSION_PAUSE\"\n while [ ! -f \"$VERSION_RESUME\" ]; do sleep 0.01; done\nfi\nexec \"$VERSION_REAL_GIT\" \"$@\"\n").unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let real_git = std::process::Command::new("which")
        .arg("git")
        .output()
        .unwrap();
    assert!(real_git.status.success());
    let pause = project.home().join("paused");
    let resume = project.home().join("resume");
    let mut paths = vec![shim_dir];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let mut command = lpm_spawnable(&project);
    command
        .current_dir(project.path().join("packages/core"))
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env(
            "VERSION_REAL_GIT",
            String::from_utf8(real_git.stdout).unwrap().trim(),
        )
        .env("VERSION_PAUSE", &pause)
        .env("VERSION_RESUME", &resume)
        .args(["version", "patch", "--json"]);
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !pause.exists() {
        if child.try_wait().unwrap().is_some() || std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!(
                "version did not reach Git pause: {:?}",
                child.wait_with_output()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let original = project.read_file("packages/core/package.json");
    std::fs::rename(
        project.path().join("packages/core"),
        project.path().join("original-core"),
    )
    .unwrap();
    project.write_file("packages/core/package.json", &original);
    std::fs::write(resume, "resume").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        !out.status.success(),
        "version wrote a replacement generation"
    );
    assert_eq!(project.read_file("packages/core/package.json"), original);
    assert_eq!(
        std::fs::read_to_string(project.path().join("original-core/package.json")).unwrap(),
        original
    );
}

#[cfg(unix)]
#[test]
fn version_refuses_a_replaced_lock_directory_after_contention() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    let lock_path = lpm_common::project_install_lock(project.path());
    let old_lock = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();
    let marker = project.home().join("lock-directory-replacement");
    let mut cmd = lpm_spawnable(&project);
    cmd.env(LOCK_CONTENTION_MARKER_ENV, &marker)
        .args(["version", "patch", "--no-git-tag-version"]);
    let mut child = cmd.spawn().unwrap();
    wait_for_lock_contention(&mut child, &marker, &lock_path);
    std::fs::rename(
        project.path().join(".lpm"),
        project.home().join("old-state"),
    )
    .unwrap();
    let replacement_lock = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();
    drop(old_lock);
    let out = child.wait_with_output().unwrap();
    drop(replacement_lock);
    assert!(
        !out.status.success(),
        "version used a lock from a different state directory"
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.2.3"
    );
    assert!(!project.file_exists(".lpm/release-apply/journal.json"));
}

#[cfg(unix)]
#[test]
fn version_refuses_replaced_roots_in_mutating_and_preview_modes() {
    for workspace in [false, true] {
        for preview in [false, true] {
            let original = if workspace {
                r#"{"name":"root","version":"1.2.3","workspaces":["packages/*"]}"#
            } else {
                r#"{"name":"root","version":"1.2.3"}"#
            };
            let project = TempProject::empty(original);
            let lock_path = lpm_common::project_install_lock(project.path());
            let held = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();
            let marker = project.home().join("root-replacement");
            let mut cmd = lpm_spawnable(&project);
            cmd.env(LOCK_CONTENTION_MARKER_ENV, &marker).args([
                "version",
                "patch",
                "--no-git-tag-version",
                "--json",
            ]);
            if preview {
                cmd.arg("--dry-run");
            }
            let mut child = cmd.spawn().unwrap();
            wait_for_lock_contention(&mut child, &marker, &lock_path);
            std::fs::rename(project.path(), project.home().join("original-root")).unwrap();
            std::fs::create_dir(project.path()).unwrap();
            project.write_file("package.json", original);
            drop(held);
            let out = child.wait_with_output().unwrap();
            assert!(!out.status.success());
            let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(json["error_code"], "script");
            assert!(
                json["error"]
                    .as_str()
                    .unwrap()
                    .contains("version directory changed"),
                "{json}"
            );
            assert_eq!(project.read_file("package.json"), original);
            assert_eq!(
                std::fs::read_to_string(project.home().join("original-root/package.json")).unwrap(),
                original
            );
        }
    }
}

#[test]
fn version_increments_the_rightmost_numeric_prerelease_identifier() {
    for (old, expected) in [
        ("1.2.3-1.beta", "1.2.3-2.beta"),
        ("1.2.3-alpha.1.beta", "1.2.3-alpha.2.beta"),
        ("1.2.3-alpha", "1.2.3-alpha.0"),
    ] {
        let project =
            TempProject::empty(&serde_json::json!({"name":"demo", "version":old}).to_string());
        let out = lpm(&project)
            .args(["version", "prerelease", "--no-git-tag-version"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            read_package_json(&project, "package.json")["version"],
            expected
        );
    }
}

#[test]
fn version_accepts_existing_prefixes_and_zero_padded_build_metadata() {
    for old in ["v1.2.3", "1.2.3+001"] {
        let project =
            TempProject::empty(&serde_json::json!({"name":"demo", "version":old}).to_string());
        let out = lpm(&project)
            .args(["version", "patch", "--no-git-tag-version", "--json"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            read_package_json(&project, "package.json")["version"],
            "1.2.4"
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(json["plan"]["packages"][0]["old_version"], old);
    }
}

#[test]
fn version_preserves_exact_build_metadata_spelling() {
    let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
    let out = lpm(&project)
        .args(["version", "1.3.0+001", "--no-git-tag-version"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "1.3.0+001"
    );
}

#[test]
fn version_reports_prerelease_overflow_without_panicking_or_writing() {
    let original = r#"{"name":"demo","version":"1.2.3-18446744073709551615"}"#;
    let project = TempProject::empty(original);
    let out = lpm(&project)
        .args(["version", "prerelease", "--json", "--no-git-tag-version"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("overflow must return the JSON error envelope");
    assert_eq!(json["success"], false);
    assert_eq!(project.read_file("package.json"), original);
}

#[test]
fn version_accepts_a_utf8_bom_and_preserves_original_bytes_during_preview() {
    let original = "\u{feff}{\"name\":\"demo\",\"version\":\"1.2.3\"}\n";
    let project = TempProject::empty(original);
    let out = lpm(&project)
        .args(["version", "patch", "--dry-run", "--no-git-tag-version"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(project.read_file("package.json"), original);
    let out = lpm(&project)
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let json: serde_json::Value = serde_json::from_str(
        project
            .read_file("package.json")
            .trim_start_matches('\u{feff}'),
    )
    .unwrap();
    assert_eq!(json["version"], "1.2.4");
}

#[test]
fn version_restores_the_original_bom_manifest_when_commit_signing_fails() {
    let project = super::initialized_git_project();
    let original = "\u{feff}{\"name\":\"demo\",\"version\":\"1.2.3\"}\n";
    project.write_file("package.json", original);
    run_git(&project, &["add", "package.json"]);
    run_git(&project, &["commit", "-m", "add BOM"]);
    run_git(
        &project,
        &["config", "gpg.program", "nonexistent-version-signer"],
    );
    run_git(&project, &["config", "commit.gpgSign", "true"]);
    let out = lpm(&project)
        .args(["version", "patch", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        json["error"].as_str().unwrap().contains("git commit"),
        "{json}"
    );
    assert_eq!(project.read_file("package.json"), original);
    assert_eq!(run_git(&project, &["diff", "--cached", "--name-only"]), "");
}

#[cfg(unix)]
#[test]
fn version_rejects_fifo_manifests_without_blocking() {
    for (file, preview) in [
        ("package.json", false),
        ("package.json", true),
        ("pnpm-workspace.yaml", false),
        ("pnpm-workspace.yaml", true),
    ] {
        let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
        let path = project.path().join(file);
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let mut command = lpm(&project);
        command.args(["version", "patch", "--no-git-tag-version", "--json"]);
        if preview {
            command.arg("--dry-run");
        }
        let out = command
            .timeout(std::time::Duration::from_secs(3))
            .output()
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out.stdout)
            .expect("special input must fail promptly with JSON");
        assert_eq!(json["success"], false);
    }
}

#[cfg(unix)]
#[test]
fn version_refuses_replaced_member_directories_after_lock_contention() {
    let project = member_project();
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();
    let marker = project.home().join("version-directory-replacement");
    let mut cmd = lpm_spawnable(&project);
    cmd.current_dir(project.path().join("packages/core"))
        .env(LOCK_CONTENTION_MARKER_ENV, &marker)
        .args(["version", "patch", "--no-git-tag-version"]);
    let mut child = cmd.spawn().unwrap();
    wait_for_lock_contention(&mut child, &marker, &lock_path);
    std::fs::rename(
        project.path().join("packages/core"),
        project.path().join("original-core"),
    )
    .unwrap();
    let replacement = r#"{"name":"core","version":"5.0.0"}"#;
    project.write_file("packages/core/package.json", replacement);
    drop(transaction_lock);
    let out = child.wait_with_output().unwrap();
    assert!(
        !out.status.success(),
        "version accepted a different project directory"
    );
    assert_eq!(project.read_file("packages/core/package.json"), replacement);
    assert_eq!(
        read_package_json(&project, "original-core/package.json")["version"],
        "1.2.3"
    );
}

#[cfg(unix)]
#[test]
fn version_never_creates_lock_files_through_symlinks() {
    for leaf in [
        None,
        Some(".install.lock"),
        Some(".install.lock.writer-intent"),
        Some(".install.lock.writer-queue"),
    ] {
        let project = TempProject::empty(r#"{"name":"demo","version":"1.2.3"}"#);
        let outside = tempfile::tempdir().unwrap();
        if let Some(leaf) = leaf {
            std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
            std::os::unix::fs::symlink(
                outside.path().join("outside-lock"),
                project.path().join(".lpm").join(leaf),
            )
            .unwrap();
        } else {
            std::os::unix::fs::symlink(outside.path(), project.path().join(".lpm")).unwrap();
        }
        let out = lpm(&project)
            .args(["version", "patch", "--no-git-tag-version", "--json"])
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert_eq!(
            std::fs::read_dir(outside.path()).unwrap().count(),
            0,
            "created outside locks through {leaf:?}"
        );
        assert_eq!(
            read_package_json(&project, "package.json")["version"],
            "1.2.3"
        );
    }
}

#[cfg(unix)]
#[test]
fn version_preserves_a_replacement_after_writing_when_git_fails() {
    use std::os::unix::fs::PermissionsExt as _;
    let project = member_project();
    let shim_dir = project.home().join("git-shim");
    std::fs::create_dir(&shim_dir).unwrap();
    let shim = shim_dir.join("git");
    std::fs::write(&shim, "#!/bin/sh\nif [ \"$1\" = 'add' ]; then\n touch \"$VERSION_PAUSE\"\n while [ ! -f \"$VERSION_RESUME\" ]; do sleep 0.01; done\nfi\nexec \"$VERSION_REAL_GIT\" \"$@\"\n").unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let real_git = std::process::Command::new("which")
        .arg("git")
        .output()
        .unwrap();
    assert!(real_git.status.success());
    let pause = project.home().join("paused");
    let resume = project.home().join("resume");
    let mut paths = vec![shim_dir];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let mut command = lpm_spawnable(&project);
    command
        .current_dir(project.path().join("packages/core"))
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env(
            "VERSION_REAL_GIT",
            String::from_utf8(real_git.stdout).unwrap().trim(),
        )
        .env("VERSION_PAUSE", &pause)
        .env("VERSION_RESUME", &resume)
        .args(["version", "patch", "--json"]);
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !pause.exists() {
        if child.try_wait().unwrap().is_some() || std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!(
                "version did not reach Git pause: {:?}",
                child.wait_with_output()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let original = project.read_file("packages/core/package.json");
    std::fs::rename(
        project.path().join("packages/core"),
        project.home().join("original-core"),
    )
    .unwrap();
    project.write_file("packages/core/package.json", &original);
    std::fs::write(resume, "resume").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        !out.status.success(),
        "version wrote a replacement generation"
    );
    assert_eq!(project.read_file("packages/core/package.json"), original);
    assert_eq!(
        std::fs::read_to_string(project.home().join("original-core/package.json")).unwrap(),
        original
    );
}
