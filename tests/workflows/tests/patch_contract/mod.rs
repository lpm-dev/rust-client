use super::*;

fn commit_output(project: &TempProject, staging: &Path) -> std::process::Output {
    lpm_with_registry(project, "http://127.0.0.1:1")
        .args(["patch-commit", staging.to_str().unwrap(), "--json"])
        .output()
        .unwrap()
}

fn shared_artifact_collision(prior_registration: bool, equivalent_path: bool, case_variant: bool) {
    let project = TempProject::empty(r#"{"name":"patch-owner"}"#);
    let integrity = seed_store_package(&project, "foo", "1.0.0", &[("index.js", "original\n")]);
    let staging = extract_staging(&project, "foo@1.0.0");
    let path = if case_variant {
        "patches/FOO@1.0.0.patch"
    } else if equivalent_path {
        "patches/./foo@1.0.0.patch"
    } else {
        "patches/foo@1.0.0.patch"
    };
    let mut manifest = serde_json::json!({"name":"patch-owner","lpm":{"patchedDependencies":{"bar@1.0.0":{"path":path,"originalIntegrity":integrity}}}});
    if prior_registration {
        manifest["lpm"]["patchedDependencies"]["foo@1.0.0"] =
            serde_json::json!({"path":"patches/foo@1.0.0.patch","originalIntegrity":integrity});
    }
    project.write_file("package.json", &manifest.to_string());
    project.write_file("patches/foo@1.0.0.patch", "artifact owned by bar\n");
    if case_variant && !project.path().join(path).exists() {
        std::fs::remove_dir_all(staging).unwrap();
        return;
    }
    let before = project.read_file("package.json");
    std::fs::write(staging.join("node_modules/foo/index.js"), "edited\n").unwrap();
    let out = commit_output(&project, &staging);
    assert!(
        !out.status.success(),
        "commit must reject another registration's artifact: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(project.read_file("package.json"), before);
    assert_eq!(
        project.read_file("patches/foo@1.0.0.patch"),
        "artifact owned by bar\n"
    );
    assert!(staging.exists());
    std::fs::remove_dir_all(staging).unwrap();
}
#[test]
fn patch_commit_rejects_shared_destination_artifact() {
    shared_artifact_collision(true, false, false);
}
#[test]
fn patch_commit_rejects_equivalent_shared_destination_path() {
    shared_artifact_collision(true, true, false);
}
#[test]
fn patch_commit_rejects_first_registration_overwriting_another_owner() {
    shared_artifact_collision(false, false, false);
}

fn rejects_unusable_filename(filename: &std::ffi::OsStr) {
    let project = TempProject::empty(r#"{"name":"patch-path"}"#);
    seed_store_package(&project, "foo", "1.0.0", &[("index.js", "original\n")]);
    let staging = extract_staging(&project, "foo@1.0.0");
    std::fs::write(
        staging.join("node_modules/foo").join(filename),
        "new content\n",
    )
    .unwrap();
    let before = project.read_file("package.json");
    let out = commit_output(&project, &staging);
    assert!(
        !out.status.success(),
        "commit accepted unusable filename {filename:?}: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(project.read_file("package.json"), before);
    assert!(!project.path().join("patches/foo@1.0.0.patch").exists());
    assert!(staging.exists());
    std::fs::remove_dir_all(staging).unwrap();
}
#[cfg(unix)]
#[test]
fn patch_commit_rejects_colon_filename_before_registration() {
    rejects_unusable_filename(std::ffi::OsStr::new("bad:name.txt"));
}
#[test]
fn patch_commit_rejects_case_insensitive_internal_filename() {
    rejects_unusable_filename(std::ffi::OsStr::new(".INTEGRITY"));
}
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn patch_commit_rejects_non_utf8_filename_without_losing_edits() {
    use std::os::unix::ffi::OsStrExt;
    rejects_unusable_filename(std::ffi::OsStr::from_bytes(b"invalid-\xff.txt"));
}
#[test]
fn patch_commit_accepts_unicode_text_filename() {
    let project = TempProject::empty(r#"{"name":"patch-unicode"}"#);
    seed_store_package(&project, "foo", "1.0.0", &[("index.js", "original\n")]);
    let staging = extract_staging(&project, "foo@1.0.0");
    std::fs::write(staging.join("node_modules/foo/café.txt"), "new content\n").unwrap();
    let out = commit_output(&project, &staging);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        project
            .read_file("patches/foo@1.0.0.patch")
            .contains("café.txt")
    );
}
#[test]
fn patch_remove_dry_run_rejects_unsafe_deletion_like_apply() {
    let project = TempProject::empty(
        r#"{"name":"remove-preview","lpm":{"patchedDependencies":{"foo@1.0.0":{"path":"package.json","originalIntegrity":"sha512-fixture"}}}}"#,
    );
    let before = project.read_file("package.json");
    let applied = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch-remove", "foo", "--json"])
        .output()
        .unwrap();
    assert!(!applied.status.success());
    let preview = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch-remove", "foo", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        !preview.status.success(),
        "preview accepted unsafe deletion: {}",
        String::from_utf8_lossy(&preview.stdout)
    );
    assert_eq!(project.read_file("package.json"), before);
    let keep = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch-remove", "foo", "--dry-run", "--keep-file", "--json"])
        .output()
        .unwrap();
    assert!(keep.status.success());
    assert_eq!(project.read_file("package.json"), before);
}

fn install_output(project: &TempProject, url: &str, flags: &[&str]) -> std::process::Output {
    lpm_with_registry(project, url)
        .args(["install", "--json"])
        .args(flags)
        .output()
        .unwrap()
}
fn assert_install_succeeds(project: &TempProject, url: &str, flags: &[&str]) {
    let out = install_output(project, url, flags);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
fn author_payload_patch(project: &TempProject, name: &str) {
    let staging = extract_staging(project, &format!("{name}@1.0.0"));
    std::fs::write(
        staging.join("node_modules").join(name).join("payload.txt"),
        "patched\n",
    )
    .unwrap();
    let out = commit_output(project, &staging);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[tokio::test]
async fn install_rejects_patch_source_drift_even_with_old_baseline_cached() {
    use support::mock_registry::{MockRegistry, make_tarball_with_files};
    let name = "patch-drift-contract";
    let project = TempProject::empty(
        &serde_json::json!({"name":"patch-source","dependencies":{name:"1.0.0"}}).to_string(),
    );
    let original = MockRegistry::start().await;
    original
        .with_package(
            name,
            "1.0.0",
            &make_tarball_with_files(name, "1.0.0", &[("payload.txt", b"original A\n")]),
        )
        .await;
    assert_install_succeeds(&project, &original.url(), &[]);
    author_payload_patch(&project, name);
    let replacement = MockRegistry::start().await;
    replacement
        .with_package(
            name,
            "1.0.0",
            &make_tarball_with_files(name, "1.0.0", &[("payload.txt", b"replacement B\n")]),
        )
        .await;
    for file in ["lpm.lock", "lpm.lockb"] {
        let _ = std::fs::remove_file(project.path().join(file));
    }
    // Both mocks serve the npm registry, so drop the metadata the first one
    // served; the store keeps the old baseline.
    let _ = std::fs::remove_dir_all(project.cache_dir().join("metadata"));
    let out = install_output(&project, &replacement.url(), &["--force"]);
    assert!(
        !out.status.success(),
        "patch authored for A must not overwrite selected B: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        project.read_file(&format!("node_modules/{name}/payload.txt")),
        "replacement B\n"
    );
    let error: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        error["error"].as_str().unwrap().contains("integrity"),
        "{error}"
    );
}

async fn omitted_patch(section: &str, offline: bool, transitive: bool, shared: bool) {
    use support::mock_registry::{MockRegistry, make_tarball, make_tarball_with_files};
    let target = "patched-omission-target";
    let runtime = "patch-runtime-root";
    let dev_parent = "patch-dev-parent";
    let mut manifest =
        serde_json::json!({"name":"patch-omission","dependencies":{runtime:"1.0.0"}});
    manifest[section] = serde_json::json!({if transitive {dev_parent} else {target}:"1.0.0"});
    let project = TempProject::empty(&manifest.to_string());
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            target,
            "1.0.0",
            &make_tarball_with_files(target, "1.0.0", &[("payload.txt", b"original\n")]),
        )
        .await;
    registry
        .with_package_and_deps(
            runtime,
            "1.0.0",
            &make_tarball(runtime, "1.0.0"),
            if shared {
                serde_json::json!({target:"1.0.0"})
            } else {
                serde_json::json!({})
            },
        )
        .await;
    if transitive {
        registry
            .with_package_and_deps(
                dev_parent,
                "1.0.0",
                &make_tarball(dev_parent, "1.0.0"),
                serde_json::json!({target:"1.0.0"}),
            )
            .await;
    }
    assert_install_succeeds(&project, &registry.url(), &[]);
    author_payload_patch(&project, target);
    assert_install_succeeds(&project, &registry.url(), &[]);
    let mut flags = if section == "devDependencies" {
        vec!["--prod"]
    } else {
        vec!["--omit", "optional"]
    };
    if offline {
        flags.push("--offline");
    }
    let omitted_out = install_output(&project, &registry.url(), &flags);
    assert!(
        omitted_out.status.success(),
        "{}",
        String::from_utf8_lossy(&omitted_out.stdout)
    );
    let installed_path = if shared {
        format!("node_modules/{runtime}/node_modules/{target}/payload.txt")
    } else {
        format!("node_modules/{target}/payload.txt")
    };
    if shared {
        let root =
            std::fs::canonicalize(project.path().join("node_modules").join(runtime)).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.parent().unwrap().join(target).join("payload.txt"))
                .unwrap(),
            "patched\n",
            "runtime={root:?}, target={:?}, output={}",
            std::fs::canonicalize(root.parent().unwrap().join(target)),
            String::from_utf8_lossy(&omitted_out.stdout)
        );
    } else {
        assert!(!project.path().join(&installed_path).exists());
        if transitive {
            assert!(
                !project
                    .path()
                    .join(format!("node_modules/{dev_parent}"))
                    .exists()
            );
        }
    }
    let package: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(
        package["lpm"]["patchedDependencies"]
            .get(format!("{target}@1.0.0"))
            .is_some()
    );
    assert_install_succeeds(&project, &registry.url(), &[]);
    let restored = if transitive {
        format!("node_modules/{dev_parent}/node_modules/{target}/payload.txt")
    } else {
        format!("node_modules/{target}/payload.txt")
    };
    let restored = if transitive {
        let root =
            std::fs::canonicalize(project.path().join("node_modules").join(dev_parent)).unwrap();
        root.parent().unwrap().join(target).join("payload.txt")
    } else {
        project.path().join(restored)
    };
    assert_eq!(std::fs::read_to_string(restored).unwrap(), "patched\n");
}
#[tokio::test]
async fn install_prod_skips_registered_dev_patch() {
    omitted_patch("devDependencies", false, false, false).await;
}
#[tokio::test]
async fn install_offline_prod_skips_registered_dev_patch() {
    omitted_patch("devDependencies", true, false, false).await;
}
#[tokio::test]
async fn install_omit_optional_skips_registered_patch() {
    omitted_patch("optionalDependencies", false, false, false).await;
}
#[tokio::test]
async fn install_offline_omit_optional_skips_registered_patch() {
    omitted_patch("optionalDependencies", true, false, false).await;
}
#[tokio::test]
async fn install_prod_skips_dev_transitive_patch() {
    omitted_patch("devDependencies", false, true, false).await;
}
#[tokio::test]
async fn install_prod_still_applies_patch_shared_by_runtime_and_dev() {
    omitted_patch("devDependencies", false, true, true).await;
}

#[cfg(unix)]
#[test]
fn patch_commit_rejects_literal_backslash_filename() {
    rejects_unusable_filename(std::ffi::OsStr::new("bad\\name.txt"));
}

#[tokio::test]
async fn dev_executes_patched_compatibility_copy() {
    use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
    let project = TempProject::empty(
        r#"{"name":"patch-compat","scripts":{"dev":"vite"},"dependencies":{"vite":"1.0.0"}}"#,
    );
    let registry = MockRegistry::start().await;
    registry.with_package("vite", "1.0.0", &make_tarball_from_pkg_json(
        serde_json::json!({"name":"vite","version":"1.0.0","bin":{"vite":"bin/dev-tool.js"}}),
        &[("payload.txt", b"original\n"), ("bin/dev-tool.js", b"#!/usr/bin/env node\nconsole.log(require('fs').readFileSync(require('path').join(__dirname, '..', 'payload.txt'), 'utf8'));\n")],
    )).await;
    assert_install_succeeds(&project, &registry.url(), &[]);
    author_payload_patch(&project, "vite");
    for _ in 0..2 {
        let out = lpm_with_registry(&project, &registry.url())
            .args(["dev", "--no-open", "--no-dashboard", "--port", "4567"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("patched"),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let root = project
            .path()
            .join("node_modules/.lpm/compat")
            .canonicalize()
            .unwrap();
        let package = project
            .path()
            .join("node_modules/vite")
            .canonicalize()
            .unwrap();
        assert!(package.starts_with(root), "{package:?}");
        assert_eq!(
            std::fs::read_to_string(package.join("payload.txt")).unwrap(),
            "patched\n"
        );
    }
}

#[test]
fn patch_commit_rejects_case_variant_shared_artifact() {
    shared_artifact_collision(false, false, true);
}
#[test]
fn patch_commit_retains_reauthored_artifact_with_case_variant_path() {
    let project = TempProject::empty(r#"{"name":"patch-case"}"#);
    let integrity = seed_store_package(&project, "foo", "1.0.0", &[("index.js", "original\n")]);
    let staging = extract_staging(&project, "foo@1.0.0");
    project.write_file("patches/FOO@1.0.0.patch", "old patch");
    if !project.path().join("patches/foo@1.0.0.patch").exists() {
        std::fs::remove_dir_all(staging).unwrap();
        return;
    }
    project.write_file("package.json", &serde_json::json!({"name":"patch-case","lpm":{"patchedDependencies":{"foo@1.0.0":{"path":"patches/FOO@1.0.0.patch","originalIntegrity":integrity}}}}).to_string());
    std::fs::write(staging.join("node_modules/foo/index.js"), "edited\n").unwrap();
    let out = commit_output(&project, &staging);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        project.path().join("patches/foo@1.0.0.patch").exists(),
        "successful commit deleted its own artifact"
    );
}

#[test]
fn install_without_dependencies_rejects_stale_patch_registration() {
    let project = TempProject::empty(r#"{"name":"stale-patch"}"#);
    seed_store_package(&project, "foo", "1.0.0", &[("payload.txt", "original\n")]);
    author_payload_patch(&project, "foo");
    let out = install_output(&project, "http://127.0.0.1:1", &[]);
    assert!(
        !out.status.success(),
        "stale patch accepted: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn patch_remove_retains_case_variant_artifact_owned_by_another_registration() {
    let project = TempProject::empty(
        r#"{"name":"patch-case","lpm":{"patchedDependencies":{"foo@1.0.0":{"path":"patches/foo.patch","originalIntegrity":"sha512-fixture"},"bar@1.0.0":{"path":"patches/FOO.patch","originalIntegrity":"sha512-fixture"}}}}"#,
    );
    project.write_file("patches/foo.patch", "shared artifact");
    if !project.path().join("patches/FOO.patch").exists() {
        return;
    }
    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch-remove", "foo", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        project.path().join("patches/FOO.patch").exists(),
        "deleted another registration's artifact"
    );
}

#[tokio::test]
async fn full_install_restores_dependencies_after_omission() {
    use support::mock_registry::{MockRegistry, make_tarball};
    let project = TempProject::empty(
        r#"{"name":"restore-omitted","dependencies":{"runtime-root":"1.0.0"},"devDependencies":{"dev-root":"1.0.0"}}"#,
    );
    let registry = MockRegistry::start().await;
    for name in ["runtime-root", "dev-root"] {
        registry
            .with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
            .await;
    }
    assert_install_succeeds(&project, &registry.url(), &[]);
    assert_install_succeeds(&project, &registry.url(), &["--prod"]);
    assert!(!project.path().join("node_modules/dev-root").exists());
    assert_install_succeeds(&project, &registry.url(), &[]);
    assert!(
        project.path().join("node_modules/dev-root").exists(),
        "full install incorrectly reused production-only freshness state"
    );
}
