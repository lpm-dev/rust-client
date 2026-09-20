use super::*;

fn verify_result(project: &TempProject, args: &[&str]) -> serde_json::Value {
    let output = lpm(project)
        .args(["store", "verify", "--json"])
        .args(args)
        .output()
        .unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn fast_verify_rejects_empty_or_non_file_package_manifests() {
    for shape in ["empty", "directory"] {
        let project = TempProject::empty(r#"{"name":"store-shape"}"#);
        seed_v1_entry(&project, "fixture", "1.0.0", true);
        let manifest = v1_entry_dir(&project, "fixture", "1.0.0").join("package.json");
        std::fs::remove_file(&manifest).unwrap();
        if shape == "empty" {
            std::fs::write(&manifest, "").unwrap();
        } else {
            std::fs::create_dir(&manifest).unwrap();
        }
        let report = verify_result(&project, &[]);
        assert_eq!(report["success"], false, "{shape}: {report}");
    }
}

#[test]
fn deep_verify_rejects_malformed_present_identity_fields() {
    for manifest in [
        "[]",
        "null",
        r#"{"name":42,"version":"1.0.0"}"#,
        r#"{"name":"fixture","version":42}"#,
    ] {
        let project = TempProject::empty(r#"{"name":"store-shape"}"#);
        seed_v1_entry(&project, "fixture", "1.0.0", true);
        std::fs::write(
            v1_entry_dir(&project, "fixture", "1.0.0").join("package.json"),
            manifest,
        )
        .unwrap();
        let report = verify_result(&project, &["--deep"]);
        assert_eq!(report["success"], false, "{manifest}: {report}");
    }
}

#[test]
fn deep_verify_accepts_legacy_manifest_without_identity_fields() {
    let project = TempProject::empty(r#"{"name":"store-shape"}"#);
    seed_v1_entry(&project, "fixture", "1.0.0", true);
    std::fs::write(
        v1_entry_dir(&project, "fixture", "1.0.0").join("package.json"),
        "{}",
    )
    .unwrap();
    let report = verify_result(&project, &["--deep"]);
    assert_eq!(report["success"], true, "{report}");
}

#[test]
fn verify_fix_refuses_redirected_package_directories() {
    for layout in ["v1", "v2", "v2-node-modules"] {
        let project = TempProject::empty(r#"{"name":"store-redirect"}"#);
        let outside = project.path().join("outside-package");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(
            outside.join("package.json"),
            r#"{"name":"fixture","version":"1.0.0"}"#,
        )
        .unwrap();
        let package = if layout == "v1" {
            seed_v1_entry(&project, "fixture", "1.0.0", true);
            v1_entry_dir(&project, "fixture", "1.0.0")
        } else {
            seed_v2_entry(&project, "fixture", "1.0.0");
            store_root(&project)
                .join("v2/links/fixture@1.0.0+0123456789abcdef/node_modules/fixture")
        };
        std::fs::remove_dir_all(&package).unwrap();
        if layout == "v2-node-modules" {
            let outside_modules = project.path().join("outside-modules");
            std::fs::create_dir(&outside_modules).unwrap();
            std::fs::rename(&outside, outside_modules.join("fixture")).unwrap();
            std::fs::remove_dir(package.parent().unwrap()).unwrap();
            lpm_common::create_dir_symlink_or_junction(&outside_modules, package.parent().unwrap())
                .unwrap();
        } else {
            lpm_common::create_dir_symlink_or_junction(&outside, &package).unwrap();
        }
        let report = verify_result(&project, &["--fix"]);
        assert_eq!(report["success"], false, "{layout}: {report}");
        assert!(!outside.join(".lpm-security.json").exists());
        assert!(
            !project
                .path()
                .join("outside-modules/fixture/.lpm-security.json")
                .exists()
        );
    }
}

#[test]
fn verify_fix_replaces_hardlinked_security_cache_without_overwriting_target() {
    let project = TempProject::empty(r#"{"name":"store-cache"}"#);
    seed_v1_entry(&project, "fixture", "1.0.0", true);
    let sentinel = project.path().join("sentinel.json");
    std::fs::write(&sentinel, b"sentinel").unwrap();
    let cache = v1_entry_dir(&project, "fixture", "1.0.0").join(".lpm-security.json");
    std::fs::hard_link(&sentinel, &cache).unwrap();
    let report = verify_result(&project, &["--fix"]);
    assert_eq!(report["success"], true, "{report}");
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    assert!(serde_json::from_slice::<serde_json::Value>(&std::fs::read(cache).unwrap()).is_ok());
}

#[test]
#[cfg(unix)]
fn verify_fix_replaces_symlinked_security_cache_without_overwriting_target() {
    let project = TempProject::empty(r#"{"name":"store-cache"}"#);
    seed_v1_entry(&project, "fixture", "1.0.0", true);
    let sentinel = project.path().join("sentinel.json");
    std::fs::write(&sentinel, b"sentinel").unwrap();
    let cache = v1_entry_dir(&project, "fixture", "1.0.0").join(".lpm-security.json");
    std::os::unix::fs::symlink(&sentinel, &cache).unwrap();
    let report = verify_result(&project, &["--fix"]);
    assert_eq!(report["success"], true, "{report}");
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    assert!(
        !std::fs::symlink_metadata(&cache)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
#[cfg(unix)]
fn clean_removes_dangling_version_root_links() {
    for version in ["v1", "v2", "v3"] {
        let project = TempProject::empty(r#"{"name":"store-clean"}"#);
        std::fs::create_dir_all(store_root(&project)).unwrap();
        let link = store_root(&project).join(version);
        std::os::unix::fs::symlink(project.path().join("missing"), &link).unwrap();
        lpm(&project)
            .args(["store", "clean", "--json"])
            .assert()
            .success();
        assert!(std::fs::symlink_metadata(link).is_err(), "{version}");
    }
}

#[test]
fn maintenance_refuses_redirected_store_roots_before_creating_control_files() {
    for action in ["verify", "clean"] {
        let project = TempProject::empty(r#"{"name":"store-root"}"#);
        let outside = project.path().join("outside-store");
        std::fs::create_dir_all(outside.join("v1/fixture@1.0.0")).unwrap();
        let sentinel = outside.join("v1/fixture@1.0.0/package.json");
        std::fs::write(&sentinel, "{}").unwrap();
        std::fs::create_dir_all(store_root(&project).parent().unwrap()).unwrap();
        lpm_common::create_dir_symlink_or_junction(&outside, &store_root(&project)).unwrap();
        lpm(&project)
            .args(["store", action, "--json"])
            .assert()
            .failure();
        assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "{}");
        assert!(!outside.join(".gc.lock").exists());
    }
}

#[test]
fn verify_refuses_redirected_store_ancestors() {
    for relative in [
        "v1",
        "v2",
        "v3",
        "v2/links",
        "v2/objects",
        "v3/blobs",
        "v3/metadata",
    ] {
        let project = TempProject::empty(r#"{"name":"store-ancestor"}"#);
        let outside = project.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let path = store_root(&project).join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        lpm_common::create_dir_symlink_or_junction(&outside, &path).unwrap();
        lpm(&project)
            .args(["store", "verify", "--fix", "--json"])
            .assert()
            .failure();
        assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0, "{relative}");
    }
}

#[test]
fn verify_fix_refuses_redirected_scope_directory() {
    let project = TempProject::empty(r#"{"name":"store-scope"}"#);
    seed_v2_entry(&project, "fixture", "1.0.0");
    let entry = store_root(&project).join("v2/links/fixture@1.0.0+0123456789abcdef");
    let sidecar = entry.join(".lpm-link-meta.json");
    let mut meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
    meta["name"] = serde_json::json!("@scope/fixture");
    std::fs::write(sidecar, serde_json::to_vec(&meta).unwrap()).unwrap();
    let link = entry.join("node_modules/@scope");
    std::fs::create_dir(&link).unwrap();
    std::fs::rename(entry.join("node_modules/fixture"), link.join("fixture")).unwrap();
    std::fs::write(
        link.join("fixture/package.json"),
        r#"{"name":"@scope/fixture","version":"1.0.0"}"#,
    )
    .unwrap();
    let outside = project.path().join("outside-scope");
    std::fs::rename(&link, &outside).unwrap();
    lpm_common::create_dir_symlink_or_junction(&outside, &link).unwrap();
    let report = verify_result(&project, &["--fix"]);
    assert_eq!(report["success"], false, "{report}");
    assert!(!outside.join("fixture/.lpm-security.json").exists());
}

#[test]
#[cfg(unix)]
fn verify_refuses_redirected_package_manifest() {
    let project = TempProject::empty(r#"{"name":"store-manifest"}"#);
    seed_v1_entry(&project, "fixture", "1.0.0", true);
    let manifest = v1_entry_dir(&project, "fixture", "1.0.0").join("package.json");
    let outside = project.path().join("outside.json");
    std::fs::rename(&manifest, &outside).unwrap();
    std::os::unix::fs::symlink(outside, manifest).unwrap();
    let report = verify_result(&project, &["--fix"]);
    assert_eq!(report["success"], false, "{report}");
}
