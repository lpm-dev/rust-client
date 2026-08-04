use super::*;
#[cfg(target_os = "linux")]
use crate::materialize::link_dir_recursive;
use crate::materialize::{MAX_DIRECTORY_SOURCE_DEPTH, materialize_directory_source};
use crate::platform::detach_package_hardlinks;
#[cfg(target_os = "linux")]
use crate::platform::make_bin_target_executable;
#[cfg(windows)]
use crate::platform::validate_cmd_path;
use crate::v1_isolated::{compute_link_stamp, link_stamp_matches};
use crate::validation::{is_valid_self_ref_name, validate_bin_name};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn bin_shim_path(bin_dir: &Path, name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        bin_dir.join(format!("{name}.cmd"))
    }
    #[cfg(not(windows))]
    {
        bin_dir.join(name)
    }
}

fn assert_directory_link_target(link: &Path, expected_relative_target: &Path, message: &str) {
    #[cfg(windows)]
    {
        use std::path::Component;

        let actual = std::fs::read_link(link).unwrap();
        assert!(actual.is_absolute(), "{message}: target must be absolute");

        let expected = link.parent().unwrap().join(expected_relative_target);
        let actual_segments: Vec<_> = actual
            .components()
            .filter_map(|component| match component {
                Component::Normal(segment) => Some(segment.to_owned()),
                _ => None,
            })
            .collect();
        let mut expected_segments = Vec::new();
        for component in expected.components() {
            match component {
                Component::Normal(segment) => expected_segments.push(segment.to_owned()),
                Component::ParentDir => {
                    expected_segments.pop();
                }
                _ => {}
            }
        }
        assert_eq!(actual_segments, expected_segments, "{message}");
    }
    #[cfg(not(windows))]
    {
        assert_eq!(
            std::fs::read_link(link).unwrap(),
            expected_relative_target,
            "{message}"
        );
    }
}

fn create_fake_store_package(dir: &Path, name: &str) -> PathBuf {
    let pkg_dir = dir.join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!("{{\"name\":\"{name}\"}}"),
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), "module.exports = {}").unwrap();
    pkg_dir
}

#[test]
fn link_single_direct_dep() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "foo");

    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result.linked, 1);

    // Root symlink exists
    let root_link = project_dir.path().join("node_modules/foo");
    assert!(root_link.symlink_metadata().is_ok());

    // Can read through symlink
    assert!(root_link.join("package.json").exists());
}

#[test]
fn link_with_transitive_dep() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let express_store = create_fake_store_package(store_dir.path(), "express");
    let debug_store = create_fake_store_package(store_dir.path(), "debug");

    let packages = vec![
        LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path: express_store,
            dependencies: vec![LinkDependency::registry("debug", "2.6.9")],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "2.6.9".to_string(),
            store_path: debug_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

    // Express is accessible from root
    assert!(
        project_dir
            .path()
            .join("node_modules/express")
            .symlink_metadata()
            .is_ok()
    );

    // Debug is NOT in root (it's transitive)
    assert!(
        project_dir
            .path()
            .join("node_modules/debug")
            .symlink_metadata()
            .is_err()
    );

    // Debug IS accessible from express's node_modules
    let express_debug = project_dir
        .path()
        .join(".lpm/wrappers/express@4.22.1/node_modules/debug");
    assert!(express_debug.symlink_metadata().is_ok());

    assert!(result.linked >= 2);
}

#[test]
fn lpm_dir_created() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "x");

    link_packages(
        project_dir.path(),
        &[LinkTarget {
            name: "x".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }],
        false,
        None,
    )
    .unwrap();

    // Wrapper root is now a project-root sibling.
    assert!(project_dir.path().join(".lpm/wrappers").is_dir());
}

fn create_fake_store_package_with_bin(dir: &Path, name: &str, bin_field: &str) -> PathBuf {
    let pkg_dir = dir.join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!("{{\"name\":\"{name}\",\"bin\":{bin_field}}}"),
    )
    .unwrap();
    std::fs::write(
        pkg_dir.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('hi')",
    )
    .unwrap();
    pkg_dir
}

#[test]
fn bin_links_created_for_string_bin() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path =
        create_fake_store_package_with_bin(store_dir.path(), "my-tool", "\"./cli.js\"");

    let packages = vec![LinkTarget {
        name: "my-tool".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result.bin_linked, 1);

    let bin_link = bin_shim_path(&project_dir.path().join("node_modules/.bin"), "my-tool");
    assert!(
        bin_link.symlink_metadata().is_ok(),
        ".bin/my-tool should exist"
    );
}

#[test]
fn bin_links_created_for_map_bin() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package_with_bin(
        store_dir.path(),
        "multi-bin",
        "{\"cmd-a\": \"./cli.js\", \"cmd-b\": \"./cli.js\"}",
    );

    let packages = vec![LinkTarget {
        name: "multi-bin".to_string(),
        version: "2.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result.bin_linked, 2);

    assert!(
        bin_shim_path(&project_dir.path().join("node_modules/.bin"), "cmd-a")
            .symlink_metadata()
            .is_ok()
    );
    assert!(
        bin_shim_path(&project_dir.path().join("node_modules/.bin"), "cmd-b")
            .symlink_metadata()
            .is_ok()
    );
}

#[test]
fn no_bin_dir_without_bins() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    // Package without "bin" field
    let store_path = create_fake_store_package(store_dir.path(), "no-bin");

    let packages = vec![LinkTarget {
        name: "no-bin".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result.bin_linked, 0);
    assert!(!project_dir.path().join("node_modules/.bin").exists());
}

#[test]
fn incremental_link_creates_marker() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "foo");

    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    link_packages(project_dir.path(), &packages, false, None).unwrap();

    // Marker file should exist after linking
    let marker = project_dir.path().join(".lpm/wrappers/foo@1.0.0/.linked");
    assert!(
        marker.exists(),
        ".linked marker should be created after linking"
    );
}

#[test]
fn incremental_link_skips_if_marker_present() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "bar");

    let packages = vec![LinkTarget {
        name: "bar".to_string(),
        version: "2.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link — creates everything
    let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result1.linked, 1);
    assert_eq!(result1.skipped, 0);

    // Second link — marker present, should skip
    let result2 = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result2.linked, 0);
    assert_eq!(result2.skipped, 1);

    // Files still accessible through symlinks
    assert!(
        project_dir
            .path()
            .join("node_modules/bar/package.json")
            .exists()
    );
}

#[test]
fn incremental_link_relinks_if_marker_missing() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "baz");

    let packages = vec![LinkTarget {
        name: "baz".to_string(),
        version: "3.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link — creates marker
    let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result1.linked, 1);

    // Delete marker to simulate corruption/manual cleanup
    let marker = project_dir.path().join(".lpm/wrappers/baz@3.0.0/.linked");
    assert!(marker.exists());
    std::fs::remove_file(&marker).unwrap();

    // Remove the linked package dir to force re-link
    let pkg_dir = project_dir
        .path()
        .join(".lpm/wrappers/baz@3.0.0/node_modules/baz");
    std::fs::remove_dir_all(&pkg_dir).unwrap();

    // Re-link — marker gone, should re-link
    let result2 = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result2.linked, 1);
    assert_eq!(result2.skipped, 0);

    // Marker should be re-created
    assert!(marker.exists());
}

#[test]
fn force_relinks_despite_marker() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "qux");

    let packages = vec![LinkTarget {
        name: "qux".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link
    link_packages(project_dir.path(), &packages, false, None).unwrap();
    let marker = project_dir.path().join(".lpm/wrappers/qux@1.0.0/.linked");
    assert!(marker.exists());

    // Force re-link — should NOT skip despite marker
    let result = link_packages(project_dir.path(), &packages, true, None).unwrap();
    assert_eq!(result.skipped, 0, "force should not skip any packages");
    assert_eq!(
        result.linked, 1,
        "force should actually re-link the package"
    );
}

#[test]
fn force_relink_actually_recreates_files() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "force-test");

    let packages = vec![LinkTarget {
        name: "force-test".to_string(),
        version: "2.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link
    let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result1.linked, 1);
    assert_eq!(result1.skipped, 0);

    // Second link without force — should skip
    let result2 = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result2.linked, 0);
    assert_eq!(result2.skipped, 1);

    // Third link with force — should re-link
    let result3 = link_packages(project_dir.path(), &packages, true, None).unwrap();
    assert_eq!(result3.linked, 1, "force should re-link the package");
    assert_eq!(result3.skipped, 0, "force should not skip any packages");
}

#[test]
fn force_relink_hoisted_cleans_and_recreates() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "hoisted-force");

    let packages = vec![LinkTarget {
        name: "hoisted-force".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link in hoisted mode
    let result1 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    assert!(result1.linked > 0);

    let hoisted_pkg = project_dir
        .path()
        .join("node_modules")
        .join("hoisted-force");
    assert!(hoisted_pkg.exists(), "package should be hoisted to root");

    // Force re-link in hoisted mode — should clean and recreate
    let result2 = link_packages_hoisted(project_dir.path(), &packages, true, None).unwrap();
    assert!(result2.linked > 0, "force should re-link in hoisted mode");
    assert!(
        hoisted_pkg.exists(),
        "package should still exist after force re-link"
    );
}

#[test]
fn self_reference_created_for_named_package() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "foo");

    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, Some("my-project")).unwrap();
    assert!(result.self_referenced);

    // Self-reference symlink should exist
    let self_link = project_dir.path().join("node_modules/my-project");
    assert!(
        self_link.symlink_metadata().is_ok(),
        "self-reference symlink should exist"
    );
}

#[test]
fn self_reference_scoped_creates_scope_dir() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "foo");

    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(
        project_dir.path(),
        &packages,
        false,
        Some("@myorg/my-project"),
    )
    .unwrap();
    assert!(result.self_referenced);

    // Scope directory should be created
    let scope_dir = project_dir.path().join("node_modules/@myorg");
    assert!(scope_dir.is_dir(), "@myorg scope dir should exist");

    // Self-reference symlink should exist
    let self_link = project_dir.path().join("node_modules/@myorg/my-project");
    assert!(
        self_link.symlink_metadata().is_ok(),
        "scoped self-reference symlink should exist"
    );
}

#[test]
fn no_self_reference_without_name() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "foo");

    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert!(!result.self_referenced);
}

#[test]
fn self_reference_skipped_when_dep_exists_with_same_name() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "conflicting");

    // Direct dep has the same name as the self-reference
    let packages = vec![LinkTarget {
        name: "conflicting".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // Self-package name matches a direct dep — dep should win
    let result = link_packages(project_dir.path(), &packages, false, Some("conflicting")).unwrap();
    assert!(
        !result.self_referenced,
        "self-reference should be skipped when dep occupies the name"
    );

    // The link should point to the dep, not the project root
    let link = project_dir.path().join("node_modules/conflicting");
    assert!(link.symlink_metadata().is_ok());
}

// ---- Hoisted mode tests ----

#[test]
fn hoisted_mode_flattens_all_packages() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let express_store = create_fake_store_package(store_dir.path(), "express");
    let debug_store = create_fake_store_package(store_dir.path(), "debug");
    let ms_store = create_fake_store_package(store_dir.path(), "ms");

    let packages = vec![
        LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path: express_store,
            dependencies: vec![LinkDependency::registry("debug", "2.6.9")],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "2.6.9".to_string(),
            store_path: debug_store,
            dependencies: vec![LinkDependency::registry("ms", "2.0.0")],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "ms".to_string(),
            version: "2.0.0".to_string(),
            store_path: ms_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result.linked, 3);

    // All packages should be at root node_modules/
    assert!(project_dir.path().join("node_modules/express").exists());
    assert!(project_dir.path().join("node_modules/debug").exists());
    assert!(project_dir.path().join("node_modules/ms").exists());
}

#[test]
fn hoisted_mode_creates_top_level_dir_per_alias_root_link_name() {
    // Alias-aware root-slot claiming. A root `npm:<target>@<range>`
    // alias carries local slot names in `LinkTarget.root_link_names`,
    // which can differ from the canonical package name.
    //
    // This test pins the v1 contract: a single LinkTarget with
    // multiple `root_link_names` entries produces a top-level
    // `node_modules/<name>/` directory FOR EACH name, all
    // backed by the same store path.
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let lodash_store = create_fake_store_package(store_dir.path(), "lodash");

    // One LinkTarget for lodash@4.18.1 with FOUR root link slots:
    // the canonical name + three npm-alias names. Mirrors what
    // `resolved_to_install_packages` produces for a project
    // that declares `lodash, lodash-a: npm:lodash, lodash-b:
    // npm:lodash, lodash-c: npm:lodash`.
    let packages = vec![LinkTarget {
        name: "lodash".to_string(),
        version: "4.18.1".to_string(),
        store_path: lodash_store,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec![
            "lodash".to_string(),
            "lodash-a".to_string(),
            "lodash-b".to_string(),
            "lodash-c".to_string(),
        ]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    // Four top-level slots → four link operations.
    assert_eq!(
        result.linked, 4,
        "v1 hoisted must materialize each root_link_names entry as a \
             distinct top-level node_modules/<name>/ directory; pre-fix \
             only the canonical (`lodash`) was created and the three \
             aliases lost their dirs"
    );

    for slot in ["lodash", "lodash-a", "lodash-b", "lodash-c"] {
        let path = project_dir.path().join("node_modules").join(slot);
        assert!(
            path.exists(),
            "node_modules/{slot}/ must exist after install — pre-fix \
                 only `lodash` survived; aliases were silently dropped"
        );
        // Each alias dir must carry the canonical's package.json
        // contents (the alias is just a different on-disk name
        // for the same source bytes).
        let pj = path.join("package.json");
        assert!(
            pj.exists(),
            "node_modules/{slot}/package.json must be the canonical \
                 lodash manifest — alias slots are different on-disk \
                 names backed by the same store entry"
        );
    }

    // Sanity: aliased deps are NOT direct UNDER the alias name —
    // the canonical's `is_direct = true` is preserved through
    // the slot expansion. (Materialized records use `pkg.name`
    // for identity, so all 4 destinations share `name=lodash`.)
    assert_eq!(result.materialized.len(), 4);
    assert!(
        result.materialized.iter().all(|m| m.name == "lodash"),
        "all 4 MaterializedPackage entries must share the canonical \
             name (`lodash`) — the slot only affects on-disk path, not \
             package identity used by patches and lifecycle scripts"
    );
}

#[test]
fn hoisted_linker_skips_root_link_name_with_traversal() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "foo");

    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["../escape".to_string(), "foo".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    assert_eq!(
        result.linked, 1,
        "only the safe hoisted root directory should be materialized",
    );
    assert!(
        project_dir.path().join("node_modules").join("foo").exists(),
        "safe hoisted root directory must still be created",
    );
    assert!(
        !project_dir.path().join("escape").exists(),
        "unsafe hoisted root name must not materialize outside node_modules",
    );
}

#[test]
fn hoisted_mode_nests_conflicts() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let express_store = create_fake_store_package(store_dir.path(), "express");
    let debug_v2_store = create_fake_store_package(store_dir.path(), "debug-v2");
    let debug_v3_store = create_fake_store_package(store_dir.path(), "debug-v3");
    let other_store = create_fake_store_package(store_dir.path(), "other");

    let packages = vec![
        LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path: express_store,
            dependencies: vec![LinkDependency::registry("debug", "2.6.9")],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "2.6.9".to_string(),
            store_path: debug_v2_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "other".to_string(),
            version: "1.0.0".to_string(),
            store_path: other_store,
            dependencies: vec![LinkDependency::registry("debug", "3.0.0")],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "3.0.0".to_string(),
            store_path: debug_v3_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // One debug at root, one nested
    assert!(project_dir.path().join("node_modules/debug").exists());

    // The conflicting version should be nested under its dependent
    let nested_debug = project_dir
        .path()
        .join("node_modules/other/node_modules/debug");
    assert!(
        nested_debug.exists(),
        "conflicting debug version should be nested under its dependent"
    );

    // Total linked = express + debug@root + other + debug@nested = 4
    assert_eq!(result.linked, 4);
}

#[test]
fn hoisted_mode_prefers_direct_deps() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let parent_store = create_fake_store_package(store_dir.path(), "parent");
    let debug_v2_store = create_fake_store_package(store_dir.path(), "debug-v2");
    let debug_v3_store = create_fake_store_package(store_dir.path(), "debug-v3");

    let packages = vec![
        LinkTarget {
            name: "parent".to_string(),
            version: "1.0.0".to_string(),
            store_path: parent_store,
            dependencies: vec![LinkDependency::registry("debug", "2.6.9")],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "2.6.9".to_string(),
            store_path: debug_v2_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        // Direct dep with different version should win root
        LinkTarget {
            name: "debug".to_string(),
            version: "3.0.0".to_string(),
            store_path: debug_v3_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // Debug at root should exist
    assert!(project_dir.path().join("node_modules/debug").exists());

    // The direct dep (3.0.0) should have won root position.
    // The transitive (2.6.9) should be nested under "parent".
    let nested_debug = project_dir
        .path()
        .join("node_modules/parent/node_modules/debug");
    assert!(
        nested_debug.exists(),
        "transitive debug should be nested under parent"
    );

    assert!(result.linked >= 3);
}

// ---- Security tests ----

// Path traversal in bin targets
#[test]
fn bin_target_path_traversal_rejected() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    // Create an "outside" file that the traversal would target
    let outside_file = store_dir.path().join("outside_secret");
    std::fs::write(&outside_file, "secret data").unwrap();

    // Create a package whose bin points to ../../outside_secret
    let pkg_name = "evil-pkg";
    let pkg_dir = store_dir.path().join(pkg_name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"evil-pkg","bin":{"evil":"../../outside_secret"}}"#,
    )
    .unwrap();
    // Create a dummy file so the package dir exists but the target escapes
    std::fs::write(pkg_dir.join("index.js"), "").unwrap();

    let packages = vec![LinkTarget {
        name: pkg_name.to_string(),
        version: "1.0.0".to_string(),
        store_path: pkg_dir,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

    // The traversal bin should be rejected — no bin link created
    assert_eq!(
        result.bin_linked, 0,
        "path traversal bin target should be rejected"
    );

    // Verify no symlink was created in .bin/
    let bin_link = project_dir.path().join("node_modules/.bin/evil");
    assert!(
        bin_link.symlink_metadata().is_err(),
        "no symlink should exist for path-traversing bin"
    );
}

// Bin name validation
#[test]
fn bin_name_with_path_separator_rejected() {
    assert!(validate_bin_name("../escape", "pkg").is_err());
}

#[test]
fn bin_name_empty_rejected() {
    assert!(validate_bin_name("", "pkg").is_err());
}

#[test]
fn bin_name_normal_allowed() {
    assert!(validate_bin_name("normal-cli", "pkg").is_ok());
}

#[test]
fn bin_name_node_warns_but_allowed() {
    // "node" should be allowed (Ok) but logs a warning
    assert!(validate_bin_name("node", "pkg").is_ok());
}

#[test]
fn bin_name_with_null_byte_rejected() {
    assert!(validate_bin_name("bad\0name", "pkg").is_err());
}

#[test]
fn bin_name_with_backslash_rejected() {
    assert!(validate_bin_name("bad\\name", "pkg").is_err());
}

#[test]
fn bin_name_windows_reserved_devices_rejected() {
    for n in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT9", "con", "Lpt5"] {
        assert!(
            validate_bin_name(n, "pkg").is_err(),
            "expected {n:?} to be rejected as Windows reserved name"
        );
    }
}

#[test]
fn bin_name_windows_reserved_with_extension_rejected() {
    assert!(validate_bin_name("CON.txt", "pkg").is_err());
    assert!(validate_bin_name("nul.js", "pkg").is_err());
}

#[test]
fn bin_name_windows_reserved_superscript_variants_rejected() {
    for n in [
        "COM\u{00B9}",     // COM¹
        "COM\u{00B2}",     // COM²
        "COM\u{00B3}",     // COM³
        "LPT\u{00B9}",     // LPT¹
        "LPT\u{00B2}",     // LPT²
        "LPT\u{00B3}",     // LPT³
        "com\u{00B9}",     // case-folded
        "COM\u{2070}",     // COM⁰
        "COM\u{2074}",     // COM⁴
        "COM\u{2079}.exe", // with extension
    ] {
        assert!(
            validate_bin_name(n, "pkg").is_err(),
            "expected {n:?} to be rejected as Windows reserved superscript variant"
        );
    }
}

#[test]
fn bin_name_with_colon_rejected() {
    assert!(validate_bin_name("foo:bar", "pkg").is_err());
}

#[test]
fn bin_name_trailing_dot_or_space_rejected() {
    assert!(validate_bin_name("foo.", "pkg").is_err());
    assert!(validate_bin_name("foo ", "pkg").is_err());
}

// Windows cmd shim injection
#[test]
#[cfg(windows)]
fn cmd_path_with_metacharacters_rejected() {
    assert!(validate_cmd_path(r#"" & whoami & echo ""#).is_err());
    assert!(validate_cmd_path("normal/path/to/script.js").is_ok());
    assert!(validate_cmd_path("path|injection").is_err());
    assert!(validate_cmd_path("path<injection").is_err());
    assert!(validate_cmd_path("path>injection").is_err());
    assert!(validate_cmd_path("path^injection").is_err());
    assert!(validate_cmd_path("path%injection").is_err());
    assert!(validate_cmd_path("path\ninjection").is_err());
}

// Validate cmd paths for junction creation
#[test]
#[cfg(windows)]
fn validate_cmd_path_rejects_ampersand() {
    assert!(validate_cmd_path("C:\\foo & del C:\\").is_err());
}

#[test]
#[cfg(windows)]
fn validate_cmd_path_allows_normal_path() {
    assert!(validate_cmd_path("C:\\Users\\foo\\node_modules").is_ok());
}

// Permission bits
#[cfg(unix)]
#[test]
fn permission_bits_add_execute_only() {
    // Mode | 0o111 should add execute without adding write for group/other
    let original_mode: u32 = 0o644;
    let fixed = original_mode | 0o111;
    assert_eq!(fixed, 0o755, "644 | 111 should be 755");

    let original_mode_2: u32 = 0o600;
    let fixed_2 = original_mode_2 | 0o111;
    assert_eq!(fixed_2, 0o711, "600 | 111 should be 711, not 755");

    // Prove the old code was wrong:
    let old_broken: u32 = 0o600 | 0o755;
    assert_eq!(old_broken, 0o755, "old code would force 755 regardless");
    assert_ne!(
        fixed_2, old_broken,
        "new code preserves restrictive permissions"
    );
}

// Relative symlinks
#[cfg(unix)]
#[test]
fn bin_links_use_relative_symlinks() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path =
        create_fake_store_package_with_bin(store_dir.path(), "rel-tool", "\"./cli.js\"");

    let packages = vec![LinkTarget {
        name: "rel-tool".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result.bin_linked, 1);

    let bin_link = project_dir.path().join("node_modules/.bin/rel-tool");
    assert!(
        bin_link.symlink_metadata().is_ok(),
        ".bin/rel-tool should exist"
    );

    // Read the symlink target and verify it's relative
    let link_target = std::fs::read_link(&bin_link).unwrap();
    assert!(
        !link_target.is_absolute(),
        "bin symlink should be relative, got: {}",
        link_target.display()
    );
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn bin_links_from_logical_tmp_paths_do_not_dangle() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::Builder::new()
        .prefix("lpm-linker-macos-tmp-")
        .tempdir_in("/tmp")
        .unwrap();

    let store_path =
        create_fake_store_package_with_bin(store_dir.path(), "tmp-tool", "\"./cli.js\"");

    let packages = vec![LinkTarget {
        name: "tmp-tool".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let lexical_root = project_dir.path();
    assert!(
        lexical_root.starts_with("/tmp"),
        "test requires a logical /tmp path, got {}",
        lexical_root.display()
    );
    assert_ne!(
        lexical_root,
        lexical_root.canonicalize().unwrap().as_path(),
        "test requires /tmp to canonicalize differently on macOS"
    );

    let result = link_packages(lexical_root, &packages, false, None).unwrap();
    assert_eq!(result.bin_linked, 1);

    let bin_link = lexical_root.join("node_modules/.bin/tmp-tool");
    assert!(
        bin_link.symlink_metadata().is_ok(),
        ".bin/tmp-tool should exist"
    );
    assert!(
        bin_link.exists(),
        ".bin/tmp-tool should resolve even when project root is addressed through logical /tmp"
    );
}

// Path traversal in hoisted mode
#[test]
fn bin_target_path_traversal_rejected_hoisted() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let outside_file = store_dir.path().join("outside_secret");
    std::fs::write(&outside_file, "secret data").unwrap();

    let pkg_name = "evil-pkg";
    let pkg_dir = store_dir.path().join(pkg_name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"evil-pkg","bin":{"evil":"../../outside_secret"}}"#,
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), "").unwrap();

    let packages = vec![LinkTarget {
        name: pkg_name.to_string(),
        version: "1.0.0".to_string(),
        store_path: pkg_dir,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(
        result.bin_linked, 0,
        "path traversal bin target should be rejected in hoisted mode"
    );
}

#[cfg(unix)]
#[test]
fn bin_target_symlink_escape_rejected() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let outside_file = store_dir.path().join("outside_secret.js");
    std::fs::write(&outside_file, "console.log('secret')").unwrap();

    let pkg_name = "symlink-escape";
    let pkg_dir = store_dir.path().join(pkg_name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"symlink-escape","bin":{"escape":"./link.js"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside_file, pkg_dir.join("link.js")).unwrap();

    let packages = vec![LinkTarget {
        name: pkg_name.to_string(),
        version: "1.0.0".to_string(),
        store_path: pkg_dir,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(
        result.bin_linked, 0,
        "bin symlinks that resolve outside the package directory should be rejected"
    );
}

#[test]
fn bin_target_absolute_path_rejected() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let outside_file = store_dir.path().join("outside_secret.js");
    std::fs::write(&outside_file, "console.log('secret')").unwrap();

    let pkg_name = "absolute-escape";
    let pkg_dir = store_dir.path().join(pkg_name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(
            "{{\"name\":\"{pkg_name}\",\"bin\":{{\"escape\":\"{}\"}}}}",
            outside_file.display()
        ),
    )
    .unwrap();

    let packages = vec![LinkTarget {
        name: pkg_name.to_string(),
        version: "1.0.0".to_string(),
        store_path: pkg_dir,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(
        result.bin_linked, 0,
        "absolute bin targets outside the package directory should be rejected"
    );
}

// Bin name ../escape should not create a link
#[test]
fn bin_name_escape_not_linked() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let pkg_name = "escape-pkg";
    let pkg_dir = store_dir.path().join(pkg_name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"escape-pkg","bin":{"../escape":"./cli.js"}}"#,
    )
    .unwrap();
    std::fs::write(pkg_dir.join("cli.js"), "#!/usr/bin/env node").unwrap();

    let packages = vec![LinkTarget {
        name: pkg_name.to_string(),
        version: "1.0.0".to_string(),
        store_path: pkg_dir,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(
        result.bin_linked, 0,
        "bin name with path traversal should be rejected"
    );
}

// ---- Self-reference name validation ----

#[test]
fn self_ref_name_valid_plain() {
    assert!(is_valid_self_ref_name("my-package"));
}

#[test]
fn self_ref_name_valid_scoped() {
    assert!(is_valid_self_ref_name("@scope/my-package"));
}

#[test]
fn self_ref_name_invalid_traversal() {
    assert!(!is_valid_self_ref_name("../../etc"));
}

#[test]
fn self_ref_name_invalid_empty() {
    assert!(!is_valid_self_ref_name(""));
}

#[test]
fn self_ref_name_invalid_null_byte() {
    assert!(!is_valid_self_ref_name("a\0b"));
}

#[test]
fn self_ref_name_invalid_backslash() {
    assert!(!is_valid_self_ref_name("foo\\bar"));
}

#[test]
fn self_ref_name_invalid_absolute() {
    assert!(!is_valid_self_ref_name("/etc/passwd"));
}

#[test]
fn self_ref_traversal_skipped_no_error() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "foo");

    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // Use a traversal name — should not create symlink, should not error
    let result = link_packages(project_dir.path(), &packages, false, Some("../../evil")).unwrap();
    assert!(!result.self_referenced);

    // No symlink created outside node_modules
    let evil_link = project_dir.path().join("node_modules/../../evil");
    assert!(evil_link.symlink_metadata().is_err());
}

#[test]
fn isolated_linker_skips_root_link_name_with_traversal() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "foo");
    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["../escape".to_string(), "foo".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

    assert_eq!(
        result.symlinked, 1,
        "only the safe root link should be created",
    );
    assert!(
        project_dir.path().join("node_modules").join("foo").exists(),
        "safe root link must still be created",
    );
    assert!(
        !project_dir.path().join("escape").exists(),
        "unsafe root link must not create an entry outside node_modules",
    );
}

#[cfg(unix)]
#[test]
fn isolated_linker_does_not_write_through_symlinked_scope_parent() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();

    let node_modules = project_dir.path().join("node_modules");
    std::fs::create_dir_all(&node_modules).unwrap();
    std::os::unix::fs::symlink(outside.path(), node_modules.join("@scope")).unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "@scope/pkg");
    let packages = vec![LinkTarget {
        name: "@scope/pkg".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

    assert!(
        result.symlinked >= 1,
        "safe root link should still be recreated after stale symlink cleanup",
    );
    assert!(
        !outside.path().join("pkg").exists(),
        "root link must not be created through a symlinked scope parent",
    );
    assert!(
        project_dir
            .path()
            .join("node_modules")
            .join("@scope")
            .join("pkg")
            .symlink_metadata()
            .is_ok(),
        "root link should be recreated under a real node_modules scope dir",
    );
}

#[test]
fn isolated_linker_skips_dependency_local_name_with_traversal() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "foo");
    let packages = vec![LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![LinkDependency::registry("../../../../escape", "1.0.0")],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

    assert_eq!(
        result.linked, 1,
        "only package materialization/root link should count; unsafe dep edge is skipped",
    );
    assert!(
        project_dir
            .path()
            .join("escape")
            .symlink_metadata()
            .is_err(),
        "unsafe dependency local name must not create an entry outside the wrapper",
    );
}

#[cfg(unix)]
#[test]
fn workspace_member_link_allows_a_missing_publish_directory_target() {
    let root = tempfile::tempdir().unwrap();
    let node_modules = root.path().join("project/node_modules");
    let publish_directory = root.path().join("packages/library/build");
    std::fs::create_dir_all(&node_modules).unwrap();
    std::fs::create_dir_all(publish_directory.parent().unwrap()).unwrap();

    link_workspace_member(&node_modules, "@fixture/library", &publish_directory).unwrap();

    let link = node_modules.join("@fixture/library");
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert!(std::fs::metadata(link).is_err());
}

#[cfg(unix)]
#[test]
fn workspace_member_link_is_idempotent_across_concurrent_calls() {
    let root = tempfile::tempdir().unwrap();
    let node_modules = root.path().join("project/node_modules");
    let member_source = root.path().join("packages/library");
    std::fs::create_dir_all(&node_modules).unwrap();
    std::fs::create_dir_all(&member_source).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(16);
        for _ in 0..16 {
            let barrier = std::sync::Arc::clone(&barrier);
            let node_modules = &node_modules;
            let member_source = &member_source;
            handles.push(scope.spawn(move || {
                barrier.wait();
                for _ in 0..20 {
                    link_workspace_member(node_modules, "@fixture/library", member_source)?;
                }
                Ok::<_, lpm_common::LpmError>(())
            }));
        }
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
    });

    let link = node_modules.join("@fixture/library");
    assert_eq!(
        std::fs::canonicalize(link).unwrap(),
        member_source.canonicalize().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn workspace_member_link_rejects_symlinked_node_modules_root() {
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let member_source = root.path().join("packages").join("foo");
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&member_source).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(member_source.join("package.json"), "{}").unwrap();
    std::os::unix::fs::symlink(&outside, project_dir.join("node_modules")).unwrap();

    let err = link_workspace_member(&project_dir.join("node_modules"), "foo", &member_source)
        .unwrap_err();

    assert!(
        format!("{err}").contains("symlinked directory"),
        "error should reject symlinked node_modules root, got: {err}",
    );
    assert!(
        outside.join("foo").symlink_metadata().is_err(),
        "workspace link must not be created through symlinked node_modules",
    );
}

// ---- Additional hoisted mode tests ----

#[test]
fn hoisted_mode_empty_packages() {
    let project_dir = tempfile::tempdir().unwrap();

    let result = link_packages_hoisted(project_dir.path(), &[], false, None).unwrap();
    assert_eq!(result.linked, 0);
    assert_eq!(result.bin_linked, 0);
}

#[test]
fn hoisted_mode_single_package() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "solo");

    let packages = vec![LinkTarget {
        name: "solo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(result.linked, 1);
    assert!(project_dir.path().join("node_modules/solo").exists());
    assert!(
        project_dir
            .path()
            .join("node_modules/solo/package.json")
            .exists()
    );
}

#[test]
fn hoisted_mode_multiple_conflicts() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let a_store = create_fake_store_package(store_dir.path(), "a");
    let b_store = create_fake_store_package(store_dir.path(), "b");
    let shared_v1_store = create_fake_store_package(store_dir.path(), "shared-v1");
    let shared_v2_store = create_fake_store_package(store_dir.path(), "shared-v2");
    let util_v1_store = create_fake_store_package(store_dir.path(), "util-v1");
    let util_v2_store = create_fake_store_package(store_dir.path(), "util-v2");

    let packages = vec![
        LinkTarget {
            name: "a".to_string(),
            version: "1.0.0".to_string(),
            store_path: a_store,
            dependencies: vec![
                LinkDependency::registry("shared", "1.0.0"),
                LinkDependency::registry("util", "1.0.0"),
            ],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "shared".to_string(),
            version: "1.0.0".to_string(),
            store_path: shared_v1_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "util".to_string(),
            version: "1.0.0".to_string(),
            store_path: util_v1_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "b".to_string(),
            version: "1.0.0".to_string(),
            store_path: b_store,
            dependencies: vec![
                LinkDependency::registry("shared", "2.0.0"),
                LinkDependency::registry("util", "2.0.0"),
            ],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "shared".to_string(),
            version: "2.0.0".to_string(),
            store_path: shared_v2_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "util".to_string(),
            version: "2.0.0".to_string(),
            store_path: util_v2_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // Root should have: a, b, shared (v1 wins first-come), util (v1 wins first-come)
    assert!(project_dir.path().join("node_modules/a").exists());
    assert!(project_dir.path().join("node_modules/b").exists());
    assert!(project_dir.path().join("node_modules/shared").exists());
    assert!(project_dir.path().join("node_modules/util").exists());

    // Conflicting v2 should be nested under b
    assert!(
        project_dir
            .path()
            .join("node_modules/b/node_modules/shared")
            .exists()
    );
    assert!(
        project_dir
            .path()
            .join("node_modules/b/node_modules/util")
            .exists()
    );

    // 4 root + 2 nested = 6
    assert_eq!(result.linked, 6);
}

/// Regression test for conflict nesting when conflict-versioned
/// packages have consumers that are themselves at different versions.
///
/// Setup mirrors the real eslint failure mode in miniature:
/// - `anchor` (direct, hoisted) → depends on `consumer@10`
/// - `consumer@3` (transitive, hoisted) → depends on `dep@1`
/// - `dep@1` (hoisted)
/// - `consumer@10` (transitive, nested under `anchor`) → depends on `dep@5`
/// - `dep@5` (transitive, must nest under **anchor**, NOT under hoisted `consumer@3`)
///
/// Pre-fix lpm placed `dep@5` at `node_modules/consumer/node_modules/dep`
/// (under `consumer@3`!), which broke Node resolution because
/// `consumer@3` would `require('dep')` and find v5 first instead of
/// the v1 it actually needs. Post-fix, `dep@5` lands at
/// `node_modules/anchor/node_modules/dep` — sibling to `consumer@10`,
/// which is where Node's resolver finds it from `consumer@10`'s
/// position when walking up.
#[test]
fn hoisted_mode_nests_conflict_under_consumer_anchor_not_same_named_root() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let anchor_store = create_fake_store_package(store_dir.path(), "anchor");
    let consumer_v3_store = create_fake_store_package(store_dir.path(), "consumer-v3");
    let consumer_v10_store = create_fake_store_package(store_dir.path(), "consumer-v10");
    let dep_v1_store = create_fake_store_package(store_dir.path(), "dep-v1");
    let dep_v5_store = create_fake_store_package(store_dir.path(), "dep-v5");

    let packages = vec![
        // Anchor (direct) → consumer@10
        LinkTarget {
            name: "anchor".to_string(),
            version: "1.0.0".to_string(),
            store_path: anchor_store,
            dependencies: vec![LinkDependency::registry("consumer", "10.0.0")],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        // Consumer@3 (transitive, encountered first → hoisted) → dep@1
        LinkTarget {
            name: "consumer".to_string(),
            version: "3.0.0".to_string(),
            store_path: consumer_v3_store,
            dependencies: vec![LinkDependency::registry("dep", "1.0.0")],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        // Dep@1 (transitive, hoisted)
        LinkTarget {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            store_path: dep_v1_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        // Some-other-direct (forces consumer@3 to come before consumer@10
        // in declaration order — this test would be vacuous without
        // ordering control). Actually we rely on packages-vec order.
        LinkTarget {
            name: "consumer".to_string(),
            version: "10.0.0".to_string(),
            store_path: consumer_v10_store,
            dependencies: vec![LinkDependency::registry("dep", "5.0.0")],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        // Dep@5 (transitive, must nest under anchor)
        LinkTarget {
            name: "dep".to_string(),
            version: "5.0.0".to_string(),
            store_path: dep_v5_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // Hoisted at root: anchor, consumer@3, dep@1.
    assert!(project_dir.path().join("node_modules/anchor").exists());
    assert!(project_dir.path().join("node_modules/consumer").exists());
    assert!(project_dir.path().join("node_modules/dep").exists());

    // Consumer@10 nests under anchor (its consumer is anchor, hoisted).
    assert!(
        project_dir
            .path()
            .join("node_modules/anchor/node_modules/consumer")
            .exists(),
        "consumer@10 should nest under anchor, its hoisted consumer"
    );

    // **The bug fix.** dep@5 must nest under `anchor`, NOT under
    // `consumer` (which is consumer@3's slot). Pre-fix, the algorithm
    // would have placed dep@5 at node_modules/consumer/node_modules/dep,
    // which is WRONG because consumer@3 needs dep@1, not dep@5.
    assert!(
        project_dir
            .path()
            .join("node_modules/anchor/node_modules/dep")
            .exists(),
        "dep@5 MUST nest under anchor (consumer@10's hoisted ancestor), \
             not under consumer (which is consumer@3's slot — would shadow dep@1 \
             from consumer@3's perspective and break Node resolution)"
    );
    assert!(
        !project_dir
            .path()
            .join("node_modules/consumer/node_modules/dep")
            .exists(),
        "dep@5 must NOT be nested under consumer@3 (the pre-fix bug)"
    );

    // Total linked = anchor + consumer@3 + dep@1 (3 hoisted) +
    // consumer@10 + dep@5 (2 nested) = 5.
    assert_eq!(result.linked, 5);
}

#[test]
fn interrupted_link_cleaned_up_and_relinked() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "partial");

    // Simulate an interrupted link: create the pkg_nm directory but NOT the .linked marker.
    // wrapper root is `.lpm/wrappers/`, not `node_modules/.lpm/`.
    let lpm_dir = project_dir.path().join(".lpm/wrappers");
    let pkg_entry_dir = lpm_dir.join("partial@1.0.0");
    let pkg_nm = pkg_entry_dir.join("node_modules").join("partial");
    std::fs::create_dir_all(&pkg_nm).unwrap();
    // Write a partial file to prove this directory gets cleaned up
    std::fs::write(pkg_nm.join("stale.txt"), "should be removed").unwrap();
    // Crucially, do NOT create pkg_entry_dir.join(".linked")

    let packages = vec![LinkTarget {
        name: "partial".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

    // The stale directory should have been cleaned up and re-linked
    assert_eq!(
        result.linked, 1,
        "package should be re-linked after cleanup"
    );

    // The stale file should be gone
    assert!(
        !pkg_nm.join("stale.txt").exists(),
        "stale file should be removed"
    );

    // The real package files should be present
    assert!(
        pkg_nm.join("package.json").exists(),
        "package.json should exist after re-link"
    );

    // The .linked marker should now exist
    assert!(
        pkg_entry_dir.join(".linked").exists(),
        ".linked marker should be created"
    );
}

// ─── Hoisted self-reference tests ──────────────────────────────────

#[test]
fn hoisted_self_reference_created() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "dep-a");
    let packages = vec![LinkTarget {
        name: "dep-a".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result =
        link_packages_hoisted(project_dir.path(), &packages, false, Some("my-project")).unwrap();

    assert!(result.self_referenced);
    let self_link = project_dir.path().join("node_modules/my-project");
    assert!(
        self_link.symlink_metadata().is_ok(),
        "self-ref symlink should exist"
    );
}

#[test]
fn hoisted_self_reference_skipped_when_dep_has_same_name() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "clash");
    let packages = vec![LinkTarget {
        name: "clash".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result =
        link_packages_hoisted(project_dir.path(), &packages, false, Some("clash")).unwrap();

    // Dependency "clash" takes the slot — self-reference should NOT be created
    assert!(!result.self_referenced);
    // But the dependency should be linked
    assert!(
        project_dir
            .path()
            .join("node_modules/clash/package.json")
            .exists()
    );
}

#[test]
fn hoisted_self_reference_scoped() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "dep");
    let packages = vec![LinkTarget {
        name: "dep".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages_hoisted(
        project_dir.path(),
        &packages,
        false,
        Some("@my-org/my-project"),
    )
    .unwrap();

    assert!(result.self_referenced);
    let scope_dir = project_dir.path().join("node_modules/@my-org");
    assert!(scope_dir.exists(), "@scope dir should be created");
    let self_link = scope_dir.join("my-project");
    assert!(
        self_link.symlink_metadata().is_ok(),
        "scoped self-ref should exist"
    );
}

#[test]
fn hoisted_self_reference_none_when_no_name() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "dep");
    let packages = vec![LinkTarget {
        name: "dep".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    assert!(!result.self_referenced);
}

// ─── Hoisted metadata incremental tests ────────────────────────────

#[test]
fn hoisted_metadata_written_after_link() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "pkg");
    let packages = vec![LinkTarget {
        name: "pkg".to_string(),
        version: "2.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // Hoisted-symmetry: metadata sidecar lives at
    // `<project>/.lpm/hoisted/metadata.json` — sibling of
    // `.lpm/wrappers/`, no longer under `node_modules/`.
    let metadata_path = LayoutPaths::for_project(project_dir.path()).hoisted_metadata_path();
    assert!(metadata_path.exists(), "metadata file should be written");

    let data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&metadata_path).unwrap()).unwrap();
    let hoisted = data["hoisted"].as_object().unwrap();
    assert_eq!(hoisted.get("pkg").unwrap().as_str().unwrap(), "2.0.0");
}

#[test]
fn hoisted_incremental_skip_when_unchanged() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "stable");
    let packages = vec![LinkTarget {
        name: "stable".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link — should actually link
    let r1 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(r1.linked, 1);
    assert_eq!(r1.skipped, 0);

    // Second link with same packages — should skip via metadata
    let r2 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    assert_eq!(r2.linked, 0, "no new links on unchanged layout");
    assert_eq!(r2.skipped, 1, "should skip all packages");
}

#[test]
fn hoisted_incremental_relinks_on_version_change() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_v1 = create_fake_store_package(store_dir.path(), "pkg-v1");
    let store_v2 = create_fake_store_package(store_dir.path(), "pkg-v2");

    let packages_v1 = vec![LinkTarget {
        name: "pkg".to_string(),
        version: "1.0.0".to_string(),
        store_path: store_v1,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link with v1
    let r1 = link_packages_hoisted(project_dir.path(), &packages_v1, false, None).unwrap();
    assert_eq!(r1.linked, 1);

    // Second link with v2 — should detect version change and re-link
    let packages_v2 = vec![LinkTarget {
        name: "pkg".to_string(),
        version: "2.0.0".to_string(),
        store_path: store_v2,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let r2 = link_packages_hoisted(project_dir.path(), &packages_v2, false, None).unwrap();
    assert_eq!(r2.linked, 1, "should re-link on version change");
    assert_eq!(r2.skipped, 0);
}

#[test]
fn hoisted_incremental_cleans_stale_packages() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_a = create_fake_store_package(store_dir.path(), "pkg-a");
    let store_b = create_fake_store_package(store_dir.path(), "pkg-b");

    // First link: pkg-a + pkg-b
    let packages_v1 = vec![
        LinkTarget {
            name: "pkg-a".to_string(),
            version: "1.0.0".to_string(),
            store_path: store_a.clone(),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "pkg-b".to_string(),
            version: "1.0.0".to_string(),
            store_path: store_b,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    link_packages_hoisted(project_dir.path(), &packages_v1, false, None).unwrap();
    assert!(project_dir.path().join("node_modules/pkg-b").exists());

    // Second link: only pkg-a (pkg-b removed from deps)
    let packages_v2 = vec![LinkTarget {
        name: "pkg-a".to_string(),
        version: "1.0.0".to_string(),
        store_path: store_a,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let _r2 = link_packages_hoisted(project_dir.path(), &packages_v2, false, None).unwrap();

    // Pkg-a should still be there (already existed, no re-link needed)
    assert!(project_dir.path().join("node_modules/pkg-a").exists());
    // Pkg-b should be cleaned up
    assert!(
        !project_dir.path().join("node_modules/pkg-b").exists(),
        "stale pkg-b should be removed"
    );
    // Metadata should reflect only pkg-a (post-symmetry location).
    let meta_path = LayoutPaths::for_project(project_dir.path()).hoisted_metadata_path();
    let data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert!(data["hoisted"].get("pkg-a").is_some());
    assert!(data["hoisted"].get("pkg-b").is_none());
}

#[test]
fn hoisted_force_ignores_metadata() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let store_path = create_fake_store_package(store_dir.path(), "forced");
    let packages = vec![LinkTarget {
        name: "forced".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link
    link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // Force re-link — should not skip even though metadata matches
    let r2 = link_packages_hoisted(project_dir.path(), &packages, true, None).unwrap();
    // Force=true cleans then re-copies, so linked should be > 0
    assert_eq!(r2.linked, 1, "force should re-link everything");
    assert_eq!(r2.skipped, 0);
}

// ── Hoisted-symmetry mode-switch convergence regression tests ────

/// Hoisted → isolated: previous hoisted install left
/// `node_modules/<pkg>/` as a real directory (clonefile/hardlink
/// content). Subsequent isolated install must REPLACE that with a
/// symlink into `<project>/.lpm/wrappers/...`, not silently leave
/// the hoisted bytes in place.
#[test]
fn mode_switch_hoisted_to_isolated_replaces_root_dir_with_symlink() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "express");

    let packages = vec![LinkTarget {
        name: "express".to_string(),
        version: "4.22.1".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // Step 1 — hoisted install. Plants a real directory at
    // node_modules/express/ via link_dir_recursive.
    link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    let express_path = project_dir.path().join("node_modules").join("express");
    assert!(express_path.is_dir());
    let post_hoisted_is_symlink = express_path
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink();
    assert!(
        !post_hoisted_is_symlink,
        "post-hoisted: node_modules/express must be a real directory, not a symlink"
    );

    // Step 2 — isolated install on the same project. Must clean
    // the hoisted dir and plant the isolated symlink.
    link_packages(project_dir.path(), &packages, false, None).unwrap();

    let post_iso_meta = express_path.symlink_metadata().unwrap();
    assert!(
        lpm_common::is_symlink_or_junction(&post_iso_meta),
        "post-isolated: node_modules/express MUST be a symlink (was hoisted dir)"
    );

    // The wrapper tree must exist at the new location and contain
    // the actual package bytes.
    let wrapper_dir = project_dir
        .path()
        .join(".lpm")
        .join("wrappers")
        .join("express@4.22.1")
        .join("node_modules")
        .join("express");
    assert!(
        wrapper_dir.join("package.json").is_file(),
        "isolated wrapper must hold the package bytes"
    );

    // Inactive-mode hoisted state pruned by the deferred
    // finalize-step prune.
    assert!(
        !project_dir.path().join(".lpm").join("hoisted").exists(),
        "isolated finalize must prune .lpm/hoisted/"
    );
}

/// Isolated → hoisted: previous isolated install left
/// `node_modules/<pkg>` as a symlink pointing into
/// `<project>/.lpm/wrappers/...`. Subsequent hoisted install must
/// (1) not crash on `create_dir_all` against the (possibly broken)
/// symlink and (2) materialize a real hoisted directory there.
#[test]
fn mode_switch_isolated_to_hoisted_replaces_root_symlink_with_dir() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "lodash");

    let packages = vec![LinkTarget {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // Step 1 — isolated install. Plants a root symlink at
    // node_modules/lodash → ../.lpm/wrappers/lodash@4.17.21/node_modules/lodash/.
    link_packages(project_dir.path(), &packages, false, None).unwrap();
    let lodash_path = project_dir.path().join("node_modules").join("lodash");
    assert!(
        lpm_common::is_symlink_or_junction(&lodash_path.symlink_metadata().unwrap()),
        "post-isolated: node_modules/lodash must be a symlink"
    );

    // Step 2 — hoisted install on the same project. Must succeed
    // (no `create_dir_all` errors against the leftover symlink),
    // and leave a real directory at node_modules/lodash/.
    link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    let post_hoisted_meta = lodash_path.symlink_metadata().unwrap();
    assert!(
        !lpm_common::is_symlink_or_junction(&post_hoisted_meta),
        "post-hoisted: node_modules/lodash MUST be a real directory (was isolated symlink)"
    );
    assert!(
        lodash_path.join("package.json").is_file(),
        "hoisted dir must hold the package bytes"
    );

    // Inactive-mode wrapper state pruned by the deferred
    // post-link prune.
    assert!(
        !project_dir.path().join(".lpm").join("wrappers").exists(),
        "hoisted post-link must prune .lpm/wrappers/"
    );
}

/// Isolated → hoisted with a BROKEN leftover symlink (the user
/// already wiped `<project>/.lpm/wrappers/` manually before
/// re-running install in the other mode). Hoisted's own pre-link
/// sweep must remove the broken symlink so `link_dir_recursive`'s
/// `create_dir_all(dst)` doesn't error on macOS.
#[cfg(unix)]
#[test]
fn mode_switch_isolated_to_hoisted_handles_broken_leftover_symlink() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "react");

    let nm = project_dir.path().join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();
    // Synthesize a broken isolated-shape symlink directly,
    // simulating the post-wrapper-wipe state.
    let dangling_target = project_dir
        .path()
        .join(".lpm")
        .join("wrappers")
        .join("react@18.2.0")
        .join("node_modules")
        .join("react");
    std::os::unix::fs::symlink(&dangling_target, nm.join("react")).unwrap();

    let packages = vec![LinkTarget {
        name: "react".to_string(),
        version: "18.2.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // Must not panic / error on the broken symlink.
    link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    let react_path = nm.join("react");
    let meta = react_path.symlink_metadata().unwrap();
    assert!(
        !meta.file_type().is_symlink(),
        "broken symlink must be removed and replaced with hoisted dir"
    );
    assert!(react_path.join("package.json").is_file());
}

/// The isolated→hoisted convergence sweep deletes every top-level
/// symlink under `node_modules/`, including the self-reference symlink
/// at `node_modules/<self_name>`. The metadata-skip fast path must
/// recreate that link so incremental hoisted installs on named projects
/// keep `require("self")` working.
#[test]
fn incremental_hoisted_install_preserves_self_reference() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "dep");

    let packages = vec![LinkTarget {
        name: "dep".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let self_name = "myproj";
    let self_link = project_dir.path().join("node_modules").join(self_name);

    // First hoisted install — creates self-ref via the full re-link
    // branch.
    let r1 = link_packages_hoisted(project_dir.path(), &packages, false, Some(self_name)).unwrap();
    assert!(r1.self_referenced, "first install must create self-ref");
    let meta1 = self_link.symlink_metadata().unwrap();
    assert!(meta1.file_type().is_symlink());

    // Second hoisted install with identical packages — hits the
    // metadata-skip fast path (skipped > 0). Without the
    // unconditional self-ref recreation, the sweep deletes the
    // existing self-ref and the skip branch never restores it.
    let r2 = link_packages_hoisted(project_dir.path(), &packages, false, Some(self_name)).unwrap();
    assert_eq!(r2.skipped, 1, "second install must hit metadata fast path");
    assert!(
        self_link.symlink_metadata().is_ok(),
        "incremental install must not drop the self-ref symlink"
    );
    assert!(
        r2.self_referenced,
        "LinkResult.self_referenced must remain true on incremental"
    );
}

/// Same regression for SCOPED self-reference names
/// (`@org/pkg`). The sweep recurses into `@org/` and removes the
/// scoped self-ref; recreation must handle the scope-dir parent.
#[test]
fn incremental_hoisted_install_preserves_scoped_self_reference() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "dep");

    let packages = vec![LinkTarget {
        name: "dep".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let self_name = "@myorg/foo";
    let self_link = project_dir
        .path()
        .join("node_modules")
        .join("@myorg")
        .join("foo");

    let r1 = link_packages_hoisted(project_dir.path(), &packages, false, Some(self_name)).unwrap();
    assert!(r1.self_referenced);
    assert!(
        self_link
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let r2 = link_packages_hoisted(project_dir.path(), &packages, false, Some(self_name)).unwrap();
    assert_eq!(r2.skipped, 1);
    assert!(
        self_link.symlink_metadata().is_ok(),
        "incremental install must not drop the scoped self-ref symlink"
    );
    assert!(r2.self_referenced);
}

/// Hoisted → isolated convergence under scoped names
/// (`@scope/foo`). The scope dir is itself a real directory; the
/// inner package dir is what we need to clean.
#[test]
fn mode_switch_hoisted_to_isolated_handles_scoped_dirs() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "node");

    let packages = vec![LinkTarget {
        name: "@types/node".to_string(),
        version: "20.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // Hoisted install — synthesizes node_modules/@types/node/ as
    // a real dir.
    link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    let scoped_path = project_dir
        .path()
        .join("node_modules")
        .join("@types")
        .join("node");
    assert!(scoped_path.is_dir());
    assert!(
        !scoped_path
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // Isolated install on the same project.
    link_packages(project_dir.path(), &packages, false, None).unwrap();

    let post_iso_meta = scoped_path.symlink_metadata().unwrap();
    assert!(
        post_iso_meta.file_type().is_symlink(),
        "post-isolated: node_modules/@types/node MUST be a symlink"
    );
}

// ── `LinkResult.materialized` population ─────────────────────────
//
// The patch engine consumes `LinkResult.materialized` directly so it
// never has to reverse-engineer linker shapes. These tests pin the
// contract that the linker reports every physical destination it
// wrote — including the `<project>/.lpm/hoisted/nested/<name>/`
// shape (post-symmetry; pre-symmetry: `node_modules/.lpm/nested/`)
// that the first draft missed.

#[test]
fn isolated_mode_records_canonical_destination() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "lodash");

    let packages = vec![LinkTarget {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

    // Exactly one materialized entry, pointing at the canonical
    // .lpm/<safe>@<ver>/node_modules/<name>/ path.
    assert_eq!(result.materialized.len(), 1);
    let m = &result.materialized[0];
    assert_eq!(m.name, "lodash");
    assert_eq!(m.version, "4.17.21");
    assert_eq!(
        m.destination,
        project_dir
            .path()
            .join(".lpm/wrappers/lodash@4.17.21/node_modules/lodash")
    );
    // The recorded destination must actually exist on disk after a
    // successful link — this is the user-visible contract.
    assert!(m.destination.exists());
    assert!(m.destination.join("package.json").exists());
}

#[test]
fn isolated_mode_records_destination_on_marker_skip_path() {
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "lodash");

    let packages = vec![LinkTarget {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    }];

    // First link populates the marker
    let _ = link_packages(project_dir.path(), &packages, false, None).unwrap();
    // Second link takes the marker-skip fast path
    let r2 = link_packages(project_dir.path(), &packages, false, None).unwrap();

    assert_eq!(r2.skipped, 1);
    // Materialized list MUST still be populated even on the skip
    // path — the patch engine needs the destination either way.
    assert_eq!(r2.materialized.len(), 1);
    assert!(r2.materialized[0].destination.exists());
}

#[test]
fn hoisted_mode_records_root_and_under_hoisted_parent_destinations() {
    // Express + a transitive debug. Root-hoisted express, root-hoisted
    // debug. Materialized list should contain both roots.
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let express_store = create_fake_store_package(store_dir.path(), "express");
    let debug_store = create_fake_store_package(store_dir.path(), "debug");

    let packages = vec![
        LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path: express_store,
            dependencies: vec![LinkDependency::registry("debug", "2.6.9")],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "2.6.9".to_string(),
            store_path: debug_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // Both packages should be at root (no version conflict)
    let dests: Vec<&PathBuf> = result.materialized.iter().map(|m| &m.destination).collect();
    assert!(
        dests.contains(&&project_dir.path().join("node_modules/express")),
        "express root destination missing from materialized list"
    );
    assert!(
        dests.contains(&&project_dir.path().join("node_modules/debug")),
        "debug root destination missing from materialized list"
    );
}

#[test]
fn hoisted_mode_records_lpm_nested_destination_when_parent_not_hoisted() {
    // Two competing versions of `debug`, neither parent is hoisted —
    // the loser-of-conflict should land at the hoisted-nested
    // fallback root (post-symmetry: `<project>/.lpm/hoisted/nested/debug`).
    // This is the F-V4 third shape that the first design draft
    // missed.
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    // Create a fixture where the linker must use the .lpm/nested
    // shape. We need:
    //  - a hoisted "debug@2" (won the root slot first)
    //  - a "debug@3" that loses, with NO hoisted parent depending on it
    //
    // The simplest construction: two transitive deps under a
    // single direct dep, where the conflicting "debug@3" is depended
    // on by another transitive that is itself NOT hoisted (because
    // the same name was already taken).
    let direct_store = create_fake_store_package(store_dir.path(), "direct");
    let trans_store = create_fake_store_package(store_dir.path(), "trans");
    let trans2_store = create_fake_store_package(store_dir.path(), "trans");
    let debug_v2_store = create_fake_store_package(store_dir.path(), "debug-v2");
    let debug_v3_store = create_fake_store_package(store_dir.path(), "debug-v3");

    let packages = vec![
        LinkTarget {
            name: "direct".to_string(),
            version: "1.0.0".to_string(),
            store_path: direct_store,
            dependencies: vec![
                LinkDependency::registry("trans", "1.0.0"),
                LinkDependency::registry("debug", "2.0.0"),
            ],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "trans".to_string(),
            version: "1.0.0".to_string(),
            store_path: trans_store,
            dependencies: vec![LinkDependency::registry("debug", "3.0.0")],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        // Force a second `trans` version so trans@1.0.0 is NOT hoisted
        // (the second version wins root because it's identical here;
        // either way, neither variant is `is_direct`, so both lose to
        // a directly-declared `trans@2.0.0` if present).
        LinkTarget {
            name: "trans".to_string(),
            version: "2.0.0".to_string(),
            store_path: trans2_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "2.0.0".to_string(),
            store_path: debug_v2_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "3.0.0".to_string(),
            store_path: debug_v3_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // The patch engine relies on the linker being authoritative.
    // We assert two contracts:
    //   1. Every physical copy on disk is reported in `materialized`.
    //   2. If any package landed at .lpm/nested/, it appears in the list.
    let dests: Vec<&PathBuf> = result.materialized.iter().map(|m| &m.destination).collect();
    for dest in &dests {
        assert!(
            dest.exists(),
            "materialized destination {dest:?} does not exist on disk"
        );
    }

    // The hoisted-nested shape may or may not be exercised
    // depending on hoist tie-breaking, but if the nested fallback
    // root exists at all, every package inside it must be in the
    // materialized list. Post-symmetry the nested root is at
    // `<project>/.lpm/hoisted/nested/`, resolved through
    // [`LayoutPaths`] so the fixture and production code can
    // never disagree on the location.
    let nested_root = LayoutPaths::for_project(project_dir.path()).hoisted_nested_root();
    if nested_root.exists() {
        for entry in std::fs::read_dir(&nested_root).unwrap().flatten() {
            let path = entry.path();
            assert!(
                dests.contains(&&path),
                "linker created {path:?} but did not report it in materialized"
            );
        }
    }
}

#[test]
fn hoisted_mode_records_destinations_on_metadata_skip_path() {
    // Run the linker twice. The second run should hit the
    // metadata-fast-path (`needs_relink == false`). The materialized
    // list MUST still be populated — that's the offline-correctness
    // contract for the patch engine.
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();

    let express_store = create_fake_store_package(store_dir.path(), "express");
    let debug_store = create_fake_store_package(store_dir.path(), "debug");

    let packages = vec![
        LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path: express_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        LinkTarget {
            name: "debug".to_string(),
            version: "2.6.9".to_string(),
            store_path: debug_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
    ];

    let _r1 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
    let r2 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

    // Skip path was taken
    assert!(r2.skipped > 0);
    // Materialized still populated end-to-end
    assert_eq!(r2.materialized.len(), 2);
    for m in &r2.materialized {
        assert!(m.destination.exists());
    }
}

// ── detach_package_hardlinks ─────────────────────────────────────
//
// Cross-platform invariants of the public function (returns 0 on
// non-Linux, leaves files alone on every platform when nlink == 1,
// never touches symlinks). The Linux-only inode-break test is
// gated on `target_os = "linux"` because nlink semantics differ
// on macOS APFS (clonefile produces nlink=1 by design).

#[test]
fn detach_returns_zero_on_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let n = detach_package_hardlinks(dir.path()).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn detach_leaves_symlinks_intact() {
    let dir = tempfile::tempdir().unwrap();
    // Plain file the symlink will point at.
    let target = dir.path().join("real.js");
    std::fs::write(&target, b"module.exports = 1").unwrap();
    // Symlink "alias.js" → "real.js" (relative).
    let link = dir.path().join("alias.js");
    #[cfg(unix)]
    std::os::unix::fs::symlink("real.js", &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("real.js", &link).unwrap();

    detach_package_hardlinks(dir.path()).unwrap();

    // Symlink still exists AND still points at "real.js".
    let meta = std::fs::symlink_metadata(&link).unwrap();
    assert!(meta.file_type().is_symlink());
    let resolved = std::fs::read_link(&link).unwrap();
    assert_eq!(resolved, std::path::PathBuf::from("real.js"));
}

#[test]
fn detach_recurses_into_subdirs_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("a").join("b").join("c");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("file.txt"), b"hello").unwrap();
    // No hardlinks → 0 detached, but recursion must visit every
    // level without blowing up.
    let n = detach_package_hardlinks(dir.path()).unwrap();
    assert_eq!(n, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn detach_breaks_hardlink_so_writes_dont_touch_store() {
    use std::os::unix::fs::MetadataExt;

    // Simulate the linker's Linux path: a "store" dir holds the
    // canonical bytes; a "live" dir hardlinks them. After detach,
    // mutating the live copy must NOT mutate the store copy.
    let store = tempfile::tempdir().unwrap();
    let live = tempfile::tempdir().unwrap();

    let store_file = store.path().join("package.json");
    std::fs::write(&store_file, b"{\"name\":\"esbuild\",\"v\":\"0.21.5\"}").unwrap();

    let live_file = live.path().join("package.json");
    std::fs::hard_link(&store_file, &live_file).unwrap();

    // Sanity: shared inode, nlink == 2 on both sides.
    let store_ino_before = std::fs::metadata(&store_file).unwrap().ino();
    let live_ino_before = std::fs::metadata(&live_file).unwrap().ino();
    assert_eq!(store_ino_before, live_ino_before);
    assert_eq!(std::fs::metadata(&store_file).unwrap().nlink(), 2);

    // Detach.
    let detached = detach_package_hardlinks(live.path()).unwrap();
    assert_eq!(detached, 1, "exactly one file should have been detached");

    // After detach: live and store have DIFFERENT inodes.
    let store_ino_after = std::fs::metadata(&store_file).unwrap().ino();
    let live_ino_after = std::fs::metadata(&live_file).unwrap().ino();
    assert_ne!(
        store_ino_after, live_ino_after,
        "live and store must point at different inodes after detach"
    );
    // Store's nlink is back to 1 (we removed our link to it).
    assert_eq!(std::fs::metadata(&store_file).unwrap().nlink(), 1);
    // Content preserved on both sides.
    assert_eq!(
        std::fs::read(&store_file).unwrap(),
        b"{\"name\":\"esbuild\",\"v\":\"0.21.5\"}"
    );
    assert_eq!(
        std::fs::read(&live_file).unwrap(),
        b"{\"name\":\"esbuild\",\"v\":\"0.21.5\"}"
    );

    // The core invariant: writing to live must NOT mutate store.
    std::fs::write(&live_file, b"MUTATED-BY-POSTINSTALL").unwrap();
    assert_eq!(
        std::fs::read(&store_file).unwrap(),
        b"{\"name\":\"esbuild\",\"v\":\"0.21.5\"}",
        "store content must be unchanged after writing to live copy"
    );
    assert_eq!(
        std::fs::read(&live_file).unwrap(),
        b"MUTATED-BY-POSTINSTALL"
    );

    // No leftover .lpm-detach-tmp-* files.
    for entry in std::fs::read_dir(live.path()).unwrap() {
        let n = entry.unwrap().file_name();
        let s = n.to_string_lossy();
        assert!(
            !s.starts_with(".lpm-detach-tmp-"),
            "temp file leaked into the live dir: {s}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn detach_is_idempotent_already_independent_files_skipped() {
    // First call detaches; second call observes nlink == 1 and
    // does nothing. This matches the rebuild-loop invariant where
    // a re-run of `lpm rebuild` on an already-detached project
    // must be a fast no-op, not a redundant copy.
    use std::os::unix::fs::MetadataExt;

    let store = tempfile::tempdir().unwrap();
    let live = tempfile::tempdir().unwrap();
    let store_file = store.path().join("file");
    std::fs::write(&store_file, b"x").unwrap();
    std::fs::hard_link(&store_file, live.path().join("file")).unwrap();

    let first = detach_package_hardlinks(live.path()).unwrap();
    assert_eq!(first, 1);
    let second = detach_package_hardlinks(live.path()).unwrap();
    assert_eq!(second, 0);

    // And a plain non-hardlinked file (nlink == 1) is left alone
    // even on the first pass.
    let solo = tempfile::tempdir().unwrap();
    std::fs::write(solo.path().join("solo.txt"), b"y").unwrap();
    assert_eq!(
        std::fs::metadata(solo.path().join("solo.txt"))
            .unwrap()
            .nlink(),
        1
    );
    let n = detach_package_hardlinks(solo.path()).unwrap();
    assert_eq!(n, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn detach_recurses_and_breaks_links_in_subdirs() {
    // The lifecycle-script package shape has nested files
    // (`./bin/foo`, `./lib/index.js`, etc). Detach must reach
    // them, not just the top level.
    use std::os::unix::fs::MetadataExt;

    let store = tempfile::tempdir().unwrap();
    let live = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(store.path().join("bin")).unwrap();
    std::fs::create_dir_all(live.path().join("bin")).unwrap();
    let store_bin = store.path().join("bin").join("esbuild");
    std::fs::write(&store_bin, b"#!/bin/sh\necho real").unwrap();
    std::fs::hard_link(&store_bin, live.path().join("bin").join("esbuild")).unwrap();

    let n = detach_package_hardlinks(live.path()).unwrap();
    assert_eq!(n, 1);

    let store_ino = std::fs::metadata(&store_bin).unwrap().ino();
    let live_ino = std::fs::metadata(live.path().join("bin").join("esbuild"))
        .unwrap()
        .ino();
    assert_ne!(store_ino, live_ino);
}

#[cfg(target_os = "linux")]
#[test]
fn make_bin_target_executable_detaches_hardlink_before_chmod() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let store = tempfile::tempdir().unwrap();
    let live = tempfile::tempdir().unwrap();
    let store_bin = store.path().join("cli.js");
    let live_bin = live.path().join("cli.js");
    std::fs::write(&store_bin, b"#!/usr/bin/env node\n").unwrap();
    std::fs::set_permissions(&store_bin, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::hard_link(&store_bin, &live_bin).unwrap();

    make_bin_target_executable(&live_bin).unwrap();

    assert_ne!(
        std::fs::metadata(&store_bin).unwrap().ino(),
        std::fs::metadata(&live_bin).unwrap().ino(),
        "chmod target must no longer share the store inode"
    );
    assert_eq!(
        std::fs::metadata(&store_bin).unwrap().permissions().mode() & 0o777,
        0o644,
        "store mode must stay unchanged"
    );
    assert_eq!(
        std::fs::metadata(&live_bin).unwrap().permissions().mode() & 0o111,
        0o111,
        "live bin target must become executable"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn link_dir_recursive_rejects_symlinked_directory_entries() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("payload.js"), b"payload").unwrap();
    std::os::unix::fs::symlink(target.path(), src.path().join("dep")).unwrap();

    let err = link_dir_recursive(src.path(), &dst.path().join("out")).unwrap_err();
    assert!(
        err.to_string().contains("symlink"),
        "expected symlink refusal, got {err}"
    );
    assert!(
        !dst.path()
            .join("out")
            .join("dep")
            .join("payload.js")
            .exists(),
        "linking must not follow a symlinked directory out of the store tree"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn detach_preserves_preexisting_files_that_resemble_legacy_temps() {
    let dir = tempfile::tempdir().unwrap();
    let stale = dir.path().join(".lpm-detach-tmp-99999");
    std::fs::write(&stale, b"orphaned").unwrap();
    std::fs::write(dir.path().join("real.json"), b"{}").unwrap();

    detach_package_hardlinks(dir.path()).unwrap();

    assert_eq!(std::fs::read(&stale).unwrap(), b"orphaned");
    assert!(
        dir.path().join("real.json").exists(),
        "non-temp files must be left alone"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn detach_is_noop_on_non_linux() {
    // The function compiles on every platform but only does
    // work on Linux. On macOS / Windows the linker uses
    // clonefile / copy respectively, so the live copy is
    // already independent at link time.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
    let n = detach_package_hardlinks(dir.path()).unwrap();
    assert_eq!(n, 0);
    // File untouched.
    assert_eq!(std::fs::read(dir.path().join("file.txt")).unwrap(), b"x");
}

// ── wrapper_segment + materialize_directory_source ───────────────

fn make_local_source_dir(root: &Path, name: &str) -> PathBuf {
    let pkg = root.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!("{{\"name\":\"{name}\",\"version\":\"0.0.0\"}}"),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), b"module.exports = 'src';").unwrap();
    pkg
}

#[test]
fn wrapper_segment_uses_at_for_cas_backed_targets() {
    let target = LinkTarget {
        name: "express".to_string(),
        version: "4.22.1".to_string(),
        store_path: PathBuf::from("/tmp/store"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    assert_eq!(target.wrapper_segment(), "express@4.22.1");
}

#[test]
fn wrapper_segment_uses_plus_for_local_source_targets() {
    let target = LinkTarget {
        name: "my-lib".to_string(),
        version: "0.0.0".to_string(),
        store_path: PathBuf::from("/tmp/source"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: Some("f-1234567890abcdef".to_string()),
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    assert_eq!(target.wrapper_segment(), "my-lib+f-1234567890abcdef");
}

#[test]
fn wrapper_segment_sanitizes_scoped_names() {
    // `/` is replaced with `+` for filesystem safety in BOTH
    // shapes — the only difference is the version-vs-wrapper-id
    // tail.
    let cas = LinkTarget {
        name: "@scope/pkg".to_string(),
        version: "1.0.0".to_string(),
        store_path: PathBuf::from("/tmp/store"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    assert_eq!(cas.wrapper_segment(), "@scope+pkg@1.0.0");

    let local = LinkTarget {
        name: "@scope/pkg".to_string(),
        version: "0.0.0".to_string(),
        store_path: PathBuf::from("/tmp/source"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: Some("f-abcd".to_string()),
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    assert_eq!(local.wrapper_segment(), "@scope+pkg+f-abcd");
}

#[test]
fn materialize_directory_source_creates_per_file_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let src = make_local_source_dir(root.path(), "lib");
    let dst = root.path().join("dst");

    let count = materialize_directory_source(&src, &dst).unwrap();

    // package.json + index.js = 2 files → 2 symlinks.
    assert_eq!(count, 2);
    assert!(
        dst.join("package.json")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        dst.join("index.js")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // Read-through works.
    assert_eq!(
        std::fs::read(dst.join("index.js")).unwrap(),
        b"module.exports = 'src';"
    );
}

#[test]
fn materialize_directory_source_handles_nested_subdirectories() {
    let root = tempfile::tempdir().unwrap();
    let src = make_local_source_dir(root.path(), "nested-lib");
    let lib_subdir = src.join("src").join("util");
    std::fs::create_dir_all(&lib_subdir).unwrap();
    std::fs::write(lib_subdir.join("helper.js"), b"export const x = 1").unwrap();

    let dst = root.path().join("dst");
    let count = materialize_directory_source(&src, &dst).unwrap();

    // 2 top-level + 1 nested = 3 symlinks. Subdirectories are
    // real dirs in the wrapper.
    assert_eq!(count, 3);
    assert!(dst.join("src").join("util").is_dir());
    assert!(
        !dst.join("src")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "nested dir must be a real dir, not a symlink",
    );
    assert!(
        dst.join("src/util/helper.js")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn materialize_directory_source_excludes_node_modules() {
    let root = tempfile::tempdir().unwrap();
    let src = make_local_source_dir(root.path(), "with-deps");
    // Top-level node_modules.
    let nm = src.join("node_modules");
    std::fs::create_dir_all(nm.join("hidden")).unwrap();
    std::fs::write(nm.join("hidden/index.js"), b"hidden").unwrap();
    // Nested node_modules under a regular subdir — also excluded
    // (recursive exclusion).
    std::fs::create_dir_all(src.join("packages/inner/node_modules")).unwrap();
    std::fs::write(
        src.join("packages/inner/node_modules/hidden.js"),
        b"hidden-nested",
    )
    .unwrap();
    std::fs::write(src.join("packages/inner/visible.js"), b"visible").unwrap();

    let dst = root.path().join("dst");
    materialize_directory_source(&src, &dst).unwrap();

    // node_modules/ subtree never created.
    assert!(!dst.join("node_modules").exists());
    // Nested node_modules also skipped, but its sibling visible.js
    // survives.
    assert!(!dst.join("packages/inner/node_modules").exists());
    assert!(dst.join("packages/inner/visible.js").exists());
}

#[test]
fn materialize_directory_source_excludes_dot_git() {
    let root = tempfile::tempdir().unwrap();
    let src = make_local_source_dir(root.path(), "with-git");
    let git = src.join(".git");
    std::fs::create_dir_all(git.join("objects/aa")).unwrap();
    std::fs::write(git.join("HEAD"), b"ref: refs/heads/main").unwrap();
    std::fs::write(git.join("objects/aa/something"), b"git-object").unwrap();

    let dst = root.path().join("dst");
    materialize_directory_source(&src, &dst).unwrap();

    assert!(!dst.join(".git").exists(), ".git must be excluded");
    // Other dotfiles preserved (e.g., .npmrc would be).
    std::fs::write(src.join(".npmrc"), b"registry=https://x").unwrap();
    let dst2 = root.path().join("dst2");
    materialize_directory_source(&src, &dst2).unwrap();
    assert!(
        dst2.join(".npmrc").exists(),
        "non-.git/non-node_modules dotfiles must survive",
    );
}

#[test]
fn materialize_directory_source_symlinks_target_canonical_source() {
    let root = tempfile::tempdir().unwrap();
    let src = make_local_source_dir(root.path(), "abs-target");
    let dst = root.path().join("dst");
    materialize_directory_source(&src, &dst).unwrap();

    let link = dst.join("index.js");
    let link_target = std::fs::read_link(&link).unwrap();
    // Symlinks are absolute.
    assert!(
        link_target.is_absolute(),
        "wrapper symlinks must be absolute, got {link_target:?}",
    );
    // And they point at the canonicalized source path.
    let source_file = src.join("index.js");
    assert_eq!(
        link.canonicalize().unwrap(),
        source_file.canonicalize().unwrap()
    );
}

#[test]
fn materialize_directory_source_edits_visible_through_wrapper() {
    // The point of per-file symlinks: edits to the source file
    // are visible immediately via the wrapper, no relink needed.
    // This is the dev-loop UX contract for file: deps.
    let root = tempfile::tempdir().unwrap();
    let src = make_local_source_dir(root.path(), "live-edit");
    let dst = root.path().join("dst");
    materialize_directory_source(&src, &dst).unwrap();

    // Initial content visible.
    assert_eq!(
        std::fs::read(dst.join("index.js")).unwrap(),
        b"module.exports = 'src';"
    );

    // Mutate the SOURCE file (not the wrapper).
    std::fs::write(src.join("index.js"), b"module.exports = 'edited';").unwrap();

    // Edit visible through the wrapper — no re-link required.
    assert_eq!(
        std::fs::read(dst.join("index.js")).unwrap(),
        b"module.exports = 'edited';"
    );
}

#[test]
fn materialize_directory_source_errors_on_missing_source() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("does-not-exist");
    let dst = root.path().join("dst");
    let err = materialize_directory_source(&missing, &dst)
        .expect_err("materialize must error when the source path does not exist");
    // Error message names the source path so users can debug.
    let msg = format!("{err:?}");
    assert!(msg.contains("does-not-exist"), "got: {msg}");
}

/// **symlink escape.** A
/// symlink in the source tree that resolves OUTSIDE the source's
/// own realpath still materializes successfully (matches Node's
/// resolution from the source itself), but the wrapper symlink
/// points at the off-tree target. The contract is intentional:
/// the linker is transparent to whatever the source declares.
/// This test pins the success-with-escape behavior so a future change
/// doesn't tighten the warn into a hard error.
#[cfg(unix)]
#[test]
fn materialize_directory_source_passes_through_symlink_that_escapes_root() {
    let root = tempfile::tempdir().unwrap();
    // Create the escape target OUTSIDE the source root.
    let outside_dir = root.path().join("outside");
    std::fs::create_dir_all(&outside_dir).unwrap();
    let outside_file = outside_dir.join("config.json");
    std::fs::write(&outside_file, b"{\"escape\":true}").unwrap();

    let src = make_local_source_dir(root.path(), "escape-pkg");
    // Symlink inside the source pointing OUT of the source root.
    let escape_link = src.join("config.json");
    std::os::unix::fs::symlink(&outside_file, &escape_link).unwrap();

    let dst = root.path().join("dst");
    let count = materialize_directory_source(&src, &dst)
        .expect("escape symlinks materialize successfully (warn-only)");
    assert!(
        count > 0,
        "at least one entry (the escape symlink + the package.json from make_local_source_dir) materialized"
    );
    // Wrapper symlink points at the off-tree target's realpath.
    let wrapper_link = dst.join("config.json");
    assert!(
        wrapper_link
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "wrapper entry must be a symlink, even when target escapes",
    );
    let resolved = wrapper_link.canonicalize().unwrap();
    assert_eq!(
        resolved,
        outside_file.canonicalize().unwrap(),
        "wrapper symlink resolves to the off-tree target, transparent to the source",
    );
}

/// **depth bound.** A maliciously or accidentally deep source tree must
/// produce a clean error rather than a stack overflow.
///
/// Constructs a chain `src/a/a/a/.../a/file.js` with depth +5
/// past the bound. Single-letter dir names keep total path under
/// the OS's PATH_MAX even at depth 261.
#[test]
fn materialize_directory_source_errors_above_depth_bound() {
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("deep-pkg");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"deep-pkg","version":"0.0.0"}"#,
    )
    .unwrap();

    let mut deep_path = src.clone();
    for _ in 0..(MAX_DIRECTORY_SOURCE_DEPTH + 5) {
        deep_path.push("a");
    }
    std::fs::create_dir_all(&deep_path).unwrap();
    std::fs::write(deep_path.join("leaf.js"), b"// leaf\n").unwrap();

    let dst = root.path().join("dst");
    let err = materialize_directory_source(&src, &dst)
        .expect_err("walk must error past MAX_DIRECTORY_SOURCE_DEPTH");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("maximum walk depth"),
        "depth-bound error message should mention the limit; got: {msg}"
    );
}

// ── link_one_package + link_finalize integration with wrapper_id ────────

#[test]
fn link_one_package_directory_uses_per_file_symlinks_and_plus_wrapper() {
    // End-to-end: a LinkTarget with wrapper_id Some(...) goes
    // through the per-file-symlink path AND lands in a
    // `+`-shaped wrapper. The `.linked` marker is written
    // post-link so the marker check still works.
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let src = make_local_source_dir(root.path(), "local-foo");

    // Cleanup_stale_entries creates node_modules/.lpm; we mimic
    // its precondition by calling link_packages() directly.
    let target = LinkTarget {
        name: "local-foo".to_string(),
        version: "0.0.0".to_string(),
        store_path: src,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["local-foo".to_string()]),
        wrapper_id: Some("f-deadbeef00000000".to_string()),
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    let result = link_packages(&project_dir, &[target], false, None).unwrap();
    assert_eq!(result.linked, 1);

    // Wrapper at the `+` shape, not `@`.
    let wrapper = project_dir.join(".lpm/wrappers/local-foo+f-deadbeef00000000");
    assert!(wrapper.is_dir(), "expected wrapper at {wrapper:?}");
    let pkg_nm = wrapper.join("node_modules/local-foo");
    assert!(pkg_nm.is_dir(), "wrapper's pkg dir missing: {pkg_nm:?}");
    // Per-file symlinks materialized.
    assert!(
        pkg_nm
            .join("index.js")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // `.linked` marker present on the wrapper itself, not the
    // pkg_nm subtree.
    assert!(wrapper.join(".linked").exists());

    // Root symlink at node_modules/local-foo points at the
    // wrapper's pkg_nm slot.
    let root_link = project_dir.join("node_modules/local-foo");
    let resolved = root_link.canonicalize().unwrap();
    assert_eq!(resolved, pkg_nm.canonicalize().unwrap());
}

#[test]
fn link_one_package_registry_unaffected_by_wrapper_id_change() {
    // Regression: when wrapper_id is None, link_one_package
    // continues to use link_dir_recursive (hardlink/clonefile/
    // copy) and the `@`-shape wrapper. Day-2 must not regress
    // any registry-source linking.
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");
    let store_path = create_fake_store_package(&store_dir, "foo");

    let target = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    link_packages(&project_dir, &[target], false, None).unwrap();

    // Wrapper at `@`-shape.
    assert!(
        project_dir
            .join(".lpm/wrappers/foo@1.0.0/node_modules/foo/package.json")
            .exists(),
    );
    // Top-level pkg files materialized as REAL files (hardlink
    // / clonefile), not symlinks. (On macOS this is a clonefile
    // result, which symlink_metadata reports as a regular file.)
    let pkg_json_meta = project_dir
        .join(".lpm/wrappers/foo@1.0.0/node_modules/foo/package.json")
        .symlink_metadata()
        .unwrap();
    assert!(
        !pkg_json_meta.file_type().is_symlink(),
        "registry-source materialization must not be symlinks",
    );
}

/// The `.linked` marker carries a stamp encoding the LinkTarget's
/// identity. After a successful materialization the marker file
/// must contain the stamp text, not empty bytes.
#[test]
fn link_one_package_writes_stamped_marker() {
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");
    let store_path = create_fake_store_package(&store_dir, "foo");

    let target = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    link_packages(&project_dir, std::slice::from_ref(&target), false, None).unwrap();

    let marker = project_dir.join(".lpm/wrappers/foo@1.0.0/.linked");
    let on_disk = std::fs::read_to_string(&marker).unwrap();
    assert!(
        !on_disk.is_empty(),
        "marker must carry an identity stamp, not be empty",
    );
    assert!(
        on_disk.starts_with("lpm-link-stamp v2\n"),
        "stamp must start with the v2 header for forward-compat reads: {on_disk:?}",
    );
    assert_eq!(
        on_disk,
        compute_link_stamp(&target),
        "on-disk stamp must round-trip with compute_link_stamp",
    );
}

/// **stamp mismatch.** A wrapper materialized from one LinkTarget must
/// not be reused by a subsequent install of a different source kind that
/// happens to share the same wrapper segment. The stamp check detects
/// the mismatch and forces re-materialization.
#[test]
fn link_one_package_relinks_when_marker_stamp_does_not_match() {
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");

    // First install: source A lands at `.lpm/foo@1.0.0/` with
    // marker stamp identifying source A.
    let store_a = create_fake_store_package(&store_dir, "foo-a");
    std::fs::write(
        store_a.join("package.json"),
        r#"{"name":"foo","version":"1.0.0","_marker":"source-a"}"#,
    )
    .unwrap();
    let target_a = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: store_a,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    link_packages(&project_dir, &[target_a], false, None).unwrap();

    let pkg_json_path = project_dir.join(".lpm/wrappers/foo@1.0.0/node_modules/foo/package.json");
    let marker = project_dir.join(".lpm/wrappers/foo@1.0.0/.linked");
    let after_first: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap()).unwrap();
    assert_eq!(after_first["_marker"].as_str(), Some("source-a"));
    assert!(marker.exists(), "first install must write marker");

    // Second install: a DIFFERENT source materialized to the
    // same wrapper segment. Different store_path means a
    // different stamp; the marker check must detect the
    // mismatch and re-materialize.
    let store_b = create_fake_store_package(&store_dir, "foo-b");
    std::fs::write(
        store_b.join("package.json"),
        r#"{"name":"foo","version":"1.0.0","_marker":"source-b"}"#,
    )
    .unwrap();
    let target_b = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: store_b,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    link_packages(&project_dir, std::slice::from_ref(&target_b), false, None).unwrap();

    // The wrapper now contains source B's package.json — proves
    // the stamp-mismatch branch fired and re-materialized
    // instead of silently reusing source A's bytes.
    let after_second: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap()).unwrap();
    assert_eq!(
        after_second["_marker"].as_str(),
        Some("source-b"),
        "stamp mismatch must force re-materialization with the new source",
    );
    // And the marker now reflects target_b's identity.
    let new_stamp = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(
        new_stamp,
        compute_link_stamp(&target_b),
        "marker must be rewritten with the new target's stamp on relink",
    );
}

/// Legacy empty `.linked` markers (`fs::write(marker, "")`) must
/// be treated as a stamp mismatch and force re-materialization,
/// not silently trusted as "wrapper is valid".
#[test]
fn link_one_package_relinks_when_legacy_empty_marker_present() {
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");

    // Manually plant a legacy wrapper: a directory with stale bytes and
    // an empty .linked marker.
    let wrapper_pkg_nm = project_dir.join(".lpm/wrappers/foo@1.0.0/node_modules/foo");
    std::fs::create_dir_all(&wrapper_pkg_nm).unwrap();
    std::fs::write(
        wrapper_pkg_nm.join("package.json"),
        r#"{"name":"foo","version":"1.0.0","_marker":"stale-pre-r3"}"#,
    )
    .unwrap();
    let marker = project_dir.join(".lpm/wrappers/foo@1.0.0/.linked");
    std::fs::write(&marker, "").unwrap();

    // Sanity: the marker is empty as a legacy install would leave it.
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "");

    // New install with a fresh source. Same wrapper segment as
    // the legacy planted dir.
    let store_path = create_fake_store_package(&store_dir, "fresh-foo");
    std::fs::write(
        store_path.join("package.json"),
        r#"{"name":"foo","version":"1.0.0","_marker":"fresh-r3"}"#,
    )
    .unwrap();
    let target = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    link_packages(&project_dir, std::slice::from_ref(&target), false, None).unwrap();

    // Wrapper must now reflect the FRESH source, not the legacy
    // planted bytes — proves the empty-marker fast-path didn't
    // skip the relink.
    let pkg_json_path = wrapper_pkg_nm.join("package.json");
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap()).unwrap();
    assert_eq!(
        after["_marker"].as_str(),
        Some("fresh-r3"),
        "legacy empty marker must not bypass the stamp check",
    );
    // Marker now stamped.
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        compute_link_stamp(&target),
    );
}

/// **stale dep edges.** On a stamp-mismatch relink, the linker must
/// wipe the full wrapper directory, not only `pkg_nm`, because sibling
/// dependency symlinks live in the same wrapper's `node_modules/`.
#[test]
fn link_one_package_clears_stale_dep_edges_on_stamp_mismatch_relink() {
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");

    // Sibling dep target (so the Stage 2 dep loop has somewhere
    // to point its symlink). Doesn't need a wrapper id; CAS-shape
    // segment lands at `.lpm/leftpad@1.0.0/`.
    let leftpad_store = create_fake_store_package(&store_dir, "leftpad");
    let leftpad_target = LinkTarget {
        name: "leftpad".to_string(),
        version: "1.0.0".to_string(),
        store_path: leftpad_store,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: false,
        root_link_names: Some(Vec::new()),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    // First install: target A declares a `leftpad` dep, so the
    // wrapper at `.lpm/foo@1.0.0/` will get a sibling symlink at
    // `node_modules/leftpad`.
    let pkg_a_store = create_fake_store_package(&store_dir, "foo-a");
    std::fs::write(
        pkg_a_store.join("package.json"),
        r#"{"name":"foo","version":"1.0.0","_marker":"a"}"#,
    )
    .unwrap();
    let target_a = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: pkg_a_store,
        dependencies: vec![LinkDependency::registry("leftpad", "1.0.0")],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["foo".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    link_packages(
        &project_dir,
        &[target_a, leftpad_target.clone()],
        false,
        None,
    )
    .unwrap();

    let leftpad_symlink = project_dir.join(".lpm/wrappers/foo@1.0.0/node_modules/leftpad");
    assert!(
        leftpad_symlink.symlink_metadata().is_ok(),
        "leftpad sibling symlink must exist after target A's install",
    );

    // Second install: target B reuses the SAME `foo@1.0.0` segment
    // (so cleanup_stale_entries preserves the wrapper) but has a
    // DIFFERENT `store_path` (so the stamp mismatches) AND no
    // dependencies. The stamp-mismatch branch must wipe the full
    // pkg_entry_dir, taking the stale leftpad sibling symlink with it.
    let pkg_b_store = create_fake_store_package(&store_dir, "foo-b");
    std::fs::write(
        pkg_b_store.join("package.json"),
        r#"{"name":"foo","version":"1.0.0","_marker":"b"}"#,
    )
    .unwrap();
    let target_b = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: pkg_b_store,
        dependencies: vec![], // <- intentionally empty
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["foo".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    link_packages(&project_dir, &[target_b, leftpad_target], false, None).unwrap();

    // Leftpad sibling is gone because the wrapper was wiped on stamp
    // mismatch.
    assert!(
        leftpad_symlink.symlink_metadata().is_err(),
        "stale sibling dep edge must be cleared on stamp-mismatch relink by wiping \
             pkg_entry_dir, not just pkg_nm. Found: {:?}",
        leftpad_symlink.symlink_metadata(),
    );

    // Sanity: target B's package.json is what's at the wrapper now.
    let after: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            project_dir.join(".lpm/wrappers/foo@1.0.0/node_modules/foo/package.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(after["_marker"].as_str(), Some("b"));
}

/// The stamp must encode dep edges. Without them, two installs
/// with the SAME `store_path` but DIFFERENT `target.dependencies`
/// (e.g., child resolved version went `leftpad@1.0.0` →
/// `leftpad@2.0.0`) produce identical stamps. The fast path then
/// skips relinking and Stage 2's "skip if exists" dep loop keeps
/// the stale dep symlink pointing at the OLD child wrapper.
#[test]
fn link_one_package_relinks_when_only_dep_edges_change_v2_stamp() {
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");

    // Two distinct child versions, materialized at distinct
    // wrapper segments by the linker's CAS-shape rule.
    let leftpad1_store = create_fake_store_package(&store_dir, "leftpad-v1");
    let leftpad1_target = LinkTarget {
        name: "leftpad".to_string(),
        version: "1.0.0".to_string(),
        store_path: leftpad1_store,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: false,
        root_link_names: Some(Vec::new()),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    let leftpad2_store = create_fake_store_package(&store_dir, "leftpad-v2");
    let leftpad2_target = LinkTarget {
        name: "leftpad".to_string(),
        version: "2.0.0".to_string(),
        store_path: leftpad2_store,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: false,
        root_link_names: Some(Vec::new()),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    // The same `foo` source — same `store_path` across both runs.
    // Only `dependencies` changes between target_a and target_b.
    let foo_source = create_fake_store_package(&store_dir, "foo-source");
    let target_a = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: foo_source.clone(),
        dependencies: vec![LinkDependency::registry("leftpad", "1.0.0")],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["foo".to_string()]),
        wrapper_id: Some("f-aaaa".to_string()),
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    link_packages(&project_dir, &[leftpad1_target, target_a], false, None).unwrap();

    let leftpad_symlink = project_dir.join(".lpm/wrappers/foo+f-aaaa/node_modules/leftpad");
    let after_a = std::fs::read_link(&leftpad_symlink).unwrap();
    assert!(
        after_a.to_string_lossy().contains("leftpad@1.0.0"),
        "after run 1 leftpad symlink must point at v1 wrapper, got {after_a:?}",
    );

    // Run 2: same `foo` store_path, same wrapper_id — but a
    // different `dependencies` slot pointing at leftpad@2.0.0.
    // Same materialization identity but a different dependency edge:
    // the deps line differs, forcing re-materialization and a new
    // symlink target.
    let target_b = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: foo_source,
        dependencies: vec![LinkDependency::registry("leftpad", "2.0.0")],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["foo".to_string()]),
        wrapper_id: Some("f-aaaa".to_string()),
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    link_packages(&project_dir, &[leftpad2_target, target_b], false, None).unwrap();

    let after_b = std::fs::read_link(&leftpad_symlink).unwrap();
    assert!(
        after_b.to_string_lossy().contains("leftpad@2.0.0"),
        "stamp must include dep edges so a deps-only \
             change forces a relink. leftpad symlink should now point \
             at the v2 wrapper, got {after_b:?}",
    );
    // Negative regression: must NOT still point at v1.
    assert!(
        !after_b.to_string_lossy().contains("leftpad@1.0.0"),
        "stale dep edge from run 1 survived run 2 — v2 stamp didn't \
             catch the deps-only change. Got: {after_b:?}",
    );
}

/// Stamp content is deterministic — same target → same stamp.
#[test]
fn compute_link_stamp_is_deterministic_for_same_target() {
    let target = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: PathBuf::from("/tmp/store/foo"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: Some("t-deadbeef".to_string()),
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    let s1 = compute_link_stamp(&target);
    let s2 = compute_link_stamp(&target);
    assert_eq!(s1, s2);
    assert!(s1.starts_with("lpm-link-stamp v2\n"));
    assert!(s1.contains("wrapper_id=t-deadbeef"));
    assert!(s1.contains("materialization=cas"));
    assert!(s1.contains("store_path=/tmp/store/foo"));
}

/// Distinct identity → distinct stamps. Specifically: same
/// `(name, version, wrapper_segment)` but different `store_path`
/// or `materialization` or `wrapper_id` produce different
/// stamps. This guards source-kind changes that share a wrapper segment.
#[test]
fn compute_link_stamp_changes_when_identity_differs() {
    let base = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: PathBuf::from("/tmp/store/registry/foo"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    // Same wrapper segment (`foo@1.0.0`), different store_path.
    let other_store = LinkTarget {
        store_path: PathBuf::from("/tmp/store/tarball-local/sha256-aaaa/foo"),
        ..base.clone()
    };
    assert_ne!(compute_link_stamp(&base), compute_link_stamp(&other_store));

    // Different materialization.
    let other_mat = LinkTarget {
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        ..base.clone()
    };
    assert_ne!(compute_link_stamp(&base), compute_link_stamp(&other_mat));

    // Different wrapper_id (None vs Some).
    let other_wid = LinkTarget {
        wrapper_id: Some("t-1234567890abcdef".to_string()),
        ..base.clone()
    };
    assert_ne!(compute_link_stamp(&base), compute_link_stamp(&other_wid));
}

/// `link_stamp_matches` returns false for missing markers, empty
/// markers, garbled bytes, and stamps that don't match the
/// target's identity.
#[test]
fn link_stamp_matches_rejects_missing_empty_garbled_and_mismatched_markers() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join(".linked");
    let target = LinkTarget {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        store_path: PathBuf::from("/tmp/store/foo"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    // Missing.
    assert!(!link_stamp_matches(&marker, &target));

    // Empty legacy marker.
    std::fs::write(&marker, "").unwrap();
    assert!(!link_stamp_matches(&marker, &target));

    // Garbled.
    std::fs::write(&marker, "not a stamp at all").unwrap();
    assert!(!link_stamp_matches(&marker, &target));

    // Mismatched (different store_path).
    let other = LinkTarget {
        store_path: PathBuf::from("/tmp/store/bar"),
        ..target.clone()
    };
    std::fs::write(&marker, compute_link_stamp(&other)).unwrap();
    assert!(!link_stamp_matches(&marker, &target));

    // Match.
    std::fs::write(&marker, compute_link_stamp(&target)).unwrap();
    assert!(link_stamp_matches(&marker, &target));
}

#[test]
fn cleanup_stale_entries_recognizes_directory_wrapper_segments() {
    // `+`-shape wrappers must be recognized by cleanup as
    // expected entries when their LinkTarget is in the package
    // set. Otherwise directory deps would get swept on the second
    // `lpm install` run.
    //
    // Wrappers live at `<project>/.lpm/wrappers/`,
    // resolved through `LayoutPaths` so the test setup tracks
    // production semantics automatically.
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let layout = LayoutPaths::for_project(&project_dir);
    let lpm_dir = layout.isolated_wrapper_root();
    std::fs::create_dir_all(&lpm_dir).unwrap();
    // Pre-create a `+`-shape wrapper as if from a prior install.
    let wrapper = lpm_dir.join("local-foo+f-deadbeef00000000");
    std::fs::create_dir_all(&wrapper).unwrap();
    std::fs::write(wrapper.join("marker"), b"x").unwrap();
    // Also a stale `+`-shape wrapper that isn't expected.
    let stale = lpm_dir.join("stale-pkg+f-1111222233334444");
    std::fs::create_dir_all(&stale).unwrap();

    let target = LinkTarget {
        name: "local-foo".to_string(),
        version: "0.0.0".to_string(),
        store_path: PathBuf::from("/tmp/source"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: Some("f-deadbeef00000000".to_string()),
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    cleanup_stale_entries(&project_dir, &[target]).unwrap();

    assert!(wrapper.exists(), "expected wrapper must survive cleanup");
    assert!(!stale.exists(), "stale wrapper must be removed");
}

#[test]
fn link_finalize_directory_root_symlink_targets_plus_wrapper() {
    // Stage 3 root-symlink target path uses `wrapper_segment`
    // so the `+`-shape lookup is honored.
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let src = make_local_source_dir(root.path(), "local-bar");

    let target = LinkTarget {
        name: "local-bar".to_string(),
        version: "0.0.0".to_string(),
        store_path: src,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["local-bar".to_string()]),
        wrapper_id: Some("f-cafebabe00000000".to_string()),
        materialization: Materialization::DirectorySource,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    link_packages(&project_dir, &[target], false, None).unwrap();

    let root_link = project_dir.join("node_modules/local-bar");
    // Relative shape:
    // `node_modules/local-bar` → `../.lpm/wrappers/local-bar+f-.../node_modules/local-bar`
    let expected = PathBuf::from("..")
        .join(".lpm")
        .join("wrappers")
        .join("local-bar+f-cafebabe00000000")
        .join("node_modules")
        .join("local-bar");
    assert_directory_link_target(&root_link, &expected, "directory root link target");
}

// ── Legacy root-symlink retarget ─────────────────────────────────
//
// Pre-fix bug: the layout migration wipes `node_modules/.lpm/` but
// does NOT touch root symlinks at `node_modules/<pkg>` whose
// targets point into the legacy wrapper-root shape (`.lpm/<seg>/...`,
// no `wrappers/` segment). Stage 3 root-symlink creation skips
// any `root_link.exists()` entry, so the legacy symlink survives,
// its target points at a wiped location → broken `node_modules/<pkg>`.
//
// Post-fix: `cleanup_stale_entries` removes any root symlink whose
// target string identifies it as the legacy shape. Stage 3 then
// recreates with the correct new target.

#[test]
fn cleanup_stale_entries_removes_legacy_shape_root_symlink() {
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let nm = project_dir.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    // Plant a legacy-shape root symlink — `.lpm/<seg>/node_modules/<pkg>`
    // (the pre- target shape), no `wrappers/` segment.
    let legacy_target = PathBuf::from(".lpm")
        .join("express@4.22.1")
        .join("node_modules")
        .join("express");
    let root_link = nm.join("express");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&legacy_target, &root_link).unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(&legacy_target, &root_link);

    // Sanity: the legacy link IS present pre-cleanup.
    assert!(root_link.symlink_metadata().is_ok());

    // Express IS in the resolution set (a direct dep we're keeping).
    let express = LinkTarget {
        name: "express".to_string(),
        version: "4.22.1".to_string(),
        store_path: project_dir.join("does-not-matter"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["express".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    cleanup_stale_entries(&project_dir, &[express]).unwrap();

    // The legacy-shape symlink must be removed so Stage 3 can
    // create a fresh one with the new target shape.
    assert!(
        root_link.symlink_metadata().is_err(),
        "cleanup must remove legacy-shape root symlink so Stage 3 retargets it"
    );
}

#[test]
fn cleanup_stale_entries_removes_legacy_shape_scoped_root_symlink() {
    // Scoped names (`@scope/pkg`) live one level deeper in
    // `node_modules/` and traverse a separate branch in the
    // cleanup sweep. The legacy-shape detector must apply
    // there too — without it, scoped legacy symlinks
    // (`node_modules/@types/node` → `../.lpm/@types+node@.../...`)
    // would survive the migration broken just like the
    // unscoped case.
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let nm = project_dir.join("node_modules");
    std::fs::create_dir_all(nm.join("@types")).unwrap();

    // Pre- scoped target shape: `../.lpm/<seg>/node_modules/<scope>/<name>`
    // (one extra `..` for the scope dir, no `wrappers/` segment).
    let legacy_target = PathBuf::from("..")
        .join(".lpm")
        .join("@types+node@20.0.0")
        .join("node_modules")
        .join("@types")
        .join("node");
    let scoped_link = nm.join("@types").join("node");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&legacy_target, &scoped_link).unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(&legacy_target, &scoped_link);

    // The scoped pkg IS in the resolution set (a kept direct dep).
    let types_node = LinkTarget {
        name: "@types/node".to_string(),
        version: "20.0.0".to_string(),
        store_path: project_dir.join("does-not-matter"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["@types/node".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    cleanup_stale_entries(&project_dir, &[types_node]).unwrap();

    // Legacy-shape scoped symlink must be removed so Stage 3
    // can recreate it pointing at `../../.lpm/wrappers/<seg>/...`.
    assert!(
        scoped_link.symlink_metadata().is_err(),
        "scoped legacy-shape symlink must be removed during cleanup"
    );
}

#[test]
fn cleanup_stale_entries_preserves_new_shape_root_symlink() {
    // Counterpoint: a NEW-shape root symlink (target contains
    // `.lpm/wrappers/`) must NOT be removed. Stage 3's "skip if
    // exists" guard then keeps the install fast on the warm path.
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let nm = project_dir.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    let new_target = PathBuf::from("..")
        .join(".lpm")
        .join("wrappers")
        .join("express@4.22.1")
        .join("node_modules")
        .join("express");
    let root_link = nm.join("express");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&new_target, &root_link).unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(&new_target, &root_link);

    let express = LinkTarget {
        name: "express".to_string(),
        version: "4.22.1".to_string(),
        store_path: project_dir.join("does-not-matter"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["express".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    cleanup_stale_entries(&project_dir, &[express]).unwrap();

    assert!(
        root_link.symlink_metadata().is_ok(),
        "new-shape root symlink must survive cleanup (warm-install fast path)"
    );
}

#[test]
fn cleanup_stale_entries_preserves_workspace_member_symlink() {
    // Workspace member symlinks point at workspace source dirs
    // (e.g., `../packages/foo`) — their target string contains
    // neither `.lpm/` nor `.lpm/wrappers/`. The legacy-shape
    // detector must leave them alone.
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let nm = project_dir.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();
    let member_src = root.path().join("packages").join("foo");
    std::fs::create_dir_all(&member_src).unwrap();
    let workspace_target = PathBuf::from("..").join("packages").join("foo");
    let root_link = nm.join("foo");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&workspace_target, &root_link).unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(&workspace_target, &root_link);

    // Foo is a direct dep so the existing stale-name sweep keeps it.
    let foo = LinkTarget {
        name: "foo".to_string(),
        version: "0.0.0".to_string(),
        store_path: member_src,
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["foo".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    cleanup_stale_entries(&project_dir, &[foo]).unwrap();

    assert!(
        root_link.symlink_metadata().is_ok(),
        "workspace member symlink (target outside .lpm/) must survive cleanup"
    );
}

#[test]
fn cleanup_stale_entries_preserves_self_reference_symlink() {
    // Self-ref `node_modules/<self>` → `..` (project root).
    // Target contains no `.lpm/`, must survive cleanup.
    let root = tempfile::tempdir().unwrap();
    let project_dir = root.path().join("project");
    let nm = project_dir.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();
    let self_link = nm.join("self-pkg");
    #[cfg(unix)]
    std::os::unix::fs::symlink(PathBuf::from(".."), &self_link).unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(PathBuf::from(".."), &self_link);

    // Self-pkg is in the package set so the stale-name sweep keeps it.
    let self_pkg = LinkTarget {
        name: "self-pkg".to_string(),
        version: "0.0.0".to_string(),
        store_path: project_dir.join("does-not-matter"),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["self-pkg".to_string()]),
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    cleanup_stale_entries(&project_dir, &[self_pkg]).unwrap();

    assert!(
        self_link.symlink_metadata().is_ok(),
        "self-ref symlink (target = ..) must survive cleanup"
    );
}

#[test]
fn link_finalize_retargets_legacy_root_symlink_after_migration() {
    // End-to-end: simulate an upgrade-in-place migration where
    // the legacy wrapper tree was wiped (61.3) but a legacy
    // root symlink survives. Re-running the install must
    // produce a working `node_modules/<pkg>` pointing at the
    // NEW wrapper-root shape.
    let store_dir = tempfile::tempdir().unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    let store_path = create_fake_store_package(store_dir.path(), "express");

    // Simulate post-migration state: legacy `node_modules/.lpm/`
    // is gone (the 61.3 wipe ran), but the legacy root symlink
    // remains pointing at the wiped location.
    let nm = project_dir.path().join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();
    let legacy_target = PathBuf::from(".lpm")
        .join("express@4.22.1")
        .join("node_modules")
        .join("express");
    let root_link = nm.join("express");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&legacy_target, &root_link).unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(&legacy_target, &root_link);

    // Run a normal link pass.
    link_packages(
        project_dir.path(),
        &[LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }],
        false,
        None,
    )
    .unwrap();

    // The root symlink must now point at the NEW wrapper shape,
    // and the resolved target must actually exist (no broken link).
    let expected = PathBuf::from("..")
        .join(".lpm")
        .join("wrappers")
        .join("express@4.22.1")
        .join("node_modules")
        .join("express");
    assert_directory_link_target(
        &root_link,
        &expected,
        "post-migration root symlink must point at the new wrapper shape, not the wiped legacy location",
    );
    // `node_modules/express/package.json` resolves through the
    // new symlink — proves the install actually works.
    assert!(
        root_link.join("package.json").exists(),
        "post-migration `node_modules/<pkg>` must resolve to a real file"
    );
}

// ── dep-target wrapper-segment branch ────────────────────────────

#[test]
fn link_one_package_dep_target_uses_plus_shape_for_file_source_edge() {
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");
    let parent_store = create_fake_store_package(&store_dir, "parent");

    let parent = LinkTarget {
        name: "parent".to_string(),
        version: "1.0.0".to_string(),
        store_path: parent_store,
        dependencies: vec![LinkDependency::new(
            "local-dep",
            "local-dep",
            "0.1.0",
            Some("f-deadbeef00000000".to_string()),
        )],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    link_packages(&project_dir, &[parent], false, None).unwrap();

    // Inside parent's wrapper, `local-dep` symlink target uses `+`-shape.
    let dep_link = project_dir.join(".lpm/wrappers/parent@1.0.0/node_modules/local-dep");
    // Expected: `../../local-dep+f-deadbeef00000000/node_modules/local-dep`
    let expected = PathBuf::from("..")
        .join("..")
        .join("local-dep+f-deadbeef00000000")
        .join("node_modules")
        .join("local-dep");
    assert_directory_link_target(
        &dep_link,
        &expected,
        "file source edge must route to + shape",
    );
}

#[test]
fn link_one_package_dep_target_uses_plus_shape_for_link_source_edge() {
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");
    let parent_store = create_fake_store_package(&store_dir, "parent");

    let parent = LinkTarget {
        name: "parent".to_string(),
        version: "1.0.0".to_string(),
        store_path: parent_store,
        dependencies: vec![LinkDependency::new(
            "linked-dep",
            "linked-dep",
            "0.1.0",
            Some("l-cafebabe00000000".to_string()),
        )],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    link_packages(&project_dir, &[parent], false, None).unwrap();

    let dep_link = project_dir.join(".lpm/wrappers/parent@1.0.0/node_modules/linked-dep");
    let expected = PathBuf::from("..")
        .join("..")
        .join("linked-dep+l-cafebabe00000000")
        .join("node_modules")
        .join("linked-dep");
    assert_directory_link_target(
        &dep_link,
        &expected,
        "link source edge must route to + shape",
    );
}

#[test]
fn link_one_package_dep_target_uses_at_shape_for_semver_version() {
    // Regression: `dep_version = "4.17.21"` (a normal SemVer)
    // continues to produce `<safe>@4.17.21` as before. Day-5's
    // branch must not regress the registry/tarball case.
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("store");
    let project_dir = root.path().join("project");
    let parent_store = create_fake_store_package(&store_dir, "parent");

    let parent = LinkTarget {
        name: "parent".to_string(),
        version: "1.0.0".to_string(),
        store_path: parent_store,
        dependencies: vec![LinkDependency::registry("lodash", "4.17.21")],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
        materialization: Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };

    link_packages(&project_dir, &[parent], false, None).unwrap();

    let dep_link = project_dir.join(".lpm/wrappers/parent@1.0.0/node_modules/lodash");
    let expected = PathBuf::from("..")
        .join("..")
        .join("lodash@4.17.21")
        .join("node_modules")
        .join("lodash");
    assert_directory_link_target(
        &dep_link,
        &expected,
        "SemVer dep_version MUST keep the @ shape",
    );
}
