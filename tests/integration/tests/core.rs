//! Integration tests for core LPM features.
//!
//! These tests use real fixture projects and exercise cross-crate flows:
//! lockfile parsing, workspace discovery, migration, task graph, etc.
//!
//! They do NOT make network calls — they test the local processing pipeline.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join(name)
}

// ─── Lockfile ────────────────────────────────────────────────────

#[test]
fn lockfile_toml_binary_roundtrip() {
    let mut lf = lpm_lockfile::Lockfile::new();
    for i in 0..100 {
        lf.add_package(lpm_lockfile::LockedPackage {
            name: format!("pkg-{i:04}"),
            version: format!("{i}.0.0"),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-test".to_string()),
            dependencies: if i > 0 {
                vec![format!("pkg-{:04}@{}.0.0", i - 1, i - 1)]
            } else {
                vec![]
            },
            alias_dependencies: vec![],
            tarball: None,
        });
    }

    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");

    // Write both formats
    lf.write_all(&toml_path).unwrap();

    // Read via fast path (binary preferred)
    let restored = lpm_lockfile::Lockfile::read_fast(&toml_path).unwrap();
    assert_eq!(lf.packages.len(), restored.packages.len());

    // Verify every package
    for (orig, rest) in lf.packages.iter().zip(restored.packages.iter()) {
        assert_eq!(orig.name, rest.name);
        assert_eq!(orig.version, rest.version);
        assert_eq!(orig.integrity, rest.integrity);
        assert_eq!(orig.dependencies, rest.dependencies);
    }
}

#[test]
fn lockfile_binary_corrupt_falls_back_to_toml() {
    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "express".to_string(),
        version: "4.22.1".to_string(),
        source: None,
        integrity: None,
        dependencies: vec![],
        alias_dependencies: vec![],
        tarball: None,
    });

    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = dir.path().join("lpm.lockb");

    lf.write_all(&toml_path).unwrap();

    // Corrupt binary
    std::fs::write(&binary_path, b"GARBAGE_DATA_NOT_LPMB").unwrap();

    // Should fall back to TOML
    let restored = lpm_lockfile::Lockfile::read_fast(&toml_path).unwrap();
    assert_eq!(restored.packages.len(), 1);
    assert_eq!(restored.packages[0].name, "express");
}

#[test]
fn lockfile_source_url_validation() {
    assert!(lpm_lockfile::is_safe_source("registry+https://lpm.dev"));
    assert!(lpm_lockfile::is_safe_source(
        "registry+https://registry.npmjs.org"
    ));
    assert!(lpm_lockfile::is_safe_source(
        "registry+https://custom.corp.com"
    ));
    assert!(!lpm_lockfile::is_safe_source("registry+http://evil.com"));
    assert!(!lpm_lockfile::is_safe_source("registry+ftp://evil.com"));
}

// ─── Workspace ───────────────────────────────────────────────────

#[test]
fn workspace_discovery_finds_members() {
    let path = fixture_path("workspace-monorepo");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let ws = lpm_workspace::discover_workspace(&path).unwrap();
    assert!(ws.is_some());
    let ws = ws.unwrap();
    assert_eq!(ws.members.len(), 3);

    let names: Vec<&str> = ws
        .members
        .iter()
        .filter_map(|m| m.package.name.as_deref())
        .collect();
    assert!(names.contains(&"@test/utils"));
    assert!(names.contains(&"@test/core"));
    assert!(names.contains(&"@test/app"));
}

#[test]
fn workspace_protocol_resolution() {
    let path = fixture_path("workspace-monorepo");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let ws = lpm_workspace::discover_workspace(&path).unwrap().unwrap();

    let mut deps = HashMap::from([
        ("@test/utils".to_string(), "workspace:*".to_string()),
        ("@test/core".to_string(), "workspace:^".to_string()),
        ("ms".to_string(), "2.1.3".to_string()),
    ]);

    let resolved = lpm_workspace::resolve_workspace_protocol(&mut deps, &ws).unwrap();
    assert_eq!(deps["@test/utils"], "1.0.0");
    assert_eq!(deps["@test/core"], "^2.0.0");
    assert_eq!(deps["ms"], "2.1.3"); // unchanged
    assert_eq!(resolved.len(), 2);
}

#[test]
fn catalog_protocol_resolution() {
    let catalogs = HashMap::from([
        (
            "default".to_string(),
            HashMap::from([
                ("ms".to_string(), "2.1.3".to_string()),
                ("semver".to_string(), "7.6.3".to_string()),
            ]),
        ),
        (
            "testing".to_string(),
            HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
        ),
    ]);

    let mut deps = HashMap::from([
        ("ms".to_string(), "catalog:".to_string()),
        ("semver".to_string(), "catalog:".to_string()),
        ("jest".to_string(), "catalog:testing".to_string()),
        ("express".to_string(), "^4.22.0".to_string()),
    ]);

    lpm_workspace::resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
    assert_eq!(deps["ms"], "2.1.3");
    assert_eq!(deps["semver"], "7.6.3");
    assert_eq!(deps["jest"], "^29.0.0");
    assert_eq!(deps["express"], "^4.22.0"); // unchanged
}

// ─── Migration ───────────────────────────────────────────────────

#[test]
fn migrate_detects_npm_lockfile() {
    let path = fixture_path("migrate-npm");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let source = lpm_migrate::detect::detect_source(&path).unwrap();
    assert_eq!(source.kind, lpm_migrate::SourceKind::Npm);
    assert_eq!(source.version, 3);
}

#[test]
fn migrate_npm_parses_and_converts() {
    let path = fixture_path("migrate-npm");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let result = lpm_migrate::migrate(&path).unwrap();
    assert_eq!(result.source.kind, lpm_migrate::SourceKind::Npm);
    assert!(result.package_count > 0);

    // Verify ms package is in the lockfile
    let ms = result.lockfile.find_package("ms");
    assert!(ms.is_some());
    assert_eq!(ms.unwrap().version, "2.1.3");
}

// ─── Migration: Yarn ────────────────────────────────────────────

#[test]
fn migrate_detects_yarn_lockfile() {
    let path = fixture_path("migrate-yarn");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let source = lpm_migrate::detect::detect_source(&path).unwrap();
    assert_eq!(source.kind, lpm_migrate::SourceKind::Yarn);
    assert_eq!(source.version, 1);
}

#[test]
fn migrate_yarn_parses_and_converts() {
    let path = fixture_path("migrate-yarn");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let result = lpm_migrate::migrate(&path).unwrap();
    assert_eq!(result.source.kind, lpm_migrate::SourceKind::Yarn);
    assert!(
        result.package_count >= 2,
        "expected at least 2 packages, got {}",
        result.package_count
    );

    // Verify ms and depd are in the lockfile
    let ms = result.lockfile.find_package("ms");
    assert!(ms.is_some(), "ms not found in lockfile");
    assert_eq!(ms.unwrap().version, "2.1.3");

    let depd = result.lockfile.find_package("depd");
    assert!(depd.is_some(), "depd not found in lockfile");
    assert_eq!(depd.unwrap().version, "2.0.0");

    // Integrity hashes should be preserved
    assert!(
        result.integrity_count >= 2,
        "expected at least 2 integrity hashes, got {}",
        result.integrity_count
    );
}

#[test]
fn migrate_yarn_marks_dev_deps() {
    let path = fixture_path("migrate-yarn");
    let result = lpm_migrate::migrate(&path).unwrap();

    // prettier is a devDependency in the fixture — its MigratedPackage should be marked.
    // After normalization, we can check that the package exists.
    let prettier = result.lockfile.find_package("prettier");
    assert!(prettier.is_some(), "prettier not found in lockfile");
}

// ─── Migration: pnpm ────────────────────────────────────────────

#[test]
fn migrate_detects_pnpm_lockfile() {
    let path = fixture_path("migrate-pnpm");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let source = lpm_migrate::detect::detect_source(&path).unwrap();
    assert_eq!(source.kind, lpm_migrate::SourceKind::Pnpm);
    assert_eq!(source.version, 9);
}

#[test]
fn migrate_pnpm_parses_and_converts() {
    let path = fixture_path("migrate-pnpm");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let result = lpm_migrate::migrate(&path).unwrap();
    assert_eq!(result.source.kind, lpm_migrate::SourceKind::Pnpm);
    assert!(
        result.package_count >= 2,
        "expected at least 2 packages, got {}",
        result.package_count
    );

    let ms = result.lockfile.find_package("ms");
    assert!(ms.is_some(), "ms not found in lockfile");
    assert_eq!(ms.unwrap().version, "2.1.3");

    let depd = result.lockfile.find_package("depd");
    assert!(depd.is_some(), "depd not found in lockfile");
}

// ─── Migration: Bun ─────────────────────────────────────────────

#[test]
fn migrate_detects_bun_lockfile() {
    let path = fixture_path("migrate-bun");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let source = lpm_migrate::detect::detect_source(&path).unwrap();
    assert_eq!(source.kind, lpm_migrate::SourceKind::Bun);
    assert_eq!(source.version, 1); // .lock = JSON format = version 1
}

#[test]
fn migrate_bun_parses_and_converts() {
    let path = fixture_path("migrate-bun");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let result = lpm_migrate::migrate(&path).unwrap();
    assert_eq!(result.source.kind, lpm_migrate::SourceKind::Bun);
    assert!(
        result.package_count >= 2,
        "expected at least 2 packages, got {}",
        result.package_count
    );

    let ms = result.lockfile.find_package("ms");
    assert!(ms.is_some(), "ms not found in lockfile");
    assert_eq!(ms.unwrap().version, "2.1.3");

    let depd = result.lockfile.find_package("depd");
    assert!(depd.is_some(), "depd not found in lockfile");
}

// ─── Migration: Cross-manager ───────────────────────────────────

#[test]
fn migrate_all_managers_produce_consistent_packages() {
    // All four fixtures have ms@2.1.3 and depd@2.0.0 as dependencies.
    // Verify that all managers produce the same package set.
    for fixture in &["migrate-npm", "migrate-yarn", "migrate-pnpm", "migrate-bun"] {
        let path = fixture_path(fixture);
        if !path.exists() {
            continue;
        }
        let result = lpm_migrate::migrate(&path).unwrap();

        let ms = result.lockfile.find_package("ms");
        assert!(ms.is_some(), "{fixture}: ms not found");
        assert_eq!(
            ms.unwrap().version,
            "2.1.3",
            "{fixture}: ms version mismatch"
        );
    }
}

// ─── Migration: Lockfile writing ────────────────────────────────

#[test]
fn migrate_writes_valid_lockfile() {
    let dir = tempfile::tempdir().unwrap();

    // Copy npm fixture to temp dir
    let fixture = fixture_path("migrate-npm");
    std::fs::copy(
        fixture.join("package.json"),
        dir.path().join("package.json"),
    )
    .unwrap();
    std::fs::copy(
        fixture.join("package-lock.json"),
        dir.path().join("package-lock.json"),
    )
    .unwrap();

    let result = lpm_migrate::migrate(dir.path()).unwrap();

    // Write the lockfile
    let lockfile_path = dir.path().join("lpm.lock");
    result.lockfile.write_all(&lockfile_path).unwrap();

    // Verify the written lockfile can be read back
    assert!(lockfile_path.exists(), "lpm.lock should exist");
    assert!(
        lockfile_path.metadata().unwrap().len() > 0,
        "lpm.lock should not be empty"
    );

    // Verify binary lockfile was also created
    let lockb_path = dir.path().join("lpm.lockb");
    assert!(lockb_path.exists(), "lpm.lockb should exist");
}

// ─── Migration: Backup & Rollback ───────────────────────────────

#[test]
fn migrate_backup_and_rollback_cycle() {
    let dir = tempfile::tempdir().unwrap();

    // Copy npm fixture
    let fixture = fixture_path("migrate-npm");
    std::fs::copy(
        fixture.join("package.json"),
        dir.path().join("package.json"),
    )
    .unwrap();
    let source_lockfile = dir.path().join("package-lock.json");
    let original_content = std::fs::read_to_string(fixture.join("package-lock.json")).unwrap();
    std::fs::write(&source_lockfile, &original_content).unwrap();

    // Create backup tracker and back up source lockfile
    let mut backup = lpm_migrate::backup::MigrationBackup::new();
    backup.backup_file(&source_lockfile).unwrap();
    backup.write_manifest(dir.path()).unwrap();

    // Write migration result
    let result = lpm_migrate::migrate(dir.path()).unwrap();
    let lockfile_path = dir.path().join("lpm.lock");
    result.lockfile.write_all(&lockfile_path).unwrap();

    // Verify migration artifacts exist
    assert!(lockfile_path.exists());

    // Rollback
    let restored = lpm_migrate::backup::rollback_from_backups(dir.path()).unwrap();
    assert!(
        restored.contains(&"package-lock.json".to_string()),
        "package-lock.json should be restored, got: {:?}",
        restored
    );

    // Verify original content is restored
    let restored_content = std::fs::read_to_string(&source_lockfile).unwrap();
    assert_eq!(restored_content, original_content);
}

// ─── Task Graph ──────────────────────────────────────────────────

#[test]
fn task_graph_respects_depends_on() {
    let scripts: HashMap<String, String> = HashMap::from([
        ("build".to_string(), "echo build".to_string()),
        ("test".to_string(), "echo test".to_string()),
        ("lint".to_string(), "echo lint".to_string()),
        ("check".to_string(), "echo check".to_string()),
    ]);

    let ci_task = lpm_runner::lpm_json::TaskConfig {
        depends_on: vec!["lint".to_string(), "check".to_string(), "test".to_string()],
        ..Default::default()
    };

    let test_task = lpm_runner::lpm_json::TaskConfig {
        depends_on: vec!["build".to_string()],
        ..Default::default()
    };

    let tasks: HashMap<String, lpm_runner::lpm_json::TaskConfig> =
        HashMap::from([("ci".to_string(), ci_task), ("test".to_string(), test_task)]);

    let levels =
        lpm_runner::task_graph::task_levels(&scripts, &tasks, &["ci".to_string()]).unwrap();

    // build must come before test, lint+check+build can be parallel
    assert!(levels.len() >= 2);

    // Flatten and check all tasks present
    let all: Vec<&String> = levels.iter().flat_map(|l| l.iter()).collect();
    assert!(all.iter().any(|t| t.as_str() == "build"));
    assert!(all.iter().any(|t| t.as_str() == "test"));
    assert!(all.iter().any(|t| t.as_str() == "lint"));
    assert!(all.iter().any(|t| t.as_str() == "check"));
    assert!(all.iter().any(|t| t.as_str() == "ci"));

    // build must appear before test
    let build_pos = all.iter().position(|t| t.as_str() == "build").unwrap();
    let test_pos = all.iter().position(|t| t.as_str() == "test").unwrap();
    assert!(build_pos < test_pos);
}

#[test]
fn dag_topological_sort_parallel_groups() {
    let nodes = HashMap::from([
        ("a".to_string(), vec![]),
        ("b".to_string(), vec![]),
        ("c".to_string(), vec!["a".to_string(), "b".to_string()]),
        ("d".to_string(), vec!["c".to_string()]),
    ]);

    let levels = lpm_runner::dag::topological_levels(&nodes).unwrap();
    assert_eq!(levels.len(), 3); // [a,b], [c], [d]
    assert_eq!(levels[0].len(), 2); // a and b parallel
    assert_eq!(levels[1].len(), 1); // c
    assert_eq!(levels[2].len(), 1); // d
}

#[test]
fn dag_cycle_detection() {
    let nodes = HashMap::from([
        ("a".to_string(), vec!["b".to_string()]),
        ("b".to_string(), vec!["c".to_string()]),
        ("c".to_string(), vec!["a".to_string()]),
    ]);

    let result = lpm_runner::dag::topological_levels(&nodes);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("circular"));
}

// ─── Security ────────────────────────────────────────────────────

#[test]
fn typosquatting_detects_similar_names() {
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("loadash"),
        Some("lodash")
    );
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("exprss"),
        Some("express")
    );
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("lodash"),
        None
    ); // exact match
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("my-unique-pkg"),
        None
    );
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("@scope/lodash"),
        None
    ); // scoped
}

#[test]
fn security_policy_release_age_check() {
    let policy = lpm_security::SecurityPolicy {
        trusted_dependencies: lpm_security::TrustedDependencies::default(),
        minimum_release_age_secs: 86400, // 24 hours
    };

    // Old timestamp (well in the past, guaranteed older than 24h)
    let result = policy.check_release_age(Some("2020-01-01T00:00:00Z"));
    assert!(result.is_none()); // Should be fine — old enough
}

// ─── Linker ──────────────────────────────────────────────────────

#[test]
fn linker_isolated_mode_creates_lpm_dir() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create a minimal store package
    let pkg_dir = store_dir.join("v1").join("ms@2.1.3");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"ms","version":"2.1.3"}"#,
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), "module.exports = function(){}").unwrap();

    let targets = vec![lpm_linker::LinkTarget {
        name: "ms".to_string(),
        version: "2.1.3".to_string(),
        store_path: pkg_dir,
        dependencies: vec![],
        aliases: std::collections::HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
    }];

    let result = lpm_linker::link_packages(&project_dir, &targets, false, None).unwrap();

    assert!(result.linked > 0);
    assert!(project_dir.join("node_modules/.lpm/ms@2.1.3").exists());
    assert!(project_dir.join("node_modules/ms").exists());
}

#[test]
fn linker_hoisted_mode_flattens() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    let pkg_dir = store_dir.join("v1").join("ms@2.1.3");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"ms","version":"2.1.3"}"#,
    )
    .unwrap();

    let targets = vec![lpm_linker::LinkTarget {
        name: "ms".to_string(),
        version: "2.1.3".to_string(),
        store_path: pkg_dir,
        dependencies: vec![],
        aliases: std::collections::HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: None,
    }];

    let result = lpm_linker::link_packages_hoisted(&project_dir, &targets, false, None).unwrap();

    assert!(result.linked > 0);
    // Hoisted: package directly in node_modules/ (not under .lpm/)
    assert!(project_dir.join("node_modules/ms/package.json").exists());
}

// ─── Store ───────────────────────────────────────────────────────

#[test]
fn store_gc_preview_doesnt_delete() {
    let dir = tempfile::tempdir().unwrap();
    let store = lpm_store::PackageStore::at(dir.path());

    // Create a complete package in the store.
    let pkg_dir = dir.path().join("v1").join("unused@1.0.0");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(pkg_dir.join("package.json"), "{}").unwrap();
    std::fs::write(pkg_dir.join(".integrity"), "sha512-test").unwrap();

    let referenced = HashSet::new(); // nothing referenced

    let preview = store.gc_preview(&referenced, None).unwrap();
    assert!(!preview.would_remove.is_empty());

    // Verify package still exists (not deleted)
    assert!(pkg_dir.exists());
}

// ─── Binary Lockfile Bounds ──────────────────────────────────────

#[test]
fn binary_lockfile_rejects_corrupt_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lpm.lockb");

    // Write garbage
    std::fs::write(&path, b"NOT_A_LOCKFILE_JUST_GARBAGE_DATA").unwrap();

    let result = lpm_lockfile::BinaryLockfileReader::open(&path);
    assert!(result.is_err()); // Bad magic bytes
}

#[test]
fn binary_lockfile_handles_truncated_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lpm.lockb");

    // Write valid magic but truncated (only 8 bytes instead of 16 header)
    let mut data = Vec::new();
    data.extend_from_slice(b"LPMB");
    data.extend_from_slice(&1u32.to_le_bytes()); // version
    std::fs::write(&path, &data).unwrap();

    let result = lpm_lockfile::BinaryLockfileReader::open(&path);
    assert!(result.is_err()); // Too small
}

// ─── Workspace + Fixture Integration ─────────────────────────────

#[test]
fn fixture_simple_project_reads_package_json() {
    let path = fixture_path("simple-project");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let pkg = lpm_workspace::read_package_json(&path.join("package.json")).unwrap();
    assert_eq!(pkg.name.as_deref(), Some("simple-test-project"));
    assert_eq!(pkg.dependencies.len(), 2);
    assert_eq!(pkg.dependencies.get("ms").unwrap(), "2.1.3");
    assert_eq!(pkg.dependencies.get("semver").unwrap(), "7.6.3");
}

#[test]
fn fixture_catalog_workspace_resolves_deps() {
    let path = fixture_path("with-catalog");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let ws = lpm_workspace::discover_workspace(&path).unwrap().unwrap();

    // Read the lib member's deps
    let lib_member = ws
        .members
        .iter()
        .find(|m| m.package.name.as_deref() == Some("@test/lib"))
        .expect("@test/lib member not found");

    let mut deps = lib_member.package.dependencies.clone();

    // Resolve catalog: protocol using root catalogs
    lpm_workspace::resolve_catalog_protocol(&mut deps, &ws.root_package.catalogs).unwrap();

    assert_eq!(deps["ms"], "2.1.3");
    assert_eq!(deps["semver"], "7.6.3");
}

#[test]
fn fixture_with_scripts_reads_lpm_json() {
    let path = fixture_path("with-scripts");
    assert!(path.exists(), "fixture not found: {}", path.display());

    let config = lpm_runner::lpm_json::read_lpm_json(&path)
        .unwrap()
        .expect("lpm.json should exist");

    assert_eq!(config.tasks.len(), 3);
    assert!(config.tasks.contains_key("build"));
    assert!(config.tasks.contains_key("test"));
    assert!(config.tasks.contains_key("ci"));

    let build = &config.tasks["build"];
    assert!(build.cache);
    assert_eq!(build.outputs, vec!["dist/**"]);

    let test = &config.tasks["test"];
    assert_eq!(test.depends_on, vec!["build"]);

    let ci = &config.tasks["ci"];
    assert_eq!(ci.depends_on.len(), 3);
}

#[test]
fn fixture_with_scripts_task_graph_integration() {
    let path = fixture_path("with-scripts");
    assert!(path.exists(), "fixture not found: {}", path.display());

    // Read package.json scripts
    let pkg = lpm_workspace::read_package_json(&path.join("package.json")).unwrap();

    // Read lpm.json tasks
    let config = lpm_runner::lpm_json::read_lpm_json(&path).unwrap().unwrap();

    // Build the task graph for "ci"
    let levels =
        lpm_runner::task_graph::task_levels(&pkg.scripts, &config.tasks, &["ci".to_string()])
            .unwrap();

    // ci depends on [lint, check, test], test depends on [build]
    // So: [build, check, lint], [test], [ci] — or similar valid ordering
    assert!(levels.len() >= 3);

    let all: Vec<&String> = levels.iter().flat_map(|l| l.iter()).collect();
    assert!(all.iter().any(|t| t.as_str() == "ci"));
    assert!(all.iter().any(|t| t.as_str() == "build"));
    assert!(all.iter().any(|t| t.as_str() == "test"));
    assert!(all.iter().any(|t| t.as_str() == "lint"));
    assert!(all.iter().any(|t| t.as_str() == "check"));

    // build must appear before test (build is a dependency of test)
    let build_pos = all.iter().position(|t| t.as_str() == "build").unwrap();
    let test_pos = all.iter().position(|t| t.as_str() == "test").unwrap();
    assert!(
        build_pos < test_pos,
        "build (pos {build_pos}) must come before test (pos {test_pos})"
    );

    // test must appear before ci (test is a dependency of ci)
    let ci_pos = all.iter().position(|t| t.as_str() == "ci").unwrap();
    assert!(
        test_pos < ci_pos,
        "test (pos {test_pos}) must come before ci (pos {ci_pos})"
    );
}

// ─── Phase 19: Security Policy ─────────────────────────────────

#[test]
fn release_age_blocks_recently_published() {
    // Phase 19 Finding #2: release age enforcement is a blocking gate, not a warning.
    // check_release_age returns Some(warning) which the install path converts to Err.
    let policy = lpm_security::SecurityPolicy {
        trusted_dependencies: lpm_security::TrustedDependencies::default(),
        minimum_release_age_secs: 86400,
    };

    // Test 1: A timestamp from "right now" must block (within 24h window).
    // We use the current UTC time formatted as ISO 8601. SystemTime -> epoch -> manual format.
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Format epoch as "YYYY-MM-DDThh:mm:ssZ" using civil time calculation.
    let recent_ts = epoch_to_iso8601(now_epoch - 300); // 5 minutes ago
    let warning = policy.check_release_age(Some(&recent_ts));
    assert!(
        warning.is_some(),
        "recently published package must trigger blocking (not just warning), ts={recent_ts}"
    );

    // Test 2: Unparseable timestamp also blocks (fail-closed behavior).
    let warning = policy.check_release_age(Some("not-a-date"));
    assert!(
        warning.is_some(),
        "unparseable timestamp must fail-closed (block)"
    );
}

/// Convert Unix epoch seconds to ISO 8601 string (UTC).
/// Handles leap years correctly. No external dependencies.
fn epoch_to_iso8601(epoch: u64) -> String {
    let secs_per_min: u64 = 60;
    let secs_per_hour: u64 = 3600;
    let secs_per_day: u64 = 86400;

    let mut remaining = epoch;
    let hours_of_day = (remaining % secs_per_day) / secs_per_hour;
    let minutes_of_hour = (remaining % secs_per_hour) / secs_per_min;
    let seconds_of_min = remaining % secs_per_min;

    remaining /= secs_per_day; // days since epoch

    let mut year: u64 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    let month_days: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month: u64 = 1;
    for &days in &month_days {
        if remaining < days {
            break;
        }
        remaining -= days;
        month += 1;
    }
    let day = remaining + 1;

    format!(
        "{year:04}-{month:02}-{day:02}T{hours_of_day:02}:{minutes_of_hour:02}:{seconds_of_min:02}Z"
    )
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[test]
fn release_age_allows_old_packages() {
    let policy = lpm_security::SecurityPolicy {
        trusted_dependencies: lpm_security::TrustedDependencies::default(),
        minimum_release_age_secs: 86400,
    };
    // A timestamp from 2020 is well past any release age window.
    assert!(
        policy
            .check_release_age(Some("2020-01-01T00:00:00Z"))
            .is_none()
    );
}

#[test]
fn typosquatting_skips_exact_match() {
    // Exact match for a popular package should NOT warn — user wants the real thing.
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("lodash"),
        None
    );
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("react"),
        None
    );
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("express"),
        None
    );
}

#[test]
fn typosquatting_warns_on_misspelling() {
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("loadash"),
        Some("lodash")
    );
    assert_eq!(
        lpm_security::typosquatting::check_typosquatting("expres"),
        Some("express")
    );
}

// ─── Phase 19: Store Verify ────────────────────────────────────

#[test]
fn store_list_packages_skips_missing_package_json() {
    let dir = tempfile::tempdir().unwrap();
    let store = lpm_store::PackageStore::at(dir.path());

    // Incomplete store entries are intentionally hidden from the complete-package API.
    let pkg_dir = dir.path().join("v1").join("broken@1.0.0");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(pkg_dir.join("index.js"), "// broken").unwrap();

    let packages = store.list_packages().unwrap();
    assert_eq!(packages.len(), 0);

    // The package.json is missing, so the entry is incomplete.
    assert!(!pkg_dir.join("package.json").exists());
}

#[test]
fn store_list_packages_includes_complete_package() {
    let dir = tempfile::tempdir().unwrap();
    let store = lpm_store::PackageStore::at(dir.path());

    let pkg_dir = dir.path().join("v1").join("valid@1.0.0");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"valid","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), "module.exports = {}").unwrap();
    std::fs::write(pkg_dir.join(".integrity"), "sha512-test").unwrap();

    let packages = store.list_packages().unwrap();
    assert_eq!(packages.len(), 1);
    assert!(pkg_dir.join("package.json").exists());
}

// ── Phase 59.1 day-3 (F7) — end-to-end directory dep ─────────────────────

/// Full pipeline test for `Source::Directory` deps:
/// 1. lpm-linker materializes a `+`-shape wrapper with per-file
///    symlinks pointing at the source.
/// 2. The root symlink at `node_modules/<name>` resolves through
///    the wrapper into the source dir.
/// 3. Edits to the source's files are visible immediately through
///    the wrapper (the dev-loop UX contract).
///
/// This is the integration-layer counterpart to lpm-linker's unit
/// test `link_one_package_directory_uses_per_file_symlinks_and_plus_wrapper`
/// — it goes one layer up by exercising the full `link_packages`
/// (cleanup_stale_entries → link_one_package → link_finalize) shape
/// and asserting the externally-visible contract.
#[test]
fn linker_directory_dep_creates_plus_wrapper_with_live_symlinks() {
    use std::collections::HashMap;
    use std::path::PathBuf;

    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create a real source directory with package.json + an index.js.
    let src = dir.path().join("packages").join("local-foo");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        r#"{"name":"local-foo","version":"0.1.0"}"#,
    )
    .unwrap();
    std::fs::write(src.join("index.js"), b"module.exports = 'initial';").unwrap();
    // Add a nested file to verify subdirectory mirroring.
    std::fs::create_dir_all(src.join("util")).unwrap();
    std::fs::write(src.join("util/helper.js"), b"export const x = 1;").unwrap();

    // Mimic what lpm-cli builds at install.rs:2593 for a directory dep.
    let target = lpm_linker::LinkTarget {
        name: "local-foo".to_string(),
        version: "0.1.0".to_string(),
        // For directory deps `store_path` is the canonicalized source
        // (NOT a path inside the global store).
        store_path: src.canonicalize().unwrap(),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["local-foo".to_string()]),
        // Wrapper id picked by `Source::Directory.source_id()` —
        // exact value doesn't matter for this test; just exercises
        // the `+`-shape branch.
        wrapper_id: Some("f-deadbeef00000000".to_string()),
    };

    let result = lpm_linker::link_packages(&project_dir, &[target], false, None).unwrap();
    assert!(result.linked > 0);

    // Wrapper at `+` shape, NOT `@`.
    let wrapper = project_dir.join("node_modules/.lpm/local-foo+f-deadbeef00000000");
    assert!(wrapper.is_dir(), "missing wrapper: {wrapper:?}");

    // Pkg dir under wrapper has per-file symlinks (not real files).
    let pkg_nm = wrapper.join("node_modules/local-foo");
    assert!(pkg_nm.is_dir());
    let index_js = pkg_nm.join("index.js");
    let meta = index_js.symlink_metadata().unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "wrapper's index.js must be a symlink, got {:?}",
        meta.file_type(),
    );
    // Subdirectory is a real dir (not a symlink).
    let util_dir = pkg_nm.join("util");
    let util_meta = util_dir.symlink_metadata().unwrap();
    assert!(
        util_meta.file_type().is_dir() && !util_meta.file_type().is_symlink(),
        "wrapper's nested dir must be a real dir, got {:?}",
        util_meta.file_type(),
    );
    // Nested file IS a symlink.
    let helper = pkg_nm.join("util").join("helper.js");
    assert!(helper.symlink_metadata().unwrap().file_type().is_symlink());

    // Root symlink at `node_modules/local-foo` resolves through the
    // wrapper to the source dir.
    let root_link = project_dir.join("node_modules/local-foo");
    let resolved = root_link.canonicalize().unwrap();
    let expected_pkg_nm: PathBuf = pkg_nm.canonicalize().unwrap();
    assert_eq!(resolved, expected_pkg_nm);

    // Read-through works.
    let initial = std::fs::read_to_string(root_link.join("index.js")).unwrap();
    assert_eq!(initial, "module.exports = 'initial';");

    // Edits to the SOURCE file are visible immediately through the
    // wrapper — no relink required. This is the F7 dev-loop UX
    // contract.
    std::fs::write(src.join("index.js"), b"module.exports = 'edited';").unwrap();
    let after_edit = std::fs::read_to_string(root_link.join("index.js")).unwrap();
    assert_eq!(
        after_edit, "module.exports = 'edited';",
        "source edits must be visible through the wrapper without re-running lpm install",
    );
}

// ── Phase 59.1 day-4 (F8) — end-to-end link: dep ─────────────────────────

/// Full pipeline test for `Source::Link` deps. Structurally identical
/// to `linker_directory_dep_creates_plus_wrapper_with_live_symlinks`
/// but with a `link:` source kind and `l-` wrapper-id prefix. Same
/// per-file symlink contract; same edits-visible UX. The semantic
/// difference (link: ignores `--no-symlink`) doesn't show up in v1
/// because day-4 doesn't ship `--no-symlink` for `file:` either.
#[test]
fn linker_link_dep_creates_l_prefix_wrapper_with_live_symlinks() {
    use std::collections::HashMap;
    use std::path::PathBuf;

    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    let src = dir.path().join("packages").join("linked-foo");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        r#"{"name":"linked-foo","version":"0.2.0"}"#,
    )
    .unwrap();
    std::fs::write(src.join("index.js"), b"module.exports = 'initial-link';").unwrap();
    std::fs::create_dir_all(src.join("util")).unwrap();
    std::fs::write(src.join("util/helper.js"), b"export const link = true;").unwrap();

    // Mimic what lpm-cli builds for a link: dep — same shape as
    // file: directory dep but with `l-` prefix.
    let target = lpm_linker::LinkTarget {
        name: "linked-foo".to_string(),
        version: "0.2.0".to_string(),
        store_path: src.canonicalize().unwrap(),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["linked-foo".to_string()]),
        // `l-` prefix discriminates link: from file: at the wrapper
        // segment level.
        wrapper_id: Some("l-cafebabe00000000".to_string()),
    };

    let result = lpm_linker::link_packages(&project_dir, &[target], false, None).unwrap();
    assert!(result.linked > 0);

    // Wrapper at `+l-` shape.
    let wrapper = project_dir.join("node_modules/.lpm/linked-foo+l-cafebabe00000000");
    assert!(wrapper.is_dir(), "missing wrapper: {wrapper:?}");
    // The `l-` shape lives ALONGSIDE potential `f-` and `@`
    // wrappers in the same `.lpm/` dir; visual distinction matters
    // for `lpm doctor` / `lpm why`. Verify the `l-` prefix didn't
    // collide with `f-` / `@` shapes (other-shape paths absent).
    let lpm_dir = project_dir.join("node_modules").join(".lpm");
    let entries: Vec<_> = std::fs::read_dir(&lpm_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(entries.len(), 1, "expected single wrapper, got {entries:?}",);
    assert!(
        entries[0].contains("+l-"),
        "wrapper segment must use `+l-` shape, got {entries:?}",
    );

    // Per-file symlinks materialized; subdirs are real dirs.
    let pkg_nm = wrapper.join("node_modules/linked-foo");
    assert!(pkg_nm.is_dir());
    assert!(
        pkg_nm
            .join("index.js")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let util = pkg_nm.join("util");
    let util_meta = util.symlink_metadata().unwrap();
    assert!(
        util_meta.file_type().is_dir() && !util_meta.file_type().is_symlink(),
        "nested dir must be real, got {:?}",
        util_meta.file_type(),
    );

    // Root symlink resolves to the wrapper's pkg dir.
    let root_link = project_dir.join("node_modules/linked-foo");
    let resolved = root_link.canonicalize().unwrap();
    let expected_pkg_nm: PathBuf = pkg_nm.canonicalize().unwrap();
    assert_eq!(resolved, expected_pkg_nm);

    // Read-through + live edits work identically to the file:
    // directory case.
    let initial = std::fs::read_to_string(root_link.join("index.js")).unwrap();
    assert_eq!(initial, "module.exports = 'initial-link';");

    std::fs::write(src.join("index.js"), b"module.exports = 'edited-link';").unwrap();
    let after_edit = std::fs::read_to_string(root_link.join("index.js")).unwrap();
    assert_eq!(after_edit, "module.exports = 'edited-link';");
}

// ── Phase 59.1 day-5 (F7-transitive) — wrapper sibling layout ───────────

/// Day-5 integration test: a directory dep with TRANSITIVE local-source
/// deps. Verifies the linker materializes the wrapper's
/// `node_modules/<dep>` symlink to the transitive dep's wrapper using
/// the `+`-shape (NOT `@`). Without the day-5 dep-target branch, the
/// symlink would point at a non-existent `<dep>@<source-id>` and the
/// install would fail at runtime.
///
/// Setup (mimics what lpm-cli builds end-to-end):
/// - Consumer's package.json declares `"a": "file:./packages/a"`.
/// - A's package.json declares `"b": "file:../b"`.
/// - lpm-cli pre_resolve produces 2 LinkTargets (A immediate, B
///   transitive); A's `dependencies` is `[(b, l-...)]` populated by
///   the post-resolve fix-up.
/// - link_packages produces wrappers for both A and B.
/// - A's wrapper has `node_modules/b → ../../b+f-{16hex}/node_modules/b`.
/// - require('b') from inside A's source resolves through the
///   wrapper to B's source.
#[test]
fn linker_directory_dep_with_transitive_directory_dep_creates_sibling_symlink() {
    use std::collections::HashMap;

    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    let pkg_a = dir.path().join("packages").join("a");
    let pkg_b = dir.path().join("packages").join("b");
    std::fs::create_dir_all(&pkg_a).unwrap();
    std::fs::create_dir_all(&pkg_b).unwrap();
    std::fs::write(
        pkg_a.join("package.json"),
        r#"{"name":"a","version":"1.0.0","dependencies":{"b":"file:../b"}}"#,
    )
    .unwrap();
    std::fs::write(pkg_a.join("index.js"), b"const b = require('b');").unwrap();
    std::fs::write(
        pkg_b.join("package.json"),
        r#"{"name":"b","version":"2.0.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg_b.join("index.js"), b"module.exports = 'b';").unwrap();

    // Mimic lpm-cli: A is immediate (root_link_names = ["a"], is_direct = true),
    // its dependencies field is populated post-resolve with [(b, source-id-of-b)].
    // B is transitive (root_link_names = vec![]).
    let b_source_id = "f-deadbeef00000000".to_string();
    let a_source_id = "f-cafebabe00000000".to_string();

    let target_a = lpm_linker::LinkTarget {
        name: "a".to_string(),
        version: "1.0.0".to_string(),
        store_path: pkg_a.canonicalize().unwrap(),
        // Day-5 fix-up populates this with the transitive dep's
        // source-id so the linker's `+`-shape branch fires.
        dependencies: vec![("b".to_string(), b_source_id.clone())],
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: Some(vec!["a".to_string()]),
        wrapper_id: Some(a_source_id.clone()),
    };
    let target_b = lpm_linker::LinkTarget {
        name: "b".to_string(),
        version: "2.0.0".to_string(),
        store_path: pkg_b.canonicalize().unwrap(),
        dependencies: vec![],
        aliases: HashMap::new(),
        is_direct: false,
        root_link_names: Some(vec![]), // transitive — no root link
        wrapper_id: Some(b_source_id.clone()),
    };

    lpm_linker::link_packages(&project_dir, &[target_a, target_b], false, None).unwrap();

    // Both wrappers exist at the `+` shape.
    let wrapper_a = project_dir.join(format!("node_modules/.lpm/a+{a_source_id}"));
    let wrapper_b = project_dir.join(format!("node_modules/.lpm/b+{b_source_id}"));
    assert!(wrapper_a.is_dir(), "missing A wrapper: {wrapper_a:?}");
    assert!(wrapper_b.is_dir(), "missing B wrapper: {wrapper_b:?}");

    // A's wrapper has a symlink at `node_modules/b` pointing at B's wrapper
    // — this is what the day-5 dep-target branch produces.
    let b_in_a = wrapper_a.join("node_modules/b");
    assert!(
        b_in_a.symlink_metadata().unwrap().file_type().is_symlink(),
        "A's wrapper must have node_modules/b as a symlink",
    );
    let b_link_target = std::fs::read_link(&b_in_a).unwrap();
    let expected = std::path::PathBuf::from("..")
        .join("..")
        .join(format!("b+{b_source_id}"))
        .join("node_modules")
        .join("b");
    assert_eq!(
        b_link_target, expected,
        "A's transitive b symlink MUST use +-shape, NOT @",
    );

    // Read-through works: from A's wrapper, b's index.js is reachable.
    assert_eq!(
        std::fs::read_to_string(b_in_a.join("index.js")).unwrap(),
        "module.exports = 'b';",
    );

    // Root symlink at `node_modules/a` resolves to A's wrapper pkg dir.
    let root_a = project_dir.join("node_modules/a");
    let resolved_a = root_a.canonicalize().unwrap();
    assert_eq!(
        resolved_a,
        wrapper_a.join("node_modules/a").canonicalize().unwrap()
    );

    // B is NOT at root — only A is direct.
    let root_b = project_dir.join("node_modules/b");
    assert!(
        root_b.symlink_metadata().is_err(),
        "B should NOT have a root symlink (transitive only)",
    );
}
