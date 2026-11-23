// ── install state (delegated to crate::install_state) ──

/// An install-hash file this release trusts: `hash`, the format of the
/// shims it links on Windows, and the schema of its store keys.
fn current_hash_file(hash: &str) -> String {
    format!(
        "{hash}\ns:{}\nk:{}\nr:{}\n",
        lpm_linker::BIN_SHIM_FORMAT,
        lpm_store::v2::GraphKey::SCHEMA_VERSION,
        lpm_security::INSTALL_SCRIPT_RULES
    )
}

/// Set up a tempdir that looks like a post-install project:
/// package.json, lpm.lock, node_modules/, .lpm/install-hash.
fn setup_installed_project(dir: &std::path::Path) {
    let pkg = r#"{"name":"test","dependencies":{"lodash":"^4.0.0"}}"#;

    std::fs::write(dir.join("package.json"), pkg).unwrap();
    lpm_lockfile::Lockfile::default()
        .write_all(&dir.join(lpm_lockfile::LOCKFILE_NAME))
        .unwrap();
    std::fs::create_dir_all(dir.join("node_modules")).unwrap();

    let lock = crate::commands::install::workspace_lockfile::active_lockfile_content(dir);
    let hash = crate::install_state::compute_install_hash(pkg, &lock);
    std::fs::create_dir_all(dir.join(".lpm")).unwrap();
    std::fs::write(
        dir.join(".lpm").join("install-hash"),
        current_hash_file(&hash),
    )
    .unwrap();
}

#[test]
fn fast_exit_when_everything_matches() {
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());

    assert!(
        crate::install_state::check_install_state(dir.path()).up_to_date,
        "should be up to date when hash matches and node_modules is clean"
    );
}

#[test]
fn fast_exit_allows_v2_compatibility_root() {
    let _env =
        crate::test_env::ScopedEnv::set([("LPM_STORE_VERSION", std::ffi::OsString::from("v2"))]);
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());
    std::fs::create_dir_all(
        dir.path()
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .join("eslint@9.39.4+51e8155e339ce359"),
    )
    .unwrap();
    let pkg = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
    let lock = crate::commands::install::workspace_lockfile::active_lockfile_content(dir.path());
    let hash = crate::install_state::compute_install_hash(&pkg, &lock);
    std::fs::write(
        dir.path().join(".lpm").join("install-hash"),
        current_hash_file(&hash),
    )
    .unwrap();

    assert!(
        crate::install_state::check_install_state(dir.path()).up_to_date,
        "virtual-store compatibility islands must not look like legacy v1 wrapper state"
    );
}

#[test]
fn fast_exit_fails_when_package_json_changed() {
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());

    // Simulate adding a new dependency
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"test","dependencies":{"lodash":"^4.0.0","express":"^4.0.0"}}"#,
    )
    .unwrap();

    assert!(
        !crate::install_state::check_install_state(dir.path()).up_to_date,
        "should NOT be up to date when package.json changed"
    );
}

#[test]
fn fast_exit_fails_when_lockfile_changed() {
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());

    // Simulate lockfile update
    lpm_lockfile::Lockfile::new_with_resolver("changed-test-resolver")
        .write_all(&dir.path().join(lpm_lockfile::LOCKFILE_NAME))
        .unwrap();

    assert!(
        !crate::install_state::check_install_state(dir.path()).up_to_date,
        "should NOT be up to date when lockfile changed"
    );
}

#[test]
fn fast_exit_fails_when_no_lockfile() {
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());
    std::fs::remove_file(dir.path().join("lpm.lock")).unwrap();

    assert!(
        !crate::install_state::check_install_state(dir.path()).up_to_date,
        "should NOT be up to date when lockfile is missing"
    );
}

#[test]
fn fast_exit_fails_when_no_node_modules() {
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());
    std::fs::remove_dir_all(dir.path().join("node_modules")).unwrap();

    assert!(
        !crate::install_state::check_install_state(dir.path()).up_to_date,
        "should NOT be up to date when node_modules is missing"
    );
}

#[test]
fn fast_exit_fails_when_no_hash_file() {
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());
    std::fs::remove_file(dir.path().join(".lpm").join("install-hash")).unwrap();

    assert!(
        !crate::install_state::check_install_state(dir.path()).up_to_date,
        "should NOT be up to date when install-hash is missing"
    );
}

#[test]
fn fast_exit_fails_when_node_modules_modified() {
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());

    // Touch node_modules AFTER the hash was written — simulates
    // external modification (user deleted a package folder, etc.)
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::create_dir_all(dir.path().join("node_modules").join("new-pkg")).unwrap();

    assert!(
        !crate::install_state::check_install_state(dir.path()).up_to_date,
        "should NOT be up to date when node_modules was modified after hash"
    );
}

#[test]
fn fast_exit_on_empty_project() {
    let dir = tempfile::tempdir().unwrap();
    // Completely empty directory — no package.json at all
    assert!(
        !crate::install_state::check_install_state(dir.path()).up_to_date,
        "should NOT be up to date on empty directory"
    );
}

#[test]
fn v1_local_sources_do_not_require_a_store_analysis_cache() {
    let dir = tempfile::tempdir().unwrap();
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path().join(".lpm-home"));
    let mut package = super::fake_pkg("local-package", "1.0.0", true);
    package.source = "directory+packages/local-package".to_string();

    assert!(super::super::state::source_analysis_caches_are_current(
        &lpm_root,
        dir.path(),
        &[package],
        lpm_store::StoreVersion::V1,
        lpm_store::SecurityAnalysisPolicy::Enabled,
    ));
}

#[test]
fn v2_local_source_requires_its_synthetic_object_analysis_cache() {
    let dir = tempfile::tempdir().unwrap();
    let source_dir = dir.path().join("packages").join("local-package");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::write(
        source_dir.join("package.json"),
        r#"{"name":"local-package","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(source_dir.join("index.js"), "eval('local')").unwrap();

    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path().join(".lpm-home"));
    let mut package = super::fake_pkg("local-package", "1.0.0", true);
    package.source = "directory+packages/local-package".to_string();
    let source_sri = super::super::local_source_sri(
        &package.name,
        &package.version,
        package.wrapper_id_for_source().as_deref(),
        &source_dir.canonicalize().unwrap(),
    );
    let store = lpm_store::v2::Store::from_lpm_root(&lpm_root);
    let object_dir = store
        .populate_object_from_local_source(&source_dir, &source_sri)
        .unwrap();

    assert!(super::super::state::source_analysis_caches_are_current(
        &lpm_root,
        dir.path(),
        std::slice::from_ref(&package),
        lpm_store::StoreVersion::V2,
        lpm_store::SecurityAnalysisPolicy::Enabled,
    ));

    std::fs::remove_file(object_dir.join(".lpm-security.json")).unwrap();
    assert!(!super::super::state::source_analysis_caches_are_current(
        &lpm_root,
        dir.path(),
        &[package],
        lpm_store::StoreVersion::V2,
        lpm_store::SecurityAnalysisPolicy::Enabled,
    ));
}

/// Verify that --force is defined as a CLI flag on the Install command.
/// This is a structural test — ensures the flag doesn't get accidentally removed.
#[test]
fn force_flag_defined_in_cli() {
    use clap::Parser;

    // Parse with --force — should succeed
    let result = crate::Cli::try_parse_from(["lpm", "install", "--force"]);
    assert!(
        result.is_ok(),
        "lpm install --force should be a valid command: {:?}",
        result.err()
    );
}

/// Verify that --force can be combined with other install flags.
#[test]
fn force_flag_combines_with_other_flags() {
    use clap::Parser;

    let result =
        crate::Cli::try_parse_from(["lpm", "install", "--force", "--offline", "--allow-new"]);
    assert!(
        result.is_ok(),
        "lpm install --force --offline --allow-new should parse: {:?}",
        result.err()
    );
}

/// Verify check_install_state returns up_to_date for a properly set up project,
/// confirming that --force's bypass of this check is meaningful.
#[test]
fn force_bypass_is_meaningful() {
    let dir = tempfile::tempdir().unwrap();
    setup_installed_project(dir.path());

    // Without --force, this returns true (fast exit)
    assert!(
        crate::install_state::check_install_state(dir.path()).up_to_date,
        "project should be up-to-date — --force bypasses this"
    );

    // With --force, the guard `!force && ... && install_state.up_to_date`
    // short-circuits, so the check result is ignored.
    // We can't test the full pipeline here (needs registry), but we
    // verify that the bypass target exists and returns true.
}

#[cfg(unix)]
#[test]
fn local_directories_named_in_other_bytes_have_their_own_identity() {
    use std::os::unix::ffi::OsStrExt as _;

    let identity = |name: &[u8]| {
        let directory = std::path::Path::new("/projects").join(std::ffi::OsStr::from_bytes(name));
        super::super::local_source_sri("local-package", "1.0.0", Some("f-source"), &directory)
    };

    assert_ne!(identity(b"shared-\xfe"), identity(b"shared-\xff"));
    let written: [&[u8]; 5] = [
        b"lpm-v2-local-source",
        b"local-package",
        b"1.0.0",
        b"f-source",
        b"/projects/shared",
    ];
    assert_eq!(
        identity(b"shared"),
        lpm_store::compute_sri_hash(&written.join(&0)),
    );
}

/// HOME and USERPROFILE moved to `home`, with npm's user and global config
/// paths inside it, so no `.npmrc` of the machine running the test is read.
fn npm_env_under(home: &std::path::Path) -> [(&'static str, Option<std::ffi::OsString>); 7] {
    [
        ("HOME", Some(home.as_os_str().to_owned())),
        ("USERPROFILE", Some(home.as_os_str().to_owned())),
        ("LPM_HOME", Some(home.join(".lpm").into_os_string())),
        (
            "NPM_CONFIG_USERCONFIG",
            Some(home.join(".npmrc").into_os_string()),
        ),
        (
            "NPM_CONFIG_GLOBALCONFIG",
            Some(home.join("global-npmrc").into_os_string()),
        ),
        ("npm_config_userconfig", None),
        ("npm_config_globalconfig", None),
    ]
}

/// A home whose `~/.npmrc` is `npmrc`, and the routes of a project in it.
fn routes_under_user_npmrc(
    npmrc: impl FnOnce(&std::path::Path) -> String,
) -> (
    tempfile::TempDir,
    crate::test_env::ScopedEnv,
    lpm_registry::RouteTable,
) {
    let home = tempfile::tempdir().unwrap();
    let env = crate::test_env::ScopedEnv::update(npm_env_under(home.path()));
    std::fs::write(home.path().join(".npmrc"), npmrc(home.path())).unwrap();
    let project = home.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let routes = lpm_registry::RouteTable::from_env_and_filesystem(&project).unwrap();
    (home, env, routes)
}

fn strict_ssl_warning_is_pending(routes: &lpm_registry::RouteTable) -> bool {
    let tagged = routes.tls_overrides().strict_ssl.as_ref().unwrap();
    crate::commands::registry_reads::first_npmrc_security_warning(
        &crate::commands::registry_reads::strict_ssl_warning_key(&tagged.source, tagged.line),
    )
}

#[tokio::test]
async fn an_up_to_date_install_that_sends_nothing_builds_no_client_and_warns_about_no_npmrc_setting()
 {
    let (_home, _env, routes) = routes_under_user_npmrc(|_| "strict-ssl=false\n".to_string());
    let base = lpm_registry::RegistryClient::new();
    let client = crate::commands::install::state::UpToDateRequestClient::new(&base, Some(&routes));

    let warnings =
        crate::commands::install::accounting::verify_lpm_install_access(&client, &[], true)
            .await
            .expect("an install without LPM.dev packages checks no access");
    crate::commands::install::accounting::report_pool_install_attribution(
        &client,
        &[],
        lpm_registry::ManagedInstallAccounting,
    )
    .await
    .expect("an install without packages reports no attribution");

    assert!(warnings.is_empty());
    assert!(strict_ssl_warning_is_pending(&routes));
}

#[tokio::test]
async fn the_up_to_date_paths_first_request_warns_and_reads_each_origins_tls_files_only_to_contact_it()
 {
    let (_home, _env, routes) = routes_under_user_npmrc(|home| {
        format!(
            "strict-ssl=false\n//lpm.dev/:cafile={}\n",
            home.join("missing-ca.pem").display()
        )
    });
    let base = lpm_registry::RegistryClient::new();
    let client = crate::commands::install::state::UpToDateRequestClient::new(&base, Some(&routes));

    let configured =
        crate::commands::install::accounting::InstallRequestClient::request_client(&client)
            .expect("a request that doesn't go to LPM.dev doesn't read its cafile");

    assert!(!strict_ssl_warning_is_pending(&routes));
    let error = configured
        .http()
        .for_url("https://lpm.dev/api/registry/@lpm.dev/acme.kit")
        .await
        .expect_err("contacting LPM.dev reads its cafile");
    assert!(error.to_string().contains("missing-ca.pem"), "{error}");
}

/// A project `lpm install` would leave behind with `lpm.lock` rooting `leaf`
/// at `root_version` while `package.json` asks for `leaf@1.0.0`, and the
/// install hash an install writes for exactly these files.
fn installed_project_rooting_leaf_at(dir: &std::path::Path, root_version: &str) {
    installed_project(
        dir,
        r#"{"name":"consumer","dependencies":{"leaf":"1.0.0"}}"#,
        root_version,
        lpm_lockfile::CatalogSnapshots::new(),
    );
}

/// [`installed_project_rooting_leaf_at`] with `pkg` as `package.json` and
/// `catalogs` as the lockfile's catalog snapshot.
fn installed_project(
    dir: &std::path::Path,
    pkg: &str,
    root_version: &str,
    catalogs: lpm_lockfile::CatalogSnapshots,
) {
    let source = "registry+https://registry.npmjs.org";
    let instance_id =
        lpm_common::PackageInstanceId::derive("leaf", root_version, source, "root/leaf");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: "leaf".to_string(),
        version: root_version.to_string(),
        source: Some(source.to_string()),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "leaf".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance_id),
            package: "leaf".to_string(),
            version: root_version.to_string(),
            source: Some(source.to_string()),
        },
    );
    lockfile.catalogs = catalogs;
    installed_project_locked_as(dir, pkg, &lockfile);
}

/// A project installed from `pkg` and `lockfile`, with a matching install
/// hash.
fn installed_project_locked_as(
    dir: &std::path::Path,
    pkg: &str,
    lockfile: &lpm_lockfile::Lockfile,
) {
    std::fs::write(dir.join("package.json"), pkg).unwrap();
    lockfile
        .write_all(&dir.join(lpm_lockfile::LOCKFILE_NAME))
        .unwrap();
    std::fs::create_dir_all(dir.join("node_modules")).unwrap();

    let global = crate::commands::config::GlobalConfig::load_checked().unwrap();
    let linker =
        crate::linker_config::resolve_effective_linker_from_bytes(None, pkg, &global, dir).unwrap();
    let integrity = crate::commands::config::resolve_object_integrity_policy(&global).unwrap();
    let lock = crate::commands::install::workspace_lockfile::active_lockfile_snapshot(dir);
    crate::commands::install::state::write_post_install_hash_with_context(
        dir,
        linker,
        integrity,
        lpm_store::SecurityAnalysisPolicy::Disabled,
        "none",
        None,
        &lock,
    )
    .unwrap();
}

#[test]
fn the_up_to_date_check_refuses_a_lockfile_whose_roots_miss_the_manifest() {
    let home = tempfile::tempdir().unwrap();
    let _env = crate::test_env::ScopedEnv::update(npm_env_under(home.path()).into_iter().chain([
        ("LPM_LINKER", None),
        (lpm_store::StoreVersion::ENV_VAR, None),
        (lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None),
    ]));
    let mode = crate::install_state::FastLaneMode {
        json: true,
        timing: false,
        frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
        no_skills: true,
        min_release_age: None,
        min_release_age_exclude: Vec::new(),
    };

    for (root_version, up_to_date) in [("1.0.0", true), ("2.0.0", false)] {
        let project = tempfile::tempdir().unwrap();
        installed_project_rooting_leaf_at(project.path(), root_version);
        let pkg = std::fs::read_to_string(project.path().join("package.json")).unwrap();

        assert_eq!(
            crate::commands::install::sync_noop::is_up_to_date(project.path(), &pkg, &mode)
                .unwrap(),
            up_to_date,
            "leaf rooted at {root_version} for a manifest asking for 1.0.0"
        );
    }
}

#[test]
fn the_up_to_date_check_compares_catalog_dependencies_with_the_lockfiles_catalog_snapshot() {
    let home = tempfile::tempdir().unwrap();
    let _env = crate::test_env::ScopedEnv::update(npm_env_under(home.path()).into_iter().chain([
        ("LPM_LINKER", None),
        (lpm_store::StoreVersion::ENV_VAR, None),
        (lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None),
    ]));
    let mode = crate::install_state::FastLaneMode {
        json: true,
        timing: false,
        frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
        no_skills: true,
        min_release_age: None,
        min_release_age_exclude: Vec::new(),
    };
    let snapshot = |specifier: &str, version: &str| {
        lpm_lockfile::CatalogSnapshots::from([(
            "default".to_string(),
            std::collections::BTreeMap::from([(
                "leaf".to_string(),
                lpm_lockfile::CatalogSnapshotEntry {
                    specifier: specifier.to_string(),
                    version: version.to_string(),
                    reference: "catalog:".to_string(),
                },
            )]),
        )])
    };
    let required = r#"{"name":"consumer","catalogs":{"default":{"leaf":"1.0.0"}},"dependencies":{"leaf":"catalog:"}}"#;
    let optional = r#"{"name":"consumer","catalogs":{"default":{"leaf":"1.0.0"}},"optionalDependencies":{"leaf":"catalog:"}}"#;
    let cases = [
        (
            "a matching snapshot",
            required,
            snapshot("1.0.0", "1.0.0"),
            true,
        ),
        (
            "a matching snapshot for an optional dependency",
            optional,
            snapshot("1.0.0", "1.0.0"),
            true,
        ),
        (
            "a snapshot of an older catalog entry",
            required,
            snapshot("^0.9.0", "1.0.0"),
            false,
        ),
        (
            "a snapshot naming another version than the locked root",
            required,
            snapshot("1.0.0", "1.0.1"),
            false,
        ),
        (
            "no snapshot for an installed optional dependency",
            optional,
            lpm_lockfile::CatalogSnapshots::new(),
            false,
        ),
        (
            "a reference to a catalog the manifest doesn't define",
            r#"{"name":"consumer","catalogs":{"default":{"leaf":"1.0.0"}},"dependencies":{"leaf":"catalog:testing"}}"#,
            snapshot("1.0.0", "1.0.0"),
            false,
        ),
    ];

    for (case, pkg, catalogs, up_to_date) in cases {
        let project = tempfile::tempdir().unwrap();
        installed_project(project.path(), pkg, "1.0.0", catalogs);

        assert_eq!(
            crate::commands::install::sync_noop::is_up_to_date(project.path(), pkg, &mode).unwrap(),
            up_to_date,
            "{case}"
        );
    }
}

#[test]
fn the_up_to_date_check_accepts_a_catalog_override_of_a_transitive_dependency() {
    let home = tempfile::tempdir().unwrap();
    let _env = crate::test_env::ScopedEnv::update(npm_env_under(home.path()).into_iter().chain([
        ("LPM_LINKER", None),
        (lpm_store::StoreVersion::ENV_VAR, None),
        (lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None),
    ]));
    let mode = crate::install_state::FastLaneMode {
        json: true,
        timing: false,
        frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
        no_skills: true,
        min_release_age: None,
        min_release_age_exclude: Vec::new(),
    };
    let source = "registry+https://registry.npmjs.org";
    let locked = |name: &str, path: &str| lpm_lockfile::LockedPackage {
        instance_id: Some(lpm_common::PackageInstanceId::derive(
            name, "1.0.0", source, path,
        )),
        name: name.to_string(),
        version: "1.0.0".to_string(),
        source: Some(source.to_string()),
        ..Default::default()
    };
    let mut lockfile = lpm_lockfile::Lockfile::new();
    let leaf = locked("leaf", "root/parent/leaf");
    let mut parent = locked("parent", "root/parent");
    parent.dependencies = vec!["leaf@1.0.0".to_string()];
    parent.dependency_targets =
        std::collections::BTreeMap::from([("leaf".to_string(), leaf.instance_id.unwrap())]);
    lockfile.root_resolutions.insert(
        "parent".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: parent.instance_id,
            package: "parent".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
        },
    );
    lockfile.add_package(parent);
    lockfile.add_package(leaf);
    lockfile.catalogs.insert(
        "default".to_string(),
        std::collections::BTreeMap::from([(
            "leaf".to_string(),
            lpm_lockfile::CatalogSnapshotEntry {
                specifier: "1.0.0".to_string(),
                version: "1.0.0".to_string(),
                reference: "catalog:".to_string(),
            },
        )]),
    );
    let pkg = r#"{"name":"consumer","catalogs":{"default":{"leaf":"1.0.0"}},"dependencies":{"parent":"1.0.0"},"overrides":{"leaf":"catalog:"}}"#;
    let project = tempfile::tempdir().unwrap();
    installed_project_locked_as(project.path(), pkg, &lockfile);

    assert!(
        crate::commands::install::sync_noop::is_up_to_date(project.path(), pkg, &mode).unwrap()
    );
}

#[test]
fn the_up_to_date_check_accepts_an_unapplied_catalog_override_of_a_direct_dependency() {
    let home = tempfile::tempdir().unwrap();
    let _env = crate::test_env::ScopedEnv::update(npm_env_under(home.path()).into_iter().chain([
        ("LPM_LINKER", None),
        (lpm_store::StoreVersion::ENV_VAR, None),
        (lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None),
    ]));
    let mode = crate::install_state::FastLaneMode {
        json: true,
        timing: false,
        frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
        no_skills: true,
        min_release_age: None,
        min_release_age_exclude: Vec::new(),
    };
    // The override doesn't change what the dependency's range selects, so
    // the lockfile records no snapshot for it.
    let pkg = r#"{"name":"consumer","catalogs":{"default":{"leaf":"1.0.0"}},"dependencies":{"leaf":"^1.0.0"},"overrides":{"leaf":"catalog:"}}"#;
    let project = tempfile::tempdir().unwrap();
    installed_project(
        project.path(),
        pkg,
        "1.0.0",
        lpm_lockfile::CatalogSnapshots::new(),
    );

    assert!(
        crate::commands::install::sync_noop::is_up_to_date(project.path(), pkg, &mode).unwrap()
    );
}

#[test]
fn sync_noop_bails_out_when_global_config_enables_strict_release_age() {
    let home = tempfile::tempdir().unwrap();
    let _env = crate::test_env::ScopedEnv::update(npm_env_under(home.path()).into_iter().chain([
        ("LPM_LINKER", None),
        (lpm_store::StoreVersion::ENV_VAR, None),
        (lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None),
    ]));
    let mode = crate::install_state::FastLaneMode {
        json: true,
        timing: false,
        frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
        no_skills: true,
        min_release_age: None,
        min_release_age_exclude: Vec::new(),
    };
    let pkg = r#"{"name":"consumer","dependencies":{"leaf":"^1.0.0"}}"#;
    let project = tempfile::tempdir().unwrap();
    installed_project(
        project.path(),
        pkg,
        "1.0.0",
        lpm_lockfile::CatalogSnapshots::new(),
    );

    assert!(
        crate::commands::install::sync_noop::is_up_to_date(project.path(), pkg, &mode).unwrap()
    );

    let lpm_dir = home.path().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(
        lpm_dir.join("config.toml"),
        "minimum-release-age-secs = 604800\nrelease-age-policy = \"strict\"\n",
    )
    .unwrap();
    assert!(
        !crate::commands::install::sync_noop::is_up_to_date(project.path(), pkg, &mode).unwrap(),
        "enabling strict minimum-release-age must force lockfile revalidation"
    );

    // Once `.lpm/install-hash` records the verified strict release-age key,
    // matching invocations fast-exit while tighter CLI windows re-enter the pipeline.
    let verified_key = crate::install_state::release_age_freshness_key(
        604_800,
        crate::release_age_config::ReleaseAgePolicy::Strict,
        &[],
        false,
    )
    .unwrap();
    let hash_path = project.path().join(".lpm/install-hash");
    let mut hash_state = std::fs::read_to_string(&hash_path).unwrap();
    hash_state.push_str(&format!("g:{verified_key}\n"));
    std::fs::write(&hash_path, hash_state).unwrap();

    assert!(
        crate::commands::install::sync_noop::is_up_to_date(project.path(), pkg, &mode).unwrap(),
        "verified strict release-age policy should allow sync no-op"
    );
    let cli_same = crate::install_state::FastLaneMode {
        min_release_age: Some("7d".to_string()),
        ..mode.clone()
    };
    assert!(
        crate::commands::install::sync_noop::is_up_to_date(project.path(), pkg, &cli_same).unwrap(),
        "matching CLI --min-release-age=7d should stay on the sync no-op fast lane"
    );
    let cli_tighter = crate::install_state::FastLaneMode {
        min_release_age: Some("30d".to_string()),
        ..mode
    };
    assert!(
        !crate::commands::install::sync_noop::is_up_to_date(project.path(), pkg, &cli_tighter)
            .unwrap(),
        "tightening --min-release-age via CLI must invalidate the sync no-op fast lane"
    );
}
