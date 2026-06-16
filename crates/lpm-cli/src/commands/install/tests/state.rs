// ── install state (delegated to crate::install_state) ──

/// Set up a tempdir that looks like a post-install project:
/// package.json, lpm.lock, node_modules/, .lpm/install-hash.
fn setup_installed_project(dir: &std::path::Path) {
    let pkg = r#"{"name":"test","dependencies":{"lodash":"^4.0.0"}}"#;
    let lock = "[packages]\nname = \"lodash\"\nversion = \"4.17.21\"\n";

    std::fs::write(dir.join("package.json"), pkg).unwrap();
    std::fs::write(dir.join("lpm.lock"), lock).unwrap();
    std::fs::create_dir_all(dir.join("node_modules")).unwrap();

    let hash = crate::install_state::compute_install_hash(pkg, lock);
    std::fs::create_dir_all(dir.join(".lpm")).unwrap();
    std::fs::write(dir.join(".lpm").join("install-hash"), &hash).unwrap();
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
    let lock = std::fs::read_to_string(dir.path().join("lpm.lock")).unwrap();
    let hash = crate::install_state::compute_install_hash(&pkg, &lock);
    std::fs::write(dir.path().join(".lpm").join("install-hash"), hash).unwrap();

    assert!(
        crate::install_state::check_install_state(dir.path()).up_to_date,
        "v2 compatibility islands must not look like legacy v1 wrapper state"
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
    std::fs::write(
        dir.path().join("lpm.lock"),
        "[packages]\nname = \"lodash\"\nversion = \"4.17.22\"\n",
    )
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
