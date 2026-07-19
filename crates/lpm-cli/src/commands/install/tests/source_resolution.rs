use super::*;

// ── local-tarball path traversal ─────────────

/// The classic exploit shape: a manifest entry like
/// `"foo": "file:../../../etc/passwd.tgz"` would, previously, resolve
/// against `project_dir` and read whatever lives at the resolved
/// path into the LPM CAS. Rejecting `..` components at the
/// manifest boundary closes that door without touching the legit
/// `file:./local.tgz` / `file:/abs/path.tgz` shapes.
#[test]
fn validate_local_tarball_raw_path_rejects_parent_dir_components() {
    for path in [
        "../escape.tgz",
        "../../escape.tgz",
        "subdir/../../../escape.tgz",
        "./../escape.tgz",
    ] {
        let err = validate_local_tarball_raw_path(path)
            .err()
            .unwrap_or_else(|| panic!("expected reject for {path}"));
        assert!(err.contains("`..`"), "path {path:?} got: {err}");
    }
}

#[test]
fn validate_local_tarball_raw_path_accepts_relative_within_project() {
    for path in [
        "local.tgz",
        "./local.tgz",
        "subdir/local.tgz",
        "./subdir/nested/local.tgz",
    ] {
        assert!(
            validate_local_tarball_raw_path(path).is_ok(),
            "path {path:?} must be accepted"
        );
    }
}

#[test]
fn validate_local_tarball_raw_path_accepts_absolute_paths() {
    // Absolute paths are an explicit user choice (shared CI cache,
    // CI artifact dir, etc.). The traversal-surprise risk only
    // applies when the manifest *appears* to stay relative but
    // sneaks out via `..`.
    for path in ["/tmp/local.tgz", "/var/cache/lpm/foo.tgz"] {
        assert!(
            validate_local_tarball_raw_path(path).is_ok(),
            "absolute path {path:?} must be accepted"
        );
    }
}

// ── migration tests ───────────────────────────

#[test]
fn needs_v2_migration_detects_legacy_isolated_wrappers() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".lpm/wrappers/express@4.21.0")).unwrap();
    assert!(needs_v2_migration(dir.path()));
}

#[test]
fn needs_v2_migration_detects_legacy_hoisted_metadata() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".lpm/hoisted")).unwrap();
    std::fs::write(dir.path().join(".lpm/hoisted/metadata.json"), b"{}").unwrap();
    assert!(needs_v2_migration(dir.path()));
}

#[test]
fn needs_v2_migration_returns_false_on_clean_v2_or_fresh_project() {
    let dir = tempfile::tempdir().unwrap();
    // Fresh project (no .lpm at all) — must NOT trigger migration.
    assert!(!needs_v2_migration(dir.path()));

    // Clean v2 install: project node_modules has symlinks but no
    // legacy `.lpm/wrappers/` or `.lpm/hoisted/`.
    std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
    std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
    std::fs::write(dir.path().join(".lpm/install-hash"), b"hash").unwrap();
    assert!(
        !needs_v2_migration(dir.path()),
        "v2 install with no legacy markers must not request migration"
    );
}

#[test]
fn migrate_v1_to_v2_wipes_all_required_paths() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();

    // Synthesize a fully-populated v1 isolated install.
    let wrappers = project.join(".lpm/wrappers/express@4.21.0/node_modules/express");
    std::fs::create_dir_all(&wrappers).unwrap();
    std::fs::write(wrappers.join("package.json"), b"{}").unwrap();
    std::fs::write(project.join(".lpm/install-hash"), b"deadbeef").unwrap();
    let nm = project.join("node_modules");
    std::fs::create_dir_all(nm.join(".bin")).unwrap();
    std::fs::write(nm.join(".bin/some-shim"), b"#!/bin/sh").unwrap();
    std::fs::create_dir_all(nm.join("express")).unwrap();
    // Also a hoisted-mode sidecar to verify both legacy roots are wiped.
    std::fs::create_dir_all(project.join(".lpm/hoisted")).unwrap();
    std::fs::write(project.join(".lpm/hoisted/metadata.json"), b"{}").unwrap();

    migrate_v1_to_v2(project).unwrap();

    assert!(!project.join(".lpm/wrappers").exists());
    assert!(!project.join(".lpm/hoisted").exists());
    assert!(!project.join("node_modules").exists());
    assert!(!project.join(".lpm/install-hash").exists());
    // Project root + .lpm dir itself survive — only the legacy
    // children get wiped, so other lpm sidecars (build-state,
    // trust-snapshot) aren't accidentally collateral.
    assert!(project.exists());
    assert!(project.join(".lpm").exists());
}

#[test]
fn migrate_v1_to_v2_is_idempotent_on_clean_state() {
    let dir = tempfile::tempdir().unwrap();
    // No legacy state at all — migration must succeed as a no-op.
    migrate_v1_to_v2(dir.path()).unwrap();
    // Second call also a no-op.
    migrate_v1_to_v2(dir.path()).unwrap();
}

#[test]
fn migrate_v1_to_v2_preserves_project_lpm_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();

    // build-state and trust-snapshot live alongside install-hash
    // but persist across installs (they encode user-approved
    // policy); migration must NOT wipe them.
    std::fs::create_dir_all(project.join(".lpm")).unwrap();
    std::fs::write(project.join(".lpm/build-state.json"), b"{}").unwrap();
    std::fs::write(project.join(".lpm/trust-snapshot.json"), b"{}").unwrap();
    std::fs::create_dir_all(project.join(".lpm/wrappers")).unwrap();

    migrate_v1_to_v2(project).unwrap();

    assert!(project.join(".lpm/build-state.json").exists());
    assert!(project.join(".lpm/trust-snapshot.json").exists());
    assert!(!project.join(".lpm/wrappers").exists());
}

// ── pre_resolve_non_registry_deps ───────────────
// End-to-end test of the manifest-side wiring: a manifest dep map
// containing a tarball-URL spec is correctly extracted, downloaded,
// and converted into an InstallPackage with the right source +
// identity fields.

#[tokio::test]
async fn pre_resolve_extracts_tarball_url_deps_from_manifest() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = build_test_tarball();
    let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();

    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());

    let mut deps = HashMap::from([
        // Registry-style — must be left alone.
        ("react".to_string(), "^19.0.0".to_string()),
        // Tarball-URL — must be extracted.
        ("foo".to_string(), url.clone()),
    ]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        store_root.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("pre_resolve must succeed")
    .install_pkgs;

    // Registry dep stays in `deps`; tarball dep is removed.
    assert_eq!(deps.len(), 1);
    assert!(deps.contains_key("react"));
    assert!(!deps.contains_key("foo"));

    // One InstallPackage produced for the tarball dep.
    assert_eq!(install_pkgs.len(), 1);
    let pkg = &install_pkgs[0];
    // Real (name, version) read from the tarball's package.json.
    assert_eq!(pkg.name, "test-tarball-pkg");
    assert_eq!(pkg.version, "1.0.0");
    // Source records the URL identity.
    assert_eq!(pkg.source, format!("tarball+{url}"));
    // Integrity is the computed SRI.
    assert_eq!(pkg.integrity.as_deref(), Some(expected_sri.as_str()));
    // tarball_url carries the URL for fetch_and_store_tarball_url.
    assert_eq!(pkg.tarball_url.as_deref(), Some(url.as_str()));
    // root_link_names uses the manifest dep KEY ("foo"), NOT the
    // package's declared name ("test-tarball-pkg"). This is what
    // makes node_modules/foo/ link to the package.
    assert_eq!(
        pkg.root_link_names.as_deref(),
        Some(["foo".to_string()].as_slice())
    );
    assert!(pkg.is_direct);
    assert!(!pkg.is_lpm);
    // 59.0 limitation: tarball-URL deps are leaves.
    assert!(pkg.dependencies.is_empty());
    assert!(pkg.aliases.is_empty());

    // Tarball is materialized in the integrity-keyed CAS.
    assert!(store.has_tarball(&expected_sri));
}

#[tokio::test]
async fn pre_resolve_preserves_declared_sha256_integrity() {
    // A non-SHA-512 SRI declared in the dependency specifier flows through
    // verification, CAS storage, and InstallPackage identity unchanged.
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = build_test_tarball();
    let correct_sri = Integrity::from_bytes(HashAlgorithm::Sha256, &body).to_string();

    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());

    // Spec with #sha256-… integrity — Specifier::parse picks it up.
    let mut deps = HashMap::from([("foo".to_string(), format!("{url}#{correct_sri}"))]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        store_root.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("matching declared integrity must succeed")
    .install_pkgs;
    assert_eq!(install_pkgs.len(), 1);
    assert_eq!(
        install_pkgs[0].integrity.as_deref(),
        Some(correct_sri.as_str())
    );
    let stored = store.tarball_store_path(&correct_sri).unwrap();
    assert_eq!(
        lpm_store::read_stored_integrity(&stored).as_deref(),
        Some(correct_sri.as_str())
    );
}

#[tokio::test]
async fn pre_resolve_no_op_when_no_tarball_url_deps() {
    // When the dep map is registry-only, pre_resolve is a no-op:
    // returns empty Vec, doesn't touch deps, doesn't hit network.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());

    let mut deps = HashMap::from([
        ("react".to_string(), "^19.0.0".to_string()),
        ("lodash".to_string(), "*".to_string()),
    ]);
    let original_deps = deps.clone();

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        store_root.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("no-op call must succeed")
    .install_pkgs;
    assert!(install_pkgs.is_empty());
    assert_eq!(deps, original_deps);
}

// ── (): --strict-integrity ──────────────────────────

#[tokio::test]
async fn pre_resolve_strict_integrity_rejects_undeclared_sri() {
    // CI-recommended posture: tarball URL with NO inline SRI
    // declaration is rejected with a clear actionable error,
    // rather than silently trusting the first response.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());

    // No #sha512-... suffix, no integrity in spec.
    let mut deps = HashMap::from([("foo".to_string(), "https://example.com/foo.tgz".to_string())]);

    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        store_root.path(),
        &mut deps,
        true,
        true,
        &[],
    )
    .await;
    match result {
        Err(LpmError::Registry(msg)) => {
            assert!(
                msg.contains("strict-integrity"),
                "error must mention --strict-integrity: {msg}"
            );
            assert!(
                msg.contains("foo"),
                "error must name the offending dep: {msg}"
            );
            assert!(
                msg.contains("sha512") || msg.contains("sha256"),
                "error must point at the fix (declare an SRI): {msg}"
            );
        }
        other => panic!("expected Registry error, got {other:?}"),
    }
    // Dep was REMOVED from `deps` before strict-integrity fired
    // (Specifier::parse classified it). The error short-circuits
    // before the install proceeds — install must abort.
    assert!(!deps.contains_key("foo"));
}

#[tokio::test]
async fn pre_resolve_strict_integrity_accepts_declared_sri() {
    // Same posture, but the spec DECLARES an SRI inline:
    // `https://e.com/foo.tgz#sha512-…`. Strict-integrity passes.
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = build_test_tarball();
    let sri = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();

    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());

    // SRI declared inline — strict mode is happy.
    let mut deps = HashMap::from([("foo".to_string(), format!("{url}#{sri}"))]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        store_root.path(),
        &mut deps,
        true,
        true,
        &[],
    )
    .await
    .expect("strict-integrity with declared SRI must succeed")
    .install_pkgs;
    assert_eq!(install_pkgs.len(), 1);
    assert_eq!(install_pkgs[0].integrity.as_deref(), Some(sri.as_str()));
}

// ── (reviewed): unsupported Specifier variants ────────────
// Git/File/Link specifiers parse cleanly but the install pipeline
// doesn't support them in 59.0. Pre-resolve must surface a clear,
// actionable error at the manifest boundary instead of letting the
// dep fall through to the resolver and produce an opaque
// node_semver parse error.

#[tokio::test]
async fn pre_resolve_rejects_git_specifier_with_clear_error() {
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());

    let mut deps = HashMap::from([(
        "my-fork".to_string(),
        "git+https://github.com/foo/bar.git".to_string(),
    )]);
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        store_root.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect_err("git specifier must be rejected at pre-resolve");
    let msg = err.to_string();
    assert!(
        msg.contains("my-fork"),
        "error must name the dep, got: {msg}"
    );
    assert!(
        msg.contains("git") && msg.contains("not yet supported"),
        "error must explain the limitation, got: {msg}"
    );
    assert!(
        msg.contains("Workaround"),
        "error must offer a workaround, got: {msg}"
    );
}

#[tokio::test]
async fn pre_resolve_rejects_github_shorthand_via_git_arm() {
    // `github:user/repo` expands to a Git Specifier — same arm.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());

    let mut deps = HashMap::from([("forked".to_string(), "github:foo/bar".to_string())]);
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        store_root.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect_err("github: shorthand must be rejected at pre-resolve");
    assert!(err.to_string().contains("forked"));
}

// ── (): directory-dep happy paths ──────────────────

#[tokio::test]
async fn pre_resolve_extracts_directory_dep_from_file_specifier() {
    // Round-trip: a `file:./packages/foo` directory dep produces
    // an InstallPackage with the right shape — `directory+<path>`
    // source, `integrity: None`, `tarball_url: None`, name/version
    // read from the source's package.json, dep KEY in
    // root_link_names.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    // Create a real source directory.
    let src = project_dir.path().join("packages").join("local-thing");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"local-thing","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(src.join("index.js"), b"module.exports = 1").unwrap();

    let mut deps = HashMap::from([
        ("react".to_string(), "^19.0.0".to_string()),
        (
            "local".to_string(),
            "file:./packages/local-thing".to_string(),
        ),
    ]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("directory-dep pre_resolve must succeed")
    .install_pkgs;

    // Registry dep stays in `deps`; directory dep is removed.
    assert_eq!(deps.len(), 1);
    assert!(deps.contains_key("react"));
    assert!(!deps.contains_key("local"));

    assert_eq!(install_pkgs.len(), 1);
    let p = &install_pkgs[0];
    assert_eq!(p.name, "local-thing");
    assert_eq!(p.version, "1.0.0");
    // Wire-format source preserves the user-typed RELATIVE path.
    assert_eq!(p.source, "directory+./packages/local-thing");
    // No integrity (mutable content) and no tarball_url.
    assert!(p.integrity.is_none());
    assert!(p.tarball_url.is_none());
    // Dep KEY for root_link_names (umbrella
    // fetched-name policy).
    assert_eq!(
        p.root_link_names.as_deref(),
        Some(["local".to_string()].as_slice()),
    );
    assert!(p.is_direct);
    // limitation: transitive deps not yet wired (-
    // transitive lands day 4).
    assert!(p.dependencies.is_empty());
}

#[tokio::test]
async fn pre_resolve_rejects_file_directory_without_package_json() {
    // A `file:` directory that lacks `package.json` is unusable —
    // the pre_resolve directory arm reads `package.json` to learn
    // (name, version), so a missing manifest must surface a clear
    // error rather than crashing inside the JSON parser.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    // Directory exists but has no package.json.
    let src = project_dir.path().join("packages").join("no-manifest");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("README.md"), b"no manifest here").unwrap();

    let mut deps = HashMap::from([(
        "broken".to_string(),
        "file:./packages/no-manifest".to_string(),
    )]);
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect_err("missing package.json must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("package.json") || msg.contains("read"),
        "got: {msg}",
    );
}

#[tokio::test]
async fn pre_resolve_directory_dep_warns_on_top_level_node_modules() {
    // ( partial; full policy ): when the source
    // dir has a top-level node_modules/, emit a warn-once. 's
    // `materialize_directory_source` already excludes node_modules
    // at materialization time; this warn just tells the user
    // their host state is being ignored.
    //
    // Test verifies the function still SUCCEEDS — the warn is
    // informational, not a hard error.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("with-deps");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"with-deps","version":"0.1.0"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(src.join("node_modules").join("hidden")).unwrap();

    let mut deps = HashMap::from([("foo".to_string(), "file:./with-deps".to_string())]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true, // json_output suppresses output::warn but the success path holds
        false,
        &[],
    )
    .await
    .expect("directory dep with node_modules must still succeed")
    .install_pkgs;
    assert_eq!(install_pkgs.len(), 1);
}

#[tokio::test]
async fn pre_resolve_directory_dep_renamed_via_dep_key() {
    // umbrella
    // package.json `name` controls store identity. A renamed dep
    // (`"my-alias": "file:./packages/foo"` where foo's
    // package.json says name "foo") still works.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("packages").join("foo");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"foo","version":"2.0.0"}"#,
    )
    .unwrap();

    let mut deps = HashMap::from([("my-alias".to_string(), "file:./packages/foo".to_string())]);
    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("renamed directory dep must succeed")
    .install_pkgs;
    assert_eq!(install_pkgs.len(), 1);
    let p = &install_pkgs[0];
    assert_eq!(p.name, "foo"); // identity = real package name
    assert_eq!(
        p.root_link_names.as_deref(),
        Some(["my-alias".to_string()].as_slice()),
    );
}

#[tokio::test]
async fn pre_resolve_directory_dep_wrapper_id_is_source_id() {
    // The contract: InstallPackage::wrapper_id_for_source()
    // returns Some for a directory dep, matching
    // `Source::Directory { path }.source_id()` for the
    // user-typed relative path. This is what the linker's
    // `wrapper_id` ends up holding.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("local");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"local","version":"0.1.0"}"#,
    )
    .unwrap();

    let raw_path = "./local";
    let mut deps = HashMap::from([("local".to_string(), format!("file:{raw_path}"))]);
    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap()
    .install_pkgs;
    assert_eq!(install_pkgs.len(), 1);
    let p = &install_pkgs[0];
    let expected = lpm_lockfile::Source::Directory {
        path: raw_path.to_string(),
    }
    .source_id();
    assert_eq!(
        p.wrapper_id_for_source(),
        Some(expected.clone()),
        "wrapper_id_for_source must match Source::Directory.source_id()",
    );
    // Sanity: shape is `f-{16hex}`.
    assert!(
        expected.starts_with("f-") && expected.len() == 18,
        "got: {expected:?}",
    );
}

/// every non-Registry
/// source produces a non-None `wrapper_id`, and `materialization_for_source`
/// picks `DirectorySource` only for `Source::Directory` / `Source::Link`.
/// Tarballs need wrapper ids so registry `foo@1.0.0` and tarball
/// `foo@1.0.0` cannot collide at the same `.lpm/foo@1.0.0/`
/// wrapper segment.
#[test]
fn wrapper_id_and_materialization_helpers_cover_every_source_kind() {
    // Each test case constructs a minimal InstallPackage with the
    // given `source` field (parsed by `source_kind()`) and asserts
    // both helper outputs.
    let cases: &[(&str, Option<&str>, lpm_linker::Materialization)] = &[
        // Registry: legacy "no wrapper id" shape, CAS-backed.
        (
            "registry+https://registry.npmjs.org/",
            None,
            lpm_linker::Materialization::CasBacked,
        ),
        // Tarball remote: current wrapper id, still CAS-backed.
        (
            "tarball+https://example.com/foo.tgz",
            Some("t-"),
            lpm_linker::Materialization::CasBacked,
        ),
        // Tarball local: current wrapper id, still CAS-backed.
        // Different URL than the remote case → different hash →
        // different wrapper segment.
        (
            "tarball+file:./vendor/foo.tgz",
            Some("t-"),
            lpm_linker::Materialization::CasBacked,
        ),
        // Directory: wrapper id, DirectorySource.
        (
            "directory+./packages/foo",
            Some("f-"),
            lpm_linker::Materialization::DirectorySource,
        ),
        // Link: wrapper id, DirectorySource.
        (
            "link+./packages/foo",
            Some("l-"),
            lpm_linker::Materialization::DirectorySource,
        ),
    ];

    for (source, want_prefix, want_mat) in cases {
        let pkg = InstallPackage {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            source: (*source).to_string(),
            dependencies: vec![],
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        };
        let wid = pkg.wrapper_id_for_source();
        match want_prefix {
            None => assert!(
                wid.is_none(),
                "expected None wrapper_id for {source:?}, got {wid:?}",
            ),
            Some(prefix) => {
                let s = wid
                    .as_ref()
                    .unwrap_or_else(|| panic!("expected Some(...) for {source:?}, got None"));
                assert!(
                    s.starts_with(prefix) && s.len() == prefix.len() + 16,
                    "{source:?} → wid {s:?} must start with {prefix:?} + 16 hex",
                );
            }
        }
        assert_eq!(
            pkg.materialization_for_source(),
            *want_mat,
            "materialization mismatch for {source:?}",
        );
    }
}

/// the principal
/// known gap fix. Two tarball InstallPackages at the same
/// `(name, version)` but with different URLs (one remote https,
/// one local file:) must produce DISTINCT wrapper_ids.
#[test]
fn tarball_remote_and_local_produce_distinct_wrapper_ids() {
    let remote = InstallPackage {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: "tarball+https://example.com/foo-1.0.0.tgz".to_string(),
        dependencies: vec![],
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct: true,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: None,
        metadata_checked_for_tarball: false,
    };
    let local = InstallPackage {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: "tarball+file:./vendor/foo-1.0.0.tgz".to_string(),
        dependencies: vec![],
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct: true,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: None,
        metadata_checked_for_tarball: false,
    };

    let remote_wid = remote
        .wrapper_id_for_source()
        .expect("remote tarball must have wrapper_id");
    let local_wid = local
        .wrapper_id_for_source()
        .expect("local tarball must have wrapper_id");
    assert_ne!(
        remote_wid, local_wid,
        "remote vs local tarball at same (name, version) must produce distinct wrapper_ids",
    );
    assert!(remote_wid.starts_with("t-"));
    assert!(local_wid.starts_with("t-"));
}

/// `classify_source_dep`
/// rejects tarball-URL, git, and file-tarball transitives at
/// manifest-read time. Unsupported transitives must not be appended to
/// the consumer's `deps` map, where the resolver's `NpmRange::parse`
/// rejects them as invalid semver ranges. This test pins the contract:
/// reject early with an actionable error.
#[test]
fn classify_source_dep_rejects_unsupported_transitive_specs() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    // Create a real tarball file so file: classification can stat it.
    let tgz_path = base.join("foo.tgz");
    std::fs::write(&tgz_path, b"mock-tarball-bytes").unwrap();

    // Each case: (raw_spec, expected_substring_in_error).
    // The substring is what the regression user would actually see
    // in the failed install — verifies the message is actionable.
    let cases: &[(&str, &str)] = &[
        // Remote tarball URL.
        ("https://example.com/foo.tgz", "tarball URL"),
        ("http://example.com/foo.tgz", "tarball URL"),
        // Local file tarball (file: → regular file).
        ("file:./foo.tgz", "file: tarball"),
        // Git in canonical form.
        ("git+https://github.com/foo/bar.git", "git source"),
        ("git+ssh://git@github.com/foo/bar.git", "git source"),
        // Git host shorthand (Specifier::parse expands to Git).
        ("github:foo/bar", "git source"),
        ("gitlab:foo/bar#main", "git source"),
    ];

    for (raw, want_substr) in cases {
        let res = classify_source_dep(base, raw, "child");
        let err = res.expect_err(&format!("raw spec {raw:?} should be rejected; got Ok",));
        let msg = err.to_string();
        assert!(
            msg.contains(want_substr),
            "raw {raw:?}: error message should mention {want_substr:?}, got: {msg}",
        );
        // All errors should reference the source-dir path so the
        // user can locate the offending manifest.
        assert!(
            msg.contains(&base.display().to_string()),
            "raw {raw:?}: error must include base_dir path; got: {msg}",
        );
        // And the dep name so the user can locate the offending entry.
        assert!(
            msg.contains("child"),
            "raw {raw:?}: error must include dep_name; got: {msg}",
        );
    }
}

/// the supported
/// transitive shapes (registry semver / npm-alias / workspace,
/// file: directory, link:) all classify correctly without error.
/// Regression guard against an over-eager reject in the the invariant
/// fix.
#[test]
fn classify_source_dep_accepts_supported_transitive_specs() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    // Create the directory target for the file: case.
    let dir_target = base.join("packages").join("local-foo");
    std::fs::create_dir_all(&dir_target).unwrap();
    std::fs::write(
        dir_target.join("package.json"),
        br#"{"name":"local-foo","version":"0.1.0"}"#,
    )
    .unwrap();

    // (raw_spec, expected DepKind discriminant)
    // Each case must classify cleanly — no Err.
    let cases: &[(&str, DepKind)] = &[
        // Plain semver shapes.
        ("^1.2.3", DepKind::Registry),
        ("~1.0", DepKind::Registry),
        ("1.2.3", DepKind::Registry),
        (">=1.0 <2.0", DepKind::Registry),
        ("*", DepKind::Registry),
        ("latest", DepKind::Registry),
        // npm: alias.
        ("npm:@scope/other@^2.0", DepKind::Registry),
        // workspace: protocol (resolved by the local-source walker).
        ("workspace:*", DepKind::Workspace),
        ("workspace:^1.0.0", DepKind::Workspace),
        // file: directory and link: directory.
        ("file:./packages/local-foo", DepKind::FileDir),
        ("link:./packages/local-foo", DepKind::Link),
    ];

    for (raw, want_kind) in cases {
        let kind = classify_source_dep(base, raw, "child")
            .unwrap_or_else(|e| panic!("raw {raw:?} should classify cleanly, got: {e}"));
        assert_eq!(&kind, want_kind, "raw {raw:?} kind mismatch");
    }
}

/// when a local source's
/// `package.json` declares an unsupported transitive dep, the
/// error surfaces from `read_source_dep_specs` (the manifest-
/// read boundary) with the dep name, raw spec, and source dir
/// in the message. This is the exact path the `recurse_local_source_deps`
/// walker takes before resolver input is built.
#[test]
fn read_source_dep_specs_propagates_unsupported_transitive_error() {
    let dir = tempfile::tempdir().unwrap();
    let source_dir = dir.path().join("local-source");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::write(
        source_dir.join("package.json"),
        br#"{
          "name": "local-source",
          "version": "0.1.0",
          "dependencies": {
            "ok-dep": "^1.0.0",
            "bad-dep": "https://example.com/foo-1.0.0.tgz"
          }
        }"#,
    )
    .unwrap();

    let err = read_source_dep_specs(&source_dir)
        .expect_err("manifest with a transitive https:// tarball must error at read-spec time");
    let msg = err.to_string();
    assert!(
        msg.contains("bad-dep"),
        "msg should mention dep name: {msg}"
    );
    assert!(
        msg.contains("https://example.com/foo-1.0.0.tgz"),
        "msg should include the raw spec: {msg}",
    );
    assert!(
        msg.contains("tarball URL"),
        "msg should categorize the offending shape: {msg}",
    );
    assert!(
        msg.contains(&source_dir.display().to_string()),
        "msg should reference the source dir for grep-ability: {msg}",
    );
}

#[test]
fn read_source_dep_specs_optional_dependency_overrides_required_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let source_dir = dir.path().join("local-source");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::write(
        source_dir.join("package.json"),
        br#"{
          "name": "local-source",
          "version": "0.1.0",
          "dependencies": { "native": "git+https://example.com/overridden.git" },
          "optionalDependencies": { "native": "file:./native" }
        }"#,
    )
    .unwrap();
    std::fs::create_dir_all(source_dir.join("native")).unwrap();

    let specs = read_source_dep_specs(&source_dir)
        .expect("overridden required declaration must not be classified");
    assert!(
        matches!(
            specs.as_slice(),
            [SourceDep {
                local_name,
                kind: DepKind::FileDir,
                optional: true,
                ..
            }] if local_name == "native"
        ),
        "only the optional winning declaration should remain: {specs:?}",
    );
}

#[tokio::test]
async fn pre_resolve_marks_duplicate_local_dependency_optional_after_override() {
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project = tempfile::tempdir().unwrap();
    let host = project.path().join("packages/local-host");
    let native = project.path().join("packages/local-native");
    std::fs::create_dir_all(&host).unwrap();
    std::fs::create_dir_all(&native).unwrap();
    std::fs::write(
        host.join("package.json"),
        br#"{
          "name":"local-host",
          "version":"1.0.0",
          "dependencies":{"local-native":"file:../local-native"},
          "optionalDependencies":{"local-native":"file:../local-native"}
        }"#,
    )
    .unwrap();
    std::fs::write(
        native.join("package.json"),
        br#"{"name":"local-native","version":"1.0.0"}"#,
    )
    .unwrap();
    let mut deps = HashMap::from([(
        "local-host".to_string(),
        "file:./packages/local-host".to_string(),
    )]);

    let mut result =
        pre_resolve_non_registry_deps(&client, &store, project.path(), &mut deps, true, false, &[])
            .await
            .expect("pre-resolve duplicate local dependency");
    apply_post_resolve_directory_link_fixup(&mut result.install_pkgs, &result.source_deps);

    let native = result
        .install_pkgs
        .iter()
        .find(|package| package.name == "local-native")
        .expect("local-native install package");
    assert!(
        native.optional,
        "overridden local dependency must be optional"
    );
}

/// when a local source's
/// `package.json` declares `"<name>": "workspace:*"` for a name
/// that matches a workspace member, `recurse_local_source_deps`
/// must skip appending the spec to the consumer deps map. The top-level
/// `extract_workspace_protocol_deps` pass has already run and cannot see
/// appended transitive entries.
///
/// This pins the pre_resolve boundary contract: workspace transitives
/// matching a member must NOT pollute the resolver deps map.
#[tokio::test]
async fn workspace_transitive_with_matching_member_does_not_pollute_resolver_deps() {
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    // Local source that declares a workspace: transitive.
    let src = project_dir.path().join("packages").join("foo");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{
            "name": "foo",
            "version": "1.0.0",
            "dependencies": {
                "bar": "workspace:*"
            }
        }"#,
    )
    .unwrap();

    // The matching workspace member (mocked — the linker's
    // `link_workspace_members` symlinks it at the project root
    // post-install; for the pre_resolve test we just need a
    // member with the right name).
    let bar_dir = project_dir.path().join("workspace-members").join("bar");
    std::fs::create_dir_all(&bar_dir).unwrap();
    let workspace_members = vec![WorkspaceMemberLink {
        name: "bar".to_string(),
        version: "2.5.0".to_string(),
        source_dir: bar_dir,
    }];

    let mut deps = HashMap::from([("foo".to_string(), "file:./packages/foo".to_string())]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &workspace_members,
    )
    .await
    .expect("workspace transitive with matching member must not error");

    // Critical contract: `bar` must NOT be in the consumer deps
    // map. If it were, the resolver would crash on the
    // `workspace:*` range.
    assert!(
        !deps.contains_key("bar"),
        "workspace: transitive must not be appended to resolver deps map; found: {deps:?}",
    );
    // Sanity: the directory dep itself was processed.
    assert_eq!(
        result.install_pkgs.len(),
        1,
        "expected 1 InstallPackage for foo"
    );
    assert_eq!(result.install_pkgs[0].name, "foo");
}

#[test]
fn v2_direct_workspace_pre_resolve_promotes_workspace_child_to_source_graph() {
    let project_dir = tempfile::tempdir().unwrap();
    let packages = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages).unwrap();

    let foo_dir = make_local_pkg(&packages, "foo", "1.0.0", r#"{"bar":"workspace:*"}"#);
    let bar_dir = make_local_pkg(&packages, "bar", "1.0.0", "");

    let foo = WorkspaceMemberLink {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source_dir: foo_dir,
    };
    let bar = WorkspaceMemberLink {
        name: "bar".to_string(),
        version: "1.0.0".to_string(),
        source_dir: bar_dir,
    };
    let mut deps = HashMap::new();
    let foo_provider = DirectWorkspaceMemberProvider {
        name: foo.name.clone(),
        version: foo.version.clone(),
        source_dir: foo.source_dir.clone(),
        source: workspace_member_source(project_dir.path(), &foo.source_dir),
    };

    let mut result = pre_resolve_v2_direct_workspace_member_deps(
        project_dir.path(),
        &mut deps,
        std::slice::from_ref(&foo_provider),
        &[foo, bar.clone()],
        true,
    )
    .expect("v2 direct workspace pre-resolve should promote workspace child");

    let names: Vec<&str> = result
        .install_pkgs
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names, vec!["foo", "bar"]);

    let foo_source = result
        .install_pkgs
        .iter()
        .find(|p| p.name == "foo")
        .map(|p| p.source.clone())
        .unwrap();
    let bar_source = workspace_member_source(project_dir.path(), &bar.source_dir);
    let foo_specs = result
        .source_deps
        .get(&foo_source)
        .expect("foo source deps should be stashed");
    assert_eq!(foo_specs.len(), 1);
    assert_eq!(foo_specs[0].kind, DepKind::Workspace);
    assert_eq!(
        foo_specs[0].target_source.as_deref(),
        Some(bar_source.as_str())
    );

    apply_post_resolve_directory_link_fixup(&mut result.install_pkgs, &result.source_deps);
    let bar_source_id = lpm_lockfile::Source::parse(&bar_source)
        .unwrap()
        .source_id();
    let foo_pkg = result
        .install_pkgs
        .iter()
        .find(|p| p.name == "foo")
        .unwrap();
    assert_eq!(
        foo_pkg.dependencies,
        vec![("bar".to_string(), bar_source_id)]
    );
}

/// when a local source's
/// `package.json` declares `"<name>": "workspace:*"` but no
/// workspace member matches (e.g., the consumer's project is
/// not a workspace, or the named package isn't a member),
/// pre_resolve errors with a clear message naming the dep, the
/// raw spec, the source dir, and the available members.
#[tokio::test]
async fn workspace_transitive_without_matching_member_errors_with_actionable_message() {
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("packages").join("foo");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{
            "name": "foo",
            "version": "1.0.0",
            "dependencies": {
                "bar": "workspace:^1.0.0"
            }
        }"#,
    )
    .unwrap();

    let mut deps = HashMap::from([("foo".to_string(), "file:./packages/foo".to_string())]);

    // Empty workspace_members — the consumer's project is not a
    // workspace (or `bar` isn't a member). Either way, the
    // walker has no member to resolve to.
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect_err("workspace transitive without matching member must error");

    let msg = err.to_string();
    assert!(
        msg.contains("bar"),
        "msg must name the offending dep: {msg}"
    );
    assert!(
        msg.contains("workspace:^1.0.0"),
        "msg must include the raw spec: {msg}",
    );
    assert!(
        msg.contains("not a workspace"),
        "msg must explain why no member matched (project is not a workspace): {msg}",
    );
    assert!(
        msg.contains(&src.display().to_string()),
        "msg must reference the source dir for grep-ability: {msg}",
    );
}

#[tokio::test]
async fn store_path_or_err_routes_directory_to_canonical_realpath() {
    // The post-resolve dispatcher (link_targets construction at
    // install.rs:2593) calls `store_path_or_err`. For a directory
    // dep that must return the canonicalized source path, NOT the
    // global store. follow-up's lesson: write a regression
    // test that exercises the post-resolve dispatcher's path-
    // resolution AT THE SAME TIME as the pre_resolve work.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("packages").join("p1");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"p1","version":"0.1.0"}"#,
    )
    .unwrap();

    // InstallPackage shape mimicking the pre_resolve output for
    // `file:./packages/p1`.
    let pkg = InstallPackage {
        name: "p1".to_string(),
        version: "0.1.0".to_string(),
        source: "directory+./packages/p1".to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: Some(vec!["p1".to_string()]),
        is_direct: true,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: None,
        metadata_checked_for_tarball: false,
    };

    let path = pkg
        .store_path_or_err(&store, project_dir.path(), None)
        .expect("directory store_path_or_err must succeed for an existing source");
    assert_eq!(path, src.canonicalize().unwrap());
    // Also sanity: `store_has_source_aware` returns true.
    assert!(pkg.store_has_source_aware(&store, project_dir.path()));
}

#[tokio::test]
async fn store_path_or_err_directory_errors_on_missing_source() {
    // If the source dir was deleted between resolve time and link
    // time, `store_path_or_err` surfaces a typed error so the
    // install pipeline fails with a clear message rather than
    // crashing in the linker.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let project_dir = tempfile::tempdir().unwrap();

    let pkg = InstallPackage {
        name: "missing".to_string(),
        version: "0.1.0".to_string(),
        source: "directory+./does-not-exist".to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: Some(vec!["missing".to_string()]),
        is_direct: true,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: None,
        metadata_checked_for_tarball: false,
    };

    let err = pkg
        .store_path_or_err(&store, project_dir.path(), None)
        .expect_err("missing source dir must produce a typed error");
    let msg = err.to_string();
    assert!(
        msg.contains("directory") || msg.contains("does-not-exist"),
        "got: {msg}",
    );
    // store_has_source_aware also returns false.
    assert!(!pkg.store_has_source_aware(&store, project_dir.path()));
}

#[tokio::test]
async fn pre_resolve_rejects_file_missing_path_with_clear_error() {
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let mut deps = HashMap::from([(
        "missing".to_string(),
        "file:./does-not-exist.tgz".to_string(),
    )]);
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect_err("file: missing path must be rejected at pre-resolve");
    let msg = err.to_string();
    assert!(msg.contains("missing"), "got: {msg}");
    assert!(msg.contains("unreadable"), "got: {msg}");
}

// ── (): local-tarball happy paths ───────────────────

#[tokio::test]
async fn pre_resolve_extracts_local_tarball_from_file_specifier() {
    // Round-trip: write a real .tgz under the project dir, declare
    // `"foo": "file:./foo.tgz"`, assert pre_resolve returns one
    // InstallPackage with the right (name, version, source,
    // integrity), and that the bytes ended up in the local-tarball
    // CAS keyed by SHA-256.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let body = build_test_tarball();
    let tarball_path = project_dir.path().join("foo.tgz");
    std::fs::write(&tarball_path, &body).unwrap();

    let expected_sha256 = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&body);
        format!("{:x}", h.finalize())
    };
    let expected_sri = lpm_common::integrity::Integrity::from_bytes(
        lpm_common::integrity::HashAlgorithm::Sha256,
        &body,
    )
    .to_string();

    let mut deps = HashMap::from([
        ("react".to_string(), "^19.0.0".to_string()),
        ("foo".to_string(), "file:./foo.tgz".to_string()),
    ]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("local-tarball pre_resolve must succeed")
    .install_pkgs;

    // Registry dep stays in `deps`; file: tarball dep is removed.
    assert_eq!(deps.len(), 1);
    assert!(deps.contains_key("react"));
    assert!(!deps.contains_key("foo"));

    // One InstallPackage produced for the file: tarball.
    assert_eq!(install_pkgs.len(), 1);
    let p = &install_pkgs[0];
    assert_eq!(p.name, "test-tarball-pkg");
    assert_eq!(p.version, "1.0.0");
    // `tarball+file:./foo.tgz` — raw user-typed path preserved.
    assert_eq!(p.source, "tarball+file:./foo.tgz");
    // `root_link_names` carries the dep KEY (`foo`), not the
    // package's real name. Same posture as the tarball-URL arm.
    assert_eq!(p.root_link_names.as_deref(), Some(&["foo".to_string()][..]));
    assert_eq!(p.integrity, Some(expected_sri));
    assert!(p.is_direct);
    // Local tarballs have no remote URL → tarball_url stays None.
    assert!(p.tarball_url.is_none());

    // Bytes landed in the content-keyed local-tarball CAS.
    assert!(store.has_local_tarball(&expected_sha256));
    let cas_path = store.tarball_local_store_path(&expected_sha256).unwrap();
    assert!(cas_path.join("package.json").exists());
    assert!(cas_path.join(".integrity").exists());
}

#[tokio::test]
async fn pre_resolve_local_tarball_dedupes_same_content_across_paths() {
    // Two consumers using `file:./a.tgz` and `file:./sub/b.tgz`
    // of identical bytes share one CAS slot. Identity is
    // content-only — the user-typed path differs in the
    // InstallPackage source / lockfile entry, but the store
    // entry dedupes.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let body = build_test_tarball();
    let path_a = project_dir.path().join("a.tgz");
    let path_b = project_dir.path().join("sub").join("b.tgz");
    std::fs::create_dir_all(path_b.parent().unwrap()).unwrap();
    std::fs::write(&path_a, &body).unwrap();
    std::fs::write(&path_b, &body).unwrap();

    let mut deps = HashMap::from([
        ("alpha".to_string(), "file:./a.tgz".to_string()),
        ("beta".to_string(), "file:./sub/b.tgz".to_string()),
    ]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("dedupe pre_resolve must succeed")
    .install_pkgs;

    assert_eq!(install_pkgs.len(), 2);
    // Both InstallPackages carry the same integrity (content
    // hash) but distinct sources (user-typed paths).
    assert_eq!(install_pkgs[0].integrity, install_pkgs[1].integrity);
    let sources: Vec<&str> = install_pkgs.iter().map(|p| p.source.as_str()).collect();
    assert!(sources.contains(&"tarball+file:./a.tgz"));
    assert!(sources.contains(&"tarball+file:./sub/b.tgz"));

    // One CAS slot for both — content-keyed dedupe.
    let expected_sha256 = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&body);
        format!("{:x}", h.finalize())
    };
    assert!(store.has_local_tarball(&expected_sha256));
}

#[tokio::test]
async fn pre_resolve_local_tarball_strict_integrity_does_not_apply() {
    // Strict-integrity is for tarball-URL deps where the manifest
    // may declare an SRI suffix. Local tarballs have no separate
    // declared-vs-computed SRI — the content hash IS the integrity,
    // computed on every fetch. `--strict-integrity` must not error
    // on a file: tarball.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let body = build_test_tarball();
    std::fs::write(project_dir.path().join("foo.tgz"), &body).unwrap();

    let mut deps = HashMap::from([("foo".to_string(), "file:./foo.tgz".to_string())]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        true, // strict_integrity = true
        &[],
    )
    .await
    .expect("file: tarball must succeed even under --strict-integrity")
    .install_pkgs;
    assert_eq!(install_pkgs.len(), 1);
}

#[tokio::test]
async fn pre_resolve_local_tarball_dep_key_warns_on_name_mismatch() {
    // Same dep-key vs fetched-name policy as the tarball-URL arm:
    // warn rather than reject. Asserted here by checking that the InstallPackage uses the dep KEY
    // for `root_link_names` even when the package's real name
    // differs.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let body = build_test_tarball(); // packs name=test-tarball-pkg
    std::fs::write(project_dir.path().join("renamed.tgz"), &body).unwrap();

    let mut deps = HashMap::from([(
        "renamed-locally".to_string(),
        "file:./renamed.tgz".to_string(),
    )]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("renamed local tarball must succeed")
    .install_pkgs;
    assert_eq!(install_pkgs.len(), 1);
    let p = &install_pkgs[0];
    // Identity = real package name from the inner package.json.
    assert_eq!(p.name, "test-tarball-pkg");
    // Layout = dep KEY.
    assert_eq!(
        p.root_link_names.as_deref(),
        Some(&["renamed-locally".to_string()][..]),
    );
}

// ── (): link: dep happy paths + boundaries ─────────

#[tokio::test]
async fn pre_resolve_extracts_link_dep_from_link_specifier() {
    // Round-trip: a `link:./packages/foo` dep produces an
    // InstallPackage with `source: "link+<rel-path>"`,
    // `integrity: None`, `tarball_url: None`, name/version from
    // the source's package.json, dep KEY in root_link_names.
    // wrapper_id_for_source returns `Some("l-{16hex}")` (NOT
    // `"f-..."` — matches Source::Link.source_id() shape).
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("packages").join("linked-foo");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"linked-foo","version":"0.2.0"}"#,
    )
    .unwrap();
    std::fs::write(src.join("index.js"), b"module.exports = 'linked'").unwrap();

    let mut deps = HashMap::from([
        ("react".to_string(), "^19.0.0".to_string()),
        (
            "linked-foo".to_string(),
            "link:./packages/linked-foo".to_string(),
        ),
    ]);

    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("link: dep pre_resolve must succeed")
    .install_pkgs;

    // Registry dep stays in `deps`; link: dep is removed.
    assert_eq!(deps.len(), 1);
    assert!(deps.contains_key("react"));
    assert!(!deps.contains_key("linked-foo"));

    assert_eq!(install_pkgs.len(), 1);
    let p = &install_pkgs[0];
    assert_eq!(p.name, "linked-foo");
    assert_eq!(p.version, "0.2.0");
    // Wire-format source uses the `link+` prefix (NOT `directory+`).
    assert_eq!(p.source, "link+./packages/linked-foo");
    assert!(p.integrity.is_none());
    assert!(p.tarball_url.is_none());
    assert_eq!(
        p.root_link_names.as_deref(),
        Some(["linked-foo".to_string()].as_slice()),
    );
    assert!(p.is_direct);
    // limitation: graph leaf (transitives day 5).
    assert!(p.dependencies.is_empty());

    // wrapper_id is `l-{16hex(rel-path)}` per Source::Link.source_id().
    let wid = p
        .wrapper_id_for_source()
        .expect("link: must have wrapper_id");
    assert!(
        wid.starts_with("l-") && wid.len() == 18,
        "expected l-{{16hex}} shape, got: {wid:?}",
    );
}

#[tokio::test]
async fn pre_resolve_link_dep_wrapper_id_differs_from_file_directory() {
    // Same realpath used by both file: directory AND link: should
    // produce DIFFERENT wrapper_ids (`f-...` vs `l-...`) — the
    // discriminator in source-id encodes specifier kind so the
    // two arms get distinct wrappers.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("shared");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"shared","version":"1.0.0"}"#,
    )
    .unwrap();

    // First pass: file: directory dep.
    let mut file_deps = HashMap::from([("shared".to_string(), "file:./shared".to_string())]);
    let file_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut file_deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap()
    .install_pkgs;
    let file_wid = file_pkgs[0].wrapper_id_for_source().unwrap();

    // Second pass: link: dep, same source.
    let mut link_deps = HashMap::from([("shared".to_string(), "link:./shared".to_string())]);
    let link_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut link_deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap()
    .install_pkgs;
    let link_wid = link_pkgs[0].wrapper_id_for_source().unwrap();

    assert!(file_wid.starts_with("f-"));
    assert!(link_wid.starts_with("l-"));
    // Distinct wrappers even though the realpath is identical —
    // the prefix carries semantic difference (link: ignores
    // `--no-symlink`, file: respects it).
    assert_ne!(file_wid, link_wid);
    // But the hex tail (the path-hash component) is identical.
    assert_eq!(&file_wid[2..], &link_wid[2..]);
}

#[tokio::test]
async fn pre_resolve_rejects_link_pointing_at_regular_file() {
    // `link:./foo.tgz` (regular file) is rejected — link: requires
    // a directory containing package.json. The error message
    // points at `file:` as the right alternative for tarballs.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    std::fs::write(project_dir.path().join("foo.tgz"), b"fake tarball").unwrap();

    let mut deps = HashMap::from([("bad".to_string(), "link:./foo.tgz".to_string())]);
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect_err("link: pointing at a file must error");
    let msg = err.to_string();
    assert!(msg.contains("link:"), "got: {msg}");
    assert!(
        msg.contains("regular file") || msg.contains("file:"),
        "error must point at the right alternative, got: {msg}",
    );
}

#[tokio::test]
async fn pre_resolve_rejects_link_with_missing_path() {
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let mut deps = HashMap::from([("missing".to_string(), "link:./does-not-exist".to_string())]);
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect_err("missing link: target must error");
    let msg = err.to_string();
    assert!(msg.contains("missing"), "got: {msg}");
    assert!(msg.contains("unreadable"), "got: {msg}");
}

#[tokio::test]
async fn pre_resolve_rejects_link_without_package_json() {
    // link: directory must contain package.json (read for name/
    // version). Missing manifest → typed error, NOT a downstream
    // panic.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("no-manifest");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("README.md"), b"no manifest").unwrap();

    let mut deps = HashMap::from([("broken".to_string(), "link:./no-manifest".to_string())]);
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect_err("link: target without package.json must error");
    let msg = err.to_string();
    assert!(
        msg.contains("package.json") || msg.contains("read"),
        "got: {msg}",
    );
}

#[tokio::test]
async fn pre_resolve_link_dep_dep_key_warns_on_name_mismatch() {
    // Same dep-key vs fetched-name policy as every other arm
    // (umbrella— locked as warn-not-reject).
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("packages").join("foo");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"foo","version":"3.0.0"}"#,
    )
    .unwrap();

    let mut deps = HashMap::from([(
        "renamed-link".to_string(),
        "link:./packages/foo".to_string(),
    )]);
    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("renamed link: dep must succeed")
    .install_pkgs;
    let p = &install_pkgs[0];
    assert_eq!(p.name, "foo"); // store identity = real name
    assert_eq!(
        p.root_link_names.as_deref(),
        Some(["renamed-link".to_string()].as_slice()),
    );
}

#[tokio::test]
async fn pre_resolve_link_dep_routes_through_store_path_to_canonical_realpath() {
    // The post-resolve dispatcher path for link: deps — same as
    // file: directory deps (both go through Source::Directory or
    // Source::Link arm in store_path_or_err which canonicalize
    // the source path). lesson institutionalized: write
    // a regression test for the post-resolve dispatcher AT THE
    // SAME TIME as the pre_resolve test.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let project_dir = tempfile::tempdir().unwrap();

    let src = project_dir.path().join("linked");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        br#"{"name":"linked","version":"1.0.0"}"#,
    )
    .unwrap();

    let pkg = InstallPackage {
        name: "linked".to_string(),
        version: "1.0.0".to_string(),
        source: "link+./linked".to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: Some(vec!["linked".to_string()]),
        is_direct: true,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: None,
        metadata_checked_for_tarball: false,
    };

    let path = pkg
        .store_path_or_err(&store, project_dir.path(), None)
        .expect("link: store_path_or_err must succeed");
    assert_eq!(path, src.canonicalize().unwrap());
    assert!(pkg.store_has_source_aware(&store, project_dir.path()));
}

// ── (-transitive): recursive walk + post-resolve fix-up ─

fn make_local_pkg(parent: &Path, name: &str, version: &str, deps_json: &str) -> PathBuf {
    let dir = parent.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = if deps_json.is_empty() {
        format!(r#"{{"name":"{name}","version":"{version}"}}"#)
    } else {
        format!(r#"{{"name":"{name}","version":"{version}","dependencies":{deps_json}}}"#)
    };
    std::fs::write(dir.join("package.json"), manifest).unwrap();
    dir
}

#[tokio::test]
async fn pre_resolve_recurses_into_transitive_file_directory_deps() {
    // Consumer declares `"a": "file:./packages/a"`. Source A
    // declares `"b": "file:../b"`. contract: pre_resolve
    // walks A's pkg.json, finds B, builds B as a transitive
    // InstallPackage. Both A and B appear in install_pkgs.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let packages_dir = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages_dir).unwrap();
    // B (transitive) — no deps.
    let _b = make_local_pkg(&packages_dir, "b", "1.0.0", "");
    // A (immediate) — depends on file:../b.
    let _a = make_local_pkg(&packages_dir, "a", "1.0.0", r#"{"b":"file:../b"}"#);

    let mut deps = HashMap::from([("a".to_string(), "file:./packages/a".to_string())]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("recursive pre_resolve must succeed");

    // 2 InstallPackages: A (immediate) + B (transitive).
    assert_eq!(result.install_pkgs.len(), 2);
    let names: Vec<&str> = result
        .install_pkgs
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"b"));

    // A is direct (root); B is transitive.
    let a = result.install_pkgs.iter().find(|p| p.name == "a").unwrap();
    let b = result.install_pkgs.iter().find(|p| p.name == "b").unwrap();
    assert!(a.is_direct);
    assert!(!b.is_direct);
    assert_eq!(
        a.root_link_names.as_deref(),
        Some(["a".to_string()].as_slice())
    );
    // Transitives get an EMPTY root_link_names (explicitly zero
    // — distinguishes "transitive, no root link" from the
    // pre- default).
    assert_eq!(b.root_link_names.as_deref(), Some(&[][..]));

    // source_deps is keyed by source string and contains A's deps.
    let a_specs = result
        .source_deps
        .get(&a.source)
        .expect("A's source-deps must be stashed");
    assert_eq!(a_specs.len(), 1);
    assert_eq!(a_specs[0].local_name, "b");
    assert_eq!(a_specs[0].kind, DepKind::FileDir);
    assert_eq!(a_specs[0].target_source.as_deref(), Some("directory+../b"));
}

#[tokio::test]
async fn pre_resolve_appends_registry_transitives_to_consumer_deps() {
    // Consumer declares `"a": "file:./packages/a"`. Source A
    // declares `"lodash": "^4.0.0"`. contract: lodash
    // gets appended to the consumer's `deps` map so the
    // resolver picks it up.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let pkg_a = project_dir.path().join("packages").join("a");
    std::fs::create_dir_all(&pkg_a).unwrap();
    std::fs::write(
        pkg_a.join("package.json"),
        r#"{"name":"a","version":"1.0.0","dependencies":{"lodash":"^4.0.0"}}"#,
    )
    .unwrap();

    let mut deps = HashMap::from([("a".to_string(), "file:./packages/a".to_string())]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap();

    // a was consumed (file: dep removed from deps); lodash was
    // appended (transitive registry dep).
    assert!(!deps.contains_key("a"));
    assert_eq!(deps.get("lodash"), Some(&"^4.0.0".to_string()));
    assert_eq!(result.install_pkgs.len(), 1); // just A
}

#[tokio::test]
async fn pre_resolve_consumer_decl_wins_over_transitive_registry_dep() {
    // First-come-first-serve merge: the consumer's own
    // declaration of `lodash@^5` wins over A's declaration of
    // `lodash@^4`. Acceptable v1 (umbrella).
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let pkg_a = project_dir.path().join("packages").join("a");
    std::fs::create_dir_all(&pkg_a).unwrap();
    std::fs::write(
        pkg_a.join("package.json"),
        r#"{"name":"a","version":"1.0.0","dependencies":{"lodash":"^4.0.0"}}"#,
    )
    .unwrap();

    let mut deps = HashMap::from([
        ("a".to_string(), "file:./packages/a".to_string()),
        ("lodash".to_string(), "^5.0.0".to_string()),
    ]);
    pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap();

    // Consumer's declaration wins.
    assert_eq!(deps.get("lodash"), Some(&"^5.0.0".to_string()));
}

#[tokio::test]
async fn pre_resolve_recursion_realpath_cycle_detect() {
    // A → B → A (each via file:). Realpath cycle detect stops
    // the recursion. Both A and B appear EXACTLY ONCE in
    // install_pkgs (no duplicates from the cycle).
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let packages_dir = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages_dir).unwrap();
    let _b = make_local_pkg(
        &packages_dir,
        "b",
        "1.0.0",
        r#"{"a":"file:../a"}"#, // cycle back
    );
    let _a = make_local_pkg(&packages_dir, "a", "1.0.0", r#"{"b":"file:../b"}"#);

    let mut deps = HashMap::from([("a".to_string(), "file:./packages/a".to_string())]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("cycle must not infinite-loop");

    let names: Vec<&str> = result
        .install_pkgs
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names.iter().filter(|n| **n == "a").count(), 1);
    assert_eq!(names.iter().filter(|n| **n == "b").count(), 1);
}

#[tokio::test]
async fn pre_resolve_recursion_depth_bounded_at_3() {
    // A → B → C → D, all file: directory deps. bound is
    // depth 3 from the consumer. Consumer is depth 0, A is
    // immediate (handled by the existing pre_resolve loops).
    // Recursion processes A's deps (depth 1: B), B's deps
    // (depth 2: C), C's deps (depth 3: D — last allowed level).
    // D's deps would be at depth 4 → not processed.
    //
    // For this test, D has no transitive deps anyway, so we
    // just verify that D appears in install_pkgs (since depth
    // 3 IS within bound).
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let packages_dir = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages_dir).unwrap();
    let _d = make_local_pkg(&packages_dir, "d", "1.0.0", "");
    let _c = make_local_pkg(&packages_dir, "c", "1.0.0", r#"{"d":"file:../d"}"#);
    let _b = make_local_pkg(&packages_dir, "b", "1.0.0", r#"{"c":"file:../c"}"#);
    let _a = make_local_pkg(&packages_dir, "a", "1.0.0", r#"{"b":"file:../b"}"#);

    let mut deps = HashMap::from([("a".to_string(), "file:./packages/a".to_string())]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap();

    let names: Vec<&str> = result
        .install_pkgs
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"b"));
    assert!(names.contains(&"c"));
    assert!(names.contains(&"d")); // depth 3, INSIDE the bound
}

#[tokio::test]
async fn pre_resolve_recursion_depth_bound_excludes_depth_4() {
    // Push the chain one deeper: A → B → C → D → E. E is at
    // depth 4 from the consumer; the recursion must NOT
    // process its enclosing source's deps (D's deps), so E is
    // absent from install_pkgs. D itself is at depth 3 →
    // present.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let packages_dir = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages_dir).unwrap();
    let _e = make_local_pkg(&packages_dir, "e", "1.0.0", "");
    let _d = make_local_pkg(&packages_dir, "d", "1.0.0", r#"{"e":"file:../e"}"#);
    let _c = make_local_pkg(&packages_dir, "c", "1.0.0", r#"{"d":"file:../d"}"#);
    let _b = make_local_pkg(&packages_dir, "b", "1.0.0", r#"{"c":"file:../c"}"#);
    let _a = make_local_pkg(&packages_dir, "a", "1.0.0", r#"{"b":"file:../b"}"#);

    let mut deps = HashMap::from([("a".to_string(), "file:./packages/a".to_string())]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap();

    let names: Vec<&str> = result
        .install_pkgs
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert!(names.contains(&"d"), "d (depth 3) MUST be processed");
    assert!(
        !names.contains(&"e"),
        "e (depth 4) MUST NOT be processed (depth bound)",
    );
}

#[tokio::test]
async fn pre_resolve_recursion_diamond_dedupes_via_visited() {
    // A → C (file:); B → C (file:). Two separate immediate
    // deps converge on C. contract: visited-set is
    // shared across immediates so C appears EXACTLY ONCE in
    // install_pkgs (no duplicate).
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let packages_dir = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages_dir).unwrap();
    let _c = make_local_pkg(&packages_dir, "c", "1.0.0", "");
    let _a = make_local_pkg(&packages_dir, "a", "1.0.0", r#"{"c":"file:../c"}"#);
    let _b = make_local_pkg(&packages_dir, "b", "1.0.0", r#"{"c":"file:../c"}"#);

    let mut deps = HashMap::from([
        ("a".to_string(), "file:./packages/a".to_string()),
        ("b".to_string(), "file:./packages/b".to_string()),
    ]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap();

    let c_count = result.install_pkgs.iter().filter(|p| p.name == "c").count();
    assert_eq!(c_count, 1, "diamond converges to a single C InstallPackage");
}

#[test]
fn apply_post_resolve_fixup_populates_directory_dependencies() {
    // Direct test of the post-resolve fix-up. Build a synthetic
    // `packages` vec with:
    // - directory dep "a" (transitive deps: [lodash, b])
    // - registry dep "lodash@4.17.21"
    // - directory dep "b"
    // Build matching source_deps. After fix-up, "a"'s dependencies
    // field has [(lodash, 4.17.21), (b, f-...)].
    let mut packages = vec![
        InstallPackage {
            name: "a".to_string(),
            version: "1.0.0".to_string(),
            source: "directory+./packages/a".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(vec!["a".to_string()]),
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        },
        InstallPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: "registry+https://registry.npmjs.org".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct: false,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        },
        InstallPackage {
            name: "b".to_string(),
            version: "1.0.0".to_string(),
            source: "directory+./packages/b".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(Vec::new()), // transitive
            is_direct: false,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        },
    ];

    let mut source_deps = HashMap::new();
    source_deps.insert(
        "directory+./packages/a".to_string(),
        vec![
            SourceDep {
                local_name: "lodash".to_string(),
                raw_spec: "^4.0.0".to_string(),
                kind: DepKind::Registry,
                optional: false,
                target_source: None,
            },
            SourceDep {
                local_name: "b".to_string(),
                raw_spec: "file:../b".to_string(),
                kind: DepKind::FileDir,
                optional: false,
                target_source: Some("directory+./packages/b".to_string()),
            },
        ],
    );

    apply_post_resolve_directory_link_fixup(&mut packages, &source_deps);

    let a = packages.iter().find(|p| p.name == "a").unwrap();
    assert_eq!(a.dependencies.len(), 2);
    // Registry transitive resolves to the version from the
    // resolver output ("4.17.21").
    assert!(
        a.dependencies
            .contains(&("lodash".to_string(), "4.17.21".to_string()))
    );
    // file: transitive resolves to the source-id (`f-{16hex}`)
    // matching B's wrapper segment.
    let b_source_id = lpm_lockfile::Source::Directory {
        path: "./packages/b".to_string(),
    }
    .source_id();
    assert!(
        a.dependencies.contains(&("b".to_string(), b_source_id)),
        "A's deps must reference B by source-id, got {:?}",
        a.dependencies,
    );
}

#[test]
fn apply_post_resolve_fixup_preserves_registry_alias_edges_from_source_deps() {
    let mut packages = vec![
        InstallPackage {
            name: "consumer".to_string(),
            version: "1.0.0".to_string(),
            source: "directory+./packages/consumer".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(vec!["consumer".to_string()]),
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        },
        InstallPackage {
            name: "@jsr/std__path".to_string(),
            version: "1.1.6".to_string(),
            source: "registry+https://npm.jsr.io".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        },
    ];

    let mut source_deps = HashMap::new();
    source_deps.insert(
        "directory+./packages/consumer".to_string(),
        vec![SourceDep {
            local_name: "@std/path".to_string(),
            raw_spec: "npm:@jsr/std__path@^1.1.0".to_string(),
            kind: DepKind::Registry,
            optional: false,
            target_source: None,
        }],
    );

    apply_post_resolve_directory_link_fixup(&mut packages, &source_deps);

    let consumer = packages.iter().find(|p| p.name == "consumer").unwrap();
    assert_eq!(
        consumer.dependencies,
        vec![("@std/path".to_string(), "1.1.6".to_string())]
    );
    assert_eq!(
        consumer.aliases.get("@std/path").map(String::as_str),
        Some("@jsr/std__path")
    );
}

#[test]
fn apply_post_resolve_fixup_uses_declared_source_when_name_version_collides() {
    let fork_source = "directory+./packages/react-fork".to_string();
    let fork_source_id = lpm_lockfile::Source::Directory {
        path: "./packages/react-fork".to_string(),
    }
    .source_id();
    let mut packages = vec![
        InstallPackage {
            name: "consumer".to_string(),
            version: "1.0.0".to_string(),
            source: "directory+./packages/consumer".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(vec!["consumer".to_string()]),
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        },
        InstallPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: "registry+https://registry.npmjs.org".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        },
        InstallPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: fork_source.clone(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(Vec::new()),
            is_direct: false,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        },
    ];

    let mut source_deps = HashMap::new();
    source_deps.insert(
        "directory+./packages/consumer".to_string(),
        vec![SourceDep {
            local_name: "react".to_string(),
            raw_spec: "file:../react-fork".to_string(),
            kind: DepKind::FileDir,
            optional: false,
            target_source: Some(fork_source),
        }],
    );

    apply_post_resolve_directory_link_fixup(&mut packages, &source_deps);

    let consumer = packages.iter().find(|p| p.name == "consumer").unwrap();
    assert_eq!(
        consumer.dependencies,
        vec![("react".to_string(), fork_source_id)]
    );
}

#[test]
fn apply_post_resolve_fixup_skips_missing_registry_deps() {
    // If the resolver didn't provide a version for a name in
    // source_deps (e.g., optionalDependency platform-skip),
    // the fix-up silently drops that entry from the parent's
    // dependencies. The linker won't try to create a symlink
    // pointing at a missing wrapper.
    let mut packages = vec![InstallPackage {
        name: "a".to_string(),
        version: "1.0.0".to_string(),
        source: "directory+./packages/a".to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: Some(vec!["a".to_string()]),
        is_direct: true,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: None,
        metadata_checked_for_tarball: false,
    }];

    let mut source_deps = HashMap::new();
    source_deps.insert(
        "directory+./packages/a".to_string(),
        vec![SourceDep {
            local_name: "missing-from-resolver".to_string(),
            raw_spec: "^1.0.0".to_string(),
            kind: DepKind::Registry,
            optional: false,
            target_source: None,
        }],
    );

    apply_post_resolve_directory_link_fixup(&mut packages, &source_deps);
    assert!(packages[0].dependencies.is_empty());
}

// ── ( + ): workspace overlap + node_modules dedupe ─

fn make_workspace_member(parent: &Path, name: &str, version: &str) -> WorkspaceMemberLink {
    let dir = parent.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
    WorkspaceMemberLink {
        name: name.to_string(),
        version: version.to_string(),
        source_dir: dir.canonicalize().unwrap(),
    }
}

#[tokio::test]
async fn pre_resolve_directory_dep_overlapping_workspace_member_dedupes() {
    // contract: a `file:` directory dep whose realpath
    // matches a workspace member's source_dir is DEDUPED — no
    // InstallPackage built; the workspace member is already
    // extracted and will be linked by `link_workspace_members`.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    // Build a workspace member at packages/foo and pretend
    // workspace discovery extracted it.
    let packages = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages).unwrap();
    let member = make_workspace_member(&packages, "foo", "1.0.0");

    // Consumer also declares `"foo": "file:./packages/foo"` —
    // pointing at the SAME realpath. dedupes.
    let mut deps = HashMap::from([
        ("foo".to_string(), "file:./packages/foo".to_string()),
        ("react".to_string(), "^19.0.0".to_string()),
    ]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        std::slice::from_ref(&member),
    )
    .await
    .expect("workspace-member dedupe must not error on a clean overlap");

    // No InstallPackage built for the file: dep — the workspace
    // member handles it.
    assert_eq!(
        result.install_pkgs.len(),
        0,
        "workspace-member dedupe must skip InstallPackage construction; got {:?}",
        result
            .install_pkgs
            .iter()
            .map(|p| &p.name)
            .collect::<Vec<_>>(),
    );
    // file: dep was still removed from `deps` (the partition step ran).
    assert!(!deps.contains_key("foo"));
    assert!(deps.contains_key("react"));
}

#[tokio::test]
async fn pre_resolve_link_dep_overlapping_workspace_member_dedupes() {
    // Same contract for link: deps. The dedupe is realpath-
    // based and applies uniformly to file: directory and link:
    // sources.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let packages = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages).unwrap();
    let member = make_workspace_member(&packages, "linked", "0.5.0");

    let mut deps = HashMap::from([("linked".to_string(), "link:./packages/linked".to_string())]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        std::slice::from_ref(&member),
    )
    .await
    .unwrap();

    assert_eq!(result.install_pkgs.len(), 0);
    assert!(!deps.contains_key("linked"));
}

#[tokio::test]
async fn pre_resolve_overlap_with_version_mismatch_is_hard_error() {
    // contract: realpath match BUT versions disagree → hard
    // error. The error names both versions so the user can sync
    // one of the package.json files.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let packages = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages).unwrap();
    // The source on disk has version 2.0.0.
    let pkg_dir = packages.join("foo");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        br#"{"name":"foo","version":"2.0.0"}"#,
    )
    .unwrap();
    // The workspace member metadata recorded version 1.0.0
    // (drifted from the current package.json — concurrent edit
    // or stale workspace cache).
    let member = WorkspaceMemberLink {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source_dir: pkg_dir.canonicalize().unwrap(),
    };

    let mut deps = HashMap::from([("foo".to_string(), "file:./packages/foo".to_string())]);
    let err = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        std::slice::from_ref(&member),
    )
    .await
    .expect_err("version-mismatch overlap must be a hard error");
    let msg = err.to_string();
    assert!(msg.contains("workspace"), "got: {msg}");
    assert!(msg.contains("foo"), "got: {msg}");
    assert!(msg.contains("1.0.0") && msg.contains("2.0.0"), "got: {msg}");
}

#[tokio::test]
async fn pre_resolve_directory_dep_outside_workspace_does_not_dedupe() {
    // Regression: a `file:` directory dep whose realpath does
    // NOT match any workspace member's source_dir continues to
    // produce a normal InstallPackage. The dedupe must
    // not over-fire on plain non-workspace projects.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    // Workspace member at packages/foo.
    let packages = project_dir.path().join("packages");
    std::fs::create_dir_all(&packages).unwrap();
    let member = make_workspace_member(&packages, "foo", "1.0.0");
    // Consumer's file: dep points at packages/bar — DIFFERENT path.
    let _bar = make_workspace_member(&packages, "bar", "0.0.1");

    let mut deps = HashMap::from([("bar".to_string(), "file:./packages/bar".to_string())]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        std::slice::from_ref(&member),
    )
    .await
    .unwrap();

    // bar is NOT a workspace member → InstallPackage built.
    assert_eq!(result.install_pkgs.len(), 1);
    assert_eq!(result.install_pkgs[0].name, "bar");
}

#[test]
fn detect_workspace_overlap_realpath_byte_equal_match() {
    // Direct test of detect_workspace_overlap. With the same
    // realpath on both sides + same version, returns
    // DedupeWith(member).
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("foo");
    std::fs::create_dir_all(&pkg).unwrap();
    let canon = pkg.canonicalize().unwrap();
    let member = WorkspaceMemberLink {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source_dir: canon.clone(),
    };
    match detect_workspace_overlap(
        &canon,
        "1.0.0",
        std::slice::from_ref(&member),
        "foo",
        "file:./foo",
    )
    .unwrap()
    {
        WorkspaceOverlap::DedupeWith(m) => assert_eq!(m.name, "foo"),
        WorkspaceOverlap::NoOverlap => panic!("expected DedupeWith"),
    }
}

#[test]
fn detect_workspace_overlap_no_overlap_when_paths_differ() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let member = WorkspaceMemberLink {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source_dir: a.canonicalize().unwrap(),
    };
    let result = detect_workspace_overlap(
        &b.canonicalize().unwrap(),
        "1.0.0",
        std::slice::from_ref(&member),
        "foo",
        "file:./b",
    )
    .unwrap();
    assert!(matches!(result, WorkspaceOverlap::NoOverlap));
}

#[test]
fn detect_workspace_overlap_empty_members_short_circuits() {
    // When workspace_members is empty (non-workspace install),
    // detect_workspace_overlap returns NoOverlap without doing
    // any FS work. Tests the empty-slice fast path.
    let dir = tempfile::tempdir().unwrap();
    let result = detect_workspace_overlap(dir.path(), "1.0.0", &[], "foo", "file:./").unwrap();
    assert!(matches!(result, WorkspaceOverlap::NoOverlap));
}

#[tokio::test]
async fn pre_resolve_warns_once_per_realpath_for_pkg_node_modules() {
    // finalization: when two file: deps point at the same
    // realpath (the user accidentally writes both `file:./foo`
    // and `file:././foo`), the pkg/node_modules warn fires
    // ONCE — dedupe via the shared HashSet.
    //
    // For deterministic test output we set json_output=true
    // (which suppresses output::warn altogether) — the contract
    // we're testing is the SET behavior, exposed indirectly via
    // pre_resolve succeeding with both deps. The warn dedupe
    // shape is covered by direct unit tests below; this test
    // verifies the integration doesn't regress when two deps
    // realpath-converge.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let project_dir = tempfile::tempdir().unwrap();

    let pkg = project_dir.path().join("foo");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"foo","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(pkg.join("node_modules")).unwrap();

    // Two deps with different keys but same realpath.
    let mut deps = HashMap::from([
        ("a".to_string(), "file:./foo".to_string()),
        ("b".to_string(), "file:././foo".to_string()),
    ]);
    let result = pre_resolve_non_registry_deps(
        &client,
        &store,
        project_dir.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .unwrap();

    // Both deps produce InstallPackages (they're keyed
    // differently in the partition step) but the SAME realpath
    // is processed — 's dedupe set keeps the warn count to
    // one (suppressed entirely under json_output anyway).
    // The test passes if pre_resolve doesn't error.
    assert_eq!(result.install_pkgs.len(), 2);
}

#[test]
fn maybe_warn_pkg_node_modules_dedupes_via_realpath_set() {
    // Direct test of the helper: same realpath called twice
    // → the set inserts only the first time. We pass
    // json_output=false to exercise the actual warn path
    // (which emits to stderr; visible during test runs but
    // doesn't fail anything). The dedupe contract is what we
    // verify via set size.
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("node_modules")).unwrap();
    let canon = src.canonicalize().unwrap();

    let mut warned = std::collections::HashSet::new();
    // First call inserts.
    maybe_warn_pkg_node_modules(&canon, "a", false, &mut warned);
    assert_eq!(warned.len(), 1);
    // Second call — same path — does NOT re-insert (HashSet
    // semantics). The dedupe is verified by set size.
    maybe_warn_pkg_node_modules(&canon, "b", false, &mut warned);
    assert_eq!(warned.len(), 1);
    // Different path inserts.
    let other = dir.path().join("other");
    std::fs::create_dir_all(other.join("node_modules")).unwrap();
    maybe_warn_pkg_node_modules(&other.canonicalize().unwrap(), "c", false, &mut warned);
    assert_eq!(warned.len(), 2);
}

#[test]
fn maybe_warn_pkg_node_modules_json_output_suppresses_set_update() {
    // Under json_output=true, the helper short-circuits before
    // touching the set — the warning text would never reach the
    // user, so set tracking is moot. Documents the
    // current implementation's contract.
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("node_modules")).unwrap();
    let mut warned = std::collections::HashSet::new();
    maybe_warn_pkg_node_modules(
        &src.canonicalize().unwrap(),
        "a",
        true, // json_output
        &mut warned,
    );
    assert!(
        warned.is_empty(),
        "json_output=true must short-circuit (no set update)",
    );
}

#[test]
fn maybe_warn_pkg_node_modules_no_op_when_no_node_modules() {
    // If the source dir has NO node_modules subdir, the set is
    // not touched (no warn fires).
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    let mut warned = std::collections::HashSet::new();
    maybe_warn_pkg_node_modules(&src.canonicalize().unwrap(), "a", false, &mut warned);
    assert!(warned.is_empty());
}

#[tokio::test]
async fn pre_resolve_passes_through_supported_specifier_variants() {
    // SemverRange / NpmAlias / Workspace flow through unchanged —
    // the pre-resolve gate only rejects unsupported source shapes.
    // Tarball is consumed and removed from `deps` here; covered by a
    // separate test.
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());

    let mut deps = HashMap::from([
        ("react".to_string(), "^19.0.0".to_string()),
        (
            "strip-ansi-cjs".to_string(),
            "npm:strip-ansi@^6.0.1".to_string(),
        ),
        ("my-pkg".to_string(), "workspace:*".to_string()),
        ("legacy".to_string(), "1.2.3".to_string()),
    ]);
    let install_pkgs = pre_resolve_non_registry_deps(
        &client,
        &store,
        store_root.path(),
        &mut deps,
        true,
        false,
        &[],
    )
    .await
    .expect("supported specs must pass through unchanged")
    .install_pkgs;
    assert!(install_pkgs.is_empty(), "no tarball deps to extract");
    assert_eq!(deps.len(), 4, "all 4 supported deps must remain in the map");
}
