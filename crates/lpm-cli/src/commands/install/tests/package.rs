use super::*;

#[test]
fn install_package_source_kind_parses_tarball() {
    let pkg = install_package_for_tarball("https://e.com/foo.tgz", None);
    match pkg.source_kind() {
        Ok(lpm_lockfile::Source::Tarball { url }) => {
            assert_eq!(url, "https://e.com/foo.tgz");
        }
        other => panic!("expected Source::Tarball, got {other:?}"),
    }
}

#[test]
fn install_package_source_kind_parses_registry() {
    let mut pkg = install_package_for_tarball("ignored", None);
    pkg.source = "registry+https://registry.npmjs.org".to_string();
    match pkg.source_kind() {
        Ok(lpm_lockfile::Source::Registry { url }) => {
            assert_eq!(url, "https://registry.npmjs.org");
        }
        other => panic!("expected Source::Registry, got {other:?}"),
    }
}

// ── invariant: prevent silent source substitution ───────
// A registry-CAS hit at (name, version) must not fulfill a
// Source::Tarball dep with the same name+version. These tests lock the
// source-aware existence and path contracts that prevent it.

fn build_minimal_tarball_with_pkg(name: &str, version: &str) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let pkg_json = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        let body = pkg_json.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", body)
            .unwrap();
        builder.finish().unwrap();
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn prevalidate_v2_reusable_objects_returns_verified_registry_hits() {
    let _env = crate::test_env::ScopedEnv::update([("LPM_V2_OBJECT_INTEGRITY", None)]);
    let dir = tempfile::tempdir().unwrap();
    let store = lpm_store::v2::Store::at(dir.path().join("store"));
    let tarball = build_minimal_tarball_with_pkg("cache-hit", "1.0.0");
    let (object_dir, sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();

    let mut pkg = fake_pkg("cache-hit", "1.0.0", true);
    pkg.integrity = Some(sri);
    let key = install_pkg_key(&pkg);

    let prevalidation = prevalidate_v2_reusable_objects(&[pkg], std::sync::Arc::new(store))
        .await
        .unwrap();

    assert_eq!(prevalidation.candidate_count, 1);
    assert_eq!(prevalidation.hits.len(), 1);
    assert!(prevalidation.concurrency >= 1);
    assert_eq!(prevalidation.validation_timings.checked_count, 1);
    assert_eq!(prevalidation.validation_timings.hit_count, 1);
    assert_eq!(
        prevalidation.validation_timings.object_sidecar_read_count,
        1
    );
    assert_eq!(prevalidation.validation_timings.snapshot_hit_count, 0);
    let hit = prevalidation
        .hits
        .get(&key)
        .expect("prevalidation must return the v2 object hit");
    assert_eq!(hit.path, object_dir);
    assert!(hit.object_integrity.as_str().starts_with("sha256-"));
}

#[tokio::test]
async fn prevalidate_v2_reusable_objects_source_policy_trusts_tampered_registry_objects() {
    let _env = crate::test_env::ScopedEnv::update([("LPM_V2_OBJECT_INTEGRITY", None)]);
    let dir = tempfile::tempdir().unwrap();
    let store = lpm_store::v2::Store::at(dir.path().join("store"));
    let tarball = build_minimal_tarball_with_pkg("tampered", "1.0.0");
    let (object_dir, sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();
    std::fs::write(
        object_dir.join("package.json"),
        br#"{"name":"tampered","version":"1.0.0","changed":true}"#,
    )
    .unwrap();

    let mut pkg = fake_pkg("tampered", "1.0.0", true);
    pkg.integrity = Some(sri);

    let prevalidation = prevalidate_v2_reusable_objects(&[pkg], std::sync::Arc::new(store))
        .await
        .unwrap();

    assert_eq!(prevalidation.candidate_count, 1);
    assert_eq!(prevalidation.hits.len(), 1);
    assert_eq!(prevalidation.validation_timings.checked_count, 1);
    assert_eq!(prevalidation.validation_timings.hit_count, 1);
    assert_eq!(prevalidation.validation_timings.removed_count, 0);
    assert!(object_dir.exists());
}

#[tokio::test]
async fn prevalidate_v2_reusable_objects_tree_policy_removes_tampered_registry_objects() {
    let _env = crate::test_env::ScopedEnv::set([(
        "LPM_V2_OBJECT_INTEGRITY",
        std::ffi::OsString::from("tree"),
    )]);
    let dir = tempfile::tempdir().unwrap();
    let store = lpm_store::v2::Store::at(dir.path().join("store"));
    let tarball = build_minimal_tarball_with_pkg("tampered-tree", "1.0.0");
    let (object_dir, sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();
    std::fs::write(
        object_dir.join("package.json"),
        br#"{"name":"tampered-tree","version":"1.0.0","changed":true}"#,
    )
    .unwrap();

    let mut pkg = fake_pkg("tampered-tree", "1.0.0", true);
    pkg.integrity = Some(sri);

    let prevalidation = prevalidate_v2_reusable_objects(&[pkg], std::sync::Arc::new(store))
        .await
        .unwrap();

    assert_eq!(prevalidation.candidate_count, 1);
    assert!(prevalidation.hits.is_empty());
    assert_eq!(prevalidation.validation_timings.checked_count, 1);
    assert_eq!(prevalidation.validation_timings.miss_count, 1);
    assert_eq!(prevalidation.validation_timings.removed_count, 1);
    assert!(
        !object_dir.exists(),
        "tree policy must remove tampered v2 objects before cache reuse"
    );
}

#[test]
fn v2_link_task_concurrency_caps_large_warm_relink_batches() {
    let _env = crate::test_env::ScopedEnv::update([("LPM_V2_LINK_TASKS", None)]);
    let concurrency = v2_link_task_concurrency(1309);

    assert!(concurrency <= V2_LINK_TASK_MAX_CONCURRENCY);
    assert!(concurrency < 1309);
}

#[test]
fn v2_link_task_concurrency_uses_positive_env_override() {
    let _env = crate::test_env::ScopedEnv::set([("LPM_V2_LINK_TASKS", "4".into())]);

    assert_eq!(v2_link_task_concurrency(1309), 4);
    assert_eq!(v2_link_task_concurrency(2), 2);
}

#[test]
fn v2_link_task_concurrency_ignores_invalid_env_override() {
    let _env = crate::test_env::ScopedEnv::set([("LPM_V2_LINK_TASKS", "0".into())]);

    let concurrency = v2_link_task_concurrency(1309);

    assert!(concurrency <= V2_LINK_TASK_MAX_CONCURRENCY);
    assert!(concurrency > 0);
}

#[test]
fn store_has_source_aware_does_not_accept_registry_for_tarball_pkg() {
    // Construct: a registry-CAS entry exists at (name, version).
    // A Source::Tarball InstallPackage with the *same* (name,
    // version) but a different content/integrity must NOT be
    // satisfied by the registry copy.
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    // Pre-populate the registry slot at (react, 19.0.0).
    let registry_tarball = build_minimal_tarball_with_pkg("react", "19.0.0");
    store
        .store_package("react", "19.0.0", &registry_tarball)
        .unwrap();
    assert!(store.has_package("react", "19.0.0"));

    // Different content, different integrity. This is the
    // declared tarball-source identity.
    let tarball_content = build_minimal_tarball_with_pkg("react", "19.0.0");
    let tarball_sri = Integrity::from_bytes(HashAlgorithm::Sha512, b"different bytes").to_string();

    let mut pkg = install_package_for_tarball("https://e.com/react.tgz", Some(&tarball_sri));
    pkg.name = "react".to_string();
    pkg.version = "19.0.0".to_string();

    // Previously bug: store.has_package(name, version) == true →
    // install would mark cached + spawn link from registry CAS.
    // Post-fix: source-aware check sees Source::Tarball, looks
    // up by integrity, finds nothing → fetch must run.
    assert!(
        !pkg.store_has_source_aware(&store, dir.path()),
        "registry CAS hit at (react, 19.0.0) MUST NOT satisfy a Source::Tarball pkg \
         with different integrity (silent-substitution prevention)"
    );
    let _ = tarball_content; // keep variable alive for the test scope
}

#[test]
fn store_has_source_aware_uses_tarball_cas_when_integrity_present() {
    // Positive: when the same tarball SRI IS in the CAS, the
    // source-aware check returns true.
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let tarball = build_minimal_tarball_with_pkg("foo", "1.0.0");
    let sri = Integrity::from_bytes(HashAlgorithm::Sha512, &tarball).to_string();
    store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
    assert!(store.has_tarball(&sri));

    let mut pkg = install_package_for_tarball("https://e.com/foo.tgz", Some(&sri));
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();

    assert!(pkg.store_has_source_aware(&store, dir.path()));
}

#[test]
fn store_has_source_aware_trust_on_first_use_returns_false() {
    // Pre-fetch trust-on-first-use: integrity is None. Even if
    // a registry CAS hit exists at (name, version), the source-
    // aware check must return false so the fetch runs and
    // computes the SRI.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    // Pre-populate the registry slot.
    let registry_tarball = build_minimal_tarball_with_pkg("foo", "1.0.0");
    store
        .store_package("foo", "1.0.0", &registry_tarball)
        .unwrap();

    // Source::Tarball with NO integrity (trust-on-first-use).
    let mut pkg = install_package_for_tarball("https://e.com/foo.tgz", None);
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();

    assert!(
        !pkg.store_has_source_aware(&store, dir.path()),
        "trust-on-first-use must always force a fetch — the registry CAS hit \
         must NOT satisfy a Source::Tarball pkg without recorded integrity"
    );
}

#[test]
fn store_has_source_aware_local_tarball_uses_tarball_local_subtree() {
    // follow-up: parallel coverage for the
    // store_has_source_aware routing fix. A local-tarball
    // package with content stored in `tarball-local/` must
    // return true; a registry CAS hit at (name, version) for
    // the same name/version must NOT satisfy it.
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let body = build_minimal_tarball_with_pkg("foo", "1.0.0");
    let sri = Integrity::from_bytes(HashAlgorithm::Sha256, &body).to_string();
    let hex = sri_to_sha256_hex(&sri).expect("sha256 SRI must convert to hex");

    // Pre-populate ONLY the local-tarball subtree.
    store.store_local_tarball_at_cas_path(&hex, &body).unwrap();
    assert!(store.has_local_tarball(&hex));
    // Registry CAS slot is empty.
    assert!(!store.has_package("foo", "1.0.0"));

    let mut pkg = install_package_for_tarball("file:./foo.tgz", Some(&sri));
    pkg.source = "tarball+file:./foo.tgz".to_string();
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();
    pkg.tarball_url = None;

    assert!(
        pkg.store_has_source_aware(&store, dir.path()),
        "local-tarball CAS hit must satisfy store_has_source_aware",
    );
}

#[test]
fn store_has_source_aware_local_tarball_remote_subtree_does_not_satisfy() {
    // Inverse of the above: a hit in the REMOTE-tarball subtree
    // (`v1/tarball/...`) at the same SRI must NOT satisfy a
    // local-tarball package. The two subtrees are disjoint by
    // identity (URL is part of the remote arm's identity, content-
    // only for the local arm), so cross-arm satisfaction would
    // re-open the silent-substitution gap.
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let body = build_minimal_tarball_with_pkg("foo", "1.0.0");
    let sri = Integrity::from_bytes(HashAlgorithm::Sha256, &body).to_string();

    // Populate ONLY the remote-tarball subtree.
    store.store_tarball_at_cas_path(&sri, &body).unwrap();
    assert!(store.has_tarball(&sri));
    // local-tarball subtree empty.
    let hex = sri_to_sha256_hex(&sri).unwrap();
    assert!(!store.has_local_tarball(&hex));

    let mut pkg = install_package_for_tarball("file:./foo.tgz", Some(&sri));
    pkg.source = "tarball+file:./foo.tgz".to_string();
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();
    pkg.tarball_url = None;

    assert!(
        !pkg.store_has_source_aware(&store, dir.path()),
        "remote-tarball CAS hit must NOT satisfy a Source::Tarball {{ file:... }} pkg",
    );
}

#[test]
fn store_path_source_aware_routes_tarball_to_cas_path() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let sri = Integrity::from_bytes(HashAlgorithm::Sha512, b"some content").to_string();
    let mut pkg = install_package_for_tarball("https://e.com/foo.tgz", Some(&sri));
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();

    let path = pkg
        .store_path_source_aware(&store, dir.path(), None)
        .unwrap();
    let expected = store.tarball_store_path(&sri).unwrap();
    assert_eq!(path, expected);
    // Critical: NOT the registry CAS path.
    assert_ne!(path, store.package_dir("foo", "1.0.0"));
}

#[test]
fn store_path_source_aware_returns_none_for_tarball_without_integrity() {
    // If Source::Tarball without integrity returned a fallback to
    // package_dir(name, version), the linker would silently link from the
    // registry CAS slot. Returning None forces callers to explicitly handle
    // the missing-integrity case.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let mut pkg = install_package_for_tarball("https://e.com/foo.tgz", None);
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();

    assert!(
        pkg.store_path_source_aware(&store, dir.path(), None)
            .is_none(),
        "Source::Tarball without integrity must return None, NOT a registry-CAS fallback"
    );
}

#[test]
fn store_path_source_aware_sri_override_wins_over_recorded_integrity() {
    // Post-fetch: the freshly-computed SRI overrides any stale
    // value in p.integrity. Used by the dispatch site to point
    // the linker at the just-stored CAS dir.
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let stale_sri = Integrity::from_bytes(HashAlgorithm::Sha512, b"stale").to_string();
    let fresh_sri = Integrity::from_bytes(HashAlgorithm::Sha512, b"fresh").to_string();

    let mut pkg = install_package_for_tarball("https://e.com/foo.tgz", Some(&stale_sri));
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();

    let path_with_override = pkg
        .store_path_source_aware(&store, dir.path(), Some(&fresh_sri))
        .unwrap();
    let expected = store.tarball_store_path(&fresh_sri).unwrap();
    assert_eq!(path_with_override, expected);
}

#[test]
fn store_path_source_aware_routes_local_tarball_to_tarball_local_subtree() {
    // follow-up: a `Source::Tarball` whose URL
    // is `file:...` (local-file tarball) must route to the
    // `tarball-local/` CAS subtree, NOT the remote-tarball
    // `tarball/` subtree. Without this, 's pre_resolve
    // extracts to `v1/tarball-local/sha256-{hex}/` but the
    // post-resolve link-target builder looks in `v1/tarball/
    // sha256-{hex}/` and fails with "missing dir" at link time.
    //
    // The integrity SRI is the SAME bytes either way (sha256 of
    // the tarball content); only the subtree differs.
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let body = b"local-tarball-content";
    let sri = Integrity::from_bytes(HashAlgorithm::Sha256, body).to_string();
    let hex: String = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(body);
        format!("{:x}", h.finalize())
    };

    let mut pkg = install_package_for_tarball("file:./foo.tgz", Some(&sri));
    pkg.source = "tarball+file:./foo.tgz".to_string();
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();
    pkg.tarball_url = None; // local tarballs have no remote URL

    let path = pkg
        .store_path_source_aware(&store, dir.path(), None)
        .unwrap();
    let expected = store.tarball_local_store_path(&hex).unwrap();
    assert_eq!(
        path, expected,
        "file: tarball must route to v1/tarball-local/, got {path:?}",
    );
    // Critical: NOT the remote-tarball CAS path.
    assert_ne!(path, store.tarball_store_path(&sri).unwrap());
    // Critical: NOT the registry CAS path either.
    assert_ne!(path, store.package_dir("foo", "1.0.0"));
}

#[test]
fn store_path_or_err_returns_typed_error_for_local_tarball_without_sri() {
    // Same invariant as the remote-tarball arm: a `Source::Tarball`
    // package (local OR remote) reaching a path-resolution site
    // without an SRI is a programmer error.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let mut pkg = install_package_for_tarball("file:./foo.tgz", None);
    pkg.source = "tarball+file:./foo.tgz".to_string();
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();
    pkg.tarball_url = None;

    let err = pkg
        .store_path_or_err(&store, dir.path(), None)
        .expect_err("missing-SRI local tarball must produce a typed error");
    let msg = err.to_string();
    assert!(msg.contains("foo") && msg.contains("1.0.0"), "got: {msg}");
}

#[test]
fn store_path_source_aware_local_tarball_sri_override_wins() {
    // Symmetric with the remote arm — a freshly-computed SRI
    // (post-fetch) overrides any recorded value. For local
    // tarballs the SRI is the content hash of the just-read
    // bytes, so the override case is rare in practice but the
    // contract should still hold.
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let stale_sri = Integrity::from_bytes(HashAlgorithm::Sha256, b"stale").to_string();
    let fresh_sri = Integrity::from_bytes(HashAlgorithm::Sha256, b"fresh").to_string();
    let fresh_hex: String = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"fresh");
        format!("{:x}", h.finalize())
    };

    let mut pkg = install_package_for_tarball("file:./foo.tgz", Some(&stale_sri));
    pkg.source = "tarball+file:./foo.tgz".to_string();
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();
    pkg.tarball_url = None;

    let path = pkg
        .store_path_source_aware(&store, dir.path(), Some(&fresh_sri))
        .unwrap();
    assert_eq!(path, store.tarball_local_store_path(&fresh_hex).unwrap());
}

#[test]
fn store_path_source_aware_registry_unaffected_by_override() {
    // Registry sources ignore sri_override entirely (the override
    // is meaningless for their identity model).
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let mut pkg = install_package_for_tarball("ignored", Some("ignored"));
    pkg.source = "registry+https://registry.npmjs.org".to_string();
    pkg.name = "react".to_string();
    pkg.version = "19.0.0".to_string();

    let path = pkg
        .store_path_source_aware(&store, dir.path(), Some("sha512-doesntmatter"))
        .unwrap();
    assert_eq!(path, store.package_dir("react", "19.0.0"));
}

// ── (reviewed): store_path_or_err typed-error path ────────

#[test]
fn store_path_or_err_returns_typed_error_for_tarball_without_sri() {
    // The typed-error variant: a Source::Tarball pkg with neither
    // an override nor a recorded integrity yields an LpmError::Registry
    // naming the package, not a panic. Replaces the four `.expect()`
    // call sites in the install pipeline with `?` propagation.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let mut pkg = install_package_for_tarball("https://e.com/foo.tgz", None);
    pkg.name = "foo".to_string();
    pkg.version = "1.0.0".to_string();

    let err = pkg
        .store_path_or_err(&store, dir.path(), None)
        .expect_err("missing-SRI tarball source must produce a typed error");
    let msg = err.to_string();
    assert!(
        msg.contains("foo") && msg.contains("1.0.0"),
        "error must name the offending package, got: {msg}"
    );
    assert!(
        msg.contains("install-source"),
        "error should cite the invariant context, got: {msg}"
    );
}

#[test]
fn store_path_or_err_succeeds_when_sri_recorded() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let sri = Integrity::from_bytes(HashAlgorithm::Sha512, b"x").to_string();
    let pkg = install_package_for_tarball("https://e.com/foo.tgz", Some(&sri));

    let path = pkg
        .store_path_or_err(&store, dir.path(), None)
        .expect("recorded integrity must yield a valid CAS path");
    assert_eq!(path, store.tarball_store_path(&sri).unwrap());
}

#[test]
fn store_path_or_err_succeeds_with_override() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let fresh = Integrity::from_bytes(HashAlgorithm::Sha512, b"fresh").to_string();
    let pkg = install_package_for_tarball("https://e.com/foo.tgz", None);

    let path = pkg
        .store_path_or_err(&store, dir.path(), Some(&fresh))
        .expect("override must satisfy the SRI requirement");
    assert_eq!(path, store.tarball_store_path(&fresh).unwrap());
}

#[test]
fn store_path_or_err_registry_never_errors() {
    // Registry sources have no SRI requirement at this layer —
    // store_path_or_err always returns Ok for them.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path());

    let mut pkg = install_package_for_tarball("ignored", None);
    pkg.source = "registry+https://registry.npmjs.org".to_string();
    pkg.name = "react".to_string();
    pkg.version = "19.0.0".to_string();

    let path = pkg
        .store_path_or_err(&store, dir.path(), None)
        .expect("registry sources must always succeed");
    assert_eq!(path, store.package_dir("react", "19.0.0"));
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

#[test]
fn tarball_wrapper_id_distinguishes_integrity_pins_for_the_same_url() {
    let mut first = install_package_for_tarball("https://example.com/react.tgz", None);
    first.integrity = Some("sha512-AAAAAAAA".to_string());
    let mut second = first.clone();
    second.integrity = Some("sha512-BBBBBBBB".to_string());

    assert_ne!(
        first.wrapper_id_for_source(),
        second.wrapper_id_for_source(),
        "declared content pins must split wrapper identity even when the URL is unchanged"
    );
}

// ── cross-source collision regression ───────────────────
// A Source::Tarball pkg and a Source::Registry pkg with the same
// (name, version) must produce distinct PackageKeys so the install-pipeline's
// bookkeeping (FetchCoordinator, fresh_urls, integrity_map,
// root_link_map) can attach state to the right package.

#[test]
fn install_pkg_key_distinguishes_integrity_pins_for_the_same_url() {
    let mut first = install_package_for_tarball("https://example.com/react.tgz", None);
    first.integrity = Some("sha512-AAAAAAAA".to_string());
    let mut second = first.clone();
    second.integrity = Some("sha512-BBBBBBBB".to_string());

    assert_ne!(
        install_pkg_key(&first),
        install_pkg_key(&second),
        "fetch bookkeeping must not merge different content pins for one URL"
    );
}

#[test]
fn build_v2_targets_selects_integrity_by_source_wrapper_identity() {
    let mut first = install_package_for_tarball("https://example.com/react.tgz", None);
    first.integrity = Some("sha512-AAAAAAAA".to_string());
    let mut second = first.clone();
    second.integrity = Some("sha512-BBBBBBBB".to_string());

    let link_target = |package: &InstallPackage| LinkTarget {
        name: package.name.clone(),
        version: package.version.clone(),
        store_path: PathBuf::from("unused"),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        is_direct: true,
        root_link_names: None,
        wrapper_id: package.wrapper_id_for_source(),
        materialization: lpm_linker::Materialization::CasBacked,
        peers: Vec::new(),
        patch_fingerprint: None,
    };
    let targets = build_v2_targets(
        &[first.clone(), second.clone()],
        &[link_target(&first), link_target(&second)],
    )
    .expect("source-distinct targets must retain their own integrity");

    assert_eq!(targets[0].source_sri, "sha512-AAAAAAAA");
    assert_eq!(targets[1].source_sri, "sha512-BBBBBBBB");
}

#[test]
fn install_pkg_key_distinguishes_registry_from_tarball_with_same_name_version() {
    // Construct both halves of the collision case:
    // - a registry react@19.0.0 (the fork's parent)
    // - a tarball-URL react@19.0.0 (the fork itself)
    // They share (name, version) but differ in source — install_pkg_key
    // embeds the full source string so they produce distinct keys.
    let mut registry_pkg = install_package_for_tarball("ignored", None);
    registry_pkg.name = "react".to_string();
    registry_pkg.version = "19.0.0".to_string();
    registry_pkg.source = "registry+https://registry.npmjs.org".to_string();

    let mut tarball_pkg = install_package_for_tarball(
        "https://e.com/forks-of-react.tgz",
        Some("sha512-fakesha512contentdoesntmatterforthistest=="),
    );
    tarball_pkg.name = "react".to_string();
    tarball_pkg.version = "19.0.0".to_string();

    let reg_key = install_pkg_key(&registry_pkg);
    let tar_key = install_pkg_key(&tarball_pkg);

    // Same (name, version), distinct source → distinct compound keys.
    assert_ne!(
        reg_key, tar_key,
        "same name+version from different sources must produce distinct install keys"
    );
    assert!(
        reg_key.contains("registry+https://registry.npmjs.org"),
        "registry key must embed the registry source URL"
    );
    assert!(
        tar_key.contains("tarball+https://e.com/forks-of-react.tgz"),
        "tarball key must embed the tarball URL"
    );
}

#[test]
fn dedupe_install_packages_by_identity_merges_workspace_reentry_source_graph() {
    let mut resolver_pkg = install_package_for_tarball("ignored", None);
    resolver_pkg.name = "@smoke/cycle-b".to_string();
    resolver_pkg.version = "1.0.0".to_string();
    resolver_pkg.source = "directory+../../packages/cycle-b".to_string();
    resolver_pkg.root_link_names = None;
    resolver_pkg.is_direct = false;
    resolver_pkg.tarball_url = None;

    let mut source_graph_pkg = resolver_pkg.clone();
    source_graph_pkg.dependencies = vec![("@smoke/cycle-a".to_string(), "f-cycle-a".to_string())];
    source_graph_pkg.root_link_names = Some(Vec::new());

    let mut packages = vec![resolver_pkg, source_graph_pkg];
    dedupe_install_packages_by_identity(&mut packages);

    assert_eq!(
        packages.len(),
        1,
        "same name/version/source package reached through resolver re-entry and source graph must collapse before linking"
    );
    assert_eq!(
        packages[0].dependencies,
        vec![("@smoke/cycle-a".to_string(), "f-cycle-a".to_string())],
        "merged package must retain source-graph dependencies"
    );
    assert_eq!(
        packages[0].root_link_names.as_deref(),
        Some(&[][..]),
        "merged transitive workspace package must stay off root links"
    );
}

#[test]
fn explicit_file_install_package_becomes_typed_peer_provider() {
    let mut package = install_package_for_tarball("ignored", None);
    package.name = "react".to_string();
    package.version = "18.3.1".to_string();
    package.source = "directory+./packages/react".to_string();
    package.root_link_names = Some(vec!["react".to_string()]);
    package.is_direct = true;

    let providers = explicit_peer_providers_from_install_packages([&package]).unwrap();

    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].local_name, "react");
    assert_eq!(providers[0].package_name, "react");
    assert_eq!(providers[0].version.to_string(), "18.3.1");
    assert_eq!(
        providers[0].source,
        lpm_resolver::PeerProviderSource::File("packages/react".to_string())
    );
}

#[test]
fn non_semver_source_package_can_be_indexed_as_an_explicit_peer_provider() {
    let mut package = install_package_for_tarball("ignored", None);
    package.name = "private-react".to_string();
    package.version = "dev".to_string();
    package.source = "directory+./packages/private-react".to_string();
    package.root_link_names = Some(vec!["private-react".to_string()]);
    package.is_direct = true;

    let providers = explicit_peer_providers_from_install_packages([&package])
        .expect("an unrelated private source package must not require a semver version");

    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].version.to_string(), "dev");
}
