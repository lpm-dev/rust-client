use super::*;

#[test]
fn locked_provenance_name_index_preserves_prefixes_and_scopes() {
    let evidence = lpm_lockfile::LockedProvenance {
        snapshot: lpm_common::ProvenanceSnapshot {
            present: true,
            ..Default::default()
        },
        subject_name: "pkg:npm/foobar@1.0.0".to_string(),
        subject_sha512: "00".repeat(64),
        integrated_time_secs: 1,
        log_id: "log".to_string(),
        log_index: 1,
        bundle_sha256: format!("sha256-{}", "00".repeat(32)),
    };
    let provenance = std::collections::BTreeMap::from([
        (
            "foobar@1.0.0#r-0123456789abcdef".to_string(),
            evidence.clone(),
        ),
        (
            "@scope/widget@2.0.0#r-fedcba9876543210".to_string(),
            evidence,
        ),
    ]);
    let names = locked_provenance_names(&provenance);

    assert!(names.contains("foobar"));
    assert!(names.contains("@scope/widget"));
    assert!(!names.contains("foo"));
    assert!(!names.contains("widget"));
}

#[test]
fn speculative_picker_uses_slim_metadata_for_dist_tags_and_transitive_deps() {
    let slim = SpeculativePackageMetadata::from(registry_metadata(serde_json::json!({
        "name": "fixture",
        "description": "large field that speculation does not need",
        "readme": "also intentionally dropped",
        "dist-tags": {
            "latest": "2.0.0"
        },
        "versions": {
            "1.0.0": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": {
                    "left-pad": "^1.0.0"
                },
                "dist": {
                    "tarball": "https://registry.example/fixture-1.0.0.tgz",
                    "integrity": "sha512-one"
                }
            },
            "2.0.0": {
                "name": "fixture",
                "version": "2.0.0",
                "dependencies": {
                    "chalk": "^5.0.0"
                },
                "dist": {
                    "tarball": "https://registry.example/fixture-2.0.0.tgz",
                    "integrity": "sha512-two"
                }
            }
        }
    })));

    assert_eq!(
        pick_speculative_version(&slim, "latest"),
        Some((
            "2.0.0".to_string(),
            "https://registry.example/fixture-2.0.0.tgz".to_string(),
            Some("sha512-two".to_string()),
        ))
    );
    assert_eq!(
        pick_speculative_version(&slim, "^1.0.0"),
        Some((
            "1.0.0".to_string(),
            "https://registry.example/fixture-1.0.0.tgz".to_string(),
            Some("sha512-one".to_string()),
        ))
    );
    assert_eq!(
        slim.info
            .deps
            .get("1.0.0")
            .and_then(|dependencies| dependencies.get("left-pad")),
        Some(&"^1.0.0".to_string())
    );
}

#[test]
fn speculative_dependency_enqueue_rewrites_aliases_and_skips_optional_deps() {
    let slim = SpeculativePackageMetadata::from(registry_metadata(serde_json::json!({
        "name": "fixture",
        "dist-tags": {
            "latest": "1.0.0"
        },
        "versions": {
            "1.0.0": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": {
                    "plain": "^1.0.0",
                    "alias-local": "npm:alias-target@^2.0.0"
                },
                "optionalDependencies": {
                    "optional-only": "^3.0.0"
                },
                "dist": {
                    "tarball": "https://registry.example/fixture-1.0.0.tgz",
                    "integrity": "sha512-one"
                }
            }
        }
    })));
    let mut queue = Vec::new();

    push_regular_speculative_dependencies(&slim, "1.0.0", 2, &mut queue);

    let actual: std::collections::BTreeSet<_> = queue.into_iter().collect();
    let expected = std::collections::BTreeSet::from([
        ("alias-target".to_string(), "^2.0.0".to_string(), 2, false),
        ("plain".to_string(), "^1.0.0".to_string(), 2, false),
    ]);
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn managed_lpm_stale_url_retry_preserves_the_accounting_marker() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let body = build_test_tarball();
    let integrity = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();
    let server = MockServer::start().await;
    let stale_url = format!("{}/stale.tgz", server.uri());
    let fresh_url = format!("{}/fresh.tgz", server.uri());

    Mock::given(method("GET"))
        .and(path("/stale.tgz"))
        .and(header(
            lpm_registry::MANAGED_INSTALL_ACCOUNTING_HEADER,
            lpm_registry::MANAGED_INSTALL_ACCOUNTING_VERSION,
        ))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/acme.pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "@lpm.dev/acme.pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "@lpm.dev/acme.pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": fresh_url,
                        "integrity": integrity,
                    },
                },
            },
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fresh.tgz"))
        .and(header(
            lpm_registry::MANAGED_INSTALL_ACCOUNTING_HEADER,
            lpm_registry::MANAGED_INSTALL_ACCOUNTING_VERSION,
        ))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("test-token")
            .with_cache_dir(None),
    );
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let store_root = tempfile::tempdir().expect("store root");
    let store = PackageStore::at(store_root.path());
    let mut package = fake_pkg("@lpm.dev/acme.pkg", "1.0.0", true);
    package.source = format!("registry+{}", server.uri());
    package.is_lpm = true;
    package.integrity = Some(integrity);
    package.tarball_url = Some(stale_url);
    package.metadata_checked_for_tarball = true;
    let gate_stats = Arc::new(GateStats::default());

    let (_, _, final_url, _) = fetch_and_store_legacy(
        &client,
        &route_table,
        &store,
        None,
        &package,
        0,
        ArtifactSelection::LockfileReplay,
        &gate_stats,
        install_pkg_acquire_permit(),
        &None,
        ManagedInstallAccounting,
    )
    .await
    .expect("managed stale URL recovery should succeed");

    assert_eq!(final_url, fresh_url);
}

#[tokio::test]
async fn tarball_url_install_trust_on_first_use_lands_in_cas_path() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let body = build_test_tarball();
    let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let pkg = install_package_for_tarball(&url, None);

    let (computed_sri, timings, final_url, fresh_object) = fetch_and_store_tarball_url(
        &client,
        &store,
        None,
        &pkg,
        0,
        install_pkg_acquire_permit(),
        &None,
    )
    .await
    .expect("tarball install must succeed");
    assert!(
        fresh_object.is_none(),
        "v1 tarball install must not report a v2 fresh object"
    );

    // Returned SRI matches an independent SHA-512 of the bytes.
    assert_eq!(computed_sri, expected_sri);
    // The URL we actually fetched is what we report back (no
    // redirect rewriting — contract).
    assert_eq!(final_url, url);
    // Tarball is materialized at the CAS path keyed by integrity.
    assert!(store.has_tarball(&computed_sri));
    let cas_path = store.tarball_store_path(&computed_sri).unwrap();
    assert!(cas_path.join("package.json").exists());
    assert!(cas_path.join(".integrity").exists());
    // Timings sanity: url_lookup is exactly 0 (we never round-
    // tripped to a registry — that's the structural guarantee
    // of fetch_and_store_tarball_url).
    assert_eq!(timings.url_lookup_ms, 0);
}

#[tokio::test]
async fn tarball_url_install_match_succeeds() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let body = build_test_tarball();
    let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let pkg = install_package_for_tarball(&url, Some(&expected_sri));

    let (computed_sri, _, _, _) = fetch_and_store_tarball_url(
        &client,
        &store,
        None,
        &pkg,
        0,
        install_pkg_acquire_permit(),
        &None,
    )
    .await
    .expect("matching SRI must succeed");
    assert_eq!(computed_sri, expected_sri);
    assert!(store.has_tarball(&computed_sri));
}

#[tokio::test]
async fn tarball_url_install_v2_extracts_object() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let body = build_test_tarball();
    let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store_v2_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let store_v2 = lpm_store::v2::Store::at(store_v2_root.path());
    let client = Arc::new(RegistryClient::new());
    let pkg = install_package_for_tarball(&url, Some(&expected_sri));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore
        .clone()
        .try_acquire_owned()
        .expect("permit must be available in test setup");

    let (computed_sri, _, _, fresh_object) =
        fetch_and_store_tarball_url(&client, &store, Some(&store_v2), &pkg, 0, permit, &None)
            .await
            .expect("v2 tarball install must succeed");

    assert_eq!(computed_sri, expected_sri);
    assert!(
        store_v2
            .reusable_object_dir(&computed_sri)
            .unwrap()
            .is_some(),
        "v2 tarball install must populate the object store"
    );
    assert!(
        fresh_object.is_some(),
        "v2 tarball install must return the freshly extracted object"
    );
    assert_eq!(semaphore.available_permits(), 1);
}

#[tokio::test]
async fn buffered_download_keeps_its_slot_until_extraction_can_start() {
    let download_semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let download_permit = download_semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("download semaphore must remain open");
    let extract_semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let held_extract_permit = extract_semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("extract semaphore must remain open");
    let limiter = Some(extract_semaphore);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();

    let handoff = tokio::spawn(async move {
        started_tx
            .send(())
            .expect("handoff test receiver must remain alive");
        handoff_buffered_download_to_extract(download_permit, &limiter).await
    });
    started_rx
        .await
        .expect("handoff task must reach the extraction wait");
    tokio::task::yield_now().await;

    assert_eq!(download_semaphore.available_permits(), 0);

    drop(held_extract_permit);
    let (extract_permit, _) = handoff
        .await
        .expect("handoff task must not panic")
        .expect("handoff must succeed");
    assert_eq!(download_semaphore.available_permits(), 1);
    assert!(extract_permit.is_some());
}

#[tokio::test]
async fn tarball_url_install_v2_returns_canonical_sri_for_sha256_declaration() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let body = build_test_tarball();
    let declared_sri = Integrity::from_bytes(HashAlgorithm::Sha256, &body).to_string();
    let canonical_sri = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store_v2_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let store_v2 = lpm_store::v2::Store::at(store_v2_root.path());
    let client = Arc::new(RegistryClient::new());
    let pkg = install_package_for_tarball(&url, Some(&declared_sri));

    let (computed_sri, _, _, fresh_object) = fetch_and_store_tarball_url(
        &client,
        &store,
        Some(&store_v2),
        &pkg,
        0,
        install_pkg_acquire_permit(),
        &None,
    )
    .await
    .expect("v2 tarball install must accept matching sha256 declarations");

    assert_eq!(computed_sri, canonical_sri);
    assert!(
        store_v2
            .reusable_object_dir(&computed_sri)
            .unwrap()
            .is_some(),
        "v2 object lookups must use the canonical sha512 SRI"
    );
    assert!(
        fresh_object.is_some(),
        "v2 sha256-declared tarballs must still produce a fresh object for event-driven linking"
    );
}

#[tokio::test]
async fn tarball_url_install_mismatch_errors_no_extraction() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let body = build_test_tarball();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    // invariant: algo-aware verifier parses the
    // expected SRI before comparing, so the fixture must be a
    // valid sha512 SRI of *different* content (the realistic
    // threat: lockfile drift). used malformed base64
    // which slipped through string-compare.
    let wrong_sri = Integrity::from_bytes(HashAlgorithm::Sha512, b"different content").to_string();

    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let pkg = install_package_for_tarball(&url, Some(&wrong_sri));

    let result = fetch_and_store_tarball_url(
        &client,
        &store,
        None,
        &pkg,
        0,
        install_pkg_acquire_permit(),
        &None,
    )
    .await;

    assert!(
        matches!(result, Err(LpmError::IntegrityMismatch { .. })),
        "expected IntegrityMismatch, got {result:?}"
    );

    // Nothing stored: a mismatch must NOT leave a half-written
    // CAS entry. The store dir for the wrong (impossible to
    // compute) SRI doesn't exist; more importantly, no entry
    // exists for the legitimate SRI either, since we never
    // proceeded past the integrity check.
    let store_v1 = store_root.path().join("v1").join("tarball");
    // Either the tarball/ subtree is absent entirely, or it
    // exists but is empty — both are valid post-mismatch states
    // (the parent dir might be created during path computation
    // depending on filesystem semantics, but no CAS entry should
    // be present).
    if store_v1.exists() {
        let entries: Vec<_> = std::fs::read_dir(&store_v1).unwrap().collect();
        assert!(
            entries.is_empty(),
            "no CAS entry must be left after integrity mismatch: {entries:?}"
        );
    }
}

#[tokio::test]
async fn tarball_url_install_cache_hit_skips_redundant_download() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let body = build_test_tarball();
    let server = MockServer::start().await;
    // expect(2) — first install fetches; second hits the
    // already-stored CAS path. download_tarball_with_integrity
    // doesn't itself dedupe (the store does), so the network
    // request count actually goes up to 2 here. The win is at
    // the *extract* layer: the second store_tarball_at_cas_path
    // call is a fast-path return. (A future might
    // add a pre-fetch CAS-existence check; not in 5b's scope.)
    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let pkg = install_package_for_tarball(&url, None);

    let (sri1, _, _, _) = fetch_and_store_tarball_url(
        &client,
        &store,
        None,
        &pkg,
        0,
        install_pkg_acquire_permit(),
        &None,
    )
    .await
    .unwrap();
    let cas_path = store.tarball_store_path(&sri1).unwrap();
    let mtime1 = std::fs::metadata(cas_path.join("package.json"))
        .unwrap()
        .modified()
        .unwrap();

    let (sri2, _, _, _) = fetch_and_store_tarball_url(
        &client,
        &store,
        None,
        &pkg,
        0,
        install_pkg_acquire_permit(),
        &None,
    )
    .await
    .unwrap();
    assert_eq!(sri1, sri2);
    let mtime2 = std::fs::metadata(cas_path.join("package.json"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        mtime1, mtime2,
        "second install must hit the existing CAS dir, not re-extract"
    );
}

#[tokio::test]
async fn speculative_v2_download_extracts_object() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let body = build_test_tarball();
    let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let url = format!("{}/foo.tgz", server.uri());

    let store_root = tempfile::tempdir().unwrap();
    let store_v2_root = tempfile::tempdir().unwrap();
    let client = Arc::new(RegistryClient::new().with_npm_registry_url(server.uri()));
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let store = PackageStore::at(store_root.path());
    let store_v2 = lpm_store::v2::Store::at(store_v2_root.path());
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let speculation_semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let coord = Arc::new(FetchCoordinator::default());

    let outcome = speculative_download_and_store(
        &client,
        &route_table,
        &store,
        Some(&store_v2),
        &semaphore,
        Some(&speculation_semaphore),
        &coord,
        "test-tarball-pkg",
        "1.0.0",
        &url,
        Some(&expected_sri),
        &None,
        ManagedInstallAccounting,
    )
    .await
    .expect("speculative v2 download must succeed");
    assert_eq!(outcome, SpeculativeFetchOutcome::Stored);

    assert!(
        store_v2
            .reusable_object_dir(&expected_sri)
            .unwrap()
            .is_some(),
        "speculation must populate the v2 object store"
    );
    assert_eq!(semaphore.available_permits(), 1);
}

#[test]
fn registry_speculation_key_matches_install_package_key() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let mut package = install_package_for_tarball("ignored", None);
    package.name = "react".to_string();
    package.version = "19.0.0".to_string();
    package.source = "registry+https://registry.npmjs.org".to_string();

    assert_eq!(
        registry_install_pkg_key(
            &package.name,
            &package.version,
            &route_table,
            &RegistryClient::new(),
        ),
        install_pkg_key(&package)
    );
}

#[test]
fn canonical_cached_registry_tarball_url_uses_unscoped_archive_name_for_scoped_npm() {
    let client = RegistryClient::new();
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);

    assert_eq!(
        canonical_cached_registry_tarball_url(
            &client,
            &route_table,
            "@types/node",
            "20.0.0",
            false,
        )
        .as_deref(),
        Some("https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz"),
    );
}

#[test]
fn canonical_cached_registry_tarball_url_uses_package_archive_name_for_lpm() {
    let client = RegistryClient::new();
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);

    assert_eq!(
        canonical_cached_registry_tarball_url(
            &client,
            &route_table,
            "@lpm.dev/owner.react",
            "1.0.0",
            true,
        )
        .as_deref(),
        Some("https://lpm.dev/api/registry/@lpm.dev/owner.react/-/react-1.0.0.tgz"),
    );
}

#[tokio::test]
async fn resolve_tarball_url_trusts_canonical_cached_npm_url_without_metadata_lookup() {
    let server = wiremock::MockServer::start().await;
    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let cached_url = format!("{}/left-pad/-/left-pad-1.0.0.tgz", server.uri());

    let resolved = resolve_tarball_url(
        &client,
        &route_table,
        "left-pad",
        "1.0.0",
        false,
        Some(&cached_url),
        false,
    )
    .await
    .expect("canonical cached URL should not need registry metadata");

    assert_eq!(resolved.url, cached_url);
}

#[tokio::test]
async fn resolve_tarball_url_trusts_canonical_cached_lpm_url_without_metadata_lookup() {
    let server = wiremock::MockServer::start().await;
    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(server.uri())
            .with_cache_dir(None),
    );
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let cached_url = format!(
        "{}/api/registry/@lpm.dev/owner.react/-/react-1.0.0.tgz",
        server.uri()
    );

    let resolved = resolve_tarball_url(
        &client,
        &route_table,
        "@lpm.dev/owner.react",
        "1.0.0",
        true,
        Some(&cached_url),
        false,
    )
    .await
    .expect("canonical cached LPM URL should not need registry metadata");

    assert_eq!(resolved.url, cached_url);
}

#[tokio::test]
async fn resolve_tarball_url_verifies_noncanonical_cached_url_against_metadata() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = wiremock::MockServer::start().await;
    let metadata_url = format!("{}/left-pad/-/left-pad-1.0.0.tgz", server.uri());
    let cached_url = format!("{}/tarballs/left-pad/-/left-pad-1.0.0.tgz", server.uri());
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "left-pad",
            "dist-tags": {
                "latest": "1.0.0"
            },
            "versions": {
                "1.0.0": {
                    "name": "left-pad",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": metadata_url,
                        "integrity": "sha512-test"
                    }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let err = match resolve_tarball_url(
        &client,
        &route_table,
        "left-pad",
        "1.0.0",
        false,
        Some(&cached_url),
        false,
    )
    .await
    {
        Ok(resolved) => panic!(
            "non-canonical cached URL must still be checked against metadata, got {}",
            resolved.url
        ),
        Err(err) => err,
    };

    assert!(
        err.to_string().contains("does not match registry metadata"),
        "metadata mismatch error should be preserved, got: {err}"
    );
}

// ── : redirect handling ────────────────────────────────
// The lockfile records the *declared* URL, not
// the final-redirect target. The integrity is computed from the
// bytes that actually arrive (post-redirect), and that's what
// gets recorded in the source identity.

#[test]
fn fetch_coordinator_does_not_serialize_cross_source_collision() {
    // FetchCoordinator was the highest-impact bookkeeping bug:
    // pre-, two Sources of the same (name, version) shared
    // a fetch lock and serialized for no reason. Post-,
    // distinct keys → distinct locks → parallel fetch.
    let coord = FetchCoordinator::default();

    let mut registry_pkg = install_package_for_tarball("ignored", None);
    registry_pkg.name = "react".to_string();
    registry_pkg.version = "19.0.0".to_string();
    registry_pkg.source = "registry+https://registry.npmjs.org".to_string();

    let mut tarball_pkg = install_package_for_tarball(
        "https://e.com/forks-of-react.tgz",
        Some("sha512-fakeshacontentdoesntmatterforthistest=="),
    );
    tarball_pkg.name = "react".to_string();
    tarball_pkg.version = "19.0.0".to_string();

    // Drive lock acquisition synchronously via a runtime —
    // the coordinator's API is async but the test only needs
    // the per-key Arc ID comparison.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let lock_a = coord.lock_for(install_pkg_key(&registry_pkg)).await;
        let lock_b = coord.lock_for(install_pkg_key(&tarball_pkg)).await;
        // Distinct source-string keys → distinct locks. We compare by
        // pointer identity (Arc::as_ptr) — same key would yield
        // the SAME Arc; different keys yield different Arcs.
        assert!(
            !Arc::ptr_eq(&lock_a, &lock_b),
            "registry react@19.0.0 and tarball react@19.0.0 must NOT share a fetch lock"
        );
    });
}

#[tokio::test]
async fn tarball_url_install_handles_301_redirect() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = build_test_tarball();
    let sri = Integrity::from_bytes(HashAlgorithm::Sha512, &body).to_string();

    // /foo.tgz redirects to /actual.tgz.
    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("Location", format!("{}/actual.tgz", server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/actual.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let declared_url = format!("{}/foo.tgz", server.uri());
    let store_root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(store_root.path());
    let client = Arc::new(RegistryClient::new());
    let pkg = install_package_for_tarball(&declared_url, None);

    let (computed_sri, _, final_url, _) = fetch_and_store_tarball_url(
        &client,
        &store,
        None,
        &pkg,
        0,
        install_pkg_acquire_permit(),
        &None,
    )
    .await
    .expect("redirect must be followed");

    // Bytes arrived: SRI matches independent calc on the final
    // body (proves redirect was followed and content is right).
    assert_eq!(computed_sri, sri);
    // Identity preserves the DECLARED URL, not the redirect target.
    // Lockfile identity freezes content (via integrity) plus the
    // user-controlled URL, not the redirect path.
    assert_eq!(
        final_url, declared_url,
        "final_url must report the declared URL, not the redirect target"
    );
    // Tarball lands in CAS keyed by the computed SRI of the
    // final-body content.
    assert!(store.has_tarball(&computed_sri));
}
