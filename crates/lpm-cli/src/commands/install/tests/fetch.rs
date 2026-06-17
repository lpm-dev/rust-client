use super::*;

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

    let (computed_sri, timings, final_url) =
        fetch_and_store_tarball_url(&client, &store, None, &pkg, 0, install_pkg_acquire_permit())
            .await
            .expect("tarball install must succeed");

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

    let (computed_sri, _, _) =
        fetch_and_store_tarball_url(&client, &store, None, &pkg, 0, install_pkg_acquire_permit())
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

    let (computed_sri, _, _) =
        fetch_and_store_tarball_url(&client, &store, Some(&store_v2), &pkg, 0, permit)
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
    assert_eq!(semaphore.available_permits(), 1);
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

    let result =
        fetch_and_store_tarball_url(&client, &store, None, &pkg, 0, install_pkg_acquire_permit())
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

    let (sri1, _, _) =
        fetch_and_store_tarball_url(&client, &store, None, &pkg, 0, install_pkg_acquire_permit())
            .await
            .unwrap();
    let cas_path = store.tarball_store_path(&sri1).unwrap();
    let mtime1 = std::fs::metadata(cas_path.join("package.json"))
        .unwrap()
        .modified()
        .unwrap();

    let (sri2, _, _) =
        fetch_and_store_tarball_url(&client, &store, None, &pkg, 0, install_pkg_acquire_permit())
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

    speculative_download_and_store(
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
    )
    .await
    .expect("speculative v2 download must succeed");

    assert!(
        store_v2
            .reusable_object_dir(&expected_sri)
            .unwrap()
            .is_some(),
        "speculation must populate the v2 object store"
    );
    assert_eq!(semaphore.available_permits(), 1);
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

    let (computed_sri, _, final_url) =
        fetch_and_store_tarball_url(&client, &store, None, &pkg, 0, install_pkg_acquire_permit())
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
