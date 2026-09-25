use super::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn history() -> serde_json::Value {
    serde_json::json!({
        "name": "shared-history",
        "versions": {
            "1.0.0": {"name": "shared-history", "version": "1.0.0", "os": ["linux"], "libc": ["glibc"], "dependencies": {"first": "1"}, "dist": {"integrity": "sha512-one"}},
            "2.0.0": {"name": "shared-history", "version": "2.0.0", "os": ["darwin"], "dependencies": {"second": "2"}, "dist": {"integrity": "sha512-two"}},
            "3.0.0": {"name": "shared-history", "version": "3.0.0", "cpu": ["arm64"]}
        },
        "time": {"1.0.0": "2025-01-01T00:00:00Z", "2.0.0": "2025-02-01T00:00:00Z"}
    })
}

async fn fetch(client: &RegistryClient, version: &str) -> TimedPackageMetadata {
    client
        .get_npm_version_from_history_with_timings("shared-history", version)
        .await
        .unwrap()
}

#[tokio::test]
async fn sequential_versions_reuse_one_history_without_merging_version_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared-history"))
        .and(header("accept", "application/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(history())
                .insert_header("Cache-Control", "max-age=300"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().into()))
        .with_synchronous_cache_writes(true);
    let first = fetch(&client, "1.0.0").await;
    let second = fetch(&client, "2.0.0").await;
    let third = fetch(&client, "3.0.0").await;
    assert_eq!(first.metadata.versions.len(), 1);
    assert_eq!(second.metadata.versions.len(), 1);
    assert_eq!(third.metadata.versions.len(), 1);
    assert_eq!(first.metadata.versions["1.0.0"].libc, ["glibc"]);
    assert_eq!(second.metadata.versions["2.0.0"].os, ["darwin"]);
    assert_eq!(
        second.metadata.versions["2.0.0"].dependencies["second"],
        "2"
    );
    assert_eq!(first.metadata.time["1.0.0"], "2025-01-01T00:00:00Z");
    assert_eq!(second.metadata.time["2.0.0"], "2025-02-01T00:00:00Z");
    assert!(first.timings.body_bytes > 0);
    assert_eq!(
        second.timings.body_bytes, 0,
        "reused bytes must not count as another download"
    );
    assert_eq!(third.timings.body_bytes, 0);
    server.verify().await;
}

#[tokio::test]
async fn concurrent_versions_coalesce_one_canonical_history_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared-history"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(30))
                .set_body_json(history())
                .insert_header("Cache-Control", "max-age=300"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().into()))
        .with_synchronous_cache_writes(true);
    let (first, second, third) = tokio::join!(
        fetch(&client, "1.0.0"),
        fetch(&client, "2.0.0"),
        fetch(&client, "3.0.0")
    );
    assert_eq!(
        [first, second, third]
            .iter()
            .filter(|item| item.timings.body_bytes > 0)
            .count(),
        1
    );
    server.verify().await;
}

#[tokio::test]
async fn histories_with_zero_freshness_are_not_reused_across_versions() {
    for directive in ["no-store", "no-cache", "max-age=0", "max-age=invalid"] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/shared-history"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(history())
                    .insert_header("Cache-Control", directive),
            )
            .expect(2)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(cache.path().into()));
        fetch(&client, "1.0.0").await;
        assert!(fetch(&client, "2.0.0").await.timings.body_bytes > 0);
        server.verify().await;
    }
}

#[tokio::test]
async fn package_and_version_invalidation_remove_reusable_histories() {
    for package_level in [true, false] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/shared-history"))
            .respond_with(ResponseTemplate::new(200).set_body_json(history()))
            .expect(2)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(cache.path().into()));
        fetch(&client, "1.0.0").await;
        if package_level {
            client.invalidate_metadata_cache("shared-history");
        } else {
            client.invalidate_npm_version_metadata_cache("shared-history", "1.0.0");
        }
        assert!(fetch(&client, "2.0.0").await.timings.body_bytes > 0);
        server.verify().await;
    }
}

#[tokio::test]
async fn reusable_histories_do_not_cross_registry_or_http_client_boundaries() {
    let first = MockServer::start().await;
    let second = MockServer::start().await;
    for (server, count) in [(&first, 2), (&second, 1)] {
        Mock::given(method("GET"))
            .and(path("/shared-history"))
            .respond_with(ResponseTemplate::new(200).set_body_json(history()))
            .expect(count)
            .mount(server)
            .await;
    }
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(first.uri())
        .with_cache_dir(Some(cache.path().into()));
    fetch(&client, "1.0.0").await;
    let other = client
        .clone_with_config()
        .with_npm_registry_url(second.uri());
    assert!(fetch(&other, "2.0.0").await.timings.body_bytes > 0);
    let other = client
        .clone_with_config()
        .with_tls_overrides_for(
            &TlsOverrides {
                strict_ssl: Some(crate::npmrc::TaggedBool {
                    value: false,
                    source: "test".into(),
                    line: 1,
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
    assert!(fetch(&other, "3.0.0").await.timings.body_bytes > 0);
    first.verify().await;
    second.verify().await;
}

#[tokio::test]
async fn reused_history_missing_a_version_falls_back_to_the_exact_document() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared-history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(history()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/shared-history/4.0.0"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"name":"shared-history","version":"4.0.0"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().into()));
    fetch(&client, "1.0.0").await;
    let missing = fetch(&client, "4.0.0").await;
    assert!(!missing.timings.selected_from_history);
    assert_eq!(missing.metadata.versions["4.0.0"].version, "4.0.0");
    server.verify().await;
}

#[tokio::test]
async fn in_flight_history_cannot_restore_reuse_after_invalidation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared-history"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(80))
                .set_body_json(history()),
        )
        .expect(2)
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().into()));
    let pending_client = client.clone_with_config();
    let pending = tokio::spawn(async move { fetch(&pending_client, "1.0.0").await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while server.received_requests().await.unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    client.invalidate_metadata_cache("shared-history");
    pending.await.unwrap();
    client.flush_pending_cache_writes().await;
    assert!(
        client
            .read_metadata_cache(&client.npm_selected_history_cache_key(
                "shared-history",
                "1.0.0",
                PublicNpmAccess::ANONYMOUS
            ))
            .is_none(),
        "a pre-invalidation response must not recreate a selected cache entry"
    );
    assert!(fetch(&client, "2.0.0").await.timings.body_bytes > 0);
    server.verify().await;
}

#[tokio::test]
async fn cancelled_history_fetch_releases_the_next_version_lookup() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared-history"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(80))
                .set_body_json(history()),
        )
        .expect(2)
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().into()));
    let pending_client = client.clone_with_config();
    let pending = tokio::spawn(async move { fetch(&pending_client, "1.0.0").await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while server.received_requests().await.unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    let next = tokio::time::timeout(Duration::from_secs(2), fetch(&client, "2.0.0"))
        .await
        .unwrap();
    assert!(next.timings.body_bytes > 0);
    server.verify().await;
}

#[tokio::test]
async fn reused_history_preserves_the_original_selected_cache_expiry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared-history"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(history())
                .insert_header("Cache-Control", "max-age=300"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().into()))
        .with_synchronous_cache_writes(true);
    fetch(&client, "1.0.0").await;
    let first_path = client
        .cache_path(&client.npm_selected_history_cache_key(
            "shared-history",
            "1.0.0",
            PublicNpmAccess::ANONYMOUS,
        ))
        .unwrap();
    let first_expiry = std::fs::metadata(first_path).unwrap().modified().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    fetch(&client, "2.0.0").await;
    let second_path = client
        .cache_path(&client.npm_selected_history_cache_key(
            "shared-history",
            "2.0.0",
            PublicNpmAccess::ANONYMOUS,
        ))
        .unwrap();
    let second_expiry = std::fs::metadata(second_path).unwrap().modified().unwrap();
    assert!(second_expiry <= first_expiry + Duration::from_millis(50));
    server.verify().await;
}

#[tokio::test]
async fn conditional_no_store_response_invalidates_reusable_canonical_history() {
    for status in [200, 304] {
        let server = MockServer::start().await;
        let responses = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&responses);
        Mock::given(method("GET"))
            .and(path("/shared-history"))
            .respond_with(move |request: &wiremock::Request| {
                let index = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if index == 1 {
                    assert!(request.headers.contains_key("if-none-match"));
                }
                if index == 1 && status == 304 {
                    return ResponseTemplate::new(304)
                        .insert_header("ETag", "\"history\"")
                        .insert_header("Cache-Control", "no-store");
                }
                ResponseTemplate::new(200)
                    .set_body_json(history())
                    .insert_header("ETag", "\"history\"")
                    .insert_header(
                        "Cache-Control",
                        if index == 1 {
                            "no-store"
                        } else {
                            "max-age=300"
                        },
                    )
            })
            .expect(3)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(cache.path().into()))
            .with_synchronous_cache_writes(true);
        fetch(&client, "1.0.0").await;
        let path = client
            .cache_path(&client.npm_selected_history_cache_key(
                "shared-history",
                "1.0.0",
                PublicNpmAccess::ANONYMOUS,
            ))
            .unwrap();
        filetime::set_file_mtime(
            path,
            filetime::FileTime::from_system_time(
                std::time::SystemTime::now() - Duration::from_secs(1),
            ),
        )
        .unwrap();
        fetch(&client, "1.0.0").await;
        assert!(
            fetch(&client, "3.0.0").await.timings.body_bytes > 0,
            "no-store response must remove reusable earlier canonical bytes"
        );
        server.verify().await;
    }
}
