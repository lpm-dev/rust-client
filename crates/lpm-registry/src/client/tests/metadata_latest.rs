use super::*;
use crate::UpstreamRoute;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn latest_document(name: &str, version: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name, "version": version,
        "dist": {"tarball": "https://example.invalid/pkg.tgz", "integrity": "sha512-test"}
    })
}

#[tokio::test]
async fn latest_cache_is_separate_from_history_and_cleared_by_package_invalidation() {
    let server = MockServer::start().await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().to_path_buf()))
        .with_synchronous_cache_writes(true)
        .clone_with_metadata_memory_cache();
    Mock::given(method("GET"))
        .and(path("/@scope/pkg/latest"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(latest_document("@scope/pkg", "2.0.0")),
        )
        .expect(2)
        .mount(&server)
        .await;
    let first = client
        .get_npm_latest_metadata_direct_with_timings("@scope/pkg")
        .await
        .unwrap();
    assert_eq!(
        first.metadata.dist_tags.get("latest").map(String::as_str),
        Some("2.0.0")
    );
    assert!(
        client
            .get_npm_latest_metadata_direct_with_timings("@scope/pkg")
            .await
            .unwrap()
            .timings
            .cache_hit
    );
    assert!(
        client
            .npm_metadata_memory_cache("@scope/pkg", &UpstreamRoute::NpmDirect)
            .is_none()
    );
    assert!(
        client
            .read_metadata_cache(&client.npm_direct_metadata_cache_key("@scope/pkg"))
            .is_none()
    );
    client.invalidate_metadata_cache("@scope/pkg");
    assert!(
        !client
            .get_npm_latest_metadata_direct_with_timings("@scope/pkg")
            .await
            .unwrap()
            .timings
            .cache_hit
    );
}

#[tokio::test]
async fn latest_revalidates_its_own_etag_without_pin_to_a_concrete_version() {
    let server = MockServer::start().await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().to_path_buf()))
        .with_synchronous_cache_writes(true);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"latest-2\"")
                .insert_header("cache-control", "max-age=0")
                .set_body_json(latest_document("pkg", "2.0.0")),
        )
        .expect(1)
        .mount(&server)
        .await;
    client
        .get_npm_latest_metadata_direct_with_timings("pkg")
        .await
        .unwrap();
    server.verify().await;
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .and(header("if-none-match", "\"latest-2\""))
        .respond_with(ResponseTemplate::new(304).insert_header("cache-control", "max-age=0"))
        .expect(1)
        .mount(&server)
        .await;
    let revalidated = client
        .get_npm_latest_metadata_direct_with_timings("pkg")
        .await
        .unwrap();
    assert!(revalidated.timings.not_modified);
    server.verify().await;
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .and(header("if-none-match", "\"latest-2\""))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("cache-control", "max-age=60")
                .set_body_json(latest_document("pkg", "3.0.0")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let changed = client
        .get_npm_latest_metadata_direct_with_timings("pkg")
        .await
        .unwrap();
    assert_eq!(changed.metadata.latest_version_tag(), Some("3.0.0"));
}

#[tokio::test]
async fn latest_no_store_response_is_not_reused() {
    let server = MockServer::start().await;
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().to_path_buf()))
        .with_synchronous_cache_writes(true);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("cache-control", "no-store")
                .set_body_json(latest_document("pkg", "2.0.0")),
        )
        .expect(2)
        .mount(&server)
        .await;
    for _ in 0..2 {
        assert!(
            !client
                .get_npm_latest_metadata_direct_with_timings("pkg")
                .await
                .unwrap()
                .timings
                .cache_hit
        );
    }
    assert!(
        client
            .read_metadata_cache(&client.npm_direct_latest_metadata_cache_key("pkg"))
            .is_none()
    );
}

#[tokio::test]
async fn latest_rejects_wrong_identity_and_invalid_versions() {
    let server = MockServer::start().await;
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(None);
    for body in [
        latest_document("wrong", "2.0.0"),
        latest_document("pkg", "not-a-version"),
    ] {
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            client
                .get_npm_latest_metadata_direct_with_timings("pkg")
                .await
                .is_err()
        );
        server.verify().await;
    }
}
