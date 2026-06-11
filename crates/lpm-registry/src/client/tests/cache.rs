use super::*;

#[test]
fn cache_roundtrip_with_etag() {
    let (client, _tmp) = client_with_temp_cache();
    let meta = test_metadata("@lpm.dev/test.pkg");
    let etag = "\"abc123\"";

    client.write_metadata_cache("test-key", &meta, Some(etag));
    let result = client.read_metadata_cache("test-key");

    assert!(result.is_some(), "cache read should succeed");
    let (read_meta, read_etag) = result.unwrap();
    assert_eq!(read_meta.name, "@lpm.dev/test.pkg");
    assert_eq!(read_etag.as_deref(), Some("\"abc123\""));
}

#[test]
fn cache_roundtrip_without_etag() {
    let (client, _tmp) = client_with_temp_cache();
    let meta = test_metadata("@lpm.dev/test.no-etag");

    client.write_metadata_cache("no-etag-key", &meta, None);
    let result = client.read_metadata_cache("no-etag-key");

    assert!(result.is_some(), "cache read should succeed without etag");
    let (read_meta, read_etag) = result.unwrap();
    assert_eq!(read_meta.name, "@lpm.dev/test.no-etag");
    assert!(read_etag.is_none(), "etag should be None when not stored");
}

#[test]
fn cache_survives_new_client_process_boundary() {
    let (writer, _tmp) = client_with_temp_cache();
    let meta = test_metadata("@lpm.dev/test.restart");

    writer.write_metadata_cache("restart-key", &meta, Some("\"restart-etag\""));

    let mut reader = RegistryClient::new();
    reader.cache_dir = writer.cache_dir;

    let result = reader.read_metadata_cache("restart-key");

    assert!(
        result.is_some(),
        "cache entries should remain readable across fresh client instances"
    );
    let (read_meta, read_etag) = result.unwrap();
    assert_eq!(read_meta.name, "@lpm.dev/test.restart");
    assert_eq!(read_etag.as_deref(), Some("\"restart-etag\""));
}

#[test]
fn old_format_cache_treated_as_miss() {
    let (client, _tmp) = client_with_temp_cache();

    // Synthesize an old-format entry: 64-char hex HMAC line + JSON
    // payload. The exact HMAC bytes don't matter — the new reader
    // never reaches HMAC verification because the magic check at the
    // top fails first.
    if let Some(path) = client.cache_path("old-format-key") {
        let json_data = r#"{"name":"old","versions":{}}"#;
        let fake_hmac = "0".repeat(64);
        let old_content = format!("{fake_hmac}\n{json_data}");
        std::fs::write(&path, old_content).unwrap();
    }

    let result = client.read_metadata_cache("old-format-key");
    assert!(
        result.is_none(),
        "old HMAC-format cache must be treated as a miss after the magic-header switch"
    );
}

#[test]
fn cache_miss_on_truncated_or_unmagic_content() {
    let (client, _tmp) = client_with_temp_cache();
    if let Some(path) = client.cache_path("garbage-key") {
        std::fs::write(&path, b"not-a-real-cache-file").unwrap();
    }
    assert!(
        client.read_metadata_cache("garbage-key").is_none(),
        "non-magic content must be rejected"
    );

    // Truncated magic — header started but never finished.
    if let Some(path) = client.cache_path("trunc-key") {
        std::fs::write(&path, b"LPM-MD").unwrap();
    }
    assert!(
        client.read_metadata_cache("trunc-key").is_none(),
        "truncated magic must be rejected"
    );
}

#[test]
fn read_cache_content_returns_etag_and_data() {
    let (client, _tmp) = client_with_temp_cache();
    let meta = test_metadata("@lpm.dev/test.etag-read");

    client.write_metadata_cache("etag-read-key", &meta, Some("W/\"xyz789\""));
    let content = client.read_cache_content("etag-read-key");
    assert!(content.is_some(), "cache content should be present");
    let content = content.unwrap();
    assert_eq!(content.etag.as_deref(), Some("W/\"xyz789\""));
    // Verify the data can be deserialized
    let deserialized: PackageMetadata = rmp_serde::from_slice(&content.data)
        .or_else(|_| serde_json::from_slice(&content.data))
        .expect("data should deserialize");
    assert_eq!(deserialized.name, "@lpm.dev/test.etag-read");
}

#[test]
fn read_cache_content_returns_none_etag_when_no_etag() {
    let (client, _tmp) = client_with_temp_cache();
    let meta = test_metadata("@lpm.dev/test.no-etag-read");

    client.write_metadata_cache("no-etag-read-key", &meta, None);
    let content = client.read_cache_content("no-etag-read-key");
    assert!(
        content.is_some(),
        "cache content should be present even without etag"
    );
    assert!(content.unwrap().etag.is_none());
}

#[test]
fn cache_miss_on_nonexistent_key() {
    let (client, _tmp) = client_with_temp_cache();
    let result = client.read_metadata_cache("nonexistent-key");
    assert!(result.is_none());
}

#[test]
fn messagepack_roundtrip_preserves_all_fields() {
    let (client, _tmp) = client_with_temp_cache();
    let mut meta = test_metadata("@lpm.dev/test.fields");
    meta.description = Some("A test package with fields".to_string());
    meta.downloads = Some(9999);
    meta.distribution_mode = Some("pool".to_string());
    meta.ecosystem = Some("node".to_string());

    client.write_metadata_cache("fields-key", &meta, Some("\"v1\""));
    let (read_meta, _) = client.read_metadata_cache("fields-key").unwrap();

    assert_eq!(read_meta.name, meta.name);
    assert_eq!(read_meta.description, meta.description);
    assert_eq!(read_meta.downloads, meta.downloads);
    assert_eq!(read_meta.distribution_mode, meta.distribution_mode);
    assert_eq!(read_meta.ecosystem, meta.ecosystem);
    assert_eq!(
        read_meta.dist_tags.get("latest"),
        Some(&"1.0.0".to_string())
    );
}

#[tokio::test]
async fn etag_304_revalidation_lpm_metadata() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let pkg_name = "@lpm.dev/test.etag-pkg";
    let body = test_metadata_json(pkg_name);

    // First request: server returns 200 + ETag + body
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-pkg"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(&body)
                .append_header("ETag", "\"v1-abc123\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    let name = PackageName::parse(pkg_name).unwrap();
    let result = client.get_package_metadata(&name).await;
    assert!(result.is_ok(), "first fetch should succeed");
    let meta = result.unwrap();
    assert_eq!(meta.name, pkg_name);

    // Expire the cache by setting mtime to 10 minutes ago
    if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    // Reset mocks for second request
    server.reset().await;

    // Second request: server sees If-None-Match, returns 304
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-pkg"))
        .and(header("If-None-Match", "\"v1-abc123\""))
        .respond_with(ResponseTemplate::new(304))
        .expect(1)
        .mount(&server)
        .await;

    let result2 = client.get_package_metadata(&name).await;
    assert!(result2.is_ok(), "304 revalidation should succeed");
    let meta2 = result2.unwrap();
    assert_eq!(meta2.name, pkg_name, "should return cached metadata on 304");
}

#[tokio::test]
async fn etag_updated_on_new_response() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let pkg_name = "@lpm.dev/test.etag-update";
    let body_v1 = test_metadata_json(pkg_name);

    // First request: returns with ETag v1
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-update"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(&body_v1)
                .append_header("ETag", "\"v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    let name = PackageName::parse(pkg_name).unwrap();
    client.get_package_metadata(&name).await.unwrap();

    // Expire cache
    if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    server.reset().await;

    // Second request: server rejects old ETag, returns new data + new ETag
    let body_v2 = serde_json::json!({
        "name": pkg_name,
        "description": "updated package",
        "latestVersion": "2.0.0",
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "2.0.0": {
                "name": pkg_name,
                "version": "2.0.0",
                "dist": {
                    "tarball": "https://example.com/pkg-2.0.0.tgz",
                    "integrity": "sha512-test2"
                },
                "dependencies": {}
            }
        }
    })
    .to_string();

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-update"))
        .and(header("If-None-Match", "\"v1\""))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(&body_v2)
                .append_header("ETag", "\"v2\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    let meta2 = client.get_package_metadata(&name).await.unwrap();
    assert_eq!(
        meta2.latest_version.as_deref(),
        Some("2.0.0"),
        "should return new metadata after ETag change"
    );

    // Verify cache now has v2 ETag
    let content = client.read_cache_content(&format!("lpm:{pkg_name}"));
    assert!(content.is_some());
    assert_eq!(
        content.unwrap().etag.as_deref(),
        Some("\"v2\""),
        "cache should store the new ETag"
    );
}

#[tokio::test]
async fn ttl_cache_hit_skips_http() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let pkg_name = "@lpm.dev/test.ttl-hit";
    let body = test_metadata_json(pkg_name);

    // First request: normal 200
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.ttl-hit"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(&body)
                .append_header("ETag", "\"fresh\""),
        )
        .expect(1) // MUST be called exactly once
        .mount(&server)
        .await;

    let name = PackageName::parse(pkg_name).unwrap();
    client.get_package_metadata(&name).await.unwrap();

    // Second request within TTL — should NOT hit the server (expect(1) enforces this)
    let result2 = client.get_package_metadata(&name).await;
    assert!(result2.is_ok(), "TTL cache hit should return immediately");
    assert_eq!(result2.unwrap().name, pkg_name);
}

#[tokio::test]
async fn npm_metadata_etag_304_revalidation() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let npm_name = "express";
    let body = test_metadata_json(npm_name);

    // First request via proxy path: 200 + ETag
    Mock::given(method("GET"))
        .and(path("/api/registry/express"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(&body)
                .append_header("ETag", "\"npm-v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_npm_package_metadata(npm_name).await;
    assert!(result.is_ok());

    // Expire cache
    if let Some(cache_path) = client.cache_path(&format!("npm:{npm_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    server.reset().await;

    // Second request: If-None-Match → 304
    Mock::given(method("GET"))
        .and(path("/api/registry/express"))
        .and(header("If-None-Match", "\"npm-v1\""))
        .respond_with(ResponseTemplate::new(304))
        .expect(1)
        .mount(&server)
        .await;

    let result2 = client.get_npm_package_metadata(npm_name).await;
    assert!(result2.is_ok(), "npm 304 revalidation should succeed");
    assert_eq!(result2.unwrap().name, npm_name);
}

#[tokio::test]
async fn etag_304_with_undecodable_cached_payload_refetches_lpm_metadata() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let pkg_name = "@lpm.dev/test.etag-refetch";
    let name = PackageName::parse(pkg_name).unwrap();

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-refetch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json(pkg_name))
                .append_header("ETag", "\"v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    client.get_package_metadata(&name).await.unwrap();

    let cache_path = client
        .cache_path(&format!("lpm:{pkg_name}"))
        .expect("cache path should exist");
    // Synthesize a magic-valid but undeserializable cache entry.
    // Magic passes → ETag extracted → payload fails msgpack/JSON decode
    // → caller drops the cached payload and refetches.
    let corrupted_data = b"not-valid-metadata";
    let mut corrupted_content = Vec::new();
    corrupted_content.extend_from_slice(METADATA_CACHE_MAGIC);
    corrupted_content.extend_from_slice(b"\"v1\"");
    corrupted_content.push(b'\n');
    corrupted_content.extend_from_slice(corrupted_data);
    std::fs::write(&cache_path, corrupted_content).unwrap();

    let past = filetime::FileTime::from_unix_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 600,
        0,
    );
    filetime::set_file_mtime(&cache_path, past).unwrap();

    server.reset().await;

    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_responder = Arc::clone(&request_count);
    let refreshed_body = serde_json::json!({
        "name": pkg_name,
        "description": "refetched package",
        "latestVersion": "2.0.0",
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "2.0.0": {
                "name": pkg_name,
                "version": "2.0.0",
                "dist": {
                    "tarball": "https://example.com/pkg-2.0.0.tgz",
                    "integrity": "sha512-refetched"
                },
                "dependencies": {}
            }
        }
    })
    .to_string();

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-refetch"))
        .respond_with(move |request: &wiremock::Request| {
            let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                assert_eq!(
                    request
                        .headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok()),
                    Some("\"v1\"")
                );
                ResponseTemplate::new(304)
            } else {
                assert!(request.headers.get("if-none-match").is_none());
                ResponseTemplate::new(200)
                    .set_body_string(refreshed_body.clone())
                    .append_header("ETag", "\"v2\"")
            }
        })
        .expect(2)
        .mount(&server)
        .await;

    let refreshed = client.get_package_metadata(&name).await.unwrap();
    assert_eq!(refreshed.latest_version.as_deref(), Some("2.0.0"));
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
    assert_eq!(
        client
            .read_cache_content(&format!("lpm:{pkg_name}"))
            .unwrap()
            .etag
            .as_deref(),
        Some("\"v2\"")
    );
}

#[tokio::test]
async fn npm_etag_304_with_undecodable_cached_payload_refetches_proxy_metadata() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let npm_name = "express-refetch";

    Mock::given(method("GET"))
        .and(path("/api/registry/express-refetch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json(npm_name))
                .append_header("ETag", "\"npm-v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    client.get_npm_package_metadata(npm_name).await.unwrap();

    let cache_path = client
        .cache_path(&format!("npm:{npm_name}"))
        .expect("npm cache path should exist");
    // Same shape as the matching synthesizer above (magic + ETag +
    // undeserializable bytes) applied to the npm proxy path.
    let corrupted_data = b"not-valid-npm-metadata";
    let mut corrupted_content = Vec::new();
    corrupted_content.extend_from_slice(METADATA_CACHE_MAGIC);
    corrupted_content.extend_from_slice(b"\"npm-v1\"");
    corrupted_content.push(b'\n');
    corrupted_content.extend_from_slice(corrupted_data);
    std::fs::write(&cache_path, corrupted_content).unwrap();

    let past = filetime::FileTime::from_unix_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 600,
        0,
    );
    filetime::set_file_mtime(&cache_path, past).unwrap();

    server.reset().await;

    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_responder = Arc::clone(&request_count);
    let refreshed_body = serde_json::json!({
        "name": npm_name,
        "description": "refetched proxy package",
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "2.0.0": {
                "name": npm_name,
                "version": "2.0.0",
                "dist": {
                    "tarball": "https://example.com/pkg-2.0.0.tgz",
                    "integrity": "sha512-refetched"
                },
                "dependencies": {}
            }
        }
    })
    .to_string();

    Mock::given(method("GET"))
        .and(path("/api/registry/express-refetch"))
        .respond_with(move |request: &wiremock::Request| {
            let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                assert_eq!(
                    request
                        .headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok()),
                    Some("\"npm-v1\"")
                );
                ResponseTemplate::new(304)
            } else {
                assert!(request.headers.get("if-none-match").is_none());
                ResponseTemplate::new(200)
                    .set_body_string(refreshed_body.clone())
                    .append_header("ETag", "\"npm-v2\"")
            }
        })
        .expect(2)
        .mount(&server)
        .await;

    let refreshed = client.get_npm_package_metadata(npm_name).await.unwrap();
    assert_eq!(refreshed.name, npm_name);
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
    assert_eq!(
        client
            .read_cache_content(&format!("npm:{npm_name}"))
            .unwrap()
            .etag
            .as_deref(),
        Some("\"npm-v2\"")
    );
}

#[tokio::test]
async fn etag_revalidation_retries_429_and_keeps_conditional_header() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let pkg_name = "@lpm.dev/test.etag-retry-429";
    let name = PackageName::parse(pkg_name).unwrap();

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-retry-429"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json(pkg_name))
                .append_header("ETag", "\"v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    client.get_package_metadata(&name).await.unwrap();

    if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    server.reset().await;

    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_responder = Arc::clone(&request_count);
    let refreshed_body = serde_json::json!({
        "name": pkg_name,
        "description": "revalidated after 429",
        "latestVersion": "2.0.0",
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "2.0.0": {
                "name": pkg_name,
                "version": "2.0.0",
                "dist": {
                    "tarball": "https://example.com/pkg-2.0.0.tgz",
                    "integrity": "sha512-retry"
                },
                "dependencies": {}
            }
        }
    })
    .to_string();

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-retry-429"))
        .respond_with(move |request: &wiremock::Request| {
            assert_eq!(
                request
                    .headers
                    .get("if-none-match")
                    .and_then(|value| value.to_str().ok()),
                Some("\"v1\"")
            );

            let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                ResponseTemplate::new(429).append_header("retry-after", "0")
            } else {
                ResponseTemplate::new(200)
                    .set_body_string(refreshed_body.clone())
                    .append_header("ETag", "\"v2\"")
            }
        })
        .expect(2)
        .mount(&server)
        .await;

    let refreshed = client.get_package_metadata(&name).await.unwrap();
    assert_eq!(refreshed.latest_version.as_deref(), Some("2.0.0"));
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn npm_etag_revalidation_retries_503_and_keeps_conditional_header() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let npm_name = "express-retry-503";

    Mock::given(method("GET"))
        .and(path("/api/registry/express-retry-503"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json(npm_name))
                .append_header("ETag", "\"npm-v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    client.get_npm_package_metadata(npm_name).await.unwrap();

    if let Some(cache_path) = client.cache_path(&format!("npm:{npm_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    server.reset().await;

    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_responder = Arc::clone(&request_count);
    let refreshed_body = serde_json::json!({
        "name": npm_name,
        "description": "proxy revalidated after 503",
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "2.0.0": {
                "name": npm_name,
                "version": "2.0.0",
                "dist": {
                    "tarball": "https://example.com/pkg-2.0.0.tgz",
                    "integrity": "sha512-retry"
                },
                "dependencies": {}
            }
        }
    })
    .to_string();

    Mock::given(method("GET"))
        .and(path("/api/registry/express-retry-503"))
        .respond_with(move |request: &wiremock::Request| {
            assert_eq!(
                request
                    .headers
                    .get("if-none-match")
                    .and_then(|value| value.to_str().ok()),
                Some("\"npm-v1\"")
            );

            let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                ResponseTemplate::new(503).set_body_string("temporary metadata outage")
            } else {
                ResponseTemplate::new(200)
                    .set_body_string(refreshed_body.clone())
                    .append_header("ETag", "\"npm-v2\"")
            }
        })
        .expect(2)
        .mount(&server)
        .await;

    let refreshed = client.get_npm_package_metadata(npm_name).await.unwrap();
    assert_eq!(refreshed.name, npm_name);
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn npm_etag_revalidation_exhausts_429_and_returns_rate_limited() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let npm_name = "express-rate-limited";

    Mock::given(method("GET"))
        .and(path("/api/registry/express-rate-limited"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json(npm_name))
                .append_header("ETag", "\"npm-v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    client.get_npm_package_metadata(npm_name).await.unwrap();

    if let Some(cache_path) = client.cache_path(&format!("npm:{npm_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    server.reset().await;

    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_responder = Arc::clone(&request_count);

    Mock::given(method("GET"))
        .and(path("/api/registry/express-rate-limited"))
        .respond_with(move |request: &wiremock::Request| {
            assert_eq!(
                request
                    .headers
                    .get("if-none-match")
                    .and_then(|value| value.to_str().ok()),
                Some("\"npm-v1\"")
            );
            request_count_for_responder.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(429).append_header("retry-after", "0")
        })
        .expect((MAX_RETRIES + 1) as u64)
        .mount(&server)
        .await;

    let result = client.get_npm_package_metadata(npm_name).await;
    match result {
        Err(LpmError::RateLimited { retry_after_secs }) => {
            assert_eq!(retry_after_secs, 0);
        }
        other => panic!("expected final rate-limit error, got {other:?}"),
    }

    assert_eq!(
        request_count.load(Ordering::SeqCst),
        (MAX_RETRIES + 1) as usize
    );
}

#[tokio::test]
async fn npm_etag_revalidation_exhausts_503_and_returns_http_error() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let npm_name = "express-http-503";

    Mock::given(method("GET"))
        .and(path("/api/registry/express-http-503"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json(npm_name))
                .append_header("ETag", "\"npm-v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    client.get_npm_package_metadata(npm_name).await.unwrap();

    if let Some(cache_path) = client.cache_path(&format!("npm:{npm_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    server.reset().await;

    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_responder = Arc::clone(&request_count);

    Mock::given(method("GET"))
        .and(path("/api/registry/express-http-503"))
        .respond_with(move |request: &wiremock::Request| {
            assert_eq!(
                request
                    .headers
                    .get("if-none-match")
                    .and_then(|value| value.to_str().ok()),
                Some("\"npm-v1\"")
            );
            request_count_for_responder.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(503).set_body_string("temporary proxy metadata outage")
        })
        .expect((MAX_RETRIES + 1) as u64)
        .mount(&server)
        .await;

    let result = client.get_npm_package_metadata(npm_name).await;
    match result {
        Err(LpmError::Http { status, message }) => {
            assert_eq!(status, 503);
            assert!(message.contains("temporary proxy metadata outage"));
        }
        other => panic!("expected final http error, got {other:?}"),
    }

    assert_eq!(
        request_count.load(Ordering::SeqCst),
        (MAX_RETRIES + 1) as usize
    );
}

#[tokio::test]
async fn etag_revalidation_exhausts_429_and_returns_rate_limited() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let pkg_name = "@lpm.dev/test.etag-rate-limited";
    let name = PackageName::parse(pkg_name).unwrap();

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-rate-limited"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json(pkg_name))
                .append_header("ETag", "\"v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    client.get_package_metadata(&name).await.unwrap();

    if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    server.reset().await;

    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_responder = Arc::clone(&request_count);

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-rate-limited"))
        .respond_with(move |request: &wiremock::Request| {
            assert_eq!(
                request
                    .headers
                    .get("if-none-match")
                    .and_then(|value| value.to_str().ok()),
                Some("\"v1\"")
            );
            request_count_for_responder.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(429).append_header("retry-after", "0")
        })
        .expect((MAX_RETRIES + 1) as u64)
        .mount(&server)
        .await;

    let result = client.get_package_metadata(&name).await;
    match result {
        Err(LpmError::RateLimited { retry_after_secs }) => {
            assert_eq!(retry_after_secs, 0);
        }
        other => panic!("expected final rate-limit error, got {other:?}"),
    }

    assert_eq!(
        request_count.load(Ordering::SeqCst),
        (MAX_RETRIES + 1) as usize
    );
}

#[tokio::test]
async fn etag_revalidation_exhausts_503_and_returns_http_error() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let pkg_name = "@lpm.dev/test.etag-http-503";
    let name = PackageName::parse(pkg_name).unwrap();

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-http-503"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json(pkg_name))
                .append_header("ETag", "\"v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    client.get_package_metadata(&name).await.unwrap();

    if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();
    }

    server.reset().await;

    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_responder = Arc::clone(&request_count);

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.etag-http-503"))
        .respond_with(move |request: &wiremock::Request| {
            assert_eq!(
                request
                    .headers
                    .get("if-none-match")
                    .and_then(|value| value.to_str().ok()),
                Some("\"v1\"")
            );
            request_count_for_responder.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(503).set_body_string("temporary metadata outage")
        })
        .expect((MAX_RETRIES + 1) as u64)
        .mount(&server)
        .await;

    let result = client.get_package_metadata(&name).await;
    match result {
        Err(LpmError::Http { status, message }) => {
            assert_eq!(status, 503);
            assert!(message.contains("temporary metadata outage"));
        }
        other => panic!("expected final http error, got {other:?}"),
    }

    assert_eq!(
        request_count.load(Ordering::SeqCst),
        (MAX_RETRIES + 1) as usize
    );
}

#[test]
fn with_cache_dir_some_path_roundtrips_across_clients() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cache_path = tmp.path().to_path_buf();

    // Client A writes a synthetic metadata entry into tmp.
    let client_a = RegistryClient::new().with_cache_dir(Some(cache_path.clone()));
    let pkg_name = "with-cache-dir-roundtrip";
    let metadata: PackageMetadata =
        serde_json::from_str(&test_metadata_json(pkg_name)).expect("parse test metadata");
    client_a.write_metadata_cache(&format!("npm:{pkg_name}"), &metadata, None);

    // Fresh client B pointed at the same dir reads it back.
    let client_b = RegistryClient::new().with_cache_dir(Some(cache_path));
    let (cached, _etag) = client_b
        .read_metadata_cache(&format!("npm:{pkg_name}"))
        .expect("fresh client with same cache_dir must read back the prior write");
    assert_eq!(
        cached.name, pkg_name,
        "round-tripped cache entry must preserve the package name"
    );
}

#[test]
fn oversized_metadata_cache_file_collapses_to_miss() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cache_dir = tmp.path().to_path_buf();
    let client = RegistryClient::new().with_cache_dir(Some(cache_dir));

    let pkg_name = "oversized-cache-file";
    let key = format!("npm:{pkg_name}");

    // Write a small valid entry first so the path exists.
    let metadata: PackageMetadata =
        serde_json::from_str(&test_metadata_json(pkg_name)).expect("parse test metadata");
    client.write_metadata_cache(&key, &metadata, None);
    let cache_file = client
        .cache_path(&key)
        .expect("cache_path resolves when cache_dir is configured");
    assert!(cache_file.exists(), "cache write must land on disk");

    // Truncate the file and pad it past the cap. We use the magic
    // header prefix so the rejection isn't simply due to a missing
    // magic byte — we want to prove the size check fires before
    // the magic comparison.
    let mut padding = METADATA_CACHE_MAGIC.to_vec();
    padding.extend(b"\n"); // empty ETag line
    padding.resize((METADATA_CACHE_FILE_CAP + 1024) as usize, b'x');
    std::fs::write(&cache_file, &padding).expect("rewrite cache file oversized");

    // Read must return None (cache miss).
    let result = client.read_metadata_cache(&key);
    assert!(
        result.is_none(),
        "oversized cache file must collapse to a miss"
    );

    // Same posture on the stale-conditional read path.
    let content = client.read_cache_content(&key);
    assert!(
        content.is_none(),
        "read_cache_content must also refuse oversized files"
    );
}

#[tokio::test]
async fn cache_partitions_per_auth_principal() {
    // The cache key includes an auth fingerprint so a fetch under
    // credential A cannot warm a cache entry that credential B (or
    // anonymous) would read without proving its own access.
    // Same URL + different tokens = distinct cache entries; each
    // principal's request hits the network even when another's
    // already populated the URL.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Two responses for the SAME URL — the test infrastructure can
    // pick which based on token, but we use simple matchers and
    // count requests instead. The key assertion is: each principal
    // hits the network on its first call, even though the URL is
    // identical.
    Mock::given(method("GET"))
        .and(path("/private-pkg"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json_with_version("private-pkg", "1.0.0")),
        )
        .expect(2) // CRITICAL: both principals must hit the network
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    let auth_a = bearer_for(&server.uri(), "TOKEN-A");
    let auth_b = bearer_for(&server.uri(), "TOKEN-B");

    // Principal A populates the cache.
    client
        .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth_a))
        .await
        .unwrap();
    // Principal B must NOT see A's cached entry.
    client
        .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth_b))
        .await
        .unwrap();
    // wiremock's `.expect(2)` enforces that both fetches hit the
    // network (verified at server drop). If the cache had served
    // B from A's entry, only 1 request would have arrived.
}

#[tokio::test]
async fn cache_warm_hit_with_same_auth() {
    // Defense-in-depth for the partitioning: identical credentials
    // MUST still produce a warm hit. Otherwise we've replaced one
    // bug with another (denying every warm hit on auth'd requests).
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/private-pkg"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json_with_version("private-pkg", "1.0.0")),
        )
        .expect(1) // exactly one network fetch despite two calls
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    let auth = bearer_for(&server.uri(), "TOKEN-A");
    // First call: miss → fetch.
    client
        .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth))
        .await
        .unwrap();
    // Second call same auth: warm hit.
    client
        .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth))
        .await
        .unwrap();
}

#[tokio::test]
async fn cache_anon_does_not_serve_to_authed_or_vice_versa() {
    // The most dangerous case: an anonymous fetch warming the cache
    // for a URL that requires auth. Or an authed fetch making the
    // anonymous principal think the URL is reachable. Both must
    // miss across the auth/no-auth boundary.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/private-pkg"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json_with_version("private-pkg", "1.0.0")),
        )
        .expect(2)
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    // First: anonymous.
    client
        .get_npm_metadata_from(&server.uri(), "private-pkg", None)
        .await
        .unwrap();
    // Second: authed. Must hit the network — anonymous's cache
    // entry doesn't satisfy us.
    let auth = bearer_for(&server.uri(), "TOKEN-X");
    client
        .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth))
        .await
        .unwrap();
}

#[tokio::test]
async fn invalidate_custom_metadata_cache_removes_authed_entry() {
    // The legacy `invalidate_metadata_cache(name)` can't reach
    // custom-registry entries whose key includes URL and auth fingerprint.
    // Test: write a custom-registry entry, invalidate via the new method,
    // confirm next read misses.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/some-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json("some-pkg")))
        .expect(2) // 1st write, 2nd post-invalidation refetch
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    let auth = bearer_for(&server.uri(), "TOKEN-X");

    // Populate.
    client
        .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
        .await
        .unwrap();

    // Legacy name-only invalidate must NOT find the custom entry —
    // otherwise the new method is redundant.
    client.invalidate_metadata_cache("some-pkg");
    // After legacy invalidate: still cached (warm hit).
    // We can't directly assert "1 network fetch so far" without
    // restructuring, so we rely on the `.expect(2)` total at end.

    // New method WITH the URL+auth must invalidate.
    client.invalidate_custom_metadata_cache(&server.uri(), "some-pkg", Some(&auth));
    // Next call: miss → fetch.
    client
        .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
        .await
        .unwrap();
}
