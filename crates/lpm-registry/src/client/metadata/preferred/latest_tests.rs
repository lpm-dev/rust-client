use super::tests::{history, preferred_test_client};
use super::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn downloadable_history(server: &MockServer) -> serde_json::Value {
    let mut body = history();
    for version in ["1.0.0", "2.0.0"] {
        body["versions"][version]["dist"] = serde_json::json!({
            "tarball": format!("{}/pkg/-/pkg-{version}.tgz", server.uri()),
            "integrity": format!("sha512-{}==", "A".repeat(86))
        });
    }
    body
}

async fn mount_history(server: &MockServer, body: &serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn request_paths(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| request.url.path().to_owned())
        .collect()
}

#[tokio::test]
async fn resolver_preference_fetches_latest_without_history() {
    let server = MockServer::start().await;
    let mut body = history();
    let latest = &mut body["versions"]["2.0.0"];
    latest["dist"] = serde_json::json!({
        "tarball": format!("{}/pkg/-/pkg-2.0.0.tgz", server.uri()),
        "integrity": format!("sha512-{}==", "A".repeat(86))
    });
    latest["dependencies"] = serde_json::json!({"child": "^1.0.0"});
    latest["optionalDependencies"] = serde_json::json!({"optional": "^1.0.0"});
    latest["peerDependencies"] = serde_json::json!({"peer": "^1.0.0"});
    latest["engines"] = serde_json::json!({"node": ">=20"});
    latest["os"] = serde_json::json!(["linux"]);
    latest["cpu"] = serde_json::json!(["x64"]);
    latest["libc"] = serde_json::json!(["musl"]);
    latest["scripts"] = serde_json::json!({"install": "node install.js"});
    let expected: VersionMetadata = serde_json::from_value(latest.clone()).unwrap();
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(latest.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    let (selected, complete) = client
        .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |v| v == "2.0.0")
        .await
        .unwrap();
    assert!(!complete);
    assert_eq!(selected.metadata.versions.len(), 1);
    assert_eq!(
        serde_json::to_value(&selected.metadata.versions["2.0.0"]).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    let requests = server.received_requests().await.unwrap();
    let paths: Vec<_> = requests.iter().map(|request| request.url.path()).collect();
    assert_eq!(paths, ["/pkg/latest"]);
}

#[tokio::test]
async fn invalid_latest_documents_fall_back_to_history() {
    for case in [
        "missing",
        "name",
        "version",
        "tarball",
        "integrity",
        "invalid-integrity-with-shasum",
        "empty-integrity-with-shasum",
        "malformed",
        "oversized",
    ] {
        let server = MockServer::start().await;
        let body = downloadable_history(&server);
        let mut latest = body["versions"]["2.0.0"].clone();
        match case {
            "name" => latest["name"] = serde_json::json!("wrong-package"),
            "version" => latest["version"] = serde_json::json!("invalid"),
            "tarball" => latest["dist"]["tarball"] = serde_json::Value::Null,
            "integrity" => latest["dist"]["integrity"] = serde_json::Value::Null,
            "invalid-integrity-with-shasum" => {
                latest["dist"]["integrity"] = serde_json::json!("malformed");
                latest["dist"]["shasum"] = serde_json::json!("a".repeat(40));
            }
            "empty-integrity-with-shasum" => {
                latest["dist"]["integrity"] = serde_json::json!("");
                latest["dist"]["shasum"] = serde_json::json!("a".repeat(40));
            }
            _ => {}
        }
        let response = match case {
            "missing" => ResponseTemplate::new(404),
            "malformed" => ResponseTemplate::new(200).set_body_raw("{", "application/json"),
            "oversized" => {
                ResponseTemplate::new(200)
                    .set_body_bytes(vec![b' '; MAX_VERSION_METADATA_BYTES + 1])
            }
            _ => ResponseTemplate::new(200).set_body_json(latest),
        };
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(response)
            .mount(&server)
            .await;
        mount_history(&server, &body).await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        let (result, _) = client
            .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(result.metadata.versions.contains_key("2.0.0"), "{case}");
        assert_eq!(
            request_paths(&server).await,
            ["/pkg/latest", "/pkg"],
            "{case}"
        );
    }
}

#[tokio::test]
async fn latest_outside_the_range_falls_back_to_complete_history() {
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body["versions"]["2.0.0"]))
        .mount(&server)
        .await;
    mount_history(&server, &body).await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    let (result, complete) = client
        .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |v| v == "1.0.0")
        .await
        .unwrap();
    assert!(complete);
    assert!(result.metadata.versions.contains_key("1.0.0"));
    assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg"]);
}

#[tokio::test]
async fn fresh_history_caches_precede_latest_documents() {
    for complete in [false, true] {
        let server = MockServer::start().await;
        let body = downloadable_history(&server);
        mount_history(&server, &body).await;
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        if complete {
            client.get_npm_metadata_direct("pkg").await.unwrap();
        } else {
            client
                .get_npm_preferred_metadata_direct_with_timings("pkg", |_| true)
                .await
                .unwrap();
        }
        let (result, versions_complete) = client
            .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(result.timings.cache_hit);
        assert_eq!(versions_complete, complete);
        assert_eq!(request_paths(&server).await, ["/pkg"]);
    }
}

#[tokio::test]
async fn latest_cache_does_not_satisfy_complete_history_consumers() {
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body["versions"]["2.0.0"]))
        .mount(&server)
        .await;
    mount_history(&server, &body).await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    let (selected, complete) = client
        .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true)
        .await
        .unwrap();
    assert!(!complete);
    assert_eq!(selected.metadata.versions.len(), 1);
    let full = client.get_npm_metadata_direct("pkg").await.unwrap();
    assert_eq!(full.versions.len(), 2);
    assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg"]);
}

#[tokio::test]
async fn concurrent_latest_requests_share_one_document() {
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&body["versions"]["2.0.0"])
                .set_delay(std::time::Duration::from_millis(25))
                .insert_header("Cache-Control", "max-age=300"),
        )
        .mount(&server)
        .await;
    mount_history(&server, &body).await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    let (first, second) = tokio::join!(
        client.get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true),
        client.get_npm_preferred_metadata_for_resolution_with_timings("pkg", |v| v == "2.0.0")
    );
    assert!(!first.unwrap().1);
    assert!(!second.unwrap().1);
    assert_eq!(request_paths(&server).await, ["/pkg/latest"]);
}

#[tokio::test]
async fn package_cache_invalidation_refetches_the_latest_document() {
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&body["versions"]["2.0.0"])
                .insert_header("Cache-Control", "max-age=300"),
        )
        .mount(&server)
        .await;
    mount_history(&server, &body).await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    for invalidate in [false, false, true] {
        if invalidate {
            client.invalidate_metadata_cache("pkg");
        }
        let (result, complete) = client
            .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(!complete);
        assert!(result.metadata.versions.contains_key("2.0.0"));
    }
    assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg/latest"]);
}

#[tokio::test]
async fn latest_no_store_responses_are_not_reused() {
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&body["versions"]["2.0.0"])
                .insert_header("Cache-Control", "no-store"),
        )
        .mount(&server)
        .await;
    mount_history(&server, &body).await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    for _ in 0..2 {
        let (result, _) = client
            .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(!result.timings.cache_hit);
    }
    assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg/latest"]);
}

#[tokio::test]
async fn latest_failed_parse_bytes_are_counted_when_history_recovers() {
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    let malformed = format!("{{{}", " ".repeat(1024));
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(malformed.clone(), "application/json"),
        )
        .mount(&server)
        .await;
    mount_history(&server, &body).await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    let (result, _) = client
        .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true)
        .await
        .unwrap();
    assert_eq!(
        result.timings.body_bytes as usize,
        malformed.len() + serde_json::to_vec(&body).unwrap().len()
    );
    assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg"]);
}

#[tokio::test]
#[expect(
    clippy::await_holding_lock,
    reason = "The fault injection deliberately blocks only background disk publication."
)]
async fn latest_document_is_reused_while_disk_publication_is_pending() {
    use crate::client::state::MetadataCacheMutation;
    use std::sync::{Arc, Mutex, atomic::AtomicU64};
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&body["versions"]["2.0.0"])
                .insert_header("Cache-Control", "max-age=300"),
        )
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path())
        .await
        .with_synchronous_cache_writes(false);
    let key = client.npm_latest_metadata_cache_key("pkg");
    let mutation = Arc::new(MetadataCacheMutation {
        revision: AtomicU64::new(0),
        operation: Mutex::new(()),
    });
    client
        .metadata_cache_mutations
        .lock()
        .unwrap()
        .insert(client.cache_path(&key).unwrap(), Arc::clone(&mutation));
    let publication = mutation.operation.lock().unwrap();
    for _ in 0..2 {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(result.0.metadata.versions.contains_key("2.0.0"));
    }
    drop(publication);
    assert_eq!(request_paths(&server).await, ["/pkg/latest"]);
}

#[tokio::test]
async fn latest_response_started_before_invalidation_cannot_repopulate_the_cache() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for version_only in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let latest = serde_json::json!({
            "name":"pkg", "version":"2.0.0", "dist": {
                "tarball":format!("{origin}/pkg.tgz"),
                "integrity":format!("sha512-{}==", "A".repeat(86))
            }
        });
        let (started, observed) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = Vec::with_capacity(1024);
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                assert!(request.len() < 16 * 1024);
                assert_ne!(connection.read_buf(&mut request).await.unwrap(), 0);
            }
            assert!(request.starts_with(b"GET /pkg/latest "));
            started.send(()).unwrap();
            if released.await.is_err() {
                return;
            }
            let body = serde_json::to_vec(&latest).unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=300\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            connection.write_all(headers.as_bytes()).await.unwrap();
            connection.write_all(&body).await.unwrap();
        });
        let cache = tempfile::tempdir().unwrap();
        let client = std::sync::Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(origin)
                .with_cache_dir(Some(cache.path().to_owned()))
                .with_synchronous_cache_writes(true),
        );
        let fetching = std::sync::Arc::clone(&client);
        let task = tokio::spawn(async move {
            fetching
                .get_npm_preferred_metadata_for_resolution_with_timings("pkg", |_| true)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), observed)
            .await
            .unwrap()
            .unwrap();
        if version_only {
            client.invalidate_npm_version_metadata_cache("pkg", "2.0.0");
        } else {
            client.invalidate_metadata_cache("pkg");
        }
        release.send(()).unwrap();
        task.await.unwrap().unwrap();
        serving.await.unwrap();
        assert!(
            client
                .history_cache
                .lookup(&client.npm_latest_metadata_cache_key("pkg"))
                .1
                .is_none()
        );
        assert!(
            !client
                .cache_path(&client.npm_latest_metadata_cache_key("pkg"))
                .unwrap()
                .exists()
        );
    }
}

#[tokio::test]
async fn latest_revalidation_keeps_full_manifest_fields_and_updated_freshness() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let server = MockServer::start().await;
    let mut body = downloadable_history(&server)["versions"]["2.0.0"].clone();
    body["devDependencies"] = serde_json::json!({"compiler":"^1.0.0"});
    body["os"] = serde_json::json!(["linux"]);
    body["cpu"] = serde_json::json!(["arm64"]);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(move |request: &wiremock::Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200)
                    .set_body_json(&body)
                    .insert_header("Cache-Control", "no-cache")
                    .insert_header("ETag", "\"first\"")
            } else {
                assert_eq!(request.headers.get("if-none-match").unwrap(), "\"first\"");
                ResponseTemplate::new(304)
                    .insert_header("Cache-Control", "max-age=300")
                    .insert_header("ETag", "\"second\"")
            }
        })
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    client
        .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
        .await
        .unwrap();
    let second = client
        .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
        .await
        .unwrap();
    assert!(second.fetched.timings.not_modified);
    assert!(second.platform_metadata_complete);
    assert!(!second.versions_complete);
    let third = client
        .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
        .await
        .unwrap();
    assert!(third.fetched.timings.cache_hit);
    let manifest = &third.fetched.metadata.versions["2.0.0"];
    assert_eq!(manifest.dev_dependencies["compiler"], "^1.0.0");
    assert_eq!(manifest.os, ["linux"]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unusable_latest_revalidation_refetches_without_a_validator() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    for corrupt in [false, true] {
        let server = MockServer::start().await;
        let body = downloadable_history(&server)["versions"]["2.0.0"].clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(move |request: &wiremock::Request| {
                if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(304)
                } else {
                    assert!(!request.headers.contains_key("if-none-match"));
                    ResponseTemplate::new(200).set_body_json(&body)
                }
            })
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        if corrupt {
            let mut invalid: VersionMetadata =
                serde_json::from_value(downloadable_history(&server)["versions"]["2.0.0"].clone())
                    .unwrap();
            invalid.name = "other-package".into();
            client.write_metadata_cache_with_directive(
                &client.npm_latest_metadata_cache_key("pkg"),
                &invalid,
                Some("\"old\""),
                MetadataCacheDirective::Store {
                    fresh_for: std::time::Duration::ZERO,
                },
            );
        }
        let result = client
            .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(!result.fetched.timings.not_modified);
        assert!(result.fetched.metadata.versions.contains_key("2.0.0"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn latest_cache_is_isolated_between_registry_origins() {
    let cache = tempfile::tempdir().unwrap();
    let servers = [MockServer::start().await, MockServer::start().await];
    for (server, version) in servers.iter().zip(["1.0.0", "2.0.0"]) {
        let body = downloadable_history(server);
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body["versions"][version]))
            .mount(server)
            .await;
        let client = preferred_test_client(server, cache.path()).await;
        let result = client
            .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(!result.fetched.timings.cache_hit);
        assert!(result.fetched.metadata.versions.contains_key(version));
        assert_eq!(request_paths(server).await, ["/pkg/latest"]);
    }
}

#[tokio::test]
async fn latest_command_reuse_does_not_require_a_disk_cache() {
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body["versions"]["2.0.0"]))
        .mount(&server)
        .await;
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(None);
    for expected_hit in [false, true] {
        let result = client
            .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert_eq!(result.fetched.timings.cache_hit, expected_hit);
    }
    assert_eq!(request_paths(&server).await, ["/pkg/latest"]);
}

#[tokio::test]
async fn different_ranges_share_latest_then_fall_back_to_history() {
    let server = MockServer::start().await;
    let body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body["versions"]["2.0.0"]))
        .mount(&server)
        .await;
    mount_history(&server, &body).await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    let (latest, older) = tokio::join!(
        client.get_npm_preferred_resolution_metadata_with_timings("pkg", |v| v == "2.0.0"),
        client.get_npm_preferred_resolution_metadata_with_timings("pkg", |v| v == "1.0.0"),
    );
    assert!(
        latest
            .unwrap()
            .fetched
            .metadata
            .versions
            .contains_key("2.0.0")
    );
    let older = older.unwrap();
    assert!(older.versions_complete);
    assert!(older.fetched.metadata.versions.contains_key("1.0.0"));
    assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg"]);
}

#[tokio::test]
async fn latest_without_integrity_accepts_a_valid_shasum() {
    let server = MockServer::start().await;
    let mut body = downloadable_history(&server)["versions"]["2.0.0"].clone();
    body["dist"].as_object_mut().unwrap().remove("integrity");
    body["dist"]["shasum"] = serde_json::json!("a".repeat(40));
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    let result = client
        .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
        .await
        .unwrap();
    assert!(result.platform_metadata_complete);
    assert_eq!(request_paths(&server).await, ["/pkg/latest"]);
}

#[tokio::test]
async fn a_fresh_complete_history_precedes_an_older_latest_memory_entry() {
    let server = MockServer::start().await;
    let mut body = downloadable_history(&server);
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body["versions"]["2.0.0"]))
        .mount(&server)
        .await;
    body["dist-tags"]["latest"] = serde_json::json!("1.0.0");
    mount_history(&server, &body).await;
    let cache = tempfile::tempdir().unwrap();
    let client = preferred_test_client(&server, cache.path()).await;
    client
        .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
        .await
        .unwrap();
    client.get_npm_metadata_direct("pkg").await.unwrap();
    let result = client
        .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
        .await
        .unwrap();
    assert!(result.versions_complete);
    assert_eq!(result.fetched.metadata.dist_tags["latest"], "1.0.0");
    assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg"]);
}

#[tokio::test]
async fn latest_zero_freshness_is_not_reused_in_memory() {
    for policy in ["no-cache", "max-age=0"] {
        let server = MockServer::start().await;
        let body = downloadable_history(&server);
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&body["versions"]["2.0.0"])
                    .insert_header("Cache-Control", policy),
            )
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        for _ in 0..2 {
            let result = client
                .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
                .await
                .unwrap();
            assert!(!result.fetched.timings.cache_hit);
        }
        assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg/latest"]);
    }
}

#[tokio::test]
async fn latest_revalidation_does_not_override_uncacheable_directives() {
    for policy in ["no-store", "no-cache", "max-age=0"] {
        let server = MockServer::start().await;
        let body = downloadable_history(&server)["versions"]["2.0.0"].clone();
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(304).insert_header("Cache-Control", policy))
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        let key = client.npm_latest_metadata_cache_key("pkg");
        let manifest: VersionMetadata = serde_json::from_value(body).unwrap();
        client.write_metadata_cache_with_directive(
            &key,
            &manifest,
            Some("\"first\""),
            MetadataCacheDirective::Store {
                fresh_for: Duration::ZERO,
            },
        );
        let result = client
            .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(result.fetched.timings.not_modified);
        assert!(client.history_cache.lookup(&key).1.is_none());
        assert!(
            client
                .read_metadata_cache_entry_as_async::<VersionMetadata>(&key)
                .await
                .is_none()
        );
        if policy == "no-store" {
            assert!(!client.cache_path(&key).unwrap().exists());
        }
    }
}

#[tokio::test]
async fn small_latest_documents_fit_the_remaining_history_budget_without_http_buffer_slack() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let fixture_server = MockServer::start().await;
    let body =
        serde_json::to_vec(&downloadable_history(&fixture_server)["versions"]["2.0.0"]).unwrap();
    assert!(body.len() < 16 * 1024);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            loop {
                line.clear();
                if socket.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            seen.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nCache-Control: public, max-age=300\r\nConnection: close\r\n\r\n{:x}\r\n",
                body.len()
            );
            socket
                .get_mut()
                .write_all(response.as_bytes())
                .await
                .unwrap();
            socket.get_mut().write_all(&body).await.unwrap();
            socket.get_mut().write_all(b"\r\n0\r\n\r\n").await.unwrap();
            socket.get_mut().shutdown().await.unwrap();
        }
    });
    let client = RegistryClient::new()
        .with_npm_registry_url(format!("http://{address}"))
        .with_cache_dir(None);
    let mut held: Vec<_> = (0..15)
        .map(|_| client.history_cache.retain(vec![0; 512 * 1024]).unwrap())
        .collect();
    held.push(client.history_cache.retain(vec![0; 496 * 1024]).unwrap());
    for _ in 0..2 {
        let result = client
            .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(result.fetched.metadata.versions.contains_key("2.0.0"));
    }
    server.abort();
    let _ = server.await;
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    drop(held);
}

#[tokio::test]
async fn latest_retention_limits_allow_safe_refetch_without_disk_caching() {
    for exhaust_budget in [false, true] {
        let server = MockServer::start().await;
        let mut body = downloadable_history(&server)["versions"]["2.0.0"].clone();
        if !exhaust_budget {
            body["description"] = serde_json::json!("x".repeat(512 * 1024));
        }
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let client = RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None);
        let _held: Vec<_> = if exhaust_budget {
            (0..16)
                .map(|_| client.history_cache.retain(vec![0; 512 * 1024]).unwrap())
                .collect()
        } else {
            Vec::new()
        };
        for _ in 0..2 {
            let result = client
                .get_npm_preferred_resolution_metadata_with_timings("pkg", |_| true)
                .await
                .unwrap();
            assert!(result.fetched.metadata.versions.contains_key("2.0.0"));
            assert!(
                client
                    .history_cache
                    .lookup(&client.npm_latest_metadata_cache_key("pkg"))
                    .1
                    .is_none()
            );
        }
        assert_eq!(request_paths(&server).await, ["/pkg/latest", "/pkg/latest"]);
    }
}

#[tokio::test]
async fn invalidated_latest_revalidation_cannot_modify_newer_cache_data() {
    for policy in ["max-age=300", "no-store"] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(304).insert_header("Cache-Control", policy))
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        let key = client.npm_latest_metadata_cache_key("pkg");
        let generation = client.history_cache.lookup(&key).0;
        client.invalidate_metadata_cache("pkg");
        let manifest: VersionMetadata =
            serde_json::from_value(downloadable_history(&server)["versions"]["2.0.0"].clone())
                .unwrap();
        client.write_metadata_cache_with_directive(
            &key,
            &manifest,
            Some("\"same\""),
            MetadataCacheDirective::Store {
                fresh_for: Duration::ZERO,
            },
        );
        let path = client.cache_path(&key).unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        let validator = client.read_cache_validator(&key);
        let response = reqwest::get(format!("{}/pkg/latest", server.uri()))
            .await
            .unwrap();
        let cached = client
            .cached_metadata_after_304_at_generation::<VersionMetadata, _>(
                &key,
                &response,
                validator.as_ref(),
                |manifest| manifest.name == "pkg" && manifest.version == "2.0.0",
                Some(generation),
            )
            .await
            .unwrap();
        assert!(cached.remaining_freshness.is_zero());
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
        assert_eq!(cached.value.version, "2.0.0");
    }
}
