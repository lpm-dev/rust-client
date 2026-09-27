use super::*;

fn marked_client(pool: &'static str) -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::HeaderName::from_static("x-lpm-pool"),
            reqwest::header::HeaderValue::from_static(pool),
        )]))
        .build()
        .unwrap()
}

fn policy_client(registry: &str) -> RegistryClient {
    let mut client = RegistryClient::new()
        .with_npm_registry_url(registry)
        .with_cache_dir(None);
    client.http = HttpClients::from_default_clients(
        marked_client("general"),
        marked_client("policy"),
        marked_client("manual"),
    );
    client
}

fn release_times() -> serde_json::Value {
    serde_json::json!({
        "name": "pool-package",
        "time": {"1.0.0": "2025-01-01T00:00:00Z"}
    })
}

#[tokio::test]
async fn release_time_requests_execute_on_the_policy_metadata_pool() {
    use crate::UpstreamRoute;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pool-package"))
        .respond_with(ResponseTemplate::new(200).set_body_json(release_times()))
        .expect(1)
        .mount(&server)
        .await;
    let client = policy_client(&server.uri());
    client
        .get_npm_release_times_routed_full("pool-package", UpstreamRoute::NpmDirect)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers["x-lpm-pool"], "policy");
}

#[tokio::test]
async fn release_time_rate_limit_retries_preserve_anonymous_policy_pool() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let seen = AtomicUsize::new(0);
    Mock::given(method("GET"))
        .and(path("/pool-package"))
        .respond_with(move |_: &wiremock::Request| {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(429).insert_header("Retry-After", "0")
            } else {
                ResponseTemplate::new(200).set_body_json(release_times())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let client = policy_client(&server.uri())
        .with_base_url(server.uri())
        .with_token("unused-private-session");
    client
        .get_npm_release_times_routed_full("pool-package", crate::UpstreamRoute::NpmDirect)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.headers["x-lpm-pool"], "policy");
        assert_eq!(request.headers["accept"], "application/json");
        assert!(!request.headers.contains_key("authorization"));
    }
}

#[tokio::test]
async fn release_time_redirects_reselect_the_destination_policy_pool() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for status in [302, 307] {
        let source = MockServer::start().await;
        let target = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pool-package"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Location", format!("{}/landing", target.uri())),
            )
            .expect(1)
            .mount(&source)
            .await;
        Mock::given(method("GET"))
            .and(path("/landing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(release_times()))
            .expect(1)
            .mount(&target)
            .await;
        let mut client = policy_client(&source.uri()).with_token("unused-private-session");
        Arc::get_mut(&mut client.http).unwrap().eager.insert(
            OriginKey::from_request_url(&target.uri()).unwrap(),
            CachedClient {
                client: marked_client("target-general"),
                policy_metadata_client: marked_client("target-policy"),
                manual_redirect_client: marked_client("target-manual"),
                identity_fp: None,
            },
        );
        client
            .get_npm_release_times_routed_full("pool-package", crate::UpstreamRoute::NpmDirect)
            .await
            .unwrap();
        let source_requests = source.received_requests().await.unwrap();
        let target_requests = target.received_requests().await.unwrap();
        assert_eq!(source_requests[0].headers["x-lpm-pool"], "policy");
        assert_eq!(target_requests[0].headers["x-lpm-pool"], "target-policy");
        assert!(!source_requests[0].headers.contains_key("authorization"));
        assert!(!target_requests[0].headers.contains_key("authorization"));
    }
}

#[tokio::test]
async fn unusable_release_time_revalidation_retries_on_the_policy_pool_without_a_validator() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let cache = tempfile::tempdir().unwrap();
    let client = policy_client(&server.uri())
        .with_cache_dir(Some(cache.path().to_path_buf()))
        .with_synchronous_cache_writes(true);
    let wrong: ReleaseTimeMetadata = serde_json::from_value(serde_json::json!({
        "name": "wrong-package", "time": {"1.0.0": "2025-01-01T00:00:00Z"}
    }))
    .unwrap();
    client.write_metadata_cache_with_directive(
        &client.npm_direct_release_times_cache_key("pool-package"),
        &wrong,
        Some("\"stale\""),
        MetadataCacheDirective::Store {
            fresh_for: Duration::ZERO,
        },
    );
    Mock::given(method("GET"))
        .and(path("/pool-package"))
        .respond_with(|request: &wiremock::Request| {
            if request.headers.contains_key("if-none-match") {
                ResponseTemplate::new(304)
            } else {
                ResponseTemplate::new(200).set_body_json(release_times())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    client
        .get_npm_release_times_routed_full("pool-package", crate::UpstreamRoute::NpmDirect)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].headers["if-none-match"], "\"stale\"");
    assert!(!requests[1].headers.contains_key("if-none-match"));
    for request in requests {
        assert_eq!(request.headers["x-lpm-pool"], "policy");
    }
}
