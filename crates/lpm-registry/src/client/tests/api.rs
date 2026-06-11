use super::*;

#[tokio::test]
#[ignore = "requires network — run with --ignored"]
async fn health_check_succeeds() {
    let client = RegistryClient::new();
    let healthy = client.health_check().await.unwrap();
    assert!(healthy);
}

#[tokio::test]
async fn whoami_maps_401_to_auth_required() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(401).set_body_string("expired"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.whoami().await;
    assert!(matches!(result, Err(LpmError::AuthRequired)));
}

#[tokio::test]
async fn whoami_maps_403_to_forbidden_with_body() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden-body"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.whoami().await;
    assert!(matches!(result, Err(LpmError::Forbidden(body)) if body == "forbidden-body"));
}

#[tokio::test]
async fn whoami_maps_upstream_proxy_entitlement_denial() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "upstream_proxy_entitlement_required",
            "message": "A Pro account or active org membership is required.",
            "reason": "personal_plan_not_eligible",
            "entitlementSource": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.whoami().await;

    match result {
        Err(LpmError::UpstreamProxyEntitlementRequired {
            message,
            reason,
            entitlement_source,
        }) => {
            assert_eq!(
                message,
                "A Pro account or active org membership is required."
            );
            assert_eq!(reason.as_deref(), Some("personal_plan_not_eligible"));
            assert_eq!(entitlement_source, None);
        }
        other => panic!("expected typed entitlement error, got {other:?}"),
    }
}

#[tokio::test]
async fn whoami_maps_404_to_not_found_with_body() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(404).set_body_string("missing-user"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.whoami().await;
    assert!(matches!(result, Err(LpmError::NotFound(body)) if body == "missing-user"));
}

#[tokio::test]
async fn whoami_returns_parse_error_on_malformed_json() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.whoami().await;
    assert!(
        matches!(result, Err(LpmError::Registry(message)) if message.contains("failed to parse JSON"))
    );
}

#[tokio::test]
async fn whoami_retries_429_and_sends_bearer_auth_header() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("test-auth-token");

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", "Bearer test-auth-token"))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "0"))
        .expect(4)
        .mount(&server)
        .await;

    let result = client.whoami().await;
    assert!(matches!(
        result,
        Err(LpmError::RateLimited {
            retry_after_secs: 0
        })
    ));
}

#[tokio::test]
async fn whoami_retries_500_then_succeeds_after_backoff() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Instant;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct WhoamiRetryResponder {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for WhoamiRetryResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
            if call_index == 0 {
                ResponseTemplate::new(500).set_body_string("transient upstream failure")
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "username": "retry-user"
                }))
            }
        }
    }

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(WhoamiRetryResponder {
            calls: Arc::clone(&calls),
        })
        .expect(2)
        .mount(&server)
        .await;

    let started_at = Instant::now();
    let result = client
        .whoami()
        .await
        .expect("whoami should succeed after retry");

    assert_eq!(result.username.as_deref(), Some("retry-user"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(
        started_at.elapsed() >= backoff_delay(0),
        "retryable 500 should incur at least one backoff interval"
    );
}

#[tokio::test]
async fn revoke_token_sends_bearer_auth_header_and_token_body() {
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("revoke-me-token");

    Mock::given(method("POST"))
        .and(path("/api/registry/tokens/revoke"))
        .and(header("authorization", "Bearer revoke-me-token"))
        .and(body_string_contains("\"token\":\"revoke-me-token\""))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    client
        .revoke_token()
        .await
        .expect("revoke_token should succeed with auth header and token body");
}

#[tokio::test]
async fn publish_package_treats_500_with_existing_version_as_success() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let encoded_name = "@lpm.dev/test.publish-safe";

    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(500).set_body_string("publish boom"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.publish-safe"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json(encoded_name)))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .publish_package(
            encoded_name,
            &serde_json::json!({ "name": encoded_name }),
            None,
            0,
        )
        .await
        .expect("publish should succeed when version exists after 500");

    assert_eq!(result["name"], encoded_name);
}

#[tokio::test]
async fn check_name_returns_parse_error_on_malformed_json() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("check-name-token");

    Mock::given(method("GET"))
        .and(path("/api/registry/check-name"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.check_name("owner.package-name").await;

    assert!(matches!(
        result,
        Err(LpmError::Registry(message))
            if message.contains("failed to parse JSON")
                && message.contains("/api/registry/check-name?name=owner.package-name")
    ));
}

#[tokio::test]
async fn publish_package_returns_http_500_when_version_missing_after_500() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let encoded_name = "@lpm.dev/test.publish-missing";

    Mock::given(method("PUT"))
        .and(path("/api/registry/@lpm.dev/test.publish-missing"))
        .respond_with(ResponseTemplate::new(500).set_body_string("publish boom"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.publish-missing"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .publish_package(
            encoded_name,
            &serde_json::json!({ "name": encoded_name }),
            None,
            0,
        )
        .await;

    assert!(matches!(
        result,
        Err(LpmError::Http { status: 500, message }) if message == "publish boom"
    ));
}
