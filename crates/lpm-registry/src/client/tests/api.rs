use super::*;

fn replayable_json(value: &serde_json::Value) -> lpm_http::ReplayableRequestBody {
    lpm_http::ReplayableRequestBody::from_bytes(serde_json::to_vec(value).unwrap())
}

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
async fn whoami_follows_organization_continuation_pages() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let cursor = "00000000-0000-4000-8000-000000000001";
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "owner@lpm.dev",
            "organizations": [{ "slug": "first" }],
            "available_scopes": ["@first"],
            "organizations_next_cursor": cursor
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami/organizations"))
        .and(query_param("cursor", cursor))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "organizations": [{ "slug": "second" }],
            "organizations_next_cursor": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("test-token")
        .whoami()
        .await
        .unwrap();

    assert_eq!(
        response
            .organizations
            .iter()
            .map(|org| org.slug.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
}

#[tokio::test]
async fn publish_preflight_sends_resolved_identity_and_bearer_without_mutation() {
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", "@lpm.dev/owner.resolved"))
        .and(query_param("version", "1.2.3"))
        .and(header("authorization", "Bearer publish-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": "@lpm.dev/owner.resolved",
            "version": "1.2.3",
            "packageExists": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token");
    let response = client
        .publish_preflight("@lpm.dev/owner.resolved", "1.2.3")
        .await
        .unwrap();
    assert!(response.success);
    assert!(response.package_exists);
}

#[tokio::test]
async fn publication_status_sends_package_identity_and_publish_bearer() {
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publication-status"))
        .and(query_param("name", "@lpm.dev/owner.resolved"))
        .and(query_param("version", "1.2.3"))
        .and(header("authorization", "Bearer publish-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "@lpm.dev/owner.resolved",
            "version": "1.2.3",
            "status": "pending_review",
            "reviewStatus": "pending",
            "currentLatestVersion": "1.1.0"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .get_publication_status("@lpm.dev/owner.resolved", "1.2.3")
        .await
        .expect("publication status request should succeed");

    assert_eq!(response.status, "pending_review");
    assert_eq!(response.current_latest_version.as_deref(), Some("1.1.0"));
}

#[tokio::test]
async fn publication_status_rejects_a_mismatched_response_identity() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publication-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "@lpm.dev/other.package",
            "version": "9.9.9",
            "status": "active",
            "reviewStatus": "approved"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .get_publication_status("@lpm.dev/owner.resolved", "1.2.3")
        .await
        .expect_err("mismatched status response must fail closed");

    assert!(error.to_string().contains("mismatched package identity"));
}

#[tokio::test]
async fn publish_preflight_rejects_an_unsuccessful_success_envelope() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "name": "@lpm.dev/owner.resolved",
            "version": "1.2.3"
        })))
        .mount(&server)
        .await;

    let error = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .publish_preflight("@lpm.dev/owner.resolved", "1.2.3")
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("denied"), "{error}");
}

#[tokio::test]
async fn publish_preflight_rejects_a_mismatched_response_identity() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": "@lpm.dev/owner.other",
            "version": "9.9.9"
        })))
        .mount(&server)
        .await;

    let error = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .publish_preflight("@lpm.dev/owner.resolved", "1.2.3")
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("mismatched package identity"), "{error}");
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
async fn get_skills_sends_bearer_for_private_and_pending_versions() {
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("skills-owner-token");

    Mock::given(method("GET"))
        .and(path("/api/registry/skills"))
        .and(query_param("name", "owner.private-package"))
        .and(query_param("version", "1.0.2"))
        .and(header("authorization", "Bearer skills-owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "owner.private-package",
            "version": "1.0.2",
            "available": true,
            "skillsCount": 0,
            "skillsStatus": null,
            "skills": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = client
        .get_skills("owner.private-package", Some("1.0.2"))
        .await
        .expect("owner-authenticated skills lookup should succeed");

    assert_eq!(response.version.as_deref(), Some("1.0.2"));
    assert!(response.skills.is_empty());
}

#[tokio::test]
async fn get_skills_allows_anonymous_public_reads_without_a_bearer() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/api/registry/skills"))
        .and(query_param("name", "owner.public-package"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "owner.public-package",
            "version": "1.0.0",
            "available": true,
            "skillsCount": 0,
            "skillsStatus": null,
            "skills": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = client
        .get_skills("owner.public-package", None)
        .await
        .expect("anonymous public skills lookup should succeed");

    let requests = server
        .received_requests()
        .await
        .expect("mock server should retain received requests");
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].headers.contains_key("authorization"));
    assert_eq!(response.version.as_deref(), Some("1.0.0"));
    assert!(response.skills.is_empty());
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
async fn revoke_session_sends_bearer_auth_header_without_token_body() {
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("revoke-me-token");

    Mock::given(method("POST"))
        .and(path("/api/cli/revoke"))
        .and(header("authorization", "Bearer revoke-me-token"))
        .and(body_bytes(Vec::<u8>::new()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    client
        .revoke_session()
        .await
        .expect("revoke_session should succeed with bearer-only authentication");
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

    let payload = replayable_json(&serde_json::json!({ "name": encoded_name }));
    let result = client
        .publish_package(encoded_name, &payload, None, 0)
        .await
        .expect("publish should succeed when version exists after 500");

    assert_eq!(result["name"], encoded_name);
}

#[tokio::test]
async fn publish_package_replays_the_exact_body_after_gateway_failure() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct PublishRetryResponder {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for PublishRetryResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).set_body_string("temporary gateway failure")
            } else {
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"success": true}))
            }
        }
    }

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("publish-token");
    let encoded_name = "@lpm.dev/test.replay";
    let value = serde_json::json!({
        "name": encoded_name,
        "_attachments": {"archive.tgz": {"data": "cmVwbGF5"}}
    });
    let expected_body = serde_json::to_vec(&value).unwrap();
    let expected_length = expected_body.len().to_string();
    let payload = replayable_json(&value);
    let calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("PUT"))
        .and(path("/api/registry/@lpm.dev/test.replay"))
        .and(header("authorization", "Bearer publish-token"))
        .respond_with(PublishRetryResponder {
            calls: Arc::clone(&calls),
        })
        .expect(2)
        .mount(&server)
        .await;

    let result = client
        .publish_package(encoded_name, &payload, Some("123456"), 6)
        .await
        .expect("publish should succeed after the gateway retry");

    assert_eq!(result["success"], true);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let requests = server.received_requests().await.unwrap();
    let publish_requests = requests
        .iter()
        .filter(|request| request.method.as_str() == "PUT")
        .collect::<Vec<_>>();
    assert_eq!(publish_requests.len(), 2);
    for request in publish_requests {
        assert_eq!(request.body, expected_body);
        assert_eq!(
            request
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some(expected_length.as_str())
        );
        assert_eq!(
            request
                .headers
                .get("x-otp")
                .and_then(|value| value.to_str().ok()),
            Some("123456")
        );
    }
}

#[tokio::test]
async fn publish_package_replays_put_body_and_length_across_same_origin_307() {
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token");
    let encoded_name = "@lpm.dev/test.redirect";
    let value = serde_json::json!({
        "name": encoded_name,
        "_attachments": {"archive.tgz": {"data": "cmVkaXJlY3Q="}}
    });
    let expected_body = serde_json::to_vec(&value).unwrap();
    let expected_length = expected_body.len().to_string();
    let payload = replayable_json(&value);

    Mock::given(method("PUT"))
        .and(path("/api/registry/@lpm.dev/test.redirect"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/redirected-publish"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/redirected-publish"))
        .and(header("authorization", "Bearer publish-token"))
        .and(header("x-otp", "123456"))
        .and(header("content-length", expected_length.as_str()))
        .and(body_bytes(expected_body))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "success": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .publish_package(encoded_name, &payload, Some("123456"), 8)
        .await
        .expect("same-origin 307 should replay the publish request");

    assert_eq!(result["success"], true);
}

#[tokio::test]
async fn publish_package_strips_bearer_and_otp_across_cross_origin_303() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/capture"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "success": true
        })))
        .expect(1)
        .mount(&target)
        .await;

    let redirector = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/registry/@lpm.dev/test.cross-origin"))
        .respond_with(
            ResponseTemplate::new(303)
                .insert_header("location", format!("{}/capture", target.uri())),
        )
        .expect(1)
        .mount(&redirector)
        .await;

    let payload = replayable_json(&serde_json::json!({
        "name": "@lpm.dev/test.cross-origin"
    }));
    let result = RegistryClient::new()
        .with_base_url(redirector.uri())
        .with_token("publish-token")
        .publish_package("@lpm.dev/test.cross-origin", &payload, Some("123456"), 0)
        .await
        .expect("cross-origin 303 should complete without forwarding credentials");

    assert_eq!(result["success"], true);
    let requests = target.received_requests().await.unwrap();
    let redirected = requests.first().expect("redirect target request");
    assert!(redirected.headers.get("authorization").is_none());
    assert!(redirected.headers.get("x-otp").is_none());
    assert!(redirected.headers.get("npm-otp").is_none());
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

    let payload = replayable_json(&serde_json::json!({ "name": encoded_name }));
    let result = client
        .publish_package(encoded_name, &payload, None, 0)
        .await;

    assert!(matches!(
        result,
        Err(LpmError::Http { status: 500, message }) if message == "publish boom"
    ));
}
