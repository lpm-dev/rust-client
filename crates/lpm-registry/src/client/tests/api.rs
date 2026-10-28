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
    let verdict = client
        .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", None)
        .await
        .unwrap();
    let PublishPreflightVerdict::Accepted(response) = verdict else {
        panic!("expected an accepted preflight, got {verdict:?}");
    };
    assert!(response.success);
    assert!(response.package_exists);
}

#[tokio::test]
async fn publish_preflight_sends_the_size_it_is_given() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("size", "1048576"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": "@lpm.dev/owner.resolved",
            "version": "1.2.3",
            "packageExists": false
        })))
        .expect(1)
        .mount(&server)
        .await;

    let verdict = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", Some(1024 * 1024))
        .await
        .unwrap();

    assert!(
        matches!(verdict, PublishPreflightVerdict::Accepted(_)),
        "{verdict:?}"
    );
}

#[tokio::test]
async fn publish_preflight_keeps_a_refusal_s_status_code_and_message() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for (status, body, code, error) in [
        (
            402,
            serde_json::json!({ "error": "Billing is past due.", "code": "ORG_BILLING_LAPSED" }),
            Some("ORG_BILLING_LAPSED"),
            "Billing is past due.",
        ),
        (
            403,
            serde_json::json!({ "error": "Token does not have publish permissions" }),
            None,
            "Token does not have publish permissions",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publish-preflight"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;

        let verdict = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("publish-token")
            .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", Some(1))
            .await
            .unwrap();

        let PublishPreflightVerdict::Refused {
            status: refused,
            code: refused_code,
            error: message,
            ..
        } = verdict
        else {
            panic!("expected a refusal, got {verdict:?}");
        };
        assert_eq!(
            (refused, refused_code.as_deref(), message.as_str()),
            (status, code, error)
        );
    }
}

#[tokio::test]
async fn publish_preflight_names_the_status_of_an_answer_that_isnt_json() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(ResponseTemplate::new(413).set_body_string("<html>too large</html>"))
        .expect(1)
        .mount(&server)
        .await;

    let verdict = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", Some(1))
        .await
        .unwrap();

    let PublishPreflightVerdict::Refused {
        status,
        code,
        error,
        body,
        ..
    } = verdict
    else {
        panic!("expected a refusal, got {verdict:?}");
    };
    assert_eq!(
        (status, code, error.as_str(), body.as_str()),
        (
            413,
            None,
            "HTTP 413 Payload Too Large",
            "<html>too large</html>"
        )
    );
}

#[tokio::test]
async fn a_publish_preflight_refusal_is_the_error_any_request_s_failure_is() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for (status, body) in [
        (403, "Insufficient permissions"),
        (404, "no such package"),
        (429, "slow down"),
        (409, "ordered-alpha-error"),
    ] {
        let server = MockServer::start().await;
        if status == 429 {
            // Retried at once three times; the last answer's wait is the
            // one reported.
            Mock::given(method("GET"))
                .and(path("/api/registry/-/package/publish-preflight"))
                .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
                .up_to_n_times(3)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publish-preflight"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("retry-after", "7")
                    .set_body_string(body),
            )
            .mount(&server)
            .await;

        let verdict = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("publish-token")
            .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", None)
            .await
            .unwrap();

        let error = verdict.into_result().unwrap_err();
        match status {
            403 => assert!(
                matches!(&error, LpmError::Forbidden(message) if message == body),
                "{error:?}"
            ),
            404 => assert!(
                matches!(&error, LpmError::NotFound(message) if message == body),
                "{error:?}"
            ),
            429 => assert!(
                matches!(
                    error,
                    LpmError::RateLimited {
                        retry_after_secs: 7
                    }
                ),
                "{error:?}"
            ),
            _ => assert!(
                matches!(&error, LpmError::Http { status: 409, message } if message == body),
                "{error:?}"
            ),
        }
    }
}

#[tokio::test]
async fn publish_preflight_redacts_a_refusal_s_reflection_of_its_bearer() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let token = "lpm-preflight-reflection-secret";
    for (status, body) in [
        (
            403,
            serde_json::json!({ "error": format!("bearer {token} may not publish") }).to_string(),
        ),
        (409, format!("submitted bearer was {token}")),
        // The last of the retried answers.
        (429, format!("slow down, {token}")),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publish-preflight"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("retry-after", "0")
                    .set_body_string(body),
            )
            .mount(&server)
            .await;

        let verdict = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token(token)
            .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", None)
            .await
            .unwrap();

        let PublishPreflightVerdict::Refused { error, body, .. } = &verdict else {
            panic!("expected a refusal, got {verdict:?}");
        };
        for text in [error, body] {
            assert!(!text.contains(token), "{status}: bearer leaked: {text}");
        }
        assert!(body.contains("<redacted>"), "{status}: {body}");
        let error = format!("{:?}", verdict.into_result().unwrap_err());
        assert!(!error.contains(token), "{status}: bearer leaked: {error}");
    }
}

#[tokio::test]
async fn publish_preflight_retries_a_server_error_before_reading_the_answer() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for status in [408, 500, 502, 503, 504] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publish-preflight"))
            .respond_with(ResponseTemplate::new(status))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publish-preflight"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": "Version 1.2.3 already exists. You cannot overwrite versions.",
                "code": "VERSION_EXISTS",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let verdict = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("publish-token")
            .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", None)
            .await
            .unwrap();

        assert!(
            matches!(
                &verdict,
                PublishPreflightVerdict::Refused { status: 403, code: Some(code), .. }
                    if code == "VERSION_EXISTS"
            ),
            "{status}: {verdict:?}"
        );
    }
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
    assert_eq!(response.hold, None);
}

#[tokio::test]
async fn publication_status_reads_a_hold_and_leaves_out_one_it_cant_read() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let cases = [
        (
            serde_json::json!({
                "reason": "publication_intent_changed",
                "message": "It was published for a distribution this package doesn't have.",
                "final": true
            }),
            Some(PublicationHold {
                reason: Some("publication_intent_changed".into()),
                message: Some(
                    "It was published for a distribution this package doesn't have.".into(),
                ),
                is_final: true,
            }),
        ),
        (
            serde_json::json!({ "reason": "release_cooldown", "message": "Soon." }),
            Some(PublicationHold {
                reason: Some("release_cooldown".into()),
                message: Some("Soon.".into()),
                is_final: false,
            }),
        ),
        (
            serde_json::json!({ "reason": "package_archived", "message": 5, "final": null }),
            Some(PublicationHold {
                reason: Some("package_archived".into()),
                message: None,
                is_final: false,
            }),
        ),
        (
            serde_json::json!({ "final": "yes" }),
            Some(PublicationHold {
                reason: None,
                message: None,
                is_final: false,
            }),
        ),
        (serde_json::json!("held"), None),
        (serde_json::Value::Null, None),
    ];
    for (hold, expected) in cases {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publication-status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "@lpm.dev/owner.resolved",
                "version": "1.2.3",
                "status": "processing",
                "reviewStatus": "approved",
                "hold": hold
            })))
            .mount(&server)
            .await;

        let response = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("publish-token")
            .get_publication_status("@lpm.dev/owner.resolved", "1.2.3")
            .await
            .expect("a hold never fails the poll");

        assert_eq!(response.hold, expected, "{hold}");
    }
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
            "version": "1.2.3",
            "packageExists": false
        })))
        .mount(&server)
        .await;

    let error = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", None)
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("denied"), "{error}");
}

#[tokio::test]
async fn publish_preflight_rejects_a_mismatched_response_identity() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Another package, or another version of this one.
    for (name, version) in [
        ("@lpm.dev/owner.other", "1.2.3"),
        ("@lpm.dev/owner.resolved", "9.9.9"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publish-preflight"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "name": name,
                "version": version,
                "packageExists": false
            })))
            .mount(&server)
            .await;

        let error = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("publish-token")
            .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", None)
            .await
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("mismatched package identity"),
            "{name}@{version}: {error}"
        );
    }
}

#[tokio::test]
async fn publish_preflight_rejects_a_response_without_package_existence() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": "@lpm.dev/owner.resolved",
            "version": "1.2.3"
        })))
        .mount(&server)
        .await;

    let error = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .publish_preflight("@lpm.dev/owner.resolved", "1.2.3", None)
        .await
        .expect_err("a missing packageExists field must fail closed")
        .to_string();

    assert!(error.contains("packageExists"), "{error}");
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
        .publish_package(encoded_name, "1.0.0", "sha512-test", &payload, None, 0)
        .await
        .expect("publish should succeed when version exists after 500");

    assert_eq!(result["name"], encoded_name);
}

#[tokio::test]
async fn publish_package_does_not_treat_a_different_existing_version_as_success() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let encoded_name = "@lpm.dev/test.publish-version-mismatch";

    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(500).set_body_string("publish boom"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.publish-version-mismatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json_with_version(encoded_name, "0.9.0")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let payload = replayable_json(&serde_json::json!({ "name": encoded_name }));
    let result = client
        .publish_package(encoded_name, "1.0.0", "sha512-test", &payload, None, 0)
        .await;

    assert!(matches!(
        result,
        Err(LpmError::Http { status: 500, message }) if message == "publish boom"
    ));
}

#[tokio::test]
async fn publish_package_rejects_500_recovery_when_the_stored_integrity_differs() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let encoded_name = "@lpm.dev/test.publish-integrity-mismatch";

    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(500).set_body_string("publish boom"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/registry/@lpm.dev/test.publish-integrity-mismatch",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": encoded_name,
            "versions": {
                "1.0.0": {
                    "name": encoded_name,
                    "version": "1.0.0",
                    "dist": {"integrity": "sha512-stored-other-artifact"}
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let payload = replayable_json(&serde_json::json!({
        "name": encoded_name,
        "versions": {
            "1.0.0": {
                "dist": {"integrity": "sha512-attempted-artifact"}
            }
        }
    }));
    let result = client
        .publish_package(
            encoded_name,
            "1.0.0",
            "sha512-attempted-artifact",
            &payload,
            None,
            0,
        )
        .await;

    assert!(
        matches!(result, Err(LpmError::Registry(ref message)) if message.contains("integrity") && message.contains("does not match")),
        "mismatched stored content must not be reported as this publish's success: {result:?}",
    );
}

#[tokio::test]
async fn publish_package_reconciles_a_committed_503_before_replaying_the_put() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct CommittedThenConflict {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for CommittedThenConflict {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).set_body_string("stored before gateway failure")
            } else {
                ResponseTemplate::new(409).set_body_string("version already exists")
            }
        }
    }

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let encoded_name = "@lpm.dev/test.publish-committed-503";
    let calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("PUT"))
        .and(path("/api/registry/@lpm.dev/test.publish-committed-503"))
        .respond_with(CommittedThenConflict {
            calls: Arc::clone(&calls),
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/test.publish-committed-503"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json(encoded_name)))
        .expect(1)
        .mount(&server)
        .await;

    let payload = replayable_json(&serde_json::json!({
        "name": encoded_name,
        "versions": {
            "1.0.0": {"dist": {"integrity": "sha512-test"}}
        }
    }));
    let result = client
        .publish_package(encoded_name, "1.0.0", "sha512-test", &payload, None, 0)
        .await
        .expect("the committed upload must be reconciled as success");

    assert_eq!(result["name"], encoded_name);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a committed ambiguous response must not replay the publish body",
    );
}

#[tokio::test]
async fn publish_package_warns_before_retry_when_a_503_recovery_probe_fails() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let encoded_name = "@lpm.dev/test.publish-ambiguous-probe-failure";

    Mock::given(method("PUT"))
        .and(path(
            "/api/registry/@lpm.dev/test.publish-ambiguous-probe-failure",
        ))
        .respond_with(ResponseTemplate::new(503).set_body_string("gateway lost the response"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/registry/@lpm.dev/test.publish-ambiguous-probe-failure",
        ))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let payload = replayable_json(&serde_json::json!({
        "name": encoded_name,
        "versions": {
            "1.0.0": {"dist": {"integrity": "sha512-test"}}
        }
    }));
    let result = client
        .publish_package(encoded_name, "1.0.0", "sha512-test", &payload, None, 0)
        .await;

    assert!(
        matches!(result, Err(LpmError::Registry(ref message)) if message.contains("ambiguous") && message.contains("Inspect the registry before retrying")),
        "an unreconciled ambiguous publish must warn against a blind retry: {result:?}",
    );
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
        .publish_package(
            encoded_name,
            "1.0.0",
            "sha512-test",
            &payload,
            Some("123456"),
            6,
        )
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
async fn publish_package_redacts_a_registry_reflection_of_its_one_time_code() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let code = "731905";
    for status in [403, 404, 422] {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/registry/@lpm.dev/test.reflection"))
            .respond_with(
                ResponseTemplate::new(status).set_body_string(format!("code {code} was refused")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let payload = replayable_json(&serde_json::json!({
            "name": "@lpm.dev/test.reflection"
        }));

        let error = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("publish-token")
            .publish_package(
                "@lpm.dev/test.reflection",
                "1.0.0",
                "sha512-test",
                &payload,
                Some(code),
                0,
            )
            .await
            .expect_err("registry rejection must remain an error")
            .to_string();

        assert!(!error.contains(code), "{status}: code leaked: {error}");
        assert!(error.contains("<redacted>"), "{status}: {error}");
    }
}

#[tokio::test]
async fn publish_package_redacts_a_registry_reflection_of_its_bearer() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let token = "lpm-publish-reflection-secret";
    let server = MockServer::start().await;
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token(token);
    Mock::given(method("PUT"))
        .and(path("/api/registry/@lpm.dev/test.reflection"))
        .respond_with(
            ResponseTemplate::new(403).set_body_string(format!("submitted bearer was {token}")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let payload = replayable_json(&serde_json::json!({
        "name": "@lpm.dev/test.reflection"
    }));

    let error = client
        .publish_package(
            "@lpm.dev/test.reflection",
            "1.0.0",
            "sha512-test",
            &payload,
            None,
            0,
        )
        .await
        .expect_err("registry rejection must remain an error")
        .to_string();

    assert!(
        !error.contains(token),
        "reflected bearer leaked through the error: {error}"
    );
    assert!(error.contains("<redacted>"));
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
        .publish_package(
            encoded_name,
            "1.0.0",
            "sha512-test",
            &payload,
            Some("123456"),
            8,
        )
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
        .publish_package(
            "@lpm.dev/test.cross-origin",
            "1.0.0",
            "sha512-test",
            &payload,
            Some("123456"),
            0,
        )
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
        .publish_package(encoded_name, "1.0.0", "sha512-test", &payload, None, 0)
        .await;

    assert!(matches!(
        result,
        Err(LpmError::Http { status: 500, message }) if message == "publish boom"
    ));
}

fn opened_publish_upload(server_uri: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "11111111-1111-4111-8111-111111111111",
        "uploadUrl": format!("{server_uri}/storage/publish-uploads/upload.tgz?X-Amz-Signature=signed"),
        "uploadHeaders": {
            "content-type": "application/gzip",
            "if-none-match": "*",
        },
        "expiresAt": "2099-01-01T00:00:00.000Z",
    })
}

fn publish_upload(server_uri: &str) -> PublishUpload {
    serde_json::from_value(opened_publish_upload(server_uri)).unwrap()
}

#[tokio::test]
async fn create_publish_upload_sends_the_tarball_s_identity_with_the_bearer() {
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/package/uploads"))
        .and(header("authorization", "Bearer publish-token"))
        .and(body_json(serde_json::json!({
            "name": "@lpm.dev/owner.pkg",
            "version": "1.2.3",
            "size": 4096,
            "integrity": "sha512-abc",
        })))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(opened_publish_upload(&server.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;

    let upload = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .create_publish_upload("@lpm.dev/owner.pkg", "1.2.3", 4096, "sha512-abc")
        .await
        .unwrap();

    assert_eq!(upload.id, "11111111-1111-4111-8111-111111111111");
    assert_eq!(
        upload.upload_url,
        format!(
            "{}/storage/publish-uploads/upload.tgz?X-Amz-Signature=signed",
            server.uri()
        )
    );
    assert_eq!(upload.upload_headers["if-none-match"], "*");
}

#[tokio::test]
async fn create_publish_upload_states_a_refusal_as_the_publish_would() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for (status, body, expected) in [
        (
            413,
            serde_json::json!({
                "error": "Tarball too large (100.01 MiB). Maximum single package size is 100 MiB.",
                "code": "TARBALL_TOO_LARGE",
            })
            .to_string(),
            "publish failed (413 Payload Too Large): Tarball too large (100.01 MiB). Maximum single package size is 100 MiB. [TARBALL_TOO_LARGE]",
        ),
        (
            403,
            serde_json::json!({
                "error": "Version 1.2.3 already exists. You cannot overwrite versions.",
                "code": "VERSION_EXISTS",
            })
            .to_string(),
            "Version 1.2.3 already exists. Verify the existing release in the registry if an earlier publish was interrupted. To publish different contents, choose a new version.",
        ),
        (
            409,
            "upstream unavailable".to_string(),
            "publish failed (409 Conflict): HTTP 409 Conflict",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/registry/-/package/uploads"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let error = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("publish-token")
            .create_publish_upload("@lpm.dev/owner.pkg", "1.2.3", 1, "sha512-abc")
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("registry error: {expected}"),
            "{status}"
        );
    }
}

#[tokio::test]
async fn create_publish_upload_maps_401_to_auth_required() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/package/uploads"))
        .respond_with(ResponseTemplate::new(401).set_body_string("expired"))
        .mount(&server)
        .await;

    let result = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .create_publish_upload("@lpm.dev/owner.pkg", "1.2.3", 1, "sha512-abc")
        .await;

    assert!(matches!(result, Err(LpmError::AuthRequired)), "{result:?}");
}

#[tokio::test]
async fn upload_publish_tarball_sends_the_tarball_with_its_headers_and_no_bearer() {
    use wiremock::matchers::{body_bytes, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let tarball = Arc::new(b"tarball bytes for storage".to_vec());
    Mock::given(method("PUT"))
        .and(path("/storage/publish-uploads/upload.tgz"))
        .and(query_param("X-Amz-Signature", "signed"))
        .and(header("content-type", "application/gzip"))
        .and(header("if-none-match", "*"))
        .and(body_bytes(tarball.as_slice()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("publish-token")
        .upload_publish_tarball(&publish_upload(&server.uri()), &tarball)
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert!(requests[0].headers.get("authorization").is_none());
    assert_eq!(
        requests[0].headers.get("content-length").unwrap(),
        &tarball.len().to_string()
    );
}

#[tokio::test]
async fn upload_publish_tarball_takes_a_412_as_an_earlier_try_s_upload() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(412).set_body_string(
            "<Error><Code>PreconditionFailed</Code><Message>At least one of the pre-conditions you specified did not hold</Message></Error>",
        ))
        .expect(1)
        .mount(&server)
        .await;

    RegistryClient::new()
        .with_base_url(server.uri())
        .upload_publish_tarball(&publish_upload(&server.uri()), &Arc::new(vec![1, 2, 3]))
        .await
        .unwrap();
}

#[tokio::test]
async fn upload_publish_tarball_retries_a_storage_server_error() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    RegistryClient::new()
        .with_base_url(server.uri())
        .upload_publish_tarball(&publish_upload(&server.uri()), &Arc::new(vec![1, 2, 3]))
        .await
        .unwrap();
}

#[tokio::test]
async fn upload_publish_tarball_states_storage_s_refusal_without_retrying() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(403).set_body_string(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match the signature you provided.</Message></Error>",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let error = RegistryClient::new()
        .with_base_url(server.uri())
        .upload_publish_tarball(&publish_upload(&server.uri()), &Arc::new(vec![1, 2, 3]))
        .await
        .unwrap_err();

    assert!(
        matches!(
            &error,
            LpmError::Http { status: 403, message }
                if message == "tarball upload failed: SignatureDoesNotMatch: The request signature we calculated does not match the signature you provided."
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn upload_publish_tarball_refuses_a_header_it_would_not_send() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let mut upload = publish_upload(&server.uri());
    upload
        .upload_headers
        .insert("Authorization".into(), "Bearer leaked".into());

    let error = RegistryClient::new()
        .with_base_url(server.uri())
        .upload_publish_tarball(&upload, &Arc::new(vec![1, 2, 3]))
        .await
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("tarball upload header LPM doesn't send: Authorization"),
        "{error}"
    );
}

#[test]
fn publish_upload_debug_leaves_out_its_presigned_url() {
    let rendered = format!("{:?}", publish_upload("https://storage.example"));

    assert!(!rendered.contains("X-Amz-Signature"), "{rendered}");
    assert!(
        rendered.contains("11111111-1111-4111-8111-111111111111"),
        "{rendered}"
    );
}
