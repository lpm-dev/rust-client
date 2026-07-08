use super::*;

#[tokio::test]
async fn npm_firewall_batch_verdicts_sends_bearer_auth_header_when_token_is_present() {
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("firewall-token");

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(header("authorization", "Bearer firewall-token"))
        .and(body_string_contains("\"decisionDetail\":\"actionable\""))
        .and(body_string_contains("\"name\":\"left-pad\""))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "requestId": "req-1",
                    "policyMode": "product_default",
                    "summary": {
                        "total": 1,
                        "allow": 0,
                        "warn": 0,
                        "block": 1,
                        "unknown": 0,
                        "matched": 1
                    },
                    "diagnostics": {
                        "packageCount": 1,
                        "lookupConcurrency": 64,
                        "kvReadCount": 1,
                        "kvLookupMs": 12,
                        "entitlementMs": 0,
                        "parseMs": 1,
                        "totalMs": 13,
                        "matchedCount": 1,
                        "decisionDetail": "actionable",
                        "returnedDecisionCount": 1,
                        "kvNamespaceLabel": "test",
                        "flaggedPackageIndex": {
                            "enabled": true,
                            "used": true,
                            "status": "hit",
                            "cacheStatus": "miss-l1",
                            "key": "test-index",
                            "readMs": 2,
                            "packageKeyCount": 1,
                            "candidateCount": 1,
                            "detailReadCount": 1,
                            "skippedPackageLookupCount": 0,
                            "generatedAt": "2026-06-24T00:00:00.000Z"
                        },
                        "matchSources": {
                            "integrity": 0,
                            "package": 1,
                            "none": 0
                        },
                        "lookupDuration": {
                            "count": 1,
                            "sumMs": 12,
                            "maxMs": 12,
                            "p50Ms": 12,
                            "p95Ms": 12
                        }
                    },
                    "decisions": [{
                        "decisionId": "req-1:1",
                        "name": "left-pad",
                        "version": "1.3.0",
                        "action": "block",
                        "verdict": "malicious",
                        "reason": "product_default policy maps malicious to block",
                        "matchSource": "package",
                        "matchedKey": "fw:npm:v1:left-pad@1.3.0",
                        "policyMode": "product_default"
                    }]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .npm_firewall_batch_verdicts(&[NpmFirewallBatchPackage {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            integrity: None,
            published_at: None,
        }])
        .await
        .expect("firewall verdict request should succeed");

    assert_eq!(result.summary.block, 1);
    assert_eq!(result.decisions[0].action, NpmFirewallAction::Block);
    let diagnostics = result
        .diagnostics
        .expect("firewall diagnostics should be preserved");
    assert_eq!(diagnostics.lookup_concurrency, 64);
    assert_eq!(diagnostics.kv_read_count, 1);
    assert_eq!(diagnostics.decision_detail.as_deref(), Some("actionable"));
    assert_eq!(diagnostics.returned_decision_count, 1);
    assert_eq!(diagnostics.kv_namespace_label.as_deref(), Some("test"));
    let index = diagnostics
        .flagged_package_index
        .expect("flagged package index diagnostics should be preserved");
    assert!(index.enabled);
    assert!(index.used);
    assert_eq!(index.status.as_deref(), Some("hit"));
    assert_eq!(index.package_key_count, 1);
    assert_eq!(diagnostics.match_sources.package, 1);
    assert_eq!(diagnostics.lookup_duration.p95_ms, 12.0);
    let client_timing = result
        .client_timing
        .expect("client timing should be attached to firewall response");
    assert!(client_timing.request_body_bytes > 0);
    assert!(client_timing.response_body_bytes > 0);
}

#[tokio::test]
async fn npm_firewall_batch_verdicts_maps_firewall_entitlement_denial() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("firewall-token");

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "npm_firewall_entitlement_required",
            "message": "A Pro account or active org membership is required.",
            "reason": "personal_plan_not_eligible",
            "entitlementSource": "personal"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .npm_firewall_batch_verdicts(&[NpmFirewallBatchPackage {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            integrity: None,
            published_at: None,
        }])
        .await;

    match result {
        Err(LpmError::NpmFirewallEntitlementRequired {
            message,
            reason,
            entitlement_source,
        }) => {
            assert_eq!(
                message,
                "A Pro account or active org membership is required."
            );
            assert_eq!(reason.as_deref(), Some("personal_plan_not_eligible"));
            assert_eq!(entitlement_source.as_deref(), Some("personal"));
        }
        other => panic!("expected typed firewall entitlement error, got {other:?}"),
    }
}

#[tokio::test]
async fn npm_firewall_batch_verdicts_sends_policy_profile_when_configured() {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let client = RegistryClient::new().with_base_url(server.uri());

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"policyProfile\""))
        .and(body_string_contains(
            "\"lpmAiAgentControlSurface\":\"warn\"",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "requestId": "req-policy",
                    "policyMode": "product_default",
                    "summary": {
                        "total": 1,
                        "allow": 0,
                        "warn": 1,
                        "block": 0,
                        "unknown": 0,
                        "matched": 1
                    },
                    "decisions": [{
                        "decisionId": "req-policy:1",
                        "name": "@accio-ai/cli",
                        "version": "0.1.29",
                        "action": "warn",
                        "verdict": "malicious",
                        "reason": "client policy maps lpm_ai_agent_control_surface to warn",
                        "matchSource": "package",
                        "matchedKey": "fw:npm:v1:%40accio-ai%2Fcli@0.1.29",
                        "policyMode": "product_default",
                        "policy": {
                            "key": "ai_agent_control_surface",
                            "group": "lpm_ai_agent_control_surface",
                            "intent": "dangerous_capability",
                            "defaultAction": "block"
                        },
                        "authority": {
                            "source": "lpm_ai",
                            "sourceType": "lpm",
                            "externalIntel": false
                        }
                    }]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .npm_firewall_batch_verdicts_with_posture_and_policy(
            &[NpmFirewallBatchPackage {
                name: "@accio-ai/cli".to_string(),
                version: "0.1.29".to_string(),
                integrity: None,
                published_at: None,
            }],
            AuthPosture::AnonymousPreferred,
            Some(NpmFirewallPolicyProfile {
                lpm_ai_agent_control_surface: NpmFirewallPolicyAction::Warn,
                ..NpmFirewallPolicyProfile::default()
            }),
        )
        .await
        .expect("firewall verdict request should succeed");

    assert_eq!(result.decisions[0].action, NpmFirewallAction::Warn);
    assert_eq!(
        result.decisions[0]
            .policy
            .as_ref()
            .map(|policy| policy.group.as_str()),
        Some("lpm_ai_agent_control_surface")
    );
    assert_eq!(
        result.decisions[0]
            .authority
            .as_ref()
            .map(|authority| authority.source.as_str()),
        Some("lpm_ai")
    );
}

#[tokio::test]
async fn npm_firewall_batch_verdicts_rejects_unknown_action() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let client = RegistryClient::new().with_base_url(server.uri());

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "requestId": "req-1",
                    "policyMode": "product_default",
                    "summary": {
                        "total": 1,
                        "allow": 1,
                        "warn": 0,
                        "block": 0,
                        "unknown": 1,
                        "matched": 0
                    },
                    "decisions": [{
                        "decisionId": "req-1:1",
                        "name": "kleur",
                        "version": "4.1.5",
                        "action": "quarantine",
                        "verdict": "unknown",
                        "reason": "unknown future action",
                        "matchSource": "none",
                        "matchedKey": null,
                        "policyMode": "product_default"
                    }]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .npm_firewall_batch_verdicts(&[NpmFirewallBatchPackage {
            name: "kleur".to_string(),
            version: "4.1.5".to_string(),
            integrity: None,
            published_at: None,
        }])
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn npm_firewall_batch_verdicts_can_run_anonymously_even_when_token_is_set() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("firewall-token");

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "requestId": "req-1",
                    "policyMode": "product_default",
                    "summary": {
                        "total": 1,
                        "allow": 1,
                        "warn": 0,
                        "block": 0,
                        "unknown": 1,
                        "matched": 0
                    },
                    "decisions": [{
                        "decisionId": "req-1:1",
                        "name": "kleur",
                        "version": "4.1.5",
                        "action": "allow",
                        "verdict": "unknown",
                        "reason": "unknown package is allowed by default policy",
                        "matchSource": "none",
                        "matchedKey": null,
                        "policyMode": "product_default"
                    }]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    client
        .npm_firewall_batch_verdicts_with_posture(
            &[NpmFirewallBatchPackage {
                name: "kleur".to_string(),
                version: "4.1.5".to_string(),
                integrity: None,
                published_at: None,
            }],
            AuthPosture::AnonymousPreferred,
        )
        .await
        .expect("anonymous firewall verdict request should succeed");

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "exactly one request expected");
    assert!(
        received[0].headers.get("authorization").is_none(),
        "anonymous firewall verdict requests must not attach bearer auth"
    );
}
