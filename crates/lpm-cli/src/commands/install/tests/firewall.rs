use super::*;
use crate::commands::install::firewall::{
    DEFAULT_NPM_FIREWALL_CHUNK_SIZE, NpmFirewallChunkedPreflightConfig, NpmFirewallLookupMode,
    NpmFirewallPreflightResult, NpmFirewallPreflightStats, PreflightSettings,
    finish_npm_firewall_preflight, npm_firewall_chunk_size, npm_firewall_package,
    npm_firewall_package_from_selected_event, npm_firewall_packages,
    request_npm_firewall_preflight, request_npm_firewall_preflight_with_bypass,
    request_npm_firewall_preflight_with_force, spawn_chunked_npm_firewall_preflight,
};
use crate::firewall_bypass::{FirewallBypassRule, FirewallBypassRules, FirewallBypassScope};
use crate::npm_firewall_config::NpmFirewallMode;

fn package_with_source(name: &str, source: &str) -> InstallPackage {
    InstallPackage {
        instance_id: None,
        dependency_targets: HashMap::new(),
        peer_targets: HashMap::new(),
        name: name.to_string(),
        version: "1.0.0".to_string(),
        source: source.to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct: false,
        is_lpm: false,
        peers: Vec::new(),
        integrity: Some("sha512-test".to_string()),
        unpacked_size: None,
        registry_signatures: Vec::new(),
        registry_published_at: Some("2025-01-01T00:00:00.000Z".to_string()),
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: Some("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz".to_string()),
        metadata_checked_for_tarball: true,
        manifest_fingerprint: None,
    }
}

fn firewall_client() -> lpm_registry::RegistryClient {
    lpm_registry::RegistryClient::new().with_base_url("https://lpm.dev")
}

#[test]
fn npm_firewall_mode_parses_monitor_and_legacy_report_values() {
    assert_eq!(
        NpmFirewallMode::parse("report"),
        Some(NpmFirewallMode::Monitor)
    );
    assert_eq!(NpmFirewallMode::parse("1"), Some(NpmFirewallMode::Enforce));
    assert_eq!(
        NpmFirewallMode::parse("TRUE"),
        Some(NpmFirewallMode::Enforce)
    );
    assert_eq!(
        NpmFirewallMode::parse(" Report "),
        Some(NpmFirewallMode::Monitor)
    );
}

#[test]
fn npm_firewall_mode_rejects_unrecognized_values() {
    assert_eq!(NpmFirewallMode::parse("maybe"), None);
}

#[test]
fn npm_firewall_lookup_mode_parses_package_only_values() {
    assert_eq!(
        NpmFirewallLookupMode::from_env_value(Some("package-only")),
        NpmFirewallLookupMode::PackageOnly
    );
    assert_eq!(
        NpmFirewallLookupMode::from_env_value(Some("package_version")),
        NpmFirewallLookupMode::PackageOnly
    );
}

#[test]
fn npm_firewall_lookup_mode_defaults_to_package_only() {
    assert_eq!(
        NpmFirewallLookupMode::from_env_value(Some("maybe")),
        NpmFirewallLookupMode::PackageOnly
    );
}

#[test]
fn npm_firewall_lookup_mode_accepts_integrity_debug_values() {
    assert_eq!(
        NpmFirewallLookupMode::from_env_value(Some("package-and-integrity")),
        NpmFirewallLookupMode::PackageAndIntegrity
    );
}

#[test]
fn npm_firewall_chunk_size_uses_positive_values_or_default() {
    assert_eq!(npm_firewall_chunk_size("128"), 128);
    assert_eq!(
        npm_firewall_chunk_size("0"),
        DEFAULT_NPM_FIREWALL_CHUNK_SIZE
    );
    assert_eq!(
        npm_firewall_chunk_size("not-a-number"),
        DEFAULT_NPM_FIREWALL_CHUNK_SIZE
    );
}

#[test]
fn only_enforced_firewall_disables_tarball_prefetch() {
    assert!(NpmFirewallMode::Enforce.disables_tarball_prefetch());
    assert!(!NpmFirewallMode::Monitor.disables_tarball_prefetch());
    assert!(!NpmFirewallMode::Off.disables_tarball_prefetch());
}

#[test]
fn npm_firewall_mode_requires_auth_for_monitor_and_enforce() {
    assert_eq!(
        NpmFirewallMode::Monitor.auth_posture(),
        lpm_registry::client::AuthPosture::AuthRequired
    );
    assert_eq!(
        NpmFirewallMode::Enforce.auth_posture(),
        lpm_registry::client::AuthPosture::AuthRequired
    );
}

#[tokio::test]
async fn enforce_firewall_preflight_maps_legacy_entitlement_denial_to_firewall_error() {
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "upstream_proxy_entitlement_required",
            "message": "A Pro account or active org membership is required.",
            "reason": "personal_plan_not_eligible",
            "entitlementSource": "personal"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = request_npm_firewall_preflight(
        NpmFirewallMode::Enforce,
        NpmFirewallLookupMode::PackageOnly,
        lpm_registry::client::NpmFirewallPolicyProfile::default(),
        client,
        vec![lpm_registry::client::NpmFirewallBatchPackage {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            integrity: None,
            published_at: None,
        }],
        false,
    )
    .await
    .expect("a failed enforce request is carried on the result, not returned early");
    assert!(
        result.failure.is_some(),
        "the request failure must be carried as `failure`"
    );

    match finish_npm_firewall_preflight(result, true) {
        Err(lpm_common::LpmError::NpmFirewallEntitlementRequired {
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
        other => panic!("expected firewall entitlement error, got {other:?}"),
    }
}

#[tokio::test]
async fn enforce_firewall_preflight_exchanges_ci_oidc_token_when_no_bearer_exists() {
    use std::ffi::OsString;
    use std::sync::Arc;
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _env = crate::test_env::ScopedEnv::update([
        ("LPM_OIDC_TOKEN", Some(OsString::from("ci-oidc-jwt"))),
        ("LPM_GITLAB_OIDC_TOKEN", None),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", None),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None),
        ("LPM_TOKEN", None),
    ]);
    let server = MockServer::start().await;
    let client = Arc::new(lpm_registry::RegistryClient::new().with_base_url(server.uri()));

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .and(query_param("scope", "read"))
        .and(body_string_contains("\"token\":\"ci-oidc-jwt\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "exchanged-firewall-token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(header("authorization", "Bearer exchanged-firewall-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "req-ci",
            "policyMode": "product_default",
            "summary": {
                "total": 1,
                "allow": 1,
                "warn": 0,
                "block": 0,
                "unknown": 0,
                "matched": 0
            },
            "decisions": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = request_npm_firewall_preflight(
        NpmFirewallMode::Enforce,
        NpmFirewallLookupMode::PackageOnly,
        lpm_registry::client::NpmFirewallPolicyProfile::default(),
        client,
        vec![lpm_registry::client::NpmFirewallBatchPackage {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            integrity: None,
            published_at: None,
        }],
        false,
    )
    .await
    .expect("firewall preflight should use the OIDC-exchanged token");

    assert_eq!(result.stats.checked_count, 1);
    assert_eq!(result.stats.allow_count, 1);
}

#[tokio::test]
async fn enforce_firewall_preflight_prefers_existing_bearer_over_ci_oidc() {
    use std::ffi::OsString;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _env = crate::test_env::ScopedEnv::update([
        ("LPM_OIDC_TOKEN", Some(OsString::from("ci-oidc-jwt"))),
        ("LPM_GITLAB_OIDC_TOKEN", None),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", None),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None),
        ("LPM_TOKEN", None),
    ]);
    let server = MockServer::start().await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("existing-firewall-token"),
    );

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(header("authorization", "Bearer existing-firewall-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "req-existing",
            "policyMode": "product_default",
            "summary": {
                "total": 1,
                "allow": 1,
                "warn": 0,
                "block": 0,
                "unknown": 0,
                "matched": 0
            },
            "decisions": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = request_npm_firewall_preflight(
        NpmFirewallMode::Enforce,
        NpmFirewallLookupMode::PackageOnly,
        lpm_registry::client::NpmFirewallPolicyProfile::default(),
        client,
        vec![lpm_registry::client::NpmFirewallBatchPackage {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            integrity: None,
            published_at: None,
        }],
        false,
    )
    .await
    .expect("firewall preflight should keep the existing bearer");

    assert_eq!(result.stats.checked_count, 1);
    assert_eq!(result.stats.allow_count, 1);
}

#[tokio::test]
async fn chunked_enforce_firewall_preflight_exchanges_ci_oidc_token_once() {
    use std::ffi::OsString;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _env = crate::test_env::ScopedEnv::update([
        ("LPM_OIDC_TOKEN", Some(OsString::from("ci-oidc-jwt"))),
        ("LPM_GITLAB_OIDC_TOKEN", None),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", None),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None),
        ("LPM_TOKEN", None),
    ]);
    let server = MockServer::start().await;
    let client = Arc::new(lpm_registry::RegistryClient::new().with_base_url(server.uri()));

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .and(query_param("scope", "read"))
        .and(body_string_contains("\"token\":\"ci-oidc-jwt\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "exchanged-firewall-token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(header("authorization", "Bearer exchanged-firewall-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "req-ci",
            "policyMode": "product_default",
            "summary": {
                "total": 1,
                "allow": 1,
                "warn": 0,
                "block": 0,
                "unknown": 0,
                "matched": 0
            },
            "decisions": []
        })))
        .expect(2)
        .mount(&server)
        .await;

    let (selected_tx, selected_rx) = mpsc::channel(1);
    let (fetch_tx, mut fetch_rx) = mpsc::channel(1);
    let join = spawn_chunked_npm_firewall_preflight(
        selected_rx,
        fetch_tx,
        Arc::clone(&client),
        NpmFirewallChunkedPreflightConfig {
            route_table: RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            mode: NpmFirewallMode::Enforce,
            lookup_mode: NpmFirewallLookupMode::PackageOnly,
            policy_profile: lpm_registry::client::NpmFirewallPolicyProfile::default(),
            offline: false,
            chunk_size: 1,
            bypass: crate::firewall_bypass::FirewallBypassRules::none(),
        },
    );

    for name in ["left-pad", "is-number"] {
        selected_tx
            .send(lpm_resolver::SelectedPackageEvent {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                is_lpm: false,
                tarball_url: None,
                integrity: None,
                unpacked_size: None,
                platform: None,
                node_engine: None,
                optional: false,
            })
            .await
            .expect("selected package receiver should be open");
    }
    drop(selected_tx);

    let drain = join.drain();
    let collect = async {
        let mut released = Vec::with_capacity(2);
        while let Some(event) = fetch_rx.recv().await {
            released.push(event.name);
        }
        released
    };
    let (result, mut released) = tokio::join!(drain, collect);
    let result = result.expect("chunked firewall preflight should use one exchanged token");
    drop(client);

    released.sort();

    assert_eq!(result.stats.checked_count, 2);
    assert_eq!(result.stats.chunk_count, 2);
    assert_eq!(result.stats.allow_count, 2);
    assert_eq!(released, ["is-number", "left-pad"]);
}

fn selected_event(name: &str) -> lpm_resolver::SelectedPackageEvent {
    lpm_resolver::SelectedPackageEvent {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        is_lpm: false,
        tarball_url: None,
        integrity: None,
        unpacked_size: None,
        platform: None,
        node_engine: None,
        optional: false,
    }
}

async fn delayed_warn_verdict_server(delay: std::time::Duration) -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(200).set_delay(delay).set_body_json(
            serde_json::json!({
                "requestId": "req-delayed",
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
                    "decisionId": "decision-delayed",
                    "name": "left-pad",
                    "version": "1.0.0",
                    "action": "warn",
                    "verdict": "suspicious",
                    "reason": "test warning",
                    "matchSource": "package",
                    "policyMode": "product_default",
                    "enqueueScan": false
                }]
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;
    server
}

fn chunked_config(mode: NpmFirewallMode) -> NpmFirewallChunkedPreflightConfig {
    NpmFirewallChunkedPreflightConfig {
        route_table: RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        mode,
        lookup_mode: NpmFirewallLookupMode::PackageOnly,
        policy_profile: lpm_registry::client::NpmFirewallPolicyProfile::default(),
        offline: false,
        chunk_size: 1,
        bypass: crate::firewall_bypass::FirewallBypassRules::none(),
    }
}

#[tokio::test]
async fn chunked_monitor_firewall_releases_packages_before_the_verdict_and_still_records_it() {
    use std::sync::Arc;
    use tokio::sync::mpsc;

    let server = delayed_warn_verdict_server(std::time::Duration::from_secs(5)).await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let (selected_tx, selected_rx) = mpsc::channel(1);
    let (fetch_tx, mut fetch_rx) = mpsc::channel(1);
    let join = spawn_chunked_npm_firewall_preflight(
        selected_rx,
        fetch_tx,
        client,
        chunked_config(NpmFirewallMode::Monitor),
    );

    selected_tx.send(selected_event("left-pad")).await.unwrap();
    let released = tokio::time::timeout(std::time::Duration::from_secs(2), fetch_rx.recv())
        .await
        .expect("monitor mode must release the package before the verdict returns")
        .expect("fetch channel open");
    assert_eq!(released.name, "left-pad");
    drop(selected_tx);

    let result = join.drain().await.expect("monitor preflight completes");
    assert_eq!(result.stats.checked_count, 1);
    assert_eq!(result.stats.warn_count, 1);
    assert_eq!(result.decisions.len(), 1);
    assert!(fetch_rx.recv().await.is_none());
}

#[tokio::test]
async fn chunked_enforce_firewall_holds_packages_until_the_verdict() {
    use std::sync::Arc;
    use tokio::sync::mpsc;

    let server = delayed_warn_verdict_server(std::time::Duration::from_secs(2)).await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let (selected_tx, selected_rx) = mpsc::channel(1);
    let (fetch_tx, mut fetch_rx) = mpsc::channel(1);
    let join = spawn_chunked_npm_firewall_preflight(
        selected_rx,
        fetch_tx,
        client,
        chunked_config(NpmFirewallMode::Enforce),
    );

    selected_tx.send(selected_event("left-pad")).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), fetch_rx.recv())
            .await
            .is_err(),
        "enforce mode released a package before its verdict"
    );
    drop(selected_tx);
    let (result, released) = tokio::join!(join.drain(), fetch_rx.recv());
    assert_eq!(result.unwrap().stats.warn_count, 1);
    assert_eq!(released.unwrap().name, "left-pad");
}

#[test]
fn npm_firewall_stats_serializes_timing_and_verdict_counts() {
    let mut stats = NpmFirewallPreflightStats {
        mode: NpmFirewallMode::Monitor,
        checked_count: 12,
        batch_ms: 34,
        chunk_count: 2,
        chunk_sum_ms: 30,
        chunk_max_ms: 21,
        ..NpmFirewallPreflightStats::default()
    };
    stats.record_summary(lpm_registry::client::NpmFirewallSummary {
        total: 12,
        allow: 9,
        warn: 1,
        block: 0,
        unknown: 2,
        matched: 1,
    });
    stats.record_worker_diagnostics(Some(lpm_registry::client::NpmFirewallDiagnostics {
        package_count: 12,
        lookup_concurrency: 64,
        kv_read_count: 14,
        kv_lookup_ms: 8.0,
        entitlement_ms: 1.0,
        parse_ms: 2.0,
        total_ms: 11.0,
        matched_count: 1,
        decision_detail: Some("actionable".to_string()),
        returned_decision_count: 1,
        kv_namespace_label: Some("test".to_string()),
        flagged_package_index: Some(
            lpm_registry::client::NpmFirewallFlaggedPackageIndexDiagnostics {
                enabled: true,
                used: true,
                status: Some("hit".to_string()),
                cache_status: Some("miss-l1".to_string()),
                key: Some("test-index".to_string()),
                read_ms: 2.0,
                package_key_count: 1,
                candidate_count: 1,
                detail_read_count: 1,
                skipped_package_lookup_count: 11,
                generated_at: Some("2026-06-24T00:00:00.000Z".to_string()),
            },
        ),
        match_sources: lpm_registry::client::NpmFirewallMatchSources {
            integrity: 1,
            package: 0,
            none: 11,
        },
        lookup_duration: lpm_registry::client::NpmFirewallLookupDuration {
            count: 12,
            sum_ms: 70.0,
            max_ms: 9.0,
            p50_ms: 5.0,
            p95_ms: 9.0,
        },
    }));
    stats.record_client_timing(Some(lpm_registry::client::NpmFirewallClientTiming {
        request_ms: 21,
        body_read_ms: 3,
        json_parse_ms: 4,
        total_ms: 28,
        request_body_bytes: 2048,
        response_body_bytes: 4096,
    }));

    let json = stats.to_json();

    assert_eq!(json["enabled"], true);
    assert_eq!(json["mode"], "monitor");
    assert_eq!(json["lookup_mode"], "package_only");
    assert_eq!(json["checked_count"], 12);
    assert_eq!(json["batch_ms"], 34);
    assert_eq!(json["chunk_count"], 2);
    assert_eq!(json["chunk_sum_ms"], 30);
    assert_eq!(json["chunk_max_ms"], 21);
    assert_eq!(json["allow_count"], 9);
    assert_eq!(json["warn_count"], 1);
    assert_eq!(json["block_count"], 0);
    assert_eq!(json["unknown_count"], 2);
    assert_eq!(json["matched_count"], 1);
    assert_eq!(json["worker"]["lookupConcurrency"], 64);
    assert_eq!(json["worker"]["kvReadCount"], 14);
    assert_eq!(json["worker"]["decisionDetail"], "actionable");
    assert_eq!(json["worker"]["returnedDecisionCount"], 1);
    assert_eq!(json["worker"]["kvNamespaceLabel"], "test");
    assert_eq!(json["worker"]["flaggedPackageIndex"]["enabled"], true);
    assert_eq!(json["worker"]["flaggedPackageIndex"]["used"], true);
    assert_eq!(json["worker"]["flaggedPackageIndex"]["status"], "hit");
    assert_eq!(
        json["worker"]["flaggedPackageIndex"]["skippedPackageLookupCount"],
        11
    );
    assert_eq!(json["worker"]["matchSources"]["integrity"], 1);
    assert_eq!(json["worker"]["lookupDuration"]["p95Ms"], 9.0);
    assert_eq!(json["client"]["requestMs"], 21);
    assert_eq!(json["client"]["bodyReadMs"], 3);
    assert_eq!(json["client"]["jsonParseMs"], 4);
    assert_eq!(json["client"]["totalMs"], 28);
    assert_eq!(json["client"]["requestBodyBytes"], 2048);
    assert_eq!(json["client"]["responseBodyBytes"], 4096);
}

#[test]
fn npm_firewall_package_includes_public_npm_registry_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("left-pad", "registry+https://registry.npmjs.org");

    let verdict_package = npm_firewall_package(
        &package,
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageAndIntegrity,
    )
    .expect("public npm package is eligible");

    assert_eq!(verdict_package.name, "left-pad");
    assert_eq!(verdict_package.integrity.as_deref(), Some("sha512-test"));
    assert_eq!(
        verdict_package.published_at.as_deref(),
        Some("2025-01-01T00:00:00.000Z")
    );
}

#[test]
fn npm_firewall_package_includes_public_npm_registry_from_npmrc() {
    let client = firewall_client();
    for (registry, source) in [
        (
            "https://registry.npmjs.org/",
            "registry+https://registry.npmjs.org",
        ),
        (
            "https://registry.npmjs.org:443/",
            "registry+https://registry.npmjs.org:443",
        ),
        (
            "https://registry.npmjs.com/",
            "registry+https://registry.npmjs.com",
        ),
        (
            "https://registry.npmjs.com:443/",
            "registry+https://registry.npmjs.com:443",
        ),
        (
            "https://REGISTRY.NPMJS.ORG/",
            "registry+https://REGISTRY.NPMJS.ORG",
        ),
    ] {
        let npmrc = lpm_registry::NpmrcConfig::parse(
            &format!("registry={registry}\n"),
            "test-npmrc",
            &|_| None,
        );
        let route_table = RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let package = package_with_source("left-pad", source);

        let verdict_package = npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity,
        )
        .expect("explicit public npm registry is eligible");

        assert_eq!(verdict_package.name, "left-pad");
        assert_eq!(verdict_package.integrity.as_deref(), Some("sha512-test"));
    }
}

#[test]
fn npm_firewall_package_includes_public_npm_routed_through_lpm_proxy() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("left-pad", "registry+https://lpm.dev");

    let verdict_package = npm_firewall_package(
        &package,
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageOnly,
    )
    .expect("public npm through lpm.dev proxy is eligible");

    assert_eq!(verdict_package.name, "left-pad");
    assert_eq!(verdict_package.version, "1.0.0");
}

#[test]
fn npm_firewall_package_can_omit_integrity_for_package_only_lookup() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("left-pad", "registry+https://registry.npmjs.org");

    let verdict_package = npm_firewall_package(
        &package,
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageOnly,
    )
    .expect("public npm package is eligible");

    assert_eq!(verdict_package.name, "left-pad");
    assert_eq!(verdict_package.integrity.as_deref(), None);
}

#[test]
fn npm_firewall_package_skips_custom_registry_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("private-pkg", "registry+https://registry.internal.test");

    assert!(
        npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[test]
fn npm_firewall_package_skips_lpm_same_origin_custom_registry_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("private-pkg", "registry+https://lpm.dev/private-registry");

    assert!(
        npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[test]
fn npm_firewall_package_skips_lpm_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("@lpm.dev/private", "registry+https://lpm.dev");

    assert!(
        npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[test]
fn npm_firewall_package_skips_incompatible_platform_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let mut package = package_with_source("left-pad", "registry+https://registry.npmjs.org");
    package.platform = Some(lpm_resolver::PlatformMeta {
        os: vec!["definitely-not-this-os".to_string()],
        cpu: Vec::new(),
        libc: Vec::new(),
    });

    assert!(
        npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[test]
fn npm_firewall_package_from_selected_event_uses_package_only_lookup() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let event = lpm_resolver::SelectedPackageEvent {
        name: "left-pad".to_string(),
        version: "1.0.0".to_string(),
        is_lpm: false,
        tarball_url: None,
        integrity: Some("sha512-test".to_string()),
        unpacked_size: None,
        platform: None,
        node_engine: None,
        optional: false,
    };

    let verdict_package = npm_firewall_package_from_selected_event(
        &event,
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageOnly,
    )
    .expect("public npm package is eligible");

    assert_eq!(verdict_package.name, "left-pad");
    assert_eq!(verdict_package.version, "1.0.0");
    assert_eq!(verdict_package.integrity.as_deref(), None);
}

#[test]
fn npm_firewall_package_from_selected_event_includes_public_npm_registry_from_npmrc() {
    let client = firewall_client();
    for registry in [
        "https://registry.npmjs.org/",
        "https://registry.npmjs.org:443/",
        "https://registry.npmjs.com/",
        "https://registry.npmjs.com:443/",
        "https://REGISTRY.NPMJS.ORG/",
    ] {
        let npmrc = lpm_registry::NpmrcConfig::parse(
            &format!("registry={registry}\n"),
            "test-npmrc",
            &|_| None,
        );
        let route_table = RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let event = lpm_resolver::SelectedPackageEvent {
            name: "left-pad".to_string(),
            version: "1.0.0".to_string(),
            is_lpm: false,
            tarball_url: None,
            integrity: Some("sha512-test".to_string()),
            unpacked_size: None,
            platform: None,
            node_engine: None,
            optional: false,
        };

        let verdict_package = npm_firewall_package_from_selected_event(
            &event,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageOnly,
        )
        .expect("explicit public npm registry is eligible");

        assert_eq!(verdict_package.name, "left-pad");
        assert_eq!(verdict_package.integrity.as_deref(), None);
    }
}

#[test]
fn npm_firewall_package_from_selected_event_skips_incompatible_platform_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let event = lpm_resolver::SelectedPackageEvent {
        name: "left-pad".to_string(),
        version: "1.0.0".to_string(),
        is_lpm: false,
        tarball_url: None,
        integrity: Some("sha512-test".to_string()),
        unpacked_size: None,
        platform: Some(lpm_resolver::PlatformMeta {
            os: vec!["definitely-not-this-os".to_string()],
            cpu: Vec::new(),
            libc: Vec::new(),
        }),
        node_engine: None,
        optional: true,
    };

    assert!(
        npm_firewall_package_from_selected_event(
            &event,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[tokio::test]
async fn monitor_verdict_cache_reuses_clean_allows_and_keeps_enforce_live() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Cache-Control", "max-age=300")
                .set_body_json(serde_json::json!({
                    "requestId": "req-allow",
                    "policyMode": "product_default",
                    "summary": {
                        "total": 1,
                        "allow": 1,
                        "warn": 0,
                        "block": 0,
                        "unknown": 0,
                        "matched": 0
                    },
                    "decisions": []
                })),
        )
        .expect(3)
        .mount(&server)
        .await;

    let cache = tempfile::tempdir().unwrap();
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("monitor-cache-token")
            .with_cache_dir(Some(cache.path().to_path_buf())),
    );
    let pkgs = vec![lpm_registry::client::NpmFirewallBatchPackage {
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        integrity: None,
        published_at: None,
    }];
    let profile = lpm_registry::client::NpmFirewallPolicyProfile::default();

    // 1. Cold monitor call hits server and caches clean allow.
    let first = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs.clone(),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(first.stats.checked_count, 1);
    assert_eq!(first.stats.allow_count, 1);
    assert_eq!(first.stats.cache_hit_count, 0);

    // 2. Warm monitor call serves from cache with zero HTTP calls.
    let second = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs.clone(),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(second.stats.checked_count, 1);
    assert_eq!(second.stats.allow_count, 1);
    assert_eq!(second.stats.cache_hit_count, 1);
    assert!(!second.stats.rpc_failed);
    assert_eq!(second.stats.to_json()["cache_hit_count"], 1);

    // 3. --force bypasses monitor cache.
    let forced = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs.clone(),
        false,
        true,
    )
    .await
    .unwrap();
    assert_eq!(forced.stats.cache_hit_count, 0);

    // 4. Enforce mode always calls live even when monitor cache is warm.
    let enforced = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Enforce,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs,
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(enforced.stats.cache_hit_count, 0);
    server.verify().await;
}

#[tokio::test]
async fn monitor_verdict_cache_never_caches_warns_unknowns_or_no_store() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Cache-Control", "no-store")
                .set_body_json(serde_json::json!({
                    "requestId": "req-nostore",
                    "policyMode": "product_default",
                    "summary": {
                        "total": 1,
                        "allow": 1,
                        "warn": 0,
                        "block": 0,
                        "unknown": 0,
                        "matched": 0
                    },
                    "decisions": []
                })),
        )
        .expect(2)
        .mount(&server)
        .await;

    let cache = tempfile::tempdir().unwrap();
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("monitor-nostore-token")
            .with_cache_dir(Some(cache.path().to_path_buf())),
    );
    let pkgs = vec![lpm_registry::client::NpmFirewallBatchPackage {
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        integrity: None,
        published_at: None,
    }];
    let profile = lpm_registry::client::NpmFirewallPolicyProfile::default();

    for _ in 0..2 {
        let res = request_npm_firewall_preflight_with_force(
            NpmFirewallMode::Monitor,
            NpmFirewallLookupMode::PackageOnly,
            profile,
            Arc::clone(&client),
            pkgs.clone(),
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res.stats.cache_hit_count, 0);
    }
    server.verify().await;
}

#[tokio::test]
async fn monitor_verdict_cache_isolates_auth_identity_and_policy_profile() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "req-iso",
            "policyMode": "product_default",
            "summary": {
                "total": 1,
                "allow": 1,
                "warn": 0,
                "block": 0,
                "unknown": 0,
                "matched": 0
            },
            "decisions": []
        })))
        .expect(3)
        .mount(&server)
        .await;

    let cache = tempfile::tempdir().unwrap();
    let client_a = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("token-user-a")
            .with_cache_dir(Some(cache.path().to_path_buf())),
    );
    let client_b = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("token-user-b")
            .with_cache_dir(Some(cache.path().to_path_buf())),
    );
    let pkgs = vec![lpm_registry::client::NpmFirewallBatchPackage {
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        integrity: None,
        published_at: None,
    }];
    let default_profile = lpm_registry::client::NpmFirewallPolicyProfile::default();
    let mut stricter_profile = default_profile;
    stricter_profile.lpm_ai_suspicious = lpm_registry::client::NpmFirewallPolicyAction::Block;

    // 1. User A populates cache.
    let res1 = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        default_profile,
        Arc::clone(&client_a),
        pkgs.clone(),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(res1.stats.cache_hit_count, 0);

    // 2. User B must miss cache.
    let res2 = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        default_profile,
        client_b,
        pkgs.clone(),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(res2.stats.cache_hit_count, 0);

    // 3. User A with stricter policy profile must miss cache.
    let res3 = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        stricter_profile,
        client_a,
        pkgs,
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(res3.stats.cache_hit_count, 0);
    server.verify().await;
}

#[tokio::test]
async fn monitor_verdict_cache_caches_unflagged_allows_and_rechecks_warned_packages() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let pkgs = body["packages"].as_array().unwrap();
            if pkgs.len() == 2 {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "requestId": "req-mixed-1",
                    "policyMode": "product_default",
                    "summary": {
                        "total": 2,
                        "allow": 1,
                        "warn": 1,
                        "block": 0,
                        "unknown": 1,
                        "matched": 1
                    },
                    "decisions": [{
                        "decisionId": "dec-warn",
                        "name": "flagged-pkg",
                        "version": "1.0.0",
                        "action": "warn",
                        "verdict": "suspicious",
                        "reason": "test warning",
                        "matchSource": "package",
                        "policyMode": "product_default",
                        "enqueueScan": false
                    }]
                }))
            } else {
                assert_eq!(pkgs.len(), 1);
                assert_eq!(pkgs[0]["name"], "flagged-pkg");
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "requestId": "req-mixed-2",
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
                        "decisionId": "dec-warn-2",
                        "name": "flagged-pkg",
                        "version": "1.0.0",
                        "action": "warn",
                        "verdict": "suspicious",
                        "reason": "test warning",
                        "matchSource": "package",
                        "policyMode": "product_default",
                        "enqueueScan": false
                    }]
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;

    let cache = tempfile::tempdir().unwrap();
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("monitor-mixed-token")
            .with_cache_dir(Some(cache.path().to_path_buf())),
    );
    let pkgs = vec![
        lpm_registry::client::NpmFirewallBatchPackage {
            name: "clean-pkg".to_string(),
            version: "1.0.0".to_string(),
            integrity: None,
            published_at: None,
        },
        lpm_registry::client::NpmFirewallBatchPackage {
            name: "flagged-pkg".to_string(),
            version: "1.0.0".to_string(),
            integrity: None,
            published_at: None,
        },
    ];
    let profile = lpm_registry::client::NpmFirewallPolicyProfile::default();

    let first = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs.clone(),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(first.stats.checked_count, 2);
    assert_eq!(first.stats.allow_count, 1);
    assert_eq!(first.stats.warn_count, 1);
    assert_eq!(first.stats.unknown_count, 1);
    assert_eq!(first.stats.cache_hit_count, 0);

    // Second run serves clean-pkg from cache (preserving unknown_count) and only queries flagged-pkg live.
    let second = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        client,
        pkgs,
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(second.stats.checked_count, 2);
    assert_eq!(second.stats.allow_count, 1);
    assert_eq!(second.stats.warn_count, 1);
    assert_eq!(second.stats.unknown_count, 1);
    assert_eq!(second.stats.cache_hit_count, 1);
    assert_eq!(second.decisions.len(), 1);
    server.verify().await;
}

#[tokio::test]
async fn monitor_verdict_cache_honors_age_header_and_evicts_on_force_warn() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_cb = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(move |_request: &wiremock::Request| {
            let n = calls_cb.fetch_add(1, Ordering::SeqCst);
            match n {
                // First call: max-age=60, Age=60 → remaining TTL = 0 → NoStore!
                0 => ResponseTemplate::new(200)
                    .insert_header("Cache-Control", "max-age=60")
                    .insert_header("Age", "60")
                    .set_body_json(serde_json::json!({
                        "requestId": "req-aged",
                        "policyMode": "product_default",
                        "summary": {
                            "total": 1,
                            "allow": 1,
                            "warn": 0,
                            "block": 0,
                            "unknown": 0,
                            "matched": 1
                        },
                        "decisions": []
                    })),
                // Second call: fresh clean allow (matched=1) → cached!
                1 => ResponseTemplate::new(200)
                    .insert_header("Cache-Control", "max-age=60")
                    .set_body_json(serde_json::json!({
                        "requestId": "req-fresh",
                        "policyMode": "product_default",
                        "summary": {
                            "total": 1,
                            "allow": 1,
                            "warn": 0,
                            "block": 0,
                            "unknown": 0,
                            "matched": 1
                        },
                        "decisions": []
                    })),
                // Third (--force) & fourth (post-eviction) calls: warn!
                _ => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "requestId": "req-warn",
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
                        "decisionId": "dec-warn",
                        "name": "left-pad",
                        "version": "1.3.0",
                        "action": "warn",
                        "verdict": "suspicious",
                        "reason": "newly flagged",
                        "matchSource": "package",
                        "policyMode": "product_default",
                        "enqueueScan": false
                    }]
                })),
            }
        })
        .expect(4)
        .mount(&server)
        .await;

    let cache = tempfile::tempdir().unwrap();
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("monitor-age-token")
            .with_cache_dir(Some(cache.path().to_path_buf())),
    );
    let pkgs = vec![lpm_registry::client::NpmFirewallBatchPackage {
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        integrity: None,
        published_at: None,
    }];
    let profile = lpm_registry::client::NpmFirewallPolicyProfile::default();

    // 1. Aged response is not stored.
    let first = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs.clone(),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(first.stats.cache_hit_count, 0);

    // 2. Misses cache (because aged response was not stored) and populates cache.
    let second = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs.clone(),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(second.stats.cache_hit_count, 0);

    // 3. Warm hit preserves exact matched_count = 1.
    let warm = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs.clone(),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(warm.stats.cache_hit_count, 1);
    assert_eq!(warm.stats.matched_count, 1);
    assert_eq!(warm.stats.unknown_count, 0);

    // 4. --force observes Warn and evicts the cached Allow.
    let forced = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        Arc::clone(&client),
        pkgs.clone(),
        false,
        true,
    )
    .await
    .unwrap();
    assert_eq!(forced.stats.warn_count, 1);

    // 5. Next normal run must miss cache and observe Warn live.
    let after_evict = request_npm_firewall_preflight_with_force(
        NpmFirewallMode::Monitor,
        NpmFirewallLookupMode::PackageOnly,
        profile,
        client,
        pkgs,
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(after_evict.stats.cache_hit_count, 0);
    assert_eq!(after_evict.stats.warn_count, 1);
    server.verify().await;
}

#[tokio::test]
async fn monitor_verdict_cache_fails_closed_on_incomplete_non_allow_decisions() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Summary claims 2 warns, but decisions only lists 1 — must not cache any package.
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "req-partial",
            "policyMode": "product_default",
            "summary": {
                "total": 3,
                "allow": 1,
                "warn": 2,
                "block": 0,
                "unknown": 1,
                "matched": 2
            },
            "decisions": [{
                "decisionId": "dec-1",
                "name": "bad-a",
                "version": "1.0.0",
                "action": "warn",
                "verdict": "suspicious",
                "reason": "warn a",
                "matchSource": "package",
                "policyMode": "product_default",
                "enqueueScan": false
            }]
        })))
        .expect(2)
        .mount(&server)
        .await;

    let cache = tempfile::tempdir().unwrap();
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("monitor-partial-token")
            .with_cache_dir(Some(cache.path().to_path_buf())),
    );
    let pkgs = vec![
        lpm_registry::client::NpmFirewallBatchPackage {
            name: "clean-pkg".to_string(),
            version: "1.0.0".to_string(),
            integrity: None,
            published_at: None,
        },
        lpm_registry::client::NpmFirewallBatchPackage {
            name: "bad-a".to_string(),
            version: "1.0.0".to_string(),
            integrity: None,
            published_at: None,
        },
        lpm_registry::client::NpmFirewallBatchPackage {
            name: "bad-b".to_string(),
            version: "1.0.0".to_string(),
            integrity: None,
            published_at: None,
        },
    ];
    let profile = lpm_registry::client::NpmFirewallPolicyProfile::default();

    for _ in 0..2 {
        let res = request_npm_firewall_preflight_with_force(
            NpmFirewallMode::Monitor,
            NpmFirewallLookupMode::PackageOnly,
            profile,
            Arc::clone(&client),
            pkgs.clone(),
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res.stats.cache_hit_count, 0);
    }
    server.verify().await;
}

#[cfg(unix)]
#[tokio::test]
async fn monitor_verdict_cache_refuses_symlinked_cache_directory() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "req-symlink",
            "policyMode": "product_default",
            "summary": {
                "total": 1,
                "allow": 1,
                "warn": 0,
                "block": 0,
                "unknown": 0,
                "matched": 1
            },
            "decisions": []
        })))
        .expect(2)
        .mount(&server)
        .await;

    let root = tempfile::tempdir().unwrap();
    let cache_root = root.path().join("cache");
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&cache_root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, cache_root.join("firewall-verdicts")).unwrap();

    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("monitor-symlink-token")
            .with_cache_dir(Some(cache_root)),
    );
    let pkgs = vec![lpm_registry::client::NpmFirewallBatchPackage {
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        integrity: None,
        published_at: None,
    }];
    let profile = lpm_registry::client::NpmFirewallPolicyProfile::default();

    for _ in 0..2 {
        let res = request_npm_firewall_preflight_with_force(
            NpmFirewallMode::Monitor,
            NpmFirewallLookupMode::PackageOnly,
            profile,
            Arc::clone(&client),
            pkgs.clone(),
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res.stats.cache_hit_count, 0);
    }
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
    server.verify().await;
}

fn verdict_decision(name: &str, action: &str) -> serde_json::Value {
    serde_json::json!({
        "decisionId": format!("decision-{name}"),
        "name": name,
        "version": "1.0.0",
        "action": action,
        "verdict": if action == "block" { "malicious" } else { "clean" },
        "reason": format!("{action} {name}"),
        "matchSource": "package",
        "policyMode": "product_default",
        "enqueueScan": false,
        "policy": { "group": "lpm_ai_confirmed_malware" },
        "display": {
            "summary": format!("{name} summary"),
            "reportUrl": format!("https://firewall.lpm.dev/npm/{name}/v/1.0.0")
        }
    })
}

fn verdict_response(block: u64, decisions: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "requestId": "req-test",
        "policyMode": "product_default",
        "summary": {
            "total": 1,
            "allow": u64::from(block == 0),
            "warn": 0,
            "block": block,
            "unknown": 0,
            "matched": block
        },
        "decisions": decisions
    })
}

fn decision(name: &str, action: &str) -> lpm_registry::client::NpmFirewallDecision {
    serde_json::from_value(verdict_decision(name, action)).unwrap()
}

#[tokio::test]
async fn chunked_enforce_firewall_names_blocks_from_every_chunk_and_releases_nothing_after_one() {
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    for name in ["evil-a", "evil-c"] {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-firewall/verdicts"))
            .and(body_string_contains(format!("\"name\":\"{name}\"")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(verdict_response(1, vec![verdict_decision(name, "block")])),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"good-b\""))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(400))
                .set_body_json(verdict_response(0, Vec::new())),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let (selected_tx, selected_rx) = mpsc::channel(4);
    let (fetch_tx, mut fetch_rx) = mpsc::channel(4);
    let join = spawn_chunked_npm_firewall_preflight(
        selected_rx,
        fetch_tx,
        client,
        chunked_config(NpmFirewallMode::Enforce),
    );

    selected_tx.send(selected_event("evil-a")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    selected_tx.send(selected_event("good-b")).await.unwrap();
    selected_tx.send(selected_event("evil-c")).await.unwrap();
    drop(selected_tx);

    let result = join.drain().await.expect("enforce preflight completes");
    assert!(
        fetch_rx.recv().await.is_none(),
        "no package may download once a chunk is blocked"
    );
    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected a firewall block");
    };
    let mut names: Vec<_> = blocked
        .packages
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["evil-a", "evil-c"]);
    assert_eq!(
        blocked.source,
        lpm_common::NpmFirewallBlockSource::Preflight
    );
}

#[test]
fn firewall_block_counted_only_in_the_summary_still_blocks() {
    let stats = NpmFirewallPreflightStats {
        mode: NpmFirewallMode::Enforce,
        block_count: 2,
        unattributed_block_count: 1,
        ..NpmFirewallPreflightStats::default()
    };
    let result = NpmFirewallPreflightResult {
        failure: None,
        stats,
        decisions: vec![decision("named-block", "block")],
        report_error: None,
    };

    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected a firewall block");
    };

    assert_eq!(blocked.packages.len(), 1);
    assert_eq!(blocked.unattributed_count, 1);
    assert_eq!(blocked.blocked_count(), 2);
    assert_eq!(blocked.to_string(), "2 packages blocked by LPM Firewall");
}

#[tokio::test]
async fn firewall_summary_without_a_block_row_is_recorded_as_unattributed() {
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(verdict_response(1, Vec::new())))
        .expect(1)
        .mount(&server)
        .await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let package = lpm_registry::client::NpmFirewallBatchPackage {
        name: "summary-only".into(),
        version: "1.0.0".into(),
        integrity: None,
        published_at: None,
    };

    let result = request_npm_firewall_preflight(
        NpmFirewallMode::Enforce,
        NpmFirewallLookupMode::PackageOnly,
        lpm_registry::client::NpmFirewallPolicyProfile::default(),
        client,
        vec![package],
        false,
    )
    .await
    .unwrap();

    assert_eq!(result.stats.unattributed_block_count, 1);
    assert!(matches!(
        finish_npm_firewall_preflight(result, true),
        Err(LpmError::NpmFirewallBlocked(blocked)) if blocked.unattributed_count == 1
    ));
}

#[test]
fn firewall_block_error_names_each_blocked_version_once() {
    let stats = NpmFirewallPreflightStats {
        mode: NpmFirewallMode::Enforce,
        block_count: 2,
        ..NpmFirewallPreflightStats::default()
    };
    let result = NpmFirewallPreflightResult {
        failure: None,
        stats,
        decisions: vec![decision("twice", "block"), decision("twice", "block")],
        report_error: None,
    };

    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected a firewall block");
    };

    assert_eq!(blocked.packages.len(), 1);
    let package = &blocked.packages[0];
    assert_eq!(package.coordinate(), "twice@1.0.0");
    assert_eq!(
        package.policy_group.as_deref(),
        Some("lpm_ai_confirmed_malware")
    );
    assert_eq!(
        package.report_url.as_deref(),
        Some("https://firewall.lpm.dev/npm/twice/v/1.0.0")
    );
}

#[test]
fn firewall_verdict_request_asks_once_for_peer_instances_of_one_version() {
    let client = firewall_client();
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let first = package_with_source("shared", "registry+https://registry.npmjs.org");
    let second = first.clone();

    let requested = npm_firewall_packages(
        &[first, second],
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageOnly,
    );

    assert_eq!(requested.len(), 1);
    assert_eq!(requested[0].name, "shared");
}

fn global_rule(raw: &str) -> FirewallBypassRule {
    FirewallBypassRule::new(
        &crate::firewall_bypass::FirewallBypassSpec::parse(raw).unwrap(),
        FirewallBypassScope::Global,
        None,
        false,
        lpm_common::Timestamp::now(),
    )
}

fn grouped_block(name: &str, verdict: &str, group: &str) -> serde_json::Value {
    let mut decision = verdict_decision(name, "block");
    decision["verdict"] = serde_json::json!(verdict);
    decision["policy"] = serde_json::json!({ "group": group });
    decision
}

async fn verdict_server(response: serde_json::Value) -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;
    server
}

async fn enforce_with_rules(
    response: serde_json::Value,
    requested: &[&str],
    bypass: FirewallBypassRules,
) -> NpmFirewallPreflightResult {
    let server = verdict_server(response).await;
    let client = std::sync::Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    request_npm_firewall_preflight_with_bypass(
        PreflightSettings {
            mode: NpmFirewallMode::Enforce,
            lookup_mode: NpmFirewallLookupMode::PackageOnly,
            policy_profile: lpm_registry::client::NpmFirewallPolicyProfile::default(),
            offline: false,
            force: false,
            bypass,
        },
        client,
        requested
            .iter()
            .map(|name| lpm_registry::client::NpmFirewallBatchPackage {
                name: (*name).to_string(),
                version: "1.0.0".into(),
                integrity: None,
                published_at: None,
            })
            .collect(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn bypass_rule_lets_a_policy_block_through_and_reports_the_rule() {
    let result = enforce_with_rules(
        verdict_response(
            1,
            vec![grouped_block(
                "agent-tool",
                "suspicious",
                "lpm_ai_agent_control_surface",
            )],
        ),
        &["agent-tool"],
        FirewallBypassRules::preloaded(&[global_rule("agent-tool")], Vec::new(), None, true),
    )
    .await;

    let stats = finish_npm_firewall_preflight(result, true).expect("the rule lifts the block");

    assert_eq!(stats.bypassed.len(), 1);
    assert_eq!(stats.bypassed[0].rule.spec, "agent-tool");
    let json = stats.to_security_json();
    assert_eq!(json["bypassed_count"], 1);
    assert_eq!(json["bypassed"][0]["name"], "agent-tool");
    assert_eq!(json["bypassed"][0]["rule"]["spec"], "agent-tool");
    assert_eq!(stats.to_json().get("bypassed"), None);
}

#[tokio::test]
async fn name_rule_does_not_lift_a_malware_block() {
    let result = enforce_with_rules(
        verdict_response(
            1,
            vec![grouped_block(
                "hijacked",
                "malicious",
                "lpm_ai_confirmed_malware",
            )],
        ),
        &["hijacked"],
        FirewallBypassRules::preloaded(&[global_rule("hijacked")], Vec::new(), None, true),
    )
    .await;

    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected a firewall block");
    };

    assert_eq!(blocked.packages[0].block_class.as_deref(), Some("malware"));
    assert!(!blocked.packages[0].bypassable);
    assert_eq!(blocked.bypass_command, None);
}

#[tokio::test]
async fn bypass_rule_lifts_no_block_row_for_a_version_the_request_did_not_ask_about() {
    let result = enforce_with_rules(
        verdict_response(
            1,
            vec![grouped_block(
                "unrequested",
                "suspicious",
                "lpm_ai_suspicious",
            )],
        ),
        &["requested"],
        FirewallBypassRules::preloaded(&[global_rule("unrequested")], Vec::new(), None, true),
    )
    .await;

    assert!(result.stats.bypassed.is_empty());
    assert!(finish_npm_firewall_preflight(result, true).is_err());
}

#[tokio::test]
async fn block_error_offers_one_bypass_command_for_every_liftable_block() {
    let result = enforce_with_rules(
        serde_json::json!({
            "requestId": "req-test",
            "policyMode": "product_default",
            "summary": { "total": 2, "allow": 0, "warn": 0, "block": 2, "unknown": 0, "matched": 2 },
            "decisions": [
                grouped_block("first-tool", "suspicious", "lpm_ai_telemetry"),
                grouped_block("@scope/second", "suspicious", "lpm_ai_agent_control_surface"),
            ]
        }),
        &["first-tool", "@scope/second"],
        FirewallBypassRules::none(),
    )
    .await;

    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected a firewall block");
    };

    assert_eq!(
        blocked.bypass_command.as_deref(),
        Some("lpm firewall bypass add \"first-tool@1.0.0\" \"@scope/second@1.0.0\"")
    );
}

#[tokio::test]
async fn block_error_explains_why_a_managed_policy_leaves_no_bypass() {
    let result = enforce_with_rules(
        verdict_response(
            1,
            vec![grouped_block(
                "agent-tool",
                "suspicious",
                "lpm_ai_agent_control_surface",
            )],
        ),
        &["agent-tool"],
        FirewallBypassRules::preloaded(&[global_rule("agent-tool")], Vec::new(), None, false),
    )
    .await;

    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected a firewall block");
    };

    assert_eq!(blocked.bypass_command, None);
    assert!(
        blocked
            .bypass_unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("[firewall].bypass")),
        "{:?}",
        blocked.bypass_unavailable_reason
    );
}

#[tokio::test]
async fn block_error_says_when_the_bypass_rules_could_not_be_read() {
    let result = enforce_with_rules(
        verdict_response(
            1,
            vec![grouped_block(
                "agent-tool",
                "suspicious",
                "lpm_ai_agent_control_surface",
            )],
        ),
        &["agent-tool"],
        FirewallBypassRules::unreadable("failed signature verification"),
    )
    .await;

    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected a firewall block");
    };

    assert!(
        blocked
            .bypass_unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("failed signature verification")),
        "{:?}",
        blocked.bypass_unavailable_reason
    );
}

#[tokio::test]
async fn managed_bypass_entry_lifts_a_block_where_local_rules_do_not_apply() {
    let result = enforce_with_rules(
        verdict_response(
            1,
            vec![grouped_block(
                "agent-tool",
                "suspicious",
                "lpm_ai_agent_control_surface",
            )],
        ),
        &["agent-tool"],
        FirewallBypassRules::preloaded(
            &[],
            vec![crate::security_approval::ManagedFirewallBypass {
                spec: "agent-tool@1.0.0".into(),
                covers_malware: false,
            }],
            None,
            false,
        ),
    )
    .await;

    let stats = finish_npm_firewall_preflight(result, true).unwrap();

    assert_eq!(stats.bypassed[0].rule.source, "managed");
}

#[tokio::test]
async fn chunked_enforce_firewall_releases_a_chunk_whose_only_block_a_rule_lifts() {
    use std::sync::Arc;
    use tokio::sync::mpsc;

    let server = verdict_server(verdict_response(
        1,
        vec![grouped_block("left-pad", "suspicious", "lpm_ai_telemetry")],
    ))
    .await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let (selected_tx, selected_rx) = mpsc::channel(1);
    let (fetch_tx, mut fetch_rx) = mpsc::channel(1);
    let mut config = chunked_config(NpmFirewallMode::Enforce);
    config.bypass =
        FirewallBypassRules::preloaded(&[global_rule("left-pad@1.0.0")], Vec::new(), None, true);
    let join = spawn_chunked_npm_firewall_preflight(selected_rx, fetch_tx, client, config);

    selected_tx.send(selected_event("left-pad")).await.unwrap();
    drop(selected_tx);
    let (result, released) = tokio::join!(join.drain(), fetch_rx.recv());

    assert_eq!(
        released.expect("the lifted package downloads").name,
        "left-pad"
    );
    let stats = finish_npm_firewall_preflight(result.unwrap(), true).unwrap();
    assert_eq!(stats.bypassed.len(), 1);
}

#[tokio::test]
async fn chunked_enforce_keeps_a_found_block_when_a_later_chunk_request_fails() {
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"evil-a\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(verdict_response(
            1,
            vec![verdict_decision("evil-a", "block")],
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"broken-b\""))
        .respond_with(ResponseTemplate::new(500).set_delay(std::time::Duration::from_millis(300)))
        .mount(&server)
        .await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let (selected_tx, selected_rx) = mpsc::channel(4);
    let (fetch_tx, mut fetch_rx) = mpsc::channel(4);
    let join = spawn_chunked_npm_firewall_preflight(
        selected_rx,
        fetch_tx,
        client,
        chunked_config(NpmFirewallMode::Enforce),
    );

    selected_tx.send(selected_event("evil-a")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    selected_tx.send(selected_event("broken-b")).await.unwrap();
    drop(selected_tx);

    let result = join.drain().await.expect("the found block survives");
    assert!(fetch_rx.recv().await.is_none());
    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected the firewall block");
    };
    assert_eq!(blocked.packages[0].name, "evil-a");
    assert!(blocked.unchecked_reason.is_some());
}

#[tokio::test]
async fn batch_enforce_keeps_a_found_block_when_a_later_batch_request_fails() {
    use std::sync::Arc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"p-0\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(verdict_response(
            1,
            vec![{
                let mut decision = verdict_decision("p-0", "block");
                decision["version"] = serde_json::json!("1.0.0");
                decision
            }],
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"p-512\""))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let packages = (0..=512)
        .map(|index| lpm_registry::client::NpmFirewallBatchPackage {
            name: format!("p-{index}"),
            version: "1.0.0".into(),
            integrity: None,
            published_at: None,
        })
        .collect();

    let result = request_npm_firewall_preflight(
        NpmFirewallMode::Enforce,
        NpmFirewallLookupMode::PackageOnly,
        lpm_registry::client::NpmFirewallPolicyProfile::default(),
        client,
        packages,
        false,
    )
    .await
    .expect("the found block survives");

    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected the firewall block");
    };
    assert_eq!(blocked.packages[0].name, "p-0");
    assert!(blocked.unchecked_reason.is_some());
}

#[tokio::test]
async fn chunked_enforce_keeps_a_block_that_arrives_after_an_earlier_chunk_failed() {
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"broken-a\""))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"evil-b\""))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(verdict_response(
                    1,
                    vec![verdict_decision("evil-b", "block")],
                ))
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&server)
        .await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let (selected_tx, selected_rx) = mpsc::channel(4);
    let (fetch_tx, mut fetch_rx) = mpsc::channel(4);
    let join = spawn_chunked_npm_firewall_preflight(
        selected_rx,
        fetch_tx,
        client,
        chunked_config(NpmFirewallMode::Enforce),
    );

    selected_tx.send(selected_event("evil-b")).await.unwrap();
    selected_tx.send(selected_event("broken-a")).await.unwrap();
    drop(selected_tx);

    let result = join.drain().await.expect("the block outlives the failure");
    assert!(fetch_rx.recv().await.is_none());
    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected the firewall block");
    };
    assert_eq!(blocked.packages[0].name, "evil-b");
    assert!(blocked.unchecked_reason.is_some());
}

#[tokio::test]
async fn batch_enforce_checks_the_batches_after_a_failed_one() {
    use std::sync::Arc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"p-0\""))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"p-512\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(verdict_response(
            1,
            vec![verdict_decision("p-512", "block")],
        )))
        .mount(&server)
        .await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let packages = (0..=512)
        .map(|index| lpm_registry::client::NpmFirewallBatchPackage {
            name: format!("p-{index}"),
            version: "1.0.0".into(),
            integrity: None,
            published_at: None,
        })
        .collect();

    let result = request_npm_firewall_preflight(
        NpmFirewallMode::Enforce,
        NpmFirewallLookupMode::PackageOnly,
        lpm_registry::client::NpmFirewallPolicyProfile::default(),
        client,
        packages,
        false,
    )
    .await
    .expect("the later block is found");

    let LpmError::NpmFirewallBlocked(blocked) =
        finish_npm_firewall_preflight(result, true).unwrap_err()
    else {
        panic!("expected the firewall block");
    };
    assert_eq!(blocked.packages[0].name, "p-512");
    assert!(blocked.unchecked_reason.is_some());
}

#[tokio::test]
async fn chunked_enforce_releases_nothing_an_allowed_chunk_clears_after_a_failure() {
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"broken-a\""))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .and(body_string_contains("\"name\":\"clean-c\""))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(verdict_response(
                    0,
                    vec![verdict_decision("clean-c", "allow")],
                ))
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = Arc::new(
        lpm_registry::RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("firewall-token"),
    );
    let (selected_tx, selected_rx) = mpsc::channel(4);
    let (fetch_tx, mut fetch_rx) = mpsc::channel(4);
    let join = spawn_chunked_npm_firewall_preflight(
        selected_rx,
        fetch_tx,
        client,
        chunked_config(NpmFirewallMode::Enforce),
    );

    let started = std::time::Instant::now();
    selected_tx.send(selected_event("clean-c")).await.unwrap();
    selected_tx.send(selected_event("broken-a")).await.unwrap();
    drop(selected_tx);

    let drained = join.drain().await.unwrap();
    assert!(drained.failure.is_some());
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(300),
        "drain returned before the allowed chunk's verdict arrived"
    );
    assert!(finish_npm_firewall_preflight(drained, true).is_err());
    assert!(fetch_rx.recv().await.is_none());
    server.verify().await;
}
