use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn document(server: &MockServer, endpoint: &str, body: serde_json::Value, count: u64) {
    Mock::given(method("GET"))
        .and(path(endpoint))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(count)
        .mount(server)
        .await;
}

fn history(name: &str, latest: &str, versions: &[&str]) -> serde_json::Value {
    let versions: serde_json::Map<_, _> = versions
        .iter()
        .map(|version| {
            (
                version.to_string(),
                version_document_json(name, version, &[]),
            )
        })
        .collect();
    serde_json::json!({"name": name, "dist-tags": {"latest": latest}, "versions": versions})
}

async fn resolve(server: &MockServer, range: &str) -> ResolveResult {
    resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([("shared".into(), range.into())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn satisfying_latest_is_preferred_even_when_history_contains_a_newer_version() {
    let server = MockServer::start().await;
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "2.1.0", &[]),
        1,
    )
    .await;
    document(
        &server,
        "/shared",
        history("shared", "2.1.0", &["2.1.0", "2.9.0"]),
        0,
    )
    .await;
    let result = resolve(&server, "^2").await;
    assert_eq!(result.packages[0].version.to_string(), "2.1.0");
}

#[tokio::test]
async fn incompatible_latest_falls_back_to_history_once() {
    let server = MockServer::start().await;
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "3.0.0", &[]),
        1,
    )
    .await;
    document(
        &server,
        "/shared",
        history("shared", "3.0.0", &["2.1.0", "2.9.0", "3.0.0"]),
        1,
    )
    .await;
    let result = resolve(&server, "^2").await;
    assert_eq!(result.packages[0].version.to_string(), "2.9.0");
}

#[tokio::test]
async fn prerelease_latest_does_not_satisfy_a_stable_range() {
    let server = MockServer::start().await;
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "2.1.0-beta.1", &[]),
        1,
    )
    .await;
    document(
        &server,
        "/shared",
        history("shared", "2.1.0-beta.1", &["2.0.0", "2.1.0-beta.1"]),
        1,
    )
    .await;
    let result = resolve(&server, "^2").await;
    assert_eq!(result.packages[0].version.to_string(), "2.0.0");
}

#[tokio::test]
async fn explicit_prerelease_range_accepts_a_latest_prerelease_document() {
    let server = MockServer::start().await;
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "2.1.0-beta.1", &[]),
        1,
    )
    .await;
    document(
        &server,
        "/shared",
        history("shared", "2.1.0-beta.1", &["2.1.0-beta.1"]),
        0,
    )
    .await;
    let result = resolve(&server, "^2.1.0-beta.1").await;
    assert_eq!(result.packages[0].version.to_string(), "2.1.0-beta.1");
}

#[tokio::test]
async fn named_tags_fetch_history_instead_of_assuming_latest() {
    let server = MockServer::start().await;
    let mut full = history("shared", "2.0.0", &["1.0.0", "2.0.0"]);
    full["dist-tags"]["stable"] = serde_json::json!("1.0.0");
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "2.0.0", &[]),
        0,
    )
    .await;
    document(&server, "/shared", full, 1).await;
    let result = resolve(&server, "stable").await;
    assert_eq!(result.packages[0].version.to_string(), "1.0.0");
}

#[tokio::test]
async fn incomplete_latest_distribution_falls_back_to_history() {
    let server = MockServer::start().await;
    let mut latest = version_document_json("shared", "2.0.0", &[]);
    latest["dist"] = serde_json::json!({});
    document(&server, "/shared/latest", latest, 1).await;
    document(
        &server,
        "/shared",
        history("shared", "2.0.0", &["2.0.0"]),
        1,
    )
    .await;
    assert_eq!(
        resolve(&server, "^2").await.packages[0].version.to_string(),
        "2.0.0"
    );
}

#[tokio::test]
async fn unresolved_older_peer_hydrates_a_latest_only_cache() {
    let server = MockServer::start().await;
    let mut consumer = version_document_json("consumer", "1.0.0", &[]);
    consumer["peerDependencies"] = serde_json::json!({"shared": "^1"});
    document(&server, "/consumer/1.0.0", consumer, 1).await;
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "2.0.0", &[]),
        1,
    )
    .await;
    document(
        &server,
        "/shared",
        history("shared", "2.0.0", &["1.0.0", "2.0.0"]),
        1,
    )
    .await;
    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([
            ("shared".into(), "^2".into()),
            ("consumer".into(), "1.0.0".into()),
        ]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .unwrap();
    let mut versions: Vec<_> = result
        .packages
        .iter()
        .filter(|p| p.package.canonical_name() == "shared")
        .map(|p| p.version.to_string())
        .collect();
    versions.sort();
    assert_eq!(versions, ["1.0.0", "2.0.0"]);
}

#[tokio::test]
async fn latest_partial_cache_cannot_hide_override_history() {
    let server = MockServer::start().await;
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "2.0.0", &[]),
        0,
    )
    .await;
    document(
        &server,
        "/shared",
        history("shared", "2.0.0", &["1.0.0", "2.0.0"]),
        1,
    )
    .await;
    let cache: SharedCache = Arc::default();
    let info = crate::provider::parse_owned_partial_metadata_to_cache_info(
        serde_json::from_value(history("shared", "2.0.0", &["2.0.0"])).unwrap(),
    );
    cache.insert(CanonicalKey::npm("shared"), Arc::new(info));
    let result = resolve_greedy_fused_with_cache_options_and_policy(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([("shared".into(), "^2".into())]),
        override_set("shared", "1.0.0"),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        cache,
        true,
        true,
        ResolverPolicy::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.packages[0].version.to_string(), "1.0.0");
}

#[test]
fn latest_proof_follows_current_tag_and_does_not_create_range_coverage() {
    let older = crate::provider::parse_owned_partial_metadata_to_cache_info(
        serde_json::from_value(history("shared", "2.1.0", &["2.1.0"])).unwrap(),
    );
    let newer = crate::provider::parse_owned_partial_metadata_to_cache_info(
        serde_json::from_value(history("shared", "3.0.0", &["3.0.0"])).unwrap(),
    );
    let range = NpmRange::parse("^2").unwrap();
    assert!(older.has_installable_latest_for_range(&range));
    let merged = crate::provider::merge_cached_package_info(&older, &newer);
    assert!(!merged.has_installable_latest_for_range(&range));
    assert!(merged.needs_metadata_for_range(&range));
    assert!(
        !merged.has_installable_latest_for_range(&NpmRange::parse_registry_spec("beta").unwrap())
    );
}

#[tokio::test]
async fn history_dependent_policies_hydrate_a_latest_only_shared_fact() {
    for policy in [
        ResolverPolicy::with_cutoff_unix(86_400, 1_750_000_000, TrustPolicyMode::Off),
        ResolverPolicy::with_cutoff_unix_and_release_age_excludes(
            86_400,
            1_750_000_000,
            TrustPolicyMode::Off,
            [CanonicalKey::npm("shared")],
        ),
        ResolverPolicy::with_cutoff_unix(0, 0, TrustPolicyMode::NoDowngrade),
    ] {
        let server = MockServer::start().await;
        let mut full = history("shared", "2.0.0", &["1.0.0", "2.0.0"]);
        full["time"] = serde_json::json!({"1.0.0":"2025-01-01T00:00:00.000Z", "2.0.0":"2025-01-02T00:00:00.000Z"});
        Mock::given(method("GET"))
            .and(path("/shared"))
            .respond_with(ResponseTemplate::new(200).set_body_json(full.clone()))
            .expect(1..=3)
            .mount(&server)
            .await;
        document(
            &server,
            "/shared/latest",
            version_document_json("shared", "2.0.0", &[]),
            0,
        )
        .await;
        let facts: SharedCache = Arc::default();
        let info = crate::provider::parse_owned_partial_metadata_to_cache_info(
            serde_json::from_value(history("shared", "2.0.0", &["2.0.0"])).unwrap(),
        );
        facts.insert(CanonicalKey::npm("shared"), Arc::new(info));
        let result = resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots(
            Arc::new(
                RegistryClient::new()
                    .with_npm_registry_url(server.uri())
                    .with_cache_dir(None),
            ),
            crate::resolve::RootDependencies::required(HashMap::from([(
                "shared".into(),
                "^2".into(),
            )])),
            OverrideSet::empty(),
            RouteTable::from_mode_only(RouteMode::Direct),
            8,
            None,
            Arc::default(),
            true,
            true,
            policy,
            None,
            Some(facts),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.packages[0].version.to_string(), "2.0.0");
    }
}

#[tokio::test]
async fn concurrent_exact_and_latest_aliases_preserve_both_versions() {
    let server = MockServer::start().await;
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "2.0.0", &[]),
        1,
    )
    .await;
    document(
        &server,
        "/shared/1.0.0",
        version_document_json("shared", "1.0.0", &[]),
        1,
    )
    .await;
    document(
        &server,
        "/shared",
        history("shared", "2.0.0", &["1.0.0", "2.0.0"]),
        0,
    )
    .await;
    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([
            ("first".into(), "npm:shared@1.0.0".into()),
            ("second".into(), "npm:shared@^2".into()),
        ]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .unwrap();
    let mut versions: Vec<_> = result
        .packages
        .iter()
        .map(|p| p.version.to_string())
        .collect();
    versions.sort();
    assert_eq!(versions, ["1.0.0", "2.0.0"]);
}

#[tokio::test]
async fn fresh_history_disk_cache_avoids_a_latest_network_probe() {
    let server = MockServer::start().await;
    let cache = tempfile::tempdir().unwrap();
    document(
        &server,
        "/shared",
        history("shared", "2.0.0", &["1.0.0", "2.0.0"]),
        1,
    )
    .await;
    document(
        &server,
        "/shared/latest",
        version_document_json("shared", "2.0.0", &[]),
        0,
    )
    .await;
    let client = || {
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(cache.path().to_path_buf()))
    };
    let seeder = client();
    seeder.get_npm_metadata_direct("shared").await.unwrap();
    seeder.flush_pending_cache_writes().await;
    let result = resolve_greedy_fused(
        Arc::new(client()),
        HashMap::from([("shared".into(), "^2".into())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(result.packages[0].version.to_string(), "2.0.0");
}
