use super::*;

#[tokio::test]
async fn fusion_latest_document_covers_matching_ranges_and_full_platform_fields() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    for (name, deps) in [
        ("a-child", serde_json::json!({})),
        ("z-parent", serde_json::json!({"a-child": ">=1.0.0"})),
    ] {
        let body = serde_json::json!({
            "name": name, "version": "1.1.0", "dependencies": deps,
            "os":["linux", "darwin", "win32"], "cpu":["arm64","x64"],
            "dist": {"tarball":format!("{}/{name}.tgz", server.uri()),
                "integrity":format!("sha512-{}==", "A".repeat(86))}
        });
        Mock::given(method("GET"))
            .and(path(format!("/{name}/latest")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        // History raced against the latest document never answers in time.
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({}))
                    .set_delay(std::time::Duration::from_secs(30)),
            )
            .expect(..=1)
            .mount(&server)
            .await;
    }
    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([
            ("a-child".to_owned(), "^1.0.0".to_owned()),
            ("z-parent".to_owned(), "*".to_owned()),
        ]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(result.packages.len(), 2);
    for name in ["a-child", "z-parent"] {
        let info = &result.cache[&CanonicalKey::npm(name)];
        assert!(!info.versions_complete);
        assert!(info.platform_metadata_complete);
        assert_eq!(
            info.versions.as_ref(),
            [NpmVersion::parse("1.1.0").unwrap()]
        );
    }
    server.verify().await;
}

#[tokio::test]
async fn latest_alias_metadata_hydrates_history_for_an_older_required_peer() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let mut consumer = version_document_json("consumer", "1.0.0", &[]);
    consumer["peerDependencies"] = serde_json::json!({"shared": "^1"});
    for (endpoint, mut document) in [
        ("/consumer/latest", consumer),
        (
            "/shared/latest",
            version_document_json("shared", "2.0.0", &[]),
        ),
    ] {
        document["dist"]["integrity"] = serde_json::json!(format!("sha512-{}==", "A".repeat(86)));
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
            .expect(1)
            .mount(&server)
            .await;
    }
    let mut history = metadata_json_version("shared", "2.0.0", &[]);
    history["versions"]["1.0.0"] = version_document_json("shared", "1.0.0", &[]);
    // Peer hydration needs history even when the raced history was abandoned.
    Mock::given(method("GET"))
        .and(path("/shared"))
        .respond_with(ResponseTemplate::new(200).set_body_json(history))
        .expect(1..=2)
        .mount(&server)
        .await;
    let result = resolve_greedy_fused_with_cache_options_and_policy(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([
            ("pinned".into(), "npm:shared@^2.0.0".into()),
            ("consumer".into(), "^1.0.0".into()),
        ]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        Arc::default(),
        true,
        true,
        ResolverPolicy::default(),
    )
    .await
    .expect("the complete history contains the required older peer");
    let versions: std::collections::BTreeSet<_> = result
        .packages
        .iter()
        .filter(|package| package.package.canonical_name() == "shared")
        .map(|package| package.version.to_string())
        .collect();
    assert_eq!(
        versions,
        std::collections::BTreeSet::from(["1.0.0".into(), "2.0.0".into()])
    );
}

#[tokio::test]
async fn authenticated_public_npm_routes_use_the_direct_npm_documents() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ABBREVIATED: &str = "application/vnd.npm.install-v1+json";
    let server = MockServer::start().await;
    let authorized = || header("authorization", "Bearer npm-token");
    let mut latest = version_document_json("ranged", "1.4.0", &[]);
    latest["dist"]["integrity"] = serde_json::json!(format!("sha512-{}==", "A".repeat(86)));
    Mock::given(method("GET"))
        .and(path("/ranged/latest"))
        .and(authorized())
        .respond_with(ResponseTemplate::new(200).set_body_json(latest))
        .expect(1)
        .mount(&server)
        .await;
    // History raced against the latest document never answers in time.
    Mock::given(method("GET"))
        .and(path("/ranged"))
        .and(authorized())
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({}))
                .set_delay(std::time::Duration::from_secs(30)),
        )
        .expect(..=1)
        .mount(&server)
        .await;
    // Exact pins select their manifest from full history.
    Mock::given(method("GET"))
        .and(path("/pinned"))
        .and(header("accept", "application/json"))
        .and(authorized())
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_json_version("pinned", "1.2.3", &[])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/pinned"))
        .and(header("accept", ABBREVIATED))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let address = server.address();
    let npmrc = lpm_registry::NpmrcConfig::parse(
        &format!(
            "registry={}/\n//{}:{}/:_authToken=npm-token\n",
            server.uri(),
            address.ip(),
            address.port()
        ),
        "test",
        &|_| None,
    );

    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([
            ("ranged".to_owned(), "^1.0.0".to_owned()),
            ("pinned".to_owned(), "1.2.3".to_owned()),
        ]),
        OverrideSet::empty(),
        RouteTable::new(RouteMode::Direct, npmrc).expect("valid npmrc"),
        8,
        None,
        true,
    )
    .await
    .expect("authenticated public npm metadata resolves");

    assert_eq!(result.packages.len(), 2);
    assert!(!result.cache[&CanonicalKey::npm("ranged")].versions_complete);
    server.verify().await;
}
