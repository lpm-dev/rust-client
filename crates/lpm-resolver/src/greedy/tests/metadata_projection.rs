use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn history(server: &MockServer) -> serde_json::Value {
    let dist = |version: &str| {
        serde_json::json!({
            "tarball": format!("{}/pkg-{version}.tgz", server.uri()),
            "integrity": format!("sha512-{version}"),
            "signatures": [{"keyid": "SHA256:key", "sig": format!("sig-{version}")}]
        })
    };
    serde_json::json!({
        "name": "pkg",
        "modified": "2026-01-02T03:04:05.000Z",
        "dist-tags": {"latest": "2.0.0", "next": "3.0.0-rc.1"},
        "versions": {
            "1.0.0": {"name": "pkg", "version": "1.0.0", "dist": dist("1.0.0"),
                "dependencies": {"left": "^1.0.0"}, "engines": {"node": ">=18"}},
            "1.1.0": {"name": "pkg", "version": "1.1.0", "dist": dist("1.1.0"),
                "dependencies": {"left": "^1.1.0", "alias": "npm:right@^2.0.0"},
                "optionalDependencies": {"native": "^1.0.0"},
                "peerDependencies": {"react": "^19.0.0"},
                "peerDependenciesMeta": {"react": {"optional": true}},
                "os": ["darwin", "linux"], "cpu": ["arm64", "x64"], "libc": ["glibc"]},
            "2.0.0": {"name": "pkg", "version": "2.0.0", "dist": dist("2.0.0"),
                "dependencies": {"left": "^2.0.0"}, "devDependencies": {"tool": "^1.0.0"}},
            "3.0.0-rc.1": {"name": "pkg", "version": "3.0.0-rc.1", "dist": dist("3.0.0-rc.1")}
        }
    })
}

async fn fetch(client: &RegistryClient, range: &str) -> FetchedMetadata {
    fetch_preferred_metadata_for_resolver(
        client,
        &RouteTable::from_mode_only(RouteMode::Direct),
        &CanonicalKey::npm("pkg"),
        &ResolverPolicy::default(),
        true,
        false,
        NpmRange::parse(range).unwrap(),
    )
    .await
    .unwrap()
}

/// Replace every cached document's payload, keeping its header and
/// freshness, so only a stored projection can still answer.
fn discard_cached_documents(cache: &std::path::Path) -> usize {
    let mut discarded = 0;
    for entry in std::fs::read_dir(cache).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some() {
            continue;
        }
        let expiry = std::fs::metadata(&path).unwrap().modified().unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let payload = bytes
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'\n')
            .nth(3)
            .unwrap()
            .0
            + 1;
        bytes.truncate(payload);
        bytes.extend_from_slice(b"not a document");
        std::fs::write(&path, bytes).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(expiry)
            .unwrap();
        discarded += 1;
    }
    discarded
}

#[tokio::test(flavor = "current_thread")]
async fn stored_projections_resolve_to_the_manifests_their_documents_parse_to() {
    for (range, versions_complete) in [("^1.0.0", true), ("^2.0.0", false)] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(history(&server)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(cache.path().to_path_buf()));

        let parsed = fetch(&client, range).await;
        client.flush_pending_cache_writes().await;
        assert_eq!(parsed.info.versions_complete, versions_complete, "{range}");
        assert_eq!(discard_cached_documents(cache.path()), 1, "{range}");
        let projected = fetch(&client, range).await;

        assert_eq!(*projected.info, *parsed.info, "{range}");
        assert_eq!(projected.latest_version, parsed.latest_version, "{range}");
        assert_eq!(
            projected
                .speculation
                .as_ref()
                .map(|speculation| &speculation.dist_tags),
            parsed
                .speculation
                .as_ref()
                .map(|speculation| &speculation.dist_tags),
            "{range}"
        );
        server.verify().await;
    }
}
