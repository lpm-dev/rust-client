use super::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug, PartialEq, Eq)]
struct Label(String);

impl MetadataProjection for Label {
    const FORMAT: &'static str = "test-label/1";

    fn decode(bytes: &[u8]) -> Option<Self> {
        std::str::from_utf8(bytes)
            .ok()
            .filter(|text| *text != "undecodable")
            .map(|text| Self(text.to_owned()))
    }
}

#[derive(Debug)]
struct OtherLabel;

impl MetadataProjection for OtherLabel {
    const FORMAT: &'static str = "test-label/2";

    fn decode(_: &[u8]) -> Option<Self> {
        Some(Self)
    }
}

fn written_slot(client: &RegistryClient, key: &str, metadata: &PackageMetadata) -> ProjectionSlot {
    client
        .write_metadata_cache_entry(key, metadata, None, MetadataCacheDirective::Unspecified)
        .and_then(|write| write.source)
        .and_then(|source| {
            source.slot::<Label>(ProjectionFacts {
                versions_complete: true,
                latest: None,
            })
        })
        .expect("a persisted document yields a projection slot")
}

async fn resolve<P: MetadataProjection>(
    client: &RegistryClient,
    key: &str,
) -> CachedResolution<PackageMetadata, P> {
    client
        .read_metadata_cache_resolution_async::<PackageMetadata, P>(key)
        .await
        .expect("fresh entry")
        .value
}

fn replace_payload(client: &RegistryClient, key: &str, payload: &[u8]) {
    let path = client.cache_path(key).unwrap();
    let expiry = std::fs::metadata(&path).unwrap().modified().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    let payload_start = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(3)
        .unwrap()
        .0
        + 1;
    bytes.truncate(payload_start);
    bytes.extend_from_slice(payload);
    std::fs::write(&path, bytes).unwrap();
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(expiry)).unwrap();
}

#[tokio::test]
async fn a_bound_projection_answers_without_decoding_the_document() {
    let (mut client, _cache) = client_with_temp_cache();
    client.synchronous_cache_writes = true;
    let slot = written_slot(&client, "entry", &test_metadata("pkg"));
    client.store_metadata_projection(slot, b"projected".to_vec());
    replace_payload(&client, "entry", b"not a document");

    match resolve::<Label>(&client, "entry").await {
        CachedResolution::Projected { value, facts } => {
            assert_eq!(value, Label("projected".to_owned()));
            assert!(facts.versions_complete);
        }
        CachedResolution::Document { .. } => panic!("the bound projection should answer"),
    }
}

#[tokio::test]
async fn rewriting_a_document_orphans_its_projection() {
    let (mut client, _cache) = client_with_temp_cache();
    client.synchronous_cache_writes = true;
    let slot = written_slot(&client, "entry", &test_metadata("pkg"));
    client.store_metadata_projection(slot, b"projected".to_vec());
    client.write_metadata_cache("entry", &test_metadata("rewritten"), None);

    match resolve::<Label>(&client, "entry").await {
        CachedResolution::Document { value, source } => {
            assert_eq!(value.name, "rewritten");
            assert!(source.is_some());
        }
        CachedResolution::Projected { .. } => panic!("a projection of the old document answered"),
    }
}

#[tokio::test]
async fn refreshing_freshness_keeps_the_projection_bound() {
    let (mut client, _cache) = client_with_temp_cache();
    client.synchronous_cache_writes = true;
    let slot = written_slot(&client, "entry", &test_metadata("pkg"));
    client.store_metadata_projection(slot, b"projected".to_vec());
    client.refresh_metadata_cache_freshness("entry", METADATA_CACHE_TTL);

    assert!(matches!(
        resolve::<Label>(&client, "entry").await,
        CachedResolution::Projected { .. }
    ));
}

#[tokio::test]
async fn invalidating_an_entry_removes_its_projection() {
    let (mut client, _cache) = client_with_temp_cache();
    client.synchronous_cache_writes = true;
    let slot = written_slot(&client, "entry", &test_metadata("pkg"));
    client.store_metadata_projection(slot, b"projected".to_vec());
    let projection = client
        .cache_path("entry")
        .unwrap()
        .with_extension("projection");
    assert!(projection.exists());

    client.invalidate_metadata_cache_key("entry");

    assert!(!projection.exists());
}

#[tokio::test]
async fn projections_in_another_format_or_undecodable_fall_back_to_the_document() {
    let (mut client, _cache) = client_with_temp_cache();
    client.synchronous_cache_writes = true;
    let slot = written_slot(&client, "entry", &test_metadata("pkg"));
    client.store_metadata_projection(slot.clone(), b"projected".to_vec());
    assert!(matches!(
        resolve::<OtherLabel>(&client, "entry").await,
        CachedResolution::Document { .. }
    ));
    assert!(matches!(
        resolve::<NoProjection>(&client, "entry").await,
        CachedResolution::Document {
            source: Some(_),
            ..
        }
    ));

    client.store_metadata_projection(slot, b"undecodable".to_vec());
    assert!(matches!(
        resolve::<Label>(&client, "entry").await,
        CachedResolution::Document { .. }
    ));
}

fn history() -> serde_json::Value {
    serde_json::json!({"name":"pkg","dist-tags":{"latest":"2.0.0"},"versions":{
        "1.0.0":{"name":"pkg","version":"1.0.0"},
        "2.0.0":{"name":"pkg","version":"2.0.0"}
    }})
}

async fn preferred_client(server: &MockServer) -> (RegistryClient, tempfile::TempDir) {
    let cache = tempfile::tempdir().unwrap();
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(cache.path().to_path_buf()))
        .with_synchronous_cache_writes(true);
    (client, cache)
}

async fn resolve_preferred(
    client: &RegistryClient,
    accepts: impl Fn(&str) -> bool + Send + Sync + 'static,
) -> TimedPreferredResolution<Label> {
    client
        .get_npm_preferred_resolution_with_timings::<Label, _>(
            "pkg",
            PublicNpmAccess::ANONYMOUS,
            accepts,
        )
        .await
        .unwrap()
}

fn store_document_projection(client: &RegistryClient, resolution: TimedPreferredResolution<Label>) {
    match resolution.metadata {
        ResolutionMetadata::Document {
            projection: Some(slot),
            ..
        } => client.store_metadata_projection(slot, b"projected".to_vec()),
        other => panic!("expected a document with a projection slot, got {other:?}"),
    }
}

#[tokio::test]
async fn preferred_histories_answer_with_projections_only_when_they_cover_the_range() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(history())
                .insert_header("Cache-Control", "max-age=300"),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/pkg/latest"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let (client, _cache) = preferred_client(&server).await;

    let fetched = resolve_preferred(&client, |_| true).await;
    assert!(!fetched.versions_complete);
    store_document_projection(&client, fetched);

    let projected = resolve_preferred(&client, |_| true).await;
    assert!(projected.timings.cache_hit);
    assert!(!projected.versions_complete);
    assert!(matches!(
        projected.metadata,
        ResolutionMetadata::Projected(Label(ref label)) if label == "projected"
    ));

    let outside_latest = resolve_preferred(&client, |version| version == "1.0.0").await;
    assert!(outside_latest.versions_complete);
    let ResolutionMetadata::Document { metadata, .. } = outside_latest.metadata else {
        panic!("a partial projection cannot answer a range that excludes its latest version");
    };
    assert_eq!(metadata.versions.len(), 2);
    server.verify().await;
}

#[tokio::test]
async fn revalidation_keeps_a_projection_only_while_the_entry_is_refreshed_in_place() {
    for (revalidated_max_age, projected) in [("max-age=300", true), ("max-age=120", false)] {
        let server = MockServer::start().await;
        let (client, _cache) = preferred_client(&server).await;
        let initial = Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(history())
                    .insert_header("Cache-Control", "max-age=300")
                    .insert_header("ETag", "\"initial\""),
            )
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        let fetched = resolve_preferred(&client, |version| version == "1.0.0").await;
        assert!(fetched.versions_complete);
        store_document_projection(&client, fetched);
        drop(initial);

        let key = client.npm_direct_metadata_cache_key("pkg", PublicNpmAccess::ANONYMOUS);
        let entry = client.cache_path(&key).unwrap();
        filetime::set_file_mtime(&entry, filetime::FileTime::from_unix_time(1, 0)).unwrap();
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .and(header("If-None-Match", "\"initial\""))
            .respond_with(
                ResponseTemplate::new(304)
                    .insert_header("Cache-Control", revalidated_max_age)
                    .insert_header("ETag", "\"initial\""),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let revalidated = resolve_preferred(&client, |version| version == "1.0.0").await;
        assert!(revalidated.timings.not_modified);
        assert!(revalidated.versions_complete);
        assert_eq!(
            matches!(revalidated.metadata, ResolutionMetadata::Projected(_)),
            projected,
            "{revalidated_max_age}"
        );
        if !projected {
            let ResolutionMetadata::Document {
                projection: Some(_),
                ..
            } = revalidated.metadata
            else {
                panic!("a rewritten entry should offer a slot for its new content");
            };
            assert!(matches!(
                resolve::<Label>(&client, &key).await,
                CachedResolution::Document { .. }
            ));
        }
        server.verify().await;
    }
}
