use super::*;
use crate::sigstore_verify::tuf::test_support::{RoleSet, repository_files};
use std::collections::BTreeMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const AXIOS_BUNDLE: &[u8] =
    include_bytes!("../../../tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json");

/// The built-in trust root without the Rekor log that recorded the axios
/// bundle: what a copy of LPM built before Sigstore added that log holds.
fn trust_root_without_the_axios_log() -> Vec<u8> {
    let mut root: serde_json::Value = serde_json::from_slice(EMBEDDED_TRUST_ROOT_JSON).unwrap();
    let logs = root["tlogs"].as_array_mut().unwrap();
    let before = logs.len();
    logs.retain(|log| log["baseUrl"] != "https://rekor.sigstore.dev");
    assert_eq!(logs.len(), before - 1);
    serde_json::to_vec(&root).unwrap()
}

async fn serve(files: BTreeMap<String, Vec<u8>>) -> MockServer {
    let server = MockServer::start().await;
    mount(&server, files).await;
    server
}

async fn mount(server: &MockServer, files: BTreeMap<String, Vec<u8>>) {
    for (file, bytes) in files {
        Mock::given(method("GET"))
            .and(path(format!("/{file}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(server)
            .await;
    }
}

/// A repository that serves `trusted_root` under targets version
/// `targets_version`.
async fn sigstore_serving(
    roles: &RoleSet,
    trusted_root: &[u8],
    targets_version: u64,
) -> MockServer {
    serve(repository_files(
        roles,
        targets_version,
        targets_version,
        targets_version,
        trusted_root,
    ))
    .await
}

async fn failing_repository() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    server
}

fn store_holding(
    roles: &RoleSet,
    held: Vec<u8>,
    embedded_targets_version: u64,
    cache_file: Option<PathBuf>,
    repository: Repository,
) -> TrustStore {
    TrustStore {
        embedded_tuf_root: Cow::Owned(roles.signed_root(1)),
        embedded_trusted_root: Cow::Owned(held),
        embedded_targets_version,
        cache_file,
        repository,
        current: RwLock::new(None),
        last_fetch: tokio::sync::Mutex::new(None),
        last_metadata: Mutex::new(None),
    }
}

async fn verify_axios(
    store: &TrustStore,
    refresh: TrustRefresh,
) -> Result<VerifiedProvenance, VerifyError> {
    store
        .verify(
            AXIOS_BUNDLE,
            &IdentityExpectations::none(),
            VerifyOptions::npm_attestation(),
            refresh,
        )
        .await
}

fn assert_missing_rekor_key(error: &VerifyError) {
    assert!(
        matches!(
            error,
            VerifyError::MissingTrustMaterial {
                check: "Rekor SET",
                ..
            }
        ),
        "{error:?}"
    );
}

async fn timestamp_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == "/timestamp.json")
        .count()
}

#[tokio::test]
async fn a_bundle_from_a_log_the_held_root_lacks_verifies_after_fetching_sigstores_current_root() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, EMBEDDED_TRUST_ROOT_JSON, 1).await;
    let cache = tempfile::tempdir().unwrap();
    let cache_file = cache.path().join("metadata").join(CACHE_FILE_NAME);
    let store = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file.clone()),
        Repository::Url(server.uri()),
    );

    verify_axios(&store, TrustRefresh::WhenMissing)
        .await
        .expect("the fetched trust root holds the log");

    let offline = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file),
        Repository::Disabled,
    );
    verify_axios(&offline, TrustRefresh::WhenMissing)
        .await
        .expect("the cached trust root holds the log");
}

#[tokio::test]
async fn the_held_root_alone_does_not_verify_a_bundle_from_a_log_it_lacks() {
    let roles = RoleSet::new();
    let store = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        None,
        Repository::Disabled,
    );

    let error = verify_axios(&store, TrustRefresh::WhenMissing)
        .await
        .unwrap_err();

    let VerifyError::TrustRootNotRefreshed { error, refresh } = error else {
        panic!("{error:?}");
    };
    assert_missing_rekor_key(&error);
    assert!(
        refresh.contains(&format!("{REPOSITORY_URL_OVERRIDE_ENV}=off")),
        "{refresh}"
    );
}

#[tokio::test]
async fn a_failed_fetch_keeps_the_held_root_and_says_why() {
    let roles = RoleSet::new();
    let server = failing_repository().await;
    let store = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        None,
        Repository::Url(server.uri()),
    );

    let error = verify_axios(&store, TrustRefresh::WhenMissing)
        .await
        .unwrap_err();

    let VerifyError::TrustRootNotRefreshed { error, refresh } = error else {
        panic!("{error:?}");
    };
    assert_missing_rekor_key(&error);
    assert!(refresh.contains("HTTP 500"), "{refresh}");
}

#[tokio::test]
async fn a_failed_fetch_before_verifying_falls_back_to_the_held_root() {
    let roles = RoleSet::new();
    let server = failing_repository().await;
    let store = store_holding(
        &roles,
        EMBEDDED_TRUST_ROOT_JSON.to_vec(),
        1,
        None,
        Repository::Url(server.uri()),
    );

    verify_axios(&store, TrustRefresh::BeforeVerifying)
        .await
        .expect("the held trust root verifies the bundle");

    let asked = server.received_requests().await.unwrap();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0].url.path(), "/2.root.json");
}

#[tokio::test]
async fn sigstores_current_root_is_fetched_at_most_once_an_hour() {
    let roles = RoleSet::new();
    let stale = trust_root_without_the_axios_log();
    let server = sigstore_serving(&roles, &stale, 1).await;
    let store = store_holding(&roles, stale, 1, None, Repository::Url(server.uri()));

    for _ in 0..2 {
        let error = verify_axios(&store, TrustRefresh::WhenMissing)
            .await
            .unwrap_err();
        assert_missing_rekor_key(&error);
    }

    assert_eq!(timestamp_requests(&server).await, 1);
}

#[tokio::test]
async fn a_cached_trust_root_that_no_longer_verifies_is_ignored() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, EMBEDDED_TRUST_ROOT_JSON, 1).await;
    let cache = tempfile::tempdir().unwrap();
    let cache_file = cache.path().join(CACHE_FILE_NAME);
    let store = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file.clone()),
        Repository::Url(server.uri()),
    );
    verify_axios(&store, TrustRefresh::WhenMissing)
        .await
        .unwrap();
    let mut cached: CacheFile =
        serde_json::from_slice(&std::fs::read(&cache_file).unwrap()).unwrap();
    cached.metadata.trusted_root = cached.metadata.trusted_root.replacen("rekor", "rekr", 1);
    std::fs::write(&cache_file, serde_json::to_vec(&cached).unwrap()).unwrap();

    let offline = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file),
        Repository::Disabled,
    );
    let error = verify_axios(&offline, TrustRefresh::WhenMissing)
        .await
        .unwrap_err();

    assert!(
        matches!(error, VerifyError::TrustRootNotRefreshed { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_cached_trust_root_older_than_the_built_in_one_is_ignored() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, EMBEDDED_TRUST_ROOT_JSON, 1).await;
    let cache = tempfile::tempdir().unwrap();
    let cache_file = cache.path().join(CACHE_FILE_NAME);
    let store = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file.clone()),
        Repository::Url(server.uri()),
    );
    verify_axios(&store, TrustRefresh::WhenMissing)
        .await
        .unwrap();

    let newer_binary = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        2,
        Some(cache_file),
        Repository::Disabled,
    );
    let error = verify_axios(&newer_binary, TrustRefresh::WhenMissing)
        .await
        .unwrap_err();

    assert!(
        matches!(error, VerifyError::TrustRootNotRefreshed { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_repository_older_than_the_built_in_trust_root_is_not_used() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, EMBEDDED_TRUST_ROOT_JSON, 1).await;
    let store = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        2,
        None,
        Repository::Url(server.uri()),
    );

    let error = verify_axios(&store, TrustRefresh::WhenMissing)
        .await
        .unwrap_err();

    let VerifyError::TrustRootNotRefreshed { refresh, .. } = error else {
        panic!("{error:?}");
    };
    assert!(refresh.contains("older than"), "{refresh}");
}

const LPM_RELEASE_BUNDLE: &[u8] =
    include_bytes!("../../../tests/fixtures/sigstore_bundles/21-real-lpm-release-v0.84.0.json");

async fn verify_lpm_release(
    store: &TrustStore,
    refresh: TrustRefresh,
) -> Result<VerifiedProvenance, VerifyError> {
    let release_workflow = IdentityExpectations {
        expected_issuer: Some("https://token.actions.githubusercontent.com".into()),
        expected_san_uri_prefix: Some("https://github.com/lpm-dev/rust-client/".into()),
        expected_workflow_path: Some(".github/workflows/release.yml".into()),
    };
    store
        .verify(
            LPM_RELEASE_BUNDLE,
            &release_workflow,
            VerifyOptions::strict(),
            refresh,
        )
        .await
}

#[tokio::test]
async fn a_release_signed_after_sigstore_added_a_log_verifies_on_a_copy_built_before() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, EMBEDDED_TRUST_ROOT_JSON, 1).await;
    let store = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        None,
        Repository::Url(server.uri()),
    );

    verify_lpm_release(&store, TrustRefresh::BeforeVerifying)
        .await
        .expect("the fetched trust root holds the log that recorded the release");
}

/// The built-in trust root with the log that recorded the bundles retired
/// before they were signed, as Sigstore would publish it after retiring a
/// compromised key.
fn trust_root_retiring_the_axios_log() -> Vec<u8> {
    let mut root: serde_json::Value = serde_json::from_slice(EMBEDDED_TRUST_ROOT_JSON).unwrap();
    let log = root["tlogs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|log| log["baseUrl"] == "https://rekor.sigstore.dev")
        .unwrap();
    log["publicKey"]["validFor"]["end"] = serde_json::json!("2022-01-01T00:00:00Z");
    serde_json::to_vec(&root).unwrap()
}

#[tokio::test]
async fn a_log_key_sigstore_retired_stops_counting_when_fetching_before_verifying() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, &trust_root_retiring_the_axios_log(), 1).await;
    let store = |repository| {
        store_holding(
            &roles,
            EMBEDDED_TRUST_ROOT_JSON.to_vec(),
            1,
            None,
            repository,
        )
    };

    let error = verify_lpm_release(
        &store(Repository::Url(server.uri())),
        TrustRefresh::BeforeVerifying,
    )
    .await
    .unwrap_err();
    assert_missing_rekor_key(&error);

    verify_lpm_release(
        &store(Repository::Url(server.uri())),
        TrustRefresh::WhenMissing,
    )
    .await
    .expect("without fetching first, the held trust root still counts the key");
}

#[tokio::test]
async fn a_release_verifies_with_the_held_root_when_sigstores_repository_fails() {
    let roles = RoleSet::new();
    let server = failing_repository().await;
    let store = store_holding(
        &roles,
        EMBEDDED_TRUST_ROOT_JSON.to_vec(),
        1,
        None,
        Repository::Url(server.uri()),
    );

    verify_lpm_release(&store, TrustRefresh::BeforeVerifying)
        .await
        .expect("the held trust root verifies the release");
}

/// The built-in trust root with every CT log entry in a shape this version
/// can't read, as a future schema change might publish them.
fn trust_root_with_unreadable_ct_logs() -> Vec<u8> {
    let mut root: serde_json::Value = serde_json::from_slice(EMBEDDED_TRUST_ROOT_JSON).unwrap();
    for log in root["ctlogs"].as_array_mut().unwrap() {
        log["publicKey"] = serde_json::json!({"keyDetails": "PKIX_FUTURE", "validFor": {"start": "2022-10-20T00:00:00Z"}});
    }
    serde_json::to_vec(&root).unwrap()
}

/// The built-in trust root with every CT log retired.
fn trust_root_retiring_every_ct_log() -> Vec<u8> {
    let mut root: serde_json::Value = serde_json::from_slice(EMBEDDED_TRUST_ROOT_JSON).unwrap();
    for log in root["ctlogs"].as_array_mut().unwrap() {
        log["publicKey"]["validFor"]["end"] = serde_json::json!("2023-01-01T00:00:00Z");
    }
    serde_json::to_vec(&root).unwrap()
}

#[tokio::test]
async fn a_fetched_trust_root_this_version_cannot_use_keeps_the_held_one() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, &trust_root_with_unreadable_ct_logs(), 1).await;
    let store = store_holding(
        &roles,
        EMBEDDED_TRUST_ROOT_JSON.to_vec(),
        1,
        None,
        Repository::Url(server.uri()),
    );

    verify_lpm_release(&store, TrustRefresh::BeforeVerifying)
        .await
        .expect("the held trust root still verifies the release");

    let refresh = store.refresh().await.unwrap_err();
    assert!(refresh.contains("CT log"), "{refresh}");
}

#[test]
fn a_fetched_trust_root_with_unreadable_timestamp_authorities_is_still_used() {
    let mut root: serde_json::Value = serde_json::from_slice(EMBEDDED_TRUST_ROOT_JSON).unwrap();
    for authority in root["timestampAuthorities"].as_array_mut().unwrap() {
        authority["certChain"] = serde_json::json!({"futureEncoding": true});
    }
    let usable = usable_trust_root(&serde_json::to_vec(&root).unwrap(), SystemTime::now())
        .expect("bundles with a Rekor v1 entry don't need a timestamp authority");
    assert!(usable.timestamp_authorities.is_empty());
    assert!(!usable.rekor_keys.is_empty());
}

#[tokio::test]
async fn a_role_sigstore_retired_entirely_stops_counting() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, &trust_root_retiring_every_ct_log(), 1).await;
    let store = store_holding(
        &roles,
        EMBEDDED_TRUST_ROOT_JSON.to_vec(),
        1,
        None,
        Repository::Url(server.uri()),
    );

    let error = verify_lpm_release(&store, TrustRefresh::BeforeVerifying)
        .await
        .unwrap_err();

    assert!(
        matches!(error, VerifyError::TrustRootExpired { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_older_fetch_never_replaces_a_newer_cached_trust_root() {
    let roles = RoleSet::new();
    let newer = sigstore_serving(&roles, EMBEDDED_TRUST_ROOT_JSON, 2).await;
    let older = sigstore_serving(&roles, &trust_root_without_the_axios_log(), 1).await;
    let cache = tempfile::tempdir().unwrap();
    let cache_file = cache.path().join(CACHE_FILE_NAME);
    let slower = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file.clone()),
        Repository::Url(older.uri()),
    );
    let fetched_before_the_update = tuf::refresh(
        &roles.signed_root(1),
        None,
        &HttpFetcher::new(&older.uri()).unwrap(),
        SystemTime::now(),
    )
    .await
    .unwrap();
    let faster = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file.clone()),
        Repository::Url(newer.uri()),
    );
    verify_axios(&faster, TrustRefresh::WhenMissing)
        .await
        .unwrap();

    slower.write_cache(fetched_before_the_update).await;

    let offline = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file),
        Repository::Disabled,
    );
    verify_axios(&offline, TrustRefresh::WhenMissing)
        .await
        .expect("the cache still holds the newer trust root");
}

#[tokio::test]
async fn a_process_that_cannot_cache_still_refuses_a_rollback() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, EMBEDDED_TRUST_ROOT_JSON, 5).await;
    let store = store_holding(
        &roles,
        EMBEDDED_TRUST_ROOT_JSON.to_vec(),
        1,
        None,
        Repository::Url(server.uri()),
    );
    store.refresh().await.unwrap();

    server.reset().await;
    mount(
        &server,
        repository_files(&roles, 4, 4, 4, EMBEDDED_TRUST_ROOT_JSON),
    )
    .await;
    *store.last_fetch.lock().await = None;
    let refresh = store.refresh().await.unwrap_err();

    assert!(refresh.contains("went back"), "{refresh}");
}

#[tokio::test]
async fn a_fetched_trust_root_missing_a_role_keeps_the_held_one() {
    let roles = RoleSet::new();
    let mut renamed: serde_json::Value = serde_json::from_slice(EMBEDDED_TRUST_ROOT_JSON).unwrap();
    let logs = renamed.as_object_mut().unwrap().remove("tlogs").unwrap();
    renamed["transparencyLogs"] = logs;
    let server = sigstore_serving(&roles, &serde_json::to_vec(&renamed).unwrap(), 1).await;
    let store = store_holding(
        &roles,
        EMBEDDED_TRUST_ROOT_JSON.to_vec(),
        1,
        None,
        Repository::Url(server.uri()),
    );

    verify_lpm_release(&store, TrustRefresh::BeforeVerifying)
        .await
        .expect("the held trust root still verifies the release");
    let refresh = store.refresh().await.unwrap_err();
    assert!(refresh.contains("Rekor"), "{refresh}");
}

#[tokio::test]
async fn a_fetch_another_process_made_within_the_hour_is_reused() {
    let roles = RoleSet::new();
    let server = sigstore_serving(&roles, EMBEDDED_TRUST_ROOT_JSON, 1).await;
    let cache = tempfile::tempdir().unwrap();
    let cache_file = cache.path().join(CACHE_FILE_NAME);
    let first = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file.clone()),
        Repository::Url(server.uri()),
    );
    first.refresh().await.unwrap();
    let second = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        Some(cache_file),
        Repository::Url(server.uri()),
    );

    verify_lpm_release(&second, TrustRefresh::BeforeVerifying)
        .await
        .unwrap();

    assert_eq!(timestamp_requests(&server).await, 1);
}

#[tokio::test]
async fn a_failed_fetch_is_retried_after_a_minute_not_an_hour() {
    let roles = RoleSet::new();
    let server = failing_repository().await;
    let store = store_holding(
        &roles,
        trust_root_without_the_axios_log(),
        1,
        None,
        Repository::Url(server.uri()),
    );
    store.refresh().await.unwrap_err();
    server.reset().await;
    mount(
        &server,
        repository_files(&roles, 1, 1, 1, EMBEDDED_TRUST_ROOT_JSON),
    )
    .await;

    store.refresh().await.unwrap_err();
    let failed_at = store.last_fetch.lock().await.as_ref().unwrap().0;
    *store.last_fetch.lock().await = Some((
        failed_at - RETRY_FAILED_FETCH_AFTER,
        Err("an earlier failure".into()),
    ));

    store.refresh().await.unwrap();
}

#[tokio::test]
async fn the_release_gate_verifies_with_the_built_in_trust_root_only() {
    let release_workflow = IdentityExpectations {
        expected_issuer: Some("https://token.actions.githubusercontent.com".into()),
        expected_san_uri_prefix: Some("https://github.com/lpm-dev/rust-client/".into()),
        expected_workflow_path: Some(".github/workflows/release.yml".into()),
    };

    verify_sigstore_bundle_with_built_in_trust_root(
        LPM_RELEASE_BUNDLE,
        &release_workflow,
        VerifyOptions::strict(),
    )
    .expect("the built-in trust root verifies a release");
}

#[test]
fn repository_overrides_must_be_https_or_loopback() {
    let default = Repository::Url(DEFAULT_REPOSITORY_URL.to_string());
    assert_eq!(repository_from_override(None), default);
    assert_eq!(repository_from_override(Some(String::new())), default);
    assert_eq!(
        repository_from_override(Some("OFF".into())),
        Repository::Disabled
    );
    assert_eq!(
        repository_from_override(Some("http://mirror.example.com".into())),
        default
    );
    for accepted in [
        "https://mirror.example.com/sigstore",
        "http://127.0.0.1:8080",
    ] {
        assert_eq!(
            repository_from_override(Some(accepted.into())),
            Repository::Url(accepted.into())
        );
    }
}

/// Run daily by the release trust monitor. Sigstore's live repository must
/// still verify under the TUF root built into LPM and serve the trust root
/// built into LPM, so a release ships Sigstore's current keys.
#[tokio::test]
#[ignore = "reaches Sigstore's live TUF repository"]
async fn sigstores_live_repository_serves_the_built_in_trust_root() {
    let fetcher = HttpFetcher::new(DEFAULT_REPOSITORY_URL).unwrap();

    let metadata = tuf::refresh(EMBEDDED_TUF_ROOT, None, &fetcher, SystemTime::now())
        .await
        .expect("Sigstore's live repository verifies under the built-in TUF root");

    let verified = metadata.verified_trusted_root(EMBEDDED_TUF_ROOT).unwrap();
    assert!(
        verified.targets_version >= EMBEDDED_TRUSTED_ROOT_TARGETS_VERSION,
        "targets version {} is older than the built-in {EMBEDDED_TRUSTED_ROOT_TARGETS_VERSION}",
        verified.targets_version
    );
    assert!(
        metadata.roots.is_empty(),
        "Sigstore published {} TUF root version(s) newer than the built-in one. Replace \
         crates/lpm-cli/assets/sigstore_tuf_root.json with the newest root.",
        metadata.roots.len()
    );
    for (role, supported, threshold) in metadata.key_support(EMBEDDED_TUF_ROOT).unwrap() {
        assert!(
            supported > threshold,
            "Sigstore's {role} role has {supported} key(s) LPM can verify, against a threshold \
             of {threshold}. One more change to a key type LPM can't verify stops refreshes; \
             add support for the new key type."
        );
    }
    assert!(
        verified.bytes == EMBEDDED_TRUST_ROOT_JSON,
        "Sigstore published a new trust root under targets version {}. Replace \
         crates/lpm-cli/assets/sigstore_trusted_root.json with it, set \
         EMBEDDED_TRUSTED_ROOT_TARGETS_VERSION to that version, and replace \
         assets/sigstore_tuf_root.json with Sigstore's newest root ({} newer than the \
         built-in one).",
        verified.targets_version,
        metadata.roots.len()
    );
}
