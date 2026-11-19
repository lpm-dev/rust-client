use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// An HTTPS listener whose self-signed certificate no client trusts. Each
/// TCP connection it accepts is one handshake attempt.
struct UntrustedHttpsServer {
    url: String,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl UntrustedHttpsServer {
    async fn start() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed certificate");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
        )
        .expect("TLS server configuration");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the HTTPS listener");
        let port = listener.local_addr().expect("listener address").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let handshakes = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                handshakes.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        });
        Self {
            url: format!("https://localhost:{port}"),
            connections,
            task,
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for UntrustedHttpsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn assert_untrusted_certificate(error: &LpmError) {
    let rendered = error.to_string();
    assert!(
        rendered.contains("UnknownIssuer"),
        "the error should name the untrusted certificate: {rendered}"
    );
}

#[tokio::test]
async fn a_registry_certificate_the_client_does_not_trust_fails_on_the_first_handshake() {
    let server = UntrustedHttpsServer::start().await;
    let client = RegistryClient::new()
        .with_base_url(&server.url)
        .with_token("registry-token");

    let error = client
        .whoami()
        .await
        .expect_err("an untrusted certificate must fail the request");

    assert_untrusted_certificate(&error);
    assert_eq!(
        server.connections(),
        1,
        "no retry can make an untrusted certificate trusted"
    );
}

#[tokio::test]
async fn a_publish_to_a_registry_with_an_untrusted_certificate_fails_once_and_unambiguously() {
    let server = UntrustedHttpsServer::start().await;
    let client = RegistryClient::new()
        .with_base_url(&server.url)
        .with_token("publish-token");
    let encoded_name = "@lpm.dev/owner.pkg";
    let payload = lpm_http::ReplayableRequestBody::from_bytes(
        serde_json::to_vec(&serde_json::json!({ "name": encoded_name })).unwrap(),
    );

    let error = client
        .publish_package(encoded_name, "1.0.0", "sha512-test", &payload, None, 0)
        .await
        .expect_err("an untrusted certificate must fail the publish");

    assert_untrusted_certificate(&error);
    assert!(
        !error.to_string().contains("ambiguous"),
        "a publish the server never received isn't ambiguous: {error}"
    );
    assert_eq!(
        server.connections(),
        1,
        "neither a retry nor a reconciliation probe can pass an untrusted certificate"
    );
}

#[tokio::test]
async fn a_tarball_upload_to_storage_with_an_untrusted_certificate_fails_on_the_first_handshake() {
    let server = UntrustedHttpsServer::start().await;
    let upload: PublishUpload = serde_json::from_value(serde_json::json!({
        "id": "11111111-1111-4111-8111-111111111111",
        "uploadUrl": format!("{}/storage/upload.tgz?X-Amz-Signature=signed", server.url),
        "uploadHeaders": { "content-type": "application/gzip" },
        "expiresAt": "2099-01-01T00:00:00.000Z",
    }))
    .expect("publish upload");

    let error = RegistryClient::new()
        .with_base_url(&server.url)
        .upload_publish_tarball(&upload, &Arc::new(vec![1, 2, 3]))
        .await
        .expect_err("an untrusted certificate must fail the upload");

    assert_untrusted_certificate(&error);
    assert!(
        !error.to_string().contains("X-Amz-Signature"),
        "the presigned URL stays out of the error: {error}"
    );
    assert_eq!(server.connections(), 1);
}

/// A registry that stores a publish and then redirects to `status_url`,
/// answering the reconciliation probe with `stored` or a 404.
async fn registry_redirecting_publishes_to(status_url: &str, stored: bool) -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/registry/@lpm.dev/owner.pkg"))
        .respond_with(ResponseTemplate::new(303).insert_header("location", status_url))
        .expect(1)
        .mount(&server)
        .await;
    let probe = if stored {
        ResponseTemplate::new(200).set_body_string(test_metadata_json("@lpm.dev/owner.pkg"))
    } else {
        ResponseTemplate::new(404)
    };
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/owner.pkg"))
        .respond_with(probe)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_publish_whose_redirect_meets_an_untrusted_certificate_is_reconciled_and_not_replayed() {
    let status = UntrustedHttpsServer::start().await;
    let status_url = format!("{}/status", status.url);
    let encoded_name = "@lpm.dev/owner.pkg";
    let payload = lpm_http::ReplayableRequestBody::from_bytes(
        serde_json::to_vec(&serde_json::json!({ "name": encoded_name })).unwrap(),
    );

    for stored in [true, false] {
        let registry = registry_redirecting_publishes_to(&status_url, stored).await;
        let connections_before = status.connections();
        let (client, _tmp) = client_with_mock_server(&registry.uri());

        let result = client
            .with_token("publish-token")
            .publish_package(encoded_name, "1.0.0", "sha512-test", &payload, None, 0)
            .await;

        if stored {
            let published = result.expect("the registry kept the publish before redirecting");
            assert_eq!(published["name"], encoded_name);
        } else {
            assert_untrusted_certificate(
                &result.expect_err("a publish the registry doesn't have must fail"),
            );
        }
        assert_eq!(
            status.connections() - connections_before,
            1,
            "stored={stored}: the publish must not be replayed into the same certificate"
        );
    }
}

#[tokio::test]
async fn a_publish_whose_answer_misses_its_deadline_is_reconciled_with_the_registry() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // The registry stores the publish, then answers after the deadline.
    Mock::given(method("PUT"))
        .and(path("/api/registry/@lpm.dev/owner.pkg"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(5)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/owner.pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(test_metadata_json("@lpm.dev/owner.pkg")),
        )
        .mount(&server)
        .await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let url = format!("{}/api/registry/@lpm.dev/owner.pkg", server.uri());
    let payload = lpm_http::ReplayableRequestBody::from_bytes(
        serde_json::to_vec(&serde_json::json!({ "name": "@lpm.dev/owner.pkg" })).unwrap(),
    );
    let request_client = reqwest::Client::new();

    let response = client
        .send_publish_safe(
            || {
                Ok(request_client
                    .put(&url)
                    .timeout(std::time::Duration::from_millis(200))
                    .body(payload.body()))
            },
            &payload,
            None,
            "@lpm.dev/owner.pkg",
            "1.0.0",
            "sha512-test",
        )
        .await
        .expect("a publish the registry has must not be reported as failed");

    assert!(matches!(response, PublishSafeResponse::Recovered(_)));
}

/// Gives `client` lazy `.npmrc` TLS settings for `url`'s origin and holds
/// that origin's client build open, as a passphrase prompt nobody answers
/// would. Abort the returned task to release it.
async fn hold_client_build_open(
    client: &mut RegistryClient,
    url: &str,
) -> tokio::task::JoinHandle<()> {
    let origin = OriginKey::from_request_url(url).expect("origin");
    let mut tls_overrides = TlsOverrides::default();
    tls_overrides
        .per_origin
        .insert(origin.clone(), OriginTlsOverrides::default());
    let lazy = tls_overrides
        .per_origin
        .keys()
        .map(|origin| (origin.clone(), tokio::sync::OnceCell::new()))
        .collect();
    client.http = Arc::new(HttpClients {
        default: DefaultClient::built(cached(RegistryClient::build_http_client(
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
        ))),
        eager: HashMap::new(),
        lazy,
        built_client_sets: AtomicUsize::new(0),
        tls_overrides: Arc::new(tls_overrides),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
        per_origin_identity_certs: HashMap::new(),
        next_request_lane: AtomicUsize::new(0),
    });
    let (building_tx, building_rx) = tokio::sync::oneshot::channel();
    let http = Arc::clone(&client.http);
    let held_build = tokio::spawn(async move {
        http.lazy[&origin]
            .get_or_init(|| {
                let _ = building_tx.send(());
                std::future::pending()
            })
            .await;
    });
    building_rx
        .await
        .expect("the origin's client build started");
    held_build
}

async fn publish_with_a_200ms_deadline(
    client: &RegistryClient,
    url: &str,
) -> Result<PublishSafeResponse, LpmError> {
    let payload = lpm_http::ReplayableRequestBody::from_bytes(
        serde_json::to_vec(&serde_json::json!({ "name": "@lpm.dev/owner.pkg" })).unwrap(),
    );
    let request_client = reqwest::Client::new();
    client
        .send_publish_safe(
            || {
                Ok(request_client
                    .put(url)
                    .timeout(std::time::Duration::from_millis(200))
                    .body(payload.body()))
            },
            &payload,
            None,
            "@lpm.dev/owner.pkg",
            "1.0.0",
            "sha512-test",
        )
        .await
}

#[tokio::test]
async fn a_publish_whose_deadline_runs_out_between_redirect_hops_is_reconciled_with_the_registry() {
    let status = wiremock::MockServer::start().await;
    let status_url = format!("{}/status", status.uri());
    let registry = registry_redirecting_publishes_to(&status_url, true).await;
    let (mut client, _tmp) = client_with_mock_server(&registry.uri());
    // The redirect target's client is still being built when the deadline
    // passes.
    let held_build = hold_client_build_open(&mut client, &status_url).await;

    let response = publish_with_a_200ms_deadline(
        &client,
        &format!("{}/api/registry/@lpm.dev/owner.pkg", registry.uri()),
    )
    .await;
    held_build.abort();

    assert!(
        matches!(response, Ok(PublishSafeResponse::Recovered(_))),
        "the registry kept the publish before redirecting: {:?}",
        response.err()
    );
    assert!(status.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_publish_whose_deadline_runs_out_before_it_is_sent_is_neither_sent_nor_probed() {
    let registry = wiremock::MockServer::start().await;
    let (mut client, _tmp) = client_with_mock_server(&registry.uri());
    let url = format!("{}/api/registry/@lpm.dev/owner.pkg", registry.uri());
    let held_build = hold_client_build_open(&mut client, &url).await;

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        publish_with_a_200ms_deadline(&client, &url),
    )
    .await;
    held_build.abort();

    let Err(error) =
        outcome.expect("a publish nothing received must not wait on a reconciliation probe")
    else {
        panic!("a publish that was never sent fails");
    };
    assert!(
        error.to_string().contains("before it was sent"),
        "the error says nothing reached the registry: {error}"
    );
    assert!(registry.received_requests().await.unwrap().is_empty());
}
