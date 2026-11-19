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
