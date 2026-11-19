use super::*;
use crate::npmrc::{OriginTlsOverrides, TaggedPath};
use std::sync::Arc;

/// An HTTPS listener on 127.0.0.1 whose certificate, for `localhost` and
/// `127.0.0.1`, a private test CA signs. It answers every request `200 ok`.
struct CaSignedHttpsServer {
    port: u16,
    ca_pem: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}

impl CaSignedHttpsServer {
    async fn start() -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "lpm-registry test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign the CA");
        let ca_pem = ca_cert.pem().into_bytes();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("leaf parameters");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("sign the leaf");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf_cert.der().clone(), ca_cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )
        .expect("TLS server configuration");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the HTTPS listener");
        let port = listener.local_addr().expect("listener address").port();
        let task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = [0u8; 4096];
                    let _ = tls.read(&mut request).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self { port, ca_pem, task }
    }
}

impl Drop for CaSignedHttpsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn get_with(builder: reqwest::ClientBuilder, url: String) -> Result<(), String> {
    let client = builder.build().map_err(|error| error.to_string())?;
    client
        .get(url)
        .send()
        .await
        .map(|_| ())
        .map_err(|error| lpm_http::error_chain(&error))
}

#[tokio::test]
async fn a_tls_client_builder_without_npmrc_settings_trusts_only_the_bundled_roots() {
    let server = CaSignedHttpsServer::start().await;
    let url = format!("https://localhost:{}/", server.port);

    let builder = RegistryClient::new()
        .tls_client_builder_for(&url)
        .await
        .expect("builder");

    let error = get_with(builder, url)
        .await
        .expect_err("the bundled roots don't include the test CA");
    assert!(error.contains("UnknownIssuer"), "{error}");
}

#[tokio::test]
async fn a_tls_client_builder_trusts_a_per_origin_cafile_only_for_its_origin() {
    let server = CaSignedHttpsServer::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &server.ca_pem).expect("write the CA");
    let mut per_origin = HashMap::new();
    per_origin.insert(
        OriginKey {
            host_lower: "localhost".into(),
            port: Some(server.port),
        },
        OriginTlsOverrides {
            cafiles: vec![TaggedPath {
                path: ca_path,
                source: "test .npmrc".into(),
                line: 1,
                source_dir: None,
            }],
            certfile: None,
            keyfile: None,
        },
    );
    let client = RegistryClient::new()
        .with_tls_overrides(&TlsOverrides {
            per_origin,
            ..Default::default()
        })
        .expect("TLS overrides");
    let configured = format!("https://localhost:{}/", server.port);
    let other = format!("https://127.0.0.1:{}/", server.port);

    get_with(
        client
            .tls_client_builder_for(&configured)
            .await
            .expect("builder"),
        configured,
    )
    .await
    .expect("the origin's cafile makes its certificate trusted");
    let error = get_with(
        client
            .tls_client_builder_for(&other)
            .await
            .expect("builder"),
        other,
    )
    .await
    .expect_err("another origin keeps the bundled roots");
    assert!(error.contains("UnknownIssuer"), "{error}");
}

#[tokio::test]
async fn a_tls_client_builder_trusts_a_global_cafile_for_every_origin() {
    let server = CaSignedHttpsServer::start().await;
    let client = RegistryClient::new()
        .with_tls_overrides(&TlsOverrides {
            extra_roots: vec![crate::npmrc::TaggedRoot {
                pem_bytes: Arc::new(server.ca_pem.clone()),
                source: "test .npmrc".into(),
                line: 1,
            }],
            ..Default::default()
        })
        .expect("TLS overrides");

    for url in [
        format!("https://localhost:{}/", server.port),
        format!("https://127.0.0.1:{}/", server.port),
    ] {
        get_with(
            client.tls_client_builder_for(&url).await.expect("builder"),
            url,
        )
        .await
        .expect("a global cafile applies to every origin");
    }
}
