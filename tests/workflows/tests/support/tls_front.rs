//! An HTTPS front for [`MockRegistry`]: a TLS listener on `localhost`
//! whose certificate a private test CA signs, forwarding each decrypted
//! connection to the mock. A command reaches it only when `.npmrc`'s
//! `cafile=` makes it trust that CA.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

use super::mock_registry::{MockRegistry, compute_integrity};

pub struct TlsFront {
    /// `https://localhost:<port>`.
    pub url: String,
    /// The test CA's certificate, for a `cafile=` line.
    pub ca_path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TlsFront {
    /// Start the front for `mock`, writing the CA certificate into `directory`.
    pub fn start(mock: &MockRegistry, directory: &Path) -> Self {
        let upstream = mock.server().address().to_owned();
        let ca_key = KeyPair::generate().expect("generate the test CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "lpm workflow test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("self-sign the test CA");
        let ca_path = directory.join("lpm-test-ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).expect("write the test CA certificate");
        let issuer = Issuer::new(ca_params, ca_key);

        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("leaf certificate parameters");
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().expect("generate the leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("sign the leaf certificate");

        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(leaf_cert.der().to_vec()),
                CertificateDer::from(ca_cert.der().to_vec()),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("TLS server configuration");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the TLS front");
        listener
            .set_nonblocking(true)
            .expect("make the TLS front listener non-blocking");
        let port = listener.local_addr().expect("TLS front address").port();
        let (shutdown, mut stopped) = tokio::sync::oneshot::channel::<()>();
        // The test thread blocks on the `lpm` child process, so the front
        // serves from a runtime of its own.
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("TLS front runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("register the TLS front listener");
                loop {
                    let (stream, _) = tokio::select! {
                        accepted = listener.accept() => match accepted {
                            Ok(accepted) => accepted,
                            Err(_) => continue,
                        },
                        _ = &mut stopped => break,
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let Ok(mut plain) = tokio::net::TcpStream::connect(upstream).await else {
                            return;
                        };
                        let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
                    });
                }
            });
        });

        Self {
            url: format!("https://localhost:{port}"),
            ca_path,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    /// The `.npmrc` line that trusts the test CA for this front only.
    pub fn per_origin_cafile_line(&self) -> String {
        let origin = self.url.trim_start_matches("https:");
        format!("{origin}/:cafile={}\n", self.ca_path.display())
    }

    /// Write `~/.npmrc` for `home`: `extra` lines, then the per-origin
    /// `cafile=` line that trusts this front.
    pub fn write_user_npmrc(&self, home: &Path, extra: &str) {
        std::fs::write(
            home.join(".npmrc"),
            format!("{extra}{}", self.per_origin_cafile_line()),
        )
        .expect("write ~/.npmrc");
    }

    /// `metadata` with each version's `dist.tarball` on `mock` moved to this
    /// front.
    pub fn advertise(
        &self,
        mock: &MockRegistry,
        mut metadata: serde_json::Value,
    ) -> serde_json::Value {
        let mock_url = mock.url();
        if let Some(versions) = metadata["versions"].as_object_mut() {
            for document in versions.values_mut() {
                if let Some(tarball) = document["dist"]["tarball"].as_str()
                    && let Some(path) = tarball.strip_prefix(&mock_url)
                {
                    document["dist"]["tarball"] = format!("{}{path}", self.url).into();
                }
            }
        }
        metadata
    }

    /// Serve `name`'s `versions` (version, tarball) from `mock`, with each
    /// tarball advertised through this front. The last version is `latest`.
    pub async fn mount_package(
        &self,
        mock: &MockRegistry,
        name: &str,
        versions: &[(&str, Vec<u8>)],
    ) {
        let mut documents = serde_json::Map::new();
        let mut times = serde_json::Map::new();
        for (version, tarball) in versions {
            let tarball_path = MockRegistry::tarball_path(name, version);
            mock.register_tarball_bytes(name, version, tarball);
            documents.insert(
                (*version).to_string(),
                serde_json::json!({
                    "name": name,
                    "version": version,
                    "dist": {
                        "tarball": format!("{}{tarball_path}", self.url),
                        "integrity": compute_integrity(tarball),
                    },
                }),
            );
            times.insert(
                (*version).to_string(),
                serde_json::Value::String("2025-01-01T00:00:00.000Z".into()),
            );
            Mock::given(method("GET"))
                .and(path(tarball_path))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(tarball.clone())
                        .insert_header("content-type", "application/octet-stream"),
                )
                .mount(mock.server())
                .await;
        }
        let latest = versions.last().expect("at least one version").0;
        let metadata = serde_json::json!({
            "name": name,
            "dist-tags": { "latest": latest },
            "versions": documents,
            "time": times,
        });
        for metadata_path in [format!("/api/registry/{name}"), format!("/{name}")] {
            Mock::given(method("GET"))
                .and(path(metadata_path))
                .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
                .mount(mock.server())
                .await;
        }
        mock.with_batch_metadata(vec![metadata]).await;
    }
}

impl Drop for TlsFront {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
