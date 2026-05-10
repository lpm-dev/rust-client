//! Shared TLS test scaffolding for `lpm-registry` integration tests.
//!
//! Lifted from the original inline copy in `cafile_strict_ssl.rs`
//! when Phase 58.3 (mTLS / per-origin TLS) added a second consumer
//! (`mtls.rs`). The pre-Phase-58.3 file header in `cafile_strict_ssl.rs`
//! noted: *"One consumer = inline; two = refactor."* This is the lift.
//!
//! ## Consumers
//!
//! - `tests/cafile_strict_ssl.rs` — Phase 58.1, server-only TLS.
//! - `tests/mtls.rs` — Phase 58.3, mutual TLS (server requires client cert).
//!
//! Each consumer brings the module in via:
//!
//! ```ignore
//! #[path = "util/tls_server.rs"]
//! mod tls_server;
//! ```
//!
//! …because every `tests/<file>.rs` is its own crate and items in
//! sibling subdirectories aren't auto-included. The `#[path]` form
//! avoids the `tests/util/mod.rs` ceremony for a single shared file.
//!
//! ## What's here
//!
//! - **Cert factory.** [`TestCa`] (root CA) + [`make_root_ca`].
//!   [`LeafCert`] + [`make_leaf`] for SERVER leaves of three shapes
//!   ([`LeafShape::Valid`] / [`Mismatch`] / [`Expired`]).
//!   [`ClientLeaf`] + [`make_client_leaf`] for CLIENT identity leaves
//!   used by the mTLS matrix.
//! - **TLS server.** [`spawn_tls_server`] for server-only (no client
//!   auth); [`spawn_tls_server_mutual`] for required client cert.
//!   Both bind `127.0.0.1:0` (kernel-assigned port), return the port
//!   + a `JoinHandle`, and serve a static 200 OK after the handshake.
//! - **Crypto provider.** [`ensure_crypto_provider`] installs rustls
//!   0.23's ring provider (idempotent — safe across tests).

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

// ---- Cert factory -----------------------------------------------------

pub struct TestCa {
    /// CA cert object — needed as the `issuer` argument to
    /// [`CertificateParams::signed_by`] when minting leaves.
    pub cert: rcgen::Certificate,
    /// DER form for inclusion in the server's TLS chain.
    pub cert_der: CertificateDer<'static>,
    /// PEM form for the client's `cafile=` / `ca=` trust-store and
    /// for inclusion in mTLS-verifier root sets.
    pub cert_pem: String,
    /// CA keypair — needed as the `issuer_key` argument to
    /// [`CertificateParams::signed_by`].
    pub key_pair: KeyPair,
}

pub fn make_root_ca() -> TestCa {
    let ca_key = KeyPair::generate().expect("CA keypair");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "lpm test root CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&ca_key).expect("self-sign CA");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let cert_pem = cert.pem();
    TestCa {
        cert,
        cert_der,
        cert_pem,
        key_pair: ca_key,
    }
}

pub struct LeafCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

#[derive(Clone, Copy)]
// Each `tests/<file>.rs` is its own crate; `mtls.rs` only uses
// `Valid`, while `cafile_strict_ssl.rs` uses all three. Suppress the
// per-crate dead-code lint for variants the current test crate
// happens not to consume.
#[allow(dead_code)]
pub enum LeafShape {
    Valid,
    Mismatch,
    Expired,
}

/// Mint a SERVER leaf signed by `ca`, shaped per `shape`.
///
/// `ServerAuth` EKU + the SAN matches `localhost`+`127.0.0.1` for
/// the `Valid` case. `Mismatch` swaps the SAN to a different host
/// to exercise hostname verification; `Expired` predates `notAfter`
/// to exercise validity checks.
pub fn make_leaf(ca: &TestCa, shape: LeafShape) -> LeafCert {
    let (sans, not_after): (Vec<String>, OffsetDateTime) = match shape {
        LeafShape::Valid => (
            vec!["localhost".into(), "127.0.0.1".into()],
            OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 3600),
        ),
        LeafShape::Mismatch => (
            vec!["not-the-right-host.com".into()],
            OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 3600),
        ),
        LeafShape::Expired => (
            vec!["localhost".into(), "127.0.0.1".into()],
            OffsetDateTime::now_utc() - Duration::from_secs(2 * 24 * 3600),
        ),
    };

    let mut params = CertificateParams::new(sans).expect("leaf params");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "lpm test leaf");
    params.not_after = not_after;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key_pair = KeyPair::generate().expect("leaf keypair");
    let cert = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .expect("leaf signed by CA");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    LeafCert {
        cert_der,
        key_der: PrivateKeyDer::Pkcs8(key_der),
    }
}

/// A CLIENT identity leaf — for the mTLS matrix. Same general shape
/// as a server leaf but with `ClientAuth` EKU instead of `ServerAuth`,
/// and exposed as PEM so it can be written to disk for
/// `lpm-registry`'s on-disk-only `Identity::from_pem` loader path.
///
/// Per-test-crate `#[allow(dead_code)]`: each `tests/<file>.rs` is
/// its own crate, and `cafile_strict_ssl.rs` doesn't construct
/// client leaves. The mTLS-only consumers ARE consumers; the lint
/// is misled by the per-crate compilation boundary.
#[allow(dead_code)]
pub struct ClientLeaf {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Mint a client identity leaf signed by `ca`. Always valid +
/// long-lived; the matrix exercises wrong-CA and missing-identity
/// cases by swapping the signing CA, not by shape.
#[allow(dead_code)]
pub fn make_client_leaf(ca: &TestCa) -> ClientLeaf {
    let mut params =
        CertificateParams::new(vec!["lpm test client".to_string()]).expect("client leaf params");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "lpm test client");
    params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 3600);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key_pair = KeyPair::generate().expect("client keypair");
    let cert = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .expect("client leaf signed by CA");
    ClientLeaf {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

// ---- TLS server ------------------------------------------------------

/// rustls 0.23 needs a CryptoProvider installed. Picks `ring`
/// (matches the dev-dep feature). Idempotent — safe across tests.
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Spawn a server-only TLS listener on `127.0.0.1:0`. Returns the
/// kernel-assigned port + a `JoinHandle` for the accept loop.
///
/// Server presents `[leaf, root_ca]`. Static 200 OK after handshake.
pub async fn spawn_tls_server(leaf: LeafCert, ca: &TestCa) -> (u16, JoinHandle<()>) {
    ensure_crypto_provider();
    let chain = vec![leaf.cert_der.clone(), ca.cert_der.clone()];
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, leaf.key_der)
        .expect("rustls ServerConfig");
    spawn_with_config(config).await
}

/// Spawn a TLS listener that REQUIRES client certs verified against
/// `client_trust_ca`'s root. Phase 58.3 mTLS matrix uses this.
#[allow(dead_code)] // see ClientLeaf — per-test-crate visibility
///
/// `server_ca` is the CA that signed the server leaf (presented in
/// the chain to the client). `client_trust_ca` is the CA whose root
/// goes into the verifier's trust store; clients presenting a
/// certificate signed by that CA are accepted, others are rejected
/// at the handshake.
///
/// In tests, server_ca and client_trust_ca are usually different
/// CAs (so a wrong-CA client identity legitimately fails).
pub async fn spawn_tls_server_mutual(
    leaf: LeafCert,
    server_ca: &TestCa,
    client_trust_ca: &TestCa,
) -> (u16, JoinHandle<()>) {
    ensure_crypto_provider();
    let chain = vec![leaf.cert_der.clone(), server_ca.cert_der.clone()];
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(client_trust_ca.cert_der.clone())
        .expect("add client-trust CA");
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, leaf.key_der)
        .expect("rustls ServerConfig (mTLS)");
    spawn_with_config(config).await
}

async fn spawn_with_config(config: ServerConfig) -> (u16, JoinHandle<()>) {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(handle_one_connection(acceptor, stream));
        }
    });
    (port, handle)
}

async fn handle_one_connection(acceptor: TlsAcceptor, stream: TcpStream) {
    let Ok(mut tls) = acceptor.accept(stream).await else {
        return; // handshake failed; drop the connection
    };
    let mut buf = [0u8; 4096];
    let mut total = Vec::with_capacity(512);
    loop {
        match tokio::time::timeout(Duration::from_millis(200), tls.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    let _ = tls
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
    let _ = tls.shutdown().await;
}

// ---- Probe helpers ---------------------------------------------------

/// Classify a `RegistryClient` request error into "TLS handshake
/// failed" vs "TLS OK / body parse failed" by keyword. Lifted with
/// the rest of the scaffolding so both consumers (`cafile_strict_ssl`
/// + `mtls`) classify the same way.
///
/// Returns `Err(message)` if classification says handshake failed,
/// `Ok(())` if it says handshake succeeded (body parse irrelevant).
pub fn classify_request_error(msg: String) -> Result<(), String> {
    let lower = msg.to_lowercase();
    let handshake_keywords = [
        "tls",
        "certificate",
        "self-signed",
        "self signed",
        "unknown ca",
        "unknown issuer",
        "invalid peer",
        "handshake",
        "name not match",
        "subject name does not match",
        "expired",
        "not yet valid",
        "certvalidation",
        "invalidcertificate",
        "badcertificate",
        // mTLS-specific: server rejecting client identity surfaces
        // through these classes.
        "certificaterequired",
        "certificate required",
        "received fatal alert",
        "alertreceived",
    ];
    let body_keywords = [
        "decode",
        "json",
        "parse",
        "eof while parsing",
        "unexpected end",
    ];
    if handshake_keywords.iter().any(|k| lower.contains(k)) {
        Err(msg)
    } else if body_keywords.iter().any(|k| lower.contains(k)) {
        Ok(())
    } else {
        // Unknown — treat as handshake failure to be safe.
        Err(msg)
    }
}
