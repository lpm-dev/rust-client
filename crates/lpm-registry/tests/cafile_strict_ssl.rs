//! Phase 58.1 day-4 — `cafile` / `ca` / `strict-ssl` integration matrix.
//!
//! 12-cell test grid (3 server cert shapes × 4 client configs) that
//! pins the user-visible contracts of [`RegistryClient::with_tls_overrides`].
//! Per Gemini's day-4 design call, the matrix specifically proves that
//! `strict-ssl=false` ignores ALL three classic cert defects (untrusted
//! CA, hostname mismatch, expired) — not just the unknown-CA path that
//! a naive trust-root extension would already cover.
//!
//! ## Cert chain shape (matches enterprise reality)
//!
//! - One rcgen-generated **Root CA** per test (so they don't share state).
//! - Three **leaf certs**, each signed by the test's Root CA:
//!   - `valid` — SAN: `localhost`, `127.0.0.1`. `notAfter`: ~1 year out.
//!   - `mismatch` — SAN: `not-the-right-host.com`. `notAfter`: ~1 year out.
//!   - `expired` — SAN: `localhost`, `127.0.0.1`. `notAfter`: 2 days ago.
//! - Server presents `[leaf, root_ca]` chain (per Gemini's gotcha — some
//!   rustls paths balk if the root isn't explicit in the chain).
//! - Tests load the **Root CA's PEM** via `cafile=` / `ca=`. This
//!   matches how a corporate IT setup typically works (one CA in the
//!   trust store; many short-lived leaves issued from it).
//!
//! ## Outcome map (the spec)
//!
//! | server cert | default | cafile  | ca-inline | strict-ssl=false |
//! | ----------- | ------- | ------- | --------- | ---------------- |
//! | valid       | FAIL    | **OK**  | **OK**    | **OK**           |
//! | mismatch    | FAIL    | FAIL    | FAIL      | **OK**           |
//! | expired     | FAIL    | FAIL    | FAIL      | **OK**           |
//!
//! The bottom-right column is the load-bearing column for `strict-ssl=false`.
//! The middle two columns prove cafile/ca are additive trust-root only —
//! they don't disable hostname or expiry validation.
//!
//! ## Test server shape
//!
//! Hand-rolled `tokio::net::TcpListener` + `tokio_rustls::TlsAcceptor`.
//! Returns a hard-coded HTTP/1.1 200 OK response after the handshake.
//! Each test spawns its own listener on `127.0.0.1:0` (kernel-assigned
//! port) and drops it on test exit — fully parallel-safe, no shared state.
//!
//! ## Future split (Phase 58.3 mTLS)
//!
//! The TLS server util + cert-chain helpers (`make_root_ca`, `make_leaf`,
//! `spawn_tls_server`, `handle_one_connection`) live inline here for one
//! consumer. When Phase 58.3 (mTLS / per-origin TLS) lands a second
//! TLS-handshake test file, lift this scaffolding into
//! `crates/lpm-registry/tests/util/tls_server.rs` (with a `mod util;`
//! shim per integration test file, since each `tests/*.rs` is its own
//! crate). One consumer = inline; two = refactor. Don't preemptively
//! create the `tests/util/` dir for one user.

use lpm_registry::{RegistryClient, TaggedBool, TaggedRoot, TlsOverrides};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, IsCa, KeyPair, KeyUsagePurpose,
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

// ---- Cert generation ---------------------------------------------------

struct TestCa {
    /// The CA cert object — needed as the `issuer` argument to
    /// [`CertificateParams::signed_by`] when minting leaves.
    cert: rcgen::Certificate,
    /// DER form for inclusion in the server's TLS chain.
    cert_der: CertificateDer<'static>,
    /// PEM form for the client's `cafile=` / `ca=` trust-store.
    cert_pem: String,
    /// CA keypair — needed as the `issuer_key` argument to
    /// [`CertificateParams::signed_by`].
    key_pair: KeyPair,
}

fn make_root_ca() -> TestCa {
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

struct LeafCert {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
}

#[derive(Clone, Copy)]
enum LeafShape {
    Valid,
    Mismatch,
    Expired,
}

fn make_leaf(ca: &TestCa, shape: LeafShape) -> LeafCert {
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
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
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

// ---- TLS test server ---------------------------------------------------

fn ensure_crypto_provider() {
    // rustls 0.23 needs a CryptoProvider installed; pick `ring` because
    // we already pull it in via the dev-dep feature. Idempotent — safe
    // to call once per test.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn spawn_tls_server(leaf: LeafCert, ca: &TestCa) -> (u16, JoinHandle<()>) {
    ensure_crypto_provider();

    let chain = vec![leaf.cert_der.clone(), ca.cert_der.clone()];
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, leaf.key_der)
        .expect("rustls ServerConfig");
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
    // Read the request bytes (and discard them — we only care that the
    // handshake succeeded). Drain until we see the end of headers.
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

// ---- Client probes -----------------------------------------------------

#[derive(Clone, Copy)]
enum ClientConfig {
    Default,
    Cafile,
    CaInline,
    StrictSslFalse,
}

fn build_client(cfg: ClientConfig, ca_pem: &str) -> RegistryClient {
    let base = RegistryClient::new();
    match cfg {
        ClientConfig::Default => base,
        ClientConfig::Cafile | ClientConfig::CaInline => {
            // For this test the on-disk vs inline distinction is
            // immaterial — both paths feed the same `extra_roots`
            // pipeline in `with_tls_overrides`. Day-1's parser tests
            // already pin the file-vs-inline parsing difference.
            let tls = TlsOverrides {
                extra_roots: vec![TaggedRoot {
                    pem_bytes: ca_pem.as_bytes().to_vec(),
                    source: "test:.npmrc".into(),
                    line: 1,
                }],
                strict_ssl: None,
            };
            base.with_tls_overrides(&tls).expect("builder ok")
        }
        ClientConfig::StrictSslFalse => {
            let tls = TlsOverrides {
                extra_roots: Vec::new(),
                strict_ssl: Some(TaggedBool {
                    value: false,
                    source: "test:.npmrc".into(),
                    line: 1,
                }),
            };
            base.with_tls_overrides(&tls).expect("builder ok")
        }
    }
}

/// Fire a metadata GET at the test server through `RegistryClient` and
/// return whether the TLS handshake succeeded (Ok(_)) or not (Err(_)).
/// The actual response body is irrelevant — the server returns a static
/// 200 OK with empty body after handshake. Empty body fails downstream
/// JSON parse and surfaces as a (non-TLS) error class which we treat as
/// "TLS OK" via the keyword classification below.
async fn probe(client: &RegistryClient, port: u16) -> Result<(), String> {
    let base_url = format!("https://localhost:{port}");
    let configured = client.clone_with_config().with_npm_registry_url(base_url);
    match configured.get_npm_metadata_direct("test-pkg").await {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            // Network / handshake errors are what we care about. The
            // server returns 200 with empty body for *successful*
            // handshakes — that body fails JSON parse downstream and
            // surfaces as a Registry error too. Distinguish:
            //   - Success-on-handshake → "decode" / "parse" / "JSON" / "EOF"
            //   - Failure-on-handshake → "tls" / "certificate" / "handshake"
            //                            / "connection" / "self-signed"
            //                            / "invalid peer" / "unknown ca"
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
                // Handshake succeeded; body parse failed. That's a "TLS OK".
                Ok(())
            } else {
                // Other error class — assume handshake failure to be
                // safe (these tests want to flag any TLS-layer break).
                Err(msg)
            }
        }
    }
}

// ---- The 12 cells ------------------------------------------------------

async fn cell(server_shape: LeafShape, cli_cfg: ClientConfig) -> Result<(), String> {
    let ca = make_root_ca();
    let leaf = make_leaf(&ca, server_shape);
    let (port, _handle) = spawn_tls_server(leaf, &ca).await;
    let client = build_client(cli_cfg, &ca.cert_pem);
    probe(&client, port).await
}

// Valid leaf row.
#[tokio::test]
async fn valid_default_fails_unknown_ca() {
    assert!(cell(LeafShape::Valid, ClientConfig::Default).await.is_err());
}
#[tokio::test]
async fn valid_cafile_succeeds() {
    cell(LeafShape::Valid, ClientConfig::Cafile)
        .await
        .expect("valid leaf + cafile must handshake");
}
#[tokio::test]
async fn valid_ca_inline_succeeds() {
    cell(LeafShape::Valid, ClientConfig::CaInline)
        .await
        .expect("valid leaf + ca-inline must handshake");
}
#[tokio::test]
async fn valid_strict_ssl_false_succeeds() {
    cell(LeafShape::Valid, ClientConfig::StrictSslFalse)
        .await
        .expect("strict-ssl=false ignores unknown CA");
}

// Hostname-mismatch leaf row.
#[tokio::test]
async fn mismatch_default_fails() {
    assert!(
        cell(LeafShape::Mismatch, ClientConfig::Default)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn mismatch_cafile_still_fails_on_hostname() {
    // Critical: cafile only adds trust roots; it does NOT disable
    // hostname verification. A leaf with a wrong SAN must still fail.
    assert!(
        cell(LeafShape::Mismatch, ClientConfig::Cafile)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn mismatch_ca_inline_still_fails_on_hostname() {
    assert!(
        cell(LeafShape::Mismatch, ClientConfig::CaInline)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn mismatch_strict_ssl_false_succeeds() {
    // Critical: strict-ssl=false must disable hostname check too,
    // not just the unknown-CA check. This is what differentiates
    // it from cafile in scope.
    cell(LeafShape::Mismatch, ClientConfig::StrictSslFalse)
        .await
        .expect("strict-ssl=false ignores hostname mismatch");
}

// Expired leaf row.
#[tokio::test]
async fn expired_default_fails() {
    assert!(
        cell(LeafShape::Expired, ClientConfig::Default)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn expired_cafile_still_fails_on_validity() {
    // Critical: cafile does NOT disable validity-period checks.
    assert!(
        cell(LeafShape::Expired, ClientConfig::Cafile)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn expired_ca_inline_still_fails_on_validity() {
    assert!(
        cell(LeafShape::Expired, ClientConfig::CaInline)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn expired_strict_ssl_false_succeeds() {
    // Critical: strict-ssl=false must disable expiry check too.
    cell(LeafShape::Expired, ClientConfig::StrictSslFalse)
        .await
        .expect("strict-ssl=false ignores expired cert");
}
