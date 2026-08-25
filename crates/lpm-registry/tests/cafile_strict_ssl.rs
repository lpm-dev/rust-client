//! `cafile` / `ca` / `strict-ssl` integration matrix.
//!
//! 12-cell test grid (3 server cert shapes × 4 client configs) that
//! pins the user-visible contracts of [`RegistryClient::with_tls_overrides`].
//! The matrix specifically proves that `strict-ssl=false` ignores ALL
//! three classic cert defects (untrusted CA, hostname mismatch, expired)
//! — not just the unknown-CA path that a naive trust-root extension would
//! already cover.
//!
//! ## Cert chain shape (matches enterprise reality)
//!
//! - One rcgen-generated **Root CA** per test (so they don't share state).
//! - Three **leaf certs**, each signed by the test's Root CA:
//!   - `valid` — SAN: `localhost`, `127.0.0.1`. `notAfter`: ~1 year out.
//!   - `mismatch` — SAN: `not-the-right-host.com`. `notAfter`: ~1 year out.
//!   - `expired` — SAN: `localhost`, `127.0.0.1`. `notAfter`: 2 days ago.
//! - Server presents `[leaf, root_ca]` chain — some rustls paths balk if
//!   the root isn't explicit in the chain.
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
//! Hand-rolled `tokio::net::TcpListener` + `tokio_rustls::TlsAcceptor`,
//! shared with the mTLS test server via [`tls_server`].
//! Returns a hard-coded HTTP/1.1 200 OK response after the handshake.
//! Each test spawns its own listener on `127.0.0.1:0` (kernel-assigned
//! port) and drops it on test exit — fully parallel-safe, no shared state.

#[path = "util/tls_server.rs"]
mod tls_server;

use lpm_registry::{RegistryClient, TaggedBool, TaggedRoot, TlsOverrides};
use tls_server::{LeafShape, classify_request_error, make_leaf, make_root_ca, spawn_tls_server};

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
                    pem_bytes: ca_pem.as_bytes().to_vec().into(),
                    source: "test:.npmrc".into(),
                    line: 1,
                }],
                strict_ssl: None,
                ..Default::default()
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
                ..Default::default()
            };
            base.with_tls_overrides(&tls).expect("builder ok")
        }
    }
}

/// Fire a metadata GET at the test server through `RegistryClient` and
/// return whether the TLS handshake succeeded (Ok(_)) or not (Err(_)).
async fn probe(client: &RegistryClient, port: u16) -> Result<(), String> {
    let base_url = format!("https://localhost:{port}");
    let configured = client.clone_with_config().with_npm_registry_url(base_url);
    match configured.get_npm_metadata_direct("test-pkg").await {
        Ok(_) => Ok(()),
        Err(e) => classify_request_error(e.to_string()),
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
