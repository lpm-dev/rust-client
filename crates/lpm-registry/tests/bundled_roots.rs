//! LPM's clients trust the root certificates built into LPM and never the
//! operating system's store, so a CA installed on a machine can't vouch for a
//! registry or any other server LPM talks to.

#[path = "util/tls_server.rs"]
mod tls_server;

use std::process::Command;

use tls_server::{LeafShape, make_leaf, make_root_ca, spawn_tls_server};

const PORT: &str = "LPM_BUNDLED_ROOTS_TEST_PORT";
const CA_FILE: &str = "LPM_BUNDLED_ROOTS_TEST_CA_FILE";

/// Serves a certificate from a test CA, then checks LPM's clients in a child
/// process whose `SSL_CERT_FILE` holds that CA. Linux's system store is read
/// from `SSL_CERT_FILE`, so there the CA is trusted by the operating system.
#[tokio::test(flavor = "multi_thread")]
async fn clients_trust_the_bundled_roots_and_not_the_system_store() {
    let ca = make_root_ca();
    let (port, server) = spawn_tls_server(make_leaf(&ca, LeafShape::Valid), &ca).await;
    let directory = tempfile::tempdir().unwrap();
    let ca_file = directory.path().join("ca.pem");
    std::fs::write(&ca_file, &ca.cert_pem).unwrap();
    let no_certificates = directory.path().join("no-certificates");
    std::fs::create_dir(&no_certificates).unwrap();

    let output = tokio::task::spawn_blocking(move || {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "system_store_probe", "--ignored", "--nocapture"])
            .env("SSL_CERT_FILE", &ca_file)
            .env("SSL_CERT_DIR", &no_certificates)
            .env(PORT, port.to_string())
            .env(CA_FILE, &ca_file)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    server.abort();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("test system_store_probe ... ok"),
        "{stdout}\n{stderr}"
    );
}

fn assert_unknown_issuer(error: &dyn std::fmt::Debug) {
    let error = format!("{error:?}");
    assert!(error.contains("UnknownIssuer"), "{error}");
}

#[tokio::test]
#[ignore = "run by clients_trust_the_bundled_roots_and_not_the_system_store"]
async fn system_store_probe() {
    let port = std::env::var(PORT).expect("run by the parent test");
    let ca_file = std::env::var(CA_FILE).expect("run by the parent test");
    let url = format!("https://localhost:{port}/");

    let error = lpm_http::client_builder()
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .expect_err("the bundled roots don't include the test CA");
    assert_unknown_issuer(&error);

    let blocking_url = url.clone();
    let error = tokio::task::spawn_blocking(move || {
        lpm_http::blocking_client_builder()
            .build()
            .unwrap()
            .get(&blocking_url)
            .send()
    })
    .await
    .unwrap()
    .expect_err("the bundled roots don't include the test CA");
    assert_unknown_issuer(&error);

    let ca = reqwest::Certificate::from_pem(&std::fs::read(ca_file).unwrap()).unwrap();
    let response = lpm_http::client_builder_trusting_only([ca])
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .expect("the test CA vouches for the server");
    assert_eq!(response.status(), 200);

    // A client that consulted the system store would accept the server here,
    // which shows the checks above can tell the two apart.
    #[cfg(target_os = "linux")]
    {
        let response = reqwest::Client::builder()
            .build()
            .unwrap()
            .get(&url)
            .send()
            .await
            .expect("Linux's system store holds the test CA");
        assert_eq!(response.status(), 200);
    }
}
