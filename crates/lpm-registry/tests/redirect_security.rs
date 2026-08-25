#[path = "util/tls_server.rs"]
mod tls_server;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use lpm_registry::{RegistryClient, TaggedBool, TaggedRoot, TlsOverrides};
use tls_server::{
    LeafShape, TestCa, make_leaf, make_root_ca, spawn_tls_server_with_response,
    spawn_tls_server_with_response_capture,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn metadata_response() -> Vec<u8> {
    let body = br#"{"name":"redirect-fixture","dist-tags":{},"versions":{}}"#;
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = Vec::with_capacity(headers.len() + body.len());
    response.extend_from_slice(headers.as_bytes());
    response.extend_from_slice(body);
    response
}

fn redirect_response(status: u16, location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn trusted_client(ca: &TestCa) -> reqwest::Client {
    let root = reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).expect("test root PEM");
    lpm_http::client_builder()
        .add_root_certificate(root)
        .build()
        .expect("build trusted HTTP client")
}

fn registry_client(url: String, ca: &TestCa, allow_insecure: bool) -> RegistryClient {
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: ca.cert_pem.as_bytes().to_vec().into(),
            source: "redirect test CA".into(),
            line: 1,
        }],
        ..TlsOverrides::default()
    };
    RegistryClient::new()
        .with_npm_registry_url(url)
        .with_cache_dir(None)
        .with_insecure(allow_insecure)
        .with_tls_overrides(&tls)
        .expect("build trusted registry client")
}

async fn spawn_plain_http_server(response: Vec<u8>) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP target");
    let port = listener.local_addr().expect("HTTP target address").port();
    let request_count = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&request_count);
    let response: Arc<[u8]> = response.into();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let count = Arc::clone(&count);
            let response = Arc::clone(&response);
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                count.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, request_count)
}

async fn spawn_plain_http_metadata_server() -> (u16, Arc<AtomicUsize>) {
    spawn_plain_http_server(metadata_response()).await
}

#[tokio::test]
async fn registry_metadata_refuses_https_redirect_to_http_before_contacting_target() {
    let (http_port, http_request_count) = spawn_plain_http_metadata_server().await;
    let ca = make_root_ca();
    let leaf = make_leaf(&ca, LeafShape::Valid);
    let redirect = redirect_response(
        302,
        &format!("http://127.0.0.1:{http_port}/redirect-fixture?target_token=must-not-appear"),
    );
    let (https_port, _https_server) = spawn_tls_server_with_response(leaf, &ca, redirect).await;
    let client = registry_client(format!("https://localhost:{https_port}"), &ca, false);

    let result = client
        .get_npm_metadata_direct("redirect-fixture?origin_token=must-not-appear")
        .await;

    assert_eq!(
        http_request_count.load(Ordering::SeqCst),
        0,
        "the cleartext redirect target must not receive a request"
    );
    let error = result.expect_err("the HTTPS-to-HTTP redirect must be refused");
    assert!(
        error.to_string().contains("refused HTTPS-to-HTTP redirect"),
        "unexpected redirect refusal: {error}"
    );
    assert!(
        !error.to_string().contains("must-not-appear"),
        "redirect refusal exposed a URL secret: {error}"
    );
}

#[tokio::test]
async fn every_supported_redirect_status_refuses_https_to_http() {
    for status in [301, 302, 303, 307, 308] {
        let ca = make_root_ca();
        let leaf = make_leaf(&ca, LeafShape::Valid);
        let response = redirect_response(
            status,
            "http://127.0.0.1:9/cleartext?target_token=must-not-appear",
        );
        let (port, _server) = spawn_tls_server_with_response(leaf, &ca, response).await;
        let error = trusted_client(&ca)
            .get(format!(
                "https://localhost:{port}/start?origin_token=must-not-appear"
            ))
            .send()
            .await
            .expect_err("HTTPS-to-HTTP redirect must fail");

        assert!(
            lpm_http::is_https_downgrade(&error),
            "status {status} did not produce the downgrade error: {error:?}"
        );
        assert_eq!(
            lpm_http::display_error(&error).to_string(),
            lpm_http::HTTPS_DOWNGRADE_REFUSAL
        );
        assert_eq!(
            lpm_http::error_chain(&error),
            lpm_http::HTTPS_DOWNGRADE_REFUSAL
        );
    }
}

#[tokio::test]
async fn https_to_https_to_http_refuses_second_redirect_before_cleartext_contact() {
    let (http_port, http_request_count) = spawn_plain_http_metadata_server().await;
    let ca = make_root_ca();
    let second_leaf = make_leaf(&ca, LeafShape::Valid);
    let second_response = redirect_response(
        302,
        &format!("http://127.0.0.1:{http_port}/redirect-fixture"),
    );
    let (second_port, _second_server) =
        spawn_tls_server_with_response(second_leaf, &ca, second_response).await;
    let first_leaf = make_leaf(&ca, LeafShape::Valid);
    let first_response = redirect_response(302, &format!("https://localhost:{second_port}/second"));
    let (first_port, _first_server) =
        spawn_tls_server_with_response(first_leaf, &ca, first_response).await;

    let error = trusted_client(&ca)
        .get(format!("https://localhost:{first_port}/first"))
        .send()
        .await
        .expect_err("second-hop downgrade must fail");

    assert!(lpm_http::is_https_downgrade(&error));
    assert_eq!(http_request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http_to_https_to_http_refuses_downgrade_after_upgrade() {
    let (target_port, target_request_count) = spawn_plain_http_metadata_server().await;
    let ca = make_root_ca();
    let https_leaf = make_leaf(&ca, LeafShape::Valid);
    let https_response = redirect_response(
        302,
        &format!("http://127.0.0.1:{target_port}/redirect-fixture"),
    );
    let (https_port, _https_server) =
        spawn_tls_server_with_response(https_leaf, &ca, https_response).await;
    let initial_response =
        redirect_response(302, &format!("https://localhost:{https_port}/secure-hop"));
    let (initial_port, _initial_request_count) = spawn_plain_http_server(initial_response).await;

    let error = trusted_client(&ca)
        .get(format!("http://127.0.0.1:{initial_port}/start"))
        .send()
        .await
        .expect_err("cleartext after an HTTPS upgrade must fail");

    assert!(lpm_http::is_https_downgrade(&error));
    assert_eq!(target_request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn https_to_https_redirect_succeeds_within_limit() {
    let ca = make_root_ca();
    let target_leaf = make_leaf(&ca, LeafShape::Valid);
    let (target_port, target_requests, _target_server) =
        spawn_tls_server_with_response_capture(target_leaf, &ca, metadata_response()).await;
    let redirect_leaf = make_leaf(&ca, LeafShape::Valid);
    let redirect = redirect_response(
        302,
        &format!("https://localhost:{target_port}/redirect-fixture"),
    );
    let (redirect_port, _redirect_server) =
        spawn_tls_server_with_response(redirect_leaf, &ca, redirect).await;

    let response = trusted_client(&ca)
        .get(format!("https://localhost:{redirect_port}/start"))
        .send()
        .await
        .expect("secure redirect should succeed");

    assert!(response.status().is_success());
    assert_eq!(target_requests.lock().expect("request capture").len(), 1);
}

#[tokio::test]
async fn redirect_limit_still_refuses_the_eleventh_hop() {
    let ca = make_root_ca();
    let terminal_leaf = make_leaf(&ca, LeafShape::Valid);
    let (terminal_port, terminal_requests, _terminal_server) =
        spawn_tls_server_with_response_capture(terminal_leaf, &ca, metadata_response()).await;
    let mut next_url = format!("https://localhost:{terminal_port}/terminal");
    for hop in 0..=lpm_http::DEFAULT_REDIRECT_LIMIT {
        let leaf = make_leaf(&ca, LeafShape::Valid);
        let response = redirect_response(302, &next_url);
        let (port, _server) = spawn_tls_server_with_response(leaf, &ca, response).await;
        next_url = format!("https://localhost:{port}/hop-{hop}");
    }

    let error = trusted_client(&ca)
        .get(next_url)
        .send()
        .await
        .expect_err("an eleventh redirect must exceed the default limit");

    assert!(error.is_redirect());
    assert!(lpm_http::error_chain(&error).contains("too many redirects"));
    assert!(
        terminal_requests
            .lock()
            .expect("request capture")
            .is_empty()
    );
}

#[tokio::test]
async fn http_loopback_to_http_loopback_redirect_remains_allowed() {
    let (target_port, target_request_count) = spawn_plain_http_metadata_server().await;
    let redirect = redirect_response(
        302,
        &format!("http://127.0.0.1:{target_port}/redirect-fixture"),
    );
    let (redirect_port, _redirect_request_count) = spawn_plain_http_server(redirect).await;
    let client = lpm_http::client_builder()
        .build()
        .expect("build HTTP client");

    let response = client
        .get(format!("http://127.0.0.1:{redirect_port}/start"))
        .send()
        .await
        .expect("HTTP loopback redirect should succeed");

    assert!(response.status().is_success());
    assert_eq!(target_request_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn https_redirect_to_every_loopback_spelling_is_refused() {
    for target in [
        "http://localhost:9/target",
        "http://127.0.0.1:9/target",
        "http://[::1]:9/target",
    ] {
        let ca = make_root_ca();
        let leaf = make_leaf(&ca, LeafShape::Valid);
        let response = redirect_response(302, target);
        let (port, _server) = spawn_tls_server_with_response(leaf, &ca, response).await;
        let error = trusted_client(&ca)
            .get(format!("https://localhost:{port}/start"))
            .send()
            .await
            .expect_err("HTTPS redirect to cleartext loopback must fail");

        assert!(
            lpm_http::is_https_downgrade(&error),
            "loopback target {target} was not classified as a downgrade"
        );
    }
}

#[tokio::test]
async fn no_follow_policy_returns_redirect_without_contacting_target() {
    let (target_port, target_request_count) = spawn_plain_http_metadata_server().await;
    let ca = make_root_ca();
    let leaf = make_leaf(&ca, LeafShape::Valid);
    let response = redirect_response(
        302,
        &format!("http://127.0.0.1:{target_port}/redirect-fixture"),
    );
    let (port, _server) = spawn_tls_server_with_response(leaf, &ca, response).await;
    let root = reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).expect("test root PEM");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(root)
        .build()
        .expect("build no-follow client");

    let response = client
        .get(format!("https://localhost:{port}/start"))
        .send()
        .await
        .expect("no-follow client should return the redirect response");

    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert_eq!(target_request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cross_origin_https_redirect_strips_sensitive_headers() {
    let ca = make_root_ca();
    let target_leaf = make_leaf(&ca, LeafShape::Valid);
    let (target_port, target_requests, _target_server) =
        spawn_tls_server_with_response_capture(target_leaf, &ca, metadata_response()).await;
    let redirect_leaf = make_leaf(&ca, LeafShape::Valid);
    let redirect = redirect_response(
        302,
        &format!("https://127.0.0.1:{target_port}/redirect-fixture"),
    );
    let (redirect_port, _redirect_server) =
        spawn_tls_server_with_response(redirect_leaf, &ca, redirect).await;

    trusted_client(&ca)
        .get(format!("https://localhost:{redirect_port}/start"))
        .header(reqwest::header::AUTHORIZATION, "Bearer secret")
        .header(reqwest::header::COOKIE, "session=secret")
        .header("cookie2", "legacy=secret")
        .header(reqwest::header::PROXY_AUTHORIZATION, "Basic secret")
        .header(reqwest::header::WWW_AUTHENTICATE, "secret-challenge")
        .header("x-visible-header", "preserved")
        .send()
        .await
        .expect("cross-origin HTTPS redirect should succeed");

    let requests = target_requests.lock().expect("request capture");
    let request = String::from_utf8_lossy(requests.first().expect("redirect target request"));
    let request = request.to_ascii_lowercase();
    for header in [
        "authorization:",
        "cookie:",
        "cookie2:",
        "proxy-authorization:",
        "www-authenticate:",
    ] {
        assert!(
            !request.contains(header),
            "sensitive header followed: {header}"
        );
    }
    assert!(request.contains("x-visible-header: preserved"));
}

#[tokio::test]
async fn blocking_client_refuses_https_to_http_before_contacting_target() {
    let (target_port, target_request_count) = spawn_plain_http_metadata_server().await;
    let ca = make_root_ca();
    let leaf = make_leaf(&ca, LeafShape::Valid);
    let response = redirect_response(
        302,
        &format!("http://127.0.0.1:{target_port}/redirect-fixture"),
    );
    let (port, _server) = spawn_tls_server_with_response(leaf, &ca, response).await;
    let root = reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).expect("test root PEM");
    let url = format!("https://localhost:{port}/start");

    let error = tokio::task::spawn_blocking(move || {
        lpm_http::blocking_client_builder()
            .add_root_certificate(root)
            .build()
            .expect("build blocking client")
            .get(url)
            .send()
            .expect_err("blocking downgrade must fail")
    })
    .await
    .expect("blocking request task");

    assert!(lpm_http::is_https_downgrade(&error));
    assert_eq!(target_request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn insecure_mode_allows_direct_http_but_not_https_redirect_downgrade() {
    let (direct_port, direct_request_count) = spawn_plain_http_metadata_server().await;
    let direct_ca = make_root_ca();
    let direct_client =
        registry_client(format!("http://127.0.0.1:{direct_port}"), &direct_ca, true);
    let metadata = direct_client
        .get_npm_metadata_direct("redirect-fixture")
        .await
        .expect("explicit direct HTTP should remain allowed");
    assert_eq!(metadata.name, "redirect-fixture");
    assert_eq!(direct_request_count.load(Ordering::SeqCst), 1);

    let (target_port, target_request_count) = spawn_plain_http_metadata_server().await;
    let ca = make_root_ca();
    let leaf = make_leaf(&ca, LeafShape::Valid);
    let response = redirect_response(
        302,
        &format!("http://127.0.0.1:{target_port}/redirect-fixture"),
    );
    let (port, _server) = spawn_tls_server_with_response(leaf, &ca, response).await;
    let result = registry_client(format!("https://localhost:{port}"), &ca, true)
        .get_npm_metadata_direct("redirect-fixture")
        .await;

    assert!(
        result
            .expect_err("insecure mode must not allow redirect downgrade")
            .to_string()
            .contains(lpm_http::HTTPS_DOWNGRADE_REFUSAL)
    );
    assert_eq!(target_request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn disabled_certificate_verification_does_not_allow_redirect_downgrade() {
    let (target_port, target_request_count) = spawn_plain_http_metadata_server().await;
    let ca = make_root_ca();
    let leaf = make_leaf(&ca, LeafShape::Valid);
    let response = redirect_response(
        302,
        &format!("http://127.0.0.1:{target_port}/redirect-fixture"),
    );
    let (port, _server) = spawn_tls_server_with_response(leaf, &ca, response).await;
    let tls = TlsOverrides {
        strict_ssl: Some(TaggedBool {
            value: false,
            source: "redirect strict-ssl test".into(),
            line: 1,
        }),
        ..TlsOverrides::default()
    };
    let client = RegistryClient::new()
        .with_npm_registry_url(format!("https://localhost:{port}"))
        .with_cache_dir(None)
        .with_tls_overrides(&tls)
        .expect("build strict-ssl=false client");

    let error = client
        .get_npm_metadata_direct("redirect-fixture")
        .await
        .expect_err("strict-ssl=false must not allow redirect downgrade");

    assert!(
        error
            .to_string()
            .contains(lpm_http::HTTPS_DOWNGRADE_REFUSAL)
    );
    assert_eq!(target_request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unsupported_redirect_scheme_is_not_followed() {
    let ca = make_root_ca();
    let leaf = make_leaf(&ca, LeafShape::Valid);
    let response = redirect_response(302, "file:///etc/passwd");
    let (port, _server) = spawn_tls_server_with_response(leaf, &ca, response).await;

    let response = trusted_client(&ca)
        .get(format!("https://localhost:{port}/start"))
        .send()
        .await
        .expect("unsupported redirect scheme should return the redirect response");

    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert_eq!(response.url().scheme(), "https");
}
