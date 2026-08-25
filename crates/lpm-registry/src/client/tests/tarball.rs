use super::*;

#[tokio::test]
async fn authenticated_tarball_download_refreshes_rejected_stored_session() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _lock = auth_env_lock().await;
    let home = tempfile::tempdir().unwrap();
    let _env = ScopedAuthEnv::file_backed(home.path());
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/private.tgz"))
        .and(header("authorization", "Bearer stale-access"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/cli/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "rotated-access",
            "refreshToken": "rotated-refresh",
            "expiresAt": "2099-01-01T00:00:00Z",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/private.tgz"))
        .and(header("authorization", "Bearer rotated-access"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"private-package"))
        .expect(1)
        .mount(&server)
        .await;

    lpm_auth::store_refresh_backed_session(
        &server.uri(),
        "stale-access",
        "valid-refresh",
        "2099-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    let session = std::sync::Arc::new(lpm_auth::SessionManager::new(server.uri(), None));
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_session(session);

    let bytes = client
        .download_tarball(&format!("{}/private.tgz", server.uri()))
        .await
        .expect("a rejected stored session should refresh before tarball retry");

    assert_eq!(bytes, b"private-package");
}

#[tokio::test]
async fn download_tarball_allows_https() {
    // We can't actually download, but we can verify HTTPS URLs pass validation.
    // The request will fail at the network level, not at URL validation.
    let client = RegistryClient::new();
    let result = client
        .download_tarball("https://registry.npmjs.org/express/-/express-4.22.1.tgz")
        .await;
    // Should NOT be a "must use HTTPS" error — it may fail for other reasons (network)
    if let Err(ref e) = result {
        let msg = e.to_string();
        assert!(
            !msg.contains("tarball URL must use HTTPS"),
            "HTTPS URL should be accepted"
        );
    }
}

#[tokio::test]
async fn download_tarball_rejects_http_without_insecure() {
    let client = RegistryClient::new();
    let result = client.download_tarball("http://evil.com/malware.tgz").await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("tarball URL must use HTTPS"),
        "HTTP URL should be rejected: {msg}"
    );
    assert!(
        msg.contains("--insecure"),
        "error should hint at --insecure flag: {msg}"
    );
}

#[tokio::test]
async fn download_tarball_rejects_file_scheme() {
    let client = RegistryClient::new();
    let result = client.download_tarball("file:///etc/passwd").await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("tarball URL must use HTTPS"),
        "file:// URL should be rejected: {msg}"
    );
}

#[tokio::test]
async fn download_tarball_allows_localhost() {
    let client = RegistryClient::new();
    let result = client
        .download_tarball("http://localhost:3000/pkg.tgz")
        .await;
    // Should NOT be a "must use HTTPS" error
    if let Err(ref e) = result {
        let msg = e.to_string();
        assert!(
            !msg.contains("tarball URL must use HTTPS"),
            "localhost URL should be accepted: {msg}"
        );
    }
}

#[tokio::test]
async fn download_tarball_allows_loopback_ipv4() {
    let client = RegistryClient::new();
    let result = client
        .download_tarball("http://127.0.0.1:3000/pkg.tgz")
        .await;
    if let Err(ref e) = result {
        let msg = e.to_string();
        assert!(
            !msg.contains("tarball URL must use HTTPS"),
            "127.0.0.1 URL should be accepted: {msg}"
        );
    }
}

#[tokio::test]
async fn download_tarball_allows_loopback_ipv6() {
    let client = RegistryClient::new();
    let result = client.download_tarball("http://[::1]:3000/pkg.tgz").await;
    if let Err(ref e) = result {
        let msg = e.to_string();
        assert!(
            !msg.contains("tarball URL must use HTTPS"),
            "[::1] URL should be accepted: {msg}"
        );
    }
}

#[tokio::test]
async fn download_tarball_with_integrity_trust_on_first_use() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = b"hello tarball content for trust-on-first-use";

    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(&server)
        .await;

    let client = RegistryClient::new();
    let url = format!("{}/foo.tgz", server.uri());
    let (data, sri) = client
        .download_tarball_with_integrity(&url, None)
        .await
        .expect("trust-on-first-use must succeed");

    assert_eq!(data.as_slice(), body);
    // The returned SRI is canonical sha512 form computed from
    // the bytes — assert against an independent computation so
    // a regression in the streaming hasher would surface here.
    let expected = Integrity::from_bytes(HashAlgorithm::Sha512, body).to_string();
    assert_eq!(sri, expected);
}

#[tokio::test]
async fn download_tarball_with_integrity_match_succeeds() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = b"matching-integrity content";
    let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha512, body).to_string();

    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(&server)
        .await;

    let client = RegistryClient::new();
    let url = format!("{}/foo.tgz", server.uri());
    let (data, sri) = client
        .download_tarball_with_integrity(&url, Some(&expected_sri))
        .await
        .expect("matching SRI must succeed");

    assert_eq!(data.as_slice(), body);
    assert_eq!(sri, expected_sri);
}

#[tokio::test]
async fn download_tarball_to_file_with_integrity_preserves_verified_file_and_algorithm() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = b"file-backed sha256 content";
    let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha256, body).to_string();
    Mock::given(method("GET"))
        .and(path("/file-backed.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let client = RegistryClient::new();
    let downloaded = client
        .download_tarball_to_file_with_integrity(
            &format!("{}/file-backed.tgz", server.uri()),
            &expected_sri,
        )
        .await
        .expect("matching file-backed SRI must succeed");

    assert_eq!(downloaded.sri, expected_sri);
    assert_eq!(downloaded.compressed_size, body.len() as u64);
    assert_eq!(std::fs::read(downloaded.file.path()).unwrap(), body);
}

#[tokio::test]
async fn download_tarball_to_file_with_integrity_rejects_mismatch() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = b"file-backed actual content";
    let expected_sri =
        Integrity::from_bytes(HashAlgorithm::Sha512, b"different expected content").to_string();
    Mock::given(method("GET"))
        .and(path("/tampered-file-backed.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let client = RegistryClient::new();
    let error = client
        .download_tarball_to_file_with_integrity(
            &format!("{}/tampered-file-backed.tgz", server.uri()),
            &expected_sri,
        )
        .await
        .expect_err("mismatched file-backed SRI must fail");

    assert!(matches!(error, LpmError::IntegrityMismatch { .. }));
}

#[tokio::test]
async fn download_tarball_with_integrity_sha256_match_succeeds() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = b"sha256-declared content";
    let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha256, body).to_string();
    assert!(
        expected_sri.starts_with("sha256-"),
        "test fixture must declare sha256: {expected_sri}"
    );

    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(&server)
        .await;

    let client = RegistryClient::new();
    let url = format!("{}/foo.tgz", server.uri());
    let (data, sri) = client
        .download_tarball_with_integrity(&url, Some(&expected_sri))
        .await
        .expect("sha256 match must succeed");

    assert_eq!(data.as_slice(), body);
    // Returned SRI is in the algorithm the caller declared.
    assert_eq!(sri, expected_sri);
    assert!(sri.starts_with("sha256-"));
}

#[tokio::test]
async fn download_tarball_with_integrity_sha256_mismatch_returns_sha256_actual() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = b"actual content not matching declared hash";
    // Valid sha256 SRI of *different* content — the algo-aware
    // verifier parses, recomputes with sha256, and surfaces
    // mismatch with `actual` in the same algorithm.
    let wrong_sha256 =
        Integrity::from_bytes(HashAlgorithm::Sha256, b"wrong content bytes").to_string();

    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(&server)
        .await;

    let client = RegistryClient::new();
    let url = format!("{}/foo.tgz", server.uri());
    let result = client
        .download_tarball_with_integrity(&url, Some(&wrong_sha256))
        .await;

    match result {
        Err(LpmError::IntegrityMismatch { expected, actual }) => {
            assert_eq!(expected, wrong_sha256);
            // Diagnostic surfaces the actual in the SAME algorithm
            // the user declared — they can compare bytes-vs-bytes
            // without recomputing.
            assert!(
                actual.starts_with("sha256-"),
                "actual must be in declared algorithm for direct comparison: {actual}"
            );
            assert_ne!(actual, wrong_sha256);
        }
        other => panic!("expected IntegrityMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn download_tarball_with_integrity_mismatch_returns_error() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = b"some content";
    // The algo-aware path parses the expected SRI before comparing,
    // so use a valid sha512 SRI of *different* bytes — the realistic
    // threat model (lockfile/manifest drifted, content changed).
    let wrong_sri = Integrity::from_bytes(
        HashAlgorithm::Sha512,
        b"different content bytes; declared hash will not match",
    )
    .to_string();

    Mock::given(method("GET"))
        .and(path("/foo.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(&server)
        .await;

    let client = RegistryClient::new();
    let url = format!("{}/foo.tgz", server.uri());
    let result = client
        .download_tarball_with_integrity(&url, Some(&wrong_sri))
        .await;

    match result {
        Err(LpmError::IntegrityMismatch { expected, actual }) => {
            assert_eq!(expected, wrong_sri);
            assert!(
                actual.starts_with("sha512-"),
                "actual SRI must surface so users can update their lockfile: {actual:?}"
            );
            assert_ne!(actual, wrong_sri);
        }
        other => panic!("expected IntegrityMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn download_tarball_with_integrity_inherits_scheme_guard() {
    // Reusing download_tarball_with_hash → download_tarball_to_file
    // means the scheme guard fires for non-loopback http://.
    // This locks that inheritance — a regression that bypassed
    // the guard would let a tarball dep fetch from
    // `http://evil.com/...` silently.
    let client = RegistryClient::new();
    let result = client
        .download_tarball_with_integrity("http://evil.example.com/x.tgz", None)
        .await;
    match result {
        Err(LpmError::Registry(msg)) => {
            assert!(
                msg.contains("tarball URL must use HTTPS"),
                "scheme guard should reject non-loopback http: {msg}"
            );
        }
        // Some build envs map the scheme guard through other
        // error variants — accept any Err that mentions HTTPS.
        Err(other) => {
            let msg = other.to_string();
            assert!(
                msg.contains("HTTPS") || msg.contains("https"),
                "expected scheme-guard error mentioning HTTPS, got {msg}"
            );
        }
        Ok(_) => panic!("non-loopback http:// must be rejected"),
    }
}

#[tokio::test]
async fn download_tarball_maps_firewall_block_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let client = RegistryClient::new();

    Mock::given(method("GET"))
        .and(path("/is-number/-/is-number-7.0.0.tgz"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "blocked_by_lpm_firewall",
            "decisionId": "decision-1",
            "package": "is-number@7.0.0",
            "verdict": "malicious",
            "reason": "product_default policy maps malicious to block",
            "matchSource": "package"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/is-number/-/is-number-7.0.0.tgz", server.uri());
    let result = client.download_tarball_to_file(&url).await;

    match result {
        Err(LpmError::NpmFirewallBlocked {
            package,
            verdict,
            reason,
            decision_id,
            match_source,
        }) => {
            assert_eq!(package, "is-number@7.0.0");
            assert_eq!(verdict, "malicious");
            assert_eq!(reason, "product_default policy maps malicious to block");
            assert_eq!(decision_id.as_deref(), Some("decision-1"));
            assert_eq!(match_source.as_deref(), Some("package"));
        }
        other => panic!("expected typed firewall block error, got {other:?}"),
    }
}

#[tokio::test]
async fn download_to_file_streams_and_hashes() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    // Small "tarball" body (doesn't need to be valid gzip for this test)
    let body = b"fake-tarball-content-for-hash-test";

    Mock::given(method("GET"))
        .and(path("/tarball/pkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/pkg-1.0.0.tgz", server.uri());
    let downloaded = client.download_tarball_to_file(&url).await.unwrap();

    // Verify file exists and has correct size
    assert_eq!(downloaded.compressed_size, body.len() as u64);

    // Verify file content matches
    let file_content = std::fs::read(downloaded.file.path()).unwrap();
    assert_eq!(file_content, body);

    // Verify SRI hash is correct
    use base64::Engine;
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(body);
    let expected_sri = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    );
    assert_eq!(downloaded.sri, expected_sri);
}

#[tokio::test]
async fn file_spools_share_an_aggregate_compressed_size_budget() {
    use std::sync::Arc;

    use super::super::tarball::CompressedTarballSpoolBudget;

    let reservation_size = super::super::tarball::COMPRESSED_TARBALL_SPOOL_PERMIT_BYTES;
    let budget = Arc::new(CompressedTarballSpoolBudget::new(4 * reservation_size));
    let mut retained = Vec::with_capacity(4);
    for _ in 0..4 {
        let reservation = budget.reserve(None, reservation_size).await.unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"data").unwrap();
        retained.push(
            DownloadedTarball::new(
                file,
                "sha512-fixture".to_string(),
                "sha512-fixture".to_string(),
                4,
                reservation,
            )
            .unwrap(),
        );
    }

    let waiting_budget = Arc::clone(&budget);
    let mut waiting =
        tokio::spawn(async move { waiting_budget.reserve(None, reservation_size).await });
    tokio::time::timeout(std::time::Duration::from_millis(100), &mut waiting)
        .await
        .expect_err("a fifth unknown-size spool must wait for aggregate capacity");

    drop(retained.pop());
    tokio::time::timeout(std::time::Duration::from_secs(2), waiting)
        .await
        .expect("releasing one spool must unblock the waiting download")
        .expect("reservation task must not panic")
        .expect("reservation must succeed");
}

#[tokio::test]
async fn file_spool_rejects_retention_larger_than_its_reservation() {
    use super::super::tarball::CompressedTarballSpoolBudget;

    let budget = CompressedTarballSpoolBudget::new(4);
    let reservation = budget.reserve(Some(4), 4).await.unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    let error = DownloadedTarball::new(
        file,
        "sha512-fixture".to_string(),
        "sha512-fixture".to_string(),
        5,
        reservation,
    )
    .expect_err("the retained spool must not exceed its reserved capacity");

    assert!(
        error.to_string().contains("reserved spool size"),
        "error must explain the aggregate spool invariant: {error}"
    );
}

#[tokio::test]
async fn download_to_file_rejects_oversized_tarball() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    // Send 2KB body but set limit to 1KB — exercises the real rejection path
    let body = vec![0u8; 2048];

    Mock::given(method("GET"))
        .and(path("/tarball/oversized.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/oversized.tgz", server.uri());
    let result = client.download_tarball_to_file_with_limit(&url, 1024).await;

    assert!(result.is_err(), "oversized tarball should be rejected");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("exceeds maximum compressed size"),
        "error should mention size limit: {msg}"
    );
    assert!(
        msg.contains("1024"),
        "error should mention the limit value: {msg}"
    );
}

#[tokio::test]
async fn download_to_file_rejects_oversized_content_length_before_streaming() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let body = vec![7u8; 2048];

    Mock::given(method("GET"))
        .and(path("/tarball/header-oversized.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/header-oversized.tgz", server.uri());
    let result = client.download_tarball_to_file_with_limit(&url, 1024).await;

    assert!(
        result.is_err(),
        "oversized content-length should be rejected before streaming"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("Content-Length"),
        "error should mention Content-Length preflight enforcement: {msg}"
    );
    assert!(
        msg.contains("2048"),
        "error should mention the announced size: {msg}"
    );
    assert!(
        msg.contains("1024"),
        "error should mention the configured limit: {msg}"
    );
}

#[tokio::test]
async fn download_to_file_maps_404_to_not_found_with_body() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/tarball/missing.tgz"))
        .respond_with(ResponseTemplate::new(404).set_body_string("missing tarball"))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/missing.tgz", server.uri());
    let result = client.download_tarball_to_file(&url).await;

    assert!(matches!(result, Err(LpmError::NotFound(body)) if body == "missing tarball"));
}

#[tokio::test]
async fn download_to_file_retries_429_and_sends_bearer_auth_header() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("download-auth-token");

    Mock::given(method("GET"))
        .and(path("/tarball/rate-limited.tgz"))
        .and(header("authorization", "Bearer download-auth-token"))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "0"))
        .expect(4)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/rate-limited.tgz", server.uri());
    let result = client.download_tarball_to_file(&url).await;

    assert!(matches!(
        result,
        Err(LpmError::RateLimited {
            retry_after_secs: 0
        })
    ));
}

#[tokio::test]
async fn download_to_file_retries_503_then_succeeds() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct DownloadRetryResponder {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for DownloadRetryResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
            if call_index == 0 {
                ResponseTemplate::new(503).set_body_string("temporary tarball outage")
            } else {
                ResponseTemplate::new(200).set_body_bytes(b"retry-success-body".to_vec())
            }
        }
    }

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("GET"))
        .and(path("/tarball/retry-503.tgz"))
        .respond_with(DownloadRetryResponder {
            calls: Arc::clone(&calls),
        })
        .expect(2)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/retry-503.tgz", server.uri());
    let downloaded = client
        .download_tarball_to_file(&url)
        .await
        .expect("download should succeed after retrying 503");

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        downloaded.compressed_size,
        b"retry-success-body".len() as u64
    );
    let file_content = std::fs::read(downloaded.file.path()).unwrap();
    assert_eq!(file_content, b"retry-success-body");
}

#[tokio::test]
async fn download_to_file_retries_500_then_succeeds() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct Download500RetryResponder {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for Download500RetryResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
            if call_index == 0 {
                ResponseTemplate::new(500).set_body_string("temporary tarball 500")
            } else {
                ResponseTemplate::new(200).set_body_bytes(b"retry-500-success".to_vec())
            }
        }
    }

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("GET"))
        .and(path("/tarball/retry-500.tgz"))
        .respond_with(Download500RetryResponder {
            calls: Arc::clone(&calls),
        })
        .expect(2)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/retry-500.tgz", server.uri());
    let downloaded = client
        .download_tarball_to_file(&url)
        .await
        .expect("download should succeed after retrying a transient 500");

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        downloaded.compressed_size,
        b"retry-500-success".len() as u64
    );
    let file_content = std::fs::read(downloaded.file.path()).unwrap();
    assert_eq!(file_content, b"retry-500-success");
}

#[tokio::test]
async fn download_to_file_surfaces_chunk_read_failures() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind raw http test server");
    let addr = listener
        .local_addr()
        .expect("raw http test server should have a local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("raw http test server should accept a request");

        let mut request_buf = [0u8; 1024];
        let _ = stream.read(&mut request_buf).await;

        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\nZZZ\r\n",
                )
                .await
                .expect("raw http test server should write malformed chunked body");
        let _ = stream.shutdown().await;
    });

    let client = RegistryClient::new();
    let url = format!("http://127.0.0.1:{}/tarball/broken-chunks.tgz", addr.port());
    let result = client.download_tarball_to_file(&url).await;

    server
        .await
        .expect("raw http test server task should complete cleanly");

    assert!(
        result.is_err(),
        "broken chunked bodies should fail the download"
    );
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("failed to read tarball chunk"),
        "chunked transfer parse errors should surface as tarball chunk read failures: {message}"
    );
}

#[tokio::test]
async fn download_to_file_surfaces_truncated_content_length_interruptions() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind raw http interruption server");
    let addr = listener
        .local_addr()
        .expect("interruption server should have a local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("interruption server should accept a request");

        let mut request_buf = [0u8; 1024];
        let _ = stream.read(&mut request_buf).await;

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello")
            .await
            .expect("interruption server should write partial body");
        let _ = stream.shutdown().await;
    });

    let client = RegistryClient::new();
    let url = format!(
        "http://127.0.0.1:{}/tarball/truncated-body.tgz",
        addr.port()
    );
    let result = client.download_tarball_to_file(&url).await;

    server
        .await
        .expect("interruption server task should complete cleanly");

    assert!(
        result.is_err(),
        "truncated content-length bodies should fail the download"
    );
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("failed to read tarball chunk"),
        "mid-body interruptions should surface as tarball chunk read failures: {message}"
    );
}

#[test]
fn write_tarball_chunk_maps_io_failures() {
    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "disk full in test",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let result = write_tarball_chunk(&mut FailingWriter, b"chunk-data");

    assert!(matches!(
        result,
        Err(LpmError::Io(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied
                && error
                    .to_string()
                    .contains("failed to write tarball chunk to temp file: disk full in test")
    ));
}

#[test]
fn flush_tarball_file_maps_io_failures() {
    struct FlushFailingWriter;

    impl std::io::Write for FlushFailingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "flush failed in test",
            ))
        }
    }

    let result = flush_tarball_file(&mut FlushFailingWriter);

    assert!(matches!(
        result,
        Err(LpmError::Io(error))
            if error.kind() == std::io::ErrorKind::BrokenPipe
                && error
                    .to_string()
                    .contains("failed to flush tarball temp file: flush failed in test")
    ));
}

#[tokio::test]
async fn download_to_file_accepts_within_limit() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    let body = vec![0u8; 512];

    Mock::given(method("GET"))
        .and(path("/tarball/small.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/small.tgz", server.uri());
    let result = client.download_tarball_to_file_with_limit(&url, 1024).await;

    assert!(result.is_ok(), "tarball within limit should succeed");
    assert_eq!(result.unwrap().compressed_size, 512);
}

#[tokio::test]
async fn download_to_file_temp_file_cleaned_on_drop() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/tarball/cleanup.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"data".to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/cleanup.tgz", server.uri());
    let temp_path;
    {
        let downloaded = client.download_tarball_to_file(&url).await.unwrap();
        temp_path = downloaded.file.path().to_path_buf();
        assert!(temp_path.exists(), "temp file should exist during download");
    }
    // DownloadedTarball dropped — NamedTempFile auto-deletes
    assert!(
        !temp_path.exists(),
        "temp file should be cleaned up after drop"
    );
}

#[tokio::test]
async fn download_to_file_hash_mismatch_detected_by_caller() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("GET"))
        .and(path("/tarball/tampered.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"real-content".to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/tarball/tampered.tgz", server.uri());
    let downloaded = client.download_tarball_to_file(&url).await.unwrap();

    // The download itself always succeeds — hash mismatch is detected by
    // the caller comparing downloaded.sri against expected integrity.
    let wrong_integrity = "sha512-AAAAAAAAAA==";
    assert_ne!(
        downloaded.sri, wrong_integrity,
        "hash should not match tampered expectation"
    );
}

#[tokio::test]
async fn download_to_file_rejects_http_non_localhost_without_insecure() {
    let client = RegistryClient::new();
    let result = client
        .download_tarball_to_file("http://evil.com/pkg.tgz")
        .await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("HTTPS"), "should mention HTTPS requirement");
    assert!(
        msg.contains("--insecure"),
        "error should hint at --insecure flag: {msg}"
    );
}

#[tokio::test]
async fn download_tarball_streaming_rejects_http_without_insecure() {
    let client = RegistryClient::new();
    let result = client
        .download_tarball_streaming("http://evil.com/pkg.tgz")
        .await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("HTTPS"), "should mention HTTPS requirement");
    assert!(
        msg.contains("--insecure"),
        "error should hint at --insecure flag: {msg}"
    );
}

#[tokio::test]
async fn download_to_file_rejects_localhost_prefix_attack_domain() {
    let client = RegistryClient::new();
    let result = client
        .download_tarball_to_file("http://localhost.evil.com/pkg.tgz")
        .await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("HTTPS"), "should mention HTTPS requirement");
}

#[tokio::test]
async fn download_tarball_with_auth_attaches_bearer() {
    // A custom-registry tarball download must carry the `.npmrc`
    // Authorization header. The auth-aware download method attaches the
    // Bearer token to the request.
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .and(header("Authorization", "Bearer SECRET-TOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake-tarball-bytes"))
        .expect(1)
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    let auth = bearer_for(&server.uri(), "SECRET-TOKEN");
    let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());
    let downloaded = client
        .download_tarball_to_file_with_auth(&url, Some(&auth))
        .await
        .expect("auth-attached tarball download must succeed");
    assert_eq!(downloaded.compressed_size, 18); // "fake-tarball-bytes".len()
}

#[tokio::test]
async fn download_tarball_with_auth_strips_authorization_on_cross_origin_redirect() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let redirector = MockServer::start().await;
    let target = MockServer::start().await;
    let saw_authorization = Arc::new(AtomicBool::new(false));
    let body = b"redirected-tarball-body".to_vec();
    let target_url = format!("{}/target.tgz", target.uri());

    Mock::given(method("GET"))
        .and(path("/target.tgz"))
        .respond_with(AuthorizationRecorder {
            saw_authorization: Arc::clone(&saw_authorization),
            body: body.clone(),
        })
        .expect(1)
        .mount(&target)
        .await;

    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .and(header("Authorization", "Bearer SECRET-TOKEN"))
        .respond_with(ResponseTemplate::new(302).append_header("Location", target_url.as_str()))
        .expect(1)
        .mount(&redirector)
        .await;

    let (client, _tmp) = client_with_mock_server(&redirector.uri());
    let auth = bearer_for(&redirector.uri(), "SECRET-TOKEN");
    let url = format!("{}/foo/-/foo-1.0.0.tgz", redirector.uri());

    let downloaded = client
        .download_tarball_to_file_with_auth(&url, Some(&auth))
        .await
        .expect("redirected tarball download must succeed");

    assert_eq!(downloaded.compressed_size, body.len() as u64);
    assert!(
        !saw_authorization.load(Ordering::SeqCst),
        "Authorization must not follow a cross-origin tarball redirect"
    );
}

#[tokio::test]
async fn path_scoped_auth_is_stripped_from_a_same_origin_redirect_outside_its_prefix() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let saw_authorization = Arc::new(AtomicBool::new(false));
    let body = b"redirected-tarball-body".to_vec();

    Mock::given(method("GET"))
        .and(path("/outside/target.tgz"))
        .respond_with(AuthorizationRecorder {
            saw_authorization: Arc::clone(&saw_authorization),
            body: body.clone(),
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/foo.tgz"))
        .and(header("Authorization", "Bearer PATH-TOKEN"))
        .respond_with(ResponseTemplate::new(302).append_header("Location", "/outside/target.tgz"))
        .expect(1)
        .mount(&server)
        .await;

    let origin = crate::npmrc::OriginKey::from_request_url(&format!("{}/_", server.uri()))
        .expect("mock server origin");
    let auth = crate::npmrc::RegistryAuth::Bearer {
        scope: crate::npmrc::AuthScope {
            origin,
            path_prefix: std::sync::Arc::from("/api/"),
        },
        token: secrecy::SecretString::from("PATH-TOKEN".to_string()),
    };
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let downloaded = client
        .download_tarball_to_file_with_auth(&format!("{}/api/foo.tgz", server.uri()), Some(&auth))
        .await
        .expect("same-origin redirect should complete without leaking scoped auth");

    assert_eq!(downloaded.compressed_size, body.len() as u64);
    assert!(
        !saw_authorization.load(Ordering::SeqCst),
        "path-scoped Authorization escaped its configured prefix"
    );
}

#[tokio::test]
async fn download_tarball_with_auth_anon_when_none() {
    // No npmrc auth for this URL → request goes anonymous (no
    // Authorization header). Importantly, the LPM session bearer
    // is NOT leaked — that's the bug the new method exists to
    // prevent.
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Reject any request that DOES carry Authorization.
    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(401))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x"))
        .mount(&server)
        .await;

    // Even if the client has a session bearer, the auth-aware path
    // must NOT attach it.
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("LPM-SESSION-BEARER");
    let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());
    client
        .download_tarball_to_file_with_auth(&url, None)
        .await
        .expect("anonymous download must succeed");
}

#[tokio::test]
async fn routed_npm_tarball_download_does_not_attach_lpm_bearer() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    let server = MockServer::start().await;
    let saw_authorization = Arc::new(AtomicBool::new(false));

    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .respond_with(AuthorizationRecorder {
            saw_authorization: Arc::clone(&saw_authorization),
            body: b"fake-routed-tarball".to_vec(),
        })
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url("https://lpm.dev")
        .with_npm_registry_url(server.uri())
        .with_token("LPM-SESSION-BEARER");
    client.cache_dir = Some(tmp.path().to_path_buf());
    let route_table = crate::route::RouteTable::from_mode_only(crate::route::RouteMode::Direct);
    let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());

    let downloaded = client
        .download_tarball_routed(&route_table, "foo", &url)
        .await
        .expect("routed npm tarball download should succeed anonymously");

    assert_eq!(downloaded.compressed_size, 19);
    assert!(
        !saw_authorization.load(Ordering::SeqCst),
        "routed npm tarballs must not receive the LPM session bearer"
    );
}

#[tokio::test]
async fn routed_npm_file_spool_refuses_unconfigured_tarball_origin_before_request() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let configured_registry = MockServer::start().await;
    let unconfigured_origin = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"poisoned-tarball"))
        .mount(&unconfigured_origin)
        .await;

    let client = RegistryClient::new()
        .with_base_url("https://lpm.dev")
        .with_npm_registry_url(configured_registry.uri());
    let route_table = crate::route::RouteTable::from_mode_only(crate::route::RouteMode::Direct);
    let poisoned_url = format!("{}/foo/-/foo-1.0.0.tgz", unconfigured_origin.uri());

    let error = client
        .download_tarball_routed(&route_table, "foo", &poisoned_url)
        .await
        .expect_err("an unconfigured tarball origin must be rejected");

    assert!(
        error
            .to_string()
            .contains("origin is not in the configured set")
    );
    assert!(
        unconfigured_origin
            .received_requests()
            .await
            .expect("received requests")
            .is_empty(),
        "origin validation must run before starting the request"
    );
}

#[tokio::test]
async fn routed_npm_tarball_streaming_does_not_attach_lpm_bearer() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    let server = MockServer::start().await;
    let saw_authorization = Arc::new(AtomicBool::new(false));

    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .respond_with(AuthorizationRecorder {
            saw_authorization: Arc::clone(&saw_authorization),
            body: b"fake-streamed-tarball".to_vec(),
        })
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url("https://lpm.dev")
        .with_npm_registry_url(server.uri())
        .with_token("LPM-SESSION-BEARER");
    client.cache_dir = Some(tmp.path().to_path_buf());
    let route_table = crate::route::RouteTable::from_mode_only(crate::route::RouteMode::Direct);
    let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());

    let response = client
        .download_tarball_streaming_routed(&route_table, "foo", &url)
        .await
        .expect("routed npm streaming tarball download should succeed anonymously");
    let body = response.bytes().await.expect("stream body should read");

    assert_eq!(body.as_ref(), b"fake-streamed-tarball");
    assert!(
        !saw_authorization.load(Ordering::SeqCst),
        "routed npm streaming tarballs must not receive the LPM session bearer"
    );
}

#[tokio::test]
async fn routed_lpm_tarball_download_keeps_lpm_bearer() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/lpm-tarball.tgz"))
        .and(header("authorization", "Bearer LPM-SESSION-BEARER"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake-lpm-tarball"))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_npm_registry_url("https://registry.npmjs.org")
        .with_token("LPM-SESSION-BEARER");
    client.cache_dir = Some(tmp.path().to_path_buf());
    let route_table = crate::route::RouteTable::from_mode_only(crate::route::RouteMode::Direct);
    let url = format!("{}/lpm-tarball.tgz", server.uri());

    let downloaded = client
        .download_tarball_routed(&route_table, "@lpm.dev/acme.pkg", &url)
        .await
        .expect("routed LPM tarball download should carry the LPM bearer");

    assert_eq!(downloaded.compressed_size, 16);
}

#[tokio::test]
async fn routed_lpm_tarball_download_refuses_the_configured_npm_origin() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let lpm_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lpm-tarball.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"wrong-origin"))
        .mount(&npm_server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(lpm_server.uri())
        .with_npm_registry_url(npm_server.uri())
        .with_token("LPM-SESSION-BEARER");
    let route_table = crate::route::RouteTable::from_mode_only(crate::route::RouteMode::Direct);
    let url = format!("{}/lpm-tarball.tgz", npm_server.uri());

    let error = client
        .download_tarball_routed(&route_table, "@lpm.dev/acme.pkg", &url)
        .await
        .expect_err("LPM tarballs must stay on the configured LPM origin");

    assert!(error.to_string().contains("configured LPM registry"));
    assert!(
        npm_server
            .received_requests()
            .await
            .expect("received requests")
            .is_empty(),
        "the origin gate must run before attaching the LPM bearer"
    );
}

#[tokio::test]
async fn managed_lpm_file_spool_download_sends_accounting_marker() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/lpm-tarball.tgz"))
        .and(header(
            MANAGED_INSTALL_ACCOUNTING_HEADER,
            MANAGED_INSTALL_ACCOUNTING_VERSION,
        ))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"managed-file-spool"))
        .expect(1)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("LPM-SESSION-BEARER");
    let route_table = crate::route::RouteTable::from_mode_only(crate::route::RouteMode::Direct);
    let url = format!("{}/lpm-tarball.tgz", server.uri());

    let downloaded = client
        .download_tarball_routed_managed(
            &route_table,
            "@lpm.dev/acme.pkg",
            &url,
            ManagedInstallAccounting,
        )
        .await
        .expect("managed file-spool download should succeed");

    assert_eq!(downloaded.compressed_size, 18);
}

#[tokio::test]
async fn managed_lpm_streaming_download_sends_accounting_marker() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/lpm-tarball.tgz"))
        .and(header(
            MANAGED_INSTALL_ACCOUNTING_HEADER,
            MANAGED_INSTALL_ACCOUNTING_VERSION,
        ))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"managed-stream"))
        .expect(1)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("LPM-SESSION-BEARER");
    let route_table = crate::route::RouteTable::from_mode_only(crate::route::RouteMode::Direct);
    let url = format!("{}/lpm-tarball.tgz", server.uri());

    let response = client
        .download_tarball_streaming_routed_managed(
            &route_table,
            "@lpm.dev/acme.pkg",
            &url,
            ManagedInstallAccounting,
        )
        .await
        .expect("managed streaming download should succeed");

    assert_eq!(
        response.bytes().await.expect("read managed stream"),
        b"managed-stream".as_slice()
    );
}

#[tokio::test]
async fn managed_npm_download_sends_neither_accounting_marker_nor_lpm_bearer() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"managed-npm"))
        .expect(1)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url("https://lpm.dev")
        .with_npm_registry_url(server.uri())
        .with_token("LPM-SESSION-BEARER");
    let route_table = crate::route::RouteTable::from_mode_only(crate::route::RouteMode::Direct);
    let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());

    client
        .download_tarball_routed_managed(&route_table, "foo", &url, ManagedInstallAccounting)
        .await
        .expect("managed install context must not alter npm request isolation");

    let requests = server.received_requests().await.expect("received requests");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.get("authorization").is_none());
    assert!(
        requests[0]
            .headers
            .get(MANAGED_INSTALL_ACCOUNTING_HEADER)
            .is_none()
    );
}

#[tokio::test]
async fn managed_custom_registry_download_sends_custom_auth_but_no_lpm_marker_or_bearer() {
    use crate::npmrc::NpmrcConfig;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foo/-/foo-1.0.0.tgz"))
        .and(header("authorization", "Bearer CUSTOM-TOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"managed-custom"))
        .expect(1)
        .mount(&server)
        .await;

    let registry_url = server.uri();
    let registry_authority = registry_url
        .strip_prefix("http://")
        .expect("wiremock server uses http");
    let npmrc = NpmrcConfig::parse(
        &format!(
            "registry={}/\n//{registry_authority}/:_authToken=CUSTOM-TOKEN\n",
            registry_url
        ),
        "test",
        &|_| None,
    );
    let route_table = crate::route::RouteTable::new(crate::route::RouteMode::Direct, npmrc)
        .expect("mock npmrc should be valid");
    let client = RegistryClient::new()
        .with_base_url("https://lpm.dev")
        .with_token("LPM-SESSION-BEARER");
    let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());

    client
        .download_tarball_routed_managed(&route_table, "foo", &url, ManagedInstallAccounting)
        .await
        .expect("managed install context should preserve custom Registry auth");

    let requests = server.received_requests().await.expect("received requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer CUSTOM-TOKEN")
    );
    assert!(
        requests[0]
            .headers
            .get(MANAGED_INSTALL_ACCOUNTING_HEADER)
            .is_none()
    );
}

#[tokio::test]
async fn download_tarball_with_auth_origin_mismatch_returns_error() {
    // S2 defense parity with `get_npm_metadata_from`: auth scoped
    // to origin A, request to origin B → hard-fail before the
    // network. The auth-mismatch must surface as Registry error,
    // not silently drop or leak.
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let auth = bearer_for("https://attacker.example", "STOLEN");
    let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());

    let result = client
        .download_tarball_to_file_with_auth(&url, Some(&auth))
        .await;
    match result {
        Err(LpmError::Registry(msg)) => {
            assert!(
                msg.contains("scope mismatch"),
                "error must mention scope mismatch: {msg}"
            );
        }
        other => panic!("expected origin-mismatch Registry error, got {other:?}"),
    }
}
