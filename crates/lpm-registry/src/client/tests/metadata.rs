use super::*;

#[tokio::test]
#[ignore = "requires network + auth — run with --ignored"]
async fn fetch_package_metadata() {
    let token = std::env::var("LPM_TOKEN").expect("LPM_TOKEN env var required");
    let client = RegistryClient::new().with_token(token);
    let name = PackageName::parse("@lpm.dev/tolgaergin.blocks").unwrap();
    let metadata = client.get_package_metadata(&name).await.unwrap();

    assert_eq!(metadata.name, "@lpm.dev/tolgaergin.blocks");
    assert!(metadata.latest_version_tag().is_some());
    assert!(!metadata.versions.is_empty());
}

#[tokio::test]
#[ignore = "requires network — run with --ignored"]
async fn nonexistent_package_returns_error() {
    let client = RegistryClient::new();
    let name = PackageName::parse("@lpm.dev/nonexistent-user.nonexistent-package-12345").unwrap();
    let result = client.get_package_metadata(&name).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn worker_metadata_http3_marks_lpm_dev_worker_requests_by_default_when_feature_is_enabled() {
    let client = RegistryClient::new().with_base_url("https://lpm.dev");
    let url = "https://lpm.dev/api/registry/batch-metadata";

    let request = client
        .build_worker_metadata_get(url)
        .await
        .expect("request builder should be created")
        .build()
        .expect("request should build");

    #[cfg(feature = "experimental-http3")]
    assert_eq!(request.version(), reqwest::Version::HTTP_3);
    #[cfg(not(feature = "experimental-http3"))]
    assert_eq!(request.version(), reqwest::Version::default());
}

#[tokio::test]
async fn worker_metadata_http3_can_be_disabled_for_lpm_dev_worker_requests() {
    let client = RegistryClient::new()
        .with_base_url("https://lpm.dev")
        .with_worker_metadata_http3_enabled(false);
    let url = "https://lpm.dev/api/registry/batch-metadata";

    let request = client
        .build_worker_metadata_get(url)
        .await
        .expect("request builder should be created")
        .build()
        .expect("request should build");

    assert_eq!(request.version(), reqwest::Version::default());
}

#[tokio::test]
async fn worker_metadata_http3_does_not_mark_direct_npm_origin() {
    let client = RegistryClient::new()
        .with_base_url("https://lpm.dev")
        .with_worker_metadata_http3_enabled(true);
    let url = "https://registry.npmjs.org/react";

    let request = client
        .build_worker_metadata_get(url)
        .await
        .expect("request builder should be created")
        .build()
        .expect("request should build");

    assert_eq!(request.version(), reqwest::Version::default());
}

#[tokio::test]
async fn worker_metadata_http3_does_not_mark_custom_https_worker_origin_by_default() {
    let client = RegistryClient::new()
        .with_base_url("https://registry.example.test")
        .with_worker_metadata_http3_enabled(true);
    let url = "https://registry.example.test/api/registry/batch-metadata";

    let request = client
        .build_worker_metadata_get(url)
        .await
        .expect("request builder should be created")
        .build()
        .expect("request should build");

    assert_eq!(request.version(), reqwest::Version::default());
}

#[tokio::test]
async fn worker_metadata_http3_does_not_mark_http_worker_origin() {
    let client = RegistryClient::new()
        .with_base_url("http://localhost:4873")
        .with_worker_metadata_http3_enabled(true);
    let url = "http://localhost:4873/api/registry/react";

    let request = client
        .build_worker_metadata_get(url)
        .await
        .expect("request builder should be created")
        .build()
        .expect("request should build");

    assert_eq!(request.version(), reqwest::Version::default());
}

#[test]
fn worker_metadata_http3_policy_prefers_h3_when_lpm_http_is_unset() {
    let enabled = RegistryClient::worker_metadata_http3_enabled_for_lpm_http(None);

    #[cfg(feature = "experimental-http3")]
    assert!(enabled);
    #[cfg(not(feature = "experimental-http3"))]
    assert!(!enabled);
}

#[test]
fn worker_metadata_http3_policy_honors_explicit_worker_h2_opt_out() {
    let enabled = RegistryClient::worker_metadata_http3_enabled_for_lpm_http(Some("h2-worker"));

    assert!(!enabled);
}

#[test]
fn worker_metadata_http3_policy_honors_explicit_worker_h3_mode() {
    let enabled = RegistryClient::worker_metadata_http3_enabled_for_lpm_http(Some("h3-worker"));

    #[cfg(feature = "experimental-http3")]
    assert!(enabled);
    #[cfg(not(feature = "experimental-http3"))]
    assert!(!enabled);
}

#[test]
fn worker_metadata_http3_policy_honors_default_transport_opt_out() {
    let enabled = RegistryClient::worker_metadata_http3_enabled_for_lpm_http(Some("default"));

    assert!(!enabled);
}

#[test]
fn worker_metadata_http3_policy_honors_h1_pool_transport_opt_out() {
    let enabled = RegistryClient::worker_metadata_http3_enabled_for_lpm_http(Some("h1-pool"));

    assert!(!enabled);
}

#[test]
fn worker_metadata_http3_fallback_request_resets_version_for_default_transport() {
    let request = reqwest::Client::new()
        .post("https://lpm.dev/api/registry/batch-metadata")
        .version(reqwest::Version::HTTP_3)
        .json(&serde_json::json!({ "packages": ["react"], "deep": true }))
        .build()
        .expect("request should build");

    let fallback = RegistryClient::worker_metadata_http3_fallback_request(&request)
        .expect("cloneable metadata request should build fallback")
        .expect("HTTP/3 request should have fallback");

    assert_eq!(fallback.version(), reqwest::Version::default());
    assert_eq!(fallback.url(), request.url());
}

#[test]
fn worker_metadata_http3_fallback_only_handles_network_errors() {
    assert!(RegistryClient::worker_metadata_http3_should_fallback(
        &LpmError::Network("quic handshake failed".into())
    ));
    assert!(!RegistryClient::worker_metadata_http3_should_fallback(
        &LpmError::Http {
            status: 403,
            message: "blocked".into(),
        }
    ));
    assert!(!RegistryClient::worker_metadata_http3_should_fallback(
        &LpmError::AuthRequired
    ));
}

#[tokio::test]
async fn npm_proxy_miss_falls_back_to_direct_npm_registry() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("failed to create temp dir");

    let npm_name = "express-proxy-miss";
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri())
        .with_synchronous_cache_writes(true);
    client.cache_dir = Some(tmp.path().to_path_buf());

    Mock::given(method("GET"))
        .and(path("/api/registry/express-proxy-miss"))
        .respond_with(ResponseTemplate::new(404).set_body_string("proxy miss"))
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/express-proxy-miss"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json(npm_name)))
        .expect(1)
        .mount(&npm_server)
        .await;

    let result = client.get_npm_package_metadata(npm_name).await;
    assert!(
        result.is_ok(),
        "proxy miss should fall back to direct npm registry"
    );
    assert_eq!(result.unwrap().name, npm_name);

    let cached = client
        .read_cache_content(&format!("npm:{npm_name}"))
        .expect("fallback result should be cached");
    let metadata = RegistryClient::deserialize_cached_metadata(&cached.data)
        .expect("cached fallback metadata should deserialize");
    assert_eq!(metadata.name, npm_name);
}

#[tokio::test]
async fn npm_proxy_metadata_sends_bearer_when_token_is_available() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    let proxy_server = MockServer::start().await;
    let npm_name = "authenticated-proxy-metadata";
    let saw_authorization = Arc::new(AtomicBool::new(false));

    Mock::given(method("GET"))
        .and(path("/api/registry/authenticated-proxy-metadata"))
        .respond_with(AuthorizationRecorder {
            saw_authorization: Arc::clone(&saw_authorization),
            body: test_metadata_json(npm_name).into_bytes(),
        })
        .expect(1)
        .mount(&proxy_server)
        .await;

    let (client, _tmp) = client_with_mock_server(&proxy_server.uri());
    let client = client.with_token("stored-lpm-token");

    let metadata = client
        .get_npm_package_metadata(npm_name)
        .await
        .expect("npm proxy metadata should succeed with LPM bearer auth");

    assert_eq!(metadata.name, npm_name);
    assert!(
        saw_authorization.load(Ordering::SeqCst),
        "npm metadata proxy requests must attach LPM bearer auth when available"
    );
}

#[tokio::test]
async fn npm_proxy_access_denial_falls_back_to_direct_npm_registry() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("failed to create temp dir");

    let npm_name = "express-proxy-access-denied";
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri())
        .with_synchronous_cache_writes(true);
    client.cache_dir = Some(tmp.path().to_path_buf());

    Mock::given(method("GET"))
        .and(path("/api/registry/express-proxy-access-denied"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "upstream_proxy_entitlement_required",
            "message": "upstream proxy access required"
        })))
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/express-proxy-access-denied"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json(npm_name)))
        .expect(1)
        .mount(&npm_server)
        .await;

    let result = client.get_npm_package_metadata(npm_name).await;
    assert!(
        result.is_ok(),
        "proxy access denial should fall back to direct npm registry"
    );
    assert_eq!(result.unwrap().name, npm_name);
}

#[tokio::test]
async fn npm_proxy_firewall_block_does_not_fallback_to_direct_npm_registry() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("failed to create temp dir");

    let npm_name = "blocked-by-firewall";
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri());
    client.cache_dir = Some(tmp.path().to_path_buf());

    Mock::given(method("GET"))
        .and(path("/api/registry/blocked-by-firewall"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "blocked_by_lpm_firewall",
            "package": npm_name,
            "verdict": "malicious",
            "reason": "test policy block",
            "decisionId": "decision-test"
        })))
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/blocked-by-firewall"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json(npm_name)))
        .expect(0)
        .mount(&npm_server)
        .await;

    let result = client.get_npm_package_metadata(npm_name).await;
    assert!(matches!(
        result,
        Err(LpmError::NpmFirewallBlocked {
            package,
            verdict,
            reason,
            ..
        }) if package == npm_name && verdict == "malicious" && reason == "test policy block"
    ));
}

#[tokio::test]
async fn npm_proxy_wrong_package_body_returns_registry_error_without_fallback() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("failed to create temp dir");

    let npm_name = "express-proxy-wrong-body";
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri());
    client.cache_dir = Some(tmp.path().to_path_buf());

    Mock::given(method("GET"))
        .and(path("/api/registry/express-proxy-wrong-body"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json("some-other-package"))
                .append_header("ETag", "\"proxy-v1\""),
        )
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/express-proxy-wrong-body"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json(npm_name)))
        .expect(0)
        .mount(&npm_server)
        .await;

    let result = client.get_npm_package_metadata(npm_name).await;
    assert!(matches!(
        result,
        Err(LpmError::Registry(message))
            if message.contains("unexpected package")
                && message.contains("some-other-package")
                && message.contains(npm_name)
    ));

    assert!(
        client
            .read_cache_content(&format!("npm:{npm_name}"))
            .is_none(),
        "wrong-package proxy bodies should not be cached"
    );
}

#[tokio::test]
async fn batch_metadata_json_keeps_valid_entries_when_some_are_malformed() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let valid_name = "express";
    let valid_metadata: serde_json::Value =
        serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        valid_name: valid_metadata,
                        "broken-package": {
                            "description": "missing required name"
                        }
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .batch_metadata(&[valid_name.to_string(), "broken-package".to_string()])
        .await
        .expect("partial JSON batch response should still succeed");

    assert_eq!(result.len(), 1);
    assert_eq!(result[valid_name].name, valid_name);
    assert!(!result.contains_key("broken-package"));
}

#[tokio::test]
async fn batch_metadata_sends_bearer_auth_header_when_token_is_present() {
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let client = client.with_token("batch-auth-token");
    let valid_name = "express";
    let valid_metadata: serde_json::Value =
        serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .and(header("authorization", "Bearer batch-auth-token"))
        .and(body_string_contains("\"packages\":[\"express\"]"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        valid_name: valid_metadata,
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .batch_metadata(&[valid_name.to_string()])
        .await
        .expect("batch metadata should succeed with bearer auth header");

    assert_eq!(result.len(), 1);
    assert_eq!(result[valid_name].name, valid_name);
}

#[tokio::test]
async fn batch_metadata_omits_auth_header_when_token_is_absent() {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct RejectAuthHeaderResponder {
        response_body: serde_json::Value,
    }

    impl Respond for RejectAuthHeaderResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            if request.headers.contains_key("authorization") {
                ResponseTemplate::new(400).set_body_string("unexpected authorization header")
            } else {
                ResponseTemplate::new(200)
                    .append_header("content-type", "application/json")
                    .set_body_json(self.response_body.clone())
            }
        }
    }

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let valid_name = "express";
    let valid_metadata: serde_json::Value =
        serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .and(body_string_contains("\"packages\":[\"express\"]"))
        .respond_with(RejectAuthHeaderResponder {
            response_body: serde_json::json!({
                "packages": {
                    valid_name: valid_metadata,
                }
            }),
        })
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .batch_metadata(&[valid_name.to_string()])
        .await
        .expect("anonymous batch metadata should not send an authorization header");

    assert_eq!(result.len(), 1);
    assert_eq!(result[valid_name].name, valid_name);
}

#[tokio::test]
async fn batch_metadata_json_missing_packages_field_returns_parse_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "status": "ok"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client.batch_metadata(&["express".to_string()]).await;

    assert!(matches!(
        result,
        Err(LpmError::Registry(message)) if message == "batch response missing packages"
    ));
}

#[tokio::test]
async fn batch_metadata_json_skips_mismatched_package_identity_and_does_not_cache_it() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let requested_name = "express";
    let wrong_name = "lodash";
    let wrong_metadata: serde_json::Value =
        serde_json::from_str(&test_metadata_json(wrong_name)).expect("valid metadata json");

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        requested_name: wrong_metadata,
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .batch_metadata(&[requested_name.to_string()])
        .await
        .expect("mismatched JSON batch entries should be ignored, not fail the whole batch");

    assert!(
        result.is_empty(),
        "mismatched metadata should not be returned"
    );
    assert!(
        client
            .read_metadata_cache(&format!("npm:{requested_name}"))
            .is_none(),
        "mismatched metadata should not poison the requested package cache"
    );
}

#[tokio::test]
async fn batch_metadata_ndjson_keeps_valid_entries_when_some_lines_are_malformed() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let valid_name = "lodash";
    let valid_metadata: serde_json::Value =
        serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");
    let ndjson_body = format!(
        "{}\n{}\n{}\n",
        serde_json::json!({
            "name": valid_name,
            "metadata": valid_metadata,
        }),
        serde_json::json!({
            "name": "broken-line",
            "metadata": {
                "description": "missing required name"
            }
        }),
        "{not-json"
    );

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .batch_metadata(&[valid_name.to_string(), "broken-line".to_string()])
        .await
        .expect("partial NDJSON batch response should still succeed");

    assert_eq!(result.len(), 1);
    assert_eq!(result[valid_name].name, valid_name);
    assert!(!result.contains_key("broken-line"));
}

#[tokio::test]
async fn batch_metadata_ndjson_parses_final_line_without_trailing_newline() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let valid_name = "chalk";
    let valid_metadata: serde_json::Value =
        serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");
    let ndjson_body = serde_json::json!({
        "name": valid_name,
        "metadata": valid_metadata,
    })
    .to_string();

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .batch_metadata(&[valid_name.to_string()])
        .await
        .expect("NDJSON batch without trailing newline should still parse final line");

    assert_eq!(result.len(), 1);
    assert_eq!(result[valid_name].name, valid_name);
}

#[tokio::test]
async fn batch_metadata_ndjson_parses_line_split_across_http_chunks() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 4096];
        let _ = stream.read(&mut request).await.unwrap();

        let metadata_json = test_metadata_json("kleur");
        let line = format!("{{\"name\":\"kleur\",\"metadata\":{metadata_json}}}\n");
        let split_at = line.find("\"metadata\"").unwrap();
        let chunks = [
            &line[..split_at],
            &line[split_at..split_at + 17],
            &line[split_at + 17..],
        ];

        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

        for chunk in chunks {
            let header = format!("{:X}\r\n", chunk.len());
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(chunk.as_bytes()).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
            stream.flush().await.unwrap();
            sleep(Duration::from_millis(10)).await;
        }

        stream.write_all(b"0\r\n\r\n").await.unwrap();
        stream.flush().await.unwrap();
    });

    let (client, _tmp) = client_with_mock_server(&format!("http://{address}"));
    let result = client
        .batch_metadata(&["kleur".to_string()])
        .await
        .expect("NDJSON parser should handle lines split across chunk boundaries");

    assert_eq!(result.len(), 1);
    assert_eq!(result["kleur"].name, "kleur");
    assert!(
        client.read_metadata_cache("npm:kleur").is_some(),
        "chunk-split NDJSON entries should still warm the metadata cache"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn batch_metadata_ndjson_parses_utf8_split_across_http_chunks() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 4096];
        let _ = stream.read(&mut request).await.unwrap();

        let mut metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json("kleur")).unwrap();
        metadata["description"] = serde_json::json!("snowman ☃ package");
        let line = serde_json::json!({
            "name": "kleur",
            "metadata": metadata,
        })
        .to_string()
            + "\n";
        let bytes = line.as_bytes();
        let split_start = bytes
            .windows("☃".len())
            .position(|window| window == "☃".as_bytes())
            .unwrap();
        let chunks = [
            &bytes[..split_start + 1],
            &bytes[split_start + 1..split_start + 2],
            &bytes[split_start + 2..],
        ];

        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

        for chunk in chunks {
            let header = format!("{:X}\r\n", chunk.len());
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(chunk).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
            stream.flush().await.unwrap();
            sleep(Duration::from_millis(10)).await;
        }

        stream.write_all(b"0\r\n\r\n").await.unwrap();
        stream.flush().await.unwrap();
    });

    let (client, _tmp) = client_with_mock_server(&format!("http://{address}"));
    let result = client
        .batch_metadata(&["kleur".to_string()])
        .await
        .expect("NDJSON parser should handle UTF-8 sequences split across chunk boundaries");

    assert_eq!(result.len(), 1);
    assert_eq!(result["kleur"].name, "kleur");
    assert_eq!(
        result["kleur"].description.as_deref(),
        Some("snowman ☃ package")
    );

    server.await.unwrap();
}

#[tokio::test]
async fn batch_metadata_ndjson_ignores_truncated_final_line_after_valid_entries() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let valid_name = "kleur";
    let valid_metadata: serde_json::Value =
        serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");
    let ndjson_body = format!(
        "{}\n{{\"name\":\"broken-final\",\"metadata\":",
        serde_json::json!({
            "name": valid_name,
            "metadata": valid_metadata,
        })
    );

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .batch_metadata(&[valid_name.to_string(), "broken-final".to_string()])
        .await
        .expect("truncated trailing NDJSON should preserve already parsed metadata");

    assert_eq!(result.len(), 1);
    assert_eq!(result[valid_name].name, valid_name);
    assert!(!result.contains_key("broken-final"));
}

#[tokio::test]
async fn batch_metadata_ndjson_skips_mismatched_package_identity_and_does_not_cache_it() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());
    let requested_name = "express";
    let wrong_name = "lodash";
    let wrong_metadata: serde_json::Value =
        serde_json::from_str(&test_metadata_json(wrong_name)).expect("valid metadata json");
    let ndjson_body = serde_json::json!({
        "name": requested_name,
        "metadata": wrong_metadata,
    })
    .to_string();

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .batch_metadata(&[requested_name.to_string()])
        .await
        .expect("mismatched NDJSON entries should be ignored, not fail the whole batch");

    assert!(
        result.is_empty(),
        "mismatched metadata should not be returned"
    );
    assert!(
        client
            .read_metadata_cache(&format!("npm:{requested_name}"))
            .is_none(),
        "mismatched metadata should not poison the requested package cache"
    );
}

#[tokio::test]
async fn batch_metadata_json_truncated_body_returns_parse_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_raw("{\"packages\":{\"express\":", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = client.batch_metadata(&["express".to_string()]).await;

    assert!(matches!(
        result,
        Err(LpmError::Registry(message)) if message.contains("batch metadata") && message.contains("failed to parse JSON")
    ));
}

#[tokio::test]
async fn batch_metadata_deep_tolerates_slow_streaming_body_under_read_timeout() {
    // Client scoped tight: connect_timeout = read_timeout = 500 ms.
    // Any individual chunk gap > 500 ms would trip read_timeout and
    // fail the test — the stream server intentionally stays under
    // that bound by sending every 300 ms.
    let tmp = tempfile::tempdir().expect("temp dir");
    let short = std::time::Duration::from_millis(500);
    let http_default = RegistryClient::build_http_client(short, short);

    // Stream 4 NDJSON lines at 200 ms apart → 800 ms wall-clock
    // total. That's ~1.6× the 500 ms window a wall-clock
    // `.timeout()` would have enforced. With `read_timeout`, the
    // per-chunk window resets on each chunk so the full body arrives
    // intact. Kept short so the test itself stays under 1 s.
    let packages: Vec<String> = (0..4).map(|i| format!("slow-pkg-{i}")).collect();
    let (base_url, server_handle) =
        slow_streaming_ndjson_server(packages.clone(), std::time::Duration::from_millis(200)).await;

    let mut client = RegistryClient::new().with_base_url(&base_url);
    // `http` is `Arc<HttpClients>`. Wrap the short-timeout default
    // client in a fresh HttpClients shell.
    client.http = HttpClients::from_default_client(http_default);
    client.cache_dir = Some(tmp.path().to_path_buf());

    let started = std::time::Instant::now();
    let result = client.batch_metadata_deep(&packages).await;
    let elapsed = started.elapsed();

    server_handle.await.expect("server task completed");

    assert!(
        result.is_ok(),
        "slow-but-progressing stream must succeed with read_timeout; got {:?} after {elapsed:?}",
        result.err(),
    );
    let map = result.unwrap();
    assert_eq!(
        map.len(),
        4,
        "all 4 NDJSON entries should parse; got {}",
        map.len()
    );
    assert!(
        elapsed >= std::time::Duration::from_millis(700),
        "stream should take ~800 ms total (4 chunks × 200 ms); \
             got {elapsed:?}. If this is fast, the test isn't actually \
             exercising the long-stream case the fix targets."
    );
}

#[tokio::test]
async fn batch_metadata_deep_fails_under_old_wallclock_timeout() {
    // Regression guard written in reverse: same slow streaming server the
    // happy-path test uses, but the client is built with `.timeout()` — a
    // wall-clock cap. The stream takes ~3 s total, the wall-clock is 500 ms,
    // so the request dies mid-body with a reqwest body decode error sourced
    // from `operation timed out`. This test deliberately invokes the reqwest
    // builder directly with the old API shape so the wire-level failure mode
    // stays visible: if someone re-introduces `.timeout(N)` on the prod
    // builder, this test is the spec that says "that path fails for
    // legitimately slow streams."
    let tmp = tempfile::tempdir().expect("temp dir");
    let old_style_http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .expect("build client");

    // 4 chunks × 200 ms = 800 ms total stream, exceeding the
    // 500 ms wall-clock timeout by ~300 ms.
    let packages: Vec<String> = (0..4).map(|i| format!("wallclock-pkg-{i}")).collect();
    let (base_url, server_handle) =
        slow_streaming_ndjson_server(packages.clone(), std::time::Duration::from_millis(200)).await;

    let mut client = RegistryClient::new().with_base_url(&base_url);
    // Wrap the wall-clock-timeout client in HttpClients.
    client.http = HttpClients::from_default_client(old_style_http);
    client.cache_dir = Some(tmp.path().to_path_buf());

    let result = client.batch_metadata_deep(&packages).await;

    // Abort the server task — the client died mid-stream so the
    // server's `write_half.flush()` will return `BrokenPipe` on
    // some chunk. Abort prevents the spawned task from panicking
    // into the test harness with a misleading "write chunk" error
    // that looks like a test assertion failure.
    server_handle.abort();

    match result {
        Ok(map) => panic!(
            "wall-clock `.timeout()` should abort mid-body; \
                 instead got a successful map of {} entries. If this test \
                 now passes, either the reqwest API changed semantics \
                 (unlikely — `.timeout()` is still wall-clock in 0.12) \
                 or the streaming server finished faster than expected; \
                 re-check the timings.",
            map.len(),
        ),
        Err(LpmError::Registry(msg)) => {
            assert!(
                msg.contains("timed out") || msg.contains("timeout"),
                "error should mention the timeout, but was: {msg}"
            );
        }
        Err(other) => panic!("expected Registry timeout error, got {other:?}"),
    }
}

#[tokio::test]
async fn get_npm_metadata_direct_skips_proxy_tier_entirely() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Two mock servers: proxy (= base_url, LPM Worker) and direct
    // npm registry. direct-tier fetch must hit ONLY the npm server.
    // If the implementation ever silently falls back through the
    // proxy tier, the proxy server's `expect(0)` will fail.
    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;

    let pkg = "lodash";
    let body = test_metadata_json(pkg);

    // Proxy mock configured to fail the test if hit. `expect(0)` is
    // verified when the server is dropped.
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{pkg}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(&body))
        .expect(0)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/{pkg}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(&body))
        .expect(1)
        .mount(&npm_server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri());
    client.cache_dir = Some(tmp.path().to_path_buf());

    let got = client
        .get_npm_metadata_direct(pkg)
        .await
        .expect("direct fetch should succeed");
    assert_eq!(got.name, pkg);
    // expectations verified when mocks are dropped — proxy must
    // have received 0 calls.
}

#[tokio::test]
async fn parallel_fetch_preserves_input_order_across_varying_latencies() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let npm_server = MockServer::start().await;
    let proxy_server = MockServer::start().await;

    // Six packages. Configure inverted per-response delays so
    // package `aaa` (first input) is the slowest response — if the
    // fan-out returned in completion order, `aaa` would end up last.
    let names: Vec<String> = ["aaa", "bbb", "ccc", "ddd", "eee", "fff"]
        .into_iter()
        .map(String::from)
        .collect();

    for (i, name) in names.iter().enumerate() {
        let body = test_metadata_json(name);
        let delay = std::time::Duration::from_millis(50 * (names.len() - i) as u64);
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(&body)
                    .set_delay(delay),
            )
            .mount(&npm_server)
            .await;
    }

    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri());
    client.cache_dir = Some(tmp.path().to_path_buf());
    let client = Arc::new(client);

    let (results, stats) = client.parallel_fetch_npm_manifests(&names, 6).await;

    assert_eq!(results.len(), names.len());
    for (input_name, (out_name, out_result)) in names.iter().zip(results.iter()) {
        assert_eq!(
            input_name, out_name,
            "fan-out must return entries in input order regardless of completion order"
        );
        assert!(
            out_result.is_ok(),
            "all {input_name} fetches should succeed; got {out_result:?}"
        );
    }
    assert_eq!(stats.halve_events, 0, "no 429s, no halving");
    assert_eq!(
        stats.final_concurrency, stats.initial_concurrency,
        "clean run must not shrink the pool"
    );
}

#[tokio::test]
async fn parallel_fetch_trace_records_direct_npm_metadata_detail_rows() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = crate::timing::metadata_fetch_detail_test_lock()
        .lock()
        .await;
    crate::timing::reset_metadata_detail();

    let npm_server = MockServer::start().await;
    let proxy_server = MockServer::start().await;
    let names: Vec<String> = ["trace-one", "trace-two"]
        .into_iter()
        .map(String::from)
        .collect();

    for name in &names {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(name))
                    .set_delay(std::time::Duration::from_millis(5)),
            )
            .expect(1)
            .mount(&npm_server)
            .await;
    }

    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri());
    client.cache_dir = Some(tmp.path().to_path_buf());
    let client = Arc::new(client);

    let (results, _stats) = client
        .parallel_fetch_npm_manifests_inner(&names, 2, true)
        .await;
    let snapshot = crate::timing::snapshot_metadata_fetch_detail();
    crate::timing::reset_metadata_detail();

    assert!(results.iter().all(|(_, result)| result.is_ok()));
    assert_eq!(snapshot.calls, 2);
    assert_eq!(snapshot.route_npm_direct_count, 2);
    assert!(snapshot.body_bytes_sum > 0);
    assert_eq!(snapshot.version_count_sum, 2);
    assert!(snapshot.attribution.raw_fetch_sum_ms > 0);
    assert!(names.iter().all(|name| {
        snapshot
            .top_slow_packages
            .by_total
            .iter()
            .any(|row| row.package == *name && row.route == "npm_direct")
    }));
}

#[tokio::test]
async fn parallel_fetch_per_entry_failures_do_not_abort_batch() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let npm_server = MockServer::start().await;
    let proxy_server = MockServer::start().await;

    // One name 404s, the rest succeed. The whole batch must still
    // return; the 404 surfaces as a per-entry Err, not a batch abort.
    Mock::given(method("GET"))
        .and(path("/exists-one"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json("exists-one")))
        .mount(&npm_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&npm_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/exists-two"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json("exists-two")))
        .mount(&npm_server)
        .await;

    let names = vec![
        "exists-one".to_string(),
        "missing".to_string(),
        "exists-two".to_string(),
    ];
    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri());
    client.cache_dir = Some(tmp.path().to_path_buf());
    let client = Arc::new(client);

    let (results, _stats) = client.parallel_fetch_npm_manifests(&names, 8).await;

    assert_eq!(results.len(), 3);
    assert!(results[0].1.is_ok(), "exists-one should succeed");
    match &results[1].1 {
        Err(LpmError::NotFound(_)) => {}
        other => panic!("missing should surface 404 as NotFound, got {other:?}"),
    }
    assert!(results[2].1.is_ok(), "exists-two should succeed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn halve_on_429_ratchets_even_under_full_saturation() {
    // Regression test for the halve-on-429 ratchet bug: if the
    // implementation only forgets permits
    // it can `try_acquire_owned` synchronously, a fully-saturated
    // pool registers a halve event without any actual reduction —
    // the pool stays at `initial_concurrency`.
    //
    // The fix adds a deferred-forget debt counter paid by the next
    // task completions. This test pins the saturated moment by
    // making pkg-0 return a fast 429 while pkg-1..pkg-7 return
    // very slow 200s. When pkg-0's task enters the halving block,
    // the other 7 tasks are provably blocked inside send_with_retry
    // holding their permits — so immediate `try_acquire_owned`
    // forgets ZERO permits, and the whole halve must come from
    // the deferred-debt path.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let npm_server = MockServer::start().await;
    let proxy_server = MockServer::start().await;

    // pkg-0: fast 429. MAX_RETRIES=3 inside send_with_retry, with
    // Retry-After=0 → ~4 attempts, no sleep between them; surfaces
    // RateLimited quickly.
    Mock::given(method("GET"))
        .and(path("/pkg-0"))
        .respond_with(ResponseTemplate::new(429).append_header("Retry-After", "0"))
        .mount(&npm_server)
        .await;

    // pkg-1..pkg-7: slow 200s. The 2-second delay ensures they are
    // STILL IN-FLIGHT when pkg-0's task enters the halving code,
    // forcing every permit to be held and the `try_acquire_owned`
    // path to forget zero.
    for i in 1..8 {
        let name = format!("pkg-{i}");
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(&name))
                    .set_delay(std::time::Duration::from_secs(2)),
            )
            .mount(&npm_server)
            .await;
    }

    let names: Vec<String> = (0..8).map(|i| format!("pkg-{i}")).collect();
    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri());
    client.cache_dir = Some(tmp.path().to_path_buf());
    let client = Arc::new(client);

    // initial=8 matches names.len() so every task immediately acquires
    // a permit — no permits sit idle. When pkg-0's 429 fires, every
    // other permit is held by a task still in its 2s delay.
    let (results, stats) = client.parallel_fetch_npm_manifests(&names, 8).await;

    // pkg-0 RateLimited; the rest successful.
    assert_eq!(results.len(), 8);
    match &results[0].1 {
        Err(LpmError::RateLimited { .. }) => {}
        other => panic!("pkg-0 should surface RateLimited; got {other:?}"),
    }
    for (i, (name, r)) in results.iter().enumerate().skip(1) {
        assert!(
            r.is_ok(),
            "pkg-{i} ({name}) should have succeeded; got {r:?}"
        );
    }

    // The core assertion: halving actually happened under a scenario
    // where the synchronous `try_acquire_owned` path could only have
    // forgotten ZERO permits. Any final_concurrency < initial proves
    // the deferred-debt path is carrying its weight.
    assert!(
        stats.final_concurrency < stats.initial_concurrency,
        "halve-on-429 must actually reduce final concurrency under saturation; \
             got initial={}, final={}, halve_events={}",
        stats.initial_concurrency,
        stats.final_concurrency,
        stats.halve_events,
    );
    assert_eq!(
        stats.halve_events, 1,
        "exactly one halve event should be recorded (got {})",
        stats.halve_events,
    );
    // Floor respected.
    assert!(
        stats.final_concurrency >= 4,
        "final concurrency must not drop below the floor of 4 (got {})",
        stats.final_concurrency,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn halve_on_429_multi_concurrent_races_respect_floor() {
    // Reviewer regression for the multi-429 ratchet race: when N
    // concurrent tasks all observe 429 before any of them decrements
    // the ceiling, the old logic had each task independently compute
    // `want_forget` against the stale `current=8`, each enqueue 4
    // into debt, and the 8 subsequent completions drive effective
    // pool to 0 — below the floor of 4.
    //
    // Fix: CAS on `current_ceiling` at halving time, so at most one
    // handler per ceiling transition wins the halving decision.
    // Others see the new lower ceiling (or `<= floor`) and back off.
    //
    // This test forces the race by (a) saturating the pool with 8
    // in-flight requests, (b) delaying every 429 response by the
    // same amount so all 8 tasks enter the halving block within a
    // tight window. Under the broken algorithm the pool shrinks
    // past the floor; the fix holds it at >= floor.
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let npm_server = MockServer::start().await;
    let proxy_server = MockServer::start().await;

    // Every request: slow 429. Uniform 300ms delay keeps the 8
    // tasks' `RateLimited` surfacings bunched, maximising the race
    // window on the halving block.
    Mock::given(method("GET"))
        .and(path_regex(r"^/race-\d+$"))
        .respond_with(
            ResponseTemplate::new(429)
                .append_header("Retry-After", "0")
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&npm_server)
        .await;

    let names: Vec<String> = (0..8).map(|i| format!("race-{i}")).collect();
    let tmp = tempfile::tempdir().expect("tmp");
    let mut client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri());
    client.cache_dir = Some(tmp.path().to_path_buf());
    let client = Arc::new(client);

    let (_results, stats) = client.parallel_fetch_npm_manifests(&names, 8).await;

    // The core assertion: concurrent 429s must NOT drive final
    // ceiling below the floor. With the broken logic this goes to
    // 0; with the CAS fix it stops at 4.
    assert!(
        stats.final_concurrency >= 4,
        "multi-429 race must respect floor; got initial={} final={} halve_events={}",
        stats.initial_concurrency,
        stats.final_concurrency,
        stats.halve_events,
    );
    // With initial=8 and floor=4, exactly one halve step is
    // possible (8→4). More than one means a handler halved past
    // the floor.
    assert_eq!(
        stats.halve_events, 1,
        "with floor=4 and initial=8 only a single halve step is \
             representable; got {}",
        stats.halve_events,
    );
}

#[tokio::test]
async fn registry_signing_keys_are_singleflight_cached() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = serde_json::json!({
        "keys": [{
            "expires": null,
            "keyid": "SHA256:test-key",
            "keytype": "ecdsa-sha2-nistp256",
            "scheme": "ecdsa-sha2-nistp256",
            "key": "public-key"
        }]
    });
    Mock::given(method("GET"))
        .and(path("/-/npm/v1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&server)
        .await;

    let server_uri = server.uri();
    let (client, _tmp) = client_with_mock_server(&server_uri);
    let (first, second) = tokio::join!(
        client.get_registry_signing_keys(&server_uri, None),
        client.get_registry_signing_keys(&server_uri, None)
    );

    let first = first.expect("first key lookup succeeds");
    let second = second.expect("second key lookup succeeds");
    assert_eq!(first, second);
    assert_eq!(first.len(), 1);

    let third = client
        .get_registry_signing_keys(&server_uri, None)
        .await
        .expect("warm key lookup succeeds");
    assert_eq!(third, first);
}

#[tokio::test]
async fn get_npm_metadata_from_attaches_bearer_auth() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/some-pkg"))
        .and(header("Authorization", "Bearer SECRET-TOKEN-123"))
        .and(header("Accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json("some-pkg")))
        .expect(1)
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    let auth = bearer_for(&server.uri(), "SECRET-TOKEN-123");
    let meta = client
        .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
        .await
        .expect("auth-attached fetch should succeed");
    assert_eq!(meta.name, "some-pkg");
}

#[tokio::test]
async fn get_npm_metadata_from_attaches_basic_auth() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/some-pkg"))
        .and(header("Authorization", "Basic dXNlcjpwYXNz"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json("some-pkg")))
        .expect(1)
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    let auth = basic_for(&server.uri(), "dXNlcjpwYXNz");
    let meta = client
        .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
        .await
        .expect("Basic auth fetch should succeed");
    assert_eq!(meta.name, "some-pkg");
}

#[tokio::test]
async fn get_npm_metadata_from_no_auth_sends_anonymous() {
    // No Authorization header sent when auth is None. We assert
    // the absence by setting up TWO mocks: the matched-no-auth one
    // returns 200; if the request had any Authorization header,
    // wiremock would route nowhere and 404.
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Reject any request that DOES carry Authorization.
    Mock::given(method("GET"))
        .and(path("/some-pkg"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(401))
        .expect(0) // never matched
        .mount(&server)
        .await;
    // Accept the no-auth request.
    Mock::given(method("GET"))
        .and(path("/some-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json("some-pkg")))
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    let meta = client
        .get_npm_metadata_from(&server.uri(), "some-pkg", None)
        .await
        .expect("anonymous fetch should succeed");
    assert_eq!(meta.name, "some-pkg");
}

#[tokio::test]
async fn get_npm_metadata_from_origin_mismatch_returns_error() {
    // S2 defense: auth scoped to origin A, request to origin B.
    // The fetch site MUST refuse to send and surface a clear error
    // — no network call is made.
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let (client, _tmp) = client_with_mock_server(&server.uri());

    // Auth scoped to a DIFFERENT host than the server.
    let auth = bearer_for("https://attacker.example", "STOLEN");

    let result = client
        .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
        .await;

    match result {
        Err(LpmError::Registry(msg)) => {
            assert!(
                msg.contains("origin mismatch"),
                "error must mention origin mismatch: {msg}"
            );
        }
        other => panic!("expected origin-mismatch Registry error, got {other:?}"),
    }
    // Bonus: the mock server received NO request, since we hard-
    // failed before the network. wiremock's default is "no
    // expectations set ⇒ no requests required", so this is
    // implicit — we just don't assert any mock was matched.
}

#[tokio::test]
async fn get_npm_metadata_from_uses_host_keyed_cache() {
    // Two distinct registries serving the same package name must
    // not collide in the cache.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let registry_a = MockServer::start().await;
    let registry_b = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/colliding-name"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json_with_version("colliding-name", "1.0.0")),
        )
        .mount(&registry_a)
        .await;
    Mock::given(method("GET"))
        .and(path("/colliding-name"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json_with_version("colliding-name", "9.9.9")),
        )
        .mount(&registry_b)
        .await;

    let (client, _tmp) = client_with_mock_server(&registry_a.uri());

    let meta_a = client
        .get_npm_metadata_from(&registry_a.uri(), "colliding-name", None)
        .await
        .unwrap();
    let meta_b = client
        .get_npm_metadata_from(&registry_b.uri(), "colliding-name", None)
        .await
        .unwrap();

    // Each registry's response is preserved — no cross-talk.
    assert_eq!(meta_a.latest_version.as_deref(), Some("1.0.0"));
    assert_eq!(meta_b.latest_version.as_deref(), Some("9.9.9"));
}

#[tokio::test]
async fn get_npm_metadata_from_distinguishes_path_prefixed_registries_on_same_origin() {
    // Two npm-compatible registries on the same host:port but
    // different path prefixes — e.g., GitLab npm Package Registry
    // (`/api/v4/projects/<id>/packages/npm`). Earlier drafts keyed
    // the cache on (host, port); this test pins the regression.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Project 1 path serves "1.0.0".
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/1/packages/npm/colliding-name"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json_with_version("colliding-name", "1.0.0")),
        )
        .mount(&server)
        .await;
    // Project 2 path serves "2.0.0".
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/2/packages/npm/colliding-name"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(test_metadata_json_with_version("colliding-name", "2.0.0")),
        )
        .mount(&server)
        .await;

    let (client, _tmp) = client_with_mock_server(&server.uri());
    let base_a = format!("{}/api/v4/projects/1/packages/npm", server.uri());
    let base_b = format!("{}/api/v4/projects/2/packages/npm", server.uri());
    let meta_a = client
        .get_npm_metadata_from(&base_a, "colliding-name", None)
        .await
        .unwrap();
    let meta_b = client
        .get_npm_metadata_from(&base_b, "colliding-name", None)
        .await
        .unwrap();
    assert_eq!(
        meta_a.latest_version.as_deref(),
        Some("1.0.0"),
        "project 1 must see its own version"
    );
    assert_eq!(
        meta_b.latest_version.as_deref(),
        Some("2.0.0"),
        "project 2 must NOT inherit project 1's cache entry"
    );
}

#[test]
fn validate_pem_root_catches_malformed_second_block_in_multi_cert_bundle() {
    // Regression — pre-fix `validate_pem_root` only validated the
    // FIRST cert block in a PEM. A common cafile shape (root + intermediate
    // bundle, multi-CERT) where block 1 was valid but block 2 was malformed
    // would slip through validation and surface as a generic
    // "HTTP client build failed: builder error" without source citation.
    // Now every block is validated; the offending block's offset is cited.
    let valid = rcgen_pem();
    let mut bundle = Vec::with_capacity(valid.len() * 2 + 256);
    bundle.extend_from_slice(&valid);
    bundle.extend_from_slice(
        b"\n-----BEGIN CERTIFICATE-----\n@@@ not base64 @@@\n-----END CERTIFICATE-----\n",
    );
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: bundle,
            source: "/Users/me/.npmrc".into(),
            line: 12,
        }],
        strict_ssl: None,
        ..Default::default()
    };
    let client = RegistryClient::new();
    match client.with_tls_overrides(&tls) {
        Ok(_) => panic!("malformed 2nd block must fail validation, got Ok"),
        Err(LpmError::Cert(msg)) => {
            assert!(
                msg.contains("/Users/me/.npmrc:12"),
                "error must cite source:line — got: {msg}"
            );
            assert!(
                msg.contains("not valid base64"),
                "error must explain the failure mode — got: {msg}"
            );
        }
        Err(other) => panic!("expected Cert error, got: {other}"),
    }
}

#[test]
fn validate_pem_root_accepts_valid_multi_cert_bundle() {
    // Positive case for the loop: a root + intermediate where BOTH
    // are valid PEM blocks must pass. Two distinct rcgen certs
    // concatenated with a separator newline.
    let mut bundle = rcgen_pem();
    bundle.push(b'\n');
    bundle.extend_from_slice(&rcgen_pem());
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: bundle,
            source: "test".into(),
            line: 1,
        }],
        strict_ssl: None,
        ..Default::default()
    };
    let client = RegistryClient::new();
    assert!(
        client.with_tls_overrides(&tls).is_ok(),
        "two valid concatenated cert blocks must pass"
    );
}
