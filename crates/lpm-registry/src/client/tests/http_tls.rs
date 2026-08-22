use super::*;

#[test]
fn with_tls_overrides_default_is_noop() {
    // No extra roots, no strict_ssl set → no rebuild, no error.
    let client = RegistryClient::new();
    assert!(
        client.with_tls_overrides(&TlsOverrides::default()).is_ok(),
        "default TLS overrides must be a no-op"
    );
}

#[test]
fn with_tls_overrides_explicit_strict_ssl_true_is_noop() {
    // `strict-ssl=true` is the default — explicitly setting it to
    // true should not force a rebuild.
    let tls = TlsOverrides {
        extra_roots: Vec::new(),
        strict_ssl: Some(TaggedBool {
            value: true,
            source: "test".into(),
            line: 1,
        }),
        ..Default::default()
    };
    let client = RegistryClient::new();
    assert!(client.with_tls_overrides(&tls).is_ok());
}

#[test]
fn with_tls_overrides_with_valid_pem_builds_ok() {
    let pem = rcgen_pem();
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: pem,
            source: "test:.npmrc".into(),
            line: 1,
        }],
        strict_ssl: None,
        ..Default::default()
    };
    let client = RegistryClient::new();
    assert!(client.with_tls_overrides(&tls).is_ok());
}

#[test]
fn with_tls_overrides_with_malformed_pem_returns_err_with_source() {
    // Bytes that fail `reqwest::Certificate::from_pem`. The error
    // must cite the contributing source/line so the user can find
    // the offending `.npmrc` line, not just see "TLS broke".
    //
    // Note: reqwest's `from_pem` is permissive about the BODY
    // content as long as the BEGIN/END markers are present
    // (validation happens later in `.build()`). To exercise the
    // source-citing path on `from_pem` itself, we pass bytes with
    // no PEM marker at all — these would never reach the builder
    // through the normal parser (the parse-time `contains_pem_certificate_block`
    // check rejects them), but a direct caller of `with_tls_overrides`
    // with hand-built `TaggedRoot` (or a future PEM source we don't
    // marker-check) would.
    let no_marker = b"this is plainly not a PEM file".to_vec();
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: no_marker,
            source: "/Users/me/.npmrc".into(),
            line: 7,
        }],
        strict_ssl: None,
        ..Default::default()
    };
    let client = RegistryClient::new();
    match client.with_tls_overrides(&tls) {
        Ok(_) => panic!("expected Err for malformed PEM, got Ok"),
        Err(LpmError::Cert(msg)) => {
            assert!(
                msg.contains("/Users/me/.npmrc:7"),
                "error must cite source:line — got: {msg}"
            );
            assert!(
                msg.contains("npmrc cafile/ca"),
                "error must identify the npmrc origin — got: {msg}"
            );
        }
        Err(other) => panic!("expected Cert error, got: {other}"),
    }
}

#[test]
fn with_tls_overrides_strict_ssl_false_builds_ok() {
    let tls = TlsOverrides {
        extra_roots: Vec::new(),
        strict_ssl: Some(TaggedBool {
            value: false,
            source: "test".into(),
            line: 1,
        }),
        ..Default::default()
    };
    let client = RegistryClient::new();
    assert!(client.with_tls_overrides(&tls).is_ok());
}

#[test]
fn with_tls_overrides_combined_pem_and_strict_ssl_builds_ok() {
    // Both knobs at once — install.rs's worst-case combined-overrides
    // path. Builder must accept both without conflict.
    let pem = rcgen_pem();
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: pem,
            source: "test".into(),
            line: 1,
        }],
        strict_ssl: Some(TaggedBool {
            value: false,
            source: "test".into(),
            line: 2,
        }),
        ..Default::default()
    };
    let client = RegistryClient::new();
    assert!(client.with_tls_overrides(&tls).is_ok());
}

#[test]
fn http_clients_default_only_returns_default_for_every_url() {
    let client = RegistryClient::new();
    // Two distinct origins, both fall through to default since no
    // per-origin TLS is configured.
    let c1 = client
        .http
        .for_url_no_build("https://registry.npmjs.org/react");
    let c2 = client.http.for_url_no_build("https://corp.internal/lib");
    // Pointer equality on `&reqwest::Client` is the precise check —
    // both must point to the SAME default client, not equivalent
    // copies. (`Arc`-internal so equality of the underlying Arc
    // pointers is what we want.)
    assert!(std::ptr::eq(c1, c2), "every URL must route to default");
}

#[test]
fn http_clients_eager_hit_overrides_default() {
    // Build with a per-origin cafile entry (deferred-read; no
    // actual file IO since we'll synthesize the eager entry).
    let pem = rcgen_pem();
    // Synthesize an HttpClients directly so the test doesn't need
    // a real .npmrc parse (the eager build path needs file IO,
    // which we exercise in the integration test for mTLS proper).
    let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
    let per_origin_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&pem).expect("rcgen pem"))
        .build()
        .expect("client build");
    let origin = OriginKey {
        host_lower: "corp.internal".into(),
        port: None,
    };
    let mut eager = HashMap::new();
    eager.insert(origin.clone(), cached(per_origin_client));
    let http = Arc::new(HttpClients {
        default: cached(default),
        eager,
        lazy: tokio::sync::Mutex::new(HashMap::new()),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        per_origin_identity_fps: HashMap::new(),
    });
    let mut client = RegistryClient::new();
    client.http = http;
    // Eager origin → per_origin_client (NOT default).
    let picked = client
        .http
        .for_url_no_build("https://corp.internal:443/foo");
    // Different origin → default.
    let other = client.http.for_url_no_build("https://other.example/bar");
    // Pointer-eq each against the source it should match.
    // `for_url_no_build` returns `&reqwest::Client` (the .client
    // field of CachedClient), so pierce CachedClient on the rhs.
    assert!(
        std::ptr::eq(picked, &client.http.eager.get(&origin).unwrap().client),
        "eager origin must dispatch to its registered client"
    );
    assert!(
        std::ptr::eq(other, &client.http.default.client),
        "non-eager origin must dispatch to default"
    );
}

#[tokio::test]
async fn specialized_dispatch_uses_dedicated_policy_and_manual_redirect_clients() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .respond_with(ResponseTemplate::new(200))
        .expect(3)
        .mount(&server)
        .await;

    let regular = reqwest::Client::builder()
        .default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::HeaderName::from_static("x-lpm-pool"),
            reqwest::header::HeaderValue::from_static("regular"),
        )]))
        .build()
        .expect("regular client");
    let policy = reqwest::Client::builder()
        .default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::HeaderName::from_static("x-lpm-pool"),
            reqwest::header::HeaderValue::from_static("policy"),
        )]))
        .build()
        .expect("policy client");
    let manual_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::HeaderName::from_static("x-lpm-pool"),
            reqwest::header::HeaderValue::from_static("manual-redirect"),
        )]))
        .build()
        .expect("manual redirect client");
    let clients = HttpClients::from_default_clients(regular, policy, manual_redirect);
    let url = format!("{}/metadata", server.uri());

    clients
        .for_url(&url)
        .await
        .expect("regular dispatch")
        .get(&url)
        .send()
        .await
        .expect("regular response");
    clients
        .for_policy_metadata_url(&url)
        .await
        .expect("policy dispatch")
        .get(&url)
        .send()
        .await
        .expect("policy response");
    clients
        .for_manual_redirect_url(&url)
        .await
        .expect("manual redirect dispatch")
        .get(&url)
        .send()
        .await
        .expect("manual redirect response");

    let requests = server.received_requests().await.expect("request recording");
    let pools: Vec<&str> = requests
        .iter()
        .map(|request| {
            request
                .headers
                .get("x-lpm-pool")
                .and_then(|value| value.to_str().ok())
                .expect("pool header")
        })
        .collect();
    assert_eq!(pools, vec!["regular", "policy", "manual-redirect"]);
}

#[tokio::test]
async fn manual_redirect_dispatch_reselects_the_client_for_each_origin() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cached_with_manual_origin(origin: &'static str) -> CachedClient {
        let manual_redirect_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(reqwest::header::HeaderMap::from_iter([(
                reqwest::header::HeaderName::from_static("x-manual-origin"),
                reqwest::header::HeaderValue::from_static(origin),
            )]))
            .build()
            .expect("manual redirect client");
        CachedClient {
            client: reqwest::Client::new(),
            policy_metadata_client: reqwest::Client::new(),
            manual_redirect_client,
            identity_fp: None,
        }
    }

    let target = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/capture"))
        .and(header("x-manual-origin", "target"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&target)
        .await;
    let source = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/initial"))
        .and(header("x-manual-origin", "source"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/capture", target.uri())),
        )
        .expect(1)
        .mount(&source)
        .await;

    let mut eager = HashMap::new();
    eager.insert(
        OriginKey::from_request_url(&source.uri()).unwrap(),
        cached_with_manual_origin("source"),
    );
    eager.insert(
        OriginKey::from_request_url(&target.uri()).unwrap(),
        cached_with_manual_origin("target"),
    );
    let clients = HttpClients {
        default: cached(reqwest::Client::new()),
        eager,
        lazy: tokio::sync::Mutex::new(HashMap::new()),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        per_origin_identity_fps: HashMap::new(),
    };
    let body = lpm_http::ReplayableRequestBody::from_bytes(b"body".to_vec());
    let mut request = reqwest::Request::new(
        reqwest::Method::PUT,
        reqwest::Url::parse(&format!("{}/initial", source.uri())).unwrap(),
    );
    request.headers_mut().insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );

    let response = lpm_http::send_with_replayable_redirects(&clients, request, Some(&body))
        .await
        .expect("redirect should use each origin's manual client");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[test]
fn http_clients_eager_port_none_matches_any_port() {
    let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
    let pem = rcgen_pem();
    let per_origin_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&pem).expect("rcgen pem"))
        .build()
        .expect("client build");
    // Insert with port: None.
    let key_no_port = OriginKey {
        host_lower: "host.internal".into(),
        port: None,
    };
    let mut eager = HashMap::new();
    eager.insert(key_no_port.clone(), cached(per_origin_client));
    let http = Arc::new(HttpClients {
        default: cached(default),
        eager,
        lazy: tokio::sync::Mutex::new(HashMap::new()),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        per_origin_identity_fps: HashMap::new(),
    });
    let mut client = RegistryClient::new();
    client.http = http;
    // Both 443 (default https) and 8443 must hit the no-port entry.
    let picked_443 = client.http.for_url_no_build("https://host.internal/foo");
    let picked_8443 = client
        .http
        .for_url_no_build("https://host.internal:8443/bar");
    let stored = &client.http.eager.get(&key_no_port).unwrap().client;
    assert!(std::ptr::eq(picked_443, stored));
    assert!(std::ptr::eq(picked_8443, stored));
}

#[tokio::test]
async fn http_clients_lazy_builds_and_memoizes() {
    // Synthesize TlsOverrides with a per-origin cafile pointing
    // at a real PEM file, but don't pre-build the eager client.
    let pem = rcgen_pem();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &pem).unwrap();
    let origin = OriginKey {
        host_lower: "lazy.internal".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin.clone(),
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![crate::npmrc::TaggedPath {
                path: ca_path,
                source: "test".into(),
                line: 1,
                source_dir: None,
            }],
            certfile: None,
            keyfile: None,
        },
    );
    let tls = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
    let http = Arc::new(HttpClients {
        default: cached(default),
        eager: HashMap::new(),
        lazy: tokio::sync::Mutex::new(HashMap::new()),
        tls_overrides: Arc::new(tls),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        per_origin_identity_fps: HashMap::new(),
    });
    // First call must build + insert.
    let c1 = http.for_url("https://lazy.internal/pkg").await.expect("ok");
    // Second call must hit the lazy cache (not rebuild).
    let c2 = http
        .for_url("https://lazy.internal/other")
        .await
        .expect("ok");
    // Same origin → same cached entry. The dispatcher inserts
    // under the URL's concrete-port origin (`Some(443)` for
    // HTTPS), not the configured port-None entry — both calls
    // produce the same key, so the second call's `guard.get`
    // hits without rebuild. Verify the lazy map has exactly one
    // entry, keyed by the concrete-port origin.
    let concrete_port_key = OriginKey {
        host_lower: "lazy.internal".into(),
        port: Some(443),
    };
    let map = http.lazy.lock().await;
    assert_eq!(map.len(), 1, "lazy map must contain exactly one entry");
    assert!(
        map.contains_key(&concrete_port_key),
        "lazy entry must be keyed by the URL's concrete-port origin (got keys: {:?})",
        map.keys().map(|k| k.to_string()).collect::<Vec<_>>()
    );
    // The originally-configured port-None origin is the per_origin
    // TLS lookup key, not the lazy cache key — the dispatcher's
    // (host, Some(port)) → (host, None) fallback bridges the two.
    // Reference but unused: prevents the unused-binding warning.
    let _ = origin;
    // Sanity: both returned clients are usable Client values.
    let _ = (c1, c2);
}

#[tokio::test]
async fn http_clients_no_per_origin_tls_falls_through_to_default() {
    let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
    let http = Arc::new(HttpClients {
        default: cached(default.clone()),
        eager: HashMap::new(),
        lazy: tokio::sync::Mutex::new(HashMap::new()),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        per_origin_identity_fps: HashMap::new(),
    });
    let _ = http
        .for_url("https://anywhere.example/foo")
        .await
        .expect("ok");
    // Lazy map must remain empty (no per-origin TLS to build).
    let map = http.lazy.lock().await;
    assert!(map.is_empty());
}

#[tokio::test]
async fn http_clients_per_origin_certfile_xor_is_fatal_at_build() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    std::fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let origin = OriginKey {
        host_lower: "halfconf.internal".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin.clone(),
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![],
            certfile: Some(crate::npmrc::TaggedPath {
                path: cert_path,
                source: "test:.npmrc".into(),
                line: 7,
                source_dir: None,
            }),
            keyfile: None,
        },
    );
    let tls = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
    let http = Arc::new(HttpClients {
        default: cached(default),
        eager: HashMap::new(),
        lazy: tokio::sync::Mutex::new(HashMap::new()),
        tls_overrides: Arc::new(tls),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        per_origin_identity_fps: HashMap::new(),
    });
    let result = http.for_url("https://halfconf.internal/foo").await;
    match result {
        Err(LpmError::Cert(msg)) => {
            assert!(msg.contains("test:.npmrc:7"), "msg: {msg}");
            assert!(msg.contains("certfile"), "msg: {msg}");
            assert!(msg.contains("keyfile"), "msg: {msg}");
            assert!(msg.contains("halfconf.internal"), "msg: {msg}");
        }
        other => panic!("expected Cert error, got: {other:?}"),
    }
}

#[tokio::test]
async fn http_clients_unreached_half_config_does_not_break_unrelated_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    std::fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let unreached_origin = OriginKey {
        host_lower: "unused.internal".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        unreached_origin,
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![],
            certfile: Some(crate::npmrc::TaggedPath {
                path: cert_path,
                source: "test:.npmrc".into(),
                line: 7,
                source_dir: None,
            }),
            keyfile: None,
        },
    );
    let tls = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
    let http = Arc::new(HttpClients {
        default: cached(default),
        eager: HashMap::new(),
        lazy: tokio::sync::Mutex::new(HashMap::new()),
        tls_overrides: Arc::new(tls),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        per_origin_identity_fps: HashMap::new(),
    });
    // Request to a DIFFERENT origin must succeed (lookup → default).
    let _ = http
        .for_url("https://different.example/foo")
        .await
        .expect("unrelated lookup must not fail on unreached half-config");
}

#[tokio::test]
async fn production_tarball_path_triggers_lazy_build_for_per_origin_tls() {
    // Synthesize a per-origin TLS config for a host that's NOT in
    // the eager set. Use a self-signed CA so the per-origin client
    // build works (we never actually connect — the test fails
    // before that on URL scheme / DNS, which is fine; we're
    // verifying that the LAZY MAP gets populated).
    let pem = rcgen_pem();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &pem).unwrap();
    let origin = OriginKey {
        host_lower: "lazy-target.invalid".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin.clone(),
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![crate::npmrc::TaggedPath {
                path: ca_path,
                source: "test".into(),
                line: 1,
                source_dir: None,
            }],
            certfile: None,
            keyfile: None,
        },
    );
    let tls = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    // Build via the real entry point — empty eager_origins so the
    // origin can ONLY surface via lazy. This is the exact shape
    // T4's request-aware effective set will produce for transitive
    // origins.
    let client = RegistryClient::new()
        .with_tls_overrides_for(&tls, &[])
        .expect("build ok");
    // Sanity: eager is empty.
    assert!(client.http.eager.is_empty());
    // Trigger a tarball download. The connection will fail (host
    // is .invalid + no listener), but the lazy build of the
    // per-origin client must happen BEFORE the network attempt.
    // We don't care about the request outcome — only that the
    // lazy map gets populated.
    let url = "https://lazy-target.invalid/foo/-/foo-1.0.0.tgz";
    let _ = client.download_tarball_to_file_with_auth(url, None).await;
    // Verify: lazy map now contains an entry for the URL's
    // concrete-port origin (per-origin lookup with port=None
    // fallback hit; insertion key is the URL's resolved origin).
    let lazy = client.http.lazy.lock().await;
    let concrete_port_key = OriginKey {
        host_lower: "lazy-target.invalid".into(),
        port: Some(443),
    };
    assert_eq!(
        lazy.len(),
        1,
        "lazy map must be populated by production tarball path; got: {:?}",
        lazy.keys().map(|k| k.to_string()).collect::<Vec<_>>()
    );
    assert!(
        lazy.contains_key(&concrete_port_key),
        "lazy entry must be keyed by URL's concrete-port origin"
    );
}

#[test]
fn principal_fingerprint_anon_when_no_auth_no_identity() {
    let fp = principal_fingerprint(None, None);
    assert_eq!(fp, "anon");
}

#[test]
fn npmrc_auth_refuses_cleartext_non_loopback_destination() {
    let url = "http://registry.example.test/package";
    let auth = bearer_for("http://registry.example.test", "secret-token");
    let request = reqwest::Client::new().get(url);

    assert!(
        apply_npmrc_auth(request, url, Some(&auth)).is_err(),
        "credentials must not be attached to cleartext non-loopback requests"
    );
}

#[test]
fn npmrc_auth_allows_cleartext_loopback_destination() {
    let url = "http://127.0.0.1:4873/package";
    let auth = bearer_for("http://127.0.0.1:4873", "local-token");
    let request = reqwest::Client::new().get(url);

    assert!(apply_npmrc_auth(request, url, Some(&auth)).is_ok());
}

#[test]
fn principal_fingerprint_changes_with_identity_alone() {
    // Same auth (none), different identity hash → different fingerprint.
    // Re-issued client cert must invalidate cache cleanly.
    let fp_a = principal_fingerprint(None, Some("aaaaaaaaaaaaaaaa"));
    let fp_b = principal_fingerprint(None, Some("bbbbbbbbbbbbbbbb"));
    assert_ne!(fp_a, fp_b);
    assert!(fp_a.starts_with("principal-"));
    assert!(fp_b.starts_with("principal-"));
}

#[test]
fn principal_fingerprint_changes_with_auth_alone() {
    use crate::npmrc::{OriginKey, RegistryAuth};
    let bearer_a = RegistryAuth::Bearer {
        origin: OriginKey {
            host_lower: "x".into(),
            port: None,
        },
        token: SecretString::from("token-a".to_string()),
    };
    let bearer_b = RegistryAuth::Bearer {
        origin: OriginKey {
            host_lower: "x".into(),
            port: None,
        },
        token: SecretString::from("token-b".to_string()),
    };
    let fp_a = principal_fingerprint(Some(&bearer_a), None);
    let fp_b = principal_fingerprint(Some(&bearer_b), None);
    assert_ne!(fp_a, fp_b);
}

#[test]
fn principal_fingerprint_auth_plus_identity_differs_from_auth_alone() {
    // The auth + identity composition is non-trivial: same auth
    // with vs. without an identity hash MUST produce distinct
    // fingerprints, otherwise a client that re-issues a cert
    // would still hit the old cache entry under the same auth.
    use crate::npmrc::{OriginKey, RegistryAuth};
    let bearer = RegistryAuth::Bearer {
        origin: OriginKey {
            host_lower: "x".into(),
            port: None,
        },
        token: SecretString::from("tok".to_string()),
    };
    let fp_no_id = principal_fingerprint(Some(&bearer), None);
    let fp_with_id = principal_fingerprint(Some(&bearer), Some("ffffffffffffffff"));
    assert_ne!(fp_no_id, fp_with_id);
}

#[test]
fn cert_pem_fingerprint_is_deterministic_and_truncated() {
    let pem = b"-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----\n";
    let fp1 = cert_pem_fingerprint(pem);
    let fp2 = cert_pem_fingerprint(pem);
    assert_eq!(&*fp1, &*fp2);
    assert_eq!(fp1.len(), 16);
    // Different bytes → different fingerprint.
    let other = b"-----BEGIN CERTIFICATE-----\nEFGH\n-----END CERTIFICATE-----\n";
    let fp_other = cert_pem_fingerprint(other);
    assert_ne!(&*fp1, &*fp_other);
}

#[test]
fn lazy_target_origin_identity_fp_namespaces_cache_pre_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");

    // First identity.
    let cert_a =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen a");
    std::fs::write(&cert_path, cert_a.cert.pem()).unwrap();
    std::fs::write(&key_path, cert_a.key_pair.serialize_pem()).unwrap();

    let origin = OriginKey {
        host_lower: "lazy.internal".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin,
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![],
            certfile: Some(crate::npmrc::TaggedPath {
                path: cert_path.clone(),
                source: "test".into(),
                line: 1,
                source_dir: None,
            }),
            keyfile: Some(crate::npmrc::TaggedPath {
                path: key_path.clone(),
                source: "test".into(),
                line: 2,
                source_dir: None,
            }),
        },
    );
    let tls_a = TlsOverrides {
        per_origin: per_origin_map.clone(),
        ..Default::default()
    };
    // CRUCIAL: pass empty eager_origins — origin is lazy-only.
    let client_a = RegistryClient::new()
        .with_tls_overrides_for(&tls_a, &[])
        .expect("build a");
    // Pre-fix this would have been None / default-fp; post-fix
    // it MUST be a real fingerprint of cert_a's PEM.
    let fp_a = client_a
        .http
        .identity_fp_for_url("https://lazy.internal/foo")
        .expect("lazy-target origin must report a non-default fp");
    assert_eq!(fp_a.len(), 16);

    // Rotate the cert: write a DIFFERENT cert+key pair to the
    // same paths, rebuild HttpClients. fp must change.
    let cert_b =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen b");
    std::fs::write(&cert_path, cert_b.cert.pem()).unwrap();
    std::fs::write(&key_path, cert_b.key_pair.serialize_pem()).unwrap();
    let tls_b = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    let client_b = RegistryClient::new()
        .with_tls_overrides_for(&tls_b, &[])
        .expect("build b");
    let fp_b = client_b
        .http
        .identity_fp_for_url("https://lazy.internal/foo")
        .expect("after rotation, lazy-target fp still present");
    assert_ne!(
        fp_a, fp_b,
        "rotated cert must change cache namespace for lazy-target origin"
    );
}

#[test]
fn http_clients_identity_fp_for_url_reflects_per_origin_cert() {
    // Generate a matching cert+key pair (same signing_key). Using
    // separate `rcgen_pem()` calls for cert and key would produce
    // a mismatched pair that fails `Identity::from_pem`.
    let cert_with_key =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_pem_str = cert_with_key.cert.pem();
    let key_pem_str = cert_with_key.key_pair.serialize_pem();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("client.pem");
    std::fs::write(&cert_path, &cert_pem_str).unwrap();
    let key_path = dir.path().join("client.key");
    std::fs::write(&key_path, &key_pem_str).unwrap();
    let origin = OriginKey {
        host_lower: "corp.internal".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin.clone(),
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![],
            certfile: Some(crate::npmrc::TaggedPath {
                path: cert_path,
                source: "test".into(),
                line: 1,
                source_dir: None,
            }),
            keyfile: Some(crate::npmrc::TaggedPath {
                path: key_path,
                source: "test".into(),
                line: 2,
                source_dir: None,
            }),
        },
    );
    let tls = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    let client = RegistryClient::new()
        .with_tls_overrides_for(&tls, std::slice::from_ref(&origin))
        .expect("build ok");
    // URL targeting the eager origin → fp present.
    let fp = client.http.identity_fp_for_url("https://corp.internal/foo");
    assert!(fp.is_some(), "per-origin client must carry an identity_fp");
    assert_eq!(fp.unwrap().len(), 16);
    // URL for an unrelated origin (default-routed, no global
    // identity configured) → fp None.
    let fp_other = client.http.identity_fp_for_url("https://other.example/bar");
    assert!(
        fp_other.is_none(),
        "default client without global identity must have None fp"
    );
}

#[test]
fn render_effective_tls_summary_returns_none_when_default_only() {
    let client = RegistryClient::new();
    assert!(client.render_effective_tls_summary().is_none());
}

#[test]
fn render_effective_tls_summary_reports_global_extra_roots() {
    let pem = rcgen_pem();
    let tls = TlsOverrides {
        extra_roots: vec![TaggedRoot {
            pem_bytes: pem,
            source: "test".into(),
            line: 1,
        }],
        ..Default::default()
    };
    let client = RegistryClient::new()
        .with_tls_overrides_for(&tls, &[])
        .expect("build ok");
    let summary = client.render_effective_tls_summary().expect("summary");
    assert!(
        summary.contains("1 extra root certificate"),
        "got: {summary}"
    );
    assert!(
        !summary.contains("extra root certificates "),
        "must singularize"
    );
}

#[test]
fn render_effective_tls_summary_pluralizes_extra_roots() {
    let mut bundle = rcgen_pem();
    bundle.push(b'\n');
    bundle.extend_from_slice(&rcgen_pem());
    let tls = TlsOverrides {
        extra_roots: vec![
            TaggedRoot {
                pem_bytes: rcgen_pem(),
                source: "a".into(),
                line: 1,
            },
            TaggedRoot {
                pem_bytes: rcgen_pem(),
                source: "b".into(),
                line: 2,
            },
        ],
        ..Default::default()
    };
    let client = RegistryClient::new()
        .with_tls_overrides_for(&tls, &[])
        .expect("build ok");
    let summary = client.render_effective_tls_summary().expect("summary");
    assert!(
        summary.contains("2 extra root certificates"),
        "got: {summary}"
    );
}

#[test]
fn render_effective_tls_summary_omits_unreached_per_origin_overrides() {
    let pem = rcgen_pem();
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &pem).unwrap();
    // Configure per-origin TLS for `unused.internal`...
    let unused = OriginKey {
        host_lower: "unused.internal".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        unused,
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![crate::npmrc::TaggedPath {
                path: ca_path,
                source: "test".into(),
                line: 1,
                source_dir: None,
            }],
            certfile: None,
            keyfile: None,
        },
    );
    let tls = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    // ...but pass empty eager_origins (effective set is empty).
    let client = RegistryClient::new()
        .with_tls_overrides_for(&tls, &[])
        .expect("build ok");
    // Nothing was eager-built and no global surface → None.
    assert!(
        client.render_effective_tls_summary().is_none(),
        "configured-but-unreached origin must not appear in summary"
    );
}

#[test]
fn render_effective_tls_summary_lists_eager_per_origin_clients() {
    let pem = rcgen_pem();
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &pem).unwrap();
    let origin = OriginKey {
        host_lower: "corp.internal".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin.clone(),
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![crate::npmrc::TaggedPath {
                path: ca_path,
                source: "test".into(),
                line: 1,
                source_dir: None,
            }],
            certfile: None,
            keyfile: None,
        },
    );
    let tls = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    let client = RegistryClient::new()
        .with_tls_overrides_for(&tls, std::slice::from_ref(&origin))
        .expect("build ok");
    let summary = client.render_effective_tls_summary().expect("summary");
    assert!(
        summary.contains("per-origin TLS for //corp.internal/"),
        "got: {summary}"
    );
}

#[test]
fn with_tls_overrides_for_eager_builds_only_supplied_origins() {
    // Two origins configured; we'll only ask for one.
    let pem = rcgen_pem();
    let dir = tempfile::tempdir().unwrap();
    let ca1 = dir.path().join("ca1.pem");
    let ca2 = dir.path().join("ca2.pem");
    std::fs::write(&ca1, &pem).unwrap();
    std::fs::write(&ca2, &pem).unwrap();
    let origin1 = OriginKey {
        host_lower: "wanted.internal".into(),
        port: None,
    };
    let origin2 = OriginKey {
        host_lower: "ignored.internal".into(),
        port: None,
    };
    let mut per_origin_map = HashMap::new();
    per_origin_map.insert(
        origin1.clone(),
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![crate::npmrc::TaggedPath {
                path: ca1,
                source: "test".into(),
                line: 1,
                source_dir: None,
            }],
            certfile: None,
            keyfile: None,
        },
    );
    per_origin_map.insert(
        origin2.clone(),
        crate::npmrc::OriginTlsOverrides {
            cafiles: vec![crate::npmrc::TaggedPath {
                path: ca2,
                source: "test".into(),
                line: 2,
                source_dir: None,
            }],
            certfile: None,
            keyfile: None,
        },
    );
    let tls = TlsOverrides {
        per_origin: per_origin_map,
        ..Default::default()
    };
    let client = RegistryClient::new()
        .with_tls_overrides_for(&tls, std::slice::from_ref(&origin1))
        .expect("eager build ok");
    // Only origin1 was eager-built.
    assert!(client.http.eager.contains_key(&origin1));
    assert!(!client.http.eager.contains_key(&origin2));
}

#[tokio::test]
async fn cross_host_redirect_strips_authorization_header() {
    use wiremock::matchers::{header_exists, method, path as match_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::{Request, Respond};

    // Server B captures whatever the client sends after the redirect.
    let server_b = MockServer::start().await;

    // A 302 from A to B is built dynamically so the redirect target
    // matches whatever ephemeral port the test runtime picked.
    struct RedirectTo(String);
    impl Respond for RedirectTo {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            ResponseTemplate::new(302).append_header("Location", self.0.as_str())
        }
    }

    let server_a = MockServer::start().await;
    let b_target = format!("{}/landing", server_b.uri());
    Mock::given(method("GET"))
        .and(match_path("/hop"))
        .respond_with(RedirectTo(b_target))
        .expect(1)
        .mount(&server_a)
        .await;

    // Server B: any GET to `/landing` must NOT carry an
    // `Authorization` header. `header_exists` is the negative
    // matcher — by asserting an `expect(0)` mock on this shape
    // we'd silently pass even if no request arrived, so we set
    // up TWO mocks and let the harness count.
    let bearer_hit = Mock::given(method("GET"))
        .and(match_path("/landing"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
        .expect(0)
        .named("authorization-should-NOT-leak");
    let clean_hit = Mock::given(method("GET"))
        .and(match_path("/landing"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .named("post-redirect-request-without-authorization");
    server_b.register(bearer_hit).await;
    server_b.register(clean_hit).await;

    let client = RegistryClient::build_http_client_with_tls(
        CONNECT_TIMEOUT,
        READ_TIMEOUT,
        &TlsOverrides::default(),
    )
    .expect("default TLS config builds");

    let body = client
        .get(format!("{}/hop", server_a.uri()))
        .bearer_auth("secret-bearer-token")
        .send()
        .await
        .expect("redirect chain should resolve")
        .text()
        .await
        .expect("body");
    assert_eq!(
        body, "OK",
        "post-redirect response must come from the no-auth mock; got {body:?}"
    );

    // wiremock asserts `expect(N)` counts on Drop; force the check
    // explicitly so the failure mode is loud and immediate.
    server_a.verify().await;
    server_b.verify().await;
}
