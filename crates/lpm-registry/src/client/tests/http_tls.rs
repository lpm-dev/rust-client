use super::*;

fn lazy_cells(
    tls: &TlsOverrides,
) -> HashMap<OriginKey, tokio::sync::OnceCell<Result<CachedClient, Arc<str>>>> {
    tls.per_origin
        .keys()
        .map(|origin| (origin.clone(), tokio::sync::OnceCell::new()))
        .collect()
}

fn lazy_identity_certs(tls: &TlsOverrides) -> HashMap<OriginKey, LazyIdentityCert> {
    tls.per_origin
        .iter()
        .filter_map(|(origin, overrides)| {
            overrides.certfile.as_ref().map(|certfile| {
                (
                    origin.clone(),
                    LazyIdentityCert {
                        certfile: certfile.clone(),
                        material: std::sync::OnceLock::new(),
                    },
                )
            })
        })
        .collect()
}

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
            pem_bytes: pem.into(),
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
fn unreached_per_origin_identity_certificates_are_not_read_eagerly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("large-cert.pem");
    let mut bytes = vec![b'A'; lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES as usize];
    let marker = b"-----BEGIN CERTIFICATE-----";
    bytes[..marker.len()].copy_from_slice(marker);
    std::fs::write(&cert_path, bytes).expect("write certificate fixture");

    let mut per_origin = HashMap::new();
    for index in 0..17 {
        per_origin.insert(
            OriginKey {
                host_lower: format!("registry-{index}.example.test"),
                port: None,
            },
            crate::npmrc::OriginTlsOverrides {
                cafiles: Vec::new(),
                certfile: Some(crate::npmrc::TaggedPath {
                    path: cert_path.clone(),
                    source: "test".to_string(),
                    line: index + 1,
                    source_dir: None,
                }),
                keyfile: None,
            },
        );
    }
    let tls = TlsOverrides {
        per_origin,
        ..TlsOverrides::default()
    };

    RegistryClient::new()
        .with_tls_overrides_for(&tls, &[])
        .expect("unreached identity certificates must stay lazy");
}

#[test]
fn eager_per_origin_tls_client_sets_are_bounded_before_file_reads() {
    let mut per_origin = HashMap::new();
    let mut eager_origins = Vec::new();
    for index in 0..65 {
        let origin = OriginKey {
            host_lower: format!("registry-{index}.example.test"),
            port: None,
        };
        eager_origins.push(origin.clone());
        per_origin.insert(
            origin,
            OriginTlsOverrides {
                cafiles: vec![TaggedPath {
                    path: format!("missing-{index}.pem").into(),
                    source: "test".into(),
                    line: index + 1,
                    source_dir: None,
                }],
                ..OriginTlsOverrides::default()
            },
        );
    }
    let tls = TlsOverrides {
        per_origin,
        ..TlsOverrides::default()
    };

    let error = match RegistryClient::new().with_tls_overrides_for(&tls, &eager_origins) {
        Ok(_) => panic!("per-origin HTTP client sets must be bounded"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("64"), "{error}");
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
            pem_bytes: no_marker.into(),
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
            pem_bytes: pem.into(),
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
        lazy: HashMap::new(),
        built_client_sets: std::sync::atomic::AtomicUsize::new(1),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
        per_origin_identity_certs: HashMap::new(),
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
    Mock::given(method("GET"))
        .and(path("/capture"))
        .and(header("x-manual-origin", "target"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&target)
        .await;
    let source = MockServer::start().await;
    Mock::given(method("GET"))
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
        lazy: HashMap::new(),
        built_client_sets: std::sync::atomic::AtomicUsize::new(2),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
        per_origin_identity_certs: HashMap::new(),
    };
    let request = reqwest::Request::new(
        reqwest::Method::GET,
        reqwest::Url::parse(&format!("{}/initial", source.uri())).unwrap(),
    );

    let response = lpm_http::send_with_replayable_redirects(&clients, request, None)
        .await
        .expect("redirect should use each origin's manual client");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn retry_transport_reselects_origin_specific_clients_across_redirects() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cached_for_origin(origin: &'static str) -> CachedClient {
        let headers = reqwest::header::HeaderMap::from_iter([(
            reqwest::header::HeaderName::from_static("x-selected-origin"),
            reqwest::header::HeaderValue::from_static(origin),
        )]);
        let automatic = reqwest::Client::builder()
            .default_headers(headers.clone())
            .build()
            .expect("automatic client");
        let manual = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .build()
            .expect("manual client");
        CachedClient {
            client: automatic.clone(),
            policy_metadata_client: automatic,
            manual_redirect_client: manual,
            identity_fp: None,
        }
    }

    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/landing"))
        .and(header("x-selected-origin", "target"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&target)
        .await;
    let source = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hop"))
        .and(header("x-selected-origin", "source"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/landing", target.uri())),
        )
        .expect(1)
        .mount(&source)
        .await;

    let mut eager = HashMap::new();
    eager.insert(
        OriginKey::from_request_url(&source.uri()).unwrap(),
        cached_for_origin("source"),
    );
    eager.insert(
        OriginKey::from_request_url(&target.uri()).unwrap(),
        cached_for_origin("target"),
    );
    let http = Arc::new(HttpClients {
        default: cached(reqwest::Client::new()),
        eager,
        lazy: HashMap::new(),
        built_client_sets: std::sync::atomic::AtomicUsize::new(2),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
        per_origin_identity_certs: HashMap::new(),
    });
    let mut client = RegistryClient::new();
    client.http = http;
    let request = reqwest::Request::new(
        reqwest::Method::GET,
        reqwest::Url::parse(&format!("{}/hop", source.uri())).unwrap(),
    );

    let response = client
        .send_request_with_retry_and_npmrc_auth(request, None, None)
        .await
        .expect("redirect must reselect the target origin client");
    assert_eq!(response.text().await.unwrap(), "ok");
}

#[test]
fn http_clients_eager_portless_scope_excludes_explicit_non_default_ports() {
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
        lazy: HashMap::new(),
        built_client_sets: std::sync::atomic::AtomicUsize::new(1),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
        per_origin_identity_certs: HashMap::new(),
    });
    let mut client = RegistryClient::new();
    client.http = http;
    let picked_443 = client.http.for_url_no_build("https://host.internal/foo");
    let picked_8443 = client
        .http
        .for_url_no_build("https://host.internal:8443/bar");
    let stored = &client.http.eager.get(&key_no_port).unwrap().client;
    assert!(std::ptr::eq(picked_443, stored));
    assert!(std::ptr::eq(picked_8443, &client.http.default.client));
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
        lazy: lazy_cells(&tls),
        built_client_sets: std::sync::atomic::AtomicUsize::new(0),
        tls_overrides: Arc::new(tls),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
        per_origin_identity_certs: HashMap::new(),
    });
    // First call must build + insert.
    let c1 = http.for_url("https://lazy.internal/pkg").await.expect("ok");
    // Second call must hit the lazy cache (not rebuild).
    let c2 = http
        .for_url("https://lazy.internal/other")
        .await
        .expect("ok");
    let map = &http.lazy;
    assert_eq!(map.len(), 1, "lazy map must contain exactly one entry");
    assert!(
        map.contains_key(&origin),
        "lazy entry must be keyed by the portless request origin (got keys: {:?})",
        map.keys().map(|k| k.to_string()).collect::<Vec<_>>()
    );
    assert!(map[&origin].get().is_some(), "lazy client was not cached");
    // Sanity: both returned clients are usable Client values.
    let _ = (c1, c2);
}

#[tokio::test]
async fn unrelated_origins_bypass_a_busy_lazy_tls_builder() {
    let configured_origin = OriginKey {
        host_lower: "configured.internal".into(),
        port: None,
    };
    let mut per_origin = HashMap::new();
    per_origin.insert(
        configured_origin.clone(),
        OriginTlsOverrides {
            cafiles: vec![TaggedPath {
                path: "unused.pem".into(),
                source: "test".into(),
                line: 1,
                source_dir: None,
            }],
            ..OriginTlsOverrides::default()
        },
    );
    let tls = TlsOverrides {
        per_origin,
        ..TlsOverrides::default()
    };
    let clients = Arc::new(HttpClients {
        default: cached(reqwest::Client::new()),
        eager: HashMap::new(),
        lazy: lazy_cells(&tls),
        built_client_sets: std::sync::atomic::AtomicUsize::new(0),
        tls_overrides: Arc::new(tls),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
        per_origin_identity_certs: HashMap::new(),
    });
    let blocked_clients = Arc::clone(&clients);
    let blocked_origin = configured_origin.clone();
    let blocked = tokio::spawn(async move {
        let _ = blocked_clients.lazy[&blocked_origin]
            .get_or_init(std::future::pending)
            .await;
    });
    tokio::task::yield_now().await;

    let result = tokio::time::timeout(
        Duration::from_millis(50),
        clients.for_url("https://unrelated.internal/pkg"),
    )
    .await;

    blocked.abort();
    assert!(
        result.is_ok(),
        "an unrelated origin waited on the TLS build mutex"
    );
}

#[tokio::test]
async fn http_clients_no_per_origin_tls_falls_through_to_default() {
    let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
    let http = Arc::new(HttpClients {
        default: cached(default.clone()),
        eager: HashMap::new(),
        lazy: HashMap::new(),
        built_client_sets: std::sync::atomic::AtomicUsize::new(0),
        tls_overrides: Arc::new(TlsOverrides::default()),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
        per_origin_identity_certs: HashMap::new(),
    });
    let _ = http
        .for_url("https://anywhere.example/foo")
        .await
        .expect("ok");
    // Lazy map must remain empty (no per-origin TLS to build).
    assert!(http.lazy.is_empty());
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
        lazy: lazy_cells(&tls),
        built_client_sets: std::sync::atomic::AtomicUsize::new(0),
        per_origin_identity_certs: lazy_identity_certs(&tls),
        tls_overrides: Arc::new(tls),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
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
        lazy: lazy_cells(&tls),
        built_client_sets: std::sync::atomic::AtomicUsize::new(0),
        per_origin_identity_certs: lazy_identity_certs(&tls),
        tls_overrides: Arc::new(tls),
        passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
        global_identity: None,
        tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
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
    // Verify: lazy map now contains the portless request origin.
    let lazy = &client.http.lazy;
    assert_eq!(
        lazy.len(),
        1,
        "lazy map must be populated by production tarball path; got: {:?}",
        lazy.keys().map(|k| k.to_string()).collect::<Vec<_>>()
    );
    assert!(
        lazy.contains_key(&origin),
        "lazy entry must be keyed by URL's portless origin"
    );
    assert!(
        lazy[&origin].get().is_some_and(Result::is_ok),
        "lazy client build was not cached"
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
    use crate::npmrc::{AuthScope, OriginKey, RegistryAuth};
    let bearer_a = RegistryAuth::Bearer {
        scope: AuthScope::from_origin(OriginKey {
            host_lower: "x".into(),
            port: None,
        }),
        token: SecretString::from("token-a".to_string()),
    };
    let bearer_b = RegistryAuth::Bearer {
        scope: AuthScope::from_origin(OriginKey {
            host_lower: "x".into(),
            port: None,
        }),
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
    use crate::npmrc::{AuthScope, OriginKey, RegistryAuth};
    let bearer = RegistryAuth::Bearer {
        scope: AuthScope::from_origin(OriginKey {
            host_lower: "x".into(),
            port: None,
        }),
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
fn tls_material_reads_respect_remaining_aggregate_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root.pem");
    std::fs::write(&path, b"12345").unwrap();
    let budget = TlsMaterialBudget::new_with_retained_source(
        0,
        lpm_common::TLS_MATERIAL_AGGREGATE_CAP_BYTES - 4,
    )
    .unwrap();

    let error = match budget.read_material(&path, "test TLS material") {
        Ok(_) => panic!("a file larger than the remaining budget must be refused"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("aggregate limit"), "{error}");
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

#[tokio::test]
async fn unreadable_lazy_identity_cannot_use_the_default_cache_namespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let origin = OriginKey {
        host_lower: "lazy.internal".into(),
        port: None,
    };
    let mut per_origin = HashMap::new();
    per_origin.insert(
        origin,
        crate::npmrc::OriginTlsOverrides {
            cafiles: Vec::new(),
            certfile: Some(crate::npmrc::TaggedPath {
                path: dir.path().join("missing-cert.pem"),
                source: "user:.npmrc".into(),
                line: 7,
                source_dir: None,
            }),
            keyfile: Some(crate::npmrc::TaggedPath {
                path: dir.path().join("missing-key.pem"),
                source: "user:.npmrc".into(),
                line: 8,
                source_dir: None,
            }),
        },
    );
    let client = RegistryClient::new()
        .with_tls_overrides_for(
            &TlsOverrides {
                per_origin,
                ..TlsOverrides::default()
            },
            &[],
        )
        .expect("unreached lazy identity failures stay deferred");

    assert_eq!(
        client
            .http
            .identity_fp_for_url("https://lazy.internal/package"),
        Some("identity-unavailable")
    );
    let error = client
        .http
        .for_url("https://lazy.internal/package")
        .await
        .expect_err("targeting an unreadable identity must fail before dispatch");
    assert!(error.to_string().contains("user:.npmrc:7"));
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
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
            pem_bytes: pem.into(),
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
                pem_bytes: rcgen_pem().into(),
                source: "a".into(),
                line: 1,
            },
            TaggedRoot {
                pem_bytes: rcgen_pem().into(),
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
