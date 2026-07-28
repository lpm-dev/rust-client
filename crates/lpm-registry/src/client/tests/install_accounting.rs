use super::*;

#[tokio::test]
async fn report_managed_pool_install_posts_authenticated_exact_roots_without_depth() {
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let expected_body = serde_json::json!({
        "roots": [
            {
                "name": "@lpm.dev/alice.alpha",
                "version": "1.0.0",
            },
            {
                "name": "@lpm.dev/carol.charlie",
                "version": "3.0.0",
            },
        ],
    });
    Mock::given(method("POST"))
        .and(path("/api/registry/pool/install-report"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("test-token");
    let roots = vec![
        ManagedInstallRoot::new("@lpm.dev/alice.alpha", "1.0.0"),
        ManagedInstallRoot::new("@lpm.dev/carol.charlie", "3.0.0"),
    ];

    client
        .report_managed_pool_install(&roots, ManagedInstallAccounting)
        .await
        .expect("authenticated accounting report should succeed");
}

#[tokio::test]
async fn report_managed_pool_install_is_a_noop_for_empty_roots() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("test-token");

    client
        .report_managed_pool_install(&[], ManagedInstallAccounting)
        .await
        .expect("empty accounting roots should not require a request");

    assert!(
        server
            .received_requests()
            .await
            .expect("received requests")
            .is_empty()
    );
}

#[tokio::test]
async fn report_managed_pool_install_retries_transient_failures_with_identical_payloads() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct RetryResponder {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for RetryResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).set_body_string("temporary outage")
            } else {
                ResponseTemplate::new(200)
            }
        }
    }

    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/api/registry/pool/install-report"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(RetryResponder {
            calls: Arc::clone(&calls),
        })
        .expect(2)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("test-token");
    let roots = vec![ManagedInstallRoot::new("@lpm.dev/alice.alpha", "1.0.0")];

    client
        .report_managed_pool_install(&roots, ManagedInstallAccounting)
        .await
        .expect("transient accounting failure should be retried");

    let requests = server.received_requests().await.expect("received requests");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(requests[0].body, requests[1].body);
}

#[tokio::test]
async fn report_managed_pool_install_stops_after_the_bounded_retry_budget() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/pool/install-report"))
        .respond_with(ResponseTemplate::new(503).set_body_string("persistent outage"))
        .expect((MAX_RETRIES + 1) as u64)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("test-token");
    let roots = vec![ManagedInstallRoot::new("@lpm.dev/alice.alpha", "1.0.0")];

    let result = client
        .report_managed_pool_install(&roots, ManagedInstallAccounting)
        .await;

    assert!(matches!(result, Err(LpmError::Http { status: 503, .. })));
}

#[tokio::test]
async fn repeated_identical_pool_install_reports_remain_retry_safe() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/pool/install-report"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("test-token");
    let roots = vec![ManagedInstallRoot::new("@lpm.dev/alice.alpha", "1.0.0")];

    client
        .report_managed_pool_install(&roots, ManagedInstallAccounting)
        .await
        .expect("first report should succeed");
    client
        .report_managed_pool_install(&roots, ManagedInstallAccounting)
        .await
        .expect("repeated report should succeed");

    let requests = server.received_requests().await.expect("received requests");
    assert_eq!(requests[0].body, requests[1].body);
}

#[tokio::test]
async fn report_managed_pool_install_sends_deterministic_bounded_chunks() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/pool/install-report"))
        .respond_with(ResponseTemplate::new(200))
        .expect(3)
        .mount(&server)
        .await;

    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("test-token");
    let roots = (0..401)
        .rev()
        .map(|index| ManagedInstallRoot::new(format!("@lpm.dev/alice.package-{index:03}"), "1.0.0"))
        .collect::<Vec<_>>();

    client
        .report_managed_pool_install(&roots, ManagedInstallAccounting)
        .await
        .expect("bounded accounting chunks should succeed");

    let requests = server.received_requests().await.expect("received requests");
    let chunks = requests
        .iter()
        .map(|request| {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("JSON accounting body");
            body["roots"]
                .as_array()
                .expect("roots array")
                .iter()
                .map(|root| root["name"].as_str().expect("root name").to_string())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        chunks.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![200, 200, 1]
    );
    assert!(chunks.iter().flatten().map(String::as_str).is_sorted());
}
