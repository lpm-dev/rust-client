use super::*;

fn graph_of_roots(roots: &[ManagedInstallRoot]) -> ManagedInstallGraph {
    let mut roots = roots.to_vec();
    roots.sort_unstable();
    roots.dedup();
    ManagedInstallGraph {
        roots: (0..roots.len()).collect(),
        nodes: roots
            .into_iter()
            .map(|root| ManagedInstallNode {
                name: root.name,
                version: root.version,
                dependencies: Vec::new(),
            })
            .collect(),
    }
}

#[tokio::test]
async fn report_managed_pool_install_posts_authenticated_graph_without_depth() {
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let expected_body = serde_json::json!({ "graph": { "roots": [0,1], "nodes": [
        { "name": "@lpm.dev/alice.alpha", "version": "1.0.0", "dependencies": [] },
        { "name": "@lpm.dev/carol.charlie", "version": "3.0.0", "dependencies": [] }
    ] } });
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
        .report_managed_pool_install(&graph_of_roots(&roots), ManagedInstallAccounting)
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
        .report_managed_pool_install(&ManagedInstallGraph::default(), ManagedInstallAccounting)
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
        .report_managed_pool_install(&graph_of_roots(&roots), ManagedInstallAccounting)
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
        .report_managed_pool_install(&graph_of_roots(&roots), ManagedInstallAccounting)
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
        .report_managed_pool_install(&graph_of_roots(&roots), ManagedInstallAccounting)
        .await
        .expect("first report should succeed");
    client
        .report_managed_pool_install(&graph_of_roots(&roots), ManagedInstallAccounting)
        .await
        .expect("repeated report should succeed");

    let requests = server.received_requests().await.expect("received requests");
    assert_eq!(requests[0].body, requests[1].body);
}

#[tokio::test]
async fn report_managed_pool_install_sends_one_atomic_graph_without_chunking() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/pool/install-report"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
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
        .report_managed_pool_install(&graph_of_roots(&roots), ManagedInstallAccounting)
        .await
        .expect("bounded accounting chunks should succeed");

    let requests = server.received_requests().await.expect("received requests");
    let chunks = requests
        .iter()
        .map(|request| {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("JSON accounting body");
            body["graph"]["nodes"]
                .as_array()
                .expect("roots array")
                .iter()
                .map(|root| root["name"].as_str().expect("root name").to_string())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), vec![401]);
    assert!(chunks.iter().flatten().map(String::as_str).is_sorted());
}

#[tokio::test]
async fn legacy_pool_reports_cross_npm_bridges_and_bound_root_batches() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/pool/install-report"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            if body.get("graph").is_some() {
                ResponseTemplate::new(400).set_body_json(
                    serde_json::json!({"error":"Request body must contain only a roots array"}),
                )
            } else {
                ResponseTemplate::new(200)
            }
        })
        .expect(4)
        .mount(&server)
        .await;
    let mut graph = ManagedInstallGraph {
        roots: vec![0, 1],
        nodes: vec![ManagedInstallNode {
            name: "npm-bridge".into(),
            version: "1.0.0".into(),
            dependencies: (1..=401).collect(),
        }],
    };
    graph.nodes.extend((0..401).map(|index| ManagedInstallNode {
        name: format!("@lpm.dev/alice.root-{index:03}"),
        version: "1.0.0".into(),
        dependencies: vec![402],
    }));
    graph.nodes.push(ManagedInstallNode {
        name: "@lpm.dev/bob.transitive".into(),
        version: "1.0.0".into(),
        dependencies: vec![],
    });
    RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("test-token")
        .report_managed_pool_install(&graph, ManagedInstallAccounting)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let roots: Vec<Vec<serde_json::Value>> = requests[1..]
        .iter()
        .map(|r| {
            serde_json::from_slice::<serde_json::Value>(&r.body).unwrap()["roots"]
                .as_array()
                .unwrap()
                .clone()
        })
        .collect();
    assert_eq!(
        roots.iter().map(Vec::len).collect::<Vec<_>>(),
        [200, 200, 1]
    );
    assert!(roots.iter().flatten().all(|root| {
        root["name"]
            .as_str()
            .unwrap()
            .starts_with("@lpm.dev/alice.root-")
    }));
    assert!(
        roots
            .iter()
            .flatten()
            .map(|root| root["name"].as_str().unwrap())
            .is_sorted()
    );
}

#[tokio::test]
async fn pool_reports_do_not_downgrade_unrelated_rejections() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    for (status, message) in [
        (400, "Invalid graph"),
        (403, "Request body must contain only a roots array"),
        (404, "Not found"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/registry/pool/install-report"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({"error":message})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let graph = graph_of_roots(&[ManagedInstallRoot::new("@lpm.dev/alice.root", "1.0.0")]);
        assert!(
            RegistryClient::new()
                .with_base_url(server.uri())
                .with_token("test-token")
                .report_managed_pool_install(&graph, ManagedInstallAccounting)
                .await
                .is_err()
        );
    }
}
