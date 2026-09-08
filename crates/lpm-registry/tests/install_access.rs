use lpm_registry::{ManagedInstallRoot, RegistryClient};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test]
async fn install_access_batches_unique_versions_and_requires_complete_decisions() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/install-check"))
        .respond_with(|request: &wiremock::Request| {
            assert_eq!(
                request.headers.get("authorization").unwrap(),
                "Bearer lpm_test"
            );
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let packages: Vec<_> = body["packages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| json!({"name":item["name"], "version":item["version"], "allowed":true}))
                .collect();
            assert!(packages.len() <= 200);
            ResponseTemplate::new(200).set_body_json(json!({"packages":packages}))
        })
        .expect(2)
        .mount(&server)
        .await;
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("lpm_test");
    let mut packages: Vec<_> = (0..201)
        .map(|n| ManagedInstallRoot::new(format!("@lpm.dev/test.package-{n}"), "1.0.0"))
        .collect();
    packages.extend(packages.clone());
    assert!(
        client
            .check_install_access(&packages)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(client.check_install_access(&[]).await.unwrap().is_empty());
}

#[tokio::test]
async fn install_access_fails_closed_on_missing_duplicate_mismatched_and_malformed_decisions() {
    let package = ManagedInstallRoot::new("@lpm.dev/test.package", "1.0.0");
    let allowed = json!({"name":package.name,"version":package.version,"allowed":true});
    for response in [
        json!({"packages":[]}),
        json!({"packages":[allowed.clone(),allowed.clone()]}),
        json!({"packages":[{"name":package.name,"version":"2.0.0","allowed":true}]}),
        json!({"packages":[{"name":package.name,"version":package.version}]}),
        json!({"packages":[{"name":package.name,"version":package.version,"allowed":"true"}]}),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/registry/install-check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let client = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("lpm_test");
        assert!(
            client
                .check_install_access(std::slice::from_ref(&package))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn install_access_does_not_treat_an_unavailable_endpoint_as_permission() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/install-check"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error":"Not found"})))
        .mount(&server)
        .await;
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("lpm_test");
    assert!(
        client
            .check_install_access(&[ManagedInstallRoot::new("@lpm.dev/test.package", "1.0.0")])
            .await
            .is_err()
    );
}
