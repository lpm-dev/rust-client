use super::*;

fn accounting_package(
    name: &str,
    version: &str,
    is_direct: bool,
    is_lpm: bool,
    dependencies: &[(&str, &str)],
) -> InstallPackage {
    let mut package = fake_pkg(name, version, is_direct);
    package.is_lpm = is_lpm;
    package.dependencies = dependencies
        .iter()
        .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
        .collect();
    package
}

fn root_names(packages: &[InstallPackage]) -> Vec<String> {
    let graph = build_managed_install_graph(packages);
    graph
        .roots
        .iter()
        .map(|index| {
            let root = &graph.nodes[*index];
            format!("{}@{}", root.name, root.version)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[test]
fn npm_only_graph_has_no_pool_accounting_roots() {
    let root = accounting_package("npm-root", "1.0.0", true, false, &[("npm-child", "2.0.0")]);
    let child = accounting_package("npm-child", "2.0.0", false, false, &[]);

    assert!(build_managed_install_graph(&[root, child]).nodes.is_empty());
}

#[test]
fn direct_lpm_package_is_an_accounting_root() {
    let alpha = accounting_package("@lpm.dev/alice.alpha", "1.0.0", true, true, &[]);

    assert_eq!(root_names(&[alpha]), vec!["@lpm.dev/alice.alpha@1.0.0"]);
}

#[test]
fn lpm_descendant_below_direct_lpm_root_is_not_an_additional_root() {
    let alpha = accounting_package(
        "@lpm.dev/alice.alpha",
        "1.0.0",
        true,
        true,
        &[("npm-x", "1.0.0")],
    );
    let npm_x = accounting_package(
        "npm-x",
        "1.0.0",
        false,
        false,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", false, true, &[]);

    assert_eq!(
        root_names(&[beta, npm_x, alpha]),
        vec!["@lpm.dev/alice.alpha@1.0.0"]
    );
}

#[test]
fn non_pool_lpm_root_remains_in_the_reported_graph() {
    let private_root = accounting_package(
        "@lpm.dev/alice.private-root",
        "1.0.0",
        true,
        true,
        &[("@lpm.dev/bob.pool-dependency", "2.0.0")],
    );
    let pool_dependency =
        accounting_package("@lpm.dev/bob.pool-dependency", "2.0.0", false, true, &[]);

    assert_eq!(
        root_names(&[pool_dependency, private_root]),
        vec!["@lpm.dev/alice.private-root@1.0.0"]
    );
}

#[test]
fn npm_root_is_preserved_when_it_reaches_lpm_dependencies() {
    let npm_x = accounting_package(
        "npm-x",
        "1.0.0",
        true,
        false,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", false, true, &[]);

    assert_eq!(root_names(&[beta, npm_x]), vec!["npm-x@1.0.0"]);
}

#[test]
fn multiple_direct_roots_are_sorted_and_deduplicated() {
    let charlie = accounting_package("@lpm.dev/carol.charlie", "3.0.0", true, true, &[]);
    let alpha = accounting_package("@lpm.dev/alice.alpha", "1.0.0", true, true, &[]);
    let alpha_duplicate = accounting_package("@lpm.dev/alice.alpha", "1.0.0", true, true, &[]);

    assert_eq!(
        root_names(&[charlie, alpha_duplicate, alpha]),
        vec!["@lpm.dev/alice.alpha@1.0.0", "@lpm.dev/carol.charlie@3.0.0",]
    );
}

#[test]
fn direct_lpm_root_remains_separate_when_also_covered_by_an_lpm_ancestor() {
    let alpha = accounting_package(
        "@lpm.dev/alice.alpha",
        "1.0.0",
        true,
        true,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", true, true, &[]);

    assert_eq!(
        root_names(&[beta, alpha]),
        vec!["@lpm.dev/alice.alpha@1.0.0", "@lpm.dev/bob.beta@2.0.0",]
    );
}

#[test]
fn direct_npm_and_lpm_roots_are_both_preserved() {
    let alpha = accounting_package(
        "@lpm.dev/alice.alpha",
        "1.0.0",
        true,
        true,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let npm_x = accounting_package(
        "npm-x",
        "1.0.0",
        true,
        false,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", false, true, &[]);

    assert_eq!(
        root_names(&[npm_x, beta, alpha]),
        vec!["@lpm.dev/alice.alpha@1.0.0", "npm-x@1.0.0",]
    );
}

#[test]
fn npm_cycles_are_bounded_while_discovering_lpm_roots() {
    let npm_x = accounting_package("npm-x", "1.0.0", true, false, &[("npm-y", "1.0.0")]);
    let npm_y = accounting_package(
        "npm-y",
        "1.0.0",
        false,
        false,
        &[("npm-x", "1.0.0"), ("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", false, true, &[]);

    assert_eq!(root_names(&[npm_y, beta, npm_x]), vec!["npm-x@1.0.0"]);
}

#[tokio::test]
async fn completed_install_reports_resolved_edges_including_aliases_and_peers() {
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
        .with_token("pool-fixture");
    let mut root = accounting_package(
        "@lpm.dev/alice.a",
        "1.0.0",
        true,
        true,
        &[("npm-middle", "1.0.0")],
    );
    root.peers.push(lpm_common::PeerEdge::registry(
        "peer",
        "@lpm.dev/carol.peer",
        "3.0.0",
    ));
    let mut middle = accounting_package("npm-middle", "1.0.0", false, false, &[("alias", "2.0.0")]);
    middle
        .aliases
        .insert("alias".into(), "@lpm.dev/bob.b".into());
    let child = accounting_package("@lpm.dev/bob.b", "2.0.0", false, true, &[]);
    let peer = accounting_package("@lpm.dev/carol.peer", "3.0.0", false, true, &[]);
    report_pool_install_attribution(
        &client,
        &[root, middle, child, peer],
        ManagedInstallAccounting,
    )
    .await
    .unwrap();
    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let graph = &body["graph"];
    let nodes = graph["nodes"]
        .as_array()
        .expect("the complete installed graph must be reported");
    let by_name = |name: &str| nodes.iter().position(|node| node["name"] == name).unwrap();
    let root_index = by_name("@lpm.dev/alice.a");
    let middle_index = by_name("npm-middle");
    let child_index = by_name("@lpm.dev/bob.b");
    let peer_index = by_name("@lpm.dev/carol.peer");
    assert_eq!(graph["roots"], serde_json::json!([root_index]));
    let mut expected = vec![middle_index, peer_index];
    expected.sort_unstable();
    assert_eq!(
        nodes[root_index]["dependencies"],
        serde_json::json!(expected)
    );
    assert_eq!(
        nodes[middle_index]["dependencies"],
        serde_json::json!([child_index])
    );
    assert_eq!(nodes[child_index]["version"], "2.0.0");
    assert!(nodes.iter().all(|node| node.get("depth").is_none()));
}
