use super::*;
use support::lpm_with_registry_and_npm;

async fn mount_metadata(
    mock: &MockRegistry,
    name: &str,
    dependencies: serde_json::Value,
    peers: serde_json::Value,
    optional_peers: serde_json::Value,
) {
    let metadata = serde_json::json!({
        "name":name, "dist-tags":{"latest":"1.0.0"},
        "versions":{"1.0.0":{"name":name,"version":"1.0.0", "dependencies":dependencies,
            "peerDependencies":peers, "peerDependenciesMeta":optional_peers,
            "dist":{"tarball":mock.tarball_url(name,"1.0.0"),"integrity":compute_integrity(b"unused")}}}
    });
    mock.with_package_metadata_and_tarballs(name, metadata, &[])
        .await;
}

#[tokio::test]
async fn conflicting_duplicate_roots_fail_before_registry_requests() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "pkg",
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "pkg@^2", "pkg@^1", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "conflicting root ranges must fail instead of selecting the last"
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        requests.is_empty(),
        "root validation must precede metadata requests: {requests:?}"
    );
}

#[tokio::test]
async fn identical_duplicate_roots_coalesce_bare_and_wildcard_specs() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "pkg",
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "pkg", "pkg@*", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["count"], 1);
}

#[tokio::test]
async fn versioned_root_alias_keeps_its_local_name_and_exact_target() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "pkg",
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "local@npm:pkg@^1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("local → pkg@1.0.0"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn resolve_json_preserves_roots_aliases_and_exact_edges_without_installing() {
    let project =
        TempProject::empty(r#"{"name":"root","version":"1.0.0","dependencies":{"unrelated":"1"}}"#);
    let manifest = project.read_file("package.json");
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "pkg",
        serde_json::json!({"local":"npm:child@^1"}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    mount_metadata(
        &mock,
        "child",
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "pkg", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let nodes = json["packages"].as_array().unwrap();
    let root = nodes.iter().find(|p| p["package"] == "pkg").unwrap();
    let child = nodes.iter().find(|p| p["package"] == "child").unwrap();
    assert!(root["id"].is_u64(), "exact identities are required: {json}");
    assert_eq!(root["dependencies"]["local"], child["id"]);
    assert_eq!(json["roots"][0]["name"], "pkg");
    assert_eq!(json["roots"][0]["target"], root["id"]);
    assert_eq!(project.read_file("package.json"), manifest);
    assert!(!project.file_exists("lpm.lock"));
    assert!(!project.file_exists("node_modules"));
    assert_eq!(mock.tarball_request_count("pkg", "1.0.0").await, 0);
}

#[tokio::test]
async fn optional_peer_is_quiet_when_absent_but_reported_when_present_and_incompatible() {
    for present in [false, true] {
        let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        mount_metadata(
            &mock,
            "plugin",
            serde_json::json!({}),
            serde_json::json!({"host":"^2"}),
            serde_json::json!({"host":{"optional":true}}),
        )
        .await;
        mount_metadata(
            &mock,
            "host",
            serde_json::json!({}),
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .await;
        let mut command = lpm_with_registry_and_npm(&project, &mock.url());
        command.args(["resolve", "plugin", "--json"]);
        if present {
            command.arg("host");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            json["peer_issues"]["bad_count"],
            usize::from(present),
            "{json}"
        );
        assert_eq!(json["peer_issues"]["missing_count"], 0, "{json}");
        if present {
            assert_eq!(json["peer_issues"]["bad"][0]["peer"], "host");
        }
    }
}

#[tokio::test]
async fn shared_dependency_dag_is_expanded_once_in_human_output() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    for depth in 0..10 {
        let deps = if depth == 9 {
            serde_json::json!({})
        } else {
            serde_json::json!({format!("a{}",depth+1):"1",format!("b{}",depth+1):"1"})
        };
        for side in ["a", "b"] {
            mount_metadata(
                &mock,
                &format!("{side}{depth}"),
                deps.clone(),
                serde_json::json!({}),
                serde_json::json!({}),
            )
            .await;
        }
    }
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "a0", "b0"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.lines().count() < 100,
        "shared nodes must not expand exponentially: {} lines",
        text.lines().count()
    );
    assert!(text.contains("(shared)"), "{text}");
}

#[tokio::test]
async fn root_alias_configures_tls_for_its_target_instead_of_the_local_scope() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "pkg",
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    std::fs::write(
        project.home().join(".npmrc"),
        format!(
            "@unused:registry=https://unused.invalid\n//unused.invalid/:cafile={}\n",
            project.path().join("missing-ca.pem").display()
        ),
    )
    .unwrap();
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "@unused/alias@npm:pkg", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn resolve_human_output_reports_optional_peer_version_mismatch() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "plugin",
        serde_json::json!({}),
        serde_json::json!({"host":"^2"}),
        serde_json::json!({"host":{"optional":true}}),
    )
    .await;
    mount_metadata(
        &mock,
        "host",
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "plugin", "host"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("requires peer host (^2), but host@1.0.0 was resolved"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn pubgrub_reports_missing_required_peer_without_changing_exit_status() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "plugin",
        serde_json::json!({}),
        serde_json::json!({"host":"^1"}),
        serde_json::json!({}),
    )
    .await;
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .env("LPM_RESOLVER", "pubgrub")
        .args(["resolve", "plugin", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["peer_issues"]["missing_count"], 1, "{json}");
    assert_eq!(json["peer_issues"]["missing"][0]["peer"], "host");
}

#[tokio::test]
async fn canonical_json_names_do_not_include_pubgrub_root_alias_context() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "pkg",
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .env("LPM_RESOLVER", "pubgrub")
        .args(["resolve", "local@npm:pkg", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["packages"][0]["package"], "pkg", "{json}");
}

#[tokio::test]
async fn resolve_reports_best_effort_peer_conflicts_and_exact_peer_targets() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    for (name, range) in [("consumer-a", "^1"), ("consumer-b", "^2")] {
        mount_metadata(
            &mock,
            name,
            serde_json::json!({}),
            serde_json::json!({"host":range}),
            serde_json::json!({}),
        )
        .await;
    }
    mock.with_full_package_metadata(
        "host",
        "2.0.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("host", "1.0.0")),
            ),
            (
                "2.0.0",
                serde_json::json!({}),
                Some(make_tarball("host", "2.0.0")),
            ),
        ],
    )
    .await;
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "consumer-a", "consumer-b", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["peer_issues"]["conflicts_count"], 1, "{json}");
    assert_eq!(json["peer_issues"]["bad_count"], 1, "{json}");
    assert_eq!(json["roots"].as_array().unwrap().len(), 2);
    let nodes = json["packages"].as_array().unwrap();
    let provider = nodes
        .iter()
        .find(|p| p["package"] == "host" && p["version"] == "2.0.0")
        .unwrap();
    let consumer = nodes.iter().find(|p| p["package"] == "consumer-b").unwrap();
    assert_eq!(consumer["peers"]["host"], provider["id"]);
    for node in nodes {
        for kind in ["dependencies", "peers"] {
            for target in node[kind].as_object().unwrap().values() {
                assert!(nodes.iter().any(|p| p["id"] == *target));
            }
        }
    }
}

#[tokio::test]
async fn resolve_preserves_fatal_peer_conflict_error_details() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_metadata(
        &mock,
        "plugin",
        serde_json::json!({}),
        serde_json::json!({"host":"^99"}),
        serde_json::json!({}),
    )
    .await;
    mount_metadata(
        &mock,
        "host",
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await;
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["resolve", "plugin", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["error_code"], "resolution_failed");
    assert_eq!(json["error"]["kind"], "peer_conflict");
    assert_eq!(json["error"]["package"], "host");
}

#[tokio::test]
async fn resolve_roots_preserve_argument_order_and_coalesce_scoped_duplicates() {
    let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    for name in ["@scope/second", "@scope/first"] {
        mount_metadata(
            &mock,
            name,
            serde_json::json!({}),
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .await;
    }
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args([
            "resolve",
            "@scope/second",
            "@scope/first",
            "@scope/second@*",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let roots = json["roots"].as_array().unwrap();
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0]["name"], "@scope/second");
    assert_eq!(roots[1]["name"], "@scope/first");
}

#[tokio::test]
async fn wildcard_prerelease_selection_follows_the_active_resolver() {
    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "pkg",
        "2.0.0-beta.1",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("pkg", "1.0.0")),
            ),
            (
                "2.0.0-beta.1",
                serde_json::json!({}),
                Some(make_tarball("pkg", "2.0.0-beta.1")),
            ),
        ],
    )
    .await;
    for (mode, expected) in [("greedy-fusion", "1.0.0"), ("pubgrub", "2.0.0-beta.1")] {
        let project = TempProject::empty(r#"{"name":"root","version":"1.0.0"}"#);
        let output = lpm_with_registry_and_npm(&project, &mock.url())
            .env("LPM_RESOLVER", mode)
            .args(["resolve", "pkg", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["packages"][0]["version"], expected, "{mode}: {json}");
    }
}
