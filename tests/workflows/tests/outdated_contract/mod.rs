use super::*;

async fn mount_contract_metadata(server: &MockServer, name: &str, latest: &str, next: &str) {
    let versions = [
        "1.0.0",
        "1.5.0",
        "1.9.0",
        "2.0.0",
        "2.0.0-beta.1",
        "2.0.0-beta.2",
    ]
    .into_iter()
    .map(|version| {
        (
            version.to_string(),
            serde_json::json!({ "name": name, "version": version }),
        )
    })
    .collect::<serde_json::Map<_, _>>();
    let times = versions
        .keys()
        .map(|version| {
            (
                version.clone(),
                serde_json::json!("2025-01-01T00:00:00.000Z"),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name, "dist-tags": { "latest": latest, "next": next }, "versions": versions, "time": times,
        })))
        .expect(1)
        .mount(server).await;
}

async fn check_latest_declaration(alias: bool, catalog: bool) {
    let name = "@lpm.dev/owner.latest-contract";
    let local = if alias { "alias" } else { name };
    let spec = if alias {
        format!("npm:{name}@latest")
    } else {
        "latest".to_string()
    };
    let mut manifest = serde_json::json!({ "name": "outdated-latest", "dependencies": { (local): if catalog { "catalog:" } else { &spec } } });
    if catalog {
        manifest["catalogs"] = serde_json::json!({ "default": { (local): spec } });
    }
    let project = TempProject::empty(&manifest.to_string());
    let mut lock = lpm_lockfile::Lockfile::new();
    if alias {
        lock.root_aliases
            .insert(local.to_string(), name.to_string());
    }
    lock.add_package(lpm_lockfile::LockedPackage {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://lpm.dev".to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lock, &[(local, name, "1.0.0")]);
    lock.write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    let server = MockServer::start().await;
    mount_contract_metadata(&server, name, "1.5.0", "2.0.0").await;
    let out = lpm_with_registry_and_npm(&project, &server.uri())
        .args(["outdated", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["packages"][0]["wanted"], "1.5.0", "{json}");
    assert_eq!(
        json["packages"][0]["wanted_range"],
        if catalog { "catalog:" } else { &spec }
    );
}

#[tokio::test]
async fn outdated_preserves_latest_tag_for_direct_dependencies() {
    check_latest_declaration(false, false).await;
}
#[tokio::test]
async fn outdated_preserves_latest_tag_for_aliases() {
    check_latest_declaration(true, false).await;
}
#[tokio::test]
async fn outdated_preserves_latest_tag_from_catalogs() {
    check_latest_declaration(false, true).await;
}
#[tokio::test]
async fn outdated_preserves_latest_tag_for_catalog_aliases() {
    check_latest_declaration(true, true).await;
}

async fn check_newer_wanted(current: &str, next: &str) {
    let name = "@lpm.dev/owner.next-contract";
    let project = TempProject::empty(
        &serde_json::json!({ "name": "outdated-next", "dependencies": { (name): "next" } })
            .to_string(),
    );
    write_minimal_lockfile(&project, name, current);
    let server = MockServer::start().await;
    mount_contract_metadata(&server, name, "1.9.0", next).await;
    let out = lpm_with_registry_and_npm(&project, &server.uri())
        .args(["outdated", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["packages"][0]["wanted"], next, "{json}");
    assert_eq!(json["outdated_count"], 1, "{json}");
    assert_eq!(json["packages"][0]["outdated"], true, "{json}");
}
#[tokio::test]
async fn outdated_reports_newer_prerelease_wanted_above_latest() {
    check_newer_wanted("2.0.0-beta.1", "2.0.0-beta.2").await;
}
#[tokio::test]
async fn outdated_reports_newer_named_tag_when_latest_is_unchanged() {
    check_newer_wanted("1.9.0", "2.0.0").await;
}

async fn check_revalidation(route: &str) {
    let name = if route == "lpm" {
        "@lpm.dev/owner.fresh-outdated"
    } else {
        "fresh-outdated"
    };
    let project = TempProject::empty(
        &serde_json::json!({ "name": "outdated-fresh", "dependencies": { (name): "^1.0.0" } })
            .to_string(),
    );
    let server = MockServer::start().await;
    let source = match route {
        "lpm" => "registry+https://lpm.dev".to_string(),
        "public" => "registry+https://registry.npmjs.org".to_string(),
        _ => format!("registry+{}", server.uri()),
    };
    write_minimal_lockfile_with_source(&project, name, "1.0.0", &source);
    if route == "proxy" {
        let lock = project.read_file("lpm.lock");
        project.write_file(
            "lpm.lock",
            &format!(
                "{lock}tarball = \"{}/tarballs/fresh-outdated-1.0.0.tgz\"\n",
                server.uri()
            ),
        );
    }
    for latest in ["1.0.0", "1.5.0"] {
        server.reset().await;
        mount_contract_metadata(&server, name, latest, "2.0.0").await;
        let out = lpm_with_registry_and_npm(&project, &server.uri())
            .env(
                "LPM_NPM_ROUTE",
                if route == "public" { "direct" } else { "proxy" },
            )
            .args(["outdated", "--json"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            json["packages"][0]["latest"], latest,
            "route={route}: {json}"
        );
        server.verify().await;
    }
}
#[tokio::test]
async fn outdated_revalidates_lpm_metadata_on_each_invocation() {
    check_revalidation("lpm").await;
}
#[tokio::test]
async fn outdated_revalidates_public_npm_metadata_on_each_invocation() {
    check_revalidation("public").await;
}
#[tokio::test]
async fn outdated_revalidates_proxy_metadata_on_each_invocation() {
    check_revalidation("proxy").await;
}
