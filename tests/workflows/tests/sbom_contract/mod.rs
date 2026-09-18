use super::*;
use serde_json::{Value, json};

fn sbom_json(project: &TempProject, arguments: &[&str]) -> Value {
    let output = lpm(project)
        .env("LPM_NPM_ROUTE", "direct")
        .args(["sbom", "--json"])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn sbom_nested_invocation_reads_selected_project_but_writes_relative_to_cwd() {
    let project = seed_project();
    project.write_file("src/index.js", "");
    let output = lpm(&project)
        .current_dir(project.path().join("src"))
        .args(["sbom", "--json", "--output", "report.json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value =
        serde_json::from_slice(&std::fs::read(project.path().join("src/report.json")).unwrap())
            .unwrap();
    assert_eq!(document["metadata"]["component"]["name"], "sbom-app");
    assert!(!project.path().join("report.json").exists());
}

#[test]
fn sbom_reads_bom_prefixed_root_and_installed_manifests() {
    let project = seed_project();
    for path in ["package.json", "node_modules/left-pad/package.json"] {
        let content = std::fs::read_to_string(project.path().join(path)).unwrap();
        project.write_file(path, &format!("\u{feff}{content}"));
    }
    let document = sbom_json(&project, &[]);
    assert_eq!(document["metadata"]["component"]["name"], "sbom-app");
}

#[test]
fn sbom_rejects_non_object_root_manifests() {
    let project = seed_project();
    project.write_file("package.json", "null");
    let output = lpm(&project).args(["sbom", "--json"]).output().unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn sbom_preserves_metadata_for_exact_instances_in_nested_install_slots() {
    let project = contextual_sbom_project();
    std::fs::remove_dir_all(project.path().join("node_modules/shared")).unwrap();
    for (parent, license) in [("parent-a", "MIT"), ("parent-b", "Apache-2.0")] {
        project.write_file(
            &format!("node_modules/{parent}/node_modules/shared/package.json"),
            &json!({"name":"shared","version":"1.0.0","license":license}).to_string(),
        );
    }
    let document = sbom_json(&project, &[]);
    let components = document["components"].as_array().unwrap();
    let declarations: std::collections::BTreeSet<_> = components
        .iter()
        .filter(|component| component["name"] == "shared")
        .map(|component| component["licenses"].to_string())
        .collect();
    assert_eq!(declarations.len(), 2, "{document}");
}

#[test]
fn sbom_resolves_root_alias_install_slots() {
    let project = seed_project();
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let resolution = lockfile.root_resolutions.remove("left-pad").unwrap();
    lockfile
        .root_resolutions
        .insert("alias-pad".to_string(), resolution);
    lockfile
        .root_aliases
        .insert("alias-pad".to_string(), "left-pad".to_string());
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    project.write_file(
        "package.json",
        r#"{"name":"aliased","dependencies":{"alias-pad":"npm:left-pad@^1.3.0"}}"#,
    );
    std::fs::rename(
        project.path().join("node_modules/left-pad"),
        project.path().join("node_modules/alias-pad"),
    )
    .unwrap();
    let document = sbom_json(&project, &[]);
    assert!(
        document["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "left-pad")
    );
}

#[test]
fn sbom_discards_whitespace_license_declarations() {
    for license in [
        json!(" \n\t"),
        json!({"type":"  "}),
        json!([" ", {"type":"\t"}]),
    ] {
        let project = seed_project();
        project.write_file(
            "node_modules/left-pad/package.json",
            &json!({"name":"left-pad","version":"1.3.0","license":license}).to_string(),
        );
        let document = sbom_json(&project, &["--format", "spdx"]);
        let package = document["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "left-pad")
            .unwrap();
        assert_eq!(package["licenseDeclared"], "NOASSERTION", "{package}");
    }
}

#[test]
fn sbom_spdx_preserves_custom_declarations_without_invalid_expressions() {
    for license in [
        "UNLICENSED",
        "SEE LICENSE IN LICENSE",
        "Custom internal license",
    ] {
        let project = seed_project();
        project.write_file(
            "node_modules/left-pad/package.json",
            &json!({"name":"left-pad","version":"1.3.0","license":license}).to_string(),
        );
        let document = sbom_json(&project, &["--format", "spdx"]);
        let package = document["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "left-pad")
            .unwrap();
        assert_eq!(package["licenseDeclared"], "NOASSERTION", "{package}");
        assert!(
            package["licenseComments"]
                .as_str()
                .unwrap()
                .contains(license),
            "{package}"
        );
        let cdx = sbom_json(&project, &[]);
        assert!(
            cdx["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == "left-pad")
                .unwrap()["licenses"]
                .to_string()
                .contains(license)
        );
    }
}

#[test]
fn sbom_spdx_preserves_grouping_when_combining_license_declarations() {
    let project = seed_project();
    project.write_file(
        "node_modules/left-pad/package.json",
        r#"{"name":"left-pad","version":"1.3.0","licenses":["MIT OR Apache-2.0","BSD-3-Clause"]}"#,
    );
    let document = sbom_json(&project, &["--format", "spdx"]);
    let package = document["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "left-pad")
        .unwrap();
    assert_eq!(
        package["licenseDeclared"],
        "BSD-3-Clause AND (MIT OR Apache-2.0)"
    );
}

#[cfg(unix)]
#[test]
fn sbom_rejects_fifo_output_without_waiting_for_a_reader() {
    let project = seed_project();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(project.path().join("report.json"))
            .status()
            .unwrap()
            .success()
    );
    let mut child = support::lpm_spawnable(&project)
        .args(["sbom", "--output", "report.json", "--json"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("SBOM blocked while opening a FIFO output");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn registry_project(registry: &str) -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"host","version":"1.0.0","dependencies":{"widget":"1.0.0"}}"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "widget".into(),
        version: "1.0.0".into(),
        source: Some(format!("registry+{registry}")),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[("widget", "widget", "1.0.0")]);
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    project.write_file(
        "node_modules/widget/package.json",
        r#"{"name":"widget","version":"1.0.0"}"#,
    );
    project
}

#[tokio::test]
async fn sbom_enrichment_uses_locked_registry_instead_of_current_route() {
    let locked = support::mock_registry::MockRegistry::start().await;
    let current = support::mock_registry::MockRegistry::start().await;
    for (server, description) in [(&locked, "locked origin"), (&current, "wrong origin")] {
        Mock::given(method("GET")).and(path("/widget")).respond_with(ResponseTemplate::new(200)
            .set_body_json(json!({"name":"widget","versions":{"1.0.0":{"name":"widget","version":"1.0.0","description":description}}})))
            .mount(server.server()).await;
    }
    let project = registry_project(&locked.url());
    project.write_file(".npmrc", &format!("registry={}\n", current.url()));
    let document = sbom_json(&project, &["--registry-metadata"]);
    assert_eq!(document["components"][0]["description"], "locked origin");
    assert!(
        current
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn sbom_registry_enrichment_retains_license_and_publisher_fields() {
    let registry = support::mock_registry::MockRegistry::start().await;
    Mock::given(method("GET")).and(path("/widget")).respond_with(ResponseTemplate::new(200)
        .set_body_json(json!({"name":"widget","versions":{"1.0.0":{"name":"widget","version":"1.0.0","description":"registry description","license":"MIT","homepage":"https://example.test/widget","repository":{"url":"https://example.test/widget.git"},"author":{"name":"Publisher"}}}})))
        .mount(registry.server()).await;
    let project = registry_project(&registry.url());
    project.write_file(".npmrc", &format!("registry={}\n", registry.url()));
    let document = sbom_json(&project, &["--registry-metadata"]);
    let component = &document["components"][0];
    assert!(
        component["licenses"].to_string().contains("MIT"),
        "{component}"
    );
    assert!(
        component
            .to_string()
            .contains("https://example.test/widget"),
        "{component}"
    );
    assert!(component.to_string().contains("Publisher"), "{component}");
}

#[test]
fn sbom_legacy_roots_select_requested_versions_and_aliases() {
    for root_name in ["shared", "alias"] {
        let spec = if root_name == "alias" {
            "npm:shared@^2.0.0"
        } else {
            "^2.0.0"
        };
        let project = TempProject::empty(&json!({"name":"host","version":"1.0.0","dependencies":{root_name:spec},"devDependencies":{"parent":"1.0.0"}}).to_string());
        project.write_file("lpm.lock", "[metadata]\nlockfile-version = 2\nresolved-with = \"pubgrub\"\n[[packages]]\nname=\"parent\"\nversion=\"1.0.0\"\ndependencies=[\"shared@1.0.0\"]\n[[packages]]\nname=\"shared\"\nversion=\"1.0.0\"\n[[packages]]\nname=\"shared\"\nversion=\"2.0.0\"\n");
        for (name, version) in [
            ("parent", "1.0.0"),
            ("shared", "1.0.0"),
            ("shared", "2.0.0"),
        ] {
            let package_dir = project
                .store_dir()
                .join("v1")
                .join(format!("{name}@{version}"));
            std::fs::create_dir_all(&package_dir).unwrap();
            std::fs::write(
                package_dir.join("package.json"),
                json!({"name":name,"version":version}).to_string(),
            )
            .unwrap();
            std::fs::write(package_dir.join(".integrity"), "sha512-fixture").unwrap();
        }
        let output = support::lpm_v1(&project)
            .args(["sbom", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        let shared = document["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "shared" && p["version"] == "2.0.0")
            .unwrap();
        assert_eq!(shared["scope"], "required", "{document}");
        let old = document["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "shared" && p["version"] == "1.0.0")
            .unwrap();
        assert_eq!(old["scope"], "excluded", "{document}");
        let root_ref = document["metadata"]["component"]["bom-ref"]
            .as_str()
            .unwrap();
        let roots = dependency_targets(&document, root_ref);
        assert_eq!(roots.len(), 2, "{document}");
        assert!(
            roots.contains(&shared["bom-ref"].as_str().unwrap().to_string()),
            "{document}"
        );
    }
}

#[test]
fn sbom_platform_skip_does_not_hide_a_missing_compatible_instance() {
    let project = contextual_sbom_project();
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    for package in &mut lockfile.packages {
        package.optional = true;
        if package.name == "parent-a" {
            package.os = vec![if cfg!(windows) { "darwin" } else { "win32" }.to_string()];
        }
    }
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    std::fs::remove_dir_all(project.path().join("node_modules/shared")).unwrap();
    std::fs::remove_dir_all(project.path().join("node_modules/parent-a")).unwrap();
    let output = lpm(&project).args(["sbom", "--json"]).output().unwrap();
    assert!(
        !output.status.success(),
        "a missing dependency of the compatible branch must fail: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn sbom_rejects_fifo_installed_manifests_without_waiting_for_a_writer() {
    let project = seed_project();
    let manifest = project.path().join("node_modules/left-pad/package.json");
    std::fs::remove_file(&manifest).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&manifest)
            .status()
            .unwrap()
            .success()
    );
    let mut child = support::lpm_spawnable(&project)
        .args(["sbom", "--json"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("SBOM blocked while reading an installed FIFO manifest");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[tokio::test]
async fn sbom_registry_enrichment_preserves_local_license_authority() {
    let registry = support::mock_registry::MockRegistry::start().await;
    Mock::given(method("GET")).and(path("/widget")).respond_with(ResponseTemplate::new(200)
        .set_body_json(json!({"name":"widget","versions":{"1.0.0":{"name":"widget","version":"1.0.0","license":"MIT"}}})))
        .mount(registry.server()).await;
    let project = registry_project(&registry.url());
    project.write_file(".npmrc", &format!("registry={}\n", registry.url()));
    project.write_file(
        "node_modules/widget/package.json",
        r#"{"name":"widget","version":"1.0.0","license":"UNLICENSED"}"#,
    );
    let document = sbom_json(&project, &["--registry-metadata"]);
    assert_eq!(
        document["components"][0]["licenses"],
        json!([{"license":{"name":"UNLICENSED"}}])
    );
}

#[test]
fn sbom_missing_exact_alias_does_not_inherit_an_unrelated_root_manifest() {
    let project = seed_project();
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let resolution = lockfile.root_resolutions.remove("left-pad").unwrap();
    lockfile
        .root_resolutions
        .insert("alias-pad".to_string(), resolution);
    lockfile
        .root_aliases
        .insert("alias-pad".to_string(), "left-pad".to_string());
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    project.write_file(
        "package.json",
        r#"{"name":"aliased","dependencies":{"alias-pad":"npm:left-pad@^1.3.0"}}"#,
    );
    let output = lpm(&project).args(["sbom", "--json"]).output().unwrap();
    assert!(
        !output.status.success(),
        "missing alias slot must not use leftover canonical-name slot: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn sbom_locked_registry_ignores_unrelated_current_route_tls_identity() {
    let registry = support::mock_registry::MockRegistry::start().await;
    let unrelated = support::mock_registry::MockRegistry::start().await;
    Mock::given(method("GET")).and(path("/widget")).respond_with(ResponseTemplate::new(200)
        .set_body_json(json!({"name":"widget","versions":{"1.0.0":{"name":"widget","version":"1.0.0","description":"locked"}}})))
        .mount(registry.server()).await;
    let project = registry_project(&registry.url());
    let authority = unrelated.url().trim_start_matches("http://").to_string();
    project.write_file(".npmrc", &format!("registry={}\n", unrelated.url()));
    std::fs::write(
        project.home().join(".npmrc"),
        format!("//{authority}/:certfile=missing.pem\n//{authority}/:keyfile=missing.key\n"),
    )
    .unwrap();
    let document = sbom_json(&project, &["--registry-metadata"]);
    assert_eq!(document["components"][0]["description"], "locked");
}

#[test]
fn sbom_deduplicates_multiple_aliases_to_the_same_root_instance() {
    let project = registry_project("https://registry.npmjs.org");
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let resolution = lockfile.root_resolutions["widget"].clone();
    lockfile
        .root_resolutions
        .insert("alias".to_string(), resolution);
    lockfile
        .root_aliases
        .insert("alias".to_string(), "widget".to_string());
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    project.write_file("package.json", r#"{"name":"host","version":"1.0.0","dependencies":{"widget":"1.0.0","alias":"npm:widget@1.0.0"}}"#);
    project.write_file(
        "node_modules/alias/package.json",
        r#"{"name":"widget","version":"1.0.0"}"#,
    );
    let document = sbom_json(&project, &[]);
    let root = document["metadata"]["component"]["bom-ref"]
        .as_str()
        .unwrap();
    assert_eq!(dependency_targets(&document, root).len(), 1, "{document}");
}

#[test]
fn sbom_preserves_recorded_legacy_root_versions() {
    let project = TempProject::empty(
        r#"{"name":"host","dependencies":{"shared":"^1.0.0","parent":"1.0.0"}}"#,
    );
    project.write_file("lpm.lock", "[metadata]\nlockfile-version=8\nresolved-with=\"pubgrub\"\n[root-resolutions.shared]\npackage=\"shared\"\nversion=\"1.0.0\"\n[root-resolutions.parent]\npackage=\"parent\"\nversion=\"1.0.0\"\n[[packages]]\nname=\"parent\"\nversion=\"1.0.0\"\ndependencies=[\"shared@1.5.0\"]\n[[packages]]\nname=\"shared\"\nversion=\"1.0.0\"\n[[packages]]\nname=\"shared\"\nversion=\"1.5.0\"\n");
    for (path, name, version) in [
        ("parent", "parent", "1.0.0"),
        ("shared", "shared", "1.0.0"),
        ("parent/node_modules/shared", "shared", "1.5.0"),
    ] {
        project.write_file(
            &format!("node_modules/{path}/package.json"),
            &json!({"name":name,"version":version}).to_string(),
        );
    }
    let document = sbom_json(&project, &[]);
    let root = document["metadata"]["component"]["bom-ref"]
        .as_str()
        .unwrap();
    let roots = dependency_targets(&document, root);
    let package = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "shared" && p["version"] == "1.0.0")
        .unwrap();
    assert!(roots.contains(&package["bom-ref"].as_str().unwrap().to_string()));
}

#[test]
fn sbom_reads_version_twelve_structured_peer_paths_and_edges() {
    let project = TempProject::empty(r#"{"name":"host","devDependencies":{"parent":"1.0.0"}}"#);
    project.write_file("lpm.lock", "[metadata]\nlockfile-version=12\nresolved-with=\"pubgrub\"\n[root-resolutions.parent]\npackage=\"parent\"\nversion=\"1.0.0\"\n[[packages]]\nname=\"parent\"\nversion=\"1.0.0\"\npeer-edges=[{local-name=\"alias\",target-name=\"provider\",target-version=\"1.0.0\"}]\n[[packages]]\nname=\"provider\"\nversion=\"1.0.0\"\n");
    project.write_file(
        "node_modules/parent/package.json",
        r#"{"name":"parent","version":"1.0.0"}"#,
    );
    project.write_file(
        "node_modules/parent/node_modules/alias/package.json",
        r#"{"name":"provider","version":"1.0.0","license":"MIT"}"#,
    );
    let document = sbom_json(&project, &[]);
    let parent = component_reference(&document, "parent");
    let provider = component_reference(&document, "provider");
    assert_eq!(dependency_targets(&document, &parent), vec![provider]);
    assert_eq!(
        document["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "provider")
            .unwrap()["scope"],
        "excluded"
    );
}

#[tokio::test]
async fn sbom_rejects_a_virtual_materialization_with_different_locked_integrity() {
    let project = installed_manifest_dependency_graph("isolated").await;
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let package = lockfile
        .packages
        .iter_mut()
        .find(|package| package.name == "multi-license")
        .unwrap();
    assert_ne!(
        package.integrity.as_deref(),
        Some(support::VALID_TEST_INTEGRITY)
    );
    package.integrity = Some(support::VALID_TEST_INTEGRITY.to_string());
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    let output = lpm(&project).args(["sbom", "--json"]).output().unwrap();
    assert!(
        !output.status.success(),
        "mismatched materialization supplied metadata: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn sbom_rejects_registry_query_and_fragment_before_requests() {
    let registry = support::mock_registry::MockRegistry::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)
        .set_body_json(json!({"name":"widget","versions":{"1.0.0":{"name":"widget","version":"1.0.0","description":"wrong endpoint"}}})))
        .mount(registry.server()).await;
    for suffix in ["?extra=1", "#fragment"] {
        let project = registry_project(&format!("{}{suffix}", registry.url()));
        let output = lpm(&project)
            .env("LPM_NPM_ROUTE", "direct")
            .args(["sbom", "--json", "--registry-metadata"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn sbom_recovers_a_stored_session_when_private_locked_version_is_hidden() {
    const NAME: &str = "@lpm.dev/acme.widget";
    let registry = support::mock_registry::MockRegistry::start().await;
    let project =
        TempProject::empty(&json!({"name":"host","dependencies":{NAME:"1.0.0"}}).to_string());
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: NAME.into(),
        version: "1.0.0".into(),
        source: Some("registry+https://lpm.dev".into()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[(NAME, NAME, "1.0.0")]);
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    project.write_file(
        &format!("node_modules/{NAME}/package.json"),
        &json!({"name":NAME,"version":"1.0.0"}).to_string(),
    );
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{NAME}")))
        .respond_with(|request: &Request| {
            let versions = if request
                .headers
                .get("authorization")
                .is_some_and(|header| header == "Bearer rotated-access")
            {
                json!({"1.0.0":{"name":NAME,"version":"1.0.0","description":"private version"}})
            } else {
                json!({"2.0.0":{"name":NAME,"version":"2.0.0"}})
            };
            ResponseTemplate::new(200).set_body_json(json!({"name":NAME,"versions":versions}))
        })
        .mount(registry.server())
        .await;
    registry
        .with_refresh_expected(
            "valid-refresh",
            "rotated-access",
            "rotated-refresh",
            "2099-01-01T00:00:00Z",
            1,
        )
        .await;
    support::auth_state::seed_sessions(
        project.home(),
        &[support::auth_state::SessionSeed {
            registry_url: &registry.url(),
            access_token: Some("expired-access"),
            refresh_token: Some("valid-refresh"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    let document = sbom_json(
        &project,
        &["--registry", &registry.url(), "--registry-metadata"],
    );
    assert_eq!(document["components"][0]["description"], "private version");
}

#[tokio::test]
async fn sbom_fetches_provenance_once_for_shared_artifact_instances() {
    let project = contextual_sbom_project();
    let registry = support::mock_registry::MockRegistry::start().await;
    let base = registry.server().uri();
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    for package in &mut lockfile.packages {
        package.source = Some(format!("registry+{base}"));
        package.integrity = Some(format!("sha512-{}==", "A".repeat(86)));
    }
    for root in lockfile.root_resolutions.values_mut() {
        root.source = Some(format!("registry+{base}"));
    }
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    for name in ["parent-a", "parent-b", "shared"] {
        let mut version = json!({"name":name,"version":"1.0.0"});
        if name == "shared" {
            version["dist"] = json!({"attestations":{"url":format!("{base}/attestation")}});
        }
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"name":name,"versions":{"1.0.0":version}})),
            )
            .mount(registry.server())
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/attestation"))
        .respond_with(ResponseTemplate::new(404))
        .mount(registry.server())
        .await;
    let document = sbom_json(&project, &["--registry-metadata"]);
    assert_eq!(
        document["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["name"] == "shared")
            .count(),
        2
    );
    let requests = registry.server().received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/attestation")
            .count(),
        1
    );
}
