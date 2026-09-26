//! Install-time metadata reuse across versions of the same package.
mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

#[tokio::test]
async fn install_enriches_three_scripted_versions_from_one_cached_history() {
    let mock = MockRegistry::start().await;
    let mut versions = serde_json::Map::new();
    let mut times = serde_json::Map::new();
    let mut tarballs = Vec::new();
    for (version, published) in [
        ("1.0.0", "2024-01-01T00:00:00.000Z"),
        ("2.0.0", "2024-02-01T00:00:00.000Z"),
        ("3.0.0", "2024-03-01T00:00:00.000Z"),
    ] {
        let mut manifest = serde_json::json!({"name":"scripted","version":version,"scripts":{"postinstall":"node postinstall.js"}});
        let tarball = make_tarball_from_pkg_json(
            manifest.clone(),
            &[("postinstall.js", b"process.exit(0);\n")],
        );
        manifest["dist"] = serde_json::json!({"tarball":mock.tarball_url("scripted", version), "integrity":compute_integrity(&tarball)});
        versions.insert(version.into(), manifest);
        times.insert(version.into(), published.into());
        tarballs.push((version, tarball));
    }
    mock.with_package_metadata_and_tarballs("scripted", serde_json::json!({"name":"scripted","dist-tags":{"latest":"3.0.0"},"versions":versions,"time":times}), &tarballs).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"one":"npm:scripted@^1","two":"npm:scripted@^2","three":"npm:scripted@^3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TIMING_DETAIL", "trace")
        .args([
            "--json",
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
    let blocked = state["blocked_packages"].as_array().unwrap();
    assert_eq!(blocked.len(), 3);
    for package in blocked {
        let version = package["version"].as_str().unwrap();
        assert_eq!(package["published_at"], times[version]);
        assert_eq!(package["integrity"], versions[version]["dist"]["integrity"]);
    }
    let metadata = envelope["timing"]["detail"]["metadata"].as_array().unwrap();
    let blocked = metadata
        .iter()
        .find(|entry| entry["purpose"] == "blocked_set")
        .unwrap();
    assert_eq!(blocked["rpc_count"], 0);
    assert_eq!(blocked["cache_hit_count"], 1, "{blocked}");
    assert_eq!(blocked["request_count"], 1, "{blocked}");
}
