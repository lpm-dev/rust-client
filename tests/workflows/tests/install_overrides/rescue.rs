use super::*;

async fn assert_missing_range_override(
    mode: &str,
    root: bool,
    path: bool,
    optional: bool,
    alias: bool,
) {
    let mock = MockRegistry::start().await;
    let target = mock
        .mount_full_package_metadata_routes(
            "override-target",
            "2.0.0",
            &[(
                "2.0.0",
                serde_json::json!({}),
                Some(make_tarball("override-target", "2.0.0")),
            )],
        )
        .await;
    let local = if alias {
        "target-alias"
    } else {
        "override-target"
    };
    let range = if alias {
        "npm:override-target@^1"
    } else {
        "^1"
    };
    let consumer = mock
        .mount_full_package_metadata_routes(
            "override-consumer",
            "1.0.0",
            &[(
                "1.0.0",
                serde_json::json!({local: range}),
                Some(make_tarball("override-consumer", "1.0.0")),
            )],
        )
        .await;
    mock.with_batch_metadata(vec![target, consumer]).await;
    let selector = if path {
        "override-consumer>override-target"
    } else {
        "override-target"
    };
    let dependencies = if root {
        serde_json::json!({local: range})
    } else {
        serde_json::json!({"override-consumer": "1.0.0"})
    };
    let section = if optional {
        "optionalDependencies"
    } else {
        "dependencies"
    };
    let project = TempProject::empty(
        &serde_json::json!({
            "name": "rescue-override", "version": "1.0.0", section: dependencies,
            "lpm": {"overrides": {selector: "2.0.0"}}
        })
        .to_string(),
    );
    let mut command = lpm_with_registry(&project, &mock.url());
    command.args([
        "install",
        "--json",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]);
    match mode {
        "pubgrub" => {
            command.env("LPM_RESOLVER", "pubgrub");
        }
        "legacy" => {
            command.env("LPM_GREEDY_FUSION", "0");
        }
        _ => {}
    }
    let output = command.output().expect("install rescue override");
    assert!(
        output.status.success(),
        "{mode} root={root} path={path} optional={optional} alias={alias}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let lock = project.read_file("lpm.lock");
    assert!(
        lock.contains("name = \"override-target\""),
        "override target missing: {lock}"
    );
    assert!(
        lock.contains("version = \"2.0.0\""),
        "override version missing: {lock}"
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("install JSON");
    let hits = json["applied_overrides"]
        .as_array()
        .expect("applied override trace");
    assert!(
        hits.iter().any(|hit| hit["package"] == "override-target"
            && hit["from_version"].is_null()
            && hit["to_version"] == "2.0.0"),
        "trace must not invent a natural version: {hits:?}"
    );
    if root && !optional && mode == "default" {
        insta::assert_json_snapshot!(serde_json::json!({
            "schema_version": json["schema_version"],
            "success": json["success"],
            "applied_overrides": hits,
        }), @r###"
        {
          "schema_version": 2,
          "success": true,
          "applied_overrides": [
            {
              "raw_key": "override-target",
              "source": "lpm.overrides",
              "package": "override-target",
              "from_version": null,
              "to_version": "2.0.0",
              "via_parent": null
            }
          ]
        }
        "###);
    }
}

#[tokio::test]
async fn plain_override_rescues_missing_root_range() {
    for mode in ["default", "legacy", "pubgrub"] {
        assert_missing_range_override(mode, true, false, false, false).await;
    }
}

#[tokio::test]
async fn plain_override_rescues_missing_transitive_range() {
    for mode in ["default", "legacy", "pubgrub"] {
        assert_missing_range_override(mode, false, false, false, false).await;
    }
}

#[tokio::test]
async fn path_override_rescues_missing_transitive_alias_range() {
    for mode in ["default", "legacy", "pubgrub"] {
        assert_missing_range_override(mode, false, true, false, true).await;
    }
}

#[tokio::test]
async fn plain_override_rescues_missing_optional_root_range() {
    for mode in ["default", "legacy", "pubgrub"] {
        assert_missing_range_override(mode, true, false, true, false).await;
    }
}

#[tokio::test]
async fn pubgrub_preserves_distinct_transitive_alias_versions() {
    let mock = MockRegistry::start().await;
    let target = mock
        .mount_full_package_metadata_routes(
            "override-target",
            "2.0.0",
            &[
                (
                    "2.0.0",
                    serde_json::json!({}),
                    Some(make_tarball("override-target", "2.0.0")),
                ),
                (
                    "1.0.0",
                    serde_json::json!({}),
                    Some(make_tarball("override-target", "1.0.0")),
                ),
            ],
        )
        .await;
    let consumer = mock.mount_full_package_metadata_routes("override-consumer", "1.0.0", &[
        ("1.0.0", serde_json::json!({"target-one": "npm:override-target@1.0.0", "target-two": "npm:override-target@2.0.0"}), Some(make_tarball("override-consumer", "1.0.0"))),
    ]).await;
    mock.with_batch_metadata(vec![target, consumer]).await;
    let project = TempProject::empty(
        r#"{"name":"alias-root","version":"1.0.0","dependencies":{"override-consumer":"1.0.0"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_RESOLVER", "pubgrub")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install transitive aliases");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let lock = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let consumer = lock
        .packages
        .iter()
        .find(|package| package.name == "override-consumer")
        .unwrap();
    for (local, version) in [("target-one", "1.0.0"), ("target-two", "2.0.0")] {
        let target = consumer
            .dependency_targets
            .get(local)
            .expect("exact alias edge");
        let package = lock
            .packages
            .iter()
            .find(|package| package.instance_id.as_ref() == Some(target))
            .expect("target instance");
        assert_eq!(
            package.version, version,
            "{local} must retain its requested version"
        );
    }
    assert_ne!(
        consumer.dependency_targets.get("target-one"),
        consumer.dependency_targets.get("target-two")
    );
}
