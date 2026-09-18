use super::*;

async fn versions() -> MockRegistry {
    let registry = MockRegistry::start().await;
    registry
        .with_full_package_metadata(
            "save-fixture",
            "2.0.0",
            &[
                (
                    "1.0.0",
                    serde_json::json!({}),
                    Some(make_tarball("save-fixture", "1.0.0")),
                ),
                (
                    "2.0.0",
                    serde_json::json!({}),
                    Some(make_tarball("save-fixture", "2.0.0")),
                ),
            ],
        )
        .await;
    registry
}

#[tokio::test]
async fn conflicting_requests_fail_before_manifest_or_registry_changes() {
    for specs in [
        ["save-fixture", "save-fixture@1.0.0"],
        ["save-fixture@1.0.0", "save-fixture"],
        ["save-fixture@latest", "save-fixture@1.0.0"],
        ["save-fixture@1.0.0", "save-fixture@latest"],
    ] {
        let registry = versions().await;
        let manifest = "{\"name\":\"consumer\",\"version\":\"1.0.0\"}\n";
        let project = TempProject::empty(manifest);
        let output = lpm_with_registry_and_npm(&project, &registry.url())
            .env("LPM_TYPOSQUAT_GUARD", "0")
            .args([
                "install",
                "--no-skills",
                "--no-editor-setup",
                "--no-security-summary",
            ])
            .args(specs)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{specs:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("conflicting package requests"), "{stderr}");
        assert!(
            stderr.contains(specs[0]) && stderr.contains(specs[1]),
            "{stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(project.path().join("package.json")).unwrap(),
            manifest
        );
        assert!(!project.path().join("lpm.lock").exists());
        assert!(!project.path().join("node_modules").exists());
        assert!(
            registry
                .server()
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn conflicting_requests_do_not_initialize_a_project() {
    let registry = versions().await;
    let project = TempProject::empty("{\"name\":\"consumer\"}");
    std::fs::remove_file(project.path().join("package.json")).unwrap();
    let output = lpm_with_registry_and_npm(&project, &registry.url())
        .env("LPM_TYPOSQUAT_GUARD", "0")
        .args([
            "install",
            "save-fixture",
            "save-fixture@1.0.0",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!project.path().join("package.json").exists());
    assert!(!project.path().join("lpm.lock").exists());
    assert!(!project.path().join("node_modules").exists());
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
async fn conflicting_filtered_requests_preserve_all_workspace_manifests() {
    let registry = versions().await;
    let root = "{\"name\":\"root\",\"private\":true,\"workspaces\":[\"packages/*\"]}";
    let member = "{\"name\":\"app\",\"version\":\"1.0.0\"}";
    let project = TempProject::empty(root);
    project.write_file("packages/app/package.json", member);
    let output = lpm_with_registry_and_npm(&project, &registry.url())
        .env("LPM_TYPOSQUAT_GUARD", "0")
        .args([
            "install",
            "save-fixture@latest",
            "save-fixture@1.0.0",
            "--filter",
            "app",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("package.json")).unwrap(),
        root
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("packages/app/package.json")).unwrap(),
        member
    );
    assert!(!project.path().join("lpm.lock").exists());
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
async fn identical_requests_install_one_dependency_with_the_requested_policy() {
    let registry = versions().await;
    for (specs, expected) in [
        (["save-fixture", "save-fixture@"], "^2.0.0"),
        (["save-fixture@1.0.0", "save-fixture@1.0.0"], "1.0.0"),
        (["save-fixture@latest", "save-fixture@latest"], "^2.0.0"),
    ] {
        let project = TempProject::empty("{\"name\":\"consumer\"}");
        lpm_with_registry_and_npm(&project, &registry.url())
            .env("LPM_TYPOSQUAT_GUARD", "0")
            .args([
                "install",
                "--no-skills",
                "--no-editor-setup",
                "--no-security-summary",
            ])
            .args(specs)
            .assert()
            .success();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["dependencies"],
            serde_json::json!({"save-fixture":expected})
        );
    }
}

#[tokio::test]
async fn source_shaped_registry_tags_cannot_replace_requested_package_sources() {
    let registry = MockRegistry::start().await;
    let name = "input-package";
    let tag = "npm:real-package@1.0.0";
    let mut metadata = registry
        .mount_full_package_metadata_routes(
            name,
            "9.9.9",
            &[(
                "9.9.9",
                serde_json::json!({}),
                Some(make_tarball(name, "9.9.9")),
            )],
        )
        .await;
    metadata["dist-tags"][tag] = serde_json::json!("9.9.9");
    for route in [format!("/{name}"), format!("/api/registry/{name}")] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(&metadata))
            .with_priority(1)
            .mount(registry.server())
            .await;
    }
    let manifest = "{\"name\":\"consumer\"}";
    let project = TempProject::empty(manifest);
    let output = lpm_with_registry_and_npm(&project, &registry.url())
        .env("LPM_TYPOSQUAT_GUARD", "0")
        .args([
            "install",
            &format!("{name}@{tag}"),
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("package.json")).unwrap(),
        manifest
    );
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
async fn automatic_catalog_modes_preserve_local_dependency_sources() {
    for mode in ["prefer", "strict"] {
        for catalog_present in [true, false] {
            for (existing, request) in [
                (None, "shared@workspace:*"),
                (Some("workspace:*"), "shared"),
                (Some("file:../shared"), "shared"),
            ] {
                let registry = MockRegistry::start().await;
                let root = serde_json::json!({"name":"root","private":true,"workspaces":["packages/*"],
                    "catalogs":{"default":if catalog_present { serde_json::json!({"shared":"^1.0.0"}) } else { serde_json::json!({}) }},
                    "lpm":{"catalogMode":mode}});
                let project = TempProject::empty(&root.to_string());
                let mut member = serde_json::json!({"name":"app","version":"1.0.0"});
                if let Some(source) = existing {
                    member["dependencies"] = serde_json::json!({"shared":source});
                }
                project.write_file("packages/app/package.json", &member.to_string());
                project.write_file(
                    "packages/shared/package.json",
                    r#"{"name":"shared","version":"1.0.0"}"#,
                );
                let output = lpm_with_registry_and_npm(&project, &registry.url())
                    .env("LPM_TYPOSQUAT_GUARD", "0")
                    .args([
                        "install",
                        request,
                        "--filter",
                        "app",
                        "--no-skills",
                        "--no-editor-setup",
                        "--no-security-summary",
                    ])
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{mode} {existing:?} catalog={catalog_present}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let manifest: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(project.path().join("packages/app/package.json"))
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    manifest["dependencies"]["shared"],
                    existing.unwrap_or("workspace:*"),
                    "{mode}"
                );
                assert!(
                    project
                        .path()
                        .join("packages/app/node_modules/shared/package.json")
                        .is_file()
                );
                assert!(
                    registry
                        .server()
                        .received_requests()
                        .await
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }
}

#[tokio::test]
async fn forced_catalog_rejects_local_source_conversion_before_registry_access() {
    let registry = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"workspaces":["packages/*"],"catalogs":{"default":{"shared":"^1.0.0"}}}"#,
    );
    let member = r#"{"name":"app","version":"1.0.0"}"#;
    project.write_file("packages/app/package.json", member);
    project.write_file(
        "packages/shared/package.json",
        r#"{"name":"shared","version":"1.0.0"}"#,
    );
    let output = lpm_with_registry_and_npm(&project, &registry.url())
        .env("LPM_TYPOSQUAT_GUARD", "0")
        .args([
            "install",
            "shared@workspace:*",
            "--catalog",
            "--filter",
            "app",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot replace a source dependency"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("packages/app/package.json")).unwrap(),
        member
    );
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
async fn automatic_catalog_modes_preserve_existing_alias_sources() {
    for mode in ["prefer", "strict"] {
        let registry = MockRegistry::start().await;
        registry
            .with_package(
                "real-package",
                "1.0.0",
                &make_tarball("real-package", "1.0.0"),
            )
            .await;
        let project = TempProject::empty(
            &serde_json::json!({
                "name":"consumer", "dependencies":{"local-alias":"npm:real-package@1.0.0"},
                "catalogs":{"default":{"local-alias":"^1.0.0"}}, "lpm":{"catalogMode":mode}
            })
            .to_string(),
        );
        lpm_with_registry_and_npm(&project, &registry.url())
            .env("LPM_TYPOSQUAT_GUARD", "0")
            .args([
                "install",
                "local-alias",
                "--no-skills",
                "--no-editor-setup",
                "--no-security-summary",
            ])
            .assert()
            .success();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["dependencies"]["local-alias"],
            "npm:real-package@1.0.0"
        );
        let installed: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(project.path().join("node_modules/local-alias/package.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(installed["name"], "real-package");
        assert!(
            registry
                .server()
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| !request.url.path().ends_with("/local-alias"))
        );
    }
}

#[tokio::test]
async fn automatic_catalog_modes_preserve_key_relative_jsr_sources() {
    for mode in ["manual", "prefer", "strict"] {
        let registry = MockRegistry::start().await;
        registry
            .with_package(
                "@jsr/std__path",
                "1.1.6",
                &make_tarball("@jsr/std__path", "1.1.6"),
            )
            .await;
        let project = TempProject::empty(
            &serde_json::json!({
                "name":"consumer", "dependencies":{"@std/path":"jsr:^1.1.0"},
                "catalogs":{"default":{"@std/path":"^1.1.0"}}, "lpm":{"catalogMode":mode}
            })
            .to_string(),
        );
        project.write_file(".npmrc", &format!("@jsr:registry={}\n", registry.url()));
        lpm_with_registry_and_npm(&project, &registry.url())
            .env("LPM_TYPOSQUAT_GUARD", "0")
            .args([
                "install",
                "@std/path",
                "--no-skills",
                "--no-editor-setup",
                "--no-security-summary",
            ])
            .assert()
            .success();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["dependencies"]["@std/path"], "jsr:^1.1.0",
            "{mode}"
        );
        let installed: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(project.path().join("node_modules/@std/path/package.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(installed["name"], "@jsr/std__path", "{mode}");
    }
}

#[tokio::test]
async fn bare_reinstall_save_flags_preserve_source_dependencies() {
    for mode in ["manual", "prefer", "strict"] {
        for source in ["workspace:*", "file:../shared", "npm:real-package@1.0.0"] {
            let registry = MockRegistry::start().await;
            registry
                .with_package(
                    "real-package",
                    "1.0.0",
                    &make_tarball("real-package", "1.0.0"),
                )
                .await;
            let project = TempProject::empty(
                &serde_json::json!({
                    "name":"root", "private":true, "workspaces":["packages/*"],
                    "catalogs":{"default":{"shared":"^1.0.0"}}, "lpm":{"catalogMode":mode}
                })
                .to_string(),
            );
            project.write_file("packages/app/package.json", &serde_json::json!({"name":"app","version":"1.0.0","dependencies":{"shared":source}}).to_string());
            project.write_file(
                "packages/shared/package.json",
                r#"{"name":"shared","version":"1.0.0"}"#,
            );
            lpm_with_registry_and_npm(&project, &registry.url())
                .env("LPM_TYPOSQUAT_GUARD", "0")
                .args([
                    "install",
                    "shared",
                    "--exact",
                    "--filter",
                    "app",
                    "--no-skills",
                    "--no-editor-setup",
                    "--no-security-summary",
                ])
                .assert()
                .success();
            let manifest: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(project.path().join("packages/app/package.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                manifest["dependencies"]["shared"], source,
                "{mode} {source}"
            );
            let installed: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(
                    project
                        .path()
                        .join("packages/app/node_modules/shared/package.json"),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                installed["name"],
                if source.starts_with("npm:") {
                    "real-package"
                } else {
                    "shared"
                }
            );
        }
    }
}

#[tokio::test]
async fn lpm_scoped_workspace_requests_do_not_fetch_ecosystem_metadata() {
    for mode in ["manual", "prefer", "strict"] {
        for bare in [false, true] {
            let registry = MockRegistry::start().await;
            let project = TempProject::empty(
                &serde_json::json!({
                    "name":"root", "private":true, "workspaces":["packages/*"],
                    "lpm":{"catalogMode":mode}
                })
                .to_string(),
            );
            let mut member = serde_json::json!({"name":"app","version":"1.0.0"});
            if bare {
                member["dependencies"] = serde_json::json!({"@lpm.dev/acme.shared":"workspace:*"});
            }
            project.write_file("packages/app/package.json", &member.to_string());
            project.write_file(
                "packages/shared/package.json",
                r#"{"name":"@lpm.dev/acme.shared","version":"1.0.0"}"#,
            );
            let request = if bare {
                "@lpm.dev/acme.shared"
            } else {
                "@lpm.dev/acme.shared@workspace:*"
            };
            lpm_with_registry_and_npm(&project, &registry.url())
                .env("LPM_TYPOSQUAT_GUARD", "0")
                .args([
                    "install",
                    request,
                    "--filter",
                    "app",
                    "--no-skills",
                    "--no-editor-setup",
                    "--no-security-summary",
                ])
                .assert()
                .success();
            let manifest: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(project.path().join("packages/app/package.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                manifest["dependencies"]["@lpm.dev/acme.shared"],
                "workspace:*"
            );
            assert!(
                project
                    .path()
                    .join("packages/app/node_modules/@lpm.dev/acme.shared/package.json")
                    .is_file()
            );
            assert!(
                registry
                    .server()
                    .received_requests()
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[tokio::test]
async fn path_shaped_registry_tags_cannot_replace_requested_sources() {
    for tag in ["../local", "/tmp/local.tgz", "./local"] {
        let registry = MockRegistry::start().await;
        let mut metadata = registry
            .mount_full_package_metadata_routes(
                "input-package",
                "9.9.9",
                &[(
                    "9.9.9",
                    serde_json::json!({}),
                    Some(make_tarball("input-package", "9.9.9")),
                )],
            )
            .await;
        metadata["dist-tags"][tag] = serde_json::json!("9.9.9");
        for route in ["/input-package", "/api/registry/input-package"] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(&metadata))
                .with_priority(1)
                .mount(registry.server())
                .await;
        }
        let manifest = r#"{"name":"consumer"}"#;
        let project = TempProject::empty(manifest);
        let output = lpm_with_registry_and_npm(&project, &registry.url())
            .env("LPM_TYPOSQUAT_GUARD", "0")
            .args([
                "install",
                &format!("input-package@{tag}"),
                "--no-skills",
                "--no-editor-setup",
                "--no-security-summary",
            ])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{tag}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            std::fs::read_to_string(project.path().join("package.json")).unwrap(),
            manifest
        );
        assert!(
            registry
                .server()
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn mixed_local_and_swift_targets_fail_before_manifest_changes() {
    let registry = MockRegistry::start().await;
    let name = "@lpm.dev/acme.shared";
    let mut metadata = registry.package_metadata(name, "1.0.0", b"unused");
    metadata["versions"]["1.0.0"]["_ecosystem"] = serde_json::json!("swift");
    registry
        .with_package_metadata(name, "1.0.0", b"unused", metadata)
        .await;
    let root = r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#;
    let project = TempProject::empty(root);
    let member = serde_json::json!({"name":"app","dependencies":{name:"npm:real-package@1.0.0"}})
        .to_string();
    let other = r#"{"name":"other","version":"1.0.0"}"#;
    project.write_file("packages/app/package.json", &member);
    project.write_file("packages/other/package.json", other);

    let output = lpm_with_registry_and_npm(&project, &registry.url())
        .env("LPM_TYPOSQUAT_GUARD", "0")
        .args([
            "install",
            name,
            "--filter",
            "app",
            "--filter",
            "other",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("source dependency in some selected manifests"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("packages/app/package.json"), member);
    assert_eq!(project.read_file("packages/other/package.json"), other);
    assert!(!project.path().join("lpm.lock").exists());
}

#[tokio::test]
async fn catalog_backed_aliases_survive_reinstall_and_save_flags() {
    for mode in ["manual", "prefer", "strict"] {
        for flag in [None, Some("--exact")] {
            let registry = MockRegistry::start().await;
            registry
                .with_package(
                    "real-package",
                    "1.0.0",
                    &make_tarball("real-package", "1.0.0"),
                )
                .await;
            let project = TempProject::empty(
                &serde_json::json!({
                    "name":"consumer", "dependencies":{"local-alias":"catalog:"},
                    "catalogs":{"default":{"local-alias":"npm:real-package@^1.0.0"}},
                    "lpm":{"catalogMode":mode}
                })
                .to_string(),
            );
            let mut command = lpm_with_registry_and_npm(&project, &registry.url());
            command.env("LPM_TYPOSQUAT_GUARD", "0").args([
                "install",
                "local-alias",
                "--no-skills",
                "--no-editor-setup",
                "--no-security-summary",
            ]);
            if let Some(flag) = flag {
                command.arg(flag);
            }
            command.assert().success();
            let manifest: serde_json::Value =
                serde_json::from_str(&project.read_file("package.json")).unwrap();
            assert_eq!(
                manifest["dependencies"]["local-alias"], "catalog:",
                "{mode} {flag:?}"
            );
            let installed: serde_json::Value =
                serde_json::from_str(&project.read_file("node_modules/local-alias/package.json"))
                    .unwrap();
            assert_eq!(installed["name"], "real-package");
            lpm_with_registry_and_npm(&project, &registry.url())
                .args([
                    "install",
                    "--frozen-lockfile",
                    "--no-skills",
                    "--no-editor-setup",
                    "--no-security-summary",
                ])
                .assert()
                .success();
        }
    }
}
