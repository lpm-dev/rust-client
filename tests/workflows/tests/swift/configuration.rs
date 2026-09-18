use super::*;

#[tokio::test]
async fn explicit_scope_setup_preserves_extensions_and_unrelated_registry_entries() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    project.write_file(".swiftpm/configuration/registries.json", r#"{"version":1,"extension":{"keep":true},"registries":{"other":{"url":"https://other.example"},"lpmdev":{"url":"https://old.example","extension":"keep"}}}"#);
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    command
        .args(["swift-registry", "--json"])
        .assert()
        .success();
    let config: serde_json::Value =
        serde_json::from_str(&project.read_file(".swiftpm/configuration/registries.json")).unwrap();
    assert_eq!(config["extension"]["keep"], true);
    assert_eq!(
        config["registries"]["other"]["url"],
        "https://other.example"
    );
    assert_eq!(config["registries"]["lpmdev"]["extension"], "keep");
    assert_eq!(
        config["registries"]["lpmdev"]["url"],
        format!("{}/api/swift-registry", mock.url())
    );
    assert_eq!(
        config["registries"]["lpmdev"]["supportsAvailability"],
        false
    );
}

#[tokio::test]
async fn malformed_later_workspace_configuration_prevents_setup_for_every_member() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_workspace();
    configure_existing_registry(&project, &mock.url(), &cert);
    let manifest = project.read_file("packages/swift-member/Package.swift");
    project.write_file(
        "packages/z-swift/package.json",
        r#"{"name":"z-swift","version":"1.0.0"}"#,
    );
    project.write_file("packages/z-swift/Package.swift", &manifest);
    project.write_file(
        "packages/z-swift/.swiftpm/configuration/registries.json",
        "invalid member configuration",
    );
    let global = swiftpm_home(&project).join("configuration/registries.json");
    let original_global = std::fs::read(&global).unwrap();
    let command_log = project.home().join("swift-commands.log");
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    configure_fake_swift_command_log(&mut command, &command_log);
    let output = command
        .args(["install", "--filter", "*", "--yes", SWIFT_PACKAGE])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid SwiftPM configuration"));
    assert_eq!(
        project.read_file("packages/swift-member/Package.swift"),
        manifest
    );
    assert_eq!(
        project.read_file("packages/z-swift/Package.swift"),
        manifest
    );
    assert_eq!(
        project.read_file("packages/z-swift/.swiftpm/configuration/registries.json"),
        "invalid member configuration"
    );
    assert_eq!(std::fs::read(global).unwrap(), original_global);
    assert!(
        !project
            .path()
            .join("packages/swift-member/.swiftpm")
            .exists()
    );
    assert!(!command_log.exists());
}

#[tokio::test]
async fn invalid_configuration_stops_explicit_setup_and_install_before_swift_or_file_changes() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    for global in [true, false] {
        for install in [true, false] {
            let project = swift_project();
            configure_existing_registry(&project, &mock.url(), &cert);
            let local_config = project
                .path()
                .join(".swiftpm/configuration/registries.json");
            let global_config = swiftpm_home(&project).join("configuration/registries.json");
            let invalid = if global {
                &global_config
            } else {
                &local_config
            };
            std::fs::write(invalid, "invalid original configuration").unwrap();
            let certificate = swiftpm_home(&project).join("security/trusted-root-certs/lpm.der");
            std::fs::write(&certificate, "previous certificate").unwrap();
            let files = [
                project.path().join("Package.swift"),
                local_config.clone(),
                global_config.clone(),
                certificate,
            ];
            let originals = files
                .iter()
                .map(|path| std::fs::read(path).unwrap())
                .collect::<Vec<_>>();
            let command_log = project.home().join("swift-commands.log");
            let mut command = lpm_with_registry(&project, &mock.url());
            configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
            configure_fake_swift_command_log(&mut command, &command_log);
            if install {
                command.args(["install", SWIFT_PACKAGE, "--yes", "--force"]);
            } else {
                command.args(["swift-registry", "--force"]);
            }
            let output = command.output().unwrap();
            assert!(
                !output.status.success(),
                "global={global}, install={install}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("Invalid SwiftPM configuration"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            for (path, original) in files.iter().zip(originals) {
                assert_eq!(std::fs::read(path).unwrap(), original, "{}", path.display());
            }
            assert!(
                !command_log.exists(),
                "Swift must not run before configuration preflight"
            );
        }
    }
}
