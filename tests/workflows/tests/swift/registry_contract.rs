use super::*;

#[tokio::test]
async fn swift_registry_normalizes_a_trailing_slash() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    let mut command = lpm_with_registry(&project, &format!("{}/", mock.url()));
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command.args(["swift-registry", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json["registry_url"],
        format!("{}/api/swift-registry", mock.url())
    );
}

#[tokio::test]
async fn swift_registry_uppercase_https_still_configures_authentication() {
    let mock = MockRegistry::start().await;
    let registry_url = mock.url().replacen("http://", "HTTPS://", 1);
    let project = swift_project();
    let capture = project.path().join("login.json");
    let mut command = lpm_with_registry(&project, &registry_url);
    configure_fake_swift(&mut command, &project, &[], 0);
    configure_fake_swift_login_capture(&mut command, &capture);
    let output = command
        .env("LPM_TEST_SWIFT_LOGIN_EXIT_CODE", "7")
        .args(["swift-registry", "--token", "session-token", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let args: Vec<String> =
        serde_json::from_slice(&std::fs::read(&capture).unwrap_or_else(|_| {
            panic!("authentication was skipped: {}", combined_output(&output))
        }))
        .unwrap();
    assert_eq!(
        args[0],
        format!(
            "{}/api/swift-registry",
            registry_url.replacen("HTTPS://", "https://", 1)
        )
    );
}

#[tokio::test]
async fn swift_registry_rejects_query_and_fragment_before_scope_changes() {
    let mock = MockRegistry::start().await;
    for suffix in ["?mode=registry", "#registry"] {
        let project = swift_project();
        let capture = project.path().join("commands.log");
        let mut command = lpm_with_registry(&project, &format!("{}{suffix}", mock.url()));
        configure_fake_swift(&mut command, &project, &[], 0);
        configure_fake_swift_command_log(&mut command, &capture);
        let output = command.args(["swift-registry", "--json"]).output().unwrap();
        assert!(!output.status.success(), "{}", combined_output(&output));
        assert!(!capture.exists(), "invalid base URL invoked SwiftPM");
        assert!(!project.path().join(".swiftpm").exists());
    }
}

#[tokio::test]
async fn swift_registry_json_does_not_break_a_subprocess_stderr_writer() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command
        .env("LPM_TEST_SWIFT_SET_STDERR", "1")
        .args(["swift-registry", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["success"], true);
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[tokio::test]
async fn swift_registry_http_json_reports_unencrypted_transport() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command.args(["swift-registry", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["https"], false);
    assert_eq!(json["trust_anchor"], "insecure_http");
    assert_eq!(json["authentication_outcome"], "skipped_http");
    insta::assert_json_snapshot!("swift_registry_http_setup", json, {
        ".registry_url" => "[registry]/api/swift-registry"
    });
}

const LPM_DEV: &str = "https://lpm.dev";
const LPM_DEV_ROOT: &str = "c96df3ac7c141082cae02d6cbfa41b3753d64972e3199c64ba41a05359966cde";

fn lpm_dev_roots_directory(project: &TempProject) -> std::path::PathBuf {
    swiftpm_home(project)
        .join("security")
        .join("lpm-trusted-roots")
        .join("lpm.dev")
}

fn lpm_dev_signing(project: &TempProject) -> serde_json::Value {
    let config: serde_json::Value = serde_json::from_slice(
        &std::fs::read(swiftpm_home(project).join("configuration/registries.json")).unwrap(),
    )
    .unwrap();
    config["security"]["registryOverrides"]["lpm.dev"]["signing"].clone()
}

fn assert_lpm_dev_is_pinned(project: &TempProject) {
    let signing = lpm_dev_signing(project);
    assert_eq!(signing["onUnsigned"], "error", "{signing}");
    assert_eq!(signing["onUntrustedCertificate"], "error", "{signing}");
    assert_eq!(
        signing["includeDefaultTrustedRootCertificates"], false,
        "{signing}"
    );
    let roots = lpm_dev_roots_directory(project);
    assert_eq!(
        std::fs::canonicalize(signing["trustedRootCertificatesPath"].as_str().unwrap()).unwrap(),
        std::fs::canonicalize(&roots).unwrap()
    );
    let entries: Vec<_> = std::fs::read_dir(&roots)
        .unwrap()
        .map(|entry| entry.unwrap())
        .collect();
    assert_eq!(entries.len(), 1, "the roots directory holds only the root");
    assert_eq!(
        entries[0].file_name(),
        format!("{LPM_DEV_ROOT}.der").as_str()
    );
    let root = std::fs::read(entries[0].path()).unwrap();
    assert_eq!(
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&root)),
        LPM_DEV_ROOT
    );
}

#[tokio::test]
async fn swift_registry_pins_lpm_dev_releases_to_its_built_in_signing_root() {
    let project = swift_project();
    let mut command = lpm_with_registry(&project, LPM_DEV);
    configure_fake_swift(&mut command, &project, &[], 0);

    let output = command.args(["swift-registry", "--json"]).output().unwrap();

    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["trust_anchor"], "pinned_root");
    assert_eq!(json["signer_trust_policy"], "error");
    insta::assert_json_snapshot!("swift_registry_lpm_dev_setup", json);
    assert_lpm_dev_is_pinned(&project);
}

#[tokio::test]
async fn swift_registry_replaces_lpm_dev_s_earlier_silent_allow_and_unused_certificate() {
    let project = swift_project();
    configure_existing_registry(&project, LPM_DEV);
    assert_eq!(
        lpm_dev_signing(&project)["onUntrustedCertificate"],
        "silentAllow"
    );
    let earlier_certificate = swiftpm_home(&project).join("security/trusted-root-certs/lpm.der");
    std::fs::create_dir_all(earlier_certificate.parent().unwrap()).unwrap();
    std::fs::write(
        &earlier_certificate,
        b"certificate an earlier release wrote",
    )
    .unwrap();
    let mut command = lpm_with_registry(&project, LPM_DEV);
    configure_fake_swift(&mut command, &project, &[], 0);

    let output = command.args(["swift-registry", "--json"]).output().unwrap();

    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["signing_certificate_outcome"], "installed");
    assert_eq!(json["signing_trust_outcome"], "configured");
    assert_lpm_dev_is_pinned(&project);
    assert!(!earlier_certificate.exists());
}

#[tokio::test]
async fn swift_registry_warns_when_the_project_s_own_signing_settings_set_the_pin_aside() {
    let project = swift_project();
    project.write_file(
        ".swiftpm/configuration/registries.json",
        &serde_json::json!({
            "version": 1,
            "registries": {"lpmdev": {"url": format!("{LPM_DEV}/api/swift-registry")}},
            "security": {"default": {"signing": {"onUnsigned": "warn"}}}
        })
        .to_string(),
    );

    let mut command = lpm_with_registry(&project, LPM_DEV);
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command.args(["swift-registry"]).output().unwrap();
    assert!(output.status.success(), "{}", combined_output(&output));
    assert!(
        combined_output(&output).contains("has its own signing settings"),
        "{}",
        combined_output(&output)
    );

    let mut command = lpm_with_registry(&project, LPM_DEV);
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command.args(["swift-registry", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["project_signing_overrides_pin"], true);
    assert_lpm_dev_is_pinned(&project);
}

#[tokio::test]
async fn xcode_registry_scopes_use_the_same_normalized_url() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    Mock::given(wiremock::matchers::path_regex(r"^//"))
        .respond_with(|request: &wiremock::Request| {
            let mut location = format!("/{}", request.url.path().trim_start_matches('/'));
            if let Some(query) = request.url.query() {
                location.push('?');
                location.push_str(query);
            }
            ResponseTemplate::new(307).insert_header("Location", location.as_str())
        })
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"xcode-app","version":"1.0.0"}"#);
    write_xcode_project(&project, "", "MyApp");
    configure_existing_registry(&project, &mock.url());
    let mut command = lpm_with_registry(&project, &format!("{}/", mock.url()));
    configure_fake_swift(&mut command, &project, &["unused"], 0);
    command
        .args(["install", "--yes", SWIFT_PACKAGE])
        .assert()
        .success();
    let global: serde_json::Value = serde_json::from_slice(
        &std::fs::read(swiftpm_home(&project).join("configuration/registries.json")).unwrap(),
    )
    .unwrap();
    let local: serde_json::Value = serde_json::from_str(
        &project.read_file("Packages/LPMDependencies/.swiftpm/configuration/registries.json"),
    )
    .unwrap();
    let expected = format!("{}/api/swift-registry", mock.url());
    assert_eq!(local["registries"]["lpmdev"]["url"], expected);
    assert_eq!(global["registries"]["lpmdev"]["url"], expected);
}

#[tokio::test]
async fn swift_registry_repairs_xcode_user_scope_and_preserves_other_registries() {
    for existing in [false, true] {
        let mock = MockRegistry::start().await;
        mount_swift_package(&mock).await;
        let project = TempProject::empty(r#"{"name":"xcode-registry-setup","version":"1.0.0"}"#);
        write_xcode_project(&project, "", "MyApp");
        let global_path = swiftpm_home(&project).join("configuration/registries.json");
        if existing {
            configure_existing_registry(&project, &mock.url());
            let mut global: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&global_path).unwrap()).unwrap();
            global["registries"]["acme"] =
                serde_json::json!({"url":"https://packages.example.com"});
            std::fs::write(&global_path, serde_json::to_vec(&global).unwrap()).unwrap();
        }
        for _ in 0..2 {
            let mut command = lpm_with_registry(&project, &mock.url());
            configure_fake_swift(&mut command, &project, &[], 0);
            command
                .args(["swift-registry", "--json"])
                .assert()
                .success();
            let global: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&global_path).unwrap()).unwrap();
            assert_eq!(
                global["registries"]["lpmdev"]["url"],
                format!("{}/api/swift-registry", mock.url())
            );
            if existing {
                assert_eq!(
                    global["registries"]["acme"]["url"],
                    "https://packages.example.com"
                );
            }
        }
    }
}

#[tokio::test]
async fn swift_registry_ambiguous_xcode_selection_stops_before_configuration_changes() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = TempProject::empty(r#"{"name":"ambiguous-xcode-setup","version":"1.0.0"}"#);
    write_xcode_project(&project, "", "First");
    write_xcode_project(&project, "", "Second");
    let capture = project.path().join("swift-commands.log");
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &[], 0);
    configure_fake_swift_command_log(&mut command, &capture);
    command
        .args(["swift-registry", "--json"])
        .assert()
        .failure();
    assert!(!capture.exists());
    assert!(!project.path().join(".swiftpm").exists());
    assert!(
        !swiftpm_home(&project)
            .join("configuration/registries.json")
            .exists()
    );
}

#[tokio::test]
async fn swift_registry_prefers_local_swift_manifest_over_xcode_global_scope() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    write_xcode_project(&project, "", "MyApp");
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &[], 0);
    command
        .args(["swift-registry", "--json"])
        .assert()
        .success();
    let global: serde_json::Value = serde_json::from_slice(
        &std::fs::read(swiftpm_home(&project).join("configuration/registries.json")).unwrap(),
    )
    .unwrap();
    assert!(global["registries"]["lpmdev"].is_null());
}
