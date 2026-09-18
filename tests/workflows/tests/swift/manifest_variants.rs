use super::*;

async fn mount_variants(mock: &MockRegistry) -> Vec<u8> {
    let cert = rcgen::generate_simple_self_signed(vec!["lpm.dev".into()])
        .unwrap()
        .cert
        .der()
        .to_vec();
    Mock::given(method("GET"))
        .and(path("/api/swift-registry/certificate"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(cert.clone()))
        .mount(mock.server())
        .await;
    let tarball = b"unused swift package tarball";
    let mut metadata = mock.package_metadata(SWIFT_PACKAGE, SWIFT_VERSION, tarball);
    metadata["versions"][SWIFT_VERSION]["_ecosystem"] = serde_json::json!("swift");
    metadata["versions"][SWIFT_VERSION]["_swiftMeta"] = serde_json::json!({
        "products": [], "platforms": [], "requiredCapabilities": ["swift-manifest-variants-v1"],
        "manifestSet": { "schemaVersion": 1, "manifests": [
            { "filename": "Package.swift", "toolsVersion": "5.9.0", "platforms": [{"name":"ios","version":"13.0"}], "products": [{ "name": "Basic", "type": "library", "targets": ["Basic"] }] },
            { "filename": "Package@swift-6.swift", "toolsVersion": "6.0.0", "platforms": [{"name":"ios","version":"17.0"}], "products": [{ "name": "Modern", "type": "library", "targets": ["Modern"] }] }
        ]}
    });
    mock.with_package_metadata(SWIFT_PACKAGE, SWIFT_VERSION, tarball, metadata)
        .await;
    cert
}

#[tokio::test]
async fn swift_install_selects_the_library_from_the_resolving_tools_version() {
    let mock = MockRegistry::start().await;
    let cert = mount_variants(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    command
        .args([
            "install",
            SWIFT_PACKAGE,
            "--yes",
            "--json",
            "--no-audit-after-install",
        ])
        .assert()
        .success();
    let manifest = std::fs::read_to_string(project.path().join("Package.swift")).unwrap();
    assert!(manifest.contains(".product(name: \"Modern\""), "{manifest}");
    assert!(!manifest.contains(".product(name: \"Basic\""), "{manifest}");
}

#[tokio::test]
async fn swift_install_accepts_the_native_apple_vendor_version_prefix() {
    let mock = MockRegistry::start().await;
    let cert = mount_variants(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    command
        .env("LPM_TEST_SWIFT_VENDOR", "Apple ")
        .args([
            "install",
            SWIFT_PACKAGE,
            "--yes",
            "--json",
            "--no-audit-after-install",
        ])
        .assert()
        .success();
    assert!(project.read_file("Package.swift").contains("Modern"));
}

#[tokio::test]
async fn swift_install_rejects_an_incompatible_manifest_without_editing_the_project() {
    let mock = MockRegistry::start().await;
    let cert = mount_variants(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);
    let before = project.read_file("Package.swift");
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    command
        .env("LPM_TEST_SWIFT_TOOLS_VERSION", "5.8.0")
        .args(["install", SWIFT_PACKAGE, "--yes", "--json"])
        .assert()
        .failure();
    assert_eq!(project.read_file("Package.swift"), before);
}

#[tokio::test]
async fn xcode_uses_the_selected_manifests_product_and_platform() {
    let mock = MockRegistry::start().await;
    let cert = mount_variants(&mock).await;
    let project = TempProject::empty(r#"{"name":"xcode-app","version":"1.0.0"}"#);
    write_xcode_project(&project, "", "MyApp");
    configure_existing_registry(&project, &mock.url(), &cert);
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["unused"], 0);
    command
        .args([
            "install",
            SWIFT_PACKAGE,
            "--yes",
            "--json",
            "--no-audit-after-install",
        ])
        .assert()
        .success();
    let wrapper = project.read_file("Packages/LPMDependencies/Package.swift");
    assert!(wrapper.contains("Modern"), "{wrapper}");
    assert!(wrapper.contains(".iOS(\"17.0\")"), "{wrapper}");
}

#[tokio::test]
async fn xcode_toolchain_mismatch_fails_before_wrapper_or_project_edits() {
    let mock = MockRegistry::start().await;
    mount_variants(&mock).await;
    let project = TempProject::empty(r#"{"name":"xcode-app","version":"1.0.0"}"#);
    write_xcode_project(&project, "", "MyApp");
    let before = project.read_file("MyApp.xcodeproj/project.pbxproj");
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["unused"], 0);
    let output = command
        .env("LPM_TEST_XCODE_SWIFT_TOOLS_VERSION", "5.9.0")
        .args(["install", SWIFT_PACKAGE, "--yes", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert!(combined_output(&output).contains("different tools versions"));
    assert_eq!(project.read_file("MyApp.xcodeproj/project.pbxproj"), before);
    assert!(!project.file_exists("Packages/LPMDependencies/Package.swift"));
}
