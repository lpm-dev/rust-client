use super::*;

fn project() -> TempProject {
    let project = TempProject::empty(r#"{"name":"xcode-app","version":"1.0.0"}"#);
    write_xcode_project(&project, "", "MyApp");
    project
}

fn install(project: &TempProject, mock: &MockRegistry) -> assert_cmd::Command {
    let mut command = lpm_with_registry(project, &mock.url());
    configure_fake_swift(&mut command, project, &["unused"], 0);
    command.args(["install", "--yes", SWIFT_PACKAGE]);
    command
}

#[tokio::test]
async fn xcode_reinstall_repairs_missing_target_and_framework_references() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = project();
    configure_existing_registry(&project, &mock.url(), &cert);
    install(&project, &mock).assert().success();
    let path = "MyApp.xcodeproj/project.pbxproj";
    let original = project.read_file(path);
    let damaged = original
        .lines()
        .filter(|line| {
            !line.trim().ends_with("/* LPMDependencies */,")
                && !line
                    .trim()
                    .ends_with("/* LPMDependencies in Frameworks */,")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert_ne!(original, damaged);
    project.write_file(path, &damaged);
    install(&project, &mock).assert().success();
    let repaired = project.read_file(path);
    assert!(
        repaired
            .lines()
            .any(|line| line.trim().ends_with("/* LPMDependencies */,")),
        "app product reference missing: {repaired}"
    );
    assert!(
        repaired.lines().any(|line| line
            .trim()
            .ends_with("/* LPMDependencies in Frameworks */,")),
        "Frameworks reference missing: {repaired}"
    );
    install(&project, &mock).assert().success();
    assert_eq!(project.read_file(path), repaired);
}

fn workspace(project: &TempProject) -> &'static str {
    project.write_file(
        "Custom.xcworkspace/contents.xcworkspacedata",
        r#"<Workspace version="1.0"><FileRef location="group:MyApp.xcodeproj"/></Workspace>"#,
    );
    let lock = "Custom.xcworkspace/xcshareddata/swiftpm/Package.resolved";
    project.write_file(lock, r#"{"version":3,"pins":[{"identity":"old"}]}"#);
    lock
}

#[tokio::test]
async fn xcode_install_updates_the_containing_workspace_lockfile() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = project();
    configure_existing_registry(&project, &mock.url(), &cert);
    let lock = workspace(&project);
    let log = project.path().join("xcode.log");
    install(&project, &mock)
        .env("LPM_TEST_XCODE_LOCKFILE", project.path().join(lock))
        .env("LPM_TEST_XCODE_LOG", &log)
        .assert()
        .success();
    assert!(project.read_file(lock).contains("lpmdev.acme_swift-logger"));
    let commands = std::fs::read_to_string(log).unwrap();
    assert!(
        commands.contains("-project"),
        "project resolution omitted: {commands}"
    );
    assert!(
        commands.contains("-workspace") && commands.contains("Custom QA"),
        "{commands}"
    );
}

#[tokio::test]
async fn xcode_resolution_failure_restores_workspace_lockfile_and_project() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = project();
    configure_existing_registry(&project, &mock.url(), &cert);
    let lock = workspace(&project);
    let original = project.read_file(lock);
    let pbx = project.read_file("MyApp.xcodeproj/project.pbxproj");
    install(&project, &mock)
        .env("LPM_TEST_XCODE_LOCKFILE", project.path().join(lock))
        .env("LPM_TEST_XCODE_EXIT", "74")
        .assert()
        .failure();
    assert_eq!(project.read_file(lock), original);
    assert_eq!(project.read_file("MyApp.xcodeproj/project.pbxproj"), pbx);
    assert!(!project.file_exists("Packages/LPMDependencies/Package.swift"));
}

#[tokio::test]
async fn xcode_install_uses_effective_xcconfig_deployment_minima() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = project();
    configure_existing_registry(&project, &mock.url(), &cert);
    let path = "MyApp.xcodeproj/project.pbxproj";
    let pbx = project.read_file(path).replace(
        "isa = PBXProject;",
        "isa = PBXProject;\n baseConfigurationReference = EEEEEEEEEEEEEEEEEEEEEEEE;",
    );
    project.write_file(path, &pbx);
    let settings = serde_json::json!({"Debug":{"IPHONEOS_DEPLOYMENT_TARGET":"17.0","SUPPORTED_PLATFORMS":"iphoneos iphonesimulator","TVOS_DEPLOYMENT_TARGET":"26.5"},"Release":{"IPHONEOS_DEPLOYMENT_TARGET":"18.0"}});
    install(&project, &mock)
        .env("LPM_TEST_XCODE_SETTINGS", settings.to_string())
        .assert()
        .success();
    let wrapper = project.read_file("Packages/LPMDependencies/Package.swift");
    assert!(wrapper.contains(".iOS(\"17.0\")"), "{wrapper}");
    assert!(
        !wrapper.contains(".tvOS("),
        "unsupported platform default leaked: {wrapper}"
    );
}

#[tokio::test]
async fn xcode_reinstall_repairs_a_deleted_frameworks_phase() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = project();
    configure_existing_registry(&project, &mock.url(), &cert);
    install(&project, &mock).assert().success();
    let path = "MyApp.xcodeproj/project.pbxproj";
    let original = project.read_file(path);
    let start = original
        .find("/* Begin PBXFrameworksBuildPhase section */")
        .unwrap();
    let end = original
        .find("/* End PBXFrameworksBuildPhase section */")
        .unwrap()
        + "/* End PBXFrameworksBuildPhase section */".len();
    let damaged = format!("{}{}", &original[..start], &original[end..])
        .replace("\t\t\t\tAAAAAAAAAAAAAAAAAAAAAAAA /* Frameworks */,\n", "");
    project.write_file(path, &damaged);
    install(&project, &mock).assert().success();
    let repaired = project.read_file(path);
    assert!(repaired.contains("isa = PBXFrameworksBuildPhase;"));
    assert!(repaired.lines().any(|line| {
        line.trim()
            .ends_with("/* LPMDependencies in Frameworks */,")
    }));
    install(&project, &mock).assert().success();
    assert_eq!(project.read_file(path), repaired);
}

#[tokio::test]
async fn xcode_failed_resolution_removes_a_new_project_lockfile() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = project();
    configure_existing_registry(&project, &mock.url(), &cert);
    let lock = "MyApp.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved";
    install(&project, &mock)
        .env("LPM_TEST_XCODE_LOCKFILE", project.path().join(lock))
        .env("LPM_TEST_XCODE_EXIT", "74")
        .assert()
        .failure();
    assert!(!project.file_exists(lock));
}

#[tokio::test]
async fn xcode_install_resolves_a_workspace_containing_a_nested_project() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = TempProject::empty(r#"{"name":"xcode-app","version":"1.0.0"}"#);
    write_xcode_project(&project, "App", "MyApp");
    project.write_file(
        "Custom.xcworkspace/contents.xcworkspacedata",
        r#"<Workspace version="1.0"><FileRef location="group:App/MyApp.xcodeproj"/></Workspace>"#,
    );
    configure_existing_registry(&project, &mock.url(), &cert);
    let lock = "Custom.xcworkspace/xcshareddata/swiftpm/Package.resolved";
    let log = project.path().join("xcode.log");
    install(&project, &mock)
        .env("LPM_TEST_XCODE_LOCKFILE", project.path().join(lock))
        .env("LPM_TEST_XCODE_LOG", &log)
        .assert()
        .success();
    assert!(project.read_file(lock).contains("lpmdev.acme_swift-logger"));
    assert!(
        std::fs::read_to_string(log)
            .unwrap()
            .contains("Custom.xcworkspace")
    );
    assert!(!project.file_exists("Packages/LPMDependencies/Package.swift"));
}
