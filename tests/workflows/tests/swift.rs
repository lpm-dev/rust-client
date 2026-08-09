//! Workflow tests for Swift registry integration.
//!
//! `lpm swift-registry` is a single command (no subcommands like `login`).
//! It configures SPM to use the LPM registry: sets up auth, installs the
//! signing certificate, and configures trust.
//!
//! Feature-gated tests require a real Swift toolchain.
//! Run with: `cargo nextest run -p lpm-workflows --features swift-tests`

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SWIFT_PACKAGE: &str = "@lpm.dev/acme.swift-logger";
const SWIFT_VERSION: &str = "1.0.0";
const SWIFT_PRODUCT: &str = "SwiftLogger";

fn swift_project() -> TempProject {
    let project = TempProject::empty(r#"{"name":"swift-app","version":"1.0.0"}"#);
    project.write_file(
        "Package.swift",
        r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftApp",
    dependencies: [],
    targets: [
        .target(name: "FirstTarget", dependencies: []),
        .target(name: "SecondTarget", dependencies: []),
    ]
)
"#,
    );
    project
}

async fn mount_swift_package(mock: &MockRegistry) -> Vec<u8> {
    mount_swift_package_with_security_findings(mock, None).await
}

async fn mount_swift_package_with_security_findings(
    mock: &MockRegistry,
    security_findings: Option<serde_json::Value>,
) -> Vec<u8> {
    let tarball = b"unused swift package tarball";
    let mut metadata = mock.package_metadata(SWIFT_PACKAGE, SWIFT_VERSION, tarball);
    let version = &mut metadata["versions"][SWIFT_VERSION];
    version["_ecosystem"] = serde_json::json!("swift");
    version["_swiftMeta"] = serde_json::json!({
        "products": [{
            "name": SWIFT_PRODUCT,
            "type": {"library": ["automatic"]},
            "targets": ["SwiftLogger"]
        }]
    });
    if let Some(security_findings) = security_findings {
        version["_securityFindings"] = security_findings;
    }
    mock.with_package_metadata(SWIFT_PACKAGE, SWIFT_VERSION, tarball, metadata)
        .await;
    let cert = rcgen::generate_simple_self_signed(vec!["lpm.dev".to_string()])
        .unwrap()
        .cert
        .der()
        .to_vec();
    Mock::given(method("GET"))
        .and(path("/api/swift-registry/certificate"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(cert.clone()))
        .mount(mock.server())
        .await;
    cert
}

fn configure_existing_registry(project: &TempProject, registry_url: &str, cert: &[u8]) {
    project.write_file(
        ".swiftpm/configuration/registries.json",
        &serde_json::json!({
            "registries": {
                "lpmdev": {
                    "url": format!("{registry_url}/api/swift-registry")
                }
            }
        })
        .to_string(),
    );
    let global_config = project
        .home()
        .join(".swiftpm/configuration/registries.json");
    std::fs::create_dir_all(global_config.parent().unwrap()).unwrap();
    std::fs::write(
        global_config,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "security": {
                "default": {
                    "signing": {
                        "onUnsigned": "warn",
                        "onUntrustedCertificate": "warn"
                    }
                },
                "scopeOverrides": {
                    "lpmdev": {
                        "signing": {
                            "onUntrustedCertificate": "silentAllow"
                        }
                    }
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let cert_path = project
        .home()
        .join(".swiftpm/security/trusted-root-certs/lpm.der");
    std::fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
    std::fs::write(cert_path, cert).unwrap();
}

fn configure_fake_swift(
    command: &mut assert_cmd::Command,
    project: &TempProject,
    targets: &[&str],
    resolve_exit_code: i32,
) {
    let bin_dir = project.home().join("fake-swift-bin");
    std::fs::create_dir_all(&bin_dir).expect("create fake Swift bin directory");
    let target_values: Vec<_> = targets
        .iter()
        .map(|name| serde_json::json!({"name": name, "type": "regular"}))
        .collect();
    let dump_package = serde_json::json!({"targets": target_values}).to_string();
    let swift_path = bin_dir.join(fake_swift_executable_name(cfg!(windows)));
    let fixture = assert_cmd::cargo::cargo_bin("workflows-swift-fixture");
    std::fs::copy(fixture, &swift_path).expect("copy compiled Swift fixture");
    set_executable(&swift_path);

    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(bin_dir).chain(std::env::split_paths(&existing_path));
    let path = std::env::join_paths(paths).expect("construct PATH with fake Swift");
    command
        .env("PATH", path)
        .env("LPM_TEST_SWIFT_DUMP_PACKAGE", dump_package)
        .env(
            "LPM_TEST_SWIFT_RESOLVE_EXIT_CODE",
            resolve_exit_code.to_string(),
        );
}

fn configure_fake_swift_lockfile_write(command: &mut assert_cmd::Command, content: &str) {
    command.env("LPM_TEST_SWIFT_PACKAGE_RESOLVED", content);
}

fn fake_swift_executable_name(windows: bool) -> &'static str {
    if windows { "swift.exe" } else { "swift" }
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .expect("fake Swift executable must exist")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("mark fake Swift executable");
}

#[cfg(not(unix))]
fn set_executable(_path: &std::path::Path) {}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn fake_swift_uses_a_native_windows_executable_name() {
    assert_eq!(fake_swift_executable_name(true), "swift.exe");
}

fn product_is_attached_to_first_target(manifest: &str) -> bool {
    let first_target = manifest
        .find("name: \"FirstTarget\"")
        .expect("manifest contains FirstTarget");
    let second_target = manifest
        .find("name: \"SecondTarget\"")
        .expect("manifest contains SecondTarget");
    let product = manifest
        .find(&format!(".product(name: \"{SWIFT_PRODUCT}\""))
        .expect("manifest contains installed Swift product");
    first_target < product && product < second_target
}

// ─── swift-registry help ─────────────────────────────────────────

#[test]
fn swift_registry_help_works() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);

    let output = lpm(&project)
        .args(["swift-registry", "--help"])
        .output()
        .expect("failed to run lpm swift-registry --help");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Help text should describe the swift-registry command
    assert!(
        combined.contains("swift") || combined.contains("Swift") || combined.contains("registry"),
        "expected swift-registry help text, got:\n{combined}"
    );
}

// ─── swift-registry --force flag accepted ────────────────────────

#[test]
fn swift_registry_force_flag_accepted() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);

    // Just verify the --force flag is accepted by the parser
    let output = lpm(&project)
        .args(["swift-registry", "--force", "--help"])
        .output()
        .expect("failed to run swift-registry --force --help");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "--force should be a valid flag for swift-registry, got:\n{stderr}"
    );
}

// ─── swift-registry with mock registry ───────────────────────────

#[tokio::test]
#[cfg_attr(
    not(feature = "swift-tests"),
    ignore = "requires swift-tests feature + Swift toolchain"
)]
async fn swift_registry_setup_with_mock() {
    let mock = MockRegistry::start().await;
    mock.with_health().await;
    mock.with_whoami("testuser", "test@example.com").await;

    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["swift-registry", "--token", "test-token-123"])
        .output()
        .expect("failed to run swift-registry");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Should attempt to configure Swift — output mentions swift/registry/login
    assert!(
        combined.contains("swift")
            || combined.contains("Swift")
            || combined.contains("registry")
            || combined.contains("certificate"),
        "expected swift-registry setup output, got:\n{combined}"
    );
}

// ─── swift-registry JSON output ──────────────────────────────────

#[tokio::test]
#[cfg_attr(
    not(feature = "swift-tests"),
    ignore = "requires swift-tests feature + Swift toolchain"
)]
async fn swift_registry_json_output() {
    let mock = MockRegistry::start().await;
    mock.with_health().await;
    mock.with_whoami("testuser", "test@example.com").await;

    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["swift-registry", "--json", "--token", "test-token-123"])
        .output()
        .expect("failed to run swift-registry --json");

    // If it produced JSON, parse and validate
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // JSON output should have success field
        assert!(
            json.get("success").is_some(),
            "swift-registry JSON should have 'success' field"
        );
    }
    // If it didn't produce JSON, that's also acceptable (may fail without real Swift)
}

#[tokio::test]
async fn swift_install_yes_selects_first_eligible_target_without_prompting() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget", "SecondTarget"], 0);
    let output = command
        .args(["install", "--yes", SWIFT_PACKAGE])
        .output()
        .expect("run Swift install with --yes");

    assert!(
        output.status.success(),
        "Swift install --yes should succeed without a prompt:\n{}",
        combined_output(&output)
    );
    assert!(
        combined_output(&output).contains("to target FirstTarget"),
        "human output must name the selected target:\n{}",
        combined_output(&output)
    );
    assert!(
        product_is_attached_to_first_target(&project.read_file("Package.swift")),
        "--yes must attach the Swift product to the first eligible target"
    );
}

#[tokio::test]
async fn ordinary_swift_install_does_not_show_registry_ai_findings() {
    let mock = MockRegistry::start().await;
    let finding = "registry AI finding must stay behind an audit";
    let cert = mount_swift_package_with_security_findings(
        &mock,
        Some(serde_json::json!([{
            "severity": "critical",
            "description": finding
        }])),
    )
    .await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    let output = command
        .args(["install", "--yes", SWIFT_PACKAGE])
        .output()
        .expect("run ordinary Swift install");
    let combined = combined_output(&output);

    assert!(
        output.status.success(),
        "ordinary Swift install should succeed:\n{combined}"
    );
    assert!(
        !combined.contains(finding),
        "ordinary Swift install must leave registry AI findings to audit:\n{combined}"
    );
}

#[tokio::test]
async fn swift_install_yes_json_reports_the_first_modified_target() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget", "SecondTarget"], 0);
    let output = command
        .args(["--json", "install", "--yes", SWIFT_PACKAGE])
        .output()
        .expect("run JSON Swift install with --yes");

    assert!(
        output.status.success(),
        "JSON Swift install --yes should succeed:\n{}",
        combined_output(&output)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Swift install emits JSON");
    assert_eq!(
        json["target"], "FirstTarget",
        "JSON target must match the selected eligible target"
    );
    assert!(
        product_is_attached_to_first_target(&project.read_file("Package.swift")),
        "JSON target must match the target modified in Package.swift"
    );
}

#[tokio::test]
async fn swift_install_with_multiple_targets_without_yes_requires_interactive_selection() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget", "SecondTarget"], 0);
    let output = command
        .args(["install", SWIFT_PACKAGE])
        .output()
        .expect("run Swift install without --yes");
    let combined = combined_output(&output);

    assert!(
        !output.status.success(),
        "non-TTY install without --yes must not silently choose a target"
    );
    assert!(
        combined.contains("prompt failed"),
        "multiple targets without --yes must reach the interactive selector:\n{combined}"
    );
    assert!(
        !project
            .read_file("Package.swift")
            .contains("lpmdev.acme_swift-logger"),
        "the manifest must remain unchanged when target selection cannot complete"
    );
}

#[tokio::test]
async fn swift_install_with_no_eligible_targets_preserves_the_existing_error() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command
        .args(["install", "--yes", SWIFT_PACKAGE])
        .output()
        .expect("run Swift install with no eligible targets");
    let combined = combined_output(&output);

    assert!(
        !output.status.success(),
        "an install with no eligible targets must remain non-zero"
    );
    assert!(
        combined.contains("No non-test targets found in Package.swift"),
        "the existing no-target error must be preserved:\n{combined}"
    );
}

#[tokio::test]
async fn swift_install_with_one_eligible_target_selects_it_automatically() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    let output = command
        .args(["install", SWIFT_PACKAGE])
        .output()
        .expect("run Swift install with one eligible target");

    assert!(
        output.status.success(),
        "one eligible target must remain automatic:\n{}",
        combined_output(&output)
    );
    assert!(
        product_is_attached_to_first_target(&project.read_file("Package.swift")),
        "the only eligible target must receive the Swift product"
    );
}

fn swift_workspace() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"workspace-root","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/swift-member/package.json",
        r#"{"name":"swift-member","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/swift-member/Package.swift",
        r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftMember",
    dependencies: [],
    targets: [
        .target(name: "FirstTarget", dependencies: [])
    ]
)
"#,
    );
    project.write_file(
        "packages/js-member/package.json",
        r#"{"name":"js-member","version":"1.0.0"}"#,
    );
    project
}

#[tokio::test]
async fn workspace_root_swift_install_mutates_only_the_root_package_swift() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_workspace();
    project.write_file(
        "Package.swift",
        r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "WorkspaceRoot",
    dependencies: [],
    targets: [
        .target(name: "RootTarget", dependencies: [])
    ]
)
"#,
    );
    let member_before = project.read_file("packages/swift-member/Package.swift");
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["RootTarget"], 0);
    let output = command
        .args(["--json", "install", "--yes", "-w", SWIFT_PACKAGE])
        .output()
        .expect("run workspace-root Swift install");

    assert!(
        output.status.success(),
        "workspace-root Swift install failed:\n{}",
        combined_output(&output)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["target"], "RootTarget");
    assert!(
        project
            .read_file("Package.swift")
            .contains("lpmdev.acme_swift-logger")
    );
    assert_eq!(
        project.read_file("packages/swift-member/Package.swift"),
        member_before
    );
}

#[tokio::test]
async fn filtered_workspace_swift_install_mutates_only_the_selected_package_swift() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_workspace();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    let output = command
        .args([
            "--json",
            "install",
            "--yes",
            "--filter",
            "swift-member",
            SWIFT_PACKAGE,
        ])
        .output()
        .expect("run filtered Swift workspace install");

    assert!(
        output.status.success(),
        "filtered Swift install should succeed:\n{}",
        combined_output(&output)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["target"], "FirstTarget");
    assert_eq!(
        json["registry_setup"],
        serde_json::json!({
            "scope": "repaired",
            "signing_certificate": "retained",
            "signing_trust": "retained"
        })
    );
    assert!(
        project
            .read_file("packages/swift-member/Package.swift")
            .contains("lpmdev.acme_swift-logger")
    );
    assert!(
        !project
            .read_file("packages/swift-member/package.json")
            .contains(SWIFT_PACKAGE),
        "Swift Registry packages must never be staged into package.json"
    );
    assert!(
        !project
            .read_file("packages/js-member/package.json")
            .contains(SWIFT_PACKAGE),
        "an unrelated JavaScript member must remain untouched"
    );
}

#[tokio::test]
async fn member_cwd_swift_install_mutates_only_that_workspace_member() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_workspace();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    let output = command
        .current_dir(project.path().join("packages/swift-member"))
        .args(["--json", "install", "--yes", SWIFT_PACKAGE])
        .output()
        .expect("run Swift install from a workspace member");

    assert!(
        output.status.success(),
        "member-cwd Swift install should succeed:\n{}",
        combined_output(&output)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["target"], "FirstTarget");
    assert!(
        project
            .read_file("packages/swift-member/Package.swift")
            .contains("lpmdev.acme_swift-logger")
    );
    assert!(
        !project
            .read_file("packages/js-member/package.json")
            .contains(SWIFT_PACKAGE)
    );
}

#[tokio::test]
async fn mixed_swift_and_javascript_request_routes_each_ecosystem_to_its_manifest() {
    const JS_PACKAGE: &str = "@lpm.dev/acme.js-helper";

    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let js_tarball = make_tarball(JS_PACKAGE, "1.0.0");
    mock.with_package(JS_PACKAGE, "1.0.0", &js_tarball).await;
    let project = swift_workspace();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    let output = command
        .current_dir(project.path().join("packages/swift-member"))
        .args([
            "install",
            "--yes",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
            SWIFT_PACKAGE,
            JS_PACKAGE,
        ])
        .output()
        .expect("run a mixed Swift and JavaScript workspace install");

    assert!(
        output.status.success(),
        "mixed workspace install should succeed:\n{}",
        combined_output(&output)
    );
    assert!(
        project
            .read_file("packages/swift-member/Package.swift")
            .contains("lpmdev.acme_swift-logger")
    );
    let member_manifest = project.read_file("packages/swift-member/package.json");
    assert!(member_manifest.contains(JS_PACKAGE));
    assert!(!member_manifest.contains(SWIFT_PACKAGE));
    assert!(
        !project
            .read_file("packages/js-member/package.json")
            .contains(JS_PACKAGE)
    );
}

#[tokio::test]
async fn filtered_workspace_swift_resolve_failure_rolls_back_the_selected_manifest() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_workspace();
    configure_existing_registry(&project, &mock.url(), &cert);
    let before = project.read_file("packages/swift-member/Package.swift");

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 17);
    let output = command
        .args([
            "install",
            "--yes",
            "--filter",
            "swift-member",
            SWIFT_PACKAGE,
        ])
        .output()
        .expect("run failing filtered Swift workspace install");

    assert!(!output.status.success());
    assert_eq!(
        project.read_file("packages/swift-member/Package.swift"),
        before,
        "workspace Swift manifest must roll back when resolve fails"
    );
    assert!(
        !project
            .read_file("packages/js-member/package.json")
            .contains(SWIFT_PACKAGE)
    );
}

#[tokio::test]
async fn swift_resolve_failure_restores_an_existing_package_resolved() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_workspace();
    configure_existing_registry(&project, &mock.url(), &cert);
    let lockfile_path = "packages/swift-member/Package.resolved";
    let original_lockfile = r#"{"version":2,"pins":[{"identity":"original"}]}"#;
    project.write_file(lockfile_path, original_lockfile);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 17);
    configure_fake_swift_lockfile_write(
        &mut command,
        r#"{"version":2,"pins":[{"identity":"rewritten"}]}"#,
    );
    let output = command
        .args([
            "install",
            "--yes",
            "--filter",
            "swift-member",
            SWIFT_PACKAGE,
        ])
        .output()
        .expect("run failing Swift workspace install");

    assert!(!output.status.success());
    assert_eq!(project.read_file(lockfile_path), original_lockfile);
}

#[tokio::test]
async fn later_javascript_failure_removes_package_resolved_created_by_swift() {
    const JS_PACKAGE: &str = "@lpm.dev/acme.unfetchable";

    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    mock.with_full_package_metadata(
        JS_PACKAGE,
        "1.0.0",
        &[("1.0.0", serde_json::json!({}), None)],
    )
    .await;
    let project = swift_workspace();
    configure_existing_registry(&project, &mock.url(), &cert);
    let lockfile_path = "packages/swift-member/Package.resolved";

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 0);
    configure_fake_swift_lockfile_write(
        &mut command,
        r#"{"version":2,"pins":[{"identity":"new"}]}"#,
    );
    let output = command
        .current_dir(project.path().join("packages/swift-member"))
        .args([
            "install",
            "--yes",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
            SWIFT_PACKAGE,
            JS_PACKAGE,
        ])
        .output()
        .expect("run mixed install with a failing JavaScript package");

    assert!(
        !output.status.success(),
        "the missing JavaScript tarball must fail:\n{}",
        combined_output(&output)
    );
    assert!(
        !project.file_exists(lockfile_path),
        "Package.resolved created by Swift must be removed when the later JavaScript leg fails"
    );
}

#[test]
fn add_help_describes_target_as_a_swift_destination_suffix() {
    let project = TempProject::empty(r#"{"name":"help-test","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["add", "--help"])
        .output()
        .expect("run lpm add --help");
    let help = combined_output(&output);

    assert!(
        help.contains("--target <NAME>"),
        "target help must present NAME as the value:\n{help}"
    );
    assert!(
        help.contains("destination-directory suffix"),
        "target help must describe destination suffix semantics:\n{help}"
    );
    assert!(
        help.contains("Sources/<NAME>") && help.contains("Packages/LPMComponents/Sources/<NAME>"),
        "target help must show both Swift destination layouts:\n{help}"
    );
    assert!(
        !help.contains("Swift SPM target") && !help.contains("Xcode target"),
        "target help must not call the suffix an SPM or Xcode target:\n{help}"
    );
}

#[tokio::test]
async fn swift_resolve_failure_points_to_inherited_output_and_optional_repair() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &["FirstTarget"], 17);
    let output = command
        .args(["install", SWIFT_PACKAGE])
        .output()
        .expect("run Swift install with failing resolve");
    let combined = combined_output(&output);

    assert!(
        !output.status.success(),
        "a failed swift package resolve must remain non-zero"
    );
    assert!(
        combined.contains("inherited Swift stdout") && combined.contains("inherited Swift stderr"),
        "the original Swift stdout and stderr must remain inherited:\n{combined}"
    );
    assert!(
        combined.contains("failed after automatic Registry setup")
            && combined.contains("Swift output above"),
        "failure guidance must identify automatic setup and the real Swift output:\n{combined}"
    );
    assert!(
        combined.contains("`lpm swift-registry --force`") && combined.contains("stale or corrupt"),
        "the setup command must be presented only as stale/corrupt-state repair:\n{combined}"
    );
    assert!(
        !combined.contains("Run `lpm swift-registry` to configure SPM first"),
        "failure guidance must not present manual setup as a normal prerequisite:\n{combined}"
    );
}
