//! Workflow tests for Swift registry integration.
//!
//! `lpm swift-registry` is a single command (no subcommands like `login`).
//! It configures SPM to use the LPM registry: sets up auth, installs the
//! signing certificate, and configures trust.
//!
//! Feature-gated tests require a real Swift toolchain.
//! Run with: `cargo nextest run -p lpm-workflows --features swift-tests`

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};

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

async fn mount_swift_package(mock: &MockRegistry) {
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
    mock.with_package_metadata(SWIFT_PACKAGE, SWIFT_VERSION, tarball, metadata)
        .await;
}

fn configure_existing_registry(project: &TempProject, registry_url: &str) {
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

    #[cfg(windows)]
    let swift_path = bin_dir.join("swift.cmd");
    #[cfg(not(windows))]
    let swift_path = bin_dir.join("swift");

    #[cfg(windows)]
    let script = format!(
        "@echo off\r\n\
         if \"%1 %2\"==\"package dump-package\" (\r\n\
           echo {dump_package}\r\n\
           exit /b 0\r\n\
         )\r\n\
         if \"%1 %2\"==\"package resolve\" (\r\n\
           if not \"{resolve_exit_code}\"==\"0\" (\r\n\
             echo inherited Swift stdout\r\n\
             1>&2 echo inherited Swift stderr\r\n\
           )\r\n\
           exit /b {resolve_exit_code}\r\n\
         )\r\n\
         exit /b 64\r\n"
    );
    #[cfg(not(windows))]
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1 $2\" = \"package dump-package\" ]; then\n\
           printf '%s\\n' '{dump_package}'\n\
           exit 0\n\
         fi\n\
         if [ \"$1 $2\" = \"package resolve\" ]; then\n\
           if [ {resolve_exit_code} -ne 0 ]; then\n\
             printf '%s\\n' 'inherited Swift stdout'\n\
             printf '%s\\n' 'inherited Swift stderr' >&2\n\
           fi\n\
           exit {resolve_exit_code}\n\
         fi\n\
         exit 64\n"
    );
    std::fs::write(&swift_path, script).expect("write fake Swift executable");
    set_executable(&swift_path);

    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(bin_dir).chain(std::env::split_paths(&existing_path));
    let path = std::env::join_paths(paths).expect("construct PATH with fake Swift");
    command.env("PATH", path);
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
    mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url());

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
async fn swift_install_yes_json_reports_the_first_modified_target() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url());

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
    mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url());

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
    mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url());

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
    mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url());

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
    mount_swift_package(&mock).await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url());

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
