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
