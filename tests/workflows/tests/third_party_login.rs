mod support;

use support::assertions::parse_json_output;
use support::{TempProject, lpm};

#[test]
fn login_npm_with_explicit_token_uses_slim_success() {
    let project = TempProject::empty(r#"{"name":"login-npm-token","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["login", "--npm", "--token", "npm-fallback-token"])
        .output()
        .expect("failed to run lpm login --npm --token");

    assert!(
        output.status.success(),
        "explicit npm token login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Token stored for npmjs.org"),
        "token login must use a slim success line, got:\n{stderr}",
    );
    assert!(
        stderr.contains("secure storage backend: encrypted file fallback"),
        "token login must report the secure storage backend, got:\n{stderr}",
    );
    assert!(
        stderr.contains("Encrypted file fallback is active"),
        "token login must warn when auth storage uses the encrypted file fallback, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "token login must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn login_npm_with_explicit_token_json_reports_file_backed_storage_backend() {
    let project = TempProject::empty(r#"{"name":"login-npm-token","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["login", "--npm", "--token", "npm-fallback-token", "--json"])
        .output()
        .expect("failed to run lpm login --npm --token --json");

    assert!(
        output.status.success(),
        "explicit npm token login json should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(
        json["storage_backend"],
        serde_json::json!("encrypted_file_fallback")
    );
    assert_eq!(json["storage_degraded"], serde_json::json!(true));
}
