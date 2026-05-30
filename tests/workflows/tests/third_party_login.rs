mod support;

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
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "token login must not use cliclack gutter output, got:\n{stderr}",
    );
}
