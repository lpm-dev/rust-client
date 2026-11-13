mod support;

use support::assertions::parse_json_output;
use support::{TempProject, lpm};

/// A proxy error has its own machine-readable code, `proxy`, apart from a
/// script's.
#[test]
fn proxy_errors_report_the_proxy_error_code_in_json() {
    let project = TempProject::empty(r#"{"name":"proxy-error","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["proxy", "status", "--detach", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["success"], false);
    assert_eq!(envelope["error_code"], "proxy");
    insta::assert_json_snapshot!("proxy_error_json", envelope);
}

#[test]
fn proxy_status_json_distinguishes_bound_and_public_https_addresses() {
    let project = TempProject::empty(r#"{"name":"proxy-status","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["proxy", "status", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["tlsAddr"], serde_json::Value::Null);
    assert_eq!(value["public_tls_addr"], serde_json::Value::Null);
    insta::assert_json_snapshot!("proxy_status_json_absent", value);
}
