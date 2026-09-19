mod support;

use support::{TempProject, lpm};

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
