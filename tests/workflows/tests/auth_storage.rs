mod support;

use support::assertions::parse_json_output;
use support::auth_state::{SessionSeed, seed_sessions};
use support::{TempProject, lpm_with_registry};

fn doctor_check<'a>(json: &'a serde_json::Value, code: &str) -> &'a serde_json::Value {
    json["checks"]
        .as_array()
        .expect("doctor checks must be an array")
        .iter()
        .find(|check| check["code"].as_str() == Some(code))
        .unwrap_or_else(|| panic!("doctor output must include `{code}`: {json}"))
}

#[test]
fn doctor_json_reports_file_backed_auth_storage_as_warning() {
    let project = TempProject::empty(r#"{"name":"auth-storage","version":"1.0.0"}"#);
    let registry_url = "https://lpm.example.test";
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url,
            access_token: Some("stored-token"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, registry_url)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    let check = doctor_check(&json, "auth_storage_fallback");
    assert_eq!(check["severity"].as_str(), Some("warn"));
    assert_eq!(check["passed"].as_bool(), Some(true));
    assert_eq!(
        check["detail"].as_str(),
        Some("secure storage backend: encrypted file fallback")
    );
}
