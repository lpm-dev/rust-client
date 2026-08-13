//! Workflow coverage for `lpm doctor` validation of `lpm.json`.

mod support;

use support::assertions::parse_json_output;
use support::{TempProject, lpm};

fn doctor_lpm_json_check(project: &TempProject) -> serde_json::Value {
    let output = lpm(project)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);

    json["checks"]
        .as_array()
        .expect("doctor checks must be an array")
        .iter()
        .find(|check| {
            check["code"]
                .as_str()
                .is_some_and(|code| code.starts_with("lpm_json_"))
        })
        .unwrap_or_else(|| panic!("doctor must emit an lpm.json check: {json}"))
        .clone()
}

#[test]
fn doctor_accepts_every_supported_top_level_lpm_json_field() {
    let project = TempProject::empty(r#"{"name":"doctor-config","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
            "runtime": {},
            "env": {},
            "tasks": {},
            "remoteCache": {},
            "tools": {},
            "services": {},
            "proxy": {},
            "https": true,
            "tunnel": {},
            "publish": {},
            "envSchema": {},
            "environments": {},
            "cert": {},
            "$schema": "https://cli.lpm.dev/schemas/lpm.json",
            "vault": "vault-123",
            "vaultSync": {
                "personalVersion": 7,
                "personalSyncedAt": "2026-08-13T09:00:00Z",
                "orgVersions": {"acme": 4},
                "orgSyncedAt": {"acme": "2026-08-13T09:01:00Z"}
            }
        }"#,
    );

    let config_check = doctor_lpm_json_check(&project);

    assert_eq!(
        config_check["code"], "lpm_json_valid",
        "doctor must accept every field from the canonical lpm.json schema: {config_check}"
    );
    insta::assert_json_snapshot!(
        "doctor_accepts_every_supported_top_level_lpm_json_field",
        config_check
    );
}

#[test]
fn doctor_continues_to_warn_for_unknown_top_level_lpm_json_fields() {
    let project = TempProject::empty(r#"{"name":"doctor-config","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"notAnLpmField": {}}"#);

    let config_check = doctor_lpm_json_check(&project);

    assert_eq!(
        (
            config_check["code"].as_str(),
            config_check["severity"].as_str(),
            config_check["detail"].as_str()
        ),
        (
            Some("lpm_json_schema_warnings"),
            Some("warn"),
            Some("unknown field \"notAnLpmField\"")
        ),
        "doctor must preserve its warning contract for unknown fields: {config_check}"
    );
}

#[test]
fn doctor_reports_type_errors_for_schema_derived_fields() {
    let invalid_fields = [
        ("remoteCache", r#"{"remoteCache": true}"#),
        ("proxy", r#"{"proxy": true}"#),
        ("envSchema", r#"{"envSchema": true}"#),
        ("environments", r#"{"environments": true}"#),
        ("cert", r#"{"cert": true}"#),
    ];

    for (field, lpm_json) in invalid_fields {
        let project = TempProject::empty(r#"{"name":"doctor-config","version":"1.0.0"}"#);
        project.write_file("lpm.json", lpm_json);
        let config_check = doctor_lpm_json_check(&project);
        let detail = config_check["detail"].as_str().unwrap_or_default();

        assert_eq!(
            (
                config_check["code"].as_str(),
                config_check["severity"].as_str(),
                detail.starts_with("schema error:"),
                detail.contains("unknown field")
            ),
            (Some("lpm_json_schema_warnings"), Some("warn"), true, false),
            "doctor must type-check the supported field `{field}`: {config_check}"
        );
    }
}
