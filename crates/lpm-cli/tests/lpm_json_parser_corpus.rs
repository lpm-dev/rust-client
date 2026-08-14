//! **Tier placement: cli-binary.** Justification class:
//! **parser/schema corpus**. These tests exercise source-level `lpm.json`
//! parsing behavior that cannot be represented after JSON has been reduced to
//! a `serde_json::Value`, including duplicate object keys.

mod common;

use std::fs;

#[test]
fn dev_rejects_duplicate_service_keys_before_starting_a_child() {
    let project = tempfile::tempdir().unwrap();
    let lpm_home = project.path().join("lpm-home");
    fs::write(
        project.path().join("package.json"),
        r#"{"name":"duplicate-service-parser","private":true}"#,
    )
    .unwrap();
    fs::write(
        project.path().join("lpm.json"),
        r#"{
            "services": {
                "web": { "command": "node -e \"require('fs').writeFileSync('started', '')\"" },
                "web": { "command": "node -e \"require('fs').writeFileSync('started', '')\"" }
            }
        }"#,
    )
    .unwrap();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        &lpm_home,
        None,
        &["dev", "--no-install", "--no-open"],
    );

    assert!(
        !status.success(),
        "duplicate services were accepted: {stdout}"
    );
    assert!(
        format!("{stdout}\n{stderr}").contains("duplicate service `web`"),
        "duplicate service error was not actionable: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        !project.path().join("started").exists(),
        "a child started before duplicate services were rejected"
    );
}
