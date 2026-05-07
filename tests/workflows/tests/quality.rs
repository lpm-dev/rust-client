mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

fn sample_quality_report() -> serde_json::Value {
    serde_json::json!({
        "name": "owner.widget",
        "score": 73,
        "maxScore": 100,
        "tier": "silver",
        "ecosystem": "node",
        "checks": [
            {
                "id": "readme",
                "category": "docs",
                "label": "README present",
                "passed": true,
                "points": 10,
                "maxPoints": 10,
                "detail": "this detail must stay hidden"
            },
            {
                "id": "provenance",
                "category": "security",
                "label": "Provenance attestations",
                "passed": false,
                "points": 0,
                "maxPoints": 20,
                "detail": "missing provenance attestations"
            }
        ]
    })
}

#[tokio::test]
async fn quality_human_output_groups_checks_and_shows_failed_detail_only() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_quality_report("owner.widget", sample_quality_report())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget"])
        .output()
        .expect("failed to run lpm quality");

    assert!(
        output.status.success(),
        "lpm quality failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("owner.widget"), "package name missing");
    assert!(combined.contains("score"), "score field missing");
    assert!(combined.contains("tier"), "tier field missing");
    assert!(combined.contains("ecosystem"), "ecosystem field missing");
    assert!(combined.contains("docs"), "docs category missing");
    assert!(combined.contains("security"), "security category missing");
    assert!(
        combined.contains("README present"),
        "passed check label missing"
    );
    assert!(
        combined.contains("Provenance attestations"),
        "failed check label missing"
    );
    assert!(
        combined.contains("missing provenance attestations"),
        "failed detail must be shown"
    );
    assert!(
        !combined.contains("this detail must stay hidden"),
        "passed-check detail must stay hidden"
    );
}

#[tokio::test]
async fn quality_json_envelope_matches_snapshot() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_quality_report("owner.widget", sample_quality_report())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget", "--json"])
        .output()
        .expect("failed to run lpm quality --json");

    assert!(
        output.status.success(),
        "lpm quality --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("quality --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["name"], serde_json::json!("owner.widget"));
    assert_eq!(envelope["score"], serde_json::json!(73));

    insta::assert_json_snapshot!("quality_json_envelope_owner_widget", envelope);
}
