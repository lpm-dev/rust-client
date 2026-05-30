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
async fn quality_human_output_uses_slim_completion_and_shows_failed_detail_only() {
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("owner.widget"), "package name missing");
    assert!(stdout.contains("score"), "score field missing");
    assert!(stdout.contains("tier"), "tier field missing");
    assert!(stdout.contains("ecosystem"), "ecosystem field missing");
    assert!(stdout.contains("checks"), "checks section missing");
    assert!(
        stdout.contains("✓ README present"),
        "passed check label missing"
    );
    assert!(
        stdout.contains("✗ Provenance attestations"),
        "failed check label missing"
    );
    assert!(
        stdout.contains("missing provenance attestations"),
        "failed detail must be shown"
    );
    assert!(
        !stdout.contains("this detail must stay hidden"),
        "passed-check detail must stay hidden"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Quality report ready"),
        "quality must finish with a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "quality must not use cliclack gutter output, got:\n{stderr}",
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
