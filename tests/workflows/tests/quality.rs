mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

fn sample_quality_report() -> serde_json::Value {
    serde_json::json!({
        "name": "owner.widget",
        "status": "complete",
        "rulesVersion": 1,
        "score": 73,
        "maxScore": 100,
        "tier": "good",
        "ecosystem": "js",
        "categories": {
            "documentation": { "score": 26, "max": 32 },
            "api": { "score": 21, "max": 26 },
            "provenance": { "score": 0, "max": 12 },
            "health": { "score": 26, "max": 30 }
        },
        "checks": [
            {
                "id": "readme",
                "category": "documentation",
                "label": "README present",
                "status": "passed",
                "passed": true,
                "points": 6,
                "maxPoints": 6,
                "detail": "this detail must stay hidden"
            },
            {
                "id": "api-docs",
                "category": "documentation",
                "label": "API docs",
                "status": "partial",
                "passed": false,
                "points": 6,
                "maxPoints": 10,
                "detail": "12 of 20 exports have doc comments"
            },
            {
                "id": "trusted-publishing",
                "category": "provenance",
                "label": "Provenance attestations",
                "status": "failed",
                "passed": false,
                "points": 0,
                "maxPoints": 5,
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
    assert!(stdout.contains("rules"), "rules version missing");
    assert!(stdout.contains("Docs"), "docs category missing");
    assert!(stdout.contains("API"), "API category missing");
    assert!(
        stdout.contains("26/32"),
        "a complete report's totals missing"
    );
    assert!(
        stdout.contains("◐ API docs"),
        "a partial check must show as partial"
    );
    assert!(
        stdout.contains("12 of 20 exports have doc comments"),
        "a partial check's detail must be shown"
    );
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

#[tokio::test]
async fn quality_shows_scoring_while_the_report_is_pending() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let mut report = sample_quality_report();
    report["status"] = serde_json::json!("pending");
    report["score"] = serde_json::Value::Null;
    report["checks"][2]["status"] = serde_json::json!("pending");
    mock.with_quality_report("owner.widget", report).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget"])
        .output()
        .expect("failed to run lpm quality");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Scoring…"),
        "pending report must say Scoring…:\n{stdout}"
    );
    assert!(
        !stdout.contains("73/100"),
        "a pending report shows no score:\n{stdout}"
    );
    assert!(stdout.contains("◦ Provenance attestations"), "{stdout}");
    assert!(
        !stdout.contains("26/32"),
        "a pending report shows no category totals:\n{stdout}"
    );
}

#[tokio::test]
async fn quality_says_when_the_registry_couldnt_score_a_release() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let mut report = sample_quality_report();
    report["status"] = serde_json::json!("unavailable");
    report["unavailableReason"] = serde_json::json!("The archive couldn't be analyzed");
    report["score"] = serde_json::Value::Null;
    report["tier"] = serde_json::Value::Null;
    for index in [0, 1] {
        report["checks"][index]["status"] = serde_json::json!("unavailable");
        report["checks"][index]["points"] = serde_json::json!(0);
    }
    mock.with_quality_report("owner.widget", report).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget"])
        .output()
        .expect("failed to run lpm quality");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Score unavailable"), "{stdout}");
    assert!(
        stdout.contains("The archive couldn't be analyzed"),
        "{stdout}"
    );
    assert!(stdout.contains("– README present"), "{stdout}");
    assert!(stdout.contains("not checked"), "{stdout}");
    assert!(!stdout.contains("✗ README present"), "{stdout}");
    assert!(!stdout.contains("26/32"), "{stdout}");
    assert!(!stdout.contains("73/100"), "{stdout}");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget", "--json"])
        .output()
        .expect("failed to run lpm quality --json");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["status"], "unavailable");
    assert_eq!(envelope["available"], true);
    assert!(envelope["categories"].is_null());
    assert!(envelope["score"].is_null());
}

#[tokio::test]
async fn quality_reads_a_report_from_a_registry_without_categories_or_status() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_quality_report(
        "owner.widget",
        serde_json::json!({
            "name": "owner.widget", "score": 40, "maxScore": 100, "tier": "needs-work",
            "checks": [
                {"id": "has-readme", "label": "Has README", "passed": true, "points": 8, "maxPoints": 8},
                {"id": "has-types", "label": "Has types", "passed": false, "points": 0, "maxPoints": 8, "detail": "No types"}
            ]
        }),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget"])
        .output()
        .expect("failed to run lpm quality");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("40/100"), "{stdout}");
    assert!(stdout.contains("✓ Has README"), "{stdout}");
    assert!(stdout.contains("✗ Has types"), "{stdout}");
    assert!(stdout.contains("No types"), "{stdout}");
}

#[path = "quality_contract/mod.rs"]
mod contract;
