mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

fn sample_pool_stats() -> serde_json::Value {
    serde_json::json!({
        "billingPeriod": "2026-05",
        "totalWeightedDownloads": 3210,
        "estimatedEarningsCents": 12345,
        "packages": [
            {
                "name": "@lpm.dev/neo.widget",
                "weightedDownloads": 2100,
                "estimatedEarningsCents": 8000
            },
            {
                "name": "@lpm.dev/neo.button",
                "weightedDownloads": 1110,
                "estimatedEarningsCents": 4345
            }
        ]
    })
}

#[tokio::test]
async fn pool_human_output_formats_revenue_summary_and_package_rows() {
    let project = TempProject::empty(r#"{"name":"pool-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_pool_stats("pool-session-token", sample_pool_stats())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "pool-session-token")
        .args(["pool"])
        .output()
        .expect("failed to run lpm pool");

    assert!(
        output.status.success(),
        "lpm pool failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Pool Revenue Stats"),
        "pool header missing, got:\n{combined}"
    );
    assert!(
        combined.contains("2026-05"),
        "billing period missing, got:\n{combined}"
    );
    assert!(
        combined.contains("3210"),
        "weighted downloads missing, got:\n{combined}"
    );
    assert!(
        combined.contains("$123.45"),
        "earnings must be formatted as dollars, got:\n{combined}"
    );
    assert!(
        combined.contains("@lpm.dev/neo.widget") && combined.contains("(2100 downloads)"),
        "first package row missing, got:\n{combined}"
    );
    assert!(
        combined.contains("@lpm.dev/neo.button") && combined.contains("(1110 downloads)"),
        "second package row missing, got:\n{combined}"
    );
}

#[tokio::test]
async fn pool_json_envelope_matches_snapshot() {
    let project = TempProject::empty(r#"{"name":"pool-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_pool_stats("pool-session-token", sample_pool_stats())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "pool-session-token")
        .args(["pool", "--json"])
        .output()
        .expect("failed to run lpm pool --json");

    assert!(
        output.status.success(),
        "lpm pool --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("pool --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["billingPeriod"], serde_json::json!("2026-05"));
    assert_eq!(envelope["totalWeightedDownloads"], serde_json::json!(3210));

    insta::assert_json_snapshot!("pool_json_envelope_two_packages", envelope);
}
