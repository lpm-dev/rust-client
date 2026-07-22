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

fn assert_pool_output_is_terminal_safe(rendered: &str) {
    assert!(
        rendered.contains("safe?FORGED?rewritten?end"),
        "hostile pool fields must remain visible as one sanitized field: {rendered:?}",
    );
    for attacker_fragment in [
        "\u{1b}", "\u{7}", "\u{8}", "\r", "\u{007f}", "\u{0090}", "\u{009c}", "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "pool output retained {attacker_fragment:?}: {rendered:?}",
        );
    }
}

#[tokio::test]
async fn pool_registry_fields_cannot_inject_terminal_rows() {
    let project = TempProject::empty(r#"{"name":"pool-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let hostile = "safe\nFORGED\rrewritten\u{8}\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";
    mock.with_pool_stats(
        "pool-session-token",
        serde_json::json!({
            "billingPeriod": hostile,
            "totalWeightedDownloads": 1,
            "estimatedEarningsCents": 1,
            "packages": [{
                "name": hostile,
                "weightedDownloads": 1,
                "estimatedEarningsCents": 1
            }]
        }),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "pool-session-token")
        .args(["pool"])
        .output()
        .expect("failed to run lpm pool");

    assert!(output.status.success(), "lpm pool failed: {output:?}");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_pool_output_is_terminal_safe(&rendered);
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
        combined.contains("3,210"),
        "weighted downloads missing, got:\n{combined}"
    );
    assert!(
        combined.contains("$123.45"),
        "earnings must be formatted as dollars, got:\n{combined}"
    );
    assert!(
        combined.contains("@lpm.dev/neo.widget") && combined.contains("(2,100 downloads)"),
        "first package row missing, got:\n{combined}"
    );
    assert!(
        combined.contains("@lpm.dev/neo.button") && combined.contains("(1,110 downloads)"),
        "second package row missing, got:\n{combined}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "pool must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[tokio::test]
async fn pool_human_output_applies_slim_color_roles_when_forced() {
    let project = TempProject::empty(r#"{"name":"pool-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_pool_stats("pool-session-token", sample_pool_stats())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "pool-session-token")
        .args(["--color=always", "pool"])
        .output()
        .expect("failed to run colored lpm pool");

    assert!(
        output.status.success(),
        "colored lpm pool failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("\x1b[33mPool Revenue Stats")
            && combined.contains("\x1b[2mbilling period")
            && combined.contains("\x1b[32m$123.45")
            && combined.contains("\x1b[36m@lpm.dev/neo.widget"),
        "pool should color sections, labels, earnings, and package scopes, got:\n{combined:?}",
    );
}

#[tokio::test]
async fn pool_registry_fields_are_sanitized_before_trusted_styles_are_applied() {
    let project = TempProject::empty(r#"{"name":"pool-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let hostile =
        "safe\nFORGED\rrewritten\u{8}\u{1b}[2J\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";
    mock.with_pool_stats(
        "pool-session-token",
        serde_json::json!({
            "billingPeriod": hostile,
            "totalWeightedDownloads": 1,
            "estimatedEarningsCents": 1,
            "packages": [{
                "name": hostile,
                "weightedDownloads": 1,
                "estimatedEarningsCents": 1
            }]
        }),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "pool-session-token")
        .args(["--color=always", "pool"])
        .output()
        .expect("failed to run colored lpm pool");

    assert!(
        output.status.success(),
        "colored lpm pool failed: {output:?}"
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        rendered.contains("\u{1b}[33mPool Revenue Stats")
            && rendered.contains("\u{1b}[36msafe?FORGED?rewritten?end"),
        "trusted color roles must survive around sanitized fields: {rendered:?}",
    );
    for attacker_fragment in [
        "\u{1b}[2J",
        "\u{1b}]52",
        "\u{7}",
        "\u{8}",
        "\r",
        "\u{0090}",
        "\u{009c}",
        "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "colored pool output retained {attacker_fragment:?}: {rendered:?}",
        );
    }
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
