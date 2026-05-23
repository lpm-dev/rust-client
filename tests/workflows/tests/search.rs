mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

fn sample_search_package(description: &str, download_count: u64) -> serde_json::Value {
    serde_json::json!({
        "name": "react",
        "owner": "neo",
        "description": description,
        "distributionMode": "pool",
        "downloadCount": download_count,
        "latestVersion": "1.2.3"
    })
}

#[tokio::test]
async fn search_without_matches_warns_and_exits_zero() {
    let project = TempProject::empty(r#"{"name":"search-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_search_results("@lpm.dev/nothing-here", 20, vec![])
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["search", "@lpm.dev/nothing-here"])
        .output()
        .expect("failed to run lpm search");

    assert!(
        output.status.success(),
        "search with zero results must exit 0"
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No packages found for \"@lpm.dev/nothing-here\""),
        "expected empty-result warning, got:\n{combined}"
    );
}

#[tokio::test]
async fn search_human_output_truncates_long_description_and_compacts_download_count() {
    let project = TempProject::empty(r#"{"name":"search-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let long_description = "This description is intentionally long so the human output path must truncate it before rendering to the terminal.";
    mock.with_search_results(
        "@lpm.dev/react",
        20,
        vec![sample_search_package(long_description, 12_345)],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["search", "@lpm.dev/react"])
        .output()
        .expect("failed to run lpm search");

    assert!(
        output.status.success(),
        "lpm search failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("@lpm.dev/neo.react"),
        "package name must be rendered, got:\n{combined}"
    );
    assert!(
        combined.contains("v1.2.3"),
        "latest version must be rendered, got:\n{combined}"
    );
    assert!(
        combined.contains("12K"),
        "download count must use compact K formatting, got:\n{combined}"
    );
    assert!(
        combined.contains(
            "This description is intentionally long so the human output path must truncate..."
        ),
        "long descriptions must be truncated with an ellipsis, got:\n{combined}"
    );
}

#[tokio::test]
async fn search_json_envelope_one_result_matches_snapshot() {
    let project = TempProject::empty(r#"{"name":"search-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_search_results(
        "@lpm.dev/react",
        20,
        vec![sample_search_package("Fast UI package", 12_345)],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["search", "@lpm.dev/react", "--json"])
        .output()
        .expect("failed to run lpm search --json");

    assert!(
        output.status.success(),
        "lpm search --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("search --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert_eq!(envelope["packages"][0]["name"], serde_json::json!("react"));
    assert_eq!(
        envelope["packages"][0]["latestVersion"],
        serde_json::json!("1.2.3")
    );

    insta::assert_json_snapshot!("search_json_envelope_one_result", envelope);
}
