//! Opt-in timeline artifacts preserve install output and failure behavior.
mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

fn artifacts(directory: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .collect()
}

fn assert_link_materialization_timeline(records: &[serde_json::Value]) {
    let task = records
        .iter()
        .find(|record| record["name"] == "v2_link_task")
        .expect("link task must expose admission and blocking-worker timing");
    let events: Vec<_> = records
        .iter()
        .filter(|record| record["kind"] == "event" && record["parent"] == task["id"])
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        events,
        [
            "admission_start",
            "admission_end",
            "enqueue",
            "work_start",
            "work_end"
        ]
    );
    let link = records
        .iter()
        .find(|record| record["name"] == "link_one" && record["parent"] == task["id"])
        .expect("link work must retain its task ancestry");
    let materialize = records
        .iter()
        .find(|record| record["name"] == "link_materialize" && record["parent"] == link["id"])
        .expect("materialization must expose its wall-time span");
    assert!(
        records
            .iter()
            .any(|record| record["kind"] == "span_close" && record["id"] == materialize["id"])
    );
    #[cfg(target_os = "macos")]
    {
        let clone = records
            .iter()
            .find(|record| record["name"] == "clonefile" && record["parent"] == materialize["id"])
            .expect("macOS materialization must expose the clone attempt");
        assert!(records.iter().any(|record| record["name"] == "clone_result"
            && record["parent"] == clone["id"]
            && record["fields"]["success"].as_u64().is_some()));
    }
}

#[test]
fn global_install_startup_error_still_exports_an_incomplete_timeline() {
    let project = TempProject::empty(r#"{"name":"timeline","version":"1.0.0"}"#);
    project.write_file("not-a-directory", "file");
    let directory = project.path().join("timeline");
    let output = lpm(&project)
        .env("LPM_HOME", project.path().join("not-a-directory"))
        .env("LPM_INSTALL_TIMELINE_DIR", &directory)
        .args(["--json", "install", "--global", "missing"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let files = artifacts(&directory);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["outcome"], "incomplete");
}

#[tokio::test]
async fn successful_install_exports_numeric_timeline_separately_from_json_stdout() {
    let project = TempProject::empty(
        r#"{"name":"timeline","version":"1.0.0","dependencies":{"timeline-package":"1.0.0"}}"#,
    );
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            "timeline-package",
            "1.0.0",
            &make_tarball("timeline-package", "1.0.0"),
        )
        .await;
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    let directory = project.path().join("timeline");
    let output = lpm_with_registry(&project, &registry.url())
        .env("LPM_INSTALL_TIMELINE_DIR", &directory)
        .env("RUST_LOG", "off")
        .args([
            "--json",
            "install",
            "--no-frozen-lockfile",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["success"], true);
    let files = artifacts(&directory);
    assert_eq!(files.len(), 1);
    let trace = &files[0];
    assert_eq!(trace["outcome"], "success");
    let records = trace["records"].as_array().unwrap();
    assert_link_materialization_timeline(records);
    assert!(records.iter().any(|r| r["name"] == "metadata_body"));
    assert!(records.iter().any(|r| r["name"] == "tree_walk_end"));
    assert!(
        records
            .iter()
            .all(|r| r["at_us"].as_u64().unwrap() <= trace["cutoff_us"].as_u64().unwrap())
    );
    let unparented_fetches = records
        .iter()
        .filter(|r| {
            matches!(
                r["name"].as_str(),
                Some("tarball_fetch" | "speculative_tarball")
            ) && r["parent"].is_null()
        })
        .count();
    let rename_starts = records
        .iter()
        .filter(|r| r["name"] == "rename_start")
        .count();
    let rename_ends = records.iter().filter(|r| r["name"] == "rename_end").count();
    assert!(
        unparented_fetches == 0 && rename_starts == rename_ends,
        "unparented fetches={unparented_fetches}; rename starts={rename_starts}, ends={rename_ends}"
    );
    let serialized = serde_json::to_string(trace).unwrap();
    for excluded in [
        "timeline-package",
        &registry.url(),
        &project.path().display().to_string(),
    ] {
        assert!(!serialized.contains(excluded));
    }
    insta::assert_json_snapshot!(serde_json::json!({
        "schema_version": trace["schema_version"], "origin": trace["origin"],
        "outcome": trace["outcome"], "record_limit": trace["record_limit"], "dropped_records": trace["dropped_records"]
    }), @r#"
    {
      "schema_version": 1,
      "origin": "subscriber_initialized",
      "outcome": "success",
      "record_limit": 50000,
      "dropped_records": 0
    }
    "#);
}

#[test]
fn failed_install_exports_error_timeline_without_replacing_json_error() {
    let project = TempProject::empty("{ malformed");
    let directory = project.path().join("timeline");
    let output = lpm(&project)
        .env("LPM_INSTALL_TIMELINE_DIR", &directory)
        .args(["--json", "install", "--no-skills", "--no-editor-setup"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["success"], false);
    let files = artifacts(&directory);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["outcome"], "error");
}

#[test]
fn timeline_export_failure_does_not_fail_install_or_corrupt_json() {
    let project = TempProject::empty(r#"{"name":"timeline","version":"1.0.0"}"#);
    project.write_file("not-a-directory", "file");
    let output = lpm(&project)
        .env(
            "LPM_INSTALL_TIMELINE_DIR",
            project.path().join("not-a-directory"),
        )
        .args([
            "--json",
            "install",
            "--no-frozen-lockfile",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["success"], true);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not write the install timeline")
    );
}

#[tokio::test]
async fn metadata_timeline_correlates_retries_blocking_parse_and_ordered_commit() {
    use support::mock_registry::compute_integrity;
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    let project = TempProject::empty(
        r#"{"name":"timeline","version":"1.0.0","dependencies":{"timeline-a":"1.0.0","timeline-b":"1.0.0"}}"#,
    );
    let registry = MockRegistry::start().await;
    for name in ["timeline-a", "timeline-b"] {
        registry
            .with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
            .await;
    }
    let tarball = make_tarball("timeline-a", "1.0.0");
    Mock::given(method("GET"))
        .and(path("/timeline-a"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(registry.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/timeline-a"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(100))
            .set_body_json(serde_json::json!({
                "name": "timeline-a", "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"name": "timeline-a", "version": "1.0.0",
                    "dist": {"tarball": registry.tarball_url("timeline-a", "1.0.0"), "integrity": compute_integrity(&tarball)}}},
                "description": "x".repeat(96 * 1024)
            })))
        .with_priority(2)
        .mount(registry.server()).await;
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    let directory = project.path().join("timeline");
    let output = lpm_with_registry(&project, &registry.url())
        .env("LPM_INSTALL_TIMELINE_DIR", &directory)
        .env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "1")
        .env("RUST_LOG", "off")
        .args([
            "--json",
            "install",
            "--no-frozen-lockfile",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let files = artifacts(&directory);
    let records = files[0]["records"].as_array().unwrap();
    let retry = records
        .iter()
        .find(|r| r["name"] == "headers_observed" && r["fields"]["status"] == 503)
        .unwrap();
    let request_events: Vec<_> = records
        .iter()
        .filter(|r| r["kind"] == "event" && r["parent"] == retry["parent"])
        .collect();
    assert_eq!(
        request_events
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "request_attempt",
            "headers_observed",
            "backoff_start",
            "backoff_end",
            "request_attempt",
            "headers_observed"
        ]
    );
    assert_eq!(request_events[4]["fields"]["attempt"], 1);
    assert_eq!(request_events[5]["fields"]["status"], 200);
    let parse = records
        .iter()
        .find(|r| r["name"] == "metadata_parse" && r["fields"]["blocking"] == 1)
        .unwrap();
    let parse_events: Vec<_> = records
        .iter()
        .filter(|r| r["kind"] == "event" && r["parent"] == parse["id"])
        .collect();
    assert_eq!(
        parse_events
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["enqueue", "work_start", "work_end", "await_resume"]
    );
    assert!(
        parse_events
            .windows(2)
            .all(|pair| pair[0]["at_us"].as_u64() <= pair[1]["at_us"].as_u64())
    );
    let operations: std::collections::HashMap<_, _> = records
        .iter()
        .filter(|r| r["name"] == "resolver_metadata")
        .map(|r| {
            (
                r["id"].as_u64().unwrap(),
                r["fields"]["sequence"].as_u64().unwrap(),
            )
        })
        .collect();
    let commits: Vec<_> = records
        .iter()
        .filter(|r| r["name"] == "graph_commit_start")
        .map(|r| operations[&r["parent"].as_u64().unwrap()])
        .collect();
    assert!(commits.len() >= 2);
    assert!(commits.windows(2).all(|pair| pair[0] < pair[1]));
    for id in operations.keys() {
        let events: Vec<_> = records
            .iter()
            .filter(|r| r["kind"] == "event" && r["parent"].as_u64() == Some(*id))
            .collect();
        let finished = events
            .iter()
            .position(|r| r["name"] == "metadata_task_finished")
            .unwrap();
        let observed = events
            .iter()
            .position(|r| r["name"] == "resolver_observed")
            .unwrap();
        let committed = events
            .iter()
            .position(|r| r["name"] == "graph_commit_start")
            .unwrap();
        assert!(finished < observed && observed < committed);
    }
}

async fn assert_install_fetch_ancestry(route: &str) {
    let workspace = route == "workspace";
    let policy = matches!(route, "policy" | "policy-foreground");
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    let registry = MockRegistry::start().await;
    let mut dependencies = serde_json::Map::new();
    for index in 0..if policy || route == "experimental" {
        1
    } else {
        8
    } {
        let name = format!("timeline-overlap-{index}");
        let tarball = make_tarball(&name, "1.0.0");
        registry.with_package(&name, "1.0.0", &tarball).await;
        Mock::given(method("GET"))
            .and(path(MockRegistry::tarball_path(&name, "1.0.0")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball)
                    .set_delay(std::time::Duration::from_millis(100)),
            )
            .with_priority(1)
            .mount(registry.server())
            .await;
        dependencies.insert(name, serde_json::json!("1.0.0"));
    }
    let manifest = serde_json::json!({"name":"timeline-overlap","version":"1.0.0","private":true,"dependencies":dependencies});
    let project = TempProject::empty(&manifest.to_string());
    if workspace {
        project.write_file("package.json", &serde_json::json!({"name":"timeline-workspace","version":"1.0.0","private":true,"workspaces":["packages/*"]}).to_string());
        project.write_file("packages/member/package.json", &manifest.to_string());
    }
    if !matches!(route, "workspace" | "experimental") {
        project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    }
    if policy {
        let config = serde_json::json!({"policy":{"extensions":{"timeline":{"command":[assert_cmd::cargo::cargo_bin("workflows-policy-extension").display().to_string(), "--action", "allow", "--name", "timeline-overlap-0", "--version", "1.0.0"],"mode":"enforce"}}}});
        std::fs::create_dir_all(project.home().join(".lpm")).unwrap();
        std::fs::write(
            project.home().join(".lpm/config.toml"),
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
    }
    let directory = project.path().join("timeline");
    let mut command = lpm_with_registry(&project, &registry.url());
    if route == "ready-files" {
        command.env("LPM_INTERNAL_READY_FILE_ADMISSION", "1");
    }
    if route == "serial" {
        command.env("LPM_SERIAL_LINK", "1");
    }
    if route == "policy-foreground" {
        command.env("LPM_FETCH_OVERLAP", "0");
    }
    command
        .env("LPM_INSTALL_TIMELINE_DIR", &directory)
        .env("LPM_FETCH_OVERLAP_MIN_SELECTED", "1")
        .env("LPM_FUSION_SPECULATION_PERMITS", "1")
        .env("LPM_TIMING_DETAIL", "1")
        .args([
            "--json",
            "install",
            "--timing",
            "--no-frozen-lockfile",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ]);
    if workspace {
        command
            .env("LPM_INTERNAL_TEST_NPM_REGISTRY_URL", registry.url())
            .arg("--recursive");
    }
    if route == "experimental" {
        command
            .env("LPM_INTERNAL_TEST_NPM_REGISTRY_URL", registry.url())
            .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
            .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
            .env("LPM_INSTALLER_SPIKE_GRAPH", "resolve-worklist")
            .env("LPM_INSTALLER_SPIKE_PARITY", "deny");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let files = artifacts(&directory);
    assert_eq!(files.len(), 1);
    let records = files[0]["records"].as_array().unwrap();
    if route == "ready-files" {
        assert!(
            records
                .iter()
                .any(|record| record["name"] == "ready_file_admission")
        );
    }
    if route == "serial" {
        assert!(
            !records
                .iter()
                .any(|record| record["name"] == "v2_link_task")
        );
        assert!(
            records
                .iter()
                .any(|record| record["name"] == "link_materialize")
        );
    } else {
        assert_link_materialization_timeline(records);
    }
    let spans: std::collections::HashMap<u64, &serde_json::Value> = records
        .iter()
        .filter(|r| r["kind"] == "span_open")
        .map(|r| (r["id"].as_u64().unwrap(), r))
        .collect();
    if policy {
        let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(stdout["timing"]["policy_extensions"]["ran_count"], 1);
        assert!(!spans.values().any(|r| r["name"] == "speculative_tarball"));
        assert_eq!(
            spans
                .values()
                .any(|r| r["name"] == "package_fetch_dispatch"),
            route == "policy",
        );
    }
    let fetches: Vec<_> = spans
        .values()
        .filter(|r| r["name"] == "tarball_fetch")
        .collect();
    assert!(
        !fetches.is_empty(),
        "fixture must exercise authoritative fetches"
    );
    let expected_marker = match route {
        "normal" | "serial" | "ready-files" => "selected_fetch_dispatch",
        "workspace" => "workspace_fetch_task",
        // Either the dispatcher or foreground fetch can acquire the package lock first.
        "policy" | "policy-foreground" => "install_pipeline",
        "experimental" => "resolver_fetch_task",
        _ => panic!("unknown fixture route"),
    };
    let mut route_exercised = false;
    for fetch in fetches {
        let mut current = Some(fetch["id"].as_u64().unwrap());
        let mut reached_install = false;
        while let Some(id) = current {
            let span = spans[&id];
            route_exercised |= span["name"] == expected_marker;
            if span["name"] == "install_pipeline" {
                reached_install = true;
                break;
            }
            current = span["parent"].as_u64();
        }
        assert!(reached_install, "fetch lacks install ancestry: {fetch}");
    }
    assert!(
        route_exercised,
        "fixture did not fetch through {expected_marker}"
    );
}

#[tokio::test]
async fn overlapping_resolution_fetches_retain_install_timeline_ancestry() {
    assert_install_fetch_ancestry("normal").await;
}

#[tokio::test]
async fn serial_linking_exports_materialization_without_async_link_tasks() {
    assert_install_fetch_ancestry("serial").await;
}

#[tokio::test]
async fn ready_file_admission_keeps_selected_fetch_and_link_ancestry() {
    assert_install_fetch_ancestry("ready-files").await;
}

#[tokio::test]
async fn workspace_shared_fetches_retain_install_timeline_ancestry() {
    assert_install_fetch_ancestry("workspace").await;
}

#[tokio::test]
async fn post_policy_fetches_retain_install_timeline_ancestry() {
    assert_install_fetch_ancestry("policy").await;
}

#[tokio::test]
async fn post_policy_foreground_fetches_retain_install_timeline_ancestry() {
    assert_install_fetch_ancestry("policy-foreground").await;
}

#[tokio::test]
async fn experimental_fetches_retain_install_timeline_ancestry() {
    assert_install_fetch_ancestry("experimental").await;
}
