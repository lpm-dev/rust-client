//! Workflow tests for `lpm cache clean [subcat]` and `lpm cache path [subcat]`.
//!
//! These cover the subcategory dispatch (`metadata` / `tasks` / `dlx`) and
//! the all-subcategory blanket form. No registry, no network.

mod support;

use support::{TempProject, lpm};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cache_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("cache")
}

/// Seed a cache subcategory with one file so the size accounting and the
/// clean removal have something to act on.
fn seed_subcat(project: &TempProject, subcat: &str, filename: &str, bytes: &[u8]) {
    let dir = cache_root(project).join(subcat);
    std::fs::create_dir_all(&dir).expect("failed to create cache subcat");
    std::fs::write(dir.join(filename), bytes).expect("failed to seed cache file");
}

#[tokio::test]
async fn cache_status_json_reports_local_usage_and_remote_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v8/artifacts/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "enabled",
            "usageBytes": 1024,
            "limitBytes": 2048
        })))
        .mount(&server)
        .await;

    let project = TempProject::empty(r#"{"name":"cache-status","version":"1.0.0"}"#);
    seed_subcat(&project, "tasks", "entry.bin", b"cached-task");
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
            "remoteCache": {{
                "enabled": true,
                "url": "{}/v8"
            }}
        }}"#,
            server.uri(),
        ),
    );

    let output = lpm(&project)
        .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
        .args(["--json", "cache", "status"])
        .output()
        .expect("failed to run lpm cache status --json");

    assert!(
        output.status.success(),
        "cache status --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("cache status --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert!(envelope["local"]["bytes"].as_u64().unwrap_or(0) >= 11);
    assert_eq!(envelope["remote"]["enabled"], serde_json::json!(true));
    assert_eq!(envelope["remote"]["status"], serde_json::json!("enabled"));
    assert_eq!(envelope["remote"]["usage_bytes"], serde_json::json!(1024));
    assert_eq!(envelope["remote"]["limit_bytes"], serde_json::json!(2048));
}

// ─── path subcommand ──────────────────────────────────────────────────

#[test]
fn cache_path_without_subcategory_prints_cache_root() {
    let project = TempProject::empty(r#"{"name":"cache-path","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["cache", "path"])
        .output()
        .expect("failed to run lpm cache path");

    assert!(
        output.status.success(),
        "lpm cache path failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = cache_root(&project).display().to_string();
    assert!(
        stdout.trim().ends_with(&expected) || stdout.trim() == expected,
        "lpm cache path must print the isolated cache root, got: {stdout}\nexpected suffix: {expected}",
    );
}

#[test]
fn cache_path_metadata_subcategory_prints_metadata_dir() {
    let project = TempProject::empty(r#"{"name":"cache-path","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["cache", "path", "metadata"])
        .output()
        .expect("failed to run lpm cache path metadata");

    assert!(output.status.success(), "lpm cache path metadata failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = cache_root(&project).join("metadata").display().to_string();
    assert!(
        stdout.trim() == expected,
        "lpm cache path metadata must print the metadata subdir, got: {stdout}\nexpected: {expected}",
    );
}

#[test]
fn cache_path_unknown_subcategory_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"cache-path","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["cache", "path", "not-a-real-subcat"])
        .output()
        .expect("failed to run lpm cache path bogus");

    assert!(
        !output.status.success(),
        "lpm cache path with unknown subcat must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown cache subcategory") && stderr.contains("metadata"),
        "stderr must list valid subcategories, got:\n{stderr}"
    );
}

#[test]
fn cache_path_json_envelope_shape_is_stable() {
    let project = TempProject::empty(r#"{"name":"cache-path","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "cache", "path", "tasks"])
        .output()
        .expect("failed to run lpm cache path tasks --json");

    assert!(output.status.success(), "lpm cache path --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("cache path --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    let path = envelope["path"].as_str().expect("path must be a string");
    assert!(
        path.ends_with("tasks"),
        "path field must point at the tasks subdir, got: {path}"
    );

    insta::with_settings!({ filters => vec![
        (r#""path":\s*"[^"]+""#, r#""path": "[CACHE_TASKS_PATH]""#),
    ]}, {
        insta::assert_json_snapshot!("cache_path_tasks_json_envelope", envelope);
    });
}

// ─── clean subcommand ─────────────────────────────────────────────────

#[test]
fn cache_clean_blanket_removes_all_three_subcategories() {
    let project = TempProject::empty(r#"{"name":"cache-clean","version":"1.0.0"}"#);

    seed_subcat(&project, "metadata", "pkg-meta.json", b"{\"a\":1}");
    seed_subcat(&project, "tasks", "task-cache.bin", &[0xff; 256]);
    seed_subcat(&project, "dlx", "tool.tgz", &[0xee; 1024]);

    let output = lpm(&project)
        .args(["cache", "clean"])
        .output()
        .expect("failed to run lpm cache clean");

    assert!(
        output.status.success(),
        "lpm cache clean failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Assert on the seed *file*, not the parent dir. Under heavy
    // parallel pressure on macOS, `Path::exists()` for a directory
    // can be racy — the seed file is the contract (it must be gone).
    for (subcat, file) in [
        ("metadata", "pkg-meta.json"),
        ("tasks", "task-cache.bin"),
        ("dlx", "tool.tgz"),
    ] {
        let file_path = cache_root(&project).join(subcat).join(file);
        assert!(
            !file_path.exists(),
            "cache clean must remove the {subcat} seed file at {}",
            file_path.display(),
        );
    }
}

#[test]
fn cache_clean_with_subcategory_only_removes_that_subcat() {
    let project = TempProject::empty(r#"{"name":"cache-clean","version":"1.0.0"}"#);

    seed_subcat(&project, "metadata", "pkg-meta.json", b"{\"a\":1}");
    seed_subcat(&project, "tasks", "task-cache.bin", &[0xff; 256]);

    let output = lpm(&project)
        .args(["cache", "clean", "metadata"])
        .output()
        .expect("failed to run lpm cache clean metadata");

    assert!(output.status.success(), "lpm cache clean metadata failed");

    // File-level assertions for parallel-pressure resilience.
    assert!(
        !cache_root(&project)
            .join("metadata")
            .join("pkg-meta.json")
            .exists(),
        "metadata seed file must be removed"
    );
    assert!(
        cache_root(&project)
            .join("tasks")
            .join("task-cache.bin")
            .exists(),
        "tasks seed file must be preserved when only metadata was targeted"
    );
}

#[test]
fn cache_clean_unknown_subcategory_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"cache-clean","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["cache", "clean", "not-a-real-subcat"])
        .output()
        .expect("failed to run lpm cache clean bogus");

    assert!(
        !output.status.success(),
        "lpm cache clean with unknown subcat must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown cache subcategory") && stderr.contains("metadata"),
        "stderr must list valid subcategories, got:\n{stderr}"
    );
}

#[test]
fn cache_clean_json_envelope_reports_per_subcategory_freed_bytes() {
    let project = TempProject::empty(r#"{"name":"cache-clean","version":"1.0.0"}"#);

    seed_subcat(&project, "metadata", "a.json", &[0xaa; 100]);
    seed_subcat(&project, "tasks", "b.bin", &[0xbb; 200]);
    seed_subcat(&project, "dlx", "c.tgz", &[0xcc; 300]);

    let output = lpm(&project)
        .args(["--json", "cache", "clean"])
        .output()
        .expect("failed to run lpm cache clean --json");

    assert!(output.status.success(), "lpm cache clean --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("cache clean --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    let cleaned = envelope["cleaned"]
        .as_array()
        .expect("cleaned must be an array");
    assert_eq!(
        cleaned.len(),
        3,
        "blanket cache clean must report metadata + tasks + dlx, got {} entries: {envelope}",
        cleaned.len(),
    );

    let categories: Vec<&str> = cleaned
        .iter()
        .filter_map(|c| c["category"].as_str())
        .collect();
    assert!(categories.contains(&"metadata"));
    assert!(categories.contains(&"tasks"));
    assert!(categories.contains(&"dlx"));

    let total_bytes = envelope["total_bytes_freed"]
        .as_u64()
        .expect("total_bytes_freed must be a u64");
    assert!(
        total_bytes >= 600,
        "total_bytes_freed must include seeded payloads (>=600), got {total_bytes}\nenvelope: {envelope}"
    );
}

#[test]
fn cache_clean_on_empty_cache_succeeds_idempotently() {
    let project = TempProject::empty(r#"{"name":"cache-clean","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["cache", "clean"])
        .output()
        .expect("failed to run lpm cache clean on empty cache");

    assert!(
        output.status.success(),
        "lpm cache clean on empty cache must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
