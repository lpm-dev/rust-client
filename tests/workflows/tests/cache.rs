//! Workflow tests for `lpm cache clean [subcat]` and `lpm cache path [subcat]`.
//!
//! These cover the subcategory dispatch (`metadata` / `tasks` / `dlx` / `mcp`) and
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

#[test]
fn cache_prune_apply_json_exits_nonzero_when_tombstone_sweep_fails() {
    let project = TempProject::empty(r#"{"name":"cache-prune","version":"1.0.0"}"#);
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    std::fs::create_dir_all(root.global_root()).expect("create global root");
    std::fs::write(root.global_manifest(), b"@@@ not valid toml @@@")
        .expect("write corrupt global manifest");

    let output = lpm(&project)
        .args(["--json", "cache", "prune", "--apply"])
        .output()
        .expect("failed to run lpm cache prune --apply --json");

    assert!(
        !output.status.success(),
        "cache prune --apply must fail when tombstone sweep fails\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("cache prune --json must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["tombstone_sweep_error"].as_str().is_some(),
        "failed sweep must surface a machine-readable reason: {envelope}",
    );
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
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
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

#[tokio::test]
async fn cache_status_human_renders_tables_and_slim_completion() {
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
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
        .args(["cache", "status"])
        .output()
        .expect("failed to run lpm cache status");

    assert!(
        output.status.success(),
        "cache status failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Local cache") && stdout.contains("Remote cache"),
        "cache status must render local and remote sections, got:\n{stdout}"
    );
    assert!(
        stdout.contains("1.0 KB / 2.0 KB  █████░░░░░"),
        "cache status must render remote usage with a quota bar, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Cache status loaded"),
        "cache status must report a slim completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "cache status output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[tokio::test]
async fn cache_status_human_applies_slim_color_roles_when_forced() {
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
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
        .args(["--color=always", "cache", "status"])
        .output()
        .expect("failed to run colored lpm cache status");

    assert!(
        output.status.success(),
        "colored cache status failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\x1b[33mLocal cache")
            && stdout.contains("\x1b[2menabled")
            && stdout.contains("\x1b[32mtrue")
            && stdout.contains("\x1b[32m")
            && stdout.contains('█'),
        "cache status should color section headers, labels, status values, and the usage bar, got:\n{stdout:?}",
    );
}

#[tokio::test]
async fn cache_status_does_not_send_registry_token_to_third_party_host() {
    // A checked-in lpm.json must not be able to redirect the ambient registry
    // token (LPM_TOKEN) to an arbitrary cache host. With no cache-specific
    // token and a non-lpm.dev URL, the client must refuse rather than leak.
    let server = MockServer::start().await;
    // Deliberately mount NO routes: any request that arrives is the leak.

    let project = TempProject::empty(r#"{"name":"cache-token-leak","version":"1.0.0"}"#);
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
        .env("LPM_TOKEN", "super-secret-registry-token")
        .args(["--json", "cache", "status"])
        .output()
        .expect("failed to run lpm cache status --json");

    assert!(
        output.status.success(),
        "cache status is best-effort and must not hard-fail:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = server
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "registry token must never be sent to a non-lpm.dev cache host, got {} request(s)",
        requests.len(),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("cache status --json must be valid JSON: {e}\n---\n{stdout}"));
    let error = envelope["remote"]["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("LPM_REMOTE_CACHE_TOKEN"),
        "third-party cache host without a cache token must report a token-required error, got: {error}",
    );
}

#[tokio::test]
async fn cache_status_requires_signing_key_for_third_party_cache_host() {
    let server = MockServer::start().await;

    let project = TempProject::empty(r#"{"name":"cache-signing-required","version":"1.0.0"}"#);
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
        "cache status is best-effort and must not hard-fail:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = server
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "third-party remote cache without a signing key must not be contacted, got {} request(s)",
        requests.len(),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("cache status --json must be valid JSON: {e}\n---\n{stdout}"));
    let error = envelope["remote"]["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("LPM_REMOTE_CACHE_SIGNATURE_KEY"),
        "third-party cache host without a signing key must report a signing-key-required error, got: {error}",
    );
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
fn cache_path_mcp_subcategory_prints_managed_runtime_cache_dir() {
    let project = TempProject::empty(r#"{"name":"cache-path","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["cache", "path", "mcp"])
        .output()
        .expect("failed to run lpm cache path mcp");

    assert!(output.status.success(), "lpm cache path mcp failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = cache_root(&project).join("mcp").display().to_string();
    assert_eq!(stdout.trim(), expected);
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
fn cache_clean_blanket_removes_all_four_subcategories() {
    let project = TempProject::empty(r#"{"name":"cache-clean","version":"1.0.0"}"#);

    seed_subcat(&project, "metadata", "pkg-meta.json", b"{\"a\":1}");
    seed_subcat(&project, "tasks", "task-cache.bin", &[0xff; 256]);
    seed_subcat(&project, "dlx", "tool.tgz", &[0xee; 1024]);
    seed_subcat(&project, "mcp", "runtime.json", &[0xdd; 512]);

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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Cleared 4 cache directories"),
        "cache clean must report a slim summary, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "cache clean output must not use cliclack gutter output, got:\n{stderr}"
    );

    // Assert on the seed *file*, not the parent dir. Under heavy
    // parallel pressure on macOS, `Path::exists()` for a directory
    // can be racy — the seed file is the contract (it must be gone).
    for (subcat, file) in [
        ("metadata", "pkg-meta.json"),
        ("tasks", "task-cache.bin"),
        ("dlx", "tool.tgz"),
        ("mcp", "runtime.json"),
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
    seed_subcat(&project, "mcp", "runtime.json", &[0xdd; 400]);

    let output = lpm(&project)
        .args(["--json", "cache", "clean"])
        .output()
        .expect("failed to run lpm cache clean --json");

    assert!(output.status.success(), "lpm cache clean --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("cache clean --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["skipped"], serde_json::json!([]));
    let cleaned = envelope["cleaned"]
        .as_array()
        .expect("cleaned must be an array");
    assert_eq!(
        cleaned.len(),
        4,
        "blanket cache clean must report metadata + tasks + dlx + mcp, got {} entries: {envelope}",
        cleaned.len(),
    );

    let categories: Vec<&str> = cleaned
        .iter()
        .filter_map(|c| c["category"].as_str())
        .collect();
    assert!(categories.contains(&"metadata"));
    assert!(categories.contains(&"tasks"));
    assert!(categories.contains(&"dlx"));
    assert!(categories.contains(&"mcp"));

    let total_bytes = envelope["total_bytes_freed"]
        .as_u64()
        .expect("total_bytes_freed must be a u64");
    assert!(
        total_bytes >= 1_000,
        "total_bytes_freed must include seeded payloads (>=1000), got {total_bytes}\nenvelope: {envelope}"
    );
}

#[test]
fn cache_clean_json_reports_an_in_use_mcp_runtime_as_skipped() {
    let project = TempProject::empty(r#"{"name":"cache-clean","version":"1.0.0"}"#);
    seed_subcat(&project, "metadata", "a.json", &[0xaa; 100]);
    seed_subcat(&project, "mcp/runtime", "package.json", &[0xdd; 400]);
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    let lock_path = root.cache_mcp_lock();
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        lpm_common::with_shared_lock(lock_path, || {
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok::<_, lpm_common::LpmError>(())
        })
    });
    held_rx.recv().unwrap();

    let output = lpm(&project)
        .args(["--json", "cache", "clean"])
        .output()
        .expect("failed to run lpm cache clean --json with a busy MCP runtime");

    release_tx.send(()).unwrap();
    holder.join().unwrap().unwrap();

    assert!(
        output.status.success(),
        "blanket cache clean must continue around a busy MCP runtime: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cache clean output must be JSON");
    assert_eq!(
        envelope["skipped"],
        serde_json::json!([{
            "category": "mcp",
            "path": cache_root(&project).join("mcp").display().to_string(),
            "reason": "in use"
        }])
    );
    assert!(
        cache_root(&project)
            .join("mcp/runtime/package.json")
            .is_file(),
        "the in-use MCP runtime must remain intact"
    );
    assert!(
        !cache_root(&project).join("metadata").exists(),
        "other cache categories must still be cleaned"
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Cache is already empty"),
        "empty cache clean must use a slim completion line, got:\n{stderr}"
    );
}
