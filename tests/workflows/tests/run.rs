//! Workflow tests for `lpm run`.
//!
//! These tests spawn the real `lpm-rs` binary against fixture projects
//! and verify exit codes, stdout/stderr, and task execution behavior.

mod support;

use std::sync::{Arc, Mutex};
use support::{TempProject, lpm};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[derive(Clone, Default)]
struct RemoteCacheState {
    artifact: Arc<Mutex<Option<Vec<u8>>>>,
    tag: Arc<Mutex<Option<String>>>,
    sha: Arc<Mutex<Option<String>>>,
}

struct RemoteCacheGetResponder {
    state: RemoteCacheState,
}

impl Respond for RemoteCacheGetResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let artifact = self
            .state
            .artifact
            .lock()
            .expect("remote cache artifact mutex poisoned")
            .clone();
        let Some(artifact) = artifact else {
            return ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": "Remote cache artifact not found"
            }));
        };

        let mut response = ResponseTemplate::new(200)
            .insert_header("Content-Type", "application/octet-stream")
            .insert_header("Content-Length", artifact.len().to_string())
            .set_body_bytes(artifact);
        if let Some(tag) = self
            .state
            .tag
            .lock()
            .expect("remote cache tag mutex poisoned")
            .clone()
        {
            response = response.insert_header("x-artifact-tag", tag);
        }
        if let Some(sha) = self
            .state
            .sha
            .lock()
            .expect("remote cache sha mutex poisoned")
            .clone()
        {
            response = response.insert_header("x-artifact-sha", sha);
        }
        response
    }
}

struct RemoteCachePutResponder {
    state: RemoteCacheState,
}

impl Respond for RemoteCachePutResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        *self
            .state
            .artifact
            .lock()
            .expect("remote cache artifact mutex poisoned") = Some(request.body.clone());
        *self
            .state
            .tag
            .lock()
            .expect("remote cache tag mutex poisoned") = request
            .headers
            .get("x-artifact-tag")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        *self
            .state
            .sha
            .lock()
            .expect("remote cache sha mutex poisoned") = request
            .headers
            .get("x-artifact-sha")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);

        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "urls": [] }))
    }
}

async fn mount_stateful_remote_cache(server: &MockServer, state: RemoteCacheState) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .respond_with(RemoteCacheGetResponder {
            state: state.clone(),
        })
        .mount(server)
        .await;

    Mock::given(method("PUT"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .respond_with(RemoteCachePutResponder { state })
        .mount(server)
        .await;
}

fn remote_cache_project(server: &MockServer, extra_remote_config: &str) -> TempProject {
    let project = TempProject::empty(
        r#"{
        "name": "remote-cache-test",
        "version": "1.0.0",
        "scripts": {
            "build": "node -e \"const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt','remote-hit'); fs.writeFileSync('executed-marker','ran'); console.log('remote-build-output')\""
        }
    }"#,
    );

    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
            "remoteCache": {{
                "enabled": true,
                "url": "{}/v8"{extra_remote_config}
            }},
            "tasks": {{
                "build": {{
                    "cache": true,
                    "outputs": ["dist/**"]
                }}
            }}
        }}"#,
            server.uri(),
        ),
    );
    project
}

fn run_build_with_remote_token(project: &TempProject) -> std::process::Output {
    lpm(project)
        .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
        .args(["run", "build"])
        .output()
        .expect("failed to run lpm run build")
}

fn remove_local_task_cache(project: &TempProject) {
    let _ = std::fs::remove_dir_all(project.cache_dir().join("tasks"));
}

fn remove_project_file(project: &TempProject, rel_path: &str) {
    let path = project.path().join(rel_path);
    if path.is_dir() {
        let _ = std::fs::remove_dir_all(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

// ─── Script Execution ────────────────────────────────────────────

#[test]
fn run_executes_script_and_succeeds() {
    let project = TempProject::from_fixture("with-scripts");

    lpm(&project).args(["run", "build"]).assert().success();
}

#[test]
fn run_script_output_reaches_stdout() {
    let project = TempProject::from_fixture("with-scripts");

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("failed to run lpm");

    // The script is `echo 'built'` — it should appear somewhere in output
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("built"),
        "expected 'built' in output, got:\n{combined}"
    );
}

#[test]
fn run_forwards_exit_code_from_failing_script() {
    let project = TempProject::empty(
        r#"{
        "name": "fail-test",
        "version": "1.0.0",
        "scripts": {
            "fail": "exit 42"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["run", "fail"])
        .output()
        .expect("failed to run lpm");

    // The CLI should forward the script's exit code
    assert!(
        !output.status.success(),
        "expected non-zero exit code for failing script"
    );
    // On most systems, the exit code is forwarded directly
    if let Some(code) = output.status.code() {
        assert_eq!(code, 42, "expected exit code 42 from 'exit 42' script");
    }
}

// ─── Missing Script ──────────────────────────────────────────────

#[test]
fn run_missing_script_fails_with_error() {
    let project = TempProject::from_fixture("with-scripts");

    let output = lpm(&project)
        .args(["run", "nonexistent"])
        .output()
        .expect("failed to run lpm");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nonexistent")
            || stderr.contains("not found")
            || stderr.contains("no script"),
        "expected error message mentioning the missing script, got:\n{stderr}"
    );
}

#[test]
fn run_hidden_script_cannot_be_invoked_directly() {
    let project = TempProject::empty(
        r#"{
        "name": "hidden-direct-test",
        "version": "1.0.0",
        "scripts": {
            ".build": "echo hidden"
        }
    }"#,
    );

    let output = lpm(&project)
        .env_remove("LPM_SCRIPT_CHILD")
        .args(["run", ".build"])
        .output()
        .expect("failed to run lpm run .build");

    assert!(
        !output.status.success(),
        "direct hidden script must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hidden script") && stderr.contains("cannot be invoked directly"),
        "stderr must explain hidden direct invocation, got:\n{stderr}"
    );
}

#[test]
fn script_shortcut_hidden_script_cannot_be_invoked_directly() {
    let project = TempProject::empty(
        r#"{
        "name": "hidden-shortcut-test",
        "version": "1.0.0",
        "scripts": {
            ".build": "echo hidden"
        }
    }"#,
    );

    let output = lpm(&project)
        .env_remove("LPM_SCRIPT_CHILD")
        .args([".build"])
        .output()
        .expect("failed to run lpm .build");

    assert!(
        !output.status.success(),
        "hidden shortcut must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hidden script") && stderr.contains("cannot be invoked directly"),
        "stderr must explain hidden direct invocation, got:\n{stderr}"
    );
}

#[test]
fn run_missing_script_suggestions_omit_hidden_package_json_scripts() {
    let project = TempProject::empty(
        r#"{
        "name": "hidden-suggestion-test",
        "version": "1.0.0",
        "scripts": {
            "build": "echo visible",
            ".build": "echo hidden"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["run", "missing"])
        .output()
        .expect("failed to run lpm run missing");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("build"),
        "stderr must still suggest visible scripts, got:\n{stderr}"
    );
    assert!(
        !stderr.contains(".build"),
        "stderr must not reveal hidden scripts, got:\n{stderr}"
    );
}

// ─── No package.json ─────────────────────────────────────────────

#[test]
fn run_without_package_json_fails() {
    let _project = TempProject::empty("{}");
    // Remove the package.json we just created, leaving an empty dir with
    // an invalid package.json (no scripts field)
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").unwrap();
    cmd.current_dir(dir.path());
    cmd.env("HOME", home.path());
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env_remove("LPM_TOKEN");

    let output = cmd
        .args(["run", "build"])
        .output()
        .expect("failed to run lpm");

    assert!(!output.status.success());
}

// ─── Multiple Scripts ────────────────────────────────────────────

#[test]
fn run_multiple_scripts_executes_all() {
    let project = TempProject::from_fixture("with-scripts");

    let output = lpm(&project)
        .args(["run", "build", "lint"])
        .output()
        .expect("failed to run lpm");

    assert!(output.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Both scripts should have run
    assert!(
        combined.contains("built") || combined.contains("build"),
        "expected build output in:\n{combined}"
    );
    assert!(
        combined.contains("linted") || combined.contains("lint"),
        "expected lint output in:\n{combined}"
    );
}

// ─── Pre/Post Hooks ──────────────────────────────────────────────

#[test]
fn run_executes_pre_and_post_hooks() {
    let project = TempProject::empty(
        r#"{
        "name": "hooks-test",
        "version": "1.0.0",
        "scripts": {
            "prebuild": "echo 'pre-hook-ran'",
            "build": "echo 'main-ran'",
            "postbuild": "echo 'post-hook-ran'"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("failed to run lpm");

    assert!(output.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        combined.contains("pre-hook-ran"),
        "pre-hook should have executed, got:\n{combined}"
    );
    assert!(
        combined.contains("main-ran"),
        "main script should have executed, got:\n{combined}"
    );
    assert!(
        combined.contains("post-hook-ran"),
        "post-hook should have executed, got:\n{combined}"
    );
}

#[test]
fn run_aborts_if_pre_hook_fails() {
    let project = TempProject::empty(
        r#"{
        "name": "hook-fail-test",
        "version": "1.0.0",
        "scripts": {
            "prebuild": "exit 1",
            "build": "echo 'should-not-run'"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("failed to run lpm");

    assert!(!output.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Main script should NOT have run since pre-hook failed
    assert!(
        !combined.contains("should-not-run"),
        "main script should not run after pre-hook failure"
    );
}

// ─── Extra Arguments ─────────────────────────────────────────────

#[test]
fn run_passes_extra_args_after_separator() {
    let project = TempProject::empty(
        r#"{
        "name": "args-test",
        "version": "1.0.0",
        "scripts": {
            "echo-args": "echo"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["run", "echo-args", "--", "hello", "world"])
        .output()
        .expect("failed to run lpm");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello") && stdout.contains("world"),
        "extra args should be forwarded to the script, got:\n{stdout}"
    );
}

// ─── Task Dependencies ───────────────────────────────────────────

#[test]
fn run_respects_task_dependencies_from_lpm_json() {
    let project = TempProject::from_fixture("with-scripts");

    // `test` depends on `build` in the lpm.json fixture
    let output = lpm(&project)
        .args(["run", "test"])
        .output()
        .expect("failed to run lpm");

    assert!(output.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Both build (dependency) and test should have run
    assert!(
        combined.contains("built") || combined.contains("build"),
        "build (dependency of test) should have run, got:\n{combined}"
    );
    assert!(
        combined.contains("tested") || combined.contains("test"),
        "test should have run, got:\n{combined}"
    );
}

#[test]
fn run_visible_script_can_invoke_hidden_script() {
    let project = TempProject::empty(
        r#"{
        "name": "hidden-nested-test",
        "version": "1.0.0",
        "scripts": {
            "build": "node invoke-hidden.js",
            ".build": "node write-marker.js"
        }
    }"#,
    );
    project.write_file(
        "invoke-hidden.js",
        r#"const { spawnSync } = require('child_process');
const result = spawnSync(process.env.LPM_TEST_BIN, ['run', '.build'], { stdio: 'inherit' });
process.exit(result.status === null ? 1 : result.status);
"#,
    );
    project.write_file(
        "write-marker.js",
        "require('fs').writeFileSync('hidden-ran.txt', 'yes\\n');",
    );

    let output = lpm(&project)
        .env("LPM_TEST_BIN", assert_cmd::cargo::cargo_bin("lpm-rs"))
        .args(["run", "build"])
        .output()
        .expect("failed to run lpm run build");

    assert!(
        output.status.success(),
        "visible script must be allowed to invoke hidden script; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(project.read_file("hidden-ran.txt"), "yes\n");
}

#[test]
fn run_lpm_json_dependency_can_invoke_hidden_script() {
    let project = TempProject::empty(
        r#"{
        "name": "hidden-dependency-test",
        "version": "1.0.0",
        "scripts": {
            "build": "echo visible",
            ".build": "node write-marker.js"
        }
    }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "dependsOn": [".build"]
                }
            }
        }"#,
    );
    project.write_file(
        "write-marker.js",
        "require('fs').writeFileSync('dependency-hidden-ran.txt', 'yes\\n');",
    );

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("failed to run lpm run build");

    assert!(
        output.status.success(),
        "lpm.json dependency must be allowed to invoke hidden script; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(project.read_file("dependency-hidden-ran.txt"), "yes\n");
}

#[test]
fn script_shortcut_runs_lpm_json_meta_task_and_dependencies() {
    let project = TempProject::from_fixture("with-scripts");

    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "outputs": ["dist/**"]
                },
                "test": {
                    "dependsOn": ["build"]
                },
                "verify": {
                    "dependsOn": ["lint", "check", "test"]
                }
            }
        }"#,
    );

    let output = lpm(&project)
        .args(["verify"])
        .output()
        .expect("failed to run lpm verify");

    assert!(
        output.status.success(),
        "script shortcut must behave like 'lpm run verify'\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    for expected in ["built", "linted", "checked", "tested"] {
        assert!(
            combined.contains(expected),
            "script shortcut must run the full task graph; missing {expected} in:\n{combined}"
        );
    }
}

// ─── Env Loading ─────────────────────────────────────────────────

#[test]
fn run_loads_dotenv_file() {
    let project = TempProject::empty(
        r#"{
        "name": "env-test",
        "version": "1.0.0",
        "scripts": {
            "show-env": "node show.js"
        }
    }"#,
    );

    // Print the env var via a real .js file rather than `node -e` —
    // sidesteps cmd.exe ↔ sh quoting differences for the inline JS
    // source, which would otherwise need separate JSON literals per
    // platform.
    project.write_file("show.js", "console.log(process.env.MY_TEST_VAR || '')");
    // Create a .env file
    project.write_file(".env", "MY_TEST_VAR=hello-from-dotenv");

    let output = lpm(&project)
        .args(["run", "show-env"])
        .output()
        .expect("failed to run lpm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "lpm run show-env must exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("hello-from-dotenv"),
        "expected .env variable to be loaded, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn run_loads_env_mode_file() {
    let project = TempProject::empty(
        r#"{
        "name": "env-mode-test",
        "version": "1.0.0",
        "scripts": {
            "show-env": "node show.js"
        }
    }"#,
    );

    project.write_file("show.js", "console.log(process.env.STAGE_VAR || '')");
    // Create .env.staging file
    project.write_file(".env.staging", "STAGE_VAR=staging-value");

    let output = lpm(&project)
        .args(["run", "show-env", "--env", "staging"])
        .output()
        .expect("failed to run lpm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "lpm run show-env --env staging must exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("staging-value"),
        "expected .env.staging variable to be loaded, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// ─── Task Caching ────────────────────────────────────────────────

#[test]
fn run_cache_hit_replays_output() {
    let project = TempProject::empty(
        r#"{
        "name": "cache-test",
        "version": "1.0.0",
        "scripts": {
            "build": "echo cache-test-output"
        }
    }"#,
    );

    // Enable caching for the build task via lpm.json
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );

    // First run: should execute and cache
    let output1 = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("failed to run first build");
    assert!(output1.status.success());

    let combined1 = format!(
        "{}{}",
        String::from_utf8_lossy(&output1.stdout),
        String::from_utf8_lossy(&output1.stderr),
    );
    assert!(
        combined1.contains("cache-test-output"),
        "first run should produce output, got:\n{combined1}"
    );

    // Second run: should hit cache and replay output
    let output2 = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("failed to run cached build");
    assert!(output2.status.success());

    let combined2 = format!(
        "{}{}",
        String::from_utf8_lossy(&output2.stdout),
        String::from_utf8_lossy(&output2.stderr),
    );

    // Should contain the cached output AND a "restored from cache" message
    assert!(
        combined2.contains("cache-test-output"),
        "cache hit should replay original output, got:\n{combined2}"
    );
    assert!(
        combined2.contains("cache") || combined2.contains("restored"),
        "cache hit should mention cache, got:\n{combined2}"
    );
}

#[test]
fn run_no_cache_flag_skips_cache() {
    let project = TempProject::empty(
        r#"{
        "name": "no-cache-test",
        "version": "1.0.0",
        "scripts": {
            "build": "echo no-cache-output"
        }
    }"#,
    );

    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );

    // First run to populate cache
    lpm(&project).args(["run", "build"]).assert().success();

    // Second run with --no-cache should re-execute, not use cache
    let output = lpm(&project)
        .args(["run", "build", "--no-cache"])
        .output()
        .expect("failed to run with --no-cache");

    assert!(output.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Should produce fresh output (not say "restored from cache")
    assert!(
        combined.contains("no-cache-output"),
        "should re-execute script, got:\n{combined}"
    );
}

#[tokio::test]
async fn run_remote_cache_miss_uploads_and_later_restores_outputs() {
    let server = MockServer::start().await;
    let state = RemoteCacheState::default();
    mount_stateful_remote_cache(&server, state.clone()).await;
    let project = remote_cache_project(&server, "");

    let first = run_build_with_remote_token(&project);
    assert!(
        first.status.success(),
        "first run should succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    assert!(
        state
            .artifact
            .lock()
            .expect("remote cache artifact mutex poisoned")
            .is_some(),
        "remote miss should upload an artifact",
    );

    remove_local_task_cache(&project);
    remove_project_file(&project, "dist");
    remove_project_file(&project, "executed-marker");

    let second = run_build_with_remote_token(&project);
    assert!(
        second.status.success(),
        "remote hit run should succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );

    assert_eq!(project.read_file("dist/value.txt"), "remote-hit");
    assert!(
        !project.file_exists("executed-marker"),
        "remote hit must restore outputs without re-running the script",
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    assert!(
        combined.contains("remote-build-output") && combined.contains("cache"),
        "remote hit should replay cached output and mention cache, got:\n{combined}",
    );
}

#[tokio::test]
async fn run_remote_cache_outage_does_not_fail_successful_local_build() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .respond_with(ResponseTemplate::new(500).set_body_string("temporary outage"))
        .mount(&server)
        .await;
    let project = remote_cache_project(&server, "");

    let output = run_build_with_remote_token(&project);

    assert!(
        output.status.success(),
        "remote outage must not fail local build:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(project.read_file("dist/value.txt"), "remote-hit");
}

#[tokio::test]
async fn run_remote_cache_corrupt_artifact_is_treated_as_miss() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(b"not a gzip artifact".to_vec()),
        )
        .mount(&server)
        .await;
    let project = remote_cache_project(&server, "");

    let output = run_build_with_remote_token(&project);

    assert!(
        output.status.success(),
        "corrupt remote artifact must fall back to local build:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        project.file_exists("executed-marker"),
        "corrupt remote artifact should be a miss and execute the script",
    );
}

#[tokio::test]
async fn run_remote_cache_artifact_failing_content_hash_is_rejected() {
    // A remote cache hit must not be trusted unless the downloaded bytes match
    // the advertised `x-artifact-sha`. Without that check the client extracts
    // whatever the server returns under a valid key: the cache-poisoning path.
    let server = MockServer::start().await;
    let state = RemoteCacheState::default();
    mount_stateful_remote_cache(&server, state.clone()).await;
    let project = remote_cache_project(&server, "");

    // First run: real miss uploads a genuine artifact and its content hash.
    let first = run_build_with_remote_token(&project);
    assert!(
        first.status.success(),
        "first run should succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    // Tamper with the advertised hash so the served bytes no longer match it,
    // simulating a corrupted/poisoned object served under a legitimate key.
    *state.sha.lock().expect("remote cache sha mutex poisoned") = Some("0".repeat(64));

    remove_local_task_cache(&project);
    remove_project_file(&project, "dist");
    remove_project_file(&project, "executed-marker");

    let second = run_build_with_remote_token(&project);
    assert!(
        second.status.success(),
        "mismatched-hash artifact must fall back to local build:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    assert!(
        project.file_exists("executed-marker"),
        "artifact failing content-hash verification must be a miss and re-run the script",
    );
    assert_eq!(
        project.read_file("dist/value.txt"),
        "remote-hit",
        "outputs must come from the real local build, not the unverified remote artifact",
    );
}

#[tokio::test]
async fn run_remote_cache_bad_signature_is_treated_as_miss() {
    let server = MockServer::start().await;
    let state = RemoteCacheState::default();
    mount_stateful_remote_cache(&server, state.clone()).await;
    let project = remote_cache_project(&server, r#", "signature": true"#);

    let first = lpm(&project)
        .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
        .args(["run", "build"])
        .output()
        .expect("failed to run first signed remote build");
    assert!(first.status.success());

    *state.tag.lock().expect("remote cache tag mutex poisoned") =
        Some("sha256=bad-signature".into());
    remove_local_task_cache(&project);
    remove_project_file(&project, "dist");
    remove_project_file(&project, "executed-marker");

    let second = lpm(&project)
        .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
        .args(["run", "build"])
        .output()
        .expect("failed to run second signed remote build");

    assert!(
        second.status.success(),
        "bad remote signature must fall back to local build:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    assert!(
        project.file_exists("executed-marker"),
        "bad remote signature should be a miss and execute the script",
    );
}

#[tokio::test]
async fn run_remote_cache_disabled_does_not_contact_remote_server() {
    let server = MockServer::start().await;
    let project = TempProject::empty(
        r#"{
        "name": "remote-cache-disabled",
        "version": "1.0.0",
        "scripts": {
            "build": "node -e \"const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt','local')\""
        }
    }"#,
    );
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
            "remoteCache": {{
                "enabled": false,
                "url": "{}/v8"
            }},
            "tasks": {{
                "build": {{ "cache": true, "outputs": ["dist/**"] }}
            }}
        }}"#,
            server.uri(),
        ),
    );

    let output = run_build_with_remote_token(&project);
    assert!(output.status.success());

    let requests = server
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "disabled remote cache must not contact server, got {} requests",
        requests.len(),
    );
}

// ─── Multi-Task JSON ─────────────────────────────────────────────

#[test]
fn run_multi_task_json_output() {
    // This is tested in json_output.rs but we verify the shape here too
    let project = TempProject::from_fixture("with-scripts");

    // Run "ci" which depends on lint, check, test (which depends on build)
    let output = lpm(&project)
        .args(["run", "ci", "--json"])
        .output()
        .expect("failed to run lpm run ci --json");

    assert!(
        output.status.success(),
        "run ci --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = support::assertions::parse_json_output(&output.stdout);

    assert_eq!(json["success"], true);

    let tasks = json["tasks"].as_array().expect("tasks should be an array");
    // ci depends on lint, check, test; test depends on build
    // So we expect at least 4 tasks: build, lint, check, test
    assert!(
        tasks.len() >= 4,
        "expected at least 4 tasks (build, lint, check, test), got {}",
        tasks.len()
    );

    // All tasks should have succeeded
    for task in tasks {
        assert_eq!(
            task["success"], true,
            "task {} should have succeeded",
            task["name"]
        );
    }
}

#[test]
fn run_watch_rejects_multiple_scripts() {
    let project = TempProject::from_fixture("with-scripts");

    let output = lpm(&project)
        .args(["run", "build", "lint", "--watch"])
        .output()
        .expect("failed to run lpm run --watch with multiple scripts");

    assert!(
        !output.status.success(),
        "watch with multiple scripts must fail fast"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--watch") && stderr.contains("exactly one script"),
        "expected a watch single-script error, got:\n{stderr}"
    );
}

#[test]
fn run_watch_rejects_workspace_selection_flags() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["run", "echo", "--watch", "--filter", "@test/utils"])
        .output()
        .expect("failed to run lpm run --watch --filter");

    assert!(
        !output.status.success(),
        "watch with workspace selection flags must fail fast"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--watch") && stderr.contains("--filter"),
        "expected a watch/workspace-flag error, got:\n{stderr}"
    );
}

// ─── Parallel Execution ──────────────────────────────────────────

#[test]
fn run_parallel_executes_independent_tasks() {
    let project = TempProject::from_fixture("with-scripts");

    let output = lpm(&project)
        .args(["run", "lint", "check", "--parallel"])
        .output()
        .expect("failed to run parallel tasks");

    assert!(output.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Both tasks should have executed
    assert!(
        combined.contains("linted") || combined.contains("lint"),
        "lint should have run in parallel, got:\n{combined}"
    );
    assert!(
        combined.contains("checked") || combined.contains("check"),
        "check should have run in parallel, got:\n{combined}"
    );
}

// ─── Workspace dispatch: --filter / --all / --affected ─────────────
//
// Seeds each member's package.json with a unique script that writes a
// sentinel file. The test then asserts which members ran the script
// based on dispatch selection. Sentinels are cleaner than parsing
// streamed task output across N members.

fn seed_workspace_with_unique_scripts(project: &TempProject) {
    for member in ["app", "core", "utils"] {
        let pkg_path = format!("packages/{member}/package.json");
        let pkg_content = project.read_file(&pkg_path);
        let mut pkg: serde_json::Value =
            serde_json::from_str(&pkg_content).expect("parse member package.json");
        pkg["scripts"] = serde_json::json!({
            "echo": format!("node -e \"require('fs').writeFileSync('ran-{member}.txt','ok')\""),
        });
        project.write_file(&pkg_path, &serde_json::to_string_pretty(&pkg).unwrap());
    }
}

fn member_ran(project: &TempProject, member: &str) -> bool {
    project.file_exists(&format!("packages/{member}/ran-{member}.txt"))
}

#[test]
fn run_filter_executes_only_matched_members() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_unique_scripts(&project);

    let output = lpm(&project)
        .args(["run", "echo", "--filter", "@test/utils"])
        .output()
        .expect("failed to run lpm run --filter");

    assert!(
        output.status.success(),
        "run --filter must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        member_ran(&project, "utils"),
        "utils must have executed echo"
    );
    assert!(
        !member_ran(&project, "core"),
        "core must NOT have executed echo (not in filter)"
    );
    assert!(
        !member_ran(&project, "app"),
        "app must NOT have executed echo (not in filter)"
    );
}

fn seed_workspace_with_failing_leaf_script(project: &TempProject) {
    for member in ["app", "core", "utils"] {
        let pkg_path = format!("packages/{member}/package.json");
        let pkg_content = project.read_file(&pkg_path);
        let mut pkg: serde_json::Value =
            serde_json::from_str(&pkg_content).expect("parse member package.json");

        let command = if member == "utils" {
            format!(
                "node -e \"require('fs').writeFileSync('ran-{member}.txt','failed'); process.exit(1)\""
            )
        } else {
            format!("node -e \"require('fs').writeFileSync('ran-{member}.txt','ok')\"")
        };

        pkg["scripts"] = serde_json::json!({
            "check": command,
        });
        project.write_file(&pkg_path, &serde_json::to_string_pretty(&pkg).unwrap());
    }
}

#[test]
fn run_filter_bails_after_first_failed_workspace_member_by_default() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_failing_leaf_script(&project);

    let output = lpm(&project)
        .args(["run", "check", "--filter", "@test/*"])
        .output()
        .expect("failed to run lpm run --filter");

    assert!(
        !output.status.success(),
        "filtered workspace run must fail when a selected member script fails"
    );
    assert!(
        member_ran(&project, "utils"),
        "utils must run before the filtered batch bails"
    );
    assert!(
        !member_ran(&project, "core"),
        "core must not run after an earlier selected package fails by default"
    );
    assert!(
        !member_ran(&project, "app"),
        "app must not run after an earlier selected package fails by default"
    );
}

#[test]
fn run_all_executes_in_every_member() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_unique_scripts(&project);

    let output = lpm(&project)
        .args(["run", "echo", "--all"])
        .output()
        .expect("failed to run lpm run --all");

    assert!(
        output.status.success(),
        "run --all must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    for member in ["app", "core", "utils"] {
        assert!(
            member_ran(&project, member),
            "{member} must have executed echo under --all"
        );
    }
}

#[test]
fn run_affected_with_no_changes_executes_in_zero_members() {
    use std::process::Command;
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_unique_scripts(&project);

    // Seed a clean git history so --affected vs HEAD diff is empty.
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(project.path())
        .status()
        .expect("git init failed");
    Command::new("git")
        .args(["add", "-A"])
        .current_dir(project.path())
        .status()
        .expect("git add failed");
    Command::new("git")
        .args([
            "-c",
            "user.email=t@t.t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "init",
        ])
        .current_dir(project.path())
        .status()
        .expect("git commit failed");

    let output = lpm(&project)
        .args(["run", "echo", "--affected", "--base", "HEAD"])
        .output()
        .expect("failed to run lpm run --affected");

    assert!(
        output.status.success(),
        "run --affected with no diff must exit 0"
    );

    for member in ["app", "core", "utils"] {
        assert!(
            !member_ran(&project, member),
            "{member} must NOT execute when nothing changed since HEAD"
        );
    }
}

#[test]
fn run_filter_typo_without_fail_flag_exits_zero() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_unique_scripts(&project);

    let output = lpm(&project)
        .args(["run", "echo", "--filter", "this-does-not-exist"])
        .output()
        .expect("failed to run lpm run --filter");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    for member in ["app", "core", "utils"] {
        assert!(
            !member_ran(&project, member),
            "{member} must NOT execute on empty-match filter"
        );
    }
}

#[test]
fn run_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_unique_scripts(&project);

    let output = lpm(&project)
        .args([
            "run",
            "echo",
            "--filter",
            "this-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm run --filter --fail-if-no-match");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero"
    );
}
