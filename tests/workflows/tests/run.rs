//! Workflow tests for `lpm run`.
//!
//! These tests spawn the real `lpm-rs` binary against fixture projects
//! and verify exit codes, stdout/stderr, and task execution behavior.

mod support;

use std::sync::{Arc, Mutex};
use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_spawnable, lpm_spawnable_from_path, write_repeated_file};
use wiremock::matchers::{header, method, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[test]
fn run_rejects_an_invalid_env_schema_regex_before_starting_the_script() {
    let project = TempProject::empty(
        r#"{
            "name":"invalid-env-regex",
            "version":"1.0.0",
            "scripts":{"should-not-run":"node should-not-run.js"}
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"TOKEN":{"pattern":"("}}}}"#,
    );
    project.write_file(
        "should-not-run.js",
        "require('fs').writeFileSync('spawned.txt', 'yes');\n",
    );

    let output = lpm(&project)
        .args(["run", "should-not-run"])
        .output()
        .expect("run a script with an invalid env schema regex");

    assert!(!output.status.success(), "invalid regex must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid regex"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !project.file_exists("spawned.txt"),
        "script started before env schema validation"
    );
}

#[cfg(unix)]
#[test]
fn run_rejects_an_environment_file_symlink_outside_the_project() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(
        r#"{
            "name":"env-symlink-containment",
            "version":"1.0.0",
            "scripts":{"read-secret":"node -e \"require('fs').writeFileSync('leaked', process.env.EXTERNAL_SECRET || '<unset>')\""}
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{"environments":{"staging":{"file":"config/.env.staging"}}}"#,
    );
    let external = project.home().join("outside-secret.env");
    std::fs::write(&external, "EXTERNAL_SECRET=must-not-load\n")
        .expect("write external secret file");
    let configured = project.path().join("config/.env.staging");
    std::fs::create_dir_all(configured.parent().unwrap()).expect("create env directory");
    symlink(&external, &configured).expect("create external env symlink");

    let output = lpm(&project)
        .args(["run", "read-secret", "--env", "staging"])
        .output()
        .expect("run with an environment file symlink");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "external environment symlink was accepted:\n{combined}"
    );
    assert!(
        !project.file_exists("leaked"),
        "script ran after the environment containment failure"
    );
    assert!(
        combined.contains("outside the project"),
        "containment error was not actionable:\n{combined}"
    );
}

#[cfg(unix)]
#[test]
fn run_without_lpm_json_rejects_a_standard_env_symlink_outside_the_project() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(
        r#"{
            "name":"standard-env-symlink-containment",
            "version":"1.0.0",
            "scripts":{"read-secret":"node -e \"require('fs').writeFileSync('leaked', process.env.EXTERNAL_SECRET || '<unset>')\""}
        }"#,
    );
    let external = project.home().join("outside-standard.env");
    std::fs::write(&external, "EXTERNAL_SECRET=must-not-load\n")
        .expect("write external secret file");
    symlink(&external, project.path().join(".env")).expect("create external .env symlink");

    let output = lpm(&project)
        .args(["run", "read-secret"])
        .output()
        .expect("run without lpm.json through an external .env symlink");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "external standard environment symlink was accepted:\n{combined}"
    );
    assert!(
        !project.file_exists("leaked"),
        "script ran after the standard environment containment failure"
    );
    assert!(
        combined.contains("outside the project"),
        "containment error was not actionable:\n{combined}"
    );
}

#[cfg(windows)]
#[test]
fn run_passes_cmd_metacharacters_as_literal_arguments() {
    let project = TempProject::empty(
        r#"{
            "name":"windows-literal-args",
            "version":"1.0.0",
            "scripts":{"capture":"capture"}
        }"#,
    );
    project.write_file(
        "capture.js",
        "require('fs').writeFileSync('args.json', JSON.stringify(process.argv.slice(2)));\n",
    );
    std::fs::create_dir_all(project.path().join("node_modules/.bin"))
        .expect("create local bin directory");
    project.write_file(
        "node_modules/.bin/capture.cmd",
        "@ECHO OFF\r\nnode \"%~dp0\\..\\..\\capture.js\" %*\r\n",
    );

    let output = lpm(&project)
        .args([
            "run",
            "capture",
            "--",
            "",
            "two words",
            "tab\tvalue",
            "snowman-☃",
            "a&b",
            "c|d",
            "e<f",
            "g>h",
            "%PATH%",
            "!delayed!",
            "quoted\"value",
            "trail\\",
            "& echo PWNED > injected-marker",
        ])
        .output()
        .expect("run script with cmd.exe metacharacters");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success(), "script failed:\n{combined}");
    let args: serde_json::Value =
        serde_json::from_str(&project.read_file("args.json")).expect("parse captured arguments");
    assert_eq!(
        args,
        serde_json::json!([
            "",
            "two words",
            "tab\tvalue",
            "snowman-☃",
            "a&b",
            "c|d",
            "e<f",
            "g>h",
            "%PATH%",
            "!delayed!",
            "quoted\"value",
            "trail\\",
            "& echo PWNED > injected-marker"
        ])
    );
    assert!(!project.file_exists("injected-marker"));
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

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
fn run_manifest_task_name_cannot_forge_terminal_rows() {
    let task_name = "safe-task\nFORGED-TASK\rrewritten\u{8}\u{1b}[2J\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";
    let manifest = serde_json::json!({
        "name": "terminal-task-name",
        "version": "1.0.0",
        "scripts": {task_name: "node -e \"\""}
    });
    let project = TempProject::empty(&manifest.to_string());

    let output = lpm(&project)
        .args(["run", task_name])
        .output()
        .expect("failed to run task with terminal controls in its name");
    assert!(
        output.status.success(),
        "task must still run; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        rendered.contains("safe-task?FORGED-TASK?rewritten?end"),
        "task name must remain recognizable without injected rows; got:\n{rendered}"
    );
    for attacker_fragment in [
        "\u{1b}", "\u{7}", "\u{8}", "\r", "\u{007f}", "\u{0090}", "\u{009c}", "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "task output retained attacker fragment {attacker_fragment:?}:\n{rendered}"
        );
    }
}

#[test]
fn run_human_output_uses_slim_status_lines() {
    let project = TempProject::from_fixture("with-scripts");

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("failed to run lpm run build");

    assert!(
        output.status.success(),
        "run build must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("› Running build"),
        "must show slim run phase; got:\n{combined}"
    );
    assert!(
        combined.contains("cache") && combined.contains("miss"),
        "must show cache metadata; got:\n{combined}"
    );
    assert!(
        combined.contains("command") && combined.contains("echo 'built'"),
        "must show command metadata; got:\n{combined}"
    );
    assert!(
        combined.contains("built"),
        "must preserve script output; got:\n{combined}"
    );
    assert!(
        combined.contains("✓ build · success in"),
        "must show slim success terminus with elapsed time; got:\n{combined}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "run output should not use bordered/cliclack glyphs; got:\n{combined}"
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
    cmd.env("LPM_HOME", home.path().join(".lpm"));
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env("LPM_DISABLE_TELEMETRY", "1");
    cmd.env("LPM_FORCE_FILE_AUTH", "1");
    cmd.env("LPM_TEST_FAST_SCRYPT", "1");
    cmd.env("LPM_FORCE_FILE_VAULT", "1");
    cmd.env("LPM_DISABLE_HOST_CLI_AUTH", "1");
    cmd.env(
        "LPM_SECURITY_POLICY_PATH",
        home.path().join(".lpm/security-policy.toml"),
    );
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

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Main script stdout should NOT appear since pre-hook failed. The
    // human metadata block may still name the command that would have run.
    assert!(
        !stdout.contains("should-not-run"),
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

#[test]
fn run_prefers_an_lpm_task_command_over_the_same_named_package_script() {
    let project = TempProject::empty(
        r#"{
            "name": "task-command-precedence",
            "version": "1.0.0",
            "scripts": {
                "build": "node package-build.js"
            }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "command": "node lpm-build.js"
                }
            }
        }"#,
    );
    project.write_file(
        "package-build.js",
        "require('fs').writeFileSync('package-command-ran.txt', 'yes');",
    );
    project.write_file(
        "lpm-build.js",
        "require('fs').writeFileSync('lpm-command-ran.txt', 'yes');",
    );

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("run a task with both command sources");

    assert!(
        output.status.success(),
        "lpm task command must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        project.file_exists("lpm-command-ran.txt"),
        "lpm.json task command did not run"
    );
    assert!(
        !project.file_exists("package-command-ran.txt"),
        "same-named package.json script overrode the lpm.json task command"
    );
}

#[test]
fn sequential_run_preserves_the_requested_order_for_independent_scripts() {
    let project = TempProject::empty(
        r#"{
            "name": "requested-task-order",
            "version": "1.0.0",
            "scripts": {
                "z-prepare": "node prepare.js",
                "a-consume": "node consume.js"
            }
        }"#,
    );
    project.write_file(
        "prepare.js",
        "require('fs').writeFileSync('prepared.txt', 'yes');",
    );
    project.write_file(
        "consume.js",
        "if (!require('fs').existsSync('prepared.txt')) process.exit(23);",
    );

    let output = lpm(&project)
        .args(["run", "z-prepare", "a-consume"])
        .output()
        .expect("run independent scripts sequentially");

    assert!(
        output.status.success(),
        "sequential scripts ran out of request order\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn sequential_run_reports_environment_validation_details_before_spawn() {
    let project = TempProject::empty(
        r#"{
            "name": "sequential-env-validation",
            "version": "1.0.0"
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "deploy": {
                    "command": "node deploy.js"
                }
            },
            "envSchema": {
                "vars": {
                    "DATABASE_URL": { "required": true },
                    "STRIPE_KEY": { "required": true }
                }
            }
        }"#,
    );
    project.write_file(
        "deploy.js",
        "require('fs').writeFileSync('spawned.txt', 'yes');",
    );

    let output = lpm(&project)
        .args(["run", "--env=preview", "deploy"])
        .output()
        .expect("run a task blocked by environment validation");

    assert!(!output.status.success(), "missing required env must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("environment validation failed")
            && stderr.contains("DATABASE_URL: missing (required)")
            && stderr.contains("STRIPE_KEY: missing (required)"),
        "sequential task failure must preserve validation details:\n{stderr}"
    );
    assert!(
        !project.file_exists("spawned.txt"),
        "task spawned before environment validation completed"
    );
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

#[test]
fn run_uses_task_environment_when_cli_mode_is_absent() {
    let project = TempProject::empty(
        r#"{
        "name": "task-env-mode",
        "version": "1.0.0"
    }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "show-env": {
                    "command": "node show.js",
                    "env": "staging"
                }
            }
        }"#,
    );
    project.write_file(".env.staging", "STAGE_VAR=task-staging\n");
    project.write_file("show.js", "console.log(process.env.STAGE_VAR || '<unset>')");

    let output = lpm(&project)
        .args(["run", "show-env"])
        .output()
        .expect("run task with its configured environment");

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("task-staging"),
        "task environment was not loaded; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn run_cli_environment_overrides_task_environment() {
    let project = TempProject::empty(
        r#"{
        "name": "task-env-override",
        "version": "1.0.0"
    }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "show-env": {
                    "command": "node show.js",
                    "env": "staging"
                }
            }
        }"#,
    );
    project.write_file(".env.staging", "STAGE_VAR=task-staging\n");
    project.write_file(".env.production", "STAGE_VAR=cli-production\n");
    project.write_file("show.js", "console.log(process.env.STAGE_VAR || '<unset>')");

    let output = lpm(&project)
        .args(["run", "show-env", "--env", "production"])
        .output()
        .expect("run task with a CLI environment override");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("cli-production"));
}

#[test]
fn run_rejects_oversized_lpm_json_before_spawning_script() {
    let project = TempProject::empty(
        r#"{
        "name": "oversized-lpm-json",
        "version": "1.0.0",
        "scripts": {"probe": "node write-marker.js"}
    }"#,
    );
    project.write_file(
        "write-marker.js",
        "require('fs').writeFileSync('executed-marker', 'ran')",
    );
    let path = project.path().join("lpm.json");
    write_repeated_file(
        &path,
        br#"{"env":{},"padding":""#,
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        br#""}"#,
    );

    let output = lpm(&project)
        .args(["run", "probe"])
        .output()
        .expect("run script with oversized lpm.json");

    assert!(!output.status.success(), "oversized lpm.json must fail");
    assert!(
        !project.file_exists("executed-marker"),
        "script must not spawn after lpm.json failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()) && stderr.contains("16777216-byte limit"),
        "error must identify lpm.json and limit; got:\n{stderr}"
    );
}

#[test]
fn run_rejects_oversized_nvmrc_before_lower_precedence_pin_or_script_spawn() {
    let project = TempProject::empty(
        r#"{
        "name": "oversized-nvmrc",
        "version": "1.0.0",
        "scripts": {"probe": "node write-marker.js"}
    }"#,
    );
    project.write_file(
        "write-marker.js",
        "require('fs').writeFileSync('executed-marker', 'ran')",
    );
    project.write_file(".node-version", "20.18.0\n");
    let path = project.path().join(".nvmrc");
    write_repeated_file(
        &path,
        b"22\n#",
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        b"\n",
    );

    let output = lpm(&project)
        .env("LPM_NO_AUTO_INSTALL", "true")
        .args(["run", "probe"])
        .output()
        .expect("run script with oversized .nvmrc");

    assert!(!output.status.success(), "oversized .nvmrc must fail");
    assert!(
        !project.file_exists("executed-marker"),
        "script must not spawn after .nvmrc failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()) && stderr.contains("16777216-byte limit"),
        "error must identify .nvmrc and limit; got:\n{stderr}"
    );
}

#[test]
fn run_rejects_oversized_node_version_before_system_node_or_script_spawn() {
    let project = TempProject::empty(
        r#"{
        "name": "oversized-node-version",
        "version": "1.0.0",
        "scripts": {"probe": "node write-marker.js"}
    }"#,
    );
    project.write_file(
        "write-marker.js",
        "require('fs').writeFileSync('executed-marker', 'ran')",
    );
    let path = project.path().join(".node-version");
    write_repeated_file(
        &path,
        b"20.18.0\n#",
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        b"\n",
    );

    let output = lpm(&project)
        .args(["run", "probe"])
        .output()
        .expect("run script with oversized .node-version");

    assert!(
        !output.status.success(),
        "oversized .node-version must fail"
    );
    assert!(
        !project.file_exists("executed-marker"),
        "script must not spawn after .node-version failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()) && stderr.contains("16777216-byte limit"),
        "error must identify .node-version and limit; got:\n{stderr}"
    );
}

#[test]
fn run_rejects_oversized_dotenv_before_spawning_script() {
    let project = TempProject::empty(
        r#"{
        "name": "oversized-dotenv",
        "version": "1.0.0",
        "scripts": {"probe": "node write-marker.js"}
    }"#,
    );
    project.write_file(
        "write-marker.js",
        "require('fs').writeFileSync('executed-marker', 'ran')",
    );
    let path = project.path().join(".env");
    write_repeated_file(
        &path,
        b"SAFE=value\n#",
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        b"\n",
    );

    let output = lpm(&project)
        .args(["run", "probe"])
        .output()
        .expect("run script with oversized dotenv");

    assert!(!output.status.success(), "oversized dotenv must fail");
    assert!(
        !project.file_exists("executed-marker"),
        "script must not spawn after dotenv failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()) && stderr.contains("16777216-byte limit"),
        "error must identify dotenv and limit; got:\n{stderr}"
    );
}

// ─── Task Caching ────────────────────────────────────────────────

fn populated_task_cache_entry(project: &TempProject) -> std::path::PathBuf {
    let task_cache = project.home().join(".lpm/cache/tasks");
    let entries: Vec<_> = std::fs::read_dir(&task_cache)
        .expect("read task cache")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.chars().all(|character| character.is_ascii_hexdigit()))
        })
        .collect();
    assert_eq!(entries.len(), 1, "expected one task cache entry");
    entries.into_iter().next().unwrap()
}

fn task_cache_restore_lock_path(project: &TempProject) -> std::path::PathBuf {
    use sha2::{Digest as _, Sha256};

    let canonical_project = std::fs::canonicalize(project.path()).unwrap();
    let mut hasher = Sha256::new();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        hasher.update(canonical_project.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        for unit in canonical_project.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
    }
    project
        .home()
        .join(".lpm/cache/tasks/.locks")
        .join(format!("project-{:x}.lock", hasher.finalize()))
}

fn wait_for_task_marker(
    child: &mut std::process::Child,
    marker: &std::path::Path,
    description: &str,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            child
                .try_wait()
                .expect("inspect blocked task process")
                .is_none(),
            "task exited before {description}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "task did not reach {description}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn successful_task_remains_successful_when_cache_publication_fails() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-publication-failure",
            "version": "1.0.0",
            "scripts": {"build": "node build.js"}
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {"cache": true, "outputs": ["dist/**"]}
            }
        }"#,
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/value.txt', 'built');"#,
    );
    std::fs::create_dir_all(project.home().join(".lpm")).unwrap();
    std::fs::write(project.home().join(".lpm/cache"), "not a directory").unwrap();

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("run a successful task with an unavailable cache");

    assert!(
        output.status.success(),
        "cache publication changed task success: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("dist/value.txt"), "built");
}

#[cfg(unix)]
#[test]
fn contained_input_symlink_retarget_invalidates_task_cache() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(
        r#"{
            "name": "cache-input-symlink",
            "version": "1.0.0",
            "scripts": {"build": "node build.js"}
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["src/current"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/value.txt', fs.readlinkSync('src/current'));"#,
    );
    project.write_file("src/a.txt", "same");
    project.write_file("src/b.txt", "same");
    symlink("a.txt", project.path().join("src/current")).unwrap();

    lpm(&project).args(["run", "build"]).assert().success();
    std::fs::remove_dir_all(project.path().join("dist")).unwrap();
    std::fs::remove_file(project.path().join("src/current")).unwrap();
    symlink("b.txt", project.path().join("src/current")).unwrap();

    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/value.txt"), "b.txt");
}

fn corrupt_local_cache_project() -> TempProject {
    let project = TempProject::empty(
        r#"{
            "name": "corrupt-local-cache",
            "version": "1.0.0",
            "scripts": {"build": "node build.js"}
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {"cache": true, "outputs": ["dist/**"]}
            }
        }"#,
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
const count = fs.existsSync('execution-count') ? Number(fs.readFileSync('execution-count')) + 1 : 1;
fs.writeFileSync('execution-count', String(count));
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/value.txt', `fresh-${count}`);"#,
    );
    project
}

#[test]
fn run_missing_local_cache_archive_executes_task() {
    let project = corrupt_local_cache_project();
    lpm(&project).args(["run", "build"]).assert().success();
    let entry = populated_task_cache_entry(&project);
    std::fs::remove_file(entry.join("outputs.tar.gz")).expect("remove local cache archive");
    std::fs::remove_dir_all(project.path().join("dist")).expect("remove built output");

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("run task with missing local cache archive");

    assert!(
        output.status.success(),
        "task should recover from missing archive"
    );
    assert_eq!(project.read_file("execution-count"), "2");
    assert_eq!(project.read_file("dist/value.txt"), "fresh-2");
}

#[test]
fn run_corrupt_local_cache_archive_executes_task() {
    let project = corrupt_local_cache_project();
    lpm(&project).args(["run", "build"]).assert().success();
    let entry = populated_task_cache_entry(&project);
    std::fs::write(entry.join("outputs.tar.gz"), b"not a gzip archive")
        .expect("corrupt local cache archive");
    std::fs::remove_dir_all(project.path().join("dist")).expect("remove built output");

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("run task with corrupt local cache archive");

    assert!(
        output.status.success(),
        "task should recover from corrupt archive"
    );
    assert_eq!(project.read_file("execution-count"), "2");
    assert_eq!(project.read_file("dist/value.txt"), "fresh-2");
}

#[test]
fn run_cache_revalidates_inputs_after_waiting_for_the_restore_lock() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-restore-input-race",
            "version": "1.0.0",
            "scripts": {"build": "node build.js"}
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{"tasks":{"build":{"cache":true,"inputs":["src/**"],"outputs":["dist/**"]}}}"#,
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
const count = fs.existsSync('execution-count') ? Number(fs.readFileSync('execution-count')) + 1 : 1;
fs.writeFileSync('execution-count', String(count));
fs.mkdirSync('dist', {recursive: true});
fs.copyFileSync('src/value.txt', 'dist/value.txt');"#,
    );
    project.write_file("src/value.txt", "v1");
    lpm(&project).args(["run", "build"]).assert().success();
    std::fs::remove_dir_all(project.path().join("dist")).unwrap();

    let lock_path = task_cache_restore_lock_path(&project);
    let restore_lock = lpm_common::acquire_single_file_exclusive_lock(&lock_path)
        .expect("hold the task cache project restore lock");
    let wait_log = project.home().join("task-cache-restore-wait.log");
    let mut command = lpm_spawnable(&project);
    command.stderr(std::process::Stdio::from(
        std::fs::File::create(&wait_log).unwrap(),
    ));
    command.args(["run", "build"]);
    let mut child = command.spawn().expect("start a blocked cache restore");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting = std::fs::read_to_string(&wait_log)
            .is_ok_and(|stderr| stderr.contains("Waiting for another lpm operation"));
        if waiting {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "cache restore exited before waiting for its project lock"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "cache restore did not wait for its project lock"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    project.write_file("src/value.txt", "v2");
    drop(restore_lock);
    let output = child
        .wait_with_output()
        .expect("finish the cache restore race");
    let stderr = std::fs::read_to_string(wait_log).unwrap();

    assert!(
        output.status.success(),
        "cache restore race failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr
    );
    assert_eq!(project.read_file("execution-count"), "2");
    assert_eq!(project.read_file("dist/value.txt"), "v2");
}

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
fn run_cache_restore_removes_files_absent_from_the_cached_output_set() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-exact-outputs",
            "version": "1.0.0",
            "scripts": { "build": "node build.js" }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["build.js", "mode.txt"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
fs.rmSync('dist', {recursive: true, force: true});
fs.mkdirSync('dist', {recursive: true});
const mode = fs.readFileSync('mode.txt', 'utf8').trim();
fs.writeFileSync('dist/current.txt', mode);
if (mode === 'expanded') fs.writeFileSync('dist/stale.txt', 'stale');
fs.appendFileSync('executions.txt', `${mode}\n`);"#,
    );

    project.write_file("mode.txt", "minimal\n");
    lpm(&project).args(["run", "build"]).assert().success();

    project.write_file("mode.txt", "expanded\n");
    lpm(&project).args(["run", "build"]).assert().success();
    assert!(project.file_exists("dist/stale.txt"));

    project.write_file("mode.txt", "minimal\n");
    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/current.txt"), "minimal");
    assert!(
        !project.file_exists("dist/stale.txt"),
        "cache restore retained an output absent from the cached result"
    );
    assert_eq!(project.read_file("executions.txt"), "minimal\nexpanded\n");
}

#[test]
fn run_rejects_invalid_task_cache_globs_before_starting_script() {
    for field in ["inputs", "outputs"] {
        let project = TempProject::empty(
            r#"{
                "name": "invalid-cache-glob",
                "version": "1.0.0",
                "scripts": {
                    "build": "node build.js"
                }
            }"#,
        );
        project.write_file(
            "build.js",
            "require('fs').writeFileSync('task-started.txt', 'yes');",
        );
        let mut task = serde_json::json!({
            "cache": true,
            "outputs": ["dist/**"]
        });
        task[field] = serde_json::json!(["["]);
        project.write_file(
            "lpm.json",
            &serde_json::json!({ "tasks": { "build": task } }).to_string(),
        );

        let output = lpm(&project)
            .args(["run", "build"])
            .output()
            .expect("run a task with an invalid cache glob");
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "invalid task {field} glob was accepted\nstderr: {stderr}"
        );
        assert!(
            stderr.contains(field) && stderr.contains("invalid glob"),
            "invalid task {field} glob diagnostic was unclear: {stderr}"
        );
        assert!(
            !project.file_exists("task-started.txt"),
            "task started before its {field} glob was validated"
        );
    }
}

#[test]
fn run_cache_invalidates_when_a_default_top_level_script_changes() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-top-level-script",
            "version": "1.0.0",
            "scripts": { "build": "node build.js" }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": { "cache": true, "outputs": ["dist/**"] }
            }
        }"#,
    );
    project.write_file(
        "build.js",
        r"const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt','v1'); fs.appendFileSync('executions.txt','run\n');",
    );

    lpm(&project).args(["run", "build"]).assert().success();
    assert_eq!(project.read_file("dist/value.txt"), "v1");

    project.write_file(
        "build.js",
        r"const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt','v2'); fs.appendFileSync('executions.txt','run\n');",
    );
    std::fs::remove_dir_all(project.path().join("dist")).expect("remove first build output");

    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/value.txt"), "v2");
    assert_eq!(project.read_file("executions.txt"), "run\nrun\n");
}

#[test]
fn run_cache_invalidates_when_lockfile_resolution_changes() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-lockfile-resolution",
            "version": "1.0.0",
            "scripts": { "build": "node build.js" }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/resolution.txt', fs.readFileSync('lpm.lock', 'utf8'));
fs.appendFileSync('executions.txt', 'run\n');"#,
    );

    project.write_file("lpm.lock", "resolution = \"1.0.0\"\n");
    lpm(&project).args(["run", "build"]).assert().success();

    project.write_file("lpm.lock", "resolution = \"2.0.0\"\n");
    std::fs::remove_dir_all(project.path().join("dist")).expect("remove cached output");
    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(
        project.read_file("dist/resolution.txt"),
        "resolution = \"2.0.0\"\n"
    );
    assert_eq!(project.read_file("executions.txt"), "run\nrun\n");
}

#[test]
fn run_cache_invalidates_when_a_development_dependency_changes() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-development-dependency",
            "version": "1.0.0",
            "scripts": { "build": "node build.js" },
            "devDependencies": { "compiler": "1.0.0" }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/compiler.txt', pkg.devDependencies.compiler);
fs.appendFileSync('executions.txt', 'run\n');"#,
    );

    lpm(&project).args(["run", "build"]).assert().success();

    project.write_file(
        "package.json",
        r#"{
            "name": "cache-development-dependency",
            "version": "1.0.0",
            "scripts": { "build": "node build.js" },
            "devDependencies": { "compiler": "2.0.0" }
        }"#,
    );
    std::fs::remove_dir_all(project.path().join("dist")).expect("remove cached output");
    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/compiler.txt"), "2.0.0");
    assert_eq!(project.read_file("executions.txt"), "run\nrun\n");
}

#[test]
fn run_cache_invalidates_when_a_lifecycle_hook_changes() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-lifecycle-command",
            "version": "1.0.0",
            "scripts": {
                "build": "node build.js",
                "postbuild": "node post-v1.js"
            }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "build.js",
        "require('fs').mkdirSync('dist',{recursive:true});",
    );
    project.write_file(
        "post-v1.js",
        "require('fs').writeFileSync('dist/value.txt','v1');",
    );
    project.write_file(
        "post-v2.js",
        "require('fs').writeFileSync('dist/value.txt','v2');",
    );

    lpm(&project).args(["run", "build"]).assert().success();
    project.write_file(
        "package.json",
        r#"{
            "name": "cache-lifecycle-command",
            "version": "1.0.0",
            "scripts": {
                "build": "node build.js",
                "postbuild": "node post-v2.js"
            }
        }"#,
    );
    std::fs::remove_dir_all(project.path().join("dist")).unwrap();

    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/value.txt"), "v2");
}

#[test]
fn run_cache_invalidates_when_an_indirect_package_script_changes() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-indirect-script",
            "version": "1.0.0",
            "scripts": {
                "build": "node build.js",
                "helper": "node helper-v1.js"
            }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["source.txt"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file("source.txt", "stable");
    project.write_file(
        "build.js",
        "const fs=require('fs'); const helper=JSON.parse(fs.readFileSync('package.json')).scripts.helper; fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',helper.includes('v2')?'v2':'v1'); fs.appendFileSync('executions.txt','run\\n');",
    );

    lpm(&project).args(["run", "build"]).assert().success();
    project.write_file(
        "package.json",
        r#"{
            "name": "cache-indirect-script",
            "version": "1.0.0",
            "scripts": {
                "build": "node build.js",
                "helper": "node helper-v2.js"
            }
        }"#,
    );
    std::fs::remove_dir_all(project.path().join("dist")).expect("remove cached output");

    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/value.txt"), "v2");
    assert_eq!(project.read_file("executions.txt"), "run\nrun\n");
}

#[cfg(unix)]
#[test]
fn run_rejects_cache_input_symlinks_that_escape_the_project() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(
        r#"{
            "name": "cache-external-input",
            "version": "1.0.0",
            "scripts": { "build": "node build.js" }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["src/**"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "build.js",
        "const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',fs.readFileSync('src/value.txt'));",
    );
    std::fs::create_dir(project.path().join("src")).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("value.txt"), "outside").unwrap();
    symlink(
        outside.path().join("value.txt"),
        project.path().join("src/value.txt"),
    )
    .unwrap();

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("run task with an external cache input");

    assert!(
        !output.status.success(),
        "external cache input was accepted"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("outside project"),
        "external cache input diagnostic was unclear: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!project.file_exists("dist/value.txt"));
}

#[test]
fn run_cache_invalidates_a_dependent_when_dependency_inputs_change() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-task-dependency",
            "version": "1.0.0",
            "scripts": {
                "generate": "node generate.js",
                "build": "node build.js"
            }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "generate": {
                    "cache": true,
                    "inputs": ["generate.js"],
                    "outputs": ["generated/**"]
                },
                "build": {
                    "dependsOn": ["generate"],
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "generate.js",
        r"const fs=require('fs'); fs.mkdirSync('generated',{recursive:true}); fs.writeFileSync('generated/value.txt','v1'); fs.appendFileSync('generate-executions.txt','run\n');",
    );
    project.write_file(
        "build.js",
        r"const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',fs.readFileSync('generated/value.txt')); fs.appendFileSync('build-executions.txt','run\n');",
    );

    lpm(&project).args(["run", "build"]).assert().success();
    assert_eq!(project.read_file("dist/value.txt"), "v1");

    project.write_file(
        "generate.js",
        r"const fs=require('fs'); fs.mkdirSync('generated',{recursive:true}); fs.writeFileSync('generated/value.txt','v2'); fs.appendFileSync('generate-executions.txt','run\n');",
    );
    std::fs::remove_dir_all(project.path().join("generated")).unwrap();
    std::fs::remove_dir_all(project.path().join("dist")).unwrap();

    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/value.txt"), "v2");
    assert_eq!(project.read_file("generate-executions.txt"), "run\nrun\n");
    assert_eq!(project.read_file("build-executions.txt"), "run\nrun\n");
}

#[test]
fn run_cache_invalidates_a_dependent_when_its_dependency_command_changes() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-dependency-command",
            "version": "1.0.0",
            "scripts": {
                "generate": "node generate-v1.js",
                "build": "node build.js"
            }
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "generate": {
                    "inputs": ["generate-*.js"]
                },
                "build": {
                    "dependsOn": ["generate"],
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "generate-v1.js",
        "require('fs').mkdirSync('generated',{recursive:true}); require('fs').writeFileSync('generated/value.txt','v1');",
    );
    project.write_file(
        "generate-v2.js",
        "require('fs').mkdirSync('generated',{recursive:true}); require('fs').writeFileSync('generated/value.txt','v2');",
    );
    project.write_file(
        "build.js",
        "const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',fs.readFileSync('generated/value.txt')); fs.appendFileSync('build-executions.txt','run\\n');",
    );

    lpm(&project).args(["run", "build"]).assert().success();
    assert_eq!(project.read_file("dist/value.txt"), "v1");

    project.write_file(
        "package.json",
        r#"{
            "name": "cache-dependency-command",
            "version": "1.0.0",
            "scripts": {
                "generate": "node generate-v2.js",
                "build": "node build.js"
            }
        }"#,
    );
    std::fs::remove_dir_all(project.path().join("generated")).unwrap();
    std::fs::remove_dir_all(project.path().join("dist")).unwrap();

    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/value.txt"), "v2");
    assert_eq!(project.read_file("build-executions.txt"), "run\nrun\n");
}

#[test]
fn run_cache_invalidates_when_mapped_environment_changes() {
    let project = TempProject::empty(
        r#"{
        "name": "cache-mapped-env",
        "version": "1.0.0",
        "scripts": {
            "build": "node build.js"
        }
    }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "env": {"build": ".env.development"},
            "tasks": {
                "build": {
                    "cache": true,
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/value.txt', process.env.BUILD_VALUE || '<unset>');
console.log(process.env.BUILD_VALUE || '<unset>');"#,
    );
    project.write_file(".env.development", "BUILD_VALUE=first\n");

    lpm(&project).args(["run", "build"]).assert().success();
    project.write_file(".env.development", "BUILD_VALUE=second\n");

    let output = lpm(&project)
        .args(["run", "build"])
        .output()
        .expect("run cached task after mapped env changed");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(output.status.success(), "second build failed:\n{combined}");
    assert_eq!(project.read_file("dist/value.txt"), "second");
    assert!(
        !combined.contains("restored from cache"),
        "changed mapped env restored stale output:\n{combined}"
    );
}

#[test]
fn run_cache_invalidates_when_cli_arguments_change() {
    let project = TempProject::empty(
        r#"{
        "name": "cache-cli-arguments",
        "version": "1.0.0",
        "scripts": {
            "build": "node build.js"
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
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/value.txt', process.argv.slice(2).join('|'));
console.log(process.argv.slice(2).join('|'));"#,
    );

    lpm(&project)
        .args(["run", "build", "--", "--target", "node"])
        .assert()
        .success();
    let output = lpm(&project)
        .args(["run", "build", "--", "--target", "browser"])
        .output()
        .expect("run cached task with different arguments");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(output.status.success(), "second build failed:\n{combined}");
    assert_eq!(
        project.read_file("dist/value.txt"),
        "--target|browser",
        "second run output:\n{combined}"
    );
    assert!(
        !combined.contains("restored from cache"),
        "different arguments restored stale output:\n{combined}"
    );
}

#[test]
fn run_cached_output_is_sanitized_during_capture_and_replay() {
    let project = TempProject::empty(
        r#"{
        "name": "terminal-cache-output",
        "version": "1.0.0",
        "scripts": {
            "build": "node -e \"process.stdout.write('safe\\x1b]52;c;AAAA\\x07end\\u0090hidden\\u009c\\b\\rrewritten\\n')\""
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

    for run_number in 1..=2 {
        let output = lpm(&project)
            .args(["run", "build"])
            .output()
            .unwrap_or_else(|error| panic!("failed to run cached build {run_number}: {error}"));
        assert!(
            output.status.success(),
            "cached build {run_number} must pass"
        );
        let rendered = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            rendered.contains("safeend??rewritten"),
            "captured output must remain visible after sanitization on run {run_number}; got:\n{rendered}"
        );
        for attacker_fragment in ["\u{1b}", "\u{7}", "\u{8}", "\r", "\u{0090}", "\u{009c}"] {
            assert!(
                !rendered.contains(attacker_fragment),
                "cached output retained attacker fragment {attacker_fragment:?} on run {run_number}:\n{rendered}"
            );
        }
    }
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

#[cfg(unix)]
#[test]
fn run_workspace_no_cache_does_not_read_cache_contract_files() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({ "build": "node -e \"console.log('ran')\"" });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file("real.lock", "resolution = 1\n");
    std::os::unix::fs::symlink("real.lock", project.path().join("lpm.lock")).unwrap();

    let output = lpm(&project)
        .args(["run", "build", "--filter", "@test/app", "--no-cache"])
        .output()
        .expect("run workspace task without cache");

    assert!(
        output.status.success(),
        "--no-cache inspected cache contract files:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
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
async fn run_local_cache_hit_does_not_refresh_an_expired_remote_session() {
    let registry = MockRegistry::start().await;
    let state = RemoteCacheState::default();
    mount_stateful_remote_cache(registry.server(), state).await;
    let project = remote_cache_project(registry.server(), "");
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token: Some("local-hit-access"),
            refresh_token: Some("local-hit-refresh"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );

    let first = lpm(&project)
        .env("LPM_REGISTRY_URL", registry.url())
        .args(["run", "build"])
        .output()
        .expect("populate the local task cache");
    assert!(
        first.status.success(),
        "initial run should succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    registry.server().reset().await;
    registry
        .with_refresh_expected(
            "local-hit-refresh",
            "unused-rotated-access",
            "unused-rotated-refresh",
            "2099-01-01T00:00:00Z",
            0,
        )
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(registry.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(registry.server())
        .await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token: Some("local-hit-access"),
            refresh_token: Some("local-hit-refresh"),
            session_access_expires_at: Some("2000-01-01T00:00:00Z"),
        }],
    );
    remove_project_file(&project, "executed-marker");

    let second = lpm(&project)
        .env("LPM_REGISTRY_URL", registry.url())
        .args(["run", "build"])
        .output()
        .expect("restore the task from the local cache");
    assert!(
        second.status.success(),
        "local cache hit should succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    assert!(
        !project.file_exists("executed-marker"),
        "a local cache hit must not re-run the script",
    );
    registry.server().verify().await;
}

#[tokio::test]
async fn run_remote_cache_restore_refreshes_an_expired_same_origin_session() {
    let registry = MockRegistry::start().await;
    let state = RemoteCacheState::default();
    mount_stateful_remote_cache(registry.server(), state.clone()).await;
    let project = remote_cache_project(registry.server(), "");
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token: Some("restore-initial-access"),
            refresh_token: Some("restore-refresh"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );

    let first = lpm(&project)
        .env("LPM_REGISTRY_URL", registry.url())
        .args(["run", "build"])
        .output()
        .expect("populate the remote task cache");
    assert!(first.status.success());

    registry.server().reset().await;
    registry
        .with_refresh_expected(
            "restore-refresh",
            "restore-rotated-access",
            "restore-rotated-refresh",
            "2099-01-01T00:00:00Z",
            1,
        )
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .and(header("authorization", "Bearer restore-initial-access"))
        .respond_with(ResponseTemplate::new(401))
        .expect(0)
        .mount(registry.server())
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .and(header("authorization", "Bearer restore-rotated-access"))
        .respond_with(RemoteCacheGetResponder { state })
        .expect(1)
        .mount(registry.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(registry.server())
        .await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token: Some("restore-initial-access"),
            refresh_token: Some("restore-refresh"),
            session_access_expires_at: Some("2000-01-01T00:00:00Z"),
        }],
    );
    remove_local_task_cache(&project);
    remove_project_file(&project, "dist");
    remove_project_file(&project, "executed-marker");

    let second = lpm(&project)
        .env("LPM_REGISTRY_URL", registry.url())
        .args(["run", "build"])
        .output()
        .expect("restore from the remote task cache");
    assert!(
        second.status.success(),
        "remote restore should succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    assert_eq!(project.read_file("dist/value.txt"), "remote-hit");
    assert!(!project.file_exists("executed-marker"));
    registry.server().verify().await;
}

#[tokio::test]
async fn run_remote_cache_upload_rebuilds_the_body_after_reactive_session_refresh() {
    let registry = MockRegistry::start().await;
    let state = RemoteCacheState::default();
    registry
        .with_refresh_expected(
            "upload-refresh",
            "upload-rotated-access",
            "upload-rotated-refresh",
            "2099-01-01T00:00:00Z",
            1,
        )
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .and(header("authorization", "Bearer upload-stale-access"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(registry.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .and(header("authorization", "Bearer upload-stale-access"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(registry.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
        .and(header("authorization", "Bearer upload-rotated-access"))
        .respond_with(RemoteCachePutResponder {
            state: state.clone(),
        })
        .expect(1)
        .mount(registry.server())
        .await;

    let project = remote_cache_project(registry.server(), "");
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token: Some("upload-stale-access"),
            refresh_token: Some("upload-refresh"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", registry.url())
        .args(["run", "build"])
        .output()
        .expect("upload a task artifact with a refreshed session");
    assert!(
        output.status.success(),
        "remote upload should succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        state
            .artifact
            .lock()
            .expect("remote cache artifact mutex poisoned")
            .as_ref()
            .is_some_and(|artifact| !artifact.is_empty()),
        "the retried upload must resend the complete artifact body",
    );
    registry.server().verify().await;
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
fn run_single_task_json_output() {
    let project = TempProject::from_fixture("with-scripts");

    let output = lpm(&project)
        .args(["run", "build", "--json"])
        .output()
        .expect("failed to run lpm run build --json");

    assert!(
        output.status.success(),
        "run build --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = support::assertions::parse_json_output(&output.stdout);

    assert_eq!(json["success"], true);
    assert_eq!(json["total"], 1);
    assert_eq!(json["passed"], 1);
    assert_eq!(json["failed"], 0);
    let tasks = json["tasks"].as_array().expect("tasks should be an array");
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0]["name"], "build");
    assert_eq!(tasks[0]["success"], true);
}

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

#[test]
fn run_watch_rejects_invalid_task_globs_without_starting_the_watcher() {
    let project = TempProject::empty(
        r#"{
            "name": "watch-invalid-glob",
            "version": "1.0.0",
            "scripts": { "build": "node build.js" }
        }"#,
    );
    project.write_file("lpm.json", r#"{"tasks":{"build":{"inputs":["["]}}}"#);
    project.write_file(
        "build.js",
        "require('fs').writeFileSync('task-started.txt','yes');",
    );
    let mut command = lpm_spawnable(&project);
    command.args(["run", "build", "--watch"]);
    let mut child = command.spawn().expect("spawn invalid watch configuration");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

    let status = loop {
        if let Some(status) = child.try_wait().expect("poll invalid watch configuration") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("watch mode did not reject the invalid task glob promptly");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };

    assert!(!status.success(), "invalid watch configuration succeeded");
    assert!(
        !project.file_exists("task-started.txt"),
        "watch mode started the task before validating its input glob"
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

#[test]
fn run_parallel_stream_sanitizes_child_output_before_prefixing() {
    let manifest = serde_json::json!({
        "name": "terminal-prefixed-output",
        "version": "1.0.0",
        "scripts": {
            "hostile": r#"node -e "process.stdout.write('safe\x1b]52;c;AAAA\x07end\u0090hidden\u009c\b\rrewritten\n')""#,
            "clean": "node -e \"process.stdout.write('clean\\n')\""
        }
    });
    let project = TempProject::empty(&manifest.to_string());

    let output = lpm(&project)
        .args(["run", "hostile", "clean", "--parallel", "--stream"])
        .output()
        .expect("failed to run streamed parallel tasks");
    assert!(
        output.status.success(),
        "parallel streamed tasks must pass; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        rendered.contains("safeend??rewritten"),
        "prefixed child output must remain visible after sanitization; got:\n{rendered}"
    );
    for attacker_fragment in [
        "\u{1b}]52;c;AAAA",
        "\u{7}",
        "\u{8}",
        "\r",
        "\u{0090}",
        "\u{009c}",
        "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "prefixed child output retained attacker fragment {attacker_fragment:?}:\n{rendered}"
        );
    }
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

fn seed_workspace_with_upstream_build_tasks(project: &TempProject) {
    for member in ["app", "core", "utils"] {
        let pkg_path = format!("packages/{member}/package.json");
        let pkg_content = project.read_file(&pkg_path);
        let mut pkg: serde_json::Value =
            serde_json::from_str(&pkg_content).expect("parse member package.json");
        pkg["scripts"] = serde_json::json!({
            "build": format!("node -e \"require('fs').writeFileSync('ran-{member}.txt','ok')\""),
        });
        project.write_file(&pkg_path, &serde_json::to_string_pretty(&pkg).unwrap());
        project.write_file(
            &format!("packages/{member}/lpm.json"),
            r#"{"tasks":{"build":{"dependsOn":["^build"]}}}"#,
        );
    }
}

#[test]
fn run_filter_executes_upstream_task_dependencies_before_the_selected_member() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_upstream_build_tasks(&project);

    let output = lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run a filtered task with upstream task dependencies");

    assert!(
        output.status.success(),
        "filtered upstream task graph must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    for member in ["utils", "core", "app"] {
        assert!(
            member_ran(&project, member),
            "{member} build must execute for app's ^build dependency"
        );
    }
}

#[test]
fn run_filter_expands_one_caret_task_through_the_full_workspace_dependency_chain() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["app", "core", "utils"] {
        let package_path = format!("packages/{member}/package.json");
        let mut package: serde_json::Value =
            serde_json::from_str(&project.read_file(&package_path))
                .expect("parse workspace package.json");
        package["scripts"] = serde_json::json!({
            "build": format!("node -e \"require('fs').writeFileSync('ran-{member}.txt','ok')\"")
        });
        project.write_file(
            &package_path,
            &serde_json::to_string_pretty(&package).unwrap(),
        );
    }
    project.write_file(
        "packages/app/lpm.json",
        r#"{"tasks":{"build":{"dependsOn":["^build"]}}}"#,
    );

    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();

    for member in ["utils", "core", "app"] {
        assert!(
            member_ran(&project, member),
            "{member} build must execute for the selected app's ^build dependency"
        );
    }
}

#[test]
fn run_filter_json_counts_selected_and_upstream_task_members() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_upstream_build_tasks(&project);

    let output = lpm(&project)
        .args(["run", "build", "--filter", "@test/app", "--json"])
        .output()
        .expect("run a filtered upstream task graph as JSON");

    assert!(
        output.status.success(),
        "filtered JSON task graph must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = support::assertions::parse_json_output(&output.stdout);
    assert_eq!(json["packages"], 3);
    assert_eq!(json["succeeded"], 3);
    let mut normalized = json;
    normalized["duration_ms"] = serde_json::json!(0);
    insta::assert_json_snapshot!(normalized, @r###"
    {
      "success": true,
      "packages": 3,
      "succeeded": 3,
      "duration_ms": 0
    }
    "###);
}

#[test]
fn run_filter_accepts_an_upstream_meta_task_that_only_has_upstream_dependencies() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["app", "utils"] {
        let pkg_path = format!("packages/{member}/package.json");
        let mut pkg: serde_json::Value =
            serde_json::from_str(&project.read_file(&pkg_path)).expect("parse member package.json");
        pkg["scripts"] = serde_json::json!({
            "build": format!("node -e \"require('fs').writeFileSync('ran-{member}.txt','ok')\""),
        });
        project.write_file(&pkg_path, &serde_json::to_string_pretty(&pkg).unwrap());
    }
    project.write_file(
        "packages/app/lpm.json",
        r#"{"tasks":{"build":{"dependsOn":["^build"]}}}"#,
    );
    project.write_file(
        "packages/core/lpm.json",
        r#"{"tasks":{"build":{"dependsOn":["^build"]}}}"#,
    );

    let output = lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run an upstream caret-only meta-task");

    assert!(
        output.status.success(),
        "caret-only meta-task must succeed after its upstream task\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(member_ran(&project, "utils"), "upstream build did not run");
    assert!(member_ran(&project, "app"), "selected build did not run");
}

#[test]
fn run_filter_rejects_a_missing_upstream_workspace_task_before_execution() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let app_package_path = "packages/app/package.json";
    let mut app_package: serde_json::Value =
        serde_json::from_str(&project.read_file(app_package_path)).expect("parse app package.json");
    app_package["scripts"] = serde_json::json!({
        "build": "node -e \"require('fs').writeFileSync('app-ran.txt','yes')\"",
    });
    project.write_file(
        app_package_path,
        &serde_json::to_string_pretty(&app_package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{"tasks":{"build":{"dependsOn":["^build"]}}}"#,
    );

    let output = lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run a missing upstream workspace task");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "missing upstream task was accepted\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("does not define task 'build'"),
        "missing upstream task diagnostic was unclear: {stderr}"
    );
    assert!(
        !project.file_exists("packages/app/app-ran.txt"),
        "selected task ran before its upstream graph was validated"
    );
}

#[test]
fn run_filter_rejects_a_workspace_task_cycle_before_execution() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_upstream_build_tasks(&project);
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": { "dependsOn": ["^build", "cycle"] },
                "cycle": { "dependsOn": ["build"] }
            }
        }"#,
    );

    let output = lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run a cyclic workspace task graph");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "cyclic workspace task graph was accepted"
    );
    assert!(
        stderr.contains("circular dependency"),
        "cycle diagnostic was unclear: {stderr}"
    );
    for member in ["utils", "core", "app"] {
        assert!(
            !member_ran(&project, member),
            "{member} ran before the workspace task graph was validated"
        );
    }
}

#[test]
fn run_filter_rejects_malformed_upstream_task_dependencies_before_execution() {
    for malformed_dependency in ["^", "^^build"] {
        let project = TempProject::from_fixture("workspace-monorepo");
        let app_package_path = "packages/app/package.json";
        let mut app_package: serde_json::Value =
            serde_json::from_str(&project.read_file(app_package_path))
                .expect("parse app package.json");
        app_package["scripts"] = serde_json::json!({
            "build": "node -e \"require('fs').writeFileSync('app-ran.txt','yes')\"",
        });
        project.write_file(
            app_package_path,
            &serde_json::to_string_pretty(&app_package).unwrap(),
        );
        project.write_file(
            "packages/app/lpm.json",
            &serde_json::json!({
                "tasks": {
                    "build": { "dependsOn": [malformed_dependency] }
                }
            })
            .to_string(),
        );

        let output = lpm(&project)
            .args(["run", "build", "--filter", "@test/app"])
            .output()
            .expect("run a malformed upstream task dependency");
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "malformed upstream dependency '{malformed_dependency}' was accepted"
        );
        assert!(
            stderr.contains("invalid upstream dependency"),
            "malformed upstream diagnostic was unclear: {stderr}"
        );
        assert!(
            !project.file_exists("packages/app/app-ran.txt"),
            "task ran before malformed upstream dependency was rejected"
        );
    }
}

#[test]
fn run_workspace_cache_invalidates_when_the_root_lockfile_changes() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({ "build": "node build.js" });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["source.txt"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file("packages/app/source.txt", "stable");
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); const lock=fs.readFileSync('../../lpm.lock','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',lock); fs.appendFileSync('executions.txt','run\\n');",
    );
    project.write_file("lpm.lock", "root-resolution-v1\n");

    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();

    std::fs::remove_dir_all(project.path().join("packages/app/dist"))
        .expect("remove cached workspace output");
    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\n",
        "unchanged root contract did not restore the workspace task"
    );

    project.write_file("lpm.lock", "root-resolution-v2\n");
    std::fs::remove_dir_all(project.path().join("packages/app/dist"))
        .expect("remove cached workspace output");
    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();

    assert_eq!(
        project.read_file("packages/app/dist/value.txt"),
        "root-resolution-v2\n"
    );
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn run_workspace_revalidates_the_root_contract_before_a_later_cache_hit() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({
        "wait": "node wait.js",
        "build": "node build.js"
    });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "packages/app/wait.js",
        "const fs=require('fs'); fs.writeFileSync('wait.marker','ready'); const deadline=Date.now()+10000; while(!fs.existsSync('release.marker')&&Date.now()<deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); if(!fs.existsSync('release.marker')) process.exit(2);",
    );
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); const lock=fs.readFileSync('../../lpm.lock','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',lock); fs.appendFileSync('executions.txt','run\\n');",
    );
    project.write_file("lpm.lock", "root-resolution-v1\n");

    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();
    std::fs::remove_dir_all(project.path().join("packages/app/dist")).unwrap();

    let binary = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut command = lpm_spawnable_from_path(&project, &binary);
    command.args(["run", "wait", "build", "--filter", "@test/app"]);
    let mut child = command.spawn().expect("start a blocked workspace run");
    wait_for_task_marker(
        &mut child,
        &project.path().join("packages/app/wait.marker"),
        "the independent predecessor",
    );
    project.write_file("lpm.lock", "root-resolution-v2\n");
    project.write_file("packages/app/release.marker", "release");
    let output = child.wait_with_output().expect("finish workspace run");

    assert!(
        output.status.success(),
        "workspace run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("packages/app/dist/value.txt"),
        "root-resolution-v2\n"
    );
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn run_workspace_does_not_publish_with_a_stale_member_output_contract() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({
        "wait": "node wait.js",
        "build": "node build.js"
    });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["old/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "packages/app/wait.js",
        "const fs=require('fs'); fs.writeFileSync('wait.marker','ready'); const deadline=Date.now()+10000; while(!fs.existsSync('release.marker')&&Date.now()<deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); if(!fs.existsSync('release.marker')) process.exit(2);",
    );
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); fs.mkdirSync('old',{recursive:true}); fs.mkdirSync('new',{recursive:true}); fs.writeFileSync('old/value.txt','old'); fs.writeFileSync('new/value.txt','new'); fs.appendFileSync('executions.txt','run\\n');",
    );

    let binary = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut command = lpm_spawnable_from_path(&project, &binary);
    command.args(["run", "wait", "build", "--filter", "@test/app"]);
    let mut child = command.spawn().expect("start a blocked workspace run");
    wait_for_task_marker(
        &mut child,
        &project.path().join("packages/app/wait.marker"),
        "the stale member configuration",
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["old/**", "new/**"]
                }
            }
        }"#,
    );
    project.write_file("packages/app/release.marker", "release");
    let first = child.wait_with_output().expect("finish workspace run");
    assert!(
        first.status.success(),
        "first workspace run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    std::fs::remove_dir_all(project.path().join("packages/app/old")).unwrap();
    std::fs::remove_dir_all(project.path().join("packages/app/new")).unwrap();

    let second = lpm_spawnable_from_path(&project, &binary)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run with the updated output contract");
    assert!(
        second.status.success(),
        "second workspace run failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    assert_eq!(project.read_file("packages/app/old/value.txt"), "old");
    assert_eq!(project.read_file("packages/app/new/value.txt"), "new");
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn run_workspace_does_not_publish_output_under_a_changed_root_contract() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({ "build": "node build.js" });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); fs.writeFileSync('read.marker','ready'); const deadline=Date.now()+10000; while(!fs.existsSync('release.marker')&&Date.now()<deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); if(!fs.existsSync('release.marker')) process.exit(2); const lock=fs.readFileSync('../../lpm.lock','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',lock); fs.appendFileSync('executions.txt','run\\n');",
    );
    project.write_file("lpm.lock", "root-resolution-v1\n");

    let binary = std::env::var_os("LPM_CACHE_RACE_TEST_BINARY").map_or_else(
        || assert_cmd::cargo::cargo_bin("lpm-rs"),
        std::path::PathBuf::from,
    );
    let mut command = lpm_spawnable_from_path(&project, &binary);
    command.args(["run", "build", "--filter", "@test/app"]);
    let mut child = command.spawn().expect("start the blocked workspace task");
    let marker = project.path().join("packages/app/read.marker");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            child
                .try_wait()
                .expect("inspect blocked workspace task")
                .is_none(),
            "workspace task exited before it read the root contract"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "workspace task did not read the root contract"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    project.write_file("lpm.lock", "root-resolution-v2\n");
    project.write_file("packages/app/release.marker", "release");
    let first = child
        .wait_with_output()
        .expect("finish the blocked workspace task");
    assert!(
        first.status.success(),
        "first workspace run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    std::fs::remove_dir_all(project.path().join("packages/app/dist"))
        .expect("remove the first output");
    project.write_file("lpm.lock", "root-resolution-v1\n");

    let second = lpm_spawnable_from_path(&project, &binary)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run the task with the changed root contract");
    assert!(
        second.status.success(),
        "second workspace run failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        project.read_file("packages/app/dist/value.txt"),
        "root-resolution-v1\n"
    );
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn run_workspace_does_not_publish_output_when_member_inputs_change_during_execution() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({ "build": "node build.js" });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["source.txt", "build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file("packages/app/source.txt", "source-v1");
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); const source=fs.readFileSync('source.txt','utf8'); fs.writeFileSync('read.marker',source); const deadline=Date.now()+10000; while(!fs.existsSync('release.marker')&&Date.now()<deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); if(!fs.existsSync('release.marker')) process.exit(2); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',source); fs.appendFileSync('executions.txt','run\\n');",
    );

    let binary = std::env::var_os("LPM_CACHE_RACE_TEST_BINARY").map_or_else(
        || assert_cmd::cargo::cargo_bin("lpm-rs"),
        std::path::PathBuf::from,
    );
    let mut command = lpm_spawnable_from_path(&project, &binary);
    command.args(["run", "build", "--filter", "@test/app"]);
    let mut child = command.spawn().expect("start the blocked workspace task");
    let marker = project.path().join("packages/app/read.marker");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            child
                .try_wait()
                .expect("inspect blocked workspace task")
                .is_none(),
            "workspace task exited before it read the member input"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "workspace task did not read the member input"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    project.write_file("packages/app/source.txt", "source-v2");
    project.write_file("packages/app/release.marker", "release");
    let first = child
        .wait_with_output()
        .expect("finish the blocked workspace task");
    assert!(
        first.status.success(),
        "first workspace run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    std::fs::remove_dir_all(project.path().join("packages/app/dist"))
        .expect("remove the first output");

    let second = lpm_spawnable_from_path(&project, &binary)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run the task with the changed member input");
    assert!(
        second.status.success(),
        "second workspace run failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    assert_eq!(
        project.read_file("packages/app/dist/value.txt"),
        "source-v2"
    );
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn run_workspace_does_not_publish_output_when_a_local_dependency_output_changes() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({
        "generate": "node generate.js",
        "build": "node build.js"
    });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "generate": {
                    "cache": true,
                    "inputs": ["source.txt", "generate.js"],
                    "outputs": ["generated/**"]
                },
                "build": {
                    "dependsOn": ["generate"],
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file("packages/app/source.txt", "source-v1");
    project.write_file(
        "packages/app/generate.js",
        "const fs=require('fs'); const value=fs.readFileSync('source.txt','utf8'); fs.mkdirSync('generated',{recursive:true}); fs.writeFileSync('generated/value.txt',value);",
    );
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); fs.writeFileSync('read.marker','ready'); const deadline=Date.now()+10000; while(!fs.existsSync('release.marker')&&Date.now()<deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); if(!fs.existsSync('release.marker')) process.exit(2); const value=fs.readFileSync('generated/value.txt','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );

    let binary = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut command = lpm_spawnable_from_path(&project, &binary);
    command.args(["run", "build", "--filter", "@test/app"]);
    let mut child = command.spawn().expect("start the blocked dependent task");
    let marker = project.path().join("packages/app/read.marker");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            child
                .try_wait()
                .expect("inspect blocked dependent task")
                .is_none(),
            "dependent task exited before it signalled readiness"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "dependent task did not signal readiness"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    project.write_file("packages/app/generated/value.txt", "source-v2");
    project.write_file("packages/app/release.marker", "release");
    let first = child.wait_with_output().expect("finish the dependent task");
    assert!(
        first.status.success(),
        "first dependent run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    std::fs::remove_dir_all(project.path().join("packages/app/dist"))
        .expect("remove the first dependent output");

    let second = lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run the dependent task after restoring its dependency");
    assert!(
        second.status.success(),
        "second dependent run failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        project.read_file("packages/app/dist/value.txt"),
        "source-v1"
    );
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn run_workspace_rechecks_transitive_local_dependency_outputs_before_publication() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({
        "generate": "node generate.js",
        "build": "node build.js"
    });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "generate": {
                    "cache": true,
                    "inputs": ["source.txt", "generate.js"],
                    "outputs": ["generated/**"]
                },
                "meta": {"dependsOn": ["generate"]},
                "build": {
                    "dependsOn": ["meta"],
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file("packages/app/source.txt", "source-v1");
    project.write_file(
        "packages/app/generate.js",
        "const fs=require('fs'); const value=fs.readFileSync('source.txt','utf8'); fs.mkdirSync('generated',{recursive:true}); fs.writeFileSync('generated/value.txt',value);",
    );
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); fs.writeFileSync('read.marker','ready'); const deadline=Date.now()+10000; while(!fs.existsSync('release.marker')&&Date.now()<deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); if(!fs.existsSync('release.marker')) process.exit(2); const value=fs.readFileSync('generated/value.txt','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );

    let binary = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut command = lpm_spawnable_from_path(&project, &binary);
    command.args(["run", "build", "--filter", "@test/app"]);
    let mut child = command.spawn().expect("start the blocked dependent task");
    wait_for_task_marker(
        &mut child,
        &project.path().join("packages/app/read.marker"),
        "the transitive dependent task",
    );
    project.write_file("packages/app/generated/value.txt", "source-v2");
    project.write_file("packages/app/release.marker", "release");
    let first = child.wait_with_output().expect("finish the dependent task");
    assert!(
        first.status.success(),
        "first dependent run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    std::fs::remove_dir_all(project.path().join("packages/app/dist")).unwrap();

    let second = lpm_spawnable_from_path(&project, &binary)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("rerun the transitive dependent task");
    assert!(
        second.status.success(),
        "second dependent run failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    assert_eq!(
        project.read_file("packages/app/generated/value.txt"),
        "source-v1"
    );
    assert_eq!(
        project.read_file("packages/app/dist/value.txt"),
        "source-v1"
    );
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn run_workspace_rechecks_upstream_outputs_before_downstream_publication() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["utils", "core"] {
        let package_path = format!("packages/{member}/package.json");
        let mut package: serde_json::Value =
            serde_json::from_str(&project.read_file(&package_path))
                .expect("parse workspace package.json");
        package["scripts"] = serde_json::json!({"build": "node build.js"});
        project.write_file(
            &package_path,
            &serde_json::to_string_pretty(&package).unwrap(),
        );
        project.write_file(
            &format!("packages/{member}/lpm.json"),
            &serde_json::json!({
                "tasks": {
                    "build": {
                        "dependsOn": if member == "core" { serde_json::json!(["^build"]) } else { serde_json::json!([]) },
                        "cache": true,
                        "inputs": ["build.js", "source.txt"],
                        "outputs": ["dist/**"]
                    }
                }
            })
            .to_string(),
        );
        project.write_file(&format!("packages/{member}/source.txt"), "stable");
    }
    project.write_file(
        "packages/utils/build.js",
        "const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt','upstream-v1');",
    );
    project.write_file(
        "packages/core/build.js",
        "const fs=require('fs'); fs.writeFileSync('read.marker','ready'); const deadline=Date.now()+10000; while(!fs.existsSync('release.marker')&&Date.now()<deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); if(!fs.existsSync('release.marker')) process.exit(2); const value=fs.readFileSync('../utils/dist/value.txt','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );

    let binary = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut command = lpm_spawnable_from_path(&project, &binary);
    command.args(["run", "build", "--filter", "@test/core"]);
    let mut child = command.spawn().expect("start the blocked workspace task");
    wait_for_task_marker(
        &mut child,
        &project.path().join("packages/core/read.marker"),
        "the downstream workspace task",
    );
    project.write_file("packages/utils/dist/value.txt", "upstream-v2");
    project.write_file("packages/core/release.marker", "release");
    let first = child.wait_with_output().expect("finish workspace task");
    assert!(
        first.status.success(),
        "first workspace run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    std::fs::remove_dir_all(project.path().join("packages/core/dist")).unwrap();

    let second = lpm_spawnable_from_path(&project, &binary)
        .args(["run", "build", "--filter", "@test/core"])
        .output()
        .expect("rerun the downstream workspace task");
    assert!(
        second.status.success(),
        "second workspace run failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    assert_eq!(
        project.read_file("packages/utils/dist/value.txt"),
        "upstream-v1"
    );
    assert_eq!(
        project.read_file("packages/core/dist/value.txt"),
        "upstream-v1"
    );
    assert_eq!(
        project.read_file("packages/core/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn task_cache_rejects_an_input_aba_change_during_execution() {
    let project = TempProject::empty(
        r#"{
            "name": "cache-input-aba",
            "version": "1.0.0",
            "scripts": {"build": "node build.js"}
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["source.txt", "build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file("source.txt", "source-a");
    project.write_file("coordinate.marker", "coordinate");
    project.write_file(
        "build.js",
        "const fs=require('fs'); let value; if(fs.existsSync('coordinate.marker')) { fs.writeFileSync('ready.marker','ready'); const changeDeadline=Date.now()+10000; while(fs.readFileSync('source.txt','utf8')!=='source-b'&&Date.now()<changeDeadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); value=fs.readFileSync('source.txt','utf8'); fs.writeFileSync('read.marker','read'); const releaseDeadline=Date.now()+10000; while(!fs.existsSync('release.marker')&&Date.now()<releaseDeadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); if(!fs.existsSync('release.marker')) process.exit(2); } else { value=fs.readFileSync('source.txt','utf8'); } fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );

    let binary = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut command = lpm_spawnable_from_path(&project, &binary);
    command.args(["run", "build"]);
    let mut child = command.spawn().expect("start the ABA task");
    wait_for_task_marker(
        &mut child,
        &project.path().join("ready.marker"),
        "the pre-execution input snapshot",
    );
    project.write_file("source.txt", "source-b");
    wait_for_task_marker(
        &mut child,
        &project.path().join("read.marker"),
        "the transient input read",
    );
    project.write_file("source.txt", "source-a");
    project.write_file("release.marker", "release");
    let first = child.wait_with_output().expect("finish the ABA task");
    assert!(
        first.status.success(),
        "first ABA run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    std::fs::remove_dir_all(project.path().join("dist")).unwrap();
    std::fs::remove_file(project.path().join("coordinate.marker")).unwrap();

    let second = lpm_spawnable_from_path(&project, &binary)
        .args(["run", "build"])
        .output()
        .expect("rerun the ABA task");
    assert!(
        second.status.success(),
        "second ABA run failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    assert_eq!(project.read_file("dist/value.txt"), "source-a");
    assert_eq!(project.read_file("executions.txt"), "run\nrun\n");
}

#[test]
fn run_workspace_single_task_uses_configured_cache() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({ "build": "node build.js" });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["source.txt", "build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file("packages/app/source.txt", "stable");
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt','built'); fs.appendFileSync('executions.txt','run\\n');",
    );

    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();
    std::fs::remove_dir_all(project.path().join("packages/app/dist"))
        .expect("remove cached workspace output");
    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();

    assert_eq!(project.read_file("packages/app/dist/value.txt"), "built");
    assert_eq!(project.read_file("packages/app/executions.txt"), "run\n");
}

#[test]
fn run_workspace_cache_invalidates_downstream_tasks_after_upstream_output_changes() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["utils", "core", "app"] {
        let package_path = format!("packages/{member}/package.json");
        let mut package: serde_json::Value =
            serde_json::from_str(&project.read_file(&package_path))
                .expect("parse workspace package.json");
        package["scripts"] = serde_json::json!({ "build": "node build.js" });
        project.write_file(
            &package_path,
            &serde_json::to_string_pretty(&package).unwrap(),
        );

        let depends_on = if member == "utils" {
            serde_json::json!([])
        } else {
            serde_json::json!(["^build"])
        };
        project.write_file(
            &format!("packages/{member}/lpm.json"),
            &serde_json::json!({
                "tasks": {
                    "build": {
                        "dependsOn": depends_on,
                        "cache": true,
                        "inputs": ["build.js", "source.txt"],
                        "outputs": ["dist/**"]
                    }
                }
            })
            .to_string(),
        );
        project.write_file(&format!("packages/{member}/source.txt"), "stable");
    }
    project.write_file(
        "packages/utils/build.js",
        "const fs=require('fs'); const value=fs.readFileSync('source.txt','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );
    project.write_file(
        "packages/core/build.js",
        "const fs=require('fs'); const value=fs.readFileSync('../utils/dist/value.txt','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); const value=fs.readFileSync('../core/dist/value.txt','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );
    project.write_file("packages/utils/source.txt", "upstream-v1");

    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();

    for member in ["utils", "core", "app"] {
        std::fs::remove_dir_all(project.path().join(format!("packages/{member}/dist")))
            .expect("remove cached workspace output");
    }
    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();
    for member in ["utils", "core", "app"] {
        assert_eq!(
            project.read_file(&format!("packages/{member}/executions.txt")),
            "run\n",
            "unchanged {member} task did not restore from cache"
        );
    }

    project.write_file("packages/utils/source.txt", "upstream-v2");
    for member in ["utils", "core", "app"] {
        std::fs::remove_dir_all(project.path().join(format!("packages/{member}/dist")))
            .expect("remove cached workspace output");
    }
    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();

    assert_eq!(
        project.read_file("packages/app/dist/value.txt"),
        "upstream-v2"
    );
    for member in ["utils", "core", "app"] {
        assert_eq!(
            project.read_file(&format!("packages/{member}/executions.txt")),
            "run\nrun\n",
            "{member} cache key did not include the upstream task result"
        );
    }
}

#[test]
fn run_workspace_does_not_cache_dependents_of_non_cacheable_upstream_tasks() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["utils", "core"] {
        let package_path = format!("packages/{member}/package.json");
        let mut package: serde_json::Value =
            serde_json::from_str(&project.read_file(&package_path))
                .expect("parse workspace package.json");
        package["scripts"] = serde_json::json!({ "build": "node build.js" });
        project.write_file(
            &package_path,
            &serde_json::to_string_pretty(&package).unwrap(),
        );
    }
    project.write_file(
        "packages/utils/lpm.json",
        r#"{"tasks":{"build":{"cache":false,"outputs":["dist/**"]}}}"#,
    );
    project.write_file(
        "packages/core/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "dependsOn": ["^build"],
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "packages/utils/build.js",
        "const fs=require('fs'); const count=fs.existsSync('run-count.txt')?Number(fs.readFileSync('run-count.txt','utf8'))+1:1; fs.writeFileSync('run-count.txt',String(count)); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',String(count));",
    );
    project.write_file(
        "packages/core/build.js",
        "const fs=require('fs'); const value=fs.readFileSync('../utils/dist/value.txt','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );

    lpm(&project)
        .args(["run", "build", "--filter", "@test/core"])
        .assert()
        .success();
    std::fs::remove_dir_all(project.path().join("packages/core/dist"))
        .expect("remove downstream output");
    lpm(&project)
        .args(["run", "build", "--filter", "@test/core"])
        .assert()
        .success();

    assert_eq!(project.read_file("packages/utils/dist/value.txt"), "2");
    assert_eq!(project.read_file("packages/core/dist/value.txt"), "2");
    assert_eq!(
        project.read_file("packages/core/executions.txt"),
        "run\nrun\n"
    );
}

#[test]
fn run_workspace_does_not_restore_when_package_script_dependency_has_no_cache_contract() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({
        "generate": "node generate.js",
        "build": "node build.js"
    });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "dependsOn": ["generate"],
                    "cache": true,
                    "inputs": ["build.js"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file("packages/app/schema.txt", "schema-v1");
    project.write_file(
        "packages/app/generate.js",
        "const fs=require('fs'); const value=fs.readFileSync('schema.txt','utf8'); fs.mkdirSync('generated',{recursive:true}); fs.writeFileSync('generated/value.txt',value);",
    );
    project.write_file(
        "packages/app/build.js",
        "const fs=require('fs'); const value=fs.readFileSync('generated/value.txt','utf8'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',value); fs.appendFileSync('executions.txt','run\\n');",
    );

    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();

    project.write_file("packages/app/schema.txt", "schema-v2");
    std::fs::remove_dir_all(project.path().join("packages/app/generated"))
        .expect("remove generated input");
    std::fs::remove_dir_all(project.path().join("packages/app/dist"))
        .expect("remove cached output");
    lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .assert()
        .success();

    assert_eq!(
        project.read_file("packages/app/dist/value.txt"),
        "schema-v2"
    );
    assert_eq!(
        project.read_file("packages/app/executions.txt"),
        "run\nrun\n"
    );
}

#[cfg(unix)]
#[test]
fn run_workspace_rejects_cache_input_symlinks_that_escape_the_member() {
    use std::os::unix::fs::symlink;

    let project = TempProject::from_fixture("workspace-monorepo");
    let package_path = "packages/app/package.json";
    let mut package: serde_json::Value =
        serde_json::from_str(&project.read_file(package_path)).expect("parse app package.json");
    package["scripts"] = serde_json::json!({ "build": "node build.js" });
    project.write_file(
        package_path,
        &serde_json::to_string_pretty(&package).unwrap(),
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{
            "tasks": {
                "build": {
                    "cache": true,
                    "inputs": ["src/**"],
                    "outputs": ["dist/**"]
                }
            }
        }"#,
    );
    project.write_file(
        "packages/app/build.js",
        "require('fs').writeFileSync('task-started.txt','yes');",
    );
    std::fs::create_dir(project.path().join("packages/app/src")).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("value.txt"), "outside").unwrap();
    symlink(
        outside.path().join("value.txt"),
        project.path().join("packages/app/src/escape"),
    )
    .unwrap();

    let output = lpm(&project)
        .args(["run", "build", "--filter", "@test/app"])
        .output()
        .expect("run a workspace task with an external cache input");

    assert!(
        !output.status.success(),
        "external cache input was accepted"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("outside project"),
        "external cache input diagnostic was unclear: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !project.file_exists("packages/app/task-started.txt"),
        "workspace task ran after cache-key validation failed"
    );
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
fn run_no_bail_skips_workspace_caret_dependents_after_an_upstream_task_fails() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_failing_leaf_script(&project);
    for member in ["app", "core", "utils"] {
        project.write_file(
            &format!("packages/{member}/lpm.json"),
            r#"{"tasks":{"check":{"dependsOn":["^check"]}}}"#,
        );
    }

    let output = lpm(&project)
        .args(["run", "check", "--all", "--no-bail"])
        .output()
        .expect("run a failing workspace graph with no-bail");

    assert!(
        !output.status.success(),
        "workspace run must report the failed dependency"
    );
    assert!(
        member_ran(&project, "utils"),
        "the failing dependency did not run"
    );
    assert!(
        !member_ran(&project, "core"),
        "core ran even though its utils dependency failed"
    );
    assert!(
        !member_ran(&project, "app"),
        "app ran even though its transitive dependency failed"
    );
}

#[test]
fn run_no_bail_runs_workspace_tasks_whose_caret_dependencies_succeeded() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["app", "core", "utils"] {
        let package_path = format!("packages/{member}/package.json");
        let mut package: serde_json::Value =
            serde_json::from_str(&project.read_file(&package_path))
                .expect("parse workspace package.json");
        let lint_command = if member == "utils" {
            "node -e \"process.exit(1)\"".to_string()
        } else {
            format!("node -e \"require('fs').writeFileSync('ran-lint-{member}.txt','ok')\"")
        };
        package["scripts"] = serde_json::json!({
            "build": format!("node -e \"require('fs').writeFileSync('ran-build-{member}.txt','ok')\""),
            "lint": lint_command
        });
        project.write_file(
            &package_path,
            &serde_json::to_string_pretty(&package).unwrap(),
        );
        project.write_file(
            &format!("packages/{member}/lpm.json"),
            r#"{
                "tasks": {
                    "build": { "dependsOn": ["^build"] },
                    "lint": { "dependsOn": ["^lint"] }
                }
            }"#,
        );
    }

    let output = lpm(&project)
        .args(["run", "build", "lint", "--filter", "@test/app", "--no-bail"])
        .output()
        .expect("run independent caret task chains with no-bail");

    assert!(!output.status.success(), "the failed lint task was ignored");
    for member in ["utils", "core", "app"] {
        assert!(
            project.file_exists(&format!("packages/{member}/ran-build-{member}.txt")),
            "{member} build was skipped because an unrelated lint task failed"
        );
    }
    for member in ["core", "app"] {
        assert!(
            !project.file_exists(&format!("packages/{member}/ran-lint-{member}.txt")),
            "{member} lint ran after its caret dependency failed"
        );
    }
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
fn run_filter_typo_json_outputs_zero_package_summary() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_unique_scripts(&project);

    let output = lpm(&project)
        .args(["run", "echo", "--filter", "this-does-not-exist", "--json"])
        .output()
        .expect("failed to run lpm run --filter --json");

    assert!(
        output.status.success(),
        "empty-match JSON run must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = support::assertions::parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["packages"], 0);
    assert_eq!(json["succeeded"], 0);
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
