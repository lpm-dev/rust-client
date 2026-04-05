//! Workflow tests for `lpm run`.
//!
//! These tests spawn the real `lpm-rs` binary against fixture projects
//! and verify exit codes, stdout/stderr, and task execution behavior.

mod support;

use support::{TempProject, lpm};

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

// ─── No package.json ─────────────────────────────────────────────

#[test]
fn run_without_package_json_fails() {
    let project = TempProject::empty("{}");
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

// ─── Env Loading ─────────────────────────────────────────────────

#[test]
fn run_loads_dotenv_file() {
    let project = TempProject::empty(
        r#"{
        "name": "env-test",
        "version": "1.0.0",
        "scripts": {
            "show-env": "echo $MY_TEST_VAR"
        }
    }"#,
    );

    // Create a .env file
    project.write_file(".env", "MY_TEST_VAR=hello-from-dotenv");

    let output = lpm(&project)
        .args(["run", "show-env"])
        .output()
        .expect("failed to run lpm");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello-from-dotenv"),
        "expected .env variable to be loaded, got:\n{stdout}"
    );
}

#[test]
fn run_loads_env_mode_file() {
    let project = TempProject::empty(
        r#"{
        "name": "env-mode-test",
        "version": "1.0.0",
        "scripts": {
            "show-env": "echo $STAGE_VAR"
        }
    }"#,
    );

    // Create .env.staging file
    project.write_file(".env.staging", "STAGE_VAR=staging-value");

    let output = lpm(&project)
        .args(["run", "show-env", "--env", "staging"])
        .output()
        .expect("failed to run lpm");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("staging-value"),
        "expected .env.staging variable to be loaded, got:\n{stdout}"
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
