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
