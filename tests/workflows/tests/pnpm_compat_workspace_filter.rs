//! PNPM compatibility contracts for workspace filtering and recursive runs.

mod support;

use support::{TempProject, lpm};

fn seed_independent_workspace_with_concurrency_scripts(project: &TempProject) {
    project.write_file(
        "record-concurrency.js",
        r#"
const fs = require('fs');
const path = require('path');

const root = __dirname;
const statePath = path.join(root, 'concurrency-state.json');
const lockPath = path.join(root, 'concurrency-state.lock');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function acquireLock() {
  const deadline = Date.now() + 10000;
  while (true) {
    try {
      fs.mkdirSync(lockPath);
      return;
    } catch (error) {
      if (error.code !== 'EEXIST' || Date.now() > deadline) {
        throw error;
      }
    }
  }
}

function withLock(callback) {
  acquireLock();
  try {
    return callback();
  } finally {
    fs.rmSync(lockPath, { recursive: true, force: true });
  }
}

function mutateActive(delta) {
  withLock(() => {
    let state = { active: 0, max: 0 };
    try {
      state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }

    state.active += delta;
    if (state.active < 0) {
      throw new Error('active counter went negative');
    }
    state.max = Math.max(state.max, state.active);
    fs.writeFileSync(statePath, JSON.stringify(state));
  });
}

(async () => {
  mutateActive(1);
  await sleep(250);
  mutateActive(-1);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
"#,
    );

    for member in ["alpha", "beta", "gamma"] {
        project.write_file(
            &format!("packages/{member}/package.json"),
            &serde_json::json!({
                "name": format!("@test/{member}"),
                "version": "1.0.0",
                "scripts": {
                    "check": "node ../../record-concurrency.js",
                    "test": "node ../../record-concurrency.js",
                    "bench": "node ../../record-concurrency.js"
                }
            })
            .to_string(),
        );
    }
}

fn seed_workspace_with_no_bail_scripts(project: &TempProject) {
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

fn member_ran(project: &TempProject, member: &str) -> bool {
    project.file_exists(&format!("packages/{member}/ran-{member}.txt"))
}

fn max_recorded_concurrency(project: &TempProject) -> u64 {
    let state = project.read_file("concurrency-state.json");
    let parsed: serde_json::Value = serde_json::from_str(&state).expect("parse concurrency state");
    parsed["max"].as_u64().expect("state max is an integer")
}

fn assert_workspace_concurrency_one_serializes(
    project: &TempProject,
    output: &std::process::Output,
) {
    assert!(
        output.status.success(),
        "workspace command should succeed with capped concurrency\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        max_recorded_concurrency(project),
        1,
        "--workspace-concurrency=1 must serialize independent same-level workspace packages"
    );
}

#[test]
fn run_filter_workspace_concurrency_one_serializes_same_level_members() {
    let project = TempProject::empty(
        r#"{
        "name": "workspace-concurrency-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    seed_independent_workspace_with_concurrency_scripts(&project);

    let output = lpm(&project)
        .args([
            "run",
            "check",
            "--filter",
            "@test/*",
            "--workspace-concurrency",
            "1",
        ])
        .output()
        .expect("failed to run lpm run --filter --workspace-concurrency");

    assert_workspace_concurrency_one_serializes(&project, &output);
}

#[test]
fn test_filter_workspace_concurrency_one_serializes_same_level_members() {
    let project = TempProject::empty(
        r#"{
        "name": "workspace-concurrency-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    seed_independent_workspace_with_concurrency_scripts(&project);

    let output = lpm(&project)
        .args([
            "test",
            "--filter",
            "@test/*",
            "--workspace-concurrency",
            "1",
        ])
        .output()
        .expect("failed to run lpm test --filter --workspace-concurrency");

    assert_workspace_concurrency_one_serializes(&project, &output);
}

#[test]
fn bench_filter_workspace_concurrency_one_serializes_same_level_members() {
    let project = TempProject::empty(
        r#"{
        "name": "workspace-concurrency-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    seed_independent_workspace_with_concurrency_scripts(&project);

    let output = lpm(&project)
        .args([
            "bench",
            "--filter",
            "@test/*",
            "--workspace-concurrency",
            "1",
        ])
        .output()
        .expect("failed to run lpm bench --filter --workspace-concurrency");

    assert_workspace_concurrency_one_serializes(&project, &output);
}

#[test]
fn run_filter_no_bail_continues_after_failed_workspace_member() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_no_bail_scripts(&project);

    let output = lpm(&project)
        .args(["run", "check", "--filter", "@test/*", "--no-bail"])
        .output()
        .expect("failed to run lpm run --filter --no-bail");

    assert!(
        !output.status.success(),
        "--no-bail must still report the filtered batch failure"
    );
    for member in ["utils", "core", "app"] {
        assert!(
            member_ran(&project, member),
            "{member} must execute even though utils fails under --no-bail\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
