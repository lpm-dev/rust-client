//! PNPM compatibility contracts for workspace filtering and recursive runs.

mod support;

use support::{TempProject, lpm};

fn git(project: &TempProject, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(project.path())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .unwrap_or_else(|e| panic!("failed to run git {args:?}: {e}"));

    assert!(
        output.status.success(),
        "git {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

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

fn seed_workspace_with_filter_prod_scripts(project: &TempProject) {
    let members = [
        (
            "project-1",
            serde_json::json!({
                "name": "project-1",
                "version": "1.0.0",
                "dependencies": {
                    "project-2": "workspace:*",
                    "project-3": "workspace:*"
                },
                "scripts": {
                    "check": "node -e \"require('fs').writeFileSync('ran-project-1.txt','ok')\""
                }
            }),
        ),
        (
            "project-2",
            serde_json::json!({
                "name": "project-2",
                "version": "1.0.0",
                "scripts": {
                    "check": "node -e \"require('fs').writeFileSync('ran-project-2.txt','ok')\""
                }
            }),
        ),
        (
            "project-3",
            serde_json::json!({
                "name": "project-3",
                "version": "1.0.0",
                "dependencies": {
                    "project-2": "workspace:*"
                },
                "scripts": {
                    "check": "node -e \"require('fs').writeFileSync('ran-project-3.txt','ok')\""
                }
            }),
        ),
        (
            "project-4",
            serde_json::json!({
                "name": "project-4",
                "version": "1.0.0",
                "devDependencies": {
                    "project-3": "workspace:*"
                },
                "scripts": {
                    "check": "node -e \"require('fs').writeFileSync('ran-project-4.txt','ok')\""
                }
            }),
        ),
    ];

    for (member, manifest) in members {
        project.write_file(
            &format!("packages/{member}/package.json"),
            &serde_json::to_string_pretty(&manifest).unwrap(),
        );
    }
}

fn seed_workspace_with_readme_only_git_change(project: &TempProject) {
    project.write_file(
        "packages/app/package.json",
        &serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "scripts": {
                "check": "node -e \"require('fs').writeFileSync('ran-app.txt','ok')\""
            }
        })
        .to_string(),
    );
    project.write_file("packages/app/README.md", "before\n");

    git(project, &["init", "-b", "main"]);
    git(project, &["add", "."]);
    git(project, &["commit", "-m", "init"]);
    git(project, &["checkout", "-b", "feature"]);
    project.write_file("packages/app/README.md", "after\n");
    git(project, &["add", "."]);
    git(project, &["commit", "-m", "readme change"]);
}

fn seed_workspace_with_utils_app_git_change(project: &TempProject, changed_file: &str) {
    project.write_file(
        "packages/utils/package.json",
        &serde_json::json!({
            "name": "utils",
            "version": "1.0.0",
            "scripts": {
                "check": "node -e \"require('fs').writeFileSync('ran-utils.txt','ok')\""
            }
        })
        .to_string(),
    );
    project.write_file(
        "packages/app/package.json",
        &serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "dependencies": {
                "utils": "workspace:*"
            },
            "scripts": {
                "check": "node -e \"require('fs').writeFileSync('ran-app.txt','ok')\""
            }
        })
        .to_string(),
    );
    project.write_file(
        "packages/utils/src/index.js",
        "module.exports = 'before';\n",
    );
    project.write_file(
        "packages/utils/src/index.test.js",
        "test('before', () => {});\n",
    );
    project.write_file("packages/app/src/index.js", "require('utils');\n");

    git(project, &["init", "-b", "main"]);
    git(project, &["add", "."]);
    git(project, &["commit", "-m", "init"]);
    git(project, &["checkout", "-b", "feature"]);
    project.write_file(changed_file, "test('after', () => {});\n");
    git(project, &["add", "."]);
    git(project, &["commit", "-m", "change utils"]);
}

fn seed_workspace_with_scoped_members_in_multiple_roots(project: &TempProject) {
    project.write_file(
        "apps/web/package.json",
        &serde_json::json!({
            "name": "@scope/web",
            "version": "1.0.0"
        })
        .to_string(),
    );
    project.write_file(
        "packages/ui/package.json",
        &serde_json::json!({
            "name": "@scope/ui",
            "version": "1.0.0"
        })
        .to_string(),
    );
    project.write_file(
        "apps/admin/package.json",
        &serde_json::json!({
            "name": "@other/admin",
            "version": "1.0.0"
        })
        .to_string(),
    );
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

#[test]
fn run_filter_prod_omits_dev_dependency_dependents() {
    let project = TempProject::empty(
        r#"{
        "name": "filter-prod-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    seed_workspace_with_filter_prod_scripts(&project);

    let output = lpm(&project)
        .args(["run", "check", "--filter-prod", "...project-3"])
        .output()
        .expect("failed to run lpm run --filter-prod");

    assert!(
        output.status.success(),
        "filter-prod run should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(member_ran(&project, "project-1"));
    assert!(member_ran(&project, "project-3"));
    assert!(!member_ran(&project, "project-2"));
    assert!(!member_ran(&project, "project-4"));
}

#[test]
fn filter_git_ref_ignores_changed_files_matching_ignore_pattern() {
    let project = TempProject::empty(
        r#"{
        "name": "changed-files-ignore-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    seed_workspace_with_readme_only_git_change(&project);

    let output = lpm(&project)
        .args([
            "filter",
            "[main]",
            "--changed-files-ignore-pattern",
            "**/README.md",
        ])
        .output()
        .expect("failed to run lpm filter with changed files ignore pattern");

    assert!(
        output.status.success(),
        "filter should accept --changed-files-ignore-pattern\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.lines().any(|line| line.trim() == "app"),
        "README-only changes matching the ignore pattern should not select the app package\nstdout:\n{stdout}",
    );
}

#[test]
fn filter_git_ref_uses_workspace_changed_files_ignore_pattern_config() {
    let project = TempProject::empty(
        r#"{
        "name": "changed-files-ignore-config-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    project.write_file(
        "lpm.toml",
        r#"[workspace]
changed-files-ignore-pattern = "**/README.md"
"#,
    );
    seed_workspace_with_readme_only_git_change(&project);

    let output = lpm(&project)
        .args(["filter", "[main]"])
        .output()
        .expect("failed to run lpm filter with configured changed files ignore pattern");

    assert!(
        output.status.success(),
        "filter should read [workspace].changed-files-ignore-pattern\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.lines().any(|line| line.trim() == "app"),
        "configured ignore pattern should remove README-only changes from git-ref selection\nstdout:\n{stdout}",
    );
}

#[test]
fn run_affected_ignores_changed_files_matching_ignore_pattern() {
    let project = TempProject::empty(
        r#"{
        "name": "changed-files-ignore-run-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    seed_workspace_with_readme_only_git_change(&project);

    let output = lpm(&project)
        .args([
            "run",
            "check",
            "--affected",
            "--changed-files-ignore-pattern",
            "**/README.md",
        ])
        .output()
        .expect("failed to run lpm run --affected with changed files ignore pattern");

    assert!(
        output.status.success(),
        "ignored README-only changes should leave no affected workspace work\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !member_ran(&project, "app"),
        "app script should not run when its only changed file matched the ignore pattern"
    );
}

#[test]
fn filter_git_ref_test_pattern_keeps_test_only_package_without_dependents() {
    let project = TempProject::empty(
        r#"{
        "name": "test-pattern-filter-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    seed_workspace_with_utils_app_git_change(&project, "packages/utils/src/index.test.js");

    let output = lpm(&project)
        .args(["filter", "...[main]", "--test-pattern", "**/*.test.js"])
        .output()
        .expect("failed to run lpm filter with test pattern");

    assert!(
        output.status.success(),
        "filter should accept --test-pattern\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().any(|line| line.trim() == "utils"),
        "test-only changes should still select the directly changed package\nstdout:\n{stdout}",
    );
    assert!(
        !stdout.lines().any(|line| line.trim() == "app"),
        "test-only changes should not expand to dependents under --test-pattern\nstdout:\n{stdout}",
    );
}

#[test]
fn run_affected_test_pattern_skips_dependents_for_test_only_changes() {
    let project = TempProject::empty(
        r#"{
        "name": "test-pattern-run-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    seed_workspace_with_utils_app_git_change(&project, "packages/utils/src/index.test.js");

    let output = lpm(&project)
        .args([
            "run",
            "check",
            "--affected",
            "--test-pattern",
            "**/*.test.js",
        ])
        .output()
        .expect("failed to run lpm run --affected with test pattern");

    assert!(
        output.status.success(),
        "run should accept --test-pattern\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(member_ran(&project, "utils"));
    assert!(
        !member_ran(&project, "app"),
        "app script should not run when utils only changed in files matching --test-pattern"
    );
}

#[test]
fn filter_combined_name_and_path_syntax_intersects_name_and_path_matches() {
    let project = TempProject::empty(
        r#"{
        "name": "combined-name-path-filter-test",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["apps/*", "packages/*"]
    }"#,
    );
    seed_workspace_with_scoped_members_in_multiple_roots(&project);

    let output = lpm(&project)
        .args(["filter", "@scope/*{./apps/web}"])
        .output()
        .expect("failed to run lpm filter with combined name/path syntax");

    assert!(
        output.status.success(),
        "filter should accept pnpm's pkg{{path}} combined syntax\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().any(|line| line.trim() == "@scope/web"),
        "combined selector should keep the package matching both name and path\nstdout:\n{stdout}",
    );
    assert!(
        !stdout.lines().any(|line| line.trim() == "@scope/ui"),
        "combined selector should exclude packages matching only the name pattern\nstdout:\n{stdout}",
    );
    assert!(
        !stdout.lines().any(|line| line.trim() == "@other/admin"),
        "combined selector should exclude unrelated packages\nstdout:\n{stdout}",
    );
}
