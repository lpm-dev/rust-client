//! **Phase 59.1 audit response — round 5 fresh-binary regressions.**
//!
//! Two end-to-end repros for the auditor's round-5 HIGH findings.
//! Both manifest as silent install successes that leave the project's
//! `node_modules/` missing root symlinks.
//!
//! Pre-round-5:
//! - `link_workspace_members` only iterated the EXTRACTED top-level
//!   subset (`workspace_member_deps`) — entries the consumer's root
//!   manifest declared via `workspace:*`.
//! - F9 immediate file:/link: dedupe pushed nothing into that set,
//!   so `"foo": "file:./packages/foo"` against a member produced no
//!   `node_modules/foo` (HIGH 1).
//! - Round-3's transitive `workspace:` arm pushed nothing into that
//!   set, so `"foo": "workspace:*"` + foo's `bar: workspace:*`
//!   produced no `node_modules/bar` (HIGH 2).
//!
//! Post-round-5:
//! - `pre_resolve_non_registry_deps` returns
//!   `additional_workspace_links` collecting every member it
//!   discovered through F9 / round-3 paths.
//! - The install pipeline merges those into `workspace_member_deps`
//!   with realpath dedupe, then BFS-walks linked members'
//!   manifests for transitive `workspace:` refs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

#[allow(dead_code)]
struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-phase59-r5-workspace-root-symlinks-e2e")
        .join(format!("{name}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_manifest(dir: &Path, body: &str) {
    fs::write(dir.join("package.json"), body).unwrap();
}

fn run_lpm(cwd: &Path, args: &[&str]) -> CommandOutput {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    fs::create_dir_all(&home).unwrap();
    let output = Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env("LPM_REGISTRY_URL", "http://127.0.0.1:1")
        .env_remove("LPM_TOKEN")
        .env_remove("NPM_TOKEN")
        .output()
        .expect("failed to spawn lpm-rs");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn assert_root_symlink_to(project: &Path, root_name: &str, expected_target: &Path) {
    let link = project.join("node_modules").join(root_name);
    assert!(
        link.symlink_metadata().is_ok(),
        "missing root symlink: node_modules/{root_name} (looked at {link:?})",
    );
    let resolved = link
        .canonicalize()
        .unwrap_or_else(|e| panic!("failed to canonicalize {link:?}: {e}"));
    let expected = expected_target
        .canonicalize()
        .unwrap_or_else(|e| panic!("failed to canonicalize {expected_target:?}: {e}"));
    assert_eq!(
        resolved, expected,
        "root symlink node_modules/{root_name} resolved to {resolved:?}, expected {expected:?}",
    );
}

/// **HIGH 1 — F9 dedupe dropped the root symlink.** The auditor's
/// repro: a workspace project where the root depends on `foo` via
/// `file:./packages/foo` and `foo` is also a workspace member.
/// Pre-round-5 install exited 0 with the F9 dedupe note but left
/// `node_modules/foo` missing. Post-round-5 the F9 dedupe path
/// pushes the matched member into `additional_workspace_links` so
/// the root symlink lands.
#[test]
fn f9_immediate_file_dedupe_plants_root_symlink_for_workspace_member() {
    let project = project_dir("high1-file-dedupe");

    write_manifest(
        &project,
        r#"{
  "name": "r5-high1-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "foo": "file:./packages/foo"
  }
}"#,
    );

    let foo_dir = project.join("packages").join("foo");
    fs::create_dir_all(&foo_dir).unwrap();
    write_manifest(&foo_dir, r#"{ "name": "foo", "version": "1.0.0" }"#);

    let out = run_lpm(
        &project,
        &[
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ],
    );
    assert!(
        out.status.success(),
        "install must succeed; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // Strongest positive assertion: the root symlink the auditor
    // showed was missing pre-round-5 IS present post-round-5 and
    // resolves to foo's source directory.
    assert_root_symlink_to(&project, "foo", &foo_dir);

    // And the F9 dedupe note IS present (proves the F9 path fired —
    // we want the round-5 fix to plant the symlink THROUGH the F9
    // path, not by accident via some other code path).
    let combined = format!("{}\n{}", out.stdout, out.stderr);
    assert!(
        combined.contains("resolves to workspace member"),
        "F9 dedupe note expected (proves the round-5 fix applies to the F9 path):\n{combined}",
    );
}

/// **HIGH 2 — transitive `workspace:` matched but not root-linked.**
/// The auditor's repro: a workspace project where the root depends
/// on `foo` via `workspace:*` (so foo is in the extracted top-level
/// set), and foo's manifest declares `bar: workspace:*` (sibling
/// member). Pre-round-5 install succeeded with `node_modules/foo`
/// present but `node_modules/bar` missing — runtime resolution of
/// `bar` from inside foo fails. Post-round-5 the workspace-member
/// BFS walks foo's manifest, finds the transitive `workspace:` ref
/// to bar, looks bar up in `all_workspace_members`, and queues a
/// root symlink for it.
#[test]
fn transitive_workspace_protocol_in_member_manifest_plants_sibling_root_symlink() {
    let project = project_dir("high2-transitive-workspace");

    write_manifest(
        &project,
        r#"{
  "name": "r5-high2-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "foo": "workspace:*"
  }
}"#,
    );

    let foo_dir = project.join("packages").join("foo");
    let bar_dir = project.join("packages").join("bar");
    fs::create_dir_all(&foo_dir).unwrap();
    fs::create_dir_all(&bar_dir).unwrap();
    write_manifest(
        &foo_dir,
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": {
    "bar": "workspace:*"
  }
}"#,
    );
    write_manifest(&bar_dir, r#"{ "name": "bar", "version": "1.2.3" }"#);

    let out = run_lpm(
        &project,
        &[
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ],
    );
    assert!(
        out.status.success(),
        "install must succeed; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // Both root symlinks must exist. `foo` is the easy case (top-
    // level extracted, pre-round-5 worked). `bar` is the round-5
    // fix — it's not top-level, only transitively referenced.
    assert_root_symlink_to(&project, "foo", &foo_dir);
    assert_root_symlink_to(&project, "bar", &bar_dir);
}

/// **HIGH 1 + HIGH 2 combined — chained workspace transitive walk.**
/// Defense-in-depth: a member that's reached through F9 (HIGH 1
/// path) declares a `workspace:` transitive (HIGH 2 path). The BFS
/// must continue from the F9-discovered member, not just from the
/// extracted top-level set. Pre-round-5 a chain of `file:` →
/// `workspace:*` → `workspace:*` would lose the deepest link.
#[test]
fn f9_dedupe_then_transitive_workspace_chain_plants_all_root_symlinks() {
    let project = project_dir("chain-f9-then-workspace");

    write_manifest(
        &project,
        r#"{
  "name": "r5-chain-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "foo": "file:./packages/foo"
  }
}"#,
    );

    let foo_dir = project.join("packages").join("foo");
    let bar_dir = project.join("packages").join("bar");
    let baz_dir = project.join("packages").join("baz");
    fs::create_dir_all(&foo_dir).unwrap();
    fs::create_dir_all(&bar_dir).unwrap();
    fs::create_dir_all(&baz_dir).unwrap();
    write_manifest(
        &foo_dir,
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "workspace:*" }
}"#,
    );
    write_manifest(
        &bar_dir,
        r#"{
  "name": "bar",
  "version": "1.0.0",
  "dependencies": { "baz": "workspace:*" }
}"#,
    );
    write_manifest(&baz_dir, r#"{ "name": "baz", "version": "1.0.0" }"#);

    let out = run_lpm(
        &project,
        &[
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ],
    );
    assert!(
        out.status.success(),
        "install must succeed; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // Three-deep chain: root → foo (file: + member) → bar (workspace:)
    // → baz (workspace:). All three must end up root-linked.
    assert_root_symlink_to(&project, "foo", &foo_dir);
    assert_root_symlink_to(&project, "bar", &bar_dir);
    assert_root_symlink_to(&project, "baz", &baz_dir);
}
