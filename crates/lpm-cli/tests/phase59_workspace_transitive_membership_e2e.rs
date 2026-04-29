//! **Phase 59.1 audit response — round 4 fresh-binary regression.**
//!
//! Round 3 added a `workspace:` transitive check at the
//! `recurse_local_source_deps` boundary: a `workspace:*` spec inside a
//! local file/link source must be skipped (member is symlinked at the
//! project root, Node ancestor walk handles it) or rejected with a
//! typed error if no member matches. Round 4 found that the membership
//! slice passed into `pre_resolve_non_registry_deps` was the
//! EXTRACTED-from-top-level subset (`workspace_member_deps`), not the
//! full `ws.members` set. Result: a real workspace where the root
//! depends on `foo` via `file:` and foo's manifest declares
//! `"bar": "workspace:*"` would still hit the round-3 reject branch
//! with "(this project is not a workspace)" — even though the project
//! IS a workspace and bar IS a member.
//!
//! Round 4 fix: build `all_workspace_members` directly from
//! `ws.members` and pass that to `pre_resolve_non_registry_deps`.
//!
//! This e2e test reproduces the auditor's exact scenario through the
//! real `lpm-rs` binary. With the fix, install must SUCCEED (no
//! "not a workspace member" error) and produce a root symlink for the
//! file: dep. Pre-fix it would error.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-phase59-workspace-transitive-membership-e2e")
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

#[test]
fn workspace_transitive_resolves_against_full_membership_set_not_just_top_level_extracted() {
    let project = project_dir("workspace-transitive-membership");

    // Root project IS a workspace (`workspaces` field), but the root's
    // `dependencies` only references `foo` via `file:`. Critically:
    // the root does NOT declare `"bar": "workspace:*"` directly. Pre-
    // round-4 the membership slice passed into pre_resolve was built
    // from top-level extraction, so bar appeared invisible even though
    // it's a real workspace member.
    write_manifest(
        &project,
        r#"{
  "name": "phase59-r4-workspace-transitive-membership",
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

    let bar_dir = project.join("packages").join("bar");
    fs::create_dir_all(&bar_dir).unwrap();
    write_manifest(
        &bar_dir,
        r#"{
  "name": "bar",
  "version": "1.2.3"
}"#,
    );

    let out = run_lpm(
        &project,
        &[
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ],
    );

    // The repro has NO registry deps; install must finish without
    // errors. Pre-round-4 it errored at the round-3 reject branch
    // and lpm-rs exited non-zero.
    assert!(
        out.status.success(),
        "round-4 fix: install of a real workspace with a transitive \
         `workspace:*` against a sibling member must succeed. \
         exit_status: {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        out.stdout,
        out.stderr,
    );
    assert!(
        !out.stderr.contains("not a workspace member"),
        "round-4 fix: a transitive `workspace:*` against a real workspace member \
         must NOT trip the round-3 'not a workspace member' branch — that branch \
         was firing because the membership slice was the extracted top-level \
         subset, not the full ws.members set. stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );
    assert!(
        !out.stderr.contains("invalid range") && !out.stderr.contains("invalid version range"),
        "post-round-4 install must not crash the resolver on `workspace:` either. \
         stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // Some confirmation that the install actually completed: the
    // install summary line lands on stderr in human mode, stdout
    // carries only the timing tail. Check both so the assertion
    // doesn't break on formatting changes.
    let combined = format!("{}\n{}", out.stdout, out.stderr);
    assert!(
        combined.contains("packages installed") || combined.contains("Lockfile"),
        "expected an install-completed signal; got:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // Strongest positive assertion of the round-4 fix: F9 dedupe
    // recognized that the file: dep `foo` realpaths to a workspace
    // member, AND the transitive `bar: workspace:*` inside foo's
    // manifest didn't trip the round-3 reject path (because
    // `all_workspace_members` now sees bar as a member). The F9
    // info note is a stable signal that membership was visible.
    assert!(
        combined.contains("resolves to workspace member"),
        "F9 overlap detection must see bar as a workspace member \
         post-round-4. stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // **Round-5 audit response — strengthened positive assertion.**
    // The auditor pointed out that the round-4 e2e only checked
    // success text and never asserted that `foo` was actually linked
    // at the project root. Round-5 confirmed by direct repro that
    // the file: dep WAS being silently dropped by F9 dedupe. Now
    // verify post-install that `node_modules/foo` exists and points
    // at the workspace member's source directory.
    let foo_root_link = project.join("node_modules").join("foo");
    assert!(
        foo_root_link.symlink_metadata().is_ok(),
        "round-5 fix: F9-deduped `file:` workspace member must be linked at the \
         project root. Missing: {foo_root_link:?}",
    );
    let resolved = foo_root_link.canonicalize().unwrap();
    let expected = foo_dir.canonicalize().unwrap();
    assert_eq!(
        resolved, expected,
        "node_modules/foo must resolve to the workspace member's source dir; \
         got {resolved:?} expected {expected:?}",
    );
}
