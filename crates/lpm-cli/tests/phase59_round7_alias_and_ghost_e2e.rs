//! **Phase 59.1 audit response — round 7 fresh-binary regressions.**
//!
//! Two end-to-end repros for the auditor's round-7 findings, both in
//! [`expand_workspace_member_deps_with_transitives`].
//!
//! Pre-round-7:
//! - The BFS dedupes the visited set by canonical source path alone
//!   ([`install.rs`] visited insert), but the rest of the round-5/6
//!   pipeline (`pre_extract_file_link_workspace_members` and the
//!   online merge) intentionally treats `(name, realpath)` as the
//!   distinct key so an aliased `file:` reference and the canonical
//!   workspace name produce two `node_modules/<local>` entries. The
//!   BFS dropped the second.
//! - Members that reference a non-member via `workspace:` are
//!   silently skipped, inconsistent with `extract_workspace_protocol_deps`
//!   (root) and the round-3 reject in `recurse_local_source_deps`
//!   (transitive file:/link: walker), both of which error fail-closed.
//!
//! Post-round-7 the BFS dedupes by `(name, canonical realpath)` and
//! errors out on unresolved transitive `workspace:` refs with the
//! same shape as the round-3 reject (available-member list + source
//! manifest path).

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
        .join("lpm-phase59-r7-alias-ghost-e2e")
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

/// **HIGH (round 7) — alias + transitive workspace.** Auditor's repro
/// at `/private/tmp/lpm-workspace-test`:
///
/// - Root depends on `bar` via `workspace:*` AND `aliasfoo` via
///   `file:./packages/foo` (i.e., the consumer aliases the workspace
///   member through a file: spec).
/// - Bar's manifest depends on `foo` via `workspace:*`.
///
/// Pre-round-7: install exited 0 with `node_modules/bar` and
/// `node_modules/aliasfoo` planted, but `node_modules/foo` MISSING.
/// `require('foo')` from inside bar fails at runtime because the
/// workspace-member BFS deduped foo's realpath against the seed
/// entry pushed by `pre_extract_file_link_workspace_members` for
/// the alias — so it never queued the canonical `foo` link.
///
/// Post-round-7: dedupe by `(name, realpath)` distinguishes the alias
/// from the canonical name; both root symlinks land.
#[test]
fn alias_workspace_member_via_file_does_not_drop_canonical_transitive_link() {
    let project = project_dir("alias-plus-transitive");

    write_manifest(
        &project,
        r#"{
  "name": "r7-alias-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "bar": "workspace:*",
    "aliasfoo": "file:./packages/foo"
  }
}"#,
    );

    let foo_dir = project.join("packages").join("foo");
    let bar_dir = project.join("packages").join("bar");
    fs::create_dir_all(&foo_dir).unwrap();
    fs::create_dir_all(&bar_dir).unwrap();
    write_manifest(&foo_dir, r#"{ "name": "foo", "version": "1.0.0" }"#);
    write_manifest(
        &bar_dir,
        r#"{
  "name": "bar",
  "version": "1.0.0",
  "dependencies": { "foo": "workspace:*" }
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
    assert!(
        out.status.success(),
        "install must succeed; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // All three root symlinks must be planted. The alias path
    // resolves to foo's source dir under its alias name; the
    // canonical foo path resolves to the same dir under its
    // canonical name; bar resolves to its own dir.
    assert_root_symlink_to(&project, "aliasfoo", &foo_dir);
    assert_root_symlink_to(&project, "foo", &foo_dir);
    assert_root_symlink_to(&project, "bar", &bar_dir);
}

/// **MEDIUM (round 7) — ghost member.** Auditor's repro at
/// `/private/tmp/lpm-ghost-test`:
///
/// - Root depends on `foo` via `workspace:*` (foo IS a member).
/// - Foo's manifest declares `ghost` via `workspace:*` but no
///   `ghost` workspace member exists.
///
/// Pre-round-7: `expand_workspace_member_deps_with_transitives`
/// silently skipped the unresolved ref. Install exited 0 with no
/// error, no warning, no ghost link. Inconsistent with the root
/// extractor's reject (`extract_workspace_protocol_deps`) and the
/// round-3 transitive reject (`recurse_local_source_deps`).
///
/// Post-round-7: error out at the same boundary with the same
/// error shape — available-member list + source manifest path —
/// so misconfigured workspace graphs fail closed at install time
/// instead of breaking at runtime.
#[test]
fn ghost_workspace_protocol_in_member_manifest_errors_with_available_list() {
    let project = project_dir("ghost-member");

    write_manifest(
        &project,
        r#"{
  "name": "r7-ghost-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "foo": "workspace:*"
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
    "ghost": "workspace:*"
  }
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

    assert!(
        !out.status.success(),
        "install must fail-closed on unresolved transitive workspace ref; \
         stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // Strip everything except ASCII alphanumerics + the punctuation
    // substrings we care about. miette wraps long lines and inserts
    // `│` (U+2502) box-drawing chars into multi-line errors, which
    // would split tokens like "Available members" across the wrap
    // boundary. ASCII-whitespace strip alone (round-2 pattern) isn't
    // enough because `│` survives. Most aggressive strip: drop
    // anything that isn't ASCII alphanumeric, then match lowercase.
    let combined = format!("{}\n{}", out.stdout, out.stderr);
    let stripped: String = combined
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase();

    for needle in [
        // The unresolved name appears in the error.
        "ghost",
        // "workspace" (specifier shape) mentioned.
        "workspace",
        // "not a workspace member" diagnostic from the existing
        // round-3 reject path the round-7 fix reuses.
        "notaworkspacemember",
        // Available members list shows the foo member that DOES
        // exist (the user can see what they should have used).
        "availablemembers",
    ] {
        assert!(
            stripped.contains(needle),
            "diagnostic must mention {needle:?}; combined output:\n{combined}",
        );
    }

    // And no `node_modules/ghost` was planted (fail-closed contract).
    let ghost_link = project.join("node_modules").join("ghost");
    assert!(
        ghost_link.symlink_metadata().is_err(),
        "ghost root symlink must not exist on fail-closed install: {ghost_link:?}",
    );
}
