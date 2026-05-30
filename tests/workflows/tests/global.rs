//! Workflow tests for `lpm global *` and the `lpm install -g` / `lpm uninstall -g`
//! aliases.
//!
//! [`crates/lpm-cli/tests/global_install_state_mutation.rs`] is the
//! authoritative cli-binary survivor: it exercises the full WAL +
//! manifest + shim machinery against an isolated `~/.lpm/global/` dir.
//! This workflow-tier file covers the lighter-weight contracts that
//! don't depend on the WAL / shim repair internals:
//!
//! - `lpm global list` on an empty manifest (human + --json envelope)
//! - `lpm global list --outdated` on an empty manifest
//! - `lpm global bin` prints the isolated bin path
//! - `lpm global path <pkg>` error path (no such global)
//! - `lpm global remove <pkg>` error path (no such global)
//! - `lpm uninstall -g <pkg>` error path (alias parity)
//! - `lpm global update --dry-run` on an empty manifest (idempotent)

mod support;

use support::{TempProject, lpm};

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

fn global_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("global")
}

// ─── list (empty) ─────────────────────────────────────────────────────

#[test]
fn global_list_on_empty_manifest_succeeds_with_no_packages_message() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["global", "list"])
        .output()
        .expect("failed to run lpm global list");

    assert!(
        output.status.success(),
        "global list on empty HOME must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("No globally-installed")
            || combined.contains("no packages")
            || combined.contains("0 package"),
        "human output must indicate empty state, got:\n{combined}",
    );
    assert!(
        combined.contains("! No globally-installed packages"),
        "global list should use a slim warning for the empty state, got:\n{combined}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "global list output should not use bordered/cliclack glyphs, got:\n{combined}"
    );
}

#[test]
fn global_list_json_envelope_on_empty_manifest_carries_empty_packages_array() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "global", "list"])
        .output()
        .expect("failed to run lpm global list --json");

    assert!(output.status.success(), "global list --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("global list --json must be valid JSON: {e}\n---\n{stdout}"));

    // Schema: `packages` array — must be present and empty on fresh HOME.
    let packages = envelope["packages"]
        .as_array()
        .expect("envelope must carry packages array");
    assert!(
        packages.is_empty(),
        "fresh HOME must report zero packages, got: {envelope}",
    );
}

#[test]
fn global_list_outdated_on_empty_manifest_succeeds_with_empty_set() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        // Use --registry pointing at port 1 so the batch-metadata probe
        // fails fast if the empty-manifest short-circuit doesn't catch.
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "global",
            "list",
            "--outdated",
        ])
        .output()
        .expect("failed to run lpm global list --outdated --json");

    assert!(
        output.status.success(),
        "global list --outdated on empty manifest must succeed (no registry call needed)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("envelope must be valid JSON: {e}\n---\n{stdout}"));

    // Stable shape — packages array (may be empty), no outdated entries.
    if let Some(packages) = envelope["packages"].as_array() {
        assert!(packages.is_empty(), "empty manifest expected: {envelope}");
    }
}

// ─── bin ──────────────────────────────────────────────────────────────

#[test]
fn global_bin_prints_isolated_global_bin_directory() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["global", "bin"])
        .output()
        .expect("failed to run lpm global bin");

    assert!(
        output.status.success(),
        "global bin must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = project
        .home()
        .join(".lpm")
        .join("bin")
        .display()
        .to_string();
    assert_eq!(
        stdout.trim(),
        expected,
        "global bin must print the isolated bin dir, got: {stdout}",
    );
}

#[test]
fn global_bin_json_envelope_carries_path() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "global", "bin"])
        .output()
        .expect("failed to run lpm global bin --json");

    assert!(output.status.success(), "global bin --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("envelope must be valid JSON: {e}\n---\n{stdout}"));

    let bin_path = envelope["bin"]
        .as_str()
        .or_else(|| envelope["path"].as_str())
        .expect("envelope must carry the bin path");
    let expected = project
        .home()
        .join(".lpm")
        .join("bin")
        .display()
        .to_string();
    assert_eq!(
        bin_path, expected,
        "envelope bin path must point at the isolated bin dir: {envelope}",
    );
}

// ─── path <pkg> (error path) ──────────────────────────────────────────

#[test]
fn global_path_for_unknown_package_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["global", "path", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm global path <unknown>");

    assert!(
        !output.status.success(),
        "global path on unknown package must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-installed-pkg") || stderr.contains("not installed"),
        "stderr must mention the missing package, got:\n{stderr}",
    );
}

#[test]
fn global_path_for_unknown_package_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "global", "path", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm global path <unknown> --json");

    // Whether the process exits zero or non-zero is a separate
    // contract (finding #73 in private/findings.md flags that
    // `--json` paths uniformly exit 0). The load-bearing claim here
    // is that the failure surfaces on stdout as a parsable envelope
    // with `success: false`, not as a free-form stderr message.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json error path must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    let combined = format!("{envelope}{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        combined.contains("not-installed-pkg") || combined.contains("not installed"),
        "envelope or stderr must mention the missing package, got:\n{combined}",
    );
}

// ─── remove / uninstall -g (error path) ───────────────────────────────

#[test]
fn global_remove_unknown_package_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["global", "remove", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm global remove <unknown>");

    assert!(
        !output.status.success(),
        "global remove on unknown package must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-installed-pkg")
            || stderr.contains("not installed")
            || stderr.contains("not found"),
        "stderr must mention the missing package, got:\n{stderr}",
    );
}

#[test]
fn uninstall_g_unknown_package_matches_global_remove_error_path() {
    // `lpm uninstall -g <pkg>` and `lpm global remove <pkg>` route
    // through the same M3.3 implementation. Pin parity so a future
    // divergence between the two aliases fails this test.
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let out_uninstall = lpm(&project)
        .args(["uninstall", "-g", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm uninstall -g <unknown>");

    let out_remove = lpm(&project)
        .args(["global", "remove", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm global remove <unknown>");

    assert!(
        !out_uninstall.status.success(),
        "uninstall -g on unknown package must exit non-zero"
    );
    assert!(
        !out_remove.status.success(),
        "global remove on unknown package must exit non-zero"
    );

    // Both paths must produce an error mentioning the missing package.
    let stderr_uninstall = String::from_utf8_lossy(&out_uninstall.stderr);
    let stderr_remove = String::from_utf8_lossy(&out_remove.stderr);
    assert!(
        stderr_uninstall.contains("not-installed-pkg")
            || stderr_uninstall.contains("not installed")
            || stderr_uninstall.contains("not found"),
        "uninstall -g stderr: {stderr_uninstall}"
    );
    assert!(
        stderr_remove.contains("not-installed-pkg")
            || stderr_remove.contains("not installed")
            || stderr_remove.contains("not found"),
        "global remove stderr: {stderr_remove}"
    );
}

// ─── update (empty + dry-run) ─────────────────────────────────────────

#[test]
fn global_update_dry_run_on_empty_manifest_succeeds_without_writing_manifest() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let manifest_path = global_root(&project).join("manifest.json");

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "global",
            "update",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm global update --dry-run --json");

    assert!(
        output.status.success(),
        "global update --dry-run on empty manifest must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    // The global directory may be created as a side effect of
    // `LpmRoot::from_env()` (it ensures the home tree exists), but
    // dry-run MUST NOT write a populated manifest.
    assert!(
        !manifest_path.exists(),
        "dry-run must not create global manifest.json, but it exists at {}",
        manifest_path.display(),
    );
}

#[test]
fn global_update_unknown_package_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "global",
            "update",
            "not-installed-pkg",
        ])
        .output()
        .expect("failed to run lpm global update <unknown>");

    assert!(
        !output.status.success(),
        "global update on unknown package must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-installed-pkg")
            || stderr.contains("not installed")
            || stderr.contains("not found"),
        "stderr must mention the missing package, got:\n{stderr}",
    );
}

// ─── install -g (clap-level arg validation) ───────────────────────────

#[test]
fn install_g_without_package_args_fails_or_no_ops() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "install",
            "-g",
        ])
        .output()
        .expect("failed to run lpm install -g (no args)");

    // Either exits non-zero (no spec given) OR exits 0 with a clear
    // "nothing to do" message — both are acceptable contracts for
    // empty-args. Crashing or hanging on network is NOT.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    if output.status.success() {
        assert!(
            combined.contains("nothing")
                || combined.contains("no packages")
                || combined.contains("0 packages"),
            "if install -g succeeds with no args, output must explain why, got:\n{combined}",
        );
    } else {
        assert!(
            combined.contains("package") || combined.contains("spec"),
            "install -g without args error must mention packages/spec, got:\n{combined}",
        );
    }
}
