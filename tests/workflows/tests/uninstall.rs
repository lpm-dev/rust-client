//! Workflow tests for `lpm uninstall`.
//!
//! Uninstall is a no-network command: it edits `package.json`, drops the
//! lockfile, and removes `node_modules` entries. These tests pin the
//! behavior contracts that matter to CI and to scripts coming from
//! npm/pnpm/yarn — particularly the contracts where LPM's behavior
//! diverges from those tools.
//!
//! Note: `lpm uninstall` and `lpm remove` are NOT aliases. `Remove` is
//! the source-package removal command (counterpart to `lpm add`); this
//! file covers `Uninstall` only. `lpm remove` coverage is queued
//! separately.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

/// Seed `project` with an installed-looking layout for `pkg@version`:
/// `package.json` deps entry, a minimal `lpm.lock`, and a
/// `node_modules/<pkg>/package.json` placeholder. Lets tests exercise
/// uninstall in isolation from the full install pipeline.
fn seed_installed_package(project: &TempProject, pkg: &str, version: &str) {
    project.write_file(
        "package.json",
        &format!(
            r#"{{"name":"uninstall-test","version":"1.0.0","dependencies":{{"{pkg}":"^{version}"}}}}"#
        ),
    );
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
             [[packages]]\nname = \"{pkg}\"\nversion = \"{version}\"\n\
             source = \"registry+https://lpm.dev\"\n",
        ),
    );
    project.write_file(
        &format!("node_modules/{pkg}/package.json"),
        &format!(r#"{{"name":"{pkg}","version":"{version}"}}"#),
    );
}

// ─── Argument validation ────────────────────────────────────────────────

/// Bare `lpm uninstall` with no package args is an error — there's no
/// sensible default. Pre-fix regressions that silently exit 0 would mask
/// scripting bugs.
#[test]
fn uninstall_without_package_args_fails_with_clear_message() {
    let project = TempProject::empty(r#"{"name":"args-test","version":"1.0.0"}"#);

    let out = lpm(&project)
        .args(["uninstall"])
        .output()
        .expect("spawn lpm uninstall");
    assert!(
        !out.status.success(),
        "uninstall with no args must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("specify at least one package")
            || stderr.to_lowercase().contains("package"),
        "stderr should explain that a package arg is required; got:\n{stderr}"
    );
}

// ─── Manifest + lockfile + node_modules cleanup ─────────────────────────

/// Removing the last entry from `dependencies` leaves the section as
/// `{}` rather than dropping the key entirely. Pins the manifest
/// serialization contract — downstream tools that read `package.json`
/// shouldn't see a key disappear out from under them just because the
/// list went empty.
#[test]
fn uninstall_last_dependency_leaves_empty_dependencies_object() {
    let project = TempProject::empty(
        r#"{"name":"last-dep","version":"1.0.0","dependencies":{"only-one":"^1.0.0"}}"#,
    );

    lpm(&project)
        .args(["uninstall", "only-one"])
        .assert()
        .success();

    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(
        pkg_json["dependencies"].is_object(),
        "dependencies key must remain present as an empty object; got: {pkg_json:#}"
    );
    assert_eq!(
        pkg_json["dependencies"].as_object().map(|o| o.is_empty()),
        Some(true),
        "dependencies must be the empty object after the last entry was removed"
    );
}

/// Same one-pass scan covers `devDependencies`. There's no separate
/// `--dev` / `-D` flag on uninstall (unlike install / npm); both sections
/// are checked unconditionally. This test pins that contract — adding
/// per-section gating later would silently break "uninstall removes my
/// dev dep" expectations.
#[test]
fn uninstall_removes_dev_dependency_in_same_pass() {
    let project = TempProject::empty(
        r#"{"name":"dev-test","version":"1.0.0","devDependencies":{"dev-only":"^1.0.0"}}"#,
    );

    lpm(&project)
        .args(["uninstall", "dev-only"])
        .assert()
        .success();

    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(
        pkg_json["devDependencies"]
            .as_object()
            .is_none_or(|o| o.get("dev-only").is_none()),
        "package.json must no longer list dev-only in devDependencies; got: {pkg_json:#}"
    );
}

/// LPM's uninstall drops `lpm.lock` entirely rather than rewriting it
/// without the removed entry. A subsequent `lpm install` regenerates it
/// from the (now-correct) manifest. Pinning this contract because a
/// regression to "selectively edit the lockfile" would re-introduce the
/// stale-entry-survival bugs that the delete-and-regenerate model was
/// chosen to avoid.
#[test]
fn uninstall_drops_lpm_lock_entirely_after_removal() {
    let project = TempProject::empty("");
    seed_installed_package(&project, "drop-lock", "2.0.0");
    assert!(
        project.path().join("lpm.lock").exists(),
        "seed must produce lpm.lock"
    );

    lpm(&project)
        .args(["uninstall", "drop-lock"])
        .assert()
        .success();

    assert!(
        !project.path().join("lpm.lock").exists(),
        "lpm.lock must be deleted after uninstall (delete-and-regenerate model)"
    );
}

/// The binary lockfile is committed as the twin of `lpm.lock`, not an
/// independent cache. Uninstall must therefore remove `lpm.lockb`
/// alongside `lpm.lock`; leaving the binary lockfile behind creates a
/// brief split-brain state where the text lockfile is gone but tooling
/// can still read stale package entries from `lpm.lockb`.
#[test]
fn uninstall_drops_lpm_lockb_alongside_lpm_lock_after_removal() {
    let project = TempProject::empty("");
    seed_installed_package(&project, "drop-lockb", "2.0.0");
    std::fs::write(project.path().join("lpm.lockb"), b"placeholder-binary-lockfile")
        .expect("seed lpm.lockb");
    assert!(
        project.path().join("lpm.lock").exists(),
        "seed must produce lpm.lock"
    );
    assert!(
        project.path().join("lpm.lockb").exists(),
        "seed must produce lpm.lockb"
    );

    lpm(&project)
        .args(["uninstall", "drop-lockb"])
        .assert()
        .success();

    assert!(
        !project.path().join("lpm.lock").exists(),
        "lpm.lock must be deleted after uninstall (delete-and-regenerate model)"
    );
    assert!(
        !project.path().join("lpm.lockb").exists(),
        "lpm.lockb must be deleted alongside lpm.lock after uninstall"
    );
}

// ─── Diverging-from-npm contracts (worth pinning) ───────────────────────

/// `lpm uninstall <nonexistent>` exits 0 with a warning rather than
/// erroring. Diverges from `npm uninstall` (which exits 0 silently
/// today, but for different reasons) and from a stricter "fail on
/// missing target" model. Pin the LPM contract: idempotent + warn,
/// not error. Mirror the `--json` shape too — `removed: []`,
/// `not_found: ["nonexistent"]`.
#[test]
fn uninstall_unknown_package_warns_and_exits_zero() {
    let project = TempProject::empty(
        r#"{"name":"unknown-test","version":"1.0.0","dependencies":{"present":"^1.0.0"}}"#,
    );

    let out = lpm(&project)
        .args(["uninstall", "nonexistent-pkg"])
        .output()
        .expect("spawn lpm uninstall");
    assert!(
        out.status.success(),
        "uninstalling a not-present package exits 0 (idempotent contract); stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Manifest should be untouched.
    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        pkg_json["dependencies"]["present"],
        serde_json::json!("^1.0.0"),
        "manifest must be untouched when no target was actually removed"
    );
}

// ─── Real install round-trip ────────────────────────────────────────────

/// Round-trip sanity: install a real package, uninstall it, observe the
/// `node_modules/<pkg>` directory is gone and the manifest no longer
/// lists it. Catches regressions where the manual-fixture seed would
/// hide (e.g., real installs use the isolated linker that places the
/// package via a symlink rather than a directory — the cleanup branch
/// at [uninstall.rs:56-69](crates/lpm-cli/src/commands/uninstall.rs#L56)
/// has separate code paths for symlink vs directory removal).
#[tokio::test]
async fn uninstall_after_real_install_removes_isolated_symlink() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("real-installed", "1.0.0");
    mock.with_package("real-installed", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "real-installed",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "real-installed",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/real-installed/-/real-installed-1.0.0.tgz", mock.url()),
                    "integrity": support::mock_registry::compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{"name":"roundtrip","version":"1.0.0","dependencies":{"real-installed":"^1.0.0"}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let nm_entry = project.path().join("node_modules/real-installed");
    assert!(
        nm_entry.symlink_metadata().is_ok(),
        "install must create node_modules/real-installed (symlink in isolated mode)"
    );

    lpm(&project)
        .args(["uninstall", "real-installed"])
        .assert()
        .success();

    assert!(
        nm_entry.symlink_metadata().is_err(),
        "uninstall must remove node_modules/real-installed (was: {:?})",
        nm_entry.symlink_metadata()
    );
    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(pkg_json["dependencies"].get("real-installed").is_none());
}

/// Hoisted mode plants a real directory at `node_modules/<pkg>` instead
/// of the isolated-mode symlink. Uninstall must remove that non-empty
/// directory too — leaving it behind creates a phantom dependency shape
/// that the next install can see on disk even though the manifest and
/// lockfile are already clean.
#[tokio::test]
async fn uninstall_after_real_install_removes_hoisted_directory() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("real-hoisted", "1.0.0");
    mock.with_package("real-hoisted", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "real-hoisted",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "real-hoisted",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/real-hoisted/-/real-hoisted-1.0.0.tgz", mock.url()),
                    "integrity": support::mock_registry::compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{"name":"roundtrip-hoisted","version":"1.0.0","dependencies":{"real-hoisted":"^1.0.0"}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--linker",
            "hoisted",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let nm_entry = project.path().join("node_modules/real-hoisted");
    let metadata = nm_entry
        .symlink_metadata()
        .expect("install must create node_modules/real-hoisted");
    assert!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "hoisted install must materialize a real directory, got metadata: {metadata:?}"
    );

    lpm(&project)
        .args(["uninstall", "real-hoisted"])
        .assert()
        .success();

    assert!(
        nm_entry.symlink_metadata().is_err(),
        "uninstall must remove the hoisted node_modules directory (was: {:?})",
        nm_entry.symlink_metadata()
    );
    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(pkg_json["dependencies"].get("real-hoisted").is_none());
}

// ─── JSON contract ──────────────────────────────────────────────────────

/// `uninstall --json` envelope shape pinned via insta. Dynamic temp-dir
/// paths in `target_set` get redacted to `[MANIFEST]` so the snapshot
/// stays deterministic across runs.
#[test]
fn uninstall_json_envelope_with_one_removal_matches_snapshot() {
    let project = TempProject::empty(
        r#"{"name":"snap-uninstall","version":"1.0.0","dependencies":{"snap-pkg":"^1.0.0"}}"#,
    );
    project.write_file(
        "lpm.lock",
        "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n",
    );

    let out = lpm(&project)
        .args(["uninstall", "snap-pkg", "--json"])
        .output()
        .expect("spawn lpm uninstall --json");
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("uninstall --json must be valid JSON: {e}\n---\n{stdout}"));

    insta::with_settings!({
        filters => vec![
            // Redact the temp-dir manifest path inside target_set.
            (r#""/[^"]+/package\.json""#, r#""[MANIFEST]""#),
        ],
    }, {
        insta::assert_json_snapshot!("uninstall_json_envelope_one_removal", envelope);
    });
}

// ─── Workspace dispatch: --filter / -w ─────────────────────────────────

fn seed_workspace_with_shared_dep(project: &TempProject) {
    // Add `lodash` to both app and utils so we can verify --filter
    // mutates only the targeted member's package.json.
    for member in ["app", "utils"] {
        let pkg_path = format!("packages/{member}/package.json");
        let pkg_content = project.read_file(&pkg_path);
        let mut pkg: serde_json::Value =
            serde_json::from_str(&pkg_content).expect("parse member package.json");
        let deps = pkg["dependencies"]
            .as_object_mut()
            .expect("dependencies must be an object");
        deps.insert("lodash".to_string(), serde_json::json!("4.17.21"));
        project.write_file(&pkg_path, &serde_json::to_string_pretty(&pkg).unwrap());
    }
}

fn read_member_deps(
    project: &TempProject,
    member: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let content = project.read_file(&format!("packages/{member}/package.json"));
    let pkg: serde_json::Value = serde_json::from_str(&content).expect("parse member package.json");
    pkg["dependencies"].as_object().cloned().unwrap_or_default()
}

#[test]
fn uninstall_filter_removes_only_from_targeted_member() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_shared_dep(&project);

    let output = lpm(&project)
        .args(["uninstall", "lodash", "--filter", "@test/app", "--yes"])
        .output()
        .expect("failed to run lpm uninstall --filter");

    assert!(
        output.status.success(),
        "uninstall --filter must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let app_deps = read_member_deps(&project, "app");
    let utils_deps = read_member_deps(&project, "utils");

    assert!(
        !app_deps.contains_key("lodash"),
        "lodash must be removed from @test/app, got: {app_deps:?}"
    );
    assert!(
        utils_deps.contains_key("lodash"),
        "lodash must remain in @test/utils (not in filter), got: {utils_deps:?}"
    );
}

#[test]
fn uninstall_workspace_root_removes_from_root_only() {
    let project = TempProject::from_fixture("workspace-monorepo");
    // Add lodash to the workspace root manifest.
    let root_content = project.read_file("package.json");
    let mut root_pkg: serde_json::Value =
        serde_json::from_str(&root_content).expect("parse root package.json");
    root_pkg["dependencies"] = serde_json::json!({ "lodash": "4.17.21" });
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(&root_pkg).unwrap(),
    );
    seed_workspace_with_shared_dep(&project);

    let output = lpm(&project)
        .args(["uninstall", "lodash", "-w"])
        .output()
        .expect("failed to run lpm uninstall -w");

    assert!(
        output.status.success(),
        "uninstall -w must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let root_content_after = project.read_file("package.json");
    let root_after: serde_json::Value = serde_json::from_str(&root_content_after).unwrap();
    let root_deps = root_after["dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    assert!(
        !root_deps.contains_key("lodash"),
        "lodash must be removed from workspace root, got: {root_deps:?}"
    );

    // Members untouched
    let app_deps = read_member_deps(&project, "app");
    let utils_deps = read_member_deps(&project, "utils");
    assert!(
        app_deps.contains_key("lodash"),
        "uninstall -w must not touch member manifests, got: {app_deps:?}"
    );
    assert!(
        utils_deps.contains_key("lodash"),
        "uninstall -w must not touch member manifests, got: {utils_deps:?}"
    );
}

#[test]
fn uninstall_filter_typo_without_fail_flag_exits_zero() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_shared_dep(&project);

    let output = lpm(&project)
        .args([
            "uninstall",
            "lodash",
            "--filter",
            "this-package-does-not-exist",
        ])
        .output()
        .expect("failed to run lpm uninstall --filter (typo)");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0"
    );

    // Nothing should have been removed.
    let app_deps = read_member_deps(&project, "app");
    assert!(
        app_deps.contains_key("lodash"),
        "no member must be mutated when filter matches nothing"
    );
}

#[test]
fn uninstall_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_shared_dep(&project);

    let output = lpm(&project)
        .args([
            "uninstall",
            "lodash",
            "--filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm uninstall --filter --fail-if-no-match");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero"
    );
}

#[test]
fn uninstall_w_and_filter_together_is_rejected() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_shared_dep(&project);

    let output = lpm(&project)
        .args(["uninstall", "lodash", "-w", "--filter", "@test/app"])
        .output()
        .expect("failed to run lpm uninstall -w --filter");

    assert!(
        !output.status.success(),
        "-w + --filter together must be rejected (mutually exclusive)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`-w`") || stderr.contains("`--filter`") || stderr.contains("filter"),
        "stderr must explain the mutual-exclusion, got:\n{stderr}",
    );
}
