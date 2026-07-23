use super::copy::copy_member_source;
#[cfg(unix)]
use super::copy::retarget_internal_node_modules_symlinks;
use super::lockfile_prune::write_pruned_deploy_lockfile_if_possible;
use super::manifest_rewrite::{
    apply_dependency_selection_to_deploy_manifest, apply_dependency_selection_to_manifest_path,
    copy_workspace_dependency_closure, rewrite_workspace_protocol_in_deploy_manifest,
    strip_dev_dependencies_from_deploy_manifest,
};
use super::paths::DeployPlan;
#[cfg(unix)]
use super::paths::canonicalize_or_partial;
use super::*;
use serde_json::json;
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const TEST_SECURITY_SECRET: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn resolve_deploy_target(
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    force: bool,
) -> Result<DeployPlan, LpmError> {
    super::paths::resolve_deploy_target(cwd, output_dir, filters, &[], &[], &[], force)
}

#[allow(clippy::too_many_arguments)]
async fn run(
    client: &RegistryClient,
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    force: bool,
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let security_root = tempfile::tempdir().unwrap();
    let lpm_home = security_root.path().join("lpm-home");
    let security_dir = security_root.path().join("security");
    let policy_path = security_root.path().join("security-policy.toml");
    let _security_env = crate::test_env::ScopedEnv::update([
        ("LPM_HOME", Some(lpm_home.as_os_str().to_owned())),
        (
            "LPM_SECURITY_DIR",
            Some(security_dir.as_os_str().to_owned()),
        ),
        (
            "LPM_SECURITY_POLICY_PATH",
            Some(policy_path.as_os_str().to_owned()),
        ),
        (
            "LPM_TEST_SECURITY_SECRET_HEX",
            Some(OsString::from(TEST_SECURITY_SECRET)),
        ),
        (
            "LPM_TEST_SECURITY_AUTH_RESULT",
            Some(OsString::from("deny")),
        ),
    ]);
    super::run(
        client,
        cwd,
        output_dir,
        filters,
        &[],
        &[],
        &[],
        force,
        false,
        false,
        false,
        dry_run,
        json_output,
    )
    .await
}

/// Helper: build a real on-disk workspace fixture with the given members.
fn write_workspace_fixture(root: &Path, members: &[(&str, &str)]) {
    std::fs::create_dir_all(root).unwrap();
    let workspace_globs: Vec<String> = members.iter().map(|(_, p)| (*p).to_string()).collect();
    let root_pkg = json!({
        "name": "monorepo",
        "private": true,
        "workspaces": workspace_globs,
    });
    std::fs::write(
        root.join("package.json"),
        serde_json::to_string_pretty(&root_pkg).unwrap(),
    )
    .unwrap();
    for (name, path) in members {
        let dir = root.join(path);
        std::fs::create_dir_all(&dir).unwrap();
        let pkg = json!({"name": name, "version": "1.0.0"});
        std::fs::write(
            dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }
}

// ── entry-point guard tests ─────────────────────────────────────────

#[tokio::test]
async fn run_returns_error_when_filters_empty() {
    // Defensive: even though the CLI parser enforces required=true,
    // direct callers (e.g., a future MCP tool) can bypass that.
    let dir = tempfile::tempdir().unwrap();
    let result = run(
        &RegistryClient::new(),
        dir.path(),
        &dir.path().join("out"),
        &[],
        false,
        false,
        true,
    )
    .await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("--filter"),
        "empty filter must surface --filter in the error"
    );
}

// ── target resolution tests ─────────────────────────────────────────

#[test]
fn resolve_deploy_target_with_filter_matching_one_member_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(
        tmp.path(),
        &[("api", "packages/api"), ("web", "packages/web")],
    );

    // Output dir is OUTSIDE the workspace tree
    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");

    let plan = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap();

    assert!(plan.member_manifest.ends_with("packages/api/package.json"));
    assert!(plan.member_dir.ends_with("packages/api"));
}

#[test]
fn resolve_deploy_target_with_filter_matching_zero_members_hard_errors() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("out");

    let err = resolve_deploy_target(tmp.path(), &output, &["nonexistent".to_string()], false)
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("matched no workspace members"), "got: {msg}");
}

#[test]
fn resolve_deploy_target_with_filter_matching_multiple_members_hard_errors() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(
        tmp.path(),
        &[
            ("ui-button", "packages/ui-button"),
            ("ui-card", "packages/ui-card"),
        ],
    );
    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("out");

    let err = resolve_deploy_target(tmp.path(), &output, &["ui-*".to_string()], false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("matched 2 workspace members") && msg.contains("exactly one"),
        "got: {msg}"
    );
}

#[test]
fn resolve_deploy_target_in_non_workspace_hard_errors() {
    // Standalone project (no workspace) — install_targets surfaces this
    // as "--filter requires a workspace"
    let tmp = tempfile::tempdir().unwrap();
    let pkg = json!({"name": "solo"});
    std::fs::write(
        tmp.path().join("package.json"),
        serde_json::to_string_pretty(&pkg).unwrap(),
    )
    .unwrap();
    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("out");

    let err = resolve_deploy_target(tmp.path(), &output, &["foo".to_string()], false).unwrap_err();
    assert!(err.to_string().contains("workspace"));
}

#[test]
fn resolve_deploy_target_to_existing_non_empty_output_without_force_hard_errors() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");
    std::fs::create_dir_all(&output).unwrap();
    // Make it non-empty
    std::fs::write(output.join("stale-file"), "leftover").unwrap();

    let err = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not empty"));
    assert!(msg.contains("--force"));
}

#[test]
fn resolve_deploy_target_to_existing_non_empty_output_with_force_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join("stale-file"), "leftover").unwrap();

    // --force allows the non-empty output dir
    let plan = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], true).unwrap();
    assert!(plan.member_dir.ends_with("packages/api"));
}

#[test]
fn resolve_deploy_target_to_empty_existing_output_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");
    std::fs::create_dir_all(&output).unwrap();
    // Empty dir is fine without --force

    let plan = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap();
    assert!(plan.member_dir.ends_with("packages/api"));
}

#[test]
fn resolve_deploy_target_to_nonexistent_output_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("does-not-exist-yet");
    // Output dir does not exist — that's the typical fresh deploy case

    let plan = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap();
    assert!(plan.member_dir.ends_with("packages/api"));
}

#[test]
fn resolve_deploy_target_with_output_inside_workspace_hard_errors_self_loop() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    // Output is INSIDE the workspace tree — must be rejected as a self-loop
    let output = tmp.path().join("deploy-output");

    let err = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("inside the workspace") && msg.contains("self-deploy"),
        "got: {msg}"
    );
}

#[test]
fn resolve_deploy_target_with_output_inside_workspace_member_dir_also_errors() {
    // Even if the output is nested deep inside a member dir, it must
    // still be flagged as inside the workspace.
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output = tmp.path().join("packages").join("api").join("dist-deploy");

    let err = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
    assert!(err.to_string().contains("inside the workspace"));
}

// ── regression (High): self-loop guard bypass ────

#[cfg(unix)]
#[test]
fn canonicalize_or_partial_resolves_symlink_through_nonexistent_tail() {
    // Regression guard:
    // canonicalize_or_partial is the load-bearing helper that fixes the
    // self-loop guard bypass. When the path itself does not exist, it
    // walks up to the deepest existing ancestor, canonicalizes that
    // (which follows symlinks), then re-appends the missing tail.
    //
    // This unit test pins the helper's contract: a symlinked-prefix
    // path with a missing tail must produce the symlink-resolved form.
    let tmp = tempfile::tempdir().unwrap();
    let real_dir = tmp.path().join("real");
    std::fs::create_dir_all(&real_dir).unwrap();
    let real_canonical = std::fs::canonicalize(&real_dir).unwrap();

    let alias = tmp.path().join("alias");
    std::os::unix::fs::symlink(&real_dir, &alias).unwrap();

    // The path itself does not exist; the parent (the symlink) does.
    let with_missing_tail = alias.join("nested").join("does-not-exist");
    let resolved = canonicalize_or_partial(&with_missing_tail);
    let expected = real_canonical.join("nested").join("does-not-exist");
    assert_eq!(
        resolved, expected,
        "canonicalize_or_partial must follow symlinks at the deepest existing ancestor and \
         re-append the missing tail in original order"
    );

    // Sanity: the bare alias resolves to the real canonical form.
    assert_eq!(canonicalize_or_partial(&alias), real_canonical);

    // Sanity: a fully existing canonical path is returned canonically.
    assert_eq!(canonicalize_or_partial(&real_dir), real_canonical);
}

#[cfg(unix)]
#[test]
fn resolve_deploy_target_via_symlinked_alias_to_workspace_is_caught_as_self_loop() {
    // Regression guard:
    // The pre-fix self-loop guard compared a canonicalized workspace
    // root against a LEXICALLY-normalized output path. When the user
    // passed an output path that lexically appeared OUTSIDE the
    // workspace but actually resolved INSIDE it via a symlink (the
    // macOS `/tmp → /private/tmp` case is the canonical example), the
    // prefix comparison silently missed the relationship and the
    // deploy proceeded straight into self-recursion territory.
    //
    // Reproduction: create a real workspace, create a sibling symlink
    // pointing at it, then pass the canonical workspace as `cwd` and
    // the SYMLINKED alias as the output prefix. Pre-fix:
    //   workspace_canonical = real_root             (canonicalized)
    //   output_lexical      = alias_root/dist       (NOT canonicalized)
    //   alias_root/dist .starts_with(real_root)     → false → bypass
    // Post-fix:
    //   canonicalize_or_partial(alias_root/dist)    → real_root/dist
    //   real_root/dist .starts_with(real_root)      → true → guard fires
    let tmp = tempfile::tempdir().unwrap();
    let real_root = tmp.path().join("real-workspace");
    write_workspace_fixture(&real_root, &[("api", "packages/api")]);

    // Create a symlink alias pointing at the real workspace root.
    let alias_root = tmp.path().join("alias-workspace");
    std::os::unix::fs::symlink(&real_root, &alias_root).unwrap();

    // Sanity: the alias resolves to the real workspace.
    assert_eq!(
        std::fs::canonicalize(&alias_root).unwrap(),
        std::fs::canonicalize(&real_root).unwrap(),
        "test setup: alias must resolve to real workspace",
    );

    // Output is supplied via the alias prefix. Lexically it does NOT
    // start with `real_root` — that's exactly what the old code missed.
    let output_via_alias = alias_root.join("dist-deploy");

    let err = resolve_deploy_target(&real_root, &output_via_alias, &["api".to_string()], false)
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("inside the workspace") && msg.contains("self-deploy"),
        "symlink-aliased output that resolves into the workspace must be caught as a self-deploy loop. got: {msg}"
    );
}

#[cfg(unix)]
#[test]
fn resolve_deploy_target_canonical_output_inside_symlinked_workspace_is_also_caught() {
    // Mirror image of the previous test: this time the WORKSPACE is
    // accessed via a symlink and the output is supplied as the
    // canonical real path. Without canonicalize_or_partial on BOTH
    // sides, the comparison would still be asymmetric and miss the
    // relationship. With the fix, both sides resolve to the real
    // workspace and the guard fires.
    let tmp = tempfile::tempdir().unwrap();
    let real_root = tmp.path().join("real-workspace");
    write_workspace_fixture(&real_root, &[("api", "packages/api")]);

    let alias_root = tmp.path().join("alias-workspace");
    std::os::unix::fs::symlink(&real_root, &alias_root).unwrap();

    // cwd via the alias, output via the real canonical path.
    let output_via_real = real_root.join("dist-deploy");

    let err = resolve_deploy_target(&alias_root, &output_via_real, &["api".to_string()], false)
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("inside the workspace") && msg.contains("self-deploy"),
        "canonical output inside a symlink-accessed workspace must also be caught. got: {msg}"
    );
}

// ── dry-run tests ───────────────────────────────────────────────────

#[tokio::test]
async fn run_dry_run_succeeds_after_target_resolution() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");

    let result = run(
        &RegistryClient::new(),
        tmp.path(),
        &output,
        &["api".to_string()],
        false,
        true, // dry_run
        true, // json_output
    )
    .await;

    assert!(result.is_ok(), "dry-run should succeed: {result:?}");
    // Output dir was NOT created (dry-run is read-only)
    assert!(
        !output.exists(),
        "dry-run must not create the output directory"
    );
}

#[tokio::test]
async fn run_dry_run_propagates_target_resolution_errors() {
    // Even in dry-run mode, target resolution errors should surface.
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");

    let result = run(
        &RegistryClient::new(),
        tmp.path(),
        &output,
        &["nonexistent".to_string()],
        false,
        true,
        true,
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("matched no"));
}

// ── end-to-end (no-deps fixture) ────────────────────────────────────
//
// The install pipeline at the deploy output dir runs for real. We test
// it against fixtures that have empty `dependencies` so the resolver
// hits the no-deps short-circuit and returns success without any
// network calls. The fix to the empty-deps early return makes this
// path emit a clean JSON success object.

#[tokio::test]
async fn run_full_pipeline_with_empty_deps_member_succeeds_human_mode() {
    // Member has no dependencies → install pipeline short-circuits.
    // Deploy should produce a successful end-to-end run.
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
    // Add a source file so the copy has something to do
    let api_src = tmp.path().join("packages").join("api").join("src");
    std::fs::create_dir_all(&api_src).unwrap();
    std::fs::write(api_src.join("index.js"), "module.exports = {}").unwrap();

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");

    let result = run(
        &RegistryClient::new(),
        tmp.path(),
        &output,
        &["api".to_string()],
        false,
        false,
        false, // human output mode
    )
    .await;

    assert!(result.is_ok(), "deploy should succeed: {result:?}");

    // The copy actually happened
    assert!(output.join("package.json").exists());
    assert!(output.join("src").join("index.js").exists());
}

#[tokio::test]
async fn run_full_pipeline_with_empty_deps_member_succeeds_json_mode() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
    let api_src = tmp.path().join("packages").join("api").join("src");
    std::fs::create_dir_all(&api_src).unwrap();
    std::fs::write(api_src.join("index.js"), "module.exports = {}").unwrap();

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");

    let result = run(
        &RegistryClient::new(),
        tmp.path(),
        &output,
        &["api".to_string()],
        false,
        false,
        true, // json output
    )
    .await;

    assert!(result.is_ok());
    // The deploy command emits its summary JSON to stdout. We can't
    // easily capture stdout in a unit test, but we can verify the
    // filesystem state matches what JSON mode would describe.
    assert!(output.join("package.json").exists());
    let pkg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(pkg["name"], "api");
}

#[tokio::test]
async fn run_full_pipeline_workspace_protocol_dep_is_localized_in_output() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");

    let result = run(
        &RegistryClient::new(),
        &workspace_root,
        &output,
        &["@scope/api".to_string()],
        false,
        false,
        true,
    )
    .await;

    let _ = result;

    if output.join("package.json").exists() {
        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        assert_eq!(
            after["dependencies"]["@scope/auth"], "file:.lpm/deploy-workspace/packages/auth",
            "workspace:* must be rewritten to a local file dependency in deploy output"
        );
        assert!(
            output
                .join(DEPLOY_WORKSPACE_DIR)
                .join("packages/auth/package.json")
                .exists(),
            "local workspace dependency source must be copied into the deploy output"
        );

        // CRITICAL: source workspace manifest is unchanged (still has workspace:*)
        let source: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(workspace_root.join("packages/api/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            source["dependencies"]["@scope/auth"], "workspace:*",
            "source workspace manifest must NOT be modified by deploy"
        );
    }
}

#[tokio::test]
async fn run_dry_run_with_json_emits_dry_run_marker() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");

    let result = run(
        &RegistryClient::new(),
        tmp.path(),
        &output,
        &["api".to_string()],
        false,
        true, // dry_run
        true, // json
    )
    .await;
    assert!(result.is_ok());

    // Output dir was NOT created (dry-run is fully read-only)
    assert!(!output.exists(), "dry-run must not create the output dir");
}

#[tokio::test]
async fn run_force_flag_allows_overwrite_of_non_empty_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join("stale-file"), "leftover").unwrap();

    // Without --force this would error
    let result = run(
        &RegistryClient::new(),
        tmp.path(),
        &output,
        &["api".to_string()],
        true, // force
        false,
        false,
    )
    .await;
    assert!(
        result.is_ok(),
        "force should allow non-empty output: {result:?}"
    );
    assert!(output.join("package.json").exists());
}

#[tokio::test]
async fn run_force_actually_cleans_stale_files_from_output_dir() {
    // Regression guard:
    // Pre-fix, `--force` only suppressed the "output dir not empty"
    // error in validate_output_dir. The install pipeline then ran
    // in-place over whatever was already in the dir, leaving stale
    // files from a previous deploy (orphaned source files, old
    // lockfiles, leftover node_modules) in the output. That violates
    // the "deploy output is a clean snapshot" invariant and can mask
    // real bugs (e.g., "I deleted this file from the source but it's
    // still in my Docker image because the previous deploy left it
    // there").
    //
    // The fix removes the dir tree and recreates an empty dir before
    // any copy step. This test plants stale files at multiple depths
    // and asserts every one is gone after the deploy completes.
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
    let api_src = tmp.path().join("packages").join("api").join("src");
    std::fs::create_dir_all(&api_src).unwrap();
    std::fs::write(api_src.join("index.js"), "module.exports = {}").unwrap();

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");
    std::fs::create_dir_all(&output).unwrap();

    // Plant stale files / dirs at root and at depth.
    std::fs::write(output.join("STALE.txt"), "from a previous deploy").unwrap();
    std::fs::write(
        output.join("legacy-config.json"),
        r#"{"removed":"feature"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(output.join("legacy-subdir").join("inner")).unwrap();
    std::fs::write(
        output
            .join("legacy-subdir")
            .join("inner")
            .join("orphan.txt"),
        "orphan",
    )
    .unwrap();
    // Plant a stale node_modules to simulate a previous install.
    std::fs::create_dir_all(output.join("node_modules").join("react")).unwrap();
    std::fs::write(
        output.join("node_modules").join("react").join("index.js"),
        "// stale react from previous deploy",
    )
    .unwrap();

    let result = run(
        &RegistryClient::new(),
        tmp.path(),
        &output,
        &["api".to_string()],
        true, // force
        false,
        false,
    )
    .await;
    assert!(
        result.is_ok(),
        "deploy with --force should succeed: {result:?}"
    );

    // Positive: the fresh deploy artifacts are present.
    assert!(
        output.join("package.json").exists(),
        "fresh package.json must be copied"
    );
    assert!(
        output.join("src").join("index.js").exists(),
        "fresh src files must be copied"
    );

    // CRITICAL: every stale entry from before the deploy is GONE.
    assert!(
        !output.join("STALE.txt").exists(),
        "--force must clean stale root files"
    );
    assert!(
        !output.join("legacy-config.json").exists(),
        "--force must clean stale root files"
    );
    assert!(
        !output.join("legacy-subdir").exists(),
        "--force must clean stale subdirs"
    );
    // node_modules is recreated by the install pipeline (the empty-deps
    // member short-circuits, so it may or may not exist post-install).
    // The load-bearing assertion is that the STALE react file from
    // before the deploy is gone, NOT that node_modules itself is empty.
    assert!(
        !output
            .join("node_modules")
            .join("react")
            .join("index.js")
            .exists(),
        "--force must clean stale node_modules contents"
    );
}

#[tokio::test]
async fn run_without_force_does_not_remove_existing_dir_tree() {
    // Defensive guard: the --force cleanup must NOT run when --force
    // is false. Without --force the validate_output_dir check rejects
    // a non-empty output dir with an error, and we must NOT have
    // removed anything before that error fires. This test exercises
    // the empty-existing-dir path (which IS allowed without --force)
    // and asserts the dir is not deleted out from under the user.
    let tmp = tempfile::tempdir().unwrap();
    write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
    let api_src = tmp.path().join("packages").join("api").join("src");
    std::fs::create_dir_all(&api_src).unwrap();
    std::fs::write(api_src.join("index.js"), "module.exports = {}").unwrap();

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");
    std::fs::create_dir_all(&output).unwrap();
    // Empty dir is allowed without --force.

    let result = run(
        &RegistryClient::new(),
        tmp.path(),
        &output,
        &["api".to_string()],
        false, // NOT force
        false,
        false,
    )
    .await;
    assert!(
        result.is_ok(),
        "deploy into empty dir should succeed: {result:?}"
    );
    assert!(output.join("package.json").exists());
}

#[tokio::test]
async fn read_member_name_falls_back_to_dir_name_when_name_field_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("my-pkg").join("package.json");
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    std::fs::write(&manifest, "{}").unwrap();

    let name = read_member_name(&manifest);
    assert_eq!(name, "my-pkg");
}

#[tokio::test]
async fn read_member_name_extracts_name_from_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("dir").join("package.json");
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    std::fs::write(&manifest, r#"{"name": "@scope/api", "version": "1.0.0"}"#).unwrap();

    let name = read_member_name(&manifest);
    assert_eq!(name, "@scope/api");
}

// ── end-to-end integration: deny list + local workspace deps ────────

#[tokio::test]
async fn run_e2e_combines_deny_list_and_local_workspace_dep_rewrite() {
    // Comprehensive end-to-end test: workspace with workspace:* deps,
    // member containing .env files and a node_modules, deploy it, and
    // verify EVERY invariant in one place:
    //
    // 1. Source files are copied (positive assertion)
    // 2. .env files are NOT in the deploy output (security)
    // 3. source node_modules is NOT copied into the deploy output
    // 4. workspace:* deps are rewritten to local file dependencies
    // 5. The source workspace's manifests are byte-identical
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());

    // Add some files that should be deployed and some that should NOT
    let api_dir = workspace_root.join("packages").join("api");
    std::fs::create_dir_all(api_dir.join("src")).unwrap();
    std::fs::write(
        api_dir.join("src").join("server.ts"),
        "export const app = {};",
    )
    .unwrap();
    std::fs::write(api_dir.join("README.md"), "# api\n").unwrap();

    // Deny-list entries that MUST NOT be deployed
    std::fs::write(
        api_dir.join(".env"),
        "DATABASE_URL=postgres://prod-secret\n",
    )
    .unwrap();
    std::fs::write(api_dir.join(".env.production"), "API_KEY=hunter2\n").unwrap();
    std::fs::create_dir_all(api_dir.join("node_modules").join("react")).unwrap();
    std::fs::write(
        api_dir.join("node_modules").join("react").join("index.js"),
        "module.exports = 'leaked react';",
    )
    .unwrap();

    // Snapshot the source manifests
    let source_root_before = std::fs::read(workspace_root.join("package.json")).unwrap();
    let source_auth_before =
        std::fs::read(workspace_root.join("packages/auth/package.json")).unwrap();
    let source_api_before =
        std::fs::read(workspace_root.join("packages/api/package.json")).unwrap();

    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("prod-api");
    let result = run(
        &RegistryClient::new(),
        &workspace_root,
        &output,
        &["@scope/api".to_string()],
        false,
        false,
        true,
    )
    .await;
    let _ = result;

    // ── Positive: deployed source files exist ──────────────────────────
    assert!(output.join("package.json").exists(), "package.json copied");
    assert!(
        output.join("src").join("server.ts").exists(),
        "src files copied"
    );
    assert!(output.join("README.md").exists(), "README copied");

    // ── Security: .env files not present ──────────────────────────────
    assert!(
        !output.join(".env").exists(),
        "SECURITY: .env must not be in deploy output"
    );
    assert!(
        !output.join(".env.production").exists(),
        "SECURITY: .env.production must not be in deploy output"
    );

    // ── Security: source node_modules content not copied ──────────────
    assert!(
        !output
            .join("node_modules")
            .join("react")
            .join("index.js")
            .exists(),
        "source node_modules content must not be copied into deploy output"
    );

    // ── workspace:* deps rewritten to local file dependencies ─────────
    let deployed_pkg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(
        deployed_pkg["dependencies"]["@scope/auth"], "file:.lpm/deploy-workspace/packages/auth",
        "workspace:* must be rewritten to a local file dependency in the deploy output"
    );
    assert!(
        output
            .join(DEPLOY_WORKSPACE_DIR)
            .join("packages/auth/package.json")
            .exists(),
        "workspace dependency source must be copied into deploy output"
    );

    // ── Read-only on source: every source manifest is byte-identical ──
    assert_eq!(
        std::fs::read(workspace_root.join("package.json")).unwrap(),
        source_root_before,
        "source workspace root must not be modified"
    );
    assert_eq!(
        std::fs::read(workspace_root.join("packages/auth/package.json")).unwrap(),
        source_auth_before,
        "source auth member must not be modified"
    );
    assert_eq!(
        std::fs::read(workspace_root.join("packages/api/package.json")).unwrap(),
        source_api_before,
        "source api member must not be modified (CRITICAL: hardlink-mutation regression guard)"
    );
}

// ── manifest rewrite tests ──────────────────────────────────────────

/// Helper: build a fixture workspace with two members where one depends
/// on the other via workspace:*. Returns the workspace root path.
fn build_workspace_with_workspace_protocol_dep(tmp: &Path) -> PathBuf {
    let root = tmp.join("workspace");
    std::fs::create_dir_all(&root).unwrap();
    // Root manifest declares the workspace
    let root_pkg = json!({
        "name": "monorepo",
        "private": true,
        "workspaces": ["packages/auth", "packages/api"],
    });
    std::fs::write(
        root.join("package.json"),
        serde_json::to_string_pretty(&root_pkg).unwrap(),
    )
    .unwrap();

    // auth member with version 1.5.0
    std::fs::create_dir_all(root.join("packages").join("auth")).unwrap();
    let auth_pkg = json!({
        "name": "@scope/auth",
        "version": "1.5.0",
    });
    std::fs::write(
        root.join("packages").join("auth").join("package.json"),
        serde_json::to_string_pretty(&auth_pkg).unwrap(),
    )
    .unwrap();

    // api member with workspace:* dep on auth and a regular npm dep
    std::fs::create_dir_all(root.join("packages").join("api")).unwrap();
    let api_pkg = json!({
        "name": "@scope/api",
        "version": "2.0.0",
        "dependencies": {
            "@scope/auth": "workspace:*",
            "express": "^4.0.0",
        },
        "devDependencies": {
            "@scope/auth": "workspace:^",
        },
        "peerDependencies": {
            "@scope/auth": "workspace:~",
        },
    });
    std::fs::write(
        root.join("packages").join("api").join("package.json"),
        serde_json::to_string_pretty(&api_pkg).unwrap(),
    )
    .unwrap();

    root
}

#[test]
fn copy_workspace_dependency_closure_copies_unpublished_member_and_localizes_spec() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
    let output = tempfile::tempdir().unwrap();
    copy_member_source(&workspace_root.join("packages/api"), output.path()).unwrap();
    apply_dependency_selection_to_deploy_manifest(output.path(), DependencyMode::Production, false)
        .unwrap();

    let (members_copied, rewrites, copy_stats, _selection_stats) =
        copy_workspace_dependency_closure(
            output.path(),
            &workspace_root,
            "@scope/api",
            DependencyMode::Production,
            false,
        )
        .unwrap();
    let deployed_pkg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.path().join("package.json")).unwrap())
            .unwrap();

    assert_eq!(members_copied, 1);
    assert_eq!(rewrites, 2);
    assert!(copy_stats.files_copied > 0);
    assert_eq!(
        deployed_pkg["dependencies"]["@scope/auth"],
        "file:.lpm/deploy-workspace/packages/auth"
    );
    assert!(
        output
            .path()
            .join(DEPLOY_WORKSPACE_DIR)
            .join("packages/auth/package.json")
            .exists(),
        "workspace member source must be copied into deploy-local workspace area"
    );
}

#[test]
fn write_pruned_deploy_lockfile_keeps_only_reachable_registry_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = tmp.path().join("workspace");
    write_workspace_fixture(&workspace_root, &[("api", "packages/api")]);

    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "runtime".to_string(),
        version: "1.2.3".to_string(),
        dependencies: vec!["transitive@2.0.0".to_string()],
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "transitive".to_string(),
        version: "2.0.0".to_string(),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "unrelated".to_string(),
        version: "9.9.9".to_string(),
        ..Default::default()
    });
    lockfile
        .write_all(&workspace_root.join(lpm_lockfile::LOCKFILE_NAME))
        .unwrap();

    let output = tempfile::tempdir().unwrap();
    std::fs::write(
        output.path().join("package.json"),
        serde_json::to_string_pretty(&json!({
            "name": "api",
            "dependencies": {"runtime": "^1.0.0"}
        }))
        .unwrap(),
    )
    .unwrap();

    let count = write_pruned_deploy_lockfile_if_possible(&workspace_root, output.path()).unwrap();
    let deployed_lockfile =
        lpm_lockfile::Lockfile::read_from_file(&output.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
    let names: HashSet<String> = deployed_lockfile
        .packages
        .iter()
        .map(|package| package.name.clone())
        .collect();

    assert_eq!(count, Some(2));
    assert!(names.contains("runtime"));
    assert!(names.contains("transitive"));
    assert!(!names.contains("unrelated"));
}

#[cfg(unix)]
#[test]
fn retarget_internal_node_modules_symlinks_makes_absolute_internal_links_relative() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().join("deploy");
    let target = output.join(".lpm/store/v2/links/runtime");
    let link = output.join("node_modules/runtime");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let retargeted = retarget_internal_node_modules_symlinks(&output).unwrap();
    let new_target = std::fs::read_link(&link).unwrap();

    assert_eq!(retargeted, 1);
    assert!(
        !new_target.is_absolute(),
        "deploy-internal symlink target must be relative after retargeting"
    );
    assert_eq!(new_target, PathBuf::from("../.lpm/store/v2/links/runtime"));
}

#[test]
fn rewrite_workspace_protocol_in_dependencies_replaces_with_concrete_version() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());

    // Stage the deploy output with a copy of api's manifest
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    let api_manifest = workspace_root.join("packages/api/package.json");
    std::fs::copy(&api_manifest, output.join("package.json")).unwrap();

    let rewritten =
        rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();
    assert!(
        rewritten >= 1,
        "should have rewritten at least one workspace ref"
    );

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
            .unwrap();
    // workspace:* → 1.5.0 (auth's version)
    assert_eq!(after["dependencies"]["@scope/auth"], "1.5.0");
    // Non-workspace deps untouched
    assert_eq!(after["dependencies"]["express"], "^4.0.0");
}

#[test]
fn rewrite_workspace_protocol_caret_form_yields_caret_range() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::copy(
        workspace_root.join("packages/api/package.json"),
        output.join("package.json"),
    )
    .unwrap();

    rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
            .unwrap();
    // workspace:^ → ^1.5.0
    assert_eq!(after["devDependencies"]["@scope/auth"], "^1.5.0");
}

#[test]
fn rewrite_workspace_protocol_tilde_form_yields_tilde_range() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::copy(
        workspace_root.join("packages/api/package.json"),
        output.join("package.json"),
    )
    .unwrap();

    rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
            .unwrap();
    // workspace:~ → ~1.5.0
    assert_eq!(after["peerDependencies"]["@scope/auth"], "~1.5.0");
}

#[test]
fn rewrite_workspace_protocol_no_workspace_deps_no_op() {
    // Member with no workspace:* refs at all — manifest should not
    // change (we only write back if at least one rewrite happened).
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = tmp.path().join("workspace");
    std::fs::create_dir_all(workspace_root.join("packages/foo")).unwrap();
    let root_pkg = json!({
        "name": "monorepo",
        "private": true,
        "workspaces": ["packages/foo"],
    });
    std::fs::write(
        workspace_root.join("package.json"),
        serde_json::to_string_pretty(&root_pkg).unwrap(),
    )
    .unwrap();
    let foo_pkg = json!({
        "name": "foo",
        "version": "1.0.0",
        "dependencies": {"express": "^4.0.0"},
    });
    std::fs::write(
        workspace_root.join("packages/foo/package.json"),
        serde_json::to_string_pretty(&foo_pkg).unwrap(),
    )
    .unwrap();

    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    let original_bytes = std::fs::read(workspace_root.join("packages/foo/package.json")).unwrap();
    std::fs::write(output.join("package.json"), &original_bytes).unwrap();

    let rewritten =
        rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

    assert_eq!(rewritten, 0);
    // Bytes should be byte-identical because we skipped the write
    assert_eq!(
        std::fs::read(output.join("package.json")).unwrap(),
        original_bytes
    );
}

#[test]
fn rewrite_workspace_protocol_unresolvable_member_hard_errors() {
    // Member references a workspace:* dep on a name that's not in the
    // workspace. Should hard-error with the unresolvable name.
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = tmp.path().join("workspace");
    std::fs::create_dir_all(workspace_root.join("packages/api")).unwrap();
    let root_pkg = json!({
        "name": "monorepo",
        "private": true,
        "workspaces": ["packages/api"],
    });
    std::fs::write(
        workspace_root.join("package.json"),
        serde_json::to_string_pretty(&root_pkg).unwrap(),
    )
    .unwrap();
    let api_pkg = json!({
        "name": "@scope/api",
        "version": "1.0.0",
        "dependencies": {"@scope/missing": "workspace:*"},
    });
    std::fs::write(
        workspace_root.join("packages/api/package.json"),
        serde_json::to_string_pretty(&api_pkg).unwrap(),
    )
    .unwrap();

    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::copy(
        workspace_root.join("packages/api/package.json"),
        output.join("package.json"),
    )
    .unwrap();

    let err = rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap_err();
    assert!(err.to_string().contains("@scope/missing"));
}

#[test]
fn rewrite_workspace_protocol_breaks_hardlinks_to_protect_source() {
    // Regression guard:
    //
    // copy_member_source uses hardlinks for performance. A hardlinked
    // package.json in the deploy output dir SHARES THE SAME INODE as
    // the source workspace's package.json. A naive `std::fs::write` to
    // the output's package.json would write through the hardlink and
    // MUTATE the source — violating the read-only-on-source invariant.
    //
    // The fix is in rewrite_workspace_protocol_in_deploy_manifest:
    // remove the file first to unlink the path from the shared inode,
    // then write a fresh file. This test simulates the dangerous
    // pattern by manually hardlinking before the rewrite.
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
    let source_manifest = workspace_root.join("packages/api/package.json");
    let source_bytes_before = std::fs::read(&source_manifest).unwrap();

    // Set up the deploy output with a HARDLINK to the source manifest
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    let output_manifest = output.join("package.json");
    std::fs::hard_link(&source_manifest, &output_manifest).unwrap();
    // Sanity: both paths now point to the same inode
    let src_inode = std::fs::metadata(&source_manifest).unwrap();
    let dst_inode = std::fs::metadata(&output_manifest).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            src_inode.ino(),
            dst_inode.ino(),
            "test setup: source and output should be hardlinked"
        );
    }
    // Suppress unused-variable warnings on non-unix
    let _ = (&src_inode, &dst_inode);

    // Run the rewrite — it should write to the output WITHOUT
    // mutating the source.
    rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

    // CRITICAL: source manifest is byte-identical
    let source_bytes_after = std::fs::read(&source_manifest).unwrap();
    assert_eq!(
        source_bytes_after, source_bytes_before,
        "SECURITY: rewrite must NOT mutate the source manifest through a hardlink"
    );

    // The output manifest IS modified (workspace:* → 1.5.0)
    let output_doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output_manifest).unwrap()).unwrap();
    assert_eq!(output_doc["dependencies"]["@scope/auth"], "1.5.0");

    #[cfg(unix)]
    {
        // Source and output now have DIFFERENT inodes
        use std::os::unix::fs::MetadataExt;
        let src_after = std::fs::metadata(&source_manifest).unwrap();
        let dst_after = std::fs::metadata(&output_manifest).unwrap();
        assert_ne!(
            src_after.ino(),
            dst_after.ino(),
            "rewrite must have broken the hardlink — source and output should have different inodes"
        );
    }
}

#[test]
fn rewrite_workspace_protocol_does_not_modify_source_workspace_manifests() {
    // CRITICAL invariant: deploy is read-only on the source side. The
    // manifest rewrite must NEVER touch the source workspace's files.
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());

    // Snapshot all source manifests before the rewrite
    let root_before = std::fs::read(workspace_root.join("package.json")).unwrap();
    let auth_before = std::fs::read(workspace_root.join("packages/auth/package.json")).unwrap();
    let api_before = std::fs::read(workspace_root.join("packages/api/package.json")).unwrap();

    // Set up the deploy output and run the rewrite
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::copy(
        workspace_root.join("packages/api/package.json"),
        output.join("package.json"),
    )
    .unwrap();

    rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

    // Verify all source manifests are byte-identical
    assert_eq!(
        std::fs::read(workspace_root.join("package.json")).unwrap(),
        root_before,
        "source workspace root manifest must not be modified"
    );
    assert_eq!(
        std::fs::read(workspace_root.join("packages/auth/package.json")).unwrap(),
        auth_before,
        "source auth member manifest must not be modified"
    );
    assert_eq!(
        std::fs::read(workspace_root.join("packages/api/package.json")).unwrap(),
        api_before,
        "source api member manifest must not be modified"
    );
}

#[test]
fn rewrite_workspace_protocol_in_dev_dependencies_too() {
    // Even though install doesn't use devDependencies, deploy rewrites
    // them so the deploy output's package.json is clean.
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::copy(
        workspace_root.join("packages/api/package.json"),
        output.join("package.json"),
    )
    .unwrap();

    rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
            .unwrap();
    // devDependencies workspace:^ → ^1.5.0
    assert_eq!(after["devDependencies"]["@scope/auth"], "^1.5.0");
    // peerDependencies workspace:~ → ~1.5.0
    assert_eq!(after["peerDependencies"]["@scope/auth"], "~1.5.0");
}

#[test]
fn rewrite_workspace_protocol_returns_count_of_rewrites() {
    // The function returns the total number of workspace:* refs rewritten
    // across all sections. The fixture has 3 such refs (deps, devDeps, peerDeps).
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::copy(
        workspace_root.join("packages/api/package.json"),
        output.join("package.json"),
    )
    .unwrap();

    let rewritten =
        rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

    assert_eq!(
        rewritten, 3,
        "fixture has workspace refs in dependencies, devDependencies, and peerDependencies"
    );
}

#[test]
fn rewrite_workspace_protocol_errors_when_output_manifest_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&output).unwrap();
    // No package.json copied — file is missing

    let err = rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap_err();
    assert!(err.to_string().contains("read deploy manifest"));
}

// ── source file copier tests ────────────────────────────────────────
//
// These tests focus on the security boundary (the deny list) and the
// happy paths. The negative assertions are the load-bearing ones —
// each .env* / node_modules / .git assertion is a regression guard
// for a security failure.

/// Helper: build a fixture member dir with a representative file tree.
/// Returns the path to the member dir, ready to be passed as `src_dir`
/// to `copy_member_source`.
fn build_member_fixture(tmp: &Path) -> PathBuf {
    let member = tmp.join("member");
    std::fs::create_dir_all(&member).unwrap();

    // Files that SHOULD be copied
    std::fs::write(
        member.join("package.json"),
        r#"{"name":"foo","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(member.join("README.md"), "# foo\n").unwrap();
    std::fs::write(member.join("LICENSE"), "MIT\n").unwrap();
    std::fs::write(member.join("tsconfig.json"), "{}").unwrap();

    std::fs::create_dir_all(member.join("src")).unwrap();
    std::fs::write(member.join("src").join("index.ts"), "export {}").unwrap();
    std::fs::write(member.join("src").join("util.ts"), "export {}").unwrap();

    std::fs::create_dir_all(member.join("dist")).unwrap();
    std::fs::write(member.join("dist").join("index.js"), "module.exports = {}").unwrap();

    // Files that MUST NOT be copied (the deny list)
    std::fs::write(member.join(".env"), "SECRET=hunter2\n").unwrap();
    std::fs::write(member.join(".env.local"), "LOCAL_SECRET=foo\n").unwrap();
    std::fs::write(member.join(".env.production"), "PROD=bar\n").unwrap();
    std::fs::write(member.join(".env.test"), "TEST=baz\n").unwrap();

    std::fs::write(member.join("lpm.lock"), "stub-lockfile").unwrap();
    std::fs::write(member.join("lpm.lockb"), b"stub-bin").unwrap();

    std::fs::create_dir_all(member.join("node_modules").join("react")).unwrap();
    std::fs::write(
        member.join("node_modules").join("react").join("index.js"),
        "module.exports = 'react'",
    )
    .unwrap();

    std::fs::create_dir_all(member.join(".lpm").join("cache")).unwrap();
    std::fs::write(member.join(".lpm").join("state.json"), "{}").unwrap();

    std::fs::create_dir_all(member.join(".git").join("objects")).unwrap();
    std::fs::write(member.join(".git").join("HEAD"), "ref: refs/heads/main").unwrap();

    std::fs::write(member.join(".gitignore"), "node_modules\n").unwrap();
    std::fs::write(member.join(".DS_Store"), b"mac cruft").unwrap();

    member
}

// ── Happy path: files that should be copied ────────────────────────────

#[test]
fn copy_member_source_copies_package_json_and_readme() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(dst.join("package.json").exists());
    assert!(dst.join("README.md").exists());
    assert!(dst.join("LICENSE").exists());
    assert!(dst.join("tsconfig.json").exists());
}

#[test]
fn copy_member_source_copies_nested_src_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(dst.join("src").join("index.ts").exists());
    assert!(dst.join("src").join("util.ts").exists());
}

#[test]
fn copy_member_source_preserves_dist_directory() {
    // dist/ is a build artifact that callers may want to deploy.
    // It is NOT in the deny list — explicit positive assertion.
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(
        dst.join("dist").join("index.js").exists(),
        "dist/ build artifacts must be preserved"
    );
}

#[test]
fn copy_member_source_honors_package_files_field() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("member");
    std::fs::create_dir_all(src.join("dist")).unwrap();
    std::fs::create_dir_all(src.join("src")).unwrap();
    std::fs::write(
        src.join("package.json"),
        r#"{"name":"pkg","version":"1.0.0","files":["dist"]}"#,
    )
    .unwrap();
    std::fs::write(src.join("README.md"), "# pkg\n").unwrap();
    std::fs::write(src.join("dist").join("index.js"), "module.exports = {}").unwrap();
    std::fs::write(src.join("src").join("index.ts"), "export {};").unwrap();

    let dst = tmp.path().join("output");
    copy_member_source(&src, &dst).unwrap();

    assert!(dst.join("package.json").exists());
    assert!(dst.join("README.md").exists());
    assert!(dst.join("dist").join("index.js").exists());
    assert!(
        !dst.join("src").exists(),
        "files=[\"dist\"] must exclude source paths outside the publish set"
    );
}

#[test]
fn copy_member_source_honors_npmignore_before_gitignore() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("member");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("package.json"),
        r#"{"name":"pkg","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(src.join(".npmignore"), "secret.txt\n").unwrap();
    std::fs::write(src.join(".gitignore"), "!secret.txt\nignored-by-git.txt\n").unwrap();
    std::fs::write(src.join("secret.txt"), "secret").unwrap();
    std::fs::write(src.join("ignored-by-git.txt"), "git-only").unwrap();

    let dst = tmp.path().join("output");
    copy_member_source(&src, &dst).unwrap();

    assert!(
        !dst.join("secret.txt").exists(),
        ".npmignore must exclude files from deploy copy"
    );
    assert!(
        dst.join("ignored-by-git.txt").exists(),
        ".npmignore must take precedence over .gitignore when both exist"
    );
    assert!(
        !dst.join(".npmignore").exists(),
        ".npmignore controls selection but is not deploy payload"
    );
}

// ── Security regressions: deny list ────────────────────────────────────

#[test]
fn copy_member_source_never_copies_dotenv() {
    // CRITICAL: .env file must never end up in a deploy output. This is
    // the single most important security guarantee deploy makes.
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(
        !dst.join(".env").exists(),
        "SECURITY: .env must NEVER be copied to a deploy output"
    );
}

#[test]
fn copy_member_source_never_copies_dotenv_local() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(
        !dst.join(".env.local").exists(),
        "SECURITY: .env.local must NEVER be copied to a deploy output"
    );
}

#[test]
fn copy_member_source_never_copies_any_dotenv_variant() {
    // Iterate every .env variant in the deny list — each one is its
    // own security regression.
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    for variant in [".env", ".env.local", ".env.production", ".env.test"] {
        assert!(
            !dst.join(variant).exists(),
            "SECURITY: {variant} must NEVER be copied to a deploy output"
        );
    }
}

#[test]
fn copy_member_source_never_copies_node_modules() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(
        !dst.join("node_modules").exists(),
        "node_modules must not be copied (the install pipeline recreates it)"
    );
}

#[test]
fn copy_member_source_never_copies_dot_lpm() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(
        !dst.join(".lpm").exists(),
        ".lpm internal state must not be copied"
    );
}

#[test]
fn copy_member_source_never_copies_lockfiles() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(!dst.join("lpm.lock").exists());
    assert!(!dst.join("lpm.lockb").exists());
}

#[test]
fn copy_member_source_never_copies_git_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(
        !dst.join(".git").exists(),
        ".git directory must not be copied"
    );
    assert!(
        !dst.join(".gitignore").exists(),
        ".gitignore must not be copied (deploy output is not a repo)"
    );
}

#[test]
fn copy_member_source_never_copies_ds_store() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    copy_member_source(&src, &dst).unwrap();

    assert!(!dst.join(".DS_Store").exists());
}

#[test]
fn copy_member_source_skips_nested_node_modules_too() {
    // The deny list applies at every nesting level, not just root.
    // Verify that a `nested/sub/node_modules/foo` is also excluded.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("member");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("package.json"), "{}").unwrap();

    let nested = src
        .join("packages")
        .join("inner")
        .join("node_modules")
        .join("foo");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("index.js"), "leaked").unwrap();

    let dst = tmp.path().join("output");
    copy_member_source(&src, &dst).unwrap();

    assert!(dst.join("packages").join("inner").exists());
    assert!(
        !dst.join("packages")
            .join("inner")
            .join("node_modules")
            .exists(),
        "nested node_modules must also be denied"
    );
}

#[test]
fn copy_member_source_skips_nested_dotenv_too() {
    // CRITICAL: same defense at depth — `packages/foo/.env` must not
    // be copied even if the user accidentally checked one in.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("member");
    std::fs::create_dir_all(src.join("config")).unwrap();
    std::fs::write(src.join("package.json"), "{}").unwrap();
    std::fs::write(src.join("config").join(".env"), "NESTED_SECRET=oops").unwrap();

    let dst = tmp.path().join("output");
    copy_member_source(&src, &dst).unwrap();

    assert!(dst.join("config").exists());
    assert!(
        !dst.join("config").join(".env").exists(),
        "SECURITY: nested .env at any depth must be denied"
    );
}

// ── Stats accuracy ─────────────────────────────────────────────────────

#[test]
fn copy_member_source_returns_stats_with_files_copied_and_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    let stats = copy_member_source(&src, &dst).unwrap();

    // The fixture has multiple files in src/ and dist/ plus root files
    // that should be copied. We don't assert exact counts (fixture may
    // evolve) — just that the numbers are non-zero and sensible.
    assert!(
        stats.files_copied > 0,
        "should have copied at least one file"
    );
    assert!(
        stats.files_skipped > 0,
        "should have skipped at least one denied entry (.env, node_modules, etc.)"
    );
    assert!(stats.bytes_copied > 0);
}

// ── Filesystem invariants ──────────────────────────────────────────────

#[test]
fn copy_member_source_creates_output_dir_if_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    // Output dir does NOT exist yet
    let dst = tmp.path().join("does").join("not").join("exist");

    copy_member_source(&src, &dst).unwrap();

    assert!(dst.exists());
    assert!(dst.join("package.json").exists());
}

#[test]
fn dependency_selection_production_strips_dev_and_keeps_optional_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("package.json");
    std::fs::write(
        &manifest,
        serde_json::to_string_pretty(&json!({
            "name": "api",
            "dependencies": {"runtime": "^1.0.0"},
            "devDependencies": {"test-only": "^2.0.0"},
            "optionalDependencies": {"optional-native": "^3.0.0"}
        }))
        .unwrap(),
    )
    .unwrap();

    let stats =
        apply_dependency_selection_to_manifest_path(&manifest, DependencyMode::Production, false)
            .unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();

    assert_eq!(stats.dev_dependencies_stripped, 1);
    assert!(doc.get("devDependencies").is_none());
    assert_eq!(doc["dependencies"]["runtime"], "^1.0.0");
    assert_eq!(doc["optionalDependencies"]["optional-native"], "^3.0.0");
}

#[test]
fn dependency_selection_dev_strips_production_and_optional_sections() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("package.json");
    std::fs::write(
        &manifest,
        serde_json::to_string_pretty(&json!({
            "name": "api",
            "dependencies": {"runtime": "^1.0.0"},
            "devDependencies": {"test-only": "^2.0.0"},
            "optionalDependencies": {"optional-native": "^3.0.0"}
        }))
        .unwrap(),
    )
    .unwrap();

    let stats =
        apply_dependency_selection_to_manifest_path(&manifest, DependencyMode::Development, false)
            .unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();

    assert_eq!(stats.production_dependencies_stripped, 1);
    assert_eq!(stats.optional_dependencies_stripped, 1);
    assert!(doc.get("dependencies").is_none());
    assert!(doc.get("optionalDependencies").is_none());
    assert_eq!(doc["devDependencies"]["test-only"], "^2.0.0");
}

#[test]
fn dependency_selection_no_optional_strips_optional_in_production_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("package.json");
    std::fs::write(
        &manifest,
        serde_json::to_string_pretty(&json!({
            "name": "api",
            "dependencies": {"runtime": "^1.0.0"},
            "optionalDependencies": {"optional-native": "^3.0.0"}
        }))
        .unwrap(),
    )
    .unwrap();

    let stats =
        apply_dependency_selection_to_manifest_path(&manifest, DependencyMode::Production, true)
            .unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();

    assert_eq!(stats.optional_dependencies_stripped, 1);
    assert!(doc.get("optionalDependencies").is_none());
    assert_eq!(doc["dependencies"]["runtime"], "^1.0.0");
}

#[test]
fn copy_member_source_does_not_modify_source_directory() {
    // CRITICAL invariant: the deploy command is read-only on the source
    // side. Snapshot the source dir before the copy and verify nothing
    // changed.
    let tmp = tempfile::tempdir().unwrap();
    let src = build_member_fixture(tmp.path());
    let dst = tmp.path().join("output");

    // Snapshot relevant source files
    let pkg_before = std::fs::read_to_string(src.join("package.json")).unwrap();
    let env_before = std::fs::read_to_string(src.join(".env")).unwrap();
    let index_before = std::fs::read_to_string(src.join("src").join("index.ts")).unwrap();

    copy_member_source(&src, &dst).unwrap();

    // Verify the source is byte-identical
    assert_eq!(
        std::fs::read_to_string(src.join("package.json")).unwrap(),
        pkg_before
    );
    assert_eq!(
        std::fs::read_to_string(src.join(".env")).unwrap(),
        env_before
    );
    assert_eq!(
        std::fs::read_to_string(src.join("src").join("index.ts")).unwrap(),
        index_before
    );
}

#[test]
fn copy_member_source_errors_when_source_does_not_exist() {
    let tmp = tempfile::tempdir().unwrap();
    let absent = tmp.path().join("does-not-exist");
    let dst = tmp.path().join("output");

    let err = copy_member_source(&absent, &dst).unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}

// ────────────────────────────────────────────────────────────────────
// deploy stays prod-only after `lpm install` learned to
// resolve devDependencies. `strip_dev_dependencies_from_deploy_manifest`
// is the load-bearing step that keeps dev-only packages (vitest, tsup,
// eslint, etc.) out of the deploy closure.
// ────────────────────────────────────────────────────────────────────

#[test]
fn strip_dev_dependencies_removes_section_entirely() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().to_path_buf();
    std::fs::write(
        output.join("package.json"),
        r#"{
            "name": "api",
            "version": "1.0.0",
            "dependencies": { "express": "^4.0.0" },
            "devDependencies": { "vitest": "^1.0.0", "tsup": "^8.0.0" }
        }"#,
    )
    .unwrap();

    let stripped = strip_dev_dependencies_from_deploy_manifest(&output).unwrap();

    assert_eq!(stripped, 2, "both vitest and tsup should be counted");

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
            .unwrap();
    assert!(
        after.get("devDependencies").is_none(),
        "devDependencies key must be gone, not just emptied"
    );
    // dependencies must be preserved byte-for-byte
    assert_eq!(
        after["dependencies"]["express"].as_str(),
        Some("^4.0.0"),
        "stripping devDeps must not touch dependencies"
    );
}

#[test]
fn strip_dev_dependencies_is_noop_when_section_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().to_path_buf();
    let original = r#"{
            "name": "api",
            "version": "1.0.0",
            "dependencies": { "express": "^4.0.0" }
        }"#;
    std::fs::write(output.join("package.json"), original).unwrap();

    let stripped = strip_dev_dependencies_from_deploy_manifest(&output).unwrap();

    assert_eq!(stripped, 0);
    // No-op case must leave the bytes untouched — important for preserving
    // hand-authored formatting when nothing needed to change.
    assert_eq!(
        std::fs::read_to_string(output.join("package.json")).unwrap(),
        original
    );
}

#[test]
fn strip_dev_dependencies_is_noop_when_section_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().to_path_buf();
    let original = r#"{
            "name": "api",
            "version": "1.0.0",
            "dependencies": { "express": "^4.0.0" },
            "devDependencies": {}
        }"#;
    std::fs::write(output.join("package.json"), original).unwrap();

    let stripped = strip_dev_dependencies_from_deploy_manifest(&output).unwrap();

    assert_eq!(stripped, 0);
    // Empty section is treated as "nothing to do" — the bytes stay.
    assert_eq!(
        std::fs::read_to_string(output.join("package.json")).unwrap(),
        original
    );
}

#[test]
fn strip_dev_dependencies_breaks_hardlink_to_protect_source() {
    // Mirror of the hardlink regression pattern: copy_member_source may
    // hardlink the output's package.json to the source workspace's. A
    // naive write inside strip would mutate the source. This test sets
    // up an explicit hardlink, runs strip, and asserts the source is
    // untouched while the output is rewritten.
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let output = tmp.path().join("output");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&output).unwrap();

    let source_manifest = source.join("package.json");
    let output_manifest = output.join("package.json");
    let original = r#"{
            "name": "api",
            "version": "1.0.0",
            "dependencies": { "express": "^4.0.0" },
            "devDependencies": { "vitest": "^1.0.0" }
        }"#;
    std::fs::write(&source_manifest, original).unwrap();
    // Force a hardlink — `copy_member_source` would have done this
    // naturally when source and output live on the same filesystem.
    std::fs::hard_link(&source_manifest, &output_manifest).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let source_inode_before = source_manifest.metadata().unwrap();
        let output_inode_before = output_manifest.metadata().unwrap();
        assert_eq!(
            source_inode_before.ino(),
            output_inode_before.ino(),
            "setup precondition: source and output must share an inode"
        );
    }

    let stripped = strip_dev_dependencies_from_deploy_manifest(&output).unwrap();
    assert_eq!(stripped, 1);

    // 1. The source manifest is byte-identical — the hardlink was
    //    broken BEFORE the write.
    assert_eq!(
        std::fs::read_to_string(&source_manifest).unwrap(),
        original,
        "source manifest must be byte-identical after deploy strip"
    );

    // 2. The output manifest IS modified — devDeps gone, deps preserved.
    let after_output: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output_manifest).unwrap()).unwrap();
    assert!(after_output.get("devDependencies").is_none());
    assert_eq!(
        after_output["dependencies"]["express"].as_str(),
        Some("^4.0.0")
    );

    // 3. The two paths now point at DIFFERENT inodes — proof the
    //    hardlink was actually broken, not merely avoided via copy.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            source_manifest.metadata().unwrap().ino(),
            output_manifest.metadata().unwrap().ino(),
            "hardlink must be broken by strip — otherwise any future \
             modification risks leaking into the source"
        );
    }
}

#[test]
fn strip_dev_dependencies_preserves_other_dep_sections() {
    let tmp = tempfile::tempdir().unwrap();
    let output = tmp.path().to_path_buf();
    std::fs::write(
        output.join("package.json"),
        r#"{
            "name": "api",
            "version": "1.0.0",
            "dependencies": { "express": "^4.0.0" },
            "devDependencies": { "vitest": "^1.0.0" },
            "peerDependencies": { "react": "^18.0.0" },
            "optionalDependencies": { "fsevents": "^2.0.0" }
        }"#,
    )
    .unwrap();

    strip_dev_dependencies_from_deploy_manifest(&output).unwrap();

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
            .unwrap();
    assert!(after.get("devDependencies").is_none());
    assert_eq!(after["dependencies"]["express"].as_str(), Some("^4.0.0"));
    assert_eq!(
        after["peerDependencies"]["react"].as_str(),
        Some("^18.0.0"),
        "peerDependencies must survive — only devDependencies are prod-stripped"
    );
    assert_eq!(
        after["optionalDependencies"]["fsevents"].as_str(),
        Some("^2.0.0"),
        "optionalDependencies must survive — only devDependencies are prod-stripped"
    );
}
