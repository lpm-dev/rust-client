//! Phase 32 Phase 2 — shared target resolution for `lpm install` and
//! `lpm uninstall`.
//!
//! Both commands need to answer the same question: **which `package.json`
//! file(s) should I modify, and where should the install pipeline run for
//! each one?**
//!
//! The answer depends on:
//! 1. Whether we're inside a workspace
//! 2. Whether `--filter <expr>` was passed (one or more times)
//! 3. Whether `-w` / `--workspace-root` was passed
//! 4. Where the cwd is relative to the workspace (member dir vs root)
//! 5. Whether the user is adding/removing packages or just refreshing
//!
//! This module owns the precedence rules and returns a single
//! [`InstallTargets`] struct that the caller iterates over.
//!
//! ## Per-target install root
//!
//! **Phase 2 audit correction (2026-04):** the install pipeline runs **once
//! per target manifest, at that manifest's parent directory**. This was
//! initially designed as "one install at the workspace root" but that was
//! incorrect — LPM uses per-directory lockfiles and per-directory
//! `node_modules`, so a workspace-root install never picks up member-only
//! dependencies. The corrected model: each target manifest's parent IS the
//! install root for that target. Callers iterate.
//!
//! Use [`install_root_for`] to get the per-target install root.

use lpm_common::LpmError;
use lpm_task::filter::FilterEngine;
use lpm_task::graph::WorkspaceGraph;
use std::path::{Path, PathBuf};

/// The result of resolving CLI flags into a concrete set of `package.json`
/// files to operate on. Each target's install root is its manifest's parent
/// directory — see the module docs and [`install_root_for`].
#[derive(Debug, Clone)]
pub struct InstallTargets {
    /// Absolute paths to the `package.json` files that should be modified.
    /// One entry for `-w`, one for `cd member && lpm install`, one or more
    /// for `--filter`. Empty for the `--filter` no-match case (callers
    /// surface this via `--fail-if-no-match` semantics).
    pub member_manifests: Vec<PathBuf>,

    /// True when the operation will modify more than one `package.json`.
    /// Used by `install`/`uninstall` to gate the multi-target summary line
    /// and (in JSON mode) the JSON-Lines output format.
    pub multi_member: bool,
}

/// Return the install root for a single target manifest.
///
/// LPM uses per-directory lockfiles + `node_modules`, so the install pipeline
/// for a given `package.json` runs in that file's parent directory. For a
/// member manifest at `packages/web/package.json`, the install root is
/// `packages/web/`. For the workspace root manifest at
/// `<workspace>/package.json`, the install root is `<workspace>/`.
///
/// This is the per-target replacement for the old `InstallTargets.install_root`
/// field that incorrectly assumed a single workspace-wide install root.
pub fn install_root_for(manifest: &Path) -> &Path {
    manifest
        .parent()
        .expect("manifest path must have a parent directory")
}

/// Resolve install/uninstall targets from CLI flags.
///
/// See the module-level docs for the precedence rules. The behavior matrix
/// is reproduced as a table here for quick reference:
///
/// | Workspace? | `-w`? | `--filter`? | cwd location | Result |
/// |---|---|---|---|---|
/// | no  | -   | -   | anywhere       | install_root = cwd, members = `[cwd]` |
/// | no  | yes | any | anywhere       | error: `-w` requires workspace |
/// | no  | -   | yes | anywhere       | error: `--filter` requires workspace |
/// | yes | yes | yes | anywhere       | error: `-w` and `--filter` are contradictory |
/// | yes | yes | -   | anywhere       | install_root = root, members = `[root]` |
/// | yes | -   | yes | anywhere       | install_root = root, members = `FilterEngine` result |
/// | yes | -   | -   | inside member  | install_root = root, members = `[current_member]` |
/// | yes | -   | -   | at root        | error: ambiguous (only when `has_packages == true`) |
///
/// **Special case:** the "ambiguous workspace root" error only fires when
/// the user is adding/removing packages. Bare `lpm install` (refresh from
/// `package.json`) is allowed at the workspace root with no flags.
///
/// **Empty filter result:** if `--filter` is supplied but the engine returns
/// no matches, this function returns an `InstallTargets` with an empty
/// `member_manifests` Vec. The caller decides how to surface that — typically
/// via a `--fail-if-no-match` flag mirroring Phase 1.
pub fn resolve_install_targets(
    cwd: &Path,
    filters: &[String],
    workspace_root_flag: bool,
    has_packages: bool,
) -> Result<InstallTargets, LpmError> {
    // ── Mutual exclusion: -w and --filter never compose ──────────────────
    if workspace_root_flag && !filters.is_empty() {
        return Err(LpmError::Script(
            "`-w` (workspace root) and `--filter` cannot be used together. \
             Pick one: `-w` to target the workspace root, or `--filter <expr>` \
             to target specific members."
                .into(),
        ));
    }

    // ── Detect workspace ─────────────────────────────────────────────────
    let workspace = lpm_workspace::discover_workspace(cwd)
        .map_err(|e| LpmError::Script(format!("workspace discovery failed: {e}")))?;

    // ── Branch A: not in a workspace ─────────────────────────────────────
    let Some(workspace) = workspace else {
        if workspace_root_flag {
            return Err(LpmError::Script(
                "`-w` requires a workspace. The current directory is a standalone project — \
                 just run `lpm install` without `-w` to operate on the local package.json."
                    .into(),
            ));
        }
        if !filters.is_empty() {
            return Err(LpmError::Script(
                "`--filter` requires a workspace. The current directory is a standalone project. \
                 Run from inside a workspace, or omit `--filter` for a regular install."
                    .into(),
            ));
        }
        // Standalone project: use cwd's package.json. This is the
        // pre-Phase-2 behavior, unchanged.
        let manifest = cwd.join("package.json");
        return Ok(InstallTargets {
            member_manifests: vec![manifest],
            multi_member: false,
        });
    };

    // ── Branch B: inside a workspace ─────────────────────────────────────

    // -w → workspace root manifest
    if workspace_root_flag {
        let root_manifest = workspace.root.join("package.json");
        return Ok(InstallTargets {
            member_manifests: vec![root_manifest],
            multi_member: false,
        });
    }

    // --filter → consume the shared FilterEngine
    if !filters.is_empty() {
        let graph = WorkspaceGraph::from_workspace(&workspace);

        // Parse all filter strings into ASTs
        let mut exprs = Vec::with_capacity(filters.len());
        for raw in filters {
            let parsed = FilterEngine::parse(raw)
                .map_err(|e| LpmError::Script(format!("invalid --filter {raw:?}: {e}")))?;
            exprs.push(parsed);
        }

        let engine = FilterEngine::new(&graph, &workspace.root);
        let selected = engine
            .evaluate(&exprs)
            .map_err(|e| LpmError::Script(format!("filter error: {e}")))?;

        let member_manifests: Vec<PathBuf> = selected
            .iter()
            .map(|&id| graph.members[id].path.join("package.json"))
            .collect();

        let multi_member = member_manifests.len() > 1;
        return Ok(InstallTargets {
            member_manifests,
            multi_member,
        });
    }

    // No -w, no --filter → use cwd location to disambiguate
    let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let workspace_root_canonical = workspace
        .root
        .canonicalize()
        .unwrap_or_else(|_| workspace.root.clone());

    // Find the workspace member whose path equals (or is an ancestor of) cwd.
    let containing_member = workspace.members.iter().find(|m| {
        let member_canonical = m.path.canonicalize().unwrap_or_else(|_| m.path.clone());
        cwd_canonical == member_canonical || cwd_canonical.starts_with(&member_canonical)
    });

    if let Some(member) = containing_member {
        let member_manifest = member.path.join("package.json");
        return Ok(InstallTargets {
            member_manifests: vec![member_manifest],
            multi_member: false,
        });
    }

    // We're at the workspace root (cwd matches workspace root or is some
    // unrelated subdir of it). With packages → ambiguous error. Without
    // packages → bare refresh, target = root.
    if cwd_canonical == workspace_root_canonical {
        if has_packages {
            return Err(LpmError::Script(
                "ambiguous workspace root: `lpm install <pkg>` (or uninstall) at the workspace root \
                 needs to know WHERE to add the package. Use one of:\n  \
                 - `-w` to add to the root package.json itself\n  \
                 - `--filter <member>` to add to a specific workspace member\n  \
                 - `cd packages/<member>` and run again"
                    .into(),
            ));
        }
        // Bare `lpm install` at workspace root: refresh from root package.json.
        let root_manifest = workspace.root.join("package.json");
        return Ok(InstallTargets {
            member_manifests: vec![root_manifest],
            multi_member: false,
        });
    }

    // We're somewhere inside the workspace tree but not in any member dir
    // (e.g., a tools/ subdir, or .git/). Treat this like the workspace root
    // case: ambiguous when packages are passed, otherwise refresh from root.
    if has_packages {
        return Err(LpmError::Script(format!(
            "the current directory {cwd:?} is inside the workspace but not in any member package. \
             Use `-w` to target the workspace root, `--filter <member>` to target a specific member, \
             or `cd` into a member directory."
        )));
    }
    let root_manifest = workspace.root.join("package.json");
    Ok(InstallTargets {
        member_manifests: vec![root_manifest],
        multi_member: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    /// Build a synthetic on-disk workspace at `root`. Each member is
    /// `(name, path_segments)` — `path_segments` is joined under the root
    /// to form the member dir.
    fn write_workspace(root: &Path, members: &[(&str, &str)]) {
        fs::create_dir_all(root).unwrap();
        let workspace_globs: Vec<String> = members
            .iter()
            .map(|(_, path)| (*path).to_string())
            .collect();
        let root_pkg = json!({
            "name": "monorepo",
            "private": true,
            "workspaces": workspace_globs,
        });
        fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();

        for (name, path) in members {
            let dir = root.join(path);
            fs::create_dir_all(&dir).unwrap();
            let pkg = json!({
                "name": name,
                "version": "0.0.0",
            });
            fs::write(
                dir.join("package.json"),
                serde_json::to_string_pretty(&pkg).unwrap(),
            )
            .unwrap();
        }
    }

    /// Build a standalone (non-workspace) project at `root` with a single
    /// package.json.
    fn write_standalone(root: &Path) {
        fs::create_dir_all(root).unwrap();
        let pkg = json!({
            "name": "solo",
            "version": "0.0.0",
        });
        fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }

    // ── Decision matrix cell 1: standalone, no flags ──────────────────────

    #[test]
    fn standalone_no_flags_targets_cwd_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        write_standalone(tmp.path());

        let targets = resolve_install_targets(tmp.path(), &[], false, true).unwrap();

        assert_eq!(
            targets.member_manifests,
            vec![tmp.path().join("package.json")]
        );
        // Per-target install root: parent of the manifest = the cwd itself
        assert_eq!(install_root_for(&targets.member_manifests[0]), tmp.path());
        assert!(!targets.multi_member);
    }

    // ── Decision matrix cell 2: standalone + -w → error ───────────────────

    #[test]
    fn standalone_with_w_flag_hard_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write_standalone(tmp.path());

        let err = resolve_install_targets(tmp.path(), &[], true, true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("`-w` requires a workspace"),
            "expected -w workspace error, got: {msg}"
        );
    }

    // ── Decision matrix cell 3: standalone + --filter → error ─────────────

    #[test]
    fn standalone_with_filter_flag_hard_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write_standalone(tmp.path());

        let err =
            resolve_install_targets(tmp.path(), &["foo".to_string()], false, true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("`--filter` requires a workspace"),
            "expected --filter workspace error, got: {msg}"
        );
    }

    // ── Decision matrix cell 4: workspace + -w + --filter → error ─────────

    #[test]
    fn workspace_with_w_and_filter_together_hard_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);

        let err =
            resolve_install_targets(tmp.path(), &["foo".to_string()], true, true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("`-w` (workspace root) and `--filter` cannot be used together"),
            "expected mutual-exclusion error, got: {msg}"
        );
    }

    // ── Decision matrix cell 5: workspace + -w → root manifest ────────────

    #[test]
    fn workspace_with_w_flag_targets_root_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(
            tmp.path(),
            &[("foo", "packages/foo"), ("bar", "packages/bar")],
        );

        let targets = resolve_install_targets(tmp.path(), &[], true, true).unwrap();

        assert_eq!(targets.member_manifests.len(), 1);
        assert_eq!(targets.member_manifests[0], tmp.path().join("package.json"));
        // -w → install root is the workspace root (= manifest's parent)
        assert_eq!(install_root_for(&targets.member_manifests[0]), tmp.path());
        assert!(!targets.multi_member);
    }

    // ── Decision matrix cell 6: workspace + --filter → engine result ──────

    #[test]
    fn workspace_with_filter_uses_engine_to_select_single_member() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(
            tmp.path(),
            &[("foo", "packages/foo"), ("bar", "packages/bar")],
        );

        let targets =
            resolve_install_targets(tmp.path(), &["foo".to_string()], false, true).unwrap();

        assert_eq!(targets.member_manifests.len(), 1);
        assert!(
            targets.member_manifests[0].ends_with("packages/foo/package.json"),
            "expected packages/foo/package.json, got: {:?}",
            targets.member_manifests[0]
        );
        assert!(!targets.multi_member);
    }

    #[test]
    fn workspace_with_filter_glob_selects_multiple_members() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(
            tmp.path(),
            &[
                ("ui-button", "packages/ui-button"),
                ("ui-card", "packages/ui-card"),
                ("auth", "packages/auth"),
            ],
        );

        let targets =
            resolve_install_targets(tmp.path(), &["ui-*".to_string()], false, true).unwrap();

        assert_eq!(targets.member_manifests.len(), 2);
        assert!(targets.multi_member);
        let manifest_strings: Vec<String> = targets
            .member_manifests
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        assert!(manifest_strings.iter().any(|s| s.contains("ui-button")));
        assert!(manifest_strings.iter().any(|s| s.contains("ui-card")));
        assert!(!manifest_strings.iter().any(|s| s.contains("auth")));
    }

    #[test]
    fn workspace_with_filter_no_match_returns_empty_targets_not_error() {
        // The "no match" path returns `Ok` with an empty Vec — caller decides
        // whether to escalate via --fail-if-no-match. Mirrors Phase 1 D3.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);

        let targets =
            resolve_install_targets(tmp.path(), &["does-not-exist".to_string()], false, true)
                .unwrap();

        assert!(targets.member_manifests.is_empty());
        assert!(!targets.multi_member);
    }

    #[test]
    fn workspace_with_invalid_filter_syntax_hard_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);

        let err =
            resolve_install_targets(tmp.path(), &["foo!bar".to_string()], false, true).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid --filter"));
    }

    // ── Decision matrix cell 7: workspace, no flags, inside member ────────

    #[test]
    fn workspace_no_flags_inside_member_targets_current_member() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(
            tmp.path(),
            &[("foo", "packages/foo"), ("bar", "packages/bar")],
        );

        // Cwd is INSIDE packages/foo
        let cwd = tmp.path().join("packages").join("foo");
        let targets = resolve_install_targets(&cwd, &[], false, true).unwrap();

        assert_eq!(targets.member_manifests.len(), 1);
        assert!(targets.member_manifests[0].ends_with("packages/foo/package.json"));
        // Phase 2 audit correction: install root is the MEMBER dir, not the
        // workspace root. LPM uses per-directory lockfiles + node_modules,
        // so member-targeted installs must run their pipeline at the member.
        let expected = tmp.path().join("packages").join("foo");
        let actual = install_root_for(&targets.member_manifests[0]);
        assert_eq!(
            actual.canonicalize().unwrap(),
            expected.canonicalize().unwrap()
        );
        assert!(!targets.multi_member);
    }

    #[test]
    fn workspace_no_flags_inside_nested_subdir_of_member_still_targets_member() {
        // User runs `lpm install foo` from packages/foo/src/, not from packages/foo/
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);
        let nested = tmp.path().join("packages").join("foo").join("src");
        fs::create_dir_all(&nested).unwrap();

        let targets = resolve_install_targets(&nested, &[], false, true).unwrap();

        assert_eq!(targets.member_manifests.len(), 1);
        assert!(targets.member_manifests[0].ends_with("packages/foo/package.json"));
    }

    // ── Decision matrix cell 8: workspace, no flags, at root, with packages ──

    #[test]
    fn workspace_no_flags_at_root_with_packages_hard_errors_with_guidance() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);

        let err = resolve_install_targets(tmp.path(), &[], false, true).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ambiguous workspace root"));
        assert!(msg.contains("`-w`"));
        assert!(msg.contains("`--filter"));
    }

    // ── Special case: bare refresh at workspace root is allowed ────────────

    #[test]
    fn workspace_no_flags_at_root_no_packages_targets_root_for_refresh() {
        // `lpm install` (no args) at the workspace root is the canonical
        // refresh-from-package.json operation. Must NOT error.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);

        let targets = resolve_install_targets(tmp.path(), &[], false, false).unwrap();

        assert_eq!(targets.member_manifests.len(), 1);
        assert_eq!(targets.member_manifests[0], tmp.path().join("package.json"));
    }

    #[test]
    fn workspace_no_flags_in_unrelated_subdir_no_packages_refreshes_root() {
        // User runs `lpm install` from a tools/ subdir that isn't a member.
        // Bare refresh should still work.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);
        let tools = tmp.path().join("tools");
        fs::create_dir_all(&tools).unwrap();

        let targets = resolve_install_targets(&tools, &[], false, false).unwrap();
        assert_eq!(targets.member_manifests.len(), 1);
        assert_eq!(targets.member_manifests[0], tmp.path().join("package.json"));
    }

    #[test]
    fn workspace_no_flags_in_unrelated_subdir_with_packages_hard_errors() {
        // Same situation but the user is trying to ADD a package — that
        // should still error because we don't know which member they want.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);
        let tools = tmp.path().join("tools");
        fs::create_dir_all(&tools).unwrap();

        let err = resolve_install_targets(&tools, &[], false, true).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("inside the workspace but not in any member package"));
    }

    // ── -w override from inside a member dir ──────────────────────────────

    #[test]
    fn workspace_w_flag_from_inside_member_still_targets_root() {
        // Important: `cd packages/foo && lpm install bar -w` adds bar to the
        // root package.json, not to foo's. The -w flag is an explicit override.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(tmp.path(), &[("foo", "packages/foo")]);
        let foo = tmp.path().join("packages").join("foo");

        let targets = resolve_install_targets(&foo, &[], true, true).unwrap();

        assert_eq!(targets.member_manifests.len(), 1);
        assert_eq!(targets.member_manifests[0], tmp.path().join("package.json"));
    }

    #[test]
    fn workspace_filter_from_inside_member_targets_filter_result_not_current_member() {
        // Same idea: cd into a member dir but pass --filter with a different
        // member's name. The filter wins.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(
            tmp.path(),
            &[("foo", "packages/foo"), ("bar", "packages/bar")],
        );
        let foo = tmp.path().join("packages").join("foo");

        let targets = resolve_install_targets(&foo, &["bar".to_string()], false, true).unwrap();

        assert_eq!(targets.member_manifests.len(), 1);
        assert!(targets.member_manifests[0].ends_with("packages/bar/package.json"));
    }

    // ── Phase 2 audit fix: per-target install root invariant ──────────────

    #[test]
    fn install_root_for_returns_manifest_parent_directory() {
        // The install root for any target manifest is its parent directory.
        // This is the architectural correction from the Phase 2 audit:
        // LPM uses per-directory lockfiles + node_modules, so the install
        // pipeline runs at the manifest's parent, not at some shared root.
        use std::path::PathBuf;
        let manifest = PathBuf::from("/workspace/packages/web/package.json");
        assert_eq!(
            install_root_for(&manifest),
            std::path::Path::new("/workspace/packages/web")
        );

        let root_manifest = PathBuf::from("/workspace/package.json");
        assert_eq!(
            install_root_for(&root_manifest),
            std::path::Path::new("/workspace")
        );
    }

    #[test]
    fn workspace_filter_install_root_is_member_dir_not_workspace_root() {
        // CRITICAL Phase 2 audit regression: when --filter targets a member,
        // the install root for that target is the member's dir, NOT the
        // workspace root. The old (incorrect) Phase 2 implementation set
        // install_root to workspace_root and tripped the empty-deps
        // early-return on workspaces with no root dependencies.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace(
            tmp.path(),
            &[("app", "packages/app"), ("core", "packages/core")],
        );

        let targets =
            resolve_install_targets(tmp.path(), &["app".to_string()], false, true).unwrap();

        assert_eq!(targets.member_manifests.len(), 1);
        let install_root = install_root_for(&targets.member_manifests[0]);
        assert_eq!(
            install_root.canonicalize().unwrap(),
            tmp.path()
                .join("packages")
                .join("app")
                .canonicalize()
                .unwrap(),
            "filtered install must run at the member dir, not the workspace root"
        );
        // Negative assertion: it must NOT be the workspace root.
        assert_ne!(
            install_root.canonicalize().unwrap(),
            tmp.path().canonicalize().unwrap(),
            "regression guard: install_root must not equal workspace root for filtered installs"
        );
    }
}
