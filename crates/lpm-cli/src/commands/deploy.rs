//! `lpm deploy` — materialize a workspace member's production closure into
//! a self-contained directory ready for Docker / `COPY --from=pruned`.
//!
//! Phase 32 Phase 3. See [37-rust-client-RUNNER-VISION-phase32-phase3-status.md]
//! for the milestone breakdown and the verified architectural facts that
//! shape this design.
//!
//! ## High-level pipeline
//!
//! 1. Resolve `--filter <expr>` via [`crate::commands::install_targets`]; assert
//!    the result is exactly one member (deploy is single-target).
//! 2. Validate the output directory (must be outside the workspace, must be
//!    empty unless `--force`).
//! 3. Copy the member's source files into the output dir, applying the deny
//!    list (no `.env`, no `node_modules`, no `.git`, etc.).
//! 4. Rewrite `workspace:*` references in the copied `package.json` to
//!    concrete versions (using the SOURCE workspace as the version source).
//! 5. Run the install pipeline at the output dir to materialize the
//!    dependency tree (downloads tarballs, links into `output/node_modules`).
//! 6. Emit a structured success summary.
//!
//! ## Key invariants
//!
//! - **The source workspace is read-only.** Deploy never modifies any file
//!   under the workspace root.
//! - **`--dry-run` writes nothing.** Hard rule: zero filesystem writes when
//!   `dry_run == true`.
//! - **Deploy targets exactly one member.** Multi-member deploy is Phase 12+.
//! - **Workspace members must be PUBLISHED** for cross-member deps. The
//!   resolver has no local-package handling; an unpublished workspace member
//!   referenced via `workspace:*` will fail at the resolver step. This is
//!   documented as a Phase 3 limitation.

use crate::commands::install_targets::{install_root_for, resolve_install_targets};
use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The dependency sections in `package.json` that may contain `workspace:*`
/// references. Iterated by [`rewrite_workspace_protocol_in_deploy_manifest`]
/// to make the deploy output self-contained.
const REWRITE_DEP_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

/// Files and directories that are NEVER copied to the deploy output.
///
/// Match by EXACT basename. The list is intentionally small and conservative
/// — Phase 12+ may add a user-configurable extension via `package.json` or
/// a `--exclude <glob>` flag.
///
/// Categories:
/// - **LPM internal state**: `node_modules`, `.lpm`, `lpm.lock`, `lpm.lockb`
///   are recreated by the install pipeline at the deploy output dir, so
///   copying them is wasted work AND would mask any inconsistency.
/// - **Secrets** (CRITICAL security boundary): `.env*` files contain
///   credentials and must NEVER ride along into a deploy output. Even a
///   developer-only `.env.local` is a footgun if it leaks into a Docker image.
/// - **Version control**: `.git`, `.svn`, `.hg` — the deploy output is not
///   a repo and shouldn't carry git history.
/// - **OS / editor cruft**: `.DS_Store`, `Thumbs.db`, swap files.
const DEPLOY_DENY_BASENAMES: &[&str] = &[
    // LPM internal state
    "node_modules",
    ".lpm",
    "lpm.lock",
    "lpm.lockb",
    // Secrets — critical security boundary
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
    ".env.production",
    ".env.production.local",
    ".env.test",
    ".env.test.local",
    // Version control
    ".git",
    ".gitignore",
    ".gitattributes",
    ".svn",
    ".hg",
    // Editor / OS cruft
    ".DS_Store",
    "Thumbs.db",
];

/// Stats from a [`copy_member_source`] call. Used by the deploy summary
/// (human and JSON output paths).
#[derive(Debug, Clone, Default)]
pub(crate) struct CopyStats {
    pub files_copied: usize,
    pub files_skipped: usize,
    pub bytes_copied: u64,
}

/// Recursively copy `src_dir` into `dst_dir`, skipping any path that matches
/// the [`DEPLOY_DENY_BASENAMES`] list. Uses hardlink when possible (zero disk
/// cost on the same filesystem), falls back to file copy for cross-device.
///
/// On macOS, falls back to clonefile-via-hardlink semantics — the directory
/// tree is walked file-by-file rather than as a single clonefile call,
/// because clonefile would copy denied entries too. Per-file hardlink lets
/// us apply the deny list cleanly.
///
/// **Security invariants:**
/// - Files in [`DEPLOY_DENY_BASENAMES`] are NEVER copied (regression-tested).
/// - The function only writes inside `dst_dir`. It does not modify `src_dir`.
/// - Symlinks pointing outside `src_dir` are NOT followed; they are copied
///   as-is (preserving the link, which the user may have intentionally
///   created — Phase 3 doesn't second-guess this).
pub(crate) fn copy_member_source(src_dir: &Path, dst_dir: &Path) -> Result<CopyStats, LpmError> {
    let mut stats = CopyStats::default();

    if !src_dir.exists() {
        return Err(LpmError::Script(format!(
            "deploy: source member directory {src_dir:?} does not exist"
        )));
    }

    std::fs::create_dir_all(dst_dir)
        .map_err(|e| LpmError::Script(format!("failed to create deploy output dir: {e}")))?;

    copy_member_source_recursive(src_dir, dst_dir, &mut stats)?;
    Ok(stats)
}

/// Inner recursive walker. Separated so the public entry point can do the
/// one-time `create_dir_all` and stats initialization.
fn copy_member_source_recursive(
    src: &Path,
    dst: &Path,
    stats: &mut CopyStats,
) -> Result<(), LpmError> {
    let entries = std::fs::read_dir(src)
        .map_err(|e| LpmError::Script(format!("failed to read source dir {src:?}: {e}")))?;

    for entry in entries {
        let entry =
            entry.map_err(|e| LpmError::Script(format!("failed to read directory entry: {e}")))?;
        let basename = entry.file_name();
        let basename_str = basename.to_string_lossy();

        // Apply the deny list at every level (not just root) so a nested
        // .env or node_modules anywhere under the source is excluded.
        if DEPLOY_DENY_BASENAMES
            .iter()
            .any(|denied| *denied == basename_str.as_ref())
        {
            stats.files_skipped += 1;
            continue;
        }

        let src_path = entry.path();
        let dst_path = dst.join(&basename);

        let file_type = entry
            .file_type()
            .map_err(|e| LpmError::Script(format!("failed to stat {src_path:?}: {e}")))?;

        if file_type.is_dir() {
            std::fs::create_dir_all(&dst_path)
                .map_err(|e| LpmError::Script(format!("failed to create dir {dst_path:?}: {e}")))?;
            copy_member_source_recursive(&src_path, &dst_path, stats)?;
        } else if file_type.is_symlink() {
            // Preserve symlinks as-is. Don't follow them — that could escape
            // the source dir.
            #[cfg(unix)]
            {
                let target = std::fs::read_link(&src_path).map_err(|e| {
                    LpmError::Script(format!("failed to read symlink {src_path:?}: {e}"))
                })?;
                std::os::unix::fs::symlink(&target, &dst_path).map_err(|e| {
                    LpmError::Script(format!("failed to recreate symlink {dst_path:?}: {e}"))
                })?;
            }
            #[cfg(windows)]
            {
                // Windows symlink handling is more complex. For Phase 3,
                // copy the symlink target's contents instead. A future
                // phase can handle Windows junctions properly.
                if let Ok(target_meta) = std::fs::metadata(&src_path) {
                    if target_meta.is_dir() {
                        std::fs::create_dir_all(&dst_path).ok();
                        copy_member_source_recursive(&src_path, &dst_path, stats)?;
                    } else {
                        std::fs::copy(&src_path, &dst_path)
                            .map_err(|e| LpmError::Script(format!("symlink copy failed: {e}")))?;
                    }
                }
            }
            stats.files_copied += 1;
        } else {
            // Regular file: hardlink first, fall back to copy.
            // Hardlinks are zero-cost on the same filesystem and preserve
            // the source bytes exactly. Cross-device falls through to copy.
            let bytes = std::fs::metadata(&src_path).map(|m| m.len()).unwrap_or(0);
            if std::fs::hard_link(&src_path, &dst_path).is_err() {
                std::fs::copy(&src_path, &dst_path).map_err(|e| {
                    LpmError::Script(format!("failed to copy {src_path:?} to {dst_path:?}: {e}"))
                })?;
            }
            stats.files_copied += 1;
            stats.bytes_copied += bytes;
        }
    }

    Ok(())
}

/// Resolved deploy plan: which member to deploy and where it lives on disk.
/// Returned by [`resolve_deploy_target`] and consumed by the M3-M5 pipeline.
#[derive(Debug, Clone)]
pub(crate) struct DeployPlan {
    /// Path to the source member's `package.json`. Read by M4 (manifest
    /// rewrite) — currently `#[allow(dead_code)]` until M4 lands.
    #[allow(dead_code)] // wired in M4
    pub member_manifest: PathBuf,
    /// Path to the source member's directory (`member_manifest.parent()`).
    pub member_dir: PathBuf,
    /// Validated, normalized output directory the deploy will write into.
    pub output_dir: PathBuf,
}

/// Resolve the deploy target from CLI flags and validate the output directory.
///
/// Returns a [`DeployPlan`] on success, or an actionable [`LpmError::Script`]
/// describing what's wrong. Validation rules (per Phase 3 status doc §M2):
///
/// - `--filter` must be non-empty
/// - `--filter` must match exactly one workspace member
/// - The output directory must NOT be inside the workspace tree (self-deploy
///   loop prevention)
/// - The output directory must be empty (or not exist), unless `force` is set
pub(crate) fn resolve_deploy_target(
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    force: bool,
) -> Result<DeployPlan, LpmError> {
    if filters.is_empty() {
        return Err(LpmError::Script(
            "lpm deploy requires --filter <expr> to identify the workspace member to deploy".into(),
        ));
    }

    // 1. Resolve target via the shared install_targets helper.
    //    has_packages=true so we never hit the "ambiguous root refresh" branch.
    //    workspace_root_flag=false because deploy never targets the root manifest.
    let targets = resolve_install_targets(cwd, filters, false, true)?;

    // 2. Single-member assertion.
    if targets.member_manifests.is_empty() {
        return Err(LpmError::Script(format!(
            "lpm deploy: --filter {filters:?} matched no workspace members. \
             Refine the filter to point at exactly one member."
        )));
    }
    if targets.member_manifests.len() > 1 {
        return Err(LpmError::Script(format!(
            "lpm deploy: --filter {:?} matched {} workspace members; deploy requires exactly one. \
             Refine the filter to target a single member.",
            filters,
            targets.member_manifests.len()
        )));
    }

    let member_manifest = targets.member_manifests[0].clone();
    let member_dir = install_root_for(&member_manifest).to_path_buf();

    // 3. Output directory validation.
    let output_dir = validate_output_dir(cwd, output_dir, force)?;

    Ok(DeployPlan {
        member_manifest,
        member_dir,
        output_dir,
    })
}

/// Validate the deploy output directory.
///
/// - Must not be inside the workspace tree (prevents self-deploy loops).
/// - Must be empty, not exist yet, or `force == true`.
///
/// Returns the validated, normalized path. Does NOT create the directory
/// or clean it for `--force` — those are the caller's responsibility.
///
/// **Phase 3 audit fix (2026-04-11):** the self-loop guard now canonicalizes
/// BOTH the workspace root AND the output path through `canonicalize_or_partial`
/// before comparing. The old implementation mixed canonical and lexical paths
/// in the same comparison, which silently passed on macOS when the workspace
/// was under `/tmp/...` (because `/tmp` symlinks to `/private/tmp` and the
/// asymmetric prefix comparison missed the relationship).
fn validate_output_dir(cwd: &Path, output_dir: &Path, force: bool) -> Result<PathBuf, LpmError> {
    let normalized = lexical_normalize(&cwd.join(output_dir));

    // Self-deploy loop guard: walk up from cwd looking for a workspace root,
    // then check that the output dir is not inside it.
    if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(cwd) {
        // Resolve BOTH paths through the same normalization function so the
        // comparison is meaningful regardless of which form (canonical vs
        // lexical-with-symlinks) the inputs arrive in. This is the Phase 3
        // audit fix: the old code compared a mix of forms and missed the
        // macOS `/tmp → /private/tmp` symlink case.
        let workspace_canonical = canonicalize_or_partial(&workspace.root);
        let output_canonical = canonicalize_or_partial(&normalized);

        if output_canonical == workspace_canonical
            || output_canonical.starts_with(&workspace_canonical)
        {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} resolves to {output_canonical:?} \
                 which is inside the workspace at {workspace_canonical:?}. \
                 Choose an output directory outside the workspace to prevent self-deploy loops."
            )));
        }
    }

    // Empty / force check. Non-existent paths are fine — the copy step
    // will create them. For `--force` on a non-empty existing dir, this
    // function only suppresses the non-empty error; the actual cleanup
    // (`remove_dir_all` + `create_dir_all`) lives in `run` AFTER this
    // validation succeeds. That ordering matters: validate_output_dir is
    // the safety gate that confirms the output is OUTSIDE the workspace,
    // and we deliberately never remove anything until the gate has passed.
    // Phase 3 audit fix Medium (2026-04-11) wired the cleanup in `run`.
    if normalized.exists() {
        let is_empty = std::fs::read_dir(&normalized)
            .map(|mut iter| iter.next().is_none())
            .unwrap_or(true);
        if !is_empty && !force {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} is not empty. \
                 Use --force to overwrite, or choose an empty/nonexistent output directory."
            )));
        }
    }

    Ok(normalized)
}

/// Canonicalize a path to its symlink-resolved absolute form, even when
/// the path itself does not exist yet.
///
/// Walks up from `path` looking for the deepest existing ancestor, calls
/// `canonicalize` on it (which follows symlinks), then re-appends the
/// non-existent tail components in their original order. This produces a
/// path that is comparable with other canonicalized paths under the same
/// symlink-resolved root.
///
/// **Phase 3 audit fix (2026-04-11):** added to fix the macOS self-loop
/// guard bypass. The old implementation tried direct `canonicalize` and
/// fell back to the raw lexical form on failure. That fallback meant
/// non-existent output paths under `/tmp/...` were compared in lexical
/// form against canonical workspace roots like `/private/tmp/...`, and
/// the prefix comparison silently missed the relationship.
fn canonicalize_or_partial(path: &Path) -> PathBuf {
    // Fast path: the whole path already exists, canonicalize directly.
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    // Walk up to the deepest existing ancestor, collecting the tail
    // components we'll re-append in order.
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            // Found an existing ancestor. Canonicalize it and re-append
            // the tail in original order.
            let mut result = current.canonicalize().unwrap_or(current);
            for component in tail.iter().rev() {
                result.push(component);
            }
            return result;
        }
        let Some(parent) = current.parent().map(|p| p.to_path_buf()) else {
            // Reached the filesystem root without finding an existing
            // ancestor. Fall back to the lexical form — we did our best.
            return path.to_path_buf();
        };
        if let Some(name) = current.file_name() {
            tail.push(name.to_os_string());
        }
        current = parent;
    }
}

/// Lexical path normalization: resolve `..` and `.` components without
/// touching the disk. Used as a pre-step before [`canonicalize_or_partial`]
/// to collapse any `..` and `.` components in user-supplied paths.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

/// Rewrite `workspace:*` references in the deploy output's `package.json`
/// to concrete versions, using the **source workspace** as the version
/// source. The deploy output dir has no parent workspace, so without this
/// rewrite the install pipeline at the output dir would fail to resolve
/// `workspace:*` deps.
///
/// Iterates `dependencies`, `devDependencies`, `peerDependencies`, and
/// `optionalDependencies`. Even though LPM's install pipeline only resolves
/// `dependencies` (verified via F1 in the Phase 3 design doc), the deploy
/// output should be a clean, lookup-able package.json — so we rewrite all
/// four sections defensively.
///
/// **Read-only on the source side**: this function never modifies any file
/// outside `output_dir`. The source workspace manifests are untouched.
///
/// Returns the total number of `workspace:*` references rewritten across
/// all sections.
fn rewrite_workspace_protocol_in_deploy_manifest(
    output_dir: &Path,
    source_cwd: &Path,
) -> Result<usize, LpmError> {
    // Discover the source workspace from the original cwd. The deploy
    // output dir is intentionally outside the workspace tree (M2 enforces
    // this), so we can't discover from there.
    let workspace = lpm_workspace::discover_workspace(source_cwd)
        .map_err(|e| LpmError::Script(format!("workspace discovery failed: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "deploy: source must be inside a workspace (no workspace found)".into(),
            )
        })?;

    let manifest_path = output_dir.join("package.json");
    let content = std::fs::read_to_string(&manifest_path).map_err(|e| {
        LpmError::Script(format!(
            "failed to read deploy manifest at {manifest_path:?}: {e}"
        ))
    })?;

    let mut doc: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| LpmError::Script(format!("invalid package.json in deploy output: {e}")))?;

    let mut total_rewritten = 0;

    for section in REWRITE_DEP_SECTIONS {
        let Some(section_obj) = doc.get_mut(*section).and_then(|v| v.as_object_mut()) else {
            continue;
        };

        // Snapshot the section as a HashMap for the resolver. The resolver
        // mutates the HashMap in place; we then write the rewritten values
        // back into the original Map preserving key order.
        let mut temp_deps: HashMap<String, String> = section_obj
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();

        let resolved = lpm_workspace::resolve_workspace_protocol(&mut temp_deps, &workspace)
            .map_err(|e| LpmError::Script(format!("deploy: workspace protocol error: {e}")))?;

        // Apply each rewrite back into the section_obj, preserving the
        // original key order.
        for (name, _original_protocol, _resolved_version) in &resolved {
            if let Some(new_value) = temp_deps.get(name) {
                section_obj.insert(name.clone(), serde_json::Value::String(new_value.clone()));
            }
        }

        total_rewritten += resolved.len();
    }

    // Only write the manifest back if at least one rewrite happened.
    // Otherwise leave the source-copied bytes as-is (preserves any quirks
    // in the source formatting).
    //
    // CRITICAL: `copy_member_source` uses hardlinks for performance. A
    // naive `std::fs::write` here would write THROUGH the hardlink and
    // mutate the source workspace's `package.json`. To preserve the
    // read-only-on-source invariant, we must `remove_file` first to
    // unlink the path from the shared inode, then write a fresh file.
    // This guarantees the source manifest is byte-identical even if the
    // M3 copy used a hardlink fast path.
    if total_rewritten > 0 {
        let updated = serde_json::to_string_pretty(&doc)
            .map_err(|e| LpmError::Script(format!("failed to serialize deploy manifest: {e}")))?;
        // Break any potential hardlink by unlinking the path first.
        // remove_file is idempotent for our purposes — if it doesn't exist
        // (it should), we still create it below.
        let _ = std::fs::remove_file(&manifest_path);
        std::fs::write(&manifest_path, format!("{updated}\n"))
            .map_err(|e| LpmError::Script(format!("failed to write deploy manifest: {e}")))?;
    }

    Ok(total_rewritten)
}

/// Strip `devDependencies` from the deploy output's `package.json`.
///
/// Deploy produces a **production closure**. After 2026-04-16 `lpm install`
/// resolves both `dependencies` and `devDependencies` (matching pnpm / npm
/// semantics), so if we left `devDependencies` in the copied manifest the
/// install pipeline inside the output dir would drag dev-only packages
/// (vitest, tsup, eslint, etc.) into the deploy closure. That would bloat
/// Docker images and re-open the class of bugs this command exists to
/// prevent.
///
/// The function is a no-op when the section is absent, a no-op when the
/// section exists but is empty, and otherwise removes the key entirely.
/// Returns the number of devDependency entries that were stripped so the
/// caller can surface it in the deploy summary.
///
/// **Hardlink safety.** [`copy_member_source`] uses `hard_link` as a
/// performance fast path, so the output's `package.json` can share an
/// inode with the source workspace's `package.json`. A naive `write`
/// would mutate the source — the same trap documented in D-impl-1. We
/// use the same `remove_file` + fresh `write` dance as
/// [`rewrite_workspace_protocol_in_deploy_manifest`] to break the
/// potential hardlink.
fn strip_dev_dependencies_from_deploy_manifest(output_dir: &Path) -> Result<usize, LpmError> {
    let manifest_path = output_dir.join("package.json");
    let content = std::fs::read_to_string(&manifest_path).map_err(|e| {
        LpmError::Script(format!(
            "failed to read deploy manifest at {manifest_path:?}: {e}"
        ))
    })?;

    let mut doc: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| LpmError::Script(format!("invalid package.json in deploy output: {e}")))?;

    let stripped_count = doc
        .get("devDependencies")
        .and_then(|v| v.as_object())
        .map(|o| o.len())
        .unwrap_or(0);

    if stripped_count == 0 {
        // Key missing or empty object: nothing to do, nothing to write.
        // Leaving the (possibly hardlinked) bytes alone preserves source
        // formatting and avoids an unnecessary write.
        return Ok(0);
    }

    if let Some(obj) = doc.as_object_mut() {
        obj.remove("devDependencies");
    }

    let updated = serde_json::to_string_pretty(&doc)
        .map_err(|e| LpmError::Script(format!("failed to serialize deploy manifest: {e}")))?;

    // Break any potential hardlink to the source manifest, then write a
    // fresh inode at the path. See D-impl-1 rationale in the Phase 3 doc.
    let _ = std::fs::remove_file(&manifest_path);
    std::fs::write(&manifest_path, format!("{updated}\n"))
        .map_err(|e| LpmError::Script(format!("failed to write deploy manifest: {e}")))?;

    Ok(stripped_count)
}

/// Read the deploy target's package.json `name` field for the success
/// summary. Falls back to the directory name if `name` is missing or
/// non-string.
fn read_member_name(manifest_path: &Path) -> String {
    let fallback = || {
        manifest_path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "(unnamed)".to_string())
    };
    let Ok(content) = std::fs::read_to_string(manifest_path) else {
        return fallback();
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) else {
        return fallback();
    };
    doc.get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(fallback)
}

/// Run the `lpm deploy` command.
///
/// **M5 status:** all four steps wired — target resolution, source file
/// copy, manifest rewrite, and install pipeline at the deploy output dir.
///
/// In `--json` mode the deploy command produces a deploy-specific summary
/// JSON object on stdout AFTER the install pipeline's own JSON output.
/// Together they form a JSON-Lines stream (two objects, one per line).
/// This is the same multi-object pattern Phase 2 uses for multi-target
/// installs and is documented as the deploy JSON contract.
#[allow(clippy::too_many_arguments)] // matches the install/uninstall surface for consistency
pub async fn run(
    client: &RegistryClient,
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    force: bool,
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    let plan = resolve_deploy_target(cwd, output_dir, filters, force)?;
    let member_name = read_member_name(&plan.member_manifest);

    if dry_run {
        // Dry-run: validation succeeded, but write nothing. Surface the
        // resolved plan so the user knows what would happen.
        if json_output {
            let payload = serde_json::json!({
                "success": true,
                "dry_run": true,
                "member": member_name,
                "member_dir": plan.member_dir.display().to_string(),
                "output_dir": plan.output_dir.display().to_string(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
        } else {
            eprintln!(
                "[dry-run] would deploy {} ({}) to {}",
                member_name.bold(),
                plan.member_dir.display(),
                plan.output_dir.display()
            );
        }
        return Ok(());
    }

    if !json_output {
        output::info(&format!(
            "Deploying {} from {} to {}",
            member_name.bold(),
            plan.member_dir.display(),
            plan.output_dir.display()
        ));
    }

    // Phase 3 audit Medium fix (2026-04-11): `--force` now ACTUALLY cleans
    // the output directory. Pre-fix it only suppressed the non-empty-directory
    // error in `validate_output_dir`, then ran `copy_member_source` over the
    // existing tree in place — which left orphaned files (source files that
    // had been deleted from the member, stale lockfiles, leftover
    // node_modules from a previous deploy, etc.) in the deploy output and
    // could mask "deleted file but still in container image" bugs.
    //
    // The fix: when `--force` is set and the output dir exists, unlink the
    // whole tree and recreate the empty dir before any copy step runs. This
    // restores the "fresh deploy starts from empty" invariant that callers
    // already assume. We deliberately do this AFTER validate_output_dir has
    // confirmed the path is outside the workspace, so an accidental
    // `--force` against a path that resolves into the workspace cannot
    // wipe out source files. validate_output_dir is the safety gate;
    // remove_dir_all only runs once that gate has passed.
    if force && plan.output_dir.exists() {
        std::fs::remove_dir_all(&plan.output_dir).map_err(|e| {
            LpmError::Script(format!(
                "lpm deploy --force: failed to clear output directory {:?}: {e}",
                plan.output_dir
            ))
        })?;
        std::fs::create_dir_all(&plan.output_dir).map_err(|e| {
            LpmError::Script(format!(
                "lpm deploy --force: failed to recreate empty output directory {:?}: {e}",
                plan.output_dir
            ))
        })?;
    }

    // Step 3: source file copy with deny list. The output dir is created
    // by copy_member_source if it doesn't exist yet.
    let copy_stats = copy_member_source(&plan.member_dir, &plan.output_dir)?;

    // Step 3b (2026-04-16): strip `devDependencies` from the output
    // manifest. `lpm install` now resolves devDeps (matching pnpm/npm),
    // so without this step the install pipeline inside the output dir
    // would pull dev-only tooling into the production closure. Deploy
    // is explicitly production-only — see the module-level invariants.
    let stripped_dev_deps = strip_dev_dependencies_from_deploy_manifest(&plan.output_dir)?;

    // Step 4: rewrite workspace:* references in the deploy output's
    // package.json to concrete versions, using the SOURCE workspace's
    // member versions.
    let rewritten_count = rewrite_workspace_protocol_in_deploy_manifest(&plan.output_dir, cwd)?;

    // Step 5: run the install pipeline AT THE DEPLOY OUTPUT DIR. This
    // resolves the deps from the rewritten manifest, downloads tarballs,
    // and links them into <output_dir>/node_modules/. The output is then
    // self-contained.
    //
    // Phase 35 Step 6 fix: use the injected client (carries
    // `--registry` and the shared SessionManager). Pre-fix this site
    // built a fresh `RegistryClient::new()` with no token, so any
    // `@lpm.dev` deps in the deploy output would have been
    // unauthenticated. allow_new=true bypasses the minimumReleaseAge
    // check because deploy is for fresh installs where the user has
    // already chosen what versions to use.
    let target_set: Vec<String> = vec![plan.output_dir.display().to_string()];

    crate::commands::install::run_with_options(
        client,
        &plan.output_dir,
        json_output,
        false, // offline
        false, // force — don't force re-link, the output dir is fresh
        true,  // allow_new — deploy bypasses minimumReleaseAge
        None,  // linker_override
        true,  // no_skills — deploy outputs are typically Docker images
        true,  // no_editor_setup — same reason
        false, // no_security_summary — keep findings visible in CI
        false, // auto_build — build is a separate concern
        Some(&target_set),
        None, // direct_versions_out: deploy does not finalize Phase 33 placeholders
        None, // script_policy_override: `lpm deploy` does not expose policy flags
        None, // min_release_age_override: deploy already bypasses via allow_new=true above
        // drift-ignore: deploy captures an already-resolved tree;
        // `allow_new=true` above bypasses cooldown but drift is an
        // orthogonal gate per D16. Deploy inherits the same default
        // "enforce" — the output dir carries whatever
        // trustedDependencies the project defined, so legitimately-
        // identical identities pass normally.
        crate::provenance_fetch::DriftIgnorePolicy::default(),
    )
    .await?;

    let elapsed = start.elapsed();

    // Emit the deploy-specific summary AFTER the install pipeline's output.
    // In JSON mode this produces a JSON-Lines stream (install JSON, then
    // deploy JSON). In human mode it's a final success line.
    if json_output {
        let payload = serde_json::json!({
            "success": true,
            "dry_run": false,
            "deployed": {
                "member": member_name,
                "member_dir": plan.member_dir.display().to_string(),
                "output_dir": plan.output_dir.display().to_string(),
            },
            "copy_stats": {
                "files_copied": copy_stats.files_copied,
                "files_skipped": copy_stats.files_skipped,
                "bytes_copied": copy_stats.bytes_copied,
            },
            "workspace_protocol_rewrites": rewritten_count,
            "dev_dependencies_stripped": stripped_dev_deps,
            "duration_ms": elapsed.as_millis() as u64,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        println!();
        output::success(&format!(
            "Deployed {} to {} ({} files, {}, {:.1}s)",
            member_name.bold(),
            plan.output_dir.display(),
            copy_stats.files_copied.to_string().bold(),
            lpm_common::format_bytes(copy_stats.bytes_copied),
            elapsed.as_secs_f64(),
        ));
        if rewritten_count > 0 {
            println!(
                "  {}",
                format!("rewrote {rewritten_count} workspace:* reference(s) to concrete versions")
                    .dimmed()
            );
        }
        if stripped_dev_deps > 0 {
            println!(
                "  {}",
                format!(
                    "stripped {stripped_dev_deps} devDependency entr{} (deploy is production-only)",
                    if stripped_dev_deps == 1 { "y" } else { "ies" }
                )
                .dimmed()
            );
        }
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    // ── M1 entry-point guard tests ─────────────────────────────────────────

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

    // ── M2 target resolution tests ─────────────────────────────────────────

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

        let err =
            resolve_deploy_target(tmp.path(), &output, &["ui-*".to_string()], false).unwrap_err();
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

        let err =
            resolve_deploy_target(tmp.path(), &output, &["foo".to_string()], false).unwrap_err();
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

        let err =
            resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
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

        let err =
            resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
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

        let err =
            resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
        assert!(err.to_string().contains("inside the workspace"));
    }

    // ── Phase 3 GPT-5.4 audit regression (High): self-loop guard bypass ────

    #[cfg(unix)]
    #[test]
    fn canonicalize_or_partial_resolves_symlink_through_nonexistent_tail() {
        // PHASE 3 AUDIT REGRESSION (High):
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
        // PHASE 3 AUDIT REGRESSION (High):
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
            "PHASE 3 AUDIT REGRESSION (High): symlink-aliased output that resolves into the \
             workspace must be caught as a self-deploy loop. got: {msg}"
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
            "PHASE 3 AUDIT REGRESSION (High): canonical output inside a symlink-accessed \
             workspace must also be caught. got: {msg}"
        );
    }

    // ── M2 dry-run tests ───────────────────────────────────────────────────

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

    // ── M5 end-to-end (no-deps fixture) ────────────────────────────────────
    //
    // The install pipeline at the deploy output dir runs for real. We test
    // it against fixtures that have empty `dependencies` so the resolver
    // hits the no-deps short-circuit and returns success without any
    // network calls. The M3-fix to the empty-deps early return makes this
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
    async fn run_full_pipeline_workspace_protocol_dep_is_rewritten_in_output() {
        // The fixture has api → workspace:* auth. After deploy:
        // - output/package.json has @scope/auth: "1.5.0" (concrete version)
        // - The source workspace's api/package.json STILL has workspace:*
        // We can't run the actual install (auth isn't published) but we
        // can verify the rewrite step landed correctly.
        //
        // Caveat: this test will FAIL at the install pipeline step
        // because @scope/auth isn't in the registry. We use try_run and
        // assert the rewrite happened EVEN if the install fails.
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

        // The result will be Err because the install pipeline can't fetch
        // @scope/auth from the registry. But the source copy + rewrite
        // happen first, so we can verify them on disk regardless.
        let _ = result; // expected to fail at install step

        if output.join("package.json").exists() {
            let after: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(output.join("package.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                after["dependencies"]["@scope/auth"], "1.5.0",
                "workspace:* must be rewritten to concrete version in deploy output"
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
        // PHASE 3 AUDIT REGRESSION (Medium):
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
            "PHASE 3 AUDIT REGRESSION (Medium): --force must clean stale root files"
        );
        assert!(
            !output.join("legacy-config.json").exists(),
            "PHASE 3 AUDIT REGRESSION (Medium): --force must clean stale root files"
        );
        assert!(
            !output.join("legacy-subdir").exists(),
            "PHASE 3 AUDIT REGRESSION (Medium): --force must clean stale subdirs"
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
            "PHASE 3 AUDIT REGRESSION (Medium): --force must clean stale node_modules contents"
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

    // ── M6 end-to-end integration: deny list + rewrite together ────────────

    #[tokio::test]
    async fn run_e2e_combines_deny_list_and_manifest_rewrite() {
        // Comprehensive end-to-end test: workspace with workspace:* deps,
        // member containing .env files and a node_modules, deploy it, and
        // verify EVERY invariant in one place:
        //
        // 1. Source files are copied (positive assertion)
        // 2. .env files are NOT in the deploy output (security)
        // 3. node_modules is NOT in the deploy output (security)
        // 4. workspace:* deps are rewritten to concrete versions
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

        // Run deploy. This will fail at the install pipeline step because
        // @scope/auth isn't in the registry, but the M3+M4 work runs first.
        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");
        let _ = run(
            &RegistryClient::new(),
            &workspace_root,
            &output,
            &["@scope/api".to_string()],
            false,
            false,
            true,
        )
        .await;

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

        // ── Security: node_modules not present ────────────────────────────
        assert!(
            !output.join("node_modules").exists(),
            "node_modules must not be deployed"
        );

        // ── workspace:* deps rewritten to concrete versions ───────────────
        let deployed_pkg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        assert_eq!(
            deployed_pkg["dependencies"]["@scope/auth"], "1.5.0",
            "workspace:* must be rewritten to a concrete version in the deploy output"
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

    // ── M4 manifest rewrite tests ──────────────────────────────────────────

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
        let original_bytes =
            std::fs::read(workspace_root.join("packages/foo/package.json")).unwrap();
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

        let err =
            rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap_err();
        assert!(err.to_string().contains("@scope/missing"));
    }

    #[test]
    fn rewrite_workspace_protocol_breaks_hardlinks_to_protect_source() {
        // CRITICAL BUG REGRESSION (M5 audit during initial development):
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

        let err =
            rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap_err();
        assert!(err.to_string().contains("read deploy manifest"));
    }

    // ── M3 source file copier tests ────────────────────────────────────────
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
    // 2026-04-16: deploy stays prod-only after `lpm install` learned to
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
        // Mirror of the D-impl-1 regression pattern: copy_member_source may
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

        let source_inode_before = source_manifest.metadata().unwrap();
        let output_inode_before = output_manifest.metadata().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
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
}
