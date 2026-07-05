use crate::commands::install_targets::{install_root_for, resolve_install_targets};
use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Resolved deploy plan: which member to deploy and where it lives on disk.
/// Returned by [`resolve_deploy_target`] and consumed by the deploy pipeline.
#[derive(Debug, Clone)]
pub(in crate::commands::deploy) struct DeployPlan {
    /// Path to the source member's `package.json`. Read during manifest
    /// rewrite.
    pub member_manifest: PathBuf,
    /// Path to the source member's directory (`member_manifest.parent()`).
    pub member_dir: PathBuf,
    /// Validated, normalized output directory the deploy will write into.
    pub output_dir: PathBuf,
}

/// Resolve the deploy target from CLI flags and validate the output directory.
///
/// Returns a [`DeployPlan`] on success, or an actionable [`LpmError::Script`]
/// describing what's wrong. Validation rules:
///
/// - a filter must be non-empty
/// - filters must match exactly one workspace member
/// - The output directory must NOT be inside the workspace tree (self-deploy
///   loop prevention)
/// - The output directory must be empty (or not exist), unless `force` is set
pub(in crate::commands::deploy) fn resolve_deploy_target(
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    force: bool,
) -> Result<DeployPlan, LpmError> {
    if filters.is_empty() && filter_prod.is_empty() {
        return Err(LpmError::Script(
            "lpm deploy requires --filter <expr> or --filter-prod <expr> to identify the workspace member to deploy".into(),
        ));
    }

    // 1. Resolve target via the shared install_targets helper.
    //    has_packages=true so we never hit the "ambiguous root refresh" branch.
    //    workspace_root_flag=false because deploy never targets the root manifest.
    let targets = resolve_install_targets(
        cwd,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        false,
        true,
    )?;

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
/// the self-loop guard now canonicalizes
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
        // lexical-with-symlinks) the inputs arrive in. The old code compared
        // a mix of forms and missed the
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
    if normalized.exists() {
        let is_empty =
            std::fs::read_dir(&normalized).map_or(true, |mut iter| iter.next().is_none());
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
/// This avoids comparing canonical workspace roots against raw lexical
/// output paths when the requested output path does not exist yet.
pub(in crate::commands::deploy) fn canonicalize_or_partial(path: &Path) -> PathBuf {
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
pub(in crate::commands::deploy) fn lexical_normalize(path: &Path) -> PathBuf {
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

/// Read the deploy target's package.json `name` field for the success
/// summary. Falls back to the directory name if `name` is missing or
/// non-string.
pub(in crate::commands::deploy) fn read_member_name(manifest_path: &Path) -> String {
    let fallback = || {
        manifest_path
            .parent()
            .and_then(|p| p.file_name())
            .map_or_else(
                || "(unnamed)".to_string(),
                |n| n.to_string_lossy().to_string(),
            )
    };
    let Ok(content) = std::fs::read_to_string(manifest_path) else {
        return fallback();
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) else {
        return fallback();
    };
    doc.get("name")
        .and_then(|v| v.as_str())
        .map_or_else(fallback, |s| s.to_string())
}
