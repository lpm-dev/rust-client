use lpm_common::LpmError;
use std::path::Path;

use super::file_select::PackageFileSelector;
#[cfg(unix)]
use super::paths::canonicalize_or_partial;

/// Files and directories that are NEVER copied to the deploy output.
///
/// Match by EXACT basename. The list is intentionally small and conservative
/// —a future release may add a user-configurable extension via `package.json` or
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
    ".npmignore",
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
pub(in crate::commands::deploy) struct CopyStats {
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
///   created — doesn't second-guess this).
pub(in crate::commands::deploy) fn copy_member_source(
    src_dir: &Path,
    dst_dir: &Path,
) -> Result<CopyStats, LpmError> {
    let mut stats = CopyStats::default();

    if !src_dir.exists() {
        return Err(LpmError::Script(format!(
            "deploy: source member directory {src_dir:?} does not exist"
        )));
    }

    std::fs::create_dir_all(dst_dir)
        .map_err(|e| LpmError::Script(format!("failed to create deploy output dir: {e}")))?;

    let selector = PackageFileSelector::from_package_dir(src_dir)?;
    copy_member_source_recursive(src_dir, src_dir, dst_dir, &selector, &mut stats)?;
    Ok(stats)
}

/// Inner recursive walker. Separated so the public entry point can do the
/// one-time `create_dir_all` and stats initialization.
fn copy_member_source_recursive(
    root: &Path,
    src: &Path,
    dst: &Path,
    selector: &PackageFileSelector,
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
        let rel_path = src_path.strip_prefix(root).unwrap_or(src_path.as_path());
        if !selector.should_copy(rel_path, file_type.is_dir()) {
            stats.files_skipped += 1;
            continue;
        }

        if file_type.is_dir() {
            std::fs::create_dir_all(&dst_path)
                .map_err(|e| LpmError::Script(format!("failed to create dir {dst_path:?}: {e}")))?;
            copy_member_source_recursive(root, &src_path, &dst_path, selector, stats)?;
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
                stats.files_copied += 1;
            }
            #[cfg(windows)]
            {
                // Windows cannot recreate symlinks here without risking
                // target-type ambiguity. Skip them so deploy never follows
                // a junction or symlink out of the source member tree.
                tracing::warn!(
                    target: "lpm_cli::deploy",
                    src = %src_path.display(),
                    "skipping Windows symlink/junction in deploy member tree; refusing to follow out-of-source targets"
                );
                stats.files_skipped += 1;
            }
            #[cfg(not(any(unix, windows)))]
            {
                stats.files_skipped += 1;
            }
        } else {
            // Regular file: hardlink first, fall back to copy.
            // Hardlinks are zero-cost on the same filesystem and preserve
            // the source bytes exactly. Cross-device falls through to copy.
            let bytes = std::fs::metadata(&src_path).map_or(0, |m| m.len());
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

#[cfg(unix)]
pub(in crate::commands::deploy) fn retarget_internal_node_modules_symlinks(
    output_dir: &Path,
) -> Result<usize, LpmError> {
    let node_modules = output_dir.join("node_modules");
    if !node_modules.exists() {
        return Ok(0);
    }
    let output_root = canonicalize_or_partial(output_dir);
    retarget_internal_symlinks_recursive(&node_modules, output_dir, &output_root)
}

#[cfg(unix)]
fn retarget_internal_symlinks_recursive(
    dir: &Path,
    output_dir: &Path,
    output_root: &Path,
) -> Result<usize, LpmError> {
    let mut retargeted = 0;
    for entry in std::fs::read_dir(dir)
        .map_err(|e| LpmError::Script(format!("deploy: failed to read {dir:?}: {e}")))?
    {
        let entry = entry
            .map_err(|e| LpmError::Script(format!("deploy: failed to read dir entry: {e}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| LpmError::Script(format!("deploy: failed to stat {path:?}: {e}")))?;
        if file_type.is_symlink() {
            let target = std::fs::read_link(&path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to read symlink {path:?}: {e}"))
            })?;
            if !target.is_absolute() {
                continue;
            }
            let target_canonical = canonicalize_or_partial(&target);
            if !target_canonical.starts_with(output_root) {
                continue;
            }
            let target_for_relative = if target.starts_with(output_dir) {
                target
            } else {
                let suffix = target_canonical.strip_prefix(output_root).map_err(|e| {
                    LpmError::Script(format!(
                        "deploy: failed to strip deploy root from {target_canonical:?}: {e}"
                    ))
                })?;
                output_dir.join(suffix)
            };
            let parent = path.parent().ok_or_else(|| {
                LpmError::Script(format!("deploy: symlink path {path:?} has no parent"))
            })?;
            let relative = pathdiff::diff_paths(&target_for_relative, parent).ok_or_else(|| {
                LpmError::Script(format!(
                    "deploy: failed to compute relative symlink target from {parent:?} to {target_for_relative:?}"
                ))
            })?;
            std::fs::remove_file(&path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to replace {path:?}: {e}"))
            })?;
            std::os::unix::fs::symlink(&relative, &path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to write symlink {path:?}: {e}"))
            })?;
            retargeted += 1;
        } else if file_type.is_dir() {
            retargeted += retarget_internal_symlinks_recursive(&path, output_dir, output_root)?;
        }
    }
    Ok(retargeted)
}

#[cfg(not(unix))]
pub(in crate::commands::deploy) fn retarget_internal_node_modules_symlinks(
    _output_dir: &Path,
) -> Result<usize, LpmError> {
    Ok(0)
}
