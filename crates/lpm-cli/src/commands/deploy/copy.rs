use crate::commands::publish_common;
use lpm_common::LpmError;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use super::paths::canonicalize_or_partial;

/// Names never copied to the deploy output, at any depth, on top of what
/// `lpm publish` leaves out.
///
/// - **LPM state**: `node_modules`, `.lpm`, `lpm.lock`, `lpm.lockb` are
///   recreated by the install the deploy runs, so copying them is wasted work
///   AND would mask any inconsistency.
/// - **Secrets** (CRITICAL security boundary): every `.env*` file, matched
///   separately by prefix, and every credential file publish blocks
///   (`lpm_security::behavioral::secrets::is_blocked_file`). A publish stops
///   at a credential file `files` selects; a deploy has no secret scan, so it
///   leaves them out, even a developer-only `.env.local` that would otherwise
///   ride into a Docker image.
/// - **Version control and OS cruft**.
const DEPLOY_DENY_BASENAMES: &[&str] = &[
    "node_modules",
    ".lpm",
    "lpm.lock",
    "lpm.lockb",
    ".npmrc",
    ".netrc",
    "_netrc",
    ".git",
    ".gitignore",
    ".npmignore",
    ".gitattributes",
    ".svn",
    ".hg",
    ".DS_Store",
    "Thumbs.db",
];

/// Stats from a [`copy_member_source`] call, reported in the deploy's JSON
/// summary.
#[derive(Debug, Clone, Default)]
pub(in crate::commands::deploy) struct CopyStats {
    pub files_copied: usize,
    /// Files `lpm publish` would pack that the deploy withholds: `.env*`
    /// files, credential files and LPM state.
    pub files_skipped: usize,
    pub bytes_copied: u64,
}

/// Copies the files `lpm publish` would pack from `src_dir` into `dst_dir`,
/// less [`DEPLOY_DENY_BASENAMES`], `.env*` files and credential files, so a
/// deploy and a publish read `files`, `.npmignore` and `.gitignore` the same
/// way, and writes the `lpm.json` a publish ships. Files are hardlinked where
/// possible (zero disk cost on the same filesystem) and copied otherwise.
///
/// **Security invariants:**
/// - Denied names are NEVER copied, at any depth (regression-tested).
/// - The function only writes inside `dst_dir`. It does not modify `src_dir`.
/// - Symbolic links are not copied, as a publish doesn't pack them, and no
///   path is resolved outside `src_dir` or `dst_dir`.
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
    let output = cap_std::fs::Dir::open_ambient_dir(dst_dir, cap_std::ambient_authority())
        .map_err(|e| LpmError::Script(format!("failed to open deploy output dir: {e}")))?;

    let manifest_path = src_dir.join("package.json");
    let manifest =
        lpm_common::read_text_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
            LpmError::Script(format!(
                "deploy: failed to read package manifest {manifest_path:?}: {e}"
            ))
        })?;
    let manifest: serde_json::Value =
        serde_json::from_str(lpm_common::strip_utf8_bom_str(&manifest))
            .map_err(|e| LpmError::Script(format!("deploy: invalid package.json: {e}")))?;
    let canonical = src_dir
        .canonicalize()
        .map_err(|e| LpmError::Script(format!("deploy: failed to resolve {src_dir:?}: {e}")))?;
    let select = || -> Result<_, LpmError> {
        let source = Arc::new(publish_common::open_tarball_source_root(&canonical)?);
        let files = publish_common::collect_package_files(&manifest, &source)?;
        let lpm_json = crate::commands::publish::shipped_lpm_json(&source, src_dir)?;
        Ok((source, files, lpm_json))
    };
    let (source, files, lpm_json) = select().map_err(|error| match error {
        LpmError::Registry(message) => LpmError::Script(format!("deploy: {message}")),
        other => other,
    })?;

    let mut created_dirs: HashSet<PathBuf> = HashSet::new();
    for file in files {
        if file.path == "lpm.json" {
            continue;
        }
        if deploy_denies(&file.path) {
            stats.files_skipped += 1;
            continue;
        }
        let relative: PathBuf = file.path.split('/').collect();
        if let Some(parent) = relative.parent()
            && !parent.as_os_str().is_empty()
            && !created_dirs.contains(parent)
        {
            output.create_dir_all(parent).map_err(|e| {
                LpmError::Script(format!(
                    "failed to create dir {:?}: {e}",
                    dst_dir.join(parent)
                ))
            })?;
            created_dirs.insert(parent.to_path_buf());
        }
        if source.hard_link(&relative, &output, &relative).is_err() {
            source.copy(&relative, &output, &relative).map_err(|e| {
                LpmError::Script(format!(
                    "failed to copy {:?} to {:?}: {e}",
                    src_dir.join(&relative),
                    dst_dir.join(&relative)
                ))
            })?;
        }
        stats.files_copied += 1;
        stats.bytes_copied += file.size;
    }
    if let Some(content) = lpm_json {
        lpm_common::write_file_atomic_in_dir_with_options(
            &output,
            std::ffi::OsStr::new("lpm.json"),
            lpm_common::AtomicWriteOptions::new(),
            |file| std::io::Write::write_all(file, &content),
        )
        .map_err(|e| {
            LpmError::Script(format!(
                "failed to write {:?}: {e}",
                dst_dir.join("lpm.json")
            ))
        })?;
        stats.files_copied += 1;
        stats.bytes_copied += content.len() as u64;
    }

    Ok(stats)
}

/// Whether a package-relative `/` path names a file a deploy never copies.
fn deploy_denies(path: &str) -> bool {
    path.split('/').any(|segment| {
        segment
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(".env"))
            || DEPLOY_DENY_BASENAMES
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(segment))
    }) || lpm_security::behavioral::secrets::is_blocked_file(path)
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
