use std::path::Path;

use crate::SecurityAnalysisPolicy;
use lpm_common::LpmError;

use super::fs_util::{create_fs_symlink, ensure_store_tier_dir_locked, tmp_sibling};
use super::integrity::{
    has_local_source_sentinel, is_complete_object_dir, local_source_sentinel_path,
    remove_object_metadata_dir_best_effort, write_tree_object_integrity,
};

fn is_complete_local_source_object_dir(dir: &Path) -> bool {
    is_complete_object_dir(dir) && has_local_source_sentinel(dir)
}

fn write_local_source_sentinel(object_dir: &Path, source_root: &Path) -> Result<(), LpmError> {
    let path = local_source_sentinel_path(object_dir)?;
    if let Some(parent) = path.parent() {
        ensure_store_tier_dir_locked(parent).map_err(|e| {
            LpmError::Store(format!(
                "failed to create v2 local-source metadata dir at {}: {e}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(&path, source_root.display().to_string()).map_err(|e| {
        LpmError::Store(format!(
            "failed to write v2 local-source sentinel at {}: {e}",
            path.display()
        ))
    })
}

pub(crate) fn replace_local_source_object(
    tmp_dir: &Path,
    object_dir: &Path,
    source_root: &Path,
) -> Result<(), LpmError> {
    if !object_dir.exists() {
        return finish_local_source_object_rename(tmp_dir, object_dir, source_root);
    }

    write_local_source_sentinel(object_dir, source_root)?;

    let backup_dir = tmp_sibling(object_dir);
    if backup_dir.exists() {
        let _ = std::fs::remove_dir_all(&backup_dir);
    }

    match std::fs::rename(object_dir, &backup_dir) {
        Ok(()) => {}
        Err(_) if !object_dir.exists() => {
            return finish_local_source_object_rename(tmp_dir, object_dir, source_root);
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to move previous v2 local-source object at {} aside: {e}",
                object_dir.display()
            )));
        }
    }

    match std::fs::rename(tmp_dir, object_dir) {
        Ok(()) => {
            if let Err(e) = std::fs::remove_dir_all(&backup_dir) {
                tracing::warn!(
                    target = %backup_dir.display(),
                    "v2 local-source object: failed to remove replaced object backup: {e}"
                );
            }
            Ok(())
        }
        Err(e) if is_complete_local_source_object_dir(object_dir) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            let _ = std::fs::remove_dir_all(&backup_dir);
            tracing::debug!(
                target = %object_dir.display(),
                "v2 local-source object: concurrent refresh completed first: {e}"
            );
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            if !object_dir.exists() {
                let _ = std::fs::rename(&backup_dir, object_dir);
            } else {
                let _ = std::fs::remove_dir_all(&backup_dir);
            }
            Err(LpmError::Store(format!(
                "failed to atomically refresh v2 local-source object at {}: {e}",
                object_dir.display()
            )))
        }
    }
}

fn finish_local_source_object_rename(
    tmp_dir: &Path,
    object_dir: &Path,
    source_root: &Path,
) -> Result<(), LpmError> {
    write_local_source_sentinel(object_dir, source_root)?;
    match std::fs::rename(tmp_dir, object_dir) {
        Ok(()) => Ok(()),
        Err(_) if is_complete_local_source_object_dir(object_dir) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            remove_object_metadata_dir_best_effort(object_dir);
            Err(LpmError::Store(format!(
                "failed to atomically install v2 local-source object: {e}"
            )))
        }
    }
}

const MAX_LOCAL_SOURCE_OBJECT_DEPTH: usize = 256;

pub(crate) fn populate_local_source_object_into(
    source_root: &Path,
    tmp_dir: &Path,
    sri: &str,
    security_analysis_policy: SecurityAnalysisPolicy,
) -> Result<(), LpmError> {
    walk_local_source_object(source_root, source_root, tmp_dir, 0)?;
    if security_analysis_policy.is_enabled() {
        let analysis = lpm_security::behavioral::analyze_package(tmp_dir);
        if let Err(e) = lpm_security::behavioral::write_cached_analysis(tmp_dir, &analysis) {
            tracing::warn!("v2 local-source object: failed to write .lpm-security.json: {e}");
        }
    }

    write_tree_object_integrity(tmp_dir)?;
    std::fs::write(tmp_dir.join(".integrity"), sri).map_err(|e| {
        LpmError::Store(format!(
            "failed to write v2 local-source .integrity at {}: {e}",
            tmp_dir.display()
        ))
    })?;
    Ok(())
}

fn walk_local_source_object(
    source_root: &Path,
    src: &Path,
    dst: &Path,
    depth: usize,
) -> Result<(), LpmError> {
    if depth > MAX_LOCAL_SOURCE_OBJECT_DEPTH {
        return Err(LpmError::Store(format!(
            "v2 local-source object exceeds maximum walk depth ({MAX_LOCAL_SOURCE_OBJECT_DEPTH}) at {}",
            src.display()
        )));
    }
    std::fs::create_dir_all(dst).map_err(|e| {
        LpmError::Store(format!(
            "failed to create v2 local-source object dir at {}: {e}",
            dst.display()
        ))
    })?;

    for entry in std::fs::read_dir(src).map_err(|e| {
        LpmError::Store(format!(
            "failed to read local source directory {}: {e}",
            src.display()
        ))
    })? {
        let entry = entry
            .map_err(|e| LpmError::Store(format!("failed to enumerate local source entry: {e}")))?;
        let name = entry.file_name();
        if name == "node_modules" || name == ".git" {
            continue;
        }

        let entry_src = entry.path();
        let entry_dst = dst.join(&name);
        let metadata = std::fs::symlink_metadata(&entry_src).map_err(|e| {
            LpmError::Store(format!(
                "failed to stat local source entry {}: {e}",
                entry_src.display()
            ))
        })?;
        let ft = metadata.file_type();
        if ft.is_dir() {
            walk_local_source_object(source_root, &entry_src, &entry_dst, depth + 1)?;
        } else if ft.is_file() {
            materialize_local_source_file(&entry_src, &entry_dst)?;
        } else if ft.is_symlink() {
            let abs_target = entry_src
                .canonicalize()
                .unwrap_or_else(|_| entry_src.clone());
            if ft.is_symlink() && !abs_target.starts_with(source_root) {
                tracing::warn!(
                    source = %source_root.display(),
                    symlink = %entry_src.display(),
                    target = %abs_target.display(),
                    "v2 local-source object: symlink escapes source root; exposing target as-is"
                );
            }
            match std::fs::metadata(&abs_target) {
                Ok(meta) if meta.is_file() => {
                    materialize_local_source_file(&abs_target, &entry_dst)?;
                }
                _ => {
                    create_fs_symlink(&abs_target, &entry_dst).map_err(|e| {
                        LpmError::Store(format!(
                            "failed to stage v2 local-source symlink {} → {}: {e}",
                            entry_dst.display(),
                            abs_target.display()
                        ))
                    })?;
                }
            }
        }
    }

    Ok(())
}

fn materialize_local_source_file(src: &Path, dst: &Path) -> Result<(), LpmError> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            LpmError::Store(format!(
                "failed to create v2 local-source object parent at {}: {e}",
                parent.display()
            ))
        })?;
    }
    if let Err(e) = std::fs::hard_link(src, dst) {
        tracing::trace!(
            src = %src.display(),
            dst = %dst.display(),
            error = %e,
            "v2 local-source object: hardlink failed, falling back to copy"
        );
        std::fs::copy(src, dst).map_err(|copy_err| {
            LpmError::Store(format!(
                "failed to copy v2 local-source file {} → {}: {copy_err}",
                src.display(),
                dst.display()
            ))
        })?;
    }
    Ok(())
}
