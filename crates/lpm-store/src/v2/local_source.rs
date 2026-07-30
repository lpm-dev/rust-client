use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::Path;

use crate::SecurityAnalysisPolicy;
use lpm_common::LpmError;

use super::fs_util::{create_fs_symlink, ensure_store_tier_dir_locked, tmp_sibling};
use super::integrity::{
    OBJECT_INTEGRITY_FILENAME, has_local_source_sentinel, is_complete_object_dir,
    local_source_sentinel_path, remove_object_metadata_dir_best_effort,
    write_tree_object_integrity,
};
use super::tree_hash::is_object_metadata_sidecar_name;

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

    // An unchanged source tree produces a byte-identical snapshot.
    // Keeping the published object avoids the backup/replace rename
    // window, which a concurrent reader (validation or linking in a
    // sibling install) could otherwise observe as a mixed tree.
    if existing_snapshot_matches_replacement(tmp_dir, object_dir) {
        let _ = std::fs::remove_dir_all(tmp_dir);
        write_local_source_sentinel(object_dir, source_root)?;
        return Ok(());
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

fn existing_snapshot_matches_replacement(tmp_dir: &Path, object_dir: &Path) -> bool {
    if !is_complete_local_source_object_dir(object_dir) {
        return false;
    }
    let content_integrity = |dir: &Path| {
        std::fs::read_to_string(dir.join(OBJECT_INTEGRITY_FILENAME))
            .map(|raw| raw.trim().to_owned())
            .ok()
    };
    match (content_integrity(tmp_dir), content_integrity(object_dir)) {
        (Some(fresh), Some(existing)) => fresh == existing,
        _ => false,
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

#[inline]
fn is_excluded_local_source_entry(name: &OsStr) -> bool {
    name == "node_modules"
        || name == ".git"
        // LPM updates these VCS sidecars during installs; including them makes
        // recursive workspace package snapshots invalidate themselves.
        || name == ".gitignore"
        || name == ".gitattributes"
        || name == ".lpm"
        || name == "lpm.lock"
        || name == "lpm.lockb"
}

pub(crate) fn local_source_snapshot_matches(
    source_root: &Path,
    object_root: &Path,
) -> Result<bool, LpmError> {
    if !is_complete_local_source_object_dir(object_root) {
        return Ok(false);
    }
    local_source_snapshot_dirs_match(source_root, object_root, object_root, 0)
}

fn local_source_snapshot_dirs_match(
    source_dir: &Path,
    object_dir: &Path,
    object_root: &Path,
    depth: usize,
) -> Result<bool, LpmError> {
    if depth > MAX_LOCAL_SOURCE_OBJECT_DEPTH {
        return Err(LpmError::Store(format!(
            "v2 local-source object exceeds maximum walk depth ({MAX_LOCAL_SOURCE_OBJECT_DEPTH}) at {}",
            source_dir.display()
        )));
    }

    let source_entries =
        read_snapshot_entries(source_dir, |_, name| is_excluded_local_source_entry(name))?;
    let object_entries = read_snapshot_entries(object_dir, |dir, name| {
        is_object_metadata_sidecar_name(object_root, dir, name)
    })?;
    if source_entries.len() != object_entries.len() {
        return Ok(false);
    }

    let mut source_path = source_dir.to_path_buf();
    let mut object_path = object_dir.to_path_buf();
    for (source, object) in source_entries.iter().zip(&object_entries) {
        if source.name != object.name {
            return Ok(false);
        }
        source_path.push(&source.name);
        object_path.push(&object.name);

        let source_type = source.metadata.file_type();
        let object_type = object.metadata.file_type();
        let matches = if source_type.is_dir() {
            object_type.is_dir()
                && local_source_snapshot_dirs_match(
                    &source_path,
                    &object_path,
                    object_root,
                    depth + 1,
                )?
        } else if source_type.is_file() {
            object_type.is_file()
                && regular_files_match(
                    &source_path,
                    &source.metadata,
                    &object_path,
                    &object.metadata,
                )?
        } else if source_type.is_symlink() {
            symlink_snapshot_entry_matches(&source_path, &object_path, &object.metadata)?
        } else {
            false
        };

        source_path.pop();
        object_path.pop();
        if !matches {
            return Ok(false);
        }
    }
    Ok(true)
}

struct SnapshotEntry {
    name: OsString,
    metadata: std::fs::Metadata,
}

fn read_snapshot_entries(
    dir: &Path,
    exclude: impl Fn(&Path, &OsStr) -> bool,
) -> Result<Vec<SnapshotEntry>, LpmError> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|error| {
        LpmError::Store(format!(
            "failed to read local-source snapshot directory {}: {error}",
            dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            LpmError::Store(format!(
                "failed to enumerate local-source snapshot entry: {error}"
            ))
        })?;
        let name = entry.file_name();
        if exclude(dir, &name) {
            continue;
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect local-source snapshot entry {}: {error}",
                path.display()
            ))
        })?;
        entries.push(SnapshotEntry { name, metadata });
    }
    entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn symlink_snapshot_entry_matches(
    source_path: &Path,
    object_path: &Path,
    object_metadata: &std::fs::Metadata,
) -> Result<bool, LpmError> {
    let resolved = source_path
        .canonicalize()
        .unwrap_or_else(|_| source_path.to_path_buf());
    match std::fs::metadata(&resolved) {
        Ok(source_metadata) if source_metadata.is_file() => {
            if !object_metadata.file_type().is_file() {
                return Ok(false);
            }
            regular_files_match(&resolved, &source_metadata, object_path, object_metadata)
        }
        _ if object_metadata.file_type().is_symlink() => std::fs::read_link(object_path)
            .map(|target| target == resolved)
            .map_err(|error| {
                LpmError::Store(format!(
                    "failed to inspect local-source snapshot symlink {}: {error}",
                    object_path.display()
                ))
            }),
        _ => Ok(false),
    }
}

fn regular_files_match(
    source_path: &Path,
    source_metadata: &std::fs::Metadata,
    object_path: &Path,
    object_metadata: &std::fs::Metadata,
) -> Result<bool, LpmError> {
    if !regular_file_metadata_matches(source_metadata, object_metadata) {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if source_metadata.dev() == object_metadata.dev()
            && source_metadata.ino() == object_metadata.ino()
        {
            return Ok(true);
        }
    }

    let mut source = std::fs::File::open(source_path).map_err(|error| {
        LpmError::Store(format!(
            "failed to read local source file {}: {error}",
            source_path.display()
        ))
    })?;
    let mut object = std::fs::File::open(object_path).map_err(|error| {
        LpmError::Store(format!(
            "failed to read local-source snapshot file {}: {error}",
            object_path.display()
        ))
    })?;
    let mut source_buffer = [0u8; 8192];
    let mut object_buffer = [0u8; 8192];
    loop {
        let source_read = source.read(&mut source_buffer).map_err(|error| {
            LpmError::Store(format!(
                "failed to read local source file {}: {error}",
                source_path.display()
            ))
        })?;
        let object_read = object.read(&mut object_buffer).map_err(|error| {
            LpmError::Store(format!(
                "failed to read local-source snapshot file {}: {error}",
                object_path.display()
            ))
        })?;
        if source_read != object_read
            || source_buffer[..source_read] != object_buffer[..object_read]
        {
            return Ok(false);
        }
        if source_read == 0 {
            break;
        }
    }

    let source_after = source.metadata().map_err(|error| {
        LpmError::Store(format!(
            "failed to recheck local source file {}: {error}",
            source_path.display()
        ))
    })?;
    let object_after = object.metadata().map_err(|error| {
        LpmError::Store(format!(
            "failed to recheck local-source snapshot file {}: {error}",
            object_path.display()
        ))
    })?;
    Ok(metadata_unchanged(source_metadata, &source_after)
        && metadata_unchanged(object_metadata, &object_after))
}

fn regular_file_metadata_matches(
    source_metadata: &std::fs::Metadata,
    object_metadata: &std::fs::Metadata,
) -> bool {
    if source_metadata.len() != object_metadata.len() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        source_metadata.permissions().mode() & 0o7777
            == object_metadata.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        source_metadata.permissions().readonly() == object_metadata.permissions().readonly()
    }
}

fn metadata_unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    if before.len() != after.len()
        || before.permissions().readonly() != after.permissions().readonly()
        || before.modified().ok() != after.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.mode() == after.mode()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

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
        if is_excluded_local_source_entry(&name) {
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
