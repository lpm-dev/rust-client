use std::ffi::{OsStr, OsString};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use lpm_common::LpmError;
use sha2::{Digest, Sha256};

use super::integrity::{OBJECT_INTEGRITY_FILENAME, TREE_SNAPSHOT_FILENAME};

pub(crate) struct TreeIntegrities {
    pub(crate) content: String,
    pub(crate) metadata: String,
    pub(crate) stats: ObjectTreeStats,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ObjectTreeStats {
    pub(crate) file_count: u64,
    pub(crate) dir_count: u64,
    pub(crate) symlink_count: u64,
    pub(crate) unpacked_bytes: u64,
}

#[derive(Default)]
pub(crate) struct ExtractedObjectStats {
    stats: ObjectTreeStats,
    dirs: std::collections::HashSet<PathBuf>,
}

impl ExtractedObjectStats {
    pub(crate) fn record_file(&mut self, relative_path: &Path, size: u64) {
        self.stats.file_count = self.stats.file_count.saturating_add(1);
        self.stats.unpacked_bytes = self.stats.unpacked_bytes.saturating_add(size);

        let mut parent = relative_path.parent();
        while let Some(dir) = parent {
            if dir.as_os_str().is_empty() {
                break;
            }
            self.dirs.insert(dir.to_path_buf());
            parent = dir.parent();
        }
    }

    pub(crate) fn finish(mut self) -> ObjectTreeStats {
        self.stats.dir_count = self.dirs.len() as u64;
        self.stats
    }
}

pub(crate) fn compute_object_tree_integrities(dir: &Path) -> Result<TreeIntegrities, LpmError> {
    let mut content_hasher = Sha256::new();
    let mut metadata_hasher = Sha256::new();
    let mut stats = ObjectTreeStats::default();
    hash_object_tree_dir(
        dir,
        dir,
        Some(&mut content_hasher),
        &mut metadata_hasher,
        Some(&mut stats),
    )?;
    Ok(TreeIntegrities {
        content: format!("sha256-{}", hex::encode(content_hasher.finalize())),
        metadata: format!("sha256-{}", hex::encode(metadata_hasher.finalize())),
        stats,
    })
}

pub(crate) fn compute_tree_metadata_integrity(dir: &Path) -> Result<String, LpmError> {
    let mut hasher = Sha256::new();
    hash_object_tree_dir(dir, dir, None, &mut hasher, None)?;
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

fn hash_object_tree_dir(
    root: &Path,
    dir: &Path,
    content_hasher: Option<&mut Sha256>,
    metadata_hasher: &mut Sha256,
    stats: Option<&mut ObjectTreeStats>,
) -> Result<(), LpmError> {
    let mut relative = Vec::new();
    hash_object_tree_dir_inner(
        root,
        dir,
        &mut relative,
        content_hasher,
        metadata_hasher,
        stats,
    )
}

fn hash_object_tree_dir_inner(
    root: &Path,
    dir: &Path,
    relative: &mut Vec<u8>,
    mut content_hasher: Option<&mut Sha256>,
    metadata_hasher: &mut Sha256,
    mut stats: Option<&mut ObjectTreeStats>,
) -> Result<(), LpmError> {
    let mut entries = Vec::new();
    // Unix DirEntry values keep the directory handle alive; store owned names
    // before recursing so deep warm-cache validation stays below RLIMIT_NOFILE.
    for entry in std::fs::read_dir(dir).map_err(|e| {
        LpmError::Store(format!(
            "failed to read v2 object tree at {}: {e}",
            dir.display()
        ))
    })? {
        let entry = entry.map_err(|e| {
            LpmError::Store(format!("failed to enumerate v2 object tree entry: {e}"))
        })?;
        let file_name = entry.file_name();
        if is_object_metadata_sidecar_name(root, dir, &file_name) {
            continue;
        }
        let metadata = entry.metadata().map_err(|e| {
            LpmError::Store(format!(
                "failed to stat v2 object tree entry {}: {e}",
                dir.join(&file_name).display()
            ))
        })?;
        entries.push(ObjectTreeEntry {
            file_name,
            metadata,
        });
    }
    entries.sort_by(|a, b| a.file_name.cmp(&b.file_name));

    let mut path = dir.to_path_buf();
    for entry in entries {
        let entry_name = entry.file_name;
        let relative_len = relative.len();
        if relative_len != 0 {
            relative.push(b'/');
        }
        push_os_str_bytes(relative, &entry_name);
        let metadata = entry.metadata;
        let file_type = metadata.file_type();
        let mut path_pushed = false;
        let result = if file_type.is_dir() {
            if let Some(stats) = stats.as_deref_mut() {
                stats.dir_count = stats.dir_count.saturating_add(1);
            }
            path.push(&entry_name);
            path_pushed = true;
            let mode = object_entry_mode(&metadata).to_le_bytes();
            if let Some(hasher) = content_hasher.as_deref_mut() {
                hash_object_tree_record(hasher, b"dir", relative.as_slice(), &mode);
            }
            hash_tree_metadata_record(metadata_hasher, b"dir", relative.as_slice(), &metadata, &[]);
            hash_object_tree_dir_inner(
                root,
                &path,
                relative,
                content_hasher.as_deref_mut(),
                metadata_hasher,
                stats.as_deref_mut(),
            )
        } else if file_type.is_file() {
            if let Some(stats) = stats.as_deref_mut() {
                stats.file_count = stats.file_count.saturating_add(1);
                stats.unpacked_bytes = stats.unpacked_bytes.saturating_add(metadata.len());
            }
            hash_tree_metadata_record(
                metadata_hasher,
                b"file",
                relative.as_slice(),
                &metadata,
                &[],
            );
            if let Some(hasher) = content_hasher.as_deref_mut() {
                path.push(&entry_name);
                path_pushed = true;
                hash_object_file(hasher, relative.as_slice(), &path, &metadata)?;
            }
            Ok(())
        } else if file_type.is_symlink() {
            if let Some(stats) = stats.as_deref_mut() {
                stats.symlink_count = stats.symlink_count.saturating_add(1);
            }
            path.push(&entry_name);
            path_pushed = true;
            let target = std::fs::read_link(&path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to read v2 object symlink {}: {e}",
                    path.display()
                ))
            })?;
            let mut target_bytes = Vec::new();
            push_os_str_bytes(&mut target_bytes, target.as_os_str());
            if let Some(hasher) = content_hasher.as_deref_mut() {
                hash_object_tree_record(hasher, b"symlink", relative.as_slice(), &target_bytes);
            }
            hash_tree_metadata_record(
                metadata_hasher,
                b"symlink",
                relative.as_slice(),
                &metadata,
                &target_bytes,
            );
            Ok(())
        } else {
            path.push(&entry_name);
            path_pushed = true;
            Err(LpmError::Store(format!(
                "unsupported v2 object entry type at {}",
                path.display()
            )))
        };
        relative.truncate(relative_len);
        if path_pushed {
            path.pop();
        }
        result?;
    }
    Ok(())
}

struct ObjectTreeEntry {
    file_name: OsString,
    metadata: std::fs::Metadata,
}

fn hash_tree_metadata_record(
    hasher: &mut Sha256,
    kind: &[u8],
    relative: &[u8],
    metadata: &std::fs::Metadata,
    payload: &[u8],
) {
    hasher.update(kind);
    hasher.update(b"\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update(object_entry_mode(metadata).to_le_bytes());
    hasher.update(metadata.len().to_le_bytes());
    hasher.update(modified_time_nanos(metadata).to_le_bytes());
    hasher.update(change_time_nanos(metadata).to_le_bytes());
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
}

fn modified_time_nanos(metadata: &std::fs::Metadata) -> i128 {
    let Ok(modified) = metadata.modified() else {
        return 0;
    };
    match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    }
}

#[cfg(unix)]
fn change_time_nanos(metadata: &std::fs::Metadata) -> i128 {
    use std::os::unix::fs::MetadataExt;
    i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec())
}

#[cfg(not(unix))]
fn change_time_nanos(_metadata: &std::fs::Metadata) -> i128 {
    0
}

fn hash_object_file(
    hasher: &mut Sha256,
    relative: &[u8],
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), LpmError> {
    hasher.update(b"file\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update(object_entry_mode(metadata).to_le_bytes());
    hasher.update(metadata.len().to_le_bytes());
    let file = std::fs::File::open(path).map_err(|e| {
        LpmError::Store(format!(
            "failed to open v2 object file {} for integrity hashing: {e}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf).map_err(|e| {
            LpmError::Store(format!(
                "failed to read v2 object file {} for integrity hashing: {e}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(())
}
fn hash_object_tree_record(hasher: &mut Sha256, kind: &[u8], relative: &[u8], payload: &[u8]) {
    hasher.update(kind);
    hasher.update(b"\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
}

#[cfg(unix)]
fn push_os_str_bytes(out: &mut Vec<u8>, value: &std::ffi::OsStr) {
    use std::os::unix::ffi::OsStrExt;
    out.extend_from_slice(value.as_bytes());
}

#[cfg(windows)]
fn push_os_str_bytes(out: &mut Vec<u8>, value: &std::ffi::OsStr) {
    use std::os::windows::ffi::OsStrExt;
    for unit in value.encode_wide() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn push_os_str_bytes(out: &mut Vec<u8>, value: &std::ffi::OsStr) {
    out.extend_from_slice(value.to_string_lossy().as_bytes());
}

#[cfg(unix)]
fn object_entry_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn object_entry_mode(metadata: &std::fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

pub(crate) fn is_object_metadata_sidecar(root: &Path, path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(name) = path.file_name() else {
        return false;
    };
    is_object_metadata_sidecar_name(root, parent, name)
}

pub(crate) fn is_object_metadata_sidecar_name(root: &Path, dir: &Path, name: &OsStr) -> bool {
    if dir != root {
        return false;
    }
    let Some(name) = name.to_str() else {
        return false;
    };
    matches!(
        name,
        ".integrity" | ".lpm-security.json" | OBJECT_INTEGRITY_FILENAME | TREE_SNAPSHOT_FILENAME
    ) || name.starts_with(".lpm-tree-snapshot.json.tmp.")
        || name.starts_with("..lpm-tree-snapshot.json.tmp.")
        || name.starts_with(".lpm-object-integrity.tmp.")
        || name.starts_with("..lpm-object-integrity.tmp.")
}
