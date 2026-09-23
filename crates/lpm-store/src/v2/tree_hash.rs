use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};

use lpm_common::{LpmError, is_symlink_or_junction};
use lpm_extractor::ExtractedFileDigest;
use sha2::{Digest, Sha256};

use super::integrity::{OBJECT_INTEGRITY_FILENAME, TREE_SNAPSHOT_FILENAME};

#[derive(Debug)]
pub(crate) struct TreeIntegrities {
    pub(crate) content: String,
    pub(crate) metadata: String,
    pub(crate) stats: ObjectTreeStats,
    pub(crate) content_schema: TreeContentSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeContentSchema {
    SequentialV1,
    EntryDigestV2,
}

impl TreeContentSchema {
    pub(crate) fn from_snapshot_schema(schema: u32) -> Option<Self> {
        match schema {
            1 => Some(Self::SequentialV1),
            2 => Some(Self::EntryDigestV2),
            _ => None,
        }
    }

    pub(crate) fn snapshot_schema(self) -> u32 {
        match self {
            Self::SequentialV1 => 1,
            Self::EntryDigestV2 => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ObjectTreeStats {
    pub(crate) file_count: u64,
    pub(crate) dir_count: u64,
    pub(crate) symlink_count: u64,
    pub(crate) unpacked_bytes: u64,
}

pub(crate) struct StreamedTreeBuilder {
    file_digests: HashMap<PathBuf, [u8; 32]>,
}

#[derive(Clone, Copy)]
pub(crate) enum TreeMetadataKind {
    Directory,
    File,
    Symlink,
}

pub(crate) struct TreeMetadataBuilder {
    records: Vec<TreeMetadataRecord>,
}

struct TreeMetadataRecord {
    kind: TreeMetadataKind,
    relative: Vec<u8>,
    mode: u32,
    len: u64,
    modified_time_nanos: i128,
    change_time_nanos: i128,
    payload: Vec<u8>,
}

impl TreeMetadataBuilder {
    pub(crate) fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub(crate) fn reserve(
        &mut self,
        root: &Path,
        path: &Path,
        kind: TreeMetadataKind,
    ) -> Result<usize, LpmError> {
        let relative = relative_path_bytes(root, path)?;
        let index = self.records.len();
        self.records.push(TreeMetadataRecord {
            kind,
            relative,
            mode: 0,
            len: 0,
            modified_time_nanos: 0,
            change_time_nanos: 0,
            payload: Vec::new(),
        });
        Ok(index)
    }

    pub(crate) fn refresh(
        &mut self,
        index: usize,
        path: &Path,
        payload: Vec<u8>,
    ) -> Result<(), LpmError> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            LpmError::Store(format!(
                "failed to stat materialized tree entry {}: {error}",
                path.display()
            ))
        })?;
        let record = self.records.get_mut(index).ok_or_else(|| {
            LpmError::Store("invalid materialized tree metadata record index".into())
        })?;
        record.mode = object_entry_mode(&metadata);
        record.len = metadata.len();
        record.modified_time_nanos = modified_time_nanos(&metadata);
        record.change_time_nanos = change_time_nanos(&metadata);
        record.payload = payload;
        Ok(())
    }

    pub(crate) fn record(
        &mut self,
        root: &Path,
        path: &Path,
        kind: TreeMetadataKind,
        payload: Vec<u8>,
    ) -> Result<(), LpmError> {
        let index = self.reserve(root, path, kind)?;
        self.refresh(index, path, payload)
    }

    pub(crate) fn finish(self) -> String {
        let mut hasher = Sha256::new();
        for record in self.records {
            hash_tree_metadata_fields(
                &mut hasher,
                record.kind.tag(),
                &record.relative,
                record.mode,
                record.len,
                record.modified_time_nanos,
                record.change_time_nanos,
                &record.payload,
            );
        }
        format!("sha256-{}", hex::encode(hasher.finalize()))
    }
}

impl TreeMetadataKind {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Directory => b"dir",
            Self::File => b"file",
            Self::Symlink => b"symlink",
        }
    }
}

impl StreamedTreeBuilder {
    pub(crate) fn from_extraction(file_digests: Vec<ExtractedFileDigest>) -> Self {
        let mut digests_by_path = HashMap::with_capacity(file_digests.len());
        for entry in file_digests {
            let relative = entry.relative_path.as_path();
            if is_object_metadata_sidecar_name(
                Path::new(""),
                relative.parent().unwrap_or_else(|| Path::new("")),
                relative.file_name().unwrap_or_else(|| OsStr::new("")),
            ) {
                continue;
            }
            digests_by_path.insert(entry.relative_path, entry.blake3_digest);
        }
        Self {
            file_digests: digests_by_path,
        }
    }

    pub(crate) fn finish(mut self, dir: &Path) -> Result<TreeIntegrities, LpmError> {
        compute_entry_digest_tree_integrities_with_digests(dir, &mut self.file_digests)
    }
}

pub(crate) fn compute_object_tree_integrities(dir: &Path) -> Result<TreeIntegrities, LpmError> {
    compute_object_tree_integrities_for_schema(dir, TreeContentSchema::SequentialV1)
}

pub(crate) fn compute_object_tree_integrities_for_schema(
    dir: &Path,
    schema: TreeContentSchema,
) -> Result<TreeIntegrities, LpmError> {
    let mut content_hasher = match schema {
        TreeContentSchema::SequentialV1 => TreeContentHasher::sequential(),
        TreeContentSchema::EntryDigestV2 => TreeContentHasher::entry_digest_from_filesystem(),
    };
    compute_object_tree_integrities_with_hasher(dir, &mut content_hasher, schema)
}

fn compute_entry_digest_tree_integrities_with_digests(
    dir: &Path,
    file_digests: &mut HashMap<PathBuf, [u8; 32]>,
) -> Result<TreeIntegrities, LpmError> {
    let mut content_hasher = TreeContentHasher::entry_digest_from_extraction(file_digests);
    compute_object_tree_integrities_with_hasher(
        dir,
        &mut content_hasher,
        TreeContentSchema::EntryDigestV2,
    )
}

fn compute_object_tree_integrities_with_hasher(
    dir: &Path,
    content_hasher: &mut TreeContentHasher<'_>,
    content_schema: TreeContentSchema,
) -> Result<TreeIntegrities, LpmError> {
    let mut metadata_hasher = Sha256::new();
    let mut stats = ObjectTreeStats::default();
    hash_object_tree_dir(
        dir,
        dir,
        Some(content_hasher),
        &mut metadata_hasher,
        Some(&mut stats),
    )?;
    Ok(TreeIntegrities {
        content: content_hasher.finish()?,
        metadata: format!("sha256-{}", hex::encode(metadata_hasher.finalize())),
        stats,
        content_schema,
    })
}

pub(crate) fn compute_tree_metadata_integrity(dir: &Path) -> Result<String, LpmError> {
    #[cfg(target_os = "macos")]
    match compute_tree_metadata_integrity_bulk(dir) {
        Ok(integrity) => return Ok(integrity),
        Err(error) => tracing::trace!(
            target = %dir.display(),
            "virtual store: bulk metadata walk unavailable, using portable walker: {error}"
        ),
    }
    compute_tree_metadata_integrity_portable(dir)
}

fn compute_tree_metadata_integrity_portable(dir: &Path) -> Result<String, LpmError> {
    let mut hasher = Sha256::new();
    hash_object_tree_dir(dir, dir, None, &mut hasher, None)?;
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) fn metadata_hash_implementations_match_for_test(dir: &Path) -> Result<bool, LpmError> {
    Ok(
        compute_tree_metadata_integrity_bulk(dir)?
            == compute_tree_metadata_integrity_portable(dir)?,
    )
}

fn hash_object_tree_dir(
    root: &Path,
    dir: &Path,
    content_hasher: Option<&mut TreeContentHasher<'_>>,
    metadata_hasher: &mut Sha256,
    stats: Option<&mut ObjectTreeStats>,
) -> Result<(), LpmError> {
    let mut relative = Vec::new();
    let mut bulk_buffer = if cfg!(target_os = "macos")
        && matches!(
            content_hasher.as_deref(),
            Some(TreeContentHasher::EntryDigest {
                source: EntryDigestSource::Extraction(_),
                ..
            })
        ) {
        vec![0; 64 * 1024]
    } else {
        Vec::new()
    };
    hash_object_tree_dir_inner(
        root,
        dir,
        &mut relative,
        content_hasher,
        metadata_hasher,
        stats,
        &mut bulk_buffer,
    )
}

fn read_object_tree_entries(root: &Path, dir: &Path) -> Result<Vec<ObjectTreeEntry>, LpmError> {
    let mut entries = Vec::new();
    // Unix DirEntry values keep the directory handle alive; store owned names
    // before recursing so deep warm-cache validation stays below RLIMIT_NOFILE.
    for entry in std::fs::read_dir(dir).map_err(|e| {
        LpmError::Store(format!(
            "failed to read virtual-store object tree at {}: {e}",
            dir.display()
        ))
    })? {
        let entry = entry.map_err(|e| {
            LpmError::Store(format!(
                "failed to enumerate virtual-store object tree entry: {e}"
            ))
        })?;
        let file_name = entry.file_name();
        if is_object_metadata_sidecar_name(root, dir, &file_name) {
            continue;
        }
        let metadata = entry.metadata().map_err(|e| {
            LpmError::Store(format!(
                "failed to stat virtual-store object tree entry {}: {e}",
                dir.join(&file_name).display()
            ))
        })?;
        entries.push(ObjectTreeEntry::from_metadata(file_name, &metadata));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(entries)
}

#[cfg(all(test, target_os = "macos"))]
thread_local! {
    static BULK_FINALIZATION_DIRECTORIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn read_object_tree_entries_for_walk(
    root: &Path,
    dir: &Path,
    bulk_buffer: &mut Vec<u8>,
) -> Result<Vec<ObjectTreeEntry>, LpmError> {
    #[cfg(target_os = "macos")]
    if !bulk_buffer.is_empty() {
        match read_bulk_metadata_entries(dir, bulk_buffer) {
            Ok(mut entries) => {
                entries.retain(|entry| !is_object_metadata_sidecar_name(root, dir, &entry.name));
                for entry in &mut entries {
                    if entry.kind == ObjectTreeEntryKind::Symlink {
                        refresh_bulk_symlink_metadata(dir, entry)?;
                    }
                }
                #[cfg(test)]
                BULK_FINALIZATION_DIRECTORIES.with(|count| count.set(count.get() + 1));
                return Ok(entries);
            }
            Err(error) => {
                bulk_buffer.clear();
                tracing::trace!(target = %dir.display(), "bulk metadata unavailable for object finalization: {error}");
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = bulk_buffer;
    read_object_tree_entries(root, dir)
}

#[cfg(target_os = "macos")]
fn refresh_bulk_symlink_metadata(dir: &Path, entry: &mut ObjectTreeEntry) -> Result<(), LpmError> {
    let path = dir.join(&entry.name);
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
        LpmError::Store(format!(
            "failed to stat virtual-store object tree entry {}: {error}",
            path.display()
        ))
    })?;
    *entry = ObjectTreeEntry::from_metadata(std::mem::take(&mut entry.name), &metadata);
    Ok(())
}

fn hash_object_tree_dir_inner(
    root: &Path,
    dir: &Path,
    relative: &mut Vec<u8>,
    mut content_hasher: Option<&mut TreeContentHasher<'_>>,
    metadata_hasher: &mut Sha256,
    mut stats: Option<&mut ObjectTreeStats>,
    bulk_buffer: &mut Vec<u8>,
) -> Result<(), LpmError> {
    let entries = read_object_tree_entries_for_walk(root, dir, bulk_buffer)?;

    let mut path = dir.to_path_buf();
    for entry in entries {
        let entry_name = &entry.name;
        let relative_len = relative.len();
        if relative_len != 0 {
            relative.push(b'/');
        }
        push_os_str_bytes(relative, entry_name);
        let metadata = &entry;
        let mut path_pushed = false;
        let result = if metadata.kind == ObjectTreeEntryKind::Symlink {
            if let Some(stats) = stats.as_deref_mut() {
                stats.symlink_count = stats.symlink_count.saturating_add(1);
            }
            path.push(entry_name);
            path_pushed = true;
            let target = std::fs::read_link(&path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to read virtual-store object symlink {}: {e}",
                    path.display()
                ))
            })?;
            let mut target_bytes = Vec::new();
            push_os_str_bytes(&mut target_bytes, target.as_os_str());
            if let Some(hasher) = content_hasher.as_deref_mut() {
                hasher.hash_symlink(relative.as_slice(), metadata, &target_bytes);
            }
            hash_tree_metadata_record(
                metadata_hasher,
                b"symlink",
                relative.as_slice(),
                metadata,
                &target_bytes,
            );
            Ok(())
        } else if metadata.kind == ObjectTreeEntryKind::Directory {
            if let Some(stats) = stats.as_deref_mut() {
                stats.dir_count = stats.dir_count.saturating_add(1);
            }
            path.push(entry_name);
            path_pushed = true;
            if let Some(hasher) = content_hasher.as_deref_mut() {
                hasher.hash_directory(relative.as_slice(), metadata);
            }
            hash_tree_metadata_record(metadata_hasher, b"dir", relative.as_slice(), metadata, &[]);
            hash_object_tree_dir_inner(
                root,
                &path,
                relative,
                content_hasher.as_deref_mut(),
                metadata_hasher,
                stats.as_deref_mut(),
                bulk_buffer,
            )
        } else if metadata.kind == ObjectTreeEntryKind::File {
            if let Some(stats) = stats.as_deref_mut() {
                stats.file_count = stats.file_count.saturating_add(1);
                stats.unpacked_bytes = stats.unpacked_bytes.saturating_add(metadata.len);
            }
            hash_tree_metadata_record(metadata_hasher, b"file", relative.as_slice(), metadata, &[]);
            if let Some(hasher) = content_hasher.as_deref_mut() {
                path.push(entry_name);
                path_pushed = true;
                let materialized_relative = path.strip_prefix(root).map_err(|error| {
                    LpmError::Store(format!(
                        "failed to derive relative virtual-store object path {}: {error}",
                        path.display()
                    ))
                })?;
                hasher.hash_file(relative.as_slice(), materialized_relative, &path, metadata)?;
            }
            Ok(())
        } else {
            path.push(entry_name);
            path_pushed = true;
            Err(LpmError::Store(format!(
                "unsupported virtual-store object entry type at {}",
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

#[cfg(target_os = "macos")]
fn compute_tree_metadata_integrity_bulk(dir: &Path) -> Result<String, LpmError> {
    let mut hasher = Sha256::new();
    let mut relative = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    hash_tree_metadata_dir_bulk(dir, dir, &mut relative, &mut hasher, &mut buffer)?;
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

#[cfg(target_os = "macos")]
fn hash_tree_metadata_dir_bulk(
    root: &Path,
    dir: &Path,
    relative: &mut Vec<u8>,
    hasher: &mut Sha256,
    buffer: &mut [u8],
) -> Result<(), LpmError> {
    let entries = read_bulk_metadata_entries(dir, buffer)?;
    let mut path = dir.to_path_buf();
    for entry in entries {
        if is_object_metadata_sidecar_name(root, dir, &entry.name) {
            continue;
        }
        let relative_len = relative.len();
        if relative_len != 0 {
            relative.push(b'/');
        }
        push_os_str_bytes(relative, &entry.name);
        path.push(&entry.name);

        let result = match entry.kind {
            ObjectTreeEntryKind::Directory => {
                hash_tree_metadata_fields(
                    hasher,
                    b"dir",
                    relative,
                    entry.mode,
                    entry.len,
                    entry.modified_time_nanos,
                    entry.change_time_nanos,
                    &[],
                );
                hash_tree_metadata_dir_bulk(root, &path, relative, hasher, buffer)
            }
            ObjectTreeEntryKind::File => {
                hash_tree_metadata_fields(
                    hasher,
                    b"file",
                    relative,
                    entry.mode,
                    entry.len,
                    entry.modified_time_nanos,
                    entry.change_time_nanos,
                    &[],
                );
                Ok(())
            }
            ObjectTreeEntryKind::Symlink => {
                let target = std::fs::read_link(&path).map_err(|error| {
                    LpmError::Store(format!(
                        "failed to read virtual-store object symlink {}: {error}",
                        path.display()
                    ))
                })?;
                let mut target_bytes = Vec::new();
                push_os_str_bytes(&mut target_bytes, target.as_os_str());
                hash_tree_metadata_fields(
                    hasher,
                    b"symlink",
                    relative,
                    entry.mode,
                    target_bytes.len() as u64,
                    entry.modified_time_nanos,
                    entry.change_time_nanos,
                    &target_bytes,
                );
                Ok(())
            }
            ObjectTreeEntryKind::Unsupported => Err(LpmError::Store(format!(
                "unsupported virtual-store object entry type at {}",
                path.display()
            ))),
        };
        path.pop();
        relative.truncate(relative_len);
        result?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectTreeEntryKind {
    File,
    Directory,
    Symlink,
    Unsupported,
}

#[cfg(target_os = "macos")]
fn read_bulk_metadata_entries(
    dir: &Path,
    buffer: &mut [u8],
) -> Result<Vec<ObjectTreeEntry>, LpmError> {
    use std::os::fd::AsRawFd;

    let directory = std::fs::File::open(dir).map_err(|error| {
        LpmError::Store(format!(
            "failed to read virtual-store object tree at {}: {error}",
            dir.display()
        ))
    })?;
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_RETURNED_ATTRS
            | libc::ATTR_CMN_NAME
            | libc::ATTR_CMN_OBJTYPE
            | libc::ATTR_CMN_MODTIME
            | libc::ATTR_CMN_CHGTIME
            | libc::ATTR_CMN_ACCESSMASK,
        volattr: 0,
        dirattr: libc::ATTR_DIR_DATALENGTH,
        fileattr: libc::ATTR_FILE_DATALENGTH,
        forkattr: 0,
    };
    let mut entries = Vec::new();
    loop {
        // SAFETY: `directory` remains open for the call; `attributes` is fully
        // initialized; and `buffer` exposes a valid writable region of the
        // supplied length. The kernel reports record counts and each record is
        // bounds-checked before any returned bytes are interpreted.
        let count = unsafe {
            libc::getattrlistbulk(
                directory.as_raw_fd(),
                std::ptr::addr_of_mut!(attributes).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if count < 0 {
            return Err(LpmError::Store(format!(
                "failed to enumerate virtual-store object metadata at {}: {}",
                dir.display(),
                std::io::Error::last_os_error()
            )));
        }
        if count == 0 {
            break;
        }

        let mut offset = 0_usize;
        for _ in 0..count {
            let group_start = offset;
            let group_len = read_bulk_u32(buffer, &mut offset, buffer.len())
                .and_then(|len| usize::try_from(len).ok())
                .filter(|len| *len >= std::mem::size_of::<u32>())
                .ok_or_else(|| malformed_bulk_record(dir))?;
            let group_end = group_start
                .checked_add(group_len)
                .filter(|end| *end <= buffer.len())
                .ok_or_else(|| malformed_bulk_record(dir))?;
            entries.push(parse_bulk_metadata_entry(
                dir,
                buffer,
                &mut offset,
                group_end,
            )?);
            offset = group_end;
        }
    }
    entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

#[cfg(target_os = "macos")]
fn parse_bulk_metadata_entry(
    dir: &Path,
    buffer: &[u8],
    offset: &mut usize,
    group_end: usize,
) -> Result<ObjectTreeEntry, LpmError> {
    const REQUIRED_COMMON_ATTRIBUTES: u32 = libc::ATTR_CMN_NAME
        | libc::ATTR_CMN_OBJTYPE
        | libc::ATTR_CMN_MODTIME
        | libc::ATTR_CMN_CHGTIME
        | libc::ATTR_CMN_ACCESSMASK;

    let returned_common =
        read_bulk_u32(buffer, offset, group_end).ok_or_else(|| malformed_bulk_record(dir))?;
    let _returned_volume =
        read_bulk_u32(buffer, offset, group_end).ok_or_else(|| malformed_bulk_record(dir))?;
    let returned_directory =
        read_bulk_u32(buffer, offset, group_end).ok_or_else(|| malformed_bulk_record(dir))?;
    let returned_file =
        read_bulk_u32(buffer, offset, group_end).ok_or_else(|| malformed_bulk_record(dir))?;
    let _returned_fork =
        read_bulk_u32(buffer, offset, group_end).ok_or_else(|| malformed_bulk_record(dir))?;
    if returned_common & REQUIRED_COMMON_ATTRIBUTES != REQUIRED_COMMON_ATTRIBUTES {
        return Err(LpmError::Store(format!(
            "bulk metadata attributes unavailable at {}",
            dir.display()
        )));
    }

    let name_reference_offset = *offset;
    let name_data_offset =
        read_bulk_i32(buffer, offset, group_end).ok_or_else(|| malformed_bulk_record(dir))?;
    let name_len = read_bulk_u32(buffer, offset, group_end)
        .and_then(|len| usize::try_from(len).ok())
        .ok_or_else(|| malformed_bulk_record(dir))?;
    let name_start = i64::try_from(name_reference_offset)
        .ok()
        .and_then(|base| base.checked_add(i64::from(name_data_offset)))
        .and_then(|start| usize::try_from(start).ok())
        .ok_or_else(|| malformed_bulk_record(dir))?;
    let name_end = name_start
        .checked_add(name_len)
        .filter(|end| *end <= group_end)
        .ok_or_else(|| malformed_bulk_record(dir))?;
    let name_bytes = buffer
        .get(name_start..name_end)
        .ok_or_else(|| malformed_bulk_record(dir))?;
    let name_bytes = name_bytes
        .strip_suffix(&[0])
        .ok_or_else(|| malformed_bulk_record(dir))?;
    use std::os::unix::ffi::OsStringExt;
    let name = OsString::from_vec(name_bytes.to_vec());

    let object_type =
        read_bulk_u32(buffer, offset, group_end).ok_or_else(|| malformed_bulk_record(dir))?;
    let modified_time_nanos = read_bulk_timespec_nanos(buffer, offset, group_end)
        .ok_or_else(|| malformed_bulk_record(dir))?;
    let change_time_nanos = read_bulk_timespec_nanos(buffer, offset, group_end)
        .ok_or_else(|| malformed_bulk_record(dir))?;
    let mode = read_bulk_u32(buffer, offset, group_end)
        .ok_or_else(|| malformed_bulk_record(dir))?
        & 0o7777;

    let kind = match object_type {
        1 => ObjectTreeEntryKind::File,
        2 => ObjectTreeEntryKind::Directory,
        5 => ObjectTreeEntryKind::Symlink,
        _ => ObjectTreeEntryKind::Unsupported,
    };
    let directory_len = if returned_directory & libc::ATTR_DIR_DATALENGTH != 0 {
        Some(
            read_bulk_i64(buffer, offset, group_end)
                .and_then(|len| u64::try_from(len).ok())
                .ok_or_else(|| malformed_bulk_record(dir))?,
        )
    } else {
        None
    };
    let file_len = if returned_file & libc::ATTR_FILE_DATALENGTH != 0 {
        Some(
            read_bulk_i64(buffer, offset, group_end)
                .and_then(|len| u64::try_from(len).ok())
                .ok_or_else(|| malformed_bulk_record(dir))?,
        )
    } else {
        None
    };
    let len = match kind {
        ObjectTreeEntryKind::Directory => directory_len,
        ObjectTreeEntryKind::File => file_len,
        ObjectTreeEntryKind::Symlink => Some(0),
        ObjectTreeEntryKind::Unsupported => Some(file_len.or(directory_len).unwrap_or_default()),
    }
    .ok_or_else(|| {
        LpmError::Store(format!(
            "bulk metadata length unavailable at {}",
            dir.join(&name).display()
        ))
    })?;

    Ok(ObjectTreeEntry {
        name,
        kind,
        mode,
        len,
        modified_time_nanos,
        change_time_nanos,
    })
}

#[cfg(target_os = "macos")]
fn malformed_bulk_record(dir: &Path) -> LpmError {
    LpmError::Store(format!(
        "malformed bulk metadata record while reading {}",
        dir.display()
    ))
}

#[cfg(target_os = "macos")]
fn read_bulk_u32(buffer: &[u8], offset: &mut usize, end: usize) -> Option<u32> {
    let field_end = offset.checked_add(std::mem::size_of::<u32>())?;
    if field_end > end {
        return None;
    }
    let bytes: [u8; 4] = buffer.get(*offset..field_end)?.try_into().ok()?;
    *offset = field_end;
    Some(u32::from_ne_bytes(bytes))
}

#[cfg(target_os = "macos")]
fn read_bulk_i32(buffer: &[u8], offset: &mut usize, end: usize) -> Option<i32> {
    read_bulk_u32(buffer, offset, end).map(|value| i32::from_ne_bytes(value.to_ne_bytes()))
}

#[cfg(target_os = "macos")]
fn read_bulk_i64(buffer: &[u8], offset: &mut usize, end: usize) -> Option<i64> {
    let field_end = offset.checked_add(std::mem::size_of::<i64>())?;
    if field_end > end {
        return None;
    }
    let bytes: [u8; 8] = buffer.get(*offset..field_end)?.try_into().ok()?;
    *offset = field_end;
    Some(i64::from_ne_bytes(bytes))
}

#[cfg(target_os = "macos")]
fn read_bulk_timespec_nanos(buffer: &[u8], offset: &mut usize, end: usize) -> Option<i128> {
    let seconds = i128::from(read_bulk_i64(buffer, offset, end)?);
    let nanoseconds = i128::from(read_bulk_i64(buffer, offset, end)?);
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

struct ObjectTreeEntry {
    name: OsString,
    kind: ObjectTreeEntryKind,
    mode: u32,
    len: u64,
    modified_time_nanos: i128,
    change_time_nanos: i128,
}

impl ObjectTreeEntry {
    fn from_metadata(name: OsString, metadata: &std::fs::Metadata) -> Self {
        let kind = if is_symlink_or_junction(metadata) {
            ObjectTreeEntryKind::Symlink
        } else if metadata.is_dir() {
            ObjectTreeEntryKind::Directory
        } else if metadata.is_file() {
            ObjectTreeEntryKind::File
        } else {
            ObjectTreeEntryKind::Unsupported
        };
        Self {
            name,
            kind,
            mode: object_entry_mode(metadata),
            len: metadata.len(),
            modified_time_nanos: modified_time_nanos(metadata),
            change_time_nanos: change_time_nanos(metadata),
        }
    }
}

enum EntryDigestSource<'a> {
    Filesystem,
    Extraction(&'a mut HashMap<PathBuf, [u8; 32]>),
}

enum TreeContentHasher<'a> {
    Sequential(Sha256),
    EntryDigest {
        root: Sha256,
        source: EntryDigestSource<'a>,
    },
}

impl<'a> TreeContentHasher<'a> {
    fn sequential() -> Self {
        Self::Sequential(Sha256::new())
    }

    fn entry_digest_from_filesystem() -> Self {
        Self::entry_digest(EntryDigestSource::Filesystem)
    }

    fn entry_digest_from_extraction(file_digests: &'a mut HashMap<PathBuf, [u8; 32]>) -> Self {
        Self::entry_digest(EntryDigestSource::Extraction(file_digests))
    }

    fn entry_digest(source: EntryDigestSource<'a>) -> Self {
        let mut root = Sha256::new();
        root.update(b"lpm-tree-entry-digest-v2\0");
        Self::EntryDigest { root, source }
    }

    fn hash_symlink(&mut self, relative: &[u8], metadata: &ObjectTreeEntry, target: &[u8]) {
        match self {
            Self::Sequential(hasher) => {
                hash_object_tree_record(hasher, b"symlink", relative, target);
            }
            Self::EntryDigest { root, .. } => {
                let digest = *blake3::hash(target).as_bytes();
                hash_entry_digest_record(
                    root,
                    b"symlink",
                    relative,
                    metadata.mode,
                    target.len() as u64,
                    Some(&digest),
                );
            }
        }
    }

    fn hash_directory(&mut self, relative: &[u8], metadata: &ObjectTreeEntry) {
        match self {
            Self::Sequential(hasher) => {
                let mode = metadata.mode.to_le_bytes();
                hash_object_tree_record(hasher, b"dir", relative, &mode);
            }
            Self::EntryDigest { root, .. } => {
                hash_entry_digest_record(root, b"dir", relative, metadata.mode, 0, None)
            }
        }
    }

    fn hash_file(
        &mut self,
        relative: &[u8],
        materialized_relative: &Path,
        path: &Path,
        metadata: &ObjectTreeEntry,
    ) -> Result<(), LpmError> {
        match self {
            Self::Sequential(hasher) => hash_object_file(hasher, relative, path, metadata),
            Self::EntryDigest { root, source } => {
                let digest = match source {
                    EntryDigestSource::Filesystem => hash_object_file_blake3(path)?,
                    EntryDigestSource::Extraction(file_digests) => {
                        file_digests.remove(materialized_relative).ok_or_else(|| {
                            LpmError::Store(format!(
                                "streamed extraction omitted a file digest for {}",
                                path.display()
                            ))
                        })?
                    }
                };
                hash_entry_digest_record(
                    root,
                    b"file",
                    relative,
                    metadata.mode,
                    metadata.len,
                    Some(&digest),
                );
                Ok(())
            }
        }
    }

    fn finish(&mut self) -> Result<String, LpmError> {
        match self {
            Self::Sequential(hasher) => Ok(format!(
                "sha256-{}",
                hex::encode(std::mem::take(hasher).finalize())
            )),
            Self::EntryDigest { root, source } => {
                if let EntryDigestSource::Extraction(file_digests) = source {
                    let unmatched = file_digests.len();
                    if unmatched != 0 {
                        return Err(LpmError::Store(format!(
                            "streamed extraction retained {} digest(s) without materialized files",
                            unmatched
                        )));
                    }
                }
                Ok(format!(
                    "sha256-{}",
                    hex::encode(std::mem::take(root).finalize())
                ))
            }
        }
    }
}

fn hash_entry_digest_record(
    root: &mut Sha256,
    kind: &[u8],
    relative: &[u8],
    mode: u32,
    len: u64,
    payload_digest: Option<&[u8; 32]>,
) {
    let mut leaf = Sha256::new();
    leaf.update(b"lpm-tree-entry-v2\0");
    leaf.update((kind.len() as u64).to_le_bytes());
    leaf.update(kind);
    leaf.update((relative.len() as u64).to_le_bytes());
    leaf.update(relative);
    leaf.update(mode.to_le_bytes());
    leaf.update(len.to_le_bytes());
    match payload_digest {
        Some(digest) => {
            leaf.update([1]);
            leaf.update(digest);
        }
        None => leaf.update([0]),
    }
    root.update(leaf.finalize());
}

fn hash_tree_metadata_record(
    hasher: &mut Sha256,
    kind: &[u8],
    relative: &[u8],
    metadata: &ObjectTreeEntry,
    payload: &[u8],
) {
    hash_tree_metadata_fields(
        hasher,
        kind,
        relative,
        metadata.mode,
        metadata.len,
        metadata.modified_time_nanos,
        metadata.change_time_nanos,
        payload,
    );
}

#[expect(clippy::too_many_arguments)]
fn hash_tree_metadata_fields(
    hasher: &mut Sha256,
    kind: &[u8],
    relative: &[u8],
    mode: u32,
    len: u64,
    modified_time_nanos: i128,
    change_time_nanos: i128,
    payload: &[u8],
) {
    hasher.update(kind);
    hasher.update(b"\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update(mode.to_le_bytes());
    hasher.update(len.to_le_bytes());
    hasher.update(modified_time_nanos.to_le_bytes());
    hasher.update(change_time_nanos.to_le_bytes());
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
    metadata: &ObjectTreeEntry,
) -> Result<(), LpmError> {
    hasher.update(b"file\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update(metadata.mode.to_le_bytes());
    hasher.update(metadata.len.to_le_bytes());
    let file = std::fs::File::open(path).map_err(|e| {
        LpmError::Store(format!(
            "failed to open virtual-store object file {} for integrity hashing: {e}",
            path.display()
        ))
    })?;
    let mut reader = file;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf).map_err(|e| {
            LpmError::Store(format!(
                "failed to read virtual-store object file {} for integrity hashing: {e}",
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

fn hash_object_file_blake3(path: &Path) -> Result<[u8; 32], LpmError> {
    let file = std::fs::File::open(path).map_err(|e| {
        LpmError::Store(format!(
            "failed to open virtual-store object file {} for integrity hashing: {e}",
            path.display()
        ))
    })?;
    let mut reader = file;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf).map_err(|e| {
            LpmError::Store(format!(
                "failed to read virtual-store object file {} for integrity hashing: {e}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}
fn hash_object_tree_record(hasher: &mut Sha256, kind: &[u8], relative: &[u8], payload: &[u8]) {
    hasher.update(kind);
    hasher.update(b"\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
}

fn relative_path_bytes(root: &Path, path: &Path) -> Result<Vec<u8>, LpmError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        LpmError::Store(format!(
            "materialized tree entry escapes destination root: {}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::with_capacity(relative.as_os_str().len());
    for component in relative.components() {
        if !bytes.is_empty() {
            push_path_separator(&mut bytes);
        }
        push_os_str_bytes(&mut bytes, component.as_os_str());
    }
    if bytes.is_empty() {
        return Err(LpmError::Store(
            "materialized tree metadata cannot record its root".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn push_os_str_bytes(out: &mut Vec<u8>, value: &std::ffi::OsStr) {
    use std::os::unix::ffi::OsStrExt;
    out.extend_from_slice(value.as_bytes());
}

fn push_path_separator(out: &mut Vec<u8>) {
    out.push(b'/');
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
        // In-flight `write_file_atomic` rewrites of the sidecars above
        // stage `.lpm-<random>` temporaries in the object root; a
        // concurrent tree hash must not observe them.
        || lpm_common::atomic_write::is_atomic_temp_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_file(path: &str, content: &[u8]) -> ExtractedFileDigest {
        ExtractedFileDigest {
            relative_path: path.into(),
            blake3_digest: *blake3::hash(content).as_bytes(),
        }
    }

    #[test]
    fn relative_path_bytes_use_the_tree_hash_canonical_separator() {
        let root = Path::new("root");
        let path = root.join("parent").join("child");
        let mut expected = Vec::new();
        push_os_str_bytes(&mut expected, OsStr::new("parent"));
        expected.push(b'/');
        push_os_str_bytes(&mut expected, OsStr::new("child"));

        assert_eq!(relative_path_bytes(root, &path).unwrap(), expected);
    }

    #[test]
    fn streamed_content_digest_ignores_extraction_order_and_directory_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("lib")).unwrap();
        std::fs::write(dir.path().join("package.json"), b"{\"name\":\"fixture\"}").unwrap();
        std::fs::write(dir.path().join("lib/index.js"), b"module.exports = 1;\n").unwrap();

        let forward = StreamedTreeBuilder::from_extraction(vec![
            fixture_file("package.json", b"{\"name\":\"fixture\"}"),
            fixture_file("lib/index.js", b"module.exports = 1;\n"),
        ]);
        let forward = forward.finish(dir.path()).unwrap();

        filetime::set_file_mtime(
            dir.path().join("lib"),
            filetime::FileTime::from_unix_time(1, 0),
        )
        .unwrap();

        let reverse = StreamedTreeBuilder::from_extraction(vec![
            fixture_file("lib/index.js", b"module.exports = 1;\n"),
            fixture_file("package.json", b"{\"name\":\"fixture\"}"),
        ]);
        let reverse = reverse.finish(dir.path()).unwrap();

        assert_eq!(forward.content, reverse.content);
        assert_ne!(forward.metadata, reverse.metadata);
        assert_eq!(forward.content_schema, TreeContentSchema::EntryDigestV2);
    }

    #[test]
    fn streamed_tree_digest_matches_a_full_entry_digest_recomputation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), b"{\"name\":\"fixture\"}").unwrap();
        std::fs::write(dir.path().join("index.js"), b"module.exports = 1;\n").unwrap();
        let streamed = StreamedTreeBuilder::from_extraction(vec![
            fixture_file("package.json", b"{\"name\":\"fixture\"}"),
            fixture_file("index.js", b"module.exports = 1;\n"),
        ]);

        let streamed = streamed.finish(dir.path()).unwrap();
        let recomputed = compute_object_tree_integrities_for_schema(
            dir.path(),
            TreeContentSchema::EntryDigestV2,
        )
        .unwrap();

        assert_eq!(streamed.content, recomputed.content);
        assert_eq!(streamed.metadata, recomputed.metadata);
    }

    #[test]
    fn streamed_tree_digest_uses_the_last_duplicate_file_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), b"{\"name\":\"fixture\"}").unwrap();
        std::fs::write(dir.path().join("index.js"), b"module.exports = 2;\n").unwrap();
        let streamed = StreamedTreeBuilder::from_extraction(vec![
            fixture_file("package.json", b"{\"name\":\"fixture\"}"),
            fixture_file("index.js", b"module.exports = 1;\n"),
            fixture_file("index.js", b"module.exports = 2;\n"),
        ]);

        let streamed = streamed.finish(dir.path()).unwrap();
        let recomputed = compute_object_tree_integrities_for_schema(
            dir.path(),
            TreeContentSchema::EntryDigestV2,
        )
        .unwrap();

        assert_eq!(streamed.content, recomputed.content);
    }

    #[test]
    fn streamed_tree_digest_rejects_a_missing_file_digest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), b"{\"name\":\"fixture\"}").unwrap();
        std::fs::write(dir.path().join("index.js"), b"module.exports = 1;\n").unwrap();
        let streamed = StreamedTreeBuilder::from_extraction(vec![fixture_file(
            "package.json",
            b"{\"name\":\"fixture\"}",
        )]);

        let error = streamed.finish(dir.path()).unwrap_err();

        assert!(error.to_string().contains("omitted a file digest"));
    }

    #[test]
    fn streamed_tree_digest_rejects_a_digest_without_a_materialized_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), b"{\"name\":\"fixture\"}").unwrap();
        let streamed = StreamedTreeBuilder::from_extraction(vec![
            fixture_file("package.json", b"{\"name\":\"fixture\"}"),
            fixture_file("ghost.js", b"not materialized\n"),
        ]);

        let error = streamed.finish(dir.path()).unwrap_err();

        assert!(error.to_string().contains("without materialized files"));
    }

    #[test]
    fn streamed_tree_digest_excludes_only_root_store_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        std::fs::write(dir.path().join(".integrity"), b"package-owned root sidecar").unwrap();
        std::fs::write(
            dir.path().join("nested/.integrity"),
            b"ordinary nested file",
        )
        .unwrap();
        let streamed = StreamedTreeBuilder::from_extraction(vec![
            fixture_file(".integrity", b"package-owned root sidecar"),
            fixture_file("nested/.integrity", b"ordinary nested file"),
        ]);

        let streamed = streamed.finish(dir.path()).unwrap();
        let recomputed = compute_object_tree_integrities_for_schema(
            dir.path(),
            TreeContentSchema::EntryDigestV2,
        )
        .unwrap();

        assert_eq!(streamed.content, recomputed.content);
    }

    #[cfg(target_os = "macos")]
    fn finish_with_bulk_walk(
        root: &Path,
        files: Vec<ExtractedFileDigest>,
        directories: usize,
    ) -> Result<TreeIntegrities, LpmError> {
        let before = BULK_FINALIZATION_DIRECTORIES.with(std::cell::Cell::get);
        let result = StreamedTreeBuilder::from_extraction(files).finish(root);
        let after = BULK_FINALIZATION_DIRECTORIES.with(std::cell::Cell::get);
        assert_eq!(
            after - before,
            directories,
            "finalization must use bulk metadata for every expected directory"
        );
        result
    }
    #[cfg(target_os = "macos")]
    fn assert_integrities_match(actual: &TreeIntegrities, expected: &TreeIntegrities) {
        assert_eq!(actual.content, expected.content);
        assert_eq!(actual.metadata, expected.metadata);
        assert_eq!(actual.content_schema, expected.content_schema);
        assert_eq!(actual.stats.file_count, expected.stats.file_count);
        assert_eq!(actual.stats.dir_count, expected.stats.dir_count);
        assert_eq!(actual.stats.symlink_count, expected.stats.symlink_count);
        assert_eq!(actual.stats.unpacked_bytes, expected.stats.unpacked_bytes);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_finalization_preserves_digests_and_statistics_for_mixed_tree_entries() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("nested/empty")).unwrap();
        let unicode_path = PathBuf::from("nested/file-π");
        std::fs::write(root.join(&unicode_path), b"unicode").unwrap();
        std::fs::write(root.join("run"), b"executable").unwrap();
        std::fs::set_permissions(root.join("run"), std::fs::Permissions::from_mode(0o751)).unwrap();
        std::fs::hard_link(root.join("run"), root.join("nested/hardlinked")).unwrap();
        std::fs::write(root.join(OBJECT_INTEGRITY_FILENAME), b"excluded").unwrap();
        std::fs::write(
            root.join("nested").join(OBJECT_INTEGRITY_FILENAME),
            b"included",
        )
        .unwrap();
        std::os::unix::fs::symlink("run", root.join("link")).unwrap();
        std::os::unix::fs::symlink("missing", root.join("dangling")).unwrap();
        let mut files = vec![
            fixture_file("run", b"old bytes"),
            fixture_file("run", b"executable"),
            fixture_file("nested/hardlinked", b"executable"),
            fixture_file(OBJECT_INTEGRITY_FILENAME, b"excluded"),
            fixture_file("nested/.lpm-object-integrity", b"included"),
        ];
        files.push(ExtractedFileDigest {
            relative_path: unicode_path,
            blake3_digest: *blake3::hash(b"unicode").as_bytes(),
        });
        let actual = finish_with_bulk_walk(root, files, 3).unwrap();
        let expected =
            compute_object_tree_integrities_for_schema(root, TreeContentSchema::EntryDigestV2)
                .unwrap();
        assert_integrities_match(&actual, &expected);
        assert_eq!(actual.stats.file_count, 4);
        assert_eq!(actual.stats.dir_count, 2);
        assert_eq!(actual.stats.symlink_count, 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn failed_bulk_collection_disables_retries_without_replaying_consumed_digests() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut files = Vec::new();
        for name in ["a", "b", "c"] {
            std::fs::create_dir(root.join(name)).unwrap();
            let relative = format!("{name}/file");
            std::fs::write(root.join(&relative), name.as_bytes()).unwrap();
            files.push(fixture_file(&relative, name.as_bytes()));
        }
        let expected =
            compute_object_tree_integrities_for_schema(root, TreeContentSchema::EntryDigestV2)
                .unwrap();
        let mut digests = StreamedTreeBuilder::from_extraction(files).file_digests;
        let mut content = TreeContentHasher::entry_digest_from_extraction(&mut digests);
        let mut metadata = Sha256::new();
        let mut stats = ObjectTreeStats::default();
        let mut bulk_buffer = vec![0; 64 * 1024];
        for entry in read_object_tree_entries(root, root).unwrap() {
            let path = root.join(&entry.name);
            let mut relative = relative_path_bytes(root, &path).unwrap();
            content.hash_directory(&relative, &entry);
            hash_tree_metadata_record(&mut metadata, b"dir", &relative, &entry, &[]);
            stats.dir_count += 1;
            if entry.name == "b" {
                bulk_buffer.truncate(1);
            }
            hash_object_tree_dir_inner(
                root,
                &path,
                &mut relative,
                Some(&mut content),
                &mut metadata,
                Some(&mut stats),
                &mut bulk_buffer,
            )
            .unwrap();
            if entry.name == "a" {
                assert!(!bulk_buffer.is_empty());
                if let TreeContentHasher::EntryDigest {
                    source: EntryDigestSource::Extraction(remaining),
                    ..
                } = &content
                {
                    assert!(!remaining.contains_key(Path::new("a/file")));
                    assert_eq!(remaining.len(), 2);
                } else {
                    panic!("expected extraction digests");
                }
            } else {
                assert!(bulk_buffer.is_empty());
            }
        }
        let actual = TreeIntegrities {
            content: content.finish().unwrap(),
            metadata: format!("sha256-{}", hex::encode(metadata.finalize())),
            stats,
            content_schema: TreeContentSchema::EntryDigestV2,
        };
        assert_integrities_match(&actual, &expected);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_fallback_rejects_missing_and_unmatched_extraction_digests() {
        for extra in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("file"), b"bytes").unwrap();
            let files = if extra {
                vec![
                    fixture_file("file", b"bytes"),
                    fixture_file("absent", b"extra"),
                ]
            } else {
                vec![]
            };
            let mut digests = StreamedTreeBuilder::from_extraction(files).file_digests;
            let mut content = TreeContentHasher::entry_digest_from_extraction(&mut digests);
            let mut metadata = Sha256::new();
            let mut stats = ObjectTreeStats::default();
            let mut buffer = vec![0];
            let walked = hash_object_tree_dir_inner(
                dir.path(),
                dir.path(),
                &mut Vec::new(),
                Some(&mut content),
                &mut metadata,
                Some(&mut stats),
                &mut buffer,
            );
            assert!(buffer.is_empty());
            let error = if extra {
                walked.unwrap();
                content.finish().unwrap_err()
            } else {
                walked.unwrap_err()
            };
            assert!(error.to_string().contains(if extra {
                "without materialized files"
            } else {
                "omitted a file digest"
            }));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_symlink_refresh_errors_identify_the_affected_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut entry = ObjectTreeEntry {
            name: "missing-link".into(),
            kind: ObjectTreeEntryKind::Symlink,
            mode: 0,
            len: 0,
            modified_time_nanos: 0,
            change_time_nanos: 0,
        };
        let error = refresh_bulk_symlink_metadata(dir.path(), &mut entry)
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to stat virtual-store object tree entry"));
        assert!(error.contains(&dir.path().join("missing-link").display().to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_finalization_rejects_unsupported_filesystem_entries() {
        let dir = tempfile::tempdir().unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(dir.path().join("socket")).unwrap();
        let error = finish_with_bulk_walk(dir.path(), vec![], 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported virtual-store object entry type"));
        assert!(error.contains("socket"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_finalization_hashes_symlink_bytes_without_observing_target_mutations() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let target = external.path().join("target");
        std::fs::write(&target, b"before").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let before = finish_with_bulk_walk(root.path(), vec![], 1).unwrap();
        std::fs::write(&target, b"after with different length").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o751)).unwrap();
        let after = finish_with_bulk_walk(root.path(), vec![], 1).unwrap();
        assert_integrities_match(&after, &before);
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(external.path().join("different-target"), &link).unwrap();
        let replaced = finish_with_bulk_walk(root.path(), vec![], 1).unwrap();
        assert_ne!(replaced.content, before.content);
        assert_ne!(replaced.metadata, before.metadata);
    }

    #[cfg(unix)]
    #[test]
    fn normalized_object_entry_preserves_non_utf8_name_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let metadata = std::fs::symlink_metadata(dir.path()).unwrap();
        let name = OsString::from_vec(b"file-\xff".to_vec());
        let entry = ObjectTreeEntry::from_metadata(name, &metadata);
        let mut encoded = Vec::new();
        push_os_str_bytes(&mut encoded, &entry.name);
        assert_eq!(encoded, b"file-\xff");
    }
}
