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
    mut content_hasher: Option<&mut TreeContentHasher<'_>>,
    metadata_hasher: &mut Sha256,
    mut stats: Option<&mut ObjectTreeStats>,
) -> Result<(), LpmError> {
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
        let result = if is_symlink_or_junction(&metadata) {
            if let Some(stats) = stats.as_deref_mut() {
                stats.symlink_count = stats.symlink_count.saturating_add(1);
            }
            path.push(&entry_name);
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
                hasher.hash_symlink(relative.as_slice(), &metadata, &target_bytes);
            }
            hash_tree_metadata_record(
                metadata_hasher,
                b"symlink",
                relative.as_slice(),
                &metadata,
                &target_bytes,
            );
            Ok(())
        } else if file_type.is_dir() {
            if let Some(stats) = stats.as_deref_mut() {
                stats.dir_count = stats.dir_count.saturating_add(1);
            }
            path.push(&entry_name);
            path_pushed = true;
            if let Some(hasher) = content_hasher.as_deref_mut() {
                hasher.hash_directory(relative.as_slice(), &metadata);
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
                let materialized_relative = path.strip_prefix(root).map_err(|error| {
                    LpmError::Store(format!(
                        "failed to derive relative virtual-store object path {}: {error}",
                        path.display()
                    ))
                })?;
                hasher.hash_file(relative.as_slice(), materialized_relative, &path, &metadata)?;
            }
            Ok(())
        } else {
            path.push(&entry_name);
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
            MacosEntryKind::Directory => {
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
            MacosEntryKind::File => {
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
            MacosEntryKind::Symlink => {
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
            MacosEntryKind::Unsupported => Err(LpmError::Store(format!(
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

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MacosEntryKind {
    File,
    Directory,
    Symlink,
    Unsupported,
}

#[cfg(target_os = "macos")]
struct MacosMetadataEntry {
    name: OsString,
    kind: MacosEntryKind,
    mode: u32,
    len: u64,
    modified_time_nanos: i128,
    change_time_nanos: i128,
}

#[cfg(target_os = "macos")]
fn read_bulk_metadata_entries(
    dir: &Path,
    buffer: &mut [u8],
) -> Result<Vec<MacosMetadataEntry>, LpmError> {
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
) -> Result<MacosMetadataEntry, LpmError> {
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
        1 => MacosEntryKind::File,
        2 => MacosEntryKind::Directory,
        5 => MacosEntryKind::Symlink,
        _ => MacosEntryKind::Unsupported,
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
        MacosEntryKind::Directory => directory_len,
        MacosEntryKind::File => file_len,
        MacosEntryKind::Symlink => Some(0),
        MacosEntryKind::Unsupported => Some(file_len.or(directory_len).unwrap_or_default()),
    }
    .ok_or_else(|| {
        LpmError::Store(format!(
            "bulk metadata length unavailable at {}",
            dir.join(&name).display()
        ))
    })?;

    Ok(MacosMetadataEntry {
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
    file_name: OsString,
    metadata: std::fs::Metadata,
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

    fn hash_symlink(&mut self, relative: &[u8], metadata: &std::fs::Metadata, target: &[u8]) {
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
                    object_entry_mode(metadata),
                    target.len() as u64,
                    Some(&digest),
                );
            }
        }
    }

    fn hash_directory(&mut self, relative: &[u8], metadata: &std::fs::Metadata) {
        match self {
            Self::Sequential(hasher) => {
                let mode = object_entry_mode(metadata).to_le_bytes();
                hash_object_tree_record(hasher, b"dir", relative, &mode);
            }
            Self::EntryDigest { root, .. } => hash_entry_digest_record(
                root,
                b"dir",
                relative,
                object_entry_mode(metadata),
                0,
                None,
            ),
        }
    }

    fn hash_file(
        &mut self,
        relative: &[u8],
        materialized_relative: &Path,
        path: &Path,
        metadata: &std::fs::Metadata,
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
                    object_entry_mode(metadata),
                    metadata.len(),
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
    metadata: &std::fs::Metadata,
    payload: &[u8],
) {
    hash_tree_metadata_fields(
        hasher,
        kind,
        relative,
        object_entry_mode(metadata),
        metadata.len(),
        modified_time_nanos(metadata),
        change_time_nanos(metadata),
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
    metadata: &std::fs::Metadata,
) -> Result<(), LpmError> {
    hasher.update(b"file\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update(object_entry_mode(metadata).to_le_bytes());
    hasher.update(metadata.len().to_le_bytes());
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
    fn streamed_tree_digest_is_independent_of_extraction_entry_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("lib")).unwrap();
        std::fs::write(dir.path().join("package.json"), b"{\"name\":\"fixture\"}").unwrap();
        std::fs::write(dir.path().join("lib/index.js"), b"module.exports = 1;\n").unwrap();

        let forward = StreamedTreeBuilder::from_extraction(vec![
            fixture_file("package.json", b"{\"name\":\"fixture\"}"),
            fixture_file("lib/index.js", b"module.exports = 1;\n"),
        ]);
        let forward = forward.finish(dir.path()).unwrap();

        let reverse = StreamedTreeBuilder::from_extraction(vec![
            fixture_file("lib/index.js", b"module.exports = 1;\n"),
            fixture_file("package.json", b"{\"name\":\"fixture\"}"),
        ]);
        let reverse = reverse.finish(dir.path()).unwrap();

        assert_eq!(forward.content, reverse.content);
        assert_eq!(forward.metadata, reverse.metadata);
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
}
