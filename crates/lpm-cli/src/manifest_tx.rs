//! Snapshot-and-restore guard for the install state surface.
//!
//! introduces a "stage placeholder, run install, finalize manifest"
//! flow. The placeholder must NEVER survive a failed install — any error
//! between staging and finalize must restore the file bytes to their
//! pre-staging state.
//!
//! This module provides [`ManifestTransaction`], a `Drop`-based guard that
//! covers the **full install state surface**, not just `package.json`:
//!
//! 1. **Snapshotted (restore-on-rollback)** files have their bytes captured
//!    at construction time. On rollback, the bytes are written back; if the
//!    file did not exist at snapshot time, it is removed instead. Used for
//!    `package.json`, `Package.swift`, `lpm.lock`, `lpm.lockb`, and
//!    `Package.resolved`.
//! 2. **Invalidated (delete-on-rollback)** files are deleted unconditionally
//!    on rollback, regardless of their pre-snapshot state. Used for
//!    `.lpm/install-hash` — a cache file whose stale presence would let the
//!    install fast-exit fire on a project whose `node_modules/` no longer
//!    matches its lockfile. Deleting it forces the next `lpm install` to
//!    re-resolve and re-link, converging any drift.
//!
//! After the install pipeline succeeds, the caller invokes [`Self::commit`].
//! If anything errors before commit — `?`, early return, panic, anything —
//! the `Drop` impl restores every snapshotted path and deletes every
//! invalidated path.
//!
//! Restore is **best-effort**: a write or delete failure during `Drop` is
//! logged but does not panic, because panicking in `Drop` aborts the
//! process. Even a partial restore is strictly better than today's
//! pre-existing behavior of leaving `"*"` in the manifest, a stale lockfile
//! on disk, or an incoherent `install-hash` cache after a failed install.
//!
//! ### Why `node_modules/` is not part of the boundary
//!
//! The install pipeline mutates `node_modules/` heavily (delete + re-link),
//! and snapshotting it would mean copying potentially gigabytes of files
//! per transaction. the contract is that after a failed install,
//! the on-disk manifest and lockfiles are coherent with each other and with
//! what the user typed. The
//! `node_modules/` tree may temporarily diverge from the lockfile, but the
//! deleted `install-hash` cache forces the next `lpm install` to re-link
//! and converge. This is documented as a known limitation of the rollback
//! boundary.

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const IN_MEMORY_SNAPSHOT_LIMIT: u64 = 1024 * 1024;
const IN_MEMORY_SNAPSHOT_BUDGET: usize = 8 * 1024 * 1024;

/// A guard that restores or invalidates one or more files on `Drop`,
/// unless [`Self::commit`] is called first.
///
/// Construct with [`Self::snapshot`] (manifest-only, must exist) or
/// [`Self::snapshot_install_state`] (manifest + lockfile + invalidation
/// targets, lockfile-tier paths may be missing). After the install
/// pipeline succeeds, call [`Self::commit`]. If anything errors before
/// commit — `?`, early return, panic, anything — the `Drop` impl runs
/// the rollback.
///
/// The guard owns its snapshot bytes; callers do not need to track them.
pub struct ManifestTransaction {
    /// Files whose bytes are restored on rollback. `original_bytes` is
    /// `Some(bytes)` if the file existed at snapshot time, or `None` if
    /// it did not (rollback removes the file in that case).
    snapshots: Vec<SnapshotEntry>,
    snapshot_paths: HashSet<PathBuf>,
    in_memory_snapshot_bytes: usize,
    /// Files deleted on rollback, regardless of their pre-snapshot state.
    /// Cache files where stale data is worse than no data.
    invalidate: Vec<PathBuf>,
    rollback_dirs: Vec<PathBuf>,
    committed: bool,
}

struct SnapshotEntry {
    path: PathBuf,
    original: Option<SnapshotContent>,
    restore_guard: Option<FileFingerprint>,
}

#[derive(Clone, Copy)]
struct FileFingerprint {
    len: usize,
    sha256: [u8; 32],
}

impl FileFingerprint {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            len: bytes.len(),
            sha256: Sha256::digest(bytes).into(),
        }
    }

    fn matches_path(self, path: &Path) -> std::io::Result<bool> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
            return Ok(false);
        }
        if metadata.len() != self.len as u64 {
            return Ok(false);
        }
        let mut sha256 = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            sha256.update(&buffer[..read]);
        }
        Ok(<[u8; 32]>::from(sha256.finalize()) == self.sha256)
    }
}

enum SnapshotContent {
    Memory(Vec<u8>),
    File(std::fs::File),
}

impl SnapshotContent {
    fn from_bytes(bytes: Vec<u8>, in_memory_bytes: &mut usize) -> std::io::Result<Self> {
        if bytes.len() as u64 <= IN_MEMORY_SNAPSHOT_LIMIT
            && in_memory_bytes.saturating_add(bytes.len()) <= IN_MEMORY_SNAPSHOT_BUDGET
        {
            *in_memory_bytes += bytes.len();
            return Ok(Self::Memory(bytes));
        }
        let mut file = tempfile::tempfile()?;
        file.write_all(&bytes)?;
        Ok(Self::File(file))
    }

    fn from_path(path: &Path, in_memory_bytes: &mut usize) -> std::io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "refusing transaction snapshot path that is not a regular file: {}",
                    path.display()
                ),
            ));
        }
        let mut source = std::fs::File::open(path)?;
        let opened_metadata = source.metadata()?;
        if !opened_metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "transaction snapshot path changed before it could be opened: {}",
                    path.display()
                ),
            ));
        }
        let file_len = opened_metadata.len();
        if file_len <= IN_MEMORY_SNAPSHOT_LIMIT
            && in_memory_bytes.saturating_add(file_len as usize) <= IN_MEMORY_SNAPSHOT_BUDGET
        {
            let mut bytes = vec![0_u8; file_len as usize];
            source.read_exact(&mut bytes)?;
            let mut extra = [0_u8; 1];
            if source.read(&mut extra)? != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "transaction snapshot path grew while it was read: {}",
                        path.display()
                    ),
                ));
            }
            *in_memory_bytes += bytes.len();
            return Ok(Self::Memory(bytes));
        }
        let mut file = tempfile::tempfile()?;
        std::io::copy(&mut source, &mut file)?;
        Ok(Self::File(file))
    }

    fn restore(&mut self, path: &Path) -> std::io::Result<()> {
        match self {
            Self::Memory(bytes) => lpm_common::write_file_atomic(path, bytes),
            Self::File(source) => {
                source.seek(SeekFrom::Start(0))?;
                lpm_common::write_file_atomic_with(
                    path,
                    lpm_common::AtomicWriteOptions::new(),
                    |destination| std::io::copy(source, destination).map(|_| ()),
                )
            }
        }
    }
}

impl ManifestTransaction {
    /// Snapshot the bytes of each path. ALL paths must exist; an `Err` is
    /// returned if any read fails. Convenience wrapper around
    /// [`Self::snapshot_install_state`] for the manifest-only case where
    /// callers have nothing optional to track and no cache files to
    /// invalidate. Currently used only by the unit tests in this module —
    /// production callers (the install entry points) always use
    /// [`Self::snapshot_install_state`] directly because they snapshot
    /// the full state surface.
    #[cfg(test)]
    fn snapshot(paths: &[&Path]) -> std::io::Result<Self> {
        Self::snapshot_install_state(paths, &[], &[])
    }

    /// Snapshot the full install state surface for the rollback
    /// boundary. `required` paths must exist (typically `package.json` or
    /// `Package.swift`);
    /// `optional` paths are recorded as `Some(bytes)` if present and
    /// `None` if missing (rollback will remove them); `invalidate` paths
    /// are deleted on rollback regardless of their pre-snapshot state
    /// (cache files like `.lpm/install-hash`).
    ///
    /// Used by `run_add_packages` and `run_install_filtered_add` to
    /// guard manifests (required), `lpm.lock` + `lpm.lockb` +
    /// `Package.resolved` (optional, may be absent on a fresh project), and
    /// `.lpm/install-hash` (invalidate).
    pub fn snapshot_install_state(
        required: &[&Path],
        optional: &[&Path],
        invalidate: &[&Path],
    ) -> std::io::Result<Self> {
        let mut snapshots = Vec::with_capacity(required.len() + optional.len());
        let mut snapshot_paths = HashSet::with_capacity(required.len() + optional.len());
        let mut in_memory_snapshot_bytes = 0;

        for path in required {
            let metadata = std::fs::symlink_metadata(path)?;
            if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "refusing required transaction snapshot path that is not a regular file: {}",
                        path.display()
                    ),
                ));
            }
            let bytes = lpm_common::read_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                .map_err(std::io::Error::other)?;
            snapshots.push(SnapshotEntry {
                path: path.to_path_buf(),
                original: Some(SnapshotContent::from_bytes(
                    bytes,
                    &mut in_memory_snapshot_bytes,
                )?),
                restore_guard: None,
            });
            snapshot_paths.insert(path.to_path_buf());
        }

        Self::finish_install_state_snapshot(
            snapshots,
            snapshot_paths,
            in_memory_snapshot_bytes,
            optional,
            invalidate,
        )
    }

    /// Snapshot install state only if every required file still has the
    /// exact bytes the caller previously read.
    pub fn snapshot_install_state_if_unchanged(
        required: &[(&Path, &[u8])],
        optional: &[&Path],
        invalidate: &[&Path],
    ) -> std::io::Result<Self> {
        let mut snapshots = Vec::with_capacity(required.len() + optional.len());
        let mut snapshot_paths = HashSet::with_capacity(required.len() + optional.len());
        let mut in_memory_snapshot_bytes = 0;
        Self::snapshot_optional_paths(
            &mut snapshots,
            &mut snapshot_paths,
            &mut in_memory_snapshot_bytes,
            optional,
        )?;
        let invalidate = invalidate.iter().map(|p| p.to_path_buf()).collect();

        for (path, expected) in required {
            let metadata = std::fs::symlink_metadata(path)?;
            if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "refusing required transaction snapshot path that is not a regular file: {}",
                        path.display()
                    ),
                ));
            }
            let bytes = lpm_common::read_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                .map_err(std::io::Error::other)?;
            if bytes != *expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} changed since it was read", path.display()),
                ));
            }
            snapshots.push(SnapshotEntry {
                path: path.to_path_buf(),
                original: Some(SnapshotContent::from_bytes(
                    bytes,
                    &mut in_memory_snapshot_bytes,
                )?),
                restore_guard: None,
            });
            snapshot_paths.insert(path.to_path_buf());
        }

        Ok(Self {
            snapshots,
            snapshot_paths,
            in_memory_snapshot_bytes,
            invalidate,
            rollback_dirs: Vec::new(),
            committed: false,
        })
    }

    fn finish_install_state_snapshot(
        mut snapshots: Vec<SnapshotEntry>,
        mut snapshot_paths: HashSet<PathBuf>,
        mut in_memory_snapshot_bytes: usize,
        optional: &[&Path],
        invalidate: &[&Path],
    ) -> std::io::Result<Self> {
        Self::snapshot_optional_paths(
            &mut snapshots,
            &mut snapshot_paths,
            &mut in_memory_snapshot_bytes,
            optional,
        )?;

        Ok(Self {
            snapshots,
            snapshot_paths,
            in_memory_snapshot_bytes,
            invalidate: invalidate.iter().map(|p| p.to_path_buf()).collect(),
            rollback_dirs: Vec::new(),
            committed: false,
        })
    }

    fn snapshot_optional_paths(
        snapshots: &mut Vec<SnapshotEntry>,
        snapshot_paths: &mut HashSet<PathBuf>,
        in_memory_snapshot_bytes: &mut usize,
        optional: &[&Path],
    ) -> std::io::Result<()> {
        for path in optional {
            if !snapshot_paths.insert(path.to_path_buf()) {
                continue;
            }
            let original = match SnapshotContent::from_path(path, in_memory_snapshot_bytes) {
                Ok(content) => Some(content),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            };
            snapshots.push(SnapshotEntry {
                path: path.to_path_buf(),
                original,
                restore_guard: None,
            });
        }
        Ok(())
    }

    pub fn snapshot_optional_path(&mut self, path: &Path) -> std::io::Result<()> {
        if !self.snapshot_paths.insert(path.to_path_buf()) {
            return Ok(());
        }
        let original = match SnapshotContent::from_path(path, &mut self.in_memory_snapshot_bytes) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        self.snapshots.push(SnapshotEntry {
            path: path.to_path_buf(),
            original,
            restore_guard: None,
        });
        Ok(())
    }

    pub fn snapshot_optional_path_with_bytes(
        &mut self,
        path: &Path,
        original_bytes: Option<Vec<u8>>,
    ) -> std::io::Result<()> {
        if !self.snapshot_paths.insert(path.to_path_buf()) {
            return Ok(());
        }
        self.snapshots.push(SnapshotEntry {
            path: path.to_path_buf(),
            original: original_bytes
                .map(|bytes| SnapshotContent::from_bytes(bytes, &mut self.in_memory_snapshot_bytes))
                .transpose()?,
            restore_guard: None,
        });
        Ok(())
    }

    pub fn snapshot_optional_path_from_file(
        &mut self,
        path: &Path,
        mut original: std::fs::File,
    ) -> std::io::Result<()> {
        if !self.snapshot_paths.insert(path.to_path_buf()) {
            return Ok(());
        }
        if !original.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "refusing transaction snapshot source that is not a regular file",
            ));
        }
        original.seek(SeekFrom::Start(0))?;
        self.snapshots.push(SnapshotEntry {
            path: path.to_path_buf(),
            original: Some(SnapshotContent::File(original)),
            restore_guard: None,
        });
        Ok(())
    }

    pub fn restore_only_if_unchanged(
        &mut self,
        path: &Path,
        expected_current_bytes: &[u8],
    ) -> std::io::Result<()> {
        let entry = self
            .snapshots
            .iter_mut()
            .find(|entry| entry.path == path)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("transaction does not snapshot {}", path.display()),
                )
            })?;
        entry.restore_guard = Some(FileFingerprint::from_bytes(expected_current_bytes));
        Ok(())
    }

    pub(crate) fn verify_guarded_paths(&self) -> std::io::Result<()> {
        for entry in &self.snapshots {
            let Some(expected) = entry.restore_guard else {
                continue;
            };
            if !expected.matches_path(&entry.path)? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} changed during the transaction", entry.path.display()),
                ));
            }
        }
        Ok(())
    }

    pub fn remove_dirs_on_rollback(&mut self, directories: impl IntoIterator<Item = PathBuf>) {
        self.rollback_dirs.extend(directories);
        self.rollback_dirs.sort_unstable_by(|left, right| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| right.cmp(left))
        });
        self.rollback_dirs.dedup();
    }

    /// Mark the transaction as successful. The `Drop` impl will not
    /// restore or invalidate anything after this is called. Consumes
    /// `self` so the guard is unambiguously released.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for ManifestTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        // (1) Restore snapshotted paths.
        for entry in &mut self.snapshots {
            if let Some(expected) = entry.restore_guard {
                match expected.matches_path(&entry.path) {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(
                            "manifest transaction rollback: preserved concurrently changed {}",
                            entry.path.display()
                        );
                        continue;
                    }
                    Err(error) => {
                        tracing::error!(
                            "manifest transaction rollback: could not verify {} before restore; preserving it: {error}",
                            entry.path.display()
                        );
                        continue;
                    }
                }
            }
            match &mut entry.original {
                Some(original) => {
                    if let Err(e) = original.restore(&entry.path) {
                        tracing::error!(
                            "manifest transaction rollback: failed to restore {}: {e}",
                            entry.path.display()
                        );
                    }
                }
                None => {
                    // File did not exist at snapshot time. If it exists
                    // now, remove it; otherwise nothing to do.
                    match std::fs::remove_file(&entry.path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            tracing::error!(
                                "manifest transaction rollback: failed to remove {}: {e}",
                                entry.path.display()
                            );
                        }
                    }
                }
            }
        }

        // (2) Invalidate cache paths.
        for path in &self.invalidate {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::error!(
                        "manifest transaction rollback: failed to invalidate {}: {e}",
                        path.display()
                    );
                }
            }
        }

        for path in &self.rollback_dirs {
            match std::fs::remove_dir(path) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => {
                    tracing::error!(
                        "manifest transaction rollback: failed to remove directory {}: {error}",
                        path.display()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, content: &[u8]) {
        fs::write(path, content).unwrap();
    }

    fn read(path: &Path) -> Vec<u8> {
        fs::read(path).unwrap()
    }

    #[test]
    fn snapshot_records_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        write(&path, br#"{"name":"original"}"#);

        let tx = ManifestTransaction::snapshot(&[&path]).unwrap();

        // Mutate, then drop without commit → snapshot bytes restored.
        write(&path, br#"{"name":"corrupted"}"#);
        drop(tx);
        assert_eq!(read(&path), br#"{"name":"original"}"#);
    }

    #[test]
    fn drop_without_commit_restores_modified_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        let original = br#"{"name":"original","dependencies":{}}"#;
        write(&path, original);

        {
            let _tx = ManifestTransaction::snapshot(&[&path]).unwrap();
            // Mutate the manifest the way the stage step would.
            write(&path, br#"{"name":"original","dependencies":{"ms":"*"}}"#);
            // Drop here → rollback.
        }

        assert_eq!(
            read(&path),
            original,
            "manifest bytes must be restored byte-for-byte after Drop"
        );
    }

    #[test]
    fn commit_disables_restore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        write(&path, br#"{"name":"original"}"#);

        let tx = ManifestTransaction::snapshot(&[&path]).unwrap();
        write(&path, br#"{"name":"finalized"}"#);
        tx.commit();

        assert_eq!(
            read(&path),
            br#"{"name":"finalized"}"#,
            "committed transaction must NOT restore on drop"
        );
    }

    #[test]
    fn guarded_rollback_preserves_a_concurrent_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        write(&path, br#"{"name":"original"}"#);

        let mut tx = ManifestTransaction::snapshot(&[&path]).unwrap();
        let staged = br#"{"name":"staged"}"#;
        tx.restore_only_if_unchanged(&path, staged).unwrap();
        write(&path, staged);
        write(&path, br#"{"name":"external-edit"}"#);
        drop(tx);

        assert_eq!(read(&path), br#"{"name":"external-edit"}"#);
    }

    #[test]
    fn guarded_verification_accepts_only_the_staged_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        write(&path, br#"{"name":"original"}"#);

        let mut tx = ManifestTransaction::snapshot(&[&path]).unwrap();
        let staged = br#"{"name":"staged"}"#;
        tx.restore_only_if_unchanged(&path, staged).unwrap();
        write(&path, staged);
        assert!(tx.verify_guarded_paths().is_ok());

        write(&path, br#"{"name":"external-edit"}"#);
        assert!(tx.verify_guarded_paths().is_err());
    }

    #[test]
    fn guarded_verification_accepts_staged_bytes_larger_than_the_config_read_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        write(&path, br#"{"name":"original"}"#);

        let mut tx = ManifestTransaction::snapshot(&[&path]).unwrap();
        let staged_len = usize::try_from(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES).unwrap() + 1;
        let staged = vec![b' '; staged_len];
        tx.restore_only_if_unchanged(&path, &staged).unwrap();
        write(&path, &staged);

        assert!(tx.verify_guarded_paths().is_ok());
    }

    #[test]
    fn multiple_paths_all_restored() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("pkg-a.json");
        let b = dir.path().join("pkg-b.json");
        write(&a, b"original-a");
        write(&b, b"original-b");

        {
            let _tx = ManifestTransaction::snapshot(&[&a, &b]).unwrap();
            write(&a, b"modified-a");
            write(&b, b"modified-b");
        }

        assert_eq!(read(&a), b"original-a");
        assert_eq!(read(&b), b"original-b");
    }

    #[test]
    fn snapshot_from_open_file_restores_destination_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("destination.bin");
        let backup = dir.path().join("backup.bin");
        write(&destination, b"original destination");
        write(&backup, b"original destination");

        {
            let mut transaction = ManifestTransaction::snapshot(&[]).unwrap();
            transaction
                .snapshot_optional_path_from_file(
                    &destination,
                    std::fs::File::open(&backup).unwrap(),
                )
                .unwrap();
            write(&destination, b"replacement");
        }

        assert_eq!(read(&destination), b"original destination");
    }

    #[test]
    fn snapshot_fails_if_required_path_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");

        let result = ManifestTransaction::snapshot(&[&missing]);
        assert!(
            result.is_err(),
            "snapshot must error on missing required path"
        );
    }

    #[test]
    fn rollback_is_best_effort_when_path_removed_after_snapshot() {
        // If the install pipeline removes the manifest entirely (unlikely
        // but possible), Drop should not panic. The restore logs a tracing
        // error and continues.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        write(&path, br#"{"name":"original"}"#);

        {
            let _tx = ManifestTransaction::snapshot(&[&path]).unwrap();
            // The directory ITSELF survives, so write() during Drop will
            // succeed and recreate the file with the original bytes.
            fs::remove_file(&path).unwrap();
            // Drop here.
        }

        // File should be restored because the parent dir still exists.
        assert!(path.exists());
        assert_eq!(read(&path), br#"{"name":"original"}"#);
    }

    #[test]
    fn rollback_does_not_panic_when_parent_dir_gone() {
        // Worst case: the entire parent directory is gone by Drop time.
        // Drop must not panic.
        let path = {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("package.json");
            write(&p, b"original");

            let _tx = ManifestTransaction::snapshot(&[&p]).unwrap();
            // Stash the path before tempdir is dropped.
            p
            // `dir` drops here, removing the entire directory tree.
            // `_tx` then drops, attempting to restore — should NOT panic.
        };

        // If we got here without panicking, the test passes.
        assert!(!path.exists(), "parent dir was cleaned up");
    }

    #[test]
    fn empty_transaction_is_a_noop() {
        // Snapshotting zero paths must succeed and Drop must not panic.
        // This is the `run_install_filtered_add` corner case where the
        // resolver returns an empty target list — the transaction is
        // constructed with no entries and dropped without commit.
        let tx = ManifestTransaction::snapshot(&[]).unwrap();
        drop(tx);
    }

    // ── snapshot_install_state ──────────────────────────────────────────

    /// Required path must exist; missing required path is an error.
    #[test]
    fn snapshot_install_state_errors_on_missing_required() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");

        let result = ManifestTransaction::snapshot_install_state(&[&missing], &[], &[]);
        assert!(result.is_err());
    }

    /// Optional path may be missing; the snapshot records `None` and
    /// rollback removes the file if it appears later.
    #[test]
    fn snapshot_install_state_optional_missing_then_created_is_removed_on_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let lockfile = dir.path().join("lpm.lock");
        write(&manifest, b"{}");
        // `lockfile` does not exist.

        {
            let _tx = ManifestTransaction::snapshot_install_state(&[&manifest], &[&lockfile], &[])
                .unwrap();
            // Pipeline creates a lockfile.
            write(&lockfile, b"new lockfile bytes");
        }
        // Drop → manifest stays as-is, lockfile is removed.

        assert_eq!(read(&manifest), b"{}");
        assert!(
            !lockfile.exists(),
            "lockfile that did not exist before snapshot must be removed on rollback"
        );
    }

    /// Optional path that existed at snapshot time is restored to its
    /// original bytes, even if the install pipeline deleted it
    /// in-between (which `run_add_packages` does for re-resolution).
    #[test]
    fn snapshot_install_state_optional_existing_is_restored_after_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let lockfile = dir.path().join("lpm.lock");
        write(&manifest, b"{}");
        write(&lockfile, b"original lockfile bytes");

        {
            let _tx = ManifestTransaction::snapshot_install_state(&[&manifest], &[&lockfile], &[])
                .unwrap();
            // Pipeline removes the lockfile mid-install.
            fs::remove_file(&lockfile).unwrap();
            // And then writes a new one.
            write(&lockfile, b"new lockfile bytes");
        }
        // Drop → lockfile bytes restored to original.

        assert_eq!(
            read(&lockfile),
            b"original lockfile bytes",
            "optional path with pre-snapshot bytes must be restored"
        );
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_install_state_refuses_optional_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"private outside bytes").unwrap();
        let linked_lockfile = dir.path().join("package-lock.json");
        std::os::unix::fs::symlink(outside.path(), &linked_lockfile).unwrap();

        let result = ManifestTransaction::snapshot_install_state(&[], &[&linked_lockfile], &[]);

        assert!(result.is_err());
    }

    /// Invalidate paths are deleted on rollback regardless of their
    /// pre-snapshot state. Cache invalidation contract.
    #[test]
    fn snapshot_install_state_invalidate_path_deleted_on_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let install_hash = dir.path().join(".lpm").join("install-hash");
        write(&manifest, b"{}");
        fs::create_dir_all(install_hash.parent().unwrap()).unwrap();
        write(&install_hash, b"existing hash");

        {
            let _tx =
                ManifestTransaction::snapshot_install_state(&[&manifest], &[], &[&install_hash])
                    .unwrap();
            // Pipeline writes a new hash.
            write(&install_hash, b"new hash");
        }
        // Drop → install-hash deleted (NOT restored to "existing hash").

        assert!(
            !install_hash.exists(),
            "invalidate path must be deleted on rollback regardless of pre-snapshot state"
        );
    }

    /// Invalidate path may not exist at snapshot time and may not be
    /// created during the transaction. Drop must not panic.
    #[test]
    fn snapshot_install_state_invalidate_path_missing_throughout_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let install_hash = dir.path().join(".lpm").join("install-hash");
        write(&manifest, b"{}");
        // install-hash does not exist; never created during the tx.

        {
            let _tx =
                ManifestTransaction::snapshot_install_state(&[&manifest], &[], &[&install_hash])
                    .unwrap();
        }
        // Drop → no-op for the missing invalidate path. Must not panic.

        assert!(!install_hash.exists());
    }

    /// Commit on a snapshot_install_state transaction must skip BOTH
    /// the snapshot restore and the invalidation pass.
    #[test]
    fn snapshot_install_state_commit_skips_both_restore_and_invalidate() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let lockfile = dir.path().join("lpm.lock");
        let install_hash = dir.path().join(".lpm").join("install-hash");
        write(&manifest, b"{}");
        write(&lockfile, b"original");
        fs::create_dir_all(install_hash.parent().unwrap()).unwrap();

        let tx = ManifestTransaction::snapshot_install_state(
            &[&manifest],
            &[&lockfile],
            &[&install_hash],
        )
        .unwrap();

        write(&manifest, b"{\"new\":true}");
        write(&lockfile, b"new lockfile");
        write(&install_hash, b"new hash");

        tx.commit();

        assert_eq!(read(&manifest), b"{\"new\":true}");
        assert_eq!(read(&lockfile), b"new lockfile");
        assert_eq!(read(&install_hash), b"new hash");
    }

    #[test]
    fn rollback_restores_file_backed_large_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.lock");
        let original = vec![b'a'; IN_MEMORY_SNAPSHOT_LIMIT as usize + 1];
        write(&path, &original);

        let transaction = ManifestTransaction::snapshot_install_state(&[], &[&path], &[]).unwrap();
        write(&path, b"changed");
        drop(transaction);

        assert_eq!(read(&path), original);
    }
}
