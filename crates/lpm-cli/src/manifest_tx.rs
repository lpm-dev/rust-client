//! Snapshot-and-restore guard for the install state surface.
//!
//! Phase 33 introduces a "stage placeholder, run install, finalize manifest"
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
//!    `package.json`, `lpm.lock`, `lpm.lockb`.
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
//! pre-Phase-33 behavior of leaving `"*"` in the manifest, a stale lockfile
//! on disk, or an incoherent `install-hash` cache after a failed install.
//!
//! ### Why `node_modules/` is not part of the boundary
//!
//! The install pipeline mutates `node_modules/` heavily (delete + re-link),
//! and snapshotting it would mean copying potentially gigabytes of files
//! per transaction. Phase 33's contract is that after a failed install,
//! the on-disk state files (`package.json`, `lpm.lock`, `.lpm/install-hash`)
//! are coherent with each other and with what the user typed. The
//! `node_modules/` tree may temporarily diverge from the lockfile, but the
//! deleted `install-hash` cache forces the next `lpm install` to re-link
//! and converge. This is documented as a known limitation of the rollback
//! boundary.

use std::path::{Path, PathBuf};

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
    /// Files deleted on rollback, regardless of their pre-snapshot state.
    /// Cache files where stale data is worse than no data.
    invalidate: Vec<PathBuf>,
    committed: bool,
}

struct SnapshotEntry {
    path: PathBuf,
    original_bytes: Option<Vec<u8>>,
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

    /// Snapshot the full install state surface for Phase 33's rollback
    /// boundary. `required` paths must exist (typically the manifest);
    /// `optional` paths are recorded as `Some(bytes)` if present and
    /// `None` if missing (rollback will remove them); `invalidate` paths
    /// are deleted on rollback regardless of their pre-snapshot state
    /// (cache files like `.lpm/install-hash`).
    ///
    /// Used by `run_add_packages` and `run_install_filtered_add` to
    /// guard `package.json` (required), `lpm.lock` + `lpm.lockb`
    /// (optional, may be absent on a fresh project), and
    /// `.lpm/install-hash` (invalidate).
    pub fn snapshot_install_state(
        required: &[&Path],
        optional: &[&Path],
        invalidate: &[&Path],
    ) -> std::io::Result<Self> {
        let mut snapshots = Vec::with_capacity(required.len() + optional.len());

        for path in required {
            let bytes = std::fs::read(path)?;
            snapshots.push(SnapshotEntry {
                path: path.to_path_buf(),
                original_bytes: Some(bytes),
            });
        }

        for path in optional {
            let original_bytes = match std::fs::read(path) {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            };
            snapshots.push(SnapshotEntry {
                path: path.to_path_buf(),
                original_bytes,
            });
        }

        Ok(Self {
            snapshots,
            invalidate: invalidate.iter().map(|p| p.to_path_buf()).collect(),
            committed: false,
        })
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
        for entry in &self.snapshots {
            match &entry.original_bytes {
                Some(bytes) => {
                    if let Err(e) = std::fs::write(&entry.path, bytes) {
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
            // Mutate the manifest the way Phase 33's stage step would.
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
}
