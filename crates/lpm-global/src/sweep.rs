//! Tombstone sweep — deferred deletion of old global-install roots.
//!
//! Commits (upgrade) and rollbacks (fresh-install abort, failed uninstall
//! cleanup) append relative paths like `"installs/eslint@9.24.0"` to
//! `manifest.tombstones` instead of deleting them inline. Two reasons:
//!
//! 1. **Windows file-locking.** A `tsc --watch` run (or any long-lived tool
//!    invoked via the old shim) keeps files in the old install root open.
//!    `remove_dir_all` returns `ERROR_SHARING_VIOLATION`. Inline failure
//!    there would either wedge the tx (can't commit without cleanup) or
//!    force us to half-commit (abandon the cleanup and lie about success).
//!    Tombstoning lets commit succeed; the next sweep retries cleanup.
//!
//! 2. **Keeping the critical section short.** The tx lock is held across
//!    manifest read → write → WAL commit append. Walking a 100MB node_modules
//!    tree inside that window blocks every other global command on the host.
//!    Tombstoning defers that I/O outside the lock.
//!
//! `sweep_tombstones` is the janitor. It's **opportunistic** — best-effort
//! deletion that never fails the caller. Three call sites:
//!
//! - After every successful `install -g` / `uninstall -g` / `update -g`
//!   (post-commit, best-effort; ignored errors because the tx already
//!   succeeded).
//! - Inside `lpm store gc` (which is the user-facing "clean everything"
//!   command — runs the sweep as one of its steps).
//! - Inside recovery if we ever add it there (currently recovery only
//!   *appends* to tombstones; sweeping in recovery would be an optimisation).
//!
//! The sweep holds the **global tx lock** across the manifest read → delete
//! loop → manifest write. That serialises it against concurrent global
//! commands (which mutate the tombstone list). It's otherwise idempotent:
//! running it 100 times in a row against an empty tombstone set is cheap
//! (one lock acquire, one manifest read, no mutations, no writes).

use crate::manifest::{read_for, write_for};
use lpm_common::{LpmError, LpmRoot, as_extended_path, try_with_exclusive_lock};
use std::io::ErrorKind;
use std::path::Path;

/// Outcome of one sweep pass. Values are `u64` for `freed_bytes` and
/// small `usize` for counts — suitable for a top-level `u64`/`u64` JSON
/// emit without further conversion in the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Tombstones whose on-disk root was deleted (including those that
    /// were already absent — those count as "swept" because the user's
    /// mental model is "cleanup is done" either way).
    pub swept: Vec<String>,
    /// Tombstones that remain because the on-disk delete failed with
    /// something other than `NotFound` (e.g. Windows sharing violation,
    /// perms). Stays in the manifest for the next sweep to retry.
    pub retained: Vec<SweepFailure>,
    /// Bytes freed across all successful deletes (zero for NotFound).
    pub freed_bytes: u64,
    /// `true` when the sweep could not acquire the global tx lock — the
    /// caller should treat this as "nothing to do right now, another
    /// process owns the lock." Only returned by `try_sweep_tombstones`.
    pub skipped_locked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepFailure {
    pub relative_path: String,
    /// Human-readable description of why the delete failed — suitable for
    /// `output::warn` / JSON emission. Not structured further because the
    /// underlying errors span NotADirectory / PermissionDenied / WouldBlock /
    /// platform-specific (ERROR_SHARING_VIOLATION on Windows), and the
    /// caller doesn't branch on them.
    pub reason: String,
}

/// Try to sweep tombstones under the global tx lock. Returns `Ok(report)`
/// with `skipped_locked: true` when another process holds the lock — the
/// caller should treat that as "not now, try later" rather than an error.
/// All other outcomes (partial success, full success, empty tombstones)
/// return `skipped_locked: false`.
///
/// This is the version the **opportunistic** post-commit hooks call:
/// they don't want to block on another process's sweep, and they don't
/// want an error either. `lpm store gc` should use
/// [`sweep_tombstones`] instead, which blocks until it gets the lock.
pub fn try_sweep_tombstones(root: &LpmRoot) -> Result<SweepReport, LpmError> {
    let lock_path = root.global_tx_lock();
    match try_with_exclusive_lock(&lock_path, || sweep_under_lock(root))? {
        Some(report) => Ok(report),
        None => Ok(SweepReport {
            skipped_locked: true,
            ..SweepReport::default()
        }),
    }
}

/// Blocking sweep under the global tx lock. Used by `lpm store gc` and
/// tests. Callers that may run during another user-facing global command
/// should prefer [`try_sweep_tombstones`].
pub fn sweep_tombstones(root: &LpmRoot) -> Result<SweepReport, LpmError> {
    lpm_common::with_exclusive_lock(root.global_tx_lock(), || sweep_under_lock(root))
}

fn sweep_under_lock(root: &LpmRoot) -> Result<SweepReport, LpmError> {
    let mut manifest = read_for(root)?;
    if manifest.tombstones.is_empty() {
        return Ok(SweepReport::default());
    }

    let global_root = root.global_root();
    let mut swept = Vec::new();
    let mut retained = Vec::new();
    let mut freed_bytes: u64 = 0;
    // `tombstones.drain(..)` would work too, but taking ownership via
    // `std::mem::take` keeps the manifest in a valid state during the
    // loop in case a future refactor starts reading `manifest.tombstones`
    // mid-sweep (a bug we'd rather not create silently).
    let pending: Vec<String> = std::mem::take(&mut manifest.tombstones);

    for relative_path in pending {
        let abs = global_root.join(&relative_path);
        match delete_install_root(&abs) {
            Ok(bytes) => {
                freed_bytes = freed_bytes.saturating_add(bytes);
                swept.push(relative_path);
            }
            Err(reason) => {
                retained.push(SweepFailure {
                    relative_path: relative_path.clone(),
                    reason,
                });
                manifest.tombstones.push(relative_path);
            }
        }
    }

    // Only rewrite the manifest if we actually changed it. Manifest writes
    // are cheap (TOML serialise + rename) but not free, and the "empty
    // tombstones" early-return above already handled the no-change case.
    // Here we either swept some (drain removed entries) or retained all
    // (count unchanged but Vec re-populated in same order).
    if !swept.is_empty() {
        write_for(root, &manifest)?;
    }

    Ok(SweepReport {
        swept,
        retained,
        freed_bytes,
        skipped_locked: false,
    })
}

/// Try to remove an install root and return bytes freed. A missing path
/// is success (returns 0) — tombstones can outlive their targets if the
/// user manually cleaned up or if a crash happened after the disk delete
/// but before the manifest rewrite in a previous sweep.
///
/// Computes size BEFORE deletion (walking the tree once for bytes, then
/// letting `remove_dir_all` walk it again for deletion). The size walk
/// is wrapped in `extend_path` to handle Windows extended-length paths
/// when the tree is deeply nested.
fn delete_install_root(abs: &Path) -> Result<u64, String> {
    let extended = as_extended_path(abs);
    match std::fs::symlink_metadata(&extended) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("stat failed: {e}")),
    }
    let bytes = dir_size(&extended).unwrap_or(0);
    match std::fs::remove_dir_all(&extended) {
        Ok(()) => Ok(bytes),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(0),
        Err(e) => Err(format!("remove_dir_all failed: {e}")),
    }
}

/// Recursive tree size. Tolerant of disappearing entries (race with
/// another process cleaning up) — missing entries contribute 0 rather
/// than propagating the error, since this is best-effort accounting.
fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total: u64 = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return Ok(0);
    };
    for entry in entries.flatten() {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_dir() {
            total = total.saturating_add(dir_size(&entry.path()).unwrap_or(0));
        } else if ft.is_file()
            && let Ok(meta) = entry.metadata()
        {
            total = total.saturating_add(meta.len());
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{GlobalManifest, write_for};
    use std::fs;

    fn seed_manifest_with_tombstones(root: &LpmRoot, tombstones: &[&str]) {
        let m = GlobalManifest {
            tombstones: tombstones.iter().map(|s| (*s).to_string()).collect(),
            ..GlobalManifest::default()
        };
        write_for(root, &m).unwrap();
    }

    fn seed_install_root(root: &LpmRoot, relative: &str) -> u64 {
        let abs = root.global_root().join(relative);
        fs::create_dir_all(&abs).unwrap();
        // A known payload so `freed_bytes` is predictable.
        let payload = b"x".repeat(1024);
        fs::write(abs.join("marker.bin"), &payload).unwrap();
        fs::create_dir_all(abs.join("nested/deeper")).unwrap();
        fs::write(abs.join("nested/a.txt"), b"hello").unwrap();
        fs::write(abs.join("nested/deeper/b.txt"), b"world").unwrap();
        // 1024 + 5 + 5 = 1034 bytes
        1034
    }

    #[test]
    fn sweep_empty_tombstones_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        write_for(&root, &GlobalManifest::default()).unwrap();

        let report = sweep_tombstones(&root).unwrap();
        assert!(report.swept.is_empty());
        assert!(report.retained.is_empty());
        assert_eq!(report.freed_bytes, 0);
        assert!(!report.skipped_locked);
    }

    #[test]
    fn sweep_deletes_existing_install_roots_and_clears_tombstones() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let expected_bytes = seed_install_root(&root, "installs/eslint@9.24.0")
            + seed_install_root(&root, "installs/prettier@3.8.3");
        seed_manifest_with_tombstones(
            &root,
            &["installs/eslint@9.24.0", "installs/prettier@3.8.3"],
        );

        let report = sweep_tombstones(&root).unwrap();
        assert_eq!(report.swept.len(), 2);
        assert!(report.retained.is_empty());
        assert_eq!(report.freed_bytes, expected_bytes);

        // Manifest tombstones cleared.
        let m = read_for(&root).unwrap();
        assert!(m.tombstones.is_empty());

        // Install roots physically gone.
        assert!(!root.global_root().join("installs/eslint@9.24.0").exists());
        assert!(!root.global_root().join("installs/prettier@3.8.3").exists());
    }

    #[test]
    fn sweep_treats_already_missing_path_as_success() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        // Tombstone references a path that doesn't exist on disk —
        // maybe we crashed after delete but before manifest rewrite.
        seed_manifest_with_tombstones(&root, &["installs/ghost@1.0.0"]);

        let report = sweep_tombstones(&root).unwrap();
        assert_eq!(report.swept, vec!["installs/ghost@1.0.0".to_string()]);
        assert!(report.retained.is_empty());
        assert_eq!(report.freed_bytes, 0);

        let m = read_for(&root).unwrap();
        assert!(m.tombstones.is_empty());
    }

    /// Mixed outcome: one tombstone sweeps cleanly, another fails.
    /// The failing one must stay in the manifest so the next sweep
    /// retries it; the succeeding one must be removed.
    ///
    /// We simulate the failure by pointing a tombstone at a regular
    /// FILE instead of a directory — `remove_dir_all` on a file returns
    /// an error on all platforms (NotADirectory / similar).
    #[test]
    fn sweep_retains_failing_tombstones_and_clears_successful_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        seed_install_root(&root, "installs/good@1.0.0");
        // "bad" is a regular file, not a directory — remove_dir_all errors.
        let bad_abs = root.global_root().join("installs/bad@1.0.0");
        fs::create_dir_all(bad_abs.parent().unwrap()).unwrap();
        fs::write(&bad_abs, b"not a directory").unwrap();

        seed_manifest_with_tombstones(&root, &["installs/good@1.0.0", "installs/bad@1.0.0"]);

        let report = sweep_tombstones(&root).unwrap();
        // Exactly one swept, one retained — order preserved so the retry
        // output has a stable shape.
        assert_eq!(report.swept, vec!["installs/good@1.0.0".to_string()]);
        assert_eq!(report.retained.len(), 1);
        assert_eq!(report.retained[0].relative_path, "installs/bad@1.0.0");
        assert!(!report.retained[0].reason.is_empty());

        let m = read_for(&root).unwrap();
        assert_eq!(m.tombstones, vec!["installs/bad@1.0.0".to_string()]);
    }

    #[test]
    fn sweep_is_idempotent_on_repeated_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_install_root(&root, "installs/once@1.0.0");
        seed_manifest_with_tombstones(&root, &["installs/once@1.0.0"]);

        let first = sweep_tombstones(&root).unwrap();
        assert_eq!(first.swept.len(), 1);

        // Second call should be a no-op.
        let second = sweep_tombstones(&root).unwrap();
        assert!(second.swept.is_empty());
        assert!(second.retained.is_empty());
        assert_eq!(second.freed_bytes, 0);
    }

    #[test]
    fn try_sweep_returns_skipped_locked_when_tx_lock_held() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_install_root(&root, "installs/locked@1.0.0");
        seed_manifest_with_tombstones(&root, &["installs/locked@1.0.0"]);

        // Hold the tx lock in a nested scope so the .lock file exists
        // and is exclusively locked while we call try_sweep.
        let result = lpm_common::with_exclusive_lock(root.global_tx_lock(), || {
            let report = try_sweep_tombstones(&root)?;
            Ok::<_, LpmError>(report)
        })
        .unwrap();

        assert!(
            result.skipped_locked,
            "try_sweep must surface lock contention as skipped_locked, not error out"
        );
        assert!(result.swept.is_empty());

        // Tombstone should still be there since we held the lock.
        let m = read_for(&root).unwrap();
        assert_eq!(m.tombstones, vec!["installs/locked@1.0.0".to_string()]);
    }

    #[test]
    fn try_sweep_succeeds_when_uncontended() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_install_root(&root, "installs/free@1.0.0");
        seed_manifest_with_tombstones(&root, &["installs/free@1.0.0"]);

        let report = try_sweep_tombstones(&root).unwrap();
        assert!(!report.skipped_locked);
        assert_eq!(report.swept.len(), 1);
    }
}
