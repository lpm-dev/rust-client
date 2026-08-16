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
//! - Inside `lpm cache prune --apply` (the user-facing reachability-aware
//!   cleanup command — runs the sweep as one of its steps).
//! - Inside recovery if we ever add it there (currently recovery only
//!   *appends* to tombstones; sweeping in recovery would be an optimisation).
//!
//! The sweep holds the **global tx lock** across the manifest read → delete
//! loop → manifest write. That serialises it against concurrent global
//! commands (which mutate the tombstone list). It's otherwise idempotent:
//! running it 100 times in a row against an empty tombstone set is cheap
//! (one lock acquire, one manifest read, no mutations, no writes).

use crate::manifest::{InstallRootReferenceStatus, read_for, write_for};
use lpm_common::{LpmError, LpmRoot, as_extended_path, try_with_exclusive_lock};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

/// Outcome of one sweep pass. Values are `u64` for `freed_bytes` and
/// small `usize` for counts — suitable for a top-level `u64`/`u64` JSON
/// emit without further conversion in the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Tombstones whose cleanup is resolved. The root was deleted, was
    /// already absent, or is still referenced by a live manifest row and the
    /// stale tombstone was discarded without deleting it.
    pub swept: Vec<String>,
    /// Tombstones that remain because the on-disk delete failed or manifest
    /// state made reachability indeterminate. They stay in the manifest for
    /// the next sweep to retry.
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
/// want an error either. `lpm cache prune --apply` should use
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

/// Blocking sweep under the global tx lock. Used by `lpm cache prune --apply`
/// and tests. Callers that may run during another user-facing global command
/// should prefer [`try_sweep_tombstones`].
pub fn sweep_tombstones(root: &LpmRoot) -> Result<SweepReport, LpmError> {
    lpm_common::with_exclusive_lock(root.global_tx_lock(), || sweep_under_lock(root))
}

/// Count pending tombstones without acquiring the tx lock. Used for
/// `lpm cache prune` dry-run preview — races are cosmetic (the actual
/// non-dry-run sweep takes the lock and is authoritative).
///
/// Collapses any read/parse failure to `0`, matching the historical
/// "best-effort dry-run preview" shape. Callers that need to
/// distinguish "manifest absent / no tombstones" from "manifest exists
/// but unreadable" should use [`try_count_pending_tombstones`].
pub fn count_pending_tombstones(root: &LpmRoot) -> usize {
    try_count_pending_tombstones(root).unwrap_or(0)
}

/// Count pending tombstones, surfacing read/parse failures as `Err`.
///
/// Returns `Ok(0)` when the global manifest file does not exist (no
/// tombstones have been written yet). Returns `Err` when the manifest
/// exists but cannot be read or parsed — e.g. corrupted TOML,
/// future-schema variant, permission denied. The cache-prune emitter
/// surfaces the `Err` as a distinct `tombstone_count_error` field so
/// JSON consumers can tell "no tombstones" apart from "could not
/// inspect tombstones" (L53).
pub fn try_count_pending_tombstones(root: &LpmRoot) -> Result<usize, LpmError> {
    if !root.global_manifest().exists() {
        return Ok(0);
    }
    Ok(read_for(root)?.tombstones.len())
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
        // Manifests are not necessarily trustworthy. Recovery's `relative_install_root` already
        // refuses to *write* a tombstone path that escapes
        // `global_root`, but a corrupted, hand-edited, or
        // adversarially-poisoned manifest could still feed us paths
        // like `"../../../etc"` or `"/etc/passwd"`. `Path::join` does
        // NOT normalize parent traversals, and joining an absolute
        // arg REPLACES the base entirely — both of which would let a
        // bad tombstone reach `remove_dir_all` outside the global
        // tree. Validate before we touch the disk.
        //
        // Bad entries are RETAINED in the manifest (not silently
        // dropped) and surfaced via `SweepReport.retained` so an
        // operator running `lpm cache prune --apply` actually sees that the
        // manifest is poisoned, instead of having the evidence
        // quietly cleaned up.
        let abs = match validated_tombstone_path(&global_root, &relative_path) {
            Ok(abs) => abs,
            Err(reason) => {
                retained.push(SweepFailure {
                    relative_path: relative_path.clone(),
                    reason,
                });
                manifest.tombstones.push(relative_path);
                continue;
            }
        };
        match manifest.install_root_reference_status(&relative_path) {
            InstallRootReferenceStatus::Referenced => {
                swept.push(relative_path);
                continue;
            }
            InstallRootReferenceStatus::Indeterminate => {
                retained.push(SweepFailure {
                    relative_path: relative_path.clone(),
                    reason: "refusing install-root cleanup because a non-local manifest row has \
                             an invalid or ambiguous root path"
                        .to_string(),
                });
                manifest.tombstones.push(relative_path);
                continue;
            }
            InstallRootReferenceStatus::Unreferenced => {}
        }
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

/// Resolve a tombstone's relative path against `global_root`, refusing
/// anything that doesn't match the exact `installs/<name>@<version>`
/// shape produced by `LpmRoot::install_root_for`.
///
/// **Why such a strict shape and not "any relative path under the
/// global root"?** Blocking only `..` and absolute paths, with a final
/// `starts_with(global_root)` guard, closes the `../../etc` escape but still admits poisoned
/// entries like `"."` (resolves to `global_root` itself) or `"installs"`
/// (resolves to `global_root/installs`) — both of which `remove_dir_all`
/// would happily wipe, taking the entire global state or every live
/// install root with them.
///
/// The legitimate writers (`relative_install_root` in recover.rs, the
/// `install_root_relative` field in install/update commits, and the
/// `active.root` field in uninstall commits) ALL produce paths matching
/// `installs/<safe_name>@<version>`, where `safe_name` is the package
/// name with `/` replaced by `+`. Anything else is suspect.
///
/// Refusal cases (return `Err(reason)`):
///
/// 1. Empty path.
/// 2. Anything other than exactly two non-empty portable path segments
///    (rejects `"."`, `"installs"`, `"installs/"`, `"installs/foo/extra"`,
///    `"./installs/foo@1"`, `"../escape"`, `"/etc/passwd"`). Both `/` and
///    `\` are recognized so manifests remain readable across operating systems.
/// 3. First segment != `"installs"`.
/// 4. Second segment without an `@` separator.
/// 5. Defense in depth: even though steps 2-4 are textual, the joined
///    absolute path must `starts_with(global_root)`.
///
/// Accepting CurDir / extra path-prefix components was an explicit
/// regression — see the second-pass audit. Real writers never produce
/// them, so the validator does not either.
pub fn validated_install_root_relative(
    global_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    validated_tombstone_path(global_root, relative_path)
}

/// Validate a local-link root stored in the global manifest.
///
/// Local links use real directories under `links/<safe-package-name>`.
/// They are not tombstones and must never be swept by the install-root
/// janitor, but they need the same path-poisoning bar before any caller
/// joins a manifest string and deletes or walks it.
pub fn validated_local_link_root_relative(
    global_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    if relative_path.is_empty() {
        return Err("empty local-link root path (manifest corrupt?)".to_string());
    }
    let candidate = Path::new(relative_path);
    let mut segments: Vec<&std::ffi::OsStr> = Vec::with_capacity(2);
    for component in candidate.components() {
        match component {
            Component::Normal(s) => segments.push(s),
            Component::ParentDir => {
                return Err(format!(
                    "refusing local-link root {relative_path:?}: contains parent-directory \
                     traversal — manifest may be poisoned"
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "refusing local-link root {relative_path:?}: not a relative path under \
                     the global root — manifest may be poisoned"
                ));
            }
            Component::CurDir => {
                return Err(format!(
                    "refusing local-link root {relative_path:?}: contains current-directory \
                     reference — real local-link roots never include `./`"
                ));
            }
        }
    }
    if segments.len() != 2 {
        return Err(format!(
            "refusing local-link root {relative_path:?}: expected exactly \
             `links/<name>` (got {} segment(s))",
            segments.len()
        ));
    }
    if segments[0] != std::ffi::OsStr::new("links") {
        return Err(format!(
            "refusing local-link root {relative_path:?}: first segment must be `links/`"
        ));
    }
    if segments[1].is_empty() {
        return Err(format!(
            "refusing local-link root {relative_path:?}: leaf must not be empty"
        ));
    }

    let joined = global_root.join(candidate);
    if !joined.starts_with(global_root) {
        return Err(format!(
            "refusing local-link root {relative_path:?}: joined path escapes the global root"
        ));
    }
    Ok(joined)
}

/// Same shape check, but takes an absolute path. Used by recovery
/// when the path source is a WAL Intent's `new_root_path` field —
/// recovery doesn't know the relative form a priori. Refuses absolute
/// paths whose `strip_prefix(global_root)` fails OR whose relative
/// form doesn't pass `validated_install_root_relative`.
///
/// **L47 fix**: every `remove_dir_all` site fed by manifest- or
/// WAL-controlled paths gates through this helper first. A poisoned
/// `root = "../../victim"` joins under `global_root` to something
/// outside the tree; this helper refuses before the unlink.
pub fn validated_install_root_absolute(
    global_root: &Path,
    abs_path: &Path,
) -> Result<PathBuf, String> {
    let rel = abs_path.strip_prefix(global_root).map_err(|_| {
        format!(
            "refusing to act on {abs_path:?}: not under the global root \
             (manifest / WAL may be poisoned)"
        )
    })?;
    let rel_str = rel.to_str().ok_or_else(|| {
        format!("refusing to act on {abs_path:?}: install-root path is not valid UTF-8")
    })?;
    let validated = validated_tombstone_path(global_root, rel_str)?;
    let native_path = global_root.join(rel);
    if validated != native_path {
        return Err(format!(
            "refusing to act on {abs_path:?}: absolute install-root path uses a non-native \
             separator representation"
        ));
    }
    Ok(validated)
}

fn validated_tombstone_path(global_root: &Path, relative_path: &str) -> Result<PathBuf, String> {
    if relative_path.is_empty() {
        return Err("empty tombstone path (manifest corrupt?)".to_string());
    }
    let bytes = relative_path.as_bytes();
    let has_windows_drive_root = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    if relative_path.starts_with('/') || relative_path.starts_with('\\') || has_windows_drive_root {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: not a relative path under \
             the global root — manifest may be poisoned"
        ));
    }

    let segments: Vec<&str> = relative_path.split(['/', '\\']).collect();
    if segments.contains(&"..") {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: contains parent-directory \
             traversal — manifest may be poisoned"
        ));
    }
    if segments.contains(&".") {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: contains current-directory \
             reference — real install-root tombstones never include `./`"
        ));
    }
    if segments
        .iter()
        .any(|segment| segment.is_empty() || segment.contains([':', '\0']))
    {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: contains an invalid path segment"
        ));
    }

    // Tombstones are exactly `installs/<name>@<version>`.
    // Two segments. First is literally "installs". Second has an `@`.
    // ANYTHING else (single segment like "." or "installs", three+
    // segments like "installs/foo/extra", different prefix) is suspect.
    if segments.len() != 2 {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: expected exactly \
             `installs/<name>@<version>` (got {} segment(s))",
            segments.len()
        ));
    }
    if segments[0] != "installs" {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: first segment must be `installs/`"
        ));
    }
    let leaf = segments[1];
    if !leaf.contains('@') {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: leaf must match `<name>@<version>` \
             (no `@` found)"
        ));
    }
    if leaf
        .as_bytes()
        .last()
        .is_some_and(|last| matches!(*last, b'.' | b' '))
    {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: leaf must not end in a dot or space"
        ));
    }

    let joined = global_root.join("installs").join(leaf);
    // Defense in depth: the textual checks above should make this
    // unreachable, but a future refactor that admits a new component
    // variant would land here instead of escaping.
    if !joined.starts_with(global_root) {
        return Err(format!(
            "refusing to sweep tombstone {relative_path:?}: joined path escapes the global root"
        ));
    }
    Ok(joined)
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
    let bytes = dir_size(&extended);
    match std::fs::remove_dir_all(&extended) {
        Ok(()) => Ok(bytes),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(0),
        Err(e) => Err(format!("remove_dir_all failed: {e}")),
    }
}

/// Recursive tree size. Tolerant of disappearing entries (race with
/// another process cleaning up) — missing entries contribute 0 rather
/// than propagating the error, since this is best-effort accounting.
fn dir_size(path: &Path) -> u64 {
    let mut total: u64 = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_dir() {
            total = total.saturating_add(dir_size(&entry.path()));
        } else if ft.is_file()
            && let Ok(meta) = entry.metadata()
        {
            total = total.saturating_add(meta.len());
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{GlobalManifest, PackageEntry, PackageSource, PendingEntry, write_for};
    use chrono::Utc;
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

    fn active_entry(root: &str) -> PackageEntry {
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-active".into(),
            source: PackageSource::LpmDev,
            installed_at: Utc::now(),
            root: root.into(),
            commands: vec!["pkg".into()],
        }
    }

    fn pending_entry(root: &str) -> PendingEntry {
        PendingEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-pending".into(),
            source: PackageSource::LpmDev,
            started_at: Utc::now(),
            root: root.into(),
            commands: vec!["pkg".into()],
            replaces_version: None,
        }
    }

    #[test]
    fn count_pending_tombstones_returns_len_when_manifest_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_manifest_with_tombstones(
            &root,
            &["installs/a@1.0.0", "installs/b@2.0.0", "installs/c@3.0.0"],
        );
        assert_eq!(count_pending_tombstones(&root), 3);
    }

    #[test]
    fn count_pending_tombstones_returns_zero_when_no_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        assert_eq!(count_pending_tombstones(&root), 0);
    }

    #[test]
    fn try_count_pending_tombstones_returns_ok_zero_when_no_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        assert_eq!(try_count_pending_tombstones(&root).unwrap(), 0);
    }

    #[test]
    fn try_count_pending_tombstones_returns_err_when_manifest_is_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        std::fs::write(root.global_manifest(), b"@@@ not toml @@@").unwrap();
        let err = try_count_pending_tombstones(&root)
            .expect_err("corrupt TOML must propagate as Err so cache prune can surface it");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("manifest") || msg.contains("toml"),
            "error must describe the parse failure, got: {err}"
        );
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

    #[test]
    fn sweep_discards_stale_tombstone_without_deleting_active_install_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let relative = "installs/pkg@1.0.0";
        let install_root = root.global_root().join(relative);
        seed_install_root(&root, relative);

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), active_entry(relative));
        manifest.tombstones.push(relative.into());
        write_for(&root, &manifest).unwrap();

        let report = sweep_tombstones(&root).unwrap();

        assert_eq!(report.swept, vec![relative.to_string()]);
        assert_eq!(report.freed_bytes, 0);
        assert!(
            install_root.exists(),
            "a stale tombstone must not delete an active install root; report: {report:?}"
        );
        assert!(read_for(&root).unwrap().tombstones.is_empty());
    }

    #[test]
    fn sweep_discards_stale_tombstone_without_deleting_pending_install_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let relative = "installs/pkg@1.0.0";
        let install_root = root.global_root().join(relative);
        seed_install_root(&root, relative);

        let mut manifest = GlobalManifest::default();
        manifest
            .pending
            .insert("pkg".into(), pending_entry(relative));
        manifest.tombstones.push(relative.into());
        write_for(&root, &manifest).unwrap();

        let report = sweep_tombstones(&root).unwrap();

        assert_eq!(report.swept, vec![relative.to_string()]);
        assert_eq!(report.freed_bytes, 0);
        assert!(
            install_root.exists(),
            "a stale tombstone must not delete a pending install root; report: {report:?}"
        );
        assert!(read_for(&root).unwrap().tombstones.is_empty());
    }

    #[test]
    fn sweep_retains_tombstone_when_non_local_manifest_root_is_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let relative = "installs/pkg@1.0.0";
        let install_root = root.global_root().join(relative);
        seed_install_root(&root, relative);

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), active_entry("installs/./pkg@1.0.0"));
        manifest.tombstones.push(relative.into());
        write_for(&root, &manifest).unwrap();

        let report = sweep_tombstones(&root).unwrap();

        assert!(report.swept.is_empty());
        assert_eq!(report.retained.len(), 1);
        assert!(install_root.exists());
        assert_eq!(read_for(&root).unwrap().tombstones, vec![relative]);
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

    // ─── Poisoned-tombstone validation ─────────────────────────
    //
    // Recovery's `relative_install_root` only writes tombstones that
    // strip cleanly under `global_root`. The sweep, however, reads
    // tombstones back from a TOML file on disk that's editable by anyone
    // with $LPM_HOME write access (or by a corrupt downgrade / a future
    // bug). Without consume-side validation, a poisoned manifest could
    // make `lpm cache prune --apply` recursively delete arbitrary directories
    // outside the global tree — `Path::join` doesn't normalize `..`,
    // and joining an absolute path replaces the base.
    //
    // The tests below seed a "victim" file or directory OUTSIDE the
    // synthesized $LPM_HOME and assert it survives a sweep that
    // includes a hostile tombstone targeting it.

    /// Setup helper for traversal tests. Creates a tempdir layout:
    ///   <tmp>/lpm-home/         — synthesized $LPM_HOME
    ///   <tmp>/victim.txt        — file that MUST NOT be touched
    ///   <tmp>/victim-dir/       — directory that MUST NOT be touched
    /// Returns (LpmRoot anchored at lpm-home, victim file, victim dir).
    fn poisoned_setup() -> (tempfile::TempDir, LpmRoot, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("lpm-home");
        std::fs::create_dir_all(&home).unwrap();
        let root = LpmRoot::from_dir(&home);

        let victim_file = tmp.path().join("victim.txt");
        std::fs::write(&victim_file, b"DO NOT DELETE").unwrap();
        let victim_dir = tmp.path().join("victim-dir");
        std::fs::create_dir_all(&victim_dir).unwrap();
        std::fs::write(victim_dir.join("nested.txt"), b"DO NOT DELETE EITHER").unwrap();

        (tmp, root, victim_file, victim_dir)
    }

    #[test]
    fn sweep_refuses_parent_traversal_tombstone_and_keeps_it_in_manifest() {
        let (_tmp, root, victim_file, victim_dir) = poisoned_setup();

        // The hostile tombstone tries to escape global_root via `..`.
        // From `<tmp>/lpm-home/global/`, going up four levels lands at
        // `/`, then we descend by name back to the victim. The exact
        // depth doesn't matter — any `..` must be refused regardless of
        // whether it would reach a real victim.
        let traversal = "../../victim-dir";
        seed_manifest_with_tombstones(&root, &[traversal]);

        let report = sweep_tombstones(&root).unwrap();

        // Sweep must refuse: nothing swept, one retained with a clear
        // poison-suspecting message.
        assert!(
            report.swept.is_empty(),
            "sweep must NOT consume parent-traversal tombstone"
        );
        assert_eq!(report.retained.len(), 1);
        assert_eq!(report.retained[0].relative_path, traversal);
        assert!(
            report.retained[0]
                .reason
                .contains("parent-directory traversal"),
            "retain reason must name the traversal hazard, got: {}",
            report.retained[0].reason
        );

        // Hostile tombstone must remain in the manifest so an operator
        // sees it (and so we don't silently launder a poisoned manifest
        // into a clean one).
        let m = read_for(&root).unwrap();
        assert_eq!(m.tombstones, vec![traversal.to_string()]);

        // Victims survive untouched.
        assert!(victim_file.exists());
        assert!(victim_dir.exists());
        assert!(victim_dir.join("nested.txt").exists());
    }

    #[test]
    fn sweep_refuses_absolute_path_tombstone() {
        let (_tmp, root, victim_file, _victim_dir) = poisoned_setup();

        // Absolute path tombstone — `Path::join` would replace the base
        // entirely, so the victim_file's absolute path lands directly
        // at remove_dir_all without ever touching global_root.
        let hostile = victim_file.to_string_lossy().into_owned();
        seed_manifest_with_tombstones(&root, &[&hostile]);

        let report = sweep_tombstones(&root).unwrap();
        assert!(report.swept.is_empty());
        assert_eq!(report.retained.len(), 1);
        assert!(
            report.retained[0]
                .reason
                .contains("not a relative path under the global root"),
            "retain reason must explain the absolute-path refusal, got: {}",
            report.retained[0].reason
        );

        // Manifest preserves the hostile entry for operator visibility.
        let m = read_for(&root).unwrap();
        assert_eq!(m.tombstones, vec![hostile]);

        // Victim survives.
        assert!(victim_file.exists());
        assert_eq!(std::fs::read(&victim_file).unwrap(), b"DO NOT DELETE");
    }

    #[test]
    fn sweep_refuses_empty_tombstone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_manifest_with_tombstones(&root, &[""]);

        let report = sweep_tombstones(&root).unwrap();
        assert!(report.swept.is_empty());
        assert_eq!(report.retained.len(), 1);
        assert!(report.retained[0].reason.contains("empty tombstone"));
    }

    /// Mixed-batch behaviour: a hostile tombstone next to a legitimate
    /// one must NOT prevent the legitimate one from being swept. The
    /// hostile entry stays for the operator; the safe entry goes.
    #[test]
    fn sweep_processes_safe_tombstones_around_a_poisoned_one() {
        let (_tmp, root, _victim_file, victim_dir) = poisoned_setup();
        seed_install_root(&root, "installs/legit@1.0.0");
        seed_manifest_with_tombstones(&root, &["installs/legit@1.0.0", "../../victim-dir"]);

        let report = sweep_tombstones(&root).unwrap();

        assert_eq!(
            report.swept,
            vec!["installs/legit@1.0.0".to_string()],
            "the safe tombstone must still be swept"
        );
        assert_eq!(report.retained.len(), 1);
        assert_eq!(report.retained[0].relative_path, "../../victim-dir");

        let m = read_for(&root).unwrap();
        assert_eq!(m.tombstones, vec!["../../victim-dir".to_string()]);

        assert!(
            !root.global_root().join("installs/legit@1.0.0").exists(),
            "safe target should be gone"
        );
        assert!(victim_dir.exists(), "victim dir must remain");
    }

    /// Direct test of the validator helper. Faster signal during future
    /// refactors than going through the full sweep.
    #[test]
    fn validated_tombstone_path_unit_cases() {
        let global_root = Path::new("/home/user/.lpm/global");

        // Happy paths — the exact `installs/<name>@<version>` shape.
        assert!(validated_tombstone_path(global_root, "installs/eslint@9.24.0").is_ok());
        assert!(validated_tombstone_path(global_root, "installs/@scope+pkg@1.0.0").is_ok());
        assert!(validated_tombstone_path(global_root, r"installs\eslint@9.24.0").is_ok());

        // Pre-existing first-pass refusals.
        assert!(validated_tombstone_path(global_root, "").is_err());
        assert!(validated_tombstone_path(global_root, "../escape").is_err());
        assert!(validated_tombstone_path(global_root, "installs/../escape").is_err());
        assert!(validated_tombstone_path(global_root, "/etc/passwd").is_err());

        // These used to slip through the "stays under global_root" check and let
        // remove_dir_all wipe the whole global state or every install root.
        // Either of two refusal axes (shape OR component-kind) is
        // acceptable; both block the dangerous primitive.
        assert!(
            validated_tombstone_path(global_root, ".").is_err(),
            "`.` must be refused"
        );
        let installs_only = validated_tombstone_path(global_root, "installs").unwrap_err();
        assert!(
            installs_only.contains("expected exactly `installs/<name>@<version>`"),
            "`installs` must be refused with shape error: {installs_only}"
        );

        // CurDir is now an explicit refusal (real writers never emit `./`).
        let cur = validated_tombstone_path(global_root, "./installs/x@1.0.0").unwrap_err();
        assert!(cur.contains("current-directory"));

        // Three-segment / "extra" shapes.
        assert!(validated_tombstone_path(global_root, "installs/foo@1.0/extra").is_err());

        // First segment must be exactly `installs/`.
        let wrong_root =
            validated_tombstone_path(global_root, "scripts/eslint@9.24.0").unwrap_err();
        assert!(wrong_root.contains("first segment must be `installs/`"));

        // Leaf must contain `@`.
        let no_at = validated_tombstone_path(global_root, "installs/eslint").unwrap_err();
        assert!(no_at.contains("`<name>@<version>`"));

        assert!(validated_tombstone_path(global_root, "installs/pkg@1.0.0.").is_err());
        assert!(validated_tombstone_path(global_root, "installs/pkg@1.0.0 ").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn absolute_install_root_validator_rejects_non_native_separator_alias() {
        let global_root = Path::new("/home/user/.lpm/global");
        let non_native = global_root.join(r"installs\pkg@1.0.0");

        assert!(validated_install_root_absolute(global_root, &non_native).is_err());
    }

    /// End-to-end poisoning scenario. A tombstone of `"."` would (pre-fix)
    /// have made the sweep
    /// `remove_dir_all(global_root)`, wiping the whole global tree —
    /// manifest, installs, WAL, the lot. Assert the tree survives.
    #[test]
    fn sweep_refuses_dot_tombstone_and_does_not_wipe_global_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Seed a sibling install root + a marker file directly under
        // global_root so we can detect a wipe (the marker would vanish
        // along with everything else under global_root).
        let canary = root.global_root().join(".canary");
        std::fs::create_dir_all(canary.parent().unwrap()).unwrap();
        std::fs::write(&canary, b"DO NOT DELETE").unwrap();
        seed_install_root(&root, "installs/legit@1.0.0");
        seed_manifest_with_tombstones(&root, &["."]);

        let report = sweep_tombstones(&root).unwrap();

        assert!(report.swept.is_empty(), "`.` must NOT be swept");
        assert_eq!(report.retained.len(), 1);
        assert_eq!(report.retained[0].relative_path, ".");

        // Global tree intact.
        assert!(
            canary.exists(),
            "canary file under global_root must survive"
        );
        assert!(
            root.global_root().join("installs/legit@1.0.0").exists(),
            "legit install root must survive"
        );
    }

    /// `"installs"` (just the bare prefix) used to pass the
    /// `starts_with(global_root)` check too. `remove_dir_all` on it
    /// would remove every globally-installed package's root in one
    /// shot. Assert the prefix is refused and existing installs survive.
    #[test]
    fn sweep_refuses_bare_installs_prefix_and_does_not_wipe_installs_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        seed_install_root(&root, "installs/a@1.0.0");
        seed_install_root(&root, "installs/b@2.0.0");
        seed_manifest_with_tombstones(&root, &["installs"]);

        let report = sweep_tombstones(&root).unwrap();

        assert!(report.swept.is_empty(), "`installs` must NOT be swept");
        assert_eq!(report.retained.len(), 1);
        assert_eq!(report.retained[0].relative_path, "installs");

        // Both real install roots survive.
        assert!(root.global_root().join("installs/a@1.0.0").exists());
        assert!(root.global_root().join("installs/b@2.0.0").exists());
    }
}
