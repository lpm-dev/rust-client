//! Backup and rollback for migration files.
//!
//! Before overwriting any files (lpm.lock, .npmrc, etc.), we create `.backup`
//! copies. On failure, the caller can roll back to the original state.
//!
//! ## Manifest format
//!
//! After a successful migration, [`MigrationBackup::write_manifest`] persists
//! the backup state to `.lpm-migrate-manifest.json` in the project root so
//! `lpm migrate --rollback` can restore the pre-migration state later.
//!
//! The current format (`"version": 2`) records **project-relative POSIX
//! paths** for both backed-up and newly-created files, so files in nested
//! directories (e.g. `patches/react@18.0.0.patch`) round-trip correctly.
//!
//! Backwards compatibility:
//!
//! - **No-manifest fallback.** If no manifest is present at all, rollback
//!   falls back to scanning the project root for `.backup` files. This
//!   path is preserved so users with in-flight migrations from older LPM
//!   versions can still roll back after upgrading.
//! - **v1 manifests (basenames, no version field).** Read by the same
//!   scan-and-filter path used for the no-manifest fallback. v1 only ever
//!   stored basenames in the project root, so the scan path is sufficient.
//!
//! Only the v2 path is exercised by new migrations; v1 reads are best-effort.
//!
//! ## Path containment
//!
//! Manifest paths are validated before any filesystem operation:
//!
//! - rejected: absolute paths
//! - rejected: any path containing a `..` component
//! - rejected: paths that, after `canonicalize`, escape the project root
//!
//! The manifest is written by LPM itself, but defense-in-depth costs nothing
//! and protects against a malformed manifest from a third-party tool, a
//! corrupted on-disk write, or a partial manual edit.

use lpm_common::LpmError;
use std::path::{Component, Path, PathBuf};

/// Name of the manifest file written alongside backups.
const MANIFEST_FILENAME: &str = ".lpm-migrate-manifest.json";

/// Current manifest schema version.
const MANIFEST_VERSION: u32 = 2;

/// Tracks files that have been backed up during a migration.
#[derive(Debug)]
pub struct MigrationBackup {
    /// (original_path, backup_path, existed_before) tuples.
    backups: Vec<(PathBuf, PathBuf, bool)>,
}

impl MigrationBackup {
    /// Create a new empty backup tracker.
    pub fn new() -> Self {
        Self {
            backups: Vec::new(),
        }
    }

    /// Back up a file before modifying it.
    ///
    /// - If the file exists, copies it to `<path>.backup`.
    /// - If it doesn't exist, records that it was newly created (for removal on rollback).
    pub fn backup_file(&mut self, path: &Path) -> Result<(), LpmError> {
        let backup_path = {
            let mut name = path.as_os_str().to_os_string();
            name.push(".backup");
            PathBuf::from(name)
        };

        let existed = path.exists();

        if existed {
            std::fs::copy(path, &backup_path).map_err(|e| {
                LpmError::Script(format!("failed to backup {}: {e}", path.display()))
            })?;

            // Restrict backup permissions — backups may contain auth tokens
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&backup_path, std::fs::Permissions::from_mode(0o600));
            }
        }

        self.backups
            .push((path.to_path_buf(), backup_path, existed));
        Ok(())
    }

    /// Roll back all backed-up files to their original state.
    ///
    /// - If the file existed before, restores from the `.backup` copy.
    /// - If the file was newly created, removes it.
    ///
    /// This path does **not** clean up empty parent directories — that
    /// happens only in [`rollback_from_backups`] where we have an
    /// explicit project root to bound the walk. The immediate-failure
    /// path is rare (mid-migrate error), and a leftover empty `patches/`
    /// from a failed migration is harmless: the user's retry with
    /// `lpm migrate --force` will reuse the directory cleanly.
    pub fn rollback(&self) -> Result<(), LpmError> {
        for (original, backup, existed) in &self.backups {
            if *existed {
                // Restore from backup
                if backup.exists() {
                    std::fs::copy(backup, original).map_err(|e| {
                        LpmError::Script(format!(
                            "failed to restore {} from backup: {e}",
                            original.display()
                        ))
                    })?;
                }
            } else {
                // File was newly created — remove it
                if original.exists() {
                    std::fs::remove_file(original).map_err(|e| {
                        LpmError::Script(format!(
                            "failed to remove newly created {}: {e}",
                            original.display()
                        ))
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Write a manifest file listing all backed-up and newly created files.
    ///
    /// Used by `rollback_from_backups` to:
    /// - restore files that existed before from their `.backup` copies
    /// - remove files that were newly created by the migration
    ///
    /// Paths are written project-relative using POSIX separators so the
    /// manifest is portable across platforms.
    pub fn write_manifest(&self, project_dir: &Path) -> Result<(), LpmError> {
        let backup_entries: Vec<serde_json::Value> = self
            .backups
            .iter()
            .filter(|(_, _, existed)| *existed)
            .map(|(original, backup, _)| {
                let original_rel = relativize_to_posix(original, project_dir);
                let backup_rel = relativize_to_posix(backup, project_dir);
                serde_json::json!({
                    "original": original_rel,
                    "backup": backup_rel,
                })
            })
            .collect();

        let created_entries: Vec<serde_json::Value> = self
            .backups
            .iter()
            .filter(|(_, _, existed)| !*existed)
            .map(|(original, _, _)| serde_json::json!(relativize_to_posix(original, project_dir)))
            .collect();

        let manifest = serde_json::json!({
            "version": MANIFEST_VERSION,
            "backups": backup_entries,
            "created": created_entries,
        });
        let manifest_path = project_dir.join(MANIFEST_FILENAME);
        let contents = serde_json::to_string_pretty(&manifest)?;
        lpm_common::write_file_atomic_with_options(
            &manifest_path,
            contents,
            lpm_common::AtomicWriteOptions::new()
                .sync_file()
                .sync_parent(),
        )
        .map_err(|e| LpmError::Script(format!("failed to write backup manifest: {e}")))?;
        Ok(())
    }

    /// Clean up backup files and manifest after a successful migration.
    pub fn cleanup_backups(&self) -> Result<(), LpmError> {
        for (_, backup, _) in &self.backups {
            if backup.exists() {
                std::fs::remove_file(backup).map_err(|e| {
                    LpmError::Script(format!(
                        "failed to clean up backup {}: {e}",
                        backup.display()
                    ))
                })?;
            }
        }
        // Also remove manifest if any backup existed in a known directory
        if let Some((original, _, _)) = self.backups.first()
            && let Some(dir) = original.parent()
        {
            let manifest_path = dir.join(MANIFEST_FILENAME);
            if manifest_path.exists() {
                let _ = std::fs::remove_file(&manifest_path);
            }
        }
        Ok(())
    }
}

impl Default for MigrationBackup {
    fn default() -> Self {
        Self::new()
    }
}

/// Rollback from `.backup` files found in the project directory.
///
/// Reads `.lpm-migrate-manifest.json` if present and dispatches to the
/// matching format handler:
///
/// - **v2 manifest** (`"version": 2`): iterates manifest entries directly
///   to support nested paths like `patches/react@18.0.0.patch`. Validates
///   each path for containment before any filesystem operation. Removes
///   newly-created empty directories (e.g. `patches/`) on the way out.
/// - **v1 manifest or no `version` field**: legacy compatibility path —
///   scans the project root for `.backup` files and filters by the
///   manifest's `backups` array. Used for migrations created by older
///   LPM versions that only ever wrote basenames.
/// - **no manifest at all**: same scan-only behavior as the v1 path. Lets
///   anyone with stray `.backup` files on disk still roll back.
///
/// Returns the list of restored / removed paths (project-relative for
/// v2, basenames for v1) for the human summary.
pub fn rollback_from_backups(project_dir: &Path) -> Result<Vec<String>, LpmError> {
    let manifest_path = project_dir.join(MANIFEST_FILENAME);

    match lpm_common::read_text_file_capped(&manifest_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES) {
        Ok(content) => {
            let manifest: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| LpmError::Script(format!("failed to parse backup manifest: {e}")))?;

            let version = manifest
                .get("version")
                .and_then(|v| v.as_u64())
                .unwrap_or(1);

            if version == MANIFEST_VERSION as u64 {
                return rollback_v2(project_dir, &manifest, &manifest_path);
            }
            // Fall through to the legacy scan path for v1 (and any other
            // unknown version — best-effort recovery is preferable to
            // erroring out and stranding the user).
            return rollback_legacy_scan(project_dir, Some(&manifest), &manifest_path);
        }
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {}
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read backup manifest: {error}"
            )));
        }
    }

    rollback_legacy_scan(project_dir, None, &manifest_path)
}

/// v2 rollback: enumerate manifest entries, restore nested paths, clean
/// up empty created directories.
fn rollback_v2(
    project_dir: &Path,
    manifest: &serde_json::Value,
    manifest_path: &Path,
) -> Result<Vec<String>, LpmError> {
    let mut restored: Vec<String> = Vec::new();
    let mut removed_files: Vec<PathBuf> = Vec::new();

    // Restore from backup entries.
    if let Some(backups) = manifest.get("backups").and_then(|b| b.as_array()) {
        for entry in backups {
            let original = entry
                .get("original")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    LpmError::Script("backup manifest entry missing `original` field".into())
                })?;
            let backup = entry
                .get("backup")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    LpmError::Script("backup manifest entry missing `backup` field".into())
                })?;

            let original_path = resolve_manifest_path(project_dir, original)?;
            let backup_path = resolve_manifest_path(project_dir, backup)?;

            if !backup_path.exists() {
                // Skip silently — the backup file was already removed (e.g.,
                // user deleted .backup files manually after success). The
                // user might have intentionally accepted the new state.
                continue;
            }

            if let Some(parent) = original_path.parent()
                && !parent.exists()
            {
                std::fs::create_dir_all(parent).map_err(|e| {
                    LpmError::Script(format!(
                        "failed to create parent directory for {}: {e}",
                        original_path.display()
                    ))
                })?;
            }

            std::fs::copy(&backup_path, &original_path).map_err(|e| {
                LpmError::Script(format!(
                    "failed to restore {} from backup: {e}",
                    original_path.display()
                ))
            })?;

            std::fs::remove_file(&backup_path).map_err(|e| {
                LpmError::Script(format!(
                    "failed to remove backup {}: {e}",
                    backup_path.display()
                ))
            })?;

            restored.push(original.to_string());
        }
    }

    // Remove files that were newly created by the migration.
    if let Some(created) = manifest.get("created").and_then(|c| c.as_array()) {
        for entry in created {
            let Some(rel) = entry.as_str() else {
                continue;
            };
            let path = resolve_manifest_path(project_dir, rel)?;
            if path.exists() {
                if let Err(e) = std::fs::remove_file(&path) {
                    tracing::warn!("failed to remove created file {}: {e}", path.display());
                } else {
                    restored.push(format!("{rel} (removed)"));
                    removed_files.push(path);
                }
            }
        }
    }

    // Clean up empty parent directories that were created by
    // the migration. Walks up each removed file's parent chain stopping
    // at the project root. A non-empty directory is left alone so we
    // never delete user content.
    for path in &removed_files {
        cleanup_empty_ancestors(path, Some(project_dir));
    }

    if manifest_path.exists() {
        let _ = std::fs::remove_file(manifest_path);
    }

    Ok(restored)
}

/// Legacy rollback path: scans the project root for `.backup` files and
/// filters by the manifest if one exists. Preserved for v1 manifests and
/// for users without any manifest at all.
fn rollback_legacy_scan(
    project_dir: &Path,
    manifest: Option<&serde_json::Value>,
    manifest_path: &Path,
) -> Result<Vec<String>, LpmError> {
    let mut allowed_backups: Option<std::collections::HashSet<String>> = None;
    let mut created_files: Vec<String> = Vec::new();

    if let Some(m) = manifest {
        let set = m["backups"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|entry| entry["backup"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        allowed_backups = Some(set);

        if let Some(arr) = m["created"].as_array() {
            for entry in arr {
                if let Some(name) = entry.as_str() {
                    created_files.push(name.to_string());
                }
            }
        }
    }

    let mut restored = Vec::new();

    // Restore from .backup files in the project root.
    let entries = std::fs::read_dir(project_dir).map_err(|e| {
        LpmError::Script(format!(
            "failed to read directory {}: {e}",
            project_dir.display()
        ))
    })?;

    for entry in entries {
        let entry =
            entry.map_err(|e| LpmError::Script(format!("failed to read directory entry: {e}")))?;

        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if !file_name.ends_with(".backup") {
            continue;
        }

        // If manifest exists, only restore files listed in it.
        if let Some(ref allowed) = allowed_backups
            && !allowed.contains(&file_name)
        {
            continue;
        }

        let original_name = &file_name[..file_name.len() - ".backup".len()];
        let original_path = project_dir.join(original_name);

        std::fs::copy(&path, &original_path).map_err(|e| {
            LpmError::Script(format!(
                "failed to restore {} from backup: {e}",
                original_path.display()
            ))
        })?;

        std::fs::remove_file(&path).map_err(|e| {
            LpmError::Script(format!("failed to remove backup {}: {e}", path.display()))
        })?;

        restored.push(original_name.to_string());
    }

    // Remove files that were newly created by migration.
    for name in &created_files {
        let path = project_dir.join(name);
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!("failed to remove created file {}: {e}", path.display());
            } else {
                restored.push(format!("{name} (removed)"));
            }
        }
    }

    if manifest_path.exists() {
        let _ = std::fs::remove_file(manifest_path);
    }

    Ok(restored)
}

/// Resolve a project-relative path to an absolute path, rejecting
/// absolute inputs, `..` components, and any symlink that would take
/// the path outside the project root.
///
/// Containment is enforced by canonicalizing the **nearest existing
/// ancestor** of the resolved path and requiring it to stay inside the
/// canonicalized project root. Checking only the leaf (when it exists) is
/// not enough: if the leaf doesn't exist yet (the common case for a
/// restore target before rollback writes it) and an ancestor is a symlink
/// pointing outside the project (e.g. `patches/ -> /tmp/outside`), the
/// subsequent `create_dir_all` + `copy` would write through the symlink.
/// Walking up to an existing ancestor catches that vector regardless of
/// whether the leaf is present.
///
/// **Note on empty / directory inputs.** This function does NOT reject
/// `""` (empty resolves to the project root) or paths whose leaf is a
/// directory — both are valid for rollback-target use, where the caller
/// is operating on paths the system itself wrote. Consumers that need
/// stricter shapes (e.g. patch-source planning, where an empty value or
/// a directory is meaningless) should layer their own validation on
/// top before calling this helper.
pub fn resolve_manifest_path(project_dir: &Path, rel: &str) -> Result<PathBuf, LpmError> {
    let rel_path = Path::new(rel);

    if rel_path.is_absolute() {
        return Err(LpmError::Script(format!(
            "backup manifest entry rejected: absolute path `{rel}` is not allowed"
        )));
    }

    for component in rel_path.components() {
        match component {
            Component::ParentDir => {
                return Err(LpmError::Script(format!(
                    "backup manifest entry rejected: path `{rel}` contains a `..` component"
                )));
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(LpmError::Script(format!(
                    "backup manifest entry rejected: path `{rel}` is not project-relative"
                )));
            }
            _ => {}
        }
    }

    let joined = project_dir.join(rel_path);

    // Canonicalize the project root. Fail-closed if we can't — without a
    // resolved root we have nothing to check `starts_with` against.
    let canonical_root = project_dir.canonicalize().map_err(|e| {
        LpmError::Script(format!(
            "failed to canonicalize project root {}: {e}",
            project_dir.display()
        ))
    })?;

    // Find the nearest existing ancestor of `joined`. Walk upward until
    // we hit a path that exists — usually the leaf when restoring an
    // already-existing file, otherwise some directory up the chain.
    let probe = {
        let mut current: &Path = &joined;
        loop {
            if current.exists() {
                break current.to_path_buf();
            }
            match current.parent() {
                Some(p) => current = p,
                None => {
                    return Err(LpmError::Script(format!(
                        "backup manifest entry rejected: no existing ancestor for `{rel}`"
                    )));
                }
            }
        }
    };

    let canonical_probe = probe.canonicalize().map_err(|e| {
        LpmError::Script(format!(
            "backup manifest entry rejected: failed to canonicalize `{}`: {e}",
            probe.display()
        ))
    })?;

    if !canonical_probe.starts_with(&canonical_root) {
        return Err(LpmError::Script(format!(
            "backup manifest entry rejected: `{rel}` resolves outside the project root"
        )));
    }

    Ok(joined)
}

/// Convert an absolute path to a project-relative POSIX string for the
/// manifest. Falls back to `path.display()` if the path can't be made
/// relative — that's a programmer error (we should never back up a file
/// outside the project root) but we don't want a panic in the rollback
/// path.
fn relativize_to_posix(path: &Path, project_dir: &Path) -> String {
    let rel = path
        .strip_prefix(project_dir)
        .map_or_else(|_| path.to_path_buf(), |p| p.to_path_buf());

    rel.components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str().map(String::from),
            Component::CurDir => None,
            // ParentDir / Prefix / RootDir shouldn't appear after a clean
            // strip_prefix, but if they do we render them best-effort.
            other => Some(format!("{}", other.as_os_str().to_string_lossy())),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Walk up the parent chain of `path` and remove empty directories until
/// hitting `boundary` (exclusive) or a non-empty directory. Best-effort —
/// silently skips directories that fail to remove (typically because
/// they're not empty, which is the expected case for shared dirs).
fn cleanup_empty_ancestors(path: &Path, boundary: Option<&Path>) {
    let mut current = path.parent();
    while let Some(dir) = current {
        if let Some(b) = boundary
            && dir == b
        {
            break;
        }
        match std::fs::remove_dir(dir) {
            Ok(_) => current = dir.parent(),
            Err(_) => break, // not empty, or permission denied — stop walking
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn backup_and_rollback_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("lpm.lock");

        // Create original file
        fs::write(&file_path, "original content").unwrap();

        // Back it up
        let mut backup = MigrationBackup::new();
        backup.backup_file(&file_path).unwrap();

        // Modify the file
        fs::write(&file_path, "modified content").unwrap();
        assert_eq!(fs::read_to_string(&file_path).unwrap(), "modified content");

        // Rollback
        backup.rollback().unwrap();
        assert_eq!(fs::read_to_string(&file_path).unwrap(), "original content");
    }

    #[test]
    fn nonexistent_file_rollback_removes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("lpm.lock");

        // File doesn't exist yet
        assert!(!file_path.exists());

        // Back it up (records that it didn't exist)
        let mut backup = MigrationBackup::new();
        backup.backup_file(&file_path).unwrap();

        // Create the file (simulating migration writing it)
        fs::write(&file_path, "new content").unwrap();
        assert!(file_path.exists());

        // Rollback should remove it
        backup.rollback().unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn cleanup_removes_backup_files() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("lpm.lock");

        fs::write(&file_path, "content").unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&file_path).unwrap();

        // Backup file should exist
        let backup_path = dir.path().join("lpm.lock.backup");
        assert!(backup_path.exists());

        // Clean up
        backup.cleanup_backups().unwrap();
        assert!(!backup_path.exists());
    }

    // Extensionless dotfiles backup path
    #[test]
    fn backup_path_dotfile_without_extension() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc = dir.path().join(".npmrc");
        fs::write(&npmrc, "token=secret").unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&npmrc).unwrap();

        // Must be .npmrc.backup, NOT .npmrc.file.backup
        let expected_backup = dir.path().join(".npmrc.backup");
        assert!(expected_backup.exists(), "expected .npmrc.backup to exist");

        // Roundtrip: rollback must restore to .npmrc
        fs::write(&npmrc, "modified").unwrap();
        backup.rollback().unwrap();
        assert_eq!(fs::read_to_string(&npmrc).unwrap(), "token=secret");
    }

    #[test]
    fn backup_path_regular_extension() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("package-lock.json");
        fs::write(&lock, "{}").unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&lock).unwrap();

        let expected = dir.path().join("package-lock.json.backup");
        assert!(expected.exists(), "expected package-lock.json.backup");
    }

    #[test]
    fn rollback_from_backups_dotfile() {
        let dir = tempfile::tempdir().unwrap();
        let backup_path = dir.path().join(".npmrc.backup");
        fs::write(&backup_path, "original").unwrap();
        let npmrc = dir.path().join(".npmrc");
        fs::write(&npmrc, "modified").unwrap();

        let restored = rollback_from_backups(dir.path()).unwrap();
        assert!(restored.contains(&".npmrc".to_string()));
        assert_eq!(fs::read_to_string(&npmrc).unwrap(), "original");
    }

    // Backup permissions
    #[cfg(unix)]
    #[test]
    fn backup_file_permissions_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let npmrc = dir.path().join(".npmrc");
        fs::write(&npmrc, "token=secret").unwrap();
        // Make it world-readable
        fs::set_permissions(&npmrc, fs::Permissions::from_mode(0o644)).unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&npmrc).unwrap();

        let backup_path = dir.path().join(".npmrc.backup");
        let mode = fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "backup should be owner-only (0600), got {:o}",
            mode
        );
    }

    // Manifest-based rollback
    #[test]
    fn rollback_from_backups_only_restores_manifested_files() {
        let dir = tempfile::tempdir().unwrap();

        // Create two backup files
        fs::write(dir.path().join(".npmrc.backup"), "real backup").unwrap();
        fs::write(dir.path().join("rogue.txt.backup"), "injected").unwrap();

        // Write v1-shape manifest (no `version` field) listing only .npmrc.
        // Older LPM versions wrote this shape; the legacy scan path must
        // still honor it after the v2 upgrade.
        let manifest = serde_json::json!({
            "backups": [
                {"original": ".npmrc", "backup": ".npmrc.backup"}
            ]
        });
        fs::write(
            dir.path().join(".lpm-migrate-manifest.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        // Create target files
        fs::write(dir.path().join(".npmrc"), "modified").unwrap();
        fs::write(dir.path().join("rogue.txt"), "should stay").unwrap();

        let restored = rollback_from_backups(dir.path()).unwrap();

        // Only .npmrc should be restored
        assert!(restored.contains(&".npmrc".to_string()));
        assert!(!restored.contains(&"rogue.txt".to_string()));
        assert_eq!(
            fs::read_to_string(dir.path().join(".npmrc")).unwrap(),
            "real backup"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("rogue.txt")).unwrap(),
            "should stay"
        );
        // rogue backup should still exist (not cleaned up)
        assert!(dir.path().join("rogue.txt.backup").exists());
    }

    #[test]
    fn rollback_from_backups_restores() {
        let dir = tempfile::tempdir().unwrap();

        // Create a backup file
        let backup_path = dir.path().join("lpm.lock.backup");
        fs::write(&backup_path, "original lockfile").unwrap();

        // Create the current file (modified version)
        let file_path = dir.path().join("lpm.lock");
        fs::write(&file_path, "migrated lockfile").unwrap();

        // Rollback from backups
        let restored = rollback_from_backups(dir.path()).unwrap();

        assert!(restored.contains(&"lpm.lock".to_string()));
        assert_eq!(fs::read_to_string(&file_path).unwrap(), "original lockfile");
        assert!(!backup_path.exists()); // Backup should be removed
    }

    #[test]
    fn rollback_from_backups_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let restored = rollback_from_backups(dir.path()).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn backup_multiple_files() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("lpm.lock");
        let npmrc_path = dir.path().join(".npmrc");

        fs::write(&lock_path, "old lock").unwrap();
        fs::write(&npmrc_path, "old npmrc").unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&lock_path).unwrap();
        backup.backup_file(&npmrc_path).unwrap();

        fs::write(&lock_path, "new lock").unwrap();
        fs::write(&npmrc_path, "new npmrc").unwrap();

        backup.rollback().unwrap();

        assert_eq!(fs::read_to_string(&lock_path).unwrap(), "old lock");
        assert_eq!(fs::read_to_string(&npmrc_path).unwrap(), "old npmrc");
    }

    #[test]
    fn write_manifest_replaces_existing_file_without_mutating_other_hardlinks() {
        let dir = tempfile::tempdir().unwrap();
        let first_created = dir.path().join("first-created");
        let second_created = dir.path().join("second-created");
        let manifest_path = dir.path().join(MANIFEST_FILENAME);
        let prior_manifest_link = dir.path().join("prior-manifest.json");

        let mut backup = MigrationBackup::new();
        backup.backup_file(&first_created).unwrap();
        backup.write_manifest(dir.path()).unwrap();
        fs::hard_link(&manifest_path, &prior_manifest_link).unwrap();
        let prior_manifest = fs::read(&prior_manifest_link).unwrap();

        backup.backup_file(&second_created).unwrap();
        backup.write_manifest(dir.path()).unwrap();

        assert_eq!(fs::read(&prior_manifest_link).unwrap(), prior_manifest);
    }

    #[test]
    fn rollback_post_success_removes_newly_created_files() {
        // Simulates: migrate creates lpm.lock (new) and backs up .npmrc (existed).
        // After success, backups persist. `--rollback` should:
        // - restore .npmrc from backup
        // - remove the newly created lpm.lock
        let dir = tempfile::tempdir().unwrap();

        // .npmrc existed before migration
        fs::write(dir.path().join(".npmrc"), "original npmrc").unwrap();

        // Simulate migration: backup .npmrc, backup lpm.lock (doesn't exist yet)
        let mut backup = MigrationBackup::new();
        backup.backup_file(&dir.path().join(".npmrc")).unwrap();
        backup.backup_file(&dir.path().join("lpm.lock")).unwrap(); // records as "did not exist"

        // Migration writes new files
        fs::write(dir.path().join(".npmrc"), "modified with @lpm.dev scope").unwrap();
        fs::write(dir.path().join("lpm.lock"), "migrated lockfile content").unwrap();

        // Write manifest (like migrate.rs does after success)
        backup.write_manifest(dir.path()).unwrap();

        // Verify manifest contains both categories
        let manifest_content =
            fs::read_to_string(dir.path().join(".lpm-migrate-manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();
        assert_eq!(manifest["version"], 2);
        assert!(
            !manifest["backups"].as_array().unwrap().is_empty(),
            "should have backup entries"
        );
        assert!(
            !manifest["created"].as_array().unwrap().is_empty(),
            "should have created entries"
        );

        // Now simulate `lpm migrate --rollback`
        let restored = rollback_from_backups(dir.path()).unwrap();

        // .npmrc should be restored from backup
        assert!(
            restored.iter().any(|r| r == ".npmrc"),
            "should restore .npmrc, got: {:?}",
            restored
        );
        assert_eq!(
            fs::read_to_string(dir.path().join(".npmrc")).unwrap(),
            "original npmrc"
        );

        // lpm.lock should be removed (it was newly created)
        assert!(
            restored.iter().any(|r| r.contains("lpm.lock")),
            "should remove lpm.lock, got: {:?}",
            restored
        );
        assert!(
            !dir.path().join("lpm.lock").exists(),
            "lpm.lock should have been removed"
        );

        // Manifest should be cleaned up
        assert!(
            !dir.path().join(".lpm-migrate-manifest.json").exists(),
            "manifest should be removed after rollback"
        );
    }

    #[test]
    fn rollback_post_success_with_no_newly_created_files() {
        // When all files existed before (e.g., --force overwrite), no "created" entries
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join("lpm.lock"), "old lockfile").unwrap();
        fs::write(dir.path().join(".npmrc"), "old npmrc").unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&dir.path().join("lpm.lock")).unwrap();
        backup.backup_file(&dir.path().join(".npmrc")).unwrap();

        // Overwrite both
        fs::write(dir.path().join("lpm.lock"), "new lockfile").unwrap();
        fs::write(dir.path().join(".npmrc"), "new npmrc").unwrap();

        backup.write_manifest(dir.path()).unwrap();

        let restored = rollback_from_backups(dir.path()).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(
            fs::read_to_string(dir.path().join("lpm.lock")).unwrap(),
            "old lockfile"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join(".npmrc")).unwrap(),
            "old npmrc"
        );
    }

    // ── v2 manifest: nested-path round-trip ────────────────────────────

    #[test]
    fn v2_manifest_writes_project_relative_posix_paths() {
        // The on-disk manifest must record project-relative POSIX paths,
        // not absolute paths or platform-specific separators. Pinning the
        // wire format directly so cross-platform manifests stay portable.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("patches")).unwrap();
        let nested = dir.path().join("patches").join("react@18.0.0.patch");
        fs::write(&nested, "diff --git a/x b/y").unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&nested).unwrap();
        backup.write_manifest(dir.path()).unwrap();

        let raw = fs::read_to_string(dir.path().join(".lpm-migrate-manifest.json")).unwrap();
        let m: serde_json::Value = serde_json::from_str(&raw).unwrap();

        assert_eq!(m["version"], 2);
        assert_eq!(
            m["backups"][0]["original"], "patches/react@18.0.0.patch",
            "original must be project-relative POSIX"
        );
        assert_eq!(
            m["backups"][0]["backup"], "patches/react@18.0.0.patch.backup",
            "backup must be project-relative POSIX"
        );
    }

    #[test]
    fn v2_rollback_restores_nested_existing_file() {
        // A patch file under patches/ that existed before migration, was
        // modified by migrate, and must be restored on rollback.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("patches")).unwrap();
        let nested = dir.path().join("patches").join("react@18.0.0.patch");
        fs::write(&nested, "original patch content").unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&nested).unwrap();
        backup.write_manifest(dir.path()).unwrap();

        // Migrate "modifies" the patch.
        fs::write(&nested, "migrated patch content").unwrap();

        let restored = rollback_from_backups(dir.path()).unwrap();
        assert!(
            restored.iter().any(|r| r == "patches/react@18.0.0.patch"),
            "expected nested path in restored list, got: {:?}",
            restored
        );
        assert_eq!(
            fs::read_to_string(&nested).unwrap(),
            "original patch content"
        );
    }

    #[test]
    fn v2_rollback_removes_nested_created_file_and_empty_parent() {
        // The migrate-creates-from-nothing case: project had no patches/
        // dir, migration created `patches/foo.patch`. Rollback must
        // remove the file AND clean up the now-empty `patches/` dir.
        let dir = tempfile::tempdir().unwrap();
        let patches_dir = dir.path().join("patches");
        let nested = patches_dir.join("foo@1.0.0.patch");

        // Sanity: neither exists pre-migration.
        assert!(!patches_dir.exists());

        let mut backup = MigrationBackup::new();
        backup.backup_file(&nested).unwrap(); // records existed=false

        // Migrate writes the file (and creates the dir).
        fs::create_dir_all(&patches_dir).unwrap();
        fs::write(&nested, "patch body").unwrap();

        backup.write_manifest(dir.path()).unwrap();

        let restored = rollback_from_backups(dir.path()).unwrap();

        assert!(
            restored
                .iter()
                .any(|r| r.contains("patches/foo@1.0.0.patch")),
            "expected nested created path in restored list, got: {:?}",
            restored
        );
        assert!(!nested.exists(), "nested file should have been removed");
        assert!(
            !patches_dir.exists(),
            "empty patches/ directory should have been cleaned up"
        );
    }

    #[test]
    fn v2_rollback_keeps_non_empty_directory_with_user_content() {
        // Migration created `patches/migrated.patch` BUT the user also
        // had their own `patches/manual.patch` from before. Rollback
        // must remove only the migrated file and leave the directory
        // (because the user file is still in it).
        let dir = tempfile::tempdir().unwrap();
        let patches_dir = dir.path().join("patches");
        fs::create_dir_all(&patches_dir).unwrap();
        let user_file = patches_dir.join("manual.patch");
        fs::write(&user_file, "user-authored").unwrap();

        let migrated = patches_dir.join("auto.patch");

        let mut backup = MigrationBackup::new();
        backup.backup_file(&migrated).unwrap(); // existed=false
        fs::write(&migrated, "auto body").unwrap();

        backup.write_manifest(dir.path()).unwrap();

        let _ = rollback_from_backups(dir.path()).unwrap();

        assert!(!migrated.exists(), "migrated file should be removed");
        assert!(user_file.exists(), "user file must survive rollback");
        assert!(
            patches_dir.exists(),
            "patches/ must survive — it has user content"
        );
        assert_eq!(fs::read_to_string(&user_file).unwrap(), "user-authored");
    }

    #[test]
    fn v2_rollback_restores_nested_existing_after_modification_chain() {
        // Mixed: one root file (.npmrc, existed), one nested file
        // (patches/x.patch, existed). Both modified by migrate. Rollback
        // restores both correctly.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".npmrc"), "orig npmrc").unwrap();
        fs::create_dir_all(dir.path().join("patches")).unwrap();
        let patch = dir.path().join("patches").join("x.patch");
        fs::write(&patch, "orig patch").unwrap();

        let mut backup = MigrationBackup::new();
        backup.backup_file(&dir.path().join(".npmrc")).unwrap();
        backup.backup_file(&patch).unwrap();

        fs::write(dir.path().join(".npmrc"), "new npmrc").unwrap();
        fs::write(&patch, "new patch").unwrap();

        backup.write_manifest(dir.path()).unwrap();

        let restored = rollback_from_backups(dir.path()).unwrap();
        assert!(restored.iter().any(|r| r == ".npmrc"));
        assert!(restored.iter().any(|r| r == "patches/x.patch"));
        assert_eq!(
            fs::read_to_string(dir.path().join(".npmrc")).unwrap(),
            "orig npmrc"
        );
        assert_eq!(fs::read_to_string(&patch).unwrap(), "orig patch");
    }

    // ── Path containment ───────────────────────────────────────────────

    #[test]
    fn v2_rollback_rejects_absolute_path_in_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "version": 2,
            "backups": [
                {"original": "/etc/passwd", "backup": "/etc/passwd.backup"}
            ],
            "created": [],
        });
        fs::write(
            dir.path().join(".lpm-migrate-manifest.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        let err = rollback_from_backups(dir.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("absolute path"),
            "expected absolute-path error, got: {msg}"
        );
    }

    #[test]
    fn v2_rollback_rejects_parent_dir_in_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "version": 2,
            "backups": [],
            "created": ["../escape.txt"],
        });
        fs::write(
            dir.path().join(".lpm-migrate-manifest.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        let err = rollback_from_backups(dir.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("`..`"),
            "expected parent-dir error, got: {msg}"
        );
    }

    #[test]
    fn v2_rollback_rejects_parent_dir_mid_path() {
        // An attacker might bury `..` mid-path expecting only leading
        // segments to be checked. Component iteration catches it.
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "version": 2,
            "backups": [
                {"original": "patches/../../../etc/passwd",
                 "backup": "patches/x.backup"}
            ],
            "created": [],
        });
        fs::write(
            dir.path().join(".lpm-migrate-manifest.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        let err = rollback_from_backups(dir.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("`..`"),
            "expected parent-dir error, got: {msg}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn v2_rollback_rejects_symlinked_ancestor_for_nonexistent_leaf() {
        // Without canonicalizing the nearest existing ancestor, a manifest
        // restore target like `patches/foo.patch` would silently write
        // outside the project root when `patches/` is a symlink to an
        // external directory and the leaf doesn't exist yet.
        //
        // The component-level `..` check doesn't catch this because the
        // path string contains no `..` — the escape hops through a
        // symlink. The leaf-only `joined.exists()` canonicalize is also
        // not enough because the restore target is intentionally absent
        // when rollback is about to write it.
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        // patches -> outside (symlink)
        std::os::unix::fs::symlink(outside.path(), project.path().join("patches")).unwrap();

        // Pre-create a `.backup` file the manifest will reference.
        // Place it inside the project root (legitimate location); the
        // attack vector is the RESTORE TARGET via the symlinked ancestor.
        fs::write(project.path().join("loot.backup"), "stolen content").unwrap();

        let manifest = serde_json::json!({
            "version": 2,
            "backups": [
                {
                    "original": "patches/restored.patch",
                    "backup": "loot.backup",
                }
            ],
            "created": [],
        });
        fs::write(
            project.path().join(".lpm-migrate-manifest.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        let err = rollback_from_backups(project.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("outside the project root"),
            "expected containment error for symlinked ancestor, got: {msg}"
        );

        // The outside dir must remain untouched — no file was written there.
        let outside_entries: Vec<_> = fs::read_dir(outside.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            outside_entries.is_empty(),
            "rollback must not write through the symlinked ancestor; \
             found in outside dir: {:?}",
            outside_entries
                .iter()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );
    }

    // ── Immediate-failure rollback (MigrationBackup::rollback) ──────────

    #[test]
    fn immediate_rollback_removes_nested_created_file() {
        // The immediate-failure path doesn't clean up empty parent dirs
        // (see doc on `rollback`), but it MUST still remove a nested
        // file that the migration created mid-flow before the error.
        let dir = tempfile::tempdir().unwrap();
        let patches_dir = dir.path().join("patches");
        let nested = patches_dir.join("react@18.0.0.patch");

        let mut backup = MigrationBackup::new();
        backup.backup_file(&nested).unwrap(); // existed=false

        // Simulate migration creating both before erroring out.
        fs::create_dir_all(&patches_dir).unwrap();
        fs::write(&nested, "partial migration").unwrap();

        backup.rollback().unwrap();

        assert!(!nested.exists(), "nested created file must be removed");
        // patches_dir may or may not exist — immediate path doesn't
        // promise dir cleanup. The post-success path (`rollback_from_backups`)
        // is the one that owns that responsibility.
    }
}
