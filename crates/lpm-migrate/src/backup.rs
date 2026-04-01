//! Backup and rollback for migration files.
//!
//! Before overwriting any files (lpm.lock, .npmrc, etc.), we create `.backup`
//! copies. On failure, the caller can roll back to the original state.

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Name of the manifest file written alongside backups.
const MANIFEST_FILENAME: &str = ".lpm-migrate-manifest.json";

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

    /// Write a manifest file listing all backed-up files.
    ///
    /// Used by `rollback_from_backups` to avoid blindly restoring any `.backup` file.
    pub fn write_manifest(&self, project_dir: &Path) -> Result<(), LpmError> {
        let entries: Vec<serde_json::Value> = self
            .backups
            .iter()
            .filter(|(_, _, existed)| *existed)
            .map(|(original, backup, _)| {
                let original_name = original
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                let backup_name = backup
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                serde_json::json!({
                    "original": original_name,
                    "backup": backup_name,
                })
            })
            .collect();

        let manifest = serde_json::json!({ "backups": entries });
        let manifest_path = project_dir.join(MANIFEST_FILENAME);
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
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
/// Uses the manifest file (`.lpm-migrate-manifest.json`) to determine which
/// files to restore. Only files listed in the manifest are restored — this
/// prevents rogue `.backup` files from being blindly picked up.
///
/// Falls back to scanning for `.backup` files if no manifest exists (for
/// backwards compatibility with backups created before the manifest was added).
pub fn rollback_from_backups(project_dir: &Path) -> Result<Vec<String>, LpmError> {
    let manifest_path = project_dir.join(MANIFEST_FILENAME);

    let allowed_backups: Option<std::collections::HashSet<String>> = if manifest_path.exists() {
        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| LpmError::Script(format!("failed to read backup manifest: {e}")))?;
        let manifest: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| LpmError::Script(format!("failed to parse backup manifest: {e}")))?;
        let set = manifest["backups"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|entry| entry["backup"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Some(set)
    } else {
        None
    };

    let mut restored = Vec::new();

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

        // If manifest exists, only restore files listed in it
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

    // Clean up manifest file
    if manifest_path.exists() {
        let _ = std::fs::remove_file(&manifest_path);
    }

    Ok(restored)
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

    // Finding #2: extensionless dotfiles backup path
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

    // Finding #3: backup permissions
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

    // Finding #7: manifest-based rollback
    #[test]
    fn rollback_from_backups_only_restores_manifested_files() {
        let dir = tempfile::tempdir().unwrap();

        // Create two backup files
        fs::write(dir.path().join(".npmrc.backup"), "real backup").unwrap();
        fs::write(dir.path().join("rogue.txt.backup"), "injected").unwrap();

        // Write manifest listing only .npmrc
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
}
