//! Backup and rollback for migration files.
//!
//! Before overwriting any files (lpm.lock, .npmrc, etc.), we create `.backup`
//! copies. On failure, the caller can roll back to the original state.

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

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
        let backup_path = path.with_extension(format!(
            "{}.backup",
            path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("file")
        ));

        let existed = path.exists();

        if existed {
            std::fs::copy(path, &backup_path).map_err(|e| {
                LpmError::Script(format!(
                    "failed to backup {}: {e}",
                    path.display()
                ))
            })?;
        }

        self.backups.push((path.to_path_buf(), backup_path, existed));
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

    /// Clean up backup files after a successful migration.
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
/// Used by `lpm migrate --rollback` to restore previous state without
/// needing the in-memory `MigrationBackup` tracker.
pub fn rollback_from_backups(project_dir: &Path) -> Result<Vec<String>, LpmError> {
    let mut restored = Vec::new();

    let entries = std::fs::read_dir(project_dir).map_err(|e| {
        LpmError::Script(format!(
            "failed to read directory {}: {e}",
            project_dir.display()
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            LpmError::Script(format!("failed to read directory entry: {e}"))
        })?;

        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if file_name.ends_with(".backup") {
            // Determine the original filename by removing ".backup" suffix
            let original_name = &file_name[..file_name.len() - ".backup".len()];
            let original_path = project_dir.join(original_name);

            std::fs::copy(&path, &original_path).map_err(|e| {
                LpmError::Script(format!(
                    "failed to restore {} from backup: {e}",
                    original_path.display()
                ))
            })?;

            std::fs::remove_file(&path).map_err(|e| {
                LpmError::Script(format!(
                    "failed to remove backup {}: {e}",
                    path.display()
                ))
            })?;

            restored.push(original_name.to_string());
        }
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
        let backup_path = file_path.with_extension("lock.backup");
        assert!(backup_path.exists());

        // Clean up
        backup.cleanup_backups().unwrap();
        assert!(!backup_path.exists());
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
