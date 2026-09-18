//! Persistent migration snapshots and rollback within a project boundary.

mod files;

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

const MANIFEST_FILENAME: &str = ".lpm-migrate-manifest.json";
const MANIFEST_VERSION: u32 = 2;

#[derive(Debug, Deserialize, Serialize)]
struct BackupEntry {
    original: String,
    backup: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    #[serde(default = "legacy_version")]
    version: u32,
    #[serde(default)]
    backups: Vec<BackupEntry>,
    #[serde(default)]
    created: Vec<String>,
}

fn legacy_version() -> u32 {
    1
}

/// Tracks original files across migration retries until rollback or cleanup.
#[derive(Debug, Default)]
pub struct MigrationBackup {
    backups: Vec<(PathBuf, PathBuf, bool)>,
    project_dir: Option<PathBuf>,
    tracked: HashSet<PathBuf>,
}

impl MigrationBackup {
    /// Create an empty tracker. Use `for_project` to resume persistent snapshots.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load and validate the original snapshots from an earlier migration.
    pub fn for_project(project_dir: &Path) -> Result<Self, LpmError> {
        let mut tracker = Self {
            backups: Vec::new(),
            project_dir: Some(project_dir.to_path_buf()),
            tracked: HashSet::new(),
        };
        if let Some(manifest) = read_manifest(project_dir)? {
            let entries = manifest_entries(project_dir, manifest)?;
            validate_entries(project_dir, &entries)?;
            tracker.tracked = entries.iter().map(|(path, _, _)| path.clone()).collect();
            tracker.backups = entries;
        }
        Ok(tracker)
    }

    /// Preserve a file once, or record its absence before the first write.
    pub fn backup_file(&mut self, path: &Path) -> Result<(), LpmError> {
        let root = self.project_dir.as_deref().unwrap_or_else(|| {
            path.ancestors()
                .skip(1)
                .find(|ancestor| ancestor.is_dir())
                .unwrap_or(Path::new("."))
        });
        files::validate(root, path)?;
        if self.tracked.contains(path) {
            return Ok(());
        }
        let backup = backup_path(path);
        files::validate(root, &backup)?;
        if files::exists(root, &backup)? {
            return Err(LpmError::Script(format!(
                "refusing to replace an untracked backup {}; restore or move it before migration",
                backup.display()
            )));
        }
        let existed = files::exists(root, path)?;
        if existed {
            files::create_backup(root, path, &backup)?;
        }
        self.tracked.insert(path.to_path_buf());
        self.backups.push((path.to_path_buf(), backup, existed));
        Ok(())
    }

    /// Validate a batch before taking snapshots and persist its inventory before writes.
    pub fn backup_files(&mut self, project_dir: &Path, paths: &[&Path]) -> Result<(), LpmError> {
        for path in paths {
            files::validate(project_dir, path)?;
            if !self.tracked.contains(*path) {
                let backup = backup_path(path);
                if files::exists(project_dir, &backup)? {
                    return Err(LpmError::Script(format!(
                        "refusing to replace an untracked backup {}; restore or move it before migration",
                        backup.display()
                    )));
                }
            }
        }
        for path in paths {
            if let Err(error) = self.backup_file(path) {
                self.write_manifest(project_dir)?;
                return Err(error);
            }
        }
        self.write_manifest(project_dir)
    }

    /// Restore snapshots without deleting recovery state, so a failed rollback can be retried.
    pub fn rollback(&self) -> Result<(), LpmError> {
        let plans = self
            .backups
            .iter()
            .map(|(original, backup, existed)| {
                let root = self
                    .project_dir
                    .as_deref()
                    .unwrap_or_else(|| original.parent().unwrap_or(Path::new(".")));
                files::Restore::prepare(root, original, backup, *existed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for mut plan in plans {
            plan.apply()?;
        }
        Ok(())
    }

    /// Persist the original snapshot inventory before a managed file changes.
    pub fn write_manifest(&self, project_dir: &Path) -> Result<(), LpmError> {
        let mut manifest = Manifest {
            version: MANIFEST_VERSION,
            backups: Vec::new(),
            created: Vec::new(),
        };
        for (original, backup, existed) in &self.backups {
            let original = files::relative(project_dir, original)?
                .to_string_lossy()
                .replace('\\', "/");
            if *existed {
                manifest.backups.push(BackupEntry {
                    original,
                    backup: files::relative(project_dir, backup)?
                        .to_string_lossy()
                        .replace('\\', "/"),
                });
            } else {
                manifest.created.push(original);
            }
        }
        files::write(
            project_dir,
            &project_dir.join(MANIFEST_FILENAME),
            &serde_json::to_vec_pretty(&manifest)?,
        )
    }

    /// Remove snapshots after the caller accepts the migration.
    pub fn cleanup_backups(&self) -> Result<(), LpmError> {
        for (original, backup, existed) in &self.backups {
            if *existed {
                let root = self
                    .project_dir
                    .as_deref()
                    .unwrap_or_else(|| original.parent().unwrap_or(Path::new(".")));
                files::remove(root, backup)?;
            }
        }
        let root = self
            .project_dir
            .as_deref()
            .or_else(|| self.backups.first().and_then(|(path, _, _)| path.parent()));
        if let Some(root) = root {
            files::remove(root, &root.join(MANIFEST_FILENAME))?;
        }
        Ok(())
    }
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".backup");
    PathBuf::from(name)
}

fn read_manifest(project_dir: &Path) -> Result<Option<Manifest>, LpmError> {
    let path = project_dir.join(MANIFEST_FILENAME);
    let Some(contents) = files::read(project_dir, &path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)?
    else {
        return Ok(None);
    };
    let manifest: Manifest = serde_json::from_slice(&contents)
        .map_err(|error| LpmError::Script(format!("failed to parse backup manifest: {error}")))?;
    if !matches!(manifest.version, 1 | MANIFEST_VERSION) {
        return Err(LpmError::Script(format!(
            "unsupported backup manifest version {}",
            manifest.version
        )));
    }
    Ok(Some(manifest))
}

fn manifest_entries(
    project_dir: &Path,
    manifest: Manifest,
) -> Result<Vec<(PathBuf, PathBuf, bool)>, LpmError> {
    let mut entries = Vec::with_capacity(manifest.backups.len() + manifest.created.len());
    let mut paths = HashSet::with_capacity(entries.capacity() * 2);
    for entry in manifest.backups {
        let original = resolve_manifest_path(project_dir, &entry.original)?;
        let backup = resolve_manifest_path(project_dir, &entry.backup)?;
        if !entry.backup.ends_with(".backup")
            || !paths.insert(original.clone())
            || !paths.insert(backup.clone())
        {
            return Err(LpmError::Script(
                "conflicting or invalid backup manifest paths".into(),
            ));
        }
        entries.push((original, backup, true));
    }
    for entry in manifest.created {
        let path = resolve_manifest_path(project_dir, &entry)?;
        if !paths.insert(path.clone()) {
            return Err(LpmError::Script("duplicate backup manifest path".into()));
        }
        entries.push((path.clone(), backup_path(&path), false));
    }
    for path in paths {
        let rel = files::relative(project_dir, &path)?;
        if rel == Path::new(MANIFEST_FILENAME) || rel.starts_with(".git") {
            return Err(LpmError::Script(
                "backup manifest targets reserved project state".into(),
            ));
        }
    }
    Ok(entries)
}

fn validate_entries(
    project_dir: &Path,
    entries: &[(PathBuf, PathBuf, bool)],
) -> Result<(), LpmError> {
    for (original, backup, existed) in entries {
        files::Restore::prepare(project_dir, original, backup, *existed)?;
    }
    Ok(())
}

/// Restore every validated snapshot, then remove backups and recovery state.
/// Legacy manifests and root-level backup files use the same containment checks.
pub fn rollback_from_backups(project_dir: &Path) -> Result<Vec<String>, LpmError> {
    let manifest = match read_manifest(project_dir)? {
        Some(manifest) => manifest,
        None => {
            let mut manifest = Manifest {
                version: MANIFEST_VERSION,
                backups: Vec::new(),
                created: Vec::new(),
            };
            for entry in std::fs::read_dir(project_dir)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if let Some(original) = name.strip_suffix(".backup") {
                    manifest.backups.push(BackupEntry {
                        original: original.to_owned(),
                        backup: name,
                    });
                }
            }
            manifest
        }
    };
    let entries = manifest_entries(project_dir, manifest)?;
    let mut plans = entries
        .iter()
        .map(|(original, backup, existed)| {
            files::Restore::prepare(project_dir, original, backup, *existed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut restored = Vec::with_capacity(plans.len());
    for ((original, _, existed), plan) in entries.iter().zip(&mut plans) {
        if plan.apply()? {
            let name = relativize_to_posix(original, project_dir);
            restored.push(if *existed {
                name
            } else {
                format!("{name} (removed)")
            });
        }
    }
    for (original, backup, existed) in &entries {
        if *existed {
            files::remove(project_dir, backup)?;
        } else {
            files::cleanup_empty_parents(project_dir, original)?;
        }
    }
    files::remove(project_dir, &project_dir.join(MANIFEST_FILENAME))?;
    Ok(restored)
}

/// Reject linked ancestors and non-regular destinations before migration writes.
pub fn validate_output_path(project_dir: &Path, path: &Path) -> Result<(), LpmError> {
    files::validate(project_dir, path)
}

/// Write a managed migration file without following project links.
pub fn write_output(project_dir: &Path, path: &Path, contents: &[u8]) -> Result<(), LpmError> {
    files::write(project_dir, path, contents)
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
