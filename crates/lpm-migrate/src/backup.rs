//! Migration snapshots in `<project>/.lpm/migrate-backup/` and a rollback
//! that undoes only what the migration wrote.
//!
//! The store holds a copy of each managed file as it was before the first
//! migration, named by its SHA-256, and a manifest recording, per file, that
//! original and what the migration left there. A rollback restores a file
//! only while it still holds what the migration wrote, or is missing; a file
//! changed since, one whose migration stopped before recording what it
//! wrote, or one a later migration found holding content LPM can't
//! attribute, is reported and left alone unless the caller forces it. One
//! migration or rollback runs in a project at a time.

mod files;

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

const LEGACY_MANIFEST_FILENAME: &str = ".lpm-migrate-manifest.json";
const BACKUP_DIR: &str = "migrate-backup";
const BLOBS_DIR: &str = "files";
const MANIFEST_FILE: &str = "manifest.json";
const MANIFEST_VERSION: u32 = 3;
/// In the state directory beside the store, which a rollback removes.
const LOCK_FILE: &str = "migrate.lock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Original {
    sha256: String,
    mode: u32,
}

/// What the migration left at a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum Written {
    File {
        sha256: String,
    },
    Absent,
    /// Imported from a backup an earlier CLI made, which didn't record it.
    Unknown,
}

/// What a migration found at a path whose content LPM couldn't attribute
/// to an earlier one, and which differed from the original.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum Found {
    File { sha256: String },
    Absent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    /// Project-relative, `/`-separated.
    path: String,
    /// `None` when the file didn't exist before the migration.
    original: Option<Original>,
    /// `None` until the migration records what it wrote, and after a
    /// migration that stopped first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    written: Option<Written>,
    /// What migrations wrote over that LPM couldn't attribute, oldest
    /// first, each one the store keeps; a rollback replaces it only when
    /// forced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    found: Vec<Found>,
}

impl Entry {
    /// Whether LPM knows what the migration left at the path.
    fn attributed(&self) -> bool {
        matches!(self.written, Some(Written::File { .. } | Written::Absent))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: u32,
    entries: Vec<Entry>,
    #[serde(default)]
    created_directories: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyEntry {
    original: String,
    backup: String,
}

#[derive(Debug, Deserialize)]
struct LegacyManifest {
    #[serde(default)]
    backups: Vec<LegacyEntry>,
    #[serde(default)]
    created: Vec<String>,
}

/// Tracks the files a migration manages across retries until a rollback.
#[derive(Debug)]
pub struct MigrationBackup {
    project_dir: PathBuf,
    entries: Vec<Entry>,
    tracked: HashSet<String>,
    created_directories: Vec<String>,
    /// The backup earlier migrations left, which a failed migration puts
    /// back.
    earlier: Option<Manifest>,
    /// The paths this migration backed up, with what each held before it.
    before: HashMap<String, Option<Original>>,
    finished: bool,
    _lock: Option<MigrationLock>,
}

/// Held while a migration or a rollback runs, so another one in the same
/// project can't prune the copies it relies on or act on files this one
/// is about to change. A migration takes it before it reads what it
/// migrates.
pub struct MigrationLock {
    _held: lpm_common::SingleFileExclusiveLockHandle,
}

impl std::fmt::Debug for MigrationLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MigrationLock")
    }
}

impl MigrationLock {
    /// Waits for any other migration or rollback of `project_dir`.
    pub fn acquire(project_dir: &Path) -> Result<Self, LpmError> {
        let state = lpm_common::ensure_project_state_dir(project_dir)?;
        let file = lpm_common::open_lock_file_nofollow(&state.join(LOCK_FILE))?;
        Ok(Self {
            _held: lpm_common::acquire_single_file_exclusive_lock_from_file(file)?,
        })
    }
}

/// The outcome of [`rollback_from_backups`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RollbackReport {
    /// Files restored, and `<path> (removed)` for files the migration created.
    pub restored: Vec<String>,
}

impl MigrationBackup {
    /// Loads the snapshots of earlier migrations of `project_dir`, importing
    /// a backup an earlier CLI made beside the files. A file changed since
    /// a migration wrote it is snapshotted again as it is now, so a rollback
    /// undoes only LPM's writes.
    pub fn for_project(project_dir: &Path) -> Result<Self, LpmError> {
        Self::for_project_locked(project_dir, MigrationLock::acquire(project_dir)?)
    }

    /// [`Self::for_project`] under `lock`, which the migration took before
    /// it read what it migrates.
    pub fn for_project_locked(project_dir: &Path, lock: MigrationLock) -> Result<Self, LpmError> {
        let mut tracker = Self::empty(project_dir);
        tracker._lock = Some(lock);
        let manifest = match read_manifest(project_dir)? {
            Some(manifest) => Some(manifest),
            None => import_legacy(project_dir)?,
        };
        let Some(manifest) = manifest else {
            return Ok(tracker);
        };
        validate_manifest(project_dir, &manifest)?;
        tracker.created_directories = manifest.created_directories;
        let mut resnapshot = false;
        for mut entry in manifest.entries {
            let path = project_dir.join(&entry.path);
            let current = files::current_state(project_dir, &path)?;
            let changed_since = match &entry.written {
                Some(Written::File { sha256 }) => {
                    current.as_ref().map(|(current, _)| current) != Some(sha256)
                }
                Some(Written::Absent) => current.is_some(),
                Some(Written::Unknown) | None => false,
            };
            if changed_since {
                // What the file holds now is the user's, and LPM leaves it
                // there unless this migration writes the file: a later edit
                // is then a change after the migration, not content LPM
                // can't attribute.
                entry.written = Some(match &current {
                    Some((sha256, _)) => Written::File {
                        sha256: sha256.clone(),
                    },
                    None => Written::Absent,
                });
                entry.original = match current {
                    Some(_) => Some(tracker.store(&path)?),
                    None => None,
                };
                entry.found.clear();
                resnapshot = true;
            }
            tracker.tracked.insert(entry.path.clone());
            tracker.entries.push(entry);
        }
        if resnapshot {
            tracker.write_manifest()?;
        }
        tracker.prune_store()?;
        tracker.earlier = Some(Manifest {
            version: MANIFEST_VERSION,
            entries: tracker.entries.clone(),
            created_directories: tracker.created_directories.clone(),
        });
        Ok(tracker)
    }

    fn empty(project_dir: &Path) -> Self {
        Self {
            project_dir: project_dir.to_path_buf(),
            entries: Vec::new(),
            tracked: HashSet::new(),
            created_directories: Vec::new(),
            earlier: None,
            before: HashMap::new(),
            finished: false,
            _lock: None,
        }
    }

    /// Snapshots `path` once, or records that it is absent, before the
    /// migration first writes it. For a path an earlier migration manages,
    /// contents LPM can't attribute to it are kept as found, since they may
    /// be the user's, beside the original the backup keeps.
    pub fn backup_file(&mut self, path: &Path) -> Result<(), LpmError> {
        let root = self.project_dir.clone();
        files::validate(&root, path)?;
        let rel = portable(files::relative(&root, path)?);
        reject_reserved(&rel)?;
        if self.before.contains_key(&rel) {
            return Ok(());
        }
        let before = if files::exists(&root, path)? {
            Some(self.store(path)?)
        } else {
            None
        };
        if self.tracked.contains(&rel) {
            let entry = self
                .entries
                .iter_mut()
                .find(|entry| entry.path == rel)
                .ok_or_else(|| LpmError::Script("migration backup lost an entry".into()))?;
            let found = match &before {
                Some(found) => Found::File {
                    sha256: found.sha256.clone(),
                },
                None => Found::Absent,
            };
            let differs = before.as_ref().map(|found| &found.sha256)
                != entry.original.as_ref().map(|original| &original.sha256);
            if !entry.attributed() && differs && !entry.found.contains(&found) {
                entry.found.push(found);
            }
            entry.written = None;
            self.before.insert(rel, before);
            return Ok(());
        }
        let mut ancestor = path.parent();
        let mut missing = Vec::new();
        while let Some(directory) = ancestor
            && directory != root
            && files::directory_missing(&root, directory)?
        {
            missing.push(portable(files::relative(&root, directory)?));
            ancestor = directory.parent();
        }
        for directory in missing.into_iter().rev() {
            if !self.created_directories.contains(&directory) {
                self.created_directories.push(directory);
            }
        }
        self.tracked.insert(rel.clone());
        self.entries.push(Entry {
            path: rel.clone(),
            original: before.clone(),
            written: None,
            found: Vec::new(),
        });
        self.before.insert(rel, before);
        Ok(())
    }

    /// Validates a batch, snapshots it, and persists the inventory before
    /// any of it is written.
    pub fn backup_files(&mut self, project_dir: &Path, paths: &[&Path]) -> Result<(), LpmError> {
        debug_assert_eq!(project_dir, self.project_dir);
        for path in paths {
            files::validate(project_dir, path)?;
        }
        for path in paths {
            if let Err(error) = self.backup_file(path) {
                self.write_manifest()?;
                return Err(error);
            }
        }
        self.write_manifest()
    }

    /// Records what the migration left at each path it backed up, so a
    /// later rollback can tell LPM's writes from the user's. Call after
    /// writes, on success and on every failure that keeps the migration.
    pub fn seal(&mut self) -> Result<(), LpmError> {
        if self.finished {
            return Ok(());
        }
        for entry in &mut self.entries {
            if !self.before.contains_key(&entry.path) {
                continue;
            }
            let path = self.project_dir.join(&entry.path);
            entry.written = Some(match files::current_state(&self.project_dir, &path)? {
                Some((sha256, _)) => Written::File { sha256 },
                None => Written::Absent,
            });
        }
        self.write_manifest()
    }

    /// Within the failed migration that is running, restores each path it
    /// backed up to what it held before, and puts back the backup earlier
    /// migrations left, or removes the backup when there was none.
    pub fn rollback(&mut self) -> Result<(), LpmError> {
        let Some((_, blobs)) = files::backup_store(&self.project_dir, false)? else {
            return Ok(());
        };
        for entry in &self.entries {
            let Some(before) = self.before.get(&entry.path) else {
                continue;
            };
            files::restore(
                &self.project_dir,
                &self.project_dir.join(&entry.path),
                &blobs,
                before
                    .as_ref()
                    .map(|original| (original.sha256.as_str(), original.mode)),
            )?;
        }
        match self.earlier.take() {
            Some(earlier) => {
                let created: Vec<String> = self
                    .created_directories
                    .iter()
                    .filter(|directory| !earlier.created_directories.contains(directory))
                    .cloned()
                    .collect();
                remove_created_directories(&self.project_dir, &created)?;
                self.entries = earlier.entries;
                self.created_directories = earlier.created_directories;
                self.write_manifest()?;
                self.prune_store()?;
            }
            None => {
                remove_created_directories(&self.project_dir, &self.created_directories)?;
                remove_store(&self.project_dir)?;
            }
        }
        self.finished = true;
        Ok(())
    }

    /// Removes the stored copies no entry refers to.
    fn prune_store(&self) -> Result<(), LpmError> {
        let Some((_, blobs)) = files::backup_store(&self.project_dir, false)? else {
            return Ok(());
        };
        let referenced: HashSet<&str> = self
            .entries
            .iter()
            .flat_map(|entry| {
                let found = entry.found.iter().filter_map(|found| match found {
                    Found::File { sha256 } => Some(sha256.as_str()),
                    Found::Absent => None,
                });
                entry
                    .original
                    .as_ref()
                    .map(|original| original.sha256.as_str())
                    .into_iter()
                    .chain(found)
            })
            .collect();
        files::remove_blobs_except(&blobs, &referenced)
    }

    fn store(&self, path: &Path) -> Result<Original, LpmError> {
        let (_, blobs) = files::backup_store(&self.project_dir, true)?
            .ok_or_else(|| LpmError::Script("could not create the migration backup".into()))?;
        let (sha256, mode) = files::store_blob(&self.project_dir, path, &blobs)?;
        Ok(Original { sha256, mode })
    }

    fn write_manifest(&self) -> Result<(), LpmError> {
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            entries: self.entries.clone(),
            created_directories: self.created_directories.clone(),
        };
        let (backup, _) = files::backup_store(&self.project_dir, true)?
            .ok_or_else(|| LpmError::Script("could not create the migration backup".into()))?;
        lpm_common::write_file_atomic_in_dir_with_options(
            &backup,
            std::ffi::OsStr::new(MANIFEST_FILE),
            lpm_common::AtomicWriteOptions::new()
                .unix_mode(0o600)
                .sync_file()
                .sync_parent(),
            |file| -> Result<(), LpmError> {
                std::io::Write::write_all(file, &serde_json::to_vec_pretty(&manifest)?)?;
                Ok(())
            },
        )
    }
}

enum Decision<'a> {
    Unchanged,
    Restore,
    Changed,
    Unattributed,
    Found(&'a [Found]),
}

/// Where the backup in `project_dir` keeps what migrations found, newest
/// first, as paths that resolve from any directory.
fn describe_found(project_dir: &Path, versions: &[Found]) -> String {
    let kept: Vec<String> = versions
        .iter()
        .rev()
        .filter_map(|found| match found {
            Found::File { sha256 } => Some(
                project_dir
                    .join(lpm_common::PROJECT_STATE_DIR)
                    .join(BACKUP_DIR)
                    .join(BLOBS_DIR)
                    .join(sha256)
                    .display()
                    .to_string(),
            ),
            Found::Absent => None,
        })
        .collect();
    let missing = versions.contains(&Found::Absent);
    match (kept.is_empty(), missing) {
        (false, false) => format!("kept at {}", kept.join(", ")),
        (false, true) => format!("kept at {}; missing before a migration", kept.join(", ")),
        (true, _) => "missing before a migration".to_owned(),
    }
}

/// Whether `project_dir` holds a migration backup, in the store or in the
/// form an earlier CLI left beside the files.
pub fn has_backup(project_dir: &Path) -> bool {
    project_dir
        .join(lpm_common::PROJECT_STATE_DIR)
        .join(BACKUP_DIR)
        .join(MANIFEST_FILE)
        .exists()
        || project_dir.join(LEGACY_MANIFEST_FILENAME).exists()
}

/// Undoes a previous migration of `project_dir`: restores each managed file
/// that still holds what the migration wrote, or is missing, and removes the
/// files and directories it created. When a file changed since, or LPM
/// can't tell whether it holds the migration's write, nothing is restored
/// unless `force` is set, which restores it anyway. A complete rollback
/// removes the backup.
pub fn rollback_from_backups(project_dir: &Path, force: bool) -> Result<RollbackReport, LpmError> {
    if !has_backup(project_dir) {
        return Ok(RollbackReport::default());
    }
    let _lock = MigrationLock::acquire(project_dir)?;
    let backup = MigrationBackup::load_for_rollback(project_dir)?;
    let Some((_, blobs)) = files::backup_store(project_dir, false)? else {
        return Ok(RollbackReport::default());
    };
    let mut plans = Vec::with_capacity(backup.entries.len());
    let mut changed = Vec::new();
    let mut unattributed = Vec::new();
    let mut found = Vec::new();
    for entry in &backup.entries {
        let path = project_dir.join(&entry.path);
        let current = files::current_state(project_dir, &path)?;
        let original = entry.original.as_ref().map(|original| &original.sha256);
        let current_sha = current.as_ref().map(|(sha256, _)| sha256);
        // A complete rollback removes the backup, and with it what
        // migrations found, so that takes `force` whatever the file holds.
        let decision = if !entry.found.is_empty() {
            Decision::Found(&entry.found)
        } else if current_sha == original {
            Decision::Unchanged
        } else if current.is_none() {
            Decision::Restore
        } else {
            match &entry.written {
                Some(Written::File { sha256 }) if current_sha == Some(sha256) => Decision::Restore,
                Some(Written::File { .. } | Written::Absent) => Decision::Changed,
                Some(Written::Unknown) | None => Decision::Unattributed,
            }
        };
        match decision {
            Decision::Changed => changed.push(entry.path.clone()),
            Decision::Unattributed => unattributed.push(entry.path.clone()),
            Decision::Found(versions) => found.push(format!(
                "{} ({})",
                entry.path,
                describe_found(project_dir, versions)
            )),
            Decision::Unchanged | Decision::Restore => {}
        }
        plans.push((entry, path, decision));
    }
    if !force && (!changed.is_empty() || !unattributed.is_empty() || !found.is_empty()) {
        let mut reasons = Vec::with_capacity(3);
        if !changed.is_empty() {
            reasons.push(format!(
                "these files changed after the migration: {}",
                changed.join(", ")
            ));
        }
        if !unattributed.is_empty() {
            reasons.push(format!(
                "LPM can't tell whether these files hold what the migration wrote, because it \
                 stopped before recording it or an earlier CLI made it: {}",
                unattributed.join(", ")
            ));
        }
        if !found.is_empty() {
            reasons.push(format!(
                "migrations wrote over content in these files that LPM can't attribute to an \
                 earlier one, which the backup keeps, newest first: {}",
                found.join(", ")
            ));
        }
        return Err(LpmError::ProjectFile(format!(
            "{}; so nothing was restored. Run `lpm migrate --rollback --force` to restore the \
             copies the backup keeps from before the migrations anyway, or restore them yourself",
            reasons.join("; ")
        )));
    }
    let mut report = RollbackReport::default();
    for (entry, path, decision) in plans {
        if matches!(decision, Decision::Unchanged) {
            continue;
        }
        let stored = entry
            .original
            .as_ref()
            .map(|original| (original.sha256.as_str(), original.mode));
        if files::restore(project_dir, &path, &blobs, stored)? {
            report.restored.push(match stored {
                Some(_) => entry.path.clone(),
                None => format!("{} (removed)", entry.path),
            });
        }
    }
    remove_created_directories(project_dir, &backup.created_directories)?;
    remove_store(project_dir)?;
    Ok(report)
}

impl MigrationBackup {
    fn load_for_rollback(project_dir: &Path) -> Result<Self, LpmError> {
        let manifest = match read_manifest(project_dir)? {
            Some(manifest) => Some(manifest),
            None => import_legacy(project_dir)?,
        };
        let manifest = manifest.unwrap_or_default();
        validate_manifest(project_dir, &manifest)?;
        let mut backup = Self::empty(project_dir);
        backup.tracked = manifest
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        backup.entries = manifest.entries;
        backup.created_directories = manifest.created_directories;
        Ok(backup)
    }
}

fn remove_created_directories(project_dir: &Path, directories: &[String]) -> Result<(), LpmError> {
    let mut directories: Vec<&String> = directories.iter().collect();
    directories.sort_by_key(|directory| std::cmp::Reverse(directory.matches('/').count()));
    for directory in directories {
        files::remove_empty_directory(project_dir, &project_dir.join(directory))?;
    }
    Ok(())
}

fn remove_store(project_dir: &Path) -> Result<(), LpmError> {
    let project = cap_std::fs::Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())?;
    let state = match cap_fs_ext::DirExt::open_dir_nofollow(&project, lpm_common::PROJECT_STATE_DIR)
    {
        Ok(state) => state,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    match state.remove_dir_all(BACKUP_DIR) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_manifest(project_dir: &Path) -> Result<Option<Manifest>, LpmError> {
    let Some((backup, _)) = files::backup_store(project_dir, false)? else {
        return Ok(None);
    };
    let mut options = cap_std::fs::OpenOptions::new();
    cap_fs_ext::OpenOptionsFollowExt::follow(options.read(true), cap_fs_ext::FollowSymlinks::No);
    let file = match backup.open_with(MANIFEST_FILE, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let (contents, _) = lpm_common::read_text_file_capped_from_open_file(
        file.into_std(),
        Path::new(MANIFEST_FILE),
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| LpmError::Script(format!("failed to read the migration backup: {error}")))?;
    let manifest: Manifest = serde_json::from_str(&contents).map_err(|error| {
        LpmError::Script(format!("failed to parse the migration backup: {error}"))
    })?;
    if manifest.version != MANIFEST_VERSION {
        return Err(LpmError::Script(format!(
            "unsupported migration backup version {}",
            manifest.version
        )));
    }
    Ok(Some(manifest))
}

/// Moves a backup an earlier CLI made, `.lpm-migrate-manifest.json` and
/// `<file>.backup` copies beside the files, into the store. It recorded
/// nothing about what the migration wrote, so a rollback of it restores a
/// changed file only when forced.
fn import_legacy(project_dir: &Path) -> Result<Option<Manifest>, LpmError> {
    let legacy_path = project_dir.join(LEGACY_MANIFEST_FILENAME);
    let Some(contents) = files::read(
        project_dir,
        &legacy_path,
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    )?
    else {
        return Ok(None);
    };
    let legacy: LegacyManifest = serde_json::from_slice(&contents)
        .map_err(|error| LpmError::Script(format!("failed to parse backup manifest: {error}")))?;
    let mut backup = MigrationBackup::empty(project_dir);
    let mut legacy_copies = Vec::with_capacity(legacy.backups.len());
    for entry in &legacy.backups {
        let original = resolve_manifest_path(project_dir, &entry.original)?;
        let copy = resolve_manifest_path(project_dir, &entry.backup)?;
        if !entry.backup.ends_with(".backup") {
            return Err(LpmError::Script(
                "conflicting or invalid backup manifest paths".into(),
            ));
        }
        let rel = portable(files::relative(project_dir, &original)?);
        reject_reserved(&rel)?;
        if !backup.tracked.insert(rel.clone()) {
            return Err(LpmError::Script("duplicate backup manifest path".into()));
        }
        let (sha256, _) = {
            let (_, blobs) = files::backup_store(project_dir, true)?
                .ok_or_else(|| LpmError::Script("could not create the migration backup".into()))?;
            files::store_blob(project_dir, &copy, &blobs)?
        };
        let mode = files::current_state(project_dir, &original)?.map_or(0o644, |(_, mode)| mode);
        backup.entries.push(Entry {
            path: rel,
            original: Some(Original { sha256, mode }),
            written: Some(Written::Unknown),
            found: Vec::new(),
        });
        legacy_copies.push(copy);
    }
    for created in &legacy.created {
        let path = resolve_manifest_path(project_dir, created)?;
        let rel = portable(files::relative(project_dir, &path)?);
        reject_reserved(&rel)?;
        if !backup.tracked.insert(rel.clone()) {
            return Err(LpmError::Script("duplicate backup manifest path".into()));
        }
        backup.entries.push(Entry {
            path: rel,
            original: None,
            written: Some(Written::Unknown),
            found: Vec::new(),
        });
    }
    backup.write_manifest()?;
    for copy in legacy_copies {
        files::remove(project_dir, &copy)?;
    }
    files::remove(project_dir, &legacy_path)?;
    read_manifest(project_dir)
}

fn validate_manifest(project_dir: &Path, manifest: &Manifest) -> Result<(), LpmError> {
    let mut seen = HashSet::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        reject_reserved(&entry.path)?;
        resolve_manifest_path(project_dir, &entry.path)?;
        if !seen.insert(entry.path.as_str()) {
            return Err(LpmError::Script("duplicate backup manifest path".into()));
        }
    }
    for directory in &manifest.created_directories {
        reject_reserved(directory)?;
        resolve_manifest_path(project_dir, directory)?;
    }
    Ok(())
}

/// Rejects paths that are LPM's or git's own state rather than project files.
fn reject_reserved(rel: &str) -> Result<(), LpmError> {
    let first = rel.split('/').next().unwrap_or_default();
    if rel.is_empty()
        || first.eq_ignore_ascii_case(".git")
        || lpm_common::is_project_state_name(std::ffi::OsStr::new(first))
        || rel == LEGACY_MANIFEST_FILENAME
    {
        return Err(LpmError::Script(
            "backup manifest targets reserved project state".into(),
        ));
    }
    Ok(())
}

fn portable(rel: &Path) -> String {
    rel.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn project() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn migrate(project: &Path, files: &[(&str, &str)]) -> MigrationBackup {
        let mut backup = MigrationBackup::for_project(project).unwrap();
        let paths: Vec<PathBuf> = files.iter().map(|(path, _)| project.join(path)).collect();
        let refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        backup.backup_files(project, &refs).unwrap();
        for (path, contents) in files {
            let path = project.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        backup.seal().unwrap();
        backup
    }

    fn store(project: &Path) -> PathBuf {
        project.join(".lpm").join(BACKUP_DIR)
    }

    #[test]
    fn backups_live_in_the_self_ignoring_state_directory() {
        let dir = project();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

        migrate(
            dir.path(),
            &[("package-lock.json", "{}"), ("lpm.lock", "v1")],
        );

        assert!(store(dir.path()).join(MANIFEST_FILE).is_file());
        assert_eq!(
            fs::read_to_string(dir.path().join(".lpm/.gitignore")).unwrap(),
            lpm_common::project_state::PROJECT_STATE_IGNORE
        );
        assert!(!dir.path().join("package-lock.json.backup").exists());
        assert!(!dir.path().join(LEGACY_MANIFEST_FILENAME).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for entry in fs::read_dir(store(dir.path()).join(BLOBS_DIR)).unwrap() {
                let mode = entry.unwrap().metadata().unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        }
    }

    #[test]
    fn rollback_undoes_the_migration_and_removes_the_backup() {
        let dir = project();
        fs::write(dir.path().join("package.json"), "original").unwrap();
        migrate(
            dir.path(),
            &[("package.json", "migrated"), ("lpm.lock", "lock")],
        );

        let report = rollback_from_backups(dir.path(), false).unwrap();

        assert_eq!(
            report.restored,
            ["package.json".to_owned(), "lpm.lock (removed)".to_owned()]
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("package.json")).unwrap(),
            "original"
        );
        assert!(!dir.path().join("lpm.lock").exists());
        assert!(!store(dir.path()).exists());
    }

    #[test]
    fn a_file_changed_after_the_migration_stops_the_rollback_until_forced() {
        let dir = project();
        fs::write(dir.path().join("package.json"), "original").unwrap();
        migrate(
            dir.path(),
            &[("package.json", "migrated"), ("lpm.lock", "lock")],
        );
        fs::write(dir.path().join("lpm.lock"), "lock after lpm install foo").unwrap();

        let error = rollback_from_backups(dir.path(), false).unwrap_err();

        assert!(error.to_string().contains("lpm.lock"), "{error}");
        assert!(error.to_string().contains("--force"), "{error}");
        assert_eq!(
            fs::read_to_string(dir.path().join("package.json")).unwrap(),
            "migrated",
            "nothing is restored while a file changed"
        );
        assert!(store(dir.path()).join(MANIFEST_FILE).exists());

        let report = rollback_from_backups(dir.path(), true).unwrap();
        assert_eq!(report.restored.len(), 2);
        assert!(!dir.path().join("lpm.lock").exists());
        assert_eq!(
            fs::read_to_string(dir.path().join("package.json")).unwrap(),
            "original"
        );
    }

    #[test]
    fn a_file_deleted_after_the_migration_is_restored() {
        let dir = project();
        fs::write(dir.path().join("package-lock.json"), "npm lock").unwrap();
        migrate(dir.path(), &[("package-lock.json", "npm lock")]);
        fs::remove_file(dir.path().join("package-lock.json")).unwrap();

        let report = rollback_from_backups(dir.path(), false).unwrap();

        assert_eq!(report.restored, ["package-lock.json".to_owned()]);
        assert_eq!(
            fs::read_to_string(dir.path().join("package-lock.json")).unwrap(),
            "npm lock"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_restored_file_keeps_its_original_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = project();
        let script = dir.path().join("package.json");
        fs::write(&script, "original").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        migrate(dir.path(), &[("package.json", "migrated")]);

        rollback_from_backups(dir.path(), false).unwrap();

        assert_eq!(
            fs::metadata(&script).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn only_directories_the_migration_created_are_removed() {
        let dir = project();
        fs::create_dir(dir.path().join("patches")).unwrap();
        migrate(
            dir.path(),
            &[
                ("patches/a.patch", "patch"),
                (".github/workflows/ci.lpm.yml", "ci"),
            ],
        );

        rollback_from_backups(dir.path(), false).unwrap();

        assert!(
            dir.path().join("patches").is_dir(),
            "the user's directory stays"
        );
        assert!(!dir.path().join(".github").exists());
    }

    #[test]
    fn a_retry_keeps_the_first_snapshot_but_not_over_the_user_s_edits() {
        let dir = project();
        fs::write(dir.path().join("package.json"), "P0").unwrap();
        fs::write(dir.path().join(".npmrc"), "N0").unwrap();
        migrate(
            dir.path(),
            &[("package.json", "P-migrated"), (".npmrc", "N-migrated")],
        );
        fs::write(dir.path().join("package.json"), "P1-user").unwrap();

        migrate(
            dir.path(),
            &[
                ("package.json", "P-migrated-again"),
                (".npmrc", "N-migrated"),
            ],
        );
        rollback_from_backups(dir.path(), false).unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join("package.json")).unwrap(),
            "P1-user",
            "the rollback undoes only LPM's write over the user's edit"
        );
        assert_eq!(fs::read_to_string(dir.path().join(".npmrc")).unwrap(), "N0");
    }

    #[test]
    fn an_edit_a_migration_left_alone_is_the_user_s_and_a_later_one_rolls_back_to_it() {
        let dir = project();
        let template = ".github/workflows/ci.lpm.yml";
        drop(migrate(dir.path(), &[(template, "W1")]));
        fs::write(dir.path().join(template), "edit1").unwrap();
        // A migration that re-snapshots the template but doesn't write it.
        drop(migrate(dir.path(), &[]));
        fs::write(dir.path().join(template), "edit2").unwrap();

        let refusal = rollback_from_backups(dir.path(), false)
            .unwrap_err()
            .to_string();
        assert!(
            refusal
                .contains("these files changed after the migration: .github/workflows/ci.lpm.yml"),
            "{refusal}"
        );
        assert!(!refusal.contains("stopped before recording"), "{refusal}");

        drop(migrate(dir.path(), &[(template, "W3")]));
        rollback_from_backups(dir.path(), false).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join(template)).unwrap(),
            "edit2",
            "the rollback returns the template to the edit made before the last migration"
        );
    }

    fn legacy_npmrc_migration(project: &Path) {
        fs::write(project.join(".npmrc"), "N-migrated-by-an-earlier-cli").unwrap();
        fs::write(project.join(".npmrc.backup"), "N0").unwrap();
        fs::write(
            project.join(LEGACY_MANIFEST_FILENAME),
            serde_json::json!({
                "version": 2,
                "backups": [{"original": ".npmrc", "backup": ".npmrc.backup"}],
                "created": [],
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn an_interrupted_migration_s_files_are_not_restored_over_later_edits_unless_forced() {
        let dir = project();
        fs::write(dir.path().join("package.json"), "original").unwrap();
        let mut backup = MigrationBackup::for_project(dir.path()).unwrap();
        backup
            .backup_files(
                dir.path(),
                &[
                    &dir.path().join("package.json"),
                    &dir.path().join("lpm.lock"),
                ],
            )
            .unwrap();
        fs::write(dir.path().join("package.json"), "half-migrated").unwrap();
        fs::write(dir.path().join("lpm.lock"), "lock").unwrap();
        drop(backup);
        fs::write(
            dir.path().join("package.json"),
            "edited after the interruption",
        )
        .unwrap();

        let error = rollback_from_backups(dir.path(), false).unwrap_err();

        assert!(error.to_string().contains("package.json"), "{error}");
        assert!(error.to_string().contains("lpm.lock"), "{error}");
        assert!(error.to_string().contains("--force"), "{error}");
        assert_eq!(
            fs::read_to_string(dir.path().join("package.json")).unwrap(),
            "edited after the interruption"
        );
        assert!(dir.path().join("lpm.lock").exists());

        rollback_from_backups(dir.path(), true).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("package.json")).unwrap(),
            "original"
        );
        assert!(!dir.path().join("lpm.lock").exists());
    }

    #[test]
    fn an_interrupted_migration_s_missing_files_are_restored_without_force() {
        let dir = project();
        fs::write(dir.path().join("package-lock.json"), "npm lock").unwrap();
        let mut backup = MigrationBackup::for_project(dir.path()).unwrap();
        backup
            .backup_files(dir.path(), &[&dir.path().join("package-lock.json")])
            .unwrap();
        drop(backup);
        fs::remove_file(dir.path().join("package-lock.json")).unwrap();

        let report = rollback_from_backups(dir.path(), false).unwrap();

        assert_eq!(report.restored, ["package-lock.json".to_owned()]);
    }

    #[test]
    fn a_migration_claims_only_the_files_it_backed_up() {
        let dir = project();
        legacy_npmrc_migration(dir.path());
        fs::write(dir.path().join(".npmrc"), "N-edited").unwrap();
        migrate(dir.path(), &[("lpm.lock", "lock")]);

        let error = rollback_from_backups(dir.path(), false).unwrap_err();

        assert!(error.to_string().contains(".npmrc"), "{error}");
        assert_eq!(
            fs::read_to_string(dir.path().join(".npmrc")).unwrap(),
            "N-edited"
        );
    }

    /// What the copies a refused rollback names for `path` hold, newest
    /// first.
    fn kept_copies(project: &Path, error: &LpmError, path: &str) -> Vec<String> {
        let message = error.to_string();
        let Some((kept, _)) = message
            .split_once(&format!("{path} (kept at "))
            .and_then(|(_, rest)| rest.split_once(')'))
        else {
            panic!("no kept copy of {path} in {message}");
        };
        kept.split(", ")
            .map(|kept| {
                assert!(
                    Path::new(kept).is_absolute(),
                    "{kept} resolves from anywhere"
                );
                fs::read_to_string(project.join(kept)).unwrap()
            })
            .collect()
    }

    #[test]
    fn a_migration_over_content_lpm_cannot_attribute_keeps_it_and_the_original() {
        let dir = project();
        legacy_npmrc_migration(dir.path());
        fs::write(dir.path().join(".npmrc"), "N-edited").unwrap();

        migrate(dir.path(), &[(".npmrc", "N-migrated-again")]);
        migrate(dir.path(), &[("lpm.lock", "lock")]);
        let error = rollback_from_backups(dir.path(), false).unwrap_err();

        assert!(error.to_string().contains("--force"), "{error}");
        assert_eq!(kept_copies(dir.path(), &error, ".npmrc"), ["N-edited"]);
        assert_eq!(
            fs::read_to_string(dir.path().join(".npmrc")).unwrap(),
            "N-migrated-again"
        );
        rollback_from_backups(dir.path(), true).unwrap();
        assert_eq!(fs::read_to_string(dir.path().join(".npmrc")).unwrap(), "N0");
    }

    #[test]
    fn a_retry_after_an_interruption_rolls_back_to_before_the_first_migration_only_when_forced() {
        let dir = project();
        fs::write(dir.path().join("package.json"), "original").unwrap();
        let mut interrupted = MigrationBackup::for_project(dir.path()).unwrap();
        interrupted
            .backup_files(dir.path(), &[&dir.path().join("package.json")])
            .unwrap();
        fs::write(dir.path().join("package.json"), "half-migrated").unwrap();
        drop(interrupted);

        migrate(dir.path(), &[("package.json", "migrated")]);
        let error = rollback_from_backups(dir.path(), false).unwrap_err();

        assert_eq!(
            kept_copies(dir.path(), &error, "package.json"),
            ["half-migrated"]
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("package.json")).unwrap(),
            "migrated"
        );
        rollback_from_backups(dir.path(), true).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("package.json")).unwrap(),
            "original"
        );
    }

    #[test]
    fn every_retry_over_content_lpm_cannot_attribute_keeps_what_it_found() {
        let dir = project();
        legacy_npmrc_migration(dir.path());
        let mut interrupted = MigrationBackup::for_project(dir.path()).unwrap();
        interrupted
            .backup_files(dir.path(), &[&dir.path().join(".npmrc")])
            .unwrap();
        fs::write(dir.path().join(".npmrc"), "N-half-migrated").unwrap();
        drop(interrupted);
        fs::write(dir.path().join(".npmrc"), "N-user").unwrap();

        migrate(dir.path(), &[(".npmrc", "N-migrated-again")]);
        migrate(dir.path(), &[("lpm.lock", "lock")]);
        let error = rollback_from_backups(dir.path(), false).unwrap_err();

        assert_eq!(
            kept_copies(dir.path(), &error, ".npmrc"),
            ["N-user", "N-migrated-by-an-earlier-cli"]
        );
        rollback_from_backups(dir.path(), true).unwrap();
        assert_eq!(fs::read_to_string(dir.path().join(".npmrc")).unwrap(), "N0");
    }

    #[test]
    fn a_missing_file_still_needs_force_while_the_backup_keeps_what_a_migration_found() {
        let dir = project();
        legacy_npmrc_migration(dir.path());
        migrate(dir.path(), &[(".npmrc", "N-migrated-again")]);
        fs::remove_file(dir.path().join(".npmrc")).unwrap();

        let error = rollback_from_backups(dir.path(), false).unwrap_err();

        assert_eq!(
            kept_copies(dir.path(), &error, ".npmrc"),
            ["N-migrated-by-an-earlier-cli"]
        );
        assert!(!dir.path().join(".npmrc").exists());
        rollback_from_backups(dir.path(), true).unwrap();
        assert_eq!(fs::read_to_string(dir.path().join(".npmrc")).unwrap(), "N0");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_private_file_and_its_backup_drop_access_the_directory_passes_on() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = project();
        let chmod = |args: &[&str], path: &Path| {
            let status = std::process::Command::new("/bin/chmod")
                .args(args)
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success(), "chmod {args:?}");
        };
        chmod(
            &[
                "+a",
                "group:everyone allow read,list,search,file_inherit,directory_inherit",
            ],
            dir.path(),
        );
        let npmrc = dir.path().join(".npmrc");
        fs::write(&npmrc, "//registry.npmjs.org/:_authToken=secret\n").unwrap();
        fs::set_permissions(&npmrc, fs::Permissions::from_mode(0o600)).unwrap();
        chmod(&["-N"], &npmrc);
        let has_acl = |path: &Path| {
            lpm_common::macos_acl::has_extended_acl(fs::File::open(path).unwrap()).unwrap()
        };
        assert!(!has_acl(&npmrc));

        let mut backup = MigrationBackup::for_project(dir.path()).unwrap();
        backup.backup_files(dir.path(), &[&npmrc]).unwrap();
        write_output(
            dir.path(),
            &npmrc,
            b"//registry.npmjs.org/:_authToken=secret\n@lpm.dev:registry=x\n",
        )
        .unwrap();
        backup.seal().unwrap();
        drop(backup);

        assert!(!has_acl(&npmrc), "the rewritten .npmrc");
        assert_eq!(
            fs::metadata(&npmrc).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for directory in [store(dir.path()), store(dir.path()).join(BLOBS_DIR)] {
            assert!(!has_acl(&directory), "{}", directory.display());
        }
        for blob in fs::read_dir(store(dir.path()).join(BLOBS_DIR)).unwrap() {
            assert!(!has_acl(&blob.unwrap().path()), "a stored copy");
        }

        rollback_from_backups(dir.path(), false).unwrap();
        assert!(!has_acl(&npmrc), "the restored .npmrc");
    }

    #[test]
    fn another_migration_waits_for_a_running_one_and_leaves_its_copies() {
        let dir = project();
        let package = dir.path().join("package.json");
        fs::write(&package, "P0").unwrap();
        migrate(dir.path(), &[("package.json", "P1")]);
        let mut running = MigrationBackup::for_project(dir.path()).unwrap();
        running.backup_files(dir.path(), &[&package]).unwrap();
        fs::write(&package, "P2").unwrap();

        let project_dir = dir.path().to_path_buf();
        let other = std::thread::spawn(move || {
            drop(MigrationBackup::for_project(&project_dir).unwrap());
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let other_finished_early = other.is_finished();
        running.rollback().unwrap();
        drop(running);
        other.join().unwrap();

        assert!(!other_finished_early, "the other migration waits");
        assert_eq!(fs::read_to_string(&package).unwrap(), "P1");
        rollback_from_backups(dir.path(), false).unwrap();
        assert_eq!(fs::read_to_string(&package).unwrap(), "P0");
    }

    #[test]
    fn a_failed_retry_puts_back_only_its_own_writes_and_the_earlier_backup() {
        let dir = project();
        fs::write(dir.path().join("package.json"), "P0").unwrap();
        fs::write(dir.path().join(".npmrc"), "N0").unwrap();
        migrate(
            dir.path(),
            &[("package.json", "P-migrated"), (".npmrc", "N-migrated")],
        );
        let earlier = fs::read(store(dir.path()).join(MANIFEST_FILE)).unwrap();

        let mut retry = MigrationBackup::for_project(dir.path()).unwrap();
        let paths = [dir.path().join("package.json"), dir.path().join("lpm.lock")];
        retry
            .backup_files(dir.path(), &[paths[0].as_path(), paths[1].as_path()])
            .unwrap();
        fs::write(&paths[0], "P-half-migrated-again").unwrap();
        fs::write(&paths[1], "lock").unwrap();
        retry.rollback().unwrap();

        assert_eq!(fs::read_to_string(&paths[0]).unwrap(), "P-migrated");
        assert!(!paths[1].exists());
        assert_eq!(
            fs::read(store(dir.path()).join(MANIFEST_FILE)).unwrap(),
            earlier
        );
        assert_eq!(
            fs::read_dir(store(dir.path()).join(BLOBS_DIR))
                .unwrap()
                .count(),
            2,
            "the retry's copies are removed"
        );
        drop(retry);
        rollback_from_backups(dir.path(), false).unwrap();
        assert_eq!(fs::read_to_string(&paths[0]).unwrap(), "P0");
        assert_eq!(fs::read_to_string(dir.path().join(".npmrc")).unwrap(), "N0");
    }

    #[test]
    fn in_process_rollback_restores_everything_and_removes_the_backup() {
        let dir = project();
        fs::write(dir.path().join("package.json"), "original").unwrap();
        let mut backup = MigrationBackup::for_project(dir.path()).unwrap();
        let paths = [dir.path().join("package.json"), dir.path().join("lpm.lock")];
        backup
            .backup_files(dir.path(), &[paths[0].as_path(), paths[1].as_path()])
            .unwrap();
        fs::write(&paths[0], "half-migrated").unwrap();
        fs::write(&paths[1], "lock").unwrap();

        backup.rollback().unwrap();
        backup.seal().unwrap();

        assert_eq!(fs::read_to_string(&paths[0]).unwrap(), "original");
        assert!(!paths[1].exists());
        assert!(
            !store(dir.path()).exists(),
            "sealing after a rollback writes nothing"
        );
    }

    #[test]
    fn a_backup_from_an_earlier_cli_is_imported_and_needs_force_where_files_differ() {
        let dir = project();
        fs::write(dir.path().join("package-lock.json"), "migrated-over").unwrap();
        fs::write(dir.path().join("package-lock.json.backup"), "npm lock").unwrap();
        fs::write(dir.path().join("lpm.lock"), "lock").unwrap();
        fs::write(
            dir.path().join(LEGACY_MANIFEST_FILENAME),
            serde_json::json!({
                "version": 2,
                "backups": [{"original": "package-lock.json", "backup": "package-lock.json.backup"}],
                "created": ["lpm.lock"],
            })
            .to_string(),
        )
        .unwrap();

        let error = rollback_from_backups(dir.path(), false).unwrap_err();
        assert!(error.to_string().contains("--force"), "{error}");
        assert!(!dir.path().join(LEGACY_MANIFEST_FILENAME).exists());
        assert!(!dir.path().join("package-lock.json.backup").exists());

        rollback_from_backups(dir.path(), true).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("package-lock.json")).unwrap(),
            "npm lock"
        );
        assert!(!dir.path().join("lpm.lock").exists());
    }

    #[test]
    fn without_a_backup_nothing_is_restored_and_stray_backup_files_stay() {
        let dir = project();
        fs::write(dir.path().join("config.json"), "mine").unwrap();
        fs::write(dir.path().join("config.json.backup"), "also mine").unwrap();

        let report = rollback_from_backups(dir.path(), true).unwrap();

        assert!(report.restored.is_empty());
        assert_eq!(
            fs::read_to_string(dir.path().join("config.json")).unwrap(),
            "mine"
        );
        assert!(dir.path().join("config.json.backup").exists());
    }

    #[test]
    fn manifest_entries_naming_lpm_or_git_state_are_rejected() {
        for path in [".lpm/env-sync.json", ".git/config", ".LPM/x"] {
            let dir = project();
            fs::create_dir_all(store(dir.path()).join(BLOBS_DIR)).unwrap();
            fs::write(
                store(dir.path()).join(MANIFEST_FILE),
                serde_json::json!({
                    "version": MANIFEST_VERSION,
                    "entries": [{"path": path, "original": null}],
                })
                .to_string(),
            )
            .unwrap();

            let error = rollback_from_backups(dir.path(), true).unwrap_err();

            assert!(error.to_string().contains("reserved"), "{path}: {error}");
        }
    }

    #[test]
    fn legacy_manifest_paths_outside_the_project_are_rejected() {
        for (backups, created, expected) in [
            (
                serde_json::json!([{"original": "/etc/passwd", "backup": "/etc/passwd.backup"}]),
                serde_json::json!([]),
                "absolute path",
            ),
            (
                serde_json::json!([]),
                serde_json::json!(["../escape.txt"]),
                "`..`",
            ),
            (
                serde_json::json!([{"original": "patches/../../../etc/passwd", "backup": "patches/x.backup"}]),
                serde_json::json!([]),
                "`..`",
            ),
        ] {
            let dir = project();
            fs::write(
                dir.path().join(LEGACY_MANIFEST_FILENAME),
                serde_json::json!({"version": 2, "backups": backups, "created": created})
                    .to_string(),
            )
            .unwrap();

            let error = rollback_from_backups(dir.path(), true).unwrap_err();

            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_legacy_restore_target_through_a_linked_directory_is_rejected() {
        let dir = project();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("patches")).unwrap();
        fs::write(dir.path().join("loot.backup"), "stolen content").unwrap();
        fs::write(
            dir.path().join(LEGACY_MANIFEST_FILENAME),
            serde_json::json!({
                "version": 2,
                "backups": [{"original": "patches/restored.patch", "backup": "loot.backup"}],
                "created": [],
            })
            .to_string(),
        )
        .unwrap();

        let error = rollback_from_backups(dir.path(), true).unwrap_err();

        assert!(
            error.to_string().contains("outside the project root"),
            "{error}"
        );
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }
}
