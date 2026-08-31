use crate::added_sources_state::{
    AddedSourceFile, AddedSourceFileAction, AddedSourceRecord, AddedSourcesState,
};
use crate::install_ui;
use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;
use lpm_common::LpmError;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::directory_transaction::directory_identity;

fn manifest_lookup_keys(package: &str) -> Vec<String> {
    let mut keys = vec![package.to_string()];
    if let Ok(name) = lpm_common::PackageName::parse(package) {
        let scoped = name.scoped();
        if scoped != package {
            keys.push(scoped);
        }
    }
    keys
}

enum FileRemoval {
    Delete,
    Restore {
        backup: PathBuf,
        original_mode: Option<u32>,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RemovalFileFingerprint {
    len: u64,
    sha256: [u8; 32],
    #[cfg(unix)]
    mode: Option<u32>,
}

impl RemovalFileFingerprint {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            #[cfg(unix)]
            mode: None,
        }
    }

    fn from_path(path: &Path) -> Result<Option<Self>, LpmError> {
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(LpmError::Io(error)),
        };
        let metadata = file.metadata().map_err(LpmError::Io)?;
        if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
            return Err(LpmError::Registry(format!(
                "refusing source removal path that is not a regular file: {}",
                path.display()
            )));
        }
        let mut sha256 = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(LpmError::Io)?;
            if read == 0 {
                break;
            }
            sha256.update(&buffer[..read]);
        }
        Ok(Some(Self {
            len: metadata.len(),
            sha256: sha256.finalize().into(),
            #[cfg(unix)]
            mode: Some({
                use std::os::unix::fs::PermissionsExt as _;
                metadata.permissions().mode()
            }),
        }))
    }

    fn content_digest(self) -> String {
        format!("sha256-{}", hex::encode(self.sha256))
    }

    fn matches_path(self, path: &Path) -> Result<bool, LpmError> {
        Ok(Self::from_path(path)?.is_some_and(|current| {
            current.len == self.len && current.sha256 == self.sha256 && {
                #[cfg(unix)]
                {
                    self.mode.is_none_or(|mode| current.mode == Some(mode))
                }
                #[cfg(not(unix))]
                {
                    true
                }
            }
        }))
    }
}

#[derive(Clone, Copy)]
enum PlannedDestinationState {
    Missing,
    File(RemovalFileFingerprint),
}

impl PlannedDestinationState {
    fn from_path(path: &Path) -> Result<Self, LpmError> {
        Ok(match RemovalFileFingerprint::from_path(path)? {
            Some(fingerprint) => Self::File(fingerprint),
            None => Self::Missing,
        })
    }

    fn matches_path(self, path: &Path) -> Result<bool, LpmError> {
        match self {
            Self::Missing => match std::fs::symlink_metadata(path) {
                Ok(_) => Ok(false),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
                Err(error) => Err(LpmError::Io(error)),
            },
            Self::File(expected) => expected.matches_path(path),
        }
    }
}

struct PlannedFileRemoval {
    manifest_path: PathBuf,
    destination: PathBuf,
    expected_destination: PlannedDestinationState,
    operation: FileRemoval,
}

enum PlannedBackupMutation {
    Delete {
        path: PathBuf,
        expected: RemovalFileFingerprint,
    },
    Promote {
        source: PathBuf,
        expected_source: RemovalFileFingerprint,
        destination: PathBuf,
        expected_destination: RemovalFileFingerprint,
    },
}

struct MoveEntry {
    source: PathBuf,
    destination: PathBuf,
    destination_guard: Option<RemovalDestinationGuard>,
    #[cfg(unix)]
    source_permissions: Option<std::fs::Permissions>,
}

struct RemovalDestinationGuard {
    expected: RemovalFileFingerprint,
    #[cfg(unix)]
    file: std::fs::File,
}

impl RemovalDestinationGuard {
    fn from_path(path: &Path) -> Result<Self, LpmError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};

            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let file = options.open(path).map_err(LpmError::Io)?;
            let metadata = file.metadata().map_err(LpmError::Io)?;
            if !metadata.is_file() {
                return Err(LpmError::Registry(format!(
                    "refusing source removal guard that is not a regular file: {}",
                    path.display()
                )));
            }
            let mut sha256 = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut offset = 0;
            loop {
                let read = file.read_at(&mut buffer, offset).map_err(LpmError::Io)?;
                if read == 0 {
                    break;
                }
                sha256.update(&buffer[..read]);
                offset += read as u64;
            }
            use std::os::unix::fs::PermissionsExt as _;
            let expected = RemovalFileFingerprint {
                len: metadata.len(),
                sha256: sha256.finalize().into(),
                mode: Some(metadata.permissions().mode()),
            };
            Ok(Self { expected, file })
        }
        #[cfg(not(unix))]
        {
            let expected = RemovalFileFingerprint::from_path(path)?.ok_or_else(|| {
                LpmError::Registry(format!(
                    "source removal guard disappeared: {}",
                    path.display()
                ))
            })?;
            Ok(Self { expected })
        }
    }

    fn matches_path(&self, path: &Path) -> Result<bool, LpmError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};

            let path_metadata = std::fs::symlink_metadata(path).map_err(LpmError::Io)?;
            let file_metadata = self.file.metadata().map_err(LpmError::Io)?;
            if lpm_common::is_symlink_or_junction(&path_metadata)
                || !path_metadata.is_file()
                || path_metadata.dev() != file_metadata.dev()
                || path_metadata.ino() != file_metadata.ino()
                || path_metadata.len() != self.expected.len
                || self
                    .expected
                    .mode
                    .is_some_and(|mode| path_metadata.permissions().mode() != mode)
            {
                return Ok(false);
            }
            let mut sha256 = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut offset = 0;
            loop {
                let read = self
                    .file
                    .read_at(&mut buffer, offset)
                    .map_err(LpmError::Io)?;
                if read == 0 {
                    break;
                }
                sha256.update(&buffer[..read]);
                offset += read as u64;
            }
            Ok(<[u8; 32]>::from(sha256.finalize()) == self.expected.sha256)
        }
        #[cfg(not(unix))]
        {
            self.expected.matches_path(path)
        }
    }
}

#[cfg(unix)]
fn regular_file_permissions(path: &Path) -> Result<std::fs::Permissions, LpmError> {
    let metadata = std::fs::symlink_metadata(path).map_err(LpmError::Io)?;
    if !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing source backup that is not a regular file: {}",
            path.display()
        )));
    }
    Ok(metadata.permissions())
}

#[cfg(unix)]
fn apply_recorded_file_permissions(
    path: &Path,
    permissions: std::fs::Permissions,
) -> Result<(), LpmError> {
    let metadata = std::fs::symlink_metadata(path).map_err(LpmError::Io)?;
    if !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing to set the mode of a non-file source backup: {}",
            path.display()
        )));
    }
    std::fs::set_permissions(path, permissions).map_err(LpmError::Io)
}

struct RemovalTransaction {
    project_dir: PathBuf,
    canonical_project: PathBuf,
    quarantine: tempfile::TempDir,
    moves: Vec<MoveEntry>,
    committed: bool,
}

impl RemovalTransaction {
    fn new(project_dir: &Path) -> Result<Self, LpmError> {
        let canonical_project = project_dir.canonicalize().map_err(LpmError::Io)?;
        let quarantine = tempfile::Builder::new()
            .prefix(".source-remove-")
            .tempdir_in(canonical_project.join(".lpm"))
            .map_err(LpmError::Io)?;
        Ok(Self {
            project_dir: project_dir.to_path_buf(),
            canonical_project,
            quarantine,
            moves: Vec::new(),
            committed: false,
        })
    }

    fn resolve_path(&self, path: &Path) -> Result<PathBuf, LpmError> {
        let relative = path
            .strip_prefix(&self.project_dir)
            .or_else(|_| path.strip_prefix(&self.canonical_project))
            .map_err(|_| {
                LpmError::Registry(format!(
                    "source removal transaction path is outside the project: {}",
                    path.display()
                ))
            })?;
        if relative.as_os_str().is_empty()
            || !relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(LpmError::Registry(format!(
                "source removal transaction path is unsafe: {}",
                path.display()
            )));
        }
        Ok(self.canonical_project.join(relative))
    }

    fn validate_parent(&self, path: &Path) -> Result<(), LpmError> {
        let parent = path.parent().ok_or_else(|| {
            LpmError::Registry(format!(
                "source removal transaction path has no parent: {}",
                path.display()
            ))
        })?;
        let relative_parent = parent.strip_prefix(&self.canonical_project).map_err(|_| {
            LpmError::Registry(format!(
                "source removal transaction path is outside the project: {}",
                path.display()
            ))
        })?;
        let mut current = self.canonical_project.clone();
        let root_metadata = std::fs::symlink_metadata(&current).map_err(LpmError::Io)?;
        if lpm_common::is_symlink_or_junction(&root_metadata) || !root_metadata.is_dir() {
            return Err(LpmError::Registry(format!(
                "source removal project root is linked or not a directory: {}",
                current.display()
            )));
        }
        for component in relative_parent.components() {
            current.push(component);
            let metadata = std::fs::symlink_metadata(&current).map_err(LpmError::Io)?;
            if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_dir() {
                return Err(LpmError::Registry(format!(
                    "source removal transaction has a linked or non-directory parent: {}",
                    current.display()
                )));
            }
        }
        Ok(())
    }

    fn move_path(&mut self, source: &Path, destination: &Path) -> Result<(), LpmError> {
        let source = self.resolve_path(source)?;
        let destination = self.resolve_path(destination)?;
        self.validate_parent(&source)?;
        self.validate_parent(&destination)?;
        std::fs::rename(&source, &destination).map_err(LpmError::Io)?;
        self.moves.push(MoveEntry {
            source,
            destination,
            destination_guard: None,
            #[cfg(unix)]
            source_permissions: None,
        });
        Ok(())
    }

    fn restore_file(
        &mut self,
        source: &Path,
        destination: &Path,
        destination_mode: Option<u32>,
    ) -> Result<(), LpmError> {
        let source = self.resolve_path(source)?;
        let destination = self.resolve_path(destination)?;
        self.validate_parent(&source)?;
        self.validate_parent(&destination)?;
        #[cfg(unix)]
        let source_permissions = regular_file_permissions(&source)?;
        std::fs::rename(&source, &destination).map_err(LpmError::Io)?;
        let destination_guard = Some(RemovalDestinationGuard::from_path(&destination)?);
        self.moves.push(MoveEntry {
            source,
            destination,
            destination_guard,
            #[cfg(unix)]
            source_permissions: Some(source_permissions),
        });
        #[cfg(unix)]
        if let Some(mode) = destination_mode {
            use std::os::unix::fs::PermissionsExt as _;

            apply_recorded_file_permissions(
                &self
                    .moves
                    .last()
                    .expect("restore move was recorded above")
                    .destination,
                std::fs::Permissions::from_mode(mode),
            )?;
            let entry = self
                .moves
                .last_mut()
                .expect("restore move was recorded above");
            if let Some(guard) = entry.destination_guard.as_mut() {
                guard.expected.mode = Some(
                    std::fs::symlink_metadata(&entry.destination)
                        .map_err(LpmError::Io)?
                        .permissions()
                        .mode(),
                );
            }
        }
        #[cfg(not(unix))]
        let _ = destination_mode;
        Ok(())
    }

    fn quarantine_path(&mut self, path: &Path) -> Result<(), LpmError> {
        let destination = self
            .quarantine
            .path()
            .join(format!("entry-{}", self.moves.len()));
        self.move_path(path, &destination)
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for RemovalTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut rollback_incomplete = false;
        for entry in self.moves.iter().rev() {
            if let Err(error) = self.validate_parent(&entry.source) {
                tracing::error!(
                    "source removal rollback: could not validate the restore parent for {}: {error}",
                    entry.source.display()
                );
                rollback_incomplete = true;
                continue;
            }
            if let Err(error) = self.validate_parent(&entry.destination) {
                tracing::error!(
                    "source removal rollback: could not validate the quarantine parent for {}: {error}",
                    entry.destination.display()
                );
                rollback_incomplete = true;
                continue;
            }
            match std::fs::symlink_metadata(&entry.source) {
                Ok(_) => {
                    tracing::warn!(
                        "source removal rollback: preserved concurrently created {}",
                        entry.source.display()
                    );
                    rollback_incomplete = true;
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::error!(
                        "source removal rollback: could not verify {} before restore; preserving it: {error}",
                        entry.source.display()
                    );
                    rollback_incomplete = true;
                    continue;
                }
            }
            if let Some(expected) = &entry.destination_guard {
                match expected.matches_path(&entry.destination) {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(
                            "source removal rollback: preserved concurrently changed {}",
                            entry.destination.display()
                        );
                        rollback_incomplete = true;
                        continue;
                    }
                    Err(error) => {
                        tracing::error!(
                            "source removal rollback: could not verify {} before restore; preserving it: {error}",
                            entry.destination.display()
                        );
                        rollback_incomplete = true;
                        continue;
                    }
                }
            }
            if let Err(error) = std::fs::rename(&entry.destination, &entry.source) {
                tracing::error!(
                    "source removal rollback: failed to restore {}: {error}",
                    entry.source.display()
                );
                rollback_incomplete = true;
                continue;
            }
            #[cfg(unix)]
            {
                if let Some(permissions) = &entry.source_permissions
                    && let Err(error) =
                        apply_recorded_file_permissions(&entry.source, permissions.clone())
                {
                    tracing::error!(
                        "source removal rollback: failed to restore the mode of {}: {error}",
                        entry.source.display()
                    );
                }
            }
        }
        if rollback_incomplete {
            self.quarantine.disable_cleanup(true);
            tracing::error!(
                "source removal rollback: retained recoverable content in {}",
                self.quarantine.path().display()
            );
        }
    }
}

struct SkillRemovalPlan {
    short: String,
    directory: Option<PlannedSkillDirectory>,
    editor_links: Vec<PlannedEditorLink>,
}

struct PlannedSkillDirectory {
    path: PathBuf,
    entries: Vec<(OsString, RemovalFileFingerprint)>,
}

enum EditorLinkFingerprint {
    File(RemovalFileFingerprint),
    Link(PathBuf),
}

struct PlannedEditorLink {
    path: PathBuf,
    fingerprint: EditorLinkFingerprint,
}

fn fingerprint_skill_directory(
    directory: &Path,
) -> Result<Vec<(OsString, RemovalFileFingerprint)>, LpmError> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(LpmError::Io)? {
        let entry = entry.map_err(LpmError::Io)?;
        let path = entry.path();
        let fingerprint = RemovalFileFingerprint::from_path(&path)?.ok_or_else(|| {
            LpmError::Registry(format!(
                "package skill entry disappeared during validation: {}",
                path.display()
            ))
        })?;
        entries.push((entry.file_name(), fingerprint));
    }
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn verify_skill_directory(plan: &PlannedSkillDirectory) -> Result<(), LpmError> {
    if !crate::commands::skills::package::is_materialized_directory(&plan.path)
        || fingerprint_skill_directory(&plan.path)? != plan.entries
    {
        return Err(LpmError::Registry(format!(
            "package skill directory changed during source removal: {}",
            plan.path.display()
        )));
    }
    Ok(())
}

fn fingerprint_editor_link(path: &Path) -> Result<Option<EditorLinkFingerprint>, LpmError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(LpmError::Io(error)),
    };
    if lpm_common::is_symlink_or_junction(&metadata) {
        return std::fs::read_link(path)
            .map(EditorLinkFingerprint::Link)
            .map(Some)
            .map_err(LpmError::Io);
    }
    if !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing Cursor package skill entry that is not a file: {}",
            path.display()
        )));
    }
    RemovalFileFingerprint::from_path(path)?.map_or_else(
        || {
            Err(LpmError::Registry(format!(
                "Cursor package skill entry disappeared during validation: {}",
                path.display()
            )))
        },
        |fingerprint| Ok(Some(EditorLinkFingerprint::File(fingerprint))),
    )
}

fn verify_editor_link(plan: &PlannedEditorLink) -> Result<(), LpmError> {
    let matches = match (&plan.fingerprint, fingerprint_editor_link(&plan.path)?) {
        (EditorLinkFingerprint::File(expected), Some(EditorLinkFingerprint::File(current))) => {
            expected == &current
        }
        (EditorLinkFingerprint::Link(expected), Some(EditorLinkFingerprint::Link(current))) => {
            expected == &current
        }
        _ => false,
    };
    if !matches {
        return Err(LpmError::Registry(format!(
            "Cursor package skill entry changed during source removal: {}",
            plan.path.display()
        )));
    }
    Ok(())
}

fn contained_real_directory(
    canonical_project: &Path,
    path: &Path,
    label: &str,
) -> Result<bool, LpmError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(LpmError::Io(error)),
    };
    if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_dir() {
        return Err(LpmError::Registry(format!(
            "refusing {label} that is not a real directory: {}",
            path.display()
        )));
    }
    let canonical = path.canonicalize().map_err(LpmError::Io)?;
    if !canonical.starts_with(canonical_project) {
        return Err(LpmError::Registry(format!(
            "refusing {label} outside the project: {}",
            path.display()
        )));
    }
    Ok(true)
}

fn plan_skill_removal(
    project_dir: &Path,
    canonical_project: &Path,
    package_key: &str,
    recorded_short: Option<&str>,
) -> Result<Option<SkillRemovalPlan>, LpmError> {
    let Some(recorded_short) = recorded_short else {
        return Ok(None);
    };
    let expected_short = package_key
        .strip_prefix("@lpm.dev/")
        .and_then(|_| lpm_common::PackageName::parse(package_key).ok())
        .map(|package| package.short());
    if expected_short.as_deref() != Some(recorded_short) {
        return Err(LpmError::Registry(format!(
            "source state skill identity '{recorded_short}' does not match package '{package_key}'"
        )));
    }

    let skills_root = project_dir.join(".lpm/skills");
    let mut skill_names = Vec::new();
    let directory = if contained_real_directory(
        canonical_project,
        &skills_root,
        "package skill root",
    )? {
        let directory = skills_root.join(recorded_short);
        if contained_real_directory(canonical_project, &directory, "package skill directory")? {
            if !crate::commands::skills::package::is_materialized_directory(&directory) {
                return Err(LpmError::Registry(format!(
                    "refusing package skill directory without complete materialization provenance: {}",
                    directory.display()
                )));
            }
            skill_names = crate::commands::skills::package::materialized_skill_names(&directory)
                .ok_or_else(|| {
                    LpmError::Registry(format!(
                        "package skill directory changed during validation: {}",
                        directory.display()
                    ))
                })?;
            let entries = fingerprint_skill_directory(&directory)?;
            Some(PlannedSkillDirectory {
                path: directory,
                entries,
            })
        } else {
            None
        }
    } else {
        None
    };

    let mut editor_links = Vec::new();
    let cursor_root = project_dir.join(".cursor");
    if contained_real_directory(canonical_project, &cursor_root, "Cursor state directory")? {
        let rules = cursor_root.join("rules");
        if contained_real_directory(canonical_project, &rules, "Cursor rules directory")? {
            editor_links.reserve(skill_names.len());
            for skill_name in &skill_names {
                let path = rules.join(format!("{recorded_short}--{skill_name}.md"));
                if let Some(fingerprint) = fingerprint_editor_link(&path)? {
                    editor_links.push(PlannedEditorLink { path, fingerprint });
                }
            }
        }
    }

    Ok(Some(SkillRemovalPlan {
        short: recorded_short.to_string(),
        directory,
        editor_links,
    }))
}

fn validate_file_record(
    project_dir: &Path,
    package_key: &str,
    manifest_path: &Path,
    file: &AddedSourceFile,
) -> Result<Option<PathBuf>, LpmError> {
    match file.action {
        None if file.installed_digest.is_none()
            && file.backup_path.is_none()
            && file.backup_digest.is_none()
            && file.backup_mode.is_none() =>
        {
            Ok(None)
        }
        None => Err(LpmError::Registry(format!(
            "source state for '{}' has incomplete file provenance",
            manifest_path.display()
        ))),
        Some(AddedSourceFileAction::Create) => {
            if file.installed_digest.is_none()
                || file.backup_path.is_some()
                || file.backup_digest.is_some()
                || file.backup_mode.is_some()
            {
                return Err(LpmError::Registry(format!(
                    "source state for '{}' has invalid create provenance",
                    manifest_path.display()
                )));
            }
            Ok(None)
        }
        Some(AddedSourceFileAction::Overwrite) => {
            if file.backup_mode.is_some_and(|mode| mode & !0o7777 != 0) {
                return Err(LpmError::Registry(format!(
                    "source state for '{}' has an invalid backup mode",
                    manifest_path.display()
                )));
            }
            if file.installed_digest.is_none() {
                return Err(LpmError::Registry(format!(
                    "source state for '{}' has no installed integrity",
                    manifest_path.display()
                )));
            }
            let recorded_backup = file.backup_path.as_deref().ok_or_else(|| {
                LpmError::Registry(format!(
                    "source state for '{}' has no overwrite backup",
                    manifest_path.display()
                ))
            })?;
            let relative_backup = crate::added_sources_state::validate_recorded_backup_path(
                package_key,
                manifest_path,
                recorded_backup,
            )?;
            crate::added_sources_state::validate_existing_backup(
                project_dir,
                &relative_backup,
                file.backup_digest.as_deref(),
            )
            .map(Some)
        }
    }
}

struct FileRemovalPlan {
    removals: Vec<PlannedFileRemoval>,
    backup_mutations: Vec<PlannedBackupMutation>,
    retained: AddedSourceRecord,
    preserved: Vec<String>,
}

fn plan_file_removals(
    project_dir: &Path,
    canonical_project: &Path,
    package_key: &str,
    remaining_state: &mut AddedSourcesState,
    record: &AddedSourceRecord,
) -> Result<FileRemovalPlan, LpmError> {
    let target_paths: HashSet<&Path> = record.files.keys().map(PathBuf::as_path).collect();
    let mut shared_paths = HashSet::with_capacity(record.files.len());
    let mut managed_digests = HashSet::with_capacity(record.files.len());
    let mut successors: HashMap<(&Path, &str), Vec<String>> =
        HashMap::with_capacity(record.files.len());
    for (candidate_package, candidate_record) in &remaining_state.packages {
        for (path, file) in &candidate_record.files {
            if !target_paths.contains(path.as_path()) {
                continue;
            }
            shared_paths.insert(path.as_path());
            if let Some(digest) = file.installed_digest.as_deref() {
                managed_digests.insert((path.as_path(), digest));
            }
            if file.action == Some(AddedSourceFileAction::Overwrite)
                && let Some(backup_digest) = file.backup_digest.as_deref()
            {
                successors
                    .entry((path.as_path(), backup_digest))
                    .or_default()
                    .push(candidate_package.clone());
            }
        }
    }
    let mut removals = Vec::with_capacity(record.files.len());
    let mut backup_mutations = Vec::new();
    let mut transfers = Vec::new();
    let mut retained = AddedSourceRecord::default();
    let mut preserved = Vec::new();

    for (manifest_path, file) in &record.files {
        let destination = crate::added_sources_state::resolve_tracked_manifest_path_from_root(
            canonical_project,
            manifest_path,
        )?;
        let backup = validate_file_record(project_dir, package_key, manifest_path, file)?;
        let destination_state = PlannedDestinationState::from_path(&destination)?;
        let exists = matches!(destination_state, PlannedDestinationState::File(_));
        let shared = shared_paths.contains(manifest_path.as_path());

        if file.action.is_none() {
            if exists {
                retained.files.insert(manifest_path.clone(), file.clone());
                preserved.push(crate::added_sources_state::display_manifest_path(
                    manifest_path,
                ));
            }
            continue;
        }

        let action = file.action.expect("validated above");
        let installed_digest = file.installed_digest.as_deref().expect("validated above");
        if let Some(candidate_packages) =
            successors.get(&(manifest_path.as_path(), installed_digest))
        {
            if candidate_packages.len() != 1 {
                return Err(LpmError::Registry(format!(
                    "source state has an ambiguous overwrite chain for '{}'",
                    manifest_path.display()
                )));
            }
            let candidate_package = &candidate_packages[0];
            let candidate_file = &remaining_state
                .packages
                .get(candidate_package)
                .and_then(|record| record.files.get(manifest_path))
                .expect("successor index references an existing file owner");
            let candidate_backup = validate_file_record(
                project_dir,
                candidate_package,
                manifest_path,
                candidate_file,
            )?
            .expect("successor index contains overwrite owners only");
            let candidate_backup_fingerprint =
                RemovalFileFingerprint::from_path(&candidate_backup)?.ok_or_else(|| {
                    LpmError::Registry(format!(
                        "source overwrite backup disappeared during planning: {}",
                        candidate_backup.display()
                    ))
                })?;

            match action {
                AddedSourceFileAction::Create => {
                    backup_mutations.push(PlannedBackupMutation::Delete {
                        path: candidate_backup,
                        expected: candidate_backup_fingerprint,
                    });
                    transfers.push((candidate_package.clone(), manifest_path.clone(), None));
                }
                AddedSourceFileAction::Overwrite => {
                    let source = backup.expect("validated overwrite backup");
                    let expected_source =
                        RemovalFileFingerprint::from_path(&source)?.ok_or_else(|| {
                            LpmError::Registry(format!(
                                "source overwrite backup disappeared during planning: {}",
                                source.display()
                            ))
                        })?;
                    backup_mutations.push(PlannedBackupMutation::Promote {
                        source,
                        expected_source,
                        destination: candidate_backup,
                        expected_destination: candidate_backup_fingerprint,
                    });
                    transfers.push((
                        candidate_package.clone(),
                        manifest_path.clone(),
                        Some((
                            file.backup_digest
                                .clone()
                                .expect("validated overwrite backup digest"),
                            file.backup_mode,
                        )),
                    ));
                }
            }
            if exists {
                preserved.push(crate::added_sources_state::display_manifest_path(
                    manifest_path,
                ));
            }
            continue;
        }

        if shared && action == AddedSourceFileAction::Create {
            if exists {
                preserved.push(crate::added_sources_state::display_manifest_path(
                    manifest_path,
                ));
            }
            continue;
        }

        let current_matches = match destination_state {
            PlannedDestinationState::File(fingerprint) => {
                fingerprint.content_digest() == installed_digest
            }
            PlannedDestinationState::Missing => false,
        };
        if exists && !current_matches {
            retained.files.insert(manifest_path.clone(), file.clone());
            preserved.push(crate::added_sources_state::display_manifest_path(
                manifest_path,
            ));
            continue;
        }
        if shared && action == AddedSourceFileAction::Overwrite {
            let backup_digest = file.backup_digest.as_deref().expect("validated above");
            if !current_matches
                || !managed_digests.contains(&(manifest_path.as_path(), backup_digest))
            {
                retained.files.insert(manifest_path.clone(), file.clone());
                if exists {
                    preserved.push(crate::added_sources_state::display_manifest_path(
                        manifest_path,
                    ));
                }
                continue;
            }
        }

        match action {
            AddedSourceFileAction::Create if exists => removals.push(PlannedFileRemoval {
                manifest_path: manifest_path.clone(),
                destination,
                expected_destination: destination_state,
                operation: FileRemoval::Delete,
            }),
            AddedSourceFileAction::Create => {}
            AddedSourceFileAction::Overwrite => removals.push(PlannedFileRemoval {
                manifest_path: manifest_path.clone(),
                destination,
                expected_destination: destination_state,
                operation: FileRemoval::Restore {
                    backup: backup.expect("validated overwrite backup"),
                    original_mode: file.backup_mode,
                },
            }),
        }
    }

    drop(successors);
    drop(managed_digests);
    drop(shared_paths);
    for (owner, manifest_path, inherited_backup) in transfers {
        let file = remaining_state
            .packages
            .get_mut(&owner)
            .and_then(|record| record.files.get_mut(&manifest_path))
            .expect("planned provenance transfer references an existing owner");
        match inherited_backup {
            Some((backup_digest, backup_mode)) => {
                file.backup_digest = Some(backup_digest);
                file.backup_mode = backup_mode;
            }
            None => {
                file.action = Some(AddedSourceFileAction::Create);
                file.backup_path = None;
                file.backup_digest = None;
                file.backup_mode = None;
            }
        }
    }

    Ok(FileRemovalPlan {
        removals,
        backup_mutations,
        retained,
        preserved,
    })
}

fn apply_planned_file_removal(
    transaction: &mut RemovalTransaction,
    canonical_project: &Path,
    planned: PlannedFileRemoval,
) -> Result<String, LpmError> {
    let current_destination = crate::added_sources_state::resolve_tracked_manifest_path_from_root(
        canonical_project,
        &planned.manifest_path,
    )?;
    if current_destination != planned.destination
        || !planned
            .expected_destination
            .matches_path(&planned.destination)?
    {
        return Err(LpmError::Registry(format!(
            "tracked source path changed during removal: {}",
            planned.manifest_path.display()
        )));
    }
    match planned.operation {
        FileRemoval::Delete => transaction.quarantine_path(&planned.destination)?,
        FileRemoval::Restore {
            backup,
            original_mode,
        } => {
            if matches!(
                planned.expected_destination,
                PlannedDestinationState::File(_)
            ) {
                transaction.quarantine_path(&planned.destination)?;
            }
            transaction.restore_file(&backup, &planned.destination, original_mode)?;
        }
    }
    Ok(crate::added_sources_state::display_manifest_path(
        &planned.manifest_path,
    ))
}

fn plan_owned_directory_cleanup(
    canonical_project: &Path,
    record: &AddedSourceRecord,
    remaining_state: &mut AddedSourcesState,
    removable_files: &HashSet<PathBuf>,
) -> Result<Vec<PathBuf>, LpmError> {
    let still_owned: HashSet<PathBuf> = remaining_state
        .packages
        .values()
        .flat_map(|candidate| candidate.created_directories.iter().cloned())
        .collect();
    let tracked_ancestors = crate::added_sources_state::tracked_file_ancestor_directories(
        record.files.keys().map(PathBuf::as_path),
    );
    let removable_ancestors = crate::added_sources_state::tracked_file_ancestor_directories(
        removable_files.iter().map(PathBuf::as_path),
    );
    let mut descendant_owners = HashMap::<PathBuf, String>::new();
    for (package, candidate) in &remaining_state.packages {
        for ancestor in crate::added_sources_state::tracked_file_ancestor_directories(
            candidate.files.keys().map(PathBuf::as_path),
        ) {
            descendant_owners
                .entry(ancestor)
                .or_insert_with(|| package.clone());
        }
    }
    let mut directories = Vec::with_capacity(record.created_directories.len());
    for directory in &record.created_directories {
        if still_owned.contains(directory) {
            continue;
        }
        if !tracked_ancestors.contains(directory) {
            return Err(LpmError::Registry(format!(
                "added-source owned directory '{}' is not an ancestor of a tracked file",
                directory.display()
            )));
        }
        crate::added_sources_state::resolve_tracked_directory_path_from_root(
            canonical_project,
            directory,
        )?;
        if let Some(owner) = descendant_owners.get(directory) {
            remaining_state
                .packages
                .get_mut(owner)
                .expect("descendant owner was indexed above")
                .created_directories
                .insert(directory.clone());
        } else if removable_ancestors.contains(directory) {
            directories.push(directory.clone());
        }
    }
    validate_owned_directory_tree(canonical_project, &owned_directory_tree(&directories)?)?;
    Ok(directories)
}

#[derive(Default)]
struct OwnedDirectoryTree {
    nodes: Vec<OwnedDirectoryNode>,
    roots: Vec<usize>,
}

struct OwnedDirectoryNode {
    relative: PathBuf,
    name: OsString,
    parent: Option<usize>,
    children: Vec<usize>,
    owned: bool,
    removed_security: Option<DirectorySecurity>,
}

#[cfg(unix)]
struct DirectorySecurity {
    mode: u32,
    acl: UnixDirectoryAcl,
}

#[cfg(target_os = "linux")]
struct UnixDirectoryAcl {
    access: Option<Vec<u8>>,
    default: Option<Vec<u8>>,
}

#[cfg(target_os = "macos")]
struct UnixDirectoryAcl(Option<Vec<u8>>);

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
struct UnixDirectoryAcl;

#[cfg(windows)]
struct DirectorySecurity {
    dacl: windows_directory_security::DirectoryDacl,
}

#[cfg(not(any(unix, windows)))]
struct DirectorySecurity;

pub(crate) struct OwnedDirectoryCleanup {
    removed: usize,
    rollback: Option<OwnedDirectoryRollback>,
}

struct OwnedDirectoryRollback {
    canonical_project: PathBuf,
    tree: OwnedDirectoryTree,
}

impl OwnedDirectoryCleanup {
    pub(crate) fn removed(&self) -> usize {
        self.removed
    }

    pub(crate) fn stage_in(mut self, transaction: &mut crate::manifest_tx::ManifestTransaction) {
        let rollback = self
            .rollback
            .take()
            .expect("active directory cleanup owns rollback state");
        transaction.on_rollback(move || rollback.restore_best_effort());
    }

    pub(crate) fn commit(mut self) {
        self.rollback.take();
    }
}

impl Drop for OwnedDirectoryCleanup {
    fn drop(&mut self) {
        if let Some(rollback) = self.rollback.take() {
            rollback.restore_best_effort();
        }
    }
}

impl OwnedDirectoryRollback {
    fn restore(&self) -> Result<(), LpmError> {
        let root = open_removal_root_directory(&self.canonical_project)?;
        restore_pruned_directories(&root, &self.tree)
    }

    fn restore_best_effort(self) {
        if let Err(error) = self.restore() {
            tracing::error!("owned-directory rollback was incomplete: {error}");
        }
    }
}

fn owned_directory_tree(directories: &[PathBuf]) -> Result<OwnedDirectoryTree, LpmError> {
    let mut tree = OwnedDirectoryTree::default();
    let mut indices = HashMap::<PathBuf, usize>::new();
    for directory in directories {
        let mut relative = PathBuf::new();
        let mut parent = None;
        for component in directory.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(LpmError::Registry(format!(
                    "source removal directory path is unsafe: {}",
                    directory.display()
                )));
            };
            relative.push(name);
            let index = if let Some(&index) = indices.get(&relative) {
                index
            } else {
                let index = tree.nodes.len();
                tree.nodes.push(OwnedDirectoryNode {
                    relative: relative.clone(),
                    name: name.to_os_string(),
                    parent,
                    children: Vec::new(),
                    owned: false,
                    removed_security: None,
                });
                if let Some(parent) = parent {
                    tree.nodes[parent].children.push(index);
                } else {
                    tree.roots.push(index);
                }
                indices.insert(relative.clone(), index);
                index
            };
            parent = Some(index);
        }
        let Some(index) = parent else {
            return Err(LpmError::Registry(
                "source removal directory path is empty".to_string(),
            ));
        };
        tree.nodes[index].owned = true;
    }
    let names = tree
        .nodes
        .iter()
        .map(|node| node.name.clone())
        .collect::<Vec<_>>();
    tree.roots
        .sort_unstable_by(|left, right| names[*left].cmp(&names[*right]));
    for node in &mut tree.nodes {
        node.children
            .sort_unstable_by(|left, right| names[*left].cmp(&names[*right]));
    }
    Ok(tree)
}

fn validate_owned_directory_tree(
    canonical_project: &Path,
    tree: &OwnedDirectoryTree,
) -> Result<(), LpmError> {
    let root = open_removal_root_directory(canonical_project)?;
    validate_owned_directory_children(&root, tree)
}

fn validate_owned_directory_children(
    root: &Dir,
    tree: &OwnedDirectoryTree,
) -> Result<(), LpmError> {
    for &root_index in &tree.roots {
        let Some(mut current) = open_owned_directory_child(root, &tree.nodes[root_index])? else {
            continue;
        };
        let mut skipped_depth = 0usize;
        for operation in owned_directory_traversal(tree, root_index) {
            if skipped_depth != 0 {
                match operation {
                    OwnedDirectoryTraversal::Down(_) => skipped_depth += 1,
                    OwnedDirectoryTraversal::Up(_) => skipped_depth -= 1,
                }
                continue;
            }
            match operation {
                OwnedDirectoryTraversal::Down(child) => {
                    let Some(opened) = open_owned_directory_child(&current, &tree.nodes[child])?
                    else {
                        skipped_depth = 1;
                        continue;
                    };
                    current = opened;
                }
                OwnedDirectoryTraversal::Up(_) => {
                    current = current
                        .open_parent_dir(cap_std::ambient_authority())
                        .map_err(LpmError::Io)?;
                }
            }
        }
    }
    Ok(())
}

fn open_owned_directory_child(
    parent: &Dir,
    node: &OwnedDirectoryNode,
) -> Result<Option<Dir>, LpmError> {
    let child = match open_owned_directory_component(parent, &node.name) {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LpmError::Registry(format!(
                "added-source owned directory is linked or not a directory: {}: {error}",
                node.relative.display()
            )));
        }
    };
    let metadata = child.dir_metadata().map_err(LpmError::Io)?;
    if !metadata.is_dir() || cap_metadata_is_link_or_reparse(&metadata) {
        return Err(LpmError::Registry(format!(
            "added-source owned directory is linked or not a directory: {}",
            node.relative.display()
        )));
    }
    Ok(Some(child))
}

#[cfg(not(windows))]
fn open_owned_directory_component(parent: &Dir, name: &std::ffi::OsStr) -> std::io::Result<Dir> {
    #[cfg(test)]
    OWNED_DIRECTORY_COMPONENT_OPENS.with(|opens| opens.set(opens.get() + 1));
    parent.open_dir_nofollow(name)
}

#[cfg(windows)]
fn open_owned_directory_component(parent: &Dir, name: &std::ffi::OsStr) -> std::io::Result<Dir> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsMaybeDirExt as _};
    use cap_std::fs::{OpenOptions, OpenOptionsExt as _};
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    #[cfg(test)]
    OWNED_DIRECTORY_COMPONENT_OPENS.with(|opens| opens.set(opens.get() + 1));
    let mut options = OpenOptions::new();
    options
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    parent
        .open_with(name, &options)
        .map(|file| Dir::from_std_file(file.into_std()))
}

#[cfg(test)]
thread_local! {
    static OWNED_DIRECTORY_COMPONENT_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy)]
enum OwnedDirectoryTraversal {
    Down(usize),
    Up(usize),
}

fn owned_directory_traversal(
    tree: &OwnedDirectoryTree,
    root_index: usize,
) -> Vec<OwnedDirectoryTraversal> {
    let mut traversal = Vec::with_capacity(tree.nodes[root_index].children.len().saturating_mul(2));
    let mut pending = vec![(root_index, 0usize)];
    while let Some((index, next_child)) = pending.last_mut() {
        if let Some(&child) = tree.nodes[*index].children.get(*next_child) {
            *next_child += 1;
            traversal.push(OwnedDirectoryTraversal::Down(child));
            pending.push((child, 0));
        } else {
            let (completed, _) = pending.pop().expect("pending traversal frame");
            if !pending.is_empty() {
                traversal.push(OwnedDirectoryTraversal::Up(completed));
            }
        }
    }
    traversal
}

pub(crate) fn prune_owned_empty_directories(
    canonical_project: &Path,
    directories: Vec<PathBuf>,
) -> Result<OwnedDirectoryCleanup, LpmError> {
    prune_owned_empty_directories_with(
        canonical_project,
        directories,
        |_parent, _name, _directory| Ok(()),
        |_| {},
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PruneDirectoryOperation {
    Quarantine,
    SecuritySnapshot,
    StagedDirectoryDelete,
    RestoreHandleClone,
    PrivateDirectoryDelete,
}

fn prune_owned_empty_directories_with(
    canonical_project: &Path,
    directories: Vec<PathBuf>,
    mut remove_directory: impl FnMut(&Dir, &std::ffi::OsStr, &Path) -> std::io::Result<()>,
    on_restore_operation: impl FnMut(RestoreDirectoryOperation),
) -> Result<OwnedDirectoryCleanup, LpmError> {
    prune_owned_empty_directories_with_operations(
        canonical_project,
        directories,
        |operation, parent, name, directory| {
            if operation == PruneDirectoryOperation::Quarantine {
                remove_directory(parent, name, directory)
            } else {
                Ok(())
            }
        },
        on_restore_operation,
    )
}

fn prune_owned_empty_directories_with_operations(
    canonical_project: &Path,
    directories: Vec<PathBuf>,
    mut on_prune_operation: impl FnMut(
        PruneDirectoryOperation,
        &Dir,
        &std::ffi::OsStr,
        &Path,
    ) -> std::io::Result<()>,
    mut on_restore_operation: impl FnMut(RestoreDirectoryOperation),
) -> Result<OwnedDirectoryCleanup, LpmError> {
    let mut tree = owned_directory_tree(&directories)?;
    let root = open_removal_root_directory(canonical_project)?;
    validate_owned_directory_children(&root, &tree)?;
    match prune_owned_directory_children(&root, &mut tree, &mut on_prune_operation) {
        Ok(removed) => Ok(OwnedDirectoryCleanup {
            removed,
            rollback: Some(OwnedDirectoryRollback {
                canonical_project: canonical_project.to_path_buf(),
                tree,
            }),
        }),
        Err(error) => {
            restore_pruned_directories_with(&root, &tree, &mut on_restore_operation).map_err(
                |rollback_error| {
                    LpmError::Registry(format!(
                        "owned-directory cleanup failed ({error}) and its directory rollback was incomplete: {rollback_error}"
                    ))
                },
            )?;
            Err(LpmError::Registry(format!(
                "owned-directory cleanup failed and was rolled back: {error}"
            )))
        }
    }
}

fn prune_owned_directory_children(
    root: &Dir,
    tree: &mut OwnedDirectoryTree,
    on_operation: &mut impl FnMut(
        PruneDirectoryOperation,
        &Dir,
        &std::ffi::OsStr,
        &Path,
    ) -> std::io::Result<()>,
) -> Result<usize, LpmError> {
    let mut removed = 0;
    let mut parent_identities = vec![None; tree.nodes.len()];
    for root_index in tree.roots.clone() {
        let Some(mut current) = open_owned_directory_child(root, &tree.nodes[root_index])? else {
            continue;
        };
        let mut skipped_depth = 0usize;
        for operation in owned_directory_traversal(tree, root_index) {
            if skipped_depth != 0 {
                match operation {
                    OwnedDirectoryTraversal::Down(_) => skipped_depth += 1,
                    OwnedDirectoryTraversal::Up(_) => skipped_depth -= 1,
                }
                continue;
            }
            match operation {
                OwnedDirectoryTraversal::Down(child) => {
                    let parent_identity = directory_identity(&current).map_err(LpmError::Io)?;
                    let Some(opened) = open_owned_directory_child(&current, &tree.nodes[child])?
                    else {
                        skipped_depth = 1;
                        continue;
                    };
                    parent_identities[child] = Some(parent_identity);
                    current = opened;
                }
                OwnedDirectoryTraversal::Up(child) => {
                    let parent = current
                        .open_parent_dir(cap_std::ambient_authority())
                        .map_err(LpmError::Io)?;
                    if parent_identities[child].as_ref()
                        != Some(&directory_identity(&parent).map_err(LpmError::Io)?)
                    {
                        return Err(LpmError::Registry(format!(
                            "owned directory parent changed during cleanup: {}",
                            tree.nodes[child].relative.display()
                        )));
                    }
                    if quarantine_and_prune_owned_directory(
                        &parent,
                        current,
                        &mut tree.nodes[child],
                        on_operation,
                    )? {
                        removed += 1;
                    }
                    current = parent;
                }
            }
        }
        if quarantine_and_prune_owned_directory(
            root,
            current,
            &mut tree.nodes[root_index],
            on_operation,
        )? {
            removed += 1;
        }
    }
    Ok(removed)
}

fn quarantine_and_prune_owned_directory(
    parent: &Dir,
    opened: Dir,
    node: &mut OwnedDirectoryNode,
    on_operation: &mut impl FnMut(
        PruneDirectoryOperation,
        &Dir,
        &std::ffi::OsStr,
        &Path,
    ) -> std::io::Result<()>,
) -> Result<bool, LpmError> {
    if !node.owned {
        return Ok(false);
    }
    let expected_identity = directory_identity(&opened).map_err(LpmError::Io)?;
    let (private_name, private_directory) = crate::directory_transaction::create_private_directory(
        parent, "prune",
    )
    .map_err(|error| {
        LpmError::Registry(format!(
            "could not stage owned directory '{}': {error}",
            node.relative.display()
        ))
    })?;
    if let Err(error) = on_operation(
        PruneDirectoryOperation::Quarantine,
        parent,
        &node.name,
        &node.relative,
    ) {
        let failure = LpmError::Registry(format!(
            "could not prune owned directory '{}': {error}",
            node.relative.display()
        ));
        return Err(discard_private_prune_directory_after_failure(
            private_directory,
            node,
            failure,
        ));
    }
    if let Err(error) = parent.rename(
        &node.name,
        &private_directory,
        std::ffi::OsStr::new("directory"),
    ) {
        let cleanup = discard_private_prune_directory(private_directory, node);
        if error.kind() == std::io::ErrorKind::NotFound {
            cleanup?;
            return Ok(false);
        }
        let failure = LpmError::Registry(format!(
            "could not quarantine owned directory '{}': {error}",
            node.relative.display()
        ));
        return match cleanup {
            Ok(()) => Err(failure),
            Err(cleanup_error) => Err(LpmError::Registry(format!(
                "{failure}; discarding its private prune directory also failed: {cleanup_error}"
            ))),
        };
    }
    let quarantined = match crate::directory_transaction::open_directory_for_publication(
        &private_directory,
        std::ffi::OsStr::new("directory"),
    ) {
        Ok(directory) => directory,
        Err(error) => {
            drop(opened);
            restore_quarantined_owned_entry(parent, &private_name, private_directory, None, node)?;
            tracing::debug!(
                path = %node.relative.display(),
                "preserved a linked or non-directory replacement during owned-directory cleanup: {error}"
            );
            return Ok(false);
        }
    };
    let same_identity = directory_identity(&quarantined)
        .map(|identity| identity == expected_identity)
        .unwrap_or(false);
    let empty = quarantined
        .entries()
        .and_then(|mut entries| entries.next().transpose().map(|entry| entry.is_none()))
        .unwrap_or(false);
    if !same_identity || !empty {
        drop(opened);
        restore_quarantined_owned_entry(
            parent,
            &private_name,
            private_directory,
            Some(quarantined),
            node,
        )?;
        return Ok(false);
    }
    if let Err(error) = on_operation(
        PruneDirectoryOperation::SecuritySnapshot,
        parent,
        &node.name,
        &node.relative,
    ) {
        drop(opened);
        return Err(restore_owned_entry_after_prune_failure(
            parent,
            &private_name,
            private_directory,
            quarantined,
            node,
            LpmError::Registry(format!(
                "could not snapshot security for owned directory '{}': {error}",
                node.relative.display()
            )),
        ));
    }
    let security = match snapshot_directory_security(&quarantined) {
        Ok(security) => security,
        Err(error) => {
            drop(opened);
            return Err(restore_owned_entry_after_prune_failure(
                parent,
                &private_name,
                private_directory,
                quarantined,
                node,
                error,
            ));
        }
    };
    drop(opened);
    if let Err(error) = on_operation(
        PruneDirectoryOperation::StagedDirectoryDelete,
        parent,
        &node.name,
        &node.relative,
    ) {
        return Err(restore_owned_entry_after_prune_failure(
            parent,
            &private_name,
            private_directory,
            quarantined,
            node,
            LpmError::Registry(format!(
                "could not prune quarantined owned directory '{}': {error}",
                node.relative.display()
            )),
        ));
    }
    let restore_handle = match on_operation(
        PruneDirectoryOperation::RestoreHandleClone,
        parent,
        &node.name,
        &node.relative,
    )
    .and_then(|()| quarantined.try_clone())
    {
        Ok(handle) => handle,
        Err(error) => {
            return Err(restore_owned_entry_after_prune_failure(
                parent,
                &private_name,
                private_directory,
                quarantined,
                node,
                LpmError::Registry(format!(
                    "could not retain quarantined owned directory '{}': {error}",
                    node.relative.display()
                )),
            ));
        }
    };
    if let Err(error) = crate::directory_transaction::discard_private_directory(quarantined) {
        return Err(restore_owned_entry_after_prune_failure(
            parent,
            &private_name,
            private_directory,
            restore_handle,
            node,
            LpmError::Registry(format!(
                "could not prune quarantined owned directory '{}': {error}",
                node.relative.display()
            )),
        ));
    }
    drop(restore_handle);
    node.removed_security = Some(security);
    if let Err(error) = on_operation(
        PruneDirectoryOperation::PrivateDirectoryDelete,
        parent,
        &node.name,
        &node.relative,
    ) {
        let failure = LpmError::Registry(format!(
            "could not discard private prune directory for '{}': {error}",
            node.relative.display()
        ));
        return Err(discard_private_prune_directory_after_failure(
            private_directory,
            node,
            failure,
        ));
    }
    discard_private_prune_directory(private_directory, node)?;
    Ok(true)
}

fn discard_private_prune_directory(
    directory: Dir,
    node: &OwnedDirectoryNode,
) -> Result<(), LpmError> {
    crate::directory_transaction::discard_private_directory(directory).map_err(|error| {
        LpmError::Registry(format!(
            "could not discard private prune directory for '{}': {error}",
            node.relative.display()
        ))
    })
}

fn discard_private_prune_directory_after_failure(
    directory: Dir,
    node: &OwnedDirectoryNode,
    failure: LpmError,
) -> LpmError {
    match discard_private_prune_directory(directory, node) {
        Ok(()) => failure,
        Err(cleanup_error) => LpmError::Registry(format!(
            "{failure}; discarding its private prune directory also failed: {cleanup_error}"
        )),
    }
}

fn restore_owned_entry_after_prune_failure(
    parent: &Dir,
    private_name: &std::ffi::OsStr,
    private_directory: Dir,
    quarantined: Dir,
    node: &OwnedDirectoryNode,
    failure: LpmError,
) -> LpmError {
    match restore_quarantined_owned_entry(
        parent,
        private_name,
        private_directory,
        Some(quarantined),
        node,
    ) {
        Ok(()) => failure,
        Err(rollback_error) => LpmError::Registry(format!(
            "{failure}; restoring the quarantined owned directory also failed: {rollback_error}"
        )),
    }
}

fn restore_quarantined_owned_entry(
    parent: &Dir,
    private_name: &std::ffi::OsStr,
    private_directory: Dir,
    quarantined: Option<Dir>,
    node: &OwnedDirectoryNode,
) -> Result<(), LpmError> {
    let publication = if let Some(quarantined) = quarantined.as_ref() {
        crate::directory_transaction::publish_directory_noreplace(
            &private_directory,
            quarantined,
            std::ffi::OsStr::new("directory"),
            parent,
            &node.name,
        )
    } else {
        crate::directory_transaction::publish_entry_noreplace(
            &private_directory,
            std::ffi::OsStr::new("directory"),
            parent,
            &node.name,
        )
    };
    publication.map_err(|error| {
        LpmError::Registry(format!(
            "could not restore quarantined replacement for '{}': {error}",
            node.relative.display()
        ))
    })?;
    drop(quarantined);
    let _ = private_name;
    discard_private_prune_directory(private_directory, node)
}

#[derive(Clone, Copy)]
enum RestoreDirectoryOperation {
    Open,
    Create,
    BeforePublish,
}

fn restore_pruned_directories(root: &Dir, tree: &OwnedDirectoryTree) -> Result<(), LpmError> {
    restore_pruned_directories_with(root, tree, &mut |_| {})
}

fn restore_pruned_directories_with(
    root: &Dir,
    tree: &OwnedDirectoryTree,
    on_operation: &mut impl FnMut(RestoreDirectoryOperation),
) -> Result<(), LpmError> {
    let mut errors = Vec::new();
    let mut parent_identities = vec![None; tree.nodes.len()];
    for &root_index in &tree.roots {
        let Some(mut current) = restore_or_open_owned_directory(
            root,
            &tree.nodes[root_index],
            on_operation,
            &mut errors,
        ) else {
            continue;
        };
        let mut skipped_depth = 0usize;
        for operation in owned_directory_traversal(tree, root_index) {
            if skipped_depth != 0 {
                match operation {
                    OwnedDirectoryTraversal::Down(_) => skipped_depth += 1,
                    OwnedDirectoryTraversal::Up(_) => skipped_depth -= 1,
                }
                continue;
            }
            match operation {
                OwnedDirectoryTraversal::Down(child) => {
                    let parent_identity = match directory_identity(&current) {
                        Ok(identity) => identity,
                        Err(error) => {
                            errors.push(format!(
                                "could not identify {}: {error}",
                                tree.nodes[child].relative.display()
                            ));
                            skipped_depth = 1;
                            continue;
                        }
                    };
                    let Some(opened) = restore_or_open_owned_directory(
                        &current,
                        &tree.nodes[child],
                        on_operation,
                        &mut errors,
                    ) else {
                        skipped_depth = 1;
                        continue;
                    };
                    parent_identities[child] = Some(parent_identity);
                    current = opened;
                }
                OwnedDirectoryTraversal::Up(child) => {
                    debug_assert!(tree.nodes[child].parent.is_some());
                    let parent = match current.open_parent_dir(cap_std::ambient_authority()) {
                        Ok(parent) => parent,
                        Err(error) => {
                            errors.push(format!(
                                "could not ascend from {}: {error}",
                                tree.nodes[child].relative.display()
                            ));
                            break;
                        }
                    };
                    match directory_identity(&parent) {
                        Ok(identity) if parent_identities[child].as_ref() == Some(&identity) => {
                            current = parent;
                        }
                        Ok(_) => {
                            errors.push(format!(
                                "preserved a branch whose parent changed during rollback: {}",
                                tree.nodes[child].relative.display()
                            ));
                            break;
                        }
                        Err(error) => {
                            errors.push(format!(
                                "could not identify the parent of {}: {error}",
                                tree.nodes[child].relative.display()
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "owned-directory rollback was incomplete: {}",
            errors.join(", ")
        )))
    }
}

fn restore_or_open_owned_directory(
    parent: &Dir,
    node: &OwnedDirectoryNode,
    on_operation: &mut impl FnMut(RestoreDirectoryOperation),
    errors: &mut Vec<String>,
) -> Option<Dir> {
    if node.removed_security.is_some() {
        on_operation(RestoreDirectoryOperation::Open);
    }
    match open_owned_directory_component(parent, &node.name) {
        Ok(directory) => {
            if node.removed_security.is_some() {
                errors.push(format!(
                    "preserved concurrently recreated directory {}",
                    node.relative.display()
                ));
                None
            } else {
                Some(directory)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let Some(security) = node.removed_security.as_ref() else {
                errors.push(format!(
                    "could not open unpruned ancestor {}",
                    node.relative.display()
                ));
                return None;
            };
            on_operation(RestoreDirectoryOperation::Create);
            let (private_name, child) =
                match crate::directory_transaction::create_private_directory(parent, "restore") {
                    Ok(created) => created,
                    Err(error) => {
                        errors.push(format!(
                            "could not stage {}: {error}",
                            node.relative.display()
                        ));
                        return None;
                    }
                };
            if let Err(error) = restore_directory_security(&child, security) {
                errors.push(format!(
                    "could not restore security for {}: {error}",
                    node.relative.display()
                ));
                discard_private_restore_directory(child, &node.relative, errors);
                return None;
            }
            on_operation(RestoreDirectoryOperation::BeforePublish);
            if let Err(error) = crate::directory_transaction::publish_directory_noreplace(
                parent,
                &child,
                &private_name,
                parent,
                &node.name,
            ) {
                errors.push(format!(
                    "preserved concurrently recreated directory {}: {error}",
                    node.relative.display()
                ));
                discard_private_restore_directory(child, &node.relative, errors);
                None
            } else {
                Some(child)
            }
        }
        Err(error) => {
            errors.push(format!(
                "could not open {}: {error}",
                node.relative.display()
            ));
            None
        }
    }
}

fn discard_private_restore_directory(
    directory: Dir,
    display_path: &Path,
    errors: &mut Vec<String>,
) {
    if let Err(error) = crate::directory_transaction::discard_private_directory(directory) {
        errors.push(format!(
            "could not discard private rollback directory for {}: {error}",
            display_path.display()
        ));
    }
}

#[cfg(unix)]
fn snapshot_directory_security(directory: &Dir) -> Result<DirectorySecurity, LpmError> {
    use cap_std::fs::PermissionsExt as _;

    Ok(DirectorySecurity {
        mode: directory.dir_metadata()?.permissions().mode() & 0o7777,
        acl: snapshot_unix_directory_acl(directory)?,
    })
}

#[cfg(unix)]
fn restore_directory_security(
    directory: &Dir,
    security: &DirectorySecurity,
) -> Result<(), LpmError> {
    use cap_std::fs::PermissionsExt as _;

    directory
        .set_permissions(".", cap_std::fs::Permissions::from_mode(security.mode))
        .map_err(LpmError::Io)?;
    restore_unix_directory_acl(directory, &security.acl).map_err(LpmError::Io)
}

#[cfg(target_os = "linux")]
fn snapshot_unix_directory_acl(directory: &Dir) -> std::io::Result<UnixDirectoryAcl> {
    use std::os::fd::AsRawFd as _;

    let directory = open_linux_xattr_directory(directory)?;
    Ok(UnixDirectoryAcl {
        access: read_linux_xattr(directory.as_raw_fd(), c"system.posix_acl_access")?,
        default: read_linux_xattr(directory.as_raw_fd(), c"system.posix_acl_default")?,
    })
}

#[cfg(target_os = "linux")]
fn restore_unix_directory_acl(directory: &Dir, acl: &UnixDirectoryAcl) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let directory = open_linux_xattr_directory(directory)?;
    write_linux_xattr(
        directory.as_raw_fd(),
        c"system.posix_acl_access",
        acl.access.as_deref(),
    )?;
    write_linux_xattr(
        directory.as_raw_fd(),
        c"system.posix_acl_default",
        acl.default.as_deref(),
    )
}

#[cfg(target_os = "linux")]
fn open_linux_xattr_directory(directory: &Dir) -> std::io::Result<std::os::fd::OwnedFd> {
    rustix::fs::openat(
        directory,
        c".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn read_linux_xattr(
    fd: std::os::fd::RawFd,
    name: &std::ffi::CStr,
) -> std::io::Result<Option<Vec<u8>>> {
    // SAFETY: `name` is NUL-terminated and the null buffer requests the exact value length.
    let length = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
    if length < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENODATA) {
            return Ok(None);
        }
        return Err(error);
    }
    let mut value = vec![0; length as usize];
    // SAFETY: `value` owns a writable allocation of the length returned by `fgetxattr`.
    let read =
        unsafe { libc::fgetxattr(fd, name.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    value.truncate(read as usize);
    Ok(Some(value))
}

#[cfg(target_os = "linux")]
fn write_linux_xattr(
    fd: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    value: Option<&[u8]>,
) -> std::io::Result<()> {
    let status = if let Some(value) = value {
        // SAFETY: `name` and `value` remain valid for the duration of the syscall.
        unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) }
    } else {
        // SAFETY: `name` is a valid NUL-terminated extended-attribute name.
        unsafe { libc::fremovexattr(fd, name.as_ptr()) }
    };
    if status == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if value.is_none() && error.raw_os_error() == Some(libc::ENODATA) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(target_os = "macos")]
fn snapshot_unix_directory_acl(directory: &Dir) -> std::io::Result<UnixDirectoryAcl> {
    use std::os::fd::AsRawFd as _;

    macos_directory_acl::snapshot(directory.as_raw_fd()).map(UnixDirectoryAcl)
}

#[cfg(target_os = "macos")]
fn restore_unix_directory_acl(directory: &Dir, acl: &UnixDirectoryAcl) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    macos_directory_acl::restore(directory.as_raw_fd(), acl.0.as_deref())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn snapshot_unix_directory_acl(_directory: &Dir) -> std::io::Result<UnixDirectoryAcl> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "full directory ACL snapshots are unavailable on this platform",
    ))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn restore_unix_directory_acl(_directory: &Dir, _acl: &UnixDirectoryAcl) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "full directory ACL restoration is unavailable on this platform",
    ))
}

#[cfg(target_os = "macos")]
mod macos_directory_acl {
    use std::ffi::c_void;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    struct Acl(*mut c_void);

    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: every `Acl` is constructed from an ACL API that transfers ownership.
            unsafe {
                let _ = acl_free(self.0);
            }
        }
    }

    pub(super) fn snapshot(fd: libc::c_int) -> std::io::Result<Option<Vec<u8>>> {
        // SAFETY: `fd` references an open directory for the duration of this call.
        let acl = Acl(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) });
        if acl.0.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(error);
        }
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl.0` is a valid ACL object and `entry` points to writable storage.
        if unsafe { acl_get_entry(acl.0, 0, &mut entry) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                return Ok(None);
            }
            return Err(error);
        }
        // SAFETY: `acl.0` remains owned and valid until this function returns.
        let size = unsafe { acl_size(acl.0) };
        if size < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut bytes = vec![0; size as usize];
        // SAFETY: the destination allocation has exactly the size reported by `acl_size`.
        let copied = unsafe { acl_copy_ext(bytes.as_mut_ptr().cast(), acl.0, size) };
        if copied < 0 {
            return Err(std::io::Error::last_os_error());
        }
        bytes.truncate(copied as usize);
        Ok(Some(bytes))
    }

    pub(super) fn restore(fd: libc::c_int, bytes: Option<&[u8]>) -> std::io::Result<()> {
        let Some(bytes) = bytes else {
            // SAFETY: `fd` references the recreated directory for the duration of this call.
            let status = unsafe { acl_delete_fd_np(fd, ACL_TYPE_EXTENDED) };
            if status == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            return if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTSUP)) {
                Ok(())
            } else {
                Err(error)
            };
        };
        // SAFETY: `bytes` contains the complete external representation returned by `acl_copy_ext`.
        let acl = Acl(unsafe { acl_copy_int(bytes.as_ptr().cast()) });
        if acl.0.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` and `acl.0` remain valid for the duration of the call.
        let status = unsafe { acl_set_fd_np(fd, acl.0, ACL_TYPE_EXTENDED) };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    unsafe extern "C" {
        fn acl_free(object: *mut c_void) -> libc::c_int;
        fn acl_delete_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> libc::c_int;
        fn acl_get_entry(
            acl: *mut c_void,
            entry_id: libc::c_int,
            entry: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut c_void;
        fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, acl_type: libc::c_int) -> libc::c_int;
        fn acl_size(acl: *mut c_void) -> libc::ssize_t;
        fn acl_copy_ext(
            buffer: *mut c_void,
            acl: *mut c_void,
            size: libc::ssize_t,
        ) -> libc::ssize_t;
        fn acl_copy_int(buffer: *const c_void) -> *mut c_void;
    }
}

#[cfg(windows)]
fn snapshot_directory_security(directory: &Dir) -> Result<DirectorySecurity, LpmError> {
    Ok(DirectorySecurity {
        dacl: windows_directory_security::snapshot(directory)?,
    })
}

#[cfg(windows)]
fn restore_directory_security(
    directory: &Dir,
    security: &DirectorySecurity,
) -> Result<(), LpmError> {
    windows_directory_security::restore(directory, &security.dacl).map_err(LpmError::Io)
}

#[cfg(not(any(unix, windows)))]
fn snapshot_directory_security(_directory: &Dir) -> Result<DirectorySecurity, LpmError> {
    Ok(DirectorySecurity)
}

#[cfg(not(any(unix, windows)))]
fn restore_directory_security(
    _directory: &Dir,
    _security: &DirectorySecurity,
) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(windows)]
mod windows_directory_security {
    use std::os::windows::io::AsRawHandle as _;
    use std::ptr::null_mut;

    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OsMetadataExt as _};
    use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt as _};
    use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE, LocalFree, RtlNtStatusToDosError};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    pub(super) struct DirectoryDacl {
        sddl: String,
        protected: bool,
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: the Win32 security APIs allocated this descriptor with `LocalAlloc`.
            unsafe {
                let _ = LocalFree(self.0.cast());
            }
        }
    }

    pub(super) fn snapshot(directory: &Dir) -> std::io::Result<DirectoryDacl> {
        let handle = open_security_handle(directory, READ_CONTROL)?;
        let mut descriptor = null_mut();
        // SAFETY: the handle remains open and the initialized output receives a LocalFree-owned
        // descriptor on success.
        let status = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        let descriptor = LocalSecurityDescriptor(descriptor);
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: `descriptor` owns a valid security descriptor and both outputs are initialized.
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut text = null_mut();
        let mut text_len = 0;
        // SAFETY: the descriptor remains valid and the output allocation is released below.
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut text_len,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful conversion returned `text_len` initialized UTF-16 code units.
        let sddl = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(text, text_len as usize)
        });
        // SAFETY: the conversion API allocated `text`; it is released exactly once here.
        unsafe {
            let _ = LocalFree(text.cast());
        }
        Ok(DirectoryDacl {
            sddl,
            protected: control & SE_DACL_PROTECTED != 0,
        })
    }

    pub(super) fn restore(directory: &Dir, dacl: &DirectoryDacl) -> std::io::Result<()> {
        let handle = open_security_handle(directory, READ_CONTROL | WRITE_DAC)?;
        apply_sddl(handle.as_raw_handle().cast(), &dacl.sddl, dacl.protected)
    }

    fn open_security_handle(
        directory: &Dir,
        access_mode: u32,
    ) -> std::io::Result<cap_std::fs::File> {
        let mut options = OpenOptions::new();
        options
            .access_mode(access_mode)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .follow(FollowSymlinks::No);
        let file = directory.open_with(".", &options)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other(
                "owned-directory rollback handle is linked or not a directory",
            ));
        }
        Ok(file)
    }

    fn apply_sddl(handle: HANDLE, sddl: &str, protected: bool) -> std::io::Result<()> {
        let encoded = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = null_mut();
        // SAFETY: `encoded` is NUL-terminated and the output becomes LocalFree-owned on success.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let descriptor = LocalSecurityDescriptor(descriptor);
        let security_information = DACL_SECURITY_INFORMATION
            | if protected {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
        // SAFETY: the handle has WRITE_DAC and the converted descriptor remains valid.
        let status = unsafe { NtSetSecurityObject(handle, security_information, descriptor.0) };
        if status == 0 {
            Ok(())
        } else {
            // SAFETY: `status` is the NTSTATUS produced by `NtSetSecurityObject`.
            let error = unsafe { RtlNtStatusToDosError(status) };
            Err(std::io::Error::from_raw_os_error(error as i32))
        }
    }

    #[cfg(test)]
    pub(super) fn apply_test_dacl(directory: &Dir) -> std::io::Result<()> {
        let handle = open_security_handle(directory, READ_CONTROL | WRITE_DAC)?;
        apply_sddl(
            handle.as_raw_handle().cast(),
            "D:(A;OICI;GR;;;WD)(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)",
            false,
        )
    }

    #[cfg(test)]
    pub(super) fn test_sddl(directory: &Dir) -> std::io::Result<String> {
        snapshot(directory).map(|snapshot| snapshot.sddl)
    }
}

#[cfg(unix)]
fn open_removal_root_directory(path: &Path) -> Result<Dir, LpmError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options
        .open(path)
        .map(Dir::from_std_file)
        .map_err(LpmError::Io)
}

#[cfg(windows)]
fn open_removal_root_directory(path: &Path) -> Result<Dir, LpmError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(LpmError::Io)?;
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(LpmError::Registry(format!(
            "source removal project root is linked or not a directory: {}",
            path.display()
        )));
    }
    Ok(Dir::from_std_file(file))
}

#[cfg(not(any(unix, windows)))]
fn open_removal_root_directory(path: &Path) -> Result<Dir, LpmError> {
    Dir::open_ambient_dir(path, cap_std::ambient_authority()).map_err(LpmError::Io)
}

#[cfg(not(windows))]
fn cap_metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
fn cap_metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;

    metadata.file_attributes() & 0x400 != 0
}

struct DependencyUpdatePlan {
    original: Vec<u8>,
    body: Vec<u8>,
    removed: Vec<String>,
}

fn plan_dependency_update(
    project_dir: &Path,
    state: &mut AddedSourcesState,
    record: &AddedSourceRecord,
) -> Result<Option<DependencyUpdatePlan>, LpmError> {
    let target_names: HashSet<&str> = record.dependencies.keys().map(String::as_str).collect();
    let mut owners: HashMap<&str, Vec<(&str, &crate::added_sources_state::AddedSourceDependency)>> =
        HashMap::with_capacity(target_names.len());
    for (package, candidate_record) in &state.packages {
        for (name, dependency) in &candidate_record.dependencies {
            if target_names.contains(name.as_str()) {
                owners
                    .entry(name.as_str())
                    .or_default()
                    .push((package.as_str(), dependency));
            }
        }
    }

    let mut exclusive = Vec::new();
    let mut replacements = Vec::new();
    for (name, dependency) in &record.dependencies {
        if !dependency.inserted {
            continue;
        }
        let candidates = owners.get(name.as_str());
        if let Some((replacement, _)) = candidates.and_then(|candidates| {
            candidates.iter().find(|(_, candidate)| {
                candidate.spec == dependency.spec && candidate.section == dependency.section
            })
        }) {
            replacements.push(((*replacement).to_string(), name.clone()));
        } else if candidates.is_none() {
            exclusive.push((name, dependency));
        }
    }
    drop(owners);
    for (replacement, name) in replacements {
        state
            .packages
            .get_mut(&replacement)
            .and_then(|record| record.dependencies.get_mut(&name))
            .expect("replacement dependency was indexed above")
            .inserted = true;
    }
    if exclusive.is_empty() {
        return Ok(None);
    }

    let manifest_path = project_dir.join("package.json");
    let metadata = match std::fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(LpmError::Io(error)),
    };
    if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing package manifest that is not a regular file: {}",
            manifest_path.display()
        )));
    }
    let original =
        lpm_common::read_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|error| LpmError::Registry(format!("failed to read package.json: {error}")))?;
    let mut manifest: serde_json::Value = serde_json::from_slice(&original)
        .map_err(|error| LpmError::Registry(format!("failed to parse package.json: {error}")))?;
    let object = manifest
        .as_object_mut()
        .ok_or_else(|| LpmError::Registry("package.json root must be a JSON object".to_string()))?;
    let mut removed = Vec::new();
    for (name, dependency) in exclusive {
        let Some(section) = object
            .get_mut(&dependency.section)
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        if section.get(name).and_then(serde_json::Value::as_str) == Some(dependency.spec.as_str()) {
            section.remove(name);
            removed.push(name.clone());
        }
    }
    if removed.is_empty() {
        return Ok(None);
    }
    let mut body = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        LpmError::Registry(format!("failed to serialize package.json: {error}"))
    })?;
    body.push(b'\n');
    Ok(Some(DependencyUpdatePlan {
        original,
        body,
        removed,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveResult<'a> {
    success: bool,
    package: &'a str,
    removed: &'a [String],
    #[serde(skip_serializing_if = "string_slice_is_empty")]
    preserved: &'a [String],
    #[serde(skip_serializing_if = "string_slice_is_empty")]
    dependencies_removed: &'a [String],
}

fn string_slice_is_empty(values: &&[String]) -> bool {
    values.is_empty()
}

struct LockedRemoveResult {
    removed: Vec<String>,
    preserved: Vec<String>,
    dependencies_removed: Vec<String>,
    cleaned_directories: usize,
}

impl LockedRemoveResult {
    fn empty() -> Self {
        Self {
            removed: Vec::new(),
            preserved: Vec::new(),
            dependencies_removed: Vec::new(),
            cleaned_directories: 0,
        }
    }
}

pub async fn run(project_dir: &Path, package: &str, json_output: bool) -> Result<(), LpmError> {
    let start = Instant::now();
    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Removing tracked source files for {}",
            install_ui::yellow(package)
        ));
    }
    let result = crate::commands::install::workspace_lockfile::scope_member_project_mutation(
        project_dir,
        run_locked(project_dir, package),
    )
    .await?;
    render_result(start, package, json_output, result)
}

async fn run_locked(project_dir: &Path, package: &str) -> Result<LockedRemoveResult, LpmError> {
    let (mut state, state_snapshot) =
        crate::added_sources_state::load_state_with_snapshot(project_dir)?;
    let package_key = manifest_lookup_keys(package)
        .into_iter()
        .find(|key| state.package(key).is_some());
    let Some(package_key) = package_key else {
        return Ok(LockedRemoveResult::empty());
    };
    let state_path = crate::added_sources_state::state_path(project_dir);
    let state_snapshot = state_snapshot.ok_or_else(|| {
        LpmError::Registry(format!(
            "added-source state disappeared while locating '{package_key}'"
        ))
    })?;
    let state_original = RemovalFileFingerprint::from_bytes(&state_snapshot);
    let mut manifest_transaction =
        crate::manifest_tx::ManifestTransaction::snapshot_install_state(&[], &[], &[]).map_err(
            |error| LpmError::Registry(format!("failed to snapshot source removal state: {error}")),
        )?;
    manifest_transaction
        .snapshot_path_with_bytes_if_unchanged(&state_path, state_snapshot)
        .map_err(|error| {
            LpmError::Registry(format!(
                "failed to snapshot added-source state '{}': {error}",
                state_path.display()
            ))
        })?;

    let record = state
        .take_package(&package_key)
        .expect("manifest key was found above");
    let canonical_project = project_dir.canonicalize().map_err(LpmError::Io)?;
    let FileRemovalPlan {
        removals: file_removals,
        backup_mutations,
        mut retained,
        preserved,
    } = plan_file_removals(
        project_dir,
        &canonical_project,
        &package_key,
        &mut state,
        &record,
    )?;
    let skill_plan = plan_skill_removal(
        project_dir,
        &canonical_project,
        &package_key,
        record.skill_package_short.as_deref(),
    )?;
    let dependency_plan = plan_dependency_update(project_dir, &mut state, &record)?;
    let manifest_path = project_dir.join("package.json");
    let install_hash = project_dir.join(".lpm/install-hash");
    let (manifest_body, manifest_original, dependencies_removed) =
        if let Some(dependency_plan) = dependency_plan {
            let original = RemovalFileFingerprint::from_bytes(&dependency_plan.original);
            manifest_transaction
                .snapshot_path_with_bytes_if_unchanged(&manifest_path, dependency_plan.original)
                .map_err(|error| {
                    LpmError::Registry(format!(
                        "failed to snapshot source removal manifest '{}': {error}",
                        manifest_path.display()
                    ))
                })?;
            manifest_transaction.invalidate_path_on_rollback(install_hash.clone());
            (
                Some(dependency_plan.body),
                Some(original),
                dependency_plan.removed,
            )
        } else {
            (None, None, Vec::new())
        };
    let removable_files: HashSet<PathBuf> = file_removals
        .iter()
        .map(|planned| planned.manifest_path.clone())
        .collect();
    if !retained.files.is_empty() {
        let retained_ancestors = crate::added_sources_state::tracked_file_ancestor_directories(
            retained.files.keys().map(PathBuf::as_path),
        );
        retained.created_directories = record
            .created_directories
            .iter()
            .filter(|directory| retained_ancestors.contains(*directory))
            .cloned()
            .collect();
        retained.dependencies.clear();
        retained.skill_package_short = None;
        state.packages.insert(package_key.clone(), retained);
    }
    let owned_directory_cleanup =
        plan_owned_directory_cleanup(&canonical_project, &record, &mut state, &removable_files)?;

    let mut removal_transaction = RemovalTransaction::new(project_dir)?;
    let editor_link_count = skill_plan
        .as_ref()
        .map_or(0, |plan| plan.editor_links.len());
    let mut removed = Vec::with_capacity(
        file_removals.len() + usize::from(skill_plan.is_some()) + editor_link_count,
    );

    for mutation in backup_mutations {
        match mutation {
            PlannedBackupMutation::Delete { path, expected } => {
                if !expected.matches_path(&path)? {
                    return Err(LpmError::Registry(format!(
                        "source overwrite backup changed during removal: {}",
                        path.display()
                    )));
                }
                removal_transaction.quarantine_path(&path)?;
            }
            PlannedBackupMutation::Promote {
                source,
                expected_source,
                destination,
                expected_destination,
            } => {
                if !expected_source.matches_path(&source)?
                    || !expected_destination.matches_path(&destination)?
                {
                    return Err(LpmError::Registry(
                        "source overwrite provenance changed during removal".to_string(),
                    ));
                }
                removal_transaction.quarantine_path(&destination)?;
                removal_transaction.move_path(&source, &destination)?;
            }
        }
    }

    for planned in file_removals {
        removed.push(apply_planned_file_removal(
            &mut removal_transaction,
            &canonical_project,
            planned,
        )?);
    }

    if let Some(skill_plan) = skill_plan {
        if let Some(directory) = skill_plan.directory {
            verify_skill_directory(&directory)?;
            removal_transaction.quarantine_path(&directory.path)?;
            removed.push(format!(".lpm/skills/{}/", skill_plan.short));
        }
        for editor_link in skill_plan.editor_links {
            verify_editor_link(&editor_link)?;
            removal_transaction.quarantine_path(&editor_link.path)?;
            let display = editor_link
                .path
                .strip_prefix(project_dir)
                .or_else(|_| editor_link.path.strip_prefix(&canonical_project))
                .unwrap_or(&editor_link.path);
            removed.push(crate::added_sources_state::display_manifest_path(display));
        }
    }
    if let Some(manifest_body) = manifest_body {
        if !manifest_original
            .expect("manifest body and original fingerprint are planned together")
            .matches_path(&manifest_path)?
        {
            return Err(LpmError::Registry(
                "package.json changed during source removal".to_string(),
            ));
        }
        manifest_transaction
            .restore_only_if_unchanged(&manifest_path, &manifest_body)
            .map_err(|error| {
                LpmError::Registry(format!(
                    "failed to guard source removal manifest '{}': {error}",
                    manifest_path.display()
                ))
            })?;
        lpm_common::write_file_atomic(&manifest_path, &manifest_body).map_err(LpmError::Io)?;
        match std::fs::remove_file(&install_hash) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(LpmError::Io(error)),
        }
    }
    if !state_original.matches_path(&state_path)? {
        return Err(LpmError::Registry(
            "added-source state changed during source removal".to_string(),
        ));
    }
    crate::added_sources_state::write_state(project_dir, &state)?;
    manifest_transaction
        .restore_only_if_current(&state_path)
        .map_err(|error| {
            LpmError::Registry(format!(
                "failed to guard added-source state '{}': {error}",
                state_path.display()
            ))
        })?;
    manifest_transaction
        .verify_guarded_paths()
        .map_err(|error| LpmError::Registry(error.to_string()))?;

    let directory_cleanup =
        prune_owned_empty_directories(&canonical_project, owned_directory_cleanup)?;
    let cleaned_directories = directory_cleanup.removed();

    manifest_transaction.commit();
    removal_transaction.commit();
    directory_cleanup.commit();
    Ok(LockedRemoveResult {
        removed,
        preserved,
        dependencies_removed,
        cleaned_directories,
    })
}

fn render_result(
    start: Instant,
    package: &str,
    json_output: bool,
    result: LockedRemoveResult,
) -> Result<(), LpmError> {
    let LockedRemoveResult {
        removed,
        preserved,
        dependencies_removed,
        cleaned_directories,
    } = result;
    if json_output {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer_pretty(
            &mut stdout,
            &RemoveResult {
                success: true,
                package,
                removed: &removed,
                preserved: &preserved,
                dependencies_removed: &dependencies_removed,
            },
        )
        .map_err(|error| {
            LpmError::Registry(format!("failed to serialize remove output: {error}"))
        })?;
        stdout.write_all(b"\n").map_err(LpmError::Io)?;
        return Ok(());
    }

    if removed.is_empty() && preserved.is_empty() && dependencies_removed.is_empty() {
        install_ui::warn_line(crate::install_ui::terminal_line!(
            "No tracked source files found for {}",
            install_ui::yellow(package)
        ));
        return Ok(());
    }
    for path in &removed {
        let path = lpm_common::sanitize_terminal_inline(path);
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::red("-"),
            install_ui::dim(&path)
        ));
    }
    for path in &preserved {
        let path = lpm_common::sanitize_terminal_inline(path);
        install_ui::warn_line(crate::install_ui::terminal_line!(
            "Preserved modified, unverified, or still-owned source file {}",
            install_ui::dim(&path)
        ));
    }
    if !dependencies_removed.is_empty() {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Removed {} source-owned dependencies",
            install_ui::green(&dependencies_removed.len().to_string())
        ));
    }
    if cleaned_directories > 0 {
        install_ui::done("Cleaned empty directories");
    }
    if removed.iter().any(|path| path.ends_with('/')) {
        install_ui::done("Removed package skill directory");
    }
    let duration = install_ui::format_duration(start.elapsed());
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Done · removed {} paths in {}",
        install_ui::green(&removed.len().to_string()),
        install_ui::green(&duration)
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_provenance_rejects_modes_outside_unix_permission_bits() {
        let project = tempfile::tempdir().unwrap();
        let manifest_path = PathBuf::from("Source.ts");
        let source = project.path().join("original.ts");
        std::fs::write(&source, b"original\n").unwrap();
        let backup_path =
            crate::added_sources_state::backup_path_for_file("source-pkg", &manifest_path);
        let backup =
            crate::added_sources_state::write_backup(project.path(), &backup_path, &source)
                .unwrap();
        let file = AddedSourceFile {
            source: Some(PathBuf::from("Source.ts")),
            installed_digest: Some(crate::added_sources_state::digest_bytes(b"installed\n")),
            action: Some(AddedSourceFileAction::Overwrite),
            backup_path: Some(backup_path),
            backup_digest: Some(backup.digest),
            backup_mode: Some(0o10000),
        };

        let error =
            validate_file_record(project.path(), "source-pkg", &manifest_path, &file).unwrap_err();

        assert!(error.to_string().contains("invalid backup mode"));
    }

    #[test]
    fn owned_directory_cleanup_rolls_back_partial_pruning_before_a_successful_retry() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("legacy/nested")).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            project.path().join("legacy/nested"),
            std::fs::Permissions::from_mode(0o711),
        )
        .unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        #[cfg(windows)]
        let original_dacl = {
            let root = open_removal_root_directory(&canonical_project).unwrap();
            let legacy = root.open_dir_nofollow("legacy").unwrap();
            let nested = legacy.open_dir_nofollow("nested").unwrap();
            windows_directory_security::apply_test_dacl(&nested).unwrap();
            windows_directory_security::test_sddl(&nested).unwrap()
        };
        let directories = vec![PathBuf::from("legacy"), PathBuf::from("legacy/nested")];

        let result = prune_owned_empty_directories_with(
            &canonical_project,
            directories.clone(),
            |_parent, _name, directory| {
                if directory == Path::new("legacy") {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                Ok(())
            },
            |_| {},
        );
        let error = match result {
            Err(error) => error,
            Ok(cleanup) => {
                cleanup.commit();
                panic!("injected prune failure unexpectedly succeeded");
            }
        };

        assert!(error.to_string().contains("was rolled back"));
        assert!(project.path().join("legacy/nested").is_dir());
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(project.path().join("legacy/nested"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o711
        );
        #[cfg(windows)]
        {
            let root = open_removal_root_directory(&canonical_project).unwrap();
            let legacy = root.open_dir_nofollow("legacy").unwrap();
            let nested = legacy.open_dir_nofollow("nested").unwrap();
            assert_eq!(
                windows_directory_security::test_sddl(&nested).unwrap(),
                original_dacl
            );
        }
        let cleanup = prune_owned_empty_directories(&canonical_project, directories).unwrap();
        assert_eq!(cleanup.removed(), 2);
        cleanup.commit();
        assert!(!project.path().join("legacy").exists());
    }

    #[test]
    fn owned_directory_cleanup_restores_siblings_when_security_snapshot_fails() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("root/a")).unwrap();
        std::fs::create_dir_all(project.path().join("root/z")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();

        let result = prune_owned_empty_directories_with_operations(
            &canonical_project,
            vec![PathBuf::from("root/a"), PathBuf::from("root/z")],
            |operation, _parent, _name, directory| {
                if operation == PruneDirectoryOperation::SecuritySnapshot
                    && directory == Path::new("root/z")
                {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                Ok(())
            },
            |_| {},
        );

        assert!(result.is_err());
        assert!(project.path().join("root/a").is_dir());
        assert!(project.path().join("root/z").is_dir());
        assert!(private_prune_paths(project.path().join("root")).is_empty());
    }

    #[test]
    fn owned_directory_cleanup_restores_content_added_before_staged_delete() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("legacy")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();

        let result = prune_owned_empty_directories_with_operations(
            &canonical_project,
            vec![PathBuf::from("legacy")],
            |operation, _parent, _name, _directory| {
                if operation == PruneDirectoryOperation::StagedDirectoryDelete {
                    let private = private_prune_paths(project.path())
                        .into_iter()
                        .next()
                        .expect("private prune directory");
                    std::fs::write(private.join("directory/late.txt"), b"late content\n")?;
                }
                Ok(())
            },
            |_| {},
        );

        assert!(result.is_err());
        assert_eq!(
            std::fs::read(project.path().join("legacy/late.txt")).unwrap(),
            b"late content\n"
        );
        assert!(private_prune_paths(project.path()).is_empty());
    }

    #[test]
    fn owned_directory_cleanup_restores_after_restore_handle_clone_fails() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("legacy")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();

        let result = prune_owned_empty_directories_with_operations(
            &canonical_project,
            vec![PathBuf::from("legacy")],
            |operation, _parent, _name, _directory| {
                if operation == PruneDirectoryOperation::RestoreHandleClone {
                    return Err(std::io::Error::other("injected handle clone failure"));
                }
                Ok(())
            },
            |_| {},
        );

        assert!(result.is_err());
        assert!(project.path().join("legacy").is_dir());
        assert!(private_prune_paths(project.path()).is_empty());
    }

    #[test]
    fn owned_directory_cleanup_restores_after_private_wrapper_cleanup_fails() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("legacy")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();

        let result = prune_owned_empty_directories_with_operations(
            &canonical_project,
            vec![PathBuf::from("legacy")],
            |operation, _parent, _name, _directory| {
                if operation == PruneDirectoryOperation::PrivateDirectoryDelete {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                Ok(())
            },
            |_| {},
        );

        assert!(result.is_err());
        assert!(project.path().join("legacy").is_dir());
        assert!(private_prune_paths(project.path()).is_empty());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn owned_directory_cleanup_preserves_a_replacement_private_wrapper() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("legacy")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let displaced = project.path().join("displaced-private-wrapper");
        let mut replacement_path = None;
        let mut replacement_identity = None;

        let cleanup = prune_owned_empty_directories_with_operations(
            &canonical_project,
            vec![PathBuf::from("legacy")],
            |operation, _parent, _name, _directory| {
                if operation == PruneDirectoryOperation::PrivateDirectoryDelete {
                    let private = private_prune_paths(project.path())
                        .into_iter()
                        .next()
                        .expect("private prune directory");
                    std::fs::rename(&private, &displaced)?;
                    std::fs::create_dir(&private)?;
                    replacement_identity = Some(test_directory_identity(&private));
                    replacement_path = Some(private);
                }
                Ok(())
            },
            |_| {},
        )
        .unwrap();

        let replacement_path = replacement_path.expect("replacement private wrapper path");
        assert_eq!(
            test_directory_identity(&replacement_path),
            replacement_identity.expect("replacement private wrapper identity")
        );
        assert!(!displaced.exists(), "original private wrapper was orphaned");
        cleanup.commit();
    }

    #[cfg(windows)]
    #[test]
    fn owned_directory_cleanup_prunes_an_empty_directory_on_windows() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("legacy")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();

        let cleanup =
            prune_owned_empty_directories(&canonical_project, vec![PathBuf::from("legacy")])
                .unwrap();

        assert_eq!(cleanup.removed(), 1);
        assert!(!project.path().join("legacy").exists());
        drop(cleanup);
        assert!(project.path().join("legacy").is_dir());
    }

    fn private_prune_paths(parent: impl AsRef<Path>) -> Vec<PathBuf> {
        std::fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".lpm-prune-")
            })
            .map(|entry| entry.path())
            .collect()
    }

    #[test]
    fn owned_directory_rollback_restores_a_deep_tree_in_one_traversal() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let mut directory = PathBuf::new();
        let mut directories = Vec::with_capacity(64);
        for index in 0..64 {
            directory.push(format!("level-{index}"));
            directories.push(directory.clone());
        }
        std::fs::create_dir_all(project.path().join(&directory)).unwrap();
        let mut opens = 0;
        let mut creates = 0;

        let result = prune_owned_empty_directories_with(
            &canonical_project,
            directories,
            |_parent, _name, directory| {
                if directory == Path::new("level-0") {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                Ok(())
            },
            |operation| match operation {
                RestoreDirectoryOperation::Open => opens += 1,
                RestoreDirectoryOperation::Create => creates += 1,
                RestoreDirectoryOperation::BeforePublish => {}
            },
        );

        let error = match result {
            Err(error) => error,
            Ok(cleanup) => {
                cleanup.commit();
                panic!("injected prune failure unexpectedly succeeded");
            }
        };
        assert_eq!(creates, 63);
        assert!(opens <= 128, "rollback performed {opens} directory opens");
        assert!(
            project.path().join(directory).is_dir(),
            "rollback error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn owned_directory_cleanup_uses_bounded_handles_for_a_deep_tree() {
        const HELPER_ENV: &str = "LPM_TEST_DEEP_OWNED_DIRECTORY_HANDLES";
        if std::env::var_os(HELPER_ENV).is_some() {
            let limit = libc::rlimit {
                rlim_cur: 32,
                rlim_max: 32,
            };
            // SAFETY: this isolated helper process intentionally lowers only
            // its own descriptor limit before creating any worker threads.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

            let project = tempfile::tempdir().unwrap();
            let canonical_project = project.path().canonicalize().unwrap();
            let mut deepest = PathBuf::new();
            let mut directories = Vec::with_capacity(128);
            for _ in 0..128 {
                deepest.push("d");
                directories.push(deepest.clone());
            }
            std::fs::create_dir_all(project.path().join(&deepest)).unwrap();

            let cleanup = prune_owned_empty_directories(&canonical_project, directories).unwrap();
            assert_eq!(cleanup.removed(), 128);
            drop(cleanup);
            assert!(project.path().join(deepest).is_dir());
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::remove::tests::owned_directory_cleanup_uses_bounded_handles_for_a_deep_tree",
                "--nocapture",
            ])
            .env(HELPER_ENV, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "bounded-handle helper failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn owned_directory_cleanup_opens_deep_paths_linearly() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let mut deepest = PathBuf::new();
        let mut directories = Vec::with_capacity(128);
        for _ in 0..128 {
            deepest.push("d");
            directories.push(deepest.clone());
        }
        std::fs::create_dir_all(project.path().join(&deepest)).unwrap();
        OWNED_DIRECTORY_COMPONENT_OPENS.with(|opens| opens.set(0));

        let cleanup = prune_owned_empty_directories(&canonical_project, directories).unwrap();
        drop(cleanup);
        let opens = OWNED_DIRECTORY_COMPONENT_OPENS.with(std::cell::Cell::get);

        assert!(
            opens <= 512,
            "deep prune and rollback performed {opens} component opens"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn owned_directory_prune_preserves_a_replacement_swapped_before_removal() {
        let project = tempfile::tempdir().unwrap();
        let nested = project.path().join("legacy/nested");
        let displaced = project.path().join("displaced-nested");
        std::fs::create_dir_all(&nested).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let mut replacement_identity = None;

        let cleanup = prune_owned_empty_directories_with(
            &canonical_project,
            vec![PathBuf::from("legacy/nested")],
            |_parent, _name, _| {
                std::fs::rename(&nested, &displaced)?;
                std::fs::create_dir(&nested)?;
                replacement_identity = Some(test_directory_identity(&nested));
                Ok(())
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(
            test_directory_identity(&nested),
            replacement_identity.expect("replacement directory identity"),
            "prune deleted the concurrently created replacement"
        );
        assert!(displaced.is_dir());
        cleanup.commit();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn owned_directory_rollback_restores_extended_acl() {
        let project = tempfile::tempdir().unwrap();
        let nested = project.path().join("legacy/nested");
        std::fs::create_dir_all(&nested).unwrap();
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&nested)
            .status()
            .unwrap();
        assert!(status.success(), "failed to apply the test ACL");
        let original_acl = macos_acl_text(&nested);
        let canonical_project = project.path().canonicalize().unwrap();

        let result = prune_owned_empty_directories_with(
            &canonical_project,
            vec![PathBuf::from("legacy"), PathBuf::from("legacy/nested")],
            |_parent, _name, directory| {
                if directory == Path::new("legacy") {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                Ok(())
            },
            |_| {},
        );

        assert!(result.is_err());
        assert_eq!(macos_acl_text(&nested), original_acl);
    }

    #[cfg(target_os = "macos")]
    fn macos_acl_text(path: &Path) -> String {
        let output = std::process::Command::new("ls")
            .args(["-lde"])
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success(), "failed to read the test ACL");
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .skip(1)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn owned_directory_rollback_preserves_a_concurrently_recreated_ancestor() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("legacy/nested")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let cleanup = prune_owned_empty_directories(
            &canonical_project,
            vec![PathBuf::from("legacy"), PathBuf::from("legacy/nested")],
        )
        .unwrap();
        let replacement = project.path().join("legacy");
        std::fs::create_dir(&replacement).unwrap();
        std::fs::write(replacement.join("replacement.txt"), b"replacement\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();

        drop(cleanup);

        assert!(replacement.join("replacement.txt").is_file());
        assert!(!replacement.join("nested").exists());
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&replacement)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
    }

    #[test]
    fn owned_directory_rollback_preserves_a_concurrently_recreated_leaf() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        let nested = project.path().join("legacy/nested");
        std::fs::create_dir_all(&nested).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o711)).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let cleanup =
            prune_owned_empty_directories(&canonical_project, vec![PathBuf::from("legacy/nested")])
                .unwrap();
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("replacement.txt"), b"replacement\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();

        drop(cleanup);

        assert!(nested.join("replacement.txt").is_file());
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn owned_directory_rollback_does_not_replace_a_directory_created_before_publish() {
        let project = tempfile::tempdir().unwrap();
        let branch = project.path().join("root/branch");
        std::fs::create_dir_all(&branch).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let mut replacement_created = false;
        let mut replacement_identity = None;

        let result = prune_owned_empty_directories_with(
            &canonical_project,
            vec![PathBuf::from("root"), PathBuf::from("root/branch")],
            |_parent, _name, directory| {
                if directory == Path::new("root") {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                Ok(())
            },
            |operation| {
                if matches!(operation, RestoreDirectoryOperation::BeforePublish)
                    && !replacement_created
                {
                    std::fs::create_dir(&branch).unwrap();
                    replacement_identity = Some(test_directory_identity(&branch));
                    replacement_created = true;
                }
            },
        );

        let error = match result {
            Err(error) => error,
            Ok(cleanup) => {
                cleanup.commit();
                panic!("injected prune failure unexpectedly succeeded");
            }
        };
        assert_eq!(
            test_directory_identity(&branch),
            replacement_identity.expect("replacement directory identity"),
            "rollback replaced the concurrently created empty directory: {error}"
        );
    }

    #[cfg(unix)]
    fn test_directory_identity(path: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = std::fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    }

    #[cfg(windows)]
    fn test_directory_identity(path: &Path) -> (Option<u32>, Option<u64>) {
        use std::os::windows::fs::MetadataExt as _;

        let metadata = std::fs::metadata(path).unwrap();
        (metadata.volume_serial_number(), metadata.file_index())
    }

    #[test]
    fn owned_directory_rollback_restores_siblings_after_a_recreated_branch() {
        let project = tempfile::tempdir().unwrap();
        let recreated = project.path().join("root/a");
        let restored = project.path().join("root/z");
        std::fs::create_dir_all(&recreated).unwrap();
        std::fs::create_dir_all(&restored).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let mut replacement_created = false;

        let result = prune_owned_empty_directories_with(
            &canonical_project,
            vec![
                PathBuf::from("root"),
                PathBuf::from("root/a"),
                PathBuf::from("root/z"),
            ],
            |_parent, _name, directory| {
                if directory == Path::new("root") {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                Ok(())
            },
            |operation| {
                if matches!(operation, RestoreDirectoryOperation::BeforePublish)
                    && !replacement_created
                {
                    std::fs::create_dir(&recreated).unwrap();
                    std::fs::write(recreated.join("replacement.txt"), b"replacement\n").unwrap();
                    replacement_created = true;
                }
            },
        );

        let error = match result {
            Err(error) => error,
            Ok(cleanup) => {
                cleanup.commit();
                panic!("injected prune failure unexpectedly succeeded");
            }
        };
        assert!(
            recreated.join("replacement.txt").is_file(),
            "rollback error: {error}"
        );
        assert!(restored.is_dir(), "rollback error: {error}");
    }

    #[test]
    fn staged_directory_cleanup_rolls_back_with_the_manifest_transaction() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("legacy/nested")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let cleanup = prune_owned_empty_directories(
            &canonical_project,
            vec![PathBuf::from("legacy"), PathBuf::from("legacy/nested")],
        )
        .unwrap();
        let mut transaction =
            crate::manifest_tx::ManifestTransaction::snapshot_install_state(&[], &[], &[]).unwrap();

        cleanup.stage_in(&mut transaction);
        drop(transaction);

        assert!(project.path().join("legacy/nested").is_dir());
    }

    #[test]
    fn removal_transaction_drop_restores_an_overwrite_and_its_backup() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let destination = project.path().join("nested/Source.ts");
        std::fs::create_dir(destination.parent().unwrap()).unwrap();
        std::fs::write(&destination, b"installed\n").unwrap();
        let backup = project.path().join(".lpm/backup.bak");
        std::fs::write(&backup, b"original\n").unwrap();
        #[cfg(unix)]
        {
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o640)).unwrap();
            std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        {
            let mut transaction = RemovalTransaction::new(project.path()).unwrap();
            transaction.quarantine_path(&destination).unwrap();
            transaction
                .restore_file(&backup, &destination, Some(0o000))
                .unwrap();
        }

        assert_eq!(std::fs::read(&destination).unwrap(), b"installed\n");
        assert_eq!(std::fs::read(&backup).unwrap(), b"original\n");
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o640
            );
            assert_eq!(
                std::fs::metadata(&backup).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
    }

    #[test]
    fn removal_transaction_commit_discards_quarantined_content() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let destination = project.path().join("Source.ts");
        std::fs::write(&destination, b"installed\n").unwrap();

        let mut transaction = RemovalTransaction::new(project.path()).unwrap();
        transaction.quarantine_path(&destination).unwrap();
        transaction.commit();

        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn removal_rollback_does_not_follow_a_parent_link_created_after_quarantine() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let managed = project.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        let destination = managed.join("Source.ts");
        std::fs::write(&destination, b"managed\n").unwrap();

        let transaction = {
            let mut transaction = RemovalTransaction::new(project.path()).unwrap();
            transaction.quarantine_path(&destination).unwrap();
            transaction
        };
        std::fs::rename(&managed, project.path().join("managed-hidden")).unwrap();
        std::os::unix::fs::symlink(outside.path(), &managed).unwrap();
        drop(transaction);

        assert!(!outside.path().join("Source.ts").exists());
        let quarantines = std::fs::read_dir(project.path().join(".lpm"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".source-remove-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(quarantines.len(), 1);
        assert_eq!(
            std::fs::read(quarantines[0].join("entry-0")).unwrap(),
            b"managed\n"
        );
    }

    #[test]
    fn planned_removal_preserves_a_destination_changed_before_apply() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let destination = project.path().join("Source.ts");
        std::fs::write(&destination, b"managed\n").unwrap();
        let mut record = AddedSourceRecord::default();
        record.files.insert(
            PathBuf::from("Source.ts"),
            AddedSourceFile {
                source: None,
                installed_digest: Some(crate::added_sources_state::digest_bytes(b"managed\n")),
                action: Some(AddedSourceFileAction::Create),
                backup_path: None,
                backup_digest: None,
                backup_mode: None,
            },
        );
        let canonical_project = project.path().canonicalize().unwrap();
        let mut remaining = AddedSourcesState::default();
        let removals = plan_file_removals(
            project.path(),
            &canonical_project,
            "source-pkg",
            &mut remaining,
            &record,
        )
        .unwrap()
        .removals;
        std::fs::write(&destination, b"external edit\n").unwrap();

        let mut transaction = RemovalTransaction::new(project.path()).unwrap();
        for planned in removals {
            assert!(
                apply_planned_file_removal(&mut transaction, &canonical_project, planned).is_err()
            );
        }

        assert_eq!(std::fs::read(&destination).unwrap(), b"external edit\n");
    }
}
