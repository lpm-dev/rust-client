use crate::added_sources_state::{
    AddedSourceFile, AddedSourceFileAction, AddedSourceRecord, AddedSourcesState,
};
use crate::install_ui;
use lpm_common::LpmError;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

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
}

impl LockedRemoveResult {
    fn empty() -> Self {
        Self {
            removed: Vec::new(),
            preserved: Vec::new(),
            dependencies_removed: Vec::new(),
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
    if !retained.files.is_empty() {
        retained.dependencies.clear();
        retained.skill_package_short = None;
        state.packages.insert(package_key.clone(), retained);
    }

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

    manifest_transaction.commit();
    removal_transaction.commit();
    Ok(LockedRemoveResult {
        removed,
        preserved,
        dependencies_removed,
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
