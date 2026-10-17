//! The record of what `lpm add` delivered: for each source package, its
//! version, the files it created or overwrote with their digests, the
//! directories it created, the dependencies it inserted, and its skills.
//!
//! The record is shared project history, like `package.json`: it lives in
//! `lpm-sources.json` at the project root, with portable `/` paths, so a
//! teammate's `lpm remove` knows what an add delivered. Copies of the files
//! an add overwrote stay on the machine that made them, in
//! `.lpm/added-source-backups/`; where a copy isn't on this machine, remove
//! keeps the file. A `.lpm/added-sources.json` from earlier versions is read
//! and replaced on the next write.

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

/// The in-memory state's version: that of the newest `.lpm/added-sources.json`.
pub const SCHEMA_VERSION: u32 = 3;
/// The committed record's name, at the project root.
pub const FILENAME: &str = "lpm-sources.json";
/// The committed record's format version.
const RECORD_SCHEMA_VERSION: u32 = 1;
const LEGACY_FILENAME: &str = "added-sources.json";
const BACKUP_DIRECTORY: &str = "added-source-backups";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddedSourcesState {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub packages: BTreeMap<String, AddedSourceRecord>,
}

impl Default for AddedSourcesState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            packages: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddedSourceRecord {
    /// The delivered version, which earlier records don't hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<PathBuf, AddedSourceFile>,
    #[serde(
        default,
        rename = "createdDirectories",
        skip_serializing_if = "BTreeSet::is_empty"
    )]
    pub created_directories: BTreeSet<PathBuf>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, AddedSourceDependency>,
    #[serde(
        default,
        rename = "skillPackageShort",
        skip_serializing_if = "Option::is_none"
    )]
    pub skill_package_short: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddedSourceFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<AddedSourceFileAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_mode: Option<u32>,
}

pub struct WrittenSourceBackup {
    pub digest: String,
    pub original_mode: Option<u32>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddedSourceFileAction {
    Create,
    Overwrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddedSourceDependency {
    pub spec: String,
    pub section: String,
    pub inserted: bool,
}

#[derive(Deserialize)]
struct AddedSourcesStateV1 {
    #[serde(default)]
    packages: BTreeMap<String, AddedSourceRecordV1>,
}

#[derive(Deserialize)]
struct AddedSourcesStateHeader {
    #[serde(default = "legacy_schema_version")]
    schema_version: u32,
}

fn legacy_schema_version() -> u32 {
    1
}

#[derive(Deserialize)]
struct AddedSourceRecordV1 {
    #[serde(default)]
    files: BTreeSet<PathBuf>,
    #[serde(default, rename = "skillPackageShort")]
    skill_package_short: Option<String>,
}

impl AddedSourcesState {
    pub fn package(&self, package: &str) -> Option<&AddedSourceRecord> {
        self.packages.get(package)
    }

    pub fn take_package(&mut self, package: &str) -> Option<AddedSourceRecord> {
        self.packages.remove(package)
    }

    pub fn record_package_skill_materialization(
        &mut self,
        package: &str,
        skill_package_short: &str,
    ) -> bool {
        let Some(record) = self.packages.get_mut(package) else {
            return false;
        };
        record.skill_package_short = Some(skill_package_short.to_string());
        true
    }

    pub fn record_package_delivery(
        &mut self,
        package: &str,
        version: &str,
        files: impl IntoIterator<Item = (PathBuf, AddedSourceFile)>,
        created_directories: impl IntoIterator<Item = PathBuf>,
        dependencies: Option<Vec<(String, AddedSourceDependency)>>,
        skill_package_short: Option<&str>,
    ) {
        self.schema_version = SCHEMA_VERSION;
        let entry = self.packages.entry(package.to_string()).or_default();
        entry.version = Some(version.to_string());
        entry.files = files.into_iter().collect();
        entry.created_directories = created_directories.into_iter().collect();
        if let Some(dependencies) = dependencies {
            entry.dependencies = dependencies
                .into_iter()
                .map(|(name, mut dependency)| {
                    if !dependency.inserted
                        && entry.dependencies.get(&name).is_some_and(|previous| {
                            previous.inserted
                                && previous.spec == dependency.spec
                                && previous.section == dependency.section
                        })
                    {
                        dependency.inserted = true;
                    }
                    (name, dependency)
                })
                .collect();
        }
        if let Some(short) = skill_package_short {
            entry.skill_package_short = Some(short.to_string());
        }
    }
}

/// The committed record, `lpm-sources.json`.
pub fn state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(FILENAME)
}

fn legacy_state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(LEGACY_FILENAME)
}

/// Every file that holds the state: the record and the earlier location a
/// write replaces. Transactions that write the state snapshot and guard
/// each.
pub fn state_paths(project_dir: &Path) -> [PathBuf; 2] {
    [state_path(project_dir), legacy_state_path(project_dir)]
}

/// What each of [`state_paths`] held when the state was loaded.
#[derive(Debug, Clone, Default)]
pub struct StateSnapshot {
    pub files: Vec<(PathBuf, Option<Vec<u8>>)>,
}

impl StateSnapshot {
    /// Whether any state file existed.
    pub fn exists(&self) -> bool {
        self.files.iter().any(|(_, bytes)| bytes.is_some())
    }
}

pub fn manifest_path_for_file(project_dir: &Path, path: &Path) -> PathBuf {
    if let Ok(relative) = path.strip_prefix(project_dir) {
        return relative.to_path_buf();
    }
    if let Ok(canonical_project) = project_dir.canonicalize()
        && let Ok(relative) = path.strip_prefix(canonical_project)
    {
        return relative.to_path_buf();
    }
    path.to_path_buf()
}

pub fn backup_path_for_file(package: &str, manifest_path: &Path) -> PathBuf {
    backup_path_for_bytes(package, &portable_path_bytes(manifest_path))
}

/// Where earlier versions kept the copy, named from the native path, which
/// differs from [`backup_path_for_file`] where paths use `\`.
fn native_backup_path_for_file(package: &str, manifest_path: &Path) -> PathBuf {
    backup_path_for_bytes(package, manifest_path.as_os_str().as_encoded_bytes())
}

fn backup_path_for_bytes(package: &str, manifest_path: &[u8]) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(package.as_bytes());
    hasher.update([0]);
    hasher.update(manifest_path);
    PathBuf::from(".lpm")
        .join(BACKUP_DIRECTORY)
        .join(format!("{}.bak", hex::encode(hasher.finalize())))
}

/// Records [`backup_path_for_file`]'s names for the copies an earlier
/// version named with `earlier_name`, so the committed record, which
/// derives each name, still finds them, and moves the copies present here
/// to those names. A copy that isn't here becomes one kept elsewhere; a
/// rename an interrupted run already made is recorded the same way.
fn adopt_earlier_backup_names(
    project_dir: &Path,
    state: &mut AddedSourcesState,
    earlier_name: impl Fn(&str, &Path) -> PathBuf,
) -> Result<(), LpmError> {
    let mut backup_directory: Option<Option<PathBuf>> = None;
    for (package, record) in &mut state.packages {
        for (manifest_path, file) in &mut record.files {
            let Some(recorded) = file.backup_path.as_deref() else {
                continue;
            };
            let current = backup_path_for_file(package, manifest_path);
            if recorded == current || recorded != earlier_name(package, manifest_path) {
                continue;
            }
            if backup_directory.is_none() {
                backup_directory = Some(local_backup_directory(project_dir)?);
            }
            if let Some(directory) = backup_directory.as_ref().and_then(Option::as_deref) {
                let from = managed_backup_file_name(recorded)?;
                let to = managed_backup_file_name(&current)?;
                ensure_regular_or_missing(&directory.join(from), "source backup")?;
                ensure_regular_or_missing(&directory.join(to), "source backup")?;
                if directory.join(from).is_file() {
                    move_without_replacing_with(directory, from, to, |from, to| {
                        std::fs::hard_link(from, to)
                    })?;
                }
            }
            file.backup_path = Some(current);
        }
    }
    Ok(())
}

/// The project's source backup directory when it exists here as a real
/// directory.
fn local_backup_directory(project_dir: &Path) -> Result<Option<PathBuf>, LpmError> {
    let Some(lpm_directory) = ensure_state_directory(project_dir, false)? else {
        return Ok(None);
    };
    let directory = lpm_directory.join(BACKUP_DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Ok(_) => validate_real_directory(&directory, "source backup directory")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(LpmError::Io(error)),
    }
    Ok(Some(directory))
}

/// Moves the copy `from` in `directory` to `to`, leaving both alone when
/// `to` exists. Where `link` fails, the copy is published under `to`
/// without replacing anything, and only then removed from `from`. A copy
/// that can't take its new name is an error: the record names it only by
/// that name.
fn move_without_replacing_with(
    directory: &Path,
    from: &std::ffi::OsStr,
    to: &std::ffi::OsStr,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), LpmError> {
    let moved = |error: std::io::Error| {
        LpmError::Io(std::io::Error::new(
            error.kind(),
            format!(
                "could not move the source backup {} to {}: {error}",
                directory.join(from).display(),
                directory.join(to).display()
            ),
        ))
    };
    match link(&directory.join(from), &directory.join(to)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(_) => {
            let backups =
                cap_std::fs::Dir::open_ambient_dir(directory, cap_std::ambient_authority())
                    .map_err(moved)?;
            let mut source = backups.open(from).map_err(moved)?;
            let published = lpm_common::atomic_write::create_file_atomic_in_dir_with_options(
                &backups,
                to,
                lpm_common::AtomicWriteOptions::new()
                    .owner_only()
                    .sync_file()
                    .sync_parent(),
                |copy| std::io::copy(&mut source, copy).map(|_| ()),
            )
            .map_err(moved)?;
            if published.is_none() {
                return Ok(());
            }
        }
    }
    std::fs::remove_file(directory.join(from)).map_err(moved)
}

pub fn validate_recorded_backup_path(
    package: &str,
    manifest_path: &Path,
    recorded: &Path,
) -> Result<PathBuf, LpmError> {
    let expected = backup_path_for_file(package, manifest_path);
    if recorded != expected {
        return Err(LpmError::Registry(format!(
            "source state backup '{}' does not match the managed backup for '{}'",
            recorded.display(),
            manifest_path.display()
        )));
    }
    Ok(expected)
}

fn validate_real_directory(path: &Path, label: &str) -> Result<(), LpmError> {
    let metadata = std::fs::symlink_metadata(path).map_err(LpmError::Io)?;
    if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_dir() {
        return Err(LpmError::Registry(format!(
            "refusing {label} that is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_state_directory(project_dir: &Path, create: bool) -> Result<Option<PathBuf>, LpmError> {
    let directory = project_dir.join(".lpm");
    match std::fs::symlink_metadata(&directory) {
        Ok(_) => validate_real_directory(&directory, "LPM state directory")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;

                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&directory) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(LpmError::Io(error)),
                }
            }
            #[cfg(not(unix))]
            match std::fs::create_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
            validate_real_directory(&directory, "LPM state directory")?;
        }
        Err(error) => return Err(LpmError::Io(error)),
    }
    Ok(Some(directory))
}

fn ensure_regular_or_missing(path: &Path, label: &str) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() => {
            Err(LpmError::Registry(format!(
                "refusing {label} that is not a regular file: {}",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Io(error)),
    }
}

fn ensure_backup_directory(project_dir: &Path) -> Result<PathBuf, LpmError> {
    let lpm_directory = ensure_state_directory(project_dir, true)?.expect("created above");
    let directory = lpm_directory.join(BACKUP_DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Ok(_) => validate_real_directory(&directory, "source backup directory")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;

                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&directory) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(LpmError::Io(error)),
                }
            }
            #[cfg(not(unix))]
            match std::fs::create_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
            validate_real_directory(&directory, "source backup directory")?;
        }
        Err(error) => return Err(LpmError::Io(error)),
    }
    Ok(directory)
}

fn managed_backup_file_name(relative_backup_path: &Path) -> Result<&std::ffi::OsStr, LpmError> {
    let file_name = relative_backup_path.file_name().ok_or_else(|| {
        LpmError::Registry(format!(
            "backup path '{}' has no file name",
            relative_backup_path.display()
        ))
    })?;
    let expected_parent = Path::new(".lpm").join(BACKUP_DIRECTORY);
    if relative_backup_path.parent() != Some(expected_parent.as_path()) {
        return Err(LpmError::Registry(format!(
            "source backup path is outside the managed backup directory: {}",
            relative_backup_path.display()
        )));
    }
    Ok(file_name)
}

/// The verified copy of an overwritten file on this machine, or `None` when
/// the add that made it ran elsewhere and the copy isn't here.
pub fn local_backup(
    project_dir: &Path,
    relative_backup_path: &Path,
    expected_digest: Option<&str>,
) -> Result<Option<PathBuf>, LpmError> {
    let file_name = managed_backup_file_name(relative_backup_path)?;
    let Some(lpm_directory) = ensure_state_directory(project_dir, false)? else {
        return Ok(None);
    };
    let backup_directory = lpm_directory.join(BACKUP_DIRECTORY);
    match std::fs::symlink_metadata(&backup_directory) {
        Ok(_) => validate_real_directory(&backup_directory, "source backup directory")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(LpmError::Io(error)),
    }
    let backup_path = backup_directory.join(file_name);
    ensure_regular_or_missing(&backup_path, "source backup")?;
    if !backup_path.is_file() {
        return Ok(None);
    }
    validate_existing_backup(project_dir, relative_backup_path, expected_digest).map(Some)
}

pub fn validate_existing_backup(
    project_dir: &Path,
    relative_backup_path: &Path,
    expected_digest: Option<&str>,
) -> Result<PathBuf, LpmError> {
    let file_name = managed_backup_file_name(relative_backup_path)?;
    let lpm_directory = ensure_state_directory(project_dir, false)?.ok_or_else(|| {
        LpmError::Registry("source backup state directory is missing".to_string())
    })?;
    let backup_directory = lpm_directory.join(BACKUP_DIRECTORY);
    validate_real_directory(&backup_directory, "source backup directory")?;
    let backup_path = backup_directory.join(file_name);
    ensure_regular_or_missing(&backup_path, "source backup")?;
    if !backup_path.is_file() {
        return Err(LpmError::Registry(format!(
            "source overwrite backup '{}' is missing",
            relative_backup_path.display()
        )));
    }
    let expected_digest = expected_digest.ok_or_else(|| {
        LpmError::Registry(format!(
            "source overwrite backup '{}' has no recorded backup integrity",
            relative_backup_path.display()
        ))
    })?;
    let actual_digest = digest_file(&backup_path)?;
    if actual_digest != expected_digest {
        return Err(LpmError::Registry(format!(
            "source overwrite backup '{}' failed backup integrity verification",
            relative_backup_path.display()
        )));
    }
    Ok(backup_path)
}

pub fn write_backup(
    project_dir: &Path,
    relative_backup_path: &Path,
    source: &Path,
) -> Result<WrittenSourceBackup, LpmError> {
    let file_name = managed_backup_file_name(relative_backup_path)?;
    let backup_directory = ensure_backup_directory(project_dir)?;
    let backup_path = backup_directory.join(file_name);
    ensure_regular_or_missing(&backup_path, "source backup")?;
    ensure_regular_or_missing(source, "source backup input")?;
    let mut source = std::fs::File::open(source).map_err(LpmError::Io)?;
    #[cfg(unix)]
    let original_mode = {
        use std::os::unix::fs::PermissionsExt as _;

        Some(source.metadata()?.permissions().mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let original_mode = None;
    let mut hasher = Sha256::new();
    crate::install_recovery::write_source_with(&backup_path, Some(0o600), |destination| {
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            destination.write_all(&buffer[..read])?;
        }
        Ok(())
    })
    .map_err(LpmError::Io)?;
    Ok(WrittenSourceBackup {
        digest: format!("sha256-{}", hex::encode(hasher.finalize())),
        original_mode,
    })
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256-{}", hex::encode(Sha256::digest(bytes)))
}

pub fn digest_file(path: &Path) -> Result<String, LpmError> {
    let file = std::fs::File::open(path).map_err(LpmError::Io)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(LpmError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

pub fn source_delivery_mode(source: &Path) -> Result<Option<u32>, LpmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(Some(
            std::fs::metadata(source)?.permissions().mode() & 0o777,
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = source;
        Ok(None)
    }
}

pub fn copy_file_atomic_with_mode(
    source: &Path,
    destination: &Path,
    mode: Option<u32>,
) -> Result<String, LpmError> {
    ensure_regular_or_missing(source, "source delivery input")?;
    let mut source = std::fs::File::open(source).map_err(LpmError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    crate::install_recovery::write_source_with(
        destination,
        mode,
        |output| -> std::io::Result<()> {
            loop {
                let read = source.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                output.write_all(&buffer[..read])?;
            }
            Ok(())
        },
    )
    .map_err(LpmError::Io)?;
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

pub fn resolve_tracked_manifest_path(
    project_dir: &Path,
    manifest_path: &Path,
) -> Result<PathBuf, LpmError> {
    let project = project_dir.canonicalize().map_err(LpmError::Io)?;
    resolve_tracked_manifest_path_from_root(&project, manifest_path)
}

pub fn resolve_tracked_manifest_path_from_root(
    canonical_project: &Path,
    manifest_path: &Path,
) -> Result<PathBuf, LpmError> {
    if manifest_path.as_os_str().is_empty()
        || manifest_path.is_absolute()
        || !manifest_path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(LpmError::Registry(format!(
            "added-source state contains an unsafe path: {}",
            manifest_path.display()
        )));
    }
    if manifest_path.components().next().is_some_and(|component| {
        matches!(component, std::path::Component::Normal(name) if name.eq_ignore_ascii_case(".lpm"))
    }) {
        return Err(LpmError::Registry(format!(
            "added-source state cannot target the reserved .lpm directory: {}",
            manifest_path.display()
        )));
    }

    let destination = canonical_project.join(manifest_path);
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() => {
            return Err(LpmError::Registry(format!(
                "added-source destination is not a regular file: {}",
                destination.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(LpmError::Io(error)),
    }

    let destination_parent = destination.parent().ok_or_else(|| {
        LpmError::Registry(format!(
            "added-source destination has no parent: {}",
            destination.display()
        ))
    })?;
    let relative_parent = destination_parent
        .strip_prefix(canonical_project)
        .map_err(|_| {
            LpmError::Registry(format!(
                "added-source destination resolves outside the project: {}",
                destination.display()
            ))
        })?;
    let mut current = canonical_project.to_path_buf();
    for component in relative_parent.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_dir() => {
                return Err(LpmError::Registry(format!(
                    "added-source destination has a linked or non-directory parent: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(LpmError::Io(error)),
        }
    }
    Ok(destination)
}

pub fn resolve_tracked_directory_path_from_root(
    canonical_project: &Path,
    manifest_path: &Path,
) -> Result<PathBuf, LpmError> {
    if manifest_path.as_os_str().is_empty()
        || manifest_path.is_absolute()
        || !manifest_path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(LpmError::Registry(format!(
            "added-source state contains an unsafe directory path: {}",
            manifest_path.display()
        )));
    }
    if manifest_path.components().next().is_some_and(|component| {
        matches!(component, std::path::Component::Normal(name) if name.eq_ignore_ascii_case(".lpm"))
    }) {
        return Err(LpmError::Registry(format!(
            "added-source state cannot own the reserved .lpm directory: {}",
            manifest_path.display()
        )));
    }

    Ok(canonical_project.join(manifest_path))
}

pub fn tracked_file_ancestor_directories<'a>(
    files: impl IntoIterator<Item = &'a Path>,
) -> HashSet<PathBuf> {
    let mut ancestors = HashSet::new();
    for file in files {
        let mut parent = file.parent();
        while let Some(directory) = parent.filter(|directory| !directory.as_os_str().is_empty()) {
            ancestors.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    ancestors
}

pub fn display_manifest_path(path: &Path) -> String {
    path.display().to_string()
}

pub fn load_state_with_snapshot(
    project_dir: &Path,
) -> Result<(AddedSourcesState, StateSnapshot), LpmError> {
    let record_path = state_path(project_dir);
    let record = read_state_file(&record_path, "source package record")?;
    let legacy_path = legacy_state_path(project_dir);
    let legacy = if ensure_state_directory(project_dir, false)?.is_some() {
        read_state_file(&legacy_path, "added-source state")?
    } else {
        None
    };
    let earlier = legacy
        .as_deref()
        .map(|bytes| -> Result<AddedSourcesState, LpmError> {
            let mut state = parse_state(&legacy_path, bytes)?;
            adopt_earlier_backup_names(project_dir, &mut state, native_backup_path_for_file)?;
            Ok(state)
        })
        .transpose()?;
    let state = match (&record, earlier) {
        (Some(bytes), earlier) => {
            let mut state = parse_record(&record_path, bytes)?;
            // A teammate's record arrived before this checkout's earlier
            // state moved into it: its packages join, the record's own
            // entry winning for a package both name.
            for (package, entry) in earlier.into_iter().flat_map(|earlier| earlier.packages) {
                state.packages.entry(package).or_insert(entry);
            }
            state
        }
        (None, Some(earlier)) => earlier,
        (None, None) => AddedSourcesState::default(),
    };
    Ok((
        state,
        StateSnapshot {
            files: vec![(record_path, record), (legacy_path, legacy)],
        },
    ))
}

/// The package skills the state records, as `(skills package, version)`
/// for each delivered package that names both, read without building the
/// delivered-file inventory.
pub fn load_skill_versions(project_dir: &Path) -> Result<Vec<(String, String)>, LpmError> {
    let record_path = state_path(project_dir);
    let mut packages = match read_state_file(&record_path, "source package record")? {
        Some(bytes) => parse_record_skill_versions(&record_path, &bytes)?,
        None => BTreeMap::new(),
    };
    if ensure_state_directory(project_dir, false)?.is_some() {
        let legacy_path = legacy_state_path(project_dir);
        if let Some(bytes) = read_state_file(&legacy_path, "added-source state")? {
            for (package, skills) in parse_state_skill_versions(&legacy_path, &bytes)? {
                packages.entry(package).or_insert(skills);
            }
        }
    }
    Ok(packages.into_values().flatten().collect())
}

fn read_state_file(path: &Path, label: &str) -> Result<Option<Vec<u8>>, LpmError> {
    ensure_regular_or_missing(path, label)?;
    lpm_common::read_capped_state_file(path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .map_err(LpmError::Io)
}

fn parse_state(path: &Path, bytes: &[u8]) -> Result<AddedSourcesState, LpmError> {
    let header: AddedSourcesStateHeader = serde_json::from_slice(bytes).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    if header.schema_version > SCHEMA_VERSION {
        return Err(LpmError::Registry(format!(
            "{} uses schema version {} but this lpm binary supports up to {SCHEMA_VERSION}",
            path.display(),
            header.schema_version,
        )));
    }

    if header.schema_version <= 1 {
        let legacy: AddedSourcesStateV1 = serde_json::from_slice(bytes).map_err(|error| {
            LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
        })?;
        let packages = legacy
            .packages
            .into_iter()
            .map(|(package, record)| {
                let files = record
                    .files
                    .into_iter()
                    .map(|path| {
                        (
                            path,
                            AddedSourceFile {
                                source: None,
                                installed_digest: None,
                                action: None,
                                backup_path: None,
                                backup_digest: None,
                                backup_mode: None,
                            },
                        )
                    })
                    .collect();
                (
                    package,
                    AddedSourceRecord {
                        version: None,
                        files,
                        created_directories: BTreeSet::new(),
                        dependencies: BTreeMap::new(),
                        skill_package_short: record.skill_package_short,
                    },
                )
            })
            .collect();
        return Ok(AddedSourcesState {
            schema_version: SCHEMA_VERSION,
            packages,
        });
    }

    let mut state: AddedSourcesState = serde_json::from_slice(bytes).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    if header.schema_version < 3 {
        for record in state.packages.values_mut() {
            record.created_directories.clear();
        }
    }
    Ok(state)
}

#[derive(Deserialize)]
struct StateSkillVersions {
    #[serde(default)]
    packages: BTreeMap<String, StateRecordSkillVersion>,
}

#[derive(Deserialize)]
struct StateRecordSkillVersion {
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "skillPackageShort")]
    skill_package_short: Option<String>,
}

/// Each package the state names, with its skills package and version when
/// it records both.
type PackageSkillVersions = BTreeMap<String, Option<(String, String)>>;

fn parse_state_skill_versions(path: &Path, bytes: &[u8]) -> Result<PackageSkillVersions, LpmError> {
    let invalid = |error: serde_json::Error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    };
    let header: AddedSourcesStateHeader = serde_json::from_slice(bytes).map_err(invalid)?;
    if header.schema_version > SCHEMA_VERSION {
        return Err(LpmError::Registry(format!(
            "{} uses schema version {} but this lpm binary supports up to {SCHEMA_VERSION}",
            path.display(),
            header.schema_version,
        )));
    }
    if header.schema_version <= 1 {
        let state: StateSkillVersions = serde_json::from_slice(bytes).map_err(invalid)?;
        return Ok(state
            .packages
            .into_keys()
            .map(|package| (package, None))
            .collect());
    }
    let state: StateSkillVersions = serde_json::from_slice(bytes).map_err(invalid)?;
    Ok(state
        .packages
        .into_iter()
        .map(|(package, record)| {
            let skills = record.skill_package_short.zip(record.version);
            (package, skills)
        })
        .collect())
}

/// Writes the state to `lpm-sources.json`, or removes the record when no
/// package remains, and removes the earlier `.lpm/added-sources.json`.
pub fn write_state(project_dir: &Path, state: &AddedSourcesState) -> Result<(), LpmError> {
    let path = state_path(project_dir);
    ensure_regular_or_missing(&path, "source package record")?;
    if state.packages.is_empty() {
        match crate::install_recovery::remove_source(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(LpmError::Io(error)),
        }
    } else {
        let mut body = serde_json::to_vec_pretty(&to_record(state)?).map_err(|error| {
            LpmError::Registry(format!("failed to serialize {FILENAME}: {error}"))
        })?;
        body.push(b'\n');
        if body.len() as u64 > lpm_common::STATE_FILE_SIZE_CAP_BYTES {
            return Err(LpmError::Registry(format!(
                "{FILENAME} exceeds the {} byte size limit",
                lpm_common::STATE_FILE_SIZE_CAP_BYTES
            )));
        }
        crate::install_recovery::write_source_with(&path, Some(0o644), |file| {
            file.write_all(&body)
        })
        .map_err(LpmError::Io)?;
    }
    if ensure_state_directory(project_dir, false)?.is_some() {
        let legacy = legacy_state_path(project_dir);
        ensure_regular_or_missing(&legacy, "added-source state")?;
        match crate::install_recovery::remove_source(&legacy) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(LpmError::Io(error)),
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourcesRecord {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    packages: BTreeMap<String, SourcesRecordPackage>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourcesRecordPackage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    files: BTreeMap<String, SourcesRecordFile>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    created_directories: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    dependencies: BTreeMap<String, AddedSourceDependency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    skills: Option<String>,
}

/// A delivered file. `originalDigest` and `originalMode` describe the file
/// an add overwrote, whose copy stays on the machine that made it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourcesRecordFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<AddedSourceFileAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_mode: Option<u32>,
}

fn to_record(state: &AddedSourcesState) -> Result<SourcesRecord, LpmError> {
    let mut packages = BTreeMap::new();
    for (package, record) in &state.packages {
        let mut files = BTreeMap::new();
        for (path, file) in &record.files {
            files.insert(
                portable_path(path)?,
                SourcesRecordFile {
                    source: file.source.as_deref().map(portable_path).transpose()?,
                    digest: file.installed_digest.clone(),
                    action: file.action,
                    original_digest: file.backup_digest.clone(),
                    original_mode: file.backup_mode,
                },
            );
        }
        packages.insert(
            package.clone(),
            SourcesRecordPackage {
                version: record.version.clone(),
                files,
                created_directories: record
                    .created_directories
                    .iter()
                    .map(|path| portable_path(path))
                    .collect::<Result<_, _>>()?,
                dependencies: record.dependencies.clone(),
                skills: record.skill_package_short.clone(),
            },
        );
    }
    Ok(SourcesRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        packages,
    })
}

fn parse_record(path: &Path, bytes: &[u8]) -> Result<AddedSourcesState, LpmError> {
    let invalid =
        |error: String| LpmError::Registry(format!("failed to parse {}: {error}", path.display()));
    let record: SourcesRecord =
        serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
    if record.schema_version != RECORD_SCHEMA_VERSION {
        return Err(LpmError::Registry(format!(
            "{} uses schema version {} but this lpm binary reads version {RECORD_SCHEMA_VERSION}",
            path.display(),
            record.schema_version,
        )));
    }
    let mut packages = BTreeMap::new();
    for (package, entry) in record.packages {
        let mut files = BTreeMap::new();
        for (manifest, file) in entry.files {
            let manifest_path = native_path(&manifest).map_err(invalid)?;
            let backup_path = (file.action == Some(AddedSourceFileAction::Overwrite))
                .then(|| backup_path_for_file(&package, &manifest_path));
            files.insert(
                manifest_path,
                AddedSourceFile {
                    source: file
                        .source
                        .as_deref()
                        .map(native_path)
                        .transpose()
                        .map_err(invalid)?,
                    installed_digest: file.digest,
                    action: file.action,
                    backup_path,
                    backup_digest: file.original_digest,
                    backup_mode: file.original_mode,
                },
            );
        }
        packages.insert(
            package,
            AddedSourceRecord {
                version: entry.version,
                files,
                created_directories: entry
                    .created_directories
                    .iter()
                    .map(|path| native_path(path))
                    .collect::<Result<_, _>>()
                    .map_err(invalid)?,
                dependencies: entry.dependencies,
                skill_package_short: entry.skills,
            },
        );
    }
    Ok(AddedSourcesState {
        schema_version: SCHEMA_VERSION,
        packages,
    })
}

/// A [`SourcesRecord`] read for its skills alone: the inventories are
/// checked for shape and skipped without being built.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourcesRecordSkillVersions {
    schema_version: u32,
    #[serde(default)]
    packages: BTreeMap<String, SourcesRecordPackageSkillVersion>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourcesRecordPackageSkillVersion {
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "files")]
    _files: serde::de::IgnoredAny,
    #[serde(default, rename = "createdDirectories")]
    _created_directories: serde::de::IgnoredAny,
    #[serde(default, rename = "dependencies")]
    _dependencies: serde::de::IgnoredAny,
    #[serde(default)]
    skills: Option<String>,
}

fn parse_record_skill_versions(
    path: &Path,
    bytes: &[u8],
) -> Result<PackageSkillVersions, LpmError> {
    let record: SourcesRecordSkillVersions = serde_json::from_slice(bytes).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    if record.schema_version != RECORD_SCHEMA_VERSION {
        return Err(LpmError::Registry(format!(
            "{} uses schema version {} but this lpm binary reads version {RECORD_SCHEMA_VERSION}",
            path.display(),
            record.schema_version,
        )));
    }
    Ok(record
        .packages
        .into_iter()
        .map(|(name, package)| (name, package.skills.zip(package.version)))
        .collect())
}

/// A project-relative path as the record stores it: its names joined by
/// `/`, the same on every platform.
fn portable_path(path: &Path) -> Result<String, LpmError> {
    let mut portable = String::new();
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(LpmError::Registry(format!(
                "{FILENAME} can only hold project-relative paths: {}",
                path.display()
            )));
        };
        let name = name
            .to_str()
            .filter(|name| !name.contains(['/', '\\']))
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "{FILENAME} can only hold paths whose names are portable: {}",
                    path.display()
                ))
            })?;
        if !portable.is_empty() {
            portable.push('/');
        }
        portable.push_str(name);
    }
    Ok(portable)
}

fn portable_path_bytes(path: &Path) -> Vec<u8> {
    portable_path(path).map_or_else(
        |_| path.as_os_str().as_encoded_bytes().to_vec(),
        String::into_bytes,
    )
}

fn native_path(portable: &str) -> Result<PathBuf, String> {
    let mut path = PathBuf::new();
    for name in portable.split('/') {
        if name.is_empty() || name == "." || name == ".." || name.contains('\\') {
            return Err(format!("`{portable}` is not a project-relative path"));
        }
        path.push(name);
    }
    if path.as_os_str().is_empty() {
        return Err(format!("`{portable}` is not a project-relative path"));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn created_file(source: &str, digest: &str) -> AddedSourceFile {
        AddedSourceFile {
            source: Some(PathBuf::from(source)),
            installed_digest: Some(digest.to_string()),
            action: Some(AddedSourceFileAction::Create),
            backup_path: None,
            backup_digest: None,
            backup_mode: None,
        }
    }

    #[test]
    fn write_and_read_round_trip_package_entries() {
        let dir = tempdir().unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            "source-pkg",
            "1.0.0",
            [(
                PathBuf::from("custom/widgets/Foo.tsx"),
                created_file("Foo.tsx", "sha256-test"),
            )],
            [PathBuf::from("custom"), PathBuf::from("custom/widgets")],
            None,
            None,
        );

        write_state(dir.path(), &state).unwrap();
        let loaded = load_state_with_snapshot(dir.path()).unwrap().0;

        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        let record = loaded.package("source-pkg").unwrap();
        assert!(
            record
                .files
                .contains_key(Path::new("custom/widgets/Foo.tsx"))
        );
        assert_eq!(
            record.created_directories,
            BTreeSet::from([PathBuf::from("custom"), PathBuf::from("custom/widgets")])
        );
    }

    #[test]
    fn version_one_paths_migrate_without_destructive_provenance() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(
            legacy_state_path(dir.path()),
            r#"{"schema_version":1,"packages":{"source-pkg":{"files":["Foo.tsx"]}}}"#,
        )
        .unwrap();

        let state = load_state_with_snapshot(dir.path()).unwrap().0;
        let file = &state.package("source-pkg").unwrap().files[Path::new("Foo.tsx")];

        assert_eq!(state.schema_version, SCHEMA_VERSION);
        assert!(file.installed_digest.is_none());
        assert!(file.action.is_none());
    }

    #[test]
    fn the_record_uses_portable_paths_and_names_overwritten_originals() {
        let dir = tempdir().unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            "@lpm.dev/owner.ui",
            "2.1.0",
            [(
                PathBuf::from("src").join("components").join("Button.tsx"),
                AddedSourceFile {
                    source: Some(PathBuf::from("button").join("Button.tsx")),
                    installed_digest: Some("sha256-installed".into()),
                    action: Some(AddedSourceFileAction::Overwrite),
                    backup_path: Some(backup_path_for_file(
                        "@lpm.dev/owner.ui",
                        Path::new("src/components/Button.tsx"),
                    )),
                    backup_digest: Some("sha256-original".into()),
                    backup_mode: Some(0o644),
                },
            )],
            [PathBuf::from("src").join("components")],
            None,
            Some("owner.ui"),
        );

        write_state(dir.path(), &state).unwrap();

        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("lpm-sources.json")).unwrap())
                .unwrap();
        assert_eq!(
            written,
            serde_json::json!({
                "schemaVersion": 1,
                "packages": {"@lpm.dev/owner.ui": {
                    "version": "2.1.0",
                    "files": {"src/components/Button.tsx": {
                        "source": "button/Button.tsx",
                        "digest": "sha256-installed",
                        "action": "overwrite",
                        "originalDigest": "sha256-original",
                        "originalMode": 420,
                    }},
                    "createdDirectories": ["src/components"],
                    "skills": "owner.ui",
                }}
            })
        );
        let loaded = load_state_with_snapshot(dir.path()).unwrap().0;
        let file = &loaded.package("@lpm.dev/owner.ui").unwrap().files
            [Path::new("src/components/Button.tsx")];
        assert_eq!(
            file.backup_path,
            Some(backup_path_for_file(
                "@lpm.dev/owner.ui",
                Path::new("src/components/Button.tsx")
            ))
        );
        assert!(!dir.path().join(".lpm").exists());
    }

    #[test]
    fn skill_versions_match_the_full_state_without_its_inventory() {
        let dir = tempdir().unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            "@lpm.dev/owner.ui",
            "2.1.0",
            [(
                PathBuf::from("src/Button.tsx"),
                created_file("Button.tsx", "sha256-test"),
            )],
            [PathBuf::from("src")],
            None,
            Some("owner.ui"),
        );
        state.record_package_delivery(
            "plain-source",
            "1.0.0",
            [(
                PathBuf::from("lib.js"),
                created_file("lib.js", "sha256-lib"),
            )],
            [],
            None,
            None,
        );
        write_state(dir.path(), &state).unwrap();

        assert_eq!(
            load_skill_versions(dir.path()).unwrap(),
            vec![("owner.ui".to_string(), "2.1.0".to_string())]
        );
    }

    #[test]
    fn skill_versions_reject_an_unknown_schema_or_field() {
        let dir = tempdir().unwrap();
        for record in [
            r#"{"schemaVersion":2,"packages":{}}"#,
            r#"{"schemaVersion":1,"packages":{"p":{"version":"1.0.0","skils":"o.p"}}}"#,
        ] {
            std::fs::write(dir.path().join(FILENAME), record).unwrap();

            assert!(load_skill_versions(dir.path()).is_err(), "{record}");
            assert!(load_state_with_snapshot(dir.path()).is_err(), "{record}");
        }
    }

    #[test]
    fn skill_versions_read_the_earlier_state_in_lpm() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(
            legacy_state_path(dir.path()),
            r#"{"schema_version":3,"packages":{"@lpm.dev/owner.ui":{"version":"2.0.0","files":{},"skillPackageShort":"owner.ui"}}}"#,
        )
        .unwrap();
        assert_eq!(
            load_skill_versions(dir.path()).unwrap(),
            vec![("owner.ui".to_string(), "2.0.0".to_string())]
        );

        std::fs::write(
            legacy_state_path(dir.path()),
            r#"{"schema_version":1,"packages":{"source-pkg":{"files":["Foo.tsx"],"skillPackageShort":"owner.ui"}}}"#,
        )
        .unwrap();
        assert!(load_skill_versions(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn copies_named_the_earlier_way_are_renamed_before_the_record_takes_over() {
        let dir = tempdir().unwrap();
        let backups = dir.path().join(".lpm").join(BACKUP_DIRECTORY);
        std::fs::create_dir_all(&backups).unwrap();
        let manifest_path = Path::new("src/widget.js");
        let earlier = |package: &str, path: &Path| {
            backup_path_for_bytes(package, format!("earlier:{}", path.display()).as_bytes())
        };
        let recorded = earlier("@lpm.dev/acme.widget", manifest_path);
        std::fs::write(dir.path().join(&recorded), "original").unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            "@lpm.dev/acme.widget",
            "1.0.0",
            [(
                manifest_path.to_path_buf(),
                AddedSourceFile {
                    source: Some(PathBuf::from("widget.js")),
                    installed_digest: Some("sha256-installed".into()),
                    action: Some(AddedSourceFileAction::Overwrite),
                    backup_path: Some(recorded.clone()),
                    backup_digest: Some(digest_bytes(b"original")),
                    backup_mode: None,
                },
            )],
            [],
            None,
            None,
        );

        adopt_earlier_backup_names(dir.path(), &mut state, earlier).unwrap();
        write_state(dir.path(), &state).unwrap();

        let current = backup_path_for_file("@lpm.dev/acme.widget", manifest_path);
        assert!(!dir.path().join(&recorded).exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join(&current)).unwrap(),
            "original"
        );
        let loaded = load_state_with_snapshot(dir.path()).unwrap().0;
        let file = &loaded.package("@lpm.dev/acme.widget").unwrap().files[manifest_path];
        assert_eq!(file.backup_path.as_deref(), Some(current.as_path()));
        assert!(
            local_backup(dir.path(), &current, file.backup_digest.as_deref())
                .unwrap()
                .is_some()
        );

        let mut again = state.clone();
        again
            .packages
            .values_mut()
            .flat_map(|record| record.files.values_mut())
            .for_each(|file| file.backup_path = Some(recorded.clone()));
        adopt_earlier_backup_names(dir.path(), &mut again, earlier).unwrap();
        assert_eq!(
            again.packages["@lpm.dev/acme.widget"].files[manifest_path]
                .backup_path
                .as_deref(),
            Some(current.as_path()),
            "a rename an interrupted run made is recorded"
        );
    }

    fn delivery_backed_up_at(recorded: &Path) -> AddedSourcesState {
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            "@lpm.dev/acme.widget",
            "1.0.0",
            [(
                PathBuf::from("src/widget.js"),
                AddedSourceFile {
                    source: Some(PathBuf::from("widget.js")),
                    installed_digest: Some("sha256-installed".into()),
                    action: Some(AddedSourceFileAction::Overwrite),
                    backup_path: Some(recorded.to_path_buf()),
                    backup_digest: Some(digest_bytes(b"original")),
                    backup_mode: None,
                },
            )],
            [],
            None,
            None,
        );
        state
    }

    #[cfg(unix)]
    #[test]
    fn a_copy_that_can_t_take_its_new_name_stops_adoption_and_keeps_the_record() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let backups = dir.path().join(".lpm").join(BACKUP_DIRECTORY);
        std::fs::create_dir_all(&backups).unwrap();
        let earlier = |package: &str, path: &Path| {
            backup_path_for_bytes(package, format!("earlier:{}", path.display()).as_bytes())
        };
        let recorded = earlier("@lpm.dev/acme.widget", Path::new("src/widget.js"));
        std::fs::write(dir.path().join(&recorded), "original").unwrap();
        let mut state = delivery_backed_up_at(&recorded);
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::write(backups.join("probe"), "").is_ok() {
            std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let adopted = adopt_earlier_backup_names(dir.path(), &mut state, earlier);
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(adopted.is_err(), "{adopted:?}");
        assert_eq!(
            state.packages["@lpm.dev/acme.widget"].files[Path::new("src/widget.js")]
                .backup_path
                .as_deref(),
            Some(recorded.as_path())
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join(&recorded)).unwrap(),
            "original"
        );
    }

    #[test]
    fn without_hard_links_a_copy_is_moved_by_publishing_it_under_its_new_name() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("earlier"), "original").unwrap();
        std::fs::write(dir.path().join("taken"), "kept").unwrap();
        let no_links =
            |_: &Path, _: &Path| Err(std::io::Error::from(std::io::ErrorKind::Unsupported));

        move_without_replacing_with(dir.path(), "earlier".as_ref(), "current".as_ref(), no_links)
            .unwrap();
        std::fs::write(dir.path().join("second"), "second").unwrap();
        move_without_replacing_with(dir.path(), "second".as_ref(), "taken".as_ref(), no_links)
            .unwrap();

        assert!(!dir.path().join("earlier").exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("current")).unwrap(),
            "original"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("taken")).unwrap(),
            "kept"
        );
        assert!(
            dir.path().join("second").exists(),
            "a name already taken leaves both"
        );
    }

    #[test]
    fn earlier_names_are_recorded_the_current_way_without_a_local_copy() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        let manifest_path = Path::new("src/widget.js");
        let earlier = |package: &str, path: &Path| {
            backup_path_for_bytes(package, format!("earlier:{}", path.display()).as_bytes())
        };
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            "@lpm.dev/acme.widget",
            "1.0.0",
            [(
                manifest_path.to_path_buf(),
                AddedSourceFile {
                    source: Some(PathBuf::from("widget.js")),
                    installed_digest: Some("sha256-installed".into()),
                    action: Some(AddedSourceFileAction::Overwrite),
                    backup_path: Some(earlier("@lpm.dev/acme.widget", manifest_path)),
                    backup_digest: Some(digest_bytes(b"original")),
                    backup_mode: None,
                },
            )],
            [],
            None,
            None,
        );

        adopt_earlier_backup_names(dir.path(), &mut state, earlier).unwrap();

        let recorded = state.packages["@lpm.dev/acme.widget"].files[manifest_path]
            .backup_path
            .clone()
            .unwrap();
        assert_eq!(
            recorded,
            backup_path_for_file("@lpm.dev/acme.widget", manifest_path)
        );
        validate_recorded_backup_path("@lpm.dev/acme.widget", manifest_path, &recorded).unwrap();
        assert!(
            local_backup(dir.path(), &recorded, Some(&digest_bytes(b"original")))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn earlier_state_joins_a_record_a_teammate_committed_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let mut committed = AddedSourcesState::default();
        committed.record_package_delivery(
            "@lpm.dev/acme.y",
            "1.0.0",
            [(PathBuf::from("src/y.ts"), created_file("y.ts", "sha256-y"))],
            [],
            None,
            None,
        );
        write_state(dir.path(), &committed).unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(
            legacy_state_path(dir.path()),
            r#"{"schema_version":3,"packages":{
                "@lpm.dev/acme.x":{"version":"1.0.0","files":{"src/x.ts":{"installed_digest":"sha256-x","action":"create"}},"skillPackageShort":"acme.x"},
                "@lpm.dev/acme.y":{"version":"0.9.0","files":{"src/old-y.ts":{"installed_digest":"sha256-old","action":"create"}}}
            }}"#,
        )
        .unwrap();

        let (state, _) = load_state_with_snapshot(dir.path()).unwrap();

        assert!(
            state
                .package("@lpm.dev/acme.x")
                .unwrap()
                .files
                .contains_key(Path::new("src/x.ts"))
        );
        let y = state.package("@lpm.dev/acme.y").unwrap();
        assert_eq!(
            y.version.as_deref(),
            Some("1.0.0"),
            "the committed entry wins"
        );
        assert_eq!(
            load_skill_versions(dir.path()).unwrap(),
            vec![("acme.x".to_string(), "1.0.0".to_string())]
        );

        write_state(dir.path(), &state).unwrap();
        assert!(!legacy_state_path(dir.path()).exists());
        let reloaded = load_state_with_snapshot(dir.path()).unwrap().0;
        assert!(reloaded.package("@lpm.dev/acme.x").is_some());
    }

    #[test]
    fn writing_replaces_the_earlier_record_in_lpm_state() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(
            legacy_state_path(dir.path()),
            r#"{"schema_version":3,"packages":{"source-pkg":{"files":{"Foo.tsx":{"installed_digest":"sha256-test","action":"create"}}}}}"#,
        )
        .unwrap();
        let (state, snapshot) = load_state_with_snapshot(dir.path()).unwrap();
        assert!(snapshot.exists());

        write_state(dir.path(), &state).unwrap();

        assert!(!legacy_state_path(dir.path()).exists());
        assert!(dir.path().join("lpm-sources.json").exists());
    }

    #[test]
    fn version_two_records_load_without_directory_ownership() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(
            legacy_state_path(dir.path()),
            r#"{"schema_version":2,"packages":{"source-pkg":{"files":{"custom/Foo.tsx":{"installed_digest":"sha256-test","action":"create"}},"createdDirectories":["custom"]}}}"#,
        )
        .unwrap();

        let state = load_state_with_snapshot(dir.path()).unwrap().0;
        let record = state.package("source-pkg").unwrap();

        assert_eq!(state.schema_version, 2);
        assert!(
            record.created_directories.is_empty(),
            "schema-v2 input must not acquire schema-v3 deletion authority"
        );
        assert!(record.files.contains_key(Path::new("custom/Foo.tsx")));
    }

    #[test]
    fn tracked_file_ancestor_directories_deduplicates_large_shared_prefixes() {
        let files: Vec<PathBuf> = (0..10_000)
            .map(|index| PathBuf::from(format!("components/generated/nested/file-{index}.ts")))
            .collect();

        let ancestors = tracked_file_ancestor_directories(files.iter().map(PathBuf::as_path));

        assert_eq!(ancestors.len(), 3);
        assert!(ancestors.contains(Path::new("components")));
        assert!(ancestors.contains(Path::new("components/generated")));
        assert!(ancestors.contains(Path::new("components/generated/nested")));
    }

    #[test]
    fn tracked_manifest_paths_reject_absolute_and_parent_relative_entries() {
        let dir = tempdir().unwrap();

        assert!(resolve_tracked_manifest_path(dir.path(), Path::new("../outside.ts")).is_err());
        assert!(resolve_tracked_manifest_path(dir.path(), Path::new("/outside.ts")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn tracked_manifest_paths_reject_linked_parents_inside_the_project() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/source.ts"), b"source\n").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("linked")).unwrap();

        assert!(resolve_tracked_manifest_path(dir.path(), Path::new("linked/source.ts")).is_err());
    }

    #[test]
    fn write_state_removes_file_when_no_entries_remain() {
        let dir = tempdir().unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            "source-pkg",
            "1.0.0",
            [(
                PathBuf::from("Foo.tsx"),
                created_file("Foo.tsx", "sha256-test"),
            )],
            std::iter::empty(),
            None,
            None,
        );
        write_state(dir.path(), &state).unwrap();

        write_state(dir.path(), &AddedSourcesState::default()).unwrap();

        assert!(!state_path(dir.path()).exists());
    }

    #[test]
    fn write_state_rejects_output_larger_than_the_read_cap() {
        let dir = tempdir().unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            &"p".repeat(usize::try_from(lpm_common::STATE_FILE_SIZE_CAP_BYTES).unwrap() + 1),
            "1.0.0",
            std::iter::empty(),
            std::iter::empty(),
            None,
            None,
        );

        let error = write_state(dir.path(), &state).unwrap_err();

        assert!(error.to_string().contains("size limit"));
        assert!(!state_path(dir.path()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_state_refuses_a_linked_lpm_directory() {
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join(".lpm")).unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_delivery(
            "source-pkg",
            "1.0.0",
            [(
                PathBuf::from("Foo.tsx"),
                created_file("Foo.tsx", "sha256-test"),
            )],
            std::iter::empty(),
            None,
            None,
        );

        assert!(write_state(project.path(), &state).is_err());
        assert!(!outside.path().join(FILENAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_backup_refuses_a_linked_backup_directory() {
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        std::os::unix::fs::symlink(outside.path(), lpm_dir.join(BACKUP_DIRECTORY)).unwrap();
        let source = project.path().join("secret.txt");
        std::fs::write(&source, b"secret").unwrap();
        let relative = PathBuf::from(".lpm")
            .join(BACKUP_DIRECTORY)
            .join("backup.bak");

        assert!(write_backup(project.path(), &relative, &source).is_err());
        assert!(!outside.path().join("backup.bak").exists());
    }

    #[cfg(unix)]
    #[test]
    fn source_backup_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempdir().unwrap();
        let source = project.path().join("secret.txt");
        std::fs::write(&source, b"secret").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o751)).unwrap();
        let relative = PathBuf::from(".lpm")
            .join(BACKUP_DIRECTORY)
            .join("backup.bak");

        let written = write_backup(project.path(), &relative, &source).unwrap();

        let mode = std::fs::metadata(project.path().join(relative))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(written.original_mode, Some(0o751));
        assert_eq!(mode, 0o600);
    }
}
