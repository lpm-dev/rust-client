//! Persistence for source files and dependencies installed by `lpm add`.

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u32 = 2;
pub const FILENAME: &str = "added-sources.json";
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<PathBuf, AddedSourceFile>,
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

    pub fn record_package_delivery(
        &mut self,
        package: &str,
        files: impl IntoIterator<Item = (PathBuf, AddedSourceFile)>,
        dependencies: Option<Vec<(String, AddedSourceDependency)>>,
        skill_package_short: Option<&str>,
    ) {
        self.schema_version = SCHEMA_VERSION;
        let entry = self.packages.entry(package.to_string()).or_default();
        entry.files = files.into_iter().collect();
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

pub fn state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(FILENAME)
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
    let mut hasher = Sha256::new();
    hasher.update(package.as_bytes());
    hasher.update([0]);
    hasher.update(manifest_path.as_os_str().as_encoded_bytes());
    PathBuf::from(".lpm")
        .join(BACKUP_DIRECTORY)
        .join(format!("{}.bak", hex::encode(hasher.finalize())))
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
    lpm_common::write_file_atomic_with(
        &backup_path,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
        |destination| {
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
        },
    )
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

pub fn copy_file_atomic_with_digest(source: &Path, destination: &Path) -> Result<String, LpmError> {
    ensure_regular_or_missing(source, "source delivery input")?;
    let mut source = std::fs::File::open(source).map_err(LpmError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    lpm_common::write_file_atomic_with(
        destination,
        lpm_common::AtomicWriteOptions::new(),
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

pub fn display_manifest_path(path: &Path) -> String {
    path.display().to_string()
}

pub fn load_state_with_snapshot(
    project_dir: &Path,
) -> Result<(AddedSourcesState, Option<Vec<u8>>), LpmError> {
    if ensure_state_directory(project_dir, false)?.is_none() {
        return Ok((AddedSourcesState::default(), None));
    }
    let path = state_path(project_dir);
    ensure_regular_or_missing(&path, "added-source state")?;
    let Some(bytes) =
        lpm_common::read_capped_state_file(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)?
    else {
        return Ok((AddedSourcesState::default(), None));
    };
    let state = parse_state(&path, &bytes)?;
    Ok((state, Some(bytes)))
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
                        files,
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

    serde_json::from_slice(bytes)
        .map_err(|error| LpmError::Registry(format!("failed to parse {}: {error}", path.display())))
}

pub fn write_state(project_dir: &Path, state: &AddedSourcesState) -> Result<(), LpmError> {
    let path = state_path(project_dir);
    if state.packages.is_empty() {
        if ensure_state_directory(project_dir, false)?.is_none() {
            return Ok(());
        }
        ensure_regular_or_missing(&path, "added-source state")?;
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(LpmError::Io(error)),
        };
    }

    ensure_state_directory(project_dir, true)?;
    ensure_regular_or_missing(&path, "added-source state")?;
    let mut body = serde_json::to_vec_pretty(state).map_err(|error| {
        LpmError::Registry(format!("failed to serialize added-sources state: {error}"))
    })?;
    body.push(b'\n');
    lpm_common::write_file_atomic_with_options(
        &path,
        body,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
    )
    .map_err(LpmError::Io)
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
            [(
                PathBuf::from("custom/widgets/Foo.tsx"),
                created_file("Foo.tsx", "sha256-test"),
            )],
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
    }

    #[test]
    fn version_one_paths_migrate_without_destructive_provenance() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(
            state_path(dir.path()),
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
            [(
                PathBuf::from("Foo.tsx"),
                created_file("Foo.tsx", "sha256-test"),
            )],
            None,
            None,
        );
        write_state(dir.path(), &state).unwrap();

        write_state(dir.path(), &AddedSourcesState::default()).unwrap();

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
            [(
                PathBuf::from("Foo.tsx"),
                created_file("Foo.tsx", "sha256-test"),
            )],
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
