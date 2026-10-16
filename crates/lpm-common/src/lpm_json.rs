use std::fs::{File, Metadata, OpenOptions};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    AtomicWriteOptions, BoundedReadError, CONFIG_FILE_SIZE_CAP_BYTES,
    read_text_file_capped_from_open_file, write_file_atomic_with_options,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LpmJsonMutation<T> {
    Changed(T),
    Unchanged(T),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LpmJsonFileState {
    Existing,
    Missing,
}

impl<T> LpmJsonMutation<T> {
    pub fn into_inner(self) -> T {
        match self {
            Self::Changed(value) | Self::Unchanged(value) => value,
        }
    }

    pub fn is_changed(&self) -> bool {
        matches!(self, Self::Changed(_))
    }
}

#[derive(Debug, Error)]
pub enum LpmJsonTransactionError {
    #[error("failed to resolve project directory {path}: {source}")]
    ProjectDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("refusing to mutate lpm.json through a symbolic link or junction at {path}")]
    LinkedConfig { path: PathBuf },

    #[error("refusing to use a symbolic link or junction as the lpm.json lock directory at {path}")]
    LinkedStateDirectory { path: PathBuf },

    #[error("refusing to use a symbolic link or junction as the lpm.json lock file at {path}")]
    LinkedLockFile { path: PathBuf },

    #[error("lpm.json lock directory path is not a directory: {path}")]
    StatePathNotDirectory { path: PathBuf },

    #[error("lpm.json lock path is not a regular file: {path}")]
    LockPathNotFile { path: PathBuf },

    #[error("lpm.json path is not a regular file: {path}")]
    ConfigPathNotFile { path: PathBuf },

    #[error("failed to read lpm.json: {0}")]
    Read(#[from] BoundedReadError),

    #[error("failed to parse lpm.json: {0}")]
    Parse(#[source] serde_json::Error),

    #[error("failed to update lpm.json: top-level config must be an object")]
    RootNotObject,

    #[error("{0}")]
    Mutation(String),

    #[error("failed to serialize lpm.json: {0}")]
    Serialize(#[source] serde_json::Error),

    #[error("updated {path} exceeds {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },

    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("refusing to use a symbolic link or junction as project state at {path}")]
    LinkedLocalState { path: PathBuf },

    #[error("project state path is not a regular file: {path}")]
    LocalStatePathNotFile { path: PathBuf },

    #[error("failed to read project state: {0}")]
    ReadLocalState(#[source] BoundedReadError),

    #[error("failed to parse {path}: {source}")]
    ParseLocalState {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("{path} must hold a JSON object")]
    LocalStateNotObject { path: PathBuf },

    #[error("invalid project state file name {0:?}")]
    InvalidLocalStateName(String),
}

/// `lpm.json` and a project state file as [`read_lpm_json_with_local_state`]
/// read them; `None` is a missing file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LpmJsonAndLocalState {
    pub config: Option<Map<String, Value>>,
    pub local: Option<Map<String, Value>>,
}

/// What an [`update_lpm_json_with_local_state`] mutation edits: `lpm.json`
/// and a file in the project's `.lpm/` directory, which git never sees.
pub struct LpmJsonWithLocalState<'a> {
    pub config: &'a mut Map<String, Value>,
    pub config_state: LpmJsonFileState,
    pub local: &'a mut Map<String, Value>,
}

pub fn update_lpm_json<T>(
    project_dir: &Path,
    mutate: impl FnOnce(&mut Map<String, Value>, LpmJsonFileState) -> Result<LpmJsonMutation<T>, String>,
) -> Result<LpmJsonMutation<T>, LpmJsonTransactionError> {
    let locked = LockedProjectConfig::acquire(project_dir)?;
    let (mut root, file_state) = locked.read_config()?;
    let result = mutate(&mut root, file_state).map_err(LpmJsonTransactionError::Mutation)?;
    if result.is_changed() {
        locked.write_config(root)?;
    }
    Ok(result)
}

/// Runs `mutate` under the `lpm.json` lock with `lpm.json` and the project
/// state file `.lpm/<local_name>`, then writes what it changed: the state
/// file first, owner-only, then `lpm.json`. A state file left empty is
/// removed. Writing in that order lets [`read_lpm_json_with_local_state`]
/// read without the lock while a mutation moves a value from `lpm.json`
/// into the state file.
pub fn update_lpm_json_with_local_state<T>(
    project_dir: &Path,
    local_name: &str,
    mutate: impl FnOnce(LpmJsonWithLocalState<'_>) -> Result<T, String>,
) -> Result<T, LpmJsonTransactionError> {
    validate_local_state_name(local_name)?;
    let locked = LockedProjectConfig::acquire(project_dir)?;
    let (mut config, config_state) = locked.read_config()?;
    let local_path = locked.state_dir.join(local_name);
    let mut local = read_local_state(&local_path)?.unwrap_or_default();
    let original_config = config.clone();
    let original_local = local.clone();

    let result = mutate(LpmJsonWithLocalState {
        config: &mut config,
        config_state,
        local: &mut local,
    })
    .map_err(LpmJsonTransactionError::Mutation)?;

    if local != original_local {
        locked.recheck()?;
        write_local_state(&local_path, &local)?;
    }
    if config != original_config {
        locked.write_config(config)?;
    }
    Ok(result)
}

/// Reads `lpm.json`, then `.lpm/<local_name>`, without the lock; see
/// [`update_lpm_json_with_local_state`] for why that order is consistent.
/// A missing file reads as `None`.
pub fn read_lpm_json_with_local_state(
    project_dir: &Path,
    local_name: &str,
) -> Result<LpmJsonAndLocalState, LpmJsonTransactionError> {
    validate_local_state_name(local_name)?;
    let config_path = project_dir.join("lpm.json");
    let config = match open_config_nofollow(&config_path) {
        Ok(file) => {
            let metadata = file.metadata().map_err(|source| BoundedReadError::Io {
                path: config_path.clone(),
                source,
            })?;
            validate_opened_config(&config_path, &metadata)?;
            let (content, _) = read_text_file_capped_from_open_file(
                file,
                &config_path,
                CONFIG_FILE_SIZE_CAP_BYTES,
            )?;
            let value: Value = serde_json::from_str(crate::strip_utf8_bom_str(&content))
                .map_err(LpmJsonTransactionError::Parse)?;
            match value {
                Value::Object(map) => Some(map),
                _ => return Err(LpmJsonTransactionError::RootNotObject),
            }
        }
        Err(BoundedReadError::NotFound { .. }) => None,
        Err(error) => return Err(error.into()),
    };
    let local = read_project_local_state(project_dir, local_name)?;
    Ok(LpmJsonAndLocalState { config, local })
}

/// Reads the project state file `.lpm/<local_name>` without the lock. A
/// missing file reads as `None`.
pub fn read_project_local_state(
    project_dir: &Path,
    local_name: &str,
) -> Result<Option<Map<String, Value>>, LpmJsonTransactionError> {
    validate_local_state_name(local_name)?;
    let state_dir = crate::project_state_dir(project_dir);
    reject_linked_state_directory(&state_dir)?;
    read_local_state(&state_dir.join(local_name))
}

/// The `lpm.json` lock, held for one transaction.
struct LockedProjectConfig {
    path: PathBuf,
    state_dir: PathBuf,
    lock_path: PathBuf,
    _lock: crate::paths::SingleFileExclusiveLockHandle,
}

impl LockedProjectConfig {
    fn acquire(project_dir: &Path) -> Result<Self, LpmJsonTransactionError> {
        let project_dir = std::fs::canonicalize(project_dir).map_err(|source| {
            LpmJsonTransactionError::ProjectDirectory {
                path: project_dir.to_path_buf(),
                source,
            }
        })?;
        let path = project_dir.join("lpm.json");
        reject_linked_config(&path)?;
        let state_dir = crate::project_state_dir(&project_dir);
        reject_linked_state_directory(&state_dir)?;
        crate::ensure_project_state_dir(&project_dir).map_err(|source| {
            LpmJsonTransactionError::Write {
                path: state_dir.clone(),
                source,
            }
        })?;
        reject_linked_state_directory(&state_dir)?;
        let lock_path = state_dir.join(".config.lock");
        reject_linked_lock_file(&lock_path)?;
        let lock_file = open_lock_nofollow(&lock_path)?;
        validate_opened_lock(
            &lock_path,
            &lock_file
                .metadata()
                .map_err(|source| LpmJsonTransactionError::Write {
                    path: lock_path.clone(),
                    source,
                })?,
        )?;
        let lock = crate::paths::acquire_single_file_exclusive_lock_from_file(lock_file).map_err(
            |error| LpmJsonTransactionError::Write {
                path: lock_path.clone(),
                source: std::io::Error::other(error),
            },
        )?;
        let locked = Self {
            path,
            state_dir,
            lock_path,
            _lock: lock,
        };
        locked.recheck()?;
        Ok(locked)
    }

    fn recheck(&self) -> Result<(), LpmJsonTransactionError> {
        reject_linked_state_directory(&self.state_dir)?;
        reject_linked_lock_file(&self.lock_path)?;
        reject_linked_config(&self.path)
    }

    fn read_config(
        &self,
    ) -> Result<(Map<String, Value>, LpmJsonFileState), LpmJsonTransactionError> {
        let path = &self.path;
        let (content, file_state) = match open_config_nofollow(path) {
            Ok(file) => {
                let metadata = file.metadata().map_err(|source| BoundedReadError::Io {
                    path: path.clone(),
                    source,
                })?;
                validate_opened_config(path, &metadata)?;
                let (content, _) =
                    read_text_file_capped_from_open_file(file, path, CONFIG_FILE_SIZE_CAP_BYTES)?;
                (Some(content), LpmJsonFileState::Existing)
            }
            Err(BoundedReadError::NotFound { .. }) => (None, LpmJsonFileState::Missing),
            Err(error) => return Err(error.into()),
        };
        let value = match content {
            Some(content) => serde_json::from_str(crate::strip_utf8_bom_str(&content))
                .map_err(LpmJsonTransactionError::Parse)?,
            None => Value::Object(Map::new()),
        };
        match value {
            Value::Object(root) => Ok((root, file_state)),
            _ => Err(LpmJsonTransactionError::RootNotObject),
        }
    }

    fn write_config(&self, root: Map<String, Value>) -> Result<(), LpmJsonTransactionError> {
        self.recheck()?;
        let mut rendered = serde_json::to_string_pretty(&Value::Object(root))
            .map_err(LpmJsonTransactionError::Serialize)?;
        rendered.push('\n');
        if rendered.len() as u64 > CONFIG_FILE_SIZE_CAP_BYTES {
            return Err(LpmJsonTransactionError::TooLarge {
                path: self.path.clone(),
                limit: CONFIG_FILE_SIZE_CAP_BYTES,
            });
        }
        write_file_atomic_with_options(
            &self.path,
            rendered,
            AtomicWriteOptions::new().sync_file().sync_parent(),
        )
        .map_err(|source| LpmJsonTransactionError::Write {
            path: self.path.clone(),
            source,
        })
    }
}

fn validate_local_state_name(name: &str) -> Result<(), LpmJsonTransactionError> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(component)), None)
            if component == std::ffi::OsStr::new(name) =>
        {
            Ok(())
        }
        _ => Err(LpmJsonTransactionError::InvalidLocalStateName(
            name.to_owned(),
        )),
    }
}

fn read_local_state(path: &Path) -> Result<Option<Map<String, Value>>, LpmJsonTransactionError> {
    let file = match open_config_nofollow(path) {
        Ok(file) => file,
        Err(BoundedReadError::NotFound { .. }) => return Ok(None),
        Err(error) => {
            if std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| crate::is_symlink_or_junction(&metadata))
            {
                return Err(LpmJsonTransactionError::LinkedLocalState {
                    path: path.to_path_buf(),
                });
            }
            return Err(LpmJsonTransactionError::ReadLocalState(error));
        }
    };
    let metadata = file.metadata().map_err(|source| {
        LpmJsonTransactionError::ReadLocalState(BoundedReadError::Io {
            path: path.to_path_buf(),
            source,
        })
    })?;
    if crate::is_symlink_or_junction(&metadata) {
        return Err(LpmJsonTransactionError::LinkedLocalState {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(LpmJsonTransactionError::LocalStatePathNotFile {
            path: path.to_path_buf(),
        });
    }
    let (content, _) = read_text_file_capped_from_open_file(file, path, CONFIG_FILE_SIZE_CAP_BYTES)
        .map_err(LpmJsonTransactionError::ReadLocalState)?;
    match serde_json::from_str(crate::strip_utf8_bom_str(&content)) {
        Ok(Value::Object(map)) => Ok(Some(map)),
        Ok(_) => Err(LpmJsonTransactionError::LocalStateNotObject {
            path: path.to_path_buf(),
        }),
        Err(source) => Err(LpmJsonTransactionError::ParseLocalState {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_local_state(
    path: &Path,
    local: &Map<String, Value>,
) -> Result<(), LpmJsonTransactionError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if crate::is_symlink_or_junction(&metadata) => {
            return Err(LpmJsonTransactionError::LinkedLocalState {
                path: path.to_path_buf(),
            });
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(LpmJsonTransactionError::LocalStatePathNotFile {
                path: path.to_path_buf(),
            });
        }
        _ => {}
    }
    if local.is_empty() {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(LpmJsonTransactionError::Write {
                path: path.to_path_buf(),
                source,
            }),
        };
    }
    let mut rendered =
        serde_json::to_string_pretty(local).map_err(LpmJsonTransactionError::Serialize)?;
    rendered.push('\n');
    if rendered.len() as u64 > CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(LpmJsonTransactionError::TooLarge {
            path: path.to_path_buf(),
            limit: CONFIG_FILE_SIZE_CAP_BYTES,
        });
    }
    write_file_atomic_with_options(
        path,
        rendered,
        AtomicWriteOptions::new()
            .unix_mode(0o600)
            .sync_file()
            .sync_parent(),
    )
    .map_err(|source| LpmJsonTransactionError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn open_config_nofollow(path: &Path) -> Result<File, BoundedReadError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // Non-blocking, so a FIFO in place of the file fails the regular-file
        // check instead of waiting for a writer.
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            BoundedReadError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            BoundedReadError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn open_lock_nofollow(path: &Path) -> Result<File, LpmJsonTransactionError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|source| {
        if std::fs::symlink_metadata(path)
            .is_ok_and(|metadata| crate::is_symlink_or_junction(&metadata))
        {
            LpmJsonTransactionError::LinkedLockFile {
                path: path.to_path_buf(),
            }
        } else {
            LpmJsonTransactionError::Write {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn validate_opened_config(path: &Path, metadata: &Metadata) -> Result<(), LpmJsonTransactionError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LpmJsonTransactionError::LinkedConfig {
                path: path.to_path_buf(),
            });
        }
    }
    if !metadata.is_file() {
        return Err(LpmJsonTransactionError::ConfigPathNotFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_opened_lock(path: &Path, metadata: &Metadata) -> Result<(), LpmJsonTransactionError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LpmJsonTransactionError::LinkedLockFile {
                path: path.to_path_buf(),
            });
        }
    }
    if !metadata.is_file() {
        return Err(LpmJsonTransactionError::LockPathNotFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_linked_state_directory(path: &Path) -> Result<(), LpmJsonTransactionError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if crate::is_symlink_or_junction(&metadata) => {
            Err(LpmJsonTransactionError::LinkedStateDirectory {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if !metadata.is_dir() => Err(LpmJsonTransactionError::StatePathNotDirectory {
            path: path.to_path_buf(),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(LpmJsonTransactionError::ProjectDirectory {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn reject_linked_config(path: &Path) -> Result<(), LpmJsonTransactionError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if crate::is_symlink_or_junction(&metadata) => {
            Err(LpmJsonTransactionError::LinkedConfig {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(LpmJsonTransactionError::ConfigPathNotFile {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(LpmJsonTransactionError::ProjectDirectory {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn reject_linked_lock_file(path: &Path) -> Result<(), LpmJsonTransactionError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if crate::is_symlink_or_junction(&metadata) => {
            Err(LpmJsonTransactionError::LinkedLockFile {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(LpmJsonTransactionError::LockPathNotFile {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(LpmJsonTransactionError::ProjectDirectory {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn concurrent_transactions_preserve_both_updates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "{}\n").unwrap();
        let project = dir.path().to_path_buf();
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();

        let first_project = project.clone();
        let first = std::thread::spawn(move || {
            update_lpm_json(&first_project, |root, _| {
                first_entered_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
                root.insert("runtime".into(), serde_json::json!({"node": "22"}));
                Ok(LpmJsonMutation::Changed(()))
            })
        });
        first_entered_rx.recv().unwrap();

        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second_project = project.clone();
        let second = std::thread::spawn(move || {
            update_lpm_json(&second_project, |root, _| {
                second_entered_tx.send(()).unwrap();
                root.insert("vault".into(), Value::String("vault-123".into()));
                Ok(LpmJsonMutation::Changed(()))
            })
        });

        let entered_while_first_was_active = second_entered_rx
            .recv_timeout(Duration::from_millis(200))
            .is_ok();
        release_first_tx.send(()).unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();

        assert!(
            !entered_while_first_was_active,
            "a second transaction entered while the first transaction was active"
        );
        let final_value: Value =
            serde_json::from_str(&std::fs::read_to_string(project.join("lpm.json")).unwrap())
                .unwrap();
        assert_eq!(final_value["runtime"]["node"], "22");
        assert_eq!(final_value["vault"], "vault-123");
    }

    #[test]
    fn oversized_render_is_rejected_without_modifying_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.json");
        std::fs::write(&path, "{}\n").unwrap();
        let oversized = "x".repeat(CONFIG_FILE_SIZE_CAP_BYTES as usize);

        let error = update_lpm_json(dir.path(), |root, _| {
            root.insert("custom".into(), Value::String(oversized));
            Ok(LpmJsonMutation::Changed(()))
        })
        .expect_err("oversized output must be rejected");

        assert!(matches!(error, LpmJsonTransactionError::TooLarge { .. }));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{}\n");
    }

    #[cfg(unix)]
    #[test]
    fn linked_config_is_rejected_without_reading_or_modifying_its_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "{}\n").unwrap();
        symlink(outside.path(), dir.path().join("lpm.json")).unwrap();

        let error = update_lpm_json(dir.path(), |root, _| {
            root.insert("custom".into(), Value::Bool(true));
            Ok(LpmJsonMutation::Changed(()))
        })
        .expect_err("a linked lpm.json must be rejected");

        assert!(matches!(
            error,
            LpmJsonTransactionError::LinkedConfig { .. }
        ));
        assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "{}\n");
    }

    #[cfg(unix)]
    #[test]
    fn linked_state_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), dir.path().join(".lpm")).unwrap();

        let error = update_lpm_json(dir.path(), |root, _| {
            root.insert("custom".into(), Value::Bool(true));
            Ok(LpmJsonMutation::Changed(()))
        })
        .expect_err("linked lock directory must be rejected");

        assert!(matches!(
            error,
            LpmJsonTransactionError::LinkedStateDirectory { .. }
        ));
        assert!(!outside.path().join(".config.lock").exists());
        assert!(!dir.path().join("lpm.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn linked_lock_file_is_rejected_without_creating_its_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join(".lpm");
        std::fs::create_dir(&state_dir).unwrap();
        let outside_target = outside.path().join("created-through-lock-link");
        symlink(&outside_target, state_dir.join(".config.lock")).unwrap();

        let error = update_lpm_json(dir.path(), |root, _| {
            root.insert("custom".into(), Value::Bool(true));
            Ok(LpmJsonMutation::Changed(()))
        })
        .expect_err("linked lock file must be rejected");

        assert!(error.to_string().contains("symbolic link"));
        assert!(!outside_target.exists());
        assert!(!dir.path().join("lpm.json").exists());
    }

    #[test]
    fn local_state_moves_out_of_lpm_json_in_one_transaction() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"vault":"v1","legacy":{"version":3}}"#,
        )
        .unwrap();

        update_lpm_json_with_local_state(dir.path(), "state.json", |files| {
            let legacy = files.config.remove("legacy").unwrap();
            files.local.insert("moved".into(), legacy);
            Ok(())
        })
        .unwrap();

        let LpmJsonAndLocalState { config, local } =
            read_lpm_json_with_local_state(dir.path(), "state.json").unwrap();
        assert_eq!(
            Value::Object(config.unwrap()),
            serde_json::json!({"vault": "v1"})
        );
        assert_eq!(
            Value::Object(local.unwrap()),
            serde_json::json!({"moved": {"version": 3}})
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join(".lpm/state.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn local_state_change_leaves_lpm_json_bytes_alone() {
        let dir = tempfile::tempdir().unwrap();
        let original = "{ \"vault\": \"v1\" }";
        std::fs::write(dir.path().join("lpm.json"), original).unwrap();

        update_lpm_json_with_local_state(dir.path(), "state.json", |files| {
            files.local.insert("version".into(), serde_json::json!(4));
            Ok(())
        })
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("lpm.json")).unwrap(),
            original
        );
    }

    #[test]
    fn local_state_left_empty_is_removed_and_lpm_json_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        update_lpm_json_with_local_state(dir.path(), "state.json", |files| {
            files.local.insert("version".into(), serde_json::json!(1));
            Ok(())
        })
        .unwrap();
        assert!(dir.path().join(".lpm/state.json").is_file());

        update_lpm_json_with_local_state(dir.path(), "state.json", |files| {
            files.local.clear();
            Ok(())
        })
        .unwrap();

        assert!(!dir.path().join(".lpm/state.json").exists());
        assert!(!dir.path().join("lpm.json").exists());
    }

    #[test]
    fn failed_mutation_writes_neither_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "{}\n").unwrap();

        let error = update_lpm_json_with_local_state(dir.path(), "state.json", |files| {
            files
                .config
                .insert("vault".into(), Value::String("v1".into()));
            files.local.insert("version".into(), serde_json::json!(1));
            Err::<(), _>("refused".to_owned())
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "refused");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("lpm.json")).unwrap(),
            "{}\n"
        );
        assert!(!dir.path().join(".lpm/state.json").exists());
    }

    #[test]
    fn local_state_that_is_not_an_object_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".lpm")).unwrap();
        std::fs::write(dir.path().join(".lpm/state.json"), "[]").unwrap();

        let error = read_lpm_json_with_local_state(dir.path(), "state.json").unwrap_err();

        assert!(matches!(
            error,
            LpmJsonTransactionError::LocalStateNotObject { .. }
        ));
    }

    #[test]
    fn local_state_name_must_be_one_file_name() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["", "..", "nested/state.json", "/state.json"] {
            let error = update_lpm_json_with_local_state(dir.path(), name, |_| Ok(())).unwrap_err();
            assert!(
                matches!(error, LpmJsonTransactionError::InvalidLocalStateName(_)),
                "{name:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn fifo_lpm_json_or_state_file_is_rejected_without_waiting_for_a_writer() {
        for fifo in ["lpm.json", ".lpm/state.json"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join(".lpm")).unwrap();
            let path = dir.path().join(fifo);
            let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

            let (done_tx, done_rx) = mpsc::channel();
            let project = dir.path().to_path_buf();
            std::thread::spawn(move || {
                let read = read_lpm_json_with_local_state(&project, "state.json").is_err();
                let update = update_lpm_json_with_local_state(&project, "state.json", |files| {
                    files.local.insert("version".into(), serde_json::json!(1));
                    Ok(())
                })
                .is_err();
                done_tx.send((read, update)).unwrap();
            });

            let (read_failed, update_failed) = done_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("{fifo}: blocked waiting for a FIFO writer"));
            assert!(read_failed && update_failed, "{fifo}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn linked_local_state_is_rejected_without_reading_or_modifying_its_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "{}").unwrap();
        std::fs::create_dir(dir.path().join(".lpm")).unwrap();
        symlink(outside.path(), dir.path().join(".lpm/state.json")).unwrap();

        let error = update_lpm_json_with_local_state(dir.path(), "state.json", |files| {
            files.local.insert("version".into(), serde_json::json!(1));
            Ok(())
        })
        .unwrap_err();

        assert!(matches!(
            error,
            LpmJsonTransactionError::LinkedLocalState { .. }
        ));
        assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "{}");
    }

    #[test]
    fn config_directory_is_rejected_without_modifying_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.json");
        std::fs::create_dir(&path).unwrap();

        let error = update_lpm_json(dir.path(), |root, _| {
            root.insert("custom".into(), Value::Bool(true));
            Ok(LpmJsonMutation::Changed(()))
        })
        .expect_err("an lpm.json directory must be rejected");

        assert!(matches!(
            error,
            LpmJsonTransactionError::ConfigPathNotFile { .. }
        ));
        assert!(path.is_dir());
    }
}
