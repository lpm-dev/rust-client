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

    #[error("updated lpm.json at {path} exceeds {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },

    #[error("failed to write lpm.json at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn update_lpm_json<T>(
    project_dir: &Path,
    mutate: impl FnOnce(&mut Map<String, Value>, LpmJsonFileState) -> Result<LpmJsonMutation<T>, String>,
) -> Result<LpmJsonMutation<T>, LpmJsonTransactionError> {
    let project_dir = std::fs::canonicalize(project_dir).map_err(|source| {
        LpmJsonTransactionError::ProjectDirectory {
            path: project_dir.to_path_buf(),
            source,
        }
    })?;
    let path = project_dir.join("lpm.json");
    reject_linked_config(&path)?;
    let state_dir = project_dir.join(".lpm");
    reject_linked_state_directory(&state_dir)?;
    std::fs::create_dir_all(&state_dir).map_err(|source| LpmJsonTransactionError::Write {
        path: state_dir.clone(),
        source,
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
    let _lock =
        crate::paths::acquire_single_file_exclusive_lock_from_file(lock_file).map_err(|error| {
            LpmJsonTransactionError::Write {
                path: lock_path.clone(),
                source: std::io::Error::other(error),
            }
        })?;
    reject_linked_state_directory(&state_dir)?;
    reject_linked_lock_file(&lock_path)?;
    reject_linked_config(&path)?;

    let (content, file_state) = match open_config_nofollow(&path) {
        Ok(file) => {
            let metadata = file.metadata().map_err(|source| BoundedReadError::Io {
                path: path.clone(),
                source,
            })?;
            validate_opened_config(&path, &metadata)?;
            let (content, _) =
                read_text_file_capped_from_open_file(file, &path, CONFIG_FILE_SIZE_CAP_BYTES)?;
            (Some(content), LpmJsonFileState::Existing)
        }
        Err(BoundedReadError::NotFound { .. }) => (None, LpmJsonFileState::Missing),
        Err(error) => return Err(error.into()),
    };
    let mut value = match content {
        Some(content) => serde_json::from_str(&content).map_err(LpmJsonTransactionError::Parse)?,
        None => Value::Object(Map::new()),
    };
    let root = value
        .as_object_mut()
        .ok_or(LpmJsonTransactionError::RootNotObject)?;
    let result = mutate(root, file_state).map_err(LpmJsonTransactionError::Mutation)?;
    if !result.is_changed() {
        return Ok(result);
    }
    reject_linked_state_directory(&state_dir)?;
    reject_linked_lock_file(&lock_path)?;
    reject_linked_config(&path)?;

    let mut rendered =
        serde_json::to_string_pretty(&value).map_err(LpmJsonTransactionError::Serialize)?;
    rendered.push('\n');
    if rendered.len() as u64 > CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(LpmJsonTransactionError::TooLarge {
            path,
            limit: CONFIG_FILE_SIZE_CAP_BYTES,
        });
    }
    write_file_atomic_with_options(
        &path,
        rendered,
        AtomicWriteOptions::new().sync_file().sync_parent(),
    )
    .map_err(|source| LpmJsonTransactionError::Write {
        path: path.clone(),
        source,
    })?;
    Ok(result)
}

fn open_config_nofollow(path: &Path) -> Result<File, BoundedReadError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW);
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

        options.custom_flags(libc::O_NOFOLLOW);
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
