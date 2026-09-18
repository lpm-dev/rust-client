use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::{Dir, File, OpenOptions};
use lpm_common::LpmError;
use std::ffi::OsString;
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path};

const FILE_LIMIT: u64 = crate::FOREIGN_LOCKFILE_SIZE_CAP_BYTES;

pub(super) fn relative<'a>(root: &Path, path: &'a Path) -> Result<&'a Path, LpmError> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| LpmError::Script(format!("{} is outside the project root", path.display())))?;
    if rel.as_os_str().is_empty()
        || !rel
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(LpmError::Script(format!(
            "invalid migration path {}",
            path.display()
        )));
    }
    Ok(rel)
}

fn parent(root: &Path, path: &Path, create: bool) -> Result<Option<(Dir, OsString)>, LpmError> {
    let rel = relative(root, path)?;
    let mut directory = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    for part in rel.parent().unwrap_or(Path::new("")).components() {
        directory = match directory.open_dir_nofollow(part.as_os_str()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                match directory.create_dir(part.as_os_str()) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                directory.open_dir_nofollow(part.as_os_str())?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(LpmError::Script(format!(
                    "refusing linked or inaccessible migration directory {}: {error}",
                    path.display()
                )));
            }
        };
    }
    Ok(Some((
        directory,
        rel.file_name().expect("validated leaf").to_os_string(),
    )))
}

fn regular_exists(directory: &Dir, name: &OsString) -> Result<bool, LpmError> {
    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let linked = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let linked = {
        use cap_std::fs::MetadataExt as _;
        linked || metadata.file_attributes() & 0x0400 != 0
    };
    if linked || !metadata.is_file() || metadata.len() > FILE_LIMIT {
        return Err(LpmError::Script(format!(
            "migration requires a bounded regular file: {}",
            name.to_string_lossy()
        )));
    }
    Ok(true)
}

fn open_regular(directory: &Dir, name: &OsString) -> Result<File, LpmError> {
    regular_exists(directory, name)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = directory.open_with(name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > FILE_LIMIT {
        return Err(LpmError::Script(
            "migration requires a bounded regular file".into(),
        ));
    }
    Ok(file)
}

pub(super) fn exists(root: &Path, path: &Path) -> Result<bool, LpmError> {
    match parent(root, path, false)? {
        Some((directory, name)) => regular_exists(&directory, &name),
        None => Ok(false),
    }
}

pub(super) fn validate(root: &Path, path: &Path) -> Result<(), LpmError> {
    exists(root, path).map(|_| ())
}

pub(super) fn read(root: &Path, path: &Path, limit: u64) -> Result<Option<Vec<u8>>, LpmError> {
    let Some((directory, name)) = parent(root, path, false)? else {
        return Ok(None);
    };
    if !regular_exists(&directory, &name)? {
        return Ok(None);
    }
    let file = open_regular(&directory, &name)?;
    if file.metadata()?.len() > limit {
        return Err(LpmError::Script(
            "migration state exceeds size limit".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(LpmError::Script(
            "migration state exceeds size limit".into(),
        ));
    }
    Ok(Some(bytes))
}

fn copy_bounded(source: &mut File, destination: &mut File) -> Result<(), LpmError> {
    let copied = io::copy(&mut source.take(FILE_LIMIT + 1), destination)?;
    if copied > FILE_LIMIT {
        return Err(LpmError::Script("migration file exceeds size limit".into()));
    }
    destination.sync_all()?;
    Ok(())
}

pub(super) fn create_backup(root: &Path, source: &Path, backup: &Path) -> Result<(), LpmError> {
    let (directory, name) = parent(root, source, false)?
        .ok_or_else(|| LpmError::Script("migration source disappeared".into()))?;
    let mut source = open_regular(&directory, &name)?;
    let (directory, name) = parent(root, backup, false)?
        .ok_or_else(|| LpmError::Script("migration backup directory disappeared".into()))?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut destination = directory.open_with(&name, &options)?;
    if let Err(error) = copy_bounded(&mut source, &mut destination) {
        drop(destination);
        let _ = directory.remove_file(&name);
        return Err(error);
    }
    sync_directory(&directory)?;
    Ok(())
}

fn sync_directory(directory: &Dir) -> Result<(), LpmError> {
    #[cfg(unix)]
    // Reopen through the capability: Linux O_PATH descriptors cannot be synced.
    directory.open(".")?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

pub(super) fn write(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), LpmError> {
    let (directory, name) = parent(root, path, true)?.expect("created parent");
    regular_exists(&directory, &name)?;
    lpm_common::write_file_atomic_in_dir_with_options(
        &directory,
        &name,
        lpm_common::AtomicWriteOptions::new()
            .sync_file()
            .sync_parent(),
        |file| -> Result<(), LpmError> {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        },
    )
}

pub(super) fn remove(root: &Path, path: &Path) -> Result<(), LpmError> {
    if let Some((directory, name)) = parent(root, path, false)?
        && regular_exists(&directory, &name)?
    {
        directory.remove_file(name)?;
        sync_directory(&directory)?;
    }
    Ok(())
}

pub(super) struct Restore {
    destination: Option<(Dir, OsString)>,
    source: Option<File>,
}

impl Restore {
    pub(super) fn prepare(
        root: &Path,
        original: &Path,
        backup: &Path,
        existed: bool,
    ) -> Result<Self, LpmError> {
        let destination = parent(root, original, false)?;
        if let Some((directory, name)) = &destination {
            regular_exists(directory, name)?;
        }
        let source = if existed {
            let (directory, name) = parent(root, backup, false)?
                .ok_or_else(|| LpmError::Script("missing migration backup directory".into()))?;
            Some(open_regular(&directory, &name)?)
        } else {
            None
        };
        if existed && destination.is_none() {
            return Err(LpmError::Script(format!(
                "restore directory is missing for {}",
                original.display()
            )));
        }
        Ok(Self {
            destination,
            source,
        })
    }

    pub(super) fn apply(&mut self) -> Result<bool, LpmError> {
        let Some((directory, name)) = &self.destination else {
            return Ok(false);
        };
        regular_exists(directory, name)?;
        if let Some(source) = &mut self.source {
            lpm_common::write_file_atomic_in_dir_with_options(
                directory,
                name,
                lpm_common::AtomicWriteOptions::new()
                    .unix_mode(0o600)
                    .sync_file()
                    .sync_parent(),
                |file| copy_bounded(source, file),
            )?;
        } else if regular_exists(directory, name)? {
            directory.remove_file(name)?;
            sync_directory(directory)?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }
}

pub(super) fn cleanup_empty_parents(root: &Path, file: &Path) -> Result<(), LpmError> {
    let mut ancestor = file.parent();
    while let Some(path) = ancestor
        && path != root
    {
        let Some((directory, name)) = parent(root, path, false)? else {
            break;
        };
        if directory.remove_dir(&name).is_err() {
            break;
        }
        ancestor = path.parent();
    }
    Ok(())
}
