use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::{Dir, File, OpenOptions};
use lpm_common::LpmError;
use std::ffi::{OsStr, OsString};
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
    let mode = if regular_exists(&directory, &name)? {
        Some(file_mode(&open_regular(&directory, &name)?)?)
    } else {
        None
    };
    lpm_common::write_file_atomic_in_dir_with_options(
        &directory,
        &name,
        keeping_private(mode).sync_file().sync_parent(),
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

/// The SHA-256 and permission bits of the regular file at `path`, or
/// `None` when it is absent.
pub(super) fn current_state(root: &Path, path: &Path) -> Result<Option<(String, u32)>, LpmError> {
    let Some((directory, name)) = parent(root, path, false)? else {
        return Ok(None);
    };
    if !regular_exists(&directory, &name)? {
        return Ok(None);
    }
    let file = open_regular(&directory, &name)?;
    let mode = file_mode(&file)?;
    Ok(Some((hash(file)?, mode)))
}

fn hash(file: File) -> Result<String, LpmError> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let copied = io::copy(&mut file.take(FILE_LIMIT + 1), &mut hasher)?;
    if copied > FILE_LIMIT {
        return Err(LpmError::Script("migration file exceeds size limit".into()));
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(unix)]
fn file_mode(file: &File) -> Result<u32, LpmError> {
    use cap_std::fs::PermissionsExt as _;
    Ok(file.metadata()?.permissions().mode() & 0o7777)
}

/// Windows has no mode bits: a file whose DACL keeps others out reads as
/// 0600, so [`keeping_private`] restores it to its owner as it does on
/// Unix, and any other as 0644.
#[cfg(windows)]
fn file_mode(file: &File) -> Result<u32, LpmError> {
    Ok(if lpm_common::owner_only::keeps_others_out(file)? {
        0o600
    } else {
        0o644
    })
}

#[cfg(not(any(unix, windows)))]
fn file_mode(_file: &File) -> Result<u32, LpmError> {
    Ok(0o644)
}

/// Opens `<root>/.lpm/migrate-backup` and its `files` store, creating them
/// owner-only when `create` is set; `None` when absent and not created.
pub(super) fn backup_store(root: &Path, create: bool) -> Result<Option<(Dir, Dir)>, LpmError> {
    let project = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    let state = if create {
        lpm_common::ensure_project_state_dir_in(&project, root)?
    } else {
        match project.open_dir_nofollow(lpm_common::PROJECT_STATE_DIR) {
            Ok(state) => state,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    };
    let Some(backup) = open_child_dir(&state, super::BACKUP_DIR, create)? else {
        return Ok(None);
    };
    let Some(blobs) = open_child_dir(&backup, super::BLOBS_DIR, create)? else {
        return Ok(None);
    };
    Ok(Some((backup, blobs)))
}

fn open_child_dir(parent: &Dir, name: &str, create: bool) -> Result<Option<Dir>, LpmError> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => return Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LpmError::Script(format!(
                "refusing linked or inaccessible migration backup directory {name}: {error}"
            )));
        }
    }
    #[cfg(unix)]
    let builder = {
        use cap_std::fs::DirBuilderExt as _;
        let mut builder = cap_std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = cap_std::fs::DirBuilder::new();
    match parent.create_dir_with(name, &builder) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let directory = parent.open_dir_nofollow(name)?;
    #[cfg(target_os = "macos")]
    drop_inherited_access(&directory)?;
    Ok(Some(directory))
}

/// Writes a file that replaces or restores one of `mode`: owner-only, with
/// that mode, when the mode keeps the file to its owner, so a new file
/// doesn't take the access its directory passes on; else with that mode.
fn keeping_private(mode: Option<u32>) -> lpm_common::AtomicWriteOptions {
    match mode {
        Some(mode) if mode & 0o077 == 0 => lpm_common::AtomicWriteOptions::new()
            .owner_only()
            .unix_mode(mode),
        Some(mode) => lpm_common::AtomicWriteOptions::new().unix_mode(mode),
        None => lpm_common::AtomicWriteOptions::new(),
    }
}

/// Removes the extended ACL entries a backup directory inherited, which
/// its mode doesn't show, so no one else lists or reads what it holds.
#[cfg(target_os = "macos")]
fn drop_inherited_access(directory: &Dir) -> Result<(), LpmError> {
    Ok(lpm_common::macos_acl::drop_extended_acl(directory)?)
}

/// Copies the regular file at `path` into `blobs` under its SHA-256 and
/// returns that and its permission bits.
pub(super) fn store_blob(root: &Path, path: &Path, blobs: &Dir) -> Result<(String, u32), LpmError> {
    let (directory, name) = parent(root, path, false)?
        .ok_or_else(|| LpmError::Script("migration source disappeared".into()))?;
    let source = open_regular(&directory, &name)?;
    let mode = file_mode(&source)?;
    let sha256 = hash(source)?;
    if blobs.symlink_metadata(&sha256).is_ok() {
        if hash(open_regular(blobs, &OsString::from(&sha256))?)? == sha256 {
            return Ok((sha256, mode));
        }
        blobs.remove_file(&sha256)?;
    }
    let mut source = open_regular(&directory, &name)?;
    lpm_common::write_file_atomic_in_dir_with_options(
        blobs,
        OsStr::new(&sha256),
        lpm_common::AtomicWriteOptions::new()
            .owner_only()
            .sync_file()
            .sync_parent(),
        |file| copy_bounded(&mut source, file),
    )?;
    if hash(open_regular(blobs, &OsString::from(&sha256))?)? != sha256 {
        return Err(LpmError::Script(format!(
            "{} changed while it was being backed up; retry the migration",
            path.display()
        )));
    }
    Ok((sha256, mode))
}

/// Removes every stored copy whose name isn't in `keep`.
pub(super) fn remove_blobs_except(
    blobs: &Dir,
    keep: &std::collections::HashSet<&str>,
) -> Result<(), LpmError> {
    for entry in blobs.entries()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if name.to_str().is_some_and(|name| keep.contains(name)) {
            continue;
        }
        match blobs.remove_file(&name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Restores `path` to the stored copy `sha256` with `mode`, checking the
/// copy first, or removes it when `stored` is `None`. Returns whether it
/// changed anything.
pub(super) fn restore(
    root: &Path,
    path: &Path,
    blobs: &Dir,
    stored: Option<(&str, u32)>,
) -> Result<bool, LpmError> {
    match stored {
        Some((sha256, mode)) => {
            let blob = OsString::from(sha256);
            if hash(open_regular(blobs, &blob)?)? != sha256 {
                return Err(LpmError::Script(format!(
                    "the backup of {} is damaged; nothing was restored from it",
                    path.display()
                )));
            }
            let (directory, name) = parent(root, path, true)?.expect("created parent");
            regular_exists(&directory, &name)?;
            let mut source = open_regular(blobs, &blob)?;
            lpm_common::write_file_atomic_in_dir_with_options(
                &directory,
                &name,
                keeping_private(Some(mode)).sync_file().sync_parent(),
                |file| copy_bounded(&mut source, file),
            )?;
            Ok(true)
        }
        None => {
            let Some((directory, name)) = parent(root, path, false)? else {
                return Ok(false);
            };
            if !regular_exists(&directory, &name)? {
                return Ok(false);
            }
            directory.remove_file(&name)?;
            sync_directory(&directory)?;
            Ok(true)
        }
    }
}

/// Whether the directory at `path` is absent; the first missing ancestor
/// is what a write there creates.
pub(super) fn directory_missing(root: &Path, path: &Path) -> Result<bool, LpmError> {
    let rel = relative(root, path)?;
    let mut directory = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    for part in rel.components() {
        directory = match directory.open_dir_nofollow(part.as_os_str()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(error) => {
                return Err(LpmError::Script(format!(
                    "refusing linked or inaccessible migration directory {}: {error}",
                    path.display()
                )));
            }
        };
    }
    Ok(false)
}

/// Removes the directory at `path` when it is empty.
pub(super) fn remove_empty_directory(root: &Path, path: &Path) -> Result<(), LpmError> {
    if let Some((directory, name)) = parent(root, path, false)? {
        let _ = directory.remove_dir(&name);
    }
    Ok(())
}
