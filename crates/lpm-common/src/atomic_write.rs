use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const TEMP_CREATE_ATTEMPTS: usize = 32;
const TEMP_RANDOM_BYTES: usize = 12;

/// Permission and synchronization policy for an atomic file replacement.
#[derive(Debug, Clone, Copy, Default)]
pub struct AtomicWriteOptions {
    unix_mode: Option<u32>,
    sync_file: bool,
    sync_parent: bool,
}

impl AtomicWriteOptions {
    /// Preserve an existing regular file's mode, or use the process umask
    /// when creating a new destination.
    pub const fn new() -> Self {
        Self {
            unix_mode: None,
            sync_file: false,
            sync_parent: false,
        }
    }

    /// Set the exact final Unix mode. This is ignored on non-Unix platforms.
    pub const fn unix_mode(mut self, mode: u32) -> Self {
        self.unix_mode = Some(mode);
        self
    }

    /// Synchronize the file contents before replacing the destination.
    pub const fn sync_file(mut self) -> Self {
        self.sync_file = true;
        self
    }

    /// Synchronize the parent directory after replacement where supported.
    ///
    /// An error can be returned after the destination has already been
    /// replaced if the directory synchronization fails.
    pub const fn sync_parent(mut self) -> Self {
        self.sync_parent = true;
        self
    }
}

/// Rewrite `path` through a same-directory temporary file and atomic replace.
///
/// Readers of `path` observe either the previous complete file or the new
/// complete file; they never observe the truncate-then-write window created by
/// `std::fs::write` on an existing path. Existing destination symlinks are
/// replaced as path entries and are never dereferenced.
///
/// This guarantees atomic visibility, not crash-durable persistence.
pub fn write_file_atomic(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    write_file_atomic_with_options(path, contents, AtomicWriteOptions::new())
}

/// Rewrite `path` with explicit permission and synchronization options.
pub fn write_file_atomic_with_options(
    path: &Path,
    contents: impl AsRef<[u8]>,
    options: AtomicWriteOptions,
) -> io::Result<()> {
    write_file_atomic_with(path, options, |file| file.write_all(contents.as_ref()))
}

/// Rewrite `path` through one exclusively-created temporary file handle.
///
/// The callback can stream or copy content without reopening the temporary
/// path. Cleanup removes only a file this invocation successfully created.
pub fn write_file_atomic_with<T, E>(
    path: &Path,
    options: AtomicWriteOptions,
    write: impl FnOnce(&mut File) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<io::Error>,
{
    let parent = destination_parent(path).map_err(E::from)?;
    let exact_mode = destination_mode(path, options).map_err(E::from)?;
    let mut temporary =
        create_temporary(parent, exact_mode, || random_temp_path(parent)).map_err(E::from)?;

    let output = write(temporary.file_mut().map_err(E::from)?)?;
    if let Some(mode) = exact_mode {
        set_file_mode(temporary.file().map_err(E::from)?, mode).map_err(E::from)?;
    }
    if options.sync_file {
        temporary
            .file()
            .map_err(E::from)?
            .sync_all()
            .map_err(E::from)?;
    }
    temporary.commit(path).map_err(E::from)?;

    if options.sync_parent {
        sync_parent(parent).map_err(E::from)?;
    }
    Ok(output)
}

/// Atomically replace a Unix symlink path without a predictable staging name.
#[cfg(unix)]
pub fn replace_symlink_atomic(path: &Path, target: &Path) -> io::Result<()> {
    let parent = destination_parent(path)?;
    let mut last_collision = None;
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let temporary = random_temp_path(parent)?;
        match std::os::unix::fs::symlink(target, &temporary) {
            Ok(()) => {
                let mut created = CreatedPath::new(temporary);
                replace_file(created.path(), path)?;
                created.disarm();
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate an exclusive temporary symlink",
        )
    }))
}

fn destination_parent(path: &Path) -> io::Result<&Path> {
    path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no file name: {}", path.display()),
        )
    })?;
    Ok(match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    })
}

#[cfg(unix)]
fn destination_mode(path: &Path, options: AtomicWriteOptions) -> io::Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(mode) = options.unix_mode {
        return Ok(Some(mode & 0o7777));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            Ok(Some(metadata.permissions().mode() & 0o7777))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn destination_mode(_path: &Path, _options: AtomicWriteOptions) -> io::Result<Option<u32>> {
    Ok(None)
}

fn random_temp_path(parent: &Path) -> io::Result<PathBuf> {
    use base64::Engine;

    let mut random = [0u8; TEMP_RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(|error| {
        io::Error::other(format!("failed to generate temporary file name: {error}"))
    })?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    Ok(parent.join(format!(".lpm-{encoded}")))
}

fn create_temporary(
    parent: &Path,
    exact_mode: Option<u32>,
    mut next_path: impl FnMut() -> io::Result<PathBuf>,
) -> io::Result<CreatedTemporary> {
    let mut last_collision = None;
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let path = next_path()?;
        if path.parent() != Some(parent) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "temporary file path must be in the destination directory",
            ));
        }

        match open_temporary(&path, exact_mode) {
            Ok(file) => return Ok(CreatedTemporary::new(path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }

    Err(last_collision.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate an exclusive temporary file",
        )
    }))
}

fn open_temporary(path: &Path, exact_mode: Option<u32>) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(not(unix))]
    let _ = exact_mode;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(exact_mode.unwrap_or(0o666));
    }
    options.open(path)
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> io::Result<()> {
    Ok(())
}

struct CreatedTemporary {
    path: PathBuf,
    file: Option<File>,
    cleanup: bool,
}

impl CreatedTemporary {
    fn new(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file: Some(file),
            cleanup: true,
        }
    }

    fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("temporary file is already committed"))
    }

    fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("temporary file is already committed"))
    }

    fn commit(&mut self, destination: &Path) -> io::Result<()> {
        drop(self.file.take());
        replace_file(&self.path, destination)?;
        self.cleanup = false;
        Ok(())
    }
}

impl Drop for CreatedTemporary {
    fn drop(&mut self) {
        drop(self.file.take());
        if self.cleanup {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
struct CreatedPath {
    path: PathBuf,
    cleanup: bool,
}

#[cfg(unix)]
impl CreatedPath {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            cleanup: true,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.cleanup = false;
    }
}

#[cfg(unix)]
impl Drop for CreatedPath {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    let from = wide(from);
    let to = wide(to);
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    for delay_ms in [0, 50, 150, 450, 1_350, 4_050] {
        if delay_ms != 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        // SAFETY: both pointers reference nul-terminated UTF-16 buffers that
        // live for the duration of the call.
        let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) };
        if ok != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        let raw = error.raw_os_error().map(|code| code as u32);
        if !matches!(
            raw,
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_ACCESS_DENIED)
        ) || delay_ms == 4_050
        {
            return Err(error);
        }
    }
    Err(io::Error::other("atomic replacement retry loop exhausted"))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{AtomicWriteOptions, write_file_atomic_with_options};
    use super::{create_temporary, write_file_atomic};
    use std::fs;

    #[test]
    fn write_file_atomic_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        fs::write(&path, br#"{"name":"before"}"#).unwrap();

        write_file_atomic(&path, br#"{"name":"after"}"#).unwrap();

        assert_eq!(fs::read(&path).unwrap(), br#"{"name":"after"}"#);
        let tmp_files = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".lpm-"))
            .count();
        assert_eq!(tmp_files, 0);
    }

    #[test]
    fn write_file_atomic_cleans_temp_file_when_replace_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        fs::create_dir(&path).unwrap();

        assert!(write_file_atomic(&path, b"not a directory").is_err());
        let tmp_files = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".lpm-"))
            .count();
        assert_eq!(tmp_files, 0);
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_creation_skips_symlink_and_hardlink_collisions_without_mutating_them() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let sentinel = external.path().join("sentinel");
        let symlink_collision = dir.path().join(".symlink-collision");
        let hardlink_collision = dir.path().join(".hardlink-collision");
        let available = dir.path().join(".available");
        fs::write(&sentinel, b"sentinel").unwrap();
        symlink(&sentinel, &symlink_collision).unwrap();
        fs::hard_link(&sentinel, &hardlink_collision).unwrap();
        let candidates = [
            symlink_collision.clone(),
            hardlink_collision.clone(),
            available.clone(),
        ];
        let mut index = 0;

        let temporary = create_temporary(dir.path(), None, || {
            let candidate = candidates[index].clone();
            index += 1;
            Ok(candidate)
        })
        .unwrap();
        drop(temporary);

        assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
        assert!(symlink_collision.exists());
        assert!(hardlink_collision.exists());
        assert!(!available.exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_file_atomic_replaces_destination_symlink_without_dereferencing_it() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let sentinel = external.path().join("sentinel");
        let destination = dir.path().join("package.json");
        fs::write(&sentinel, b"external").unwrap();
        symlink(&sentinel, &destination).unwrap();

        write_file_atomic(&destination, b"replacement").unwrap();

        assert_eq!(fs::read(&sentinel).unwrap(), b"external");
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert!(
            !fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_file_atomic_replaces_destination_hardlink_without_mutating_other_link() {
        let dir = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let sentinel = external.path().join("sentinel");
        let destination = dir.path().join("package.json");
        fs::write(&sentinel, b"external").unwrap();
        fs::hard_link(&sentinel, &destination).unwrap();

        write_file_atomic(&destination, b"replacement").unwrap();

        assert_eq!(fs::read(&sentinel).unwrap(), b"external");
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
    }

    #[cfg(unix)]
    #[test]
    fn replace_symlink_atomic_replaces_path_entry() {
        use super::replace_symlink_atomic;

        let dir = tempfile::tempdir().unwrap();
        let old_target = dir.path().join("old");
        let new_target = dir.path().join("new");
        let link = dir.path().join("command");
        fs::write(&old_target, b"old").unwrap();
        fs::write(&new_target, b"new").unwrap();
        std::os::unix::fs::symlink(&old_target, &link).unwrap();

        replace_symlink_atomic(&link, &new_target).unwrap();

        assert_eq!(fs::read_link(&link).unwrap(), new_target);
    }

    #[cfg(unix)]
    #[test]
    fn owner_only_write_creates_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("restricted-cache");

        write_file_atomic_with_options(
            &destination,
            b"secret",
            AtomicWriteOptions::new().unix_mode(0o600),
        )
        .unwrap();

        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn default_write_preserves_existing_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("script");
        fs::write(&destination, b"before").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o751)).unwrap();

        write_file_atomic(&destination, b"after").unwrap();

        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o751
        );
    }

    #[cfg(windows)]
    #[test]
    fn exclusive_creation_skips_existing_file_collision() {
        let dir = tempfile::tempdir().unwrap();
        let collision = dir.path().join(".collision");
        let available = dir.path().join(".available");
        fs::write(&collision, b"attacker-owned").unwrap();
        let candidates = [collision.clone(), available.clone()];
        let mut index = 0;

        let temporary = create_temporary(dir.path(), None, || {
            let candidate = candidates[index].clone();
            index += 1;
            Ok(candidate)
        })
        .unwrap();
        drop(temporary);

        assert_eq!(fs::read(&collision).unwrap(), b"attacker-owned");
        assert!(!available.exists());
    }

    #[cfg(windows)]
    #[test]
    fn write_file_atomic_replaces_destination_symlink_when_privileged() {
        use std::os::windows::fs::symlink_file;

        let dir = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let sentinel = external.path().join("sentinel");
        let destination = dir.path().join("package.json");
        fs::write(&sentinel, b"external").unwrap();
        if symlink_file(&sentinel, &destination).is_err() {
            return;
        }

        write_file_atomic(&destination, b"replacement").unwrap();

        assert_eq!(fs::read(&sentinel).unwrap(), b"external");
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
    }

    #[cfg(windows)]
    #[test]
    fn write_file_atomic_supports_near_max_path_destination() {
        use std::os::windows::ffi::OsStrExt;

        fn utf16_len(path: &std::path::Path) -> usize {
            path.as_os_str().encode_wide().count()
        }

        let dir = tempfile::tempdir().unwrap();
        let padding_len = 230usize
            .checked_sub(utf16_len(dir.path()) + 1)
            .expect("temporary root must leave room for padding");
        let parent = dir.path().join("x".repeat(padding_len));
        fs::create_dir(&parent).unwrap();
        let path = parent.join(".lpm-object-integrity");
        let legacy_tmp = parent.join(format!(
            "..lpm-object-integrity.tmp.{}.0",
            std::process::id()
        ));

        assert!(utf16_len(&path) < 260);
        assert!(utf16_len(&legacy_tmp) >= 260);

        write_file_atomic(&path, b"sha256-test\n").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"sha256-test\n");
    }
}
