use std::ffi::{OsStr, OsString};
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
    owner_only: bool,
}

impl AtomicWriteOptions {
    /// Preserve an existing regular file's mode, or use the process umask
    /// when creating a new destination.
    pub const fn new() -> Self {
        Self {
            unix_mode: None,
            sync_file: false,
            sync_parent: false,
            owner_only: false,
        }
    }

    /// Set the exact final Unix mode. This is ignored on non-Unix platforms.
    pub const fn unix_mode(mut self, mode: u32) -> Self {
        self.unix_mode = Some(mode);
        self
    }

    /// Give the file to its owner alone before any content reaches it: mode
    /// 0600 on Unix, without the extended ACL entries macOS gives a new file
    /// from its directory's inheritable ones, and on Windows a protected DACL
    /// that grants only the owner and SYSTEM.
    pub const fn owner_only(mut self) -> Self {
        self.unix_mode = Some(0o600);
        self.owner_only = true;
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
    let mut temporary = create_temporary(parent, exact_mode, options.owner_only, || {
        random_temp_path(parent)
    })
    .map_err(E::from)?;
    #[cfg(any(target_os = "macos", windows))]
    if options.owner_only {
        restrict_to_owner(temporary.file().map_err(E::from)?).map_err(E::from)?;
    }

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

/// Rewrite one file relative to a retained directory capability.
///
/// The destination must be a single file name. The temporary file and final
/// replacement remain relative to `directory`, so renaming an ambient parent
/// path cannot redirect the write outside the opened directory.
pub fn write_file_atomic_in_dir_with<T, E>(
    directory: &cap_std::fs::Dir,
    destination: &OsStr,
    write: impl FnOnce(&mut cap_std::fs::File) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<io::Error>,
{
    write_file_atomic_in_dir_with_options(directory, destination, AtomicWriteOptions::new(), write)
}

/// Replace a file through a retained directory with explicit permissions and durability.
pub fn write_file_atomic_in_dir_with_options<T, E>(
    directory: &cap_std::fs::Dir,
    destination: &OsStr,
    options: AtomicWriteOptions,
    write: impl FnOnce(&mut cap_std::fs::File) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<io::Error>,
{
    validate_relative_file_name(destination).map_err(E::from)?;
    let exact_mode = match options.unix_mode {
        Some(mode) => Some(mode),
        None => capability_destination_mode(directory, destination).map_err(E::from)?,
    };
    let (temporary_name, mut temporary) =
        create_capability_temporary(directory, exact_mode, options.owner_only).map_err(E::from)?;

    let result = (|| {
        #[cfg(any(target_os = "macos", windows))]
        if options.owner_only {
            restrict_to_owner(&temporary).map_err(E::from)?;
        }
        let output = write(&mut temporary)?;
        if let Some(mode) = exact_mode {
            set_capability_file_mode(&temporary, mode).map_err(E::from)?;
        }
        if options.sync_file {
            temporary.sync_all().map_err(E::from)?;
        }
        replace_capability_file(directory, &temporary_name, destination, temporary)
            .map_err(E::from)?;
        #[cfg(unix)]
        if options.sync_parent {
            // Linux directory capabilities can use O_PATH, which cannot be synced.
            directory
                .open(".")
                .map_err(E::from)?
                .sync_all()
                .map_err(E::from)?;
        }
        Ok(output)
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary_name);
    }
    result
}

/// Creates `destination` in `directory` with complete contents, never
/// replacing an existing entry: the contents go to a temporary file that is
/// hard-linked, or else renamed without replacing, into place, so readers
/// see no partial file. Returns `None`, writing nothing, when `destination`
/// exists. Where the filesystem does neither, the file is created
/// exclusively and written in place, and removed again if that fails.
pub fn create_file_atomic_in_dir_with_options<T, E>(
    directory: &cap_std::fs::Dir,
    destination: &OsStr,
    options: AtomicWriteOptions,
    write: impl FnOnce(&mut cap_std::fs::File) -> Result<T, E>,
) -> Result<Option<T>, E>
where
    E: From<io::Error>,
{
    validate_relative_file_name(destination).map_err(E::from)?;
    let (temporary_name, mut temporary) =
        create_capability_temporary(directory, options.unix_mode, options.owner_only)
            .map_err(E::from)?;
    let result = (|| {
        #[cfg(any(target_os = "macos", windows))]
        if options.owner_only {
            restrict_to_owner(&temporary).map_err(E::from)?;
        }
        let output = write(&mut temporary)?;
        if let Some(mode) = options.unix_mode {
            set_capability_file_mode(&temporary, mode).map_err(E::from)?;
        }
        temporary.sync_all().map_err(E::from)?;
        let published = match simulated::hard_link(directory, &temporary_name, destination) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
            Err(_) => {
                match simulated::rename_without_replacing(
                    directory,
                    &temporary_name,
                    destination,
                    &temporary,
                ) {
                    Ok(renamed) => renamed,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
                    Err(error) => return Err(E::from(error)),
                }
            }
        };
        if !published
            && !copy_into_new_file(directory, &temporary_name, destination, options)
                .map_err(E::from)?
        {
            return Ok(None);
        }
        #[cfg(unix)]
        if options.sync_parent {
            directory
                .open(".")
                .map_err(E::from)?
                .sync_all()
                .map_err(E::from)?;
        }
        Ok(Some(output))
    })();
    drop(temporary);
    let _ = directory.remove_file(&temporary_name);
    result
}

/// Copies the temporary into `destination`, created exclusively, for a
/// filesystem that neither links nor renames without replacing. A failure
/// removes the partial file unless something else has replaced it since.
/// `false` when `destination` exists.
fn copy_into_new_file(
    directory: &cap_std::fs::Dir,
    temporary_name: &OsStr,
    destination: &OsStr,
    options: AtomicWriteOptions,
) -> io::Result<bool> {
    let mut exclusive = cap_std::fs::OpenOptions::new();
    exclusive.write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        exclusive.mode(options.unix_mode.unwrap_or(0o666));
    }
    #[cfg(windows)]
    if options.owner_only {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::GENERIC_WRITE;
        use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};

        exclusive.access_mode(GENERIC_WRITE | READ_CONTROL | WRITE_DAC);
    }
    let mut created = match directory.open_with(destination, &exclusive) {
        Ok(created) => created,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error),
    };
    let copied = (|| {
        #[cfg(any(target_os = "macos", windows))]
        if options.owner_only {
            restrict_to_owner(&created)?;
        }
        let mut source = directory.open(temporary_name)?;
        simulated::copy(&mut source, &mut created)?;
        created.sync_all()
    })();
    if let Err(error) = copied {
        if is_current_entry(directory, destination, &created).unwrap_or(false) {
            let _ = directory.remove_file(destination);
        }
        return Err(error);
    }
    Ok(true)
}

/// What [`create_file_atomic_in_dir_with_options`] can do on a filesystem:
/// everything, except where a test takes an ability away.
mod simulated {
    use std::ffi::OsStr;
    use std::io;

    #[cfg(test)]
    thread_local! {
        pub(super) static NO_HARD_LINKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static NO_RENAME_WITHOUT_REPLACING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static FAILING_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    pub(super) fn hard_link(
        directory: &cap_std::fs::Dir,
        from: &OsStr,
        to: &OsStr,
    ) -> io::Result<()> {
        #[cfg(test)]
        if NO_HARD_LINKS.with(std::cell::Cell::get) {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        directory.hard_link(from, directory, to)
    }

    pub(super) fn rename_without_replacing(
        directory: &cap_std::fs::Dir,
        from: &OsStr,
        to: &OsStr,
        file: &cap_std::fs::File,
    ) -> io::Result<bool> {
        #[cfg(test)]
        if NO_RENAME_WITHOUT_REPLACING.with(std::cell::Cell::get) {
            return Ok(false);
        }
        super::rename_capability_file_without_replacing(directory, from, to, file)
    }

    pub(super) fn copy(
        source: &mut cap_std::fs::File,
        destination: &mut cap_std::fs::File,
    ) -> io::Result<u64> {
        let copied = io::copy(source, destination)?;
        #[cfg(test)]
        if FAILING_COPY.with(std::cell::Cell::get) {
            return Err(io::Error::other("injected failure after the copy"));
        }
        Ok(copied)
    }
}

/// Whether `name` in `directory` is still `file`.
fn is_current_entry(
    directory: &cap_std::fs::Dir,
    name: &OsStr,
    file: &cap_std::fs::File,
) -> io::Result<bool> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let current = directory.open_with(name, &options)?.into_std();
    Ok(file_identity(&current)? == file_identity(&file.try_clone()?.into_std())?)
}

fn validate_relative_file_name(name: &OsStr) -> io::Result<()> {
    let path = Path::new(name);
    let mut components = path.components();
    if matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
    {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "atomic destination must be one relative file name: {}",
            path.display()
        ),
    ))
}

#[cfg(unix)]
fn capability_destination_mode(
    directory: &cap_std::fs::Dir,
    destination: &OsStr,
) -> io::Result<Option<u32>> {
    use cap_std::fs::PermissionsExt as _;

    match directory.symlink_metadata(destination) {
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata.permissions().mode() & 0o7777)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn capability_destination_mode(
    _directory: &cap_std::fs::Dir,
    _destination: &OsStr,
) -> io::Result<Option<u32>> {
    Ok(None)
}

fn create_capability_temporary(
    directory: &cap_std::fs::Dir,
    exact_mode: Option<u32>,
    owner_only: bool,
) -> io::Result<(OsString, cap_std::fs::File)> {
    use base64::Engine as _;

    let mut last_collision = None;
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let mut random = [0u8; TEMP_RANDOM_BYTES];
        getrandom::fill(&mut random).map_err(|error| {
            io::Error::other(format!("failed to generate temporary file name: {error}"))
        })?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        let name = OsString::from(format!(".lpm-{encoded}"));
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;

            options.mode(exact_mode.unwrap_or(0o666));
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows_sys::Win32::Storage::FileSystem::{DELETE, READ_CONTROL, WRITE_DAC};

            let _ = exact_mode;
            let security = if owner_only {
                READ_CONTROL | WRITE_DAC
            } else {
                0
            };
            options.access_mode(GENERIC_READ | GENERIC_WRITE | DELETE | security);
        }
        #[cfg(not(windows))]
        let _ = owner_only;
        #[cfg(not(any(unix, windows)))]
        let _ = exact_mode;

        match directory.open_with(&name, &options) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate an exclusive capability-relative temporary file",
        )
    }))
}

#[cfg(unix)]
fn set_capability_file_mode(file: &cap_std::fs::File, mode: u32) -> io::Result<()> {
    use cap_std::fs::PermissionsExt as _;

    file.set_permissions(cap_std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_capability_file_mode(_file: &cap_std::fs::File, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Renames the temporary to `destination` unless an entry is there, which
/// is an `AlreadyExists` error. `false` where the filesystem can't rename
/// that way.
#[cfg(target_os = "linux")]
fn rename_capability_file_without_replacing(
    directory: &cap_std::fs::Dir,
    temporary_name: &OsStr,
    destination: &OsStr,
    _temporary: &cap_std::fs::File,
) -> io::Result<bool> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let from = std::ffi::CString::new(temporary_name.as_bytes())?;
    let to = std::ffi::CString::new(destination.as_bytes())?;
    let directory = directory.as_raw_fd();
    // SAFETY: both names are NUL-terminated and outlive the call, and the
    // directory descriptor stays open for it.
    let renamed = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory,
            from.as_ptr(),
            directory,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if renamed == 0 {
        return Ok(true);
    }
    no_replace_rename_unsupported(io::Error::last_os_error())
}

#[cfg(target_os = "macos")]
fn rename_capability_file_without_replacing(
    directory: &cap_std::fs::Dir,
    temporary_name: &OsStr,
    destination: &OsStr,
    _temporary: &cap_std::fs::File,
) -> io::Result<bool> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let from = std::ffi::CString::new(temporary_name.as_bytes())?;
    let to = std::ffi::CString::new(destination.as_bytes())?;
    let directory = directory.as_raw_fd();
    // SAFETY: both names are NUL-terminated and outlive the call, and the
    // directory descriptor stays open for it.
    let renamed = unsafe {
        libc::renameatx_np(
            directory,
            from.as_ptr(),
            directory,
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if renamed == 0 {
        return Ok(true);
    }
    no_replace_rename_unsupported(io::Error::last_os_error())
}

/// `false` for the errors a filesystem without no-replace renames gives.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn no_replace_rename_unsupported(error: io::Error) -> io::Result<bool> {
    let unsupported = [libc::EINVAL, libc::ENOSYS, libc::ENOTSUP, libc::EOPNOTSUPP];
    if error
        .raw_os_error()
        .is_some_and(|code| unsupported.contains(&code))
    {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(windows)]
fn rename_capability_file_without_replacing(
    directory: &cap_std::fs::Dir,
    _temporary_name: &OsStr,
    destination: &OsStr,
    temporary: &cap_std::fs::File,
) -> io::Result<bool> {
    rename_capability_handle(directory, destination, temporary, false).map(|()| true)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn rename_capability_file_without_replacing(
    _directory: &cap_std::fs::Dir,
    _temporary_name: &OsStr,
    _destination: &OsStr,
    _temporary: &cap_std::fs::File,
) -> io::Result<bool> {
    Ok(false)
}

#[cfg(not(windows))]
fn replace_capability_file(
    directory: &cap_std::fs::Dir,
    temporary_name: &OsStr,
    destination: &OsStr,
    temporary: cap_std::fs::File,
) -> io::Result<()> {
    let _temporary = temporary;
    directory.rename(temporary_name, directory, destination)
}

#[cfg(windows)]
fn replace_capability_file(
    directory: &cap_std::fs::Dir,
    _temporary_name: &OsStr,
    destination: &OsStr,
    temporary: cap_std::fs::File,
) -> io::Result<()> {
    rename_capability_handle(directory, destination, &temporary, true)
}

/// Renames the open `file`, which needs `DELETE` access, to `destination`
/// in `directory`, failing with `AlreadyExists` when an entry is there:
/// the no-replace rename `MoveFileEx` has no flag for.
#[cfg(windows)]
pub fn rename_open_file_noreplace(
    directory: &cap_std::fs::Dir,
    destination: &OsStr,
    file: &cap_std::fs::File,
) -> io::Result<()> {
    rename_capability_handle(directory, destination, file, false)
}

/// Renames the open `temporary` to `destination` in `directory`, replacing
/// an entry there only when `replace` is set; an entry that stays is an
/// `AlreadyExists` error.
#[cfg(windows)]
fn rename_capability_handle(
    directory: &cap_std::fs::Dir,
    destination: &OsStr,
    temporary: &cap_std::fs::File,
    replace: bool,
) -> io::Result<()> {
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, RtlNtStatusToDosError,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let destination = destination.encode_wide().collect::<Vec<_>>();
    let file_name_bytes = destination
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| io::Error::other("atomic destination file name is too long"))?;
    let info_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(file_name_bytes)
        .ok_or_else(|| io::Error::other("atomic rename data is too large"))?;
    let mut storage = vec![0usize; info_bytes.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let info_bytes = u32::try_from(info_bytes)
        .map_err(|_| io::Error::other("atomic rename data is too large"))?;
    let file_name_bytes = u32::try_from(file_name_bytes)
        .map_err(|_| io::Error::other("atomic destination file name is too long"))?;
    unsafe {
        // SAFETY: storage is aligned and sized for the variable-length rename record. Both
        // handles remain open for each synchronous call, and the UTF-16 filename is copied in full.
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = directory.as_raw_handle();
        (*info).FileNameLength = file_name_bytes;
        std::ptr::copy_nonoverlapping(
            destination.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            destination.len(),
        );
    }
    for delay_ms in [0, 50, 150, 450, 1_350, 4_050] {
        if delay_ms != 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = unsafe {
            // SAFETY: `info` describes the initialized buffer above and both handles remain valid.
            NtSetInformationFile(
                temporary.as_raw_handle(),
                &mut io_status,
                info.cast(),
                info_bytes,
                FileRenameInformation,
            )
        };
        if status >= 0 {
            return Ok(());
        }
        let code = unsafe {
            // SAFETY: `status` is the NTSTATUS returned by `NtSetInformationFile`.
            RtlNtStatusToDosError(status)
        };
        let error = io::Error::from_raw_os_error(code as i32);
        if !matches!(code, ERROR_SHARING_VIOLATION | ERROR_ACCESS_DENIED) || delay_ms == 4_050 {
            return Err(error);
        }
    }
    Err(io::Error::other("atomic replacement retry loop exhausted"))
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

/// Whether `name` matches the transient temporary-file shape produced by
/// [`write_file_atomic`] (`.lpm-` + the URL-safe base64 of
/// [`TEMP_RANDOM_BYTES`] random bytes). Directory scans that must not
/// observe in-flight rewrites — the v2 store tree hash in particular —
/// use this to skip the temporary while a sibling replaces a sidecar.
pub fn is_atomic_temp_name(name: &str) -> bool {
    const ENCODED_LEN: usize = TEMP_RANDOM_BYTES.div_ceil(3) * 4 - (3 - TEMP_RANDOM_BYTES % 3) % 3;
    name.strip_prefix(".lpm-").is_some_and(|suffix| {
        suffix.len() == ENCODED_LEN
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    })
}

fn create_temporary(
    parent: &Path,
    exact_mode: Option<u32>,
    owner_only: bool,
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

        match open_temporary(&path, exact_mode, owner_only) {
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

fn open_temporary(path: &Path, exact_mode: Option<u32>, owner_only: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(not(unix))]
    let _ = exact_mode;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(exact_mode.unwrap_or(0o666));
    }
    #[cfg(windows)]
    if owner_only {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{DELETE, READ_CONTROL, WRITE_DAC};

        options.access_mode(GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC);
    }
    #[cfg(not(windows))]
    let _ = owner_only;
    options.open(path)
}

/// Opens the regular file at `path` for reading and writing without
/// following a link there, creating it when `create` is set, and gives it to
/// its owner alone as [`AtomicWriteOptions::owner_only`] gives a file it
/// writes. A file an earlier release left open to others is narrowed too.
pub fn open_owner_only_file(path: &Path, create: bool) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC,
        };

        options
            .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(format!(
            "refusing a path that is a link or not a regular file: {}",
            path.display()
        )));
    }
    set_file_mode(&file, 0o600)?;
    #[cfg(any(target_os = "macos", windows))]
    restrict_to_owner(&file)?;
    Ok(file)
}

/// Applies [`AtomicWriteOptions::owner_only`] beyond the mode to a file just
/// created.
#[cfg(target_os = "macos")]
fn restrict_to_owner(file: impl std::os::fd::AsFd) -> io::Result<()> {
    crate::macos_acl::drop_extended_acl(file)
}

#[cfg(windows)]
fn restrict_to_owner(file: &impl std::os::windows::io::AsRawHandle) -> io::Result<()> {
    crate::owner_only::protect_file(file)
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

    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let path = crate::absolute_extended_path(path)?;
        Ok(path.as_os_str().encode_wide().chain(Some(0)).collect())
    }

    let from = wide(from)?;
    let to = wide(to)?;
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

/// A file's device and number, which no other file shares while it
/// exists.
#[cfg(unix)]
pub fn file_identity(file: &std::fs::File) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
pub fn file_identity(file: &std::fs::File) -> io::Result<(u64, u64)> {
    let information = windows_file_information(file)?;
    Ok((
        u64::from(information.dwVolumeSerialNumber),
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}

#[cfg(windows)]
pub(crate) fn windows_file_information(
    file: &std::fs::File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is valid for the call and `information` is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

#[cfg(not(any(unix, windows)))]
pub fn file_identity(_file: &std::fs::File) -> io::Result<(u64, u64)> {
    Ok((0, 0))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::write_file_atomic_with_options;
    use super::{
        AtomicWriteOptions, create_file_atomic_in_dir_with_options, create_temporary, simulated,
        write_file_atomic, write_file_atomic_in_dir_with,
    };
    use std::fs;
    use std::io::{self, Write as _};

    fn create(dir: &std::path::Path, contents: &[u8]) -> io::Result<Option<()>> {
        let directory =
            cap_std::fs::Dir::open_ambient_dir(dir, cap_std::ambient_authority()).unwrap();
        create_file_atomic_in_dir_with_options(
            &directory,
            ".env".as_ref(),
            AtomicWriteOptions::new().owner_only(),
            |file| file.write_all(contents),
        )
    }

    fn leftover_temporaries(dir: &std::path::Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".lpm-"))
            .collect()
    }

    #[test]
    fn without_hard_links_a_new_file_is_renamed_into_place_whole() {
        simulated::NO_HARD_LINKS.set(true);
        let dir = tempfile::tempdir().unwrap();

        let first = create(dir.path(), b"TOKEN=first\n");
        let second = create(dir.path(), b"TOKEN=second\n");
        simulated::NO_HARD_LINKS.set(false);

        assert_eq!(first.unwrap(), Some(()));
        assert_eq!(second.unwrap(), None);
        assert_eq!(fs::read(dir.path().join(".env")).unwrap(), b"TOKEN=first\n");
        assert!(leftover_temporaries(dir.path()).is_empty());
    }

    #[test]
    fn a_copy_that_fails_leaves_no_partial_file_for_the_retry_to_keep() {
        simulated::NO_HARD_LINKS.set(true);
        simulated::NO_RENAME_WITHOUT_REPLACING.set(true);
        simulated::FAILING_COPY.set(true);
        let dir = tempfile::tempdir().unwrap();

        let failed = create(dir.path(), b"TOKEN=complete\n");
        let destination_after_failure = dir.path().join(".env").exists();
        simulated::FAILING_COPY.set(false);
        let retried = create(dir.path(), b"TOKEN=complete\n");
        simulated::NO_HARD_LINKS.set(false);
        simulated::NO_RENAME_WITHOUT_REPLACING.set(false);

        assert!(failed.is_err());
        assert!(!destination_after_failure);
        assert_eq!(retried.unwrap(), Some(()));
        assert_eq!(
            fs::read(dir.path().join(".env")).unwrap(),
            b"TOKEN=complete\n"
        );
        assert!(leftover_temporaries(dir.path()).is_empty());
    }

    #[test]
    fn a_failed_copy_leaves_a_file_that_replaced_it_alone() {
        simulated::NO_HARD_LINKS.set(true);
        simulated::NO_RENAME_WITHOUT_REPLACING.set(true);
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), b"USER=kept\n").unwrap();

        let kept = create(dir.path(), b"TOKEN=new\n");
        simulated::NO_HARD_LINKS.set(false);
        simulated::NO_RENAME_WITHOUT_REPLACING.set(false);

        assert_eq!(kept.unwrap(), None);
        assert_eq!(fs::read(dir.path().join(".env")).unwrap(), b"USER=kept\n");
    }

    #[test]
    fn capability_relative_atomic_write_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("graph.html"), b"before").unwrap();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();

        write_file_atomic_in_dir_with(&directory, "graph.html".as_ref(), |file| {
            file.write_all(b"after")
        })
        .unwrap();

        assert_eq!(fs::read(dir.path().join("graph.html")).unwrap(), b"after");
    }

    #[cfg(unix)]
    #[test]
    fn capability_relative_atomic_write_syncs_a_nested_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("nested")).unwrap();
        let root =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();
        let directory = root.open_dir("nested").unwrap();
        super::write_file_atomic_in_dir_with_options(
            &directory,
            "state.json".as_ref(),
            AtomicWriteOptions::new().sync_file().sync_parent(),
            |file| file.write_all(b"state"),
        )
        .unwrap();
        assert_eq!(directory.read("state.json").unwrap(), b"state");
    }

    #[test]
    fn capability_relative_atomic_write_cleans_its_temporary_after_callback_failure() {
        let dir = tempfile::tempdir().unwrap();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();

        let result: io::Result<()> =
            write_file_atomic_in_dir_with(&directory, "graph.html".as_ref(), |file| {
                file.write_all(b"partial")?;
                Err(io::Error::other("render failed"))
            });

        assert!(result.is_err());
        assert!(!dir.path().join("graph.html").exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn capability_relative_atomic_write_replaces_a_destination_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let sentinel = outside.path().join("sentinel");
        let destination = dir.path().join("graph.html");
        fs::write(&sentinel, b"outside").unwrap();
        symlink(&sentinel, &destination).unwrap();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();

        write_file_atomic_in_dir_with(&directory, "graph.html".as_ref(), |file| {
            file.write_all(b"replacement")
        })
        .unwrap();

        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert!(!fs::symlink_metadata(destination).unwrap().is_symlink());
    }

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

        let temporary = create_temporary(dir.path(), None, false, || {
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

        let temporary = create_temporary(dir.path(), None, false, || {
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
    fn write_file_atomic_creates_and_replaces_beyond_max_path() {
        let root = tempfile::tempdir().unwrap();
        let root_text = root.path().to_str().unwrap();
        let ordinary_root = root_text.strip_prefix(r"\\?\").unwrap_or(root_text);
        let mut parent = std::path::PathBuf::from(ordinary_root);
        while parent.as_os_str().len() < 300 {
            parent.push("nested-directory-with-spaces ü");
        }
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join(".lpm-object-integrity");
        assert!(!path.to_str().unwrap().starts_with(r"\\?\"));

        write_file_atomic(&path, b"first").unwrap();
        write_file_atomic(&path, b"replacement").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 1);
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
