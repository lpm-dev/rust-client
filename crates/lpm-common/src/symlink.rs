//! Cross-platform directory-symlink helper.
//!
//! Provides shared creation, detection, and removal helpers for directory
//! links so callers do not need to duplicate platform-specific behavior:
//!
//! - **Unix:** plain `symlink(2)` via [`std::os::unix::fs::symlink`].
//! - **Windows:** tries [`std::os::windows::fs::symlink_dir`] first
//!   (works under Developer Mode or with appropriate policy). On
//!   failure, falls back to an NTFS junction, which does not require
//!   admin privileges, set directly with `FSCTL_SET_REPARSE_POINT`.
//!   Junction targets must be absolute, so relative targets are
//!   resolved against the link's parent and lexically cleaned (`..`
//!   segments simplified) first.
//!
//! Both lpm-linker (for the install-time wrapper layout) and
//! lpm-store v2 (for sibling-symlinks under `links/<graph-key>/`) use
//! this. Centralized so a future Windows correctness or security fix
//! lands in one place.

use std::path::{Component, Path, PathBuf};

/// Create a directory link from `link` pointing to `target`.
///
/// On Unix, this is a relative-or-absolute `symlink(2)`. On Windows,
/// the call tries `CreateSymbolicLinkW` first and silently falls back
/// to an NTFS junction if the symlink fails — junctions don't need
/// admin privileges, so this is the practical Windows path for
/// end-user installs.
///
/// Returns the underlying I/O error if neither the symlink nor the
/// junction call succeeds. Callers should surface the error rather
/// than retrying — a hard failure here typically means a path
/// validation issue (invalid chars on Windows) or filesystem
/// permission, neither of which a retry resolves.
pub fn create_dir_symlink_or_junction(target: &Path, link: &Path) -> std::io::Result<()> {
    create_dir_symlink_or_junction_inner(target, link)
}

/// Create a filesystem symlink from `link` to `target`.
///
/// - **Unix:** plain `symlink(2)` for files and directories.
/// - **Windows:** `symlink_file` for files; directory targets reuse
///   [`create_dir_symlink_or_junction`] so the junction fallback still
///   applies.
pub fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    create_symlink_inner(target, link)
}

/// Return whether metadata obtained with [`std::fs::symlink_metadata`]
/// describes a symbolic link or Windows reparse-point junction.
pub fn is_symlink_or_junction(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Remove one filesystem entry without traversing a directory link.
///
/// Windows requires directory symlinks and junctions to be removed with
/// `remove_dir`, while Unix removes directory symlinks with `remove_file`.
/// Real directories are removed recursively and regular files use
/// `remove_file` on every platform.
pub fn remove_path_entry(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if is_symlink_or_junction(&metadata) {
        return remove_link(path, &metadata);
    }
    if metadata.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Removes `path` as [`remove_path_entry`] does and returns how many bytes
/// that frees, in one walk. A file counts when the link removed is its last,
/// so a file hard-linked elsewhere in the tree counts once, and one that is
/// also linked from outside it doesn't count. Directories are walked through
/// open handles and links are never followed, as `remove_dir_all` does.
///
/// On platforms without link counts every file counts at its full size.
pub fn remove_path_entry_counting_freed_bytes(path: &Path) -> std::io::Result<u64> {
    let metadata = std::fs::symlink_metadata(path)?;
    if is_symlink_or_junction(&metadata) {
        remove_link(path, &metadata)?;
        return Ok(0);
    }
    if !metadata.is_dir() {
        return remove_regular_file_counting_freed_bytes(path, &metadata);
    }
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "cannot remove a directory without a name: {}",
                path.display()
            ),
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    let freed = {
        let directory = cap_fs_ext::DirExt::open_dir_nofollow(&parent, name)?;
        clear_directory_counting_freed_bytes(&directory)?
    };
    parent.remove_dir(name)?;
    Ok(freed)
}

/// Maximum number of nested `cap_std::fs::Dir` handles kept open at once during
/// [`clear_directory_counting_freed_bytes`]. Keeping a sliding window at the top
/// of the traversal stack bounds FD usage to `O(1)` at arbitrary directory depth
/// while incurring zero reopens for normal trees up to this depth.
const MAX_CLEAR_OPEN_DIRS: usize = 24;

struct ClearDirFrame {
    name_in_parent: Option<std::ffi::OsString>,
    dir: Option<cap_std::fs::Dir>,
    pending: Vec<std::ffi::OsString>,
}

fn collect_dir_entry_names(
    directory: &cap_std::fs::Dir,
) -> std::io::Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for entry in directory.entries()? {
        names.push(entry?.file_name());
    }
    Ok(names)
}

fn evict_oldest_open_dir(stack: &mut [ClearDirFrame], open_dirs: &mut usize, protected_idx: usize) {
    for (idx, frame) in stack.iter_mut().enumerate().skip(1) {
        if idx == protected_idx {
            continue;
        }
        if frame.dir.take().is_some() {
            *open_dirs -= 1;
            return;
        }
    }
}

fn ensure_top_dir_open(
    root: &cap_std::fs::Dir,
    stack: &mut [ClearDirFrame],
    open_dirs: &mut usize,
) -> std::io::Result<()> {
    use cap_fs_ext::DirExt as _;

    let top = stack.len() - 1;
    if top == 0 || stack[top].dir.is_some() {
        return Ok(());
    }

    let anchor = (1..top)
        .rev()
        .find(|&idx| stack[idx].dir.is_some())
        .unwrap_or(0);
    let window_start = top.saturating_sub(MAX_CLEAR_OPEN_DIRS - 1).max(1);

    let mut transient: Option<cap_std::fs::Dir> = None;
    for step in (anchor + 1)..window_start {
        let parent_ref = transient.as_ref().unwrap_or_else(|| {
            if anchor == 0 {
                root
            } else {
                stack[anchor]
                    .dir
                    .as_ref()
                    .expect("anchor directory is open")
            }
        });
        let name = stack[step]
            .name_in_parent
            .as_deref()
            .expect("non-root frame carries its entry name");
        transient = Some(parent_ref.open_dir_nofollow(name)?);
    }

    for step in window_start.max(anchor + 1)..=top {
        if *open_dirs >= MAX_CLEAR_OPEN_DIRS {
            evict_oldest_open_dir(stack, open_dirs, step - 1);
        }
        let parent_ref = if let Some(dir) = transient.as_ref() {
            dir
        } else if step - 1 == 0 {
            root
        } else {
            stack[step - 1]
                .dir
                .as_ref()
                .expect("parent frame is open in sliding window")
        };
        let name = stack[step]
            .name_in_parent
            .as_deref()
            .expect("non-root frame carries its entry name");
        let opened = parent_ref.open_dir_nofollow(name)?;
        transient = None;
        stack[step].dir = Some(opened);
        *open_dirs += 1;
    }

    Ok(())
}

fn clear_directory_counting_freed_bytes(directory: &cap_std::fs::Dir) -> std::io::Result<u64> {
    use cap_fs_ext::DirExt as _;

    let mut freed = 0u64;
    let mut open_dirs = 0usize;
    let mut stack = vec![ClearDirFrame {
        name_in_parent: None,
        dir: None,
        pending: collect_dir_entry_names(directory)?,
    }];

    while !stack.is_empty() {
        ensure_top_dir_open(directory, &mut stack, &mut open_dirs)?;
        let parent_idx = stack.len() - 1;
        let Some(name) = stack[parent_idx].pending.pop() else {
            let mut finished = stack.pop().expect("stack is non-empty");
            if finished.dir.take().is_some() {
                open_dirs -= 1;
            }
            if let Some(dir_name) = finished.name_in_parent {
                ensure_top_dir_open(directory, &mut stack, &mut open_dirs)?;
                let top = stack.len() - 1;
                let parent_dir = if top == 0 {
                    directory
                } else {
                    stack[top].dir.as_ref().expect("parent directory is open")
                };
                parent_dir.remove_dir(&dir_name)?;
            }
            continue;
        };

        let parent_dir = if parent_idx == 0 {
            directory
        } else {
            stack[parent_idx]
                .dir
                .as_ref()
                .expect("active directory is open")
        };
        let metadata = parent_dir.symlink_metadata(&name)?;
        if metadata.is_dir() && !cap_metadata_is_link(&metadata) {
            if open_dirs >= MAX_CLEAR_OPEN_DIRS {
                evict_oldest_open_dir(&mut stack, &mut open_dirs, parent_idx);
            }
            let parent_dir = if parent_idx == 0 {
                directory
            } else {
                stack[parent_idx]
                    .dir
                    .as_ref()
                    .expect("active directory is open")
            };
            let child = parent_dir.open_dir_nofollow(&name)?;
            let child_pending = collect_dir_entry_names(&child)?;
            if child_pending.is_empty() {
                drop(child);
                parent_dir.remove_dir(&name)?;
            } else {
                stack.push(ClearDirFrame {
                    name_in_parent: Some(name),
                    dir: Some(child),
                    pending: child_pending,
                });
                open_dirs += 1;
            }
        } else if metadata.is_file() && !cap_metadata_is_link(&metadata) {
            freed = freed.saturating_add(cap_remove_file_counting_freed_bytes(
                parent_dir, &name, &metadata, true,
            )?);
        } else {
            parent_dir.remove_file_or_symlink(&name)?;
        }
    }

    Ok(freed)
}

/// Return `((volume_id, file_id), link_count)` for a regular file without
/// following symlinks, or `None` on platforms or filesystems where link
/// identity cannot be queried.
pub fn file_link_identity_and_count(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Option<((u64, u64), u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let _ = path;
        Some(((metadata.dev(), metadata.ino()), metadata.nlink()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        let _ = metadata;
        let file = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .ok()?;
        let info = crate::atomic_write::windows_file_information(&file).ok()?;
        let file_index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        Some((
            (u64::from(info.dwVolumeSerialNumber), file_index),
            u64::from(info.nNumberOfLinks),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, metadata);
        None
    }
}

/// Unlink one regular file inside `directory` and return the bytes freed
/// (`metadata.len()` when removing its final link, `0` when other hardlinks
/// remain). On Windows, when `may_have_hardlinks` is `true`, the link count
/// is inspected and the file is unlinked through a single handle open so
/// security scanners are not triggered twice per file.
pub fn cap_remove_file_counting_freed_bytes(
    directory: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    metadata: &cap_std::fs::Metadata,
    may_have_hardlinks: bool,
) -> std::io::Result<u64> {
    use cap_fs_ext::DirExt as _;

    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        let _ = may_have_hardlinks;
        let freed = if metadata.nlink() <= 1 {
            metadata.len()
        } else {
            0
        };
        directory.remove_file_or_symlink(name)?;
        Ok(freed)
    }
    #[cfg(windows)]
    {
        if !may_have_hardlinks {
            directory.remove_file_or_symlink(name)?;
            return Ok(metadata.len());
        }
        windows_cap_remove_file_counting_freed_bytes(directory, name, metadata)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = may_have_hardlinks;
        directory.remove_file_or_symlink(name)?;
        Ok(metadata.len())
    }
}

#[cfg(unix)]
fn remove_regular_file_counting_freed_bytes(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let freed = if metadata.nlink() <= 1 {
        metadata.len()
    } else {
        0
    };
    std::fs::remove_file(path)?;
    Ok(freed)
}

#[cfg(windows)]
fn remove_regular_file_counting_freed_bytes(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> std::io::Result<u64> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let open = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path);
    match open {
        Ok(file) => {
            let freed = match crate::atomic_write::windows_file_information(&file) {
                Ok(info) if info.nNumberOfLinks <= 1 => metadata.len(),
                Ok(_) => 0,
                Err(_) => metadata.len(),
            };
            if windows_delete_open_file(&file) {
                drop(file);
                return Ok(freed);
            }
            drop(file);
            std::fs::remove_file(path)?;
            Ok(freed)
        }
        Err(_) => {
            std::fs::remove_file(path)?;
            Ok(metadata.len())
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn remove_regular_file_counting_freed_bytes(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> std::io::Result<u64> {
    std::fs::remove_file(path)?;
    Ok(metadata.len())
}

#[cfg(windows)]
fn windows_cap_remove_file_counting_freed_bytes(
    directory: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    metadata: &cap_std::fs::Metadata,
) -> std::io::Result<u64> {
    use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = cap_std::fs::OpenOptions::new();
    options
        .access_mode(FILE_READ_ATTRIBUTES | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .follow(FollowSymlinks::No);
    match directory
        .open_with(name, &options)
        .map(cap_std::fs::File::into_std)
    {
        Ok(file) => {
            let freed = match crate::atomic_write::windows_file_information(&file) {
                Ok(info) if info.nNumberOfLinks <= 1 => metadata.len(),
                Ok(_) => 0,
                Err(_) => metadata.len(),
            };
            if windows_delete_open_file(&file) {
                drop(file);
                return Ok(freed);
            }
            drop(file);
            directory.remove_file_or_symlink(name)?;
            Ok(freed)
        }
        Err(_) => {
            directory.remove_file_or_symlink(name)?;
            Ok(metadata.len())
        }
    }
}

#[cfg(windows)]
fn windows_delete_open_file(file: &std::fs::File) -> bool {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
        FileDispositionInfo, FileDispositionInfoEx, SetFileInformationByHandle,
    };

    let handle = file.as_raw_handle();
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: `handle` is open with `DELETE` access and `ex` is valid storage for `FileDispositionInfoEx`.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            std::ptr::from_ref(&ex).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } != 0
    {
        return true;
    }
    let classic = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `handle` is open with `DELETE` access and `classic` is valid storage for `FileDispositionInfo`.
    unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            std::ptr::from_ref(&classic).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        ) != 0
    }
}

#[cfg(not(windows))]
fn cap_metadata_is_link(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
fn cap_metadata_is_link(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.is_symlink() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Remove a symbolic link or directory junction without removing its target.
///
/// This function returns an error if `path` is not a link. It never removes a
/// real directory recursively.
pub fn remove_symlink_or_junction_entry(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !is_symlink_or_junction(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to remove a non-link filesystem entry at {}",
                path.display()
            ),
        ));
    }
    remove_link(path, &metadata)
}

#[cfg(unix)]
fn remove_link(path: &Path, _metadata: &std::fs::Metadata) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

#[cfg(windows)]
fn remove_link(path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
    if metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 {
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(unix)]
fn create_dir_symlink_or_junction_inner(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(unix)]
fn create_symlink_inner(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_dir_symlink_or_junction_inner(target: &Path, link: &Path) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};

    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
    static SYMLINK_DIR_PRIVILEGE_MISSING: AtomicBool = AtomicBool::new(false);

    let link = with_backslashes(link);
    let target = with_backslashes(target);
    let abs_target = absolute_windows_link_target(&target, &link)?;
    let link_for_api = extended_if_long(&link)?;
    let target_for_api = extended_if_long(&abs_target)?;

    if !SYMLINK_DIR_PRIVILEGE_MISSING.load(Ordering::Relaxed) {
        // Try symlink_dir first — works without admin on Windows setups
        // running with Developer Mode or with the SeCreateSymbolicLink
        // privilege granted via group policy.
        match std::os::windows::fs::symlink_dir(target_for_api.as_ref(), link_for_api.as_ref()) {
            Ok(()) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) => {
                SYMLINK_DIR_PRIVILEGE_MISSING.store(true, Ordering::Relaxed);
            }
            Err(_) => {}
        }
    }
    create_junction(&abs_target, link_for_api.as_ref())
}

#[cfg(windows)]
fn extended_if_long(path: &Path) -> std::io::Result<std::borrow::Cow<'_, Path>> {
    // Win32 directory APIs enforce a 248-character MAX_PATH ceiling without `\\?\`.
    const WINDOWS_DIR_MAX_PATH: usize = 248;
    if path.as_os_str().len() >= WINDOWS_DIR_MAX_PATH {
        Ok(std::borrow::Cow::Owned(crate::absolute_extended_path(
            path,
        )?))
    } else {
        Ok(std::borrow::Cow::Borrowed(path))
    }
}

/// `path` with every `/` as `\`. A scoped package's name puts a `/` in the
/// linker's paths. Windows reads it as a separator except after a `\\?\`
/// prefix, where it would be part of a name, and no Windows file name may
/// hold one, so the backslash means the same in every form.
#[cfg(windows)]
fn with_backslashes(path: &Path) -> std::borrow::Cow<'_, Path> {
    use std::borrow::Cow;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    if !path
        .as_os_str()
        .encode_wide()
        .any(|unit| unit == u16::from(b'/'))
    {
        return Cow::Borrowed(path);
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .map(|unit| {
            if unit == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                unit
            }
        })
        .collect();
    Cow::Owned(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
}

/// Creates `link` as an NTFS junction to the absolute `target`. A junction
/// needs no privilege, and setting its reparse point directly keeps both
/// paths away from any command interpreter.
#[cfg(windows)]
fn create_junction(target: &Path, link: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_WRITE_ATTRIBUTES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;

    let reparse_data = mount_point_reparse_data(target)?;
    let reparse_data_len = u32::try_from(reparse_data.len())
        .expect("mount_point_reparse_data keeps the buffer within u16 lengths");
    std::fs::create_dir(link)?;
    let linked = std::fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(link)
        .and_then(|directory| {
            let mut returned = 0;
            // SAFETY: `directory` is an open handle and `reparse_data` outlives
            // this synchronous call, which writes no output.
            let set = unsafe {
                DeviceIoControl(
                    directory.as_raw_handle(),
                    FSCTL_SET_REPARSE_POINT,
                    reparse_data.as_ptr().cast(),
                    reparse_data_len,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if set == 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    if linked.is_err() {
        let _ = std::fs::remove_dir(link);
    }
    linked
}

/// The `REPARSE_DATA_BUFFER` of a junction to the absolute `target`: the NT
/// path Windows follows, then the path tools display.
#[cfg(windows)]
fn mount_point_reparse_data(target: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Prefix;
    use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;

    let invalid = |reason: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("cannot create a junction to {}: {reason}", target.display()),
        )
    };
    let wide: Vec<u16> = target.as_os_str().encode_wide().collect();
    let Some(Component::Prefix(prefix)) = target.components().next() else {
        return Err(invalid("the target is not absolute"));
    };
    // `\\?\` is four units long.
    let (local, print): (&[u16], &[u16]) = match prefix.kind() {
        Prefix::Disk(_) => (&wide, &wide),
        Prefix::VerbatimDisk(_) => (&wide[4..], &wide[4..]),
        Prefix::Verbatim(_) => (&wide[4..], &wide),
        Prefix::UNC(..) | Prefix::VerbatimUNC(..) | Prefix::DeviceNS(_) => {
            return Err(invalid("a junction can only point at a local volume"));
        }
    };
    let substitute: Vec<u16> = r"\??\"
        .encode_utf16()
        .chain(local.iter().copied())
        .collect();

    // Four 16-bit offsets and lengths, then both names, each NUL-terminated.
    let too_long = || invalid("the path is too long for a junction");
    let substitute_length = u16::try_from(substitute.len() * 2).map_err(|_| too_long())?;
    let print_length = u16::try_from(print.len() * 2).map_err(|_| too_long())?;
    let data_length = 8u16
        .checked_add(substitute_length)
        .and_then(|length| length.checked_add(print_length))
        .and_then(|length| length.checked_add(4))
        .ok_or_else(too_long)?;

    let mut data = Vec::with_capacity(8 + usize::from(data_length));
    data.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    data.extend_from_slice(&data_length.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    for field in [0, substitute_length, substitute_length + 2, print_length] {
        data.extend_from_slice(&field.to_le_bytes());
    }
    for unit in substitute.iter().chain(&[0]).chain(print).chain(&[0]) {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(data)
}

#[cfg(windows)]
fn absolute_windows_link_target(target: &Path, link: &Path) -> std::io::Result<PathBuf> {
    if target.is_absolute() {
        return Ok(lexically_clean(target));
    }

    let link_parent = link.parent().unwrap_or(Path::new("."));
    let absolute_parent = if link_parent.is_absolute() {
        link_parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(link_parent)
    };
    Ok(lexically_clean(&absolute_parent.join(target)))
}

/// Resolve a symlink `target` for probing against `link`'s parent directory
/// rather than the process working directory.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn resolve_symlink_probe_path(target: &Path, link: &Path) -> PathBuf {
    if target.is_absolute() {
        return lexically_clean(target);
    }
    match link
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => lexically_clean(&parent.join(target)),
        None => lexically_clean(target),
    }
}

#[cfg(windows)]
fn create_symlink_inner(target: &Path, link: &Path) -> std::io::Result<()> {
    let target_bs = with_backslashes(target);
    let link_bs = with_backslashes(link);
    let probe = resolve_symlink_probe_path(target_bs.as_ref(), link_bs.as_ref());
    let probe_for_api = extended_if_long(&probe)?;
    match std::fs::metadata(probe_for_api.as_ref()) {
        Ok(meta) if meta.is_dir() => create_dir_symlink_or_junction_inner(target, link),
        Ok(_) => {
            let link_for_api = extended_if_long(link_bs.as_ref())?;
            let target_for_api = if target_bs.is_absolute() {
                extended_if_long(target_bs.as_ref())?
            } else {
                std::borrow::Cow::Borrowed(target_bs.as_ref())
            };
            std::os::windows::fs::symlink_file(target_for_api.as_ref(), link_for_api.as_ref())
        }
        Err(e) => Err(e),
    }
}

/// Lexically simplify `..` and `.` segments in a path without touching
/// the filesystem.
///
/// `a/b/../c` → `a/c`, `./a` → `a`, leading `..` segments are
/// preserved (we have no parent to pop into). Leading `RootDir` /
/// `Prefix` components are kept verbatim.
pub fn lexically_clean(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::ParentDir => {
                let last_is_normal =
                    matches!(out.components().next_back(), Some(Component::Normal(_)));
                if last_is_normal {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn has_parent_dir_after_non_parent(path: &Path) -> bool {
    let mut seen_non_parent = false;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if seen_non_parent {
                    return true;
                }
            }
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {
                seen_non_parent = true;
            }
        }
    }
    false
}

/// Compare an existing symlink/junction target read from `link_path` against
/// `expected_target`, refusing lexical `..` collapse after any normal or root
/// component (where intermediate symlinks would resolve elsewhere) and
/// normalizing clean Windows `\\?\` / `\??\` prefixes and drive-letter case.
pub fn link_targets_equivalent(
    existing_target: &Path,
    link_path: &Path,
    expected_target: &Path,
) -> bool {
    if existing_target == expected_target {
        return true;
    }
    if has_parent_dir_after_non_parent(existing_target)
        || has_parent_dir_after_non_parent(expected_target)
    {
        return false;
    }
    let resolved_existing = resolve_symlink_probe_path(existing_target, link_path);
    let resolved_expected = resolve_symlink_probe_path(expected_target, link_path);
    if resolved_existing == resolved_expected {
        return true;
    }
    #[cfg(windows)]
    {
        matches!(
            (
                normalize_windows_link_target_str(&resolved_existing.to_string_lossy()),
                normalize_windows_link_target_str(&resolved_expected.to_string_lossy()),
            ),
            (Some(left), Some(right)) if left == right
        )
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn normalize_windows_link_target_str(raw: &str) -> Option<String> {
    let (verbatim, is_unc_verbatim, body) = if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        (true, true, unc)
    } else if let Some(nt_unc) = raw.strip_prefix(r"\??\UNC\") {
        (true, true, nt_unc)
    } else if let Some(v) = raw.strip_prefix(r"\\?\") {
        (true, false, v)
    } else if let Some(nt) = raw.strip_prefix(r"\??\") {
        (true, false, nt)
    } else {
        (false, false, raw)
    };

    if verbatim {
        if body.contains('/') {
            return None;
        }
        let trimmed = body.trim_end_matches('\\');
        if trimmed.split('\\').any(|seg| seg == "." || seg == "..") {
            return None;
        }
        let canonical = if is_unc_verbatim {
            let mut parts = trimmed.split('\\').filter(|seg| !seg.is_empty());
            let server = parts.next()?;
            let share = parts.next()?;
            let mut out = String::with_capacity(trimmed.len() + 2);
            out.push_str(r"\\");
            out.push_str(server);
            out.push('\\');
            out.push_str(share);
            for part in parts {
                out.push('\\');
                out.push_str(part);
            }
            out
        } else {
            normalize_windows_drive_prefix_preserving_case(trimmed)?
        };
        return Some(canonical);
    }

    let s = body.replace('/', "\\");
    let (prefix, rest) = if let Some(unc_rest) = s.strip_prefix(r"\\") {
        let mut iter = unc_rest.splitn(3, '\\');
        let server = iter
            .next()
            .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")?;
        let share = iter
            .next()
            .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")?;
        let tail = iter.next().unwrap_or("");
        (format!(r"\\{server}\{share}"), tail)
    } else if s.len() >= 3
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.as_bytes()[1] == b':'
        && s.as_bytes()[2] == b'\\'
    {
        let drive = s.as_bytes()[0].to_ascii_uppercase() as char;
        (format!("{drive}:\\"), &s[3..])
    } else {
        (String::new(), s.as_str())
    };

    let mut parts: Vec<&str> = Vec::new();
    let mut seen_normal = false;
    for segment in rest.split('\\') {
        match segment {
            "" | "." => {}
            ".." => {
                if !prefix.is_empty() || seen_normal {
                    return None;
                }
                parts.push("..");
            }
            other => {
                seen_normal = true;
                parts.push(other);
            }
        }
    }

    let mut out = String::with_capacity(s.len());
    out.push_str(&prefix);
    let need_leading_sep = !prefix.is_empty() && !prefix.ends_with('\\');
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 || need_leading_sep {
            out.push('\\');
        }
        out.push_str(part);
    }
    Some(out)
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn normalize_windows_drive_prefix_preserving_case(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        let drive = bytes[0].to_ascii_uppercase() as char;
        let mut out = String::with_capacity(path.len());
        out.push(drive);
        out.push_str(":\\");
        for (idx, seg) in path[3..]
            .split('\\')
            .filter(|seg| !seg.is_empty())
            .enumerate()
        {
            if idx > 0 {
                out.push('\\');
            }
            out.push_str(seg);
        }
        Some(out)
    } else if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = bytes[0].to_ascii_uppercase() as char;
        Some(format!("{drive}:\\"))
    } else {
        None
    }
}

/// The start of a `.cmd` shim that names paths relative to itself, as
/// `%dp0%`, its own directory with a trailing `\`.
///
/// `dp0` is set in a subroutine: in a batch file's main body, `%~dp0` gives
/// the current directory when cmd.exe found the file on PATH by a quoted
/// name (`"tsc" …`, `call "tsc.cmd"`). `SETLOCAL` keeps `dp0` and the shim's
/// other variables from the caller, with delayed expansion off so a `!` in a
/// path stays literal while the batch file runs (see
/// [`windows_node_cmd_shim_body`] for after). Lines end in CRLF: cmd.exe can miss a label in a file
/// with bare LFs.
pub const WINDOWS_CMD_SHIM_PREAMBLE: &str = "@GOTO start\r\n\
                                             :find_dp0\r\n\
                                             @SET \"dp0=%~dp0\"\r\n\
                                             @EXIT /b\r\n\
                                             :start\r\n\
                                             @SETLOCAL DisableDelayedExpansion\r\n\
                                             @CALL :find_dp0\r\n";

/// The lines of a node shim, after [`WINDOWS_CMD_SHIM_PREAMBLE`] and any
/// `NODE_PATH` line, that choose the Node it runs, `%_prog%`: the `node.exe`
/// beside the shim, else the first `node.exe` on `PATH`, looked up by name
/// so that no `node.js` in the current directory, which `PATHEXT` would
/// otherwise reach first, runs in its place, else `node` as cmd.exe finds
/// it.
const WINDOWS_NODE_CMD_SHIM_PROGRAM: &str = "@SET \"_prog=node\"\r\n\
     @FOR %%I IN (node.exe) DO @IF NOT \"%%~$PATH:I\"==\"\" SET \"_prog=%%~$PATH:I\"\r\n\
     @IF EXIST \"%dp0%node.exe\" SET \"_prog=%dp0%node.exe\"\r\n";

/// How a node shim's last line starts, before the target: it ends the batch
/// file with a `GOTO` to a label that isn't there, then runs Node.
const WINDOWS_NODE_CMD_SHIM_RUN_ENDING_BATCH: &str =
    "@ENDLOCAL & GOTO #_undefined_# 2>NUL || TITLE %COMSPEC% & \"%_prog%\" \"";

/// How a node shim that keeps its batch file runs Node, before the target.
const WINDOWS_NODE_CMD_SHIM_RUN: &str = "@\"%_prog%\" \"";

/// The rest of a `.cmd` shim, after [`WINDOWS_CMD_SHIM_PREAMBLE`], that runs
/// `target`, a path as a batch file names it, with the Node
/// [`WINDOWS_NODE_CMD_SHIM_PROGRAM`] chooses. With `node_path`, it puts that
/// ahead of `NODE_PATH` for Node.
///
/// The last line ends the batch file before Node starts, with a `GOTO` to a
/// label that isn't there, as npm's shims do, so Ctrl+C reaches Node with no
/// batch file left for cmd.exe to ask "Terminate batch job (Y/N)?" about.
/// cmd.exe reads that line whole before it runs it, so `%_prog%`, `%dp0%`
/// and `%*` still hold the shim's values after `ENDLOCAL`; but the caller's
/// delayed expansion, if it has that on, then applies to them, as it does
/// with npm's shims. A shim that sets `NODE_PATH` keeps its batch file
/// around Node instead, as after `ENDLOCAL` the `NODE_PATH` would reach what
/// runs after the shim.
pub fn windows_node_cmd_shim_body(target: &str, node_path: Option<&str>) -> String {
    match node_path {
        None => format!(
            "{WINDOWS_NODE_CMD_SHIM_PROGRAM}{WINDOWS_NODE_CMD_SHIM_RUN_ENDING_BATCH}{target}\" %*\r\n"
        ),
        Some(node_path) => format!(
            "@SET \"NODE_PATH={node_path};%NODE_PATH%\"\r\n\
             {WINDOWS_NODE_CMD_SHIM_PROGRAM}{WINDOWS_NODE_CMD_SHIM_RUN}{target}\" %*\r\n"
        ),
    }
}

/// The target a shim body [`windows_node_cmd_shim_body`] wrote runs, or
/// `None` for anything else.
pub fn windows_node_cmd_shim_target(body: &str) -> Option<&str> {
    let (rest, run) = match body.strip_prefix("@SET \"NODE_PATH=") {
        Some(node_path) => {
            let (line, rest) = node_path.split_once("\r\n")?;
            if !line.ends_with(";%NODE_PATH%\"") {
                return None;
            }
            (rest, WINDOWS_NODE_CMD_SHIM_RUN)
        }
        None => (body, WINDOWS_NODE_CMD_SHIM_RUN_ENDING_BATCH),
    };
    let target = rest
        .strip_prefix(WINDOWS_NODE_CMD_SHIM_PROGRAM)?
        .strip_prefix(run)?
        .strip_suffix("\" %*\r\n")?;
    (!target.contains(['"', '\r', '\n'])).then_some(target)
}

/// The target of a shim that runs Node inside an `IF EXIST` block, as
/// earlier releases wrote them, the local Node being `node`
/// (`%~dp0\node.exe`), after a `NODE_PATH` line if there is one.
pub fn windows_block_cmd_shim_target<'a>(body: &'a str, node: &str) -> Option<&'a str> {
    const PATH_NODE_PREFIX: &str = "  node \"";
    const TARGET_SUFFIX: &str = "\" %*";

    let expected_header = format!("@IF EXIST \"{node}\" (");
    let local_node_prefix = format!("  \"{node}\" \"");
    let mut lines = body.lines();
    let mut header = lines.next()?;
    if header.starts_with("@SET \"NODE_PATH=") && header.ends_with(";%NODE_PATH%\"") {
        header = lines.next()?;
    }
    if header != expected_header {
        return None;
    }
    let local_target = lines
        .next()?
        .strip_prefix(local_node_prefix.as_str())?
        .strip_suffix(TARGET_SUFFIX)?;
    if lines.next()? != ") ELSE (" {
        return None;
    }
    let path_target = lines
        .next()?
        .strip_prefix(PATH_NODE_PREFIX)?
        .strip_suffix(TARGET_SUFFIX)?;
    if lines.next()? != ")" || lines.next().is_some() || local_target != path_target {
        return None;
    }
    Some(local_target)
}

/// Reject path strings containing cmd.exe metacharacters. Used before
/// emitting a `.cmd` bin shim. Covers
/// the sub-expression triple `( ) ;` and the quote-bypass triple
/// `` ` ' \t`` so a crafted `package.json > name` can't reach cmd.exe's
/// parser through double-quoted argument shapes.
#[cfg(windows)]
pub fn validate_cmd_path(path: &str) -> Result<(), String> {
    const DANGEROUS: &[char] = &[
        '"', '&', '|', '<', '>', '^', '%', '\n', '\r', '(', ')', ';', '`', '\'', '\t',
    ];
    for ch in DANGEROUS {
        if path.contains(*ch) {
            return Err(format!(
                "path contains dangerous character '{ch}' for cmd.exe"
            ));
        }
    }
    Ok(())
}

/// `path` without a `\\?\` prefix, on a drive path (`\\?\C:\…` is `C:\…`) or
/// a network share's (`\\?\UNC\server\share\…` is `\\server\share\…`), where
/// the plain path names the same file. A canonicalized path has the prefix,
/// which Node can't run and which never shares a volume with a path built
/// from a project's. Win32 reads a name with a trailing `.` or space
/// otherwise, so such a path keeps it, as does one Unicode can't spell (a
/// name holding an unpaired surrogate), whose lossy form names another file.
pub fn windows_plain_path(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    let plain = if let Some(share) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{share}")
    } else if let Some(drive) = text
        .strip_prefix(r"\\?\")
        .filter(|rest| rest.as_bytes().get(1) == Some(&b':'))
    {
        drive.to_string()
    } else {
        return path.to_path_buf();
    };
    if std::path::absolute(&plain).is_ok_and(|absolute| absolute == Path::new(&plain)) {
        PathBuf::from(plain)
    } else {
        path.to_path_buf()
    }
}

/// The way from the directory `base` to `target`, a `..` for each of
/// `base`'s own components and then the rest of `target`, when both are
/// absolute and on one volume; `None` otherwise.
///
/// Names compare as the host's file system compares them. On Windows that is
/// without case, so a home typed as `c:\users\çağrı` still shares its folders
/// with the target's `C:\Users\Çağrı\…` on disk, and the way names none of
/// them: a shim holding a non-ASCII folder name breaks when cmd.exe reads it
/// in the console's code page.
pub fn relative_path_on_one_volume(base: &Path, target: &Path) -> Option<PathBuf> {
    if !base.is_absolute() || !target.is_absolute() {
        return None;
    }
    let base: Vec<Component<'_>> = base.components().collect();
    let target: Vec<Component<'_>> = target.components().collect();
    if !same_component(base.first()?, target.first()?)
        || base
            .iter()
            .chain(&target)
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return None;
    }
    let shared = base
        .iter()
        .zip(&target)
        .take_while(|(base, target)| same_component(base, target))
        .count();
    let capacity = (base.len() - shared) * 3
        + target[shared..]
            .iter()
            .map(|part| part.as_os_str().len() + 1)
            .sum::<usize>();
    let mut relative = PathBuf::with_capacity(capacity);
    for _ in shared..base.len() {
        relative.push("..");
    }
    for part in &target[shared..] {
        relative.push(part.as_os_str());
    }
    (!relative.as_os_str().is_empty()).then_some(relative)
}

#[cfg(windows)]
fn same_component(a: &Component<'_>, b: &Component<'_>) -> bool {
    use std::path::Prefix;
    match (a, b) {
        // `Path` already gives a drive letter in either case as one `Disk`.
        (Component::Prefix(a), Component::Prefix(b)) => match (a.kind(), b.kind()) {
            (Prefix::UNC(server_a, share_a), Prefix::UNC(server_b, share_b))
            | (Prefix::VerbatimUNC(server_a, share_a), Prefix::VerbatimUNC(server_b, share_b)) => {
                same_windows_name(server_a, server_b) && same_windows_name(share_a, share_b)
            }
            (Prefix::Verbatim(a), Prefix::Verbatim(b))
            | (Prefix::DeviceNS(a), Prefix::DeviceNS(b)) => same_windows_name(a, b),
            (a, b) => a == b,
        },
        (Component::Normal(a), Component::Normal(b)) => same_windows_name(a, b),
        (a, b) => a == b,
    }
}

#[cfg(not(windows))]
fn same_component(a: &Component<'_>, b: &Component<'_>) -> bool {
    a == b
}

/// Whether Windows takes `a` and `b` for one name: the ordinal comparison
/// without case that NTFS and Win32 use, which folds non-ASCII letters too.
#[cfg(windows)]
fn same_windows_name(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

    if a == b {
        return true;
    }
    let a: Vec<u16> = a.encode_wide().collect();
    let b: Vec<u16> = b.encode_wide().collect();
    let (Ok(a_len), Ok(b_len)) = (i32::try_from(a.len()), i32::try_from(b.len())) else {
        return false;
    };
    // SAFETY: both pointers reference initialized UTF-16 buffers for the
    // exact lengths passed to the read-only API.
    unsafe { CompareStringOrdinal(a.as_ptr(), a_len, b.as_ptr(), b_len, 1) == CSTR_EQUAL }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn a_relative_way_shares_folders_named_in_another_case() {
        assert_eq!(
            relative_path_on_one_volume(
                Path::new(r"c:\users\çağrı\.lpm\global\bin"),
                Path::new(r"C:\Users\Çağrı\.lpm\global\pkgs\tool\cli.js"),
            ),
            Some(PathBuf::from(r"..\pkgs\tool\cli.js"))
        );
        assert_eq!(
            relative_path_on_one_volume(
                Path::new(r"\\fileserver\Home\dev\bin"),
                Path::new(r"\\FILESERVER\home\dev\pkgs\cli.js"),
            ),
            Some(PathBuf::from(r"..\pkgs\cli.js"))
        );
    }

    #[test]
    fn a_relative_way_needs_one_volume() {
        for (base, target) in [
            (r"C:\bin", r"D:\pkgs\cli.js"),
            (r"\\server\one\bin", r"\\server\two\cli.js"),
            (r"\\one\share\bin", r"\\two\share\cli.js"),
            (r"C:\bin", r"\\server\share\cli.js"),
            (r"C:\bin", r"pkgs\cli.js"),
            (r"C:\bin", r"C:\bin\..\cli.js"),
        ] {
            assert_eq!(
                relative_path_on_one_volume(Path::new(base), Path::new(target)),
                None,
                "{base} -> {target}"
            );
        }
    }

    #[test]
    fn a_path_unicode_cannot_spell_keeps_its_verbatim_prefix() {
        use std::os::windows::ffi::OsStringExt as _;

        let mut wide: Vec<u16> = r"\\?\C:\Users\dev\".encode_utf16().collect();
        wide.push(0xD800);
        wide.extend("\\cli.js".encode_utf16());
        let path = PathBuf::from(std::ffi::OsString::from_wide(&wide));

        assert_eq!(windows_plain_path(&path), path);
    }

    #[test]
    fn a_plain_path_drops_the_verbatim_prefix_only_where_it_names_the_same_file() {
        for (path, plain) in [
            (r"\\?\C:\Users\dev\cli.js", r"C:\Users\dev\cli.js"),
            (r"\\?\UNC\server\share\cli.js", r"\\server\share\cli.js"),
            (r"C:\Users\dev\cli.js", r"C:\Users\dev\cli.js"),
            (r"\\?\C:\Users\dev\trailing.", r"\\?\C:\Users\dev\trailing."),
            (
                r"\\?\UNC\server\share\trailing ",
                r"\\?\UNC\server\share\trailing ",
            ),
            (r"\\?\Volume{0}\cli.js", r"\\?\Volume{0}\cli.js"),
        ] {
            assert_eq!(
                windows_plain_path(Path::new(path)),
                Path::new(plain),
                "{path}"
            );
        }
    }

    #[test]
    fn validate_cmd_path_allows_normal_path() {
        assert!(validate_cmd_path("C:\\Users\\dev\\project").is_ok());
    }

    #[test]
    fn validate_cmd_path_rejects_ampersand() {
        let err = validate_cmd_path("C:\\evil & rm -rf").unwrap_err();
        assert!(err.contains('&'));
    }

    #[test]
    fn validate_cmd_path_rejects_paren_subshell() {
        let err = validate_cmd_path("C:\\evil(echo+pwned)\\node.exe").unwrap_err();
        assert!(err.contains('('));
    }

    #[test]
    fn validate_cmd_path_rejects_semicolon() {
        let err = validate_cmd_path("C:\\evil;malicious.bat").unwrap_err();
        assert!(err.contains(';'));
    }

    #[test]
    fn validate_cmd_path_rejects_backtick() {
        let err = validate_cmd_path("C:\\evil`echo`.exe").unwrap_err();
        assert!(err.contains('`'));
    }

    #[test]
    fn validate_cmd_path_rejects_single_quote() {
        let err = validate_cmd_path("C:\\evil'cmd'.exe").unwrap_err();
        assert!(err.contains('\''));
    }

    #[test]
    fn validate_cmd_path_rejects_tab() {
        let err = validate_cmd_path("C:\\evil\tmalicious").unwrap_err();
        assert!(err.contains('\t'));
    }

    #[test]
    fn lexically_clean_simplifies_double_dots() {
        let cleaned = lexically_clean(Path::new("a/b/../c"));
        assert_eq!(cleaned, PathBuf::from("a/c"));
    }

    #[test]
    fn directory_link_survives_parent_rename_and_removes_without_touching_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("marker"), b"ok").unwrap();

        let staged = dir.path().join("staged");
        std::fs::create_dir(&staged).unwrap();
        let link = staged.join("link");
        create_dir_symlink_or_junction(Path::new("../target"), &link).unwrap();

        let published = dir.path().join("published");
        std::fs::rename(&staged, &published).unwrap();
        let published_link = published.join("link");
        assert_eq!(std::fs::read(published_link.join("marker")).unwrap(), b"ok");

        remove_path_entry(&published_link).unwrap();
        assert!(published_link.symlink_metadata().is_err());
        assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"ok");
    }

    /// A scoped package's name holds a `/`, so the linker's paths do too.
    fn assert_scoped_package_link_resolves(root: &Path) {
        let target = root.join("store/@scope/name");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("marker"), b"ok").unwrap();
        std::fs::create_dir_all(root.join("node_modules").join("@scope")).unwrap();
        let link = root.join("node_modules").join("@scope/name");

        create_dir_symlink_or_junction(&target, &link).unwrap();

        assert_eq!(std::fs::read(link.join("marker")).unwrap(), b"ok");
    }

    #[test]
    fn a_scoped_package_link_is_created_through_the_forward_slash_its_name_holds() {
        let dir = tempfile::tempdir().unwrap();
        assert_scoped_package_link_resolves(dir.path());
    }

    #[test]
    fn a_scoped_package_link_under_a_verbatim_root_is_created() {
        let dir = tempfile::tempdir().unwrap();
        assert_scoped_package_link_resolves(&dir.path().canonicalize().unwrap());
    }

    fn target_with_marker(parent: &Path) -> PathBuf {
        let target = parent.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("marker"), b"ok").unwrap();
        target
    }

    #[test]
    fn a_junction_resolves_to_its_target_and_removes_without_touching_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = target_with_marker(dir.path());
        let link = dir.path().join("link");

        create_junction(&target, &link).unwrap();

        assert!(is_symlink_or_junction(&link.symlink_metadata().unwrap()));
        assert_eq!(std::fs::read(link.join("marker")).unwrap(), b"ok");
        remove_path_entry(&link).unwrap();
        assert!(link.symlink_metadata().is_err());
        assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"ok");
    }

    #[test]
    fn a_junction_path_may_hold_characters_a_command_interpreter_would_parse() {
        let dir = tempfile::tempdir().unwrap();
        let target = target_with_marker(&dir.path().join("a&b %PATH% (c)"));
        let link = dir.path().join("x&y %TEMP%");

        create_junction(&target, &link).unwrap();

        assert_eq!(std::fs::read(link.join("marker")).unwrap(), b"ok");
    }

    #[test]
    fn a_junction_is_created_past_max_path() {
        let dir = tempfile::tempdir().unwrap();
        let deep = "d".repeat(120);
        let root = dir.path().canonicalize().unwrap().join(&deep).join(&deep);
        let target = target_with_marker(&root);
        let link = root.join("l".repeat(120));
        assert!(link.as_os_str().len() > 260);

        create_junction(&target, &link).unwrap();

        assert_eq!(std::fs::read(link.join("marker")).unwrap(), b"ok");
    }

    #[test]
    fn a_junction_never_replaces_an_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let target = target_with_marker(dir.path());
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("kept"), b"kept").unwrap();

        let error = create_junction(&target, &existing).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(!is_symlink_or_junction(
            &existing.symlink_metadata().unwrap()
        ));
        assert_eq!(std::fs::read(existing.join("kept")).unwrap(), b"kept");
    }

    #[test]
    fn a_junction_to_a_network_share_is_refused_without_leaving_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");

        let error = create_junction(Path::new(r"\\server\share\package"), &link).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(link.symlink_metadata().is_err());
    }

    #[test]
    fn a_link_to_a_network_folder_reads_as_that_folder() {
        let target = tempfile::tempdir().unwrap();
        let Some(network) = crate::test_network_path::through_network(target.path()) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        if let Err(error) = std::os::windows::fs::symlink_dir(&network, dir.path().join("link")) {
            assert!(
                std::env::var_os("LPM_TEST_REQUIRE_ADMIN_SHARES").is_none(),
                "an administrator could not create a symbolic link: {error}"
            );
            eprintln!("skipped: no symbolic link without administrator rights ({error})");
            return;
        }
        let directory =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();

        let read = directory.read_link_contents("link").unwrap();

        assert_eq!(read, network);
        assert!(read.is_absolute(), "{read:?}");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_relative_way_climbs_to_the_shared_folder_and_compares_names_exactly() {
        assert_eq!(
            relative_path_on_one_volume(
                Path::new("/home/dev/.lpm/global/bin"),
                Path::new("/home/dev/.lpm/global/pkgs/tool/cli.js"),
            ),
            Some(PathBuf::from("../pkgs/tool/cli.js"))
        );
        assert_eq!(
            relative_path_on_one_volume(Path::new("/home/Dev/bin"), Path::new("/home/dev/cli.js")),
            Some(PathBuf::from("../../dev/cli.js"))
        );
        assert_eq!(
            relative_path_on_one_volume(Path::new("/home/dev"), Path::new("relative/cli.js")),
            None
        );
        assert_eq!(
            relative_path_on_one_volume(Path::new("/home/dev"), Path::new("/home/dev")),
            None
        );
    }

    #[test]
    fn create_dir_symlink_round_trips_unix() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        create_dir_symlink_or_junction(&target, &link).unwrap();
        let read = std::fs::read_link(&link).unwrap();
        assert_eq!(read, target);
    }

    #[test]
    fn create_symlink_round_trips_file_unix() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.js");
        std::fs::write(&target, b"console.log('ok')\n").unwrap();
        let link = dir.path().join("link.js");
        create_symlink(&target, &link).unwrap();
        let read = std::fs::read_link(&link).unwrap();
        assert_eq!(read, target);
    }

    #[test]
    fn remove_path_entry_unlinks_directory_symlink_without_touching_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("marker"), b"ok").unwrap();
        let link = dir.path().join("link");
        create_dir_symlink_or_junction(&target, &link).unwrap();

        remove_path_entry(&link).unwrap();

        assert!(link.symlink_metadata().is_err());
        assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"ok");
    }
}

#[cfg(test)]
mod entry_removal_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn counting_removal_never_follows_a_link_out_of_the_tree() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"keep").unwrap();
        let tree = root.path().join("tree");
        std::fs::create_dir_all(tree.join("nested")).unwrap();
        std::fs::write(tree.join("nested/file"), b"12345").unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("nested/link")).unwrap();

        let freed = super::remove_path_entry_counting_freed_bytes(&tree).unwrap();

        assert_eq!(freed, 5);
        assert!(!tree.exists());
        assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn counting_removal_succeeds_on_deep_tree_under_low_fd_limit() {
        const CHILD: &str = "LPM_TEST_DEEP_COUNTING_REMOVAL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "symlink::entry_removal_tests::counting_removal_succeeds_on_deep_tree_under_low_fd_limit",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("deep");
        let mut cur = tree.clone();
        for depth in 0..200 {
            cur = cur.join(format!("d{depth}"));
        }
        std::fs::create_dir_all(&cur).unwrap();
        std::fs::write(cur.join("leaf.txt"), b"hello").unwrap();

        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is valid writable storage for `getrlimit`.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        let tight = libc::rlimit {
            rlim_cur: 128.min(limit.rlim_max),
            rlim_max: limit.rlim_max,
        };
        // SAFETY: lowering soft limit to <= hard limit is valid POSIX usage in this child process.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tight) }, 0);

        let freed = super::remove_path_entry_counting_freed_bytes(&tree).unwrap();
        assert_eq!(freed, 5);
        assert!(!tree.exists());
    }

    #[test]
    fn remove_symlink_or_junction_entry_preserves_the_link_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("marker"), b"ok").unwrap();
        let link = dir.path().join("link");
        create_dir_symlink_or_junction(&target, &link).unwrap();

        remove_symlink_or_junction_entry(&link).unwrap();

        assert!(link.symlink_metadata().is_err());
        assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"ok");
    }

    #[test]
    fn remove_symlink_or_junction_entry_refuses_a_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real_directory = dir.path().join("real-directory");
        std::fs::create_dir(&real_directory).unwrap();
        std::fs::write(real_directory.join("marker"), b"ok").unwrap();

        let error = remove_symlink_or_junction_entry(&real_directory)
            .expect_err("a real directory must never be removed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read(real_directory.join("marker")).unwrap(), b"ok");
    }

    #[test]
    fn resolve_symlink_probe_path_resolves_relative_targets_against_link_parent() {
        let probe = super::resolve_symlink_probe_path(
            Path::new("../shared/pkg"),
            Path::new("/workspace/project/node_modules/@scope/pkg"),
        );
        assert_eq!(
            probe,
            Path::new("/workspace/project/node_modules/shared/pkg")
        );

        let abs = super::resolve_symlink_probe_path(
            Path::new("/opt/store/pkg"),
            Path::new("/workspace/project/node_modules/pkg"),
        );
        assert_eq!(abs, Path::new("/opt/store/pkg"));
    }

    #[test]
    fn normalize_windows_link_target_handles_verbatim_prefixes_slashes_and_drive_case() {
        let verbatim = super::normalize_windows_link_target_str(
            r"\\?\C:\Users\Dev\.lpm\store\v2\links\pkg\node_modules\pkg",
        );
        let mixed = super::normalize_windows_link_target_str(
            r"c:/Users/Dev/.lpm/store/v2/links/pkg/node_modules/pkg/",
        );
        let nt_prefix = super::normalize_windows_link_target_str(
            r"\??\C:\Users\Dev\.lpm\store\v2\links\pkg\node_modules\pkg",
        );
        assert!(verbatim.is_some());
        assert_eq!(verbatim, mixed);
        assert_eq!(verbatim, nt_prefix);

        let unc_verbatim = super::normalize_windows_link_target_str(r"\\?\UNC\Server\Share\Pkg\");
        let unc_plain = super::normalize_windows_link_target_str(r"\\Server/Share/Pkg");
        assert!(unc_verbatim.is_some());
        assert_eq!(unc_verbatim, unc_plain);
    }

    #[test]
    fn link_targets_equivalent_rejects_parent_dir_after_normal_component() {
        assert!(
            !super::link_targets_equivalent(
                Path::new("decoy/../target"),
                Path::new("/workspace/project/node_modules/pkg"),
                Path::new("/workspace/project/node_modules/target"),
            ),
            "parent traversal after a normal component must not be collapsed lexically"
        );
        assert!(
            !super::link_targets_equivalent(
                Path::new("/workspace/decoy/../target"),
                Path::new("/workspace/project/node_modules/pkg"),
                Path::new("/workspace/target"),
            ),
            "absolute path with parent traversal must not be collapsed lexically"
        );
        #[cfg(unix)]
        {
            let root = tempfile::tempdir().unwrap();
            let outside = root.path().join("outside");
            let nm = root.path().join("node_modules");
            std::fs::create_dir_all(outside.join("sub")).unwrap();
            std::fs::create_dir_all(outside.join("evil")).unwrap();
            std::fs::create_dir_all(nm.join("target")).unwrap();
            std::os::unix::fs::symlink(outside.join("sub"), nm.join("decoy")).unwrap();
            let link = nm.join("pkg");
            std::os::unix::fs::symlink(Path::new("decoy/../target"), &link).unwrap();
            assert!(!super::link_targets_equivalent(
                &std::fs::read_link(&link).unwrap(),
                &link,
                &nm.join("target"),
            ));
        }
    }

    #[test]
    fn normalize_windows_link_target_rejects_verbatim_dotdot_unc_escape_and_path_case_mismatch() {
        assert_eq!(
            super::normalize_windows_link_target_str(r"\\?\C:\a\..\b"),
            None,
            "verbatim paths must not collapse parent segments"
        );
        assert_eq!(
            super::normalize_windows_link_target_str(r"\\srv\share\..\..\x"),
            None,
            "UNC server and share roots must not be popped by parent segments"
        );
        assert_ne!(
            super::normalize_windows_link_target_str(r"C:\dir\Pkg"),
            super::normalize_windows_link_target_str(r"C:\dir\pkg"),
            "path components must not be folded across case-sensitive directories"
        );
        assert_eq!(
            super::normalize_windows_link_target_str(r"c:\dir\Pkg"),
            super::normalize_windows_link_target_str(r"C:\dir\Pkg"),
            "Windows drive letters remain case-insensitive"
        );
    }
}

#[cfg(test)]
mod cmd_shim_tests {
    use super::*;

    /// A shim body that runs Node with no `NODE_PATH` ends its batch file
    /// before Node starts, so Ctrl+C asks nothing; one with `NODE_PATH`
    /// keeps it. Both look Node up on `PATH` by name, and are read back to
    /// their target.
    #[test]
    fn node_shim_bodies_end_the_batch_file_unless_they_set_node_path() {
        let target = r"%dp0%..\tool\bin\tool.js";
        let body = windows_node_cmd_shim_body(target, None);
        assert_eq!(
            body,
            "@SET \"_prog=node\"\r\n\
             @FOR %%I IN (node.exe) DO @IF NOT \"%%~$PATH:I\"==\"\" SET \"_prog=%%~$PATH:I\"\r\n\
             @IF EXIST \"%dp0%node.exe\" SET \"_prog=%dp0%node.exe\"\r\n\
             @ENDLOCAL & GOTO #_undefined_# 2>NUL || TITLE %COMSPEC% & \"%_prog%\" \"%dp0%..\\tool\\bin\\tool.js\" %*\r\n"
        );
        assert_eq!(windows_node_cmd_shim_target(&body), Some(target));

        let with_node_path = windows_node_cmd_shim_body(target, Some("%dp0%.."));
        assert!(with_node_path.starts_with("@SET \"NODE_PATH=%dp0%..;%NODE_PATH%\"\r\n"));
        assert!(with_node_path.ends_with("@\"%_prog%\" \"%dp0%..\\tool\\bin\\tool.js\" %*\r\n"));
        assert!(!with_node_path.contains("GOTO"));
        assert_eq!(windows_node_cmd_shim_target(&with_node_path), Some(target));

        assert_eq!(windows_node_cmd_shim_target("@node x.js %*\r\n"), None);
        let earlier = "@IF EXIST \"%~dp0\\node.exe\" (\r\n  \"%~dp0\\node.exe\" \"C:\\t.js\" %*\r\n) ELSE (\r\n  node \"C:\\t.js\" %*\r\n)\r\n";
        assert_eq!(windows_node_cmd_shim_target(earlier), None);
        assert_eq!(
            windows_block_cmd_shim_target(earlier, "%~dp0\\node.exe"),
            Some(r"C:\t.js")
        );
    }
}
