#[cfg(not(windows))]
use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;
use std::ffi::{OsStr, OsString};

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryIdentity {
    volume: u32,
    file_index: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryIdentity;

#[cfg(unix)]
pub(crate) fn directory_identity(directory: &Dir) -> std::io::Result<DirectoryIdentity> {
    use cap_std::fs::MetadataExt as _;

    let metadata = directory.dir_metadata()?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
pub(crate) fn directory_identity(directory: &Dir) -> std::io::Result<DirectoryIdentity> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let result = unsafe {
        // SAFETY: `directory` owns a valid handle and `information` is writable.
        GetFileInformationByHandle(
            directory.as_raw_handle(),
            std::ptr::addr_of_mut!(information),
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (volume, file_index) = windows_directory_identity_fields(
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    );
    Ok(DirectoryIdentity { volume, file_index })
}

#[cfg(any(test, windows))]
fn windows_directory_identity_fields(
    volume: u32,
    file_index_high: u32,
    file_index_low: u32,
) -> (u32, u64) {
    (
        volume,
        (u64::from(file_index_high) << 32) | u64::from(file_index_low),
    )
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn directory_identity(_directory: &Dir) -> std::io::Result<DirectoryIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "directory identity checks are unavailable on this platform",
    ))
}

pub(crate) fn create_private_directory(
    parent: &Dir,
    purpose: &str,
) -> std::io::Result<(OsString, Dir)> {
    create_private_directory_with(parent, purpose, |_, _| Ok(()))
}

fn create_private_directory_with(
    parent: &Dir,
    purpose: &str,
    mut after_create: impl FnMut(&Dir, &OsStr) -> std::io::Result<()>,
) -> std::io::Result<(OsString, Dir)> {
    use rand::RngCore as _;

    let mut last_collision = None;
    for _ in 0..32 {
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let name = OsString::from(format!(".lpm-{purpose}-{}", hex::encode(random)));
        match create_and_open_private_directory(parent, &name) {
            Ok(directory) => {
                let created_identity = directory_identity(&directory)?;
                after_create(parent, &name)?;
                let visible = open_directory_for_publication(parent, &name)?;
                if directory_identity(&visible)? != created_identity {
                    return Err(std::io::Error::other(
                        "private transaction directory changed before handle verification",
                    ));
                }
                return Ok((name, directory));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a private directory name",
        )
    }))
}

#[cfg(unix)]
fn create_and_open_private_directory(parent: &Dir, name: &OsStr) -> std::io::Result<Dir> {
    use cap_std::fs::{DirBuilderExt as _, MetadataExt as _};

    let metadata = parent.dir_metadata()?;
    let current_uid = unsafe {
        // SAFETY: `geteuid` has no pointer arguments and returns the caller's effective uid.
        libc::geteuid()
    };
    if metadata.uid() != current_uid
        || metadata.mode() & 0o022 != 0
        || private_parent_has_extended_acl(parent)?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private transaction parent is not exclusively controlled by the current user",
        ));
    }
    let mut builder = cap_std::fs::DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)?;
    open_directory_for_publication(parent, name)
}

#[cfg(target_os = "macos")]
fn private_parent_has_extended_acl(parent: &Dir) -> std::io::Result<bool> {
    use std::ffi::c_void;
    use std::os::fd::AsRawFd as _;

    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    struct Acl(*mut c_void);

    impl Drop for Acl {
        fn drop(&mut self) {
            unsafe {
                // SAFETY: `Acl` owns the object returned by `acl_get_fd_np`.
                let _ = acl_free(self.0);
            }
        }
    }

    unsafe extern "C" {
        fn acl_free(object: *mut c_void) -> libc::c_int;
        fn acl_get_entry(
            acl: *mut c_void,
            entry_id: libc::c_int,
            entry: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut c_void;
    }

    let acl = Acl(unsafe {
        // SAFETY: the parent directory handle remains valid for the duration of the call.
        acl_get_fd_np(parent.as_raw_fd(), ACL_TYPE_EXTENDED)
    });
    if acl.0.is_null() {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let mut entry = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: `acl` is owned and valid, and `entry` is an initialized output pointer.
        acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry)
    };
    if status == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINVAL) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "keeps the ACL probe signature consistent with the fallible macOS implementation"
)]
fn private_parent_has_extended_acl(_parent: &Dir) -> std::io::Result<bool> {
    Ok(false)
}

#[cfg(windows)]
fn create_and_open_private_directory(parent: &Dir, name: &OsStr) -> std::io::Result<Dir> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, HANDLE, LocalFree, OBJ_CASE_INSENSITIVE,
        RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                // SAFETY: the SDDL conversion allocated this descriptor with LocalAlloc.
                let _ = LocalFree(self.0.cast());
            }
        }
    }

    let owner_only_sddl = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut security_descriptor = std::ptr::null_mut();
    if unsafe {
        // SAFETY: the SDDL is NUL-terminated and the output becomes LocalFree-owned on success.
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            owner_only_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let security_descriptor = LocalSecurityDescriptor(security_descriptor);

    let mut name = name.encode_wide().collect::<Vec<_>>();
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or_else(|| std::io::Error::other("private transaction name is too long"))?;
    let unicode_name = UNICODE_STRING {
        Length: name_bytes,
        MaximumLength: name_bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
            .expect("OBJECT_ATTRIBUTES size fits in u32"),
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security_descriptor
            .0
            .cast::<SECURITY_DESCRIPTOR>()
            .cast_const(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        // SAFETY: the counted UTF-16 name and object attributes remain alive for the call;
        // the parent handle is valid and the output handle is initialized by NtCreateFile.
        NtCreateFile(
            &mut handle,
            GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
            &attributes,
            &mut io_status,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        let code = unsafe {
            // SAFETY: `status` is the NTSTATUS returned by `NtCreateFile`.
            RtlNtStatusToDosError(status)
        };
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }
    let file = unsafe {
        // SAFETY: successful NtCreateFile returned a new owned directory handle.
        std::fs::File::from_raw_handle(handle.cast())
    };
    Ok(Dir::from_std_file(file))
}

#[cfg(not(any(unix, windows)))]
fn create_and_open_private_directory(_parent: &Dir, _name: &OsStr) -> std::io::Result<Dir> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic private directory creation is unavailable on this platform",
    ))
}

#[cfg(not(windows))]
pub(crate) fn open_directory_for_publication(parent: &Dir, name: &OsStr) -> std::io::Result<Dir> {
    parent.open_dir_nofollow(name)
}

#[cfg(windows)]
pub(crate) fn open_directory_for_publication(parent: &Dir, name: &OsStr) -> std::io::Result<Dir> {
    use cap_fs_ext::{
        FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsMaybeDirExt as _, OsMetadataExt as _,
    };
    use cap_std::fs::{OpenOptions, OpenOptionsExt as _};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    let file = parent.open_with(name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(
            "private transaction path is linked or not a directory",
        ));
    }
    Ok(Dir::from_std_file(file.into_std()))
}

#[cfg(not(windows))]
pub(crate) fn discard_private_directory(directory: Dir) -> std::io::Result<()> {
    directory.remove_open_dir()
}

#[cfg(windows)]
pub(crate) fn discard_private_directory(directory: Dir) -> std::io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    if directory.entries()?.next().transpose()?.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::DirectoryNotEmpty,
            "private transaction directory is not empty",
        ));
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let deleted = unsafe {
        // SAFETY: the retained directory handle has DELETE access and `disposition` is a valid,
        // fixed-size FILE_DISPOSITION_INFO that remains alive for the synchronous call.
        SetFileInformationByHandle(
            directory.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::addr_of!(disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>())
                .expect("FILE_DISPOSITION_INFO size fits in u32"),
        )
    };
    if deleted == 0 {
        return Err(std::io::Error::last_os_error());
    }
    drop(directory);
    Ok(())
}

#[cfg(unix)]
pub(crate) fn publish_entry_noreplace(
    source_parent: &Dir,
    private_name: &OsStr,
    destination_parent: &Dir,
    final_name: &OsStr,
) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        source_parent,
        private_name,
        destination_parent,
        final_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}

#[cfg(windows)]
pub(crate) fn publish_entry_noreplace(
    source_parent: &Dir,
    private_name: &OsStr,
    destination_parent: &Dir,
    final_name: &OsStr,
) -> std::io::Result<()> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsMaybeDirExt as _};
    use cap_std::fs::{OpenOptions, OpenOptionsExt as _};
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    let entry = source_parent.open_with(private_name, &options)?;
    publish_windows_handle_noreplace(entry.as_raw_handle(), destination_parent, final_name)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn publish_entry_noreplace(
    _source_parent: &Dir,
    _private_name: &OsStr,
    _destination_parent: &Dir,
    _final_name: &OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace entry publication is unavailable on this platform",
    ))
}

#[cfg(unix)]
pub(crate) fn publish_directory_noreplace(
    source_parent: &Dir,
    directory: &Dir,
    private_name: &OsStr,
    destination_parent: &Dir,
    final_name: &OsStr,
) -> std::io::Result<()> {
    let expected_identity = directory_identity(directory)?;
    let visible_source = open_directory_for_publication(source_parent, private_name)?;
    if directory_identity(&visible_source)? != expected_identity {
        return Err(std::io::Error::other(
            "directory publication source identity changed",
        ));
    }
    rustix::fs::renameat_with(
        source_parent,
        private_name,
        destination_parent,
        final_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    verify_published_directory_identity(destination_parent, final_name, &expected_identity)
}

#[cfg(windows)]
pub(crate) fn publish_directory_noreplace(
    _source_parent: &Dir,
    directory: &Dir,
    _private_name: &OsStr,
    destination_parent: &Dir,
    final_name: &OsStr,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;

    let expected_identity = directory_identity(directory)?;
    publish_windows_handle_noreplace(directory.as_raw_handle(), destination_parent, final_name)?;
    verify_published_directory_identity(destination_parent, final_name, &expected_identity)
}

#[cfg(any(unix, windows))]
fn verify_published_directory_identity(
    destination_parent: &Dir,
    final_name: &OsStr,
    expected_identity: &DirectoryIdentity,
) -> std::io::Result<()> {
    let published = open_directory_for_publication(destination_parent, final_name)?;
    if &directory_identity(&published)? != expected_identity {
        return Err(std::io::Error::other(
            "published directory identity does not match the retained source",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn publish_windows_handle_noreplace(
    handle: std::os::windows::io::RawHandle,
    destination_parent: &Dir,
    final_name: &OsStr,
) -> std::io::Result<()> {
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let final_name = final_name.encode_wide().collect::<Vec<_>>();
    let file_name_bytes = final_name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| std::io::Error::other("transaction directory name is too long"))?;
    let info_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(file_name_bytes)
        .ok_or_else(|| std::io::Error::other("transaction rename data is too large"))?;
    let mut storage = vec![0usize; info_bytes.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let info_bytes = u32::try_from(info_bytes)
        .map_err(|_| std::io::Error::other("transaction rename data is too large"))?;
    let file_name_bytes = u32::try_from(file_name_bytes)
        .map_err(|_| std::io::Error::other("transaction directory name is too long"))?;
    unsafe {
        // SAFETY: storage is aligned and sized for the variable-length rename record. Both
        // directory handles remain open and the relative UTF-16 name is copied in full.
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = destination_parent.as_raw_handle();
        (*info).FileNameLength = file_name_bytes;
        std::ptr::copy_nonoverlapping(
            final_name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            final_name.len(),
        );
    }
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: `info` describes the initialized buffer above and both handles remain valid.
    let status = unsafe {
        NtSetInformationFile(
            handle,
            &mut io_status,
            info.cast(),
            info_bytes,
            FileRenameInformation,
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        // SAFETY: `status` is the NTSTATUS returned by `NtSetInformationFile`.
        let code = unsafe { RtlNtStatusToDosError(status) };
        Err(std::io::Error::from_raw_os_error(code as i32))
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn publish_directory_noreplace(
    _source_parent: &Dir,
    _directory: &Dir,
    _private_name: &OsStr,
    _destination_parent: &Dir,
    _final_name: &OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace directory publication is unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_directory_identity_combines_the_full_file_index() {
        assert_eq!(
            windows_directory_identity_fields(7, 0x1122_3344, 0x5566_7788),
            (7, 0x1122_3344_5566_7788)
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn private_directory_creation_rejects_a_replacement_before_handle_capture() {
        let root = tempfile::tempdir().unwrap();
        let parent = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        let displaced = root.path().join("displaced-private-directory");
        let replacement_path = std::cell::RefCell::new(None);

        let result = create_private_directory_with(&parent, "capture-race", |parent, name| {
            parent.rename(name, parent, OsStr::new("displaced-private-directory"))?;
            parent.create_dir(name)?;
            replacement_path.replace(Some(root.path().join(name)));
            Ok(())
        });

        assert!(result.is_err(), "replacement was returned as LPM-owned");
        assert!(displaced.is_dir(), "the created directory was lost");
        assert!(
            replacement_path
                .borrow()
                .as_ref()
                .is_some_and(|path| path.is_dir()),
            "the replacement directory was removed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_creation_rejects_a_group_writable_parent() {
        use cap_std::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let parent = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        parent
            .set_permissions(".", cap_std::fs::Permissions::from_mode(0o770))
            .unwrap();

        let result = create_private_directory(&parent, "shared-parent");

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_creation_uses_owner_only_permissions() {
        use cap_std::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let parent = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();

        let (_, directory) = create_private_directory(&parent, "private-mode").unwrap();
        let mode = directory.dir_metadata().unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o700);
        discard_private_directory(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_directory_creation_rejects_a_parent_with_an_extended_acl() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow add_subdirectory,delete_child"])
            .arg(root.path())
            .status()
            .unwrap();
        assert!(status.success(), "failed to apply the test ACL");
        let parent = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();

        let result = create_private_directory(&parent, "acl-parent");

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_publication_rejects_a_replaced_source_path() {
        let root = tempfile::tempdir().unwrap();
        let parent = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        let (_private_name, private_directory) =
            create_private_directory(&parent, "publish-source").unwrap();
        private_directory.create_dir("directory").unwrap();
        let retained = private_directory.open_dir_nofollow("directory").unwrap();
        private_directory
            .rename("directory", &private_directory, "displaced-directory")
            .unwrap();
        private_directory.create_dir("directory").unwrap();
        let replacement = private_directory.open_dir_nofollow("directory").unwrap();
        let replacement_identity = directory_identity(&replacement).unwrap();

        let result = publish_directory_noreplace(
            &private_directory,
            &retained,
            OsStr::new("directory"),
            &parent,
            OsStr::new("published"),
        );

        assert!(result.is_err(), "replacement source path was published");
        assert!(!root.path().join("published").exists());
        let visible_replacement = private_directory.open_dir_nofollow("directory").unwrap();
        assert!(
            directory_identity(&visible_replacement).unwrap() == replacement_identity,
            "replacement source path changed"
        );
    }
}
