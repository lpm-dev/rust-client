use super::*;

pub(in crate::release_plan) fn canonical_workspace_root(
    workspace_root: &Path,
) -> Result<PathBuf, LpmError> {
    let root = workspace_root.canonicalize().map_err(LpmError::Io)?;
    if !std::fs::symlink_metadata(&root)
        .map_err(LpmError::Io)?
        .is_dir()
    {
        return Err(LpmError::Script(format!(
            "release workspace root is not a directory: {}",
            root.display()
        )));
    }
    Ok(root)
}

#[cfg(test)]
pub(in crate::release_plan) fn release_state_dir(
    canonical_root: &Path,
    create: bool,
) -> Result<Option<PathBuf>, LpmError> {
    Ok(open_release_state_directory(canonical_root, create)?.map(|state| state.display))
}

pub(in crate::release_plan) fn open_release_state_directory(
    canonical_root: &Path,
    create: bool,
) -> Result<Option<ReleaseStateDirectory>, LpmError> {
    let root = open_root_directory_nofollow(canonical_root)?;
    open_release_state_directory_from_open_root(canonical_root, &root, create)
}

pub(in crate::release_plan) fn open_release_state_directory_from_open_root(
    canonical_root: &Path,
    root: &cap_std::fs::Dir,
    create: bool,
) -> Result<Option<ReleaseStateDirectory>, LpmError> {
    use cap_fs_ext::DirExt as _;

    let lpm_display = canonical_root.join(".lpm");
    let lpm_dir = match root.open_dir_nofollow(".lpm") {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match create_private_cap_directory(root, ".lpm") {
                Ok(()) => sync_cap_directory(root).map_err(LpmError::Io)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
            root.open_dir_nofollow(".lpm").map_err(|error| {
                LpmError::Script(format!(
                    "refusing LPM state directory that is not a real directory: {}: {error}",
                    lpm_display.display()
                ))
            })?
        }
        Err(error) => {
            return Err(LpmError::Script(format!(
                "refusing LPM state directory that is not a real directory: {}: {error}",
                lpm_display.display()
            )));
        }
    };
    validate_lpm_state_parent(&lpm_dir, &lpm_display)?;

    let state_display = lpm_display.join(RELEASE_STATE_DIRECTORY);
    let state_dir = match lpm_dir.open_dir_nofollow(RELEASE_STATE_DIRECTORY) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match create_private_cap_directory(&lpm_dir, RELEASE_STATE_DIRECTORY) {
                Ok(()) => sync_cap_directory(&lpm_dir).map_err(LpmError::Io)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
            lpm_dir
                .open_dir_nofollow(RELEASE_STATE_DIRECTORY)
                .map_err(|error| {
                    LpmError::Script(format!(
                        "refusing release transaction directory that is not a real directory: {}: {error}",
                        state_display.display()
                    ))
                })?
        }
        Err(error) => {
            return Err(LpmError::Script(format!(
                "refusing release transaction directory that is not a real directory: {}: {error}",
                state_display.display()
            )));
        }
    };
    validate_private_state_directory(&state_dir, &state_display)?;
    Ok(Some(ReleaseStateDirectory {
        dir: state_dir,
        display: state_display,
    }))
}

pub(in crate::release_plan) fn validate_private_state_directory(
    directory: &cap_std::fs::Dir,
    display: &Path,
) -> Result<(), LpmError> {
    let metadata = directory.dir_metadata().map_err(LpmError::Io)?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(LpmError::Script(format!(
            "refusing release transaction directory that is not a real directory: {}",
            display.display()
        )));
    }
    validate_private_unix_metadata(display, &metadata, true)?;
    protect_private_windows_directory(directory, display)
}

pub(in crate::release_plan) fn validate_private_journal_file(
    file: &cap_std::fs::File,
    display: &Path,
) -> Result<(), LpmError> {
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(LpmError::Script(format!(
            "refusing release journal path that is not a regular file: {}",
            display.display()
        )));
    }
    validate_private_unix_metadata(display, &metadata, false)?;
    protect_private_windows_file(file, display)
}

pub(in crate::release_plan) fn open_private_state_file(
    state: &ReleaseStateDirectory,
    name: &str,
) -> Result<Option<cap_std::fs::File>, LpmError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};

        options.access_mode(GENERIC_READ | READ_CONTROL | WRITE_DAC);
    }
    let file = match state.dir.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(LpmError::Io(error)),
    };
    let display = state.display.join(name);
    validate_private_journal_file(&file, &display)?;
    Ok(Some(file))
}

pub(in crate::release_plan) fn read_private_state_file_capped(
    state: &ReleaseStateDirectory,
    name: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, LpmError> {
    let Some(mut file) = open_private_state_file(state, name)? else {
        return Ok(None);
    };
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if metadata.len() > max_bytes {
        return Err(LpmError::Script(format!(
            "release transaction state exceeds the {max_bytes}-byte limit: {}",
            state.display.join(name).display()
        )));
    }
    let capacity = usize::try_from(metadata.len()).unwrap_or_default();
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(LpmError::Io)?;
    if bytes.len() as u64 > max_bytes {
        return Err(LpmError::Script(format!(
            "release transaction state exceeds the {max_bytes}-byte limit: {}",
            state.display.join(name).display()
        )));
    }
    Ok(Some(bytes))
}

pub(in crate::release_plan) fn write_private_state_file_atomic(
    state: &ReleaseStateDirectory,
    name: &str,
    bytes: &[u8],
) -> Result<(), LpmError> {
    match state.dir.symlink_metadata(name) {
        Ok(metadata) if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() => {
            return Err(LpmError::Script(format!(
                "refusing release transaction path that is not a regular file: {}",
                state.display.join(name).display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(LpmError::Io(error)),
    }

    let (temporary_name, mut temporary) =
        create_manifest_temporary(&state.dir, Some(0o600)).map_err(LpmError::Io)?;
    let result = (|| {
        temporary.write_all(bytes)?;
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt as _;
            temporary.set_permissions(cap_std::fs::Permissions::from_mode(0o600))?;
        }
        temporary.sync_all()?;
        replace_relative_file(&state.dir, &temporary_name, OsStr::new(name), temporary)?;
        sync_cap_directory(&state.dir)
    })();
    if let Err(error) = result {
        let _ = state.dir.remove_file(&temporary_name);
        return Err(LpmError::Io(error));
    }
    let file = open_private_state_file(state, name)?.ok_or_else(|| {
        LpmError::Script(format!(
            "release transaction state disappeared after replacement: {}",
            state.display.join(name).display()
        ))
    })?;
    validate_private_journal_file(&file, &state.display.join(name))
}

#[cfg(unix)]
pub(in crate::release_plan) fn validate_lpm_state_parent(
    directory: &cap_std::fs::Dir,
    display: &Path,
) -> Result<(), LpmError> {
    use cap_std::fs::MetadataExt as _;

    let metadata = directory.dir_metadata().map_err(LpmError::Io)?;
    let effective_uid = unsafe {
        // SAFETY: geteuid has no preconditions and does not dereference pointers.
        libc::geteuid()
    };
    if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
        return Err(LpmError::Script(format!(
            "LPM state directory must be owned by the current user and not group/world writable: {}",
            display.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
pub(in crate::release_plan) fn validate_lpm_state_parent(
    directory: &cap_std::fs::Dir,
    display: &Path,
) -> Result<(), LpmError> {
    protect_private_windows_directory(directory, display)
}

#[cfg(not(any(unix, windows)))]
pub(in crate::release_plan) fn validate_lpm_state_parent(
    _directory: &cap_std::fs::Dir,
    _display: &Path,
) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(unix)]
pub(in crate::release_plan) fn validate_private_unix_metadata(
    path: &Path,
    metadata: &cap_std::fs::Metadata,
    directory: bool,
) -> Result<(), LpmError> {
    use cap_std::fs::MetadataExt as _;

    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    let expected_mode = if directory { 0o700 } else { 0o600 };
    if metadata.uid() != effective_uid || metadata.mode() & 0o777 != expected_mode {
        return Err(LpmError::Script(format!(
            "release transaction state must be owned by the current user with mode {expected_mode:o}: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
pub(in crate::release_plan) fn protect_private_windows_directory(
    directory: &cap_std::fs::Dir,
    display: &Path,
) -> Result<(), LpmError> {
    use cap_std::fs::MetadataExt as _;
    use cap_std::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        READ_CONTROL, WRITE_DAC,
    };

    let mut options = cap_std::fs::OpenOptions::new();
    options
        .access_mode(READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let control = directory.open_with(".", &options).map_err(LpmError::Io)?;
    let metadata = control.metadata().map_err(LpmError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
        return Err(LpmError::Script(format!(
            "release transaction state is linked or has the wrong file type: {}",
            display.display()
        )));
    }
    apply_owner_only_windows_dacl(control.as_raw_handle().cast(), true).map_err(LpmError::Io)
}

#[cfg(windows)]
pub(in crate::release_plan) fn protect_private_windows_file(
    file: &cap_std::fs::File,
    display: &Path,
) -> Result<(), LpmError> {
    use cap_std::fs::MetadataExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = file.metadata().map_err(LpmError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err(LpmError::Script(format!(
            "release transaction state is linked or has the wrong file type: {}",
            display.display()
        )));
    }
    apply_owner_only_windows_dacl(file.as_raw_handle().cast(), false).map_err(LpmError::Io)
}

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the fallible Windows permission contract"
)]
pub(in crate::release_plan) fn protect_private_windows_directory(
    _directory: &cap_std::fs::Dir,
    _display: &Path,
) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the fallible Windows permission contract"
)]
pub(in crate::release_plan) fn protect_private_windows_file(
    _file: &cap_std::fs::File,
    _display: &Path,
) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(windows)]
pub(in crate::release_plan) fn apply_owner_only_windows_dacl(
    handle: windows_sys::Win32::Foundation::HANDLE,
    directory: bool,
) -> std::io::Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
    use windows_sys::Win32::Foundation::{LocalFree, RtlNtStatusToDosError};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let current_user_sid = current_user_sid_for_owned_windows_handle(handle)?;

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                // SAFETY: the descriptor was allocated by the SDDL conversion function and is
                // released exactly once here.
                let _ = LocalFree(self.0.cast());
            }
        }
    }

    let sddl = owner_only_windows_sddl(&current_user_sid, directory);
    let encoded = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    let converted = unsafe {
        // SAFETY: `encoded` is NUL-terminated and alive for the call. The output pointer starts
        // null and is transferred to `LocalSecurityDescriptor` only after success.
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encoded.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let status = unsafe {
        // SAFETY: `handle` remains open with WRITE_DAC and `descriptor` remains valid for the call.
        NtSetSecurityObject(
            handle,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        let code = unsafe {
            // SAFETY: `status` is the NTSTATUS returned by `NtSetSecurityObject`.
            RtlNtStatusToDosError(status)
        };
        Err(std::io::Error::from_raw_os_error(code as i32))
    }
}

#[cfg(any(windows, test))]
fn windows_owner_matches_current_identity(
    owner_matches_user: bool,
    owner_matches_default: bool,
) -> bool {
    owner_matches_user || owner_matches_default
}

#[cfg(any(windows, test))]
fn owner_only_windows_sddl(current_user_sid: &str, directory: bool) -> String {
    if directory {
        format!("D:P(A;OICI;FA;;;{current_user_sid})(A;OICI;FA;;;SY)")
    } else {
        format!("D:P(A;;FA;;;{current_user_sid})(A;;FA;;;SY)")
    }
}

#[cfg(windows)]
pub(in crate::release_plan) fn current_user_sid_for_owned_windows_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<String> {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_OWNER, TOKEN_QUERY,
        TOKEN_USER, TokenOwner, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                // SAFETY: `GetSecurityInfo` allocated the descriptor and ownership is released
                // exactly once here.
                let _ = LocalFree(self.0.cast());
            }
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                // SAFETY: `OpenProcessToken` returned this owned handle and it is closed once.
                let _ = CloseHandle(self.0);
            }
        }
    }

    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let status = unsafe {
        // SAFETY: output pointers are valid for this synchronous call. The returned owner SID is
        // borrowed from `descriptor`, which stays alive through the comparison below.
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    if owner.is_null() || descriptor.0.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "release transaction state has no owner SID",
        ));
    }

    let mut token: HANDLE = null_mut();
    let opened = unsafe {
        // SAFETY: the pseudo-process handle is valid and `token` receives an owned handle.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
    };
    if opened == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    let user_storage = windows_token_information(
        token.0,
        TokenUser,
        size_of::<TOKEN_USER>(),
        "current-user token did not contain a user SID",
    )?;
    let token_user = unsafe {
        // SAFETY: the successful token query initialized a `TOKEN_USER` at the aligned start of
        // `user_storage`, and the buffer remains alive through the SID comparison.
        &*user_storage.as_ptr().cast::<TOKEN_USER>()
    };
    if token_user.User.Sid.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "current-user token did not contain a user SID",
        ));
    }
    let owner_storage = windows_token_information(
        token.0,
        TokenOwner,
        size_of::<TOKEN_OWNER>(),
        "current-user token did not contain a default owner SID",
    )?;
    let token_owner = unsafe {
        // SAFETY: the successful token query initialized a `TOKEN_OWNER` at the aligned start of
        // `owner_storage`, and the buffer remains alive through the SID comparison.
        &*owner_storage.as_ptr().cast::<TOKEN_OWNER>()
    };
    if token_owner.Owner.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "current-user token did not contain a default owner SID",
        ));
    }
    let owner_matches_user = unsafe {
        // SAFETY: both SIDs are valid and borrow live security descriptor and token buffers.
        EqualSid(owner, token_user.User.Sid)
    } != 0;
    let owner_matches_default = unsafe {
        // SAFETY: both SIDs are valid and borrow live security descriptor and token buffers.
        EqualSid(owner, token_owner.Owner)
    } != 0;
    if !windows_owner_matches_current_identity(owner_matches_user, owner_matches_default) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "release transaction state is not owned by the current user",
        ));
    }
    windows_sid_to_string(token_user.User.Sid)
}

#[cfg(windows)]
fn windows_token_information(
    token: windows_sys::Win32::Foundation::HANDLE,
    class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS,
    minimum_size: usize,
    missing_message: &'static str,
) -> std::io::Result<Vec<usize>> {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError};
    use windows_sys::Win32::Security::GetTokenInformation;

    let mut required = 0u32;
    unsafe {
        // SAFETY: a zero-length probe is documented to set `required` to the buffer size.
        let _ = GetTokenInformation(token, class, null_mut(), 0, &mut required);
    }
    if (required as usize) < minimum_size {
        let code = unsafe {
            // SAFETY: reads the calling thread's last-error value after the failed size probe.
            GetLastError()
        };
        return Err(if code == ERROR_SUCCESS {
            std::io::Error::new(std::io::ErrorKind::InvalidData, missing_message)
        } else {
            std::io::Error::from_raw_os_error(code as i32)
        });
    }
    let storage_words = (required as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; storage_words];
    let loaded = unsafe {
        // SAFETY: `storage` is aligned and at least `required` bytes long; `required` is updated
        // only with the number of bytes written.
        GetTokenInformation(
            token,
            class,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    if loaded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(storage)
}

#[cfg(windows)]
fn windows_sid_to_string(sid: windows_sys::Win32::Security::PSID) -> std::io::Result<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    struct LocalSidString(windows_sys::core::PWSTR);

    impl Drop for LocalSidString {
        fn drop(&mut self) {
            unsafe {
                // SAFETY: the string was allocated by `ConvertSidToStringSidW` and is released
                // exactly once here.
                let _ = LocalFree(self.0.cast());
            }
        }
    }

    let mut encoded = null_mut();
    let converted = unsafe {
        // SAFETY: `sid` borrows a live token buffer and `encoded` receives an owned string.
        ConvertSidToStringSidW(sid, &mut encoded)
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let encoded = LocalSidString(encoded);
    let mut length = 0usize;
    while length <= 256 {
        let unit = unsafe {
            // SAFETY: the API returned a NUL-terminated SID string. The documented SID string
            // format is far shorter than the defensive 256-code-unit limit.
            *encoded.0.add(length)
        };
        if unit == 0 {
            let units = unsafe {
                // SAFETY: the scan above found the terminator within the allocated string.
                std::slice::from_raw_parts(encoded.0, length)
            };
            return String::from_utf16(units).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("current-user SID is not valid UTF-16: {error}"),
                )
            });
        }
        length += 1;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "current-user SID string exceeds the expected length",
    ))
}

#[cfg(not(unix))]
pub(in crate::release_plan) fn validate_private_unix_metadata(
    _path: &Path,
    _metadata: &cap_std::fs::Metadata,
    _directory: bool,
) -> Result<(), LpmError> {
    Ok(())
}

pub(in crate::release_plan) fn planned_manifest_relative_path(
    canonical_root: &Path,
    manifest_path: &Path,
) -> Result<PathBuf, LpmError> {
    let file_name = manifest_path.file_name().ok_or_else(|| {
        LpmError::Script(format!(
            "manifest path has no file name: {}",
            manifest_path.display()
        ))
    })?;
    let parent = manifest_path.parent().ok_or_else(|| {
        LpmError::Script(format!(
            "manifest path has no parent: {}",
            manifest_path.display()
        ))
    })?;
    let canonical_parent = parent.canonicalize().map_err(LpmError::Io)?;
    if !canonical_parent.starts_with(canonical_root) {
        return Err(LpmError::Script(format!(
            "release manifest escapes the workspace: {}",
            manifest_path.display()
        )));
    }
    ensure_real_directory_chain(canonical_root, &canonical_parent)?;
    let target = canonical_parent.join(file_name);
    ensure_regular_file(&target)?;
    let relative = target.strip_prefix(canonical_root).map_err(|_| {
        LpmError::Script(format!(
            "release manifest escapes the workspace: {}",
            manifest_path.display()
        ))
    })?;
    validate_relative_path(relative)?;
    Ok(relative.to_path_buf())
}

pub(in crate::release_plan) fn recovery_manifest_target(
    root_dir: &cap_std::fs::Dir,
    canonical_root: &Path,
    relative: &Path,
) -> Result<ManifestTarget, LpmError> {
    validate_relative_path(relative)?;
    open_manifest_target(root_dir, canonical_root, relative)
}

pub(in crate::release_plan) fn open_manifest_target(
    root_dir: &cap_std::fs::Dir,
    canonical_root: &Path,
    relative: &Path,
) -> Result<ManifestTarget, LpmError> {
    use cap_fs_ext::DirExt as _;

    validate_relative_path(relative)?;
    let file_name = relative.file_name().ok_or_else(|| {
        LpmError::Script(format!(
            "release manifest path has no file name: {}",
            relative.display()
        ))
    })?;
    let mut parent = root_dir.try_clone().map_err(LpmError::Io)?;
    if let Some(relative_parent) = relative.parent() {
        for component in relative_parent.components() {
            let std::path::Component::Normal(component) = component else {
                return Err(LpmError::Script(format!(
                    "release manifest parent contains an unsafe component: {}",
                    relative.display()
                )));
            };
            parent = parent.open_dir_nofollow(component).map_err(|error| {
                LpmError::Script(format!(
                    "release manifest parent changed or is linked at {}: {error}",
                    canonical_root.join(relative_parent).display()
                ))
            })?;
        }
    }
    let target = ManifestTarget {
        parent,
        file_name: file_name.to_os_string(),
        display: canonical_root.join(relative),
    };
    let _ = open_regular_manifest_file(&target)?;
    Ok(target)
}

pub(in crate::release_plan) fn ensure_regular_file(path: &Path) -> Result<(), LpmError> {
    let metadata = std::fs::symlink_metadata(path).map_err(LpmError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LpmError::Script(format!(
            "release manifest is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(in crate::release_plan) fn open_regular_manifest_file(
    target: &ManifestTarget,
) -> Result<cap_std::fs::File, LpmError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = target
        .parent
        .open_with(&target.file_name, &options)
        .map_err(LpmError::Io)?;
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(LpmError::Script(format!(
            "release manifest is not a regular file: {}",
            target.display.display()
        )));
    }
    Ok(file)
}

pub(in crate::release_plan) fn read_manifest_target(
    target: &ManifestTarget,
) -> Result<Vec<u8>, LpmError> {
    let mut file = open_regular_manifest_file(target)?;
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if metadata.len() > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Script(format!(
            "release manifest exceeds the {} byte limit: {}",
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            target.display.display()
        )));
    }
    let capacity = usize::try_from(metadata.len()).unwrap_or_default();
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(LpmError::Io)?;
    if bytes.len() as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Script(format!(
            "release manifest exceeds the {} byte limit: {}",
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            target.display.display()
        )));
    }
    Ok(bytes)
}

pub(in crate::release_plan) fn ensure_real_directory_chain(
    canonical_root: &Path,
    directory: &Path,
) -> Result<(), LpmError> {
    let relative = directory.strip_prefix(canonical_root).map_err(|_| {
        LpmError::Script(format!(
            "release manifest parent escapes the workspace: {}",
            directory.display()
        ))
    })?;
    let mut current = canonical_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(LpmError::Script(format!(
                "release manifest parent contains an unsafe component: {}",
                directory.display()
            )));
        };
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current).map_err(LpmError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LpmError::Script(format!(
                "release manifest parent is not a real directory: {}",
                current.display()
            )));
        }
    }
    Ok(())
}

pub(in crate::release_plan) fn validate_relative_path(path: &Path) -> Result<(), LpmError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(LpmError::Script(format!(
            "release journal contains an unsafe relative path: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(in crate::release_plan) fn write_manifest_target_durable(
    target: &ManifestTarget,
    bytes: &[u8],
) -> std::io::Result<()> {
    write_relative_file_durable(&target.parent, &target.file_name, bytes)
}

pub(in crate::release_plan) fn write_relative_file_durable(
    parent: &cap_std::fs::Dir,
    file_name: &OsStr,
    bytes: &[u8],
) -> std::io::Result<()> {
    let exact_mode = relative_file_mode(parent, file_name)?;
    let (temporary_name, mut temporary) = create_manifest_temporary(parent, exact_mode)?;
    let result = (|| {
        temporary.write_all(bytes)?;
        #[cfg(unix)]
        if let Some(mode) = exact_mode {
            use cap_std::fs::PermissionsExt as _;
            temporary.set_permissions(cap_std::fs::Permissions::from_mode(mode))?;
        }
        temporary.sync_all()?;
        replace_relative_file(parent, &temporary_name, file_name, temporary)?;
        sync_cap_directory(parent)
    })();
    if result.is_err() {
        let _ = parent.remove_file(&temporary_name);
    }
    result
}

fn relative_file_mode(
    parent: &cap_std::fs::Dir,
    file_name: &OsStr,
) -> std::io::Result<Option<u32>> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;

        let metadata = parent.symlink_metadata(file_name)?;
        Ok(metadata
            .is_file()
            .then(|| metadata.permissions().mode() & 0o7777))
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, file_name);
        Ok(None)
    }
}

pub(in crate::release_plan) fn create_manifest_temporary(
    parent: &cap_std::fs::Dir,
    exact_mode: Option<u32>,
) -> std::io::Result<(OsString, cap_std::fs::File)> {
    use base64::Engine as _;
    use rand::RngCore as _;

    let mut last_collision = None;
    for _ in 0..32 {
        let mut random = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut random);
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
            use windows_sys::Win32::Storage::FileSystem::DELETE;

            let _ = exact_mode;
            options.access_mode(GENERIC_READ | GENERIC_WRITE | DELETE);
        }
        #[cfg(not(any(unix, windows)))]
        let _ = exact_mode;
        match parent.open_with(&name, &options) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate an exclusive release manifest temporary file",
        )
    }))
}

#[cfg(not(windows))]
pub(in crate::release_plan) fn replace_relative_file(
    parent: &cap_std::fs::Dir,
    temporary_name: &OsStr,
    destination: &OsStr,
    temporary: cap_std::fs::File,
) -> std::io::Result<()> {
    let _temporary = temporary;
    parent.rename(temporary_name, parent, destination)
}

#[cfg(windows)]
pub(in crate::release_plan) fn replace_relative_file(
    parent: &cap_std::fs::Dir,
    _temporary_name: &OsStr,
    destination: &OsStr,
    temporary: cap_std::fs::File,
) -> std::io::Result<()> {
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
        .ok_or_else(|| std::io::Error::other("release manifest filename is too long"))?;
    let info_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(file_name_bytes)
        .ok_or_else(|| std::io::Error::other("release manifest rename data is too large"))?;
    let mut storage = vec![0usize; info_bytes.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let info_bytes = u32::try_from(info_bytes)
        .map_err(|_| std::io::Error::other("release manifest rename data is too large"))?;
    let file_name_bytes = u32::try_from(file_name_bytes)
        .map_err(|_| std::io::Error::other("release manifest filename is too long"))?;
    unsafe {
        // SAFETY: storage is aligned and sized for the variable-length rename record. Both
        // handles remain open for each synchronous call, and the UTF-16 filename is copied in full.
        (*info).Anonymous.ReplaceIfExists = true;
        (*info).RootDirectory = parent.as_raw_handle();
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
            return temporary.sync_all();
        }
        let code = unsafe {
            // SAFETY: `status` is the NTSTATUS returned by `NtSetInformationFile`.
            RtlNtStatusToDosError(status)
        };
        let error = std::io::Error::from_raw_os_error(code as i32);
        if !matches!(code, ERROR_SHARING_VIOLATION | ERROR_ACCESS_DENIED) || delay_ms == 4_050 {
            return Err(error);
        }
    }
    Err(std::io::Error::other(
        "release manifest replacement retry loop exhausted",
    ))
}

pub(in crate::release_plan) fn sync_cap_directory(dir: &cap_std::fs::Dir) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let _ = dir;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        let sync_handle = {
            use std::os::fd::{AsRawFd as _, FromRawFd as _};

            let descriptor = unsafe {
                // SAFETY: `dir` stays open, the relative C string is static, and ownership of a
                // successful descriptor is transferred to `File` exactly once.
                libc::openat(
                    dir.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe {
                // SAFETY: `descriptor` is a newly owned descriptor returned by `openat`.
                std::fs::File::from_raw_fd(descriptor)
            }
        };
        #[cfg(not(target_os = "linux"))]
        let sync_handle = dir.try_clone()?.into_std_file();
        sync_handle.sync_all()
    }
}

pub(in crate::release_plan) fn open_root_directory_nofollow(
    path: &Path,
) -> Result<cap_std::fs::Dir, LpmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        );
        options
            .open(path)
            .map(cap_std::fs::Dir::from_std_file)
            .map_err(LpmError::Io)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(LpmError::Io)?;
        let metadata = file.metadata().map_err(LpmError::Io)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LpmError::Script(format!(
                "release workspace root is linked or not a directory: {}",
                path.display()
            )));
        }
        Ok(cap_std::fs::Dir::from_std_file(file))
    }
    #[cfg(not(any(unix, windows)))]
    cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority()).map_err(LpmError::Io)
}

#[cfg(not(windows))]
pub(in crate::release_plan) fn metadata_is_link_or_reparse(
    metadata: &cap_std::fs::Metadata,
) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
pub(in crate::release_plan) fn metadata_is_link_or_reparse(
    metadata: &cap_std::fs::Metadata,
) -> bool {
    use cap_std::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
pub(in crate::release_plan) fn write_manifest_durable(
    path: &Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    lpm_common::write_file_atomic_with_options(
        path,
        bytes,
        lpm_common::AtomicWriteOptions::new()
            .sync_file()
            .sync_parent(),
    )
}

#[cfg(feature = "internal-test-sigstore-mock")]
pub(in crate::release_plan) fn abort_after_manifest_write_for_test(write_count: usize) {
    if std::env::var("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_MANIFEST_WRITES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        == Some(write_count)
    {
        std::process::abort();
    }
}

#[cfg(not(feature = "internal-test-sigstore-mock"))]
pub(in crate::release_plan) fn abort_after_manifest_write_for_test(_write_count: usize) {}

#[cfg(feature = "internal-test-sigstore-mock")]
pub(in crate::release_plan) fn abort_after_release_commit_for_test() {
    if std::env::var_os("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_COMMIT").is_some() {
        std::process::abort();
    }
}

#[cfg(not(feature = "internal-test-sigstore-mock"))]
pub(in crate::release_plan) fn abort_after_release_commit_for_test() {}

pub(in crate::release_plan) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;

    hex::encode(sha2::Sha256::digest(bytes))
}

pub(in crate::release_plan) fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
pub(in crate::release_plan) fn release_path_encoding() -> &'static str {
    "unix-bytes-v1"
}

#[cfg(windows)]
pub(in crate::release_plan) fn release_path_encoding() -> &'static str {
    "windows-utf16le-v1"
}

#[cfg(not(any(unix, windows)))]
pub(in crate::release_plan) fn release_path_encoding() -> &'static str {
    "utf8-v1"
}

pub(in crate::release_plan) fn encode_relative_path(path: &Path) -> Result<String, LpmError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    };
    #[cfg(windows)]
    let bytes = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    };
    #[cfg(not(any(unix, windows)))]
    let bytes = path
        .to_str()
        .ok_or_else(|| LpmError::Script("release manifest path is not UTF-8".into()))?
        .as_bytes()
        .to_vec();

    if bytes.len() > MAX_RELEASE_PATH_BYTES {
        return Err(LpmError::Script(
            "release manifest path exceeds the journal path limit".into(),
        ));
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(in crate::release_plan) fn decode_relative_path(encoded: &str) -> Result<PathBuf, LpmError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    if encoded.len() > MAX_RELEASE_PATH_BYTES.div_ceil(3) * 4 {
        return Err(LpmError::Script(
            "release journal path exceeds the encoded path limit".into(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        LpmError::Script(format!("release journal path is not valid base64: {error}"))
    })?;
    if bytes.len() > MAX_RELEASE_PATH_BYTES {
        return Err(LpmError::Script(
            "release journal path exceeds the decoded path limit".into(),
        ));
    }

    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(OsString::from_vec(bytes))
    };
    #[cfg(windows)]
    let path = {
        use std::os::windows::ffi::OsStringExt;
        if bytes.len() % 2 != 0 {
            return Err(LpmError::Script(
                "release journal contains malformed UTF-16 path bytes".into(),
            ));
        }
        let wide = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        PathBuf::from(OsString::from_wide(&wide))
    };
    #[cfg(not(any(unix, windows)))]
    let path = PathBuf::from(String::from_utf8(bytes).map_err(|error| {
        LpmError::Script(format!("release journal path is not valid UTF-8: {error}"))
    })?);

    validate_relative_path(&path)?;
    Ok(path)
}

#[cfg(unix)]
pub(in crate::release_plan) fn create_private_cap_directory(
    parent: &cap_std::fs::Dir,
    name: &str,
) -> std::io::Result<()> {
    use cap_std::fs::DirBuilderExt as _;

    let mut builder = cap_std::fs::DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)
}

#[cfg(not(unix))]
pub(in crate::release_plan) fn create_private_cap_directory(
    parent: &cap_std::fs::Dir,
    name: &str,
) -> std::io::Result<()> {
    parent.create_dir(name)
}

#[cfg(test)]
mod windows_owner_policy_tests {
    use super::{owner_only_windows_sddl, windows_owner_matches_current_identity};

    #[test]
    fn process_default_owner_identifies_current_windows_identity() {
        assert!(windows_owner_matches_current_identity(false, true));
    }

    #[test]
    fn unrelated_owner_is_not_current_windows_identity() {
        assert!(!windows_owner_matches_current_identity(false, false));
    }

    #[test]
    fn directory_dacl_grants_only_current_user_and_system() {
        assert_eq!(
            owner_only_windows_sddl("S-1-5-21-1000", true),
            "D:P(A;OICI;FA;;;S-1-5-21-1000)(A;OICI;FA;;;SY)"
        );
    }

    #[test]
    fn file_dacl_grants_only_current_user_and_system() {
        assert_eq!(
            owner_only_windows_sddl("S-1-5-21-1000", false),
            "D:P(A;;FA;;;S-1-5-21-1000)(A;;FA;;;SY)"
        );
    }
}
