use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid,
    GetSecurityDescriptorDacl, GetTokenInformation, IsValidAcl, IsValidSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86, SHGetFolderPathW,
};

const WRITE_MASK: u32 = 0x1000_0000
    | 0x4000_0000
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;

struct LocalAlloc(*mut c_void);

impl Drop for LocalAlloc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this pointer came from a Windows API that transfers LocalAlloc ownership.
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `OpenProcessToken` returned this owned handle and it is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub(super) struct InstallationLock {
    handle: OwnedHandle,
}

impl Drop for InstallationLock {
    fn drop(&mut self) {
        // SAFETY: this thread owns the mutex after a successful zero-time wait.
        unsafe {
            let _ = ReleaseMutex(self.handle.0);
        }
    }
}

struct SecurityContext {
    user_storage: Vec<usize>,
    system: LocalAlloc,
    administrators: LocalAlloc,
    trusted_installer: LocalAlloc,
    creator_owner: LocalAlloc,
}

impl SecurityContext {
    fn load() -> Option<Self> {
        Some(Self {
            user_storage: current_user_token()?,
            system: sid_from_sddl("S-1-5-18")?,
            administrators: sid_from_sddl("S-1-5-32-544")?,
            trusted_installer: sid_from_sddl(
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            )?,
            creator_owner: sid_from_sddl("S-1-3-0")?,
        })
    }

    fn current_user(&self) -> PSID {
        let token_user = self.user_storage.as_ptr().cast::<TOKEN_USER>();
        // SAFETY: `current_user_token` returned aligned storage initialized as `TOKEN_USER`.
        unsafe { (*token_user).User.Sid }
    }

    fn owner_is_trusted(&self, sid: PSID) -> bool {
        self.matches(sid, false)
    }

    fn write_principal_is_trusted(&self, sid: PSID, owner: PSID) -> bool {
        // SAFETY: both SIDs borrow live security descriptors or token storage.
        (unsafe { EqualSid(sid, owner) != 0 }) || self.matches(sid, true)
    }

    fn matches(&self, sid: PSID, include_creator_owner: bool) -> bool {
        if sid.is_null() {
            return false;
        }
        let candidates = [
            self.current_user(),
            self.system.0.cast(),
            self.administrators.0.cast(),
            self.trusted_installer.0.cast(),
            self.creator_owner.0.cast(),
        ];
        candidates
            .into_iter()
            .enumerate()
            .filter(|(index, _)| include_creator_owner || *index != candidates.len() - 1)
            // SAFETY: every candidate SID owns live backing storage in `self`.
            .any(|(_, candidate)| unsafe { EqualSid(sid, candidate) != 0 })
    }
}

pub(super) fn path_is_private_to_account(path: &Path, account_home: &Path) -> bool {
    path_chain_has_private_dacl(path, account_home)
}

pub(super) fn path_is_trusted_system_install(path: &Path) -> bool {
    system_roots()
        .into_iter()
        .any(|root| path_chain_has_private_dacl(path, &root))
}

pub(super) fn path_is_trusted_install_location(path: &Path, account_home: &Path) -> bool {
    path_is_private_to_account(path, account_home) || path_is_trusted_system_install(path)
}

pub(super) fn try_acquire_installation_lock(
    executable: &Path,
) -> std::io::Result<Option<InstallationLock>> {
    let name = installation_mutex_name(executable);
    // SAFETY: the name is NUL-terminated and the returned handle is owned.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let handle = OwnedHandle(handle);
    // SAFETY: `handle` is a live mutex handle and zero requests a non-blocking wait.
    match unsafe { WaitForSingleObject(handle.0, 0) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Some(InstallationLock { handle })),
        WAIT_TIMEOUT => Ok(None),
        WAIT_FAILED => Err(std::io::Error::last_os_error()),
        result => Err(std::io::Error::other(format!(
            "unexpected Windows mutex wait result {result}"
        ))),
    }
}

fn installation_mutex_name(executable: &Path) -> Vec<u16> {
    let normalized = executable.to_string_lossy().to_lowercase();
    let digest = Sha256::digest(normalized.as_bytes());
    format!(
        "Global\\dev.lpm.self-update.installation.{}",
        hex::encode(digest)
    )
    .encode_utf16()
    .chain(Some(0))
    .collect()
}

pub(super) fn path_has_trusted_dacl_to_root(path: &Path) -> bool {
    let Ok(path) = std::fs::canonicalize(path) else {
        return false;
    };
    let Some(context) = SecurityContext::load() else {
        return false;
    };
    path.ancestors()
        .all(|ancestor| path_entry_has_private_dacl(ancestor, &context))
}

fn path_chain_has_private_dacl(path: &Path, root: &Path) -> bool {
    let Ok(path) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(root) = std::fs::canonicalize(root) else {
        return false;
    };
    if !path_starts_with(&path, &root) {
        return false;
    }
    let Some(context) = SecurityContext::load() else {
        return false;
    };
    for ancestor in path.ancestors() {
        if !path_entry_has_private_dacl(ancestor, &context) {
            return false;
        }
        if paths_equal(ancestor, &root) {
            return true;
        }
    }
    false
}

fn path_entry_has_private_dacl(path: &Path, context: &SecurityContext) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return false;
    }

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the UTF-16 path is terminated and every output pointer is valid for the call.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() {
        if !descriptor.is_null() {
            // SAFETY: `GetNamedSecurityInfoW` allocated this non-null descriptor.
            unsafe {
                let _ = LocalFree(descriptor.cast());
            }
        }
        return false;
    }
    // SAFETY: the successful security-descriptor query returned an owner SID
    // backed by the live descriptor allocation.
    if unsafe { IsValidSid(owner) } == 0 || !context.owner_is_trusted(owner) {
        // SAFETY: `GetNamedSecurityInfoW` allocated this non-null descriptor.
        unsafe {
            let _ = LocalFree(descriptor.cast());
        }
        return false;
    }
    let descriptor_guard = LocalAlloc(descriptor.cast());
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    // SAFETY: the descriptor guard is live and all output pointers are writable.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor_guard.0.cast(),
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return false;
    }

    // SAFETY: the successful descriptor query returned a non-null DACL.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return false;
    }
    // SAFETY: `IsValidAcl` accepted the non-null DACL.
    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..ace_count {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: `index` is below `AceCount` and `ace` is a writable output pointer.
        if unsafe { GetAce(dacl, u32::from(index), &mut ace) } == 0 || ace.is_null() {
            return false;
        }
        // SAFETY: a successful `GetAce` returns an ACE beginning with `ACE_HEADER`.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if !matches!(
            header.AceType,
            ACCESS_ALLOWED_ACE_TYPE
                | ACCESS_ALLOWED_COMPOUND_ACE_TYPE
                | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        ) {
            continue;
        }
        let ace_size = usize::from(header.AceSize);
        if ace_size < size_of::<ACE_HEADER>() {
            return false;
        }
        // SAFETY: `GetAce` returned this ACE from an ACL accepted by `IsValidAcl`,
        // and `AceSize` describes the byte range owned by the ACE.
        let ace_bytes =
            unsafe { std::slice::from_raw_parts(ace.cast::<u8>().cast_const(), ace_size) };
        let sid_offset = match allowed_write_sid_offset(header.AceType, ace_bytes) {
            Ok(None) => continue,
            Ok(Some(offset)) => offset,
            Err(()) => return false,
        };
        // SAFETY: `allowed_write_sid_offset` validated the complete SID byte
        // range before returning its in-slice offset.
        let sid = unsafe { ace.cast::<u8>().add(sid_offset).cast::<c_void>() as PSID };
        // SAFETY: the SID byte range is within the live ACE allocation.
        if unsafe { IsValidSid(sid) } == 0 {
            return false;
        }
        // SAFETY: `IsValidSid` accepted the SID.
        let sid_length = unsafe { GetLengthSid(sid) } as usize;
        if sid_length > ace_size.saturating_sub(sid_offset) {
            return false;
        }
        if !context.write_principal_is_trusted(sid, owner) {
            return false;
        }
    }
    true
}

fn allowed_write_sid_offset(ace_type: u8, ace: &[u8]) -> Result<Option<usize>, ()> {
    let mask_offset = size_of::<ACE_HEADER>();
    let sid_offset = mask_offset.checked_add(size_of::<u32>()).ok_or(())?;
    let mask_bytes: [u8; size_of::<u32>()] = ace
        .get(mask_offset..sid_offset)
        .ok_or(())?
        .try_into()
        .map_err(|_| ())?;
    if u32::from_le_bytes(mask_bytes) & WRITE_MASK == 0 {
        return Ok(None);
    }
    if matches!(
        ace_type,
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    ) {
        return Err(());
    }
    if !matches!(
        ace_type,
        ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
    ) {
        return Err(());
    }

    const SID_HEADER_SIZE: usize = 8;
    let sid_header_end = sid_offset.checked_add(SID_HEADER_SIZE).ok_or(())?;
    let sid_header = ace.get(sid_offset..sid_header_end).ok_or(())?;
    let sub_authorities = usize::from(sid_header[1]);
    let sid_size = SID_HEADER_SIZE
        .checked_add(sub_authorities.checked_mul(size_of::<u32>()).ok_or(())?)
        .ok_or(())?;
    let sid_end = sid_offset.checked_add(sid_size).ok_or(())?;
    if sid_end > ace.len() {
        return Err(());
    }
    Ok(Some(sid_offset))
}

fn current_user_token() -> Option<Vec<usize>> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` is a writable output pointer for the current process token.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = OwnedHandle(token);
    let mut required = 0;
    // SAFETY: a zero-length probe records the required buffer length in `required`.
    unsafe {
        let _ = GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut required);
    }
    if required < size_of::<TOKEN_USER>() as u32 {
        return None;
    }
    let mut storage = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
    // SAFETY: `storage` is aligned and contains at least `required` writable bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return None;
    }
    Some(storage)
}

fn sid_from_sddl(value: &str) -> Option<LocalAlloc> {
    let wide = value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: the SDDL string is terminated and `sid` is a writable output pointer.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return None;
    }
    Some(LocalAlloc(sid.cast()))
}

fn system_roots() -> Vec<PathBuf> {
    let mut roots = [CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86]
        .into_iter()
        .filter_map(windows_known_folder)
        .collect::<Vec<_>>();
    if let Some(windows_directory) = windows_directory() {
        roots.push(windows_directory);
    }
    roots.sort_unstable();
    roots.dedup();
    roots
}

fn windows_directory() -> Option<PathBuf> {
    let mut buffer = vec![0_u16; 260];
    loop {
        let buffer_len = u32::try_from(buffer.len()).ok()?;
        // SAFETY: the buffer is writable for `buffer_len` UTF-16 code units
        // and remains live for the synchronous API call.
        let written = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer_len) } as usize;
        if written == 0 {
            return None;
        }
        if written < buffer.len() {
            buffer.truncate(written);
            return Some(PathBuf::from(std::ffi::OsString::from_wide(&buffer)));
        }
        buffer.resize(written.saturating_add(1), 0);
    }
}

fn windows_known_folder(csidl: u32) -> Option<PathBuf> {
    let mut buffer = [0_u16; 260];
    // SAFETY: the buffer satisfies the API's MAX_PATH output contract.
    let result = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            csidl as i32,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    if result < 0 {
        return None;
    }
    let length = buffer.iter().position(|value| *value == 0)?;
    Some(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length],
    )))
}

fn path_starts_with(path: &Path, root: &Path) -> bool {
    let mut path_components = path.components();
    root.components().all(|root_component| {
        path_components.next().is_some_and(|path_component| {
            path_component
                .as_os_str()
                .eq_ignore_ascii_case(root_component.as_os_str())
        })
    })
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.as_os_str().eq_ignore_ascii_case(right.as_os_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_systemroot_helper() {
        let Some(hostile_root) = std::env::var_os("LPM_TEST_HOSTILE_SYSTEMROOT") else {
            return;
        };
        let hostile_root = PathBuf::from(hostile_root);

        assert!(
            !system_roots()
                .iter()
                .any(|root| paths_equal(root, &hostile_root))
        );
    }

    #[test]
    fn hostile_systemroot_does_not_expand_trusted_install_roots() {
        let hostile_root = tempfile::tempdir().unwrap();
        let helper = format!("{}::hostile_systemroot_helper", module_path!());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &helper, "--nocapture"])
            .env("SYSTEMROOT", hostile_root.path())
            .env("LPM_TEST_HOSTILE_SYSTEMROOT", hostile_root.path())
            .status()
            .unwrap();

        assert!(status.success());
    }

    #[test]
    fn truncated_write_ace_is_rejected() {
        let mut ace = vec![0_u8; size_of::<ACE_HEADER>() + size_of::<u32>()];
        ace[0] = ACCESS_ALLOWED_ACE_TYPE;
        ace[size_of::<ACE_HEADER>()..][..size_of::<u32>()]
            .copy_from_slice(&WRITE_MASK.to_le_bytes());

        assert!(allowed_write_sid_offset(ACCESS_ALLOWED_ACE_TYPE, &ace).is_err());
    }

    #[test]
    fn compound_write_ace_is_rejected() {
        let mut ace = vec![0_u8; size_of::<ACE_HEADER>() + size_of::<u32>() + 12];
        ace[0] = ACCESS_ALLOWED_COMPOUND_ACE_TYPE;
        ace[size_of::<ACE_HEADER>()..][..size_of::<u32>()]
            .copy_from_slice(&WRITE_MASK.to_le_bytes());

        assert!(allowed_write_sid_offset(ACCESS_ALLOWED_COMPOUND_ACE_TYPE, &ace).is_err());
    }

    #[test]
    fn installation_mutex_name_is_case_insensitive() {
        assert_eq!(
            installation_mutex_name(Path::new(r"C:\Program Files\LPM\lpm.exe")),
            installation_mutex_name(Path::new(r"c:\program files\lpm\LPM.EXE"))
        );
    }

    #[test]
    fn installation_mutex_serializes_the_same_path_between_threads() {
        let path = PathBuf::from(format!(
            r"C:\Program Files\LPM\test-{}\lpm.exe",
            std::process::id()
        ));
        let thread_path = path.clone();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let lock = try_acquire_installation_lock(&thread_path)
                .unwrap()
                .expect("first installation lock");
            acquired_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(lock);
        });
        acquired_rx.recv().unwrap();

        assert!(try_acquire_installation_lock(&path).unwrap().is_none());

        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(try_acquire_installation_lock(&path).unwrap().is_some());
    }

    #[test]
    fn private_account_file_is_trusted() {
        let account = tempfile::tempdir().unwrap();
        let file = account.path().join("manager.exe");
        std::fs::write(&file, b"").unwrap();

        assert!(path_is_private_to_account(&file, account.path()));
    }

    #[test]
    fn account_file_writable_by_everyone_is_rejected() {
        let account = tempfile::tempdir().unwrap();
        let file = account.path().join("manager.exe");
        std::fs::write(&file, b"").unwrap();
        let status = std::process::Command::new("icacls")
            .arg(&file)
            .args(["/grant", "*S-1-1-0:F"])
            .status()
            .unwrap();
        assert!(status.success());

        assert!(!path_is_private_to_account(&file, account.path()));
    }
}
