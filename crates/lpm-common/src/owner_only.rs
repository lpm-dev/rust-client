//! Owner-only access for files that hold secrets on Windows, where a mode
//! of 0600 has no effect: the file's DACL grants full access to its owner,
//! to the user LPM runs as and to SYSTEM, and inherits nothing.
//!
//! The user is named as well as the owner because an elevated terminal
//! makes the Administrators the owner of what it creates. In the same
//! user's terminal afterwards, unelevated, the Administrators group is
//! there only to deny, so the owner's entry would let nobody in.

#![cfg(windows)]

use std::ptr::null_mut;

use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree, RtlNtStatusToDosError,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinBuiltinAnyPackageSid,
    WinCreatorOwnerRightsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The DACL of an owner-only file: full control for the owner, the user
/// LPM runs as and SYSTEM.
pub fn owner_only_file_dacl() -> std::io::Result<String> {
    let user = process_user_sid()?;
    Ok(format!("D:P(A;;FA;;;OW)(A;;FA;;;{user})(A;;FA;;;SY)"))
}

/// The DACL of an owner-only directory: full control for the owner, the
/// user LPM runs as and SYSTEM, which what is created in it inherits.
pub fn owner_only_directory_dacl() -> std::io::Result<String> {
    let user = process_user_sid()?;
    Ok(format!(
        "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"
    ))
}

/// The DACL of LPM's state directories, a project's `.lpm` and the LPM
/// home: [`owner_only_directory_dacl`]'s, and for ALL APPLICATION PACKAGES
/// the directory's attributes and passage through it, not its listing,
/// which a sandboxed lifecycle script needs to reach the access it was
/// granted below.
fn state_directory_dacl() -> std::io::Result<String> {
    Ok(format!("{}(A;;0xa0;;;AC)", owner_only_directory_dacl()?))
}

/// The SID of the user LPM runs as, as SDDL writes it. It is the same
/// whether or not the token is elevated.
pub fn process_user_sid() -> std::io::Result<String> {
    static SID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(sid) = SID.get() {
        return Ok(sid.clone());
    }
    let sid = ProcessUser::query()?.sid_string()?;
    Ok(SID.get_or_init(|| sid).clone())
}

/// What [`state_directory_dacl`] lets application packages do: read the
/// directory's attributes (`FILE_READ_ATTRIBUTES`) and pass through it
/// (`FILE_TRAVERSE`).
const PACKAGE_PASSAGE: u32 = 0xa0;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const INHERIT_ONLY_ACE: u8 = 0x08;

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`
        // and released once here.
        unsafe {
            let _ = LocalFree(self.0.cast());
        }
    }
}

/// Limits `file` to its owner, the user LPM runs as and SYSTEM. The handle
/// needs `WRITE_DAC`.
pub fn protect_file(file: &impl std::os::windows::io::AsRawHandle) -> std::io::Result<()> {
    set_protected_dacl(file, &owner_only_file_dacl()?)
}

/// Whether `file` is kept from everyone but its owner, the user running
/// LPM, SYSTEM and the Administrators, as [`protect_file`] or a hand-made
/// owner-only DACL keeps it: its DACL inherits nothing and grants no one
/// else access. The handle needs `READ_CONTROL`.
pub fn keeps_others_out(file: &impl std::os::windows::io::AsRawHandle) -> std::io::Result<bool> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: the handle stays open; the outputs receive a LocalFree-owned
    // descriptor and pointers into it.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: the descriptor is valid and both outputs are initialized.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // A missing DACL grants everyone everything.
    if control & SE_DACL_PROTECTED == 0 || dacl.is_null() {
        return Ok(false);
    }
    let user = ProcessUser::query()?;
    // SAFETY: GetSecurityInfo returned a DACL inside the live descriptor.
    let entries = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(entries) {
        let mut ace = null_mut();
        // SAFETY: `index` is below the DACL's entry count.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: every entry starts with an ACE_HEADER.
        let header = unsafe { *ace.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE != 0 || header.AceType == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            return Ok(false);
        }
        // SAFETY: an access-allowed entry holds its SID from `SidStart`.
        let sid: PSID =
            unsafe { std::ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart) }.cast();
        // SAFETY: `sid`, `owner` and the user's SID are valid SIDs.
        let trusted = unsafe {
            (!owner.is_null() && EqualSid(sid, owner) != 0)
                || EqualSid(sid, user.sid()) != 0
                || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
                || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0
        };
        if !trusted {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Keeps the state directory `directory`, a project's `.lpm` or the LPM
/// home, to its owner, the user LPM runs as and SYSTEM, letting sandboxed
/// lifecycle scripts through to what they are granted below, and says
/// whether it changed its DACL. One already kept so, inheriting nothing and
/// letting application packages through, is left alone. With
/// `push_to_contents`, what is already inside it stops inheriting the
/// access it had from the directory above, as in a `.lpm` an earlier
/// release made; without it only what is created there from now on is
/// kept, as for the LPM home, whose store files are hard links in
/// projects' `node_modules`. One kept by an earlier release, which named
/// only the owner, gets the user's entry the same way: a `.lpm` all through,
/// so that its folders hand it on to what is created in them (from review),
/// and the home on its own DACL, as rewriting the store's would touch every
/// file in it. Folders an earlier release made in the home still hand on
/// the owner's entry alone, so what an elevated run creates in them stays
/// the Administrators'.
pub fn protect_state_directory(
    directory: &cap_std::fs::Dir,
    push_to_contents: bool,
) -> std::io::Result<bool> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsMaybeDirExt as _};
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    let mut options = cap_std::fs::OpenOptions::new();
    options
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    let handle = directory.open_with(".", &options)?;
    let dacl = state_directory_dacl()?;
    match state_directory_access(&handle)? {
        StateDirectoryAccess::Kept => return Ok(false),
        StateDirectoryAccess::KeptForTheOwner | StateDirectoryAccess::Open if push_to_contents => {
            set_protected_tree_dacl(&final_path(&handle)?, &dacl)?;
        }
        StateDirectoryAccess::KeptForTheOwner | StateDirectoryAccess::Open => {
            set_protected_dacl(&handle, &dacl)?;
        }
    }
    Ok(true)
}

/// How a state directory's DACL compares with [`state_directory_dacl`]'s.
enum StateDirectoryAccess {
    /// It inherits nothing, lets application packages through, and gives
    /// the user LPM runs as full control of what is created in it.
    Kept,
    /// It inherits nothing and lets application packages through, as an
    /// earlier release kept it, but names only the owner.
    KeptForTheOwner,
    /// Anything else.
    Open,
}

/// The path the open `file` has, as the system resolves it.
fn final_path(
    file: &impl std::os::windows::io::AsRawHandle,
) -> std::io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    let mut buffer = vec![0_u16; 512];
    loop {
        let capacity = u32::try_from(buffer.len()).map_err(std::io::Error::other)?;
        // SAFETY: the handle is valid for the call and `buffer` holds
        // `capacity` writable units.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle().cast(),
                buffer.as_mut_ptr(),
                capacity,
                0,
            )
        } as usize;
        match length {
            0 => return Err(std::io::Error::last_os_error()),
            written if written < buffer.len() => {
                buffer.truncate(written);
                return Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
                    &buffer,
                )));
            }
            needed => buffer.resize(needed, 0),
        }
    }
}

/// How `directory`'s DACL compares with [`state_directory_dacl`]'s.
fn state_directory_access(
    directory: &impl std::os::windows::io::AsRawHandle,
) -> std::io::Result<StateDirectoryAccess> {
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: the handle stays open; the outputs receive a LocalFree-owned
    // descriptor and a pointer into it.
    let status = unsafe {
        GetSecurityInfo(
            directory.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: the descriptor is valid and both outputs are initialized.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 || dacl.is_null() {
        return Ok(StateDirectoryAccess::Open);
    }
    let user = ProcessUser::query()?;
    let (mut packages_pass, mut user_kept) = (false, false);
    // SAFETY: GetSecurityInfo returned a DACL inside the live descriptor.
    let entries = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(entries) {
        let mut ace = null_mut();
        // SAFETY: `index` is below the DACL's entry count.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: every entry starts with an ACE_HEADER.
        let header = unsafe { *ace.cast::<ACE_HEADER>() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE || header.AceFlags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: an access-allowed entry holds its mask and, from
        // `SidStart`, its SID.
        let (mask, sid): (u32, PSID) = unsafe {
            (
                (*allowed).Mask,
                std::ptr::addr_of_mut!((*allowed).SidStart).cast(),
            )
        };
        // SAFETY: `sid` is a valid SID inside the DACL.
        if mask & PACKAGE_PASSAGE == PACKAGE_PASSAGE
            && unsafe { IsWellKnownSid(sid, WinBuiltinAnyPackageSid) } != 0
        {
            packages_pass = true;
        }
        let inherited_by_all = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        // SAFETY: `sid` and the user's SID are valid SIDs.
        if mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
            && header.AceFlags & inherited_by_all == inherited_by_all
            && unsafe { EqualSid(sid, user.sid()) } != 0
        {
            user_kept = true;
        }
    }
    Ok(match (packages_pass, user_kept) {
        (true, true) => StateDirectoryAccess::Kept,
        (true, false) => StateDirectoryAccess::KeptForTheOwner,
        (false, _) => StateDirectoryAccess::Open,
    })
}

/// Sets the DACL of the directory at `path` to `sddl`'s, inheriting
/// nothing, and has what is inside it inherit from it again.
fn set_protected_tree_dacl(path: &std::path::Path, sddl: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Security::GetSecurityDescriptorDacl;

    let encoded = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    // SAFETY: `encoded` is NUL-terminated and `descriptor` receives an allocation.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encoded.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: the descriptor is valid and every output is initialized.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: `wide` is NUL-terminated and the DACL lives in the descriptor
    // through the call, which pushes inheritance through the tree.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(status as i32))
    }
}

/// The user the process runs as, read from its token.
struct ProcessUser(Vec<u64>);

impl ProcessUser {
    fn query() -> std::io::Result<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the pseudo-handle is valid; `token` receives a handle closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut length = 0;
        // SAFETY: a null buffer of length 0 asks for the size needed.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length) };
        // `u64`s keep the SID's pointer in `TOKEN_USER` aligned.
        let mut buffer = vec![0u64; (length as usize).div_ceil(8).max(1)];
        // SAFETY: `buffer` holds at least `length` bytes.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        };
        let error = std::io::Error::last_os_error();
        // SAFETY: `token` is open and closed once here.
        unsafe { CloseHandle(token) };
        if read == 0 {
            return Err(error);
        }
        Ok(Self(buffer))
    }

    fn sid(&self) -> PSID {
        // SAFETY: the buffer holds a TOKEN_USER whose SID points into it.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    /// The user's SID, as SDDL writes it.
    fn sid_string(&self) -> std::io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

        let mut text = null_mut();
        // SAFETY: the SID is valid; `text` receives a LocalFree-owned string.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut text) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `text` is NUL-terminated.
        let length = (0..)
            .take_while(|offset| unsafe { *text.add(*offset) } != 0)
            .count();
        // SAFETY: `text` holds `length` units before its NUL.
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        // SAFETY: allocated by ConvertSidToStringSidW and released once here.
        unsafe { LocalFree(text.cast()) };
        Ok(sid)
    }
}

/// Makes a directory at `path` with the owner and protected DACL that
/// `sddl` gives, which no one else has had a handle on: it is made under a
/// fresh name beside `path`, with that security from the start, and then
/// renamed to `path`, which fails with [`std::io::ErrorKind::AlreadyExists`]
/// when something got there first; nothing already there is taken over or
/// replaced. An owner other than the caller's own SID needs an elevated
/// administrator, for the Administrators, or more.
pub fn create_directory_in_place(path: &std::path::Path, sddl: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, MoveFileExW};

    let wide = |path: &std::path::Path| {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let descriptor = security_descriptor(sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut staging_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other(format!("{} has no file name", path.display())))?
        .to_os_string();
    staging_name.push(format!(".new-{stamp}"));
    let staging = path.with_file_name(staging_name);
    let (staging_wide, path_wide) = (wide(&staging), wide(path));
    // SAFETY: the name is NUL-terminated and `attributes` points to the live
    // descriptor, so the directory is never there without it.
    if unsafe { CreateDirectoryW(staging_wide.as_ptr(), &attributes) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Without MOVEFILE_REPLACE_EXISTING: whatever is at `path` stays.
    // SAFETY: both names are NUL-terminated.
    if unsafe { MoveFileExW(staging_wide.as_ptr(), path_wide.as_ptr(), 0) } == 0 {
        let error = std::io::Error::last_os_error();
        let _ = std::fs::remove_dir(&staging);
        return Err(error);
    }
    Ok(())
}

/// Makes the Administrators the owner of `file`, as only an elevated
/// administrator can, whoever the system made its owner. The handle needs
/// `WRITE_OWNER`.
pub fn give_to_administrators(
    file: &impl std::os::windows::io::AsRawHandle,
) -> std::io::Result<()> {
    set_security_object(
        file,
        OWNER_SECURITY_INFORMATION,
        &security_descriptor("O:BA")?,
    )
}

/// Whether `file` is owned by SYSTEM or the Administrators. The handle
/// needs `READ_CONTROL`.
pub fn owned_by_system_or_administrators(
    file: &impl std::os::windows::io::AsRawHandle,
) -> std::io::Result<bool> {
    let mut owner: PSID = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: the handle stays open; the outputs receive a LocalFree-owned
    // descriptor and a pointer into it.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
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
    let _descriptor = LocalSecurityDescriptor(descriptor);
    // SAFETY: `owner` points into the live descriptor.
    Ok(!owner.is_null()
        && unsafe {
            IsWellKnownSid(owner, WinLocalSystemSid) != 0
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
        })
}

/// The security descriptor `sddl` describes.
fn security_descriptor(sddl: &str) -> std::io::Result<LocalSecurityDescriptor> {
    let encoded = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    // SAFETY: `encoded` is NUL-terminated and `descriptor` receives an allocation.
    let converted = unsafe {
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
    Ok(LocalSecurityDescriptor(descriptor))
}

/// Sets the parts of `file`'s security that `information` names from
/// `descriptor`, without passing anything on to what is inside a directory.
fn set_security_object(
    file: &impl std::os::windows::io::AsRawHandle,
    information: u32,
    descriptor: &LocalSecurityDescriptor,
) -> std::io::Result<()> {
    // SAFETY: the handle is valid for the call and the descriptor outlives it.
    let status =
        unsafe { NtSetSecurityObject(file.as_raw_handle().cast(), information, descriptor.0) };
    if status == 0 {
        Ok(())
    } else {
        // SAFETY: converts an NTSTATUS to a Win32 error code.
        let error = unsafe { RtlNtStatusToDosError(status) };
        Err(std::io::Error::from_raw_os_error(error as i32))
    }
}

/// Sets `file`'s DACL to `sddl`'s, inheriting nothing. The handle needs
/// `WRITE_DAC`.
fn set_protected_dacl(
    file: &impl std::os::windows::io::AsRawHandle,
    sddl: &str,
) -> std::io::Result<()> {
    set_security_object(
        file,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        &security_descriptor(sddl)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::windows::io::AsRawHandle as _;

    /// Whether the file's DACL is protected and lets in only its owner, the
    /// user and SYSTEM.
    fn owner_user_and_system_only(path: &std::path::Path) -> bool {
        let file = std::fs::File::open(path).unwrap();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: the handle stays open; the outputs receive a LocalFree-owned
        // descriptor and a DACL pointer into it.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let descriptor = LocalSecurityDescriptor(descriptor);
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: the descriptor is valid and both outputs are initialized.
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
            0
        );
        assert!(!dacl.is_null());
        control & SE_DACL_PROTECTED != 0 && others_let_in(path).is_empty()
    }

    /// Whether the user's own token, as it is in this process, could read
    /// and write the file or directory at `path` were another account its
    /// owner. That is how an unelevated terminal finds what an elevated one
    /// made, which the Administrators own: the unelevated token holds that
    /// group only to deny. A SID no token holds stands in for it, so that
    /// the answer is the same when the tests run elevated.
    fn user_gets_in_when_another_owns(path: &std::path::Path) -> bool {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows_sys::Win32::Security::{
            AccessCheck, DuplicateToken, GENERIC_MAPPING, InitializeSecurityDescriptor,
            PRIVILEGE_SET, SECURITY_DESCRIPTOR, SecurityImpersonation, SetSecurityDescriptorDacl,
            SetSecurityDescriptorGroup, SetSecurityDescriptorOwner, TOKEN_DUPLICATE,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, READ_CONTROL,
        };

        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        let mut dacl: *mut ACL = null_mut();
        let mut found = null_mut();
        // SAFETY: as in `keeps_others_out`.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut found,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let _found = LocalSecurityDescriptor(found);

        let another = "S-1-5-21-1-2-3-1000"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut owner: PSID = null_mut();
        // SAFETY: the string is NUL-terminated; `owner` receives a
        // LocalFree-owned SID, freed with the descriptor wrapper's LocalFree.
        assert_ne!(
            unsafe { ConvertStringSidToSidW(another.as_ptr(), &mut owner) },
            0
        );
        let _owner = LocalSecurityDescriptor(owner);
        // SAFETY: an all-zero SECURITY_DESCRIPTOR is what initialization overwrites.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let pointer = std::ptr::from_mut(&mut descriptor).cast();
        // SAFETY: `pointer` is a writable descriptor; `owner` and `dacl`
        // outlive the access check below.
        unsafe {
            assert_ne!(InitializeSecurityDescriptor(pointer, 1), 0);
            assert_ne!(SetSecurityDescriptorOwner(pointer, owner, 0), 0);
            assert_ne!(SetSecurityDescriptorGroup(pointer, owner, 0), 0);
            assert_ne!(SetSecurityDescriptorDacl(pointer, 1, dacl, 0), 0);
        }

        let mut process_token: HANDLE = null_mut();
        // SAFETY: the pseudo-handle is valid; the token is closed below.
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut process_token,
                )
            },
            0
        );
        let mut token: HANDLE = null_mut();
        // SAFETY: `process_token` is open; `token` receives a handle closed below.
        let duplicated =
            unsafe { DuplicateToken(process_token, SecurityImpersonation, &mut token) };
        // SAFETY: open, and closed once here.
        unsafe { CloseHandle(process_token) };
        assert_ne!(duplicated, 0);
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        // SAFETY: an all-zero PRIVILEGE_SET is a valid empty one.
        let mut privileges: PRIVILEGE_SET = unsafe { std::mem::zeroed() };
        let mut privileges_length = std::mem::size_of::<PRIVILEGE_SET>() as u32;
        let (mut granted, mut allowed) = (0, 0);
        // SAFETY: the descriptor, token and outputs are valid for the call.
        let checked = unsafe {
            AccessCheck(
                pointer,
                token,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                &mapping,
                &mut privileges,
                &mut privileges_length,
                &mut granted,
                &mut allowed,
            )
        };
        let error = std::io::Error::last_os_error();
        // SAFETY: open, and closed once here.
        unsafe { CloseHandle(token) };
        assert_ne!(checked, 0, "{error}");
        allowed != 0
    }

    /// The SIDs a path's DACL lets in, but for the owner rights, SYSTEM
    /// and the user's own.
    fn others_let_in(path: &std::path::Path) -> Vec<String> {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL};

        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: as in `keeps_others_out`.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let _descriptor = LocalSecurityDescriptor(descriptor);
        let user = ProcessUser::query().unwrap();
        let mut others = Vec::new();
        // SAFETY: the DACL lives in the descriptor.
        for index in 0..u32::from(unsafe { (*dacl).AceCount }) {
            let mut ace = null_mut();
            // SAFETY: `index` is below the entry count.
            assert_ne!(unsafe { GetAce(dacl, index, &mut ace) }, 0);
            // SAFETY: every entry starts with a header; allowed ones hold a SID.
            let header = unsafe { *ace.cast::<ACE_HEADER>() };
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            let sid: PSID =
                unsafe { std::ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart) }
                    .cast();
            // SAFETY: both SIDs are valid.
            let trusted = unsafe {
                EqualSid(sid, user.sid()) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0
            };
            if trusted {
                continue;
            }
            let mut text = null_mut();
            // SAFETY: `sid` is valid; `text` receives a LocalFree-owned string.
            assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut text) }, 0);
            // SAFETY: `text` is NUL-terminated.
            let length = (0..)
                .take_while(|offset| unsafe { *text.add(*offset) } != 0)
                .count();
            others.push(String::from_utf16_lossy(unsafe {
                std::slice::from_raw_parts(text, length)
            }));
            // SAFETY: allocated by ConvertSidToStringSidW.
            unsafe { LocalFree(text.cast()) };
        }
        others
    }

    /// The test user's SID, as SDDL writes it.
    fn user_sid_string() -> String {
        process_user_sid().unwrap()
    }

    fn open_for_security(path: &std::path::Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC,
            WRITE_OWNER,
        };

        std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | WRITE_OWNER)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap()
    }

    #[test]
    fn a_directory_is_made_in_place_with_the_given_security() {
        let user = user_sid_string();
        let sddl = format!("O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})");
        let root = tempfile::tempdir().unwrap();

        let made = root.path().join("made");
        create_directory_in_place(&made, &sddl).unwrap();
        assert!(made.is_dir());
        assert!(others_let_in(&made).is_empty());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn nothing_already_there_is_taken_or_replaced() {
        let user = user_sid_string();
        let sddl = format!("O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})");
        let root = tempfile::tempdir().unwrap();
        let open_to_users = |path: &std::path::Path| {
            set_protected_dacl(
                &open_for_security(path),
                "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;BU)",
            )
            .unwrap();
        };

        // A directory someone else made first, open to every user.
        let directory = root.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        open_to_users(&directory);
        // A junction to somewhere else, and a file.
        let target = root.path().join("target");
        std::fs::create_dir(&target).unwrap();
        open_to_users(&target);
        let junction = root.path().join("junction");
        let made = std::process::Command::new("cmd")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let file = root.path().join("file");
        std::fs::write(&file, b"").unwrap();

        for path in [&directory, &junction, &file] {
            assert_eq!(
                create_directory_in_place(path, &sddl).unwrap_err().kind(),
                std::io::ErrorKind::AlreadyExists,
                "{}",
                path.display()
            );
        }
        assert_eq!(others_let_in(&directory), ["S-1-5-32-545"]);
        assert_eq!(others_let_in(&target), ["S-1-5-32-545"]);
        assert!(file.is_file());
        // No staging directory is left behind.
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 4);
    }

    #[test]
    fn tells_system_and_administrator_owned_files_from_a_users() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL};

        // Windows gives C:\ProgramData to SYSTEM.
        let program_data = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(r"C:\ProgramData")
            .unwrap();
        assert!(owned_by_system_or_administrators(&program_data).unwrap());

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("user.toml");
        std::fs::write(&path, b"").unwrap();
        let file = open_for_security(&path);
        set_security_object(
            &file,
            OWNER_SECURITY_INFORMATION,
            &security_descriptor(&format!("O:{}", user_sid_string())).unwrap(),
        )
        .unwrap();
        assert!(!owned_by_system_or_administrators(&file).unwrap());
    }

    #[test]
    fn a_state_directory_is_kept_to_its_owner_but_lets_packages_through() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        std::fs::write(state.join("earlier.json"), b"{}").unwrap();
        let open =
            || cap_std::fs::Dir::open_ambient_dir(&state, cap_std::ambient_authority()).unwrap();

        assert!(protect_state_directory(&open(), true).unwrap());
        assert!(!protect_state_directory(&open(), true).unwrap());

        assert_eq!(others_let_in(&state), ["S-1-15-2-1"]);
        assert!(others_let_in(&state.join("earlier.json")).is_empty());
        std::fs::write(state.join("later.json"), b"{}").unwrap();
        assert!(others_let_in(&state.join("later.json")).is_empty());
    }

    #[test]
    fn a_state_directory_kept_from_application_packages_lets_them_through_again() {
        let directory = tempfile::tempdir().unwrap();
        let open = || {
            cap_std::fs::Dir::open_ambient_dir(directory.path(), cap_std::ambient_authority())
                .unwrap()
        };
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL, WRITE_DAC,
            };
            let handle = std::fs::OpenOptions::new()
                .access_mode(READ_CONTROL | WRITE_DAC)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(directory.path())
                .unwrap();
            set_protected_dacl(&handle, "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)").unwrap();
        }

        assert!(protect_state_directory(&open(), false).unwrap());
        assert_eq!(others_let_in(directory.path()), ["S-1-15-2-1"]);
    }

    #[test]
    fn every_atomic_writer_leaves_an_owner_only_file() {
        let directory = tempfile::tempdir().unwrap();
        let handle =
            cap_std::fs::Dir::open_ambient_dir(directory.path(), cap_std::ambient_authority())
                .unwrap();
        let options = crate::AtomicWriteOptions::new().owner_only();

        crate::write_file_atomic_in_dir_with_options(
            &handle,
            std::ffi::OsStr::new("replaced.env"),
            options,
            |file| file.write_all(b"TOKEN=x\n"),
        )
        .unwrap();
        crate::atomic_write::create_file_atomic_in_dir_with_options(
            &handle,
            std::ffi::OsStr::new("created.env"),
            options,
            |file| file.write_all(b"TOKEN=x\n"),
        )
        .unwrap();
        crate::write_file_atomic_with_options(
            &directory.path().join("by-path.env"),
            b"TOKEN=x\n",
            options,
        )
        .unwrap();

        for name in ["replaced.env", "created.env", "by-path.env"] {
            assert!(
                owner_user_and_system_only(&directory.path().join(name)),
                "{name}"
            );
        }
    }

    #[test]
    fn tells_a_file_kept_to_its_owner_from_one_others_reach() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, READ_CONTROL, WRITE_DAC};
        let directory = tempfile::tempdir().unwrap();
        let open = |name: &str| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .access_mode(FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC)
                .open(directory.path().join(name))
                .unwrap()
        };

        let inherited = open("inherited.env");
        assert!(!keeps_others_out(&inherited).unwrap());

        let protected = open("protected.env");
        protect_file(&protected).unwrap();
        assert!(keeps_others_out(&protected).unwrap());

        let by_hand = open("by-hand.env");
        set_protected_dacl(
            &by_hand,
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(D;;FA;;;WD)",
        )
        .unwrap();
        assert!(keeps_others_out(&by_hand).unwrap());

        let shared = open("shared.env");
        set_protected_dacl(&shared, "D:P(A;;FA;;;OW)(A;;FR;;;BU)").unwrap();
        assert!(!keeps_others_out(&shared).unwrap());
    }

    /// From the Windows verification pass: `lpm cert trust` run from an
    /// elevated terminal left a CA key the same user's normal terminal
    /// couldn't open, as the Administrators owned it and its DACL let in
    /// only its owner.
    #[test]
    fn what_is_kept_owner_only_lets_the_user_in_whoever_owns_it() {
        let directory = tempfile::tempdir().unwrap();

        let earlier = directory.path().join("earlier.pem");
        std::fs::write(&earlier, b"key").unwrap();
        set_protected_dacl(&open_for_security(&earlier), "D:P(A;;FA;;;OW)(A;;FA;;;SY)").unwrap();
        assert!(!user_gets_in_when_another_owns(&earlier));

        let key = directory.path().join("rootCA-key.pem");
        crate::write_file_atomic_with_options(
            &key,
            b"key",
            crate::AtomicWriteOptions::new().owner_only(),
        )
        .unwrap();
        assert!(owner_user_and_system_only(&key));
        assert!(user_gets_in_when_another_owns(&key));

        // What is created in a state directory afterwards, as an elevated
        // `lpm install` writes in a project's `.lpm`.
        let state = directory.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        let open =
            || cap_std::fs::Dir::open_ambient_dir(&state, cap_std::ambient_authority()).unwrap();
        assert!(protect_state_directory(&open(), true).unwrap());
        std::fs::write(state.join("later.json"), b"{}").unwrap();
        assert!(user_gets_in_when_another_owns(&state));
        assert!(user_gets_in_when_another_owns(&state.join("later.json")));
    }

    #[test]
    fn a_state_directory_an_earlier_release_kept_names_the_user_too() {
        let directory = tempfile::tempdir().unwrap();
        let earlier_release = |state: &std::path::Path| {
            std::fs::create_dir(state).unwrap();
            set_protected_dacl(
                &open_for_security(state),
                "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;;0xa0;;;AC)",
            )
            .unwrap();
            // Made while the earlier release kept it, so they hand on the
            // owner's entry alone.
            std::fs::create_dir(state.join("store")).unwrap();
            std::fs::write(state.join("earlier.json"), b"{}").unwrap();
            assert!(!user_gets_in_when_another_owns(state));
            assert!(!user_gets_in_when_another_owns(&state.join("store")));
        };
        let open = |state: &std::path::Path| {
            cap_std::fs::Dir::open_ambient_dir(state, cap_std::ambient_authority()).unwrap()
        };

        // A `.lpm` gets the user's entry all through, so what an elevated
        // run creates in its folders lets the user in too (from review).
        let state = directory.path().join(".lpm");
        earlier_release(&state);
        assert!(protect_state_directory(&open(&state), true).unwrap());
        assert!(!protect_state_directory(&open(&state), true).unwrap());
        assert!(user_gets_in_when_another_owns(&state));
        assert_eq!(others_let_in(&state), ["S-1-15-2-1"]);
        assert!(user_gets_in_when_another_owns(&state.join("earlier.json")));
        std::fs::write(state.join("store").join("later.json"), b"{}").unwrap();
        assert!(user_gets_in_when_another_owns(
            &state.join("store").join("later.json")
        ));

        // The home gets it on its own DACL, for what is created in it from
        // now on.
        let home = directory.path().join("home");
        earlier_release(&home);
        assert!(protect_state_directory(&open(&home), false).unwrap());
        assert!(!protect_state_directory(&open(&home), false).unwrap());
        assert!(user_gets_in_when_another_owns(&home));
        std::fs::write(home.join("later.json"), b"{}").unwrap();
        assert!(user_gets_in_when_another_owns(&home.join("later.json")));
        assert!(!user_gets_in_when_another_owns(&home.join("store")));
    }
}
