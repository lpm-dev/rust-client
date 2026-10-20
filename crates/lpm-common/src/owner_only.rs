//! Owner-only access for files that hold secrets on Windows, where a mode
//! of 0600 has no effect: the file's DACL grants full access to its owner
//! and to SYSTEM and inherits nothing.

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
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const OWNER_SYSTEM_FILE_DACL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)";

/// The DACL of LPM's state directories, a project's `.lpm` and the LPM
/// home: full control for the owner and SYSTEM, which what is created in
/// them inherits, and for ALL APPLICATION PACKAGES the directory's
/// attributes and passage through it, not its listing, which a sandboxed
/// lifecycle script needs to reach the access it was granted below.
const STATE_DIRECTORY_DACL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;;0xa0;;;AC)";

/// What [`STATE_DIRECTORY_DACL`] lets application packages do: read the
/// directory's attributes (`FILE_READ_ATTRIBUTES`) and pass through it
/// (`FILE_TRAVERSE`).
const PACKAGE_PASSAGE: u32 = 0xa0;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
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

/// Limits `file` to its owner and SYSTEM. The handle needs `WRITE_DAC`.
pub fn protect_file(file: &impl std::os::windows::io::AsRawHandle) -> std::io::Result<()> {
    set_protected_dacl(file, OWNER_SYSTEM_FILE_DACL)
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
/// home, to its owner and SYSTEM, letting sandboxed lifecycle scripts
/// through to what they are granted below, and says whether it changed
/// its DACL. One already kept so, inheriting nothing and letting
/// application packages through, is left alone. With `push_to_contents`,
/// what is already inside it stops inheriting the access it had from the
/// directory above, as in a `.lpm` an earlier release made; without it
/// only what is created there from now on is kept, as for the LPM home,
/// whose store files are hard links in projects' `node_modules`.
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
    if keeps_state_directory_dacl(&handle)? {
        return Ok(false);
    }
    if push_to_contents {
        set_protected_tree_dacl(&final_path(&handle)?, STATE_DIRECTORY_DACL)?;
    } else {
        set_protected_dacl(&handle, STATE_DIRECTORY_DACL)?;
    }
    Ok(true)
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

/// Whether `directory`'s DACL inherits nothing and lets application
/// packages through it, as [`STATE_DIRECTORY_DACL`] does.
fn keeps_state_directory_dacl(
    directory: &impl std::os::windows::io::AsRawHandle,
) -> std::io::Result<bool> {
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
        return Ok(false);
    }
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
            return Ok(true);
        }
    }
    Ok(false)
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
}

/// Sets `file`'s DACL to `sddl`'s, inheriting nothing. The handle needs
/// `WRITE_DAC`.
fn set_protected_dacl(
    file: &impl std::os::windows::io::AsRawHandle,
    sddl: &str,
) -> std::io::Result<()> {
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
    let descriptor = LocalSecurityDescriptor(descriptor);
    // SAFETY: the handle is valid for the call and the descriptor outlives it.
    let status = unsafe {
        NtSetSecurityObject(
            file.as_raw_handle().cast(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        // SAFETY: converts an NTSTATUS to a Win32 error code.
        let error = unsafe { RtlNtStatusToDosError(status) };
        Err(std::io::Error::from_raw_os_error(error as i32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::windows::io::AsRawHandle as _;

    /// Whether the file's DACL is protected and holds exactly two entries.
    fn owner_and_system_only(path: &std::path::Path) -> bool {
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
        // SAFETY: GetSecurityInfo returned a DACL inside the live descriptor.
        let entries = unsafe { (*dacl).AceCount };
        control & SE_DACL_PROTECTED != 0 && entries == 2
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
                owner_and_system_only(&directory.path().join(name)),
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
}
