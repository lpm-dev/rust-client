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
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const OWNER_SYSTEM_FILE_DACL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)";

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
