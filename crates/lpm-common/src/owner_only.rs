//! Owner-only access for files that hold secrets on Windows, where a mode
//! of 0600 has no effect: the file's DACL grants full access to its owner
//! and to SYSTEM and inherits nothing.

#![cfg(windows)]

use std::ptr::null_mut;

use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
use windows_sys::Win32::Foundation::{LocalFree, RtlNtStatusToDosError};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};

const OWNER_SYSTEM_FILE_DACL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)";

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
    let encoded = OWNER_SYSTEM_FILE_DACL
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
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, SE_DACL_PROTECTED,
    };

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
}
