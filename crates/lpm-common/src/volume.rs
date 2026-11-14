//! What the volume a directory is on can't do that LPM relies on: keep files
//! to the user, and hold links to elsewhere on the computer. Windows tells
//! from the file system's flags and the directory's path; elsewhere nothing
//! is reported.

/// Why the files LPM keeps to the user in `directory` wouldn't be kept from
/// anyone, for a message, as in "it is on an exFAT drive, which keeps no file
/// permissions"; `None` where they would be, or the volume can't be told.
#[must_use]
pub fn files_not_private(directory: &cap_std::fs::Dir) -> Option<String> {
    #[cfg(any(test, feature = "test-support"))]
    if test_support::pretending() {
        return Some("it is on an exFAT drive, which keeps no file permissions".to_owned());
    }
    #[cfg(windows)]
    {
        Volume::of(directory).ok()?.why_files_are_not_private()
    }
    #[cfg(not(windows))]
    {
        let _ = directory;
        None
    }
}

/// Why `directory` can't hold the links to elsewhere on this computer that
/// a project's `node_modules` is made of, for a message; `None` where it
/// can, or the volume can't be told.
#[must_use]
pub fn links_not_held(directory: &cap_std::fs::Dir) -> Option<String> {
    #[cfg(any(test, feature = "test-support"))]
    if test_support::pretending() {
        return Some("it is on an exFAT drive, which can't hold links".to_owned());
    }
    #[cfg(windows)]
    {
        Volume::of(directory).ok()?.why_links_are_not_held()
    }
    #[cfg(not(windows))]
    {
        let _ = directory;
        None
    }
}

#[cfg(windows)]
pub use windows::Volume;

/// Whether `file` is on a volume that keeps no file permissions, such as
/// exFAT: one that takes an access list and keeps none of it. A volume
/// Windows can't tell counts as keeping them.
#[cfg(windows)]
#[must_use]
pub fn keeps_no_permissions(file: &impl std::os::windows::io::AsRawHandle) -> bool {
    #[cfg(any(test, feature = "test-support"))]
    if test_support::pretending() {
        return true;
    }
    windows::flags_of(file).is_ok_and(|flags| {
        flags & windows_sys::Win32::System::SystemServices::FILE_PERSISTENT_ACLS == 0
    })
}

/// Volumes as tests want them seen.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use std::cell::Cell;

    thread_local! {
        static EXFAT: Cell<bool> = const { Cell::new(false) };
    }

    /// Has [`super::files_not_private`] and [`super::links_not_held`] find,
    /// on this thread, that every directory is on an exFAT drive, which keeps
    /// no file permissions and holds no links, until what this returns is
    /// dropped.
    #[must_use]
    pub fn pretend_every_volume_is_exfat() -> Pretending {
        EXFAT.set(true);
        Pretending(())
    }

    /// See [`pretend_every_volume_is_exfat`].
    pub struct Pretending(());

    impl Drop for Pretending {
        fn drop(&mut self) {
            EXFAT.set(false);
        }
    }

    pub(super) fn pretending() -> bool {
        EXFAT.get()
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    use windows_sys::Win32::System::SystemServices::{
        FILE_PERSISTENT_ACLS, FILE_SUPPORTS_REPARSE_POINTS,
    };

    /// The volume an open file or directory is on.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Volume {
        flags: u32,
        file_system: String,
        network: bool,
    }

    /// The file system flags of the volume `file` is on, alone.
    pub(super) fn flags_of(file: &impl AsRawHandle) -> io::Result<u32> {
        let mut flags = 0_u32;
        let read = unsafe {
            // SAFETY: the handle stays open for the call, and Windows skips the outputs passed
            // as null.
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut flags,
                std::ptr::null_mut(),
                0,
            )
        };
        if read == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(flags)
        }
    }

    impl Volume {
        /// The volume `file` is on. A volume Windows gives no path for, as
        /// one with neither a drive letter nor a folder it is mounted in,
        /// counts as local.
        ///
        /// # Errors
        ///
        /// When Windows can't tell the volume.
        pub fn of(file: &impl AsRawHandle) -> io::Result<Self> {
            let mut flags = 0_u32;
            let mut file_system = [0_u16; 64];
            let capacity = u32::try_from(file_system.len()).map_err(io::Error::other)?;
            let read = unsafe {
                // SAFETY: the handle stays open for the call, the buffer holds `capacity` units,
                // and Windows skips the outputs passed as null.
                GetVolumeInformationByHandleW(
                    file.as_raw_handle(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut flags,
                    file_system.as_mut_ptr(),
                    capacity,
                )
            };
            if read == 0 {
                return Err(io::Error::last_os_error());
            }
            let end = file_system
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(file_system.len());
            let network =
                crate::owner_only::final_path(file).is_ok_and(|path| is_network_path(&path));
            Ok(Self {
                flags,
                file_system: String::from_utf16_lossy(&file_system[..end]),
                network,
            })
        }

        /// A volume with `flags` and `file_system`, as Windows reports them,
        /// reached through a network folder or not.
        #[must_use]
        pub fn reported(flags: u32, file_system: &str, network: bool) -> Self {
            Self {
                flags,
                file_system: file_system.to_owned(),
                network,
            }
        }

        /// Whether the file system keeps each file's owner and access list.
        /// exFAT and FAT keep neither, nor do some network file systems, such as
        /// Parallels shared folders: there, anyone using the computer can read
        /// and change every file.
        #[must_use]
        pub fn keeps_permissions(&self) -> bool {
            self.flags & FILE_PERSISTENT_ACLS != 0
        }

        /// Whether the volume is reached through a network folder (a share, a
        /// mapped network drive, a Parallels shared folder or a WSL path), whose
        /// server decides who can reach what is on it.
        #[must_use]
        pub fn is_network(&self) -> bool {
            self.network
        }

        /// Whether directory links to elsewhere on this computer work here: on a
        /// local volume whose file system holds reparse points. A network
        /// folder's server would follow a junction on its own disks, and Windows
        /// doesn't follow a symbolic link from a network folder to this computer
        /// unless told to.
        #[must_use]
        pub fn holds_local_links(&self) -> bool {
            self.flags & FILE_SUPPORTS_REPARSE_POINTS != 0 && !self.network
        }

        /// The file system's name, as in `NTFS`, `exFAT` or `PrlSF`.
        #[must_use]
        pub fn file_system(&self) -> &str {
            &self.file_system
        }

        /// See [`super::files_not_private`].
        #[must_use]
        pub fn why_files_are_not_private(&self) -> Option<String> {
            if self.keeps_permissions() {
                None
            } else if self.network {
                Some("it is in a network folder that keeps no file permissions".to_owned())
            } else {
                Some(format!(
                    "it is on {}, which keeps no file permissions",
                    self.drive()
                ))
            }
        }

        /// See [`super::links_not_held`].
        #[must_use]
        pub fn why_links_are_not_held(&self) -> Option<String> {
            if self.holds_local_links() {
                None
            } else if self.network {
                Some(
                    "it is in a network folder, which can't hold links to this computer's drives"
                        .to_owned(),
                )
            } else {
                Some(format!("it is on {}, which can't hold links", self.drive()))
            }
        }

        /// The drive as a message names it, as in "an exFAT drive".
        fn drive(&self) -> String {
            let article = match self.file_system.chars().next() {
                Some(first) if "AEIOUaeiou".contains(first) => "an",
                _ => "a",
            };
            format!("{article} {} drive", self.file_system)
        }
    }

    /// Whether `path`, a final path as Windows gives it, is a network one.
    fn is_network_path(path: &std::path::Path) -> bool {
        use std::path::{Component, Prefix};
        matches!(
            path.components().next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::UNC(..) | Prefix::VerbatimUNC(..))
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const NTFS: u32 = 0x03e7_06ff;
        const EXFAT: u32 = 0x0002_0206;
        const PARALLELS_SHARED_FOLDER: u32 = 0x0000_0003;

        #[test]
        fn ntfs_keeps_files_private_and_holds_links() {
            let volume = Volume::reported(NTFS, "NTFS", false);

            assert!(volume.keeps_permissions());
            assert!(volume.holds_local_links());
            assert_eq!(volume.why_files_are_not_private(), None);
            assert_eq!(volume.why_links_are_not_held(), None);
        }

        #[test]
        fn exfat_keeps_no_permissions_and_holds_no_links() {
            let volume = Volume::reported(EXFAT, "exFAT", false);

            assert!(!volume.keeps_permissions());
            assert!(!volume.holds_local_links());
            assert_eq!(
                volume.why_files_are_not_private().unwrap(),
                "it is on an exFAT drive, which keeps no file permissions"
            );
            assert_eq!(
                volume.why_links_are_not_held().unwrap(),
                "it is on an exFAT drive, which can't hold links"
            );
        }

        #[test]
        fn a_network_folder_holds_no_local_links_and_keeps_what_its_file_system_keeps() {
            let parallels = Volume::reported(PARALLELS_SHARED_FOLDER, "PrlSF", true);
            let windows_share = Volume::reported(NTFS, "NTFS", true);

            assert_eq!(
                parallels.why_files_are_not_private().unwrap(),
                "it is in a network folder that keeps no file permissions"
            );
            assert_eq!(windows_share.why_files_are_not_private(), None);
            for volume in [parallels, windows_share] {
                assert!(!volume.holds_local_links());
                assert_eq!(
                    volume.why_links_are_not_held().unwrap(),
                    "it is in a network folder, which can't hold links to this computer's drives"
                );
            }
        }

        #[test]
        fn only_a_unc_final_path_is_a_network_one() {
            assert!(is_network_path(std::path::Path::new(
                r"\\?\UNC\Mac\Home\work"
            )));
            assert!(is_network_path(std::path::Path::new(r"\\Mac\Home\work")));
            assert!(!is_network_path(std::path::Path::new(r"\\?\C:\work")));
            assert!(!is_network_path(std::path::Path::new(r"\\?\W:\work")));
        }

        #[test]
        fn a_temporary_directory_is_on_a_local_volume() {
            let dir = tempfile::tempdir().unwrap();
            let handle =
                cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority())
                    .unwrap();

            let volume = Volume::of(&handle).unwrap();

            assert!(!volume.is_network());
            assert!(!volume.file_system().is_empty());
        }

        #[test]
        fn a_network_path_to_a_local_directory_is_a_network_folder() {
            let dir = tempfile::tempdir().unwrap();
            let Some(network) = crate::test_network_path::through_network(dir.path()) else {
                return;
            };
            let handle =
                cap_std::fs::Dir::open_ambient_dir(&network, cap_std::ambient_authority()).unwrap();

            let volume = Volume::of(&handle).unwrap();

            assert!(volume.is_network());
            assert!(!volume.holds_local_links());
        }
    }
}
