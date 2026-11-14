//! The directory a script runs in, as the system shell can use it.
//!
//! cmd.exe can't run in a network folder: started in
//! `\\server\share\project`, it warns that UNC paths are not supported and
//! runs the script in the Windows directory instead. A script in a network
//! folder therefore runs through a drive letter: one already mapped to the
//! folder's share, or a free one LPM maps while its scripts run there.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A directory as the system shell can use it. On Windows, holding one keeps
/// the drive letter it reaches a network folder by.
#[derive(Debug)]
pub struct ScriptDirectory {
    path: PathBuf,
    #[cfg(windows)]
    _drive: Option<windows::DriveHold>,
}

impl ScriptDirectory {
    /// `directory` as the system shell can use it: itself, or on Windows,
    /// for a network folder, the same folder through a drive letter. LPM
    /// maps a free letter, from `Z:` down, only when no letter reaches the
    /// folder already, and removes it once nothing it runs uses it.
    ///
    /// # Errors
    ///
    /// On Windows, when no drive letter is free for a network folder, or the
    /// share can't be mapped.
    #[cfg(windows)]
    pub fn for_shell(directory: &Path) -> io::Result<Self> {
        match windows::network_folder(directory) {
            Some(folder) => {
                let (path, drive) = windows::through_drive(&folder)?;
                Ok(Self {
                    path,
                    _drive: Some(drive),
                })
            }
            None => Ok(Self {
                path: directory.to_path_buf(),
                _drive: None,
            }),
        }
    }

    /// `directory` itself: other systems' shells run anywhere.
    ///
    /// # Errors
    ///
    /// Never; Windows can fail.
    #[cfg(not(windows))]
    pub fn for_shell(directory: &Path) -> io::Result<Self> {
        Ok(Self {
            path: directory.to_path_buf(),
        })
    }

    /// Moves `command` to its directory as Windows can start it there. cmd.exe,
    /// which also runs every batch file, can't start in a network folder, so
    /// such a command starts in the same folder through a drive letter, which
    /// what this returns keeps. Call it just before the spawn, and keep what it
    /// returns until the process has exited. A command that doesn't run in
    /// cmd.exe, and every command elsewhere, is left as it is.
    ///
    /// # Errors
    ///
    /// When the current directory can't be read for a command that has none,
    /// and as [`Self::for_shell`].
    pub fn reach_for(command: &mut Command) -> io::Result<Option<Self>> {
        #[cfg(windows)]
        {
            if !windows::runs_in_cmd(Path::new(command.get_program())) {
                return Ok(None);
            }
            let directory = match command.get_current_dir() {
                Some(directory) if directory.is_absolute() => directory.to_path_buf(),
                Some(directory) => std::env::current_dir()?.join(directory),
                None => std::env::current_dir()?,
            };
            let reached = Self::for_shell(&directory)?;
            if reached.path != directory {
                command.current_dir(&reached.path);
            }
            Ok(Some(reached))
        }
        #[cfg(not(windows))]
        {
            let _ = command;
            Ok(None)
        }
    }

    /// The directory to start the shell in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(windows)]
mod windows {
    use std::collections::{HashMap, HashSet};
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_ASSIGNED, ERROR_DEVICE_ALREADY_REMEMBERED, ERROR_DEVICE_IN_USE,
        ERROR_MORE_DATA, ERROR_OPEN_FILES, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::WNet::{
        CONNECT_TEMPORARY, NETRESOURCEW, RESOURCETYPE_DISK, WNetAddConnection2W,
        WNetCancelConnection2W, WNetGetConnectionW,
    };
    use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;

    /// Whether `program` runs in cmd.exe: cmd.exe itself, named with or
    /// without its extension, or a batch file.
    pub(super) fn runs_in_cmd(program: &Path) -> bool {
        program.extension().is_some_and(|extension| {
            extension.eq_ignore_ascii_case("cmd") || extension.eq_ignore_ascii_case("bat")
        }) || program.file_name().is_some_and(|name| {
            name.eq_ignore_ascii_case("cmd.exe") || name.eq_ignore_ascii_case("cmd")
        })
    }

    /// A folder on a network share: the share, as in `\\server\share`, and
    /// the folder's names below it.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct NetworkFolder {
        share: OsString,
        below: Vec<OsString>,
    }

    /// The network folder `directory` names, as `\\server\share\…` or
    /// `\\?\UNC\server\share\…` do, with `.` and `..` resolved as Windows
    /// resolves them, never above the share; `None` for any other path,
    /// which cmd.exe can use as it is.
    pub(super) fn network_folder(directory: &Path) -> Option<NetworkFolder> {
        let mut components = directory.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return None;
        };
        let (Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share)) = prefix.kind()
        else {
            return None;
        };
        let mut share_path = OsString::with_capacity(server.len() + share.len() + 3);
        share_path.push(r"\\");
        share_path.push(server);
        share_path.push(r"\");
        share_path.push(share);
        let mut below = Vec::new();
        for component in components {
            match component {
                Component::Normal(name) => below.push(name.to_os_string()),
                Component::ParentDir => {
                    below.pop();
                }
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
        Some(NetworkFolder {
            share: share_path,
            below,
        })
    }

    /// The drive letters LPM mapped, by share, with how many
    /// [`super::ScriptDirectory`] values use each.
    static MAPPED: Mutex<Option<HashMap<OsString, Mapped>>> = Mutex::new(None);

    #[derive(Debug)]
    struct Mapped {
        share: OsString,
        letter: u8,
        users: usize,
    }

    /// Keeps the drive letter a script reaches a network folder by.
    #[derive(Debug)]
    pub(super) enum DriveHold {
        /// A letter LPM mapped, removed when its last user is done.
        Mapped { _hold: MappedHold },
        /// A letter someone else mapped, which may be another LPM process.
        /// The folder is kept open: Windows doesn't remove a letter that
        /// something still has open, unless it's forced to.
        Borrowed { _folder: std::fs::File },
    }

    #[derive(Debug)]
    pub(super) struct MappedHold {
        share_key: OsString,
    }

    impl Drop for MappedHold {
        fn drop(&mut self) {
            let mut mapped = MAPPED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(drives) = mapped.as_mut() else {
                return;
            };
            let Some(drive) = drives.get_mut(&self.share_key) else {
                return;
            };
            drive.users -= 1;
            if drive.users == 0 {
                let letter = drive.letter;
                let still_ours = mapped_remote(letter)
                    .is_some_and(|remote| remote.eq_ignore_ascii_case(&drive.share));
                drives.remove(&self.share_key);
                // Someone may have removed the letter, or mapped it to
                // something else, since.
                if still_ours {
                    remove_mapping_unless_used(letter);
                }
            }
        }
    }

    /// `folder` through a drive letter, and what keeps that letter.
    pub(super) fn through_drive(folder: &NetworkFolder) -> io::Result<(PathBuf, DriveHold)> {
        let share_key = folder.share.to_ascii_lowercase();
        let mut mapped = MAPPED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let drives = mapped.get_or_insert_with(HashMap::new);
        if let Some(drive) = drives.get_mut(&share_key) {
            // Someone may have removed the letter since, as `net use /delete`
            // does; its users then move to a new one.
            if !mapped_remote(drive.letter)
                .is_some_and(|remote| remote.eq_ignore_ascii_case(&folder.share))
            {
                drive.letter = map_free_letter(&folder.share)?;
                say_mapped(&folder.share, drive.letter);
            }
            drive.users += 1;
            let hold = DriveHold::Mapped {
                _hold: MappedHold { share_key },
            };
            return Ok((on_drive(drive.letter, &folder.below), hold));
        }
        if let Some((path, folder_handle)) = through_existing_drive(folder) {
            return Ok((
                path,
                DriveHold::Borrowed {
                    _folder: folder_handle,
                },
            ));
        }
        let letter = map_free_letter(&folder.share)?;
        say_mapped(&folder.share, letter);
        drives.insert(
            share_key.clone(),
            Mapped {
                share: folder.share.clone(),
                letter,
                users: 1,
            },
        );
        Ok((
            on_drive(letter, &folder.below),
            DriveHold::Mapped {
                _hold: MappedHold { share_key },
            },
        ))
    }

    /// Says, once for each share in this process, which letter LPM mapped.
    fn say_mapped(share: &OsStr, letter: u8) {
        static SAID: Mutex<Option<HashSet<OsString>>> = Mutex::new(None);
        let mut said = SAID
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if said
            .get_or_insert_with(HashSet::new)
            .insert(share.to_ascii_lowercase())
        {
            tracing::warn!(
                "cmd.exe can't run scripts in a network folder, so LPM reaches {} as {}: while its scripts run",
                share.to_string_lossy(),
                char::from(letter)
            );
        }
    }

    /// `folder` through a drive letter already mapped to its share, or to a
    /// folder of the share above it, with the folder held open through it.
    fn through_existing_drive(folder: &NetworkFolder) -> Option<(PathBuf, std::fs::File)> {
        let used = unsafe {
            // SAFETY: takes no arguments.
            GetLogicalDrives()
        };
        (b'A'..=b'Z')
            .filter(|letter| used & (1 << (letter - b'A')) != 0)
            .find_map(|letter| {
                let remote = mapped_remote(letter)?;
                let remote = network_folder(Path::new(&remote))?;
                let below = folder
                    .below
                    .strip_prefix_ignore_case(&remote, &folder.share)?;
                let path = on_drive(letter, below);
                let handle = open_folder(&path).ok()?;
                Some((path, handle))
            })
    }

    /// Opens the folder at `path` for nothing but holding it open.
    fn open_folder(path: &Path) -> io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }

    trait StripFolderPrefix {
        /// What follows `remote`'s folders in these names, when `remote` is
        /// on `share` and its folders lead these, matched without regard to
        /// case.
        fn strip_prefix_ignore_case(
            &self,
            remote: &NetworkFolder,
            share: &OsStr,
        ) -> Option<&[OsString]>;
    }

    impl StripFolderPrefix for Vec<OsString> {
        fn strip_prefix_ignore_case(
            &self,
            remote: &NetworkFolder,
            share: &OsStr,
        ) -> Option<&[OsString]> {
            if !remote.share.eq_ignore_ascii_case(share) || remote.below.len() > self.len() {
                return None;
            }
            remote
                .below
                .iter()
                .zip(self)
                .all(|(mapped, wanted)| mapped.eq_ignore_ascii_case(wanted))
                .then(|| &self[remote.below.len()..])
        }
    }

    /// What the drive `letter` is mapped to, as in `\\server\share`; `None`
    /// when it isn't a network drive.
    fn mapped_remote(letter: u8) -> Option<OsString> {
        let local = [u16::from(letter), u16::from(b':'), 0];
        let mut buffer = vec![0_u16; 260];
        loop {
            let mut length = u32::try_from(buffer.len()).ok()?;
            let status = unsafe {
                // SAFETY: `local` is NUL-terminated, and `buffer` holds `length` writable units.
                WNetGetConnectionW(local.as_ptr(), buffer.as_mut_ptr(), &mut length)
            };
            match status {
                NO_ERROR => {
                    let end = buffer.iter().position(|unit| *unit == 0)?;
                    return Some(OsString::from_wide(&buffer[..end]));
                }
                ERROR_MORE_DATA if length as usize > buffer.len() => {
                    buffer.resize(length as usize, 0);
                }
                _ => return None,
            }
        }
    }

    /// Maps the first free drive letter from `Z:` down to `share`, for this
    /// sign-in only.
    fn map_free_letter(share: &OsStr) -> io::Result<u8> {
        let used = unsafe {
            // SAFETY: takes no arguments.
            GetLogicalDrives()
        };
        let mut remote: Vec<u16> = share.encode_wide().chain(Some(0)).collect();
        for letter in (b'D'..=b'Z').rev() {
            if used & (1 << (letter - b'A')) != 0 {
                continue;
            }
            let mut local = [u16::from(letter), u16::from(b':'), 0];
            let resource = NETRESOURCEW {
                dwType: RESOURCETYPE_DISK,
                lpLocalName: local.as_mut_ptr(),
                lpRemoteName: remote.as_mut_ptr(),
                ..NETRESOURCEW::default()
            };
            let status = unsafe {
                // SAFETY: `resource` points at NUL-terminated names that outlive the call, and
                // a null password and user name ask for the signed-in user's credentials.
                WNetAddConnection2W(
                    &resource,
                    std::ptr::null(),
                    std::ptr::null(),
                    CONNECT_TEMPORARY,
                )
            };
            match status {
                NO_ERROR => return Ok(letter),
                ERROR_ALREADY_ASSIGNED | ERROR_DEVICE_ALREADY_REMEMBERED => {}
                error => {
                    return Err(io::Error::new(
                        io::Error::from_raw_os_error(error as i32).kind(),
                        format!(
                            "cmd.exe can't run scripts in a network folder, and LPM could not map {} to a drive letter: {}",
                            share.to_string_lossy(),
                            io::Error::from_raw_os_error(error as i32)
                        ),
                    ));
                }
            }
        }
        Err(io::Error::other(format!(
            "cmd.exe can't run scripts in a network folder, and no drive letter is free to reach {} by: free one, or map one to the share yourself",
            share.to_string_lossy()
        )))
    }

    /// Removes the drive `letter` LPM mapped, unless something still has a
    /// file or folder open through it, as another LPM process running a
    /// script there does. A letter left so is reused the next time.
    fn remove_mapping_unless_used(letter: u8) {
        let local = [u16::from(letter), u16::from(b':'), 0];
        for delay_ms in [0, 50, 150] {
            if delay_ms != 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
            let status = unsafe {
                // SAFETY: `local` is NUL-terminated. Without CONNECT_UPDATE_PROFILE the user's
                // remembered connections stay as they are, and without forcing, a letter in use
                // stays.
                WNetCancelConnection2W(local.as_ptr(), 0, 0)
            };
            match status {
                NO_ERROR => return,
                // What a script started may still be closing its handles.
                ERROR_OPEN_FILES | ERROR_DEVICE_IN_USE => {}
                error => {
                    tracing::debug!(
                        "could not remove the drive {}: LPM mapped for scripts: {}",
                        char::from(letter),
                        io::Error::from_raw_os_error(error as i32)
                    );
                    return;
                }
            }
        }
        tracing::debug!(
            "left the drive {}: LPM mapped for scripts, which something still uses",
            char::from(letter)
        );
    }

    fn on_drive(letter: u8, below: &[OsString]) -> PathBuf {
        let mut path = PathBuf::from(format!("{}:\\", char::from(letter)));
        for name in below {
            path.push(name);
        }
        path
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_network_path_names_its_share_and_folders() {
            for path in [
                r"\\Mac\Home\work\app",
                r"\\?\UNC\Mac\Home\work\app",
                r"\\Mac\Home\work\app\",
                r"\\Mac\Home\work\other\..\.\app",
            ] {
                assert_eq!(
                    network_folder(Path::new(path)),
                    Some(NetworkFolder {
                        share: OsString::from(r"\\Mac\Home"),
                        below: vec![OsString::from("work"), OsString::from("app")],
                    }),
                    "{path}"
                );
            }
        }

        #[test]
        fn a_network_path_never_climbs_above_its_share() {
            assert_eq!(
                network_folder(Path::new(r"\\Mac\Home\..\..\app")),
                Some(NetworkFolder {
                    share: OsString::from(r"\\Mac\Home"),
                    below: vec![OsString::from("app")],
                })
            );
        }

        #[test]
        fn a_local_path_is_not_a_network_folder() {
            for path in [r"C:\work\app", r"\\?\C:\work\app", r"W:\app"] {
                assert_eq!(network_folder(Path::new(path)), None, "{path}");
            }
        }

        #[test]
        fn cmd_and_batch_files_run_in_cmd_and_other_programs_do_not() {
            for program in [
                r"C:\Windows\System32\cmd.exe",
                "cmd",
                "CMD.EXE",
                r"C:\app\node_modules\.bin\eslint.cmd",
                "build.BAT",
            ] {
                assert!(runs_in_cmd(Path::new(program)), "{program}");
            }
            for program in [r"C:\Program Files\nodejs\node.exe", "node", "cmdline.exe"] {
                assert!(!runs_in_cmd(Path::new(program)), "{program}");
            }
        }

        #[test]
        fn a_drive_mapped_to_the_share_or_a_folder_above_reaches_the_folder() {
            let folder = network_folder(Path::new(r"\\Mac\Home\Work\App")).unwrap();
            let share = network_folder(Path::new(r"\\mac\home")).unwrap();
            let above = network_folder(Path::new(r"\\MAC\HOME\work")).unwrap();
            let beside = network_folder(Path::new(r"\\Mac\Home\other")).unwrap();
            let elsewhere = network_folder(Path::new(r"\\Mac\iCloud")).unwrap();

            let below = |remote: &NetworkFolder| {
                folder
                    .below
                    .strip_prefix_ignore_case(remote, &folder.share)
                    .map(|below| on_drive(b'Y', below))
            };

            assert_eq!(below(&share), Some(PathBuf::from(r"Y:\Work\App")));
            assert_eq!(below(&above), Some(PathBuf::from(r"Y:\App")));
            assert_eq!(below(&beside), None);
            assert_eq!(below(&elsewhere), None);
        }

        fn letter_of(path: &Path) -> u8 {
            let Some(Component::Prefix(prefix)) = path.components().next() else {
                panic!("{path:?} has no drive");
            };
            let Prefix::Disk(letter) = prefix.kind() else {
                panic!("{path:?} has no drive letter");
            };
            letter
        }

        #[test]
        fn a_network_folder_is_reached_through_a_drive_mapped_while_it_is_used() {
            let local = tempfile::tempdir().unwrap();
            let project = local.path().join("app");
            std::fs::create_dir(&project).unwrap();
            let Some(network) = crate::test_network_path::through_network(&project) else {
                return;
            };

            let first = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let second = super::super::ScriptDirectory::for_shell(&network).unwrap();

            assert_eq!(first.path(), second.path());
            assert!(network_folder(first.path()).is_none(), "{:?}", first.path());
            std::fs::write(first.path().join("written"), b"through the drive").unwrap();
            assert_eq!(
                std::fs::read(project.join("written")).unwrap(),
                b"through the drive"
            );
            let letter = letter_of(first.path());
            let mapped_by_lpm = matches!(first._drive, Some(DriveHold::Mapped { .. }));
            drop(first);
            assert!(
                mapped_remote(letter).is_some(),
                "the drive went while in use"
            );
            drop(second);
            if mapped_by_lpm {
                assert_eq!(mapped_remote(letter), None, "the drive outlived its use");
            }
        }

        #[test]
        fn a_drive_someone_else_mapped_is_reused_and_kept_while_a_script_uses_it() {
            let local = tempfile::tempdir().unwrap();
            let project = local.path().join("app");
            std::fs::create_dir(&project).unwrap();
            let Some(network) = crate::test_network_path::through_network(&project) else {
                return;
            };
            let share = network_folder(&network).unwrap().share;
            // Another process's mapping, as the user's or another LPM's.
            let theirs = map_free_letter(&share).unwrap();

            let reached = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let removed_while_used = {
                let local = [u16::from(theirs), u16::from(b':'), 0];
                // SAFETY: `local` is NUL-terminated.
                unsafe { WNetCancelConnection2W(local.as_ptr(), 0, 0) }
            };
            let path = reached.path().to_path_buf();
            drop(reached);
            let still_theirs = mapped_remote(theirs);
            remove_mapping_unless_used(theirs);

            assert_eq!(letter_of(&path), theirs, "{path:?}");
            assert!(
                matches!(removed_while_used, ERROR_OPEN_FILES | ERROR_DEVICE_IN_USE),
                "a script's drive could be removed under it: {removed_while_used}"
            );
            assert!(still_theirs.is_some(), "LPM removed a drive it didn't map");
        }
    }
}
