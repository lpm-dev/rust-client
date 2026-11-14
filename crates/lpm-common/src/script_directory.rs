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
    /// On Windows, when a letter already mapped to the share can't open the
    /// folder, or no letter is free for it, or the share can't be mapped.
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
    /// When the current directory can't be read for a command that has none
    /// or a relative one, and as [`Self::for_shell`].
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
        ERROR_ALREADY_ASSIGNED, ERROR_BAD_DEVICE, ERROR_DEVICE_ALREADY_REMEMBERED,
        ERROR_DEVICE_IN_USE, ERROR_MORE_DATA, ERROR_NOT_CONNECTED, ERROR_OPEN_FILES, NO_ERROR,
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
        /// Which mapping of the share this is, so that the holders of one
        /// found gone count nothing against the next.
        generation: u64,
    }

    static NEXT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
        generation: u64,
    }

    impl Drop for MappedHold {
        fn drop(&mut self) {
            // Under the lock, so that no other thread borrows the letter
            // between the entry's removal and the letter's, which would leave
            // it mapped with nothing tracking it.
            let mut mapped = MAPPED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(drives) = mapped.as_mut() else {
                return;
            };
            let last = match drives.get_mut(&self.share_key) {
                Some(drive) if drive.generation == self.generation => {
                    drive.users -= 1;
                    if drive.users == 0 {
                        drives.remove(&self.share_key)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            // Someone may have removed the letter, or mapped it to something
            // else, since.
            if let Some(drive) = last
                && matches!(connection_of(drive.letter), Connection::Remote(remote) if remote.eq_ignore_ascii_case(&drive.share))
            {
                remove_mapping_unless_used(drive.letter);
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
            // does, or mapped it to something else. A letter Windows can't
            // tell about counts as still there.
            let gone = match connection_of(drive.letter) {
                Connection::Remote(remote) => !remote.eq_ignore_ascii_case(&drive.share),
                Connection::NotConnected => true,
                Connection::Unknown => false,
            };
            if !gone {
                drive.users += 1;
                let hold = MappedHold {
                    share_key,
                    generation: drive.generation,
                };
                return Ok((
                    on_drive(drive.letter, &folder.below),
                    DriveHold::Mapped { _hold: hold },
                ));
            }
            drives.remove(&share_key);
        }
        let unusable = match through_existing_drive(folder) {
            Ok((path, folder_handle)) => {
                return Ok((
                    path,
                    DriveHold::Borrowed {
                        _folder: folder_handle,
                    },
                ));
            }
            // A folder a letter already reaches but can't open, missing or
            // closed to the user, won't open through another letter either.
            Err(Some((letter, error)))
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{} can't be opened through the drive {}: mapped to it: {error}",
                        on_share(folder).display(),
                        char::from(letter)
                    ),
                ));
            }
            Err(unusable) => unusable,
        };
        let letter = map_free_letter(&folder.share).map_err(|failure| {
            let (kind, failed) = match failure {
                MapFailure::NoneFree if unusable.is_some() => {
                    (io::ErrorKind::Other, "no other drive letter is free".to_owned())
                }
                MapFailure::NoneFree => (
                    io::ErrorKind::Other,
                    "no drive letter is free: free one, or map one to the share yourself"
                        .to_owned(),
                ),
                MapFailure::Refused(letter, error) => (
                    error.kind(),
                    format!("mapping it to {}: failed: {error}", char::from(letter)),
                ),
            };
            let reason = match unusable {
                Some((letter, open_error)) => format!(
                    "the drive {}: mapped to it couldn't open {} ({open_error}), and {failed}",
                    char::from(letter),
                    on_share(folder).display()
                ),
                None => failed,
            };
            io::Error::new(
                kind,
                format!(
                    "cmd.exe can't run scripts in a network folder, so LPM reaches {} through a drive letter, but {reason}",
                    folder.share.to_string_lossy()
                ),
            )
        })?;
        say_mapped(&folder.share, letter);
        let generation = NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        drives.insert(
            share_key.clone(),
            Mapped {
                share: folder.share.clone(),
                letter,
                users: 1,
                generation,
            },
        );
        Ok((
            on_drive(letter, &folder.below),
            DriveHold::Mapped {
                _hold: MappedHold {
                    share_key,
                    generation,
                },
            },
        ))
    }

    /// Says once in this process for each share and letter which letter LPM
    /// mapped.
    fn say_mapped(share: &OsStr, letter: u8) {
        static SAID: Mutex<Option<HashSet<(OsString, u8)>>> = Mutex::new(None);
        let mut said = SAID
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if said
            .get_or_insert_with(HashSet::new)
            .insert((share.to_ascii_lowercase(), letter))
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
    /// The letter mapped closest to `folder` wins, then the first. Without
    /// one, the first letter that reached it but couldn't open it, and why.
    fn through_existing_drive(
        folder: &NetworkFolder,
    ) -> Result<(PathBuf, std::fs::File), Option<(u8, io::Error)>> {
        let used = unsafe {
            // SAFETY: takes no arguments.
            GetLogicalDrives()
        };
        let mut reaching: Vec<(usize, u8, PathBuf)> = (b'A'..=b'Z')
            .filter(|letter| used & (1 << (letter - b'A')) != 0)
            .filter_map(|letter| {
                let remote = mapped_remote(letter)?;
                let remote = network_folder(Path::new(&remote))?;
                let below = folder
                    .below
                    .strip_prefix_ignore_case(&remote, &folder.share)?;
                Some((remote.below.len(), letter, on_drive(letter, below)))
            })
            .collect();
        reaching.sort_by_key(|(depth, letter, _)| (std::cmp::Reverse(*depth), *letter));
        let mut unusable = None;
        for (_, letter, path) in reaching {
            match open_folder(&path) {
                Ok(handle) => return Ok((path, handle)),
                Err(error) => {
                    unusable.get_or_insert((letter, error));
                }
            }
        }
        Err(unusable)
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

    /// What a drive letter is, as far as network drives go.
    enum Connection {
        /// A network drive mapped to this, as in `\\server\share`.
        Remote(OsString),
        /// Not a network drive.
        NotConnected,
        /// Windows couldn't tell.
        Unknown,
    }

    fn connection_of(letter: u8) -> Connection {
        let local = [u16::from(letter), u16::from(b':'), 0];
        let mut buffer = vec![0_u16; 260];
        loop {
            let Ok(mut length) = u32::try_from(buffer.len()) else {
                return Connection::Unknown;
            };
            let status = unsafe {
                // SAFETY: `local` is NUL-terminated, and `buffer` holds `length` writable units.
                WNetGetConnectionW(local.as_ptr(), buffer.as_mut_ptr(), &mut length)
            };
            match status {
                NO_ERROR => {
                    let Some(end) = buffer.iter().position(|unit| *unit == 0) else {
                        return Connection::Unknown;
                    };
                    return Connection::Remote(OsString::from_wide(&buffer[..end]));
                }
                ERROR_MORE_DATA if length as usize > buffer.len() => {
                    buffer.resize(length as usize, 0);
                }
                ERROR_NOT_CONNECTED | ERROR_BAD_DEVICE => return Connection::NotConnected,
                _ => return Connection::Unknown,
            }
        }
    }

    /// What the drive `letter` is mapped to, as in `\\server\share`; `None`
    /// when it isn't a network drive, or Windows can't tell.
    fn mapped_remote(letter: u8) -> Option<OsString> {
        match connection_of(letter) {
            Connection::Remote(remote) => Some(remote),
            Connection::NotConnected | Connection::Unknown => None,
        }
    }

    /// Maps the first free drive letter from `Z:` down to `share`, for this
    /// sign-in only.
    fn map_free_letter(share: &OsStr) -> Result<u8, MapFailure> {
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
                    return Err(MapFailure::Refused(
                        letter,
                        io::Error::from_raw_os_error(error as i32),
                    ));
                }
            }
        }
        Err(MapFailure::NoneFree)
    }

    /// Why a share couldn't be mapped to a drive letter.
    #[derive(Debug)]
    enum MapFailure {
        NoneFree,
        Refused(u8, io::Error),
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

    /// `folder` as a network path, as in `\\server\share\app`.
    fn on_share(folder: &NetworkFolder) -> PathBuf {
        let mut path = PathBuf::from(&folder.share);
        for name in &folder.below {
            path.push(name);
        }
        path
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

        /// The live drive tests run one at a time in a process: they share
        /// the registry of the letters this process mapped.
        static LIVE_DRIVES: Mutex<()> = Mutex::new(());

        /// A letter a test mapped, removed when dropped unless something
        /// still uses it.
        struct TestLetter(u8);

        impl Drop for TestLetter {
            fn drop(&mut self) {
                try_removing(self.0);
            }
        }

        /// What a non-forced removal of `letter` reports.
        fn try_removing(letter: u8) -> u32 {
            let local = [u16::from(letter), u16::from(b':'), 0];
            // SAFETY: `local` is NUL-terminated.
            unsafe { WNetCancelConnection2W(local.as_ptr(), 0, 0) }
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

        fn lpm_mapped(directory: &super::super::ScriptDirectory) -> bool {
            matches!(directory._drive, Some(DriveHold::Mapped { .. }))
        }

        /// The life of a letter LPM maps, in one test that reaches the
        /// share as `\\127.0.0.1\<drive>$`, which no other test maps or
        /// borrows, so no other process can hold its letters.
        #[test]
        fn a_drive_lpm_maps_lasts_as_long_as_anything_uses_it() {
            let _one_at_a_time = LIVE_DRIVES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let local = tempfile::tempdir().unwrap();
            let project = local.path().join("app");
            std::fs::create_dir(&project).unwrap();
            let Some(network) = crate::test_network_path::through_network_as(&project, "127.0.0.1")
            else {
                return;
            };

            // Two users share one letter, and it goes with the last.
            let first = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let second = super::super::ScriptDirectory::for_shell(&network).unwrap();
            assert!(lpm_mapped(&first), "{:?} was mapped already", first.path());
            assert_eq!(first.path(), second.path());
            assert!(network_folder(first.path()).is_none(), "{:?}", first.path());
            std::fs::write(first.path().join("written"), b"through the drive").unwrap();
            assert_eq!(
                std::fs::read(project.join("written")).unwrap(),
                b"through the drive"
            );
            let letter = letter_of(first.path());
            drop(first);
            assert!(
                mapped_remote(letter).is_some(),
                "the drive went while in use"
            );
            drop(second);
            assert_eq!(mapped_remote(letter), None, "the drive outlived its use");

            // A file still open through the letter, as another process's
            // script would have one, keeps it.
            let reached = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let letter = TestLetter(letter_of(reached.path()));
            let held_open = std::fs::File::open(reached.path().join("written")).unwrap();
            drop(reached);
            let while_open = mapped_remote(letter.0);
            drop(held_open);
            assert!(
                while_open.is_some(),
                "LPM removed a drive something still had a file open through"
            );
            assert_eq!(
                try_removing(letter.0),
                NO_ERROR,
                "the drive was still in use"
            );

            // A letter removed while held, as `net use /delete` would, is
            // mapped again. The earlier holder counts nothing against the new
            // mapping, which goes with its own last user.
            let earlier = super::super::ScriptDirectory::for_shell(&network).unwrap();
            assert!(
                lpm_mapped(&earlier),
                "{:?} was mapped already",
                earlier.path()
            );
            assert_eq!(try_removing(letter_of(earlier.path())), NO_ERROR);
            let again = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let still = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let again_letter = TestLetter(letter_of(again.path()));
            std::fs::write(again.path().join("written"), b"again").unwrap();
            assert_eq!(std::fs::read(project.join("written")).unwrap(), b"again");
            drop(earlier);
            drop(again);
            assert!(
                mapped_remote(again_letter.0).is_some(),
                "the earlier holder's drop counted against the new mapping"
            );
            drop(still);
            assert_eq!(
                mapped_remote(again_letter.0),
                None,
                "the new mapping outlived its last user"
            );
        }

        #[test]
        fn a_drive_someone_else_mapped_is_reused_and_kept_while_a_script_uses_it() {
            let _one_at_a_time = LIVE_DRIVES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let local = tempfile::tempdir().unwrap();
            let project = local.path().join("app");
            std::fs::create_dir(&project).unwrap();
            let Some(network) = crate::test_network_path::through_network(&project) else {
                return;
            };
            // Another process's mapping, as the user's or another LPM's, of
            // a folder no other test maps.
            let theirs =
                TestLetter(map_free_letter(network.parent().unwrap().as_os_str()).unwrap());
            let theirs_letter = theirs.0;

            let reached = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let removed_while_used = try_removing(theirs_letter);
            let path = reached.path().to_path_buf();
            drop(reached);
            let still_theirs = mapped_remote(theirs_letter);
            drop(theirs);

            assert_eq!(letter_of(&path), theirs_letter, "{path:?}");
            assert!(
                matches!(removed_while_used, ERROR_OPEN_FILES | ERROR_DEVICE_IN_USE),
                "a script's drive could be removed under it: {removed_while_used}"
            );
            assert!(still_theirs.is_some(), "LPM removed a drive it didn't map");
        }
    }
}
