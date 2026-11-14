//! The directory a script runs in, as the system shell can use it.
//!
//! cmd.exe can't run in a network folder: started in
//! `\\server\share\project`, it warns that UNC paths are not supported and
//! runs the script in the Windows directory instead. A script in a network
//! folder therefore runs through a drive letter: one the user mapped to the
//! folder's share, or one LPM gives the share while its scripts run there.

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
    /// for a network folder, the same folder through a drive letter. Without
    /// a letter the user mapped there, LPM defines one for this sign-in, as
    /// `subst` does, from `Z:` down, and removes its definition once nothing
    /// it runs uses it.
    ///
    /// # Errors
    ///
    /// On Windows, when no letter is free for a network folder, or Windows
    /// refuses to define one.
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

    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::WNet::WNetGetConnectionW;
    use windows_sys::Win32::Storage::FileSystem::{
        DDD_EXACT_MATCH_ON_REMOVE, DDD_NO_BROADCAST_SYSTEM, DDD_RAW_TARGET_PATH,
        DDD_REMOVE_DEFINITION, DefineDosDeviceW, GetLogicalDrives, QueryDosDeviceW,
    };

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

    /// What LPM defines a letter as for `share`, `\\server\share`: the NT
    /// path `\??\UNC\server\share`, which Windows hands to whichever network
    /// file system serves the share.
    fn definition_of(share: &OsStr) -> OsString {
        // `\\server\share` gives one of its leading separators to the prefix.
        let share: Vec<u16> = share.encode_wide().collect();
        let mut target: Vec<u16> = r"\??\UNC".encode_utf16().collect();
        target.extend_from_slice(share.get(1..).unwrap_or(&share));
        OsString::from_wide(&target)
    }

    /// The letters this process defined, by share, with how many
    /// [`super::ScriptDirectory`] values use each.
    static DEFINED: Mutex<Option<HashMap<OsString, Defined>>> = Mutex::new(None);

    #[derive(Debug)]
    struct Defined {
        letter: u8,
        definition: OsString,
        users: usize,
        /// Which definition of the share this is, so that the holders of one
        /// found gone count nothing against the next.
        generation: u64,
    }

    static NEXT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Keeps the drive letter a script reaches a network folder by.
    #[derive(Debug)]
    pub(super) enum DriveHold {
        /// A letter this process defined, whose definition goes with its
        /// last user.
        Defined { _hold: DefinedHold },
        /// A letter the user mapped, left as it is. The folder is kept open
        /// through it, which keeps Windows from removing the mapping without
        /// being forced to.
        Borrowed { _folder: std::fs::File },
    }

    #[derive(Debug)]
    pub(super) struct DefinedHold {
        share_key: OsString,
        generation: u64,
    }

    impl Drop for DefinedHold {
        fn drop(&mut self) {
            let mut defined = DEFINED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(letters) = defined.as_mut() else {
                return;
            };
            let last = match letters.get_mut(&self.share_key) {
                Some(entry) if entry.generation == self.generation => {
                    entry.users -= 1;
                    if entry.users == 0 {
                        letters.remove(&self.share_key)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(entry) = last
                && let Err(error) = undefine(entry.letter, &entry.definition)
            {
                tracing::debug!(
                    "could not remove the drive {}: LPM defined for scripts: {error}",
                    char::from(entry.letter)
                );
            }
        }
    }

    /// `folder` through a drive letter, and what keeps that letter.
    pub(super) fn through_drive(folder: &NetworkFolder) -> io::Result<(PathBuf, DriveHold)> {
        let share_key = folder.share.to_ascii_lowercase();
        let definition = definition_of(&folder.share);
        let mut defined = DEFINED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let letters = defined.get_or_insert_with(HashMap::new);
        if let Some(entry) = letters.get_mut(&share_key) {
            // Someone may have removed the definition since, or stacked one
            // of another share on it, which the letter then resolves to.
            if dos_definitions(entry.letter)
                .first()
                .is_some_and(|first| first.eq_ignore_ascii_case(&entry.definition))
            {
                entry.users += 1;
                let hold = DefinedHold {
                    share_key,
                    generation: entry.generation,
                };
                return Ok((
                    on_drive(entry.letter, &folder.below),
                    DriveHold::Defined { _hold: hold },
                ));
            }
            // Its holders count nothing against what comes next, and this
            // process's definition, if it is still there, goes now.
            if let Some(gone) = letters.remove(&share_key)
                && defines(gone.letter, &gone.definition)
            {
                let _ = undefine(gone.letter, &gone.definition);
            }
        }
        // Another LPM process's letter for the share, or one a crash left:
        // this process adds its own definition, which Windows stacks on the
        // same one, so the letter stays while either uses it.
        let letter = match (b'A'..=b'Z').find(|letter| {
            dos_definitions(*letter)
                .first()
                .is_some_and(|first| first.eq_ignore_ascii_case(&definition))
        }) {
            Some(letter) => {
                define(letter, &definition)?;
                letter
            }
            None => {
                if let Some((path, folder_handle)) = through_users_drive(folder) {
                    return Ok((
                        path,
                        DriveHold::Borrowed {
                            _folder: folder_handle,
                        },
                    ));
                }
                let letter = define_free_letter(&definition).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "cmd.exe can't run scripts in a network folder, so LPM reaches {} through a drive letter, but {error}",
                            folder.share.to_string_lossy()
                        ),
                    )
                })?;
                say_defined(&folder.share, letter);
                letter
            }
        };
        let generation = NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        letters.insert(
            share_key.clone(),
            Defined {
                letter,
                definition,
                users: 1,
                generation,
            },
        );
        Ok((
            on_drive(letter, &folder.below),
            DriveHold::Defined {
                _hold: DefinedHold {
                    share_key,
                    generation,
                },
            },
        ))
    }

    /// Says once in this process for each share and letter which letter LPM
    /// defined.
    fn say_defined(share: &OsStr, letter: u8) {
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

    /// `folder` through a drive letter the user mapped to its share, or to a
    /// folder of the share above it, with the folder held open through it.
    /// The letter mapped closest to `folder` wins, then the first. A letter
    /// counts only where the folder opened through it is `folder` itself:
    /// some network file systems answer for letters of another sign-in.
    fn through_users_drive(folder: &NetworkFolder) -> Option<(PathBuf, std::fs::File)> {
        let present = unsafe {
            // SAFETY: takes no arguments.
            GetLogicalDrives()
        };
        let mut reaching: Vec<(usize, u8, PathBuf)> = (b'A'..=b'Z')
            .filter(|letter| present & (1 << (letter - b'A')) != 0)
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
        reaching.into_iter().find_map(|(_, _, path)| {
            let handle = open_folder(&path).ok()?;
            is_folder(&handle, folder).then_some((path, handle))
        })
    }

    /// Whether the open `handle` is `folder`: whether both final paths, as
    /// the network file system resolves them, are one.
    fn is_folder(handle: &std::fs::File, folder: &NetworkFolder) -> bool {
        let Ok(reached) = crate::owner_only::final_path(handle) else {
            return false;
        };
        open_folder(&on_share(folder))
            .and_then(|direct| crate::owner_only::final_path(&direct))
            .is_ok_and(|direct| direct.as_os_str().eq_ignore_ascii_case(reached.as_os_str()))
    }

    /// `folder` as a network path, as in `\\server\share\app`.
    fn on_share(folder: &NetworkFolder) -> PathBuf {
        let mut path = PathBuf::from(&folder.share);
        for name in &folder.below {
            path.push(name);
        }
        path
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

    /// What the network drive `letter` is mapped to, as in `\\server\share`;
    /// `None` when it isn't one, or Windows can't tell.
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

    /// What the drive `letter` is defined as for this sign-in, the most
    /// recent definition first; empty when it isn't defined.
    fn dos_definitions(letter: u8) -> Vec<OsString> {
        let local = [u16::from(letter), u16::from(b':'), 0];
        let mut buffer = vec![0_u16; 1024];
        loop {
            let Ok(capacity) = u32::try_from(buffer.len()) else {
                return Vec::new();
            };
            let written = unsafe {
                // SAFETY: `local` is NUL-terminated, and `buffer` holds `capacity` units.
                QueryDosDeviceW(local.as_ptr(), buffer.as_mut_ptr(), capacity)
            } as usize;
            if written != 0 {
                return buffer[..written]
                    .split(|unit| *unit == 0)
                    .filter(|definition| !definition.is_empty())
                    .map(OsString::from_wide)
                    .collect();
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER as i32)
                && buffer.len() < 65_536
            {
                buffer.resize(buffer.len() * 4, 0);
                continue;
            }
            return Vec::new();
        }
    }

    /// Whether `definition` is among the drive `letter`'s definitions.
    fn defines(letter: u8, definition: &OsStr) -> bool {
        dos_definitions(letter)
            .iter()
            .any(|present| present.eq_ignore_ascii_case(definition))
    }

    fn define(letter: u8, definition: &OsStr) -> io::Result<()> {
        let local = [u16::from(letter), u16::from(b':'), 0];
        let target: Vec<u16> = definition.encode_wide().chain(Some(0)).collect();
        let defined = unsafe {
            // SAFETY: both names are NUL-terminated. Without a broadcast, no window hears of
            // a letter that exists only for LPM's scripts.
            DefineDosDeviceW(
                DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                local.as_ptr(),
                target.as_ptr(),
            )
        };
        if defined == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Removes one definition of the drive `letter` as `definition`, this
    /// process's own; a definition stacked on it by another process stays.
    fn undefine(letter: u8, definition: &OsStr) -> io::Result<()> {
        let local = [u16::from(letter), u16::from(b':'), 0];
        let target: Vec<u16> = definition.encode_wide().chain(Some(0)).collect();
        let removed = unsafe {
            // SAFETY: both names are NUL-terminated.
            DefineDosDeviceW(
                DDD_RAW_TARGET_PATH
                    | DDD_REMOVE_DEFINITION
                    | DDD_EXACT_MATCH_ON_REMOVE
                    | DDD_NO_BROADCAST_SYSTEM,
                local.as_ptr(),
                target.as_ptr(),
            )
        };
        if removed == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Defines the first free drive letter from `Z:` down as `definition`.
    /// A letter something else defined in the meantime is given back.
    fn define_free_letter(definition: &OsStr) -> io::Result<u8> {
        let present = unsafe {
            // SAFETY: takes no arguments.
            GetLogicalDrives()
        };
        for letter in (b'D'..=b'Z').rev() {
            if present & (1 << (letter - b'A')) != 0 || !dos_definitions(letter).is_empty() {
                continue;
            }
            define(letter, definition).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("defining {}: failed: {error}", char::from(letter)),
                )
            })?;
            if dos_definitions(letter).len() == 1 {
                return Ok(letter);
            }
            let _ = undefine(letter, definition);
        }
        Err(io::Error::other(
            "no drive letter is free: free one, or map one to the share yourself",
        ))
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
        fn a_share_is_defined_as_its_unc_device_path() {
            assert_eq!(
                definition_of(OsStr::new(r"\\Mac\Home")),
                OsString::from(r"\??\UNC\Mac\Home")
            );
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
        /// the registry of the letters this process defined.
        static LIVE_DRIVES: Mutex<()> = Mutex::new(());

        fn letter_of(path: &Path) -> u8 {
            let Some(Component::Prefix(prefix)) = path.components().next() else {
                panic!("{path:?} has no drive");
            };
            let Prefix::Disk(letter) = prefix.kind() else {
                panic!("{path:?} has no drive letter");
            };
            letter
        }

        fn lpm_defined(directory: &super::super::ScriptDirectory) -> bool {
            matches!(directory._drive, Some(DriveHold::Defined { .. }))
        }

        /// The life of a letter LPM defines, in one test that reaches the
        /// share as `\\127.0.0.1\<drive>$`, which no other test reaches.
        #[test]
        fn a_drive_lpm_defines_lasts_as_long_as_anything_uses_it() {
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
            let definition = definition_of(&network_folder(&network).unwrap().share);

            // Two users share one letter, and its definition goes with the
            // last.
            let first = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let second = super::super::ScriptDirectory::for_shell(&network).unwrap();
            assert!(lpm_defined(&first), "{:?}", first.path());
            assert_eq!(first.path(), second.path());
            std::fs::write(first.path().join("written"), b"through the drive").unwrap();
            assert_eq!(
                std::fs::read(project.join("written")).unwrap(),
                b"through the drive"
            );
            let letter = letter_of(first.path());
            drop(first);
            assert!(defines(letter, &definition), "the drive went while in use");
            drop(second);
            assert!(
                dos_definitions(letter).is_empty(),
                "the drive outlived its use"
            );

            // Another process's definition of the same letter, stacked on
            // this one's, outlives it.
            let reached = super::super::ScriptDirectory::for_shell(&network).unwrap();
            assert!(lpm_defined(&reached), "{:?}", reached.path());
            let letter = letter_of(reached.path());
            define(letter, &definition).unwrap();
            drop(reached);
            let left_for_the_other = defines(letter, &definition);
            undefine(letter, &definition).unwrap();
            assert!(
                left_for_the_other,
                "LPM removed another process's definition"
            );
            assert!(dos_definitions(letter).is_empty());

            // A definition removed while held, by someone else, is made
            // again. The earlier holder counts nothing against the new one,
            // which goes with its own last user.
            let earlier = super::super::ScriptDirectory::for_shell(&network).unwrap();
            assert!(lpm_defined(&earlier), "{:?}", earlier.path());
            undefine(letter_of(earlier.path()), &definition).unwrap();
            let again = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let still = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let again_letter = letter_of(again.path());
            std::fs::write(again.path().join("written"), b"again").unwrap();
            assert_eq!(std::fs::read(project.join("written")).unwrap(), b"again");
            drop(earlier);
            drop(again);
            assert!(
                defines(again_letter, &definition),
                "the earlier holder's drop counted against the new definition"
            );
            drop(still);
            assert!(
                dos_definitions(again_letter).is_empty(),
                "the new definition outlived its last user"
            );

            // A definition of another share stacked on the letter takes it
            // over, so the next script reaches the folder by another letter.
            let held = super::super::ScriptDirectory::for_shell(&network).unwrap();
            assert!(lpm_defined(&held), "{:?}", held.path());
            let taken = letter_of(held.path());
            let other = definition_of(OsStr::new(r"\\127.0.0.1\IPC$"));
            define(taken, &other).unwrap();
            let next = super::super::ScriptDirectory::for_shell(&network);
            undefine(taken, &other).unwrap();
            let next = next.unwrap();
            assert_ne!(letter_of(next.path()), taken, "{:?}", next.path());
            std::fs::write(next.path().join("written"), b"elsewhere").unwrap();
            assert_eq!(
                std::fs::read(project.join("written")).unwrap(),
                b"elsewhere"
            );
            drop(held);
            drop(next);
        }

        /// A drive mapped the way `net use` maps one, through the SMB
        /// redirector alone, so that its removal can't reach another
        /// network file system's drives.
        struct UsersDrive(u8);

        impl UsersDrive {
            fn map(remote: &Path) -> Self {
                use windows_sys::Win32::NetworkManagement::NetManagement::{
                    NetUseAdd, USE_DISKDEV, USE_INFO_1,
                };
                let present = unsafe {
                    // SAFETY: takes no arguments.
                    GetLogicalDrives()
                };
                let letter = (b'D'..=b'Z')
                    .rev()
                    .find(|letter| {
                        present & (1 << (letter - b'A')) == 0 && dos_definitions(*letter).is_empty()
                    })
                    .expect("a free drive letter");
                let mut local: Vec<u16> = format!("{}:", char::from(letter))
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                let mut remote: Vec<u16> =
                    remote.as_os_str().encode_wide().chain(Some(0)).collect();
                let information = USE_INFO_1 {
                    ui1_local: local.as_mut_ptr(),
                    ui1_remote: remote.as_mut_ptr(),
                    ui1_password: std::ptr::null_mut(),
                    ui1_status: 0,
                    ui1_asg_type: USE_DISKDEV,
                    ui1_refcount: 0,
                    ui1_usecount: 0,
                };
                // SAFETY: `information` points at NUL-terminated names that outlive the call.
                let status = unsafe {
                    NetUseAdd(
                        std::ptr::null(),
                        1,
                        std::ptr::from_ref(&information).cast(),
                        std::ptr::null_mut(),
                    )
                };
                assert_eq!(status, NO_ERROR, "NetUseAdd failed");
                Self(letter)
            }

            /// What a removal that isn't forced reports.
            fn remove(&self) -> u32 {
                use windows_sys::Win32::NetworkManagement::NetManagement::{
                    NetUseDel, USE_NOFORCE,
                };
                let local: Vec<u16> = format!("{}:", char::from(self.0))
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                // SAFETY: `local` is NUL-terminated.
                unsafe { NetUseDel(std::ptr::null(), local.as_ptr(), USE_NOFORCE) }
            }
        }

        impl Drop for UsersDrive {
            fn drop(&mut self) {
                self.remove();
            }
        }

        #[test]
        fn a_drive_the_user_mapped_is_reused_and_kept_while_a_script_uses_it() {
            let _one_at_a_time = LIVE_DRIVES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let local = tempfile::tempdir().unwrap();
            let project = local.path().join("app");
            std::fs::create_dir(&project).unwrap();
            let Some(network) = crate::test_network_path::through_network(&project) else {
                return;
            };
            // Of a folder no other test maps.
            let users = UsersDrive::map(network.parent().unwrap());

            let reached = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let removed_while_used = users.remove();
            let path = reached.path().to_path_buf();
            drop(reached);
            let still_mapped = mapped_remote(users.0);

            assert_eq!(letter_of(&path), users.0, "{path:?}");
            assert_eq!(
                removed_while_used,
                windows_sys::Win32::Foundation::ERROR_OPEN_FILES,
                "a script's drive could be removed under it"
            );
            assert!(
                still_mapped.is_some(),
                "LPM removed a drive the user mapped"
            );
        }
    }
}
