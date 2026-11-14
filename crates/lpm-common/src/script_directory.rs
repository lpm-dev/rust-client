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
    /// it runs uses it. Running as LocalSystem, Windows defines it for every
    /// session instead. One a crash leaves stays until sign-out, or until
    /// `subst <letter>: /d` removes it.
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

    /// The letters this process defined, with how many
    /// [`super::ScriptDirectory`] values use each.
    static DEFINED: Mutex<Option<Letters>> = Mutex::new(None);

    fn lock_defined() -> std::sync::MutexGuard<'static, Option<Letters>> {
        DEFINED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[derive(Debug, Default)]
    struct Letters {
        /// The letter each share is reached by, by share.
        current: HashMap<OsString, Defined>,
        /// Letters another share's definition took over, by generation. Each
        /// keeps this process's definition while scripts started through it
        /// run, so that it reaches their share again once the other goes.
        set_aside: HashMap<u64, Defined>,
    }

    impl Letters {
        /// One user fewer of the definition `generation` of the share
        /// `share_key`: the definition, once none is left.
        fn release(&mut self, share_key: &OsStr, generation: u64) -> Option<Defined> {
            if self
                .current
                .get(share_key)
                .is_some_and(|entry| entry.generation == generation)
            {
                let entry = self.current.get_mut(share_key)?;
                entry.users -= 1;
                return if entry.users == 0 {
                    self.current.remove(share_key)
                } else {
                    None
                };
            }
            let entry = self.set_aside.get_mut(&generation)?;
            entry.users -= 1;
            if entry.users == 0 {
                self.set_aside.remove(&generation)
            } else {
                None
            }
        }
    }

    #[derive(Debug)]
    struct Defined {
        letter: u8,
        definition: OsString,
        users: usize,
        /// Which definition of the share this is, so that each holder counts
        /// against its own, whether current or set aside.
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
            let mut defined = lock_defined();
            let Some(last) = defined
                .as_mut()
                .and_then(|letters| letters.release(&self.share_key, self.generation))
            else {
                return;
            };
            let _letters_of_the_sign_in = LetterLock::acquire();
            if let Err(error) = undefine(last.letter, &last.definition) {
                tracing::debug!(
                    "could not remove the drive {}: LPM defined for scripts: {error}",
                    char::from(last.letter)
                );
            }
        }
    }

    /// `folder` through a drive letter, and what keeps that letter.
    pub(super) fn through_drive(folder: &NetworkFolder) -> io::Result<(PathBuf, DriveHold)> {
        let share_key = folder.share.to_ascii_lowercase();
        let reached = through_defined_letter(&mut lock_defined(), &share_key, folder);
        if let Some(reached) = reached {
            return Ok(reached);
        }
        // Then a letter the user mapped. Looking for one opens network
        // folders, so it holds no lock: a share slow to answer delays only
        // the scripts in it.
        if let Some((path, folder_handle)) = through_users_drive(folder) {
            return Ok((
                path,
                DriveHold::Borrowed {
                    _folder: folder_handle,
                },
            ));
        }
        let mut defined = lock_defined();
        // Another thread may have defined one meanwhile.
        if let Some(reached) = through_defined_letter(&mut defined, &share_key, folder) {
            return Ok(reached);
        }
        let _letters_of_the_sign_in = LetterLock::acquire();
        let definition = definition_of(&folder.share);
        // Then another LPM process's letter for the share, or one a crash
        // left: this process adds its own definition, which Windows stacks on
        // the same one, so the letter stays while either uses it. Something
        // outside LPM may have taken the letter in between, which the
        // definitions then show.
        let mut stacked = None;
        if let Some(candidate) = (b'A'..=b'Z').find(|letter| {
            dos_definitions(*letter)
                .first()
                .is_some_and(|first| first.eq_ignore_ascii_case(&definition))
        }) && define(candidate, &definition).is_ok()
        {
            if dos_definitions(candidate)
                .iter()
                .all(|present| present.eq_ignore_ascii_case(&definition))
            {
                stacked = Some(candidate);
            } else {
                let _ = undefine(candidate, &definition);
            }
        }
        let letter = match stacked {
            Some(letter) => letter,
            None => define_free_letter(&definition).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cmd.exe can't run scripts in a network folder, so LPM reaches {} through a drive letter, but {error}",
                        folder.share.to_string_lossy()
                    ),
                )
            })?,
        };
        say_defined(&folder.share, letter);
        let generation = NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        defined.get_or_insert_with(Letters::default).current.insert(
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

    /// `folder` through the letter this process defined for its share, while
    /// that definition is the one in effect. Someone may have removed it
    /// since, or stacked another share's definition on it, which the letter
    /// then resolves to: such a letter is set aside for the scripts started
    /// through it, and the share is to be reached by another.
    fn through_defined_letter(
        defined: &mut Option<Letters>,
        share_key: &OsStr,
        folder: &NetworkFolder,
    ) -> Option<(PathBuf, DriveHold)> {
        let letters = defined.get_or_insert_with(Letters::default);
        let entry = letters.current.get_mut(share_key)?;
        if dos_definitions(entry.letter)
            .first()
            .is_some_and(|first| first.eq_ignore_ascii_case(&entry.definition))
        {
            entry.users += 1;
            return Some((
                on_drive(entry.letter, &folder.below),
                DriveHold::Defined {
                    _hold: DefinedHold {
                        share_key: share_key.to_os_string(),
                        generation: entry.generation,
                    },
                },
            ));
        }
        let taken_over = letters.current.remove(share_key)?;
        if defines(taken_over.letter, &taken_over.definition) {
            letters.set_aside.insert(taken_over.generation, taken_over);
        }
        None
    }

    /// Says once in this process for each share and letter which letter LPM
    /// defined for the share, whether that letter is new or another LPM
    /// process's, which the scripts reach their folder by all the same.
    fn say_defined(share: &OsStr, letter: u8) {
        #[cfg(test)]
        tests::SAID_DEFINED.with_borrow_mut(|said| said.push((share.to_ascii_lowercase(), letter)));
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
    /// some network file systems answer for letters of another sign-in. A
    /// letter defined straight to a network path, as LPM defines one, is no
    /// drive the user mapped: borrowed, it would go with the last script of
    /// whoever defined it, while stacking on it keeps it.
    fn through_users_drive(folder: &NetworkFolder) -> Option<(PathBuf, std::fs::File)> {
        let present = unsafe {
            // SAFETY: takes no arguments.
            GetLogicalDrives()
        };
        users_drives_reaching(folder, present, dos_definitions, mapped_remote)
            .into_iter()
            .find_map(|path| {
                let handle = open_folder(&path).ok()?;
                is_folder(&handle, folder).then_some((path, handle))
            })
    }

    /// `folder` through each letter the user mapped to its share or a folder
    /// above it, closest first, then by letter: among the `present` letters,
    /// as `definitions` says each is defined and `mapped_to` what each is
    /// mapped to.
    fn users_drives_reaching(
        folder: &NetworkFolder,
        present: u32,
        definitions: impl Fn(u8) -> Vec<OsString>,
        mapped_to: impl Fn(u8) -> Option<OsString>,
    ) -> Vec<PathBuf> {
        let mut reaching: Vec<(usize, u8, PathBuf)> = (b'A'..=b'Z')
            .filter(|letter| present & (1 << (letter - b'A')) != 0)
            .filter(|letter| {
                !definitions(*letter)
                    .first()
                    .is_some_and(|definition| names_a_network_path(definition))
            })
            .filter_map(|letter| {
                let remote = mapped_to(letter)?;
                let remote = network_folder(Path::new(&remote))?;
                let below = folder
                    .below
                    .strip_prefix_ignore_case(&remote, &folder.share)?;
                Some((remote.below.len(), letter, on_drive(letter, below)))
            })
            .collect();
        reaching.sort_by_key(|(depth, letter, _)| (std::cmp::Reverse(*depth), *letter));
        reaching.into_iter().map(|(_, _, path)| path).collect()
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

    /// Whether a drive's `definition` names a network path straight, as
    /// LPM's do, rather than a network file system's own device, as a mapped
    /// drive's does.
    fn names_a_network_path(definition: &OsStr) -> bool {
        definition
            .as_encoded_bytes()
            .get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case(br"\??\UNC\"))
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

    /// Whether the user's network drive `letter` is remembered, connected or
    /// not: a remembered drive that is unavailable now has no definition,
    /// and would fail to reconnect onto one of LPM's.
    fn is_remembered(letter: u8) -> bool {
        use windows_sys::Win32::Foundation::ERROR_CONNECTION_UNAVAIL;
        let local = [u16::from(letter), u16::from(b':'), 0];
        let mut buffer = [0_u16; 1];
        let mut length = 1_u32;
        let status = unsafe {
            // SAFETY: `local` is NUL-terminated, and `buffer` holds `length` writable units.
            WNetGetConnectionW(local.as_ptr(), buffer.as_mut_ptr(), &mut length)
        };
        matches!(
            status,
            NO_ERROR | ERROR_MORE_DATA | ERROR_CONNECTION_UNAVAIL
        )
    }

    /// Serializes choosing, defining and removing letters among the LPM
    /// processes of this sign-in, so that two never take one letter for
    /// different shares at once. Without it, as when the mutex can't be had
    /// in time, the checks after each definition still apply, so the wait for
    /// it is short.
    struct LetterLock(windows_sys::Win32::Foundation::HANDLE);

    impl LetterLock {
        fn acquire() -> Option<Self> {
            use windows_sys::Win32::Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0};
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            let handle = open_letter_lock()?;
            // SAFETY: `handle` is the mutex just opened. An abandoned mutex, left by a
            // process that ended while holding it, is owned all the same.
            let waited = unsafe { WaitForSingleObject(handle, 2_000) };
            if waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED {
                Some(Self(handle))
            } else {
                // SAFETY: `handle` is open and not owned.
                unsafe { CloseHandle(handle) };
                None
            }
        }
    }

    impl Drop for LetterLock {
        fn drop(&mut self) {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::ReleaseMutex;
            // SAFETY: this process owns the mutex `self.0`, opened in `acquire`.
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }

    /// Opens the mutex of this sign-in's letters, with only the rights to
    /// wait on it and release it.
    fn open_letter_lock() -> Option<windows_sys::Win32::Foundation::HANDLE> {
        use windows_sys::Win32::System::Threading::{
            CreateMutexExW, MUTEX_MODIFY_STATE, SYNCHRONIZATION_SYNCHRONIZE,
        };
        let name = letter_lock_name()?;
        // SAFETY: `name` is NUL-terminated; default security and no initial owner.
        let handle = unsafe {
            CreateMutexExW(
                std::ptr::null(),
                name.as_ptr(),
                0,
                SYNCHRONIZATION_SYNCHRONIZE | MUTEX_MODIFY_STATE,
            )
        };
        (!handle.is_null()).then_some(handle)
    }

    /// The name of the mutex of this sign-in's letters. Letters a process
    /// defines belong to its sign-in, which an elevated process has apart
    /// from the unelevated ones of the same session.
    fn letter_lock_name() -> Option<&'static [u16]> {
        static NAME: std::sync::OnceLock<Option<Vec<u16>>> = std::sync::OnceLock::new();
        NAME.get_or_init(|| {
            let sign_in = sign_in_id().ok()?;
            Some(
                format!(r"Local\lpm-script-drive-letters-{sign_in:016x}")
                    .encode_utf16()
                    .chain(Some(0))
                    .collect(),
            )
        })
        .as_deref()
    }

    /// The sign-in this process runs in: its token's authentication ID.
    fn sign_in_id() -> io::Result<u64> {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_QUERY, TOKEN_STATISTICS, TokenStatistics,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle is valid; `token` receives a handle closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a zeroed TOKEN_STATISTICS is a valid output buffer.
        let mut statistics: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
        let mut length = 0;
        // SAFETY: `statistics` holds as many writable bytes as the length passed.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenStatistics,
                std::ptr::from_mut(&mut statistics).cast(),
                std::mem::size_of_val(&statistics) as u32,
                &mut length,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: `token` is open and closed once here.
        unsafe { CloseHandle(token) };
        if read == 0 {
            return Err(error);
        }
        let id = statistics.AuthenticationId;
        Ok((u64::from(id.HighPart.cast_unsigned()) << 32) | u64::from(id.LowPart))
    }

    /// Defines the first free drive letter from `Z:` down as `definition`.
    /// A letter something else defined in the meantime is given back.
    fn define_free_letter(definition: &OsStr) -> io::Result<u8> {
        let present = unsafe {
            // SAFETY: takes no arguments.
            GetLogicalDrives()
        };
        for letter in (b'D'..=b'Z').rev() {
            if present & (1 << (letter - b'A')) != 0
                || !dos_definitions(letter).is_empty()
                || is_remembered(letter)
            {
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

        std::thread_local! {
            /// Each share and letter LPM said it defined on this thread,
            /// before telling apart what was said before.
            pub(super) static SAID_DEFINED: std::cell::RefCell<Vec<(OsString, u8)>> =
                const { std::cell::RefCell::new(Vec::new()) };
        }

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
        fn a_letter_defined_as_lpm_defines_one_names_a_network_path_and_a_mapped_drive_does_not() {
            for definition in [
                definition_of(OsStr::new(r"\\Mac\Home")),
                OsString::from(r"\??\unc\server\share"),
            ] {
                assert!(names_a_network_path(&definition), "{definition:?}");
            }
            for definition in [
                r"\Device\LanmanRedirector\;Z:000000000001e3a2\server\share",
                r"\Device\Mup\;LanmanRedirector\;Z:000000000001e3a2\server\share",
                r"\??\C:\work",
                r"\??\UN",
                "",
            ] {
                assert!(
                    !names_a_network_path(OsStr::new(definition)),
                    "{definition:?}"
                );
            }
        }

        #[test]
        fn the_letters_lock_is_named_for_this_sign_in() {
            let sign_in = sign_in_id().unwrap();
            let name = String::from_utf16(letter_lock_name().unwrap()).unwrap();

            assert_ne!(sign_in, 0);
            assert_eq!(
                name,
                format!("Local\\lpm-script-drive-letters-{sign_in:016x}\0")
            );
            // Opened, not owned: a live drive test may own it meanwhile.
            let opened = open_letter_lock().expect("the letters' lock couldn't be opened");
            // SAFETY: `opened` is the mutex just opened, closed once here.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(opened) };
        }

        #[test]
        fn a_letter_another_process_defined_is_not_taken_for_one_the_user_mapped() {
            let folder = network_folder(Path::new(r"\\Mac\Home\work\app")).unwrap();
            let present = b"WXY"
                .iter()
                .fold(0_u32, |present, letter| present | (1 << (letter - b'A')));

            let reaching = users_drives_reaching(
                &folder,
                present,
                |letter| match letter {
                    b'X' => vec![definition_of(OsStr::new(r"\\Mac\Home"))],
                    b'W' | b'Y' => vec![OsString::from(format!(
                        r"\Device\LanmanRedirector\;{}:000000000001e3a2\Mac\Home",
                        char::from(letter)
                    ))],
                    _ => Vec::new(),
                },
                // Some network file systems answer for a letter LPM defined
                // as for one the user mapped.
                |letter| match letter {
                    b'W' | b'X' => Some(OsString::from(r"\\Mac\Home")),
                    b'Y' => Some(OsString::from(r"\\Mac\Home\work")),
                    _ => None,
                },
            );

            assert_eq!(
                reaching,
                [PathBuf::from(r"Y:\app"), PathBuf::from(r"W:\work\app")]
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

            // A letter another process defined for the share is used, with a
            // definition of this process's own stacked on it, and is said as
            // a letter LPM defines is. It keeps the other's definition after
            // this one is done.
            let theirs = define_as_another_process_would(&definition);
            SAID_DEFINED.take();
            let joined = super::super::ScriptDirectory::for_shell(&network).unwrap();
            let said = SAID_DEFINED.take();
            let joined_letter = letter_of(joined.path());
            let stacked_on_theirs = dos_definitions(theirs).len();
            drop(joined);
            let theirs_left = defines(theirs, &definition);
            undefine(theirs, &definition).unwrap();
            assert_eq!(joined_letter, theirs, "{joined_letter}");
            assert_eq!(stacked_on_theirs, 2);
            assert!(theirs_left, "LPM removed the other process's definition");
            assert_eq!(
                said,
                [(
                    network_folder(&network).unwrap().share.to_ascii_lowercase(),
                    theirs
                )],
                "LPM didn't say which letter it reached the share by"
            );

            // A definition of another share stacked on the letter takes it
            // over, so the next script reaches the folder by another letter.
            // The letter keeps this process's definition for the script still
            // using it, which reaches its folder again once the other's goes,
            // and loses it with that script.
            let held = super::super::ScriptDirectory::for_shell(&network).unwrap();
            assert!(lpm_defined(&held), "{:?}", held.path());
            let taken = letter_of(held.path());
            let other = definition_of(OsStr::new(r"\\127.0.0.1\IPC$"));
            define(taken, &other).unwrap();
            let next = super::super::ScriptDirectory::for_shell(&network);
            undefine(taken, &other).unwrap();
            let next = next.unwrap();
            let next_letter = letter_of(next.path());
            let written_elsewhere = std::fs::write(next.path().join("written"), b"elsewhere")
                .and_then(|()| std::fs::read(project.join("written")));
            let back_for_the_holder = dos_definitions(taken);
            drop(held);
            let left_by_the_holder = dos_definitions(taken);
            drop(next);
            assert_ne!(next_letter, taken);
            assert_eq!(written_elsewhere.unwrap(), b"elsewhere");
            assert!(
                back_for_the_holder.len() == 1
                    && back_for_the_holder[0].eq_ignore_ascii_case(&definition),
                "the letter was taken from the script still using it: {back_for_the_holder:?}"
            );
            assert!(
                left_by_the_holder.is_empty(),
                "the letter outlived its last user: {left_by_the_holder:?}"
            );
            assert!(dos_definitions(next_letter).is_empty());
        }

        /// Defines a free letter as `definition`, as another LPM process
        /// would, under the lock LPM processes choose letters under.
        fn define_as_another_process_would(definition: &OsStr) -> u8 {
            let _letters_of_the_sign_in = LetterLock::acquire();
            define_free_letter(definition).unwrap()
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
                let _letters_of_the_sign_in = LetterLock::acquire();
                let present = unsafe {
                    // SAFETY: takes no arguments.
                    GetLogicalDrives()
                };
                let mut wide_remote: Vec<u16> =
                    remote.as_os_str().encode_wide().chain(Some(0)).collect();
                let mut tried = Vec::new();
                // A network file system can answer for a letter of another
                // sign-in, as Parallels' answers in an elevated session for
                // the user's drives, and LPM rightly takes no such letter for
                // the user's: the test needs one that reads back as mapped.
                for letter in (b'D'..=b'Z').rev().filter(|letter| {
                    present & (1 << (letter - b'A')) == 0 && dos_definitions(*letter).is_empty()
                }) {
                    let mut local: Vec<u16> = format!("{}:", char::from(letter))
                        .encode_utf16()
                        .chain(Some(0))
                        .collect();
                    let information = USE_INFO_1 {
                        ui1_local: local.as_mut_ptr(),
                        ui1_remote: wide_remote.as_mut_ptr(),
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
                    if status != NO_ERROR {
                        tried.push(format!(
                            "{}: NetUseAdd failed with {status}",
                            char::from(letter)
                        ));
                        continue;
                    }
                    let drive = Self(letter);
                    let read_back = mapped_remote(letter);
                    if read_back
                        .as_deref()
                        .is_some_and(|mapped| same_remote(mapped, remote.as_os_str()))
                    {
                        return drive;
                    }
                    tried.push(format!(
                        "{}: reads back as {read_back:?}",
                        char::from(letter)
                    ));
                }
                panic!(
                    "no free drive letter could be mapped to {} and read back as it: {tried:?}",
                    remote.display()
                );
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

        /// Whether two network paths name one folder, as Windows compares
        /// them: without regard to ASCII case or a trailing separator.
        fn same_remote(one: &OsStr, other: &OsStr) -> bool {
            let trimmed = |path: &OsStr| {
                let mut units: Vec<u16> = path.encode_wide().collect();
                while units.last() == Some(&u16::from(b'\\')) {
                    units.pop();
                }
                OsString::from_wide(&units)
            };
            trimmed(one).eq_ignore_ascii_case(trimmed(other))
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
            // It comes before a letter another LPM process defined for the
            // share.
            let definition = definition_of(&network_folder(&network).unwrap().share);
            let theirs = define_as_another_process_would(&definition);

            let reached = super::super::ScriptDirectory::for_shell(&network);
            let theirs_left = dos_definitions(theirs);
            undefine(theirs, &definition).unwrap();
            let reached = reached.unwrap();
            let removed_while_used = users.remove();
            let path = reached.path().to_path_buf();
            drop(reached);
            let still_mapped = mapped_remote(users.0);

            assert_eq!(letter_of(&path), users.0, "{path:?}");
            assert_eq!(theirs_left.len(), 1, "{theirs_left:?}");
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
