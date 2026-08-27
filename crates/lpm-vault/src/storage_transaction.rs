use std::ffi::OsStr;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

const TRANSACTION_LOCK_NAME: &str = ".vault-keychain.lock";

pub(crate) struct VaultStorageDirectory {
    directory: Dir,
    display: PathBuf,
}

impl VaultStorageDirectory {
    fn open_lpm() -> Result<Self, String> {
        let home = crate::lpm_home_dir().ok_or_else(|| "no home directory".to_owned())?;
        let home_directory = Dir::open_ambient_dir(&home, ambient_authority())
            .map_err(|error| format!("failed to open home directory: {error}"))?;
        Self::open_or_create_child(&home_directory, &home, OsStr::new(".lpm"))
    }

    pub(crate) fn open_or_create_directory(&self, name: &str) -> Result<Self, String> {
        validate_name(OsStr::new(name))?;
        Self::open_or_create_child(&self.directory, &self.display, OsStr::new(name))
    }

    fn open_or_create_child(
        parent: &Dir,
        parent_display: &Path,
        name: &OsStr,
    ) -> Result<Self, String> {
        validate_name(name)?;
        let display = parent_display.join(name);
        let directory = match parent.open_dir_nofollow(name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                let builder = {
                    use cap_std::fs::DirBuilderExt as _;
                    let mut builder = cap_std::fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder
                };
                #[cfg(not(unix))]
                let builder = cap_std::fs::DirBuilder::new();
                match parent.create_dir_with(name, &builder) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(format!(
                            "failed to create protected vault directory {}: {error}",
                            display.display()
                        ));
                    }
                }
                parent.open_dir_nofollow(name).map_err(|error| {
                    format!(
                        "refusing vault directory that is not a real directory at {}: {error}",
                        display.display()
                    )
                })?
            }
            Err(error) => {
                return Err(format!(
                    "refusing vault directory that is not a real directory at {}: {error}",
                    display.display()
                ));
            }
        };

        let metadata = directory
            .dir_metadata()
            .map_err(|error| format!("failed to inspect {}: {error}", display.display()))?;
        if !metadata.is_dir() || metadata_is_link_or_reparse(&metadata) {
            return Err(format!(
                "refusing vault directory that is not a real directory at {}",
                display.display()
            ));
        }
        #[cfg(unix)]
        {
            use cap_std::fs::{MetadataExt as _, Permissions, PermissionsExt as _};

            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(format!(
                    "refusing vault directory not owned by the current user at {}",
                    display.display()
                ));
            }
            directory
                .set_permissions(".", Permissions::from_mode(0o700))
                .map_err(|error| format!("failed to secure {}: {error}", display.display()))?;
        }
        #[cfg(windows)]
        windows_security::protect_directory(&directory)
            .map_err(|error| format!("failed to secure {}: {error}", display.display()))?;

        Ok(Self { directory, display })
    }

    fn open_lock(&self, name: &str, label: &str) -> Result<std::fs::File, String> {
        validate_name(OsStr::new(name))?;
        let name = OsStr::new(name);
        let mut options = OpenOptions::new();
        options
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};

            options.access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC);
        }
        let file = {
            const TRANSIENT_NOT_FOUND_RETRIES: usize = 2;
            let mut retries = 0;
            loop {
                match self.directory.open_with(name, &options) {
                    Ok(file) => break file,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound
                            && retries < TRANSIENT_NOT_FOUND_RETRIES =>
                    {
                        retries += 1;
                    }
                    Err(error) => return Err(format!("failed to open {label}: {error}")),
                }
            }
        };
        self.validate_regular_file(&file, name, true)?;
        #[cfg(unix)]
        {
            use cap_std::fs::{Permissions, PermissionsExt as _};
            file.set_permissions(Permissions::from_mode(0o600))
                .map_err(|error| format!("failed to secure {label}: {error}"))?;
        }
        Ok(file.into_std())
    }

    pub(crate) fn read_owner_only_file(
        &self,
        name: &str,
        label: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        validate_name(OsStr::new(name))?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Foundation::GENERIC_READ;
            use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};

            options.access_mode(GENERIC_READ | READ_CONTROL | WRITE_DAC);
        }
        let file = match self.directory.open_with(name, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("failed to open {label}: {error}")),
        };
        self.validate_regular_file(&file, OsStr::new(name), true)?;
        let path = self.display.join(name);
        let (data, _) = lpm_common::read_file_capped_from_open_file(
            file.into_std(),
            &path,
            lpm_common::STATE_FILE_SIZE_CAP_BYTES,
        )
        .map_err(|error| format!("failed to read {label}: {error}"))?;
        Ok(Some(data))
    }

    pub(crate) fn write_owner_only_file(
        &self,
        name: &str,
        contents: &[u8],
        label: &str,
    ) -> Result<(), String> {
        validate_name(OsStr::new(name))?;
        lpm_common::write_file_atomic_in_dir_with(
            &self.directory,
            OsStr::new(name),
            |file| -> std::io::Result<()> {
                #[cfg(unix)]
                {
                    use cap_std::fs::{Permissions, PermissionsExt as _};
                    file.set_permissions(Permissions::from_mode(0o600))?;
                }
                file.write_all(contents)?;
                file.sync_all()
            },
        )
        .map_err(|error| format!("failed to write {label}: {error}"))
    }

    pub(crate) fn create_owner_only_file(
        &self,
        name: &str,
        contents: &[u8],
        label: &str,
    ) -> Result<bool, String> {
        validate_name(OsStr::new(name))?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};

            options.access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC);
        }
        let mut file = match self.directory.open_with(name, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => return Err(format!("failed to create {label}: {error}")),
        };
        self.validate_regular_file(&file, OsStr::new(name), true)?;
        if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
            let _ = self.directory.remove_file(name);
            return Err(format!("failed to initialize {label}: {error}"));
        }
        Ok(true)
    }

    pub(crate) fn remove_file(&self, name: &str, label: &str) -> Result<bool, String> {
        validate_name(OsStr::new(name))?;
        match self.directory.remove_file(name) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("failed to remove {label}: {error}")),
        }
    }

    pub(crate) fn display_path(&self, name: &str) -> PathBuf {
        self.display.join(name)
    }

    pub(crate) fn contains_file_with_extension(&self, extension: &str) -> Result<bool, String> {
        let entries = self.directory.entries().map_err(|error| {
            format!(
                "failed to inspect protected directory {}: {error}",
                self.display.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to inspect an entry in {}: {error}",
                    self.display.display()
                )
            })?;
            if Path::new(&entry.file_name()).extension() == Some(OsStr::new(extension)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate_regular_file(
        &self,
        file: &cap_std::fs::File,
        name: &OsStr,
        owner_only: bool,
    ) -> Result<(), String> {
        let metadata = file.metadata().map_err(|error| {
            format!(
                "failed to inspect protected file {}: {error}",
                self.display.join(name).display()
            )
        })?;
        if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
            return Err(format!(
                "protected path is not a regular file: {}",
                self.display.join(name).display()
            ));
        }
        #[cfg(unix)]
        if owner_only {
            use cap_std::fs::{MetadataExt as _, PermissionsExt as _};

            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(format!(
                    "protected file is not owner-only: {}",
                    self.display.join(name).display()
                ));
            }
        }
        #[cfg(not(unix))]
        let _ = owner_only;
        #[cfg(windows)]
        if owner_only {
            windows_security::protect_file(file).map_err(|error| {
                format!(
                    "failed to secure protected file {}: {error}",
                    self.display.join(name).display()
                )
            })?;
        }
        Ok(())
    }
}

pub(crate) fn with_vault_transaction<T>(
    operation: impl FnOnce(&VaultStorageDirectory) -> Result<T, String>,
) -> Result<T, String> {
    let directory = VaultStorageDirectory::open_lpm()?;
    let lock_file = directory.open_lock(TRANSACTION_LOCK_NAME, "vault transaction lock")?;
    let _lock = lpm_common::acquire_single_file_exclusive_lock_from_file(lock_file)
        .map_err(|error| format!("failed to acquire vault transaction lock: {error}"))?;
    operation(&directory)
}

pub(crate) fn try_acquire_named_lock(
    name: &str,
    label: &str,
) -> Result<Option<lpm_common::SingleFileExclusiveLockHandle>, String> {
    let directory = VaultStorageDirectory::open_lpm()?;
    let lock_file = directory.open_lock(name, label)?;
    lpm_common::try_acquire_single_file_exclusive_lock_from_file(lock_file)
        .map_err(|error| format!("failed to acquire {label}: {error}"))
}

fn validate_name(name: &OsStr) -> Result<(), String> {
    let path = Path::new(name);
    let mut components = path.components();
    if matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
    {
        return Ok(());
    }
    Err(format!(
        "vault storage name must be one file or directory component: {}",
        path.display()
    ))
}

#[cfg(not(windows))]
fn metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
mod windows_security {
    use std::os::windows::io::AsRawHandle as _;
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
    const OWNER_SYSTEM_DIRECTORY_DACL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)";

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(self.0.cast());
            }
        }
    }

    pub(super) fn protect_file(file: &cap_std::fs::File) -> std::io::Result<()> {
        apply_sddl(file.as_raw_handle().cast(), OWNER_SYSTEM_FILE_DACL)
    }

    pub(super) fn protect_directory(directory: &cap_std::fs::Dir) -> std::io::Result<()> {
        use cap_fs_ext::{
            FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsMaybeDirExt as _,
            OsMetadataExt as _,
        };
        use cap_std::fs::{OpenOptions, OpenOptionsExt as _};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ,
            FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
        };

        let mut options = OpenOptions::new();
        options
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .follow(FollowSymlinks::No)
            .maybe_dir(true);
        let file = directory.open_with(".", &options)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other(
                "vault storage directory handle is not a regular directory",
            ));
        }
        apply_sddl(file.as_raw_handle().cast(), OWNER_SYSTEM_DIRECTORY_DACL)
    }

    fn apply_sddl(
        handle: windows_sys::Win32::Foundation::HANDLE,
        sddl: &str,
    ) -> std::io::Result<()> {
        let encoded = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = null_mut();
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
        let status = unsafe {
            NtSetSecurityObject(
                handle,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            let error = unsafe { RtlNtStatusToDosError(status) };
            Err(std::io::Error::from_raw_os_error(error as i32))
        }
    }
}

#[cfg(windows)]
fn metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn with_temp_home<T>(test: impl FnOnce(&Path) -> T) -> T {
        let _guard = crate::test_env_lock::acquire_env_lock();
        let home = tempfile::tempdir().expect("create temporary home");
        let snapshot = crate::test_env_lock::HomeEnvSnapshot::set(home.path());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(home.path())));
        snapshot.restore();
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn create_owner_only_file_has_one_winner_across_concurrent_transactions() {
        with_temp_home(|_| {
            let workers = 8;
            let barrier = Arc::new(Barrier::new(workers));
            let mut handles = Vec::with_capacity(workers);
            for index in 0..workers {
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    with_vault_transaction(|directory| {
                        directory.create_owner_only_file(
                            ".create-once-test",
                            format!("candidate-{index}").as_bytes(),
                            "create-once test file",
                        )
                    })
                }));
            }
            let winners = handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .expect("create worker should not panic")
                        .expect("create worker should succeed")
                })
                .filter(|created| *created)
                .count();

            assert_eq!(winners, 1);
        });
    }

    #[cfg(unix)]
    #[test]
    fn transaction_rejects_a_linked_lpm_directory() {
        with_temp_home(|home| {
            let target = tempfile::tempdir().expect("create link target");
            std::os::unix::fs::symlink(target.path(), home.join(".lpm"))
                .expect("create linked .lpm directory");

            let error = with_vault_transaction(|_| Ok(())).expect_err("link must be rejected");

            assert!(error.contains("refusing vault directory"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn protected_reads_reject_linked_files() {
        with_temp_home(|home| {
            std::fs::create_dir(home.join(".lpm")).expect("create .lpm directory");
            let target = home.join("outside-secret");
            std::fs::write(&target, b"outside").expect("write link target");
            std::os::unix::fs::symlink(&target, home.join(".lpm/.linked-key"))
                .expect("create linked protected file");

            let error = with_vault_transaction(|directory| {
                directory.read_owner_only_file(".linked-key", "linked test key")
            })
            .expect_err("linked file must be rejected");

            assert!(error.contains("failed to open linked test key"));
        });
    }
}
