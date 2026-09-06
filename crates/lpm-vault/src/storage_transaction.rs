use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

const TRANSACTION_LOCK_NAME: &str = ".vault-keychain.lock";

#[cfg(test)]
static FORCE_DIRECTORY_SYNC_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
            #[cfg(target_os = "macos")]
            macos_acl::clear_directory(&directory).map_err(|error| {
                format!(
                    "failed to remove extended access control from {}: {error}",
                    display.display()
                )
            })?;
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
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
            };

            options
                .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
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
        let file = file.into_std();
        self.validate_lock_path(&file, name, label)?;
        Ok(file)
    }

    #[cfg(unix)]
    fn validate_directory_path(&self) -> Result<(), String> {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        use std::os::unix::fs::MetadataExt as _;

        let descriptor = self.directory.dir_metadata().map_err(|error| {
            format!("failed to inspect protected vault directory descriptor: {error}")
        })?;
        let path = std::fs::symlink_metadata(&self.display).map_err(|error| {
            format!(
                "failed to inspect protected vault directory path {}: {error}",
                self.display.display()
            )
        })?;
        if !descriptor.is_dir()
            || path.file_type().is_symlink()
            || !path.is_dir()
            || descriptor.uid() != unsafe { libc::geteuid() }
            || path.uid() != unsafe { libc::geteuid() }
            || descriptor.permissions().mode() & 0o777 != 0o700
            || path.mode() & 0o777 != 0o700
            || descriptor.dev() != path.dev()
            || descriptor.ino() != path.ino()
        {
            return Err(format!(
                "protected vault directory path changed at {}",
                self.display.display()
            ));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn validate_directory_path(&self) -> Result<(), String> {
        Ok(())
    }

    #[cfg(unix)]
    fn validate_lock_path(
        &self,
        file: &std::fs::File,
        name: &OsStr,
        label: &str,
    ) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        let descriptor = file
            .metadata()
            .map_err(|error| format!("failed to inspect {label} descriptor: {error}"))?;
        let path_name = self.display.join(name);
        let path = std::fs::symlink_metadata(&path_name)
            .map_err(|error| format!("failed to inspect {label} path: {error}"))?;
        if !descriptor.is_file()
            || path.file_type().is_symlink()
            || !path.is_file()
            || descriptor.uid() != unsafe { libc::geteuid() }
            || path.uid() != unsafe { libc::geteuid() }
            || descriptor.nlink() != 1
            || path.nlink() != 1
            || descriptor.mode() & 0o777 != 0o600
            || path.mode() & 0o777 != 0o600
            || descriptor.dev() != path.dev()
            || descriptor.ino() != path.ino()
        {
            return Err(format!("{label} path changed or is not owner-only"));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn validate_lock_path(
        &self,
        _file: &std::fs::File,
        _name: &OsStr,
        _label: &str,
    ) -> Result<(), String> {
        Ok(())
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

    pub(crate) fn sha256_owner_only_file(
        &self,
        name: &str,
        label: &str,
    ) -> Result<Option<[u8; 32]>, String> {
        use sha2::Digest as _;

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

        let limit = lpm_common::STATE_FILE_SIZE_CAP_BYTES;
        let mut reader = file.into_std().take(limit.saturating_add(1));
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|error| format!("failed to read {label}: {error}"))?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > limit {
                return Err(format!("{label} exceeds the {limit}-byte limit"));
            }
            hasher.update(&buffer[..read]);
        }
        Ok(Some(hasher.finalize().into()))
    }

    pub(crate) fn write_owner_only_file(
        &self,
        name: &str,
        contents: &[u8],
        label: &str,
    ) -> Result<(), String> {
        validate_name(OsStr::new(name))?;
        validate_contents_size(contents, label)?;
        lpm_common::write_file_atomic_in_dir_with(
            &self.directory,
            OsStr::new(name),
            |file| -> std::io::Result<()> {
                #[cfg(unix)]
                {
                    use cap_std::fs::{Permissions, PermissionsExt as _};
                    #[cfg(target_os = "macos")]
                    macos_acl::clear_file(file)?;
                    file.set_permissions(Permissions::from_mode(0o600))?;
                }
                file.write_all(contents)?;
                file.sync_all()
            },
        )
        .map_err(|error| format!("failed to write {label}: {error}"))?;
        self.sync_after_mutation(label, "replacement")
    }

    pub(crate) fn write_owner_only_file_durable(
        &self,
        name: &str,
        contents: &[u8],
        label: &str,
    ) -> Result<(), String> {
        self.write_owner_only_file(name, contents, label)
    }

    fn sync_after_mutation(&self, label: &str, operation: &str) -> Result<(), String> {
        self.sync_directory(label).map_err(|error| {
            format!(
                "{operation} of {label} completed, but its durability is indeterminate: {error}"
            )
        })
    }

    fn sync_directory(&self, label: &str) -> Result<(), String> {
        #[cfg(test)]
        if FORCE_DIRECTORY_SYNC_FAILURE.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(format!(
                "failed to persist {label}: injected directory sync failure"
            ));
        }
        #[cfg(unix)]
        {
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            let directory = self
                .directory
                .open_with(".", &options)
                .map_err(|error| format!("failed to open protected vault directory: {error}"))?;
            directory
                .sync_all()
                .map_err(|error| format!("failed to persist {label}: {error}"))?;
        }
        #[cfg(not(unix))]
        let _ = label;
        Ok(())
    }

    pub(crate) fn create_owner_only_file(
        &self,
        name: &str,
        contents: &[u8],
        label: &str,
    ) -> Result<bool, String> {
        validate_name(OsStr::new(name))?;
        validate_contents_size(contents, label)?;
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
        #[cfg(target_os = "macos")]
        macos_acl::clear_file(&file)
            .map_err(|error| format!("failed to secure {label}: {error}"))?;
        self.validate_regular_file(&file, OsStr::new(name), true)?;
        if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
            let _ = self.directory.remove_file(name);
            return Err(format!("failed to initialize {label}: {error}"));
        }
        self.sync_after_mutation(label, "creation")?;
        Ok(true)
    }

    pub(crate) fn remove_file(&self, name: &str, label: &str) -> Result<bool, String> {
        validate_name(OsStr::new(name))?;
        match self.directory.remove_file(name) {
            Ok(()) => {
                self.sync_after_mutation(label, "deletion")?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("failed to remove {label}: {error}")),
        }
    }

    pub(crate) fn remove_file_durable(&self, name: &str, label: &str) -> Result<bool, String> {
        self.remove_file(name, label)
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
            #[cfg(target_os = "macos")]
            if macos_acl::has_extended_acl(file).map_err(|error| {
                format!(
                    "failed to inspect access control for protected file {}: {error}",
                    self.display.join(name).display()
                )
            })? {
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

#[cfg(target_os = "macos")]
mod macos_acl {
    use std::ffi::{c_int, c_void};
    use std::os::fd::AsRawFd as _;

    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;

    unsafe extern "C" {
        fn acl_free(value: *mut c_void) -> c_int;
        fn acl_get_fd_np(file_descriptor: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_init(entry_count: c_int) -> *mut c_void;
        fn acl_set_fd_np(file_descriptor: c_int, acl: *mut c_void, acl_type: c_int) -> c_int;
    }

    pub(super) fn has_extended_acl(file: &cap_std::fs::File) -> std::io::Result<bool> {
        has_extended_acl_fd(file.as_raw_fd())
    }

    pub(super) fn clear_file(file: &cap_std::fs::File) -> std::io::Result<()> {
        clear_extended_acl_fd(file.as_raw_fd())
    }

    pub(super) fn clear_directory(directory: &cap_std::fs::Dir) -> std::io::Result<()> {
        clear_extended_acl_fd(directory.as_raw_fd())
    }

    pub(super) fn has_extended_acl_fd(file_descriptor: c_int) -> std::io::Result<bool> {
        unsafe {
            *libc::__error() = 0;
            let acl = acl_get_fd_np(file_descriptor, ACL_TYPE_EXTENDED);
            if acl.is_null() {
                let error = *libc::__error();
                return if error == 0 || error == libc::ENOENT {
                    Ok(false)
                } else {
                    Err(std::io::Error::from_raw_os_error(error))
                };
            }
            if acl_free(acl) == 0 {
                Ok(true)
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    fn clear_extended_acl_fd(file_descriptor: c_int) -> std::io::Result<()> {
        unsafe {
            let acl = acl_init(0);
            if acl.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let result = acl_set_fd_np(file_descriptor, acl, ACL_TYPE_EXTENDED);
            let error = if result == 0 {
                None
            } else {
                Some(std::io::Error::last_os_error())
            };
            let free_result = acl_free(acl);
            if let Some(error) = error {
                return Err(error);
            }
            if free_result != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if has_extended_acl_fd(file_descriptor)? {
                return Err(std::io::Error::other(
                    "extended access control remained after removal",
                ));
            }
            Ok(())
        }
    }
}

pub(crate) fn with_vault_transaction<T>(
    operation: impl FnOnce(&VaultStorageDirectory) -> Result<T, String>,
) -> Result<T, String> {
    with_vault_transaction_before_lock(|| Ok(()), operation)
}

fn with_vault_transaction_before_lock<T>(
    before_lock: impl FnOnce() -> Result<(), String>,
    operation: impl FnOnce(&VaultStorageDirectory) -> Result<T, String>,
) -> Result<T, String> {
    let directory = VaultStorageDirectory::open_lpm()?;
    let lock_file = directory.open_lock(TRANSACTION_LOCK_NAME, "vault transaction lock")?;
    let verification_file = lock_file
        .try_clone()
        .map_err(|error| format!("failed to duplicate vault transaction lock: {error}"))?;
    directory.validate_directory_path()?;
    directory.validate_lock_path(
        &verification_file,
        OsStr::new(TRANSACTION_LOCK_NAME),
        "vault transaction lock",
    )?;
    before_lock()?;
    directory.validate_directory_path()?;
    directory.validate_lock_path(
        &verification_file,
        OsStr::new(TRANSACTION_LOCK_NAME),
        "vault transaction lock",
    )?;
    let _lock = lpm_common::acquire_single_file_exclusive_lock_from_file(lock_file)
        .map_err(|error| format!("failed to acquire vault transaction lock: {error}"))?;
    directory.validate_directory_path()?;
    directory.validate_lock_path(
        &verification_file,
        OsStr::new(TRANSACTION_LOCK_NAME),
        "vault transaction lock",
    )?;
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

fn validate_contents_size(contents: &[u8], label: &str) -> Result<(), String> {
    let limit = lpm_common::STATE_FILE_SIZE_CAP_BYTES as usize;
    if contents.len() > limit {
        return Err(format!("{label} exceeds the {limit}-byte limit"));
    }
    Ok(())
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

    struct ForcedDirectorySyncFailure;

    impl ForcedDirectorySyncFailure {
        fn new() -> Self {
            FORCE_DIRECTORY_SYNC_FAILURE.store(true, std::sync::atomic::Ordering::SeqCst);
            Self
        }
    }

    impl Drop for ForcedDirectorySyncFailure {
        fn drop(&mut self) {
            FORCE_DIRECTORY_SYNC_FAILURE.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn create_reports_indeterminate_success_when_parent_sync_fails() {
        with_temp_home(|_| {
            let result = with_vault_transaction(|directory| {
                let _failure = ForcedDirectorySyncFailure::new();
                directory.create_owner_only_file(
                    ".durable-create-test",
                    b"created",
                    "durable create test file",
                )
            });

            let error = result.expect_err("a directory sync failure must be observable");
            assert!(error.contains("durability is indeterminate"), "{error}");
        });
    }

    #[test]
    fn replacement_reports_indeterminate_success_when_parent_sync_fails() {
        with_temp_home(|_| {
            let result = with_vault_transaction(|directory| {
                directory.write_owner_only_file(
                    ".durable-replace-test",
                    b"old",
                    "durable replace test file",
                )?;
                let _failure = ForcedDirectorySyncFailure::new();
                directory.write_owner_only_file(
                    ".durable-replace-test",
                    b"new",
                    "durable replace test file",
                )
            });

            let error = result.expect_err("a directory sync failure must be observable");
            assert!(error.contains("durability is indeterminate"), "{error}");
        });
    }

    #[test]
    fn deletion_reports_indeterminate_success_when_parent_sync_fails() {
        with_temp_home(|_| {
            let result = with_vault_transaction(|directory| {
                directory.write_owner_only_file(
                    ".durable-delete-test",
                    b"old",
                    "durable delete test file",
                )?;
                let _failure = ForcedDirectorySyncFailure::new();
                directory.remove_file(".durable-delete-test", "durable delete test file")
            });

            let error = result.expect_err("a directory sync failure must be observable");
            assert!(error.contains("durability is indeterminate"), "{error}");
        });
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

    #[test]
    fn protected_streaming_digest_matches_sha256_without_materializing_the_file() {
        use sha2::Digest as _;

        with_temp_home(|_| {
            let payload = b"streamed protected payload";
            let digest = with_vault_transaction(|directory| {
                directory.write_owner_only_file(".digest-test", payload, "digest test file")?;
                directory
                    .sha256_owner_only_file(".digest-test", "digest test file")?
                    .ok_or_else(|| "missing digest test file".to_owned())
            })
            .expect("hash protected file");

            assert_eq!(digest, <[u8; 32]>::from(sha2::Sha256::digest(payload)));
        });
    }

    #[test]
    fn protected_streaming_digest_rejects_a_file_above_the_state_limit() {
        with_temp_home(|home| {
            let lpm_directory = home.join(".lpm");
            std::fs::create_dir(&lpm_directory).expect("create .lpm directory");
            let path = lpm_directory.join(".oversized-digest-test");
            let file = std::fs::File::create(&path).expect("create oversized digest file");
            file.set_len(lpm_common::STATE_FILE_SIZE_CAP_BYTES + 1)
                .expect("extend oversized digest file");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("secure oversized digest file");
            }

            let error = with_vault_transaction(|directory| {
                directory
                    .sha256_owner_only_file(".oversized-digest-test", "oversized digest test file")
            })
            .expect_err("oversized digest input must fail closed");

            assert!(error.contains("exceeds the 16777216-byte limit"), "{error}");
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
    fn transaction_rejects_lpm_directory_replacement_before_lock() {
        use std::os::unix::fs::PermissionsExt as _;

        with_temp_home(|home| {
            let directory = home.join(".lpm");
            let displaced = home.join("displaced.lpm");
            std::fs::create_dir(&directory).expect("create .lpm directory");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("secure .lpm directory");

            let result = with_vault_transaction_before_lock(
                || {
                    std::fs::rename(&directory, &displaced)
                        .map_err(|error| format!("replace .lpm directory: {error}"))?;
                    std::fs::create_dir(&directory)
                        .map_err(|error| format!("create replacement .lpm directory: {error}"))?;
                    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| format!("secure replacement .lpm directory: {error}"))?;
                    Ok(())
                },
                |_| Ok(()),
            );

            assert!(result.is_err(), "directory replacement must fail closed");
        });
    }

    #[cfg(unix)]
    #[test]
    fn transaction_rejects_lock_path_replacement_before_lock() {
        use std::os::unix::fs::PermissionsExt as _;

        with_temp_home(|home| {
            let directory = home.join(".lpm");
            std::fs::create_dir(&directory).expect("create .lpm directory");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("secure .lpm directory");
            let lock = directory.join(TRANSACTION_LOCK_NAME);
            let displaced = directory.join("displaced.lock");

            let result = with_vault_transaction_before_lock(
                || {
                    std::fs::rename(&lock, &displaced)
                        .map_err(|error| format!("displace transaction lock: {error}"))?;
                    std::fs::write(&lock, b"replacement")
                        .map_err(|error| format!("create replacement transaction lock: {error}"))?;
                    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600))
                        .map_err(|error| format!("secure replacement transaction lock: {error}"))?;
                    Ok(())
                },
                |_| Ok(()),
            );

            assert!(result.is_err(), "lock path replacement must fail closed");
        });
    }

    #[cfg(windows)]
    #[test]
    fn transaction_lock_cannot_be_replaced_while_its_handle_is_open() {
        with_temp_home(|home| {
            let directory = home.join(".lpm");
            std::fs::create_dir(&directory).expect("create .lpm directory");
            let lock = directory.join(TRANSACTION_LOCK_NAME);
            let displaced = directory.join("displaced.lock");

            let result = with_vault_transaction_before_lock(
                || {
                    std::fs::rename(&lock, &displaced)
                        .map_err(|error| format!("displace transaction lock: {error}"))?;
                    std::fs::write(&lock, b"replacement")
                        .map_err(|error| format!("create replacement transaction lock: {error}"))?;
                    Ok(())
                },
                |_| Ok(()),
            );

            assert!(result.is_err(), "lock replacement must fail closed");
        });
    }

    #[cfg(windows)]
    #[test]
    fn transaction_lock_cannot_be_deleted_while_its_handle_is_open() {
        with_temp_home(|home| {
            let lock = home.join(".lpm").join(TRANSACTION_LOCK_NAME);

            let result = with_vault_transaction_before_lock(
                || std::fs::remove_file(&lock).map_err(|error| format!("delete lock: {error}")),
                |_| Ok(()),
            );

            assert!(result.is_err(), "lock deletion must fail closed");
            assert!(lock.exists(), "the open lock path must remain present");
        });
    }

    #[cfg(unix)]
    #[test]
    fn transaction_rejects_a_hard_linked_lock_file() {
        use std::os::unix::fs::PermissionsExt as _;

        with_temp_home(|home| {
            let directory = home.join(".lpm");
            std::fs::create_dir(&directory).expect("create .lpm directory");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("secure .lpm directory");
            let target = home.join("target.lock");
            std::fs::write(&target, b"target").expect("create hard-link target");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                .expect("secure hard-link target");
            std::fs::hard_link(&target, directory.join(TRANSACTION_LOCK_NAME))
                .expect("create hard-linked transaction lock");

            let result = with_vault_transaction(|_| Ok(()));

            assert!(result.is_err(), "hard-linked lock must fail closed");
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

    #[cfg(target_os = "macos")]
    #[test]
    fn protected_reads_reject_files_with_extended_access_control() {
        with_temp_home(|home| {
            let directory = home.join(".lpm");
            std::fs::create_dir(&directory).expect("create .lpm directory");
            let path = directory.join(".acl-key");
            std::fs::write(&path, b"exposed").expect("write protected file");
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("make file owner-only by POSIX mode");
            let status = std::process::Command::new("/bin/chmod")
                .args(["+a", "group:everyone allow read"])
                .arg(&path)
                .status()
                .expect("add extended ACL");
            assert!(status.success());

            let error = with_vault_transaction(|directory| {
                directory.read_owner_only_file(".acl-key", "ACL test key")
            })
            .expect_err("extended ACL must make an owner-only file unsafe");

            assert!(error.contains("not owner-only"), "{error}");
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn protected_directory_and_new_files_remove_inherited_access_control() {
        use std::os::fd::AsRawFd as _;

        with_temp_home(|home| {
            let directory = home.join(".lpm");
            std::fs::create_dir(&directory).expect("create .lpm directory");
            let status = std::process::Command::new("/bin/chmod")
                .args([
                    "+a",
                    "group:everyone allow read,write,execute,file_inherit,directory_inherit",
                ])
                .arg(&directory)
                .status()
                .expect("add inherited extended ACL");
            assert!(status.success());

            with_vault_transaction(|directory| {
                assert!(directory.create_owner_only_file(
                    ".created-key",
                    b"protected",
                    "created ACL test key",
                )?);
                Ok(())
            })
            .expect("create protected file after clearing inherited ACL");

            let opened_directory = std::fs::File::open(&directory).expect("open .lpm directory");
            let created = std::fs::File::open(directory.join(".created-key"))
                .expect("open created protected file");
            assert!(
                !macos_acl::has_extended_acl_fd(opened_directory.as_raw_fd())
                    .expect("inspect protected directory ACL")
            );
            assert!(
                !macos_acl::has_extended_acl_fd(created.as_raw_fd())
                    .expect("inspect protected file ACL")
            );
        });
    }
}
