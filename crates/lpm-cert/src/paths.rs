//! Certificate file path management.
//!
//! CA certs: `~/.lpm/certs/rootCA.pem` + `rootCA-key.pem` (global, one per machine)
//! Project certs: `{project}/.lpm/certs/cert.pem` + `key.pem` (per-project)

use cap_std::fs::Dir;
use cap_std::fs::OpenOptions;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

#[cfg(windows)]
const WINDOWS_FILE_OPERATION_RETRY_DELAYS_MS: [u64; 6] = [0, 50, 150, 450, 1_350, 4_050];

#[cfg(windows)]
pub(crate) mod windows_security {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::windows::io::AsRawHandle as _;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
    use windows_sys::Win32::Foundation::{LocalFree, RtlNtStatusToDosError};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    const OWNER_SYSTEM_FILE_DACL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)";
    const OWNER_SYSTEM_DIRECTORY_DACL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)";

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: `self.0` is allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and is released once here.
            unsafe {
                let _ = LocalFree(self.0.cast());
            }
        }
    }

    pub(super) fn protect_cap_file(file: &cap_std::fs::File) -> std::io::Result<()> {
        apply_sddl(file.as_raw_handle().cast(), OWNER_SYSTEM_FILE_DACL, true)
    }

    pub(super) fn protect_directory(dir: &cap_std::fs::Dir) -> std::io::Result<()> {
        use cap_fs_ext::{
            FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt, OsMetadataExt as _,
        };
        use cap_std::fs::{OpenOptions, OpenOptionsExt as _};

        let mut options = OpenOptions::new();
        options
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .follow(FollowSymlinks::No)
            .maybe_dir(true);
        let file = dir.open_with(".", &options)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other(
                "certificate directory handle is not a regular directory",
            ));
        }
        apply_sddl(
            file.as_raw_handle().cast(),
            OWNER_SYSTEM_DIRECTORY_DACL,
            true,
        )
    }

    pub(crate) fn protect_directory_path(path: &Path) -> std::io::Result<()> {
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other(
                "certificate directory path is not a regular directory",
            ));
        }
        apply_sddl(
            file.as_raw_handle().cast(),
            OWNER_SYSTEM_DIRECTORY_DACL,
            true,
        )
    }

    fn apply_sddl(
        handle: windows_sys::Win32::Foundation::HANDLE,
        sddl: &str,
        protect: bool,
    ) -> std::io::Result<()> {
        let encoded = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = null_mut();
        // SAFETY: `encoded` is NUL-terminated and remains alive for the call. The output pointer
        // is initialized to null and is owned by `LocalFree` after a successful conversion.
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
        let security_information = DACL_SECURITY_INFORMATION
            | if protect {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
        // SAFETY: `handle` is the retained file or directory handle with `WRITE_DAC`, and
        // `descriptor` remains valid for the call. The native handle API updates only this pinned
        // object; the Win32 wrapper may try to propagate inheritable ACEs by path.
        let status = unsafe { NtSetSecurityObject(handle, security_information, descriptor.0) };
        if status == 0 {
            Ok(())
        } else {
            // SAFETY: `status` is the NTSTATUS returned by `NtSetSecurityObject`.
            let error = unsafe { RtlNtStatusToDosError(status) };
            Err(std::io::Error::from_raw_os_error(error as i32))
        }
    }

    #[cfg(test)]
    pub(super) fn apply_inheritable_everyone_read(file: &std::fs::File) -> std::io::Result<()> {
        apply_sddl(
            file.as_raw_handle().cast(),
            "D:(A;OICI;GR;;;WD)(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)",
            false,
        )
    }

    #[cfg(test)]
    pub(super) fn descriptor_sddl(file: &std::fs::File) -> std::io::Result<String> {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        };

        let mut descriptor = null_mut();
        // SAFETY: The output descriptor pointer is initialized to null. `file` remains open for
        // the call, and the returned allocation is owned by `LocalSecurityDescriptor`.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        let descriptor = LocalSecurityDescriptor(descriptor);
        let mut text = null_mut();
        let mut text_len = 0;
        // SAFETY: `descriptor` is valid for the call. `text` and `text_len` are initialized output
        // storage, and the returned text allocation is released with `LocalFree` below.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut text_len,
            )
        };
        if converted == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: The conversion function returned a valid UTF-16 allocation containing
        // `text_len` code units. It remains allocated until `LocalFree` below.
        let decoded = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(text, text_len as usize)
        });
        // SAFETY: `text` is allocated by the conversion function and is released once here.
        unsafe {
            let _ = LocalFree(text.cast());
        }
        Ok(decoded)
    }
}

const GLOBAL_PAIR_TRANSACTION: &str = ".lpm-ca-pair-transaction.json";
const PROJECT_PAIR_TRANSACTION: &str = ".lpm-project-pair-transaction.json";

#[derive(Serialize, Deserialize)]
struct PairTransaction {
    cert_name: String,
    key_name: String,
    cert_pem: String,
    key_pem: String,
    staged_cert_name: String,
    staged_key_name: String,
}

impl PairTransaction {
    fn new(
        cert_name: &str,
        key_name: &str,
        cert: &[u8],
        key: &[u8],
        staged_cert_name: &str,
        staged_key_name: &str,
    ) -> Result<Self, LpmError> {
        Ok(Self {
            cert_name: validate_relative_filename(cert_name)?.to_string(),
            key_name: validate_relative_filename(key_name)?.to_string(),
            cert_pem: std::str::from_utf8(cert)
                .map_err(|error| LpmError::Cert(format!("invalid certificate text: {error}")))?
                .to_string(),
            key_pem: std::str::from_utf8(key)
                .map_err(|error| LpmError::Cert(format!("invalid private-key text: {error}")))?
                .to_string(),
            staged_cert_name: validate_temporary_filename(staged_cert_name)?.to_string(),
            staged_key_name: validate_temporary_filename(staged_key_name)?.to_string(),
        })
    }
}

fn validate_relative_filename(name: &str) -> Result<&str, LpmError> {
    let path = Path::new(name);
    if matches!(
        path.components().next(),
        Some(std::path::Component::Normal(_))
    ) && path.components().count() == 1
    {
        Ok(name)
    } else {
        Err(LpmError::Cert(format!(
            "invalid certificate transaction filename {name:?}"
        )))
    }
}

fn validate_temporary_filename(name: &str) -> Result<&str, LpmError> {
    let name = validate_relative_filename(name)?;
    if name.starts_with(".lpm-cert-") {
        Ok(name)
    } else {
        Err(LpmError::Cert(
            "invalid certificate transaction temporary filename".into(),
        ))
    }
}

/// Directory for the global root CA: `~/.lpm/certs/`
pub fn ca_dir() -> Result<PathBuf, LpmError> {
    let root = lpm_common::LpmRoot::from_env()?;
    Ok(root.root().join("certs"))
}

/// Path to the root CA certificate: `~/.lpm/certs/rootCA.pem`
pub fn ca_cert_path() -> Result<PathBuf, LpmError> {
    Ok(ca_dir()?.join("rootCA.pem"))
}

/// Path to the root CA private key: `~/.lpm/certs/rootCA-key.pem`
pub fn ca_key_path() -> Result<PathBuf, LpmError> {
    Ok(ca_dir()?.join("rootCA-key.pem"))
}

pub(crate) struct GlobalCaDirectory {
    path: PathBuf,
    dir: Dir,
}

impl GlobalCaDirectory {
    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub(crate) fn exists(&self, name: &str) -> Result<bool, LpmError> {
        match self.dir.symlink_metadata(name) {
            Ok(metadata) if metadata_is_link_or_reparse(&metadata) => Err(LpmError::Cert(format!(
                "refusing linked global certificate path {}",
                self.path(name).display()
            ))),
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(LpmError::Cert(format!(
                "global certificate path {} is not a regular file",
                self.path(name).display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(LpmError::Cert(format!(
                "failed to inspect global certificate path {}: {error}",
                self.path(name).display()
            ))),
        }
    }

    pub(crate) fn read(&self, name: &str) -> Result<Vec<u8>, LpmError> {
        read_bounded_relative_file(&self.dir, name, "global certificate")
    }

    pub(crate) fn write(&self, name: &str, contents: &[u8], mode: u32) -> Result<(), LpmError> {
        reject_linked_global_entry(&self.dir, name, &self.path)?;
        let staged = stage_relative_file(&self.dir, contents, mode)?;
        replace_relative_file(&self.dir, &staged.name, name, staged.file).map_err(|error| {
            LpmError::Cert(format!(
                "failed to replace global certificate path {}: {error}",
                self.path(name).display()
            ))
        })?;
        sync_directory(&self.dir)
    }

    pub(crate) fn write_ca_pair(
        &self,
        cert_name: &str,
        key_name: &str,
        cert: &[u8],
        key: &[u8],
    ) -> Result<(), LpmError> {
        self.write_ca_pair_with_failpoint(cert_name, key_name, cert, key, || Ok(()))
    }

    fn write_ca_pair_with_failpoint(
        &self,
        cert_name: &str,
        key_name: &str,
        cert: &[u8],
        key: &[u8],
        after_cert_replace: impl FnOnce() -> Result<(), LpmError>,
    ) -> Result<(), LpmError> {
        let cert_text = std::str::from_utf8(cert)
            .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in CA certificate: {error}")))?;
        let key_text = std::str::from_utf8(key)
            .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in CA key: {error}")))?;
        crate::cert::validate_ca_key_pair(cert_text, key_text)
            .map_err(|error| LpmError::Cert(format!("invalid CA pair: {error}")))?;
        reject_linked_global_entry(&self.dir, cert_name, &self.path)?;
        reject_linked_global_entry(&self.dir, key_name, &self.path)?;
        let previous_cert = read_optional_relative_file(&self.dir, cert_name)?;
        let previous_key = read_optional_relative_file(&self.dir, key_name)?;
        let staged_cert = stage_relative_file(&self.dir, cert, 0o644)?;
        let staged_key = match stage_relative_file(&self.dir, key, 0o600) {
            Ok(staged) => staged,
            Err(error) => {
                let _ = self.dir.remove_file(&staged_cert.name);
                return Err(error);
            }
        };
        let transaction = PairTransaction::new(
            cert_name,
            key_name,
            cert,
            key,
            &staged_cert.name,
            &staged_key.name,
        )?;
        write_pair_transaction(&self.dir, GLOBAL_PAIR_TRANSACTION, &transaction)?;

        let result = (|| -> Result<(), LpmError> {
            replace_relative_file(&self.dir, &staged_cert.name, cert_name, staged_cert.file)
                .map_err(|error| {
                    LpmError::Cert(format!("failed to replace CA certificate: {error}"))
                })?;
            after_cert_replace()?;
            replace_relative_file(&self.dir, &staged_key.name, key_name, staged_key.file)
                .map_err(|error| LpmError::Cert(format!("failed to replace CA key: {error}")))?;
            sync_directory(&self.dir)?;
            Ok(())
        })();
        if let Err(error) = result {
            let cert_restore =
                restore_relative_file(&self.dir, cert_name, previous_cert.as_deref(), 0o644);
            let key_restore =
                restore_relative_file(&self.dir, key_name, previous_key.as_deref(), 0o600);
            let _ = self.dir.remove_file(&staged_cert.name);
            let _ = self.dir.remove_file(&staged_key.name);
            if let Err(restore_error) = cert_restore.and(key_restore) {
                return Err(LpmError::Cert(format!(
                    "{error}; restoring the previous CA pair also failed: {restore_error}"
                )));
            }
            remove_pair_transaction(&self.dir, GLOBAL_PAIR_TRANSACTION)?;
            return Err(error);
        }
        let _ = self.dir.remove_file(&staged_cert.name);
        let _ = self.dir.remove_file(&staged_key.name);
        let written_cert = self.read(cert_name)?;
        let written_key = self.read(key_name)?;
        let written_cert = std::str::from_utf8(&written_cert).map_err(|error| {
            LpmError::Cert(format!("invalid UTF-8 in written CA certificate: {error}"))
        })?;
        let written_key = std::str::from_utf8(&written_key)
            .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in written CA key: {error}")))?;
        crate::cert::validate_ca_key_pair(written_cert, written_key)
            .map_err(|error| LpmError::Cert(format!("written CA pair is invalid: {error}")))?;
        remove_pair_transaction(&self.dir, GLOBAL_PAIR_TRANSACTION)
    }

    pub(crate) fn remove(&self, name: &str) -> Result<(), LpmError> {
        reject_linked_global_entry(&self.dir, name, &self.path)?;
        match remove_relative_file(&self.dir, name) {
            Ok(true) => sync_directory(&self.dir),
            Ok(false) => Ok(()),
            Err(error) => Err(LpmError::Cert(format!(
                "failed to remove global certificate path {}: {error}",
                self.path(name).display()
            ))),
        }
    }

    pub(crate) fn modified(&self, name: &str) -> Result<std::time::SystemTime, LpmError> {
        reject_linked_global_entry(&self.dir, name, &self.path)?;
        self.dir
            .metadata(name)
            .and_then(|metadata| metadata.modified())
            .map(cap_std::time::SystemTime::into_std)
            .map_err(|error| {
                LpmError::Cert(format!(
                    "failed to inspect global certificate path {}: {error}",
                    self.path(name).display()
                ))
            })
    }

    #[cfg(unix)]
    pub(crate) fn mode(&self, name: &str) -> Result<u32, LpmError> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::PermissionsExt as _;

        reject_linked_global_entry(&self.dir, name, &self.path)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = self.dir.open_with(name, &options).map_err(|error| {
            LpmError::Cert(format!(
                "failed to open global certificate path {}: {error}",
                self.path(name).display()
            ))
        })?;
        Ok(file
            .metadata()
            .map_err(|error| {
                LpmError::Cert(format!(
                    "failed to inspect global certificate path {}: {error}",
                    self.path(name).display()
                ))
            })?
            .permissions()
            .mode()
            & 0o777)
    }

    pub(crate) fn acquire_operations_lock(
        &self,
    ) -> Result<lpm_common::SingleFileExclusiveLockHandle, LpmError> {
        let file = self.open_lock_file(".operations.lock", "operation")?;
        lpm_common::acquire_single_file_exclusive_lock_from_file(file)
    }

    fn open_lock_file(&self, name: &str, label: &str) -> Result<std::fs::File, LpmError> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};

        validate_relative_filename(name)?;
        reject_linked_global_entry(&self.dir, name, &self.path)?;
        let mut create_options = OpenOptions::new();
        create_options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            create_options.mode(0o600);
        }
        let file = match self.dir.open_with(name, &create_options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut existing_options = OpenOptions::new();
                existing_options
                    .read(true)
                    .write(true)
                    .follow(FollowSymlinks::No);
                self.dir
                    .open_with(name, &existing_options)
                    .map_err(|error| {
                        LpmError::Cert(format!(
                            "failed to open global certificate {label} lock: {error}"
                        ))
                    })?
            }
            Err(error) => {
                return Err(LpmError::Cert(format!(
                    "failed to create global certificate {label} lock: {error}"
                )));
            }
        };
        let metadata = file.metadata().map_err(|error| {
            LpmError::Cert(format!(
                "failed to inspect global certificate {label} lock: {error}"
            ))
        })?;
        if !metadata.is_file() {
            return Err(LpmError::Cert(format!(
                "global certificate {label} lock is not a regular file"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            file.try_clone()
                .and_then(|file| {
                    file.into_std()
                        .set_permissions(std::fs::Permissions::from_mode(0o600))
                })
                .map_err(|error| {
                    LpmError::Cert(format!(
                        "failed to tighten global certificate {label} lock permissions: {error}"
                    ))
                })?;
        }
        Ok(file.into_std())
    }
}

struct RuntimeCertificateLeaseInner {
    fingerprint: [u8; 32],
    _lock: lpm_common::SingleFileSharedLockHandle,
}

#[derive(Clone)]
pub struct RuntimeCertificateLease {
    inner: std::sync::Arc<RuntimeCertificateLeaseInner>,
}

impl std::fmt::Debug for RuntimeCertificateLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCertificateLease")
            .field(
                "fingerprint",
                &fingerprint_lock_suffix(&self.inner.fingerprint),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl RuntimeCertificateLease {
    pub(crate) fn for_test() -> Self {
        let lock = lpm_common::acquire_single_file_shared_lock_from_file(
            tempfile::tempfile().expect("create runtime certificate test lease"),
        )
        .expect("acquire runtime certificate test lease");
        Self {
            inner: std::sync::Arc::new(RuntimeCertificateLeaseInner {
                fingerprint: [0; 32],
                _lock: lock,
            }),
        }
    }
}

pub(crate) struct CertificateGenerationWriteGuard {
    _fingerprint: [u8; 32],
    _lock: lpm_common::SingleFileExclusiveLockHandle,
}

pub(crate) struct CertificateOperation {
    pub(crate) ca: GlobalCaDirectory,
    _lock: lpm_common::SingleFileExclusiveLockHandle,
}

impl CertificateOperation {
    pub(crate) fn begin() -> Result<Self, LpmError> {
        let ca = open_global_ca_directory(true)?;
        let lock = ca.acquire_operations_lock()?;
        recover_global_pair_transaction(&ca)?;
        Ok(Self { ca, _lock: lock })
    }

    #[cfg(test)]
    fn begin_at(home_path: PathBuf) -> Result<Self, LpmError> {
        let ca = open_global_ca_directory_at(home_path, true)?;
        let lock = ca.acquire_operations_lock()?;
        recover_global_pair_transaction(&ca)?;
        Ok(Self { ca, _lock: lock })
    }

    pub(crate) fn acquire_runtime_lease(
        &self,
        root_pem: &[u8],
    ) -> Result<RuntimeCertificateLease, LpmError> {
        let fingerprint = crate::cert::fingerprint_sha256_bytes(root_pem)?;
        let file = self
            .ca
            .open_lock_file(&generation_lock_name(&fingerprint), "runtime generation")?;
        let lock = lpm_common::acquire_single_file_shared_lock_from_file(file)?;
        Ok(RuntimeCertificateLease {
            inner: std::sync::Arc::new(RuntimeCertificateLeaseInner {
                fingerprint,
                _lock: lock,
            }),
        })
    }

    pub(crate) fn try_acquire_destructive_generation(
        &self,
        cert_pem: &[u8],
    ) -> Result<Option<CertificateGenerationWriteGuard>, LpmError> {
        let fingerprint = crate::cert::fingerprint_sha256_bytes(cert_pem)?;
        let file = self
            .ca
            .open_lock_file(&generation_lock_name(&fingerprint), "runtime generation")?;
        let Some(lock) = lpm_common::try_acquire_single_file_exclusive_lock_from_file(file)? else {
            return Ok(None);
        };
        Ok(Some(CertificateGenerationWriteGuard {
            _fingerprint: fingerprint,
            _lock: lock,
        }))
    }

    pub(crate) fn acquire_destructive_generation(
        &self,
        cert_pem: &[u8],
    ) -> Result<CertificateGenerationWriteGuard, LpmError> {
        let fingerprint = crate::cert::fingerprint_sha256_bytes(cert_pem)?;
        self.try_acquire_destructive_generation(cert_pem)?
            .ok_or_else(|| {
                LpmError::Cert(format!(
                    "certificate generation {} is still served by an active TLS runtime; stop that runtime and retry",
                    crate::cert::fingerprint_hex(&fingerprint)
                ))
            })
    }
}

fn generation_lock_name(fingerprint: &[u8; 32]) -> String {
    format!(".generation-{}.lock", fingerprint_lock_suffix(fingerprint))
}

fn fingerprint_lock_suffix(fingerprint: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut suffix = String::with_capacity(64);
    for byte in fingerprint {
        write!(&mut suffix, "{byte:02x}").expect("writing to a String cannot fail");
    }
    suffix
}

pub(crate) fn open_global_ca_directory(create: bool) -> Result<GlobalCaDirectory, LpmError> {
    let root = lpm_common::LpmRoot::from_env()?;
    open_global_ca_directory_at_lpm_root(root.root().to_path_buf(), create)
}

#[cfg(test)]
fn open_global_ca_directory_at(
    home_path: PathBuf,
    create: bool,
) -> Result<GlobalCaDirectory, LpmError> {
    open_global_ca_directory_at_lpm_root(home_path.join(".lpm"), create)
}

fn open_global_ca_directory_at_lpm_root(
    lpm_root_path: PathBuf,
    create: bool,
) -> Result<GlobalCaDirectory, LpmError> {
    let lpm_root_path = std::path::absolute(lpm_root_path).map_err(LpmError::Io)?;
    let root_name = lpm_root_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| LpmError::Cert("LPM_HOME must name a directory".into()))?;
    let parent_path = lpm_root_path.parent().ok_or_else(|| {
        LpmError::Cert(format!(
            "LPM_HOME has no parent directory: {}",
            lpm_root_path.display()
        ))
    })?;
    if create {
        std::fs::create_dir_all(parent_path).map_err(|error| {
            LpmError::Cert(format!(
                "failed to create LPM_HOME parent directory {}: {error}",
                parent_path.display()
            ))
        })?;
    }
    let parent =
        Dir::open_ambient_dir(parent_path, cap_std::ambient_authority()).map_err(|error| {
            LpmError::Cert(format!(
                "failed to open LPM_HOME parent directory {}: {error}",
                parent_path.display()
            ))
        })?;
    let Some(lpm) = open_or_create_directory(&parent, root_name, create, "$LPM_HOME")? else {
        return Err(LpmError::Cert("global LPM directory does not exist".into()));
    };
    let Some(certs) = open_or_create_directory(&lpm, "certs", create, "$LPM_HOME/certs")? else {
        return Err(LpmError::Cert(
            "global certificate directory does not exist".into(),
        ));
    };
    Ok(GlobalCaDirectory {
        path: lpm_root_path.join("certs"),
        dir: certs,
    })
}

/// Directory for project-specific certificates: `{project}/.lpm/certs/`
pub fn project_cert_dir(project_dir: &Path) -> Result<PathBuf, LpmError> {
    Ok(project_dir.join(".lpm").join("certs"))
}

/// Resolve and optionally create the project certificate directory without
/// following repository-controlled links or junctions.
pub(crate) fn secure_project_cert_dir(
    project_dir: &Path,
    create: bool,
) -> Result<PathBuf, LpmError> {
    let project_dir = project_dir.canonicalize().map_err(|error| {
        LpmError::Cert(format!(
            "failed to resolve project directory {}: {error}",
            project_dir.display()
        ))
    })?;
    let state_dir = project_dir.join(".lpm");
    let cert_dir = state_dir.join("certs");

    validate_project_directory_entry(&state_dir, ".lpm")?;
    if create && !state_dir.exists() {
        crate::create_dir_secure(&state_dir).map_err(|error| {
            LpmError::Cert(format!(
                "failed to create project state directory {}: {error}",
                state_dir.display()
            ))
        })?;
    }
    validate_project_directory_entry(&state_dir, ".lpm")?;
    validate_project_directory_entry(&cert_dir, ".lpm/certs")?;
    if create && !cert_dir.exists() {
        crate::create_dir_secure(&cert_dir).map_err(|error| {
            LpmError::Cert(format!(
                "failed to create project certificate directory {}: {error}",
                cert_dir.display()
            ))
        })?;
    }
    validate_project_directory_entry(&cert_dir, ".lpm/certs")?;
    Ok(cert_dir)
}

pub(crate) struct ProjectCertDirectory {
    path: PathBuf,
    dir: Dir,
}

pub(crate) struct ProjectCertMaterial {
    pub(crate) cert: Vec<u8>,
    pub(crate) key: Option<Vec<u8>>,
}

impl ProjectCertDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn read_pair(&self) -> Result<(Vec<u8>, Vec<u8>), LpmError> {
        let cert = read_relative_file(&self.dir, "cert.pem")?;
        let key = read_relative_file(&self.dir, "key.pem")?;
        Ok((cert, key))
    }

    pub(crate) fn read_optional_pair(&self) -> Result<Option<ProjectCertMaterial>, LpmError> {
        if !relative_file_exists(&self.dir, "cert.pem")? {
            return Ok(None);
        }
        let cert = read_relative_file(&self.dir, "cert.pem")?;
        let key = if relative_file_exists(&self.dir, "key.pem")? {
            Some(read_relative_file(&self.dir, "key.pem")?)
        } else {
            None
        };
        Ok(Some(ProjectCertMaterial { cert, key }))
    }

    pub(crate) fn write_pair(&self, cert: &[u8], key: &[u8]) -> Result<(), LpmError> {
        self.write_pair_with_failpoint(cert, key, || Ok(()))
    }

    fn write_pair_with_failpoint(
        &self,
        cert: &[u8],
        key: &[u8],
        after_first_replace: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<(), LpmError> {
        crate::cert::validate_project_key_pair_bytes(cert, key)?;
        reject_linked_entry(&self.dir, "cert.pem")?;
        reject_linked_entry(&self.dir, "key.pem")?;
        let previous_cert = read_optional_relative_file(&self.dir, "cert.pem")?;
        let previous_key = read_optional_relative_file(&self.dir, "key.pem")?;
        let staged_cert = stage_relative_file(&self.dir, cert, 0o644)?;
        let staged_key = match stage_relative_file(&self.dir, key, 0o600) {
            Ok(staged) => staged,
            Err(error) => {
                let _ = self.dir.remove_file(&staged_cert.name);
                return Err(error);
            }
        };
        let transaction = PairTransaction::new(
            "cert.pem",
            "key.pem",
            cert,
            key,
            &staged_cert.name,
            &staged_key.name,
        )?;
        write_pair_transaction(&self.dir, PROJECT_PAIR_TRANSACTION, &transaction)?;

        let result = (|| -> std::io::Result<()> {
            replace_relative_file(&self.dir, &staged_cert.name, "cert.pem", staged_cert.file)?;
            after_first_replace()?;
            replace_relative_file(&self.dir, &staged_key.name, "key.pem", staged_key.file)?;
            sync_directory_io(&self.dir)?;
            Ok(())
        })();
        if let Err(error) = result {
            let cert_rollback =
                restore_relative_file(&self.dir, "cert.pem", previous_cert.as_deref(), 0o644);
            let key_rollback =
                restore_relative_file(&self.dir, "key.pem", previous_key.as_deref(), 0o600);
            let _ = self.dir.remove_file(&staged_cert.name);
            let _ = self.dir.remove_file(&staged_key.name);
            let mut rollback_errors = Vec::with_capacity(2);
            if let Err(rollback_error) = cert_rollback {
                rollback_errors.push(format!("certificate rollback failed: {rollback_error}"));
            }
            if let Err(rollback_error) = key_rollback {
                rollback_errors.push(format!("private-key rollback failed: {rollback_error}"));
            }
            if rollback_errors.is_empty()
                && let Err(transaction_error) =
                    remove_pair_transaction(&self.dir, PROJECT_PAIR_TRANSACTION)
            {
                rollback_errors.push(format!(
                    "recovery transaction removal failed: {transaction_error}"
                ));
            }
            let rollback_context = if rollback_errors.is_empty() {
                String::new()
            } else {
                format!(
                    "; rollback was incomplete and the recovery transaction was retained: {}",
                    rollback_errors.join("; ")
                )
            };
            return Err(LpmError::Cert(format!(
                "failed to replace project certificate pair in {}: {error}{rollback_context}",
                self.path.display()
            )));
        }
        let (written_cert, written_key) = self.read_pair()?;
        crate::cert::validate_project_key_pair_bytes(&written_cert, &written_key)?;
        remove_pair_transaction(&self.dir, PROJECT_PAIR_TRANSACTION)
    }

    #[cfg(test)]
    fn write_atomic(&self, destination: &str, contents: &[u8], mode: u32) -> Result<(), LpmError> {
        reject_linked_entry(&self.dir, destination)?;
        let (temporary_name, mut temporary) = create_temporary(&self.dir, mode)?;
        let result = (|| {
            temporary.write_all(contents)?;
            temporary.flush()?;
            temporary.sync_all()?;
            replace_relative_file(&self.dir, &temporary_name, destination, temporary)
        })();
        if result.is_err() {
            let _ = self.dir.remove_file(&temporary_name);
        }
        result.map_err(|error| {
            LpmError::Cert(format!(
                "failed to atomically write project certificate path {}: {error}",
                self.path.join(destination).display()
            ))
        })
    }
}

struct StagedRelativeFile {
    name: String,
    file: cap_std::fs::File,
}

fn stage_relative_file(
    dir: &Dir,
    contents: &[u8],
    mode: u32,
) -> Result<StagedRelativeFile, LpmError> {
    let (name, mut file) = create_temporary(dir, mode)?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()
    })();
    if let Err(error) = result {
        let _ = dir.remove_file(&name);
        return Err(LpmError::Cert(format!(
            "failed to stage project certificate material: {error}"
        )));
    }
    Ok(StagedRelativeFile { name, file })
}

fn read_optional_relative_file(dir: &Dir, name: &str) -> Result<Option<Vec<u8>>, LpmError> {
    match dir.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(_) => read_relative_file(dir, name).map(Some),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to inspect project certificate path {name}: {error}"
        ))),
    }
}

fn write_pair_transaction(
    dir: &Dir,
    journal_name: &str,
    transaction: &PairTransaction,
) -> Result<(), LpmError> {
    reject_linked_entry(dir, journal_name)?;
    let contents = serde_json::to_vec(transaction).map_err(|error| {
        LpmError::Cert(format!("failed to serialize pair transaction: {error}"))
    })?;
    let staged = stage_relative_file(dir, &contents, 0o600)?;
    replace_relative_file(dir, &staged.name, journal_name, staged.file).map_err(|error| {
        LpmError::Cert(format!(
            "failed to publish certificate pair transaction: {error}"
        ))
    })?;
    sync_directory(dir)
}

fn read_pair_transaction(
    dir: &Dir,
    journal_name: &str,
) -> Result<Option<PairTransaction>, LpmError> {
    let Some(contents) = read_optional_relative_file(dir, journal_name)? else {
        return Ok(None);
    };
    if contents.len() as u64 > lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Cert(
            "certificate pair transaction is too large".into(),
        ));
    }
    let transaction: PairTransaction = serde_json::from_slice(&contents).map_err(|error| {
        LpmError::Cert(format!(
            "failed to parse certificate pair transaction: {error}"
        ))
    })?;
    validate_relative_filename(&transaction.cert_name)?;
    validate_relative_filename(&transaction.key_name)?;
    validate_temporary_filename(&transaction.staged_cert_name)?;
    validate_temporary_filename(&transaction.staged_key_name)?;
    Ok(Some(transaction))
}

fn remove_pair_transaction(dir: &Dir, journal_name: &str) -> Result<(), LpmError> {
    match remove_relative_file(dir, journal_name) {
        Ok(true) => sync_directory(dir),
        Ok(false) => Ok(()),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to remove certificate pair transaction: {error}"
        ))),
    }
}

fn recover_global_pair_transaction(ca: &GlobalCaDirectory) -> Result<(), LpmError> {
    let Some(transaction) = read_pair_transaction(&ca.dir, GLOBAL_PAIR_TRANSACTION)? else {
        return Ok(());
    };
    let cert = transaction.cert_pem.as_bytes();
    let key = transaction.key_pem.as_bytes();
    crate::cert::validate_ca_key_pair(&transaction.cert_pem, &transaction.key_pem)
        .map_err(|error| LpmError::Cert(format!("invalid recovering CA pair: {error}")))?;
    restore_relative_file(&ca.dir, &transaction.cert_name, Some(cert), 0o644)?;
    restore_relative_file(&ca.dir, &transaction.key_name, Some(key), 0o600)?;
    let _ = ca.dir.remove_file(&transaction.staged_cert_name);
    let _ = ca.dir.remove_file(&transaction.staged_key_name);
    remove_pair_transaction(&ca.dir, GLOBAL_PAIR_TRANSACTION)
}

fn recover_project_pair_transaction(directory: &ProjectCertDirectory) -> Result<(), LpmError> {
    let Some(transaction) = read_pair_transaction(&directory.dir, PROJECT_PAIR_TRANSACTION)? else {
        return Ok(());
    };
    let cert = transaction.cert_pem.as_bytes();
    let key = transaction.key_pem.as_bytes();
    crate::cert::validate_project_key_pair_bytes(cert, key)?;
    restore_relative_file(&directory.dir, &transaction.cert_name, Some(cert), 0o644)?;
    restore_relative_file(&directory.dir, &transaction.key_name, Some(key), 0o600)?;
    let _ = directory.dir.remove_file(&transaction.staged_cert_name);
    let _ = directory.dir.remove_file(&transaction.staged_key_name);
    remove_pair_transaction(&directory.dir, PROJECT_PAIR_TRANSACTION)
}

fn sync_directory(dir: &Dir) -> Result<(), LpmError> {
    sync_directory_io(dir)
        .map_err(|error| LpmError::Cert(format!("failed to sync certificate directory: {error}")))
}

fn sync_directory_io(dir: &Dir) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
        return Err(std::io::Error::other(
            "injected certificate directory sync failure",
        ));
    }
    #[cfg(windows)]
    {
        let _ = dir;
        // Windows FlushFileBuffers rejects ordinary directory handles. Staged files are flushed
        // before replacement, and the renamed file handle is flushed again after the atomic rename.
        // Flushing the containing volume would require administrator privileges.
        Ok(())
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        let sync_handle = {
            use std::os::fd::{AsRawFd as _, FromRawFd as _};

            // SAFETY: `dir` stays open for the call, the relative path is NUL-terminated, and the
            // returned descriptor is checked before ownership is transferred to `File` exactly once.
            // A fresh read descriptor is required because cap-std intentionally retains Linux
            // directories as O_PATH handles, which cannot be passed to fsync.
            let descriptor = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `descriptor` is a newly owned descriptor returned by `openat` above.
            unsafe { std::fs::File::from_raw_fd(descriptor) }
        };
        #[cfg(not(target_os = "linux"))]
        let sync_handle = dir.try_clone()?.into_std_file();
        sync_handle.sync_all()
    }
}

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_DIRECTORY_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fail_next_directory_sync() {
    FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.set(true));
}

fn relative_file_exists(dir: &Dir, name: &str) -> Result<bool, LpmError> {
    match dir.symlink_metadata(name) {
        Ok(metadata) if metadata_is_link_or_reparse(&metadata) => Err(LpmError::Cert(format!(
            "refusing linked project certificate path {name}"
        ))),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(LpmError::Cert(format!(
            "project certificate path {name} is not a regular file"
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to inspect project certificate path {name}: {error}"
        ))),
    }
}

fn restore_relative_file(
    dir: &Dir,
    destination: &str,
    previous: Option<&[u8]>,
    mode: u32,
) -> Result<(), LpmError> {
    match previous {
        Some(contents) => {
            let staged = stage_relative_file(dir, contents, mode)?;
            replace_relative_file(dir, &staged.name, destination, staged.file).map_err(|error| {
                LpmError::Cert(format!(
                    "failed to restore project certificate path {destination}: {error}"
                ))
            })
        }
        None => match remove_relative_file(dir, destination) {
            Ok(_) => Ok(()),
            Err(error) => Err(LpmError::Cert(format!(
                "failed to remove newly created project certificate path {destination}: {error}"
            ))),
        },
    }
}

fn read_relative_file(dir: &Dir, name: &str) -> Result<Vec<u8>, LpmError> {
    reject_linked_entry(dir, name)?;
    read_bounded_relative_file(dir, name, "project certificate")
}

fn read_bounded_relative_file(dir: &Dir, name: &str, label: &str) -> Result<Vec<u8>, LpmError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};

    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.read(true);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};

        options.access_mode(GENERIC_READ | READ_CONTROL | WRITE_DAC);
    }
    options.follow(FollowSymlinks::No);
    let file = dir
        .open_with(name, &options)
        .map_err(|error| LpmError::Cert(format!("failed to open {label} path {name}: {error}")))?;
    #[cfg(windows)]
    windows_security::protect_cap_file(&file).map_err(|error| {
        LpmError::Cert(format!("failed to protect {label} path {name}: {error}"))
    })?;
    let metadata = file.metadata().map_err(|error| {
        LpmError::Cert(format!("failed to inspect {label} path {name}: {error}"))
    })?;
    if !metadata.is_file() || metadata.len() > lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Cert(format!(
            "{label} path {name} is not a bounded regular file"
        )));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::take(file, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|error| LpmError::Cert(format!("failed to read {label} path {name}: {error}")))?;
    if contents.len() as u64 > lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Cert(format!("{label} path {name} is too large")));
    }
    Ok(contents)
}

pub(crate) fn write_sensitive_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("certificate key path has no filename: {}", path.display()),
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    let destination = name.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "certificate key filename is not valid UTF-8",
        )
    })?;
    validate_relative_filename(destination)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let (temporary_name, mut temporary) =
        create_temporary(&dir, 0o600).map_err(|error| std::io::Error::other(error.to_string()))?;
    let result = (|| {
        temporary.write_all(contents)?;
        temporary.flush()?;
        temporary.sync_all()?;
        replace_relative_file(&dir, &temporary_name, destination, temporary)?;
        sync_directory_io(&dir)
    })();
    if result.is_err() {
        let _ = dir.remove_file(&temporary_name);
    }
    result
}

fn reject_linked_global_entry(dir: &Dir, name: &str, path: &Path) -> Result<(), LpmError> {
    match dir.symlink_metadata(name) {
        Ok(metadata) if metadata_is_link_or_reparse(&metadata) => Err(LpmError::Cert(format!(
            "refusing linked global certificate path {}",
            path.join(name).display()
        ))),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(LpmError::Cert(format!(
            "global certificate path {} is not a regular file",
            path.join(name).display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to inspect global certificate path {}: {error}",
            path.join(name).display()
        ))),
    }
}

pub(crate) fn open_project_cert_directory(
    project_dir: &Path,
    create: bool,
) -> Result<Option<ProjectCertDirectory>, LpmError> {
    let project_path = project_dir.canonicalize().map_err(|error| {
        LpmError::Cert(format!(
            "failed to resolve project directory {}: {error}",
            project_dir.display()
        ))
    })?;
    let project =
        Dir::open_ambient_dir(&project_path, cap_std::ambient_authority()).map_err(|error| {
            LpmError::Cert(format!(
                "failed to open project directory {}: {error}",
                project_path.display()
            ))
        })?;
    let Some(state) = open_or_create_directory(&project, ".lpm", create, ".lpm")? else {
        return Ok(None);
    };
    let Some(certs) = open_or_create_directory(&state, "certs", create, ".lpm/certs")? else {
        return Ok(None);
    };
    let directory = ProjectCertDirectory {
        path: project_path.join(".lpm/certs"),
        dir: certs,
    };
    recover_project_pair_transaction(&directory)?;
    Ok(Some(directory))
}

fn open_or_create_directory(
    parent: &Dir,
    name: &str,
    create: bool,
    label: &str,
) -> Result<Option<Dir>, LpmError> {
    let open = || open_directory_nofollow(parent, name);

    match open() {
        Ok(dir) => {
            verify_path_identity(parent, name, &dir, label)?;
            tighten_directory_permissions(&dir, label)?;
            Ok(Some(dir))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
            match parent.create_dir(name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(LpmError::Cert(format!(
                        "failed to create project certificate directory `{label}`: {error}"
                    )));
                }
            }
            let dir = open()?;
            verify_path_identity(parent, name, &dir, label)?;
            tighten_directory_permissions(&dir, label)?;
            Ok(Some(dir))
        }
        Err(error) => Err(LpmError::Cert(format!(
            "failed to open project certificate directory `{label}` without following links: {error}"
        ))),
    }
}

fn open_directory_nofollow(parent: &Dir, name: &str) -> std::io::Result<Dir> {
    let parent_file = parent.try_clone()?.into_std_file();
    cap_primitives::fs::open_dir_nofollow(&parent_file, Path::new(name)).map(Dir::from_std_file)
}

fn verify_path_identity(
    parent: &Dir,
    name: &str,
    opened: &Dir,
    label: &str,
) -> Result<(), LpmError> {
    let current = open_directory_nofollow(parent, name).map_err(|error| {
        LpmError::Cert(format!(
            "project certificate directory `{label}` changed while it was opened: {error}"
        ))
    })?;
    let opened =
        same_file::Handle::from_file(opened.try_clone()?.into_std_file()).map_err(|error| {
            LpmError::Cert(format!(
                "failed to identify opened project certificate directory `{label}`: {error}"
            ))
        })?;
    let current = same_file::Handle::from_file(current.into_std_file()).map_err(|error| {
        LpmError::Cert(format!(
            "failed to identify current project certificate directory `{label}`: {error}"
        ))
    })?;
    if opened == current {
        Ok(())
    } else {
        Err(LpmError::Cert(format!(
            "project certificate directory `{label}` changed while it was opened"
        )))
    }
}

#[cfg(unix)]
fn tighten_directory_permissions(dir: &Dir, label: &str) -> Result<(), LpmError> {
    use cap_std::fs::PermissionsExt as _;

    dir.set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
        .map_err(|error| {
            LpmError::Cert(format!(
                "failed to tighten project certificate directory `{label}`: {error}"
            ))
        })
}

#[cfg(windows)]
fn tighten_directory_permissions(dir: &Dir, label: &str) -> Result<(), LpmError> {
    windows_security::protect_directory(dir).map_err(|error| {
        LpmError::Cert(format!(
            "failed to protect certificate directory `{label}`: {error}"
        ))
    })
}

#[cfg(not(any(unix, windows)))]
fn tighten_directory_permissions(_dir: &Dir, _label: &str) -> Result<(), LpmError> {
    Ok(())
}

fn reject_linked_entry(dir: &Dir, name: &str) -> Result<(), LpmError> {
    match dir.symlink_metadata(name) {
        Ok(metadata) if metadata_is_link_or_reparse(&metadata) => Err(LpmError::Cert(format!(
            "refusing linked project certificate path {name}"
        ))),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(LpmError::Cert(format!(
            "project certificate path {name} is not a regular file"
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to inspect project certificate path {name}: {error}"
        ))),
    }
}

#[cfg(not(windows))]
fn metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
fn metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn create_temporary(dir: &Dir, mode: u32) -> Result<(String, cap_std::fs::File), LpmError> {
    let mut last_collision = None;
    for _ in 0..32 {
        let name = format!(".lpm-cert-{:032x}", rand::random::<u128>());
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows_sys::Win32::Storage::FileSystem::{DELETE, READ_CONTROL, WRITE_DAC};

            let _ = mode;
            options.access_mode(GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC);
        }
        #[cfg(not(any(unix, windows)))]
        let _ = mode;
        match dir.open_with(&name, &options) {
            Ok(file) => {
                #[cfg(windows)]
                if let Err(error) = windows_security::protect_cap_file(&file) {
                    drop(file);
                    let _ = dir.remove_file(&name);
                    return Err(LpmError::Cert(format!(
                        "failed to protect temporary certificate file: {error}"
                    )));
                }
                return Ok((name, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => {
                return Err(LpmError::Cert(format!(
                    "failed to create temporary project certificate file: {error}"
                )));
            }
        }
    }
    Err(LpmError::Cert(format!(
        "failed to allocate a temporary project certificate file: {}",
        last_collision.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::AlreadyExists))
    )))
}

fn remove_relative_file(dir: &Dir, name: &str) -> std::io::Result<bool> {
    #[cfg(not(windows))]
    {
        match dir.remove_file(name) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    #[cfg(windows)]
    {
        for (attempt, delay_ms) in WINDOWS_FILE_OPERATION_RETRY_DELAYS_MS.iter().enumerate() {
            if *delay_ms != 0 {
                std::thread::sleep(std::time::Duration::from_millis(*delay_ms));
            }
            match dir.remove_file(name) {
                Ok(()) => return Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error)
                    if is_transient_windows_file_operation_error(&error)
                        && attempt + 1 < WINDOWS_FILE_OPERATION_RETRY_DELAYS_MS.len() => {}
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::other(
            "certificate file removal retry loop exhausted",
        ))
    }
}

#[cfg(windows)]
fn is_transient_windows_file_operation_error(error: &std::io::Error) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

    matches!(
        error.raw_os_error().map(|code| code as u32),
        Some(ERROR_SHARING_VIOLATION) | Some(ERROR_ACCESS_DENIED)
    )
}

fn replace_relative_file(
    dir: &Dir,
    source: &str,
    destination: &str,
    temporary: cap_std::fs::File,
) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        let _temporary = temporary;
        dir.rename(source, dir, destination)
    }
    #[cfg(windows)]
    {
        use std::mem::{offset_of, size_of};
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
        };
        use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
        use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

        let _ = source;
        let destination: Vec<u16> = Path::new(destination).as_os_str().encode_wide().collect();
        let file_name_bytes = destination
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| std::io::Error::other("certificate filename is too long"))?;
        let info_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
            .checked_add(file_name_bytes)
            .ok_or_else(|| std::io::Error::other("certificate rename data is too large"))?;
        let info_words = info_bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; info_words];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let info_bytes = u32::try_from(info_bytes)
            .map_err(|_| std::io::Error::other("certificate rename data is too large"))?;
        let file_name_bytes = u32::try_from(file_name_bytes)
            .map_err(|_| std::io::Error::other("certificate filename is too long"))?;
        unsafe {
            // SAFETY: storage is pointer-aligned and sized for FILE_RENAME_INFO plus
            // the complete relative UTF-16 filename. Both handles stay open through
            // every synchronous rename attempt.
            (*info).Anonymous.ReplaceIfExists = true;
            (*info).RootDirectory = dir.as_raw_handle();
            (*info).FileNameLength = file_name_bytes;
            std::ptr::copy_nonoverlapping(
                destination.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                destination.len(),
            );
        }
        for (attempt, delay_ms) in WINDOWS_FILE_OPERATION_RETRY_DELAYS_MS.iter().enumerate() {
            if *delay_ms != 0 {
                std::thread::sleep(std::time::Duration::from_millis(*delay_ms));
            }
            let mut io_status = IO_STATUS_BLOCK::default();
            let status = unsafe {
                // SAFETY: `info` points to the initialized variable-sized buffer described above.
                // Both retained handles remain valid for this synchronous native rename call.
                NtSetInformationFile(
                    temporary.as_raw_handle(),
                    &mut io_status,
                    info.cast(),
                    info_bytes,
                    FileRenameInformation,
                )
            };
            if status >= 0 {
                return temporary.sync_all();
            }
            // SAFETY: `status` is the NTSTATUS returned by `NtSetInformationFile`.
            let error =
                std::io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32);
            if !is_transient_windows_file_operation_error(&error)
                || attempt + 1 == WINDOWS_FILE_OPERATION_RETRY_DELAYS_MS.len()
            {
                return Err(error);
            }
        }
        Err(std::io::Error::other(
            "atomic project certificate replacement retry loop exhausted",
        ))
    }
}

pub(crate) fn reject_linked_project_cert_file(path: &Path) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) => {
            Err(LpmError::Cert(format!(
                "refusing linked project certificate path {}",
                path.display()
            )))
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(LpmError::Cert(format!(
            "project certificate path {} is not a regular file",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to inspect project certificate path {}: {error}",
            path.display()
        ))),
    }
}

fn validate_project_directory_entry(path: &Path, label: &str) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) => Err(LpmError::Cert(
            format!("refusing linked project certificate directory `{label}`"),
        )),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(LpmError::Cert(format!(
            "project certificate path `{label}` is not a directory"
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to inspect project certificate directory `{label}`: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    fn windows_acl_handle(path: &Path, directory: bool) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
        };

        let mut options = std::fs::OpenOptions::new();
        options
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(if directory {
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
            } else {
                FILE_FLAG_OPEN_REPARSE_POINT
            });
        options.open(path).unwrap()
    }

    #[cfg(windows)]
    fn windows_project_with_inheritable_everyone_read() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("permissive-parent");
        std::fs::create_dir(&parent).unwrap();
        let parent_handle = windows_acl_handle(&parent, true);
        windows_security::apply_inheritable_everyone_read(&parent_handle).unwrap();
        let project = parent.join("project");
        std::fs::create_dir(&project).unwrap();
        (root, project)
    }

    #[cfg(windows)]
    fn assert_windows_owner_system_dacl(path: &Path, directory: bool) {
        let handle = windows_acl_handle(path, directory);
        let sddl = windows_security::descriptor_sddl(&handle).unwrap();
        assert!(sddl.starts_with("D:P"), "DACL is not protected: {sddl}");
        assert!(
            !sddl.contains(";;;WD)"),
            "DACL still grants Everyone: {sddl}"
        );
        assert!(sddl.contains(";;;OW)"), "DACL omits owner rights: {sddl}");
        assert!(sddl.contains(";;;SY)"), "DACL omits SYSTEM: {sddl}");
    }

    #[test]
    fn global_certificate_paths_follow_the_lpm_home_override() {
        let _serial = crate::test_env_lock();
        let root = tempfile::tempdir().unwrap();
        let _restore = EnvGuard::set("LPM_HOME", root.path());

        assert_eq!(ca_dir().unwrap(), root.path().join("certs"));
    }

    #[test]
    fn ca_paths_are_under_lpm_root() {
        let _serial = crate::test_env_lock();
        let root = tempfile::tempdir().unwrap();
        let _restore = EnvGuard::set("LPM_HOME", root.path());
        let ca = ca_dir().unwrap();
        assert_eq!(ca, root.path().join("certs"));

        let cert = ca_cert_path().unwrap();
        assert!(cert.ends_with("rootCA.pem"));

        let key = ca_key_path().unwrap();
        assert!(key.ends_with("rootCA-key.pem"));
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.previous.take() {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn project_paths_are_under_project() {
        let project = Path::new("/tmp/my-project");
        let dir = project_cert_dir(project).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/my-project/.lpm/certs"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syncing_linux_capability_directory_uses_an_fsync_capable_handle() {
        let root = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();

        sync_directory_io(&dir).unwrap();
    }

    #[test]
    fn directory_sync_failure_injection_is_confined_to_the_requesting_thread() {
        let root = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        fail_next_directory_sync();
        let other_path = root.path().to_owned();

        let other_result = std::thread::spawn(move || {
            let other = Dir::open_ambient_dir(&other_path, cap_std::ambient_authority()).unwrap();
            sync_directory_io(&other)
        })
        .join()
        .unwrap();

        assert!(
            other_result.is_ok(),
            "failure injection escaped to another thread: {other_result:?}"
        );
        assert_eq!(
            sync_directory_io(&dir).unwrap_err().to_string(),
            "injected certificate directory sync failure"
        );
    }

    #[cfg(windows)]
    #[test]
    fn syncing_windows_capability_directory_avoids_unsupported_file_flush() {
        let root = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();

        sync_directory_io(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_atomic_write_replaces_an_existing_certificate_file() {
        let project = tempfile::tempdir().unwrap();
        let cert_dir = open_project_cert_directory(project.path(), true)
            .unwrap()
            .unwrap();

        cert_dir
            .write_atomic("cert.pem", b"original", 0o644)
            .unwrap();
        cert_dir
            .write_atomic("cert.pem", b"replacement", 0o644)
            .unwrap();

        assert_eq!(
            read_relative_file(&cert_dir.dir, "cert.pem").unwrap(),
            b"replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn opening_project_cert_directory_tightens_existing_directory_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        let state_dir = project.path().join(".lpm");
        let cert_dir = state_dir.join("certs");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&cert_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        open_project_cert_directory(project.path(), false)
            .unwrap()
            .unwrap();

        assert_eq!(
            std::fs::metadata(state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(cert_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn opened_project_cert_directory_remains_bound_when_path_is_replaced() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let cert_dir = open_project_cert_directory(project.path(), true)
            .unwrap()
            .unwrap();
        let cert_path = cert_dir.path().to_path_buf();
        let displaced = project.path().join("displaced-certs");

        std::fs::rename(&cert_path, &displaced).unwrap();
        std::os::unix::fs::symlink(outside.path(), &cert_path).unwrap();
        cert_dir
            .write_atomic("cert.pem", b"certificate", 0o644)
            .unwrap();

        assert!(
            !outside.path().join("cert.pem").exists(),
            "a swapped certificate directory redirected the write outside the project"
        );
        assert_eq!(
            std::fs::read(displaced.join("cert.pem")).unwrap(),
            b"certificate"
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_cert_directory_rejects_a_swapped_existing_certificate_file() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"outside").unwrap();
        let cert_dir = open_project_cert_directory(project.path(), true)
            .unwrap()
            .unwrap();
        let cert_path = cert_dir.path().join("cert.pem");
        std::os::unix::fs::symlink(outside.path(), &cert_path).unwrap();

        let error = cert_dir
            .write_atomic("cert.pem", b"certificate", 0o644)
            .unwrap_err();

        assert!(error.to_string().contains("refusing linked"));
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"outside");
    }

    #[cfg(windows)]
    #[test]
    fn opened_project_cert_directory_prevents_ancestor_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let _cert_dir = open_project_cert_directory(&project, true)
            .unwrap()
            .unwrap();
        let displaced = root.path().join("displaced-project");

        let error = std::fs::rename(&project, &displaced).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(project.join(".lpm/certs").is_dir());
        assert!(!displaced.exists());
    }

    #[cfg(windows)]
    #[test]
    fn relative_file_removal_retries_until_windows_delete_sharing_is_released() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("locked.pem");
        std::fs::write(&path, b"certificate").unwrap();
        let locked = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let release = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(locked);
        });
        started_rx.recv().unwrap();
        let dir = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();

        assert!(remove_relative_file(&dir, "locked.pem").unwrap());

        release.join().unwrap();
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn project_certificate_directories_replace_inherited_everyone_read() {
        let (_root, project) = windows_project_with_inheritable_everyone_read();

        open_project_cert_directory(&project, true)
            .unwrap()
            .unwrap();

        assert_windows_owner_system_dacl(&project.join(".lpm"), true);
        assert_windows_owner_system_dacl(&project.join(".lpm/certs"), true);
    }

    #[cfg(windows)]
    #[test]
    fn temporary_and_key_files_replace_inherited_everyone_read() {
        let (_root, project) = windows_project_with_inheritable_everyone_read();
        let cert_dir = open_project_cert_directory(&project, true)
            .unwrap()
            .unwrap();
        let (temporary_name, temporary) = create_temporary(&cert_dir.dir, 0o600).unwrap();
        let temporary_path = cert_dir.path().join(&temporary_name);

        assert_windows_owner_system_dacl(&temporary_path, false);
        drop(temporary);
        cert_dir.dir.remove_file(&temporary_name).unwrap();

        let key_path = cert_dir.path().join("manual-key.pem");
        crate::write_key_file(&key_path, b"private-key-material").unwrap();
        assert_windows_owner_system_dacl(&key_path, false);
    }

    #[cfg(windows)]
    #[test]
    fn pair_and_rotation_journals_replace_inherited_everyone_read() {
        let (root, project) = windows_project_with_inheritable_everyone_read();
        let cert_dir = open_project_cert_directory(&project, true)
            .unwrap()
            .unwrap();
        let transaction = PairTransaction {
            cert_name: "cert.pem".to_string(),
            key_name: "key.pem".to_string(),
            cert_pem: "certificate".to_string(),
            key_pem: "private-key-material".to_string(),
            staged_cert_name: ".lpm-cert-00000000000000000000000000000000".to_string(),
            staged_key_name: ".lpm-cert-11111111111111111111111111111111".to_string(),
        };
        write_pair_transaction(&cert_dir.dir, PROJECT_PAIR_TRANSACTION, &transaction).unwrap();
        assert_windows_owner_system_dacl(&cert_dir.path().join(PROJECT_PAIR_TRANSACTION), false);

        let global_home = root.path().join("global-home");
        std::fs::create_dir(&global_home).unwrap();
        let global_home_handle = windows_acl_handle(&global_home, true);
        windows_security::apply_inheritable_everyone_read(&global_home_handle).unwrap();
        drop(global_home_handle);
        let ca = open_global_ca_directory_at(global_home, true).unwrap();
        ca.write("rootCA.rotation.json", b"private-key-material", 0o600)
            .unwrap();
        assert_windows_owner_system_dacl(&ca.path("rootCA.rotation.json"), false);
    }

    #[cfg(windows)]
    #[test]
    fn reopening_existing_certificate_artifact_replaces_everyone_read() {
        let (_root, project) = windows_project_with_inheritable_everyone_read();
        let cert_dir = open_project_cert_directory(&project, true)
            .unwrap()
            .unwrap();
        let key_path = cert_dir.path().join("recovery-key.pem");
        std::fs::write(&key_path, b"private-key-material").unwrap();
        let permissive_handle = windows_acl_handle(&key_path, false);
        windows_security::apply_inheritable_everyone_read(&permissive_handle).unwrap();
        let permissive_sddl = windows_security::descriptor_sddl(&permissive_handle).unwrap();
        assert!(permissive_sddl.contains(";;;WD)"));
        drop(permissive_handle);

        let contents =
            read_bounded_relative_file(&cert_dir.dir, "recovery-key.pem", "recovery").unwrap();

        assert_eq!(contents, b"private-key-material");
        assert_windows_owner_system_dacl(&key_path, false);
    }

    #[test]
    fn pair_replacement_failure_preserves_the_original_matching_pair() {
        let project = tempfile::tempdir().unwrap();
        let cert_dir = open_project_cert_directory(project.path(), true)
            .unwrap()
            .unwrap();
        let (root_cert, root_key) = crate::ca::generate_ca().unwrap();
        let (old_cert, old_key) =
            crate::cert::generate_project_cert(&root_cert, &root_key, &[]).unwrap();
        let (new_cert, new_key) = crate::cert::generate_project_cert(
            &root_cert,
            &root_key,
            &["replacement.localhost".to_string()],
        )
        .unwrap();
        cert_dir
            .write_pair(old_cert.as_bytes(), old_key.as_bytes())
            .unwrap();

        let error = cert_dir
            .write_pair_with_failpoint(new_cert.as_bytes(), new_key.as_bytes(), || {
                Err(std::io::Error::other("injected key replacement failure"))
            })
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected key replacement failure")
        );
        let (actual_cert, actual_key) = cert_dir.read_pair().unwrap();
        assert_eq!(actual_cert, old_cert.as_bytes());
        assert_eq!(actual_key, old_key.as_bytes());
        crate::cert::validate_project_key_pair_bytes(&actual_cert, &actual_key).unwrap();
    }

    #[test]
    fn project_pair_rollback_failure_retains_the_recovery_transaction() {
        let project = tempfile::tempdir().unwrap();
        let cert_dir = open_project_cert_directory(project.path(), true)
            .unwrap()
            .unwrap();
        let (root_cert, root_key) = crate::ca::generate_ca().unwrap();
        let (old_cert, old_key) =
            crate::cert::generate_project_cert(&root_cert, &root_key, &[]).unwrap();
        let (new_cert, new_key) = crate::cert::generate_project_cert(
            &root_cert,
            &root_key,
            &["replacement.localhost".to_string()],
        )
        .unwrap();
        cert_dir
            .write_pair(old_cert.as_bytes(), old_key.as_bytes())
            .unwrap();
        let key_path = cert_dir.path().join("key.pem");

        let error = cert_dir
            .write_pair_with_failpoint(new_cert.as_bytes(), new_key.as_bytes(), || {
                std::fs::remove_file(&key_path)?;
                std::fs::create_dir(&key_path)?;
                Err(std::io::Error::other("injected key replacement failure"))
            })
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected key replacement failure")
        );
        assert!(cert_dir.path().join(PROJECT_PAIR_TRANSACTION).exists());

        std::fs::remove_dir(&key_path).unwrap();
        drop(cert_dir);
        let reopened = open_project_cert_directory(project.path(), true)
            .unwrap()
            .unwrap();
        let (actual_cert, actual_key) = reopened.read_pair().unwrap();
        assert_eq!(actual_cert, new_cert.as_bytes());
        assert_eq!(actual_key, new_key.as_bytes());
    }

    #[test]
    fn reopening_project_cert_directory_recovers_a_crash_between_pair_replacements() {
        let project = tempfile::tempdir().unwrap();
        let cert_dir = open_project_cert_directory(project.path(), true)
            .unwrap()
            .unwrap();
        let (root_cert, root_key) = crate::ca::generate_ca().unwrap();
        let (old_cert, old_key) =
            crate::cert::generate_project_cert(&root_cert, &root_key, &[]).unwrap();
        let (new_cert, new_key) = crate::cert::generate_project_cert(
            &root_cert,
            &root_key,
            &["replacement.localhost".to_string()],
        )
        .unwrap();
        cert_dir
            .write_pair(old_cert.as_bytes(), old_key.as_bytes())
            .unwrap();

        let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ =
                cert_dir.write_pair_with_failpoint(new_cert.as_bytes(), new_key.as_bytes(), || {
                    panic!("simulated process termination after certificate replacement")
                });
        }));
        assert!(crash.is_err());
        drop(cert_dir);

        let reopened = open_project_cert_directory(project.path(), true)
            .unwrap()
            .unwrap();
        let (actual_cert, actual_key) = reopened.read_pair().unwrap();
        crate::cert::validate_project_key_pair_bytes(&actual_cert, &actual_key).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn retained_global_ca_directory_cannot_be_redirected_after_a_path_swap() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ca = open_global_ca_directory_at(home.path().to_path_buf(), true).unwrap();
        let cert_path = ca.path.clone();
        let displaced = home.path().join("displaced-certs");

        std::fs::rename(&cert_path, &displaced).unwrap();
        std::os::unix::fs::symlink(outside.path(), &cert_path).unwrap();
        ca.write("rootCA.pem", b"verified", 0o644).unwrap();

        assert!(!outside.path().join("rootCA.pem").exists());
        assert_eq!(
            std::fs::read(displaced.join("rootCA.pem")).unwrap(),
            b"verified"
        );
    }

    #[cfg(unix)]
    #[test]
    fn global_ca_operation_lock_rejects_a_symlink() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let ca = open_global_ca_directory_at(home.path().to_path_buf(), true).unwrap();
        std::os::unix::fs::symlink(outside.path(), ca.path(".operations.lock")).unwrap();

        let Err(error) = ca.acquire_operations_lock() else {
            panic!("symlinked global certificate operation lock was accepted");
        };

        assert!(error.to_string().contains("refusing linked"));
    }

    #[test]
    fn global_ca_pair_replacement_failure_preserves_the_original_matching_pair() {
        let home = tempfile::tempdir().unwrap();
        let ca = open_global_ca_directory_at(home.path().to_path_buf(), true).unwrap();
        let (old_cert, old_key) = crate::ca::generate_ca().unwrap();
        let (new_cert, new_key) = crate::ca::generate_ca().unwrap();
        ca.write("rootCA.pem", old_cert.as_bytes(), 0o644).unwrap();
        ca.write("rootCA-key.pem", old_key.as_bytes(), 0o600)
            .unwrap();

        let error = ca
            .write_ca_pair_with_failpoint(
                "rootCA.pem",
                "rootCA-key.pem",
                new_cert.as_bytes(),
                new_key.as_bytes(),
                || Err(LpmError::Cert("injected key promotion failure".into())),
            )
            .unwrap_err();

        assert!(error.to_string().contains("injected key promotion failure"));
        let actual_cert = ca.read("rootCA.pem").unwrap();
        let actual_key = ca.read("rootCA-key.pem").unwrap();
        assert_eq!(actual_cert, old_cert.as_bytes());
        assert_eq!(actual_key, old_key.as_bytes());
        crate::cert::validate_ca_key_pair(
            std::str::from_utf8(&actual_cert).unwrap(),
            std::str::from_utf8(&actual_key).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn beginning_certificate_operation_recovers_a_crash_between_ca_pair_replacements() {
        let home = tempfile::tempdir().unwrap();
        let operation = CertificateOperation::begin_at(home.path().to_path_buf()).unwrap();
        let (old_cert, old_key) = crate::ca::generate_ca().unwrap();
        let (new_cert, new_key) = crate::ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                old_cert.as_bytes(),
                old_key.as_bytes(),
            )
            .unwrap();

        let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = operation.ca.write_ca_pair_with_failpoint(
                "rootCA.pem",
                "rootCA-key.pem",
                new_cert.as_bytes(),
                new_key.as_bytes(),
                || panic!("simulated process termination after certificate replacement"),
            );
        }));
        assert!(crash.is_err());
        drop(operation);

        let reopened = CertificateOperation::begin_at(home.path().to_path_buf()).unwrap();
        let actual_cert = reopened.ca.read("rootCA.pem").unwrap();
        let actual_key = reopened.ca.read("rootCA-key.pem").unwrap();
        crate::cert::validate_ca_key_pair(
            std::str::from_utf8(&actual_cert).unwrap(),
            std::str::from_utf8(&actual_key).unwrap(),
        )
        .unwrap();
    }
}
