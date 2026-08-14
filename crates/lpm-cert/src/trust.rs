//! System trust store management.
//!
//! Installs/removes the LPM root CA from the OS trust store so browsers
//! and Node.js trust certificates signed by it. Detection and removal are
//! fingerprint-keyed, not CN-keyed: a different cert that happens to share the LPM CN
//! is never mistaken for the legitimate root.

use crate::cert;
use lpm_common::LpmError;
use std::path::Path;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Stdio;

#[cfg(any(target_os = "macos", target_os = "windows"))]
const CA_COMMON_NAME: &str = "LPM Local Development CA";
const TEST_TRUST_STORE_DIR_ENV: &str = "LPM_CERT_TEST_TRUST_STORE_DIR";

#[cfg(target_os = "macos")]
const SECURITY_EXECUTABLE: &str = "/usr/bin/security";
#[cfg(target_os = "linux")]
const SUDO_EXECUTABLE_CANDIDATES: &[&str] = &[
    "/usr/bin/sudo",
    "/bin/sudo",
    "/run/wrappers/bin/sudo",
    "/nix/var/nix/profiles/default/bin/sudo",
];
#[cfg(target_os = "linux")]
const INSTALL_EXECUTABLE_CANDIDATES: &[&str] = &["/usr/bin/install", "/bin/install"];
#[cfg(target_os = "linux")]
const REMOVE_EXECUTABLE_CANDIDATES: &[&str] = &["/usr/bin/rm", "/bin/rm"];
#[cfg(target_os = "linux")]
const UPDATE_CA_EXECUTABLE_CANDIDATES: &[&str] = &[
    "/usr/sbin/update-ca-certificates",
    "/sbin/update-ca-certificates",
    "/usr/bin/update-ca-certificates",
    "/bin/update-ca-certificates",
];
#[cfg(target_os = "linux")]
const UPDATE_CA_TRUST_EXECUTABLE_CANDIDATES: &[&str] = &[
    "/usr/bin/update-ca-trust",
    "/bin/update-ca-trust",
    "/usr/sbin/update-ca-trust",
    "/sbin/update-ca-trust",
];

#[cfg(any(target_os = "linux", test))]
const UPDATE_CA_CERTIFICATES_SOURCE_PATH: &str =
    "/usr/local/share/ca-certificates/lpm-local-ca.crt";
#[cfg(any(target_os = "linux", test))]
const UPDATE_CA_CERTIFICATES_BUNDLE_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";
#[cfg(any(target_os = "linux", test))]
const UPDATE_CA_TRUST_SOURCE_PATH: &str = "/etc/pki/ca-trust/source/anchors/lpm-local-ca.crt";
#[cfg(any(target_os = "linux", test))]
const UPDATE_CA_TRUST_BUNDLE_PATH: &str = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";
#[cfg(any(target_os = "linux", test))]
const LINUX_CA_BUNDLE_SIZE_CAP_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxTrustBackendKind {
    UpdateCaCertificates,
    UpdateCaTrust,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxTrustBackend {
    kind: LinuxTrustBackendKind,
    source_path: &'static str,
    bundle_path: &'static str,
    update_executable: &'static str,
}

#[cfg(any(target_os = "linux", test))]
fn select_linux_trust_backend(
    update_ca_certificates: Option<&'static str>,
    update_ca_certificates_layout_ready: bool,
    update_ca_trust: Option<&'static str>,
    update_ca_trust_layout_ready: bool,
) -> Result<LinuxTrustBackend, LpmError> {
    if let Some(update_executable) = update_ca_certificates
        && update_ca_certificates_layout_ready
    {
        return Ok(LinuxTrustBackend {
            kind: LinuxTrustBackendKind::UpdateCaCertificates,
            source_path: UPDATE_CA_CERTIFICATES_SOURCE_PATH,
            bundle_path: UPDATE_CA_CERTIFICATES_BUNDLE_PATH,
            update_executable,
        });
    }
    if let Some(update_executable) = update_ca_trust
        && update_ca_trust_layout_ready
    {
        return Ok(LinuxTrustBackend {
            kind: LinuxTrustBackendKind::UpdateCaTrust,
            source_path: UPDATE_CA_TRUST_SOURCE_PATH,
            bundle_path: UPDATE_CA_TRUST_BUNDLE_PATH,
            update_executable,
        });
    }
    Err(LpmError::Cert(
        "automatic Linux trust-store updates require either the update-ca-certificates layout or the update-ca-trust layout. Manually install the LPM CA in this system's trust store"
            .to_string(),
    ))
}

fn test_trust_store_dir() -> Option<std::path::PathBuf> {
    if !crate::test_env_overrides_enabled() {
        return None;
    }
    std::env::var_os(TEST_TRUST_STORE_DIR_ENV).map(std::path::PathBuf::from)
}

fn test_trust_store_path() -> Option<std::path::PathBuf> {
    test_trust_store_dir().map(|dir| dir.join("lpm-local-ca.pem"))
}

fn test_trust_store_sidecar() -> Option<std::path::PathBuf> {
    test_trust_store_dir().map(|dir| dir.join("lpm-local-ca.sha256"))
}

#[cfg(target_os = "linux")]
fn trusted_root_owned_executable(
    operation: &str,
    candidates: &'static [&'static str],
) -> Result<&'static str, LpmError> {
    use std::os::unix::fs::MetadataExt;

    candidates
        .iter()
        .copied()
        .find(|path| {
            std::fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
            })
        })
        .ok_or_else(|| {
            LpmError::Cert(format!(
                "did not find a trusted {operation} executable. Checked: {}",
                candidates.join(", ")
            ))
        })
}

#[cfg(target_os = "linux")]
fn trusted_sudo_executable() -> Result<&'static str, LpmError> {
    trusted_root_owned_executable("sudo", SUDO_EXECUTABLE_CANDIDATES)
}

#[cfg(any(target_os = "linux", test))]
fn privileged_command_line(
    effective_uid: u32,
    sudo: Option<&str>,
    executable: &str,
    args: &[&str],
) -> Result<(String, Vec<String>), LpmError> {
    if effective_uid == 0 {
        return Ok((
            executable.to_string(),
            args.iter().map(|arg| (*arg).to_string()).collect(),
        ));
    }
    let sudo = sudo.ok_or_else(|| {
        LpmError::Cert(
            "administrator privileges are required, but no trusted sudo executable was found"
                .to_string(),
        )
    })?;
    let mut sudo_args = Vec::with_capacity(args.len() + 1);
    sudo_args.push(executable.to_string());
    sudo_args.extend(args.iter().map(|arg| (*arg).to_string()));
    Ok((sudo.to_string(), sudo_args))
}

#[cfg(target_os = "linux")]
fn linux_effective_uid() -> u32 {
    // SAFETY: geteuid has no inputs and returns the calling process's effective UID.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn run_privileged_interactive(
    executable: &str,
    args: &[&str],
    operation: &str,
) -> Result<(), LpmError> {
    let effective_uid = linux_effective_uid();
    let sudo = if effective_uid == 0 {
        None
    } else {
        Some(trusted_sudo_executable()?)
    };
    let (program, command_args) = privileged_command_line(effective_uid, sudo, executable, args)?;
    let status = Command::new(&program)
        .args(&command_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| LpmError::Cert(format!("failed to {operation}: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(LpmError::Cert(format!(
            "failed to {operation}: {program} exited with {status}"
        )))
    }
}

#[cfg(target_os = "linux")]
fn trusted_root_owned_directory(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
    })
}

#[cfg(target_os = "linux")]
fn linux_trust_layout_ready(source_path: &str, bundle_path: &str) -> bool {
    let Some(source_dir) = Path::new(source_path).parent() else {
        return false;
    };
    trusted_root_owned_directory(source_dir)
        && std::fs::metadata(bundle_path).is_ok_and(|metadata| metadata.is_file())
}

#[cfg(target_os = "linux")]
fn detect_linux_trust_backend() -> Result<LinuxTrustBackend, LpmError> {
    let update_ca_certificates =
        trusted_root_owned_executable("update-ca-certificates", UPDATE_CA_EXECUTABLE_CANDIDATES)
            .ok();
    let update_ca_trust =
        trusted_root_owned_executable("update-ca-trust", UPDATE_CA_TRUST_EXECUTABLE_CANDIDATES)
            .ok();
    select_linux_trust_backend(
        update_ca_certificates,
        linux_trust_layout_ready(
            UPDATE_CA_CERTIFICATES_SOURCE_PATH,
            UPDATE_CA_CERTIFICATES_BUNDLE_PATH,
        ),
        update_ca_trust,
        linux_trust_layout_ready(UPDATE_CA_TRUST_SOURCE_PATH, UPDATE_CA_TRUST_BUNDLE_PATH),
    )
}

#[cfg(target_os = "linux")]
fn validate_linux_trust_destination(backend: LinuxTrustBackend) -> Result<(), LpmError> {
    use std::os::unix::fs::MetadataExt as _;

    let source = Path::new(backend.source_path);
    let source_dir = source.parent().ok_or_else(|| {
        LpmError::Cert("Linux trust-store source path has no parent directory".to_string())
    })?;
    if !trusted_root_owned_directory(source_dir) {
        return Err(LpmError::Cert(format!(
            "Linux trust-store directory {} is missing, writable by non-root users, or is a symlink. Manually install the LPM CA instead",
            source_dir.display()
        )));
    }
    match std::fs::symlink_metadata(source) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(LpmError::Cert(format!(
            "Linux trust-store destination {} is not a trusted root-owned regular file. Manually inspect or remove it before retrying",
            source.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to inspect Linux trust-store destination {}: {error}",
            source.display()
        ))),
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_trust_refresh_args(
    kind: LinuxTrustBackendKind,
    full_refresh: bool,
) -> &'static [&'static str] {
    match (kind, full_refresh) {
        (LinuxTrustBackendKind::UpdateCaCertificates, true) => &["--fresh"],
        (LinuxTrustBackendKind::UpdateCaCertificates, false) => &[],
        (LinuxTrustBackendKind::UpdateCaTrust, _) => &["extract"],
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_trust_source_install_args<'a>(cert_path: &'a str, source_path: &'a str) -> Vec<&'a str> {
    vec!["-m", "0644", cert_path, source_path]
}

#[cfg(target_os = "windows")]
fn certutil_executable() -> Result<std::path::PathBuf, LpmError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = vec![0_u16; 260];
    loop {
        let buffer_len = u32::try_from(buffer.len())
            .map_err(|_| LpmError::Cert("Windows system directory path is too long".into()))?;
        // SAFETY: the buffer is writable for `buffer_len` UTF-16 units and
        // remains valid for this synchronous call.
        let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer_len) };
        if written == 0 {
            return Err(LpmError::Cert(format!(
                "failed to resolve Windows system directory: {}",
                std::io::Error::last_os_error()
            )));
        }
        let written = written as usize;
        if written < buffer.len() {
            buffer.truncate(written);
            return Ok(std::path::PathBuf::from(OsString::from_wide(&buffer)).join("certutil.exe"));
        }
        buffer.resize(written.saturating_add(1), 0);
    }
}

#[cfg(target_os = "windows")]
fn run_certutil_elevated(args: &[String]) -> Result<(), LpmError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, INFINITE, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    struct ProcessHandle(HANDLE);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    // SAFETY: ShellExecuteExW returned this owned process
                    // handle, and this guard closes it exactly once.
                    CloseHandle(self.0);
                }
            }
        }
    }

    let executable = certutil_executable()?;
    let verb = wide_str("runas");
    let file: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let parameters = wide_str(&quote_windows_args(args));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    let launched = unsafe {
        // SAFETY: all UTF-16 inputs are null-terminated and remain alive for
        // this synchronous call. `info` has the required size and fields.
        ShellExecuteExW(&mut info)
    };
    if launched == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            return Err(LpmError::Cert(
                "Windows elevation was cancelled for certificate trust-store access".into(),
            ));
        }
        return Err(LpmError::Cert(format!(
            "failed to start elevated certutil: {error}"
        )));
    }
    if info.hProcess.is_null() {
        return Err(LpmError::Cert(
            "elevated certutil did not return a process handle".into(),
        ));
    }

    let process = ProcessHandle(info.hProcess);
    let wait = unsafe {
        // SAFETY: `process.0` is the live handle returned above and remains
        // owned by `process` for the duration of the wait.
        WaitForSingleObject(process.0, INFINITE)
    };
    if wait == WAIT_FAILED {
        return Err(LpmError::Cert(format!(
            "failed to wait for elevated certutil: {}",
            std::io::Error::last_os_error()
        )));
    }
    if wait != WAIT_OBJECT_0 {
        return Err(LpmError::Cert(format!(
            "waiting for elevated certutil returned 0x{wait:08X}"
        )));
    }

    let mut exit_code = 1_u32;
    let read_exit_code = unsafe {
        // SAFETY: the process has finished, the handle remains live, and
        // `exit_code` is a valid out pointer.
        GetExitCodeProcess(process.0, &mut exit_code)
    };
    if read_exit_code == 0 {
        return Err(LpmError::Cert(format!(
            "failed to read elevated certutil exit code: {}",
            std::io::Error::last_os_error()
        )));
    }
    if exit_code == 0 {
        Ok(())
    } else {
        Err(LpmError::Cert(format!(
            "elevated certutil exited with code {exit_code}"
        )))
    }
}

#[cfg(target_os = "windows")]
fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn quote_windows_args(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(test, target_os = "windows"))]
fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\"' | b'\\'))
    {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0_usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        if ch == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
            continue;
        }
        quoted.extend(std::iter::repeat_n('\\', backslashes));
        backslashes = 0;
        quoted.push(ch);
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

fn install_ca_test(ca_cert_path: &Path, trust_store_path: &Path) -> Result<(), LpmError> {
    if let Some(parent) = trust_store_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| LpmError::Cert(format!("failed to create test trust store: {e}")))?;
    }

    std::fs::copy(ca_cert_path, trust_store_path)
        .map_err(|e| LpmError::Cert(format!("failed to install CA to test trust store: {e}")))?;

    let fp = cert::fingerprint_sha256(ca_cert_path)?;
    if let Some(sidecar) = test_trust_store_sidecar() {
        std::fs::write(&sidecar, cert::fingerprint_hex(&fp)).map_err(|e| {
            LpmError::Cert(format!("failed to write test sidecar fingerprint: {e}"))
        })?;
    }
    #[cfg(test)]
    if FAIL_INSTALL_AFTER_MUTATION.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(LpmError::Cert(
            "injected trust install failure after mutation".into(),
        ));
    }
    Ok(())
}

fn is_ca_installed_test(
    expected_fingerprint_hex: &str,
    trust_store_path: &Path,
) -> Result<bool, LpmError> {
    if !trust_store_path.exists() {
        return Ok(false);
    }
    let recorded = match test_trust_store_sidecar() {
        Some(p) => {
            match lpm_common::read_text_file_capped(&p, lpm_common::STATE_FILE_SIZE_CAP_BYTES) {
                Ok(recorded) => recorded,
                Err(lpm_common::BoundedReadError::NotFound { .. }) => {
                    let fp = cert::fingerprint_sha256(trust_store_path)?;
                    cert::fingerprint_hex(&fp)
                }
                Err(error) => {
                    return Err(LpmError::Cert(format!("failed to read sidecar: {error}")));
                }
            }
        }
        _ => {
            let fp = cert::fingerprint_sha256(trust_store_path)?;
            cert::fingerprint_hex(&fp)
        }
    };
    Ok(recorded.trim() == expected_fingerprint_hex)
}

fn uninstall_ca_test(
    expected_fingerprint_hex: &str,
    trust_store_path: &Path,
) -> Result<(), LpmError> {
    let installed = is_ca_installed_test(expected_fingerprint_hex, trust_store_path)?;
    if !installed {
        if trust_store_path.exists() {
            tracing::warn!(
                "test trust store contains a cert at {} whose fingerprint does not match the expected LPM CA — leaving it in place",
                trust_store_path.display()
            );
        }
        return Ok(());
    }
    if trust_store_path.exists() {
        std::fs::remove_file(trust_store_path).map_err(|e| {
            LpmError::Cert(format!("failed to remove CA from test trust store: {e}"))
        })?;
    }
    if let Some(sidecar) = test_trust_store_sidecar()
        && sidecar.exists()
    {
        std::fs::remove_file(&sidecar).map_err(|e| {
            LpmError::Cert(format!("failed to remove test sidecar fingerprint: {e}"))
        })?;
    }
    #[cfg(test)]
    if FAIL_UNINSTALL_AFTER_MUTATION.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(LpmError::Cert(
            "injected trust uninstall failure after mutation".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
static FAIL_INSTALL_AFTER_MUTATION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
static FAIL_UNINSTALL_AFTER_MUTATION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn fail_next_install_after_mutation() {
    FAIL_INSTALL_AFTER_MUTATION.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn fail_next_uninstall_after_mutation() {
    FAIL_UNINSTALL_AFTER_MUTATION.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Install the CA certificate into the system trust store.
///
/// Platform behavior:
/// - macOS: adds to user login keychain (no sudo needed)
/// - Linux: uses update-ca-certificates or update-ca-trust, directly as root or through sudo
/// - Windows: uses certutil to add to Root store (UAC prompt)
pub fn install_ca(ca_cert_path: &Path) -> Result<(), LpmError> {
    if let Some(trust_store_path) = test_trust_store_path() {
        return install_ca_test(ca_cert_path, &trust_store_path);
    }

    let path_str = ca_cert_path.to_string_lossy();

    #[cfg(target_os = "macos")]
    {
        install_ca_macos(&path_str)
    }

    #[cfg(target_os = "linux")]
    {
        install_ca_linux(&path_str)
    }

    #[cfg(target_os = "windows")]
    {
        install_ca_windows(&path_str)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(LpmError::Cert(format!(
            "automatic trust store installation is not supported on this platform. \
				 Manually add {} to your system's trusted certificates.",
            path_str
        )))
    }
}

pub(crate) fn install_ca_bytes(cert_pem: &[u8], display_path: &Path) -> Result<(), LpmError> {
    with_verified_certificate_file(cert_pem, display_path, install_ca)?;
    if !is_ca_installed_bytes(cert_pem, display_path)? {
        return Err(LpmError::Cert(format!(
            "trust store did not contain the expected certificate from {} after installation",
            display_path.display()
        )));
    }
    Ok(())
}

/// True iff a cert with the same SHA-256 fingerprint as `ca_cert_path` is currently
/// in the user trust store. Identity check, not CN substring match — a planted cert
/// with the same CN but a different fingerprint reads as "not installed."
pub fn is_ca_installed(ca_cert_path: &Path) -> Result<bool, LpmError> {
    let expected = cert::fingerprint_sha256(ca_cert_path)?;
    let expected_hex = cert::fingerprint_hex(&expected);

    if let Some(trust_store_path) = test_trust_store_path() {
        return is_ca_installed_test(&expected_hex, &trust_store_path);
    }

    #[cfg(target_os = "macos")]
    {
        is_ca_installed_macos(&expected_hex)
    }

    #[cfg(target_os = "linux")]
    {
        is_ca_installed_linux(ca_cert_path)
    }

    #[cfg(target_os = "windows")]
    {
        let sha1 = cert::fingerprint_sha1(ca_cert_path)?;
        is_ca_installed_windows(&cert::fingerprint_hex(&sha1))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = ca_cert_path;
        Ok(false)
    }
}

pub(crate) fn is_ca_installed_bytes(
    cert_pem: &[u8],
    _display_path: &Path,
) -> Result<bool, LpmError> {
    let expected_hex = cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(cert_pem)?);
    if let Some(trust_store_path) = test_trust_store_path() {
        return is_ca_installed_test(&expected_hex, &trust_store_path);
    }
    #[cfg(target_os = "macos")]
    return is_ca_installed_macos(&expected_hex);
    #[cfg(target_os = "linux")]
    return is_ca_installed_linux_bytes(cert_pem);
    #[cfg(target_os = "windows")]
    return is_ca_installed_windows(&cert::fingerprint_hex(&cert::fingerprint_sha1_bytes(
        cert_pem,
    )?));
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    Ok(false)
}

/// Remove the LPM CA from the system trust store. Only fingerprints matching
/// `ca_cert_path` are removed; lookalikes with the same CN are preserved with a
/// warning so the user can inspect them.
pub fn uninstall_ca(ca_cert_path: &Path) -> Result<(), LpmError> {
    let expected = cert::fingerprint_sha256(ca_cert_path)?;
    let expected_hex = cert::fingerprint_hex(&expected);

    if let Some(trust_store_path) = test_trust_store_path() {
        return uninstall_ca_test(&expected_hex, &trust_store_path);
    }

    #[cfg(target_os = "macos")]
    {
        uninstall_ca_macos(&expected_hex)
    }

    #[cfg(target_os = "linux")]
    {
        uninstall_ca_linux(ca_cert_path)
    }

    #[cfg(target_os = "windows")]
    {
        let sha1 = cert::fingerprint_sha1(ca_cert_path)?;
        uninstall_ca_windows(&cert::fingerprint_hex(&sha1))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = ca_cert_path;
        Err(LpmError::Cert(
            "automatic trust store removal is not supported on this platform".into(),
        ))
    }
}

pub(crate) fn uninstall_ca_bytes(cert_pem: &[u8], display_path: &Path) -> Result<(), LpmError> {
    let expected_hex = cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(cert_pem)?);
    if let Some(trust_store_path) = test_trust_store_path() {
        uninstall_ca_test(&expected_hex, &trust_store_path)?;
    } else {
        #[cfg(target_os = "macos")]
        uninstall_ca_macos(&expected_hex)?;
        #[cfg(target_os = "linux")]
        uninstall_ca_linux_bytes(cert_pem)?;
        #[cfg(target_os = "windows")]
        uninstall_ca_windows(&cert::fingerprint_hex(&cert::fingerprint_sha1_bytes(
            cert_pem,
        )?))?;
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return Err(LpmError::Cert(format!(
            "automatic trust store removal is not supported for {} on this platform",
            display_path.display()
        )));
    }
    if is_ca_installed_bytes(cert_pem, display_path)? {
        return Err(LpmError::Cert(format!(
            "trust store still contains the certificate from {} after removal",
            display_path.display()
        )));
    }
    Ok(())
}

fn with_verified_certificate_file<T>(
    cert_pem: &[u8],
    display_path: &Path,
    operation: impl FnOnce(&Path) -> Result<T, LpmError>,
) -> Result<T, LpmError> {
    let mut temporary = tempfile::Builder::new()
        .prefix(".lpm-verified-ca-")
        .tempfile()
        .map_err(|error| LpmError::Cert(format!("failed to stage verified CA: {error}")))?;
    use std::io::Write as _;
    temporary
        .write_all(cert_pem)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| LpmError::Cert(format!("failed to write verified CA: {error}")))?;
    let result = operation(temporary.path())?;
    let staged = lpm_common::read_file_capped(
        temporary.path(),
        lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| {
        LpmError::Cert(format!(
            "failed to verify staged certificate for {} after the trust-store operation: {error}",
            display_path.display()
        ))
    })?;
    if staged != cert_pem {
        return Err(LpmError::Cert(format!(
            "staged certificate for {} changed while the trust-store operation ran",
            display_path.display()
        )));
    }
    Ok(result)
}

// ── macOS ──────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn install_ca_macos(cert_path: &str) -> Result<(), LpmError> {
    tracing::debug!("installing CA to macOS login keychain: {cert_path}");

    let mut cmd = Command::new(SECURITY_EXECUTABLE);
    cmd.args(["add-trusted-cert", "-r", "trustRoot", "-k"])
        .arg(login_keychain_path()?)
        .arg(cert_path);

    let output = cmd
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("already exists") || stderr.contains("duplicate") {
            tracing::debug!("CA already in keychain");
            return Ok(());
        }
        return Err(LpmError::Cert(format!(
            "failed to install CA to keychain: {stderr}"
        )));
    }

    tracing::info!("CA installed to macOS login keychain");
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_ca_installed_macos(expected_fingerprint_hex: &str) -> Result<bool, LpmError> {
    let output = Command::new(SECURITY_EXECUTABLE)
        .args(["find-certificate", "-Z", "-a", "-c", CA_COMMON_NAME])
        .arg(login_keychain_path()?)
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("could not be found") || output.stdout.is_empty() {
            return Ok(false);
        }
        return Err(LpmError::Cert(format!(
            "`security find-certificate` failed: {stderr}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_macos_sha256_lines(&stdout)
        .any(|fp| fp.eq_ignore_ascii_case(expected_fingerprint_hex)))
}

#[cfg(target_os = "macos")]
fn uninstall_ca_macos(expected_fingerprint_hex: &str) -> Result<(), LpmError> {
    let output = Command::new(SECURITY_EXECUTABLE)
        .args(["find-certificate", "-Z", "-a", "-c", CA_COMMON_NAME])
        .arg(login_keychain_path()?)
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

    if !output.status.success() || output.stdout.is_empty() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut matched = false;
    let mut lookalikes: Vec<String> = Vec::new();
    for fp in parse_macos_sha256_lines(&stdout) {
        if fp.eq_ignore_ascii_case(expected_fingerprint_hex) {
            matched = true;
            let del = Command::new(SECURITY_EXECUTABLE)
                .args(["delete-certificate", "-Z", &fp])
                .arg(login_keychain_path()?)
                .output()
                .map_err(|e| {
                    LpmError::Cert(format!("failed to run `security delete-certificate`: {e}"))
                })?;
            if !del.status.success() {
                let stderr = String::from_utf8_lossy(&del.stderr);
                if !stderr.contains("could not be found") {
                    return Err(LpmError::Cert(format!(
                        "failed to remove CA from keychain: {stderr}"
                    )));
                }
            }
        } else {
            lookalikes.push(fp);
        }
    }

    for fp in &lookalikes {
        tracing::warn!(
            "found a different cert with CN={CA_COMMON_NAME:?} at SHA-256 {fp}; not removing"
        );
    }

    if !matched {
        tracing::info!("no LPM CA matching the on-disk fingerprint was found in the keychain");
    } else {
        tracing::info!("CA removed from macOS login keychain");
    }
    Ok(())
}

/// Parse the `SHA-256 hash: …` lines emitted by `security find-certificate -Z`.
/// Output is one block per match separated by blank lines; we yield each SHA-256
/// in original casing (uppercase hex with no separators on macOS).
#[cfg(target_os = "macos")]
fn parse_macos_sha256_lines(stdout: &str) -> impl Iterator<Item = String> + '_ {
    stdout.lines().filter_map(|line| {
        let trimmed = line.trim_start();
        let prefix = "SHA-256 hash:";
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let hex = rest.trim();
            if hex.is_empty() {
                None
            } else {
                Some(insert_colons_in_hex(hex))
            }
        } else {
            None
        }
    })
}

#[cfg(target_os = "macos")]
fn insert_colons_in_hex(hex: &str) -> String {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut out = String::with_capacity(clean.len() + clean.len() / 2);
    for (i, c) in clean.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(':');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

#[cfg(target_os = "macos")]
fn login_keychain_path() -> Result<String, LpmError> {
    let home = dirs::home_dir()
        .ok_or_else(|| LpmError::Cert("could not determine home directory".into()))?;
    let keychain = home.join("Library/Keychains/login.keychain-db");

    if keychain.exists() {
        Ok(keychain.to_string_lossy().to_string())
    } else {
        let alt = home.join("Library/Keychains/login.keychain");
        Ok(alt.to_string_lossy().to_string())
    }
}

// ── Linux ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn install_ca_linux(cert_path: &str) -> Result<(), LpmError> {
    let backend = detect_linux_trust_backend()?;
    validate_linux_trust_destination(backend)?;
    let dest = Path::new(backend.source_path);
    let bundle = Path::new(backend.bundle_path);
    let expected = lpm_common::read_file_capped(
        Path::new(cert_path),
        lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| LpmError::Cert(format!("failed to read expected CA: {error}")))?;

    tracing::debug!("installing CA to {}", dest.display());

    let install = trusted_root_owned_executable("install", INSTALL_EXECUTABLE_CANDIDATES)?;
    let install_args = linux_trust_source_install_args(cert_path, backend.source_path);
    run_privileged_interactive(
        install,
        &install_args,
        "copy the CA certificate to the Linux trust store",
    )?;
    run_privileged_interactive(
        backend.update_executable,
        linux_trust_refresh_args(backend.kind, false),
        "refresh the Linux trust store",
    )?;
    let state = linux_trust_state_at(&expected, dest, bundle)?;
    if state.source != LinuxSourceState::Matching || !state.bundle_contains {
        return Err(LpmError::Cert(format!(
            "Linux trust refresh did not publish the CA from {} into {}",
            dest.display(),
            bundle.display()
        )));
    }

    tracing::info!("CA installed to Linux trust store");
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_ca_installed_linux(expected_ca_path: &Path) -> Result<bool, LpmError> {
    let expected = lpm_common::read_file_capped(
        expected_ca_path,
        lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| LpmError::Cert(format!("failed to read expected CA: {error}")))?;
    is_ca_installed_linux_bytes(&expected)
}

#[cfg(target_os = "linux")]
fn is_ca_installed_linux_bytes(expected_ca_pem: &[u8]) -> Result<bool, LpmError> {
    let backend = detect_linux_trust_backend()?;
    is_ca_installed_linux_at(
        expected_ca_pem,
        Path::new(backend.source_path),
        Path::new(backend.bundle_path),
    )
}

#[cfg(any(target_os = "linux", test))]
fn is_ca_installed_linux_at(
    expected_ca_pem: &[u8],
    source_path: &Path,
    bundle_path: &Path,
) -> Result<bool, LpmError> {
    let state = linux_trust_state_at(expected_ca_pem, source_path, bundle_path)?;
    if state.source == LinuxSourceState::Different {
        tracing::warn!(
            "a different `lpm-local-ca.crt` is present at {}; leaving it untouched",
            source_path.display()
        );
    }
    Ok(state.bundle_contains)
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxSourceState {
    Absent,
    Matching,
    Different,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxTrustState {
    source: LinuxSourceState,
    bundle_contains: bool,
}

#[cfg(any(target_os = "linux", test))]
fn linux_trust_state_at(
    expected_ca_pem: &[u8],
    source_path: &Path,
    bundle_path: &Path,
) -> Result<LinuxTrustState, LpmError> {
    let expected_fp = cert::fingerprint_sha256_bytes(expected_ca_pem)?;
    let source = match lpm_common::read_file_capped(
        source_path,
        lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(contents) => match cert::fingerprint_sha256_bytes(&contents) {
            Ok(fingerprint) if fingerprint == expected_fp => LinuxSourceState::Matching,
            Ok(_) | Err(_) => LinuxSourceState::Different,
        },
        Err(lpm_common::BoundedReadError::NotFound { .. }) => LinuxSourceState::Absent,
        Err(error) => {
            return Err(LpmError::Cert(format!(
                "failed to inspect Linux CA source {}: {error}",
                source_path.display()
            )));
        }
    };
    let bundle_contains = linux_bundle_contains_fingerprint(bundle_path, &expected_fp)?;
    Ok(LinuxTrustState {
        source,
        bundle_contains,
    })
}

#[cfg(any(target_os = "linux", test))]
fn linux_bundle_contains_fingerprint(
    bundle_path: &Path,
    expected_fingerprint: &[u8; 32],
) -> Result<bool, LpmError> {
    use std::io::BufRead as _;

    let file = match std::fs::File::open(bundle_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(LpmError::Cert(format!(
                "failed to inspect Linux CA bundle {}: {error}",
                bundle_path.display()
            )));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        LpmError::Cert(format!(
            "failed to inspect Linux CA bundle {}: {error}",
            bundle_path.display()
        ))
    })?;
    if metadata.len() > LINUX_CA_BUNDLE_SIZE_CAP_BYTES {
        return Err(LpmError::Cert(format!(
            "Linux CA bundle {} exceeds the {}-byte safety limit",
            bundle_path.display(),
            LINUX_CA_BUNDLE_SIZE_CAP_BYTES
        )));
    }

    let mut reader = std::io::BufReader::new(file);
    let mut line = Vec::with_capacity(128);
    let mut certificate = Vec::with_capacity(2048);
    let mut total_read = 0_u64;
    let certificate_cap = lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES as usize;
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).map_err(|error| {
            LpmError::Cert(format!(
                "failed to inspect Linux CA bundle {}: {error}",
                bundle_path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        total_read = total_read.checked_add(read as u64).ok_or_else(|| {
            LpmError::Cert(format!(
                "Linux CA bundle {} is too large",
                bundle_path.display()
            ))
        })?;
        if total_read > LINUX_CA_BUNDLE_SIZE_CAP_BYTES {
            return Err(LpmError::Cert(format!(
                "Linux CA bundle {} exceeds the {}-byte safety limit",
                bundle_path.display(),
                LINUX_CA_BUNDLE_SIZE_CAP_BYTES
            )));
        }

        let marker = line.strip_suffix(b"\n").unwrap_or(&line);
        let marker = marker.strip_suffix(b"\r").unwrap_or(marker);
        if certificate.is_empty() && marker != b"-----BEGIN CERTIFICATE-----" {
            continue;
        }
        let next_len = certificate.len().checked_add(line.len()).ok_or_else(|| {
            LpmError::Cert(format!(
                "certificate block in Linux CA bundle {} is too large",
                bundle_path.display()
            ))
        })?;
        if next_len > certificate_cap {
            return Err(LpmError::Cert(format!(
                "certificate block in Linux CA bundle {} exceeds the {}-byte safety limit",
                bundle_path.display(),
                certificate_cap
            )));
        }
        certificate.extend_from_slice(&line);
        if marker != b"-----END CERTIFICATE-----" {
            continue;
        }

        let parsed = pem::parse(&certificate).map_err(|error| {
            LpmError::Cert(format!(
                "failed to parse Linux CA bundle {}: {error}",
                bundle_path.display()
            ))
        })?;
        use sha2::Digest as _;
        let fingerprint: [u8; 32] = sha2::Sha256::digest(parsed.contents()).into();
        if &fingerprint == expected_fingerprint {
            return Ok(true);
        }
        certificate.clear();
    }
    if !certificate.is_empty() {
        return Err(LpmError::Cert(format!(
            "Linux CA bundle {} contains an unterminated certificate",
            bundle_path.display()
        )));
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn uninstall_ca_linux(expected_ca_path: &Path) -> Result<(), LpmError> {
    let expected = lpm_common::read_file_capped(
        expected_ca_path,
        lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| LpmError::Cert(format!("failed to read expected CA: {error}")))?;
    uninstall_ca_linux_bytes(&expected)
}

#[cfg(target_os = "linux")]
fn uninstall_ca_linux_bytes(expected_ca_pem: &[u8]) -> Result<(), LpmError> {
    let backend = detect_linux_trust_backend()?;
    validate_linux_trust_destination(backend)?;
    let dest_path = Path::new(backend.source_path);
    let bundle_path = Path::new(backend.bundle_path);
    let state = linux_trust_state_at(expected_ca_pem, dest_path, bundle_path)?;
    if state.source == LinuxSourceState::Different {
        tracing::warn!(
            "trust-store file {} does not match on-disk LPM CA; leaving in place",
            backend.source_path
        );
    }
    let remove_source = state.source == LinuxSourceState::Matching;
    let refresh = remove_source || state.bundle_contains;
    if !refresh {
        return Ok(());
    }

    if remove_source {
        let remove = trusted_root_owned_executable("rm", REMOVE_EXECUTABLE_CANDIDATES)?;
        run_privileged_interactive(
            remove,
            &["-f", backend.source_path],
            "remove the CA certificate from the Linux trust store",
        )?;
    }
    run_privileged_interactive(
        backend.update_executable,
        linux_trust_refresh_args(backend.kind, true),
        "refresh the Linux trust store",
    )?;
    if linux_trust_state_at(expected_ca_pem, dest_path, bundle_path)?.bundle_contains {
        return Err(LpmError::Cert(format!(
            "Linux CA bundle {} still trusts the removed certificate",
            bundle_path.display()
        )));
    }

    tracing::info!("CA removed from Linux trust store");
    Ok(())
}

// ── Windows ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn install_ca_windows(cert_path: &str) -> Result<(), LpmError> {
    tracing::debug!("installing CA to Windows Root store: {cert_path}");
    run_certutil_elevated(&["-addstore".into(), "Root".into(), cert_path.to_string()])?;

    tracing::info!("CA installed to Windows Root store");
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_ca_installed_windows(expected_sha1_hex: &str) -> Result<bool, LpmError> {
    let output = Command::new(certutil_executable()?)
        .args(["-store", "Root", CA_COMMON_NAME])
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run certutil: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.is_empty() {
            return Ok(false);
        }
        return Err(LpmError::Cert(format!("certutil failed: {stderr}")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_certutil_sha1_thumbprints(&stdout)
        .iter()
        .any(|tp| tp.eq_ignore_ascii_case(expected_sha1_hex)))
}

#[cfg(target_os = "windows")]
fn uninstall_ca_windows(expected_sha1_hex: &str) -> Result<(), LpmError> {
    if !is_ca_installed_windows(expected_sha1_hex)? {
        return Ok(());
    }
    let plain = expected_sha1_hex.replace(':', "");
    run_certutil_elevated(&["-delstore".into(), "Root".into(), plain])?;

    tracing::info!("CA removed from Windows Root store");
    Ok(())
}

/// Extract every SHA-1 thumbprint emitted by `certutil -store`, robustly across
/// localized installs. The literal `sha1` token is preserved on every locale we've
/// sampled (English, German, Japanese, Chinese); only the surrounding label varies.
/// We match case-insensitively on `sha1` and capture the hex group that follows.
pub fn parse_certutil_sha1_thumbprints(stdout: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        regex::Regex::new(r"(?im)^\s*[^\n:]*\bsha1\b[^\n:]*:\s*([0-9a-f][0-9a-f\s]+)\s*$")
            .expect("compiled certutil thumbprint regex")
    });
    pattern
        .captures_iter(stdout)
        .filter_map(|cap| {
            let raw = cap.get(1)?.as_str();
            let clean: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if clean.len() == 40 {
                Some(insert_colons_uppercase(&clean))
            } else {
                None
            }
        })
        .collect()
}

fn insert_colons_uppercase(hex: &str) -> String {
    let mut out = String::with_capacity(hex.len() + hex.len() / 2);
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(':');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn login_keychain_path_resolves() {
        let path = super::login_keychain_path().unwrap();
        assert!(path.contains("Keychains/login.keychain"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn parse_macos_sha256_lines_extracts_all_blocks() {
        let stdout = "\
keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
version: 256
class: 0x80001000
SHA-256 hash: AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899

keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
version: 256
class: 0x80001000
SHA-256 hash: 1122334455667788990011223344556677889900112233445566778899001122

";
        let collected: Vec<_> = parse_macos_sha256_lines(stdout).collect();
        assert_eq!(collected.len(), 2);
        assert!(collected[0].starts_with("AA:BB:CC:"));
        assert!(collected[1].starts_with("11:22:33:"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn parse_macos_sha256_lines_returns_empty_on_no_match() {
        let stdout = "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"\nversion: 256\nclass: 0x80001000\n";
        assert_eq!(parse_macos_sha256_lines(stdout).count(), 0);
    }

    #[test]
    fn parse_certutil_sha1_english_locale() {
        let stdout = "================ Certificate 0 ================\nIssuer: CN=LPM Local Development CA\nSubject: CN=LPM Local Development CA\nCert Hash(sha1): a1 b2 c3 d4 e5 f6 78 90 12 34 56 78 90 ab cd ef 12 34 56 78\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 1);
        assert_eq!(
            tps[0],
            "A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:AB:CD:EF:12:34:56:78"
        );
    }

    #[test]
    fn parse_certutil_sha1_german_locale() {
        let stdout = "================ Zertifikat 0 ================\nAussteller: CN=LPM Local Development CA\nAntragsteller: CN=LPM Local Development CA\nZertifikathash(sha1): a1b2c3d4e5f6789012345678 90 ab cd ef 12 34 56 78\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 1);
        assert_eq!(
            tps[0],
            "A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:AB:CD:EF:12:34:56:78"
        );
    }

    #[test]
    fn parse_certutil_sha1_japanese_locale() {
        let stdout = "================ 証明書 0 ================\n発行者: CN=LPM Local Development CA\nサブジェクト: CN=LPM Local Development CA\n証明書ハッシュ(sha1): a1b2c3d4e5f6789012345678 90 ab cd ef 12 34 56 78\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 1);
        assert_eq!(
            tps[0],
            "A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:AB:CD:EF:12:34:56:78"
        );
    }

    #[test]
    fn parse_certutil_sha1_returns_none_on_no_match() {
        let stdout = "================ Certificate 0 ================\nIssuer: CN=Other CA\nNotBefore: 2026-01-01\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 0);
    }

    #[test]
    fn parse_certutil_sha1_returns_multiple_when_multiple_blocks() {
        let stdout = "Cert Hash(sha1): a1b2c3d4e5f67890123456789012345678 90 ab cd\nCert Hash(sha1): 0011223344556677889900112233445566778899\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 2);
    }

    #[test]
    fn windows_argument_quoting_preserves_paths_quotes_and_trailing_backslashes() {
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(
            quote_windows_arg(r#"C:\Program Files\LPM\root CA.pem"#),
            r#""C:\Program Files\LPM\root CA.pem""#
        );
        assert_eq!(
            quote_windows_arg(r#"host"alias.test"#),
            r#""host\"alias.test""#
        );
        assert_eq!(quote_windows_arg(r#"C:\Temp\"#), r#""C:\Temp\\""#);
    }

    #[test]
    fn verified_certificate_staging_detects_replacement_during_operation() {
        let (expected, _) = crate::ca::generate_ca_with_options(Default::default()).unwrap();
        let (replacement, _) = crate::ca::generate_ca_with_options(Default::default()).unwrap();

        let error =
            with_verified_certificate_file(expected.as_bytes(), Path::new("rootCA.pem"), |path| {
                std::fs::write(path, replacement.as_bytes()).unwrap();
                Ok(())
            })
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("changed while the trust-store operation ran")
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn is_ca_installed_uses_fingerprint_via_test_backend() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(TEST_TRUST_STORE_DIR_ENV, dir.path());

        let (ca_pem, _) = crate::ca::generate_ca().unwrap();
        let ca_path = dir.path().join("source-rootCA.pem");
        std::fs::write(&ca_path, &ca_pem).unwrap();

        assert!(!is_ca_installed(&ca_path).unwrap());

        install_ca(&ca_path).unwrap();
        assert!(is_ca_installed(&ca_path).unwrap());

        let (other_pem, _) = crate::ca::generate_ca().unwrap();
        let other_path = dir.path().join("other.pem");
        std::fs::write(&other_path, &other_pem).unwrap();
        assert!(
            !is_ca_installed(&other_path).unwrap(),
            "a different cert (same CN, different fingerprint) must read as not installed"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn uninstall_preserves_lookalike_with_different_fingerprint() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(TEST_TRUST_STORE_DIR_ENV, dir.path());

        let (real_pem, _) = crate::ca::generate_ca().unwrap();
        let real_path = dir.path().join("real.pem");
        std::fs::write(&real_path, &real_pem).unwrap();
        install_ca(&real_path).unwrap();

        let (planted_pem, _) = crate::ca::generate_ca().unwrap();
        let planted_path = dir.path().join("planted.pem");
        std::fs::write(&planted_path, &planted_pem).unwrap();

        uninstall_ca(&planted_path).unwrap();

        assert!(
            is_ca_installed(&real_path).unwrap(),
            "uninstall keyed by a non-matching fingerprint must leave the real CA alone"
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn test_trust_store_env_is_ignored_in_release_builds() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(TEST_TRUST_STORE_DIR_ENV, dir.path());

        assert_eq!(test_trust_store_path(), None);
        assert_ne!(crate::trust_store_label(), "test");
    }

    #[test]
    fn linux_source_without_generated_bundle_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("lpm-local-ca.crt");
        let bundle = dir.path().join("ca-certificates.crt");
        let (expected, _) = crate::ca::generate_ca().unwrap();
        let (other, _) = crate::ca::generate_ca().unwrap();
        std::fs::write(&source, expected.as_bytes()).unwrap();
        std::fs::write(&bundle, other.as_bytes()).unwrap();

        assert!(!is_ca_installed_linux_at(expected.as_bytes(), &source, &bundle).unwrap());
    }

    #[test]
    fn linux_generated_bundle_without_source_is_still_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("lpm-local-ca.crt");
        let bundle = dir.path().join("ca-certificates.crt");
        let (expected, _) = crate::ca::generate_ca().unwrap();
        std::fs::write(&bundle, expected.as_bytes()).unwrap();

        assert!(is_ca_installed_linux_at(expected.as_bytes(), &source, &bundle).unwrap());
    }

    #[test]
    fn linux_unrelated_source_does_not_hide_trust_from_the_generated_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("lpm-local-ca.crt");
        let bundle = dir.path().join("ca-certificates.crt");
        let (expected, _) = crate::ca::generate_ca().unwrap();
        let (other, _) = crate::ca::generate_ca().unwrap();
        std::fs::write(&source, other.as_bytes()).unwrap();
        std::fs::write(&bundle, expected.as_bytes()).unwrap();

        let state = linux_trust_state_at(expected.as_bytes(), &source, &bundle).unwrap();

        assert_eq!(state.source, LinuxSourceState::Different);
        assert!(state.bundle_contains);
    }

    #[test]
    fn linux_bundle_probe_finds_expected_ca_after_more_than_one_megabyte_of_valid_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("lpm-local-ca.crt");
        let bundle = dir.path().join("ca-certificates.crt");
        let (expected, _) = crate::ca::generate_ca().unwrap();
        let (unrelated, _) = crate::ca::generate_ca().unwrap();
        let mut contents = String::with_capacity(
            lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES as usize + expected.len(),
        );
        while contents.len() <= lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES as usize {
            contents.push_str(&unrelated);
        }
        contents.push_str(&expected);
        std::fs::write(&bundle, contents).unwrap();

        let state = linux_trust_state_at(expected.as_bytes(), &source, &bundle).unwrap();

        assert!(state.bundle_contains);
    }

    #[test]
    fn linux_bundle_probe_rejects_an_unbounded_single_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("lpm-local-ca.crt");
        let bundle = dir.path().join("ca-certificates.crt");
        let (expected, _) = crate::ca::generate_ca().unwrap();
        let mut contents = String::from("-----BEGIN CERTIFICATE-----\n");
        contents.extend(std::iter::repeat_n(
            'A',
            lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES as usize,
        ));
        contents.push_str("\n-----END CERTIFICATE-----\n");
        std::fs::write(&bundle, contents).unwrap();

        let error = linux_trust_state_at(expected.as_bytes(), &source, &bundle).unwrap_err();

        assert!(error.to_string().contains("certificate block"));
        assert!(error.to_string().contains("1048576-byte safety limit"));
    }

    #[test]
    fn root_linux_trust_commands_run_directly_without_sudo() {
        let (program, args) =
            privileged_command_line(0, None, "/usr/sbin/update-ca-certificates", &["--fresh"])
                .unwrap();

        assert_eq!(program, "/usr/sbin/update-ca-certificates");
        assert_eq!(args, ["--fresh"]);
    }

    #[test]
    fn non_root_linux_trust_commands_use_the_trusted_sudo_binary() {
        let (program, args) = privileged_command_line(
            1000,
            Some("/usr/bin/sudo"),
            "/usr/bin/update-ca-trust",
            &["extract"],
        )
        .unwrap();

        assert_eq!(program, "/usr/bin/sudo");
        assert_eq!(args, ["/usr/bin/update-ca-trust", "extract"]);
    }

    #[test]
    fn linux_ca_source_install_explicitly_sets_public_read_permissions() {
        let args = linux_trust_source_install_args("/home/user/rootCA.pem", "/trust/lpm.crt");

        assert_eq!(
            args,
            ["-m", "0644", "/home/user/rootCA.pem", "/trust/lpm.crt"]
        );
    }

    #[test]
    fn update_ca_certificates_layout_is_selected_for_debian_and_alpine() {
        let backend =
            select_linux_trust_backend(Some("/usr/sbin/update-ca-certificates"), true, None, false)
                .unwrap();

        assert_eq!(backend.kind, LinuxTrustBackendKind::UpdateCaCertificates);
        assert_eq!(backend.source_path, UPDATE_CA_CERTIFICATES_SOURCE_PATH);
        assert_eq!(backend.bundle_path, UPDATE_CA_CERTIFICATES_BUNDLE_PATH);
        assert_eq!(
            linux_trust_refresh_args(backend.kind, false),
            &[] as &[&str]
        );
        assert_eq!(linux_trust_refresh_args(backend.kind, true), ["--fresh"]);
    }

    #[test]
    fn update_ca_trust_layout_is_selected_for_fedora_and_rhel() {
        let backend =
            select_linux_trust_backend(None, false, Some("/usr/bin/update-ca-trust"), true)
                .unwrap();

        assert_eq!(backend.kind, LinuxTrustBackendKind::UpdateCaTrust);
        assert_eq!(backend.source_path, UPDATE_CA_TRUST_SOURCE_PATH);
        assert_eq!(backend.bundle_path, UPDATE_CA_TRUST_BUNDLE_PATH);
        assert_eq!(linux_trust_refresh_args(backend.kind, false), ["extract"]);
        assert_eq!(linux_trust_refresh_args(backend.kind, true), ["extract"]);
    }

    #[test]
    fn unknown_linux_trust_layout_fails_with_manual_instructions() {
        let error = select_linux_trust_backend(None, false, None, false).unwrap_err();

        assert!(error.to_string().contains("Manually install the LPM CA"));
    }

    /// Tests that mutate `LPM_CERT_TEST_TRUST_STORE_DIR` lock this mutex so they
    /// serialize within a single cargo-test binary process. nextest uses one
    /// process per test and doesn't need this, but plain `cargo test` does.
    fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set<P: AsRef<std::ffi::OsStr>>(key: &'static str, value: P) -> Self {
            let prev = std::env::var_os(key);
            // SAFETY: tests in this crate are not parallelized across this env key
            // via a separate mutex, but cargo nextest gives each test its own process,
            // and within `cargo test --lib` the two callers below run sequentially in a
            // single thread because they share `TEST_TRUST_STORE_DIR_ENV` mutation.
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }
}
