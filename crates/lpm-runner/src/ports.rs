//! Port conflict detection, resolution, and cross-service env injection.
//!
//! Before starting services, checks all declared ports for conflicts
//! and builds cross-service environment variables ({SERVICE}_URL, {SERVICE}_PORT).

use lpm_common::{ExclusiveLockHandle, LpmError, LpmRoot};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Child;
#[cfg(all(unix, any(test, not(target_os = "linux"))))]
use std::process::Command;

#[cfg(target_os = "linux")]
const PROC_STAT_FILE_SIZE_CAP_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const LINUX_BOOT_ID_FILE_SIZE_CAP_BYTES: u64 = 128;

pub(crate) struct PortAllocation {
    root: LpmRoot,
    lease_dir: PathBuf,
    _lock: ExclusiveLockHandle,
}

pub(crate) struct PortLease {
    _lock: fd_lock::RwLock<std::fs::File>,
}

impl PortAllocation {
    fn acquire() -> Result<Self, LpmError> {
        Self::acquire_for_root(LpmRoot::from_env()?)
    }

    pub(crate) fn acquire_for_root(root: LpmRoot) -> Result<Self, LpmError> {
        Self::acquire_for_paths(root, global_port_lease_dir())
    }

    #[cfg(test)]
    pub(crate) fn acquire_for_root_and_lease_dir(
        root: LpmRoot,
        lease_dir: PathBuf,
    ) -> Result<Self, LpmError> {
        Self::acquire_for_paths(root, lease_dir)
    }

    fn acquire_for_paths(root: LpmRoot, lease_dir: PathBuf) -> Result<Self, LpmError> {
        ensure_private_lease_dir(&lease_dir)?;
        let lock = lpm_common::acquire_exclusive_lock(root.ports_lock())?;
        Ok(Self {
            root,
            lease_dir,
            _lock: lock,
        })
    }

    pub(crate) fn read_overrides(&self, project_dir: &std::path::Path) -> HashMap<String, u16> {
        read_port_overrides_from(&self.root.ports_toml(), project_dir)
    }

    pub(crate) fn write_override(
        &mut self,
        project_dir: &std::path::Path,
        service_name: &str,
        port: u16,
    ) {
        write_port_override_to(&self.root.ports_toml(), project_dir, service_name, port);
    }

    fn clear_overrides(&mut self, project_dir: &std::path::Path) {
        clear_port_overrides_from(&self.root.ports_toml(), project_dir);
    }

    pub(crate) fn try_acquire_lease(&self, port: u16) -> Result<Option<PortLease>, LpmError> {
        let path = self.lease_dir.join(format!("{port}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        let mut lock = fd_lock::RwLock::new(file);
        let acquired = match lock.try_write() {
            Ok(guard) => {
                std::mem::forget(guard);
                true
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(err) => return Err(LpmError::Io(err)),
        };
        if acquired {
            Ok(Some(PortLease { _lock: lock }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(unix)]
fn global_port_lease_dir() -> PathBuf {
    PathBuf::from("/tmp").join(format!("lpm-{}-port-leases", current_effective_uid()))
}

#[cfg(windows)]
fn global_port_lease_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("LPM")
        .join("runtime")
        .join("port-leases")
}

fn ensure_private_lease_dir(path: &Path) -> Result<(), LpmError> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != current_effective_uid()
        {
            return Err(LpmError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "port lease directory {} must be a directory owned by the current user",
                    path.display()
                ),
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn current_effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() as u32 }
}

pub(crate) fn acquire_port_allocation() -> Result<PortAllocation, LpmError> {
    PortAllocation::acquire()
}

/// Status of a port.
#[derive(Debug)]
pub enum PortStatus {
    Free,
    InUse {
        pid: Option<u32>,
        process_name: Option<String>,
    },
}

/// A listening TCP port discovered from the local process table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListeningPort {
    pub port: u16,
    pub address: Option<String>,
    #[serde(skip)]
    pub address_family: Option<ListeningAddressFamily>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub command: Option<String>,
    pub cwd: Option<PathBuf>,
    pub project_dir: Option<PathBuf>,
    pub project: Option<String>,
    pub framework: Option<String>,
    pub uptime: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListeningAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ListeningSocketIdentity {
    port: u16,
    pid: Option<u32>,
    address_family: Option<ListeningAddressFamily>,
    address: Option<String>,
}

impl ListeningSocketIdentity {
    fn new(
        port: u16,
        pid: Option<u32>,
        address_family: Option<ListeningAddressFamily>,
        address: Option<String>,
    ) -> Self {
        Self {
            port,
            pid,
            address_family,
            address,
        }
    }
}

impl ListeningPort {
    pub(crate) fn socket_identity(&self) -> ListeningSocketIdentity {
        ListeningSocketIdentity::new(
            self.port,
            self.pid,
            self.address_family,
            self.address.clone(),
        )
    }

    /// Return whether this socket accepts the exact IP family and address.
    pub fn listens_on(&self, address: std::net::IpAddr, port: u16) -> bool {
        if self.port != port {
            return false;
        }
        let target_family = match address {
            std::net::IpAddr::V4(_) => ListeningAddressFamily::Ipv4,
            std::net::IpAddr::V6(_) => ListeningAddressFamily::Ipv6,
        };
        let listener_family = self.address_family.or_else(|| {
            self.address
                .as_deref()
                .and_then(listening_address_family_from_str)
        });
        if listener_family != Some(target_family) {
            return false;
        }
        self.address.as_deref().is_none_or(|listener_address| {
            listener_address
                .parse::<std::net::IpAddr>()
                .is_ok_and(|listener_address| {
                    listener_address.is_unspecified() || listener_address == address
                })
        })
    }
}

/// Check if a port is available.
pub fn check_port(port: u16) -> PortStatus {
    if loopback_port_available(port) {
        return PortStatus::Free;
    }

    let (pid, name) = find_port_owner(port);
    PortStatus::InUse {
        pid,
        process_name: name,
    }
}

pub(crate) fn loopback_port_available(port: u16) -> bool {
    loopback_addr_available("127.0.0.1", port) && loopback_addr_available("::1", port)
}

fn loopback_addr_available(host: &str, port: u16) -> bool {
    match TcpListener::bind((host, port)) {
        Ok(_) => true,
        Err(err)
            if host == "::1"
                && matches!(
                    err.kind(),
                    std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
                ) =>
        {
            true
        }
        Err(_) => false,
    }
}

/// Find the next available port starting from `start`.
pub fn find_available_port(start: u16) -> Option<u16> {
    for port in start..=65535 {
        if let PortStatus::Free = check_port(port) {
            return Some(port);
        }
    }
    None
}

/// Kill the process using a specific port.
///
/// Re-checks the PID before killing to mitigate TOCTOU race conditions
/// (the port owner could change between detection and kill).
pub fn kill_port_owner(port: u16) -> Result<(), String> {
    #[cfg(windows)]
    {
        return kill_port_owner_windows(port);
    }

    #[cfg(not(windows))]
    {
        let (pid, name) = find_port_owner(port);
        match pid {
            Some(pid) => {
                let expected_identity = process_identity_for_pid(pid).ok_or_else(|| {
                    format!(
                        "cannot verify the identity of PID {pid} on port {port} — aborting kill for safety"
                    )
                })?;
                std::thread::sleep(std::time::Duration::from_millis(50));
                let (pid_recheck, _) = find_port_owner(port);
                if pid_recheck != Some(pid) {
                    return Err(format!(
                        "port {port} owner changed (was PID {pid}, now {:?}) — aborting kill for safety",
                        pid_recheck
                    ));
                }
                if process_identity_for_pid(pid).as_ref() != Some(&expected_identity) {
                    return Err(format!(
                        "port {port} owner PID {pid} was reused — aborting kill for safety"
                    ));
                }
                if protected_pid(pid) {
                    return Err(format!(
                        "refusing to kill protected PID {pid} on port {port}"
                    ));
                }
                if pid == std::process::id() {
                    return Err(format!(
                        "refusing to kill current lpm process PID {pid} on port {port}"
                    ));
                }

                let proc_name = name.as_deref().unwrap_or("unknown");
                tracing::debug!("killing PID {pid} ({proc_name}) on port {port}");

                #[cfg(unix)]
                {
                    terminate_unix_pid_if_process_identity(pid, &expected_identity).map_err(
                        |error| format!("failed to kill PID {pid} ({proc_name}): {error}"),
                    )?;
                }
                Ok(())
            }
            None => Err(format!("no process found using port {port}")),
        }
    }
}

/// Kill a process by PID.
pub fn kill_pid(pid: u32) -> Result<(), String> {
    if protected_pid(pid) {
        return Err(format!("refusing to kill protected PID {pid}"));
    }
    if pid == std::process::id() {
        return Err(format!("refusing to kill current lpm process PID {pid}"));
    }

    #[cfg(unix)]
    {
        signal_unix_pid(pid).map_err(|error| format!("failed to kill PID {pid}: {error}"))?;
    }
    #[cfg(windows)]
    {
        terminate_windows_pid(pid, windows_process_identity_for_pid(pid))
            .map_err(|err| format!("failed to kill PID {pid}: {err}"))?;
    }

    Ok(())
}

#[cfg(unix)]
fn signal_unix_pid(pid: u32) -> Result<(), String> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| "PID is outside the platform range")?;
    if pid <= 0 {
        return Err("PID must be positive".to_string());
    }
    // SAFETY: the PID is a positive platform PID and SIGTERM does not
    // dereference memory. Callers verify ownership and process identity.
    if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(target_os = "linux")]
fn open_linux_pidfd(platform_pid: libc::pid_t) -> Result<std::os::fd::OwnedFd, std::io::Error> {
    use std::os::fd::{FromRawFd as _, OwnedFd};

    // SAFETY: `pidfd_open` receives a positive PID and no pointer arguments.
    let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, platform_pid, 0) };
    if raw_fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        let raw_fd = i32::try_from(raw_fd)
            .map_err(|_| std::io::Error::other("pidfd is outside the descriptor range"))?;
        // SAFETY: the successful syscall returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    }
}

/// Return whether this runtime can terminate a captured process identity atomically.
pub fn identity_bound_process_termination_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(platform_pid) = libc::pid_t::try_from(std::process::id()) else {
            return false;
        };
        open_linux_pidfd(platform_pid).is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        macos_signal_by_audit_token().is_some()
    }
    #[cfg(windows)]
    {
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn terminate_unix_pid_if_process_identity(
    pid: u32,
    expected: &ProcessIdentity,
) -> Result<(), String> {
    if protected_pid(pid) || pid == std::process::id() {
        return Err(format!("refusing to terminate protected PID {pid}"));
    }
    let platform_pid =
        libc::pid_t::try_from(pid).map_err(|_| "PID is outside the platform range")?;
    let pidfd = open_linux_pidfd(platform_pid);
    signal_linux_process_with(pid, expected, pidfd, process_identity_for_pid, |pidfd| {
        use std::os::fd::AsRawFd as _;

        // SAFETY: `pidfd` remains open for the syscall, SIGTERM needs no
        // siginfo pointer, and the flags argument must be zero.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGTERM,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().to_string())
        }
    })
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn signal_linux_process_with<Handle>(
    pid: u32,
    expected: &ProcessIdentity,
    pidfd: Result<Handle, std::io::Error>,
    process_identity: impl FnMut(u32) -> Option<ProcessIdentity>,
    signal_handle: impl FnOnce(Handle) -> Result<(), String>,
) -> Result<(), String> {
    match pidfd {
        Ok(pidfd) => {
            signal_if_identity_matches(pid, expected, process_identity, || signal_handle(pidfd))
        }
        // A numeric signal could target a reused PID after the identity check.
        Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => {
            Err("identity-bound process termination requires Linux pidfd support".to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn terminate_unix_pid_if_process_identity(
    pid: u32,
    expected: &ProcessIdentity,
) -> Result<(), String> {
    if protected_pid(pid) || pid == std::process::id() {
        return Err(format!("refusing to terminate protected PID {pid}"));
    }

    signal_macos_process_with(pid, expected, macos_signal_by_audit_token())
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacosAuditToken {
    values: [u32; 8],
}

#[cfg(target_os = "macos")]
type MacosSignalByAuditToken =
    unsafe extern "C" fn(*mut MacosAuditToken, libc::c_int) -> libc::c_int;

#[cfg(target_os = "macos")]
fn signal_macos_process_with(
    pid: u32,
    expected: &ProcessIdentity,
    signal_by_audit_token: Option<MacosSignalByAuditToken>,
) -> Result<(), String> {
    // A numeric signal could target a reused PID after the identity check.
    let Some(signal_by_audit_token) = signal_by_audit_token else {
        return Err(
            "identity-bound process termination is unavailable on this macOS release".to_string(),
        );
    };
    let mut audit_token = macos_audit_token(pid, expected)
        .ok_or_else(|| format!("PID {pid} has an invalid captured macOS identity"))?;
    // SAFETY: the symbol has the public libproc signature and the token points
    // to eight initialized 32-bit words for the duration of the call.
    let error = unsafe { signal_by_audit_token(&raw mut audit_token, libc::SIGTERM) };
    if error == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(error).to_string())
    }
}

#[cfg(target_os = "macos")]
fn macos_signal_by_audit_token() -> Option<MacosSignalByAuditToken> {
    static SIGNAL: std::sync::OnceLock<Option<MacosSignalByAuditToken>> =
        std::sync::OnceLock::new();
    *SIGNAL.get_or_init(|| {
        // SAFETY: RTLD_DEFAULT is a valid lookup scope and the symbol name is
        // NUL-terminated. A non-null result has the public libproc signature.
        let symbol =
            unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"proc_signal_with_audittoken".as_ptr()) };
        if symbol.is_null() {
            None
        } else {
            // SAFETY: dlsym returned the address of the named C function.
            Some(unsafe {
                std::mem::transmute::<*mut libc::c_void, MacosSignalByAuditToken>(symbol)
            })
        }
    })
}

#[cfg(target_os = "macos")]
fn macos_audit_token(pid: u32, identity: &ProcessIdentity) -> Option<MacosAuditToken> {
    let identity = identity.as_str().strip_prefix("macos:")?;
    let (unique_id, id_version) = identity.split_once(':')?;
    unique_id.parse::<u64>().ok()?;
    let id_version = id_version.parse::<i32>().ok()?;
    let platform_pid = libc::pid_t::try_from(pid).ok()?;
    let mut values = [0; 8];
    values[5] = u32::try_from(platform_pid).ok()?;
    values[7] = u32::from_ne_bytes(id_version.to_ne_bytes());
    Some(MacosAuditToken { values })
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn terminate_unix_pid_if_process_identity(
    pid: u32,
    _expected: &ProcessIdentity,
) -> Result<(), String> {
    if protected_pid(pid) || pid == std::process::id() {
        return Err(format!("refusing to terminate protected PID {pid}"));
    }
    Err("identity-bound process termination is unavailable on this Unix platform".to_string())
}

#[cfg(not(any(unix, windows)))]
fn terminate_unix_pid_if_process_identity(
    pid: u32,
    _expected: &ProcessIdentity,
) -> Result<(), String> {
    Err(format!(
        "cannot atomically validate and terminate PID {pid} on this platform"
    ))
}

#[cfg(any(target_os = "linux", test))]
fn signal_if_identity_matches(
    pid: u32,
    expected: &ProcessIdentity,
    mut process_identity: impl FnMut(u32) -> Option<ProcessIdentity>,
    signal: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if process_identity(pid).as_ref() != Some(expected) {
        return Err(format!(
            "PID {pid} identity changed before termination; aborting signal for safety"
        ));
    }
    signal()
}

/// Kill `pid` only if it still owns at least one of the requested ports.
///
/// Returns the subset of requested ports that were still owned at the moment
/// of the safety re-check. An empty vector means nothing was killed.
#[cfg(not(windows))]
pub fn kill_pid_if_owns_ports(pid: u32, ports: &[u16]) -> Result<Vec<u16>, String> {
    let Some(expected_identity) = process_identity_for_pid(pid) else {
        return Ok(Vec::new());
    };
    kill_pid_if_owns_ports_unix_with(
        pid,
        ports,
        &expected_identity,
        |port| match check_port(port) {
            PortStatus::InUse { pid, .. } => pid,
            PortStatus::Free => None,
        },
        process_identity_for_pid,
        terminate_unix_pid_if_process_identity,
    )
}

#[cfg(not(windows))]
pub fn kill_pid_if_identity_owns_ports(
    pid: u32,
    expected_identity: &ProcessIdentity,
    ports: &[u16],
) -> Result<Vec<u16>, String> {
    kill_pid_if_owns_ports_unix_with(
        pid,
        ports,
        expected_identity,
        |port| match check_port(port) {
            PortStatus::InUse { pid, .. } => pid,
            PortStatus::Free => None,
        },
        process_identity_for_pid,
        terminate_unix_pid_if_process_identity,
    )
}

#[cfg(windows)]
pub fn kill_pid_if_identity_owns_ports(
    pid: u32,
    expected_identity: &ProcessIdentity,
    ports: &[u16],
) -> Result<Vec<u16>, String> {
    kill_pid_if_identity_owns_ports_windows_with(
        pid,
        ports,
        expected_identity,
        |port| {
            let owner = find_windows_port_owner(port)?;
            let creation_ticks = owner.identity.creation_ticks?;
            Some((
                owner.pid,
                ProcessIdentity(format!("windows:{creation_ticks}")),
            ))
        },
        process_identity_for_pid,
        terminate_windows_pid_if_process_identity,
    )
}

/// Revalidate and terminate multiple captured process identities using one listener snapshot.
///
/// The returned vectors align with the input order. An empty vector means that
/// the captured process no longer exists or no longer owns a requested port.
pub fn kill_pids_if_identities_own_ports<'a>(
    candidates: impl IntoIterator<Item = (u32, &'a ProcessIdentity, &'a [u16])>,
) -> Result<Vec<Vec<u16>>, String> {
    let owners: HashSet<(u32, u16)> = list_listening_ports_platform()
        .into_iter()
        .filter_map(|row| Some((row.pid?, row.port)))
        .collect();
    kill_pids_if_identities_own_ports_with(
        candidates,
        &owners,
        process_identity_for_pid,
        |pid, identity| {
            #[cfg(unix)]
            {
                terminate_unix_pid_if_process_identity(pid, identity)
            }
            #[cfg(windows)]
            {
                terminate_windows_pid_if_process_identity(pid, identity)
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = identity;
                Err(format!(
                    "cannot atomically validate and terminate PID {pid} on this platform"
                ))
            }
        },
    )
}

fn kill_pids_if_identities_own_ports_with<'a>(
    candidates: impl IntoIterator<Item = (u32, &'a ProcessIdentity, &'a [u16])>,
    owners: &HashSet<(u32, u16)>,
    mut process_identity: impl FnMut(u32) -> Option<ProcessIdentity>,
    mut terminate_if_identity: impl FnMut(u32, &ProcessIdentity) -> Result<(), String>,
) -> Result<Vec<Vec<u16>>, String> {
    candidates
        .into_iter()
        .map(|(pid, expected_identity, ports)| {
            if process_identity(pid).as_ref() != Some(expected_identity) {
                return Ok(Vec::new());
            }
            let mut still_owned_ports: Vec<u16> = ports
                .iter()
                .copied()
                .filter(|port| owners.contains(&(pid, *port)))
                .collect();
            still_owned_ports.sort_unstable();
            still_owned_ports.dedup();
            if still_owned_ports.is_empty() {
                return Ok(still_owned_ports);
            }
            terminate_if_identity(pid, expected_identity)?;
            Ok(still_owned_ports)
        })
        .collect()
}

#[cfg(windows)]
pub fn kill_pid_if_owns_ports(pid: u32, ports: &[u16]) -> Result<Vec<u16>, String> {
    let mut still_owned_ports: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|port| {
            matches!(
                check_port(*port),
                PortStatus::InUse { pid: Some(owner), .. } if owner == pid
            )
        })
        .collect();
    still_owned_ports.sort_unstable();
    still_owned_ports.dedup();

    if still_owned_ports.is_empty() {
        return Ok(Vec::new());
    }

    let Some(expected_identity) =
        windows_process_identity_for_pid(pid).filter(|identity| identity.creation_ticks.is_some())
    else {
        return Ok(Vec::new());
    };
    still_owned_ports.retain(|port| {
        find_windows_port_owner(*port)
            .is_some_and(|owner| windows_same_process(owner.identity, expected_identity))
    });
    if still_owned_ports.is_empty() {
        return Ok(Vec::new());
    }
    terminate_windows_pid(pid, Some(expected_identity))
        .map_err(|err| format!("failed to kill PID {pid}: {err}"))?;

    Ok(still_owned_ports)
}

#[cfg(any(windows, test))]
fn kill_pid_if_identity_owns_ports_windows_with(
    pid: u32,
    ports: &[u16],
    captured_identity: &ProcessIdentity,
    mut port_owner: impl FnMut(u16) -> Option<(u32, ProcessIdentity)>,
    mut process_identity: impl FnMut(u32) -> Option<ProcessIdentity>,
    mut signal_if_identity: impl FnMut(u32, &ProcessIdentity) -> Result<(), String>,
) -> Result<Vec<u16>, String> {
    if process_identity(pid).as_ref() != Some(captured_identity) {
        return Ok(Vec::new());
    }
    let mut still_owned_ports: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|port| {
            port_owner(*port).is_some_and(|(owner_pid, owner_identity)| {
                owner_pid == pid && owner_identity == *captured_identity
            })
        })
        .collect();
    still_owned_ports.sort_unstable();
    still_owned_ports.dedup();
    if still_owned_ports.is_empty() {
        return Ok(Vec::new());
    }
    if process_identity(pid).as_ref() != Some(captured_identity) {
        return Ok(Vec::new());
    }

    signal_if_identity(pid, captured_identity)?;
    Ok(still_owned_ports)
}

#[cfg(not(windows))]
fn kill_pid_if_owns_ports_unix_with(
    pid: u32,
    ports: &[u16],
    expected_identity: &ProcessIdentity,
    mut port_owner: impl FnMut(u16) -> Option<u32>,
    mut process_identity: impl FnMut(u32) -> Option<ProcessIdentity>,
    mut signal_if_identity: impl FnMut(u32, &ProcessIdentity) -> Result<(), String>,
) -> Result<Vec<u16>, String> {
    if process_identity(pid).as_ref() != Some(expected_identity) {
        return Ok(Vec::new());
    }
    let mut still_owned_ports: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|port| port_owner(*port) == Some(pid))
        .collect();
    still_owned_ports.sort_unstable();
    still_owned_ports.dedup();

    if still_owned_ports.is_empty() {
        return Ok(Vec::new());
    }
    if process_identity(pid).as_ref() != Some(expected_identity) {
        return Ok(Vec::new());
    }

    signal_if_identity(pid, expected_identity)?;
    Ok(still_owned_ports)
}

#[cfg(windows)]
fn protected_pid(pid: u32) -> bool {
    pid <= 4
}

#[cfg(not(windows))]
fn protected_pid(pid: u32) -> bool {
    pid <= 1
}

/// List all listening TCP ports visible to the current user.
pub fn list_listening_ports() -> Vec<ListeningPort> {
    let mut rows = list_listening_ports_platform();
    #[cfg(unix)]
    enrich_listening_port_projects(&mut rows);
    sort_listening_ports(&mut rows);
    rows
}

pub(crate) fn list_listening_ports_until(
    deadline: std::time::Instant,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Option<Vec<ListeningPort>> {
    if should_cancel() || std::time::Instant::now() >= deadline {
        return None;
    }

    #[cfg(unix)]
    let rows = list_listening_ports_unix_until(deadline, should_cancel)?;
    #[cfg(not(unix))]
    let rows = list_listening_ports();

    if should_cancel() || std::time::Instant::now() >= deadline {
        None
    } else {
        Some(rows)
    }
}

#[cfg(test)]
pub(crate) fn list_listening_ports_for_pids(pids: &HashSet<u32>) -> Vec<ListeningPort> {
    if pids.is_empty() {
        return Vec::new();
    }

    #[cfg(unix)]
    let mut rows = list_listening_ports_unix_for_pids(pids);
    #[cfg(not(unix))]
    let mut rows: Vec<ListeningPort> = list_listening_ports_platform()
        .into_iter()
        .filter(|row| row.pid.is_some_and(|pid| pids.contains(&pid)))
        .collect();

    sort_listening_ports(&mut rows);
    rows
}

pub(crate) fn list_listening_ports_for_pids_until(
    pids: &HashSet<u32>,
    deadline: std::time::Instant,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Option<Vec<ListeningPort>> {
    if pids.is_empty() {
        return Some(Vec::new());
    }
    if should_cancel() || std::time::Instant::now() >= deadline {
        return None;
    }

    #[cfg(unix)]
    let mut rows = list_listening_ports_unix_for_pids_until(pids, deadline, should_cancel)?;
    #[cfg(not(unix))]
    let mut rows: Vec<ListeningPort> = list_listening_ports_platform()
        .into_iter()
        .filter(|row| row.pid.is_some_and(|pid| pids.contains(&pid)))
        .collect();

    if should_cancel() || std::time::Instant::now() >= deadline {
        return None;
    }
    sort_listening_ports(&mut rows);
    Some(rows)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessIdentity(String);

impl ProcessIdentity {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DescendantProcessSnapshot {
    identities: HashMap<u32, Option<ProcessIdentity>>,
    uncertain_descendants: bool,
}

impl DescendantProcessSnapshot {
    pub(crate) fn process_ids(&self) -> HashSet<u32> {
        self.identities.keys().copied().collect()
    }

    pub(crate) fn contains(&self, pid: u32) -> bool {
        self.identities.contains_key(&pid)
    }

    pub(crate) fn contains_same_process(
        &self,
        pid: u32,
        other: &DescendantProcessSnapshot,
    ) -> bool {
        matches!(
            (self.identities.get(&pid), other.identities.get(&pid)),
            (Some(Some(first)), Some(Some(second))) if first == second
        )
    }
}

pub(crate) fn descendant_process_snapshot(root_pid: u32) -> DescendantProcessSnapshot {
    #[cfg(unix)]
    {
        descendant_process_snapshot_unix(root_pid)
    }
    #[cfg(windows)]
    {
        descendant_process_snapshot_windows(root_pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        DescendantProcessSnapshot {
            identities: HashMap::from([(root_pid, None)]),
            uncertain_descendants: false,
        }
    }
}

pub(crate) fn descendant_process_snapshot_until(
    root_pid: u32,
    deadline: std::time::Instant,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Option<DescendantProcessSnapshot> {
    if should_cancel() || std::time::Instant::now() >= deadline {
        return None;
    }

    #[cfg(unix)]
    let snapshot = descendant_process_snapshot_unix_until(root_pid, deadline, should_cancel)?;
    #[cfg(windows)]
    let snapshot = descendant_process_snapshot_windows(root_pid);
    #[cfg(not(any(unix, windows)))]
    let snapshot = DescendantProcessSnapshot {
        identities: HashMap::from([(root_pid, None)]),
        uncertain_descendants: false,
    };

    if should_cancel() || std::time::Instant::now() >= deadline {
        None
    } else {
        Some(snapshot)
    }
}

/// Terminates an owned child and descendants that still match their captured identities.
#[doc(hidden)]
pub fn terminate_child_process_tree(
    child: &mut Child,
) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(windows)]
    {
        return terminate_child_process_tree_windows(child);
    }
    #[cfg(not(windows))]
    {
        let root_pid = child.id();
        let snapshot = descendant_process_snapshot(root_pid);
        terminate_child_process_tree_non_windows_with(child, &snapshot, |pid, expected_identity| {
            terminate_unix_pid_if_process_identity(pid, expected_identity)
        })
    }
}

#[cfg(any(not(windows), test))]
fn terminate_child_process_tree_non_windows_with(
    child: &mut Child,
    snapshot: &DescendantProcessSnapshot,
    terminate_if_identity: impl FnMut(u32, &ProcessIdentity) -> Result<(), String>,
) -> std::io::Result<std::process::ExitStatus> {
    let root_pid = child.id();
    let failures = kill_snapshot_descendants_with(snapshot, root_pid, terminate_if_identity)
        .max(usize::from(snapshot.uncertain_descendants));
    let _ = child.kill();
    let status = child.wait()?;
    if failures == 0 {
        Ok(status)
    } else {
        Err(std::io::Error::other(format!(
            "could not safely terminate {failures} descendant process(es) of PID {root_pid}"
        )))
    }
}

fn kill_snapshot_descendants_with(
    snapshot: &DescendantProcessSnapshot,
    root_pid: u32,
    mut terminate_if_identity: impl FnMut(u32, &ProcessIdentity) -> Result<(), String>,
) -> usize {
    let mut failures = 0usize;
    for (&pid, expected_identity) in snapshot
        .identities
        .iter()
        .filter(|(pid, _)| **pid != root_pid)
    {
        let Some(expected_identity) = expected_identity else {
            failures += 1;
            continue;
        };
        if terminate_if_identity(pid, expected_identity).is_err() {
            failures += 1;
        }
    }
    failures
}

#[cfg(any(windows, test))]
fn terminate_descendants_until_stable_with(
    root_pid: u32,
    deadline: std::time::Instant,
    snapshot: impl FnMut() -> DescendantProcessSnapshot,
    terminate_if_identity: impl FnMut(u32, &ProcessIdentity) -> Result<(), String>,
) -> Result<(), usize> {
    terminate_descendants_until_stable_with_clock(
        root_pid,
        deadline,
        snapshot,
        terminate_if_identity,
        std::time::Instant::now,
        std::thread::sleep,
    )
}

#[cfg(any(windows, test))]
fn terminate_descendants_until_stable_with_clock(
    root_pid: u32,
    deadline: std::time::Instant,
    mut snapshot: impl FnMut() -> DescendantProcessSnapshot,
    mut terminate_if_identity: impl FnMut(u32, &ProcessIdentity) -> Result<(), String>,
    mut now: impl FnMut() -> std::time::Instant,
    mut wait: impl FnMut(std::time::Duration),
) -> Result<(), usize> {
    let mut retry = 0u32;
    let mut saw_uncertainty = false;
    loop {
        let snapshot = snapshot();
        saw_uncertainty |= snapshot.uncertain_descendants;
        let remaining = snapshot
            .identities
            .keys()
            .filter(|pid| **pid != root_pid)
            .count();
        if remaining == 0 && !saw_uncertainty {
            return Ok(());
        }
        kill_snapshot_descendants_with(&snapshot, root_pid, &mut terminate_if_identity);
        let current = now();
        if current >= deadline {
            return Err(remaining.max(usize::from(saw_uncertainty)));
        }
        wait(termination_retry_delay(retry).min(deadline.duration_since(current)));
        retry = retry.saturating_add(1);
    }
}

#[cfg(any(windows, test))]
fn termination_retry_delay(retry: u32) -> std::time::Duration {
    let milliseconds = 10u64.checked_shl(retry.min(5)).unwrap_or(250).min(250);
    std::time::Duration::from_millis(milliseconds)
}

#[cfg(windows)]
fn terminate_child_process_tree_windows(
    child: &mut Child,
) -> std::io::Result<std::process::ExitStatus> {
    let root_pid = child.id();
    let root_identity = windows_root_process_identity_from_child(child).ok_or_else(|| {
        std::io::Error::other(format!(
            "could not capture the identity of child PID {root_pid} before process-tree cleanup"
        ))
    })?;
    let mut trusted = HashMap::from([(root_pid, root_identity)]);
    let mut trusted_parents = HashMap::new();
    let initial =
        descendant_process_snapshot_windows_with_trusted(root_pid, &trusted, &trusted_parents);
    for (pid, identity) in &initial.processes.identities {
        if let Some(identity) = identity {
            trusted.entry(*pid).or_insert_with(|| identity.clone());
        }
    }
    trusted_parents.extend(initial.parents);

    let _ = child.kill();
    let status = child.wait()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    terminate_descendants_until_stable_with(
        root_pid,
        deadline,
        || {
            let snapshot = descendant_process_snapshot_windows_with_trusted(
                root_pid,
                &trusted,
                &trusted_parents,
            );
            for (pid, identity) in &snapshot.processes.identities {
                if let Some(identity) = identity {
                    trusted.entry(*pid).or_insert_with(|| identity.clone());
                }
            }
            trusted_parents.extend(snapshot.parents);
            snapshot.processes
        },
        terminate_windows_pid_if_process_identity,
    )
    .map_err(|remaining| {
        std::io::Error::other(format!(
            "could not terminate {remaining} verified descendant process(es) of PID {root_pid} before the cleanup deadline"
        ))
    })?;
    Ok(status)
}

#[cfg(windows)]
fn windows_root_process_identity_from_child(child: &Child) -> Option<ProcessIdentity> {
    use std::os::windows::io::AsRawHandle as _;

    windows_root_process_identity_from_handle_with(
        child.as_raw_handle(),
        windows_process_creation_ticks,
    )
}

#[cfg(any(windows, test))]
fn windows_root_process_identity_from_handle_with<Handle>(
    handle: Handle,
    creation_ticks: impl FnOnce(Handle) -> Option<u64>,
) -> Option<ProcessIdentity> {
    creation_ticks(handle).map(|ticks| ProcessIdentity(format!("windows:{ticks}")))
}

#[cfg(windows)]
fn terminate_windows_pid_if_process_identity(
    pid: u32,
    expected: &ProcessIdentity,
) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };

    if protected_pid(pid) || pid == std::process::id() {
        return Err(format!("refusing to terminate protected PID {pid}"));
    }
    let creation_ticks = windows_process_identity_ticks(expected)
        .ok_or_else(|| format!("PID {pid} has an invalid captured Windows identity"))?;
    let handle =
        try_open_windows_process(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, pid)
            .map_err(|error| error.to_string())?;
    let current_ticks = windows_process_creation_ticks(handle.raw()).ok_or_else(|| {
        format!("PID {pid} creation time is unavailable; aborting kill for safety")
    })?;
    if current_ticks != creation_ticks {
        return Err(format!(
            "PID {pid} identity changed before termination; aborting kill for safety"
        ));
    }
    // SAFETY: this exact handle supplied the creation time checked above and
    // remains open with PROCESS_TERMINATE through the signal operation.
    if unsafe { TerminateProcess(handle.raw(), 1) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn windows_exit_code_is_active(exit_code: u32) -> bool {
    use windows_sys::Win32::Foundation::STILL_ACTIVE;

    exit_code == STILL_ACTIVE as u32
}

#[doc(hidden)]
pub fn process_is_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if pid <= 0 {
            return false;
        }
        // SAFETY: signal 0 performs an existence/permission check and does not
        // deliver a signal to the target process.
        let status = unsafe { libc::kill(pid, 0) };
        status == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // SAFETY: the call has no input pointers; a successful owned handle is
        // closed below after querying its exit code.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut exit_code = 0u32;
        // SAFETY: `exit_code` is writable and `handle` is live on this path.
        let queried = unsafe { GetExitCodeProcess(handle, &mut exit_code) } != 0;
        // SAFETY: `handle` is a valid owned process handle.
        unsafe {
            CloseHandle(handle);
        }
        queried && windows_exit_code_is_active(exit_code)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

#[cfg(unix)]
fn descendant_process_snapshot_unix(root_pid: u32) -> DescendantProcessSnapshot {
    let mut never_cancel = || false;
    descendant_process_snapshot_unix_until(
        root_pid,
        std::time::Instant::now() + std::time::Duration::from_millis(2_100),
        &mut never_cancel,
    )
    .unwrap_or_else(|| failed_process_tree_snapshot(root_pid))
}

#[cfg(unix)]
fn descendant_process_snapshot_unix_until(
    root_pid: u32,
    deadline: std::time::Instant,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Option<DescendantProcessSnapshot> {
    static SENDER: std::sync::OnceLock<
        Option<std::sync::mpsc::SyncSender<ProcessTreeSnapshotRequest>>,
    > = std::sync::OnceLock::new();
    let sender = SENDER
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(DISCOVERY_WORKER_QUEUE_CAPACITY);
            std::thread::Builder::new()
                .name("lpm-process-trees".to_string())
                .spawn(move || run_process_tree_snapshot_batches(receiver))
                .ok()
                .map(|_| sender)
        })
        .as_ref()?;
    let (response, snapshot) = std::sync::mpsc::sync_channel(1);
    if sender
        .try_send(ProcessTreeSnapshotRequest {
            root_pid,
            deadline,
            response,
        })
        .is_err()
    {
        return None;
    }
    receive_worker_response_until(&snapshot, deadline, should_cancel)
}

#[cfg(unix)]
#[derive(Clone)]
struct UnixProcessRecord {
    pid: u32,
    parent: u32,
    identity: Option<ProcessIdentity>,
}

#[cfg(unix)]
struct UnixProcessTable {
    children_by_parent: HashMap<u32, Vec<u32>>,
    identities: HashMap<u32, Option<ProcessIdentity>>,
}

#[cfg(unix)]
impl UnixProcessTable {
    fn from_records(records: Vec<UnixProcessRecord>) -> Self {
        let mut children_by_parent = HashMap::with_capacity(records.len());
        let mut identities = HashMap::with_capacity(records.len());
        for record in records {
            children_by_parent
                .entry(record.parent)
                .or_insert_with(Vec::new)
                .push(record.pid);
            identities.insert(record.pid, record.identity);
        }
        Self {
            children_by_parent,
            identities,
        }
    }

    fn descendants(&self, root_pid: u32) -> DescendantProcessSnapshot {
        const MAX_DESCENDANTS: usize = 16_384;
        let mut identities = HashMap::with_capacity(16);
        let mut pending = Vec::with_capacity(16);
        pending.push(root_pid);
        while let Some(pid) = pending.pop() {
            if identities.contains_key(&pid) {
                continue;
            }
            if identities.len() >= MAX_DESCENDANTS {
                return failed_process_tree_snapshot(root_pid);
            }
            let identity = self
                .identities
                .get(&pid)
                .cloned()
                .flatten()
                .or_else(|| process_identity_for_pid(pid));
            identities.insert(pid, identity);
            if let Some(children) = self.children_by_parent.get(&pid) {
                pending.extend(children.iter().copied());
            }
        }
        DescendantProcessSnapshot {
            identities,
            uncertain_descendants: false,
        }
    }
}

#[cfg(unix)]
struct ProcessTreeSnapshotRequest {
    root_pid: u32,
    deadline: std::time::Instant,
    response: std::sync::mpsc::SyncSender<DescendantProcessSnapshot>,
}

#[cfg(unix)]
fn receive_worker_response_until<T>(
    receiver: &std::sync::mpsc::Receiver<T>,
    deadline: std::time::Instant,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Option<T> {
    const CANCELLATION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(25);

    loop {
        if should_cancel() {
            return None;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match receiver.recv_timeout(remaining.min(CANCELLATION_POLL_INTERVAL)) {
            Ok(response) => return Some(response),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

#[cfg(unix)]
fn run_process_tree_snapshot_batches(
    receiver: std::sync::mpsc::Receiver<ProcessTreeSnapshotRequest>,
) {
    while let Ok(first) = receiver.recv() {
        process_tree_snapshot_batch(first, &receiver, query_unix_process_table);
    }
}

#[cfg(unix)]
fn process_tree_snapshot_batch(
    first: ProcessTreeSnapshotRequest,
    receiver: &std::sync::mpsc::Receiver<ProcessTreeSnapshotRequest>,
    query: impl FnOnce(std::time::Instant) -> Option<UnixProcessTable>,
) {
    let mut requests = Vec::with_capacity(8);
    requests.push(first);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(4);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(request) => requests.push(request),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    requests.retain(|request| std::time::Instant::now() < request.deadline);
    if requests.is_empty() {
        return;
    }

    let query_deadline = requests
        .iter()
        .map(|request| request.deadline)
        .min()
        .unwrap_or_else(std::time::Instant::now);
    let table = query(query_deadline);
    for request in requests {
        if std::time::Instant::now() >= request.deadline {
            continue;
        }
        let snapshot = table.as_ref().map_or_else(
            || failed_process_tree_snapshot(request.root_pid),
            |table| table.descendants(request.root_pid),
        );
        let _ = request.response.send(snapshot);
    }
}

fn failed_process_tree_snapshot(root_pid: u32) -> DescendantProcessSnapshot {
    DescendantProcessSnapshot {
        identities: HashMap::from([(root_pid, None)]),
        uncertain_descendants: true,
    }
}

#[cfg(target_os = "linux")]
fn query_unix_process_table(deadline: std::time::Instant) -> Option<UnixProcessTable> {
    let entries = std::fs::read_dir("/proc").ok()?;
    let boot_id = linux_boot_id();
    let mut records = Vec::new();
    for entry in entries.flatten() {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let mut stat_path = entry.path();
        stat_path.push("stat");
        let Ok(stat) = lpm_common::read_text_file_capped(&stat_path, PROC_STAT_FILE_SIZE_CAP_BYTES)
        else {
            continue;
        };
        let Some((parent, start_ticks)) = parse_proc_stat_parent_and_start_ticks(&stat) else {
            continue;
        };
        let identity = boot_id
            .as_deref()
            .map(|boot_id| ProcessIdentity(format!("linux:{boot_id}:{start_ticks}")));
        records.push(UnixProcessRecord {
            pid,
            parent,
            identity,
        });
    }
    Some(UnixProcessTable::from_records(records))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn query_unix_process_table(deadline: std::time::Instant) -> Option<UnixProcessTable> {
    let mut command = Command::new("ps");
    command.args(["-axo", "pid=,ppid="]);
    let output = command_stdout_capped_until(&mut command, deadline)?;
    let stdout = std::str::from_utf8(&output).ok()?;
    Some(UnixProcessTable::from_records(
        stdout
            .lines()
            .filter_map(parse_unix_process_record)
            .collect(),
    ))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn command_stdout_capped(command: &mut Command) -> Option<Vec<u8>> {
    command_stdout_capped_until(
        command,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )
}

#[cfg(all(unix, test))]
fn command_stdout_capped_with_timeout(
    command: &mut Command,
    command_timeout: std::time::Duration,
) -> Option<Vec<u8>> {
    command_stdout_capped_until(command, std::time::Instant::now() + command_timeout)
}

#[cfg(all(unix, any(test, not(target_os = "linux"))))]
fn command_stdout_capped_until(
    command: &mut Command,
    deadline: std::time::Instant,
) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    const OUTPUT_CAP: u64 = 8 * 1024 * 1024;

    command.process_group(0);
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let process_group = child.id();
    let (output_sender, output_receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut output = Vec::with_capacity(64 * 1024);
        let output = std::io::copy(&mut stdout.take(OUTPUT_CAP + 1), &mut output).map(|_| output);
        let _ = output_sender.send(output);
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Ok(None) | Err(_) => {
                kill_unix_process_group(process_group);
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let output = match output_receiver.recv_timeout(remaining) {
        Ok(output) => {
            let _ = reader.join();
            output.ok()?
        }
        Err(_) => {
            kill_unix_process_group(process_group);
            let _ = child.kill();
            let _ = child.wait();
            if output_receiver
                .recv_timeout(std::time::Duration::from_millis(250))
                .is_ok()
            {
                let _ = reader.join();
            }
            return None;
        }
    };
    if !status.is_some_and(|status| status.success()) || output.len() as u64 > OUTPUT_CAP {
        return None;
    }
    Some(output)
}

#[cfg(all(unix, any(test, not(target_os = "linux"))))]
fn kill_unix_process_group(process_group: u32) {
    let Ok(process_group) = libc::pid_t::try_from(process_group) else {
        return;
    };
    if process_group <= 1 {
        return;
    }
    // SAFETY: the negative PID addresses only the dedicated process group
    // created for this probe; SIGKILL does not dereference memory.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parse_unix_process_record(line: &str) -> Option<UnixProcessRecord> {
    let (pid, rest) = take_token(line.trim_start())?;
    let (parent, _) = take_token(rest.trim_start())?;
    let pid = pid.parse::<u32>().ok()?;
    Some(UnixProcessRecord {
        pid,
        parent: parent.parse::<u32>().ok()?,
        identity: None,
    })
}

pub fn process_identity_for_pid(pid: u32) -> Option<ProcessIdentity> {
    #[cfg(target_os = "linux")]
    {
        let stat_path = format!("/proc/{pid}/stat");
        let stat =
            lpm_common::read_text_file_capped(Path::new(&stat_path), PROC_STAT_FILE_SIZE_CAP_BYTES)
                .ok()?;
        let (_, start_ticks) = parse_proc_stat_parent_and_start_ticks(&stat)?;
        linux_boot_id().map(|boot_id| ProcessIdentity(format!("linux:{boot_id}:{start_ticks}")))
    }
    #[cfg(target_os = "macos")]
    {
        macos_process_identity(pid)
    }
    #[cfg(windows)]
    {
        windows_process_identity_for_pid(pid)
            .and_then(|identity| identity.creation_ticks)
            .map(|ticks| ProcessIdentity(format!("windows:{ticks}")))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        None
    }
}

pub(crate) fn process_identities_for_pids(pids: &HashSet<u32>) -> HashMap<u32, ProcessIdentity> {
    let mut identities = HashMap::with_capacity(pids.len());
    for &pid in pids {
        if let Some(identity) = process_identity_for_pid(pid) {
            identities.insert(pid, identity);
        }
    }
    identities
}

#[cfg(target_os = "linux")]
fn linux_boot_id() -> Option<String> {
    static BOOT_ID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    BOOT_ID
        .get_or_init(|| {
            lpm_common::read_text_file_capped(
                Path::new("/proc/sys/kernel/random/boot_id"),
                LINUX_BOOT_ID_FILE_SIZE_CAP_BYTES,
            )
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        })
        .clone()
}

#[cfg(target_os = "macos")]
fn macos_process_identity(pid: u32) -> Option<ProcessIdentity> {
    #[repr(C)]
    struct ProcUniqueIdentifierInfo {
        uuid: [u8; 16],
        unique_id: u64,
        parent_unique_id: u64,
        id_version: i32,
        reserved_2: u32,
        reserved_3: u64,
        reserved_4: u64,
    }

    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }

    const PROC_PID_UNIQUE_IDENTIFIER_INFO: libc::c_int = 17;
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut info = std::mem::MaybeUninit::<ProcUniqueIdentifierInfo>::uninit();
    let expected = libc::c_int::try_from(std::mem::size_of::<ProcUniqueIdentifierInfo>()).ok()?;
    // SAFETY: `info` points to an allocation of exactly `expected` bytes and
    // `proc_pidinfo` initializes it only when it reports that full size.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PID_UNIQUE_IDENTIFIER_INFO,
            0,
            info.as_mut_ptr().cast(),
            expected,
        )
    };
    if written != expected {
        return None;
    }
    // SAFETY: the successful call above initialized the complete structure.
    let info = unsafe { info.assume_init() };
    Some(ProcessIdentity(format!(
        "macos:{}:{}",
        info.unique_id, info.id_version
    )))
}

#[cfg(any(windows, test))]
#[derive(Clone)]
struct WindowsSnapshotEntry {
    pid: u32,
    parent: u32,
}

#[cfg(any(windows, test))]
struct WindowsDescendantSnapshot {
    processes: DescendantProcessSnapshot,
    parents: HashMap<u32, u32>,
}

#[cfg(windows)]
fn descendant_process_snapshot_windows(root_pid: u32) -> DescendantProcessSnapshot {
    let trusted = process_identity_for_pid(root_pid)
        .map(|identity| HashMap::from([(root_pid, identity)]))
        .unwrap_or_default();
    descendant_process_snapshot_windows_with_trusted(root_pid, &trusted, &HashMap::new()).processes
}

#[cfg(windows)]
fn descendant_process_snapshot_windows_with_trusted(
    root_pid: u32,
    trusted: &HashMap<u32, ProcessIdentity>,
    trusted_parents: &HashMap<u32, u32>,
) -> WindowsDescendantSnapshot {
    let Some(entries) = windows_process_snapshot_entries() else {
        return WindowsDescendantSnapshot {
            processes: DescendantProcessSnapshot {
                identities: HashMap::from([(root_pid, trusted.get(&root_pid).cloned())]),
                uncertain_descendants: true,
            },
            parents: HashMap::new(),
        };
    };
    windows_descendant_snapshot_from_entry_samples(
        root_pid,
        trusted,
        trusted_parents,
        &entries,
        |pid| {
            windows_process_identity_for_pid(pid)
                .and_then(|identity| identity.creation_ticks)
                .map(|ticks| ProcessIdentity(format!("windows:{ticks}")))
        },
        windows_process_snapshot_entries,
    )
}

#[cfg(windows)]
fn windows_process_snapshot_entries() -> Option<Vec<WindowsSnapshotEntry>> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    // SAFETY: the snapshot has no input pointers and is closed on every
    // successful handle path below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut pairs = Vec::new();
    // SAFETY: `entry.dwSize` is initialized as required by ToolHelp, and the
    // snapshot remains open for the complete iteration.
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while has_entry {
        pairs.push((entry.th32ProcessID, entry.th32ParentProcessID));
        // SAFETY: same initialized entry and live snapshot as above.
        has_entry = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: `snapshot` is a valid owned handle on this path.
    unsafe {
        CloseHandle(snapshot);
    }

    Some(
        pairs
            .into_iter()
            .map(|(pid, parent)| WindowsSnapshotEntry { pid, parent })
            .collect(),
    )
}

#[cfg(any(windows, test))]
fn windows_descendant_snapshot_from_entries(
    root_pid: u32,
    trusted: &HashMap<u32, ProcessIdentity>,
    trusted_parents: &HashMap<u32, u32>,
    entries: &[WindowsSnapshotEntry],
    resolve_identity: impl FnMut(u32) -> Option<ProcessIdentity>,
) -> WindowsDescendantSnapshot {
    windows_descendant_snapshot_from_entry_samples(
        root_pid,
        trusted,
        trusted_parents,
        entries,
        resolve_identity,
        || Some(entries.to_vec()),
    )
}

#[cfg(any(windows, test))]
fn windows_descendant_snapshot_from_entry_samples(
    root_pid: u32,
    trusted: &HashMap<u32, ProcessIdentity>,
    trusted_parents: &HashMap<u32, u32>,
    captured_entries: &[WindowsSnapshotEntry],
    mut resolve_identity: impl FnMut(u32) -> Option<ProcessIdentity>,
    current_entries: impl FnOnce() -> Option<Vec<WindowsSnapshotEntry>>,
) -> WindowsDescendantSnapshot {
    let identities = windows_identity_candidate_pids(root_pid, trusted, captured_entries)
        .into_iter()
        .map(|pid| (pid, resolve_identity(pid)))
        .collect::<HashMap<_, _>>();
    let Some(current_entries) = current_entries() else {
        return WindowsDescendantSnapshot {
            processes: DescendantProcessSnapshot {
                identities: HashMap::from([(root_pid, trusted.get(&root_pid).cloned())]),
                uncertain_descendants: true,
            },
            parents: HashMap::new(),
        };
    };
    let captured_edges = captured_entries
        .iter()
        .map(|entry| (entry.pid, entry.parent))
        .collect::<HashMap<_, _>>();
    let current_edges = current_entries
        .iter()
        .map(|entry| (entry.pid, entry.parent))
        .collect::<HashMap<_, _>>();
    let invalidated_candidates = identities
        .keys()
        .filter(|pid| captured_edges.get(pid) != current_edges.get(pid))
        .copied()
        .collect::<HashSet<_>>();
    windows_descendant_snapshot_from_captured_entries(
        root_pid,
        trusted,
        trusted_parents,
        &current_entries,
        &captured_edges,
        &invalidated_candidates,
        |pid| identities.get(&pid).cloned().flatten(),
    )
}

#[cfg(any(windows, test))]
fn windows_identity_candidate_pids(
    root_pid: u32,
    trusted: &HashMap<u32, ProcessIdentity>,
    entries: &[WindowsSnapshotEntry],
) -> HashSet<u32> {
    let current = entries
        .iter()
        .map(|entry| entry.pid)
        .collect::<HashSet<_>>();
    let mut children_by_parent = HashMap::<u32, Vec<u32>>::new();
    for entry in entries {
        children_by_parent
            .entry(entry.parent)
            .or_default()
            .push(entry.pid);
    }
    let mut candidates = HashSet::with_capacity(trusted.len().max(1));
    let mut visited = HashSet::with_capacity(trusted.len().max(1));
    let mut pending = trusted.keys().copied().collect::<Vec<_>>();
    pending.push(root_pid);
    while let Some(pid) = pending.pop() {
        if !visited.insert(pid) {
            continue;
        }
        if current.contains(&pid) {
            candidates.insert(pid);
        }
        if let Some(children) = children_by_parent.get(&pid) {
            pending.extend(children.iter().copied());
        }
    }
    candidates
}

#[cfg(any(windows, test))]
fn windows_descendant_snapshot_from_captured_entries(
    root_pid: u32,
    trusted: &HashMap<u32, ProcessIdentity>,
    trusted_parents: &HashMap<u32, u32>,
    entries: &[WindowsSnapshotEntry],
    captured_edges: &HashMap<u32, u32>,
    invalidated_candidates: &HashSet<u32>,
    mut resolve_identity: impl FnMut(u32) -> Option<ProcessIdentity>,
) -> WindowsDescendantSnapshot {
    let current = entries
        .iter()
        .map(|entry| (entry.pid, entry))
        .collect::<HashMap<_, _>>();
    let mut children_by_parent = HashMap::<u32, Vec<u32>>::new();
    for (&child, &parent) in trusted_parents {
        children_by_parent.entry(parent).or_default().push(child);
    }
    for entry in entries {
        if !trusted_parents.contains_key(&entry.pid) {
            children_by_parent
                .entry(entry.parent)
                .or_default()
                .push(entry.pid);
        }
    }
    for children in children_by_parent.values_mut() {
        children.sort_unstable();
        children.dedup();
    }

    let mut identity_cache = HashMap::<u32, Option<ProcessIdentity>>::new();
    let mut identity_for = |pid| {
        identity_cache
            .entry(pid)
            .or_insert_with(|| resolve_identity(pid))
            .clone()
    };
    let root_identity = trusted.get(&root_pid).cloned().or_else(|| {
        current
            .contains_key(&root_pid)
            .then(|| identity_for(root_pid))
            .flatten()
    });
    let mut identities = HashMap::from([(root_pid, root_identity.clone())]);
    let mut parents = HashMap::new();
    let mut uncertain_descendants = !invalidated_candidates.is_empty();
    let mut visited = HashSet::new();
    let mut pending = Vec::with_capacity(trusted.len().max(1));
    if let Some(root_identity) = root_identity {
        if invalidated_candidates.contains(&root_pid) {
            uncertain_descendants = true;
        } else if current.contains_key(&root_pid) {
            match identity_for(root_pid) {
                Some(current_identity) if current_identity == root_identity => {
                    pending.push((root_pid, root_identity));
                }
                Some(_) => {
                    uncertain_descendants |=
                        children_by_parent.get(&root_pid).is_some_and(|children| {
                            children.iter().any(|pid| !trusted.contains_key(pid))
                        });
                }
                None => uncertain_descendants = true,
            }
        } else {
            uncertain_descendants |= children_by_parent
                .get(&root_pid)
                .is_some_and(|children| children.iter().any(|pid| !trusted.contains_key(pid)));
        }
    }
    for (&pid, expected) in trusted {
        if pid == root_pid {
            continue;
        }
        if invalidated_candidates.contains(&pid) {
            uncertain_descendants = true;
            continue;
        }
        if !current.contains_key(&pid) {
            uncertain_descendants |= children_by_parent
                .get(&pid)
                .is_some_and(|children| children.iter().any(|child| !trusted.contains_key(child)));
            continue;
        }
        match identity_for(pid) {
            Some(current_identity) if &current_identity == expected => {
                identities.insert(pid, Some(expected.clone()));
                if let Some(&parent) = trusted_parents.get(&pid) {
                    parents.insert(pid, parent);
                }
                pending.push((pid, expected.clone()));
            }
            Some(_) => {
                uncertain_descendants |= children_by_parent.get(&pid).is_some_and(|children| {
                    children.iter().any(|child| !trusted.contains_key(child))
                });
            }
            None => uncertain_descendants = true,
        }
    }
    while let Some((parent_pid, parent_identity)) = pending.pop() {
        if !visited.insert(parent_pid) {
            continue;
        }
        let Some(children) = children_by_parent.get(&parent_pid) else {
            continue;
        };
        let current_parent_identity = identity_for(parent_pid);
        for &child_pid in children {
            if visited.contains(&child_pid) {
                continue;
            }
            if invalidated_candidates.contains(&child_pid) {
                uncertain_descendants = true;
                continue;
            }
            if let Some(trusted_child) = trusted.get(&child_pid) {
                if identity_for(child_pid).as_ref() == Some(trusted_child) {
                    identities.insert(child_pid, Some(trusted_child.clone()));
                    parents.insert(child_pid, parent_pid);
                    pending.push((child_pid, trusted_child.clone()));
                }
                continue;
            }
            let Some(entry) = current.get(&child_pid) else {
                continue;
            };
            if captured_edges.get(&child_pid) != Some(&entry.parent) {
                uncertain_descendants = true;
                continue;
            }
            let Some(child_identity) = identity_for(entry.pid) else {
                identities.insert(child_pid, None);
                uncertain_descendants = true;
                continue;
            };
            if !windows_child_identity_matches_parent_incarnation(
                &parent_identity,
                &child_identity,
                current_parent_identity.as_ref(),
            ) {
                continue;
            }
            parents.insert(child_pid, parent_pid);
            identities.insert(child_pid, Some(child_identity.clone()));
            pending.push((child_pid, child_identity));
        }
    }
    WindowsDescendantSnapshot {
        processes: DescendantProcessSnapshot {
            identities,
            uncertain_descendants,
        },
        parents,
    }
}

#[cfg(any(windows, test))]
fn windows_child_identity_matches_parent_incarnation(
    expected_parent: &ProcessIdentity,
    child: &ProcessIdentity,
    current_parent: Option<&ProcessIdentity>,
) -> bool {
    let (Some(parent_ticks), Some(child_ticks)) = (
        windows_process_identity_ticks(expected_parent),
        windows_process_identity_ticks(child),
    ) else {
        return false;
    };
    if child_ticks < parent_ticks {
        return false;
    }
    let Some(current_parent) = current_parent else {
        return false;
    };
    if current_parent == expected_parent {
        return true;
    }
    windows_process_identity_ticks(current_parent)
        .is_some_and(|replacement_ticks| child_ticks < replacement_ticks)
}

#[cfg(any(windows, test))]
fn windows_process_identity_ticks(identity: &ProcessIdentity) -> Option<u64> {
    identity.as_str().strip_prefix("windows:")?.parse().ok()
}

#[cfg(any(windows, test))]
pub(crate) fn descendant_process_ids_from_pairs(
    root_pid: u32,
    pairs: impl IntoIterator<Item = (u32, u32)>,
) -> HashSet<u32> {
    let mut children_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, parent) in pairs {
        children_by_parent.entry(parent).or_default().push(pid);
    }

    let mut descendants = HashSet::from([root_pid]);
    let mut pending = vec![root_pid];
    while let Some(parent) = pending.pop() {
        if let Some(children) = children_by_parent.get(&parent) {
            for &child in children {
                if descendants.insert(child) {
                    pending.push(child);
                }
            }
        }
    }
    descendants
}

/// Build cross-service environment variables.
///
/// For each service with a declared port, injects `{SERVICE}_URL` and `{SERVICE}_PORT`
/// into all OTHER services' environments.
///
/// Example: services "web" (port 3000) and "api" (port 4000)
/// - web gets: API_URL=http://localhost:4000, API_PORT=4000
/// - api gets: WEB_URL=http://localhost:3000, WEB_PORT=3000
pub fn build_cross_service_env(
    services: &HashMap<String, u16>,
    https: bool,
) -> HashMap<String, HashMap<String, String>> {
    let scheme = if https { "https" } else { "http" };
    let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();

    for name in services.keys() {
        result.insert(name.clone(), HashMap::new());
    }

    for (source_name, &source_port) in services {
        let upper = source_name.to_uppercase().replace('-', "_");
        let url_key = format!("{upper}_URL");
        let port_key = format!("{upper}_PORT");
        let url_value = format!("{scheme}://localhost:{source_port}");
        let port_value = source_port.to_string();

        // Inject into all OTHER services
        for (target_name, env) in result.iter_mut() {
            if target_name != source_name {
                env.insert(url_key.clone(), url_value.clone());
                env.insert(port_key.clone(), port_value.clone());
            }
        }
    }

    result
}

/// Find the PID and process name using a port.
pub(crate) fn find_port_owner(port: u16) -> (Option<u32>, Option<String>) {
    #[cfg(target_os = "linux")]
    {
        find_port_owner_from_list(port)
    }
    #[cfg(windows)]
    {
        find_port_owner_from_list(port)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        find_port_owner_lsof(port)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = port;
        (None, None)
    }
}

#[cfg(any(target_os = "linux", windows))]
fn find_port_owner_from_list(port: u16) -> (Option<u32>, Option<String>) {
    list_listening_ports()
        .into_iter()
        .find(|row| row.port == port)
        .map_or((None, None), |row| (row.pid, row.process))
}

#[cfg(target_os = "linux")]
fn list_listening_ports_platform() -> Vec<ListeningPort> {
    list_listening_ports_linux()
}

#[cfg(windows)]
fn list_listening_ports_platform() -> Vec<ListeningPort> {
    list_listening_ports_windows()
}

#[cfg(target_os = "macos")]
fn list_listening_ports_platform() -> Vec<ListeningPort> {
    list_listening_ports_macos_until(std::time::Instant::now() + std::time::Duration::from_secs(2))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn list_listening_ports_platform() -> Vec<ListeningPort> {
    list_listening_ports_lsof()
}

#[cfg(not(any(unix, windows)))]
fn list_listening_ports_platform() -> Vec<ListeningPort> {
    Vec::new()
}

fn sort_listening_ports(rows: &mut [ListeningPort]) {
    rows.sort_by(|left, right| {
        left.port
            .cmp(&right.port)
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| {
                listening_address_family_rank(left.address_family)
                    .cmp(&listening_address_family_rank(right.address_family))
            })
            .then_with(|| left.address.cmp(&right.address))
    });
}

fn listening_address_family_rank(family: Option<ListeningAddressFamily>) -> u8 {
    match family {
        Some(ListeningAddressFamily::Ipv4) => 0,
        Some(ListeningAddressFamily::Ipv6) => 1,
        None => 2,
    }
}

#[cfg(any(target_os = "linux", windows))]
fn format_elapsed_secs(total_secs: u64) -> String {
    let days = total_secs / 86_400;
    let rem = total_secs % 86_400;
    let hours = rem / 3_600;
    let minutes = (rem % 3_600) / 60;
    let seconds = rem % 60;
    if days > 0 {
        format!("{days}-{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn find_port_owner_lsof(port: u16) -> (Option<u32>, Option<String>) {
    let mut lsof = lsof_listener_query(port);
    if let Some(output) = command_stdout_capped(&mut lsof) {
        let stdout = String::from_utf8_lossy(&output);
        let pid_str = stdout.trim().lines().next().unwrap_or("").trim();
        if let Ok(pid) = pid_str.parse::<u32>() {
            let pid_arg = pid.to_string();
            let mut ps = Command::new("ps");
            ps.args(["-p", &pid_arg, "-o", "comm="]);
            let name = command_stdout_capped(&mut ps)
                .map(|output| String::from_utf8_lossy(&output).trim().to_string());
            return (Some(pid), name);
        }
    }

    (None, None)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn lsof_listener_query(port: u16) -> Command {
    let port_arg = format!("-iTCP:{port}");
    let mut command = Command::new("lsof");
    command.args(["-nP", "-a", &port_arg, "-sTCP:LISTEN", "-t"]);
    command
}

#[cfg(all(unix, not(target_os = "linux")))]
#[derive(Debug, Clone, Default)]
struct PsInfo {
    process: Option<String>,
    command: Option<String>,
    uptime: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct ProjectInfo {
    dir: PathBuf,
    name: String,
    framework: Option<String>,
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn list_listening_ports_lsof() -> Vec<ListeningPort> {
    list_listening_ports_lsof_until_inner(
        std::time::Instant::now() + std::time::Duration::from_secs(2),
        true,
    )
}

#[cfg(target_os = "macos")]
fn list_listening_ports_macos_until(deadline: std::time::Instant) -> Vec<ListeningPort> {
    if std::time::Instant::now() >= deadline {
        return Vec::new();
    }
    let mut command = Command::new("/usr/sbin/netstat");
    command.args(["-anv", "-p", "tcp"]);
    let Some(output) = command_stdout_capped_until(&mut command, deadline) else {
        return list_listening_ports_lsof_until_inner(deadline, false);
    };
    let stdout = String::from_utf8_lossy(&output);
    let mut rows = parse_macos_netstat_listen_output(&stdout);
    if rows.is_empty() && !output.is_empty() {
        return list_listening_ports_lsof_until_inner(deadline, false);
    }

    enrich_non_linux_listener_processes(&mut rows, deadline, false);
    rows
}

#[cfg(target_os = "macos")]
fn parse_macos_netstat_listen_output(output: &str) -> Vec<ListeningPort> {
    let mut rows = Vec::new();
    let mut seen = HashSet::<ListeningSocketIdentity>::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let address_family = match fields.next() {
            Some("tcp4") => ListeningAddressFamily::Ipv4,
            Some("tcp6") => ListeningAddressFamily::Ipv6,
            _ => continue,
        };
        let Some(_) = fields.next() else { continue };
        let Some(_) = fields.next() else { continue };
        let Some(local_endpoint) = fields.next() else {
            continue;
        };
        let Some(_) = fields.next() else { continue };
        if fields.next() != Some("LISTEN") {
            continue;
        }
        let Some((address, port)) = parse_macos_netstat_endpoint(local_endpoint) else {
            continue;
        };

        let mut process_parts = Vec::with_capacity(3);
        let mut pid = None;
        for token in fields.skip(4) {
            if let Some((last_name_part, pid_text)) = token.rsplit_once(':')
                && let Ok(parsed_pid) = pid_text.parse::<u32>()
            {
                if !last_name_part.is_empty() {
                    process_parts.push(last_name_part);
                }
                pid = Some(parsed_pid);
                break;
            }
            process_parts.push(token);
        }
        let process =
            pid.and_then(|_| (!process_parts.is_empty()).then(|| process_parts.join(" ")));
        let identity =
            ListeningSocketIdentity::new(port, pid, Some(address_family), address.clone());
        if !seen.insert(identity) {
            continue;
        }
        rows.push(ListeningPort {
            port,
            address,
            address_family: Some(address_family),
            pid,
            process,
            command: None,
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: None,
        });
    }
    rows
}

#[cfg(target_os = "macos")]
fn parse_macos_netstat_endpoint(value: &str) -> Option<(Option<String>, u16)> {
    let (address, port) = value.rsplit_once('.')?;
    let port = port.parse::<u16>().ok()?;
    let address = address
        .split_once('%')
        .map_or(address, |(address, _)| address);
    let address = if address.is_empty() || address == "*" {
        None
    } else {
        Some(address.to_string())
    };
    Some((address, port))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn enrich_non_linux_listener_processes(
    rows: &mut [ListeningPort],
    deadline: std::time::Instant,
    complete_cwd_after_deadline: bool,
) {
    let mut pids: Vec<u32> = rows.iter().filter_map(|row| row.pid).collect();
    pids.sort_unstable();
    pids.dedup();

    let cwd_by_pid = collect_cwds_until(&pids, deadline, complete_cwd_after_deadline);
    let ps_by_pid = collect_ps_info_until(&pids, deadline);
    for row in rows {
        if let Some(pid) = row.pid {
            if let Some(info) = ps_by_pid.get(&pid) {
                if row.process.is_none() {
                    row.process.clone_from(&info.process);
                }
                row.command.clone_from(&info.command);
                row.uptime.clone_from(&info.uptime);
            }
            row.cwd = cwd_by_pid.get(&pid).cloned();
        }
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn list_listening_ports_lsof_until(deadline: std::time::Instant) -> Vec<ListeningPort> {
    list_listening_ports_lsof_until_inner(deadline, false)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn list_listening_ports_lsof_until_inner(
    deadline: std::time::Instant,
    complete_macos_cwd_enrichment: bool,
) -> Vec<ListeningPort> {
    let mut command = Command::new("lsof");
    command.args(["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcPtn"]);
    let Some(output) = command_stdout_capped_until(&mut command, deadline) else {
        return Vec::new();
    };
    if output.is_empty() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output);
    let mut rows = parse_lsof_listen_output(&stdout);
    if rows.is_empty() {
        return rows;
    }

    enrich_non_linux_listener_processes(&mut rows, deadline, complete_macos_cwd_enrichment);

    rows
}

#[cfg(unix)]
struct PidListenerRequest {
    pids: HashSet<u32>,
    deadline: std::time::Instant,
    response: std::sync::mpsc::SyncSender<Vec<ListeningPort>>,
}

#[cfg(unix)]
struct FullListenerRequest {
    deadline: std::time::Instant,
    response: std::sync::mpsc::SyncSender<Vec<ListeningPort>>,
}

#[cfg(unix)]
const DISCOVERY_WORKER_QUEUE_CAPACITY: usize = 64;

#[cfg(unix)]
fn list_listening_ports_unix_until(
    deadline: std::time::Instant,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Option<Vec<ListeningPort>> {
    static SENDER: std::sync::OnceLock<Option<std::sync::mpsc::SyncSender<FullListenerRequest>>> =
        std::sync::OnceLock::new();
    let sender = SENDER
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(DISCOVERY_WORKER_QUEUE_CAPACITY);
            std::thread::Builder::new()
                .name("lpm-all-listeners".to_string())
                .spawn(move || run_full_listener_batches(receiver))
                .ok()
                .map(|_| sender)
        })
        .as_ref()?;
    let (response, rows) = std::sync::mpsc::sync_channel(1);
    sender
        .try_send(FullListenerRequest { deadline, response })
        .ok()?;
    receive_worker_response_until(&rows, deadline, should_cancel)
}

#[cfg(unix)]
fn run_full_listener_batches(receiver: std::sync::mpsc::Receiver<FullListenerRequest>) {
    while let Ok(first) = receiver.recv() {
        process_full_listener_batch(first, &receiver, list_listening_ports_unix_query_until);
    }
}

#[cfg(unix)]
fn list_listening_ports_unix_query_until(deadline: std::time::Instant) -> Vec<ListeningPort> {
    #[cfg(target_os = "linux")]
    let mut rows = list_listening_ports_linux();
    #[cfg(target_os = "macos")]
    let mut rows = list_listening_ports_macos_until(deadline);
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    let mut rows = list_listening_ports_lsof_until(deadline);

    if std::time::Instant::now() >= deadline {
        return Vec::new();
    }
    enrich_listening_port_projects(&mut rows);
    sort_listening_ports(&mut rows);
    rows
}

#[cfg(unix)]
fn process_full_listener_batch(
    first: FullListenerRequest,
    receiver: &std::sync::mpsc::Receiver<FullListenerRequest>,
    query: impl FnOnce(std::time::Instant) -> Vec<ListeningPort>,
) {
    let mut requests = Vec::with_capacity(8);
    requests.push(first);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(4);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(request) => requests.push(request),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    requests.retain(|request| std::time::Instant::now() < request.deadline);
    if requests.is_empty() {
        return;
    }

    let query_deadline = requests
        .iter()
        .map(|request| request.deadline)
        .min()
        .unwrap_or_else(std::time::Instant::now);
    let rows = query(query_deadline);
    for request in requests {
        if std::time::Instant::now() >= request.deadline {
            continue;
        }
        let _ = request.response.send(rows.clone());
    }
}

#[cfg(all(unix, test))]
fn list_listening_ports_unix_for_pids(pids: &HashSet<u32>) -> Vec<ListeningPort> {
    let mut never_cancel = || false;
    list_listening_ports_unix_for_pids_until(
        pids,
        std::time::Instant::now() + std::time::Duration::from_millis(2_100),
        &mut never_cancel,
    )
    .unwrap_or_else(|| {
        query_listening_ports_unix_for_pids(
            pids,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
    })
}

#[cfg(unix)]
fn list_listening_ports_unix_for_pids_until(
    pids: &HashSet<u32>,
    deadline: std::time::Instant,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Option<Vec<ListeningPort>> {
    static SENDER: std::sync::OnceLock<Option<std::sync::mpsc::SyncSender<PidListenerRequest>>> =
        std::sync::OnceLock::new();
    let sender = SENDER
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(DISCOVERY_WORKER_QUEUE_CAPACITY);
            std::thread::Builder::new()
                .name("lpm-pid-listeners".to_string())
                .spawn(move || run_pid_listener_batches(receiver))
                .ok()
                .map(|_| sender)
        })
        .as_ref()?;
    let (response, rows) = std::sync::mpsc::sync_channel(1);
    if sender
        .try_send(PidListenerRequest {
            pids: pids.clone(),
            deadline,
            response,
        })
        .is_err()
    {
        return None;
    }
    receive_worker_response_until(&rows, deadline, should_cancel)
}

#[cfg(unix)]
fn run_pid_listener_batches(receiver: std::sync::mpsc::Receiver<PidListenerRequest>) {
    while let Ok(first) = receiver.recv() {
        process_pid_listener_batch(first, &receiver, query_listening_ports_unix_for_pids);
    }
}

#[cfg(unix)]
fn process_pid_listener_batch(
    first: PidListenerRequest,
    receiver: &std::sync::mpsc::Receiver<PidListenerRequest>,
    query: impl FnOnce(&HashSet<u32>, std::time::Instant) -> Vec<ListeningPort>,
) {
    let mut requests = Vec::with_capacity(8);
    requests.push(first);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(4);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(request) => requests.push(request),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    requests.retain(|request| std::time::Instant::now() < request.deadline);
    if requests.is_empty() {
        return;
    }

    let expected_pids = requests.iter().map(|request| request.pids.len()).sum();
    let mut pids = HashSet::with_capacity(expected_pids);
    for request in &requests {
        pids.extend(request.pids.iter().copied());
    }
    let query_deadline = requests
        .iter()
        .map(|request| request.deadline)
        .min()
        .unwrap_or_else(std::time::Instant::now);
    let rows = query(&pids, query_deadline);
    for request in requests {
        if std::time::Instant::now() >= request.deadline {
            continue;
        }
        let matching = rows
            .iter()
            .filter(|row| row.pid.is_some_and(|pid| request.pids.contains(&pid)))
            .cloned()
            .collect();
        let _ = request.response.send(matching);
    }
}

#[cfg(unix)]
fn query_listening_ports_unix_for_pids(
    pids: &HashSet<u32>,
    deadline: std::time::Instant,
) -> Vec<ListeningPort> {
    #[cfg(target_os = "linux")]
    {
        let _ = deadline;
        list_listening_ports_linux_for_pids(pids)
    }
    #[cfg(not(target_os = "linux"))]
    {
        query_listening_ports_lsof_for_pids(pids, deadline)
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn query_listening_ports_lsof_for_pids(
    pids: &HashSet<u32>,
    deadline: std::time::Instant,
) -> Vec<ListeningPort> {
    let mut pids: Vec<u32> = pids.iter().copied().collect();
    pids.sort_unstable();

    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    for chunk in pids.chunks(100) {
        let pid_list = join_pids(chunk);
        let mut command = Command::new("lsof");
        command.args([
            "-nP",
            "-a",
            "-p",
            &pid_list,
            "-iTCP",
            "-sTCP:LISTEN",
            "-F",
            "pcPtn",
        ]);
        let Some(output) = command_stdout_capped_until(&mut command, deadline) else {
            continue;
        };
        if output.is_empty() {
            continue;
        }

        let stdout = String::from_utf8_lossy(&output);
        for row in parse_lsof_listen_output(&stdout) {
            if seen.insert(row.socket_identity()) {
                rows.push(row);
            }
        }
    }
    rows
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parse_lsof_listen_output(output: &str) -> Vec<ListeningPort> {
    let mut rows = Vec::new();
    let mut seen = HashSet::<ListeningSocketIdentity>::new();
    let mut current_pid = None;
    let mut current_process = None::<String>;
    let mut current_address_family = None;

    for line in output.lines() {
        let Some((tag, value)) = line.split_at_checked(1) else {
            continue;
        };
        match tag {
            "p" => {
                current_pid = value.parse::<u32>().ok();
                current_process = None;
                current_address_family = None;
            }
            "c" => {
                if !value.is_empty() {
                    current_process = Some(value.to_string());
                }
            }
            "t" => {
                current_address_family = match value {
                    "IPv4" => Some(ListeningAddressFamily::Ipv4),
                    "IPv6" => Some(ListeningAddressFamily::Ipv6),
                    _ => None,
                };
            }
            "n" => {
                let Some((address, port)) = parse_lsof_tcp_name(value) else {
                    continue;
                };
                let address_family = current_address_family.or_else(|| {
                    address
                        .as_deref()
                        .and_then(listening_address_family_from_str)
                });
                if !seen.insert(ListeningSocketIdentity::new(
                    port,
                    current_pid,
                    address_family,
                    address.clone(),
                )) {
                    continue;
                }
                rows.push(ListeningPort {
                    port,
                    address,
                    address_family,
                    pid: current_pid,
                    process: current_process.clone(),
                    command: None,
                    cwd: None,
                    project_dir: None,
                    project: None,
                    framework: None,
                    uptime: None,
                });
            }
            _ => {}
        }
    }

    rows
}

fn listening_address_family_from_str(address: &str) -> Option<ListeningAddressFamily> {
    match address.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(_) => Some(ListeningAddressFamily::Ipv4),
        std::net::IpAddr::V6(_) => Some(ListeningAddressFamily::Ipv6),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parse_lsof_tcp_name(value: &str) -> Option<(Option<String>, u16)> {
    let endpoint = value
        .strip_prefix("TCP ")
        .unwrap_or(value)
        .split(" (")
        .next()
        .unwrap_or(value)
        .trim();
    if endpoint.contains("->") {
        return None;
    }

    let (address, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let address = address.trim().trim_start_matches('[').trim_end_matches(']');
    let address = if address.is_empty() || address == "*" {
        None
    } else {
        Some(address.to_string())
    };
    Some((address, port))
}

#[cfg(target_os = "macos")]
fn collect_cwds_until(
    pids: &[u32],
    deadline: std::time::Instant,
    complete_after_deadline: bool,
) -> HashMap<u32, PathBuf> {
    let mut result = HashMap::with_capacity(pids.len());
    for &pid in pids {
        if !complete_after_deadline && std::time::Instant::now() >= deadline {
            break;
        }
        if let Some(cwd) = macos_process_cwd(pid) {
            result.insert(pid, cwd);
        }
    }
    result
}

#[cfg(target_os = "macos")]
fn macos_process_cwd(pid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;

    let pid = libc::c_int::try_from(pid).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_vnodepathinfo>::uninit();
    let expected = libc::c_int::try_from(std::mem::size_of::<libc::proc_vnodepathinfo>()).ok()?;
    // SAFETY: `info` points to an allocation of exactly `expected` bytes and
    // `proc_pidinfo` initializes it only when it reports that full size.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            expected,
        )
    };
    if written != expected {
        return None;
    }
    // SAFETY: the successful call above initialized the complete structure.
    let info = unsafe { info.assume_init() };
    // SAFETY: the byte slice is bounded by the fixed-size kernel structure and
    // has the same lifetime as `info`; it is scanned for NUL before use.
    let path = unsafe {
        std::slice::from_raw_parts(
            info.pvi_cdir.vip_path.as_ptr().cast::<u8>(),
            std::mem::size_of_val(&info.pvi_cdir.vip_path),
        )
    };
    let path = path.get(..path.iter().position(|byte| *byte == 0)?)?;
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(path)))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn collect_cwds_until(
    pids: &[u32],
    deadline: std::time::Instant,
    _complete_after_deadline: bool,
) -> HashMap<u32, PathBuf> {
    let mut result = HashMap::with_capacity(pids.len());
    for chunk in pids.chunks(100) {
        let pid_list = join_pids(chunk);
        let mut command = Command::new("lsof");
        command.args(["-a", "-d", "cwd", "-F", "pn", "-p", &pid_list]);
        let Some(output) = command_stdout_capped_until(&mut command, deadline) else {
            continue;
        };
        if output.is_empty() {
            continue;
        }

        let stdout = String::from_utf8_lossy(&output);
        let mut current_pid = None;
        for line in stdout.lines() {
            let Some((tag, value)) = line.split_at_checked(1) else {
                continue;
            };
            match tag {
                "p" => current_pid = value.parse::<u32>().ok(),
                "n" => {
                    if let Some(pid) = current_pid
                        && !value.is_empty()
                    {
                        result.insert(pid, PathBuf::from(value));
                    }
                }
                _ => {}
            }
        }
    }
    result
}

#[cfg(all(unix, not(target_os = "linux")))]
fn collect_ps_info_until(pids: &[u32], deadline: std::time::Instant) -> HashMap<u32, PsInfo> {
    let mut result = HashMap::with_capacity(pids.len());
    for chunk in pids.chunks(200) {
        let pid_list = join_pids(chunk);
        let mut command = Command::new("ps");
        command.args([
            "-p", &pid_list, "-o", "pid=", "-o", "comm=", "-o", "etime=", "-o", "command=",
        ]);
        let Some(output) = command_stdout_capped_until(&mut command, deadline) else {
            continue;
        };
        if output.is_empty() {
            continue;
        }

        let stdout = String::from_utf8_lossy(&output);
        for line in stdout.lines() {
            if let Some((pid, info)) = parse_ps_line(line) {
                result.insert(pid, info);
            }
        }
    }
    result
}

#[cfg(all(unix, not(target_os = "linux")))]
fn join_pids(pids: &[u32]) -> String {
    let mut joined = String::with_capacity(pids.len().saturating_mul(6));
    for (idx, pid) in pids.iter().enumerate() {
        if idx > 0 {
            joined.push(',');
        }
        joined.push_str(&pid.to_string());
    }
    joined
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parse_ps_line(line: &str) -> Option<(u32, PsInfo)> {
    let (pid_raw, rest) = take_token(line.trim_start())?;
    let (process_raw, rest) = take_token(rest.trim_start())?;
    let (uptime_raw, rest) = take_token(rest.trim_start())?;
    let command = rest.trim_start();
    let pid = pid_raw.parse::<u32>().ok()?;
    Some((
        pid,
        PsInfo {
            process: Some(process_raw.to_string()),
            command: (!command.is_empty()).then(|| command.to_string()),
            uptime: Some(uptime_raw.to_string()),
        },
    ))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn take_token(input: &str) -> Option<(&str, &str)> {
    if input.is_empty() {
        return None;
    }
    let idx = input
        .char_indices()
        .find_map(|(idx, ch)| ch.is_whitespace().then_some(idx))
        .unwrap_or(input.len());
    Some((&input[..idx], &input[idx..]))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct ProcTcpEntry {
    port: u16,
    address: Option<String>,
    address_family: ListeningAddressFamily,
    inode: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct LinuxTimebase {
    uptime_secs: Option<f64>,
    ticks_per_second: Option<f64>,
}

#[cfg(target_os = "linux")]
fn list_listening_ports_linux() -> Vec<ListeningPort> {
    let by_inode = linux_listening_socket_index();
    if by_inode.is_empty() {
        return Vec::new();
    }

    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        let matched_inodes = HashSet::new();
        let mut seen = HashSet::new();
        return unmatched_linux_sockets(&by_inode, &matched_inodes, &mut seen);
    };

    let timebase = LinuxTimebase {
        uptime_secs: linux_system_uptime_secs(),
        ticks_per_second: linux_ticks_per_second(),
    };
    let mut rows = Vec::with_capacity(by_inode.len());
    let mut seen = HashSet::<ListeningSocketIdentity>::with_capacity(by_inode.len());
    let mut matched_inodes: HashSet<u64> = HashSet::with_capacity(by_inode.len());

    for entry in proc_entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };

        append_linux_listeners_for_pid(
            pid,
            &entry.path(),
            &by_inode,
            &mut matched_inodes,
            &mut seen,
            &mut rows,
            timebase,
        );
    }

    rows.extend(unmatched_linux_sockets(
        &by_inode,
        &matched_inodes,
        &mut seen,
    ));
    rows
}

#[cfg(target_os = "linux")]
fn list_listening_ports_linux_for_pids(pids: &HashSet<u32>) -> Vec<ListeningPort> {
    let by_inode = linux_listening_socket_index();
    if by_inode.is_empty() {
        return Vec::new();
    }
    let timebase = LinuxTimebase {
        uptime_secs: linux_system_uptime_secs(),
        ticks_per_second: linux_ticks_per_second(),
    };
    let mut rows = Vec::with_capacity(pids.len());
    let mut seen = HashSet::<ListeningSocketIdentity>::with_capacity(pids.len());
    let mut matched_inodes = HashSet::with_capacity(pids.len());
    for &pid in pids {
        let pid_raw = pid.to_string();
        let mut proc_dir = PathBuf::with_capacity(6 + pid_raw.len());
        proc_dir.push("/proc");
        proc_dir.push(pid_raw);
        append_linux_listeners_for_pid(
            pid,
            &proc_dir,
            &by_inode,
            &mut matched_inodes,
            &mut seen,
            &mut rows,
            timebase,
        );
    }
    rows
}

#[cfg(target_os = "linux")]
fn linux_listening_socket_index() -> HashMap<u64, Vec<ProcTcpEntry>> {
    let mut sockets = parse_proc_net_tcp_file("/proc/net/tcp", false);
    sockets.extend(parse_proc_net_tcp_file("/proc/net/tcp6", true));
    let mut by_inode: HashMap<u64, Vec<ProcTcpEntry>> = HashMap::with_capacity(sockets.len());
    for socket in sockets {
        by_inode.entry(socket.inode).or_default().push(socket);
    }
    by_inode
}

#[cfg(target_os = "linux")]
fn append_linux_listeners_for_pid(
    pid: u32,
    proc_dir: &Path,
    by_inode: &HashMap<u64, Vec<ProcTcpEntry>>,
    matched_inodes: &mut HashSet<u64>,
    seen: &mut HashSet<ListeningSocketIdentity>,
    rows: &mut Vec<ListeningPort>,
    timebase: LinuxTimebase,
) {
    let matches = linux_socket_matches_for_pid(proc_dir, by_inode, matched_inodes);
    if matches.is_empty() {
        return;
    }
    let info = read_linux_process_info(pid, timebase);
    for socket in matches {
        if !seen.insert(ListeningSocketIdentity::new(
            socket.port,
            Some(pid),
            Some(socket.address_family),
            socket.address.clone(),
        )) {
            continue;
        }
        rows.push(ListeningPort {
            port: socket.port,
            address: socket.address,
            address_family: Some(socket.address_family),
            pid: Some(pid),
            process: info.process.clone(),
            command: info.command.clone(),
            cwd: info.cwd.clone(),
            project_dir: None,
            project: None,
            framework: None,
            uptime: info.uptime.clone(),
        });
    }
}

#[cfg(target_os = "linux")]
fn unmatched_linux_sockets(
    by_inode: &HashMap<u64, Vec<ProcTcpEntry>>,
    matched_inodes: &HashSet<u64>,
    seen: &mut HashSet<ListeningSocketIdentity>,
) -> Vec<ListeningPort> {
    let mut rows = Vec::new();
    for (inode, sockets) in by_inode {
        if matched_inodes.contains(inode) {
            continue;
        }
        for socket in sockets {
            if !seen.insert(ListeningSocketIdentity::new(
                socket.port,
                None,
                Some(socket.address_family),
                socket.address.clone(),
            )) {
                continue;
            }
            rows.push(ListeningPort {
                port: socket.port,
                address: socket.address.clone(),
                address_family: Some(socket.address_family),
                pid: None,
                process: None,
                command: None,
                cwd: None,
                project_dir: None,
                project: None,
                framework: None,
                uptime: None,
            });
        }
    }
    rows
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp_file(path: &str, ipv6: bool) -> Vec<ProcTcpEntry> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for line in content.lines() {
        if let Some(entry) = parse_proc_net_tcp_line(line, ipv6) {
            rows.push(entry);
        }
    }
    rows
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp_line(line: &str, ipv6: bool) -> Option<ProcTcpEntry> {
    let mut fields = line.split_whitespace();
    let slot = fields.next()?;
    if slot == "sl" {
        return None;
    }

    let local = fields.next()?;
    let _remote = fields.next()?;
    let state = fields.next()?;
    if state != "0A" {
        return None;
    }

    for _ in 0..5 {
        fields.next()?;
    }
    let inode = fields.next()?.parse::<u64>().ok()?;
    if inode == 0 {
        return None;
    }

    let (address_raw, port_raw) = local.split_once(':')?;
    let port = u16::from_str_radix(port_raw, 16).ok()?;
    let address = if ipv6 {
        parse_proc_ipv6_address(address_raw)
    } else {
        parse_proc_ipv4_address(address_raw)
    }?;

    Some(ProcTcpEntry {
        port,
        address,
        address_family: if ipv6 {
            ListeningAddressFamily::Ipv6
        } else {
            ListeningAddressFamily::Ipv4
        },
        inode,
    })
}

#[cfg(target_os = "linux")]
fn parse_proc_ipv4_address(raw: &str) -> Option<Option<String>> {
    let address = u32::from_str_radix(raw, 16).ok()?;
    let address = std::net::Ipv4Addr::from(address.to_le_bytes());
    Some((!address.is_unspecified()).then(|| address.to_string()))
}

#[cfg(target_os = "linux")]
fn parse_proc_ipv6_address(raw: &str) -> Option<Option<String>> {
    if raw.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for idx in 0..4 {
        let start = idx * 8;
        let word = u32::from_str_radix(&raw[start..start + 8], 16).ok()?;
        let byte_start = idx * 4;
        bytes[byte_start..byte_start + 4].copy_from_slice(&word.to_le_bytes());
    }
    let address = std::net::Ipv6Addr::from(bytes);
    Some((!address.is_unspecified()).then(|| address.to_string()))
}

#[cfg(target_os = "linux")]
fn linux_socket_matches_for_pid(
    proc_pid_dir: &Path,
    by_inode: &HashMap<u64, Vec<ProcTcpEntry>>,
    matched_inodes: &mut HashSet<u64>,
) -> Vec<ProcTcpEntry> {
    let Ok(fd_entries) = std::fs::read_dir(proc_pid_dir.join("fd")) else {
        return Vec::new();
    };

    let mut matches = Vec::new();
    for fd_entry in fd_entries.flatten() {
        let Ok(target) = std::fs::read_link(fd_entry.path()) else {
            continue;
        };
        let Some(inode) = socket_inode_from_link(&target) else {
            continue;
        };
        let Some(sockets) = by_inode.get(&inode) else {
            continue;
        };
        matched_inodes.insert(inode);
        matches.extend(sockets.iter().cloned());
    }
    matches
}

#[cfg(target_os = "linux")]
fn socket_inode_from_link(target: &Path) -> Option<u64> {
    let target = target.to_string_lossy();
    target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|inode| inode.parse::<u64>().ok())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default)]
struct LinuxProcessInfo {
    process: Option<String>,
    command: Option<String>,
    cwd: Option<PathBuf>,
    uptime: Option<String>,
}

#[cfg(target_os = "linux")]
fn read_linux_process_info(pid: u32, timebase: LinuxTimebase) -> LinuxProcessInfo {
    let pid_raw = pid.to_string();
    let mut proc_dir = PathBuf::with_capacity(6 + pid_raw.len());
    proc_dir.push("/proc");
    proc_dir.push(pid_raw);

    let process = std::fs::read_to_string(proc_dir.join("comm"))
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());
    let command = std::fs::read(proc_dir.join("cmdline"))
        .ok()
        .and_then(|bytes| parse_proc_cmdline(&bytes));
    let cwd = std::fs::read_link(proc_dir.join("cwd")).ok();
    let uptime = read_linux_process_uptime(&proc_dir, timebase);

    LinuxProcessInfo {
        process,
        command,
        cwd,
        uptime,
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_cmdline(bytes: &[u8]) -> Option<String> {
    let mut command = String::with_capacity(bytes.len());
    for arg in bytes.split(|byte| *byte == 0).filter(|arg| !arg.is_empty()) {
        if !command.is_empty() {
            command.push(' ');
        }
        command.push_str(&String::from_utf8_lossy(arg));
    }
    (!command.is_empty()).then_some(command)
}

#[cfg(target_os = "linux")]
fn read_linux_process_uptime(proc_dir: &Path, timebase: LinuxTimebase) -> Option<String> {
    let uptime_secs = timebase.uptime_secs?;
    let ticks_per_second = timebase.ticks_per_second?;
    let stat = std::fs::read_to_string(proc_dir.join("stat")).ok()?;
    let start_ticks = parse_proc_stat_start_ticks(&stat)?;
    let start_secs = start_ticks as f64 / ticks_per_second;
    let elapsed = uptime_secs - start_secs;
    if !elapsed.is_finite() || elapsed < 0.0 {
        return None;
    }
    Some(format_elapsed_secs(elapsed as u64))
}

#[cfg(target_os = "linux")]
fn parse_proc_stat_start_ticks(stat: &str) -> Option<u64> {
    parse_proc_stat_parent_and_start_ticks(stat).map(|(_, start_ticks)| start_ticks)
}

#[cfg(target_os = "linux")]
fn parse_proc_stat_parent_and_start_ticks(stat: &str) -> Option<(u32, u64)> {
    let mut fields = stat.rsplit_once(") ")?.1.split_whitespace();
    let _state = fields.next()?;
    let parent = fields.next()?.parse::<u32>().ok()?;
    let start_ticks = fields.nth(17)?.parse::<u64>().ok()?;
    Some((parent, start_ticks))
}

#[cfg(target_os = "linux")]
fn linux_system_uptime_secs() -> Option<f64> {
    let content = std::fs::read_to_string("/proc/uptime").ok()?;
    content.split_whitespace().next()?.parse::<f64>().ok()
}

#[cfg(target_os = "linux")]
fn linux_ticks_per_second() -> Option<f64> {
    // SAFETY: `sysconf(_SC_CLK_TCK)` has no pointer arguments and reports the
    // kernel clock-tick constant for this process.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (ticks > 0).then_some(ticks as f64)
}

#[cfg(windows)]
#[derive(Debug, Clone, Default)]
struct WindowsProcessInfo {
    process: Option<String>,
    command: Option<String>,
    uptime: Option<String>,
    identity: Option<WindowsProcessIdentity>,
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct WindowsTcpEntry {
    port: u16,
    address: Option<String>,
    address_family: ListeningAddressFamily,
    pid: u32,
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct WindowsPortOwnerSnapshot {
    pid: u32,
    process: Option<String>,
    identity: WindowsProcessIdentity,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsProcessIdentity {
    pid: u32,
    creation_ticks: Option<u64>,
}

#[cfg(windows)]
fn list_listening_ports_windows() -> Vec<ListeningPort> {
    let mut sockets = windows_tcp4_listeners();
    sockets.extend(windows_tcp6_listeners());
    if sockets.is_empty() {
        return Vec::new();
    }

    let mut rows = Vec::with_capacity(sockets.len());
    let mut seen = HashSet::<ListeningSocketIdentity>::with_capacity(sockets.len());
    let mut process_cache: HashMap<u32, WindowsProcessInfo> = HashMap::new();

    for socket in sockets {
        if !seen.insert(ListeningSocketIdentity::new(
            socket.port,
            Some(socket.pid),
            Some(socket.address_family),
            socket.address.clone(),
        )) {
            continue;
        }
        let info = process_cache
            .entry(socket.pid)
            .or_insert_with(|| read_windows_process_info(socket.pid));
        rows.push(ListeningPort {
            port: socket.port,
            address: socket.address,
            address_family: Some(socket.address_family),
            pid: Some(socket.pid),
            process: info.process.clone(),
            command: info.command.clone(),
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: info.uptime.clone(),
        });
    }

    rows
}

#[cfg(windows)]
fn windows_tcp4_listeners() -> Vec<WindowsTcpEntry> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP_STATE_LISTEN, MIB_TCPROW_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let buffer = windows_tcp_table_buffer(AF_INET as u32);
    let mut rows = Vec::new();
    for row in windows_table_rows::<MIB_TCPROW_OWNER_PID>(&buffer) {
        if row.dwState != MIB_TCP_STATE_LISTEN as u32 {
            continue;
        }
        rows.push(WindowsTcpEntry {
            port: windows_port_from_mib(row.dwLocalPort),
            address: windows_ipv4_address_from_mib(row.dwLocalAddr),
            address_family: ListeningAddressFamily::Ipv4,
            pid: row.dwOwningPid,
        });
    }
    rows
}

#[cfg(windows)]
fn windows_tcp6_listeners() -> Vec<WindowsTcpEntry> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    let buffer = windows_tcp_table_buffer(AF_INET6 as u32);
    let mut rows = Vec::new();
    for row in windows_table_rows::<MIB_TCP6ROW_OWNER_PID>(&buffer) {
        if row.dwState != MIB_TCP_STATE_LISTEN as u32 {
            continue;
        }
        rows.push(WindowsTcpEntry {
            port: windows_port_from_mib(row.dwLocalPort),
            address: windows_ipv6_address_from_mib(row.ucLocalAddr),
            address_family: ListeningAddressFamily::Ipv6,
            pid: row.dwOwningPid,
        });
    }
    rows
}

#[cfg(windows)]
fn windows_tcp_table_buffer(address_family: u32) -> Vec<u8> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER,
    };

    let mut size = 0u32;
    // SAFETY: the initial call intentionally passes a null buffer so Windows
    // fills `size` with the required byte count for the selected table.
    let mut status = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            address_family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if size == 0 && status != NO_ERROR {
        return Vec::new();
    }

    for _ in 0..3 {
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` is writable storage of the advertised byte length,
        // and `size` is passed as an in/out byte-count pointer per IP Helper.
        status = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast(),
                &mut size,
                0,
                address_family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status == NO_ERROR {
            return buffer;
        }
        if status != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return Vec::new();
        }
    }

    Vec::new()
}

#[cfg(windows)]
fn windows_table_rows<T: Copy>(buffer: &[u8]) -> Vec<T> {
    let header_size = std::mem::size_of::<u32>();
    if buffer.len() < header_size {
        return Vec::new();
    }

    let count = u32::from_ne_bytes(buffer[..header_size].try_into().unwrap()) as usize;
    let row_size = std::mem::size_of::<T>();
    let Some(bytes_len) = count.checked_mul(row_size) else {
        return Vec::new();
    };
    let Some(required_len) = header_size.checked_add(bytes_len) else {
        return Vec::new();
    };
    if buffer.len() < required_len {
        return Vec::new();
    }

    let mut rows = Vec::with_capacity(count);
    for idx in 0..count {
        let offset = header_size + idx * row_size;
        // SAFETY: bounds were checked above for every row; unaligned reads are
        // used because Windows table rows are packed in an arbitrary byte buffer.
        let row = unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<T>()) };
        rows.push(row);
    }
    rows
}

#[cfg(windows)]
fn windows_port_from_mib(port: u32) -> u16 {
    u16::from_be(port as u16)
}

#[cfg(windows)]
fn windows_ipv4_address_from_mib(address: u32) -> Option<String> {
    let address = std::net::Ipv4Addr::from(address.to_ne_bytes());
    (!address.is_unspecified()).then(|| address.to_string())
}

#[cfg(windows)]
fn windows_ipv6_address_from_mib(address: [u8; 16]) -> Option<String> {
    let address = std::net::Ipv6Addr::from(address);
    (!address.is_unspecified()).then(|| address.to_string())
}

#[cfg(windows)]
fn read_windows_process_info(pid: u32) -> WindowsProcessInfo {
    let Some(handle) = open_windows_process(
        windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
        pid,
    ) else {
        return WindowsProcessInfo::default();
    };

    let command = query_windows_process_image_path(handle.raw());
    let process = command
        .as_deref()
        .and_then(windows_file_name_from_path)
        .map(str::to_string);
    let creation_ticks = windows_process_creation_ticks(handle.raw());
    let uptime = creation_ticks.and_then(windows_process_uptime_from_creation_ticks);
    let identity = Some(WindowsProcessIdentity {
        pid,
        creation_ticks,
    });

    WindowsProcessInfo {
        process,
        command,
        uptime,
        identity,
    }
}

#[cfg(windows)]
fn find_windows_port_owner(port: u16) -> Option<WindowsPortOwnerSnapshot> {
    let mut sockets = windows_tcp4_listeners();
    sockets.extend(windows_tcp6_listeners());
    let socket = sockets.into_iter().find(|socket| socket.port == port)?;
    let info = read_windows_process_info(socket.pid);
    Some(WindowsPortOwnerSnapshot {
        pid: socket.pid,
        process: info.process,
        identity: info.identity.unwrap_or(WindowsProcessIdentity {
            pid: socket.pid,
            creation_ticks: None,
        }),
    })
}

#[cfg(windows)]
fn kill_port_owner_windows(port: u16) -> Result<(), String> {
    let Some(owner) = find_windows_port_owner(port) else {
        return Err(format!("no process found using port {port}"));
    };
    if protected_pid(owner.pid) {
        return Err(format!(
            "refusing to kill protected PID {} on port {port}",
            owner.pid
        ));
    }
    if owner.pid == std::process::id() {
        return Err(format!(
            "refusing to kill current lpm process PID {} on port {port}",
            owner.pid
        ));
    }
    if owner.identity.creation_ticks.is_none() {
        return Err(format!(
            "could not capture a stable identity for PID {} on port {port}; aborting kill for safety",
            owner.pid
        ));
    }

    std::thread::sleep(std::time::Duration::from_millis(50));
    let Some(rechecked) = find_windows_port_owner(port) else {
        return Err(format!(
            "port {port} owner changed (was PID {}, now None) - aborting kill for safety",
            owner.pid
        ));
    };
    if !windows_same_process(rechecked.identity, owner.identity) {
        return Err(format!(
            "port {port} owner changed (was PID {}, now PID {}) - aborting kill for safety",
            owner.pid, rechecked.pid
        ));
    }

    let proc_name = owner.process.as_deref().unwrap_or("unknown");
    tracing::debug!("killing PID {} ({proc_name}) on port {port}", owner.pid);
    terminate_windows_pid(owner.pid, Some(owner.identity))
        .map_err(|err| format!("failed to kill PID {} ({proc_name}): {err}", owner.pid))
}

#[cfg(windows)]
fn windows_process_identity_for_pid(pid: u32) -> Option<WindowsProcessIdentity> {
    let handle = open_windows_process(
        windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
        pid,
    )?;
    Some(windows_process_identity_from_handle(pid, handle.raw()))
}

#[cfg(windows)]
fn windows_process_identity_from_handle(
    pid: u32,
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> WindowsProcessIdentity {
    WindowsProcessIdentity {
        pid,
        creation_ticks: windows_process_creation_ticks(handle),
    }
}

#[cfg(any(windows, test))]
fn windows_same_process(current: WindowsProcessIdentity, expected: WindowsProcessIdentity) -> bool {
    if current.pid != expected.pid {
        return false;
    }
    matches!(
        (current.creation_ticks, expected.creation_ticks),
        (Some(current), Some(expected)) if current == expected
    )
}

#[cfg(windows)]
fn terminate_windows_pid(
    pid: u32,
    expected_identity: Option<WindowsProcessIdentity>,
) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };

    let expected_identity = expected_identity
        .filter(|identity| identity.creation_ticks.is_some())
        .ok_or_else(|| {
            format!("could not capture a stable identity for PID {pid}; aborting kill for safety")
        })?;
    let handle =
        try_open_windows_process(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, pid)
            .map_err(|err| err.to_string())?;
    let current = windows_process_identity_from_handle(pid, handle.raw());
    if !windows_same_process(current, expected_identity) {
        return Err(format!(
            "PID {pid} identity changed before termination; aborting kill for safety"
        ));
    }
    // SAFETY: `handle` is opened with PROCESS_TERMINATE for the re-checked PID;
    // Windows reports failure through the return code.
    if unsafe { TerminateProcess(handle.raw(), 1) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl WindowsHandle {
    fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        // SAFETY: `WindowsHandle` is only constructed from non-null owned
        // process handles returned by OpenProcess.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn open_windows_process(access: u32, pid: u32) -> Option<WindowsHandle> {
    try_open_windows_process(access, pid).ok()
}

#[cfg(windows)]
fn try_open_windows_process(access: u32, pid: u32) -> Result<WindowsHandle, std::io::Error> {
    // SAFETY: `OpenProcess` validates the PID/access mask and returns null on
    // failure; the resulting owned handle is wrapped for Drop.
    let handle = unsafe { windows_sys::Win32::System::Threading::OpenProcess(access, 0, pid) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(WindowsHandle(handle))
}

#[cfg(windows)]
fn query_windows_process_image_path(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Option<String> {
    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    // SAFETY: `buffer` is valid writable UTF-16 storage and `len` starts as
    // the buffer capacity in WCHARs, as required by QueryFullProcessImageNameW.
    let ok = unsafe {
        windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
            handle,
            0,
            buffer.as_mut_ptr(),
            &mut len,
        )
    };
    if ok == 0 || len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..len as usize]))
}

#[cfg(windows)]
fn windows_file_name_from_path(path: &str) -> Option<&str> {
    path.rsplit(|ch| ch == '\\' || ch == '/')
        .next()
        .filter(|name| !name.is_empty())
}

#[cfg(windows)]
fn windows_process_creation_ticks(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<u64> {
    let creation = windows_process_creation_time(handle)?;
    Some(filetime_ticks(creation))
}

#[cfg(windows)]
fn windows_process_creation_time(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Option<windows_sys::Win32::Foundation::FILETIME> {
    use windows_sys::Win32::Foundation::FILETIME;

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all FILETIME pointers are valid writable out parameters for the
    // opened process handle; Windows reports failure through the return code.
    let ok = unsafe {
        windows_sys::Win32::System::Threading::GetProcessTimes(
            handle,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return None;
    }
    Some(creation)
}

#[cfg(windows)]
fn windows_process_uptime_from_creation_ticks(creation_ticks: u64) -> Option<String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let creation_secs = windows_ticks_to_unix_secs(creation_ticks)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format_elapsed_secs(now.saturating_sub(creation_secs)))
}

#[cfg(all(windows, test))]
fn filetime_to_unix_secs(filetime: windows_sys::Win32::Foundation::FILETIME) -> Option<u64> {
    windows_ticks_to_unix_secs(filetime_ticks(filetime))
}

#[cfg(windows)]
fn filetime_ticks(filetime: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime)
}

#[cfg(windows)]
fn windows_ticks_to_unix_secs(ticks: u64) -> Option<u64> {
    const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
    const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;

    let secs = ticks / WINDOWS_TICKS_PER_SECOND;
    secs.checked_sub(WINDOWS_TO_UNIX_EPOCH_SECONDS)
}

#[cfg(unix)]
fn enrich_listening_port_projects(rows: &mut [ListeningPort]) {
    let mut project_cache: HashMap<PathBuf, Option<ProjectInfo>> =
        HashMap::with_capacity(rows.len());
    for row in rows {
        let Some(cwd) = row.cwd.as_deref() else {
            continue;
        };
        if let Some(project) = project_for_cwd(cwd, &mut project_cache) {
            row.project_dir = Some(project.dir.clone());
            row.project = Some(project.name.clone());
            row.framework.clone_from(&project.framework);
        }
    }
}

#[cfg(unix)]
fn project_for_cwd(
    cwd: &Path,
    cache: &mut HashMap<PathBuf, Option<ProjectInfo>>,
) -> Option<ProjectInfo> {
    project_for_cwd_with_discover(cwd, cache, discover_project_for_cwd)
}

#[cfg(unix)]
fn project_for_cwd_with_discover(
    cwd: &Path,
    cache: &mut HashMap<PathBuf, Option<ProjectInfo>>,
    discover: impl FnOnce(&Path) -> Option<ProjectInfo>,
) -> Option<ProjectInfo> {
    if let Some(cached) = cache.get(cwd) {
        return cached.clone();
    }

    let discovered = discover(cwd);
    cache.insert(cwd.to_path_buf(), discovered.clone());
    discovered
}

#[cfg(unix)]
fn discover_project_for_cwd(cwd: &Path) -> Option<ProjectInfo> {
    let mut cursor = Some(cwd);
    while let Some(dir) = cursor {
        if dir.join("package.json").exists()
            || dir.join("lpm.json").exists()
            || dir.join(".git").exists()
        {
            let name = read_package_name(dir).unwrap_or_else(|| {
                dir.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("project")
                    .to_string()
            });
            let framework = framework_label(&lpm_cert::framework::detect_framework(dir));
            return Some(ProjectInfo {
                dir: dir.to_path_buf(),
                name,
                framework,
            });
        }
        cursor = dir.parent();
    }
    None
}

#[cfg(unix)]
fn read_package_name(dir: &Path) -> Option<String> {
    let content = lpm_common::read_text_file_capped(
        &dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&content).ok()?;
    value
        .get("name")
        .and_then(|name| name.as_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

#[cfg(unix)]
fn framework_label(framework: &lpm_cert::framework::Framework) -> Option<String> {
    match framework {
        lpm_cert::framework::Framework::NextJs => Some("Next.js".to_string()),
        lpm_cert::framework::Framework::Vite => Some("Vite".to_string()),
        lpm_cert::framework::Framework::CreateReactApp => Some("Create React App".to_string()),
        lpm_cert::framework::Framework::Nuxt => Some("Nuxt".to_string()),
        lpm_cert::framework::Framework::SvelteKit => Some("SvelteKit".to_string()),
        lpm_cert::framework::Framework::Remix => Some("Remix".to_string()),
        lpm_cert::framework::Framework::Astro => Some("Astro".to_string()),
        lpm_cert::framework::Framework::Express => Some("Express".to_string()),
        lpm_cert::framework::Framework::Unknown => None,
    }
}

// ── Port Persistence ───────────────────────────────────────────────

/// Read persisted port overrides for a project.
///
/// Returns a map of service_name → port from `~/.lpm/ports.toml`.
/// Uses the project directory hash as the key to avoid conflicts.
pub fn read_port_overrides(project_dir: &std::path::Path) -> HashMap<String, u16> {
    let path = match ports_toml_path() {
        Some(p) => p,
        None => return HashMap::new(),
    };
    read_port_overrides_from(&path, project_dir)
}

fn read_port_overrides_from(
    path: &std::path::Path,
    project_dir: &std::path::Path,
) -> HashMap<String, u16> {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

    let doc: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };

    let project_key = project_hash(project_dir);
    let mut result = HashMap::new();

    if let Some(project) = doc.get(&project_key).and_then(|p| p.as_table()) {
        for (name, value) in project {
            if let Some(port) = value
                .as_integer()
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
            {
                result.insert(name.clone(), port);
            }
        }
    }

    result
}

fn write_port_override_to(
    path: &std::path::Path,
    project_dir: &std::path::Path,
    service_name: &str,
    port: u16,
) {
    let content = lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .unwrap_or_default();
    let mut doc: toml::value::Table = content
        .parse::<toml::Value>()
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_default();

    let project_key = project_hash(project_dir);
    let project_table = doc
        .entry(project_key)
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));

    if let Some(table) = project_table.as_table_mut() {
        table.insert(service_name.to_string(), toml::Value::Integer(port as i64));
    }

    atomic_write_toml(path, &doc);
}

/// Clear all port overrides for a project.
///
/// Serializes with active `lpm dev` startup so it cannot lose another
/// project's concurrent override update.
pub fn clear_port_overrides(project_dir: &std::path::Path) -> Result<(), LpmError> {
    let mut allocation = PortAllocation::acquire()?;
    allocation.clear_overrides(project_dir);
    Ok(())
}

fn clear_port_overrides_from(path: &std::path::Path, project_dir: &std::path::Path) {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(c) => c,
            Err(_) => return,
        };

    let mut doc: toml::value::Table = match content.parse::<toml::Value>() {
        Ok(v) => v.try_into().unwrap_or_default(),
        Err(_) => return,
    };

    let project_key = project_hash(project_dir);
    doc.remove(&project_key);

    atomic_write_toml(path, &doc);
}

/// Atomically write a TOML table to a file via tempfile + rename.
///
/// This prevents corruption from concurrent writes: either the old or
/// the new content is visible, never a partial write.
fn atomic_write_toml(path: &std::path::Path, doc: &toml::value::Table) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let content = toml::to_string_pretty(doc).unwrap_or_default();

    let _ = lpm_common::write_file_atomic(path, content);
}

fn ports_toml_path() -> Option<std::path::PathBuf> {
    lpm_common::LpmRoot::from_env().ok().map(|r| r.ports_toml())
}

fn project_hash(project_dir: &std::path::Path) -> String {
    let hash = crate::dlx::deterministic_hash(&project_dir.to_string_lossy());
    format!("project_{hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    struct KillOnDropChild(Option<Child>);

    #[cfg(target_os = "linux")]
    impl KillOnDropChild {
        fn new(child: Child) -> Self {
            Self(Some(child))
        }

        fn child_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("child should be available")
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for KillOnDropChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_exit_code_recognizes_still_active_value() {
        use windows_sys::Win32::Foundation::STILL_ACTIVE;

        assert!(windows_exit_code_is_active(STILL_ACTIVE as u32));
    }

    #[cfg(unix)]
    #[test]
    fn process_liveness_rejects_pids_that_do_not_fit_positive_pid_t() {
        assert!(!process_is_running(u32::MAX));
        assert!(!process_is_running(0));
    }

    #[cfg(unix)]
    #[test]
    fn process_probe_timeout_is_not_held_open_by_a_background_descendant() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 2 & exit 0"]);
        let started = std::time::Instant::now();

        let output =
            command_stdout_capped_with_timeout(&mut command, std::time::Duration::from_millis(50));
        let elapsed = started.elapsed();

        assert!(
            output.is_none(),
            "incomplete process-probe output was accepted"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "background descendant retained the process-probe worker for {elapsed:?}"
        );
    }

    #[test]
    fn check_port_reports_ipv6_loopback_listener_as_in_use() {
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            return;
        };
        let port = listener.local_addr().unwrap().port();

        assert!(matches!(check_port(port), PortStatus::InUse { .. }));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn pid_scoped_listener_discovery_includes_only_requested_processes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let rows = list_listening_ports_for_pids(&HashSet::from([std::process::id()]));

        assert!(
            rows.iter()
                .any(|row| row.port == port && row.pid == Some(std::process::id())),
            "PID-scoped listener discovery omitted the current process listener: {rows:?}"
        );
        assert!(rows.iter().all(|row| row.pid == Some(std::process::id())));
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn concurrent_pid_listener_requests_share_one_scoped_query() {
        fn row(pid: u32, port: u16) -> ListeningPort {
            ListeningPort {
                port,
                address: None,
                address_family: None,
                pid: Some(pid),
                process: None,
                command: None,
                cwd: None,
                project_dir: None,
                project: None,
                framework: None,
                uptime: None,
            }
        }

        let (requests, receiver) = std::sync::mpsc::channel();
        let (first_response, first_rows) = std::sync::mpsc::sync_channel(1);
        let (second_response, second_rows) = std::sync::mpsc::sync_channel(1);
        requests
            .send(PidListenerRequest {
                pids: HashSet::from([20, 30]),
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
                response: second_response,
            })
            .unwrap();
        process_pid_listener_batch(
            PidListenerRequest {
                pids: HashSet::from([10, 20]),
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
                response: first_response,
            },
            &receiver,
            |pids, _deadline| {
                assert_eq!(pids, &HashSet::from([10, 20, 30]));
                vec![row(10, 3010), row(20, 3020), row(30, 3030)]
            },
        );

        assert_eq!(
            first_rows
                .recv()
                .unwrap()
                .into_iter()
                .map(|row| row.pid.unwrap())
                .collect::<HashSet<_>>(),
            HashSet::from([10, 20])
        );
        assert_eq!(
            second_rows
                .recv()
                .unwrap()
                .into_iter()
                .map(|row| row.pid.unwrap())
                .collect::<HashSet<_>>(),
            HashSet::from([20, 30])
        );
    }

    #[cfg(unix)]
    #[test]
    fn expired_pid_listener_requests_do_not_invoke_a_process_query() {
        let (_requests, receiver) = std::sync::mpsc::channel();
        let (response, rows) = std::sync::mpsc::sync_channel(1);

        process_pid_listener_batch(
            PidListenerRequest {
                pids: HashSet::from([10]),
                deadline: std::time::Instant::now() - std::time::Duration::from_millis(1),
                response,
            },
            &receiver,
            |_, _| panic!("expired request invoked listener discovery"),
        );

        assert!(matches!(
            rows.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn expired_full_listener_requests_do_not_invoke_a_process_query() {
        let (_requests, receiver) = std::sync::mpsc::channel();
        let (response, rows) = std::sync::mpsc::sync_channel(1);

        process_full_listener_batch(
            FullListenerRequest {
                deadline: std::time::Instant::now() - std::time::Duration::from_millis(1),
                response,
            },
            &receiver,
            |_| panic!("expired request invoked full listener discovery"),
        );

        assert!(matches!(
            rows.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn process_snapshot_rejects_a_reused_pid_identity() {
        let first = DescendantProcessSnapshot {
            identities: HashMap::from([(20, Some(ProcessIdentity("first".to_string())))]),
            uncertain_descendants: false,
        };
        let second = DescendantProcessSnapshot {
            identities: HashMap::from([(20, Some(ProcessIdentity("second".to_string())))]),
            uncertain_descendants: false,
        };

        assert!(!first.contains_same_process(20, &second));
    }

    #[cfg(not(windows))]
    #[test]
    fn port_owner_cleanup_skips_a_pid_reused_before_the_signal() {
        let identity_calls = std::cell::Cell::new(0);
        let signalled = std::cell::Cell::new(false);

        let killed_ports = kill_pid_if_owns_ports_unix_with(
            20,
            &[3_000],
            &ProcessIdentity("original".to_string()),
            |_| Some(20),
            |_| {
                let call = identity_calls.get();
                identity_calls.set(call + 1);
                Some(ProcessIdentity(if call == 0 {
                    "original".to_string()
                } else {
                    "reused".to_string()
                }))
            },
            |_, _| {
                signalled.set(true);
                Ok(())
            },
        )
        .unwrap();

        assert!(killed_ports.is_empty());
        assert!(!signalled.get());
    }

    #[test]
    fn batched_port_owner_cleanup_intersects_and_deduplicates_one_snapshot() {
        let first_identity = ProcessIdentity("first".to_string());
        let second_identity = ProcessIdentity("second".to_string());
        let first_ports = [3_001, 3_000, 3_000];
        let second_ports = [4_000];
        let owners = HashSet::from([(20, 3_000), (20, 3_001)]);
        let terminated = std::cell::RefCell::new(Vec::new());

        let killed = kill_pids_if_identities_own_ports_with(
            [
                (20, &first_identity, first_ports.as_slice()),
                (30, &second_identity, second_ports.as_slice()),
            ],
            &owners,
            |pid| match pid {
                20 => Some(first_identity.clone()),
                30 => Some(second_identity.clone()),
                _ => None,
            },
            |pid, _| {
                terminated.borrow_mut().push(pid);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(killed, [vec![3_000, 3_001], Vec::new()]);
        assert_eq!(terminated.into_inner(), [20]);
    }

    #[test]
    fn windows_port_owner_cleanup_skips_a_pid_reused_since_endpoint_capture() {
        let signalled = std::cell::Cell::new(false);

        let killed_ports = kill_pid_if_identity_owns_ports_windows_with(
            20,
            &[3_000],
            &ProcessIdentity("windows:100".to_string()),
            |_| Some((20, ProcessIdentity("windows:200".to_string()))),
            |_| Some(ProcessIdentity("windows:200".to_string())),
            |_, _| {
                signalled.set(true);
                Ok(())
            },
        )
        .unwrap();

        assert!(killed_ports.is_empty());
        assert!(!signalled.get());
    }

    #[test]
    fn process_signal_skips_an_identity_changed_at_the_final_check() {
        let signalled = std::cell::Cell::new(false);

        let result = signal_if_identity_matches(
            20,
            &ProcessIdentity("original".to_string()),
            |_| Some(ProcessIdentity("reused".to_string())),
            || {
                signalled.set(true);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(!signalled.get());
    }

    #[cfg(unix)]
    #[test]
    fn linux_pidfd_enosys_fails_closed_without_numeric_pid_signalling() {
        let result = signal_linux_process_with::<()>(
            20,
            &ProcessIdentity("original".to_string()),
            Err(std::io::Error::from_raw_os_error(libc::ENOSYS)),
            |_| panic!("an unavailable pidfd must not inspect a numeric PID identity"),
            |_| panic!("an unavailable pidfd must not use handle-bound signalling"),
        );

        assert_eq!(
            result.unwrap_err(),
            "identity-bound process termination requires Linux pidfd support"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_pidfd_permission_errors_do_not_use_the_numeric_pid_fallback() {
        let result = signal_linux_process_with::<()>(
            20,
            &ProcessIdentity("original".to_string()),
            Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            |_| panic!("a failed pidfd open must not inspect a numeric PID identity"),
            |_| panic!("an unavailable pidfd must not use handle-bound signalling"),
        );

        assert!(result.is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_without_audit_token_signalling_fails_closed() {
        let result =
            signal_macos_process_with(20, &ProcessIdentity("macos:9001:7".to_string()), None);

        assert_eq!(
            result.unwrap_err(),
            "identity-bound process termination is unavailable on this macOS release"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_audit_token_carries_the_pid_and_pid_version() {
        let token = macos_audit_token(42, &ProcessIdentity("macos:9001:7".to_string())).unwrap();

        assert_eq!(token.values[5], 42);
        assert_eq!(token.values[7], 7);
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn direct_port_owner_query_selects_only_tcp_listeners() {
        use std::os::unix::ffi::OsStrExt as _;

        let command = lsof_listener_query(3_000);
        let args: Vec<&[u8]> = command
            .get_args()
            .map(|argument| argument.as_bytes())
            .collect();

        assert_eq!(
            args,
            [
                b"-nP".as_slice(),
                b"-a".as_slice(),
                b"-iTCP:3000".as_slice(),
                b"-sTCP:LISTEN".as_slice(),
                b"-t".as_slice(),
            ]
        );
    }

    #[test]
    fn windows_root_identity_comes_from_the_existing_child_handle() {
        let identity = windows_root_process_identity_from_handle_with((), |_| Some(100))
            .expect("child handle identity");

        assert_eq!(identity, ProcessIdentity("windows:100".to_string()));
        assert_ne!(identity, ProcessIdentity("windows:200".to_string()));
    }

    #[cfg(not(windows))]
    #[test]
    fn process_tree_cleanup_reports_descendants_that_cannot_be_signalled_safely() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let root_pid = child.id();
        let snapshot = DescendantProcessSnapshot {
            identities: HashMap::from([
                (root_pid, Some(ProcessIdentity("root".to_string()))),
                (u32::MAX, Some(ProcessIdentity("descendant".to_string()))),
            ]),
            uncertain_descendants: false,
        };

        let result =
            terminate_child_process_tree_non_windows_with(&mut child, &snapshot, |_, _| {
                Err("atomic signalling unavailable".to_string())
            });

        assert!(result.is_err());
        assert!(child.try_wait().unwrap().is_some());
    }

    #[cfg(not(windows))]
    #[test]
    fn process_tree_cleanup_reports_uncertain_descendant_discovery() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let root_pid = child.id();
        let snapshot = DescendantProcessSnapshot {
            identities: HashMap::from([(root_pid, Some(ProcessIdentity("root".to_string())))]),
            uncertain_descendants: true,
        };

        let result =
            terminate_child_process_tree_non_windows_with(&mut child, &snapshot, |_, _| {
                panic!("an uncertain root-only snapshot must not signal a numeric PID")
            });

        assert!(result.is_err());
        assert!(child.try_wait().unwrap().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pidfd_terminates_the_captured_process() {
        if !identity_bound_process_termination_available() {
            return;
        }
        let mut child = KillOnDropChild::new(Command::new("sleep").arg("30").spawn().unwrap());
        let pid = child.child_mut().id();
        let identity = process_identity_for_pid(pid).expect("child process identity");

        terminate_unix_pid_if_process_identity(pid, &identity).unwrap();
        let status = child.child_mut().wait().unwrap();

        assert!(!status.success());
    }

    #[test]
    fn process_tree_cleanup_skips_a_descendant_with_a_reused_pid() {
        let snapshot = DescendantProcessSnapshot {
            identities: HashMap::from([
                (10, Some(ProcessIdentity("root".to_string()))),
                (20, Some(ProcessIdentity("original".to_string()))),
            ]),
            uncertain_descendants: false,
        };
        let signalled = std::cell::Cell::new(false);

        kill_snapshot_descendants_with(&snapshot, 10, |_, expected| {
            let current = ProcessIdentity("reused".to_string());
            if &current == expected {
                signalled.set(true);
                Ok(())
            } else {
                Err("identity changed".to_string())
            }
        });

        assert!(!signalled.get());
    }

    #[test]
    fn process_tree_cleanup_skips_a_descendant_without_an_identity() {
        let snapshot = DescendantProcessSnapshot {
            identities: HashMap::from([
                (10, Some(ProcessIdentity("root".to_string()))),
                (20, None),
            ]),
            uncertain_descendants: true,
        };
        let signalled = std::cell::Cell::new(false);

        kill_snapshot_descendants_with(&snapshot, 10, |_, _| {
            signalled.set(true);
            Ok(())
        });

        assert!(!signalled.get());
    }

    #[test]
    fn windows_process_tree_cleanup_does_not_signal_a_pid_reused_after_validation() {
        let snapshot = DescendantProcessSnapshot {
            identities: HashMap::from([
                (10, Some(ProcessIdentity("root".to_string()))),
                (20, Some(ProcessIdentity("original".to_string()))),
            ]),
            uncertain_descendants: false,
        };
        let current = ProcessIdentity("replacement".to_string());
        let terminated_replacement = std::cell::Cell::new(false);

        kill_snapshot_descendants_with(&snapshot, 10, |_, expected| {
            if &current == expected {
                terminated_replacement.set(true);
                Ok(())
            } else {
                Err("identity changed".to_string())
            }
        });

        assert!(!terminated_replacement.get());
    }

    #[test]
    fn windows_descendant_snapshot_rejects_stale_creator_pid_ancestry() {
        let trusted = HashMap::from([(10, ProcessIdentity("windows:100".to_string()))]);
        let entries = vec![
            WindowsSnapshotEntry { pid: 10, parent: 1 },
            WindowsSnapshotEntry {
                pid: 20,
                parent: 10,
            },
        ];
        let identities = HashMap::from([
            (10, ProcessIdentity("windows:100".to_string())),
            (20, ProcessIdentity("windows:50".to_string())),
        ]);

        let snapshot = windows_descendant_snapshot_from_entries(
            10,
            &trusted,
            &HashMap::new(),
            &entries,
            |pid| identities.get(&pid).cloned(),
        );

        assert!(!snapshot.processes.contains(20));
        assert!(!snapshot.parents.contains_key(&20));
    }

    #[test]
    fn windows_descendant_snapshot_rejects_children_of_a_reused_root() {
        let trusted = HashMap::from([(10, ProcessIdentity("windows:100".to_string()))]);
        let entries = vec![
            WindowsSnapshotEntry { pid: 10, parent: 1 },
            WindowsSnapshotEntry {
                pid: 20,
                parent: 10,
            },
            WindowsSnapshotEntry {
                pid: 30,
                parent: 10,
            },
        ];
        let identities = HashMap::from([
            (10, ProcessIdentity("windows:200".to_string())),
            (20, ProcessIdentity("windows:150".to_string())),
            (30, ProcessIdentity("windows:250".to_string())),
        ]);

        let snapshot = windows_descendant_snapshot_from_entries(
            10,
            &trusted,
            &HashMap::new(),
            &entries,
            |pid| identities.get(&pid).cloned(),
        );

        assert!(!snapshot.processes.contains(20));
        assert!(!snapshot.processes.contains(30));
        assert!(snapshot.processes.uncertain_descendants);
    }

    #[test]
    fn windows_descendant_snapshot_rejects_a_child_of_an_absent_trusted_parent() {
        let trusted = HashMap::from([
            (10, ProcessIdentity("windows:100".to_string())),
            (20, ProcessIdentity("windows:120".to_string())),
        ]);
        let trusted_parents = HashMap::from([(20, 10)]);
        let entries = vec![WindowsSnapshotEntry {
            pid: 30,
            parent: 20,
        }];

        let snapshot = windows_descendant_snapshot_from_entries(
            10,
            &trusted,
            &trusted_parents,
            &entries,
            |pid| (pid == 30).then(|| ProcessIdentity("windows:300".to_string())),
        );

        assert!(!snapshot.processes.contains(30));
        assert!(snapshot.processes.uncertain_descendants);
    }

    #[test]
    fn windows_descendant_snapshot_rejects_a_pid_reused_between_topology_samples() {
        let trusted = HashMap::from([(10, ProcessIdentity("windows:100".to_string()))]);
        let captured = vec![
            WindowsSnapshotEntry { pid: 10, parent: 1 },
            WindowsSnapshotEntry {
                pid: 20,
                parent: 10,
            },
        ];
        let current = vec![
            WindowsSnapshotEntry { pid: 10, parent: 1 },
            WindowsSnapshotEntry {
                pid: 20,
                parent: 99,
            },
        ];
        let identities = HashMap::from([
            (10, ProcessIdentity("windows:100".to_string())),
            (20, ProcessIdentity("windows:300".to_string())),
        ]);

        let snapshot = windows_descendant_snapshot_from_entry_samples(
            10,
            &trusted,
            &HashMap::new(),
            &captured,
            |pid| identities.get(&pid).cloned(),
            || Some(current),
        );

        assert!(!snapshot.processes.contains(20));
        assert!(snapshot.processes.uncertain_descendants);
    }

    #[test]
    fn windows_descendant_snapshot_rejects_a_branch_with_a_changed_ancestor_edge() {
        let trusted = HashMap::from([(10, ProcessIdentity("windows:100".to_string()))]);
        let captured = vec![
            WindowsSnapshotEntry { pid: 10, parent: 1 },
            WindowsSnapshotEntry {
                pid: 20,
                parent: 10,
            },
        ];
        let current = vec![
            WindowsSnapshotEntry {
                pid: 10,
                parent: 99,
            },
            WindowsSnapshotEntry {
                pid: 20,
                parent: 10,
            },
        ];
        let identities = HashMap::from([
            (10, ProcessIdentity("windows:100".to_string())),
            (20, ProcessIdentity("windows:300".to_string())),
        ]);

        let snapshot = windows_descendant_snapshot_from_entry_samples(
            10,
            &trusted,
            &HashMap::new(),
            &captured,
            |pid| identities.get(&pid).cloned(),
            || Some(current),
        );

        assert!(!snapshot.processes.contains(20));
        assert!(snapshot.processes.uncertain_descendants);
    }

    #[test]
    fn windows_descendant_snapshot_does_not_persist_unidentified_ancestry() {
        let trusted = HashMap::from([(10, ProcessIdentity("windows:100".to_string()))]);
        let first_entries = vec![
            WindowsSnapshotEntry { pid: 10, parent: 1 },
            WindowsSnapshotEntry {
                pid: 20,
                parent: 10,
            },
        ];
        let first = windows_descendant_snapshot_from_entries(
            10,
            &trusted,
            &HashMap::new(),
            &first_entries,
            |pid| (pid == 10).then(|| ProcessIdentity("windows:100".to_string())),
        );
        let reused_entries = vec![
            WindowsSnapshotEntry { pid: 10, parent: 1 },
            WindowsSnapshotEntry {
                pid: 20,
                parent: 99,
            },
        ];
        let second = windows_descendant_snapshot_from_entries(
            10,
            &trusted,
            &first.parents,
            &reused_entries,
            |pid| match pid {
                10 => Some(ProcessIdentity("windows:100".to_string())),
                20 => Some(ProcessIdentity("windows:300".to_string())),
                _ => None,
            },
        );

        assert!(first.processes.uncertain_descendants);
        assert!(!first.parents.contains_key(&20));
        assert!(!second.processes.contains(20));
    }

    #[test]
    fn windows_descendant_snapshot_keeps_an_unidentifiable_branch_uncertain() {
        let trusted = HashMap::from([
            (10, ProcessIdentity("windows:100".to_string())),
            (20, ProcessIdentity("windows:120".to_string())),
        ]);
        let trusted_parents = HashMap::from([(20, 10)]);
        let entries = vec![
            WindowsSnapshotEntry {
                pid: 20,
                parent: 10,
            },
            WindowsSnapshotEntry {
                pid: 30,
                parent: 20,
            },
        ];

        let snapshot = windows_descendant_snapshot_from_entries(
            10,
            &trusted,
            &trusted_parents,
            &entries,
            |pid| (pid == 30).then(|| ProcessIdentity("windows:300".to_string())),
        );

        assert!(!snapshot.processes.contains(30));
        assert!(snapshot.processes.uncertain_descendants);
    }

    #[test]
    fn windows_descendant_identity_probes_ignore_unrelated_processes() {
        let trusted = HashMap::from([(10, ProcessIdentity("windows:100".to_string()))]);
        let mut entries = Vec::with_capacity(10_002);
        entries.push(WindowsSnapshotEntry { pid: 10, parent: 1 });
        entries.push(WindowsSnapshotEntry {
            pid: 20,
            parent: 10,
        });
        entries.extend((100..10_100).map(|pid| WindowsSnapshotEntry { pid, parent: 1 }));
        let probes = std::cell::Cell::new(0usize);

        let snapshot = windows_descendant_snapshot_from_entries(
            10,
            &trusted,
            &HashMap::new(),
            &entries,
            |pid| {
                probes.set(probes.get() + 1);
                match pid {
                    10 => Some(ProcessIdentity("windows:100".to_string())),
                    20 => Some(ProcessIdentity("windows:120".to_string())),
                    _ => Some(ProcessIdentity(format!(
                        "windows:{}",
                        u64::from(pid) + 1_000
                    ))),
                }
            },
        );

        assert!(snapshot.processes.contains(20));
        assert_eq!(probes.get(), 2);
    }

    #[test]
    fn windows_process_tree_cleanup_rescans_after_the_leader_stops() {
        let snapshots = std::cell::RefCell::new(std::collections::VecDeque::from([
            DescendantProcessSnapshot {
                identities: HashMap::from([
                    (10, Some(ProcessIdentity("windows:100".to_string()))),
                    (20, Some(ProcessIdentity("windows:120".to_string()))),
                ]),
                uncertain_descendants: false,
            },
            DescendantProcessSnapshot {
                identities: HashMap::from([
                    (10, Some(ProcessIdentity("windows:100".to_string()))),
                    (30, Some(ProcessIdentity("windows:130".to_string()))),
                ]),
                uncertain_descendants: false,
            },
            DescendantProcessSnapshot {
                identities: HashMap::from([(10, Some(ProcessIdentity("windows:100".to_string())))]),
                uncertain_descendants: false,
            },
        ]));
        let terminated = std::cell::RefCell::new(Vec::new());

        let result = terminate_descendants_until_stable_with(
            10,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            || {
                snapshots
                    .borrow_mut()
                    .pop_front()
                    .expect("cleanup snapshot")
            },
            |pid, _| {
                terminated.borrow_mut().push(pid);
                Ok(())
            },
        );

        assert!(result.is_ok());
        assert_eq!(terminated.borrow().as_slice(), [20, 30]);
    }

    #[test]
    fn windows_process_tree_cleanup_uses_bounded_retry_backoff() {
        let started = std::time::Instant::now();
        let clock = std::cell::Cell::new(started);
        let snapshots = std::cell::Cell::new(0usize);
        let waits = std::cell::RefCell::new(Vec::new());
        let snapshot = DescendantProcessSnapshot {
            identities: HashMap::from([
                (10, Some(ProcessIdentity("windows:100".to_string()))),
                (20, Some(ProcessIdentity("windows:120".to_string()))),
            ]),
            uncertain_descendants: false,
        };

        let result = terminate_descendants_until_stable_with_clock(
            10,
            started + std::time::Duration::from_secs(5),
            || {
                snapshots.set(snapshots.get() + 1);
                snapshot.clone()
            },
            |_, _| Err("process remained active".to_string()),
            || clock.get(),
            |delay| {
                waits.borrow_mut().push(delay);
                clock.set(clock.get() + delay);
            },
        );

        assert!(result.is_err());
        assert!(snapshots.get() <= 26, "used {} snapshots", snapshots.get());
        assert_eq!(
            &waits.borrow()[..5],
            &[
                std::time::Duration::from_millis(10),
                std::time::Duration::from_millis(20),
                std::time::Duration::from_millis(40),
                std::time::Duration::from_millis(80),
                std::time::Duration::from_millis(160),
            ]
        );
        assert!(
            waits
                .borrow()
                .iter()
                .all(|delay| *delay <= std::time::Duration::from_millis(250))
        );
    }

    #[test]
    fn windows_process_tree_cleanup_does_not_clear_prior_uncertainty() {
        let started = std::time::Instant::now();
        let clock = std::cell::Cell::new(started);
        let snapshots = std::cell::RefCell::new(std::collections::VecDeque::from([
            DescendantProcessSnapshot {
                identities: HashMap::from([
                    (10, Some(ProcessIdentity("windows:100".to_string()))),
                    (20, None),
                ]),
                uncertain_descendants: true,
            },
            DescendantProcessSnapshot {
                identities: HashMap::from([(10, Some(ProcessIdentity("windows:100".to_string())))]),
                uncertain_descendants: false,
            },
        ]));

        let result = terminate_descendants_until_stable_with_clock(
            10,
            started + std::time::Duration::from_millis(10),
            || {
                snapshots
                    .borrow_mut()
                    .pop_front()
                    .unwrap_or_else(|| DescendantProcessSnapshot {
                        identities: HashMap::from([(
                            10,
                            Some(ProcessIdentity("windows:100".to_string())),
                        )]),
                        uncertain_descendants: false,
                    })
            },
            |_, _| Ok(()),
            || clock.get(),
            |delay| clock.set(clock.get() + delay),
        );

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_process_tree_requests_share_one_process_table() {
        let (requests, receiver) = std::sync::mpsc::channel();
        let (first_response, first_snapshot) = std::sync::mpsc::sync_channel(1);
        let (second_response, second_snapshot) = std::sync::mpsc::sync_channel(1);
        requests
            .send(ProcessTreeSnapshotRequest {
                root_pid: 20,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
                response: second_response,
            })
            .unwrap();
        process_tree_snapshot_batch(
            ProcessTreeSnapshotRequest {
                root_pid: 10,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
                response: first_response,
            },
            &receiver,
            |_| {
                Some(UnixProcessTable::from_records(vec![
                    UnixProcessRecord {
                        pid: 10,
                        parent: 1,
                        identity: Some(ProcessIdentity("root-10".to_string())),
                    },
                    UnixProcessRecord {
                        pid: 11,
                        parent: 10,
                        identity: Some(ProcessIdentity("child-11".to_string())),
                    },
                    UnixProcessRecord {
                        pid: 20,
                        parent: 1,
                        identity: Some(ProcessIdentity("root-20".to_string())),
                    },
                    UnixProcessRecord {
                        pid: 21,
                        parent: 20,
                        identity: Some(ProcessIdentity("child-21".to_string())),
                    },
                ]))
            },
        );

        assert_eq!(
            first_snapshot.recv().unwrap().process_ids(),
            HashSet::from([10, 11])
        );
        assert_eq!(
            second_snapshot.recv().unwrap().process_ids(),
            HashSet::from([20, 21])
        );
    }

    #[cfg(unix)]
    #[test]
    fn expired_process_tree_requests_do_not_invoke_a_process_query() {
        let (_requests, receiver) = std::sync::mpsc::channel();
        let (response, snapshot) = std::sync::mpsc::sync_channel(1);

        process_tree_snapshot_batch(
            ProcessTreeSnapshotRequest {
                root_pid: 10,
                deadline: std::time::Instant::now() - std::time::Duration::from_millis(1),
                response,
            },
            &receiver,
            |_| panic!("expired request invoked process-tree discovery"),
        );

        assert!(matches!(
            snapshot.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn worker_response_wait_accepts_a_response_available_before_the_deadline() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender.send(42_u8).unwrap();

        let response = receive_worker_response_until(
            &receiver,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            &mut || false,
        );

        assert_eq!(response, Some(42));
    }

    #[cfg(unix)]
    #[test]
    fn worker_response_wait_rejects_a_response_sent_after_the_deadline() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _ = sender.send(42_u8);
        });
        let response = receive_worker_response_until(
            &receiver,
            std::time::Instant::now() + std::time::Duration::from_millis(20),
            &mut || false,
        );
        worker.join().unwrap();

        assert!(response.is_none(), "late worker response was accepted");
    }

    #[cfg(unix)]
    #[test]
    fn live_process_identity_is_stable_across_snapshots() {
        let pid = std::process::id();
        let first = descendant_process_snapshot(pid);
        let second = descendant_process_snapshot(pid);

        assert!(first.contains_same_process(pid, &second));
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn parse_lsof_listen_output_preserves_dual_stack_same_pid_port() {
        let rows = parse_lsof_listen_output(
            "\
p101
cnode
PTCP
tIPv4
nTCP *:3000 (LISTEN)
tIPv6
nTCP [::1]:3000 (LISTEN)
p202
credis-server
PTCP
tIPv4
nTCP 127.0.0.1:6379 (LISTEN)
",
        );

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].pid, Some(101));
        assert_eq!(rows[0].process.as_deref(), Some("node"));
        assert_eq!(rows[0].port, 3000);
        assert_eq!(rows[1].pid, Some(101));
        assert_eq!(rows[1].address.as_deref(), Some("::1"));
        assert_eq!(rows[1].port, 3000);
        assert_eq!(rows[2].pid, Some(202));
        assert_eq!(rows[2].address.as_deref(), Some("127.0.0.1"));
        assert_eq!(rows[2].port, 6379);
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn parse_lsof_tcp_name_reads_ipv6_and_wildcard_addresses() {
        assert_eq!(
            parse_lsof_tcp_name("TCP *:3000 (LISTEN)"),
            Some((None, 3000))
        );
        assert_eq!(
            parse_lsof_tcp_name("TCP [::1]:5173 (LISTEN)"),
            Some((Some("::1".to_string()), 5173))
        );
        assert_eq!(
            parse_lsof_tcp_name("TCP 127.0.0.1:8080 (LISTEN)"),
            Some((Some("127.0.0.1".to_string()), 8080))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_macos_netstat_listeners_preserves_addresses_and_process_names() {
        let rows = parse_macos_netstat_listen_output(
            "\
tcp4 0 0 127.0.0.1.63523 *.* LISTEN 0 0 131072 131072 node:74379 00100\n\
tcp6 0 0 *.5173 *.* LISTEN 0 0 131072 131072 Codex (Service):1191 00100\n\
tcp4 0 0 127.0.0.1.60000 127.0.0.1.443 ESTABLISHED 1 2 3 4 node:99 00100\n",
        );

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].address.as_deref(), Some("127.0.0.1"));
        assert_eq!(rows[0].port, 63523);
        assert_eq!(rows[0].pid, Some(74379));
        assert_eq!(rows[0].process.as_deref(), Some("node"));
        assert_eq!(rows[1].address, None);
        assert_eq!(rows[1].address_family, Some(ListeningAddressFamily::Ipv6));
        assert_eq!(rows[1].port, 5173);
        assert_eq!(rows[1].pid, Some(1191));
        assert_eq!(rows[1].process.as_deref(), Some("Codex (Service)"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_listener_query_skips_work_after_its_deadline() {
        let started = std::time::Instant::now();
        let rows = list_listening_ports_macos_until(
            std::time::Instant::now() - std::time::Duration::from_millis(1),
        );

        assert!(rows.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn parse_ps_line_preserves_full_command() {
        let (pid, info) =
            parse_ps_line("  48213 node 01:02:03 node server.js --port 3000").unwrap();

        assert_eq!(pid, 48213);
        assert_eq!(info.process.as_deref(), Some("node"));
        assert_eq!(info.uptime.as_deref(), Some("01:02:03"));
        assert_eq!(info.command.as_deref(), Some("node server.js --port 3000"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cwd_collection_does_not_drop_listener_metadata_after_lsof_deadline() {
        let cwd_by_pid = collect_cwds_until(
            &[std::process::id()],
            std::time::Instant::now() - std::time::Duration::from_millis(1),
            true,
        );

        assert_eq!(
            cwd_by_pid.get(&std::process::id()),
            std::env::current_dir().ok().as_ref()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_line_reads_ipv4_listener() {
        let row = parse_proc_net_tcp_line(
            "   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 501 0 123456 1 0000000000000000 100 0 0 10 0",
            false,
        )
        .unwrap();

        assert_eq!(row.port, 3000);
        assert_eq!(row.address.as_deref(), Some("127.0.0.1"));
        assert_eq!(row.inode, 123456);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_line_reads_ipv6_listener() {
        let row = parse_proc_net_tcp_line(
            "   1: 00000000000000000000000001000000:14B5 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 501 0 789012 1 0000000000000000 100 0 0 10 0",
            true,
        )
        .unwrap();

        assert_eq!(row.port, 5301);
        assert_eq!(row.address.as_deref(), Some("::1"));
        assert_eq!(row.inode, 789012);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_line_ignores_non_listeners() {
        assert!(parse_proc_net_tcp_line(
            "   2: 0100007F:0BB8 0100007F:1234 01 00000000:00000000 00:00000000 00000000 501 0 123456 1 0000000000000000 100 0 0 10 0",
            false,
        )
        .is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_cmdline_joins_nul_separated_args() {
        let command = parse_proc_cmdline(b"node\0server.js\0--port=3000\0").unwrap();

        assert_eq!(command, "node server.js --port=3000");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_stat_start_ticks_handles_spaces_in_process_name() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "987654";
        let stat = format!("42 (node worker thread) {}", fields.join(" "));

        assert_eq!(parse_proc_stat_start_ticks(&stat), Some(987654));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_inode_from_link_reads_proc_fd_socket_target() {
        assert_eq!(
            socket_inode_from_link(Path::new("socket:[314159]")),
            Some(314159)
        );
        assert_eq!(socket_inode_from_link(Path::new("pipe:[314159]")), None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_tcp_helpers_decode_ports_and_addresses() {
        assert_eq!(windows_port_from_mib(0xB80B), 3000);
        assert_eq!(
            windows_ipv4_address_from_mib(0x0100007F).as_deref(),
            Some("127.0.0.1")
        );

        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert_eq!(
            windows_ipv6_address_from_mib(loopback).as_deref(),
            Some("::1")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_name_from_path_handles_native_and_slash_paths() {
        assert_eq!(
            windows_file_name_from_path(r"C:\Program Files\nodejs\node.exe"),
            Some("node.exe")
        );
        assert_eq!(
            windows_file_name_from_path("C:/Program Files/nodejs/npm.cmd"),
            Some("npm.cmd")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_filetime_to_unix_secs_reads_epoch_offset() {
        use windows_sys::Win32::Foundation::FILETIME;

        let ticks = 11_644_473_600u64 * 10_000_000u64;
        let filetime = FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };

        assert_eq!(filetime_to_unix_secs(filetime), Some(0));
    }

    #[cfg(windows)]
    #[test]
    fn windows_same_process_uses_creation_ticks_when_available() {
        let expected = WindowsProcessIdentity {
            pid: 42,
            creation_ticks: Some(100),
        };

        assert!(windows_same_process(
            WindowsProcessIdentity {
                pid: 42,
                creation_ticks: Some(100),
            },
            expected,
        ));
        assert!(!windows_same_process(
            WindowsProcessIdentity {
                pid: 42,
                creation_ticks: Some(101),
            },
            expected,
        ));
        assert!(!windows_same_process(
            WindowsProcessIdentity {
                pid: 43,
                creation_ticks: Some(100),
            },
            expected,
        ));
    }

    #[test]
    fn windows_same_process_rejects_pid_match_when_creation_ticks_are_unavailable() {
        assert!(!windows_same_process(
            WindowsProcessIdentity {
                pid: 42,
                creation_ticks: None,
            },
            WindowsProcessIdentity {
                pid: 42,
                creation_ticks: Some(100),
            },
        ));
    }

    #[cfg(windows)]
    #[test]
    fn list_listening_ports_windows_includes_current_process_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let rows = list_listening_ports_windows();
        let row = rows
            .iter()
            .find(|row| row.port == port && row.pid == Some(std::process::id()))
            .unwrap_or_else(|| {
                panic!(
                    "Windows IP Helper backend must include the current test listener on port {port}; rows: {rows:?}"
                )
            });

        assert_eq!(row.address.as_deref(), Some("127.0.0.1"));
        assert!(
            row.process.as_deref().is_some_and(|name| {
                name.eq_ignore_ascii_case("lpm_runner.exe")
                    || name.to_ascii_lowercase().starts_with("lpm_runner-")
            }),
            "Windows process metadata should include current-user process name for port {port}; row: {row:?}"
        );
        assert!(
            row.command
                .as_deref()
                .is_some_and(|command| command.to_ascii_lowercase().contains("lpm_runner")),
            "Windows process metadata should include current-user command path for port {port}; row: {row:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn discover_project_for_cwd_uses_nearest_manifest_and_framework() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project = tmp.path().join("app");
        let nested = project.join("src/server");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"sample-app","devDependencies":{"vite":"^5.0.0"}}"#,
        )
        .unwrap();

        let info = discover_project_for_cwd(&nested).unwrap();

        assert_eq!(info.dir, project);
        assert_eq!(info.name, "sample-app");
        assert_eq!(info.framework.as_deref(), Some("Vite"));
    }

    #[cfg(unix)]
    #[test]
    fn project_for_cwd_reuses_cached_discovery_for_same_cwd() {
        let calls = std::cell::Cell::new(0);
        let tmp = tempfile::TempDir::new().unwrap();
        let cwd = tmp.path().join("app");
        std::fs::create_dir_all(&cwd).unwrap();
        let discovered = ProjectInfo {
            dir: cwd.clone(),
            name: "cached-app".to_string(),
            framework: None,
        };
        let mut cache = HashMap::new();

        let first = project_for_cwd_with_discover(&cwd, &mut cache, |_| {
            calls.set(calls.get() + 1);
            Some(discovered.clone())
        })
        .unwrap();
        let second = project_for_cwd_with_discover(&cwd, &mut cache, |_| {
            calls.set(calls.get() + 1);
            None
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(first.name, "cached-app");
        assert_eq!(second.name, "cached-app");
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn unsupported_platform_listening_ports_return_empty() {
        assert!(list_listening_ports_platform().is_empty());
        assert!(list_listening_ports().is_empty());
    }

    #[test]
    fn check_free_port() {
        // Port 0 lets the OS pick a free port; use a high random port
        // that's very unlikely to be in use
        let port = 49152 + (std::process::id() as u16 % 1000);
        // This might be in use, so just verify the function doesn't panic
        let _ = check_port(port);
    }

    #[test]
    fn find_available_port_works() {
        let port = find_available_port(49000);
        assert!(port.is_some());
        assert!(port.unwrap() >= 49000);
    }

    #[test]
    fn cross_service_env_two_services() {
        let mut services = HashMap::new();
        services.insert("web".to_string(), 3000u16);
        services.insert("api".to_string(), 4000u16);

        let env = build_cross_service_env(&services, false);

        // web should have API_URL and API_PORT
        let web_env = &env["web"];
        assert_eq!(web_env.get("API_URL").unwrap(), "http://localhost:4000");
        assert_eq!(web_env.get("API_PORT").unwrap(), "4000");

        // api should have WEB_URL and WEB_PORT
        let api_env = &env["api"];
        assert_eq!(api_env.get("WEB_URL").unwrap(), "http://localhost:3000");
        assert_eq!(api_env.get("WEB_PORT").unwrap(), "3000");

        // web should NOT have its own URL
        assert!(!web_env.contains_key("WEB_URL"));
    }

    #[test]
    fn write_and_read_port_override() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project_dir = tmp.path().join("my-project");
        std::fs::create_dir_all(&project_dir).unwrap();
        let root = LpmRoot::from_dir(tmp.path().join(".lpm"));
        let mut allocation =
            PortAllocation::acquire_for_root_and_lease_dir(root, tmp.path().join("leases"))
                .unwrap();

        allocation.write_override(&project_dir, "web", 4001);

        assert_eq!(allocation.read_overrides(&project_dir)["web"], 4001);
    }

    #[test]
    fn persisted_port_overrides_reject_values_outside_the_tcp_port_range() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project_dir = tmp.path().join("my-project");
        std::fs::create_dir_all(&project_dir).unwrap();
        let project_key = project_hash(&project_dir);
        let path = tmp.path().join("ports.toml");
        std::fs::write(
            &path,
            format!("[{project_key}]\nwrapped = 70000\nnegative = -1\nzero = 0\nvalid = 65535\n"),
        )
        .unwrap();

        let overrides = read_port_overrides_from(&path, &project_dir);

        assert_eq!(overrides, HashMap::from([("valid".to_string(), 65535)]));
    }

    #[test]
    fn clear_port_overrides_removes_project_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project_dir = tmp.path().join("my-project");
        let other_project_dir = tmp.path().join("other-project");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::create_dir_all(&other_project_dir).unwrap();
        let root = LpmRoot::from_dir(tmp.path().join(".lpm"));
        let mut allocation =
            PortAllocation::acquire_for_root_and_lease_dir(root, tmp.path().join("leases"))
                .unwrap();
        allocation.write_override(&project_dir, "web", 4001);
        allocation.write_override(&other_project_dir, "api", 5000);

        allocation.clear_overrides(&project_dir);

        assert!(allocation.read_overrides(&project_dir).is_empty());
        assert_eq!(allocation.read_overrides(&other_project_dir)["api"], 5000);
    }

    #[test]
    fn clear_nonexistent_project_is_harmless() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project_dir = tmp.path().join("nonexistent");
        let root = LpmRoot::from_dir(tmp.path().join(".lpm"));
        let mut allocation =
            PortAllocation::acquire_for_root_and_lease_dir(root.clone(), tmp.path().join("leases"))
                .unwrap();

        allocation.clear_overrides(&project_dir);

        assert!(!root.ports_toml().exists());
    }

    #[test]
    fn port_lease_blocks_reuse_across_different_lpm_homes_until_owner_drops() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lease_dir = tmp.path().join("leases");
        let first_allocation = PortAllocation::acquire_for_root_and_lease_dir(
            LpmRoot::from_dir(tmp.path().join("first-home")),
            lease_dir.clone(),
        )
        .unwrap();
        let first_lease = first_allocation
            .try_acquire_lease(3000)
            .unwrap()
            .expect("first lease should be available");
        drop(first_allocation);
        let second_allocation = PortAllocation::acquire_for_root_and_lease_dir(
            LpmRoot::from_dir(tmp.path().join("second-home")),
            lease_dir,
        )
        .unwrap();

        assert!(second_allocation.try_acquire_lease(3000).unwrap().is_none());
        drop(first_lease);
        assert!(second_allocation.try_acquire_lease(3000).unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn port_lease_directory_is_restricted_to_current_user() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let lease_dir = tmp.path().join("leases");
        std::fs::create_dir_all(&lease_dir).unwrap();
        std::fs::set_permissions(&lease_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let _allocation = PortAllocation::acquire_for_root_and_lease_dir(
            LpmRoot::from_dir(tmp.path().join("home")),
            lease_dir.clone(),
        )
        .unwrap();

        let mode = std::fs::metadata(lease_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[cfg(unix)]
    #[test]
    fn port_lease_directory_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target");
        let lease_dir = tmp.path().join("leases");
        std::fs::create_dir_all(&target).unwrap();
        symlink(target, &lease_dir).unwrap();

        let error = PortAllocation::acquire_for_root_and_lease_dir(
            LpmRoot::from_dir(tmp.path().join("home")),
            lease_dir,
        )
        .err()
        .expect("symlinked lease directory should be rejected");

        assert!(
            matches!(error, LpmError::Io(ref io_error) if io_error.kind() == std::io::ErrorKind::PermissionDenied),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn atomic_write_creates_parent_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("deep").join("nested").join("ports.toml");
        let doc = toml::value::Table::new();
        atomic_write_toml(&path, &doc);
        assert!(path.exists(), "file should be created with parent dirs");
    }

    #[test]
    fn cross_service_env_https() {
        let mut services = HashMap::new();
        services.insert("web".to_string(), 3000u16);
        services.insert("api".to_string(), 4000u16);

        let env = build_cross_service_env(&services, true);
        assert_eq!(env["web"].get("API_URL").unwrap(), "https://localhost:4000");
    }
}
