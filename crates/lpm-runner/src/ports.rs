//! Port conflict detection, resolution, and cross-service env injection.
//!
//! Before starting services, checks all declared ports for conflicts
//! and builds cross-service environment variables ({SERVICE}_URL, {SERVICE}_PORT).

use lpm_common::{ExclusiveLockHandle, LpmError, LpmRoot};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

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
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub command: Option<String>,
    pub cwd: Option<PathBuf>,
    pub project_dir: Option<PathBuf>,
    pub project: Option<String>,
    pub framework: Option<String>,
    pub uptime: Option<String>,
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

fn loopback_port_available(port: u16) -> bool {
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
                // Mitigate PID reuse TOCTOU by re-querying which PID owns the
                // *specific port* (not just checking if the PID exists).
                // The platform backend verifies the PID is still bound to this
                // exact port, not merely alive.
                std::thread::sleep(std::time::Duration::from_millis(50));
                let (pid_recheck, _) = find_port_owner(port);
                if pid_recheck != Some(pid) {
                    return Err(format!(
                        "port {port} owner changed (was PID {pid}, now {:?}) — aborting kill for safety",
                        pid_recheck
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
                    let output = Command::new("kill")
                        .arg(pid.to_string())
                        .output()
                        .map_err(|e| format!("failed to kill PID {pid} ({proc_name}): {e}"))?;
                    if !output.status.success() {
                        return Err(format!(
                            "failed to kill PID {pid} ({proc_name}): {}",
                            String::from_utf8_lossy(&output.stderr)
                        ));
                    }
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
        let output = Command::new("kill")
            .arg(pid.to_string())
            .output()
            .map_err(|e| format!("failed to kill PID {pid}: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "failed to kill PID {pid}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    #[cfg(windows)]
    {
        terminate_windows_pid(pid, windows_process_identity_for_pid(pid))
            .map_err(|err| format!("failed to kill PID {pid}: {err}"))?;
    }

    Ok(())
}

/// Kill `pid` only if it still owns at least one of the requested ports.
///
/// Returns the subset of requested ports that were still owned at the moment
/// of the safety re-check. An empty vector means nothing was killed.
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

    #[cfg(windows)]
    {
        let expected_identity = windows_process_identity_for_pid(pid);
        still_owned_ports.retain(|port| {
            find_windows_port_owner(*port).is_some_and(|owner| {
                expected_identity
                    .is_none_or(|expected| windows_same_process(owner.identity, expected))
            })
        });
        if still_owned_ports.is_empty() {
            return Ok(Vec::new());
        }
        terminate_windows_pid(pid, expected_identity)
            .map_err(|err| format!("failed to kill PID {pid}: {err}"))?;
    }

    #[cfg(not(windows))]
    {
        kill_pid(pid)?;
    }

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
fn find_port_owner(port: u16) -> (Option<u32>, Option<String>) {
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

#[cfg(all(unix, not(target_os = "linux")))]
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
            .then_with(|| left.address.cmp(&right.address))
    });
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
    let output = Command::new("lsof")
        .args(["-ti", &format!(":{port}")])
        .output()
        .ok();

    if let Some(output) = output
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pid_str = stdout.trim().lines().next().unwrap_or("").trim();
        if let Ok(pid) = pid_str.parse::<u32>() {
            let name = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                    } else {
                        None
                    }
                });
            return (Some(pid), name);
        }
    }

    (None, None)
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

#[cfg(all(unix, not(target_os = "linux")))]
fn list_listening_ports_lsof() -> Vec<ListeningPort> {
    let output = match Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcPn"])
        .output()
    {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };

    if output.stdout.is_empty() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rows = parse_lsof_listen_output(&stdout);
    if rows.is_empty() {
        return rows;
    }

    let mut pids: Vec<u32> = rows.iter().filter_map(|row| row.pid).collect();
    pids.sort_unstable();
    pids.dedup();

    let cwd_by_pid = collect_cwds(&pids);
    let ps_by_pid = collect_ps_info(&pids);

    for row in &mut rows {
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

    rows
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parse_lsof_listen_output(output: &str) -> Vec<ListeningPort> {
    let mut rows = Vec::new();
    let mut seen: HashSet<(u16, Option<u32>)> = HashSet::new();
    let mut current_pid = None;
    let mut current_process = None::<String>;

    for line in output.lines() {
        let Some((tag, value)) = line.split_at_checked(1) else {
            continue;
        };
        match tag {
            "p" => {
                current_pid = value.parse::<u32>().ok();
                current_process = None;
            }
            "c" => {
                if !value.is_empty() {
                    current_process = Some(value.to_string());
                }
            }
            "n" => {
                let Some((address, port)) = parse_lsof_tcp_name(value) else {
                    continue;
                };
                if !seen.insert((port, current_pid)) {
                    continue;
                }
                rows.push(ListeningPort {
                    port,
                    address,
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

#[cfg(all(unix, not(target_os = "linux")))]
fn collect_cwds(pids: &[u32]) -> HashMap<u32, PathBuf> {
    let mut result = HashMap::with_capacity(pids.len());
    for chunk in pids.chunks(100) {
        let pid_list = join_pids(chunk);
        let Ok(output) = Command::new("lsof")
            .args(["-a", "-d", "cwd", "-F", "pn", "-p", &pid_list])
            .output()
        else {
            continue;
        };
        if output.stdout.is_empty() {
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
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
fn collect_ps_info(pids: &[u32]) -> HashMap<u32, PsInfo> {
    let mut result = HashMap::with_capacity(pids.len());
    for chunk in pids.chunks(200) {
        let pid_list = join_pids(chunk);
        let Ok(output) = Command::new("ps")
            .args([
                "-p", &pid_list, "-o", "pid=", "-o", "comm=", "-o", "etime=", "-o", "command=",
            ])
            .output()
        else {
            continue;
        };
        if output.stdout.is_empty() {
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
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
    let mut sockets = parse_proc_net_tcp_file("/proc/net/tcp", false);
    sockets.extend(parse_proc_net_tcp_file("/proc/net/tcp6", true));
    if sockets.is_empty() {
        return Vec::new();
    }

    let mut by_inode: HashMap<u64, Vec<ProcTcpEntry>> = HashMap::with_capacity(sockets.len());
    for socket in sockets {
        by_inode.entry(socket.inode).or_default().push(socket);
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
    let mut seen: HashSet<(u16, Option<u32>)> = HashSet::with_capacity(by_inode.len());
    let mut matched_inodes: HashSet<u64> = HashSet::with_capacity(by_inode.len());

    for entry in proc_entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };

        let matches = linux_socket_matches_for_pid(&entry.path(), &by_inode, &mut matched_inodes);
        if matches.is_empty() {
            continue;
        }

        let info = read_linux_process_info(pid, timebase);
        for socket in matches {
            if !seen.insert((socket.port, Some(pid))) {
                continue;
            }
            rows.push(ListeningPort {
                port: socket.port,
                address: socket.address,
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

    rows.extend(unmatched_linux_sockets(
        &by_inode,
        &matched_inodes,
        &mut seen,
    ));
    rows
}

#[cfg(target_os = "linux")]
fn unmatched_linux_sockets(
    by_inode: &HashMap<u64, Vec<ProcTcpEntry>>,
    matched_inodes: &HashSet<u64>,
    seen: &mut HashSet<(u16, Option<u32>)>,
) -> Vec<ListeningPort> {
    let mut rows = Vec::new();
    for (inode, sockets) in by_inode {
        if matched_inodes.contains(inode) {
            continue;
        }
        for socket in sockets {
            if !seen.insert((socket.port, None)) {
                continue;
            }
            rows.push(ListeningPort {
                port: socket.port,
                address: socket.address.clone(),
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
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
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
    pid: u32,
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct WindowsPortOwnerSnapshot {
    pid: u32,
    process: Option<String>,
    identity: WindowsProcessIdentity,
}

#[cfg(windows)]
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
    let mut seen: HashSet<(u16, Option<u32>)> = HashSet::with_capacity(sockets.len());
    let mut process_cache: HashMap<u32, WindowsProcessInfo> = HashMap::new();

    for socket in sockets {
        if !seen.insert((socket.port, Some(socket.pid))) {
            continue;
        }
        let info = process_cache
            .entry(socket.pid)
            .or_insert_with(|| read_windows_process_info(socket.pid));
        rows.push(ListeningPort {
            port: socket.port,
            address: socket.address,
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

#[cfg(windows)]
fn windows_same_process(current: WindowsProcessIdentity, expected: WindowsProcessIdentity) -> bool {
    if current.pid != expected.pid {
        return false;
    }
    match (current.creation_ticks, expected.creation_ticks) {
        (Some(current), Some(expected)) => current == expected,
        _ => true,
    }
}

#[cfg(windows)]
fn terminate_windows_pid(
    pid: u32,
    expected_identity: Option<WindowsProcessIdentity>,
) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };

    let handle =
        try_open_windows_process(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, pid)
            .map_err(|err| err.to_string())?;
    if let Some(expected) = expected_identity {
        let current = windows_process_identity_from_handle(pid, handle.raw());
        if !windows_same_process(current, expected) {
            return Err(format!(
                "PID {pid} identity changed before termination; aborting kill for safety"
            ));
        }
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
    let content = std::fs::read_to_string(dir.join("package.json")).ok()?;
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
    let content = match std::fs::read_to_string(path) {
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
            if let Some(port) = value.as_integer() {
                result.insert(name.clone(), port as u16);
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
    let content = std::fs::read_to_string(path).unwrap_or_default();
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
    let content = match std::fs::read_to_string(path) {
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

    // Write to a temp file in the same directory, then rename.
    // Same-directory ensures we stay on the same filesystem (rename is atomic).
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let tmp_path = parent.join(format!(".ports.toml.{}.tmp", std::process::id()));
    if std::fs::write(&tmp_path, &content).is_ok() {
        if std::fs::rename(&tmp_path, path).is_err() {
            // rename failed (cross-device?), fall back to direct write
            let _ = std::fs::write(path, content);
            let _ = std::fs::remove_file(&tmp_path);
        }
    } else {
        // Fallback: direct write
        let _ = std::fs::write(path, content);
    }
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

    #[test]
    fn check_port_reports_ipv6_loopback_listener_as_in_use() {
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            return;
        };
        let port = listener.local_addr().unwrap().port();

        assert!(matches!(check_port(port), PortStatus::InUse { .. }));
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn parse_lsof_listen_output_dedupes_dual_stack_same_pid_port() {
        let rows = parse_lsof_listen_output(
            "\
p101
cnode
PTCP
nTCP *:3000 (LISTEN)
nTCP [::1]:3000 (LISTEN)
p202
credis-server
PTCP
nTCP 127.0.0.1:6379 (LISTEN)
",
        );

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pid, Some(101));
        assert_eq!(rows[0].process.as_deref(), Some("node"));
        assert_eq!(rows[0].port, 3000);
        assert_eq!(rows[1].pid, Some(202));
        assert_eq!(rows[1].address.as_deref(), Some("127.0.0.1"));
        assert_eq!(rows[1].port, 6379);
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

    #[cfg(windows)]
    #[test]
    fn windows_same_process_allows_pid_match_when_creation_ticks_are_unavailable() {
        assert!(windows_same_process(
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
