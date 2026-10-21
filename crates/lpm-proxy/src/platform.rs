use super::*;

pub(crate) fn ensure_lpm_root(path: &Path) -> Result<(), ProxyError> {
    std::fs::create_dir_all(path).map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_unix_control_peer(
    stream: &tokio::net::UnixStream,
) -> Result<(), ProxyError> {
    validate_unix_peer_uid(unix_control_peer_uid(stream)?, current_effective_uid())
}

#[cfg(unix)]
pub(crate) fn validate_unix_peer_uid(
    peer_uid: Option<u32>,
    expected_uid: u32,
) -> Result<(), ProxyError> {
    if let Some(peer_uid) = peer_uid
        && peer_uid != expected_uid
    {
        return Err(ProxyError::Ipc(format!(
            "reject control connection from UID {peer_uid}; expected UID {expected_uid}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn current_effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() as u32 }
}

#[cfg(target_os = "linux")]
pub(crate) fn unix_control_peer_uid(
    stream: &tokio::net::UnixStream,
) -> Result<Option<u32>, ProxyError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` points to valid writable storage for `libc::ucred`,
    // `len` is initialized to that storage size, and the file descriptor belongs
    // to a live Unix domain socket accepted by Tokio.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(ProxyError::Ipc(format!(
            "read control connection peer credentials: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful `getsockopt(SO_PEERCRED)` initialized the `ucred`.
    let credentials = unsafe { credentials.assume_init() };
    Ok(Some(credentials.uid))
}

#[cfg(target_os = "macos")]
pub(crate) fn unix_control_peer_uid(
    stream: &tokio::net::UnixStream,
) -> Result<Option<u32>, ProxyError> {
    use std::os::fd::AsRawFd;

    let mut uid = 0 as libc::uid_t;
    let mut gid = 0 as libc::gid_t;
    // SAFETY: `uid` and `gid` are valid writable pointers and the file
    // descriptor belongs to a live Unix domain socket accepted by Tokio.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(ProxyError::Ipc(format!(
            "read control connection peer credentials: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(Some(uid as u32))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn unix_control_peer_uid(
    _stream: &tokio::net::UnixStream,
) -> Result<Option<u32>, ProxyError> {
    Ok(None)
}

#[cfg(unix)]
pub(crate) fn process_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 performs permission/existence checking only.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
pub(crate) fn process_is_running(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return false;
    }
    // SAFETY: OpenProcess validates the PID/access mask and returns null on
    // failure; a non-null handle is closed before returning.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let mut exit_code = 0;
    // SAFETY: `exit_code` is valid writable storage for the queried process
    // handle; Windows reports failure through the return code.
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) != 0 };
    // SAFETY: `handle` is a non-null process handle opened above.
    unsafe {
        CloseHandle(handle);
    }
    ok && exit_code == STILL_ACTIVE as u32
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn process_is_running(_pid: u32) -> bool {
    true
}

/// Give up root for good, becoming `uid` with its primary group and no
/// supplementary groups.
///
/// The privileged forwarder calls this once its low ports are bound, so every
/// connection it relays is opened by the user whose daemon receives it, never
/// by root.
#[cfg(unix)]
pub fn drop_root_privileges(uid: u32) -> Result<(), ProxyError> {
    if uid == 0 {
        return Err(ProxyError::Forwarder(
            "the privileged forwarder must not keep running as root".to_string(),
        ));
    }
    let gid = primary_gid_of(uid)?;
    let os_error = |call: &str| {
        ProxyError::Forwarder(format!(
            "{call} while dropping root for UID {uid}: {}",
            std::io::Error::last_os_error()
        ))
    };
    // SAFETY: `setgroups` reads exactly one group ID from a valid pointer.
    if unsafe { libc::setgroups(1, &gid) } != 0 {
        return Err(os_error("setgroups"));
    }
    // SAFETY: `setgid` and `setuid` take plain IDs and have no memory preconditions.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(os_error("setgid"));
    }
    // SAFETY: as above.
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(os_error("setuid"));
    }
    // SAFETY: these calls only read the process credentials.
    let dropped = unsafe {
        libc::getuid() == uid
            && libc::geteuid() == uid
            && libc::getgid() == gid
            && libc::getegid() == gid
    };
    // SAFETY: `setuid` takes a plain ID; success here would mean root was regainable.
    if !dropped || unsafe { libc::setuid(0) } == 0 {
        return Err(ProxyError::Forwarder(format!(
            "the forwarder could still act as root after switching to UID {uid}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn primary_gid_of(uid: u32) -> Result<libc::gid_t, ProxyError> {
    const MAX_PASSWD_BUFFER: usize = 1 << 20;
    let mut buffer: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call, and `buffer` outlives `entry`'s use.
        let code = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        if code == libc::ERANGE && buffer.len() < MAX_PASSWD_BUFFER {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if code != 0 {
            return Err(ProxyError::Forwarder(format!(
                "look up the account for UID {uid}: {}",
                std::io::Error::from_raw_os_error(code)
            )));
        }
        if found.is_null() {
            return Err(ProxyError::Forwarder(format!(
                "no account exists for UID {uid}"
            )));
        }
        // SAFETY: `getpwuid_r` initialized `entry` because it reported a match.
        return Ok(unsafe { entry.assume_init() }.pw_gid);
    }
}

#[cfg(unix)]
pub(crate) fn read_forwarder_daemon_state(
    path: &Path,
    expected_uid: u32,
) -> Result<ProxyDaemonState, ProxyError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        // O_NONBLOCK keeps a FIFO planted at the path from blocking the open.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| {
            ProxyError::Forwarder(format!(
                "open guarded proxy state {}: {err}",
                path.display()
            ))
        })?;
    let metadata = file.metadata().map_err(|err| {
        ProxyError::Forwarder(format!(
            "read guarded proxy state metadata {}: {err}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state {} is owned by UID {}, expected UID {expected_uid}",
            path.display(),
            metadata.uid()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state {} must not be group/world accessible (mode {mode:o})",
            path.display()
        )));
    }

    let cap_u64 = lpm_common::STATE_FILE_SIZE_CAP_BYTES;
    let cap = usize::try_from(cap_u64).map_err(|_| {
        ProxyError::Forwarder("state file cap does not fit this platform".to_string())
    })?;
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(cap));
    file.by_ref()
        .take(cap_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| {
            ProxyError::Forwarder(format!(
                "read guarded proxy state {}: {err}",
                path.display()
            ))
        })?;
    if bytes.len() > cap {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state {} exceeds {cap} bytes",
            path.display()
        )));
    }
    serde_json::from_slice(&bytes).map_err(|err| {
        ProxyError::Forwarder(format!(
            "parse guarded proxy state {}: {err}",
            path.display()
        ))
    })
}

/// Resolve the backend a guarded forwarder rule delivers to.
///
/// The address comes from the user daemon's own state, so the daemon can
/// bind whichever port is free when it starts. It is accepted only while that
/// daemon is alive and owned by `expected_uid`, and only as `127.0.0.1` on an
/// unprivileged port, which is the only address the daemon binds.
#[cfg(unix)]
pub(crate) fn validate_forwarder_daemon_state(
    state: &ProxyDaemonState,
    expected_uid: u32,
    target: ForwarderTarget,
    mut process_alive: impl FnMut(u32) -> bool,
    mut process_uid: impl FnMut(u32) -> Option<u32>,
) -> Result<SocketAddr, ProxyError> {
    let advertised = match target {
        ForwarderTarget::Https => state.tls_addr.as_deref(),
        ForwarderTarget::HttpRedirect => state.http_redirect_addr.as_deref(),
    }
    .ok_or_else(|| {
        ProxyError::Forwarder(format!(
            "guarded proxy state does not advertise an {target} listener"
        ))
    })?;
    let backend_addr = parse_state_listener_addr(advertised).ok_or_else(|| {
        ProxyError::Forwarder(format!(
            "guarded proxy state advertises an unparseable {target} listener {advertised:?}"
        ))
    })?;
    if backend_addr.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        || backend_addr.port() < 1024
    {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state advertises {target} listener {backend_addr}; expected 127.0.0.1 with port >=1024"
        )));
    }
    if !process_alive(state.pid) {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy daemon PID {} is not running",
            state.pid
        )));
    }
    match process_uid(state.pid) {
        Some(uid) if uid == expected_uid => Ok(backend_addr),
        Some(uid) => Err(ProxyError::Forwarder(format!(
            "guarded proxy daemon PID {} is owned by UID {uid}, expected UID {expected_uid}",
            state.pid
        ))),
        None => Err(ProxyError::Forwarder(format!(
            "could not verify UID for guarded proxy daemon PID {}",
            state.pid
        ))),
    }
}

#[cfg(unix)]
pub(crate) fn parse_state_listener_addr(value: &str) -> Option<SocketAddr> {
    let raw = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .unwrap_or(value);
    raw.parse().ok()
}

#[cfg(target_os = "linux")]
pub(crate) fn process_owner_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_linux_status_effective_uid(&status)
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_status_effective_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

#[cfg(target_os = "macos")]
pub(crate) fn process_owner_uid(pid: u32) -> Option<u32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    // SAFETY: `info` points to writable storage sized for proc_bsdinfo, and
    // proc_pidinfo reports the number of bytes written.
    let written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if written != size as libc::c_int {
        return None;
    }
    // SAFETY: proc_pidinfo wrote a complete proc_bsdinfo when `written == size`.
    let info = unsafe { info.assume_init() };
    Some(info.pbi_uid)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn process_owner_uid(_pid: u32) -> Option<u32> {
    None
}
