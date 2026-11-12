use super::*;

pub fn proxy_state_path_from_env() -> Result<PathBuf, ProxyError> {
    Ok(lpm_common::LpmRoot::from_env()
        .map_err(|err| ProxyError::StatePath(err.to_string()))?
        .proxy_state())
}

#[cfg(unix)]
pub fn proxy_socket_path_from_env() -> Result<PathBuf, ProxyError> {
    Ok(lpm_common::LpmRoot::from_env()
        .map_err(|err| ProxyError::StatePath(err.to_string()))?
        .proxy_socket())
}

#[cfg(windows)]
pub fn proxy_pipe_name_from_env() -> Result<String, ProxyError> {
    let root =
        lpm_common::LpmRoot::from_env().map_err(|err| ProxyError::StatePath(err.to_string()))?;
    Ok(proxy_pipe_name_for_root(root.root()))
}

/// The control pipe of the proxy for the LPM home at `root`: one name for
/// the home whatever its spelling, as [`pipe_root_key`] reads it, and
/// whatever links lead to it.
pub fn proxy_pipe_name_for_root(root: &Path) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let identity = lpm_common::LpmRoot::from_dir(root).identity();
    let mut hash = FNV_OFFSET;
    for byte in pipe_root_key(&identity.to_string_lossy()).as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!(r"\\.\pipe\lpm-proxy-{hash:016x}")
}

/// The text a home's pipe is named after: the home `root` spells, in
/// lower case, with `/` for every separator, and without a `\\?\` prefix,
/// an empty or `.` name or a trailing separator, so that `lpm proxy` finds
/// the proxy however its home is spelled.
pub(crate) fn pipe_root_key(root: &str) -> String {
    let text = root.replace('\\', "/").to_lowercase();
    let (lead, rest) = if let Some(unc) = text.strip_prefix("//?/unc/") {
        ("//", unc)
    } else if let Some(local) = text.strip_prefix("//?/") {
        ("", local)
    } else if let Some(unc) = text.strip_prefix("//") {
        ("//", unc)
    } else if let Some(absolute) = text.strip_prefix('/') {
        ("/", absolute)
    } else {
        ("", text.as_str())
    };
    let mut key = String::with_capacity(text.len());
    key.push_str(lead);
    for name in rest
        .split('/')
        .filter(|name| !name.is_empty() && *name != ".")
    {
        if key.len() > lead.len() {
            key.push('/');
        }
        key.push_str(name);
    }
    key
}

pub fn read_status() -> Result<ProxyStatus, ProxyError> {
    read_status_from_path(&proxy_state_path_from_env()?)
}

pub fn read_status_from_path(path: &std::path::Path) -> Result<ProxyStatus, ProxyError> {
    let Some(bytes) =
        lpm_common::read_capped_state_file(path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|err| ProxyError::StateRead(err.to_string()))?
    else {
        return Ok(ProxyStatus::not_running());
    };

    match serde_json::from_slice::<ProxyDaemonState>(&bytes) {
        Ok(state) => Ok(ProxyStatus::stale(
            Some(state.pid),
            state.http_addr,
            state.http_redirect_addr,
            state.tls_addr,
            state.public_tls_addr,
            None,
        )),
        Err(err) => Ok(ProxyStatus::stale(
            None,
            None,
            None,
            None,
            None,
            Some(err.to_string()),
        )),
    }
}
