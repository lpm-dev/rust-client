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

pub fn proxy_pipe_name_for_root(root: &Path) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let normalized = root.to_string_lossy().replace('\\', "/").to_lowercase();
    let mut hash = FNV_OFFSET;
    for byte in normalized.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!(r"\\.\pipe\lpm-proxy-{hash:016x}")
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
            None,
        )),
        Err(err) => Ok(ProxyStatus::stale(
            None,
            None,
            None,
            None,
            Some(err.to_string()),
        )),
    }
}
