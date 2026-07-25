use super::*;

pub(crate) fn write_state_file(path: &Path, state: &ProxyDaemonState) -> Result<(), ProxyError> {
    let parent = path.parent().ok_or_else(|| {
        ProxyError::StateWrite(format!("state path has no parent: {}", path.display()))
    })?;
    ensure_lpm_root(parent)?;
    let bytes =
        serde_json::to_vec_pretty(state).map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    lpm_common::write_file_atomic_with_options(
        path,
        &bytes,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
    )
    .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    Ok(())
}
