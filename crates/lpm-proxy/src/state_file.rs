use super::*;

pub(crate) fn write_state_file(path: &Path, state: &ProxyDaemonState) -> Result<(), ProxyError> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        ProxyError::StateWrite(format!("state path has no parent: {}", path.display()))
    })?;
    ensure_lpm_root(parent)?;
    let tmp_path = parent.join(format!(".proxy.json.{}.tmp", std::process::id()));
    let bytes =
        serde_json::to_vec_pretty(state).map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    }
    file.write_all(&bytes)
        .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    std::fs::rename(&tmp_path, path).map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    Ok(())
}
