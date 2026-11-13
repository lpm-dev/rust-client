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
pub fn proxy_pipe_names_from_env() -> Result<Vec<String>, ProxyError> {
    let root =
        lpm_common::LpmRoot::from_env().map_err(|err| ProxyError::StatePath(err.to_string()))?;
    Ok(proxy_pipe_names_for_root(root.root()))
}

/// The control pipe of the proxy for the LPM home at `root`: one name for
/// the home whatever its spelling, as [`pipe_root_key`] reads it. Links on
/// the way aren't resolved: an elevated session doesn't see the user's
/// mapped or `subst` drives, so a name resolved there would differ from the
/// one the user's own proxy took.
pub fn proxy_pipe_name_for_root(root: &Path) -> String {
    pipe_name_for_key(&pipe_root_key(&root.to_string_lossy()))
}

/// The control pipes to look for the proxy of the home at `root` on, in
/// order: [`proxy_pipe_name_for_root`]'s, then, where they differ, the names
/// earlier releases gave it, after the home exactly as spelled in lower case
/// with `/` separators (see [`earlier_pipe_keys`]). A proxy one of them
/// started keeps that name until it stops, so `lpm proxy` still finds it
/// after an upgrade, and a new proxy doesn't start beside it.
pub fn proxy_pipe_names_for_root(root: &Path) -> Vec<String> {
    let spelled = root.to_string_lossy();
    let key = pipe_root_key(&spelled);
    let earlier = earlier_pipe_keys(&spelled, &key);
    let mut names = Vec::with_capacity(1 + earlier.len());
    names.push(pipe_name_for_key(&key));
    for key in earlier.iter().flatten() {
        let name = pipe_name_for_key(key);
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// The texts an earlier release may have named the pipe of the home
/// `spelled` names after, `key` being [`pipe_root_key`]'s: the home as
/// `spelled`, and for a Windows path also `key` with a trailing separator,
/// a `\\?\` prefix or both, the ways one home's spellings most often
/// differ that [`pipe_root_key`] reads as one.
fn earlier_pipe_keys(spelled: &str, key: &str) -> [Option<String>; 4] {
    let as_spelled = Some(spelled.replace('\\', "/").to_lowercase());
    let verbatim = if let Some(unc) = key.strip_prefix("//") {
        format!("//?/unc/{unc}")
    } else if key.as_bytes().get(1) == Some(&b':') {
        format!("//?/{key}")
    } else {
        return [as_spelled, None, None, None];
    };
    let with_separator = |key: &str| {
        if key.ends_with('/') {
            key.to_owned()
        } else {
            format!("{key}/")
        }
    };
    [
        as_spelled,
        Some(with_separator(key)),
        Some(with_separator(&verbatim)),
        Some(verbatim),
    ]
}

fn pipe_name_for_key(key: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for byte in key.as_bytes() {
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
