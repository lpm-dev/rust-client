use crate::LpmError;

pub fn evaluate_sudo_policy(
    effective_uid: u32,
    sudo_uid: Option<&str>,
    sudo_user: Option<&str>,
) -> Result<(), String> {
    if effective_uid != 0 || (sudo_uid.is_none() && sudo_user.is_none()) {
        return Ok(());
    }

    if let Some(uid) = sudo_uid
        && (uid.is_empty() || uid.parse::<u32>().is_err())
    {
        return Err(format!("malformed SUDO_UID value {uid:?}"));
    }
    if let Some(user) = sudo_user
        && (user.is_empty() || user.chars().any(char::is_control))
    {
        return Err(format!("malformed SUDO_USER value {user:?}"));
    }

    Err("the effective user is root and sudo identity variables are present".to_string())
}

#[cfg(unix)]
pub fn enforce_sudo_policy() -> Result<(), LpmError> {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let actual_effective_uid = unsafe { libc::geteuid() };
    // This test seam can only tighten policy: it simulates root, never disguises root as non-root.
    let effective_uid = if std::env::var_os("LPM_TEST_FORCE_ROOT_SUDO_POLICY").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        0
    } else {
        actual_effective_uid
    };
    if effective_uid != 0 {
        return Ok(());
    }

    let sudo_uid = std::env::var_os("SUDO_UID");
    let sudo_user = std::env::var_os("SUDO_USER");
    let sudo_uid_str = sudo_uid
        .as_deref()
        .map(|value| {
            value
                .to_str()
                .ok_or_else(|| "malformed non-Unicode SUDO_UID value".to_string())
        })
        .transpose()
        .map_err(LpmError::SudoExecution)?;
    let sudo_user_str = sudo_user
        .as_deref()
        .map(|value| {
            value
                .to_str()
                .ok_or_else(|| "malformed non-Unicode SUDO_USER value".to_string())
        })
        .transpose()
        .map_err(LpmError::SudoExecution)?;

    evaluate_sudo_policy(effective_uid, sudo_uid_str, sudo_user_str)
        .map_err(LpmError::SudoExecution)
}

#[cfg(not(unix))]
pub fn enforce_sudo_policy() -> Result<(), LpmError> {
    Ok(())
}
