use super::prelude::*;

pub fn security_dir() -> Result<PathBuf, LpmError> {
    #[cfg(test)]
    if let Ok(path) = std::env::var(SECURITY_DIR_ENV)
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    Ok(lpm_common::LpmRoot::from_env()?.root().join("security"))
}

pub(super) fn approved_posture_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("approved-posture.json"))
}

pub(super) fn unlocks_dir() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("unlocks"))
}

pub(super) fn approved_projects_dir() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("projects"))
}

pub(super) fn approved_global_trust_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("approved-global-trust.json"))
}

pub(super) fn audit_log_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("audit.jsonl"))
}

pub(super) fn audit_lock_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("audit.lock"))
}

pub(super) fn signing_secret_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("signing-secret.hex"))
}

pub(super) fn audit_head_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("audit-head.json"))
}
