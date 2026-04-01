//! Certificate file path management.
//!
//! CA certs: `~/.lpm/certs/rootCA.pem` + `rootCA-key.pem` (global, one per machine)
//! Project certs: `{project}/.lpm/certs/cert.pem` + `key.pem` (per-project)

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Directory for the global root CA: `~/.lpm/certs/`
pub fn ca_dir() -> Result<PathBuf, LpmError> {
    let home = dirs::home_dir()
        .ok_or_else(|| LpmError::Cert("could not determine home directory".into()))?;
    Ok(home.join(".lpm").join("certs"))
}

/// Path to the root CA certificate: `~/.lpm/certs/rootCA.pem`
pub fn ca_cert_path() -> Result<PathBuf, LpmError> {
    Ok(ca_dir()?.join("rootCA.pem"))
}

/// Path to the root CA private key: `~/.lpm/certs/rootCA-key.pem`
pub fn ca_key_path() -> Result<PathBuf, LpmError> {
    Ok(ca_dir()?.join("rootCA-key.pem"))
}

/// Directory for project-specific certificates: `{project}/.lpm/certs/`
pub fn project_cert_dir(project_dir: &Path) -> Result<PathBuf, LpmError> {
    Ok(project_dir.join(".lpm").join("certs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_paths_are_under_home() {
        let ca = ca_dir().unwrap();
        assert!(ca.ends_with(".lpm/certs"));

        let cert = ca_cert_path().unwrap();
        assert!(cert.ends_with("rootCA.pem"));

        let key = ca_key_path().unwrap();
        assert!(key.ends_with("rootCA-key.pem"));
    }

    #[test]
    fn project_paths_are_under_project() {
        let project = Path::new("/tmp/my-project");
        let dir = project_cert_dir(project).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/my-project/.lpm/certs"));
    }
}
