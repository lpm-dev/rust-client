use lpm_common::{LocalTarget, LpmError, LpmRoot};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_SESSION_RECORDS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Live `lpm dev` endpoint record used by standalone tunnel discovery.
pub struct ActiveDevSession {
    /// LPM process that owns the session record.
    pub lpm_pid: u32,
    /// Child process that owns the listener when known.
    pub owner_pid: Option<u32>,
    /// Canonical project directory.
    pub project_dir: PathBuf,
    /// Primary service name for a multi-service session.
    pub service: Option<String>,
    /// Verified child endpoint.
    pub target: LocalTarget,
}

/// RAII lease that removes its active-session record when dropped.
pub struct DevSessionLease {
    path: PathBuf,
}

impl DevSessionLease {
    /// Persist an active endpoint under the current LPM data root.
    pub fn register(
        project_dir: &Path,
        target: LocalTarget,
        owner_pid: Option<u32>,
        service: Option<String>,
    ) -> Result<Self, LpmError> {
        let root = LpmRoot::from_env()?;
        Self::register_in_root(&root, project_dir, target, owner_pid, service)
    }

    fn register_in_root(
        root: &LpmRoot,
        project_dir: &Path,
        target: LocalTarget,
        owner_pid: Option<u32>,
        service: Option<String>,
    ) -> Result<Self, LpmError> {
        let directory = root.dev_sessions_dir();
        std::fs::create_dir_all(&directory)?;
        set_private_directory_permissions(&directory)?;
        let lpm_pid = std::process::id();
        let record = ActiveDevSession {
            lpm_pid,
            owner_pid,
            project_dir: project_dir
                .canonicalize()
                .unwrap_or_else(|_| project_dir.to_path_buf()),
            service,
            target,
        };
        let path = directory.join(format!(
            "{lpm_pid}-{}-{}.json",
            owner_pid.unwrap_or_default(),
            record.target.port
        ));
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| LpmError::Script(format!("serialize dev endpoint: {error}")))?;
        lpm_common::write_file_atomic(&path, &bytes)?;
        set_private_file_permissions(&path)?;
        Ok(Self { path })
    }
}

impl Drop for DevSessionLease {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Discover active, listener-backed `lpm dev` sessions for the current user.
pub fn discover_active_sessions() -> Result<Vec<ActiveDevSession>, LpmError> {
    let root = LpmRoot::from_env()?;
    discover_active_sessions_in_root(&root)
}

fn discover_active_sessions_in_root(root: &LpmRoot) -> Result<Vec<ActiveDevSession>, LpmError> {
    let directory = root.dev_sessions_dir();
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    let listeners = crate::ports::list_listening_ports();
    let mut active = Vec::new();
    for entry in entries.take(MAX_SESSION_RECORDS).flatten() {
        let path = entry.path();
        let Some(record) = read_session_record(&path) else {
            continue;
        };
        let listener_matches = listeners.iter().any(|listener| {
            listener.port == record.target.port
                && record
                    .owner_pid
                    .is_none_or(|owner_pid| listener.pid == Some(owner_pid))
        });
        if crate::ports::process_is_running(record.lpm_pid)
            && listener_matches
            && record.target.is_loopback()
        {
            active.push(record);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
    active.sort_by(|left, right| {
        left.project_dir
            .cmp(&right.project_dir)
            .then_with(|| left.service.cmp(&right.service))
            .then_with(|| left.target.port.cmp(&right.target.port))
    });
    Ok(active)
}

fn read_session_record(path: &Path) -> Option<ActiveDevSession> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let bytes = lpm_common::read_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_common::LocalScheme;

    #[test]
    fn session_lease_removes_its_record_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(temp.path().join("lpm"));
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let lease = DevSessionLease::register_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 5173),
            Some(42),
            None,
        )
        .unwrap();
        let path = lease.path.clone();
        assert!(path.is_file());

        drop(lease);

        assert!(!path.exists());
    }
}
