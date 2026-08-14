use crate::ports::{self, ProcessIdentity};
use lpm_common::{LocalTarget, LpmError, LpmRoot};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedDevSession {
    #[serde(flatten)]
    session: ActiveDevSession,
    #[serde(default)]
    lpm_identity: Option<ProcessIdentity>,
    #[serde(default)]
    owner_identity: Option<ProcessIdentity>,
    #[serde(default)]
    https_active: bool,
}

/// RAII lease that removes its active-session record when dropped.
pub struct DevSessionLease {
    path: PathBuf,
    record_bytes: Vec<u8>,
}

/// Prepared active-session record that is not discoverable until committed.
pub struct PreparedDevSession {
    path: PathBuf,
    staged_path: PathBuf,
    record_bytes: Vec<u8>,
    previous_record_bytes: Option<Vec<u8>>,
}

/// Published session update that restores the previous record unless finalized.
pub struct PublishedDevSession {
    lease: Option<DevSessionLease>,
    previous_record_bytes: Option<Vec<u8>>,
    finalized: bool,
}

impl DevSessionLease {
    /// Persist an active endpoint under the current LPM data root.
    pub fn register(
        project_dir: &Path,
        target: LocalTarget,
        owner_pid: Option<u32>,
        owner_identity: Option<ProcessIdentity>,
        service: Option<String>,
        https_active: bool,
    ) -> Result<Self, LpmError> {
        PreparedDevSession::prepare(
            project_dir,
            target,
            owner_pid,
            owner_identity,
            service,
            https_active,
        )?
        .commit()
    }
}

impl PreparedDevSession {
    /// Serialize and durably stage a session record without publishing it.
    pub fn prepare(
        project_dir: &Path,
        target: LocalTarget,
        owner_pid: Option<u32>,
        owner_identity: Option<ProcessIdentity>,
        service: Option<String>,
        https_active: bool,
    ) -> Result<Self, LpmError> {
        let root = LpmRoot::from_env()?;
        Self::prepare_in_root(
            &root,
            project_dir,
            target,
            owner_pid,
            owner_identity,
            service,
            https_active,
        )
    }

    fn prepare_in_root(
        root: &LpmRoot,
        project_dir: &Path,
        target: LocalTarget,
        owner_pid: Option<u32>,
        owner_identity: Option<ProcessIdentity>,
        service: Option<String>,
        https_active: bool,
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
        let lpm_identity = ports::process_identity_for_pid(lpm_pid);
        let owner_identity = match (owner_pid, owner_identity) {
            (Some(owner_pid), Some(expected)) => {
                let current = ports::process_identity_for_pid(owner_pid).ok_or_else(|| {
                    LpmError::Script(
                        "verified dev endpoint owner exited before session publication".to_string(),
                    )
                })?;
                if current != expected {
                    return Err(LpmError::Script(
                        "verified dev endpoint owner changed before session publication"
                            .to_string(),
                    ));
                }
                Some(expected)
            }
            (Some(_), None) | (None, None) => None,
            (None, Some(_)) => {
                return Err(LpmError::Script(
                    "dev endpoint identity is missing its owner PID".to_string(),
                ));
            }
        };
        let persisted = PersistedDevSession {
            session: record.clone(),
            lpm_identity,
            owner_identity,
            https_active,
        };
        let path = directory.join(format!(
            "{lpm_pid}-{}.json",
            session_key(&record.project_dir, record.service.as_deref())
        ));
        let bytes = serde_json::to_vec(&persisted)
            .map_err(|error| LpmError::Script(format!("serialize dev endpoint: {error}")))?;
        let staged_path = directory.join(format!(
            ".{}-{:032x}.next",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("session"),
            rand::random::<u128>()
        ));
        lpm_common::write_file_atomic(&staged_path, &bytes)?;
        set_private_file_permissions(&staged_path)?;
        let previous_record_bytes = read_existing_record(&path)?;
        Ok(Self {
            path,
            staged_path,
            record_bytes: bytes,
            previous_record_bytes,
        })
    }

    /// Atomically publish the prepared record and return its cleanup lease.
    pub fn commit(self) -> Result<DevSessionLease, LpmError> {
        Ok(self.commit_reversible()?.finalize())
    }

    /// Publish the prepared record while retaining enough state to roll it back.
    pub fn commit_reversible(self) -> Result<PublishedDevSession, LpmError> {
        self.commit_reversible_with_directory_sync(sync_directory)
    }

    fn commit_reversible_with_directory_sync(
        self,
        sync_directory: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<PublishedDevSession, LpmError> {
        std::fs::rename(&self.staged_path, &self.path)?;
        if let Some(directory) = self.path.parent()
            && let Err(error) = sync_directory(directory)
        {
            if let Err(rollback_error) =
                restore_session_record(&self.path, self.previous_record_bytes.as_deref())
            {
                return Err(LpmError::Script(format!(
                    "publish dev session: {error}; restoring the previous session also failed: {rollback_error}"
                )));
            }
            return Err(LpmError::Io(error));
        }
        Ok(PublishedDevSession {
            lease: Some(DevSessionLease {
                path: self.path.clone(),
                record_bytes: self.record_bytes.clone(),
            }),
            previous_record_bytes: self.previous_record_bytes.clone(),
            finalized: false,
        })
    }
}

impl PublishedDevSession {
    /// Keep the published session and transfer its cleanup lease to the caller.
    pub fn finalize(mut self) -> DevSessionLease {
        self.finalized = true;
        self.lease
            .take()
            .expect("published session must retain its lease until finalization")
    }

    /// Restore the record that existed before this session was published.
    pub fn rollback(mut self) -> Result<(), LpmError> {
        let result = self.rollback_inner();
        self.finalized = true;
        result
    }

    fn rollback_inner(&mut self) -> Result<(), LpmError> {
        let lease = self
            .lease
            .take()
            .expect("published session rollback must retain its lease");
        let path = lease.path.clone();
        drop(lease);
        restore_session_record(&path, self.previous_record_bytes.as_deref())
    }
}

impl Drop for PublishedDevSession {
    fn drop(&mut self) {
        if !self.finalized
            && let Err(error) = self.rollback_inner()
        {
            tracing::error!(%error, "failed to roll back an unfinalized dev session");
        }
    }
}

impl Drop for PreparedDevSession {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.staged_path);
    }
}

impl Drop for DevSessionLease {
    fn drop(&mut self) {
        if lpm_common::read_file_capped(&self.path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .is_ok_and(|current| current == self.record_bytes)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn read_existing_record(path: &Path) -> Result<Option<Vec<u8>>, LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            lpm_common::read_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                .map(Some)
                .map_err(|error| LpmError::Script(format!("read previous dev session: {error}")))
        }
        Ok(_) => Err(LpmError::Script(format!(
            "dev session path {} is not a regular file",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(LpmError::Script(format!(
            "inspect previous dev session {}: {error}",
            path.display()
        ))),
    }
}

fn restore_session_record(path: &Path, previous: Option<&[u8]>) -> Result<(), LpmError> {
    match previous {
        Some(bytes) => {
            lpm_common::write_file_atomic(path, bytes)?;
            set_private_file_permissions(path)?;
        }
        None => match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(LpmError::Io(error)),
        },
    }
    if let Some(directory) = path.parent() {
        sync_directory(directory)?;
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

fn session_key(project_dir: &Path, service: Option<&str>) -> String {
    use sha2::Digest as _;

    let mut digest = sha2::Sha256::new();
    digest.update(project_dir.as_os_str().as_encoded_bytes());
    digest.update([0]);
    if let Some(service) = service {
        digest.update(service.as_bytes());
    }
    hex::encode(&digest.finalize()[..12])
}

/// Discover active, listener-backed `lpm dev` sessions for the current user.
pub fn discover_active_sessions() -> Result<Vec<ActiveDevSession>, LpmError> {
    let root = LpmRoot::from_env()?;
    discover_active_sessions_in_root(&root, false)
}

/// Discover active `lpm dev` sessions that currently terminate local HTTPS.
pub fn discover_active_https_sessions() -> Result<Vec<ActiveDevSession>, LpmError> {
    let root = LpmRoot::from_env()?;
    discover_active_sessions_in_root(&root, true)
}

fn discover_active_sessions_in_root(
    root: &LpmRoot,
    https_only: bool,
) -> Result<Vec<ActiveDevSession>, LpmError> {
    let directory = root.dev_sessions_dir();
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    let mut records = Vec::new();
    for entry in entries.take(MAX_SESSION_RECORDS).flatten() {
        let path = entry.path();
        let Some(record) = read_session_record(&path) else {
            continue;
        };
        records.push((path, record));
    }
    let listeners = ports::list_listening_ports();
    let mut pids = HashSet::with_capacity(records.len() * 2);
    for (_, record) in &records {
        pids.insert(record.session.lpm_pid);
        if let Some(owner_pid) = record.session.owner_pid {
            pids.insert(owner_pid);
        }
    }
    let identities = ports::process_identities_for_pids(&pids);
    let mut active = Vec::with_capacity(records.len());
    for (path, record) in records {
        if persisted_session_is_active(&record, &listeners, &identities)
            && (!https_only || record.https_active)
        {
            active.push(record.session);
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

fn listener_matches_session(
    record: &ActiveDevSession,
    listener: &crate::ports::ListeningPort,
) -> bool {
    listener.listens_on(record.target.address, record.target.port)
        && record
            .owner_pid
            .is_none_or(|owner_pid| listener.pid == Some(owner_pid))
}

fn persisted_session_is_active(
    record: &PersistedDevSession,
    listeners: &[crate::ports::ListeningPort],
    identities: &std::collections::HashMap<u32, ProcessIdentity>,
) -> bool {
    let session = &record.session;
    let Some(lpm_identity) = record.lpm_identity.as_ref() else {
        return false;
    };
    if identities.get(&session.lpm_pid) != Some(lpm_identity) {
        return false;
    }
    let (Some(owner_pid), Some(owner_identity)) =
        (session.owner_pid, record.owner_identity.as_ref())
    else {
        return false;
    };
    identities.get(&owner_pid) == Some(owner_identity)
        && session.target.is_loopback()
        && listeners
            .iter()
            .any(|listener| listener_matches_session(session, listener))
}

fn read_session_record(path: &Path) -> Option<PersistedDevSession> {
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

    fn process_identity(value: &str) -> ProcessIdentity {
        serde_json::from_value(serde_json::Value::String(value.to_string())).unwrap()
    }

    fn persisted_session() -> PersistedDevSession {
        PersistedDevSession {
            session: ActiveDevSession {
                lpm_pid: 10,
                owner_pid: Some(20),
                project_dir: PathBuf::from("project"),
                service: Some("web".to_string()),
                target: LocalTarget::loopback(LocalScheme::Http, 5173),
            },
            lpm_identity: Some(process_identity("lpm-10")),
            owner_identity: Some(process_identity("owner-20")),
            https_active: true,
        }
    }

    fn persisted_session_listener() -> crate::ports::ListeningPort {
        crate::ports::ListeningPort {
            port: 5173,
            address: Some("127.0.0.1".to_string()),
            address_family: Some(crate::ports::ListeningAddressFamily::Ipv4),
            pid: Some(20),
            process: None,
            command: None,
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: None,
        }
    }

    #[test]
    fn legacy_session_without_process_identities_is_unverifiable() {
        let mut record = persisted_session();
        record.lpm_identity = None;
        record.owner_identity = None;
        let identities = std::collections::HashMap::from([
            (10, process_identity("lpm-10")),
            (20, process_identity("owner-20")),
        ]);

        assert!(!persisted_session_is_active(
            &record,
            &[persisted_session_listener()],
            &identities,
        ));
    }

    #[test]
    fn persisted_session_rejects_reused_listener_owner_identity() {
        let record = persisted_session();
        let identities = std::collections::HashMap::from([
            (10, process_identity("lpm-10")),
            (20, process_identity("reused-owner-20")),
        ]);

        assert!(!persisted_session_is_active(
            &record,
            &[persisted_session_listener()],
            &identities,
        ));
    }

    #[test]
    fn persisted_session_rejects_reused_lpm_process_identity() {
        let record = persisted_session();
        let identities = std::collections::HashMap::from([
            (10, process_identity("reused-lpm-10")),
            (20, process_identity("owner-20")),
        ]);

        assert!(!persisted_session_is_active(
            &record,
            &[persisted_session_listener()],
            &identities,
        ));
    }

    #[test]
    fn persisted_session_process_identities_round_trip() {
        let record = persisted_session();
        let bytes = serde_json::to_vec(&record).unwrap();

        let decoded: PersistedDevSession = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(decoded, record);
    }

    #[test]
    fn persisted_session_without_https_marker_defaults_to_plain_http() {
        let record = persisted_session();
        let mut value = serde_json::to_value(record).unwrap();
        value.as_object_mut().unwrap().remove("httpsActive");

        let decoded: PersistedDevSession = serde_json::from_value(value).unwrap();

        assert!(!decoded.https_active);
    }

    #[test]
    fn session_listener_match_rejects_a_different_loopback_address_family() {
        let record = ActiveDevSession {
            lpm_pid: 10,
            owner_pid: Some(20),
            project_dir: PathBuf::from("project"),
            service: Some("web".to_string()),
            target: LocalTarget::loopback(LocalScheme::Http, 5173),
        };
        let listener = crate::ports::ListeningPort {
            port: 5173,
            address: Some("::1".to_string()),
            address_family: Some(crate::ports::ListeningAddressFamily::Ipv6),
            pid: Some(20),
            process: None,
            command: None,
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: None,
        };

        assert!(!listener_matches_session(&record, &listener));
    }

    #[test]
    fn session_lease_removes_its_record_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(temp.path().join("lpm"));
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let lease = PreparedDevSession::prepare_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 5173),
            Some(42),
            None,
            None,
            false,
        )
        .unwrap()
        .commit()
        .unwrap();
        let path = lease.path.clone();
        assert!(path.is_file());

        drop(lease);

        assert!(!path.exists());
    }

    #[test]
    fn replacement_session_is_atomic_and_survives_the_previous_lease_drop() {
        let temp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(temp.path().join("lpm"));
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let old = PreparedDevSession::prepare_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 5173),
            Some(42),
            None,
            Some("web".into()),
            false,
        )
        .unwrap()
        .commit()
        .unwrap();

        let new = PreparedDevSession::prepare_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 6173),
            Some(43),
            None,
            Some("web".into()),
            false,
        )
        .unwrap()
        .commit()
        .unwrap();

        let records: Vec<_> = std::fs::read_dir(root.dev_sessions_dir())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(records.len(), 1);
        let record: ActiveDevSession = serde_json::from_slice(
            &lpm_common::read_file_capped(
                &records[0].path(),
                lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(record.target.port, 6173);

        drop(old);
        assert!(new.path.exists());
        drop(new);
    }

    #[test]
    fn prepared_session_is_not_discoverable_until_commit() {
        let temp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(temp.path().join("lpm"));
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let prepared = PreparedDevSession::prepare_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 5173),
            Some(42),
            None,
            Some("web".into()),
            false,
        )
        .unwrap();

        assert!(!prepared.path.exists());
        assert!(prepared.staged_path.exists());

        let lease = prepared.commit().unwrap();
        assert!(lease.path.exists());
    }

    #[test]
    fn failed_session_directory_sync_restores_the_previous_record() {
        let temp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(temp.path().join("lpm"));
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let old = PreparedDevSession::prepare_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 5173),
            Some(42),
            None,
            Some("web".into()),
            false,
        )
        .unwrap()
        .commit()
        .unwrap();
        let old_bytes = old.record_bytes.clone();
        let new = PreparedDevSession::prepare_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 6173),
            Some(43),
            None,
            Some("web".into()),
            false,
        )
        .unwrap();

        let error = match new.commit_reversible_with_directory_sync(|_| {
            Err(std::io::Error::other("injected sync failure"))
        }) {
            Ok(_) => panic!("session publication unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("injected sync failure"));
        assert_eq!(std::fs::read(&old.path).unwrap(), old_bytes);
    }

    #[test]
    fn unfinalized_session_publication_restores_the_previous_record() {
        let temp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(temp.path().join("lpm"));
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let old = PreparedDevSession::prepare_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 5173),
            Some(42),
            None,
            Some("web".into()),
            false,
        )
        .unwrap()
        .commit()
        .unwrap();
        let old_bytes = old.record_bytes.clone();
        let new = PreparedDevSession::prepare_in_root(
            &root,
            &project,
            LocalTarget::loopback(LocalScheme::Http, 6173),
            Some(43),
            None,
            Some("web".into()),
            false,
        )
        .unwrap();

        let publication = new.commit_reversible().unwrap();
        assert_ne!(std::fs::read(&old.path).unwrap(), old_bytes);
        publication.rollback().unwrap();

        assert_eq!(std::fs::read(&old.path).unwrap(), old_bytes);
    }
}
