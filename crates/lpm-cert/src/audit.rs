//! Append-only JSONL audit trail for trust-store and CA mutations.
//!
//! Path: `~/.lpm/audit/cert.jsonl` (debug/test builds can override it via
//! `LPM_CERT_AUDIT_DIR`).
//! Dir mode 0o700, file mode 0o600 (Unix). One event per line, RFC 3339 timestamp.
//! Best-effort fsync: losing the last entry on hard crash is acceptable for this
//! audit trail.

use cap_std::fs::{Dir, OpenOptions};
use lpm_common::LpmError;
use serde::Serialize;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const AUDIT_DIR_ENV: &str = "LPM_CERT_AUDIT_DIR";
const AUDIT_LOG_SIZE_CAP_BYTES: u64 = lpm_common::STATE_FILE_SIZE_CAP_BYTES;
#[cfg(test)]
static FAIL_APPEND_COUNTDOWN: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

struct AuditLog {
    path: PathBuf,
    dir: Dir,
}

impl AuditLog {
    fn open(create: bool) -> Result<Option<Self>, LpmError> {
        let configured = configured_audit_dir()?;
        let mut parent = Dir::open_ambient_dir(&configured.base, cap_std::ambient_authority())
            .map_err(|error| {
                LpmError::Cert(format!(
                    "failed to open audit base directory {}: {error}",
                    configured.base.display()
                ))
            })?;
        for component in &configured.components {
            let open = || {
                let parent_file = parent.try_clone()?.into_std_file();
                cap_primitives::fs::open_dir_nofollow(&parent_file, std::path::Path::new(component))
                    .map(Dir::from_std_file)
            };
            let next = match open() {
                Ok(dir) => dir,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => {
                    return Ok(None);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                    match parent.create_dir(component) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => {
                            return Err(LpmError::Cert(format!(
                                "failed to create audit directory {}: {error}",
                                configured.path.display()
                            )));
                        }
                    }
                    open().map_err(|error| {
                        LpmError::Cert(format!(
                            "failed to open audit directory {} without following links: {error}",
                            configured.path.display()
                        ))
                    })?
                }
                Err(error) => {
                    return Err(LpmError::Cert(format!(
                        "failed to open audit directory {} without following links: {error}",
                        configured.path.display()
                    )));
                }
            };
            tighten_audit_directory(&next)?;
            parent = next;
        }
        let dir = parent;
        Ok(Some(Self {
            path: configured.path,
            dir,
        }))
    }

    fn acquire_lock(&self) -> Result<lpm_common::SingleFileExclusiveLockHandle, LpmError> {
        let file = self.open_file("cert.lock", true, false)?;
        lpm_common::acquire_single_file_exclusive_lock_from_file(file.into_std())
    }

    fn open_file(
        &self,
        name: &str,
        create: bool,
        append: bool,
    ) -> Result<cap_std::fs::File, LpmError> {
        let file = if create {
            let mut opened = None;
            for _ in 0..16 {
                reject_linked_audit_entry(&self.dir, name, &self.path)?;
                match self.open_entry(name, true, false, append) {
                    Ok(file) => {
                        opened = Some(file);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        match self.open_entry(name, true, true, append) {
                            Ok(file) => {
                                opened = Some(file);
                                break;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                            Err(error) => return Err(self.open_file_error(name, error)),
                        }
                    }
                    Err(error) => return Err(self.open_file_error(name, error)),
                }
            }
            opened.ok_or_else(|| {
                LpmError::Cert(format!(
                    "audit file {} changed repeatedly while opening",
                    self.path.join(name).display()
                ))
            })?
        } else {
            reject_linked_audit_entry(&self.dir, name, &self.path)?;
            self.open_entry(name, false, false, append)
                .map_err(|error| self.open_file_error(name, error))?
        };
        if !file
            .metadata()
            .map_err(|error| {
                LpmError::Cert(format!("failed to inspect audit file {name}: {error}"))
            })?
            .is_file()
        {
            return Err(LpmError::Cert(format!(
                "audit path {} is not a regular file",
                self.path.join(name).display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.try_clone()
                .and_then(|file| {
                    file.into_std()
                        .set_permissions(std::fs::Permissions::from_mode(0o600))
                })
                .map_err(|error| {
                    LpmError::Cert(format!("failed to tighten audit file permissions: {error}"))
                })?;
        }
        Ok(file)
    }

    fn open_entry(
        &self,
        name: &str,
        writable: bool,
        create_new: bool,
        append: bool,
    ) -> std::io::Result<cap_std::fs::File> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};

        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(writable || append)
            .create_new(create_new)
            .append(append)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        self.dir.open_with(name, &options)
    }

    fn open_file_error(&self, name: &str, error: std::io::Error) -> LpmError {
        LpmError::Cert(format!(
            "failed to open audit file {}: {error}",
            self.path.join(name).display()
        ))
    }

    fn read(&self) -> Result<Option<String>, LpmError> {
        if !entry_exists(&self.dir, "cert.jsonl", &self.path)? {
            return Ok(None);
        }
        let file = self.open_file("cert.jsonl", false, false)?;
        let metadata = file
            .metadata()
            .map_err(|error| LpmError::Cert(format!("failed to inspect audit log: {error}")))?;
        if metadata.len() > AUDIT_LOG_SIZE_CAP_BYTES {
            return Err(LpmError::Cert(format!(
                "audit log exceeds the {} byte limit",
                AUDIT_LOG_SIZE_CAP_BYTES
            )));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(AUDIT_LOG_SIZE_CAP_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| LpmError::Cert(format!("failed to read audit log: {error}")))?;
        if bytes.len() as u64 > AUDIT_LOG_SIZE_CAP_BYTES {
            return Err(LpmError::Cert(format!(
                "audit log exceeds the {} byte limit",
                AUDIT_LOG_SIZE_CAP_BYTES
            )));
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|error| LpmError::Cert(format!("audit log is not valid UTF-8: {error}")))
    }
}

struct AuditDirectoryLocation {
    path: PathBuf,
    base: PathBuf,
    components: Vec<std::ffi::OsString>,
}

fn configured_audit_dir() -> Result<AuditDirectoryLocation, LpmError> {
    if crate::test_env_overrides_enabled()
        && let Some(override_dir) = std::env::var_os(AUDIT_DIR_ENV)
    {
        let path = PathBuf::from(override_dir);
        let directory_name = path
            .file_name()
            .ok_or_else(|| LpmError::Cert("audit directory has no name".into()))?;
        let parent = path
            .parent()
            .ok_or_else(|| LpmError::Cert("audit directory has no parent".into()))?;
        let (base, components) = match parent.parent().zip(parent.file_name()) {
            Some((base, parent_name)) if parent_name == ".lpm" => (
                base.to_path_buf(),
                vec![parent_name.to_os_string(), directory_name.to_os_string()],
            ),
            _ => (parent.to_path_buf(), vec![directory_name.to_os_string()]),
        };
        return Ok(AuditDirectoryLocation {
            path,
            base,
            components,
        });
    }
    let root = lpm_common::LpmRoot::from_env()?;
    let root = std::path::absolute(root.root()).map_err(LpmError::Io)?;
    let root_name = root
        .file_name()
        .ok_or_else(|| LpmError::Cert("LPM_HOME must name a directory".into()))?;
    let base = root.parent().ok_or_else(|| {
        LpmError::Cert(format!(
            "LPM_HOME has no parent directory: {}",
            root.display()
        ))
    })?;
    Ok(AuditDirectoryLocation {
        path: root.join("audit"),
        base: base.to_path_buf(),
        components: vec![root_name.to_os_string(), "audit".into()],
    })
}

#[cfg(unix)]
fn tighten_audit_directory(dir: &Dir) -> Result<(), LpmError> {
    use cap_std::fs::PermissionsExt as _;

    dir.set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
        .map_err(|error| LpmError::Cert(format!("failed to tighten audit directory: {error}")))
}

#[cfg(not(unix))]
fn tighten_audit_directory(_dir: &Dir) -> Result<(), LpmError> {
    Ok(())
}

fn entry_exists(dir: &Dir, name: &str, path: &std::path::Path) -> Result<bool, LpmError> {
    match dir.symlink_metadata(name) {
        Ok(metadata) if metadata_is_link_or_reparse(&metadata) => Err(LpmError::Cert(format!(
            "refusing linked audit path {}",
            path.join(name).display()
        ))),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(LpmError::Cert(format!(
            "audit path {} is not a regular file",
            path.join(name).display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(LpmError::Cert(format!(
            "failed to inspect audit path {}: {error}",
            path.join(name).display()
        ))),
    }
}

#[cfg(not(windows))]
fn metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
fn metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn reject_linked_audit_entry(
    dir: &Dir,
    name: &str,
    path: &std::path::Path,
) -> Result<(), LpmError> {
    entry_exists(dir, name, path).map(|_| ())
}

/// Every action recorded to the audit trail. Serialized as a JSON object with `ts`,
/// `action`, and action-specific fields. New variants append; existing variants are
/// stable for forensic readers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AuditAction {
    #[serde(rename = "ca.generate")]
    CaGenerate {
        fingerprint: String,
        validity_days: i64,
        name_constraints: bool,
    },
    #[serde(rename = "ca.trust_install")]
    CaTrustInstall {
        fingerprint: String,
        store: &'static str,
        status: AuditStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    #[serde(rename = "ca.trust_uninstall")]
    CaTrustUninstall {
        fingerprint: String,
        store: &'static str,
        status: AuditStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    #[serde(rename = "ca.rotate.begin")]
    CaRotateBegin {
        old_fingerprint: String,
        mode: &'static str,
    },
    #[serde(rename = "ca.rotate.promote")]
    CaRotatePromote { new_fingerprint: String },
    #[serde(rename = "ca.rotate.complete")]
    CaRotateComplete {
        old_fingerprint: String,
        new_fingerprint: String,
        reissued: usize,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        skipped_missing: Vec<String>,
    },
    #[serde(rename = "ca.rotate.failed")]
    CaRotateFailed {
        old_fingerprint: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        new_fingerprint: Option<String>,
        step: &'static str,
        error: String,
    },
    #[serde(rename = "ca.reconcile_required")]
    CaReconcileRequired {
        old_fingerprint: String,
        new_fingerprint: String,
    },
    #[serde(rename = "cert.reissue")]
    CertReissue {
        path: String,
        ca_fingerprint: String,
    },
    #[serde(rename = "cert.reissue.skipped_missing")]
    CertReissueSkippedMissing { path: String },
    #[serde(rename = "ca.grace_scheduled")]
    CaGraceScheduled {
        fingerprint: String,
        removes_at: String,
    },
    #[serde(rename = "ca.reconcile.grace_removed")]
    CaReconcileGraceRemoved { fingerprint: String },
    #[serde(rename = "ca.reconcile.grace_pending")]
    CaReconcileGracePending {
        fingerprint: String,
        removes_at: String,
    },
    #[serde(rename = "ca.reconcile.stale_removed")]
    CaReconcileStaleRemoved {
        path: String,
        clock_source: &'static str,
    },
    #[serde(rename = "ca.reconcile.mtime_fallback")]
    CaReconcileMtimeFallback { path: String },
    #[serde(rename = "ca.reconcile.resolved")]
    CaReconcileResolved { old_fingerprint: String },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize)]
struct AuditEnvelope {
    ts: String,
    #[serde(flatten)]
    action: AuditAction,
}

/// Resolve the audit log path. Debug/test builds honor `LPM_CERT_AUDIT_DIR`;
/// release builds fall back to `~/.lpm/audit/cert.jsonl`.
pub fn audit_log_path() -> Result<PathBuf, LpmError> {
    Ok(configured_audit_dir()?.path.join("cert.jsonl"))
}

/// Append a single event. Best-effort fsync after write. Errors propagate so
/// callers can decide whether to fail the surrounding operation — the caller in
/// `ensure_https` swallows audit errors (we don't break HTTPS setup because the
/// audit dir is missing); the caller in `lpm cert rotate` propagates them
/// (rotation is a security-sensitive op where a missing audit record is itself
/// a finding).
pub fn append(action: AuditAction) -> Result<(), LpmError> {
    #[cfg(test)]
    if FAIL_APPEND_COUNTDOWN
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |remaining| match remaining {
                usize::MAX => None,
                0 => Some(usize::MAX),
                value => Some(value - 1),
            },
        )
        .is_ok_and(|previous| previous == 0)
    {
        return Err(LpmError::Cert("injected audit append failure".into()));
    }
    let audit = AuditLog::open(true)?
        .ok_or_else(|| LpmError::Cert("failed to create audit directory".into()))?;

    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| LpmError::Cert(format!("failed to format audit timestamp: {e}")))?;
    let envelope = AuditEnvelope { ts, action };
    let line = serde_json::to_string(&envelope)
        .map_err(|e| LpmError::Cert(format!("failed to serialize audit event: {e}")))?;

    let _lock = audit.acquire_lock()?;
    append_line(&audit, &line)
}

#[cfg(test)]
pub(crate) fn fail_next_append_after(successful_appends: usize) {
    FAIL_APPEND_COUNTDOWN.store(successful_appends, std::sync::atomic::Ordering::SeqCst);
}

fn append_line(audit: &AuditLog, line: &str) -> Result<(), LpmError> {
    let mut f = audit.open_file("cert.jsonl", true, true)?;
    writeln!(f, "{line}").map_err(|e| LpmError::Cert(format!("failed to write audit log: {e}")))?;
    let _ = f.sync_data();
    Ok(())
}

pub(crate) fn read_log() -> Result<Option<String>, LpmError> {
    let Some(audit) = AuditLog::open(false)? else {
        return Ok(None);
    };
    audit.read()
}

/// Convenience helper: log + swallow. Use when a missed audit record is not
/// fatal to the surrounding flow (e.g. `ensure_https`).
pub fn append_best_effort(action: AuditAction) {
    if let Err(e) = append(action) {
        tracing::warn!("audit append failed (event dropped): {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(debug_assertions)]
    fn with_audit_dir<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(AUDIT_DIR_ENV, dir.path());
        f(dir.path())
    }

    #[cfg(debug_assertions)]
    fn read_lines(audit_dir: &std::path::Path) -> Vec<String> {
        let log = audit_dir.join("cert.jsonl");
        let s = std::fs::read_to_string(&log).unwrap_or_default();
        s.lines().map(|l| l.to_string()).collect()
    }

    #[cfg(debug_assertions)]
    #[test]
    fn append_creates_dir_and_file_at_0700_and_0600() {
        let _serial = serial_lock();
        with_audit_dir(|dir| {
            append(AuditAction::CaGenerate {
                fingerprint: "AB:CD".into(),
                validity_days: 825,
                name_constraints: true,
            })
            .unwrap();

            let log = dir.join("cert.jsonl");
            assert!(log.exists());

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let dir_mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
                let file_mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
                assert_eq!(dir_mode, 0o700, "audit dir must be 0o700");
                assert_eq!(file_mode, 0o600, "audit log must be 0o600");
            }
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn append_writes_one_line_per_event_with_ts_and_action() {
        let _serial = serial_lock();
        with_audit_dir(|dir| {
            append(AuditAction::CaGenerate {
                fingerprint: "AB:CD".into(),
                validity_days: 825,
                name_constraints: true,
            })
            .unwrap();
            append(AuditAction::CaTrustInstall {
                fingerprint: "AB:CD".into(),
                store: "macos-login",
                status: AuditStatus::Ok,
                error: None,
            })
            .unwrap();

            let lines = read_lines(dir);
            assert_eq!(lines.len(), 2);

            for line in &lines {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                assert!(v.get("ts").and_then(|t| t.as_str()).is_some());
                assert!(v.get("action").and_then(|a| a.as_str()).is_some());
            }

            let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
            assert_eq!(first["action"], "ca.generate");
            assert_eq!(first["fingerprint"], "AB:CD");
            assert_eq!(first["validity_days"], 825);
            assert_eq!(first["name_constraints"], true);

            let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
            assert_eq!(second["action"], "ca.trust_install");
            assert_eq!(second["store"], "macos-login");
            assert_eq!(second["status"], "ok");
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn append_records_failure_with_error_string() {
        let _serial = serial_lock();
        with_audit_dir(|dir| {
            append(AuditAction::CaTrustInstall {
                fingerprint: "AB:CD".into(),
                store: "macos-login",
                status: AuditStatus::Error,
                error: Some("sudo failed".into()),
            })
            .unwrap();

            let lines = read_lines(dir);
            let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
            assert_eq!(v["status"], "error");
            assert_eq!(v["error"], "sudo failed");
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn append_records_rotate_sequence_with_complete() {
        let _serial = serial_lock();
        with_audit_dir(|dir| {
            append(AuditAction::CaRotateBegin {
                old_fingerprint: "AA:".into(),
                mode: "hard_cutover",
            })
            .unwrap();
            append(AuditAction::CertReissue {
                path: "/proj/cert.pem".into(),
                ca_fingerprint: "BB:".into(),
            })
            .unwrap();
            append(AuditAction::CaRotateComplete {
                old_fingerprint: "AA:".into(),
                new_fingerprint: "BB:".into(),
                reissued: 1,
                skipped_missing: vec![],
            })
            .unwrap();

            let lines = read_lines(dir);
            assert_eq!(lines.len(), 3);
            let actions: Vec<String> = lines
                .iter()
                .map(|l| {
                    let v: serde_json::Value = serde_json::from_str(l).unwrap();
                    v["action"].as_str().unwrap().to_string()
                })
                .collect();
            assert_eq!(
                actions,
                vec![
                    "ca.rotate.begin".to_string(),
                    "cert.reissue".to_string(),
                    "ca.rotate.complete".to_string()
                ]
            );
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn append_best_effort_swallows_on_error_directory_unwriteable() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let unwritable = dir.path().join("nonexistent-and-uncreatable").join("nope");
        let _guard = EnvGuard::set(AUDIT_DIR_ENV, &unwritable);
        // Don't try to break the assertion — the point is the function does not panic
        // or return; we drop any error.
        append_best_effort(AuditAction::CaGenerate {
            fingerprint: "AB:CD".into(),
            validity_days: 825,
            name_constraints: false,
        });
    }

    #[cfg(all(debug_assertions, unix))]
    #[test]
    fn append_rejects_a_symlinked_audit_log_without_modifying_its_target() {
        let _serial = serial_lock();
        let audit_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"sentinel").unwrap();
        std::os::unix::fs::symlink(outside.path(), audit_dir.path().join("cert.jsonl")).unwrap();
        let _guard = EnvGuard::set(AUDIT_DIR_ENV, audit_dir.path());

        let error = append(AuditAction::CaGenerate {
            fingerprint: "AB:CD".into(),
            validity_days: 825,
            name_constraints: true,
        })
        .unwrap_err();

        assert!(error.to_string().contains("linked audit"));
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"sentinel");
    }

    #[cfg(all(debug_assertions, unix))]
    #[test]
    fn append_rejects_a_symlinked_audit_lock_without_modifying_its_target() {
        let _serial = serial_lock();
        let audit_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"sentinel").unwrap();
        std::os::unix::fs::symlink(outside.path(), audit_dir.path().join("cert.lock")).unwrap();
        let _guard = EnvGuard::set(AUDIT_DIR_ENV, audit_dir.path());

        let error = append(AuditAction::CaGenerate {
            fingerprint: "AB:CD".into(),
            validity_days: 825,
            name_constraints: true,
        })
        .unwrap_err();

        assert!(error.to_string().contains("linked audit"));
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"sentinel");
    }

    #[cfg(all(debug_assertions, unix))]
    #[test]
    fn append_rejects_a_symlinked_audit_directory_without_modifying_its_target() {
        let _serial = serial_lock();
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let audit_dir = root.path().join("audit");
        std::os::unix::fs::symlink(outside.path(), &audit_dir).unwrap();
        let _guard = EnvGuard::set(AUDIT_DIR_ENV, &audit_dir);

        let error = append(AuditAction::CaGenerate {
            fingerprint: "AB:CD".into(),
            validity_days: 825,
            name_constraints: true,
        })
        .unwrap_err();

        assert!(error.to_string().contains("without following links"));
        assert!(!outside.path().join("cert.jsonl").exists());
    }

    #[cfg(all(debug_assertions, unix))]
    #[test]
    fn append_rejects_a_symlinked_lpm_parent_without_modifying_its_target() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join(".lpm")).unwrap();
        let audit_dir = home.path().join(".lpm/audit");
        let _guard = EnvGuard::set(AUDIT_DIR_ENV, &audit_dir);

        let error = append(AuditAction::CaGenerate {
            fingerprint: "AB:CD".into(),
            validity_days: 825,
            name_constraints: true,
        })
        .unwrap_err();

        assert!(error.to_string().contains("without following links"));
        assert!(!outside.path().join("audit/cert.jsonl").exists());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn audit_reader_rejects_an_oversized_log() {
        let _serial = serial_lock();
        with_audit_dir(|dir| {
            let log = std::fs::File::create(dir.join("cert.jsonl")).unwrap();
            log.set_len(AUDIT_LOG_SIZE_CAP_BYTES + 1).unwrap();

            let error = read_log().unwrap_err();

            assert!(error.to_string().contains("exceeds"));
        });
    }

    #[test]
    fn audit_log_follows_lpm_home_override() {
        let _serial = serial_lock();
        let root = tempfile::tempdir().unwrap();
        let _audit_override = EnvGuard::remove(AUDIT_DIR_ENV);
        let _lpm_home = EnvGuard::set("LPM_HOME", root.path());

        assert_eq!(
            audit_log_path().unwrap(),
            root.path().join("audit/cert.jsonl")
        );
    }

    #[cfg(all(debug_assertions, unix))]
    #[test]
    fn append_tightens_an_existing_audit_log_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let _serial = serial_lock();
        with_audit_dir(|dir| {
            let log = dir.join("cert.jsonl");
            std::fs::write(&log, b"").unwrap();
            std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();

            append(AuditAction::CaGenerate {
                fingerprint: "AB:CD".into(),
                validity_days: 825,
                name_constraints: true,
            })
            .unwrap();

            assert_eq!(
                std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
                0o600
            );
        });
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn audit_dir_env_is_ignored_in_release_builds() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(AUDIT_DIR_ENV, dir.path());

        let path = audit_log_path().unwrap();

        assert_ne!(path, dir.path().join("cert.jsonl"));
    }

    fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set<P: AsRef<std::ffi::OsStr>>(key: &'static str, value: P) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }

        fn remove(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }
}
