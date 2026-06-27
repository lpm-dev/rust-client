//! Append-only JSONL audit trail for trust-store and CA mutations.
//!
//! Path: `~/.lpm/audit/cert.jsonl` (debug/test builds can override it via
//! `LPM_CERT_AUDIT_DIR`).
//! Dir mode 0o700, file mode 0o600 (Unix). One event per line, RFC 3339 timestamp.
//! Best-effort fsync: losing the last entry on hard crash is acceptable for this
//! audit trail.

use lpm_common::LpmError;
use serde::Serialize;
use std::io::Write as _;
use std::path::PathBuf;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const AUDIT_DIR_ENV: &str = "LPM_CERT_AUDIT_DIR";

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
    if crate::test_env_overrides_enabled()
        && let Some(override_dir) = std::env::var_os(AUDIT_DIR_ENV)
    {
        return Ok(PathBuf::from(override_dir).join("cert.jsonl"));
    }
    let home = dirs::home_dir()
        .ok_or_else(|| LpmError::Cert("could not determine home directory for audit log".into()))?;
    Ok(home.join(".lpm").join("audit").join("cert.jsonl"))
}

/// Append a single event. Best-effort fsync after write. Errors propagate so
/// callers can decide whether to fail the surrounding operation — the caller in
/// `ensure_https` swallows audit errors (we don't break HTTPS setup because the
/// audit dir is missing); the caller in `lpm cert rotate` propagates them
/// (rotation is a security-sensitive op where a missing audit record is itself
/// a finding).
pub fn append(action: AuditAction) -> Result<(), LpmError> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| LpmError::Cert(format!("failed to create audit dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| LpmError::Cert(format!("failed to tighten audit dir permissions: {e}")),
            )?;
        }
    }

    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| LpmError::Cert(format!("failed to format audit timestamp: {e}")))?;
    let envelope = AuditEnvelope { ts, action };
    let line = serde_json::to_string(&envelope)
        .map_err(|e| LpmError::Cert(format!("failed to serialize audit event: {e}")))?;

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .map_err(|e| LpmError::Cert(format!("failed to open audit log: {e}")))?;
    writeln!(f, "{line}").map_err(|e| LpmError::Cert(format!("failed to write audit log: {e}")))?;
    let _ = f.sync_data();
    Ok(())
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
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
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
