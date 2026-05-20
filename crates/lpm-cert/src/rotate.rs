//! Root-CA rotation orchestration.
//!
//! Default (hard-cutover) sequence:
//!   1. Generate fresh CA + key into `rootCA.pem.next` / `rootCA-key.pem.next`.
//!   2. Trust-store install the staged CA (dual-root window opens).
//!   3. Reissue every reachable project leaf against the staged CA.
//!   4. Verify each reissued leaf chains to the staged CA.
//!   5. Promote staged → active, save old as `.previous` for transitional logging.
//!   6. Trust-store uninstall the old CA fingerprint (dual-root window closes).
//!   7. Delete `.previous` files.
//!
//! Grace-window variant (`keep_old_trusted_days = Some(n)`): steps 1–5 are identical;
//! step 6 is deferred and the old fingerprint is recorded in `~/.lpm/cert-grace.json`
//! for `lpm cert reconcile` (or the next `lpm cert rotate`) to remove at or after the
//! scheduled time.

use crate::{audit, ca, cert, paths, projects, trust, write_key_file};
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Hard cap on `keep_old_trusted_days` per plan: 90 days.
pub const MAX_GRACE_DAYS: u32 = 90;

#[derive(Debug, Clone)]
pub struct RotateOptions {
    /// Extra project directories to reissue beyond what the index knows about.
    /// Each entry must be a directory; nonexistent paths follow `skip_missing`.
    pub extra_projects: Vec<PathBuf>,
    /// If true (default), reissue continues past project dirs that have vanished.
    pub skip_missing: bool,
    /// If `Some(days)`, do not uninstall the old CA in this run; schedule its
    /// removal `days` from now via `~/.lpm/cert-grace.json`.
    pub keep_old_trusted_days: Option<u32>,
}

impl Default for RotateOptions {
    fn default() -> Self {
        Self {
            extra_projects: Vec::new(),
            skip_missing: true,
            keep_old_trusted_days: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RotateResult {
    pub success: bool,
    pub ca_rotated: bool,
    pub mode: &'static str,
    pub old_fingerprint: String,
    pub new_fingerprint: String,
    pub reissued_leaves: Vec<String>,
    pub skipped_missing: Vec<String>,
    pub old_ca_uninstalled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_ca_removal_scheduled: Option<String>,
}

/// Run the rotation flow. Returns a structured summary suitable for the JSON
/// envelope on `lpm cert rotate --json`.
pub fn rotate(opts: RotateOptions) -> Result<RotateResult, LpmError> {
    let ca_dir = paths::ca_dir()?;
    let active_cert = paths::ca_cert_path()?;
    let active_key = paths::ca_key_path()?;
    if !active_cert.exists() {
        return Err(LpmError::Cert(format!(
            "no CA to rotate at {}; run `lpm cert trust` first",
            active_cert.display()
        )));
    }
    crate::create_dir_secure(&ca_dir)
        .map_err(|e| LpmError::Cert(format!("failed to secure cert dir: {e}")))?;

    if let Some(days) = opts.keep_old_trusted_days
        && days > MAX_GRACE_DAYS
    {
        return Err(LpmError::Cert(format!(
            "keep-old-trusted-days must be <= {MAX_GRACE_DAYS}, got {days}"
        )));
    }

    // Before staging anything, verify there is no prior rotation state still
    // pointing at `rootCA.pem.previous`. Promotion unconditionally overwrites
    // those bytes; doing so while a reconcile_required or grace entry depends
    // on them would destroy the only artifact the trust store needs to remove
    // the older root. Surface the conflict and tell the user how to resolve.
    let prev_cert = ca_dir.join("rootCA.pem.previous");
    if prev_cert.exists() {
        let unresolved = crate::reconcile::scan_unresolved_reconcile_required()?;
        if !unresolved.is_empty() {
            return Err(LpmError::Cert(format!(
                "refusing to rotate: {} unresolved `ca.reconcile_required` marker(s) still depend on rootCA.pem.previous ({}). Run `lpm cert reconcile` first.",
                unresolved.len(),
                unresolved.iter().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
        let grace = read_grace_entries()?;
        if !grace.is_empty() {
            return Err(LpmError::Cert(format!(
                "refusing to rotate: {} pending grace-window entry(s) still depend on rootCA.pem.previous. Run `lpm cert reconcile` after the scheduled removal time(s), or wait for the window to close.",
                grace.len()
            )));
        }
    }

    let mode_label = if opts.keep_old_trusted_days.is_some() {
        "grace_window"
    } else {
        "hard_cutover"
    };

    let old_fp = cert::fingerprint_sha256(&active_cert)?;
    let old_fp_hex = cert::fingerprint_hex(&old_fp);

    audit::append(audit::AuditAction::CaRotateBegin {
        old_fingerprint: old_fp_hex.clone(),
        mode: mode_label,
    })?;

    // Step 1: stage the new CA + key.
    let staged_cert = ca_dir.join("rootCA.pem.next");
    let staged_key = ca_dir.join("rootCA-key.pem.next");
    let result = stage_and_run(
        &opts,
        &ca_dir,
        &active_cert,
        &active_key,
        &staged_cert,
        &staged_key,
        &old_fp_hex,
        mode_label,
    );
    match result {
        Ok(r) => Ok(r),
        Err(err) => {
            let _ = std::fs::remove_file(&staged_cert);
            let _ = std::fs::remove_file(&staged_key);
            audit::append_best_effort(audit::AuditAction::CaRotateFailed {
                old_fingerprint: old_fp_hex,
                new_fingerprint: None,
                step: "stage",
                error: err.to_string(),
            });
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_and_run(
    opts: &RotateOptions,
    ca_dir: &Path,
    active_cert: &Path,
    active_key: &Path,
    staged_cert: &Path,
    staged_key: &Path,
    old_fp_hex: &str,
    mode_label: &'static str,
) -> Result<RotateResult, LpmError> {
    let (new_cert_pem, new_key_pem) =
        ca::generate_ca().map_err(|e| LpmError::Cert(format!("failed to generate new CA: {e}")))?;
    std::fs::write(staged_cert, &new_cert_pem)
        .map_err(|e| LpmError::Cert(format!("failed to write staged CA cert: {e}")))?;
    write_key_file(staged_key, new_key_pem.as_bytes())
        .map_err(|e| LpmError::Cert(format!("failed to write staged CA key: {e}")))?;

    let new_fp = cert::fingerprint_sha256(staged_cert)?;
    let new_fp_hex = cert::fingerprint_hex(&new_fp);
    audit::append(audit::AuditAction::CaGenerate {
        fingerprint: new_fp_hex.clone(),
        validity_days: ca::CA_VALIDITY_DAYS,
        name_constraints: ca::wants_name_constraints(),
    })?;

    // Step 2: install staged CA into the trust store.
    match trust::install_ca(staged_cert) {
        Ok(()) => {
            audit::append(audit::AuditAction::CaTrustInstall {
                fingerprint: new_fp_hex.clone(),
                store: crate::trust_store_label(),
                status: audit::AuditStatus::Ok,
                error: None,
            })?;
        }
        Err(e) => {
            audit::append_best_effort(audit::AuditAction::CaTrustInstall {
                fingerprint: new_fp_hex.clone(),
                store: crate::trust_store_label(),
                status: audit::AuditStatus::Error,
                error: Some(e.to_string()),
            });
            audit::append_best_effort(audit::AuditAction::CaRotateFailed {
                old_fingerprint: old_fp_hex.to_string(),
                new_fingerprint: Some(new_fp_hex.clone()),
                step: "trust_install",
                error: e.to_string(),
            });
            return Err(e);
        }
    }

    // Step 3: reissue every reachable leaf against the staged CA.
    let staged_cert_pem = std::fs::read_to_string(staged_cert)
        .map_err(|e| LpmError::Cert(format!("failed to read staged CA cert: {e}")))?;
    let staged_key_pem = std::fs::read_to_string(staged_key)
        .map_err(|e| LpmError::Cert(format!("failed to read staged CA key: {e}")))?;

    let project_dirs = collect_project_dirs(&opts.extra_projects)?;

    let mut reissued: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for dir in &project_dirs {
        let leaf_dir = paths::project_cert_dir(dir)?;
        let leaf_cert = leaf_dir.join("cert.pem");
        let leaf_key = leaf_dir.join("key.pem");

        if !dir.exists() {
            if opts.skip_missing {
                audit::append_best_effort(audit::AuditAction::CertReissueSkippedMissing {
                    path: leaf_cert.to_string_lossy().into_owned(),
                });
                skipped.push(leaf_cert.to_string_lossy().into_owned());
                continue;
            } else {
                return rotate_abort_after_staged_install(
                    staged_cert,
                    staged_key,
                    &new_fp_hex,
                    old_fp_hex,
                    "reissue_missing",
                    format!("project dir missing: {}", dir.display()),
                );
            }
        }

        if !leaf_cert.exists() {
            // Project recorded in the index but has no leaf yet — nothing to reissue.
            continue;
        }

        let existing_sans = preserved_extra_hostnames(&leaf_cert).unwrap_or_default();
        let (cert_pem, key_pem) =
            cert::generate_project_cert(&staged_cert_pem, &staged_key_pem, &existing_sans)
                .map_err(|e| {
                    LpmError::Cert(format!(
                        "failed to reissue cert at {}: {e}",
                        leaf_cert.display()
                    ))
                })?;

        if let Err(e) = crate::create_dir_secure(&leaf_dir) {
            return rotate_abort_after_staged_install(
                staged_cert,
                staged_key,
                &new_fp_hex,
                old_fp_hex,
                "reissue_io",
                e.to_string(),
            );
        }
        if let Err(e) = std::fs::write(&leaf_cert, cert_pem.as_bytes()) {
            return rotate_abort_after_staged_install(
                staged_cert,
                staged_key,
                &new_fp_hex,
                old_fp_hex,
                "reissue_io",
                e.to_string(),
            );
        }
        if let Err(e) = write_key_file(&leaf_key, key_pem.as_bytes()) {
            return rotate_abort_after_staged_install(
                staged_cert,
                staged_key,
                &new_fp_hex,
                old_fp_hex,
                "reissue_io",
                e.to_string(),
            );
        }

        if !cert::leaf_signed_by(&leaf_cert, staged_cert).unwrap_or(false) {
            return rotate_abort_after_staged_install(
                staged_cert,
                staged_key,
                &new_fp_hex,
                old_fp_hex,
                "reissue_verify",
                format!(
                    "reissued leaf at {} fails chain verify against staged CA",
                    leaf_cert.display()
                ),
            );
        }

        audit::append_best_effort(audit::AuditAction::CertReissue {
            path: leaf_cert.to_string_lossy().into_owned(),
            ca_fingerprint: new_fp_hex.clone(),
        });
        reissued.push(leaf_cert.to_string_lossy().into_owned());
    }

    // Step 4 verification happens inline above; if we reach here every leaf passed.

    // Step 5: promote staged → active.
    let prev_cert = ca_dir.join("rootCA.pem.previous");
    let prev_key = ca_dir.join("rootCA-key.pem.previous");
    std::fs::copy(active_cert, &prev_cert)
        .map_err(|e| LpmError::Cert(format!("failed to back up active CA cert: {e}")))?;
    std::fs::copy(active_key, &prev_key)
        .map_err(|e| LpmError::Cert(format!("failed to back up active CA key: {e}")))?;
    std::fs::rename(staged_cert, active_cert)
        .map_err(|e| LpmError::Cert(format!("failed to promote staged CA cert: {e}")))?;
    std::fs::rename(staged_key, active_key)
        .map_err(|e| LpmError::Cert(format!("failed to promote staged CA key: {e}")))?;
    audit::append(audit::AuditAction::CaRotatePromote {
        new_fingerprint: new_fp_hex.clone(),
    })?;

    // Step 6: uninstall old CA from trust store, OR schedule via grace file.
    let (old_uninstalled, removal_scheduled) = match opts.keep_old_trusted_days {
        Some(days) => {
            let removes_at_dt = OffsetDateTime::now_utc() + time::Duration::days(days as i64);
            let removes_at = removes_at_dt
                .format(&Rfc3339)
                .map_err(|e| LpmError::Cert(format!("failed to format removal time: {e}")))?;
            schedule_grace(old_fp_hex, &removes_at)?;
            audit::append(audit::AuditAction::CaGraceScheduled {
                fingerprint: old_fp_hex.to_string(),
                removes_at: removes_at.clone(),
            })?;
            (false, Some(removes_at))
        }
        None => match trust::uninstall_ca(&prev_cert) {
            Ok(()) => {
                audit::append(audit::AuditAction::CaTrustUninstall {
                    fingerprint: old_fp_hex.to_string(),
                    store: crate::trust_store_label(),
                    status: audit::AuditStatus::Ok,
                    error: None,
                })?;
                (true, None)
            }
            Err(e) => {
                audit::append(audit::AuditAction::CaTrustUninstall {
                    fingerprint: old_fp_hex.to_string(),
                    store: crate::trust_store_label(),
                    status: audit::AuditStatus::Error,
                    error: Some(e.to_string()),
                })?;
                audit::append(audit::AuditAction::CaReconcileRequired {
                    old_fingerprint: old_fp_hex.to_string(),
                    new_fingerprint: new_fp_hex.clone(),
                })?;
                return Err(e);
            }
        },
    };

    // Step 7: delete `.previous` files now that the dual-root window is closed.
    if old_uninstalled {
        let _ = std::fs::remove_file(&prev_cert);
        let _ = std::fs::remove_file(&prev_key);
    }

    audit::append(audit::AuditAction::CaRotateComplete {
        old_fingerprint: old_fp_hex.to_string(),
        new_fingerprint: new_fp_hex.clone(),
        reissued: reissued.len(),
        skipped_missing: skipped.clone(),
    })?;

    Ok(RotateResult {
        success: true,
        ca_rotated: true,
        mode: mode_label,
        old_fingerprint: old_fp_hex.to_string(),
        new_fingerprint: new_fp_hex,
        reissued_leaves: reissued,
        skipped_missing: skipped,
        old_ca_uninstalled: old_uninstalled,
        old_ca_removal_scheduled: removal_scheduled,
    })
}

fn rotate_abort_after_staged_install(
    staged_cert: &Path,
    staged_key: &Path,
    new_fp_hex: &str,
    old_fp_hex: &str,
    step: &'static str,
    error: String,
) -> Result<RotateResult, LpmError> {
    let _ = trust::uninstall_ca(staged_cert);
    let _ = std::fs::remove_file(staged_cert);
    let _ = std::fs::remove_file(staged_key);
    audit::append_best_effort(audit::AuditAction::CaRotateFailed {
        old_fingerprint: old_fp_hex.to_string(),
        new_fingerprint: Some(new_fp_hex.to_string()),
        step,
        error: error.clone(),
    });
    Err(LpmError::Cert(error))
}

fn collect_project_dirs(extras: &[PathBuf]) -> Result<Vec<PathBuf>, LpmError> {
    let mut set: std::collections::BTreeSet<PathBuf> = projects::list()?.into_iter().collect();
    for extra in extras {
        set.insert(extra.clone());
    }
    Ok(set.into_iter().collect())
}

/// Return the SAN entries from `leaf_path` that should be passed as
/// `extra_hostnames` when reissuing — i.e. every DNS name + IP except the
/// three exact defaults `generate_project_cert` always adds. Uses the typed
/// accessor in `cert::read_san_entries` so we don't depend on display formatting.
///
/// Loopback aliases like `127.0.0.2` or `127.1.2.3` are NOT defaults — they
/// must round-trip through rotation. Only the literal `127.0.0.1` / `::1` /
/// `localhost` are filtered.
fn preserved_extra_hostnames(leaf_path: &Path) -> Result<Vec<String>, LpmError> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    const DEFAULT_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const DEFAULT_IPV6: Ipv6Addr = Ipv6Addr::LOCALHOST;

    let entries = cert::read_san_entries(leaf_path)?;
    let mut sans: Vec<String> = Vec::new();
    for e in entries {
        let skip = match &e {
            cert::SanEntry::Dns(d) => d == "localhost",
            cert::SanEntry::Ip(IpAddr::V4(ip)) => *ip == DEFAULT_IPV4,
            cert::SanEntry::Ip(IpAddr::V6(ip)) => *ip == DEFAULT_IPV6,
        };
        if skip {
            continue;
        }
        let s = e.as_extra_hostname();
        if s.is_empty() {
            continue;
        }
        sans.push(s);
    }
    Ok(sans)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct GraceFile {
    entries: Vec<GraceEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraceEntry {
    pub fingerprint: String,
    pub removes_at: String,
}

pub fn grace_file_path() -> Result<PathBuf, LpmError> {
    if let Some(p) = std::env::var_os("LPM_CERT_GRACE_FILE") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir()
        .ok_or_else(|| LpmError::Cert("could not determine home dir for grace file".into()))?;
    Ok(home.join(".lpm").join("cert-grace.json"))
}

fn schedule_grace(fingerprint: &str, removes_at: &str) -> Result<(), LpmError> {
    let path = grace_file_path()?;
    if let Some(parent) = path.parent() {
        crate::create_dir_secure(parent)?;
    }
    let mut file: GraceFile = if path.exists() {
        let bytes = std::fs::read(&path)
            .map_err(|e| LpmError::Cert(format!("failed to read grace file: {e}")))?;
        if bytes.is_empty() {
            GraceFile::default()
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|e| LpmError::Cert(format!("failed to parse grace file: {e}")))?
        }
    } else {
        GraceFile::default()
    };
    file.entries.retain(|e| e.fingerprint != fingerprint);
    file.entries.push(GraceEntry {
        fingerprint: fingerprint.to_string(),
        removes_at: removes_at.to_string(),
    });
    let serialized = serde_json::to_vec_pretty(&file)
        .map_err(|e| LpmError::Cert(format!("failed to serialize grace file: {e}")))?;
    std::fs::write(&path, serialized)
        .map_err(|e| LpmError::Cert(format!("failed to write grace file: {e}")))?;
    Ok(())
}

/// Read every grace-scheduled entry. Used by `lpm cert reconcile`.
pub fn read_grace_entries() -> Result<Vec<GraceEntry>, LpmError> {
    let path = grace_file_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| LpmError::Cert(format!("failed to read grace file: {e}")))?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let file: GraceFile = serde_json::from_slice(&bytes)
        .map_err(|e| LpmError::Cert(format!("failed to parse grace file: {e}")))?;
    Ok(file.entries)
}

/// Remove a fingerprint from the grace file. Returns whether anything was removed.
pub fn drop_grace_entry(fingerprint: &str) -> Result<bool, LpmError> {
    let path = grace_file_path()?;
    if !path.exists() {
        return Ok(false);
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| LpmError::Cert(format!("failed to read grace file: {e}")))?;
    if bytes.is_empty() {
        return Ok(false);
    }
    let mut file: GraceFile = serde_json::from_slice(&bytes)
        .map_err(|e| LpmError::Cert(format!("failed to parse grace file: {e}")))?;
    let before = file.entries.len();
    file.entries.retain(|e| e.fingerprint != fingerprint);
    let removed = file.entries.len() != before;
    if removed {
        let serialized = serde_json::to_vec_pretty(&file)
            .map_err(|e| LpmError::Cert(format!("failed to serialize grace file: {e}")))?;
        std::fs::write(&path, serialized)
            .map_err(|e| LpmError::Cert(format!("failed to write grace file: {e}")))?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rfc3339(s: &str) -> time::OffsetDateTime {
        time::OffsetDateTime::parse(s, &Rfc3339).unwrap()
    }

    #[test]
    fn rotate_options_default_is_skip_missing_hard_cutover() {
        let o = RotateOptions::default();
        assert!(o.skip_missing);
        assert!(o.keep_old_trusted_days.is_none());
        assert!(o.extra_projects.is_empty());
    }

    #[test]
    fn grace_entries_round_trip() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _g = EnvGuard::set("LPM_CERT_GRACE_FILE", &path);

        schedule_grace("AA:BB", "2026-08-01T00:00:00Z").unwrap();
        schedule_grace("CC:DD", "2026-09-01T00:00:00Z").unwrap();
        let entries = read_grace_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].fingerprint, "AA:BB");
        assert_eq!(entries[1].fingerprint, "CC:DD");
        let removed = parse_rfc3339(&entries[0].removes_at);
        assert_eq!(removed.year(), 2026);
    }

    #[test]
    fn schedule_grace_replaces_existing_fingerprint() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _g = EnvGuard::set("LPM_CERT_GRACE_FILE", &path);

        schedule_grace("AA:BB", "2026-08-01T00:00:00Z").unwrap();
        schedule_grace("AA:BB", "2026-12-01T00:00:00Z").unwrap();
        let entries = read_grace_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].removes_at, "2026-12-01T00:00:00Z");
    }

    #[test]
    fn drop_grace_entry_removes_only_named() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _g = EnvGuard::set("LPM_CERT_GRACE_FILE", &path);

        schedule_grace("AA:BB", "2026-08-01T00:00:00Z").unwrap();
        schedule_grace("CC:DD", "2026-09-01T00:00:00Z").unwrap();
        let removed = drop_grace_entry("AA:BB").unwrap();
        assert!(removed);
        let entries = read_grace_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fingerprint, "CC:DD");
    }

    #[test]
    fn drop_grace_entry_returns_false_when_absent() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _g = EnvGuard::set("LPM_CERT_GRACE_FILE", &path);

        assert!(!drop_grace_entry("ZZ:ZZ").unwrap());
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
