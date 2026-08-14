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

use crate::{audit, ca, cert, paths, projects, trust};
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const GRACE_FILE_ENV: &str = "LPM_CERT_GRACE_FILE";
const ROTATION_JOURNAL: &str = "rootCA.rotation.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum RotationPhase {
    Prepared,
    NewTrustPending,
    NewTrusted,
    Reissuing,
    PromotionPending,
    Promoted,
    GracePending,
    OldUntrustPending,
    CleanupPending,
    CompleteAuditPending,
    RollbackPending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotationLeafBackup {
    project_dir: PathBuf,
    cert_pem: String,
    key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotationJournal {
    version: u8,
    phase: RotationPhase,
    mode: String,
    old_fingerprint: String,
    new_fingerprint: String,
    old_cert_pem: String,
    old_key_pem: String,
    new_cert_pem: String,
    new_key_pem: String,
    #[serde(default)]
    previous_cert_pem: Option<String>,
    #[serde(default)]
    previous_key_pem: Option<String>,
    #[serde(default)]
    grace_days: Option<u32>,
    #[serde(default)]
    leaf_backups: Vec<RotationLeafBackup>,
    #[serde(default)]
    reissued_leaves: Vec<String>,
    #[serde(default)]
    skipped_missing: Vec<String>,
    #[serde(default)]
    removes_at: Option<String>,
}

impl RotationJournal {
    fn old_cert(&self) -> &[u8] {
        self.old_cert_pem.as_bytes()
    }

    fn old_key(&self) -> &[u8] {
        self.old_key_pem.as_bytes()
    }

    fn new_cert(&self) -> &[u8] {
        self.new_cert_pem.as_bytes()
    }

    fn new_key(&self) -> &[u8] {
        self.new_key_pem.as_bytes()
    }

    fn is_pre_promotion(&self) -> bool {
        matches!(
            self.phase,
            RotationPhase::Prepared
                | RotationPhase::NewTrustPending
                | RotationPhase::NewTrusted
                | RotationPhase::Reissuing
                | RotationPhase::RollbackPending
        )
    }
}

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
    let operation = paths::CertificateOperation::begin()?;
    let _recovery_guard = acquire_pending_recovery_generation(&operation)?;
    recover_pending_rotation(&operation.ca)?;
    let _active_generation_guard =
        if opts.keep_old_trusted_days.is_none() && operation.ca.exists("rootCA.pem")? {
            let active = operation.ca.read("rootCA.pem")?;
            Some(operation.acquire_destructive_generation(&active)?)
        } else {
            None
        };
    rotate_locked(&operation.ca, opts)
}

pub(crate) fn acquire_pending_recovery_generation(
    operation: &paths::CertificateOperation,
) -> Result<Option<paths::CertificateGenerationWriteGuard>, LpmError> {
    let Some(journal) = read_rotation_journal(&operation.ca)? else {
        return Ok(None);
    };
    if journal.mode != "hard_cutover" || journal.is_pre_promotion() {
        return Ok(None);
    }
    if journal.phase == RotationPhase::PromotionPending
        && active_root_matches(&operation.ca, journal.old_cert())?
    {
        return Ok(None);
    }
    operation
        .acquire_destructive_generation(journal.old_cert())
        .map(Some)
}

fn write_rotation_journal(
    ca_dir: &paths::GlobalCaDirectory,
    journal: &RotationJournal,
) -> Result<(), LpmError> {
    let contents = serde_json::to_vec_pretty(journal)
        .map_err(|error| LpmError::Cert(format!("serialize CA rotation journal: {error}")))?;
    if contents.len() as u64 > lpm_common::STATE_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Cert(format!(
            "CA rotation journal exceeds the {} byte limit",
            lpm_common::STATE_FILE_SIZE_CAP_BYTES
        )));
    }
    ca_dir.write(ROTATION_JOURNAL, &contents, 0o600)
}

fn read_rotation_journal(
    ca_dir: &paths::GlobalCaDirectory,
) -> Result<Option<RotationJournal>, LpmError> {
    if !ca_dir.exists(ROTATION_JOURNAL)? {
        return Ok(None);
    }
    let contents = ca_dir.read(ROTATION_JOURNAL)?;
    if contents.len() as u64 > lpm_common::STATE_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Cert(format!(
            "CA rotation journal exceeds the {} byte limit",
            lpm_common::STATE_FILE_SIZE_CAP_BYTES
        )));
    }
    let journal: RotationJournal = serde_json::from_slice(&contents)
        .map_err(|error| LpmError::Cert(format!("parse CA rotation journal: {error}")))?;
    if journal.version != 1 {
        return Err(LpmError::Cert(format!(
            "unsupported CA rotation journal version {}",
            journal.version
        )));
    }
    cert::validate_ca_key_pair(&journal.old_cert_pem, &journal.old_key_pem)
        .map_err(|error| LpmError::Cert(format!("invalid old CA pair in journal: {error}")))?;
    cert::validate_ca_key_pair(&journal.new_cert_pem, &journal.new_key_pem)
        .map_err(|error| LpmError::Cert(format!("invalid new CA pair in journal: {error}")))?;
    if cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(journal.old_cert())?)
        != journal.old_fingerprint
        || cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(journal.new_cert())?)
            != journal.new_fingerprint
    {
        return Err(LpmError::Cert(
            "CA rotation journal fingerprints do not match its certificate material".into(),
        ));
    }
    if !matches!(journal.mode.as_str(), "hard_cutover" | "grace_window") {
        return Err(LpmError::Cert(format!(
            "invalid CA rotation mode {:?}",
            journal.mode
        )));
    }
    if journal.mode == "grace_window"
        && journal.grace_days.is_some_and(|days| days > MAX_GRACE_DAYS)
    {
        return Err(LpmError::Cert(
            "CA rotation journal contains an invalid grace period".into(),
        ));
    }
    match (&journal.previous_cert_pem, &journal.previous_key_pem) {
        (Some(cert), Some(key)) => cert::validate_ca_key_pair(cert, key).map_err(|error| {
            LpmError::Cert(format!("invalid previous CA pair in journal: {error}"))
        })?,
        (None, None) => {}
        _ => {
            return Err(LpmError::Cert(
                "rotation journal contains an incomplete previous CA pair".into(),
            ));
        }
    }
    for backup in &journal.leaf_backups {
        cert::validate_project_key_pair_bytes(
            backup.cert_pem.as_bytes(),
            backup.key_pem.as_bytes(),
        )
        .map_err(|error| {
            LpmError::Cert(format!(
                "invalid leaf backup for {} in rotation journal: {error}",
                backup.project_dir.display()
            ))
        })?;
    }
    Ok(Some(journal))
}

pub(crate) fn recover_pending_rotation(ca_dir: &paths::GlobalCaDirectory) -> Result<(), LpmError> {
    recover_pending_rotation_result(ca_dir).map(|_| ())
}

fn recover_pending_rotation_result(
    ca_dir: &paths::GlobalCaDirectory,
) -> Result<Option<RotateResult>, LpmError> {
    let Some(mut journal) = read_rotation_journal(ca_dir)? else {
        return Ok(None);
    };
    let promotion_pending_with_old_root = journal.phase == RotationPhase::PromotionPending
        && active_root_matches(ca_dir, journal.old_cert())?;
    if journal.is_pre_promotion() || promotion_pending_with_old_root {
        journal.phase = RotationPhase::RollbackPending;
        write_rotation_journal(ca_dir, &journal)?;
        for backup in journal.leaf_backups.iter().rev() {
            let directory = paths::open_project_cert_directory(&backup.project_dir, false)?
                .ok_or_else(|| {
                    LpmError::Cert(format!(
                        "cannot restore certificate for missing project {}",
                        backup.project_dir.display()
                    ))
                })?;
            directory.write_pair(backup.cert_pem.as_bytes(), backup.key_pem.as_bytes())?;
        }
        ca_dir.write_ca_pair(
            "rootCA.pem",
            "rootCA-key.pem",
            journal.old_cert(),
            journal.old_key(),
        )?;
        ensure_ca_untrusted(journal.new_cert(), &ca_dir.path("rootCA.pem.next"))?;
        ensure_ca_trusted(journal.old_cert(), &ca_dir.path("rootCA.pem"))?;
        match (&journal.previous_cert_pem, &journal.previous_key_pem) {
            (Some(cert), Some(key)) => ca_dir.write_ca_pair(
                "rootCA.pem.previous",
                "rootCA-key.pem.previous",
                cert.as_bytes(),
                key.as_bytes(),
            )?,
            (None, None) => {
                ca_dir.remove("rootCA.pem.previous")?;
                ca_dir.remove("rootCA-key.pem.previous")?;
            }
            _ => {
                return Err(LpmError::Cert(
                    "rotation journal contains an incomplete previous CA pair".into(),
                ));
            }
        }
        ca_dir.remove("rootCA.pem.next")?;
        ca_dir.remove("rootCA-key.pem.next")?;
        ca_dir.remove(ROTATION_JOURNAL)?;
        return Ok(None);
    }
    if journal.phase == RotationPhase::PromotionPending {
        if !active_root_matches(ca_dir, journal.new_cert())? {
            return Err(LpmError::Cert(
                "cannot reconcile CA promotion because the active root matches neither journal generation"
                    .into(),
            ));
        }
        audit::append(audit::AuditAction::CaRotatePromote {
            new_fingerprint: journal.new_fingerprint.clone(),
        })?;
        journal.phase = RotationPhase::Promoted;
        write_rotation_journal(ca_dir, &journal)?;
    }
    reconcile_promoted_rotation(ca_dir, &mut journal)?;
    Ok(Some(rotation_result_from_journal(&journal)))
}

fn active_root_matches(
    ca_dir: &paths::GlobalCaDirectory,
    expected_cert: &[u8],
) -> Result<bool, LpmError> {
    if !ca_dir.exists("rootCA.pem")? {
        return Ok(false);
    }
    let active = ca_dir.read("rootCA.pem")?;
    Ok(cert::fingerprint_sha256_bytes(&active)? == cert::fingerprint_sha256_bytes(expected_cert)?)
}

fn ensure_ca_trusted(cert_pem: &[u8], display_path: &Path) -> Result<(), LpmError> {
    if trust::is_ca_installed_bytes(cert_pem, display_path)? {
        return Ok(());
    }
    if let Err(error) = trust::install_ca_bytes(cert_pem, display_path) {
        if trust::is_ca_installed_bytes(cert_pem, display_path)? {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn ensure_ca_untrusted(cert_pem: &[u8], display_path: &Path) -> Result<(), LpmError> {
    if !trust::is_ca_installed_bytes(cert_pem, display_path)? {
        return Ok(());
    }
    if let Err(error) = trust::uninstall_ca_bytes(cert_pem, display_path) {
        if !trust::is_ca_installed_bytes(cert_pem, display_path)? {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn reconcile_promoted_rotation(
    ca_dir: &paths::GlobalCaDirectory,
    journal: &mut RotationJournal,
) -> Result<(), LpmError> {
    #[cfg(test)]
    if FAIL_NEXT_PROMOTED_RECONCILE.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(LpmError::Cert(
            "injected promoted rotation reconciliation failure".into(),
        ));
    }
    ca_dir.write_ca_pair(
        "rootCA.pem",
        "rootCA-key.pem",
        journal.new_cert(),
        journal.new_key(),
    )?;
    ensure_ca_trusted(journal.new_cert(), &ca_dir.path("rootCA.pem"))?;

    if journal.mode == "grace_window" {
        reconcile_grace_schedule(ca_dir, journal)?;
    } else {
        reconcile_old_root_uninstall(ca_dir, journal)?;
    }

    if journal.phase == RotationPhase::CleanupPending {
        ca_dir.remove("rootCA.pem.next")?;
        ca_dir.remove("rootCA-key.pem.next")?;
        if journal.mode != "grace_window" {
            ca_dir.remove("rootCA.pem.previous")?;
            ca_dir.remove("rootCA-key.pem.previous")?;
        }
        journal.phase = RotationPhase::CompleteAuditPending;
        write_rotation_journal(ca_dir, journal)?;
    }

    if journal.phase == RotationPhase::CompleteAuditPending {
        if !audit_contains_rotation_complete(&journal.old_fingerprint, &journal.new_fingerprint)? {
            audit::append(audit::AuditAction::CaRotateComplete {
                old_fingerprint: journal.old_fingerprint.clone(),
                new_fingerprint: journal.new_fingerprint.clone(),
                reissued: journal.reissued_leaves.len(),
                skipped_missing: journal.skipped_missing.clone(),
            })?;
        }
        return remove_completed_rotation_journal(ca_dir);
    }

    Err(LpmError::Cert(format!(
        "cannot reconcile CA rotation phase {:?} for mode {:?}",
        journal.phase, journal.mode
    )))
}

#[cfg(test)]
static FAIL_NEXT_PROMOTED_RECONCILE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn fail_next_promoted_reconcile() {
    FAIL_NEXT_PROMOTED_RECONCILE.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn reconcile_grace_schedule(
    ca_dir: &paths::GlobalCaDirectory,
    journal: &mut RotationJournal,
) -> Result<(), LpmError> {
    if journal.phase == RotationPhase::Promoted {
        let days = journal.grace_days.ok_or_else(|| {
            LpmError::Cert("grace-window rotation journal is missing grace days".into())
        })?;
        if journal.removes_at.is_none() {
            journal.removes_at = Some(
                (OffsetDateTime::now_utc() + time::Duration::days(i64::from(days)))
                    .format(&Rfc3339)
                    .map_err(|error| {
                        LpmError::Cert(format!("failed to format removal time: {error}"))
                    })?,
            );
        }
        journal.phase = RotationPhase::GracePending;
        write_rotation_journal(ca_dir, journal)?;
    }
    if journal.phase == RotationPhase::GracePending {
        let removes_at = journal.removes_at.as_deref().ok_or_else(|| {
            LpmError::Cert("grace-window rotation journal is missing its removal time".into())
        })?;
        schedule_grace(&journal.old_fingerprint, removes_at)?;
        if !audit_contains_fingerprint_action(
            "ca.grace_scheduled",
            &journal.old_fingerprint,
            Some(removes_at),
        )? {
            audit::append(audit::AuditAction::CaGraceScheduled {
                fingerprint: journal.old_fingerprint.clone(),
                removes_at: removes_at.to_string(),
            })?;
        }
        journal.phase = RotationPhase::CleanupPending;
        write_rotation_journal(ca_dir, journal)?;
    }
    Ok(())
}

fn reconcile_old_root_uninstall(
    ca_dir: &paths::GlobalCaDirectory,
    journal: &mut RotationJournal,
) -> Result<(), LpmError> {
    if journal.phase == RotationPhase::Promoted {
        journal.phase = RotationPhase::OldUntrustPending;
        write_rotation_journal(ca_dir, journal)?;
    }
    if journal.phase == RotationPhase::OldUntrustPending {
        ensure_ca_untrusted(journal.old_cert(), &ca_dir.path("rootCA.pem.previous"))?;
        if !audit_contains_fingerprint_action("ca.trust_uninstall", &journal.old_fingerprint, None)?
        {
            audit::append(audit::AuditAction::CaTrustUninstall {
                fingerprint: journal.old_fingerprint.clone(),
                store: crate::trust_store_label(),
                status: audit::AuditStatus::Ok,
                error: None,
            })?;
        }
        journal.phase = RotationPhase::CleanupPending;
        write_rotation_journal(ca_dir, journal)?;
    }
    Ok(())
}

fn audit_contains_fingerprint_action(
    action: &str,
    fingerprint: &str,
    removes_at: Option<&str>,
) -> Result<bool, LpmError> {
    let Some(log) = audit::read_log()? else {
        return Ok(false);
    };
    let mut found = false;
    for line in log.lines().rev() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let event_action = value.get("action").and_then(serde_json::Value::as_str);
        if event_action == Some("ca.rotate.begin")
            && value
                .get("old_fingerprint")
                .and_then(serde_json::Value::as_str)
                == Some(fingerprint)
        {
            return Ok(found);
        }
        let status_ok = value
            .get("status")
            .is_none_or(|status| status.as_str() == Some("ok"));
        found |= event_action == Some(action)
            && value.get("fingerprint").and_then(serde_json::Value::as_str) == Some(fingerprint)
            && status_ok
            && removes_at.is_none_or(|expected| {
                value.get("removes_at").and_then(serde_json::Value::as_str) == Some(expected)
            });
    }
    Ok(false)
}

fn remove_completed_rotation_journal(ca_dir: &paths::GlobalCaDirectory) -> Result<(), LpmError> {
    match ca_dir.remove(ROTATION_JOURNAL) {
        Ok(()) => Ok(()),
        Err(error) => match ca_dir.exists(ROTATION_JOURNAL) {
            Ok(false) => Ok(()),
            Ok(true) | Err(_) => Err(error),
        },
    }
}

fn audit_contains_rotation_complete(
    old_fingerprint: &str,
    new_fingerprint: &str,
) -> Result<bool, LpmError> {
    let Some(log) = audit::read_log()? else {
        return Ok(false);
    };
    for line in log.lines().rev() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("action").and_then(serde_json::Value::as_str) == Some("ca.rotate.complete")
            && value
                .get("old_fingerprint")
                .and_then(serde_json::Value::as_str)
                == Some(old_fingerprint)
            && value
                .get("new_fingerprint")
                .and_then(serde_json::Value::as_str)
                == Some(new_fingerprint)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn pem_text(bytes: &[u8], label: &str) -> Result<String, LpmError> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in {label}: {error}")))
}

fn rotation_result_from_journal(journal: &RotationJournal) -> RotateResult {
    let grace_window = journal.mode == "grace_window";
    RotateResult {
        success: true,
        ca_rotated: true,
        mode: if grace_window {
            "grace_window"
        } else {
            "hard_cutover"
        },
        old_fingerprint: journal.old_fingerprint.clone(),
        new_fingerprint: journal.new_fingerprint.clone(),
        reissued_leaves: journal.reissued_leaves.clone(),
        skipped_missing: journal.skipped_missing.clone(),
        old_ca_uninstalled: !grace_window,
        old_ca_removal_scheduled: journal.removes_at.clone(),
    }
}

fn rotate_locked(
    ca_dir: &paths::GlobalCaDirectory,
    opts: RotateOptions,
) -> Result<RotateResult, LpmError> {
    let active_cert = ca_dir.path("rootCA.pem");
    if !ca_dir.exists("rootCA.pem")? {
        return Err(LpmError::Cert(format!(
            "no CA to rotate at {}; run `lpm cert trust` first",
            active_cert.display()
        )));
    }
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
    if ca_dir.exists("rootCA.pem.previous")? {
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

    let old_cert_bytes = ca_dir.read("rootCA.pem")?;
    let old_key_bytes = ca_dir.read("rootCA-key.pem")?;
    let old_fp = cert::fingerprint_sha256_bytes(&old_cert_bytes)?;
    let old_fp_hex = cert::fingerprint_hex(&old_fp);

    audit::append(audit::AuditAction::CaRotateBegin {
        old_fingerprint: old_fp_hex.clone(),
        mode: mode_label,
    })?;

    // Step 1: stage the new CA + key.
    let result = stage_and_run(
        &opts,
        ca_dir,
        &old_cert_bytes,
        &old_key_bytes,
        &old_fp_hex,
        mode_label,
    );
    match result {
        Ok(r) => Ok(r),
        Err(err) => {
            let recovered_result = recover_pending_rotation_result(ca_dir).map_err(
                |recovery_error| {
                    LpmError::Cert(format!(
                        "{err}; recovering the interrupted CA rotation also failed: {recovery_error}"
                    ))
                },
            )?;
            if let Some(recovered_result) = recovered_result {
                return Ok(recovered_result);
            }
            audit::append_best_effort(audit::AuditAction::CaRotateFailed {
                old_fingerprint: old_fp_hex,
                new_fingerprint: None,
                step: "rollback",
                error: err.to_string(),
            });
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_and_run(
    opts: &RotateOptions,
    ca_dir: &paths::GlobalCaDirectory,
    old_cert_bytes: &[u8],
    old_key_bytes: &[u8],
    old_fp_hex: &str,
    mode_label: &'static str,
) -> Result<RotateResult, LpmError> {
    let (new_cert_pem, new_key_pem) =
        ca::generate_ca().map_err(|e| LpmError::Cert(format!("failed to generate new CA: {e}")))?;
    ca_dir.write_ca_pair(
        "rootCA.pem.next",
        "rootCA-key.pem.next",
        new_cert_pem.as_bytes(),
        new_key_pem.as_bytes(),
    )?;

    let staged_cert_bytes = ca_dir.read("rootCA.pem.next")?;
    let staged_key_bytes = ca_dir.read("rootCA-key.pem.next")?;
    let new_fp = cert::fingerprint_sha256_bytes(&staged_cert_bytes)?;
    let new_fp_hex = cert::fingerprint_hex(&new_fp);
    let previous_pair =
        read_optional_ca_pair(ca_dir, "rootCA.pem.previous", "rootCA-key.pem.previous")?;
    let mut journal = RotationJournal {
        version: 1,
        phase: RotationPhase::Prepared,
        mode: mode_label.to_string(),
        old_fingerprint: old_fp_hex.to_string(),
        new_fingerprint: new_fp_hex.clone(),
        old_cert_pem: pem_text(old_cert_bytes, "active CA certificate")?,
        old_key_pem: pem_text(old_key_bytes, "active CA key")?,
        new_cert_pem: pem_text(&staged_cert_bytes, "staged CA certificate")?,
        new_key_pem: pem_text(&staged_key_bytes, "staged CA key")?,
        previous_cert_pem: previous_pair
            .as_ref()
            .map(|pair| pem_text(&pair.cert, "previous CA certificate"))
            .transpose()?,
        previous_key_pem: previous_pair
            .as_ref()
            .map(|pair| pem_text(&pair.key, "previous CA key"))
            .transpose()?,
        grace_days: opts.keep_old_trusted_days,
        leaf_backups: Vec::new(),
        reissued_leaves: Vec::new(),
        skipped_missing: Vec::new(),
        removes_at: None,
    };
    write_rotation_journal(ca_dir, &journal)?;
    audit::append(audit::AuditAction::CaGenerate {
        fingerprint: new_fp_hex.clone(),
        validity_days: ca::CA_VALIDITY_DAYS,
        name_constraints: ca::wants_name_constraints(),
    })?;

    // Step 2: install staged CA into the trust store.
    let staged_cert = ca_dir.path("rootCA.pem.next");
    journal.phase = RotationPhase::NewTrustPending;
    write_rotation_journal(ca_dir, &journal)?;
    match trust::install_ca_bytes(&staged_cert_bytes, &staged_cert) {
        Ok(()) => {
            journal.phase = RotationPhase::NewTrusted;
            write_rotation_journal(ca_dir, &journal)?;
            if let Err(error) = audit::append(audit::AuditAction::CaTrustInstall {
                fingerprint: new_fp_hex.clone(),
                store: crate::trust_store_label(),
                status: audit::AuditStatus::Ok,
                error: None,
            }) {
                return rotate_abort_after_staged_install(
                    ca_dir,
                    &staged_cert_bytes,
                    &new_fp_hex,
                    old_fp_hex,
                    "trust_install_audit",
                    error.to_string(),
                );
            }
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
                new_fingerprint: Some(new_fp_hex),
                step: "trust_install",
                error: e.to_string(),
            });
            return Err(e);
        }
    }

    // Step 3: reissue every reachable leaf against the staged CA.
    let staged_cert_pem = std::str::from_utf8(&staged_cert_bytes)
        .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in staged CA cert: {error}")))?;
    let staged_key_pem = std::str::from_utf8(&staged_key_bytes)
        .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in staged CA key: {error}")))?;

    let project_dirs = collect_project_dirs(&opts.extra_projects)?;
    let mut leaf_rollback = LeafRollback::default();

    let mut reissued: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for dir in &project_dirs {
        if !dir.exists() {
            let leaf_cert = paths::project_cert_dir(dir)?.join("cert.pem");
            if opts.skip_missing {
                audit::append_best_effort(audit::AuditAction::CertReissueSkippedMissing {
                    path: leaf_cert.to_string_lossy().into_owned(),
                });
                skipped.push(leaf_cert.to_string_lossy().into_owned());
                journal.skipped_missing = skipped.clone();
                write_rotation_journal(ca_dir, &journal)?;
                continue;
            } else {
                return rotate_abort_after_staged_install(
                    ca_dir,
                    &staged_cert_bytes,
                    &new_fp_hex,
                    old_fp_hex,
                    "reissue_missing",
                    format!("project dir missing: {}", dir.display()),
                );
            }
        }

        let Some(leaf_dir) = paths::open_project_cert_directory(dir, false)? else {
            continue;
        };
        let leaf_cert = leaf_dir.path().join("cert.pem");
        let leaf_key = leaf_dir.path().join("key.pem");

        if !leaf_cert.exists() {
            // Project recorded in the index but has no leaf yet — nothing to reissue.
            continue;
        }
        paths::reject_linked_project_cert_file(&leaf_cert)?;
        paths::reject_linked_project_cert_file(&leaf_key)?;

        let existing_sans = preserved_extra_hostnames(&leaf_cert).unwrap_or_default();
        let existing_dns_constraints =
            cert::read_project_dns_constraints(&leaf_cert).unwrap_or_default();
        let (previous_cert, previous_key) = leaf_dir.read_pair()?;
        let (cert_pem, key_pem) =
            if existing_sans.is_empty() && existing_dns_constraints.is_empty() {
                cert::generate_project_cert(staged_cert_pem, staged_key_pem, &existing_sans)
            } else {
                cert::generate_project_cert_with_constrained_intermediate(
                    staged_cert_pem,
                    staged_key_pem,
                    &existing_sans,
                    &existing_dns_constraints,
                )
            }
            .map_err(|e| {
                LpmError::Cert(format!(
                    "failed to reissue cert at {}: {e}",
                    leaf_cert.display()
                ))
            })?;

        journal.phase = RotationPhase::Reissuing;
        journal.leaf_backups.push(RotationLeafBackup {
            project_dir: dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf()),
            cert_pem: pem_text(&previous_cert, "project certificate backup")?,
            key_pem: pem_text(&previous_key, "project key backup")?,
        });
        write_rotation_journal(ca_dir, &journal)?;

        leaf_rollback.push(leaf_dir, previous_cert, previous_key);
        let leaf_dir = &leaf_rollback
            .entries
            .last()
            .expect("leaf rollback entry was just inserted")
            .directory;
        if let Err(e) = leaf_dir.write_pair(cert_pem.as_bytes(), key_pem.as_bytes()) {
            return rotate_abort_after_staged_install(
                ca_dir,
                &staged_cert_bytes,
                &new_fp_hex,
                old_fp_hex,
                "reissue_io",
                e.to_string(),
            );
        }

        let (reissued_cert, _) = leaf_dir.read_pair()?;
        if !cert::project_cert_chains_to_root_bytes(&reissued_cert, &staged_cert_bytes)
            .unwrap_or(false)
        {
            return rotate_abort_after_staged_install(
                ca_dir,
                &staged_cert_bytes,
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
        journal.reissued_leaves = reissued.clone();
        write_rotation_journal(ca_dir, &journal)?;
    }

    // Step 4 verification happens inline above; if we reach here every leaf passed.

    // Step 5: promote staged → active.
    journal.phase = RotationPhase::PromotionPending;
    write_rotation_journal(ca_dir, &journal)?;
    ca_dir.write_ca_pair(
        "rootCA.pem.previous",
        "rootCA-key.pem.previous",
        old_cert_bytes,
        old_key_bytes,
    )?;
    ca_dir.write_ca_pair(
        "rootCA.pem",
        "rootCA-key.pem",
        &staged_cert_bytes,
        &staged_key_bytes,
    )?;
    if let Err(error) = audit::append(audit::AuditAction::CaRotatePromote {
        new_fingerprint: new_fp_hex,
    }) {
        return Err(rollback_failed_promotion(
            ca_dir,
            old_cert_bytes,
            old_key_bytes,
            &staged_cert_bytes,
            previous_pair.as_ref(),
            error,
        ));
    }
    leaf_rollback.commit();
    journal.phase = RotationPhase::Promoted;
    write_rotation_journal(ca_dir, &journal)?;
    reconcile_promoted_rotation(ca_dir, &mut journal)?;
    Ok(rotation_result_from_journal(&journal))
}

#[cfg(test)]
mod transactional_tests {
    use super::*;

    fn audit_action_count(action: &str, fingerprint: &str) -> usize {
        audit::read_log()
            .unwrap()
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["action"] == action && event["fingerprint"] == fingerprint)
            .count()
    }

    #[test]
    fn recovery_before_promotion_restores_reissued_leaves_and_previous_trust() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let trust_dir = home.path().join("trust");
        let project = home.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let _home = EnvGuard::set("HOME", home.path());
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let operation = paths::CertificateOperation::begin().unwrap();
        let (old_cert, old_key) = ca::generate_ca().unwrap();
        let (new_cert, new_key) = ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                old_cert.as_bytes(),
                old_key.as_bytes(),
            )
            .unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem.next",
                "rootCA-key.pem.next",
                new_cert.as_bytes(),
                new_key.as_bytes(),
            )
            .unwrap();
        trust::install_ca_bytes(new_cert.as_bytes(), &operation.ca.path("rootCA.pem.next"))
            .unwrap();
        let leaf_dir = paths::open_project_cert_directory(&project, true)
            .unwrap()
            .unwrap();
        let (old_leaf, old_leaf_key) =
            cert::generate_project_cert(&old_cert, &old_key, &[]).unwrap();
        let (new_leaf, new_leaf_key) =
            cert::generate_project_cert(&new_cert, &new_key, &[]).unwrap();
        leaf_dir
            .write_pair(old_leaf.as_bytes(), old_leaf_key.as_bytes())
            .unwrap();
        leaf_dir
            .write_pair(new_leaf.as_bytes(), new_leaf_key.as_bytes())
            .unwrap();
        let old_fingerprint =
            cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(old_cert.as_bytes()).unwrap());
        let new_fingerprint =
            cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(new_cert.as_bytes()).unwrap());
        let journal = serde_json::json!({
            "version": 1,
            "phase": "reissuing",
            "mode": "hard_cutover",
            "oldFingerprint": old_fingerprint,
            "newFingerprint": new_fingerprint,
            "oldCertPem": old_cert,
            "oldKeyPem": old_key,
            "newCertPem": new_cert,
            "newKeyPem": new_key,
            "leafBackups": [{
                "projectDir": project,
                "certPem": old_leaf,
                "keyPem": old_leaf_key
            }],
            "reissuedLeaves": [leaf_dir.path().join("cert.pem")],
            "skippedMissing": []
        });
        operation
            .ca
            .write(
                ROTATION_JOURNAL,
                &serde_json::to_vec_pretty(&journal).unwrap(),
                0o600,
            )
            .unwrap();

        recover_pending_rotation(&operation.ca).unwrap();

        let (actual_leaf, actual_leaf_key) = leaf_dir.read_pair().unwrap();
        assert_eq!(actual_leaf, old_leaf.as_bytes());
        assert_eq!(actual_leaf_key, old_leaf_key.as_bytes());
        assert!(
            trust::is_ca_installed_bytes(old_cert.as_bytes(), &operation.ca.path("rootCA.pem"))
                .unwrap()
        );
        assert!(
            !trust::is_ca_installed_bytes(
                new_cert.as_bytes(),
                &operation.ca.path("rootCA.pem.next")
            )
            .unwrap()
        );
        assert!(!operation.ca.exists(ROTATION_JOURNAL).unwrap());
    }

    #[test]
    fn recovery_after_promotion_finishes_forward_without_restoring_the_old_root() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let trust_dir = home.path().join("trust");
        let _home = EnvGuard::set("HOME", home.path());
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let operation = paths::CertificateOperation::begin().unwrap();
        let (old_cert, old_key) = ca::generate_ca().unwrap();
        let (new_cert, new_key) = ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                new_cert.as_bytes(),
                new_key.as_bytes(),
            )
            .unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem.previous",
                "rootCA-key.pem.previous",
                old_cert.as_bytes(),
                old_key.as_bytes(),
            )
            .unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem.next",
                "rootCA-key.pem.next",
                new_cert.as_bytes(),
                new_key.as_bytes(),
            )
            .unwrap();
        trust::install_ca_bytes(new_cert.as_bytes(), &operation.ca.path("rootCA.pem")).unwrap();
        let journal = rotation_journal_for_test(
            RotationPhase::Promoted,
            "hard_cutover",
            &old_cert,
            &old_key,
            &new_cert,
            &new_key,
        );
        write_rotation_journal(&operation.ca, &journal).unwrap();

        recover_pending_rotation(&operation.ca).unwrap();

        assert_eq!(
            operation.ca.read("rootCA.pem").unwrap(),
            new_cert.as_bytes()
        );
        assert!(
            trust::is_ca_installed_bytes(new_cert.as_bytes(), &operation.ca.path("rootCA.pem"))
                .unwrap()
        );
        assert!(!operation.ca.exists("rootCA.pem.previous").unwrap());
        assert!(!operation.ca.exists("rootCA-key.pem.previous").unwrap());
        assert!(!operation.ca.exists("rootCA.pem.next").unwrap());
        assert!(!operation.ca.exists("rootCA-key.pem.next").unwrap());
        assert!(!operation.ca.exists(ROTATION_JOURNAL).unwrap());
        assert!(
            audit_contains_rotation_complete(&journal.old_fingerprint, &journal.new_fingerprint)
                .unwrap()
        );
    }

    #[test]
    fn cleanup_recovery_does_not_repeat_the_old_root_uninstall_audit() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let trust_dir = home.path().join("trust");
        let _home = EnvGuard::set("HOME", home.path());
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let operation = paths::CertificateOperation::begin().unwrap();
        let (old_cert, old_key) = ca::generate_ca().unwrap();
        let (new_cert, new_key) = ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                new_cert.as_bytes(),
                new_key.as_bytes(),
            )
            .unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem.previous",
                "rootCA-key.pem.previous",
                old_cert.as_bytes(),
                old_key.as_bytes(),
            )
            .unwrap();
        trust::install_ca_bytes(new_cert.as_bytes(), &operation.ca.path("rootCA.pem")).unwrap();
        let journal = rotation_journal_for_test(
            RotationPhase::CleanupPending,
            "hard_cutover",
            &old_cert,
            &old_key,
            &new_cert,
            &new_key,
        );
        audit::append(audit::AuditAction::CaRotateBegin {
            old_fingerprint: journal.old_fingerprint.clone(),
            mode: "hard_cutover",
        })
        .unwrap();
        audit::append(audit::AuditAction::CaTrustUninstall {
            fingerprint: journal.old_fingerprint.clone(),
            store: crate::trust_store_label(),
            status: audit::AuditStatus::Ok,
            error: None,
        })
        .unwrap();
        write_rotation_journal(&operation.ca, &journal).unwrap();

        recover_pending_rotation(&operation.ca).unwrap();

        assert_eq!(
            audit_action_count("ca.trust_uninstall", &journal.old_fingerprint),
            1
        );
    }

    #[test]
    fn failed_or_prior_uninstall_audits_do_not_satisfy_the_current_rotation() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let fingerprint = "AA:BB:CC";

        audit::append(audit::AuditAction::CaTrustUninstall {
            fingerprint: fingerprint.to_string(),
            store: crate::trust_store_label(),
            status: audit::AuditStatus::Ok,
            error: None,
        })
        .unwrap();
        audit::append(audit::AuditAction::CaRotateBegin {
            old_fingerprint: fingerprint.to_string(),
            mode: "hard_cutover",
        })
        .unwrap();
        audit::append(audit::AuditAction::CaTrustUninstall {
            fingerprint: fingerprint.to_string(),
            store: crate::trust_store_label(),
            status: audit::AuditStatus::Error,
            error: Some("injected failure".to_string()),
        })
        .unwrap();

        assert!(
            !audit_contains_fingerprint_action("ca.trust_uninstall", fingerprint, None).unwrap()
        );
    }

    #[test]
    fn cleanup_recovery_does_not_repeat_the_grace_schedule_audit() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let trust_dir = home.path().join("trust");
        let grace_file = home.path().join("grace.json");
        let _home = EnvGuard::set("HOME", home.path());
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let _grace = EnvGuard::set(GRACE_FILE_ENV, &grace_file);
        let operation = paths::CertificateOperation::begin().unwrap();
        let (old_cert, old_key) = ca::generate_ca().unwrap();
        let (new_cert, new_key) = ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                new_cert.as_bytes(),
                new_key.as_bytes(),
            )
            .unwrap();
        trust::install_ca_bytes(new_cert.as_bytes(), &operation.ca.path("rootCA.pem")).unwrap();
        let mut journal = rotation_journal_for_test(
            RotationPhase::CleanupPending,
            "grace_window",
            &old_cert,
            &old_key,
            &new_cert,
            &new_key,
        );
        journal.grace_days = Some(7);
        journal.removes_at = Some("2026-09-01T00:00:00Z".to_string());
        audit::append(audit::AuditAction::CaRotateBegin {
            old_fingerprint: journal.old_fingerprint.clone(),
            mode: "grace_window",
        })
        .unwrap();
        schedule_grace(
            &journal.old_fingerprint,
            journal.removes_at.as_deref().unwrap(),
        )
        .unwrap();
        audit::append(audit::AuditAction::CaGraceScheduled {
            fingerprint: journal.old_fingerprint.clone(),
            removes_at: journal.removes_at.clone().unwrap(),
        })
        .unwrap();
        write_rotation_journal(&operation.ca, &journal).unwrap();

        recover_pending_rotation(&operation.ca).unwrap();

        assert_eq!(
            audit_action_count("ca.grace_scheduled", &journal.old_fingerprint),
            1
        );
    }

    #[test]
    fn recovered_grace_rotation_returns_the_persisted_removal_time() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let trust_dir = home.path().join("trust");
        let grace_file = home.path().join("grace.json");
        let _home = EnvGuard::set("HOME", home.path());
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let _grace = EnvGuard::set(GRACE_FILE_ENV, &grace_file);
        let operation = paths::CertificateOperation::begin().unwrap();
        let (old_cert, old_key) = ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                old_cert.as_bytes(),
                old_key.as_bytes(),
            )
            .unwrap();
        trust::install_ca_bytes(old_cert.as_bytes(), &operation.ca.path("rootCA.pem")).unwrap();
        fail_next_promoted_reconcile();

        let result = rotate_locked(
            &operation.ca,
            RotateOptions {
                keep_old_trusted_days: Some(7),
                ..RotateOptions::default()
            },
        )
        .unwrap();

        assert!(result.old_ca_removal_scheduled.is_some());
    }

    #[test]
    fn trust_install_that_mutates_then_errors_is_recognized_as_complete() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let trust_dir = home.path().join("trust");
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let (cert, _) = ca::generate_ca().unwrap();
        trust::fail_next_install_after_mutation();

        ensure_ca_trusted(cert.as_bytes(), Path::new("rootCA.pem")).unwrap();

        assert!(trust::is_ca_installed_bytes(cert.as_bytes(), Path::new("rootCA.pem")).unwrap());
    }

    #[test]
    fn trust_uninstall_that_mutates_then_errors_is_recognized_as_complete() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let trust_dir = home.path().join("trust");
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let (cert, _) = ca::generate_ca().unwrap();
        trust::install_ca_bytes(cert.as_bytes(), Path::new("rootCA.pem")).unwrap();
        trust::fail_next_uninstall_after_mutation();

        ensure_ca_untrusted(cert.as_bytes(), Path::new("rootCA.pem")).unwrap();

        assert!(!trust::is_ca_installed_bytes(cert.as_bytes(), Path::new("rootCA.pem")).unwrap());
    }

    #[test]
    fn cleanup_recovery_removes_an_incomplete_previous_root_pair() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let trust_dir = home.path().join("trust");
        let _home = EnvGuard::set("HOME", home.path());
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let operation = paths::CertificateOperation::begin().unwrap();
        let (old_cert, old_key) = ca::generate_ca().unwrap();
        let (new_cert, new_key) = ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                new_cert.as_bytes(),
                new_key.as_bytes(),
            )
            .unwrap();
        operation
            .ca
            .write("rootCA.pem.previous", old_cert.as_bytes(), 0o644)
            .unwrap();
        trust::install_ca_bytes(new_cert.as_bytes(), &operation.ca.path("rootCA.pem")).unwrap();
        let journal = rotation_journal_for_test(
            RotationPhase::CleanupPending,
            "hard_cutover",
            &old_cert,
            &old_key,
            &new_cert,
            &new_key,
        );
        write_rotation_journal(&operation.ca, &journal).unwrap();

        recover_pending_rotation(&operation.ca).unwrap();

        assert!(!operation.ca.exists("rootCA.pem.previous").unwrap());
        assert!(!operation.ca.exists("rootCA-key.pem.previous").unwrap());
        assert!(!operation.ca.exists(ROTATION_JOURNAL).unwrap());
    }

    fn rotation_journal_for_test(
        phase: RotationPhase,
        mode: &str,
        old_cert: &str,
        old_key: &str,
        new_cert: &str,
        new_key: &str,
    ) -> RotationJournal {
        RotationJournal {
            version: 1,
            phase,
            mode: mode.to_string(),
            old_fingerprint: cert::fingerprint_hex(
                &cert::fingerprint_sha256_bytes(old_cert.as_bytes()).unwrap(),
            ),
            new_fingerprint: cert::fingerprint_hex(
                &cert::fingerprint_sha256_bytes(new_cert.as_bytes()).unwrap(),
            ),
            old_cert_pem: old_cert.to_string(),
            old_key_pem: old_key.to_string(),
            new_cert_pem: new_cert.to_string(),
            new_key_pem: new_key.to_string(),
            previous_cert_pem: None,
            previous_key_pem: None,
            grace_days: None,
            leaf_backups: Vec::new(),
            reissued_leaves: Vec::new(),
            skipped_missing: Vec::new(),
            removes_at: None,
        }
    }

    #[test]
    fn promotion_audit_failure_restores_the_previous_root_and_leaf() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let trust_dir = home.path().join("trust");
        let project = home.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let _home = EnvGuard::set("HOME", home.path());
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let _projects = EnvGuard::set(
            "LPM_CERT_PROJECTS_INDEX",
            home.path().join("cert-projects.json"),
        );
        let operation = paths::CertificateOperation::begin().unwrap();
        let (old_cert, old_key) = ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                old_cert.as_bytes(),
                old_key.as_bytes(),
            )
            .unwrap();
        trust::install_ca_bytes(old_cert.as_bytes(), &operation.ca.path("rootCA.pem")).unwrap();
        let leaf_dir = paths::open_project_cert_directory(&project, true)
            .unwrap()
            .unwrap();
        let (leaf_cert, leaf_key) = cert::generate_project_cert(&old_cert, &old_key, &[]).unwrap();
        leaf_dir
            .write_pair(leaf_cert.as_bytes(), leaf_key.as_bytes())
            .unwrap();
        projects::record(&project).unwrap();
        audit::fail_next_append_after(4);

        let error = rotate_locked(&operation.ca, RotateOptions::default()).unwrap_err();

        assert!(error.to_string().contains("injected audit append failure"));
        assert_eq!(
            operation.ca.read("rootCA.pem").unwrap(),
            old_cert.as_bytes()
        );
        assert_eq!(
            operation.ca.read("rootCA-key.pem").unwrap(),
            old_key.as_bytes()
        );
        let (actual_leaf, actual_key) = leaf_dir.read_pair().unwrap();
        assert_eq!(actual_leaf, leaf_cert.as_bytes());
        assert_eq!(actual_key, leaf_key.as_bytes());
        assert!(
            trust::is_ca_installed_bytes(old_cert.as_bytes(), &operation.ca.path("rootCA.pem"))
                .unwrap()
        );
        assert!(!operation.ca.exists("rootCA.pem.previous").unwrap());
        assert!(!operation.ca.exists("rootCA-key.pem.previous").unwrap());
    }

    #[test]
    fn trust_install_audit_failure_restores_the_previous_trust() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let audit_dir = home.path().join("audit");
        let trust_dir = home.path().join("trust");
        let _home = EnvGuard::set("HOME", home.path());
        let _audit = EnvGuard::set("LPM_CERT_AUDIT_DIR", &audit_dir);
        let _trust = EnvGuard::set("LPM_CERT_TEST_TRUST_STORE_DIR", &trust_dir);
        let _projects = EnvGuard::set(
            "LPM_CERT_PROJECTS_INDEX",
            home.path().join("cert-projects.json"),
        );
        let operation = paths::CertificateOperation::begin().unwrap();
        let (old_cert, old_key) = ca::generate_ca().unwrap();
        operation
            .ca
            .write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                old_cert.as_bytes(),
                old_key.as_bytes(),
            )
            .unwrap();
        trust::install_ca_bytes(old_cert.as_bytes(), &operation.ca.path("rootCA.pem")).unwrap();
        audit::fail_next_append_after(2);

        let error = rotate_locked(&operation.ca, RotateOptions::default()).unwrap_err();

        assert!(error.to_string().contains("injected audit append failure"));
        assert!(
            trust::is_ca_installed_bytes(old_cert.as_bytes(), &operation.ca.path("rootCA.pem"))
                .unwrap()
        );
        assert_eq!(
            operation.ca.read("rootCA.pem").unwrap(),
            old_cert.as_bytes()
        );
        assert!(!operation.ca.exists("rootCA.pem.next").unwrap());
        assert!(!operation.ca.exists("rootCA-key.pem.next").unwrap());
    }

    fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.previous.take() {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }
}

struct CaPair {
    cert: Vec<u8>,
    key: Vec<u8>,
}

fn read_optional_ca_pair(
    ca_dir: &paths::GlobalCaDirectory,
    cert_name: &str,
    key_name: &str,
) -> Result<Option<CaPair>, LpmError> {
    match (ca_dir.exists(cert_name)?, ca_dir.exists(key_name)?) {
        (false, false) => Ok(None),
        (true, true) => Ok(Some(CaPair {
            cert: ca_dir.read(cert_name)?,
            key: ca_dir.read(key_name)?,
        })),
        _ => Err(LpmError::Cert(format!(
            "incomplete CA backup pair: {} and {} must both exist or both be absent",
            ca_dir.path(cert_name).display(),
            ca_dir.path(key_name).display()
        ))),
    }
}

fn rollback_failed_promotion(
    ca_dir: &paths::GlobalCaDirectory,
    old_cert: &[u8],
    old_key: &[u8],
    staged_cert: &[u8],
    previous_pair: Option<&CaPair>,
    original_error: LpmError,
) -> LpmError {
    let mut rollback_errors = Vec::new();

    if let Err(error) = ca_dir.write_ca_pair("rootCA.pem", "rootCA-key.pem", old_cert, old_key) {
        rollback_errors.push(format!("restore active root pair: {error}"));
    }
    if let Err(error) = trust::uninstall_ca_bytes(staged_cert, &ca_dir.path("rootCA.pem.next")) {
        rollback_errors.push(format!("untrust staged root: {error}"));
    }
    if let Err(error) = trust::install_ca_bytes(old_cert, &ca_dir.path("rootCA.pem")) {
        rollback_errors.push(format!("restore previous root trust: {error}"));
    }

    match previous_pair {
        Some(pair) => {
            if let Err(error) = ca_dir.write_ca_pair(
                "rootCA.pem.previous",
                "rootCA-key.pem.previous",
                &pair.cert,
                &pair.key,
            ) {
                rollback_errors.push(format!("restore pre-existing root backup: {error}"));
            }
        }
        None => {
            if let Err(error) = ca_dir.remove("rootCA.pem.previous") {
                rollback_errors.push(format!("remove root certificate backup: {error}"));
            }
            if let Err(error) = ca_dir.remove("rootCA-key.pem.previous") {
                rollback_errors.push(format!("remove root key backup: {error}"));
            }
        }
    }

    if rollback_errors.is_empty() {
        original_error
    } else {
        LpmError::Cert(format!(
            "{original_error}; rotation rollback also failed: {}",
            rollback_errors.join("; ")
        ))
    }
}

struct LeafBackup {
    directory: paths::ProjectCertDirectory,
    cert: Vec<u8>,
    key: Vec<u8>,
}

#[derive(Default)]
struct LeafRollback {
    entries: Vec<LeafBackup>,
    committed: bool,
}

impl LeafRollback {
    fn push(&mut self, directory: paths::ProjectCertDirectory, cert: Vec<u8>, key: Vec<u8>) {
        self.entries.push(LeafBackup {
            directory,
            cert,
            key,
        });
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for LeafRollback {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for backup in self.entries.iter().rev() {
            if let Err(error) = backup.directory.write_pair(&backup.cert, &backup.key) {
                tracing::error!(
                    path = %backup.directory.path().display(),
                    %error,
                    "failed to restore project certificate pair after aborted CA rotation"
                );
            }
        }
    }
}

fn rotate_abort_after_staged_install(
    _ca_dir: &paths::GlobalCaDirectory,
    _staged_cert: &[u8],
    new_fp_hex: &str,
    old_fp_hex: &str,
    step: &'static str,
    error: String,
) -> Result<RotateResult, LpmError> {
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
    if crate::test_env_overrides_enabled()
        && let Some(p) = std::env::var_os(GRACE_FILE_ENV)
    {
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
    let lock_path = path.with_extension("lock");
    lpm_common::with_exclusive_lock(lock_path, || {
        let mut file = read_grace_file(&path)?;
        file.entries.retain(|e| e.fingerprint != fingerprint);
        file.entries.push(GraceEntry {
            fingerprint: fingerprint.to_string(),
            removes_at: removes_at.to_string(),
        });
        write_grace_file(&path, &file)
    })
}

/// Read every grace-scheduled entry. Used by `lpm cert reconcile`.
pub fn read_grace_entries() -> Result<Vec<GraceEntry>, LpmError> {
    let path = grace_file_path()?;
    Ok(read_grace_file(&path)?.entries)
}

/// Remove a fingerprint from the grace file. Returns whether anything was removed.
pub fn drop_grace_entry(fingerprint: &str) -> Result<bool, LpmError> {
    let path = grace_file_path()?;
    let lock_path = path.with_extension("lock");
    lpm_common::with_exclusive_lock(lock_path, || {
        let mut file = read_grace_file(&path)?;
        let before = file.entries.len();
        file.entries.retain(|e| e.fingerprint != fingerprint);
        let removed = file.entries.len() != before;
        if removed {
            write_grace_file(&path, &file)?;
        }
        Ok(removed)
    })
}

fn read_grace_file(path: &Path) -> Result<GraceFile, LpmError> {
    let Some(bytes) =
        lpm_common::read_capped_state_file(path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|error| LpmError::Cert(format!("failed to read grace file: {error}")))?
    else {
        return Ok(GraceFile::default());
    };
    if bytes.is_empty() {
        return Ok(GraceFile::default());
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| LpmError::Cert(format!("failed to parse grace file: {error}")))
}

fn write_grace_file(path: &Path, file: &GraceFile) -> Result<(), LpmError> {
    let serialized = serde_json::to_vec_pretty(file)
        .map_err(|error| LpmError::Cert(format!("failed to serialize grace file: {error}")))?;
    lpm_common::write_file_atomic_with_options(
        path,
        serialized,
        lpm_common::AtomicWriteOptions::new()
            .unix_mode(0o600)
            .sync_file()
            .sync_parent(),
    )
    .map_err(|error| LpmError::Cert(format!("failed to write grace file: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(debug_assertions)]
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
    fn committed_rotation_does_not_fail_after_the_journal_was_unlinked() {
        let _serial = serial_lock();
        let home = tempfile::tempdir().unwrap();
        let _home = EnvGuard::set("HOME", home.path());
        let operation = paths::CertificateOperation::begin().unwrap();
        operation
            .ca
            .write(ROTATION_JOURNAL, b"completed", 0o600)
            .unwrap();
        paths::fail_next_directory_sync();

        remove_completed_rotation_journal(&operation.ca).unwrap();

        assert!(!operation.ca.exists(ROTATION_JOURNAL).unwrap());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn grace_entries_round_trip() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _g = EnvGuard::set(GRACE_FILE_ENV, &path);

        schedule_grace("AA:BB", "2026-08-01T00:00:00Z").unwrap();
        schedule_grace("CC:DD", "2026-09-01T00:00:00Z").unwrap();
        let entries = read_grace_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].fingerprint, "AA:BB");
        assert_eq!(entries[1].fingerprint, "CC:DD");
        let removed = parse_rfc3339(&entries[0].removes_at);
        assert_eq!(removed.year(), 2026);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn schedule_grace_replaces_existing_fingerprint() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _g = EnvGuard::set(GRACE_FILE_ENV, &path);

        schedule_grace("AA:BB", "2026-08-01T00:00:00Z").unwrap();
        schedule_grace("AA:BB", "2026-12-01T00:00:00Z").unwrap();
        let entries = read_grace_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].removes_at, "2026-12-01T00:00:00Z");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn drop_grace_entry_removes_only_named() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _g = EnvGuard::set(GRACE_FILE_ENV, &path);

        schedule_grace("AA:BB", "2026-08-01T00:00:00Z").unwrap();
        schedule_grace("CC:DD", "2026-09-01T00:00:00Z").unwrap();
        let removed = drop_grace_entry("AA:BB").unwrap();
        assert!(removed);
        let entries = read_grace_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fingerprint, "CC:DD");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn drop_grace_entry_returns_false_when_absent() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _g = EnvGuard::set(GRACE_FILE_ENV, &path);

        assert!(!drop_grace_entry("ZZ:ZZ").unwrap());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn grace_file_env_is_ignored_in_release_builds() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-grace.json");
        let _guard = EnvGuard::set(GRACE_FILE_ENV, &path);

        assert_ne!(grace_file_path().unwrap(), path);
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
