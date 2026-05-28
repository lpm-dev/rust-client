//! `lpm cert reconcile` — clean up artifacts left by an interrupted rotation, and
//! remove expired grace-window CA trust-store entries.
//!
//! Four idempotent jobs run on each invocation:
//!
//! 1. **Grace-window expiry.** For each entry in `~/.lpm/cert-grace.json` whose
//!    scheduled time is in the past, uninstall the old CA fingerprint and drop
//!    the entry. Pending entries are surfaced in the result.
//!
//! 2. **Interrupted-rotation resolution.** Scan the audit log for any
//!    `ca.reconcile_required` event without a matching `ca.reconcile.resolved`
//!    or `ca.trust_uninstall(ok)` for the recorded old fingerprint, and retry
//!    the trust-store uninstall using `rootCA.pem.previous`. Emit
//!    `ca.reconcile.resolved` on success.
//!
//! 3. **Stale staging artifact cleanup.** `rootCA.pem.next` / `.previous` files
//!    older than 24h are deleted. `.previous` files are **preserved** as long as
//!    any `ca.reconcile_required` is unresolved — otherwise mtime cleanup would
//!    destroy the only cert bytes the platform needs to uninstall the old root.
//!    Age is anchored to filesystem mtime in this implementation (the plan's
//!    audit-anchored variant is recorded but mtime is the actual clock).
//!
//! 4. (reserved for future "status nag clearance" job — currently bundled into
//!    job 2's success path.)

use crate::{audit, cert, paths, rotate, trust};
use lpm_common::LpmError;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::PathBuf;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Default, Clone, Serialize)]
pub struct ReconcileResult {
    pub success: bool,
    pub grace_removed: Vec<String>,
    pub grace_pending: Vec<rotate::GraceEntry>,
    pub stale_removed: Vec<String>,
    pub mtime_fallback: Vec<String>,
    pub reconcile_required_cleared: bool,
    /// Old fingerprints that had `ca.reconcile_required` events resolved this run.
    pub resolved_old_fingerprints: Vec<String>,
    /// Old fingerprints still pending resolution (e.g. because the previous-cert
    /// backup was missing, or trust-store uninstall failed again).
    pub pending_old_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReconcileOptions {
    pub dry_run: bool,
}

pub fn reconcile(opts: ReconcileOptions) -> Result<ReconcileResult, LpmError> {
    let mut out = ReconcileResult {
        success: true,
        ..Default::default()
    };
    let now = OffsetDateTime::now_utc();
    let ca_dir = paths::ca_dir()?;
    let prev_cert = ca_dir.join("rootCA.pem.previous");
    let prev_key = ca_dir.join("rootCA-key.pem.previous");

    let mut unresolved_old_fps = scan_unresolved_reconcile_required()?;

    // Compute the fingerprint of the on-disk `.previous` bytes once. Both the
    // grace-expiry path and the reconcile-required retry path use this to
    // confirm that the file actually contains the cert the marker / grace entry
    // is asking us to uninstall — otherwise we'd remove the wrong root from
    // the trust store and record a false `resolved` event for the original
    // marker. This can happen on developer machines that produced the
    // pre-guard mixed state from an earlier build of this branch.
    let prev_cert_fp_hex: Option<String> = if prev_cert.exists() {
        cert::fingerprint_sha256(&prev_cert)
            .ok()
            .map(|fp| cert::fingerprint_hex(&fp))
    } else {
        None
    };

    // Job 1: grace-window expiry.
    for entry in rotate::read_grace_entries()? {
        let scheduled = OffsetDateTime::parse(&entry.removes_at, &Rfc3339).map_err(|e| {
            LpmError::Cert(format!(
                "invalid removes_at {:?} in grace file: {e}",
                entry.removes_at
            ))
        })?;
        if scheduled > now {
            out.grace_pending.push(entry);
            continue;
        }
        if opts.dry_run {
            out.grace_removed.push(entry.fingerprint.clone());
            continue;
        }
        if !prev_cert.exists() {
            tracing::warn!(
                "grace-expiry: cannot find rootCA.pem.previous; the old CA fingerprint {} must be removed manually (re-install the old root, then `lpm cert uninstall`)",
                entry.fingerprint
            );
            out.grace_pending.push(entry.clone());
            continue;
        }
        if prev_cert_fp_hex.as_deref() != Some(entry.fingerprint.as_str()) {
            tracing::warn!(
                "grace-expiry: rootCA.pem.previous fingerprint {:?} does not match grace entry {:?}; refusing to uninstall the wrong cert. The grace entry is preserved; the older root must be removed manually.",
                prev_cert_fp_hex.as_deref().unwrap_or("<unknown>"),
                entry.fingerprint,
            );
            out.grace_pending.push(entry.clone());
            continue;
        }
        match trust::uninstall_ca(&prev_cert) {
            Ok(()) => {
                audit::append_best_effort(audit::AuditAction::CaTrustUninstall {
                    fingerprint: entry.fingerprint.clone(),
                    store: crate::trust_store_label(),
                    status: audit::AuditStatus::Ok,
                    error: None,
                });
                audit::append_best_effort(audit::AuditAction::CaReconcileGraceRemoved {
                    fingerprint: entry.fingerprint.clone(),
                });
                rotate::drop_grace_entry(&entry.fingerprint)?;
                out.grace_removed.push(entry.fingerprint.clone());
                unresolved_old_fps.remove(&entry.fingerprint);
            }
            Err(e) => {
                tracing::warn!(
                    "grace-expiry: failed to uninstall old CA {}: {e}",
                    entry.fingerprint
                );
                out.grace_pending.push(rotate::GraceEntry {
                    fingerprint: entry.fingerprint.clone(),
                    removes_at: entry.removes_at.clone(),
                });
            }
        }
    }

    // Job 2: retry uninstall for any unresolved `ca.reconcile_required` markers.
    //
    // The previous-root backup is the source of truth for the cert bytes the
    // platform needs (macOS Keychain, certutil, Linux ca-certificates) to
    // identify the entry to remove. If it's gone or doesn't match the marker,
    // we cannot proceed without manual intervention — and we must NOT record
    // a `resolved` event for a fingerprint we didn't actually remove.
    let fps_to_retry: Vec<String> = unresolved_old_fps.iter().cloned().collect();
    for old_fp in fps_to_retry {
        if opts.dry_run {
            out.pending_old_fingerprints.push(old_fp);
            continue;
        }
        if !prev_cert.exists() {
            tracing::warn!(
                "reconcile_required is unresolved for old CA {}, but rootCA.pem.previous is missing — re-install the old root and run `lpm cert uninstall`, then re-run `lpm cert reconcile`",
                old_fp
            );
            out.pending_old_fingerprints.push(old_fp);
            continue;
        }
        if prev_cert_fp_hex.as_deref() != Some(old_fp.as_str()) {
            tracing::warn!(
                "reconcile_required marker for {} cannot be resolved: rootCA.pem.previous holds a different fingerprint {:?}. Restore the matching cert bytes (or run `lpm cert uninstall` manually with the correct cert in rootCA.pem) and re-run reconcile.",
                old_fp,
                prev_cert_fp_hex.as_deref().unwrap_or("<unknown>"),
            );
            out.pending_old_fingerprints.push(old_fp);
            continue;
        }
        match trust::uninstall_ca(&prev_cert) {
            Ok(()) => {
                audit::append_best_effort(audit::AuditAction::CaTrustUninstall {
                    fingerprint: old_fp.clone(),
                    store: crate::trust_store_label(),
                    status: audit::AuditStatus::Ok,
                    error: None,
                });
                audit::append_best_effort(audit::AuditAction::CaReconcileResolved {
                    old_fingerprint: old_fp.clone(),
                });
                out.reconcile_required_cleared = true;
                out.resolved_old_fingerprints.push(old_fp.clone());
                unresolved_old_fps.remove(&old_fp);
            }
            Err(e) => {
                audit::append_best_effort(audit::AuditAction::CaTrustUninstall {
                    fingerprint: old_fp.clone(),
                    store: crate::trust_store_label(),
                    status: audit::AuditStatus::Error,
                    error: Some(e.to_string()),
                });
                tracing::warn!("reconcile retry failed for {old_fp}: {e}");
                out.pending_old_fingerprints.push(old_fp);
            }
        }
    }

    // Once every reconcile_required is resolved AND every grace entry that pointed
    // at the previous-root is gone, the .previous files are safe to delete in this run.
    let prev_safe_to_remove = unresolved_old_fps.is_empty()
        && !rotate::read_grace_entries()?.iter().any(|e| {
            paths::ca_dir().is_ok_and(|d| d.join("rootCA.pem.previous").exists())
                && grace_entry_points_at_previous(e)
        });

    // Job 3: stale staging-file cleanup.
    let stale_targets = [
        "rootCA.pem.next",
        "rootCA-key.pem.next",
        "rootCA.pem.previous",
        "rootCA-key.pem.previous",
    ];
    for name in stale_targets {
        let p = ca_dir.join(name);
        if !p.exists() {
            continue;
        }
        let is_previous = name.ends_with(".previous");
        if is_previous && !prev_safe_to_remove {
            tracing::debug!(
                "preserving {} — required by an unresolved reconcile or grace entry",
                p.display()
            );
            continue;
        }
        let mtime = match std::fs::metadata(&p).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let age = std::time::SystemTime::now()
            .duration_since(mtime)
            .unwrap_or(std::time::Duration::ZERO);
        if age < std::time::Duration::from_secs(24 * 3600) {
            continue;
        }
        out.mtime_fallback.push(p.to_string_lossy().into_owned());
        if opts.dry_run {
            out.stale_removed.push(p.to_string_lossy().into_owned());
            continue;
        }
        let _ = std::fs::remove_file(&p);
        audit::append_best_effort(audit::AuditAction::CaReconcileMtimeFallback {
            path: p.to_string_lossy().into_owned(),
        });
        audit::append_best_effort(audit::AuditAction::CaReconcileStaleRemoved {
            path: p.to_string_lossy().into_owned(),
            clock_source: "mtime",
        });
        out.stale_removed.push(p.to_string_lossy().into_owned());
    }

    // If reconcile fully cleared every required marker and there are no pending
    // grace entries pointing at the previous root, we can also delete .previous
    // key file alongside the cert. (cert side already handled in Job 3 above.)
    if out.reconcile_required_cleared && !prev_cert.exists() {
        let _ = std::fs::remove_file(&prev_key);
    }

    Ok(out)
}

/// Walk the audit log and collect every `old_fingerprint` from
/// `ca.reconcile_required` that has not been resolved by a subsequent
/// `ca.reconcile.resolved` or a successful `ca.trust_uninstall`.
pub fn scan_unresolved_reconcile_required() -> Result<BTreeSet<String>, LpmError> {
    let log = audit::audit_log_path()?;
    if !log.exists() {
        return Ok(BTreeSet::new());
    }
    let s = std::fs::read_to_string(&log)
        .map_err(|e| LpmError::Cert(format!("failed to read audit log: {e}")))?;
    let mut pending: BTreeSet<String> = BTreeSet::new();
    for line in s.lines() {
        let Ok(v): Result<serde_json::Value, _> = serde_json::from_str(line) else {
            continue;
        };
        let action = v.get("action").and_then(|a| a.as_str()).unwrap_or("");
        match action {
            "ca.reconcile_required" => {
                if let Some(fp) = v.get("old_fingerprint").and_then(|f| f.as_str()) {
                    pending.insert(fp.to_string());
                }
            }
            "ca.reconcile.resolved" => {
                if let Some(fp) = v.get("old_fingerprint").and_then(|f| f.as_str()) {
                    pending.remove(fp);
                }
            }
            "ca.trust_uninstall" => {
                if v.get("status").and_then(|s| s.as_str()) == Some("ok")
                    && let Some(fp) = v.get("fingerprint").and_then(|f| f.as_str())
                {
                    pending.remove(fp);
                }
            }
            _ => {}
        }
    }
    Ok(pending)
}

fn grace_entry_points_at_previous(_e: &rotate::GraceEntry) -> bool {
    paths::ca_dir().is_ok_and(|d| d.join("rootCA.pem.previous").exists())
}

pub fn audit_log_lines() -> Result<Vec<String>, LpmError> {
    let path = audit::audit_log_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let s = std::fs::read_to_string(&path)
        .map_err(|e| LpmError::Cert(format!("failed to read audit log: {e}")))?;
    Ok(s.lines().map(|l| l.to_string()).collect())
}

pub fn audit_log_path() -> Result<PathBuf, LpmError> {
    audit::audit_log_path()
}
