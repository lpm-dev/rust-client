//! Phase 37 M3.1c — `lpm_global::recover()`: WAL replay + manifest
//! reconciliation at startup.
//!
//! Invoked exactly once per `lpm` invocation, **before** command
//! dispatch, when the parsed command is in `command_needs_global_state`
//! (M3.1d). Recovery is idempotent — running it twice produces the
//! same state as running it once.
//!
//! ## Algorithm
//!
//! 1. `try_lock` the global `.tx.lock`. If another process holds it
//!    (a long install in progress), return an empty report — recovery
//!    is safe to defer to the next invocation.
//! 2. Scan the WAL via [`crate::wal::WalReader::scan`].
//!    - `ScanStop::UnknownOp` → bail with "WAL written by newer lpm";
//!      do NOT touch any state.
//!    - `ScanStop::TornTail` → truncate to `last_good_offset` and
//!      continue (a partial append got dropped).
//!    - `ScanStop::Eof` → continue.
//! 3. Pair INTENT records with COMMIT / ABORT by `tx_id`. Any INTENT
//!    without a matching COMMIT or ABORT is "uncompleted" — needs
//!    reconciliation.
//! 4. For each uncompleted INTENT:
//!    a. Look up `[pending.<package>]` in the manifest. If missing,
//!    the WAL is ahead of the manifest — could happen if the manifest
//!    write was rolled back without a WAL ABORT; treat as a
//!    roll-back-needed case (clean up install root if any).
//!    b. Call [`validate_install_root`]. If `Ready`:
//!    Roll forward — emit shims for `new_row.commands` and
//!    `new_aliases_json`, flip `[pending.<package>]` into
//!    `[packages.<package>]`, queue the prior root (if upgrade) in
//!    `manifest.tombstones`, write COMMIT to WAL.
//!    c. Otherwise:
//!    Roll back — if the prior active row exists, restore
//!    `[packages.<package>]` from `prior_active_row_json` and restore
//!    prior alias state from `prior_command_ownership_json`. Remove
//!    `[pending.<package>]`. Queue the new install root in tombstones
//!    (the partial install is dead but its files may be locked on
//!    Windows; sweep on next gc). Write ABORT to WAL.
//! 5. After processing every uncompleted INTENT, if all WAL records
//!    are now resolved (every INTENT has a matching COMMIT or ABORT),
//!    truncate the WAL to zero — keeps the file from growing
//!    unboundedly across long-lived installations.

use crate::install_root::{InstallRootStatus, validate_install_root};
use crate::manifest::{
    AliasEntry, GlobalManifest, PackageEntry, PackageSource, PendingEntry, read_for, write_for,
};
use crate::shim::{Shim, emit_shim, remove_shim};
use crate::wal::{IntentPayload, ScanStop, WalReader, WalRecord, WalWriter};
use chrono::{DateTime, Utc};
use lpm_common::{LpmError, LpmRoot, try_with_exclusive_lock};
use std::collections::{BTreeMap, BTreeSet};

/// Outcome of one reconciled transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    RolledForward,
    RolledBack {
        reason: String,
    },
    /// The WAL referenced a manifest state we don't recognize — the
    /// install root is gone, the pending row is gone, nothing to do.
    /// Emitted as ABORT so future scans don't re-encounter the orphan.
    NothingToDo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledTx {
    pub tx_id: String,
    pub package: String,
    pub outcome: ReconciliationOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryReport {
    /// True when the lock was held by another process and recovery
    /// silently skipped.
    pub skipped_due_to_lock: bool,
    /// Outcomes of every uncompleted transaction we reconciled.
    pub reconciled: Vec<ReconciledTx>,
    /// `Some(offset)` if the WAL had a torn tail that was truncated.
    pub torn_tail_truncated_at: Option<u64>,
    /// True when the WAL was compacted to zero after recovery (all
    /// transactions resolved).
    pub wal_compacted: bool,
}

/// Error returned when recovery cannot proceed because the WAL was
/// written by a newer `lpm`. Rendered as a user-facing diagnostic by
/// the M3.1d main.rs hook so users get an actionable upgrade prompt.
#[derive(Debug)]
pub struct UnknownOpError {
    pub op: String,
    pub offset: u64,
}

impl std::fmt::Display for UnknownOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "global install WAL contains an unknown record type '{}' at offset {}. \
             This usually means a newer `lpm` wrote state this binary doesn't understand. \
             Upgrade `lpm` (or restore from the previous version) before retrying.",
            self.op, self.offset
        )
    }
}

impl std::error::Error for UnknownOpError {}

impl From<UnknownOpError> for LpmError {
    fn from(e: UnknownOpError) -> Self {
        LpmError::Io(std::io::Error::other(e.to_string()))
    }
}

pub fn recover(root: &LpmRoot) -> Result<RecoveryReport, LpmError> {
    let lock_path = root.global_tx_lock();
    let outcome = try_with_exclusive_lock(&lock_path, || run_recovery_locked(root))?;
    Ok(outcome.unwrap_or(RecoveryReport {
        skipped_due_to_lock: true,
        ..Default::default()
    }))
}

fn run_recovery_locked(root: &LpmRoot) -> Result<RecoveryReport, LpmError> {
    let wal_path = root.global_wal();
    let scan = WalReader::at(&wal_path).scan()?;

    if let ScanStop::UnknownOp { offset, ref op } = scan.stop {
        return Err(UnknownOpError {
            op: op.clone(),
            offset,
        }
        .into());
    }

    let torn_tail_offset = if let ScanStop::TornTail { .. } = scan.stop {
        // Truncate immediately so the next writer doesn't append after
        // garbage. Open the writer just for the truncation.
        let mut w = WalWriter::open(&wal_path)?;
        w.truncate_to(scan.last_good_offset)?;
        Some(scan.last_good_offset)
    } else {
        None
    };

    // Pair INTENT records with COMMIT/ABORT by tx_id. An INTENT without
    // a matching COMMIT or ABORT is uncompleted.
    let mut intents: BTreeMap<String, Box<IntentPayload>> = BTreeMap::new();
    let mut resolved: BTreeSet<String> = BTreeSet::new();
    for record in &scan.records {
        match record {
            WalRecord::Intent(payload) => {
                intents.insert(payload.tx_id.clone(), payload.clone());
            }
            WalRecord::Commit { tx_id, .. } | WalRecord::Abort { tx_id, .. } => {
                resolved.insert(tx_id.clone());
            }
        }
    }
    let uncompleted: Vec<Box<IntentPayload>> = intents
        .into_iter()
        .filter(|(tx_id, _)| !resolved.contains(tx_id))
        .map(|(_, p)| p)
        .collect();

    if uncompleted.is_empty() {
        // Nothing to reconcile. Still compact the WAL if every record
        // is committed/aborted — keeps the file bounded across many
        // successful installs.
        let wal_compacted = compact_wal_if_quiescent(&wal_path, &scan.records)?;
        return Ok(RecoveryReport {
            skipped_due_to_lock: false,
            reconciled: Vec::new(),
            torn_tail_truncated_at: torn_tail_offset,
            wal_compacted,
        });
    }

    let mut manifest = read_for(root)?;
    let mut wal_writer = WalWriter::open(&wal_path)?;
    let mut reconciled = Vec::new();

    for intent in uncompleted {
        let outcome = reconcile_one(root, &mut manifest, &mut wal_writer, &intent)?;
        reconciled.push(ReconciledTx {
            tx_id: intent.tx_id.clone(),
            package: intent.package.clone(),
            outcome,
        });
    }

    // Persist manifest after all reconciliations land, then compact WAL
    // if quiescent. Order matters: manifest write + WAL compact must
    // both succeed for "I'm done" to be true; if compact fails, the
    // worst case is a slightly larger WAL that the next recovery will
    // compact instead.
    write_for(root, &manifest)?;

    // Re-scan the WAL after the COMMIT/ABORT records we just wrote so
    // the compaction check sees them.
    let post_scan = WalReader::at(&wal_path).scan()?;
    let wal_compacted = compact_wal_if_quiescent(&wal_path, &post_scan.records)?;

    Ok(RecoveryReport {
        skipped_due_to_lock: false,
        reconciled,
        torn_tail_truncated_at: torn_tail_offset,
        wal_compacted,
    })
}

/// Reconcile one uncompleted INTENT. Mutates `manifest` in memory;
/// caller persists after all reconciliations finish. Writes one COMMIT
/// or ABORT record to the WAL per call.
fn reconcile_one(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
) -> Result<ReconciliationOutcome, LpmError> {
    let pending = match manifest.pending.get(&intent.package).cloned() {
        Some(p) => p,
        None => {
            // No pending row to reconcile. Either the install root was
            // never created, or a prior partial write wiped the row.
            // Best-effort: remove the install root if it exists, and
            // emit ABORT so future scans don't re-encounter the orphan.
            if intent.new_root_path.exists() {
                let _ = std::fs::remove_dir_all(&intent.new_root_path);
            }
            wal.append(&WalRecord::Abort {
                tx_id: intent.tx_id.clone(),
                reason: "no matching pending row in manifest".into(),
                aborted_at: Utc::now(),
            })?;
            return Ok(ReconciliationOutcome::NothingToDo);
        }
    };

    let status = validate_install_root(&intent.new_root_path, &pending.commands)?;
    if status != InstallRootStatus::Ready {
        return roll_back(root, manifest, wal, intent, &pending, status);
    }

    roll_forward(root, manifest, wal, intent, pending)
}

fn roll_forward(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    pending: PendingEntry,
) -> Result<ReconciliationOutcome, LpmError> {
    // 1. Emit shims for every command this install owns. Each shim
    //    points at the install root's `node_modules/.bin/<cmd>` —
    //    same convention as `commands::run::dlx`'s exec lookup.
    let bin_dir = root.bin_dir();
    let install_bin = intent.new_root_path.join("node_modules").join(".bin");
    for cmd in &pending.commands {
        let target = install_bin.join(cmd);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: cmd.clone(),
                target,
            },
        )?;
    }

    // 2. Apply alias rows from the WAL. The intent payload carries the
    //    full new alias state; we trust it (the install pipeline owns
    //    the collision-resolution policy that produced it).
    apply_new_aliases(manifest, &intent.new_aliases_json);
    // Emit shims for any alias entries that point at this package.
    for (alias_name, alias_entry) in manifest.aliases.clone() {
        if alias_entry.package != intent.package {
            continue;
        }
        let target = install_bin.join(&alias_entry.bin);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: alias_name,
                target,
            },
        )?;
    }

    // 3. Flip [pending] into [packages]. If this is an upgrade, queue
    //    the prior install root in tombstones for the post-commit
    //    sweep / next `store gc`.
    if let Some(prior) = pending.replaces_version.as_ref() {
        // Find the prior active row's root path so we know what to
        // tombstone. We get this from the prior_active_row_json snapshot
        // in the intent — that's the load-bearing reason it's there.
        let prior_root = intent
            .prior_active_row_json
            .as_ref()
            .and_then(|v| v.get("root"))
            .and_then(|v| v.as_str());
        if let Some(p) = prior_root {
            manifest.tombstones.push(p.to_string());
        } else {
            tracing::warn!(
                "recover: upgrade Intent for {} (replacing {}) had no prior root in payload",
                intent.package,
                prior
            );
        }
    }
    let active = PackageEntry {
        saved_spec: pending.saved_spec,
        resolved: pending.resolved,
        integrity: pending.integrity,
        source: pending.source,
        installed_at: Utc::now(),
        root: pending.root,
        commands: pending.commands,
    };
    manifest.packages.insert(intent.package.clone(), active);
    manifest.pending.remove(&intent.package);

    // 4. Append COMMIT.
    wal.append(&WalRecord::Commit {
        tx_id: intent.tx_id.clone(),
        committed_at: Utc::now(),
    })?;

    Ok(ReconciliationOutcome::RolledForward)
}

fn roll_back(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    pending: &PendingEntry,
    status: InstallRootStatus,
) -> Result<ReconciliationOutcome, LpmError> {
    // 1. Best-effort install-root cleanup. On Windows the directory may
    //    be locked by a tool the user is running against the new
    //    version — queue it as a tombstone instead of failing.
    if intent.new_root_path.exists()
        && let Err(e) = std::fs::remove_dir_all(&intent.new_root_path)
    {
        tracing::debug!(
            "recover: deferring install-root cleanup for {} via tombstone: {}",
            intent.package,
            e
        );
        manifest.tombstones.push(pending.root.clone());
    }

    // 2. Restore prior alias state. The WAL snapshot is structured as
    //    {alias_name: AliasEntry | null} where null means "this alias
    //    didn't exist before — remove it on rollback."
    restore_prior_aliases(manifest, &intent.prior_command_ownership_json);

    // 3. Remove every shim this transaction would have owned. For an
    //    upgrade where a prior version owned the same name, we re-emit
    //    that shim from the prior active row in step 4.
    let bin_dir = root.bin_dir();
    for cmd in &pending.commands {
        let _ = remove_shim(&bin_dir, cmd);
    }

    // 4. Restore [packages] from the prior active row if this was an
    //    upgrade. Re-emit shims pointing at the prior install root.
    if let Some(prior_json) = intent.prior_active_row_json.as_ref()
        && let Some(prior_entry) = parse_package_entry_from_json(prior_json)
    {
        let install_bin = root
            .global_root()
            .join(&prior_entry.root)
            .join("node_modules")
            .join(".bin");
        for cmd in &prior_entry.commands {
            let target = install_bin.join(cmd);
            emit_shim(
                &bin_dir,
                &Shim {
                    command_name: cmd.clone(),
                    target,
                },
            )?;
        }
        manifest
            .packages
            .insert(intent.package.clone(), prior_entry);
    }

    // 5. Drop the pending row.
    manifest.pending.remove(&intent.package);

    // 6. Append ABORT.
    wal.append(&WalRecord::Abort {
        tx_id: intent.tx_id.clone(),
        reason: format!("validate_install_root: {status:?}"),
        aborted_at: Utc::now(),
    })?;

    Ok(ReconciliationOutcome::RolledBack {
        reason: format!("{status:?}"),
    })
}

/// Apply the WAL's snapshot of new alias entries into the manifest.
/// `new_aliases_json` shape: `{ "<alias_name>": {"package": "...",
/// "bin": "..."}, ... }`. Defaults gracefully if the field is null
/// (pre-rev-5 IntentPayload that didn't carry the field).
fn apply_new_aliases(manifest: &mut GlobalManifest, new_aliases_json: &serde_json::Value) {
    let serde_json::Value::Object(map) = new_aliases_json else {
        return;
    };
    for (alias_name, value) in map {
        if let (Some(package), Some(bin)) = (
            value.get("package").and_then(|v| v.as_str()),
            value.get("bin").and_then(|v| v.as_str()),
        ) {
            manifest.aliases.insert(
                alias_name.clone(),
                AliasEntry {
                    package: package.to_string(),
                    bin: bin.to_string(),
                },
            );
        }
    }
}

/// Restore aliases from the prior-ownership snapshot taken at INTENT
/// time. Snapshot shape:
/// `{ "aliases": { "<alias>": {"package": "...", "bin": "..."} | null } }`
/// where `null` means "this alias did not exist before; remove it on
/// rollback."
fn restore_prior_aliases(
    manifest: &mut GlobalManifest,
    prior_command_ownership_json: &serde_json::Value,
) {
    let prior_aliases = match prior_command_ownership_json.get("aliases") {
        Some(serde_json::Value::Object(m)) => m,
        _ => return,
    };
    for (alias_name, value) in prior_aliases {
        if value.is_null() {
            manifest.aliases.remove(alias_name);
        } else if let (Some(package), Some(bin)) = (
            value.get("package").and_then(|v| v.as_str()),
            value.get("bin").and_then(|v| v.as_str()),
        ) {
            manifest.aliases.insert(
                alias_name.clone(),
                AliasEntry {
                    package: package.to_string(),
                    bin: bin.to_string(),
                },
            );
        }
    }
}

fn parse_package_entry_from_json(value: &serde_json::Value) -> Option<PackageEntry> {
    let saved_spec = value.get("saved_spec")?.as_str()?.to_string();
    let resolved = value.get("resolved")?.as_str()?.to_string();
    let integrity = value.get("integrity")?.as_str()?.to_string();
    let source: PackageSource = serde_json::from_value(value.get("source")?.clone()).ok()?;
    let installed_at: DateTime<Utc> =
        serde_json::from_value(value.get("installed_at")?.clone()).ok()?;
    let root = value.get("root")?.as_str()?.to_string();
    let commands_arr = value.get("commands")?.as_array()?;
    let commands = commands_arr
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    Some(PackageEntry {
        saved_spec,
        resolved,
        integrity,
        source,
        installed_at,
        root,
        commands,
    })
}

fn compact_wal_if_quiescent(
    wal_path: &std::path::Path,
    records: &[WalRecord],
) -> Result<bool, LpmError> {
    let mut intents = BTreeSet::new();
    let mut resolved = BTreeSet::new();
    for r in records {
        match r {
            WalRecord::Intent(p) => {
                intents.insert(p.tx_id.clone());
            }
            WalRecord::Commit { tx_id, .. } | WalRecord::Abort { tx_id, .. } => {
                resolved.insert(tx_id.clone());
            }
        }
    }
    if intents.is_subset(&resolved) && !records.is_empty() {
        let mut w = WalWriter::open(wal_path)?;
        w.truncate_to_zero()?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_root::{InstallReadyMarker, write_marker};
    use crate::manifest::{PackageSource, write_for};
    use crate::wal::TxKind;
    use std::path::Path;
    use tempfile::TempDir;

    /// Build an install root that `validate_install_root` will accept
    /// for the given `commands`.
    fn make_complete_install_root(install_root: &Path, commands: &[&str]) {
        let bin = install_root.join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        for cmd in commands {
            let target = bin.join(cmd);
            std::fs::write(&target, b"#!/bin/sh\necho ok\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        std::fs::write(install_root.join("lpm.lock"), b"# valid").unwrap();
        write_marker(
            install_root,
            &InstallReadyMarker::new(commands.iter().map(|c| c.to_string()).collect()),
        )
        .unwrap();
    }

    fn intent_install(tx_id: &str, package: &str, new_root: &Path, commands: &[&str]) -> WalRecord {
        let new_row = serde_json::json!({
            "saved_spec": format!("^1"),
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "started_at": "2026-04-15T00:00:00Z",
            "root": format!("installs/{package}@1.0.0"),
            "commands": commands,
        });
        WalRecord::Intent(Box::new(IntentPayload {
            tx_id: tx_id.into(),
            kind: TxKind::Install,
            package: package.into(),
            new_root_path: new_root.to_path_buf(),
            new_row_json: new_row,
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
        }))
    }

    fn pending_install(_package: &str, new_root_relative: &str, commands: &[&str]) -> PendingEntry {
        PendingEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-x".into(),
            source: PackageSource::LpmDev,
            started_at: Utc::now(),
            root: new_root_relative.into(),
            commands: commands.iter().map(|c| c.to_string()).collect(),
            replaces_version: None,
        }
    }

    // ─── Empty-WAL paths ───────────────────────────────────────────

    #[test]
    fn no_wal_returns_empty_report() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let report = recover(&root).unwrap();
        assert!(!report.skipped_due_to_lock);
        assert!(report.reconciled.is_empty());
        assert_eq!(report.torn_tail_truncated_at, None);
        assert!(!report.wal_compacted);
    }

    #[test]
    fn fully_resolved_wal_compacts_to_zero() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        std::fs::create_dir_all(root.global_root()).unwrap();

        // Append an Intent + Commit with no manifest changes — it's
        // already resolved so recovery should compact the file.
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_install(
            "tx1",
            "pkg",
            &tmp.path().join("phantom"),
            &["pkg"],
        ))
        .unwrap();
        w.append(&WalRecord::Commit {
            tx_id: "tx1".into(),
            committed_at: Utc::now(),
        })
        .unwrap();
        let pre = std::fs::metadata(root.global_wal()).unwrap().len();
        assert!(pre > 0);

        let report = recover(&root).unwrap();
        assert!(report.wal_compacted);
        assert_eq!(std::fs::metadata(root.global_wal()).unwrap().len(), 0);
    }

    // ─── Rollback paths ────────────────────────────────────────────

    #[test]
    fn fresh_install_with_partial_root_rolls_back() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let install_root = root.install_root_for("pkg", "1.0.0");
        // Partial: bin dir but no marker.
        std::fs::create_dir_all(install_root.join("node_modules").join(".bin")).unwrap();
        std::fs::write(install_root.join("lpm.lock"), b"x").unwrap();

        let mut manifest = GlobalManifest::default();
        manifest.pending.insert(
            "pkg".into(),
            pending_install("pkg", "installs/pkg@1.0.0", &["pkg"]),
        );
        write_for(&root, &manifest).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_install("tx1", "pkg", &install_root, &["pkg"]))
            .unwrap();

        let report = recover(&root).unwrap();
        assert_eq!(report.reconciled.len(), 1);
        assert!(matches!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledBack { .. }
        ));

        // Manifest pending is gone; packages stays empty (fresh install).
        let final_manifest = read_for(&root).unwrap();
        assert!(final_manifest.pending.is_empty());
        assert!(final_manifest.packages.is_empty());

        // Install root cleaned up.
        assert!(!install_root.exists());
    }

    // ─── Roll-forward paths ────────────────────────────────────────

    #[test]
    fn fresh_install_with_complete_root_rolls_forward() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        make_complete_install_root(&install_root, &["pkg"]);

        let mut manifest = GlobalManifest::default();
        manifest.pending.insert(
            "pkg".into(),
            pending_install("pkg", "installs/pkg@1.0.0", &["pkg"]),
        );
        write_for(&root, &manifest).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_install("tx1", "pkg", &install_root, &["pkg"]))
            .unwrap();

        let report = recover(&root).unwrap();
        assert_eq!(report.reconciled.len(), 1);
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledForward
        );

        // Manifest now has [packages.pkg] and no pending.
        let final_manifest = read_for(&root).unwrap();
        assert!(final_manifest.pending.is_empty());
        assert!(final_manifest.packages.contains_key("pkg"));

        // Shim emitted into ~/.lpm/bin/.
        let bin_path = root.bin_dir().join("pkg");
        #[cfg(unix)]
        assert!(std::fs::symlink_metadata(&bin_path).is_ok());
    }

    // ─── Idempotence ───────────────────────────────────────────────

    #[test]
    fn recover_is_idempotent_running_twice_yields_same_state() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        make_complete_install_root(&install_root, &["pkg"]);

        let mut manifest = GlobalManifest::default();
        manifest.pending.insert(
            "pkg".into(),
            pending_install("pkg", "installs/pkg@1.0.0", &["pkg"]),
        );
        write_for(&root, &manifest).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_install("tx1", "pkg", &install_root, &["pkg"]))
            .unwrap();

        let r1 = recover(&root).unwrap();
        let r2 = recover(&root).unwrap();

        // First run reconciles + compacts; second run sees a clean
        // empty WAL and reports nothing.
        assert_eq!(r1.reconciled.len(), 1);
        assert!(r2.reconciled.is_empty());

        // Manifest state stable across runs.
        let m1 = read_for(&root).unwrap();
        assert!(m1.packages.contains_key("pkg"));
    }

    // ─── Unknown-op ────────────────────────────────────────────────

    #[test]
    fn unknown_op_in_wal_returns_unknown_op_error_without_mutating_state() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        std::fs::create_dir_all(root.global_root()).unwrap();

        // Manually frame a future record op into the WAL.
        use std::io::Write;
        let payload = br#"{"op":"split","tx_id":"tx-future"}"#.to_vec();
        let len: u32 = payload.len() as u32;
        let crc = crc32fast::hash(&payload);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.global_wal())
            .unwrap();
        f.write_all(&len.to_be_bytes()).unwrap();
        f.write_all(&crc.to_be_bytes()).unwrap();
        f.write_all(&payload).unwrap();
        f.write_all(&[0x0A]).unwrap();

        let err = recover(&root).unwrap_err();
        assert!(format!("{err}").contains("unknown record type"));
        assert!(format!("{err}").contains("Upgrade"));

        // WAL not truncated — newer binary's data is preserved.
        let bytes_after = std::fs::metadata(root.global_wal()).unwrap().len();
        assert!(bytes_after > 0);
    }

    // ─── Torn tail ─────────────────────────────────────────────────

    #[test]
    fn torn_tail_is_truncated_and_recovery_proceeds() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_install(
            "tx1",
            "pkg",
            &tmp.path().join("phantom"),
            &["pkg"],
        ))
        .unwrap();
        w.append(&WalRecord::Commit {
            tx_id: "tx1".into(),
            committed_at: Utc::now(),
        })
        .unwrap();

        // Append garbage to simulate a torn third record.
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(root.global_wal())
            .unwrap()
            .write_all(&[1, 2, 3, 4])
            .unwrap();

        let report = recover(&root).unwrap();
        assert!(report.torn_tail_truncated_at.is_some());
    }
}
