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
    /// The manifest already reflects the committed state — the prior
    /// recovery / install attempt persisted the manifest mutation
    /// before crashing during the WAL COMMIT write. We just emit the
    /// missing COMMIT to make the WAL agree with the manifest.
    /// (Closes the Case A crash window: manifest written, WAL not.)
    AlreadyCommitted,
    /// The WAL referenced a manifest state we don't recognize — the
    /// install root is gone, the pending row is gone, the active row
    /// doesn't match. Emitted as ABORT so future scans don't
    /// re-encounter the orphan.
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

    // Per-tx ordering matters: the manifest write MUST hit disk before
    // the WAL COMMIT/ABORT record gets appended. If we crashed after
    // the WAL append but before the manifest persist (the inverse of
    // the High finding from the M3.1 audit), the next recovery would
    // see no uncompleted INTENT (resolved), skip recovery, and
    // permanently lose the reconciliation result. Per-tx persistence
    // closes that window: at any crash point the WAL never says "done"
    // unless the manifest already does.
    for intent in uncompleted {
        let outcome = reconcile_one(root, &mut manifest, &mut wal_writer, &intent)?;
        reconciled.push(ReconciledTx {
            tx_id: intent.tx_id.clone(),
            package: intent.package.clone(),
            outcome,
        });
    }

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

/// Reconcile one uncompleted INTENT. Persists manifest changes
/// **before** appending the WAL COMMIT/ABORT so a crash mid-step never
/// leaves the WAL claiming a transaction is done while the manifest
/// still has the pending row (the High finding from the M3.1 audit).
fn reconcile_one(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
) -> Result<ReconciliationOutcome, LpmError> {
    // First branch: handle the "no pending row" case. This is NOT
    // automatically a no-op: we have to distinguish the two scenarios
    // it covers, only one of which is safe to ABORT.
    //
    // Case A — Crash between manifest persist and WAL COMMIT:
    //   The previous attempt (recovery or install) successfully wrote
    //   the manifest's [packages.<pkg>] row but crashed before the
    //   WAL COMMIT record. The active row matches the intent's
    //   `new_row_json`. Recovery's job is to emit the missing COMMIT
    //   so the WAL agrees with the manifest. NO state mutation, NO
    //   install-root cleanup — the install is correct and live.
    //
    // Case C — Truly orphaned INTENT:
    //   No pending row, no matching active row. Either the manifest
    //   write never happened or someone deleted state out from under
    //   us. Best-effort install-root cleanup + ABORT.
    //
    // The pre-fix code conflated A and C and would have deleted the
    // active install root in Case A. Now we check active first.
    if !manifest.pending.contains_key(&intent.package) {
        if active_matches_intent(manifest, intent) {
            // Case A — manifest is at the committed state. Just emit
            // COMMIT. No manifest mutation needed; the WAL is what's
            // out of date.
            wal.append(&WalRecord::Commit {
                tx_id: intent.tx_id.clone(),
                committed_at: Utc::now(),
            })?;
            return Ok(ReconciliationOutcome::AlreadyCommitted);
        }
        // Case C — orphaned. Try to clean the install root; on
        // failure (Windows lock from a tool the user is running
        // against the orphaned bin, permission error, etc.), queue
        // the path as a tombstone so `store gc` / next recovery can
        // retry. Pre-fix the error was dropped silently and the path
        // sat as permanent debris (audit Low #2).
        let mut tombstoned = false;
        if intent.new_root_path.exists()
            && let Err(e) = std::fs::remove_dir_all(&intent.new_root_path)
        {
            if let Some(rel) = relative_install_root(root, &intent.new_root_path) {
                tracing::debug!(
                    "recover: deferring orphan-root cleanup for tx {} via tombstone: {}",
                    intent.tx_id,
                    e
                );
                manifest.tombstones.push(rel);
                tombstoned = true;
            } else {
                tracing::warn!(
                    "recover: orphan root {} could not be cleaned and is outside global_root, dropping: {}",
                    intent.new_root_path.display(),
                    e
                );
            }
        }
        // Persist tombstone before WAL ABORT so recovery's "manifest
        // is the source of truth" invariant holds in the orphan path
        // too.
        if tombstoned {
            write_for(root, manifest)?;
        }
        wal.append(&WalRecord::Abort {
            tx_id: intent.tx_id.clone(),
            reason: "no matching pending row and active row does not match new_row".into(),
            aborted_at: Utc::now(),
        })?;
        return Ok(ReconciliationOutcome::NothingToDo);
    }

    let pending = manifest.pending.get(&intent.package).cloned().unwrap();
    let status = validate_install_root(&intent.new_root_path, &pending.commands)?;
    if status != InstallRootStatus::Ready {
        return roll_back(root, manifest, wal, intent, &pending, status);
    }

    roll_forward(root, manifest, wal, intent, pending)
}

/// True when `manifest.packages[intent.package]` equals the row this
/// transaction was about to commit. Compares the load-bearing fields:
/// `saved_spec`, `resolved`, `integrity`, `source`, `root`, `commands`.
/// These are what the install pipeline writes into [packages] at
/// commit time, and what `lpm global update` re-resolves against.
///
/// `installed_at` is excluded because recovery may set a different
/// timestamp than the original install. Everything else is compared
/// strictly — particularly `source` (audit Medium #1): two installs
/// of the "same" package from `lpm-dev` vs `upstream-npm` would
/// otherwise be conflated, and a Case-A match would happily emit
/// COMMIT for the wrong persisted source, silently changing future
/// `lpm global update` behavior.
fn active_matches_intent(manifest: &GlobalManifest, intent: &IntentPayload) -> bool {
    let Some(active) = manifest.packages.get(&intent.package) else {
        return false;
    };
    let Some(new_row) = intent.new_row_json.as_object() else {
        return false;
    };
    let str_field = |k: &str| new_row.get(k).and_then(|v| v.as_str());
    let arr_field = |k: &str| new_row.get(k).and_then(|v| v.as_array());

    if str_field("saved_spec") != Some(active.saved_spec.as_str()) {
        return false;
    }
    if str_field("resolved") != Some(active.resolved.as_str()) {
        return false;
    }
    if str_field("integrity") != Some(active.integrity.as_str()) {
        return false;
    }
    // `source` is serialized as a kebab-case string ("lpm-dev" /
    // "upstream-npm") on both sides. Round-trip the active row's
    // enum through serde so the canonical string comes from the same
    // rename rule the WAL writer uses — no risk of a stale duplicate
    // mapping drifting out of sync.
    let active_source = serde_json::to_value(active.source)
        .ok()
        .and_then(|v| v.as_str().map(String::from));
    if str_field("source") != active_source.as_deref() {
        return false;
    }
    if str_field("root") != Some(active.root.as_str()) {
        return false;
    }
    let Some(cmd_arr) = arr_field("commands") else {
        return false;
    };
    let new_cmds: Vec<&str> = cmd_arr.iter().filter_map(|v| v.as_str()).collect();
    if new_cmds
        != active
            .commands
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return false;
    }
    true
}

fn roll_forward(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    pending: PendingEntry,
) -> Result<ReconciliationOutcome, LpmError> {
    let bin_dir = root.bin_dir();
    let install_bin = intent.new_root_path.join("node_modules").join(".bin");

    // 1. Reconcile aliases against the authoritative snapshot in
    //    `new_aliases_json`. The snapshot is the FULL set of aliases
    //    this package owns post-commit. Pre-fix, the merge code only
    //    inserted/updated, so an upgrade that *removed* an alias would
    //    silently keep the stale row and re-emit its shim. Now we
    //    first drop every alias the package currently owns, then
    //    apply the snapshot — making it authoritative both ways.
    let prior_pkg_aliases: Vec<(String, AliasEntry)> = manifest
        .aliases
        .iter()
        .filter(|(_, e)| e.package == intent.package)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (alias_name, _) in &prior_pkg_aliases {
        manifest.aliases.remove(alias_name);
        // Also remove the shim for any prior alias that's NOT in the
        // new snapshot. Aliases that are in the snapshot get their
        // shim re-emitted below pointing at the new install root.
        if !alias_in_snapshot(&intent.new_aliases_json, alias_name) {
            let _ = remove_shim(&bin_dir, alias_name);
        }
    }
    apply_new_aliases(manifest, &intent.new_aliases_json);

    // 2. Emit shims for every command this install owns. Each shim
    //    points at the install root's `node_modules/.bin/<cmd>` —
    //    same convention as `commands::run::dlx`'s exec lookup.
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

    // 3. Emit shims for every alias entry this package owns post-snapshot.
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

    // 4. Flip [pending] into [packages]. If this is an upgrade, queue
    //    the prior install root in tombstones for the post-commit
    //    sweep / next `store gc`.
    if let Some(prior) = pending.replaces_version.as_ref() {
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

    // 5. Persist manifest BEFORE WAL append. See reconcile_one's
    //    Case A discussion — the manifest must be at the committed
    //    state before the WAL claims so.
    write_for(root, manifest)?;

    // 6. Append COMMIT.
    wal.append(&WalRecord::Commit {
        tx_id: intent.tx_id.clone(),
        committed_at: Utc::now(),
    })?;

    Ok(ReconciliationOutcome::RolledForward)
}

/// True when `new_aliases_json` (from an INTENT payload) contains an
/// entry for `alias_name`.
fn alias_in_snapshot(snapshot: &serde_json::Value, alias_name: &str) -> bool {
    matches!(snapshot, serde_json::Value::Object(m) if m.contains_key(alias_name))
}

fn roll_back(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    pending: &PendingEntry,
    status: InstallRootStatus,
) -> Result<ReconciliationOutcome, LpmError> {
    let bin_dir = root.bin_dir();

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

    // 2. Remove the new install's own shims (commands declared on the
    //    pending row). For aliases, also remove every shim the new
    //    install would have owned per the snapshot. Those alias shims
    //    point at the dead install root and must be cleaned up before
    //    restoring prior state.
    for cmd in &pending.commands {
        let _ = remove_shim(&bin_dir, cmd);
    }
    if let serde_json::Value::Object(m) = &intent.new_aliases_json {
        for alias_name in m.keys() {
            let _ = remove_shim(&bin_dir, alias_name);
        }
    }

    // 3. Restore prior manifest state. Aliases first so the package
    //    row's shim re-emit (step 4) sees a consistent alias table.
    restore_prior_aliases(manifest, &intent.prior_command_ownership_json);

    // 4. Restore [packages] from the prior active row if this was an
    //    upgrade. Re-emit command shims AND alias shims pointing at
    //    the prior install root. Pre-fix, only command shims got
    //    re-emitted, so aliases the prior version owned were left
    //    pointing at... nothing (we already cleaned them up). Now we
    //    re-emit any aliases that the restored manifest claims point
    //    at this package — same predicate as roll_forward step 3.
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
        // Re-emit alias shims for any alias the restored manifest now
        // claims this package owns.
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
        manifest
            .packages
            .insert(intent.package.clone(), prior_entry);
    }

    // 5. Drop the pending row.
    manifest.pending.remove(&intent.package);

    // 6. Persist manifest BEFORE WAL append. See reconcile_one's
    //    Case A discussion.
    write_for(root, manifest)?;

    // 7. Append ABORT.
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

/// Convert an absolute install root path into the relative form the
/// `manifest.tombstones` list expects (`installs/<name>@<ver>`).
/// Returns `None` if the path lives outside `root.global_root()` —
/// a defensive check; recovery will refuse to tombstone in that case
/// rather than write a path the gc sweeper would interpret as
/// untrusted.
fn relative_install_root(root: &LpmRoot, abs_path: &std::path::Path) -> Option<String> {
    abs_path
        .strip_prefix(root.global_root())
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
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

    // ─── M3.1 audit regressions ────────────────────────────────────

    /// Helper: construct an INTENT with a pre-built `new_row_json` so the
    /// "active matches new_row" check has structured fields to compare.
    fn intent_with_new_row(
        tx_id: &str,
        package: &str,
        new_root: &Path,
        commands: &[&str],
    ) -> WalRecord {
        let new_row = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "installed_at": "2026-04-15T00:00:00Z",
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

    /// Audit High Finding 1+2: when the manifest already reflects the
    /// committed state (Case A — crash between manifest persist and
    /// WAL COMMIT), recovery must NOT delete the active install root.
    /// It must emit COMMIT and report `AlreadyCommitted`.
    #[test]
    fn case_a_already_committed_emits_commit_and_does_not_touch_install_root() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Plant a complete install root.
        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        make_complete_install_root(&install_root, &["pkg"]);

        // Manifest has the committed state already (no pending row,
        // [packages.pkg] points at the install root).
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "pkg".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/pkg@1.0.0".into(),
                commands: vec!["pkg".into()],
            },
        );
        write_for(&root, &manifest).unwrap();

        // WAL has the INTENT but no COMMIT — Case A from the audit.
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_with_new_row("tx1", "pkg", &install_root, &["pkg"]))
            .unwrap();

        let report = recover(&root).unwrap();
        assert_eq!(report.reconciled.len(), 1);
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::AlreadyCommitted,
            "must classify Case A as AlreadyCommitted, not rollback"
        );

        // The install root MUST still exist (the pre-fix code would
        // have deleted it).
        assert!(
            install_root.exists(),
            "active install root must not be deleted in Case A"
        );
        // [packages.pkg] still present and unchanged.
        let final_manifest = read_for(&root).unwrap();
        assert!(final_manifest.packages.contains_key("pkg"));
    }

    /// Audit Medium #1: `active_matches_intent` must compare `source`,
    /// not just spec/version/integrity/root/commands. Otherwise a
    /// Case-A match could fire for the wrong source value, silently
    /// changing future `lpm global update` resolution behavior.
    #[test]
    fn case_a_does_not_match_when_only_source_differs() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        make_complete_install_root(&install_root, &["pkg"]);

        // Active row says LpmDev. Intent's new_row says upstream-npm.
        // Every other field matches — pre-fix this would have hit
        // Case A and emitted COMMIT for the wrong source.
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "pkg".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/pkg@1.0.0".into(),
                commands: vec!["pkg".into()],
            },
        );
        write_for(&root, &manifest).unwrap();

        // Intent uses the same fields but flips source → upstream-npm.
        let new_row = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "upstream-npm",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/pkg@1.0.0",
            "commands": ["pkg"],
        });
        let intent = WalRecord::Intent(Box::new(IntentPayload {
            tx_id: "tx1".into(),
            kind: TxKind::Install,
            package: "pkg".into(),
            new_root_path: install_root.clone(),
            new_row_json: new_row,
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
        }));
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent).unwrap();

        let report = recover(&root).unwrap();
        // Source mismatch → falls through to Case C (orphaned).
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::NothingToDo,
            "source mismatch must NOT be classified as AlreadyCommitted"
        );
    }

    /// Truly orphaned INTENT: no pending, no matching active. Recovery
    /// must clean up the install root and emit ABORT.
    #[test]
    fn case_c_orphaned_intent_cleans_up_and_aborts() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::write(install_root.join("partial"), b"x").unwrap();

        // Manifest is empty (no pending, no matching active).
        write_for(&root, &GlobalManifest::default()).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_with_new_row("tx1", "pkg", &install_root, &["pkg"]))
            .unwrap();

        let report = recover(&root).unwrap();
        assert_eq!(report.reconciled.len(), 1);
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::NothingToDo
        );
        assert!(!install_root.exists(), "orphan root should be cleaned up");
    }

    /// Audit Low #2: when Case-C cleanup fails (e.g. Windows lock,
    /// permission error), the orphan path must be queued as a
    /// tombstone so `store gc` / next recovery can retry. Pre-fix the
    /// error was dropped silently and the path became permanent debris.
    #[test]
    #[cfg(unix)]
    fn case_c_locked_orphan_root_gets_tombstoned() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::write(install_root.join("file"), b"content").unwrap();

        // Drop write permission on the parent (the install_root's
        // parent directory == root.global_installs()) so that
        // `remove_dir_all` cannot remove the install_root entry.
        // POSIX requires write permission on a directory to unlink
        // its children.
        let installs_dir = root.global_installs();
        let original_perms = std::fs::metadata(&installs_dir).unwrap().permissions();
        std::fs::set_permissions(&installs_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        // Manifest has neither pending nor matching active → Case C.
        write_for(&root, &GlobalManifest::default()).unwrap();

        let new_row = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/pkg@1.0.0",
            "commands": ["pkg"],
        });
        let intent = WalRecord::Intent(Box::new(IntentPayload {
            tx_id: "tx1".into(),
            kind: TxKind::Install,
            package: "pkg".into(),
            new_root_path: install_root.clone(),
            new_row_json: new_row,
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
        }));
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent).unwrap();

        let report = recover(&root).unwrap();

        // Restore perms before any assertion-driven panic so the
        // tempdir cleanup doesn't get stuck.
        std::fs::set_permissions(&installs_dir, original_perms).unwrap();

        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::NothingToDo
        );

        // The locked orphan should now be in tombstones for store gc.
        let final_manifest = read_for(&root).unwrap();
        assert!(
            final_manifest
                .tombstones
                .iter()
                .any(|t| t.contains("pkg@1.0.0")),
            "locked orphan root must be tombstoned, got tombstones: {:?}",
            final_manifest.tombstones
        );
    }

    /// Audit Medium Finding 3: roll-forward must remove obsolete
    /// aliases that the new snapshot doesn't claim, including their
    /// shims. Without the fix, an upgrade that drops an alias would
    /// leave the stale row + stale shim.
    #[test]
    fn roll_forward_removes_alias_obsoleted_by_new_snapshot() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        make_complete_install_root(&install_root, &["pkg"]);

        // Pre-existing alias `srv` → pkg's `serve` bin (from a prior
        // install). Emit its shim too so we can verify cleanup.
        let mut manifest = GlobalManifest::default();
        manifest.aliases.insert(
            "srv".into(),
            AliasEntry {
                package: "pkg".into(),
                bin: "serve".into(),
            },
        );
        manifest.pending.insert(
            "pkg".into(),
            pending_install("pkg", "installs/pkg@1.0.0", &["pkg"]),
        );
        write_for(&root, &manifest).unwrap();
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/dev/null", root.bin_dir().join("srv")).unwrap();

        // Intent with EMPTY new_aliases_json — the upgrade dropped the
        // alias.
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_with_new_row("tx1", "pkg", &install_root, &["pkg"]))
            .unwrap();

        let report = recover(&root).unwrap();
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledForward
        );

        let final_manifest = read_for(&root).unwrap();
        assert!(
            !final_manifest.aliases.contains_key("srv"),
            "obsolete alias should be removed by snapshot"
        );
        #[cfg(unix)]
        assert!(
            std::fs::symlink_metadata(root.bin_dir().join("srv")).is_err(),
            "obsolete alias shim should be removed"
        );
    }

    /// Audit Medium Finding 4: rollback must remove alias shims the
    /// new install would have owned, AND restore alias shims for the
    /// prior version. Pre-fix, only command shims got handled.
    #[test]
    #[cfg(unix)]
    fn roll_back_cleans_up_new_alias_shims_and_restores_prior_alias_shims() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Prior install root for upgrade — keep it complete.
        let prior_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&prior_root).unwrap();
        make_complete_install_root(&prior_root, &["pkg", "serve"]);

        // New install root is INCOMPLETE so recovery rolls back.
        let new_root = root.install_root_for("pkg", "2.0.0");
        std::fs::create_dir_all(&new_root).unwrap();
        // No marker — validate_install_root returns MissingMarker.

        // Manifest: [packages.pkg] active, [pending.pkg] for upgrade,
        // [aliases.srv] currently points at pkg's serve.
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "pkg".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/pkg@1.0.0".into(),
                commands: vec!["pkg".into(), "serve".into()],
            },
        );
        manifest.aliases.insert(
            "srv".into(),
            AliasEntry {
                package: "pkg".into(),
                bin: "serve".into(),
            },
        );
        manifest.pending.insert(
            "pkg".into(),
            PendingEntry {
                saved_spec: "^2".into(),
                resolved: "2.0.0".into(),
                integrity: "sha512-y".into(),
                source: PackageSource::LpmDev,
                started_at: Utc::now(),
                root: "installs/pkg@2.0.0".into(),
                commands: vec!["pkg".into()],
                replaces_version: Some("1.0.0".into()),
            },
        );
        write_for(&root, &manifest).unwrap();

        // Plant a "new" alias shim that the upgrade tried to install
        // (e.g. an alias `pkg2` → bin) — recovery must clean this up.
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink(
            new_root.join("node_modules/.bin/pkg"),
            root.bin_dir().join("pkg2"),
        )
        .unwrap();

        // Intent says the upgrade was going to add alias `pkg2` → pkg's
        // pkg bin, replacing the prior `srv` alias.
        let new_row = serde_json::json!({
            "saved_spec": "^2",
            "resolved": "2.0.0",
            "integrity": "sha512-y",
            "source": "lpm-dev",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/pkg@2.0.0",
            "commands": ["pkg"],
        });
        let prior_row = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/pkg@1.0.0",
            "commands": ["pkg", "serve"],
        });
        let intent = WalRecord::Intent(Box::new(IntentPayload {
            tx_id: "tx1".into(),
            kind: TxKind::Upgrade,
            package: "pkg".into(),
            new_root_path: new_root.clone(),
            new_row_json: new_row,
            prior_active_row_json: Some(prior_row),
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({
                "pkg2": {"package": "pkg", "bin": "pkg"}
            }),
        }));

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent).unwrap();

        let report = recover(&root).unwrap();
        assert!(matches!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledBack { .. }
        ));

        // The new install's alias shim should be GONE.
        assert!(
            std::fs::symlink_metadata(root.bin_dir().join("pkg2")).is_err(),
            "new alias shim must be cleaned up on rollback"
        );

        // The prior alias `srv` is restored in the manifest AND its
        // shim points at the prior install root's serve bin.
        let final_manifest = read_for(&root).unwrap();
        assert!(
            final_manifest.aliases.contains_key("srv"),
            "prior alias must be restored in manifest"
        );
        let srv_link = root.bin_dir().join("srv");
        let resolved = std::fs::read_link(&srv_link).unwrap();
        assert!(
            resolved.ends_with("installs/pkg@1.0.0/node_modules/.bin/serve"),
            "prior alias shim must point at prior install root: {resolved:?}"
        );
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
