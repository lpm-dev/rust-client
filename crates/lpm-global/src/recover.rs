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
use crate::wal::{
    IntentPayload, OwnershipChange, ScanStop, TxKind, WalReader, WalRecord, WalWriter,
};
use chrono::{DateTime, Utc};
use lpm_common::{LpmError, LpmRoot, try_with_exclusive_lock};
use std::collections::{BTreeMap, BTreeSet, HashSet};

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
    /// Recovery couldn't complete this transaction this pass — usually
    /// because a transient resource (Windows file lock from an AV
    /// scanner, e.g.) was still held. Intent stays in the WAL, no
    /// COMMIT or ABORT was written, recovery will retry on the next
    /// `lpm` invocation. Recovery does NOT propagate this as an error
    /// because doing so would wedge every subsequent global-state
    /// command (audit Medium from M3.3 round).
    Deferred {
        reason: String,
    },
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
    // Dispatch by tx kind. Install/Upgrade share the staged-pending
    // model below; Uninstall has its own idempotent roll-forward
    // because the operation is destructive in-place against
    // [packages.<pkg>] (no [pending] row involved). Recovery for
    // Uninstall always rolls forward — the user's intent was to
    // remove the package; "rollback" would require re-installing,
    // which we can't do without the install pipeline.
    if matches!(intent.kind, TxKind::Uninstall) {
        return roll_forward_uninstall(root, manifest, wal, intent);
    }

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
    // Validate against the pending row's commands when it has any. M3.2
    // ships fresh-install with `pending.commands == []` (commands are
    // discovered during step 2 and recorded in the marker), so we pass
    // `None` to make the marker authoritative — the install commit
    // step uses the same idiom.
    let expected = if pending.commands.is_empty() {
        None
    } else {
        Some(pending.commands.as_slice())
    };
    let status = validate_install_root(&intent.new_root_path, expected)?;
    let marker_commands = match status {
        InstallRootStatus::Ready { commands } => commands,
        other => return roll_back(root, manifest, wal, intent, &pending, other),
    };

    // Defense in depth: recovery-side collision check (audit High from
    // the M3.2 fix round). The user-facing commit_locked already
    // performs this check + inline-rollback, so a well-behaved install
    // should never leave a pending row that would collide. But if
    // state ever does leak (older binary that lacked the commit-side
    // check, manual tampering, future bug), recovery must NOT silently
    // commit a collision. Treat a recovery-time collision as a
    // validate failure and roll back.
    //
    // Use the marker-aware roll-back so leaked shims (an older binary
    // could have emitted shims pointing at the new install before
    // crashing) get cleaned up AND the displaced original owner's
    // shim gets restored. M3.2's pending.commands is empty, so the
    // default roll_back path can't see those shims.
    let collisions = crate::find_command_collisions(manifest, &intent.package, &marker_commands);
    if !collisions.is_empty() {
        let synthetic_status = InstallRootStatus::MarkerCommandMismatch {
            extra: collisions.iter().map(|c| c.command.clone()).collect(),
        };
        return roll_back_with_authoritative_commands(
            root,
            manifest,
            wal,
            intent,
            &pending,
            synthetic_status,
            &marker_commands,
        );
    }

    roll_forward(root, manifest, wal, intent, pending, marker_commands)
}

/// True when `manifest.packages[intent.package]` equals the row this
/// transaction was about to commit. Compares the load-bearing fields:
/// `saved_spec`, `resolved`, `integrity`, `source`, `root` — those are
/// strictly equal because they're declared at Intent time and never
/// shift between Intent and Commit.
///
/// `commands` is compared with **subset semantics**: every command in
/// the Intent's `new_row_json.commands` must appear in the active
/// row's `commands` list, but the active row is allowed to declare
/// MORE commands than the Intent did. This handles M3.2's pipeline
/// where the Intent ships with `commands == []` (a vacuous subset)
/// because bin entries are discovered post-extract from the marker.
/// Pre-fix this comparison was strict and a manifest-written-but-
/// WAL-COMMIT-missing crash for an M3.2 install would have failed
/// Case A, fallen into Case C, and deleted the live install root
/// (audit High #1 from M3.2 round).
///
/// `installed_at` is excluded because recovery may set a different
/// timestamp than the original install. `source` is compared
/// strictly (audit Medium #1 from the second M3.1 round): two installs
/// of the "same" package from `lpm-dev` vs `upstream-npm` differ in
/// future `lpm global update` resolution behavior.
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
    // Subset constraint, not equality. See doc-comment.
    let active_cmds: std::collections::BTreeSet<&str> =
        active.commands.iter().map(String::as_str).collect();
    for cmd in cmd_arr.iter().filter_map(|v| v.as_str()) {
        if !active_cmds.contains(cmd) {
            return false;
        }
    }
    true
}

fn roll_forward(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    pending: PendingEntry,
    // Authoritative command list from the install-ready marker. Used
    // for shim emission AND for the active row's commands field —
    // pending.commands may be empty when M3.2's install pipeline did
    // not pre-resolve bin entries.
    marker_commands: Vec<String>,
) -> Result<ReconciliationOutcome, LpmError> {
    let bin_dir = root.bin_dir();
    let install_bin = intent.new_root_path.join("node_modules").join(".bin");

    // 0. Replay `ownership_delta` (Phase 37 M4.2). Each OwnershipChange
    //    is a typed mutation the commit-time planner recorded; replay
    //    here re-applies the same mutations idempotently. The audit
    //    calls for `diff-derived` logic to be explicitly avoided —
    //    we replay directly from the WAL's enumeration.
    //
    //    Idempotency matters: if a prior recovery already applied the
    //    delta (because of a commit/crash/recovery cycle), each variant
    //    degrades to a no-op on the already-mutated manifest.
    for change in &intent.ownership_delta {
        replay_ownership_change(manifest, &bin_dir, change);
    }

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

    // 2. Emit shims for every command this install owns per the
    //    authoritative marker, EXCEPT those that were aliased away
    //    (M4.2 invariant: declared bins that are exposed under an
    //    alias MUST NOT also appear as direct shims). We compute the
    //    aliased-away set from `ownership_delta`'s AliasInstall
    //    entries: each `bin` field names a declared bin that is
    //    exposed under an alias.
    //
    //    Marker over pending.commands: the marker was written by the
    //    install pipeline AFTER linking the bin shims (M3.1b's
    //    contract). Pre-M3.2, recovery iterated pending.commands; now
    //    M3.2's pipeline writes pending with empty commands and lets
    //    the marker be authoritative.
    let aliased_origs: HashSet<String> = intent
        .ownership_delta
        .iter()
        .filter_map(|c| match c {
            OwnershipChange::AliasInstall { bin, .. } => Some(bin.clone()),
            _ => None,
        })
        .collect();
    let final_commands: Vec<String> = marker_commands
        .iter()
        .filter(|c| !aliased_origs.contains(c.as_str()))
        .cloned()
        .collect();
    for cmd in &final_commands {
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
        // M4.2: use `final_commands` (marker minus aliased-away origs),
        // not marker_commands. The M4 invariant says
        // `PackageEntry.commands` holds ONLY directly-exposed names;
        // aliased-away bins live only in `[aliases]`.
        commands: final_commands,
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

/// Recovery branch for `TxKind::Uninstall` (M3.3).
///
/// Idempotent re-run of the uninstall pipeline: every step is a no-op
/// when its target state is already in place. Recovery can be invoked
/// after a crash at any point in the original transaction and converge
/// to the same end state.
///
/// The Intent's `prior_active_row_json` carries the pre-uninstall
/// commands list, and `prior_command_ownership_json.aliases` carries
/// the alias rows the package owned. Recovery uses both to know what
/// shims to clean up — the manifest itself may already be at the
/// post-uninstall state if the original transaction got past the
/// manifest persist step.
fn roll_forward_uninstall(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
) -> Result<ReconciliationOutcome, LpmError> {
    let bin_dir = root.bin_dir();

    // 1. Remove command shims from the prior snapshot. Idempotent —
    //    `remove_shim` returns `Ok(empty)` when the shim is absent.
    //    Track failures: any persistent shim-removal failure (after
    //    the Windows backoff retries inside `remove_shim`) means we
    //    can't safely commit the uninstall yet. Defer the transaction
    //    so it's retried on the next `lpm` invocation, but don't
    //    propagate as an error (would wedge every subsequent
    //    global-state command). Audit Medium from the M3.3 round.
    let prior_commands: Vec<String> = intent
        .prior_active_row_json
        .as_ref()
        .and_then(|v| v.get("commands"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut shim_failures: Vec<String> = Vec::new();
    for cmd in &prior_commands {
        if let Err(e) = remove_shim(&bin_dir, cmd) {
            shim_failures.push(format!("{cmd}: {e}"));
        }
    }

    // 2. Remove alias shims from the prior ownership snapshot.
    let prior_aliases: Vec<String> = intent
        .prior_command_ownership_json
        .get("aliases")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for alias_name in &prior_aliases {
        if let Err(e) = remove_shim(&bin_dir, alias_name) {
            shim_failures.push(format!("{alias_name} (alias): {e}"));
        }
    }

    if !shim_failures.is_empty() {
        let reason = format!(
            "could not remove {} shim(s) for '{}': {}. Will retry on next invocation.",
            shim_failures.len(),
            intent.package,
            shim_failures.join("; ")
        );
        tracing::warn!(
            "recover: deferring uninstall of '{}': {reason}",
            intent.package
        );
        return Ok(ReconciliationOutcome::Deferred { reason });
    }

    // 3. Drop the manifest row (idempotent) + any alias rows owned by
    //    this package (defensive — the original tx removed them, but
    //    re-running is safe).
    let pkg = intent.package.clone();
    manifest.packages.remove(&pkg);
    manifest.aliases.retain(|_, e| e.package != pkg);

    // 4. Tombstone the install root if it still exists and isn't
    //    already queued. Avoids double-pushing on every recovery pass.
    if intent.new_root_path.exists()
        && let Some(rel) = relative_install_root(root, &intent.new_root_path)
        && !manifest.tombstones.contains(&rel)
    {
        manifest.tombstones.push(rel);
    }

    // 5. Persist manifest BEFORE WAL Commit (M3.1 ordering invariant).
    write_for(root, manifest)?;

    // 6. Best-effort install-root cleanup. If this fails the tombstone
    //    we just queued keeps the retry alive for `store gc`.
    if intent.new_root_path.exists() {
        let _ = std::fs::remove_dir_all(&intent.new_root_path);
    }

    // 7. Append Commit.
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
    // Default cleanup commands = pending.commands. The collision
    // branch in reconcile_one calls `roll_back_with_authoritative_commands`
    // instead so it can pass the marker-derived list (M3.2 has empty
    // pending.commands; collision-leaked shims would otherwise survive
    // rollback).
    roll_back_with_authoritative_commands(
        root,
        manifest,
        wal,
        intent,
        pending,
        status,
        &pending.commands,
    )
}

/// Roll-back variant that takes an explicit list of commands to clean
/// up rather than reading from `pending.commands`.
///
/// **Why this matters: leaked-shim cleanup.** If an older binary
/// emitted shims for the install before crashing (the pre-M3.2-fix
/// collision-then-crash scenario), `pending.commands` is empty for
/// M3.2 fresh installs. The leaked shims would survive rollback and
/// keep shadowing the original command owner. By passing the
/// marker-derived commands list (the same list `commit_locked` would
/// have iterated to emit shims), we cover the leaked state.
///
/// **Displaced-owner restoration.** For each command we remove,
/// inspect the manifest for any OTHER package that claims it. If one
/// is found, re-emit that owner's shim pointing at its install root.
/// Without this, an old binary that crashed mid-install of a
/// conflicting package would leave the original eslint package's
/// shim deleted (or pointing at a deleted alt-eslint install root)
/// even after recovery rolls back the conflicting transaction.
fn roll_back_with_authoritative_commands(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    pending: &PendingEntry,
    status: InstallRootStatus,
    cleanup_commands: &[String],
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

    // 1.5 Revert `ownership_delta` mutations (Phase 37 M4.2).
    //
    //    The crash could have happened AFTER commit_locked began its
    //    manifest mutation (dropping the displaced owner's command or
    //    alias row) but BEFORE the WAL COMMIT append. In that window,
    //    the current-manifest scan in step 2 can't find the displaced
    //    owner — they've already lost the command. Reverting each
    //    delta FIRST puts the manifest back into the pre-commit_locked
    //    state, so step 2's scan finds the real owner again.
    //
    //    Idempotent: if the mutation was never applied (crash happened
    //    before commit_locked mutated manifest), the revert variants
    //    degrade to no-ops (insert-overwrite with same value; retain
    //    that finds nothing to push; remove that returns None).
    for change in intent.ownership_delta.iter().rev() {
        revert_ownership_change(manifest, &bin_dir, change, root);
    }

    // 2. Remove the new install's own shims, and for any command that
    //    the manifest claims is owned by ANOTHER package, restore that
    //    owner's shim (pointing at their install root). The owner
    //    lookup happens BEFORE removal so we don't false-positive on
    //    aliases the new install would have written (see step 2b).
    let mut to_restore: Vec<(String, String, String)> = Vec::new(); // (cmd, owner_pkg, owner_root)
    for cmd in cleanup_commands {
        // Skip commands the recovering package itself currently owns
        // (won't happen on M3.2 fresh install — the pending row hasn't
        // been promoted to packages yet — but a future M3.4 upgrade
        // could land here).
        if let Some(owner) = manifest.owner_of_command(cmd)
            && owner.package != intent.package
            && let Some(owner_root) = manifest.packages.get(owner.package).map(|e| e.root.clone())
        {
            to_restore.push((cmd.clone(), owner.package.to_string(), owner_root));
        }
        let _ = remove_shim(&bin_dir, cmd);
    }
    if let serde_json::Value::Object(m) = &intent.new_aliases_json {
        for alias_name in m.keys() {
            let _ = remove_shim(&bin_dir, alias_name);
        }
    }
    // Re-emit any displaced owner's shim. Pointing at the owner's
    // existing `node_modules/.bin/<cmd>` per the install pipeline's
    // shim-target convention.
    for (cmd, owner_pkg, owner_root) in &to_restore {
        let target = root
            .global_root()
            .join(owner_root)
            .join("node_modules")
            .join(".bin")
            .join(cmd);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: cmd.clone(),
                target,
            },
        )?;
        tracing::info!(
            "recover: restored displaced shim '{}' (owner: {})",
            cmd,
            owner_pkg
        );
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

/// Phase 37 M4.2: replay one OwnershipChange against the manifest
/// during recovery roll-forward.
///
/// Mirrors `install_global::apply_ownership_change_to_manifest` (kept
/// in lpm-cli because that's where the planner lives) — duplicated
/// here because lpm-global is lower-layer and can't depend on lpm-cli.
/// The two copies are semantically identical; if one changes, update
/// both together.
///
/// Idempotent for every variant: replaying a delta already applied is
/// a no-op (retain() filters nothing; remove() returns None; insert
/// overwrites with same value).
fn replay_ownership_change(
    manifest: &mut GlobalManifest,
    bin_dir: &std::path::Path,
    change: &OwnershipChange,
) {
    match change {
        OwnershipChange::DirectTransfer {
            command,
            from_package,
            ..
        } => {
            if let Some(owner) = manifest.packages.get_mut(from_package) {
                owner.commands.retain(|c| c != command);
            }
            // The shim for `command` is re-emitted in roll_forward step 2
            // pointing at the new install root. emit_shim is atomic so
            // no explicit removal is needed here.
        }
        OwnershipChange::AliasOwnerRemove { alias_name, .. } => {
            manifest.aliases.remove(alias_name);
            // The shim for the alias_name will be re-emitted in
            // roll_forward step 2 (if the new package has it as a
            // direct bin) or step 3 (if it's a new alias). Either way
            // emit_shim handles the atomic rewrite. No explicit remove
            // needed — but we DO remove it to cover the edge where
            // the new install doesn't re-emit under this name at all.
            let _ = remove_shim(bin_dir, alias_name);
        }
        OwnershipChange::AliasInstall {
            alias_name,
            package,
            bin,
        } => {
            manifest.aliases.insert(
                alias_name.clone(),
                AliasEntry {
                    package: package.clone(),
                    bin: bin.clone(),
                },
            );
        }
    }
}

/// Phase 37 M4.2: inverse of `replay_ownership_change`. Used by
/// `roll_back_with_authoritative_commands` to revert each delta entry,
/// putting the manifest back into the pre-commit_locked state so the
/// standard displaced-owner logic can run from a consistent baseline.
///
/// Every variant is idempotent when applied against a manifest that
/// has NOT been mutated yet — insert-with-same-value is a no-op, and
/// the "is this command in the list" check prevents duplicate pushes.
///
/// Also re-emits the displaced owner's shim where it existed before,
/// so the user's PATH ends up pointing at their old install even when
/// the crash happened after shim swap.
fn revert_ownership_change(
    manifest: &mut GlobalManifest,
    bin_dir: &std::path::Path,
    change: &OwnershipChange,
    root: &LpmRoot,
) {
    match change {
        OwnershipChange::DirectTransfer {
            command,
            from_package,
            from_row_snapshot,
        } => {
            // Restore the displaced owner's row from the snapshot.
            // Whether or not commit_locked had already mutated the row,
            // the snapshot IS the pre-commit state, so overwriting is
            // always correct.
            if let Some(entry) = parse_package_entry_from_json(from_row_snapshot) {
                // Re-emit the shim for `command` pointing at the
                // displaced owner's install root, using the snapshot's
                // root path.
                let install_bin = root
                    .global_root()
                    .join(&entry.root)
                    .join("node_modules")
                    .join(".bin");
                let target = install_bin.join(command);
                let _ = emit_shim(
                    bin_dir,
                    &Shim {
                        command_name: command.clone(),
                        target,
                    },
                );
                manifest.packages.insert(from_package.clone(), entry);
            }
        }
        OwnershipChange::AliasOwnerRemove {
            alias_name,
            entry_snapshot,
        } => {
            // Restore the alias row from the snapshot.
            if let (Some(package), Some(bin)) = (
                entry_snapshot.get("package").and_then(|v| v.as_str()),
                entry_snapshot.get("bin").and_then(|v| v.as_str()),
            ) {
                // Re-emit the shim under `alias_name` pointing at the
                // displaced owner's `bin` entry. Best-effort: if the
                // owner's row was itself removed, the shim restore
                // would point at a missing target — survivable because
                // the user can uninstall/reinstall. We still restore
                // the manifest row either way.
                if let Some(owner_entry) = manifest.packages.get(package) {
                    let install_bin = root
                        .global_root()
                        .join(&owner_entry.root)
                        .join("node_modules")
                        .join(".bin");
                    let target = install_bin.join(bin);
                    let _ = emit_shim(
                        bin_dir,
                        &Shim {
                            command_name: alias_name.clone(),
                            target,
                        },
                    );
                }
                manifest.aliases.insert(
                    alias_name.clone(),
                    AliasEntry {
                        package: package.to_string(),
                        bin: bin.to_string(),
                    },
                );
            }
        }
        OwnershipChange::AliasInstall { alias_name, .. } => {
            // The AliasInstall created a new alias row for the
            // installing package. Undo: drop it. The shim for
            // `alias_name` is removed by roll_back step 2's generic
            // `new_aliases_json` sweep (we don't need to remove it
            // twice).
            manifest.aliases.remove(alias_name);
        }
    }
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
    use std::path::{Path, PathBuf};
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
            ownership_delta: Vec::new(),
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
            ownership_delta: Vec::new(),
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

    /// Audit High (M3.2 round): `active_matches_intent` must accept
    /// the M3.2-shaped flow where the Intent records `commands == []`
    /// (commands are discovered from the marker post-extract) but the
    /// committed active row carries the marker-derived list. Pre-fix
    /// this comparison was strict and would have failed Case A on every
    /// successful M3.2 install whose WAL COMMIT didn't make it to disk.
    /// Subset semantics: Intent's commands must be a SUBSET of the
    /// active row's commands.
    #[test]
    fn case_a_matches_when_intent_commands_empty_and_active_has_marker_discovered_commands() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Stage the post-commit state: install root complete, manifest
        // has the active row with marker-derived commands, no pending
        // row. Simulates the M3.2 "manifest persisted, WAL append
        // crashed" window.
        let install_root = root.install_root_for("chalk-cli", "6.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        make_complete_install_root(&install_root, &["chalk"]);

        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "chalk-cli".into(),
            PackageEntry {
                saved_spec: "^6.0.0".into(),
                resolved: "6.0.0".into(),
                integrity: "sha512-abc".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: "installs/chalk-cli@6.0.0".into(),
                commands: vec!["chalk".into()],
            },
        );
        write_for(&root, &manifest).unwrap();

        // Intent records commands=[] (M3.2 pipeline shape: bin entries
        // are unknown until post-extract).
        let intent = WalRecord::Intent(Box::new(IntentPayload {
            tx_id: "tx1".into(),
            kind: TxKind::Install,
            package: "chalk-cli".into(),
            new_root_path: install_root.clone(),
            new_row_json: serde_json::json!({
                "saved_spec": "^6.0.0",
                "resolved": "6.0.0",
                "integrity": "sha512-abc",
                "source": "upstream-npm",
                "installed_at": "2026-04-15T00:00:00Z",
                "root": "installs/chalk-cli@6.0.0",
                "commands": [],
            }),
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
            ownership_delta: Vec::new(),
        }));
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent).unwrap();

        let report = recover(&root).unwrap();
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::AlreadyCommitted,
            "M3.2 commands-discovered-from-marker pattern must be Case A, NOT Case C"
        );
        assert!(
            install_root.exists(),
            "live install root must NOT be deleted"
        );
    }

    /// Even with subset semantics, an Intent that explicitly lists a
    /// command the active row doesn't own is still a real mismatch —
    /// strict subset, not arbitrary acceptance. (Symmetric of the
    /// audit Medium that source comparison must be strict.)
    #[test]
    fn case_a_does_not_match_when_intent_commands_not_subset_of_active() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        make_complete_install_root(&install_root, &["foo"]);

        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "pkg".into(),
            PackageEntry {
                saved_spec: "^1.0.0".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/pkg@1.0.0".into(),
                commands: vec!["foo".into()], // active has foo
            },
        );
        write_for(&root, &manifest).unwrap();

        // Intent expects `bar` but active has only `foo`. Subset fails.
        let intent = WalRecord::Intent(Box::new(IntentPayload {
            tx_id: "tx1".into(),
            kind: TxKind::Install,
            package: "pkg".into(),
            new_root_path: install_root.clone(),
            new_row_json: serde_json::json!({
                "saved_spec": "^1.0.0",
                "resolved": "1.0.0",
                "integrity": "sha512-x",
                "source": "lpm-dev",
                "installed_at": "2026-04-15T00:00:00Z",
                "root": "installs/pkg@1.0.0",
                "commands": ["bar"],
            }),
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
            ownership_delta: Vec::new(),
        }));
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent).unwrap();

        let report = recover(&root).unwrap();
        // Falls into Case C (orphan), NOT AlreadyCommitted.
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::NothingToDo,
            "non-subset commands must NOT match Case A"
        );
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
            ownership_delta: Vec::new(),
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

    /// Audit High (M3.2 fix round) — defense in depth: recovery must
    /// NOT silently roll forward a pending install whose marker
    /// commands would collide with an existing package's commands.
    /// The commit-side fix in `install_global::commit_locked` should
    /// prevent this state from ever existing, but if it ever does
    /// (older binary, manual tampering), recovery refuses to commit
    /// it and rolls back instead. Without this check, a user could be
    /// told "this install was refused" and then have it silently
    /// committed by the next `lpm` invocation that triggers recovery.
    #[test]
    fn recovery_rolls_back_when_pending_install_would_collide_with_existing_package() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Existing install owns `eslint`.
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "eslint".into(),
            PackageEntry {
                saved_spec: "^9".into(),
                resolved: "9.24.0".into(),
                integrity: "sha512-old".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: "installs/eslint@9.24.0".into(),
                commands: vec!["eslint".into()],
            },
        );

        // Pending install of a DIFFERENT package whose marker also
        // exposes `eslint`. Pre-fix, recovery would have rolled this
        // forward and silently overwritten the existing eslint shim.
        let install_root = root.install_root_for("alt-eslint", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        make_complete_install_root(&install_root, &["eslint"]);
        manifest.pending.insert(
            "alt-eslint".into(),
            pending_install("alt-eslint", "installs/alt-eslint@1.0.0", &[]),
        );
        write_for(&root, &manifest).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_install(
            "tx-collide",
            "alt-eslint",
            &install_root,
            &[],
        ))
        .unwrap();

        let report = recover(&root).unwrap();
        assert!(matches!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledBack { .. }
        ));

        // Existing eslint package still owns `eslint`.
        let final_manifest = read_for(&root).unwrap();
        assert!(final_manifest.packages.contains_key("eslint"));
        assert!(!final_manifest.packages.contains_key("alt-eslint"));
        assert!(!final_manifest.pending.contains_key("alt-eslint"));
    }

    // ─── M3.3 uninstall recovery ──────────────────────────────────

    fn intent_uninstall(
        tx_id: &str,
        package: &str,
        install_root: &Path,
        commands: &[&str],
        aliases: &[(&str, &str, &str)], // (alias_name, owner_pkg, bin)
    ) -> WalRecord {
        let prior_active = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": format!("installs/{package}@1.0.0"),
            "commands": commands,
        });
        let alias_map: serde_json::Map<String, serde_json::Value> = aliases
            .iter()
            .map(|(name, pkg, bin)| {
                (
                    name.to_string(),
                    serde_json::json!({"package": pkg, "bin": bin}),
                )
            })
            .collect();
        WalRecord::Intent(Box::new(IntentPayload {
            tx_id: tx_id.into(),
            kind: TxKind::Uninstall,
            package: package.into(),
            new_root_path: install_root.to_path_buf(),
            new_row_json: serde_json::Value::Null,
            prior_active_row_json: Some(prior_active),
            prior_command_ownership_json: serde_json::json!({
                "aliases": serde_json::Value::Object(alias_map),
            }),
            new_aliases_json: serde_json::Value::Null,
            ownership_delta: Vec::new(),
        }))
    }

    /// Recovery for an Uninstall that crashed BEFORE any state mutation.
    /// Manifest still has the package, shims still exist, install root
    /// still exists. Roll forward must complete the uninstall.
    #[test]
    #[cfg(unix)]
    fn recovery_completes_uninstall_that_crashed_before_any_state_change() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Package is still in manifest with all its rows.
        let install_root = root.install_root_for("eslint", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "eslint".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/eslint@1.0.0".into(),
                commands: vec!["eslint".into()],
            },
        );
        write_for(&root, &manifest).unwrap();

        // Shim still in place.
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink("/some/where", root.bin_dir().join("eslint")).unwrap();

        // Intent recorded but never committed.
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_uninstall(
            "tx-uninstall",
            "eslint",
            &install_root,
            &["eslint"],
            &[],
        ))
        .unwrap();

        let report = recover(&root).unwrap();
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledForward
        );

        let final_manifest = read_for(&root).unwrap();
        assert!(!final_manifest.packages.contains_key("eslint"));
        assert!(
            std::fs::symlink_metadata(root.bin_dir().join("eslint")).is_err(),
            "shim should be gone"
        );
        assert!(!install_root.exists(), "install root should be cleaned");
    }

    /// Recovery for an Uninstall that crashed AFTER manifest persist
    /// but before WAL Commit. Manifest is already at the final state;
    /// recovery just needs to emit the missing Commit (idempotently
    /// re-running the cleanup as a no-op is fine).
    #[test]
    fn recovery_uninstall_idempotent_when_manifest_already_clean() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Manifest is already at the post-uninstall state.
        let install_root = root.install_root_for("eslint", "1.0.0");
        write_for(&root, &GlobalManifest::default()).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_uninstall(
            "tx-uninstall",
            "eslint",
            &install_root,
            &["eslint"],
            &[],
        ))
        .unwrap();

        let report = recover(&root).unwrap();
        assert_eq!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledForward
        );
        // Manifest still empty.
        assert!(read_for(&root).unwrap().packages.is_empty());
    }

    /// Recovery cleans up alias rows owned by the package — even if
    /// the original transaction crashed before doing so itself.
    #[test]
    fn recovery_uninstall_drops_owned_alias_rows() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.install_root_for("pkg-b", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();

        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "pkg-b".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/pkg-b@1.0.0".into(),
                commands: vec!["serve".into()],
            },
        );
        manifest.aliases.insert(
            "srv".into(),
            AliasEntry {
                package: "pkg-b".into(),
                bin: "serve".into(),
            },
        );
        write_for(&root, &manifest).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_uninstall(
            "tx",
            "pkg-b",
            &install_root,
            &["serve"],
            &[("srv", "pkg-b", "serve")],
        ))
        .unwrap();

        recover(&root).unwrap();
        let final_manifest = read_for(&root).unwrap();
        assert!(!final_manifest.aliases.contains_key("srv"));
    }

    /// Audit Medium (M3.3 round): recovery-side defense. When a shim
    /// can't be removed (Windows AV lock simulated as Unix EACCES on
    /// bin_dir), recovery must NOT propagate as an error — that
    /// would wedge every subsequent global-state command. Instead it
    /// returns `Deferred` so the Intent stays in the WAL for the
    /// next invocation to retry.
    #[test]
    #[cfg(unix)]
    fn recovery_uninstall_defers_when_shim_removal_fails() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.install_root_for("eslint", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();

        // Manifest still has the package + shim still in bin_dir
        // (mid-uninstall crash state).
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "eslint".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/eslint@1.0.0".into(),
                commands: vec!["eslint".into()],
            },
        );
        write_for(&root, &manifest).unwrap();
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink("/some/where", root.bin_dir().join("eslint")).unwrap();

        // Drop write perm on bin_dir → remove_shim returns EACCES.
        let original_perms = std::fs::metadata(root.bin_dir()).unwrap().permissions();
        std::fs::set_permissions(root.bin_dir(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_uninstall(
            "tx-deferred",
            "eslint",
            &install_root,
            &["eslint"],
            &[],
        ))
        .unwrap();

        let report = recover(&root);

        // Restore perms before any assertion-driven panic.
        std::fs::set_permissions(root.bin_dir(), original_perms).unwrap();

        let report = report.unwrap();
        assert_eq!(report.reconciled.len(), 1);
        match &report.reconciled[0].outcome {
            ReconciliationOutcome::Deferred { reason } => {
                assert!(reason.contains("eslint"));
                assert!(reason.contains("retry"));
            }
            other => panic!("expected Deferred, got {other:?}"),
        }

        // Manifest unchanged — package still active.
        let final_manifest = read_for(&root).unwrap();
        assert!(final_manifest.packages.contains_key("eslint"));
        // No Commit / Abort written for this tx — Intent stays in WAL.
        let scan = WalReader::at(root.global_wal()).scan().unwrap();
        assert_eq!(scan.records.len(), 1, "only the original Intent");
    }

    /// Idempotence: running recovery twice on a half-completed
    /// uninstall converges to the same state as running it once.
    #[test]
    fn recovery_uninstall_is_idempotent_across_repeated_invocations() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
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
        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_uninstall("tx", "pkg", &install_root, &["pkg"], &[]))
            .unwrap();

        let r1 = recover(&root).unwrap();
        let r2 = recover(&root).unwrap();
        assert_eq!(r1.reconciled.len(), 1);
        assert!(r2.reconciled.is_empty());
        let m = read_for(&root).unwrap();
        assert!(m.packages.is_empty());
    }

    /// Audit Medium (M3.2 audit pass-3): the previous fix made
    /// recovery refuse to roll forward a colliding install, but the
    /// roll-back path used `pending.commands` (empty for M3.2) so any
    /// shim a pre-fix binary had already emitted before crashing
    /// survived rollback. This test stages exactly that
    /// "old-binary-leaked-shim" state and verifies recovery cleans
    /// the leaked shim AND restores the original owner's shim.
    #[test]
    #[cfg(unix)]
    fn recovery_collision_rollback_cleans_leaked_shims_and_restores_displaced_owner() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Existing eslint package, complete and live.
        let eslint_root = root.install_root_for("eslint", "9.24.0");
        std::fs::create_dir_all(&eslint_root).unwrap();
        make_complete_install_root(&eslint_root, &["eslint"]);

        // Pending alt-eslint that will collide on the `eslint` command.
        let alt_root = root.install_root_for("alt-eslint", "1.0.0");
        std::fs::create_dir_all(&alt_root).unwrap();
        make_complete_install_root(&alt_root, &["eslint"]);

        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "eslint".into(),
            PackageEntry {
                saved_spec: "^9".into(),
                resolved: "9.24.0".into(),
                integrity: "sha512-old".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: "installs/eslint@9.24.0".into(),
                commands: vec!["eslint".into()],
            },
        );
        manifest.pending.insert(
            "alt-eslint".into(),
            pending_install("alt-eslint", "installs/alt-eslint@1.0.0", &[]),
        );
        write_for(&root, &manifest).unwrap();

        // Simulate the leaked state: the old binary had ALREADY emitted
        // the `eslint` shim pointing at alt-eslint's install root
        // BEFORE crashing. We're starting recovery with the manifest's
        // [packages.eslint] still present, but the bin shim points at
        // the OTHER install.
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        let leaked_target = alt_root.join("node_modules").join(".bin").join("eslint");
        std::os::unix::fs::symlink(&leaked_target, root.bin_dir().join("eslint")).unwrap();

        let mut w = WalWriter::open(root.global_wal()).unwrap();
        w.append(&intent_install("tx-leaked", "alt-eslint", &alt_root, &[]))
            .unwrap();

        let report = recover(&root).unwrap();
        assert!(matches!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledBack { .. }
        ));

        // The leaked shim must now point at the ORIGINAL eslint
        // package's install root, not the alt-eslint one (which was
        // also deleted by rollback).
        let restored_target = std::fs::read_link(root.bin_dir().join("eslint")).unwrap();
        let expected_target = eslint_root.join("node_modules").join(".bin").join("eslint");
        assert_eq!(
            restored_target, expected_target,
            "leaked shim should be restored to point at the displaced owner"
        );
        assert!(
            !alt_root.exists(),
            "the alt-eslint install root should be cleaned up"
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
            ownership_delta: Vec::new(),
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
            ownership_delta: Vec::new(),
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

    // ─── Phase 37 M4.2: ownership_delta replay + revert ───────────────
    //
    // The M4.2 audit calls out that replace-ownership and recovery are
    // not independently shippable — a crash between Intent and Commit
    // without recovery extensions strands the displaced owner. These
    // tests pin the crash-window behavior on both axes.

    /// Seed a package row to act as the displaced owner in the tests below.
    fn seed_displaced_owner(
        manifest: &mut GlobalManifest,
        name: &str,
        commands: &[&str],
    ) -> PackageEntry {
        let entry = PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-displaced".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: format!("installs/{name}@1.0.0"),
            commands: commands.iter().map(|s| (*s).to_string()).collect(),
        };
        manifest.packages.insert(name.into(), entry.clone());
        entry
    }

    /// replay_ownership_change(DirectTransfer) must drop the command
    /// from the displaced owner's `commands` list. Roll-forward path.
    #[test]
    fn replay_direct_transfer_drops_command_from_old_owner() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut m = GlobalManifest::default();
        seed_displaced_owner(&mut m, "http-server", &["serve", "http"]);

        let change = OwnershipChange::DirectTransfer {
            command: "serve".into(),
            from_package: "http-server".into(),
            from_row_snapshot: serde_json::Value::Null,
        };
        replay_ownership_change(&mut m, &root.bin_dir(), &change);

        assert_eq!(m.packages["http-server"].commands, vec!["http"]);
    }

    /// replay_ownership_change(AliasOwnerRemove) must drop the alias row
    /// AND remove the alias shim.
    #[test]
    fn replay_alias_owner_remove_drops_alias_row() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut m = GlobalManifest::default();
        m.aliases.insert(
            "serve".into(),
            AliasEntry {
                package: "other".into(),
                bin: "server".into(),
            },
        );

        let change = OwnershipChange::AliasOwnerRemove {
            alias_name: "serve".into(),
            entry_snapshot: serde_json::json!({"package":"other","bin":"server"}),
        };
        replay_ownership_change(&mut m, &root.bin_dir(), &change);

        assert!(m.aliases.is_empty());
    }

    /// replay is idempotent: running twice produces the same state.
    #[test]
    fn replay_ownership_change_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut m = GlobalManifest::default();
        seed_displaced_owner(&mut m, "x", &["s"]);
        let change = OwnershipChange::DirectTransfer {
            command: "s".into(),
            from_package: "x".into(),
            from_row_snapshot: serde_json::Value::Null,
        };
        replay_ownership_change(&mut m, &root.bin_dir(), &change);
        replay_ownership_change(&mut m, &root.bin_dir(), &change);
        assert!(m.packages["x"].commands.is_empty());
    }

    /// revert_ownership_change(DirectTransfer) MUST restore the old
    /// owner's row from the snapshot. Roll-back path — critical for the
    /// M4.2 audit Finding #1 case (crash between Intent and Commit
    /// without recovery extensions strands the displaced owner).
    #[test]
    fn revert_direct_transfer_restores_displaced_owner_from_snapshot() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut m = GlobalManifest::default();
        // Seed a POST-commit-mutation state: http-server's row has
        // already lost `serve` (commit_locked mutated the manifest
        // before the crash).
        seed_displaced_owner(&mut m, "http-server", &["http"]);

        // Snapshot taken at Intent time (pre-commit state): http-server
        // still had `serve`.
        let pre_commit_snapshot = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-displaced",
            "source": "upstream-npm",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/http-server@1.0.0",
            "commands": ["serve", "http"],
        });
        let change = OwnershipChange::DirectTransfer {
            command: "serve".into(),
            from_package: "http-server".into(),
            from_row_snapshot: pre_commit_snapshot,
        };
        revert_ownership_change(&mut m, &root.bin_dir(), &change, &root);

        // Old owner's row restored with the pre-commit commands list.
        let restored = &m.packages["http-server"];
        assert_eq!(restored.commands, vec!["serve", "http"]);
        assert_eq!(restored.integrity, "sha512-displaced");
    }

    /// revert(AliasOwnerRemove) restores the alias row — keyed by the
    /// EXPOSED name (alias key), per the audit Finding #3 tightening.
    #[test]
    fn revert_alias_owner_remove_restores_alias_row_keyed_by_exposed_name() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut m = GlobalManifest::default();
        // Simulate post-commit state: alias row was already removed.
        // Also seed the displaced owner's package row so revert can
        // re-emit the shim (it looks up the owner's root).
        seed_displaced_owner(&mut m, "other-pkg", &["server"]);

        let snapshot = serde_json::json!({"package": "other-pkg", "bin": "server"});
        let change = OwnershipChange::AliasOwnerRemove {
            alias_name: "serve".into(), // the EXPOSED PATH name
            entry_snapshot: snapshot,
        };
        revert_ownership_change(&mut m, &root.bin_dir(), &change, &root);

        let entry = m.aliases.get("serve").expect("alias must be restored");
        assert_eq!(entry.package, "other-pkg");
        assert_eq!(entry.bin, "server");
    }

    /// revert(AliasInstall) drops the newly-written alias row. This is
    /// the "fresh install being rolled back" case.
    #[test]
    fn revert_alias_install_drops_new_alias_row() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut m = GlobalManifest::default();
        m.aliases.insert(
            "foo-serve".into(),
            AliasEntry {
                package: "foo".into(),
                bin: "serve".into(),
            },
        );
        let change = OwnershipChange::AliasInstall {
            alias_name: "foo-serve".into(),
            package: "foo".into(),
            bin: "serve".into(),
        };
        revert_ownership_change(&mut m, &root.bin_dir(), &change, &root);
        assert!(m.aliases.is_empty());
    }

    /// revert is idempotent: running twice yields the same state.
    /// Specifically, the DirectTransfer case already-restored doesn't
    /// double-restore (the snapshot matches exactly, insert-overwrites).
    #[test]
    fn revert_ownership_change_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut m = GlobalManifest::default();
        seed_displaced_owner(&mut m, "x", &["s"]);

        let snapshot = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-displaced",
            "source": "upstream-npm",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/x@1.0.0",
            "commands": ["s", "t"],
        });
        let change = OwnershipChange::DirectTransfer {
            command: "s".into(),
            from_package: "x".into(),
            from_row_snapshot: snapshot,
        };
        revert_ownership_change(&mut m, &root.bin_dir(), &change, &root);
        revert_ownership_change(&mut m, &root.bin_dir(), &change, &root);
        assert_eq!(m.packages["x"].commands, vec!["s", "t"]);
    }

    /// Integration: IntentPayload round-trips through JSON with
    /// populated ownership_delta. The WAL format stays forward-compat
    /// because OwnershipChange uses internally-tagged serde.
    #[test]
    fn intent_payload_with_ownership_delta_round_trips_json() {
        let payload = IntentPayload {
            tx_id: "tx1".into(),
            kind: TxKind::Install,
            package: "foo".into(),
            new_root_path: PathBuf::from("/tmp/installs/foo@1.0.0"),
            new_row_json: serde_json::json!({"resolved": "1.0.0"}),
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
            ownership_delta: vec![
                OwnershipChange::DirectTransfer {
                    command: "serve".into(),
                    from_package: "http-server".into(),
                    from_row_snapshot: serde_json::json!({"resolved": "2.0.0"}),
                },
                OwnershipChange::AliasOwnerRemove {
                    alias_name: "srv".into(),
                    entry_snapshot: serde_json::json!({"package":"x","bin":"y"}),
                },
                OwnershipChange::AliasInstall {
                    alias_name: "foo-serve".into(),
                    package: "foo".into(),
                    bin: "serve".into(),
                },
            ],
        };
        let json = serde_json::to_vec(&payload).unwrap();
        let parsed: IntentPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, payload);
    }

    /// Pre-M4.2 WAL entries (without `ownership_delta`) must still
    /// deserialize cleanly. `#[serde(default)]` on the field guarantees
    /// this; pin it so a future refactor doesn't drop the attribute.
    #[test]
    fn pre_m42_intent_payload_without_ownership_delta_still_deserializes() {
        let json = serde_json::json!({
            "tx_id": "tx-old",
            "kind": "install",
            "package": "old-pkg",
            "new_root_path": "/tmp/installs/old-pkg@1.0.0",
            "new_row_json": {"resolved": "1.0.0"},
            "prior_active_row_json": null,
            "prior_command_ownership_json": {},
            "new_aliases_json": {},
            // ownership_delta intentionally missing
        });
        let parsed: IntentPayload = serde_json::from_value(json).unwrap();
        assert!(parsed.ownership_delta.is_empty());
    }
}
