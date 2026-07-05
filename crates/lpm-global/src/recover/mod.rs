//! `lpm_global::recover()`: WAL replay + manifest
//! reconciliation at startup.
//!
//! Invoked exactly once per `lpm` invocation, **before** command
//! dispatch, when the parsed command is in `command_needs_global_state`
//!. Recovery is idempotent — running it twice produces the
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
use crate::manifest::{GlobalManifest, read_for, write_for};
use crate::wal::{IntentPayload, ScanStop, TxKind, WalReader, WalRecord, WalWriter};
use chrono::Utc;
use lpm_common::{LpmError, LpmRoot, as_extended_path, try_with_exclusive_lock};
use std::collections::{BTreeMap, BTreeSet};

mod manifest_ops;
mod roll_back;
mod roll_forward;
mod wal;

#[cfg(test)]
mod tests;

use self::manifest_ops::{post_resolution_path_names, post_resolution_view};
use self::roll_back::{roll_back, roll_back_with_authoritative_commands};
use self::roll_forward::{roll_forward, roll_forward_uninstall};
use self::wal::{compact_wal_if_quiescent, relative_install_root};

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
    /// command.
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
/// the main.rs hook so users get an actionable upgrade prompt.
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
    // the WAL append but before the manifest persist, the next
    // recovery would see no uncompleted INTENT, skip recovery, and
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
/// still has the pending row.
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
    // Active-row matching must happen before orphan cleanup; otherwise
    // a valid Case A crash window can be mistaken for disposable debris.
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
        // retry. Dropping the cleanup error would strand permanent
        // debris with no manifest handle.
        //
        // Validate the WAL-supplied `new_root_path` against the
        // `installs/<name>@<version>` shape before any unlink. A corrupt
        // WAL with `new_root_path = "/etc/passwd"` or any non-shape
        // path skips the inline delete and tombstone push; the orphan
        // path still resolves via WAL Abort but no outside-tree
        // filesystem mutation runs.
        let mut tombstoned = false;
        let new_root_ext = as_extended_path(&intent.new_root_path);
        let path_shape = crate::sweep::validated_install_root_absolute(
            &root.global_root(),
            &intent.new_root_path,
        );
        if let Err(reason) = &path_shape {
            tracing::warn!(
                "recover: orphan-root path for tx {} is structurally invalid ({reason}); \
                 skipping inline delete and tombstone push",
                intent.tx_id,
            );
        }
        if path_shape.is_ok()
            && new_root_ext.exists()
            && let Err(e) = std::fs::remove_dir_all(&new_root_ext)
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
    // Validate against the pending row's commands when it has any. Fresh
    // installs have `pending.commands == []` (commands are discovered
    // during step 2 and recorded in the marker), so we pass
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

    // Defense in depth: recovery-side collision check.
    //
    // The user-facing commit_locked already runs this against the
    // post-resolution state, so a well-behaved install will not leave
    // a pending row that would collide here. But recovery must keep
    // checking — leaked shims (older binary that lacked the commit-side
    // check, manual tampering, future bug) must not silently commit.
    //
    // The check honours `ownership_delta` and `new_aliases_json`: a
    // user who explicitly resolved a collision via `--replace-bin` or
    // `--alias` recorded that resolution in the second Intent, and the
    // post-resolution state is collision-free by construction. Scanning
    // the raw manifest and raw marker commands would roll back an
    // install whose collision resolutions were already durably recorded.
    // Replaying the delta into a working view matches the planner's
    // residual-collision check and tests the PATH names that will
    // actually be exposed after commit.
    let path_names = post_resolution_path_names(&marker_commands, intent);
    let working_view = post_resolution_view(manifest, intent);
    let collisions = crate::find_command_collisions(&working_view, &intent.package, &path_names);
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
/// MORE commands than the Intent did. This handles the pipeline
/// where the Intent ships with `commands == []` (a vacuous subset)
/// because bin entries are discovered post-extract from the marker.
/// Strict equality would fail the manifest-written-but-WAL-COMMIT-
/// missing crash window and could delete a live install root.
///
/// `installed_at` is excluded because recovery may set a different
/// timestamp than the original install. `source` is compared
/// strictly: two installs of the "same" package from `lpm-dev` vs `upstream-npm` differ in
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
