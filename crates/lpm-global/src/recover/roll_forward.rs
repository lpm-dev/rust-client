use std::collections::HashSet;

use chrono::Utc;
use lpm_common::{LpmError, LpmRoot, as_extended_path};

use super::ReconciliationOutcome;
use super::manifest_ops::{apply_new_aliases, replay_ownership_change};
use super::wal::relative_install_root;
use crate::manifest::{AliasEntry, GlobalManifest, PackageEntry, PendingEntry, write_for};
use crate::shim::{Shim, emit_shim, remove_shim};
use crate::wal::{IntentPayload, OwnershipChange, WalRecord, WalWriter};

pub(super) fn roll_forward(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    pending: PendingEntry,
    // Authoritative command list from the install-ready marker. Used
    // for shim emission AND for the active row's commands field —
    // pending.commands may be empty when the install pipeline did
    // not pre-resolve bin entries.
    marker_commands: Vec<String>,
) -> Result<ReconciliationOutcome, LpmError> {
    let bin_dir = root.bin_dir();
    let install_bin = intent.new_root_path.join("node_modules").join(".bin");

    // 0. Replay `ownership_delta`. Each OwnershipChange
    //    is a typed mutation the commit-time planner recorded; replay
    //    here re-applies the same mutations idempotently. Recovery
    //    replays directly from the WAL's enumeration instead of
    //    inferring changes from a manifest diff.
    //
    //    Idempotency matters: if a prior recovery already applied the
    //    delta (because of a commit/crash/recovery cycle), each variant
    //    degrades to a no-op on the already-mutated manifest.
    for change in &intent.ownership_delta {
        replay_ownership_change(manifest, &bin_dir, change);
    }

    // 1. Reconcile aliases against the authoritative snapshot in
    //    `new_aliases_json`. The snapshot is the FULL set of aliases
    //    this package owns post-commit. A merge-only update would keep
    //    aliases that an upgrade removed, so recovery first drops every
    //    alias the package currently owns, then applies the snapshot.
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
    //    (invariant: declared bins that are exposed under an
    //    alias MUST NOT also appear as direct shims). We compute the
    //    aliased-away set from two sources:
    //      - `ownership_delta`'s AliasInstall entries (install path):
    //        each `bin` field names a declared bin exposed via a new
    //        alias the install creates.
    //      - `new_aliases_json`'s `bin` fields: the snapshot of aliases
    //        the package owns post-commit. For upgrades that preserve
    //        prior aliases, `ownership_delta` is empty and this is the
    //        only signal.
    //
    //    Marker over pending.commands: the marker was written by the
    //    install pipeline AFTER linking the bin shims (marker contract).
    //    Previously, recovery iterated pending.commands; now
    //    the pipeline writes pending with empty commands and lets
    //    the marker be authoritative.
    let mut aliased_origs: HashSet<String> = intent
        .ownership_delta
        .iter()
        .filter_map(|c| match c {
            OwnershipChange::AliasInstall { bin, .. } => Some(bin.clone()),
            _ => None,
        })
        .collect();
    if let serde_json::Value::Object(m) = &intent.new_aliases_json {
        for entry in m.values() {
            if let Some(bin) = entry.get("bin").and_then(|v| v.as_str()) {
                aliased_origs.insert(bin.to_string());
            }
        }
    }
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
        // use `final_commands` (marker minus aliased-away origs),
        // not marker_commands. The invariant says
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

/// Recovery branch for `TxKind::Uninstall`.
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
pub(super) fn roll_forward_uninstall(
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
    //    propagate as an error because that would wedge every
    //    subsequent global-state command.
    //
    // Derive the command list from a structurally valid snapshot, or
    // fall back to the live manifest's `[packages.<pkg>]` row when the
    // snapshot is missing or malformed. A silent empty fallback would
    // commit the uninstall while orphaning emitted shims that have no
    // manifest row left to reconcile them. Falling back to the manifest
    // row keeps the cleanup intent honest: if both sources lack commands
    // for this package, the package was already structurally without
    // shims and the empty-vector path is correct.
    let snapshot_commands: Option<Vec<String>> = intent
        .prior_active_row_json
        .as_ref()
        .and_then(|v| v.get("commands"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    let prior_commands: Vec<String> = match snapshot_commands {
        Some(c) => c,
        None => {
            // Snapshot malformed → consult the live manifest. This
            // gives recovery the same cleanup surface the original
            // uninstall would have computed, instead of silently
            // dropping it.
            let fallback = manifest
                .packages
                .get(&intent.package)
                .map(|e| e.commands.clone())
                .unwrap_or_default();
            tracing::warn!(
                "recover: uninstall snapshot for '{}' missing/malformed commands array; \
                 falling back to live manifest row ({} command(s))",
                intent.package,
                fallback.len(),
            );
            fallback
        }
    };
    let mut shim_failures: Vec<String> = Vec::new();
    for cmd in &prior_commands {
        if let Err(e) = remove_shim(&bin_dir, cmd) {
            shim_failures.push(format!("{cmd}: {e}"));
        }
    }

    // 2. Remove alias shims from the prior ownership snapshot.
    //
    // Use the same snapshot-then-fallback shape as the commands step.
    // When `prior_command_ownership_json.aliases` is missing or not an
    // object, fall back to walking the manifest's `[aliases.*]` rows
    // owned by this package; that is the same surface the original
    // uninstall would have iterated.
    let snapshot_aliases: Option<Vec<String>> = intent
        .prior_command_ownership_json
        .get("aliases")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect());
    let prior_aliases: Vec<String> = match snapshot_aliases {
        Some(a) => a,
        None => {
            let fallback: Vec<String> = manifest
                .aliases
                .iter()
                .filter(|(_, entry)| entry.package == intent.package)
                .map(|(name, _)| name.clone())
                .collect();
            tracing::warn!(
                "recover: uninstall snapshot for '{}' missing/malformed aliases object; \
                 falling back to live manifest alias rows ({} alias(es))",
                intent.package,
                fallback.len(),
            );
            fallback
        }
    };
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

    // 2b. Replay the host-global trust prune.
    //
    // The Intent carries the prune set computed at uninstall time.
    // `remove_many` is idempotent: a crash AFTER the original tx
    // pruned re-enters recovery and replays here as a no-op (count
    // = 0). A crash BEFORE the original tx pruned executes the
    // prune for the first time here. Either way the end state is
    // identical.
    //
    // Empty prune payloads are a no-op, whether from older WAL files,
    // installs/upgrades that do not prune anything, or the conservative
    // fail-safe at uninstall time; we do not even open the trust file.
    if !intent.uninstall_trust_prune.is_empty() {
        let mut trust = crate::trusted_deps::read_for(root)?;
        let exact_keys: Vec<&str> = intent
            .uninstall_trust_prune
            .iter()
            .filter_map(|entry| entry.key.as_deref())
            .collect();
        let prune_pairs: Vec<(&str, &str)> = intent
            .uninstall_trust_prune
            .iter()
            .filter(|entry| entry.key.is_none())
            .map(|e| (e.name.as_str(), e.version.as_str()))
            .collect();
        let removed = trust.remove_exact_keys(&exact_keys) + trust.remove_many(&prune_pairs);
        if removed > 0 {
            crate::trusted_deps::write_for(root, &trust)?;
            tracing::info!(
                "recover: replayed uninstall trust-prune for '{}' — {removed} entries removed",
                intent.package
            );
        }
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

    // 5. Persist manifest BEFORE WAL Commit (manifest-before-commit ordering invariant).
    write_for(root, manifest)?;

    // 6. Best-effort install-root cleanup. If this fails the tombstone
    //    we just queued keeps the retry alive for `store gc`.
    //
    // Skip the inline delete when the WAL-supplied path does not match
    // the `installs/<name>@<version>` shape. The sweep step already
    // refused to push the relative form if it was not under
    // `global_root`, so the tombstone retry will not fire either.
    let new_root_ext = as_extended_path(&intent.new_root_path);
    if new_root_ext.exists()
        && crate::sweep::validated_install_root_absolute(&root.global_root(), &intent.new_root_path)
            .is_ok()
    {
        let _ = std::fs::remove_dir_all(&new_root_ext);
    }

    // 7. Append Commit.
    wal.append(&WalRecord::Commit {
        tx_id: intent.tx_id.clone(),
        committed_at: Utc::now(),
    })?;

    Ok(ReconciliationOutcome::RolledForward)
}
