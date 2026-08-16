use chrono::Utc;
use lpm_common::{LpmError, LpmRoot, as_extended_path};

use super::ReconciliationOutcome;
use super::manifest_ops::{
    parse_package_entry_from_json, restore_prior_aliases, revert_ownership_change,
};
use super::wal::relative_install_root;
use crate::install_root::InstallRootStatus;
use crate::manifest::{GlobalManifest, PendingEntry, write_for};
use crate::shim::{Shim, emit_shim, remove_shim};
use crate::wal::{IntentPayload, WalRecord, WalWriter};

pub(super) fn roll_back(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    pending: &PendingEntry,
    status: InstallRootStatus,
) -> Result<ReconciliationOutcome, LpmError> {
    // Default cleanup commands = pending.commands. The collision
    // branch in reconcile_one calls `roll_back_with_authoritative_commands`
    // instead so it can pass the marker-derived list (fresh installs have
    // empty pending.commands; collision-leaked shims would otherwise survive
    // rollback).
    roll_back_with_authoritative_commands(root, manifest, wal, intent, status, &pending.commands)
}

/// Roll-back variant that takes an explicit list of commands to clean
/// up rather than reading from `pending.commands`.
///
/// **Why this matters: leaked-shim cleanup.** If an older binary
/// emitted shims for the install before crashing, `pending.commands`
/// can be empty for fresh installs. The leaked shims would survive
/// rollback and keep shadowing the original command owner. By passing
/// the marker-derived commands list, we cover the leaked state.
///
/// **Displaced-owner restoration.** For each command we remove,
/// inspect the manifest for any OTHER package that claims it. If one
/// is found, re-emit that owner's shim pointing at its install root.
/// Without this, an old binary that crashed mid-install of a
/// conflicting package would leave the original eslint package's
/// shim deleted (or pointing at a deleted alt-eslint install root)
/// even after recovery rolls back the conflicting transaction.
pub(super) fn roll_back_with_authoritative_commands(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    wal: &mut WalWriter,
    intent: &IntentPayload,
    status: InstallRootStatus,
    cleanup_commands: &[String],
) -> Result<ReconciliationOutcome, LpmError> {
    let bin_dir = root.bin_dir();

    // 1. Best-effort install-root cleanup. On Windows the directory may
    //    be locked by a tool the user is running against the new
    //    version — queue it as a tombstone instead of failing.
    //
    // Validate the WAL-supplied `new_root_path` against the
    // `installs/<name>@<version>` shape before any unlink. A corrupt
    // Intent with `new_root_path` outside `global_root` skips both the
    // inline delete and the tombstone push.
    let validated_root =
        crate::sweep::validated_install_root_absolute(&root.global_root(), &intent.new_root_path);
    if let Err(reason) = &validated_root {
        tracing::warn!(
            "recover: install-root path for {} is structurally invalid ({reason}); \
             skipping inline delete and tombstone push",
            intent.package,
        );
    }
    let relative_root = validated_root
        .as_ref()
        .ok()
        .and_then(|validated| relative_install_root(root, validated));
    let root_is_referenced = relative_root.as_deref().is_some_and(|relative| {
        manifest.install_root_is_referenced_excluding_pending(relative, &intent.package)
    });
    if relative_root.is_some()
        && !root_is_referenced
        && let Ok(validated_root) = &validated_root
    {
        let validated_root_ext = as_extended_path(validated_root);
        if validated_root_ext.exists()
            && let Err(e) = std::fs::remove_dir_all(&validated_root_ext)
        {
            tracing::debug!(
                "recover: deferring install-root cleanup for {} via tombstone: {}",
                intent.package,
                e
            );
            if let Some(relative) = relative_root {
                manifest.tombstones.push(relative);
            }
        }
    }

    // 1.5 Revert `ownership_delta` mutations.
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
    //
    //    Track `remove_shim` failures: a Windows lock, AV quarantine,
    //    or concurrent recreate can leave a shim on disk pointing at
    //    the rolled-back install root. Ignoring those errors would let
    //    the leaked shim survive forever, so any failure defers the
    //    transaction for the next `lpm` invocation.
    let mut shim_failures: Vec<String> = Vec::new();
    let mut to_restore: Vec<(String, String, String)> = Vec::new(); // (cmd, owner_pkg, owner_root)
    for cmd in cleanup_commands {
        // Skip commands the recovering package itself currently owns
        // (won't happen on a fresh install — the pending row hasn't been
        // promoted to packages yet — but an upgrade could land here).
        if let Some(owner) = manifest.owner_of_command(cmd)
            && owner.package != intent.package
            && let Some(owner_root) = manifest.packages.get(owner.package).map(|e| e.root.clone())
        {
            to_restore.push((cmd.clone(), owner.package.to_string(), owner_root));
        }
        if let Err(e) = remove_shim(&bin_dir, cmd) {
            shim_failures.push(format!("{cmd}: {e}"));
        }
    }
    if let serde_json::Value::Object(m) = &intent.new_aliases_json {
        for alias_name in m.keys() {
            if let Err(e) = remove_shim(&bin_dir, alias_name) {
                shim_failures.push(format!("{alias_name} (alias): {e}"));
            }
        }
    }
    if !shim_failures.is_empty() {
        let reason = format!(
            "rolled-back transaction for '{}' could not clear {} shim(s): {}. \
             Will retry on next invocation.",
            intent.package,
            shim_failures.len(),
            shim_failures.join("; ")
        );
        tracing::warn!(
            "recover: deferring rollback of '{}': {reason}",
            intent.package
        );
        return Ok(ReconciliationOutcome::Deferred { reason });
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
    //    the prior install root. Command-only restore would leave
    //    prior-version aliases pointing at nothing, since we already
    //    cleaned them up. Re-emit any aliases that the restored manifest
    //    claims point at this package, matching roll_forward step 3.
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
