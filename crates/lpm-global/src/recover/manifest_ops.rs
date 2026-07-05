use std::collections::HashSet;

use chrono::{DateTime, Utc};
use lpm_common::LpmRoot;

use crate::manifest::{AliasEntry, GlobalManifest, PackageEntry, PackageSource};
use crate::shim::{Shim, emit_shim, remove_shim};
use crate::wal::{IntentPayload, OwnershipChange};

/// PATH names the transaction would expose AFTER its
/// `--replace-bin`/`--alias` resolutions are applied: marker commands
/// minus any that the user aliased away, plus every new alias key.
///
/// Used by the recovery-side collision check so a user-resolved
/// install whose crash landed between the second Intent and WAL Commit
/// is not rolled back as if the collision were unresolved.
///
/// "Aliased away" is the union of two sources: `ownership_delta`'s
/// AliasInstall `bin` fields (install path with explicit `--alias`),
/// and `new_aliases_json`'s `bin` fields (upgrade path preserving
/// prior aliases).
pub(super) fn post_resolution_path_names(
    marker_commands: &[String],
    intent: &IntentPayload,
) -> Vec<String> {
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
    let mut out: Vec<String> = marker_commands
        .iter()
        .filter(|c| !aliased_origs.contains(c.as_str()))
        .cloned()
        .collect();
    if let serde_json::Value::Object(m) = &intent.new_aliases_json {
        out.extend(m.keys().cloned());
    }
    out
}

/// Manifest clone with the "freeing" subset of `ownership_delta`
/// applied — `DirectTransfer` and `AliasOwnerRemove` mutations that
/// release PATH names the installing package will take. `AliasInstall`
/// is intentionally NOT applied: replaying it would make the installing
/// package own the new alias rows, and `find_command_collisions`'s
/// self-owner exclusion would then hide a real third-party owner of
/// that PATH name. Same shape the planner uses for its residual-
/// collision check at install commit time.
pub(super) fn post_resolution_view(
    manifest: &GlobalManifest,
    intent: &IntentPayload,
) -> GlobalManifest {
    let mut view = manifest.clone();
    for change in &intent.ownership_delta {
        match change {
            OwnershipChange::DirectTransfer {
                command,
                from_package,
                ..
            } => {
                if let Some(owner) = view.packages.get_mut(from_package) {
                    owner.commands.retain(|c| c != command);
                }
            }
            OwnershipChange::AliasOwnerRemove { alias_name, .. } => {
                view.aliases.remove(alias_name);
            }
            OwnershipChange::AliasInstall { .. } => {}
        }
    }
    view
}

/// Replay one OwnershipChange against the manifest
/// during recovery roll-forward.
///
/// Mirrors the global-install commit-side ownership delta applicator.
/// Duplicated here because lpm-global is lower-layer and can't depend
/// on lpm-cli. The two copies are semantically identical; if one
/// changes, update both together.
///
/// Idempotent for every variant: replaying a delta already applied is
/// a no-op (retain() filters nothing; remove() returns None; insert
/// overwrites with same value).
pub(super) fn replay_ownership_change(
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

/// Inverse of `replay_ownership_change`. Used by
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
pub(super) fn revert_ownership_change(
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
pub(super) fn apply_new_aliases(
    manifest: &mut GlobalManifest,
    new_aliases_json: &serde_json::Value,
) {
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
pub(super) fn restore_prior_aliases(
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

pub(super) fn parse_package_entry_from_json(value: &serde_json::Value) -> Option<PackageEntry> {
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
