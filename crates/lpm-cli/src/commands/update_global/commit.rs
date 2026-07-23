use super::prepare::{StagedUpgrade, UpgradePrep};
use super::rollback::{restore_prior_shims_after_aborted_upgrade, rollback_aborted_upgrade};
use chrono::Utc;
use lpm_common::{LpmError, LpmRoot};
use lpm_global::{
    CommandCollision, InstallRootStatus, PackageEntry, Shim, WalRecord, WalWriter,
    artifacts_complete, emit_shim, find_command_collisions, read_for, validate_install_root,
    write_for,
};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub(super) struct UpgradeOutput {
    pub(super) name: String,
    pub(super) from_version: String,
    pub(super) to_version: String,
    pub(super) saved_spec: String,
    pub(super) commands: Vec<String>,
}

pub(super) fn commit_upgrade_locked(
    root: &LpmRoot,
    prep: &UpgradePrep,
    staged: &StagedUpgrade,
) -> Result<UpgradeOutput, LpmError> {
    let mut manifest = read_for(root)?;

    let status = validate_install_root(&staged.install_root, None)?;
    let marker_commands = match status {
        InstallRootStatus::Ready { commands } => commands,
        other => {
            return Err(LpmError::Script(format!(
                "install root for '{}' failed validation: {other:?}. Recovery will reconcile \
                 on next `lpm` invocation.",
                prep.name
            )));
        }
    };

    // Every prior alias's `bin` field names a declared bin that
    // is exposed only via the alias key. Carrying these forward through
    // the upgrade preserves the user's alias-only exposure invariant:
    // direct shims must NOT be emitted for these bins.
    let prior_aliases: Vec<(String, String)> = prep
        .prior_aliases_json
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    v.get("bin")
                        .and_then(|b| b.as_str())
                        .map(|b| (k.clone(), b.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let aliased_origs: HashSet<&str> = prior_aliases.iter().map(|(_, bin)| bin.as_str()).collect();

    // Verify every prior alias still has its declared bin in the new
    // package. If the upgrade dropped the bin the alias targets, the
    // alias would become a dangling shim — refuse the upgrade rather
    // than silently expose a broken PATH entry.
    let marker_set: HashSet<&str> = marker_commands.iter().map(|s| s.as_str()).collect();
    let dangling: Vec<(String, String)> = prior_aliases
        .iter()
        .filter(|(_, bin)| !marker_set.contains(bin.as_str()))
        .cloned()
        .collect();
    if !dangling.is_empty() {
        let detail = format!(
            "the new version of '{}' no longer declares the bin(s) targeted by alias(es): {}. \
             Uninstall and reinstall with the desired aliases to upgrade, or pick a version that \
             still declares the bin.",
            prep.name,
            dangling
                .iter()
                .map(|(alias, bin)| format!("{alias} -> {bin}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        rollback_aborted_upgrade(root, &mut manifest, staged, &prep.name, &detail)?;
        return Err(LpmError::Script(detail));
    }

    let final_commands: Vec<String> = marker_commands
        .iter()
        .filter(|c| !aliased_origs.contains(c.as_str()))
        .cloned()
        .collect();

    // Collision guard. Self-collisions are EXPECTED for upgrades —
    // the new install owns the same command names as the prior one.
    // `find_command_collisions` excludes self-collisions for exactly
    // this case (the exclusion was added explicitly to handle upgrades
    // correctly). So a real conflict here means
    // ANOTHER package owns one of the new commands.
    //
    // Scan `final_commands` (not `marker_commands`) so an aliased-away
    // bin isn't incorrectly flagged as colliding with a third party
    // that owns the same PATH name — the aliased-away bin won't be on
    // PATH after this commit.
    let collisions: Vec<CommandCollision> =
        find_command_collisions(&manifest, &prep.name, &final_commands);
    if !collisions.is_empty() {
        // Inline rollback: drop pending row, tombstone new install
        // root (recovery sweep will retry the actual delete), write
        // WAL Abort. Manifest stays at the pre-upgrade state.
        rollback_aborted_upgrade(
            root,
            &mut manifest,
            staged,
            &prep.name,
            &format!(
                "command collision with another package: {}",
                collisions
                    .iter()
                    .map(|c| format!("{} (owned by {})", c.command, c.current_owner))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )?;
        return Err(LpmError::Script(format!(
            "upgrade of '{}' would conflict with another globally-installed package's \
             commands: {}. The pre-upgrade install is unchanged. Resolve the conflict (uninstall \
             the other package or use --alias to remap the command name) and retry.",
            prep.name,
            collisions
                .iter()
                .map(|c| c.command.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    // Atomic shim swap: emit_shim's tempfile-rename swaps existing
    // shims (same command names, new install root). The user's shell
    // sees either the old or new shim, never neither.
    //
    // Track each emitted name so the incomplete-shim rollback path below
    // can restore it to the prior install root.
    let bin_dir = root.bin_dir();
    let install_bin = staged.install_root.join("node_modules").join(".bin");
    let mut emitted_shims: Vec<String> = Vec::new();
    for cmd in &final_commands {
        let target = install_bin.join(cmd);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: cmd.clone(),
                target,
            },
        )?;
        emitted_shims.push(cmd.clone());
    }
    // Re-emit each prior alias against the new install root so the
    // alias keeps pointing at this package's bin after the OLD root
    // is tombstoned.
    for (alias_name, bin) in &prior_aliases {
        let target = install_bin.join(bin);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: alias_name.clone(),
                target,
            },
        )?;
        emitted_shims.push(alias_name.clone());
    }

    // Confirm every command's shim triple is fully present after
    // emission. Same rationale as the global-install commit path:
    // a partial triple
    // observable to other shells would diverge from the manifest commit
    // we're about to write. Recovery's roll-forward repaves shims from
    // WAL data on the next invocation if we abort here.
    let mut incomplete: Vec<String> = Vec::new();
    for cmd in &final_commands {
        if !artifacts_complete(&bin_dir, cmd) {
            incomplete.push(cmd.clone());
        }
    }
    for (alias_name, _) in &prior_aliases {
        if !artifacts_complete(&bin_dir, alias_name) {
            incomplete.push(alias_name.clone());
        }
    }
    if !incomplete.is_empty() {
        let detail = format!(
            "shim triple incomplete after upgrade emit for: {}. The transaction \
             will be reconciled by recovery on the next `lpm` invocation.",
            incomplete.join(", ")
        );
        // Restore the prior install's shims before tombstoning the new root.
        if let Err(restore_failures) =
            restore_prior_shims_after_aborted_upgrade(root, &emitted_shims, prep)
        {
            let combined = format!(
                "{detail} Additionally, the rollback could not restore {} prior shim(s): {}. \
                 Re-run `lpm` so recovery can retry the rollback.",
                restore_failures.len(),
                restore_failures.join("; ")
            );
            tracing::warn!("update -g rollback: deferring '{}': {combined}", prep.name);
            return Err(LpmError::Script(combined));
        }
        rollback_aborted_upgrade(root, &mut manifest, staged, &prep.name, &detail)?;
        return Err(LpmError::Script(detail));
    }

    // Flip [pending] → [packages]. Tombstone the OLD install root
    // (its path is in prior_active_row_json.root) so `store gc` can
    // sweep it after any tools holding files in it have exited.
    if let Some(prior_root) = prep
        .prior_active_row_json
        .get("root")
        .and_then(|v| v.as_str())
    {
        manifest.tombstones.push(prior_root.to_string());
    }
    let active = PackageEntry {
        saved_spec: prep.new_saved_spec.clone(),
        resolved: prep.new_version.to_string(),
        integrity: prep.new_integrity.clone(),
        source: prep.source,
        installed_at: Utc::now(),
        root: staged.install_root_relative.clone(),
        // `final_commands` excludes aliased-away bins per the manifest
        // invariant (PackageEntry.commands holds only directly-exposed
        // names). Pre-fix this stored marker_commands, which would
        // promote aliased-away bins back to PATH after recovery.
        commands: final_commands.clone(),
    };
    manifest.packages.insert(prep.name.clone(), active);
    manifest.pending.remove(&prep.name);
    // Aliases are already in `manifest.aliases` from the prior install
    // — we're carrying them forward unchanged. Same alias entries
    // referencing the same package + bin still resolve correctly now
    // that `packages[prep.name].root` points at the new install root.

    // Persist BEFORE WAL Commit (manifest-before-commit ordering invariant).
    write_for(root, &manifest)?;

    let mut wal = WalWriter::open(root.global_wal())?;
    wal.append(&WalRecord::Commit {
        tx_id: staged.tx_id.clone(),
        committed_at: Utc::now(),
    })?;

    Ok(UpgradeOutput {
        name: prep.name.clone(),
        from_version: prep.current_version.clone(),
        to_version: prep.new_version.to_string(),
        saved_spec: prep.new_saved_spec.clone(),
        commands: final_commands,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::test_support::{make_complete_install_root, pre_upgrade_manifest_with_alias};
    use super::*;
    use lpm_semver::Version;
    /// A package originally installed with an alias keeps that alias through upgrade.
    #[test]
    #[cfg(unix)]
    fn upgrade_preserves_alias_and_does_not_expose_aliased_away_bin() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());

        // Pre-upgrade state: foo@1.0.0 declared `dangerous`, user
        // installed with --alias dangerous=safe-name.
        let prior_root = root.install_root_for("foo", "1.0.0");
        std::fs::create_dir_all(&prior_root).unwrap();
        make_complete_install_root(&prior_root, &["dangerous"]);

        let manifest = pre_upgrade_manifest_with_alias(
            "installs/foo@1.0.0",
            &["dangerous"],
            "safe-name",
            "dangerous",
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        // Existing `safe-name` shim pointing at prior install root.
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink(
            prior_root.join("node_modules/.bin/dangerous"),
            root.bin_dir().join("safe-name"),
        )
        .unwrap();

        // Stage upgrade to foo@2.0.0 (also declares `dangerous`).
        let new_root = root.install_root_for("foo", "2.0.0");
        std::fs::create_dir_all(&new_root).unwrap();
        make_complete_install_root(&new_root, &["dangerous"]);

        let active = manifest.packages.get("foo").unwrap();
        let prior_active_row_json = serde_json::json!({
            "saved_spec": active.saved_spec,
            "resolved": active.resolved,
            "integrity": active.integrity,
            "source": serde_json::to_value(active.source).unwrap(),
            "installed_at": active.installed_at.to_rfc3339(),
            "root": active.root,
            "commands": active.commands,
        });
        let prior_aliases_json = serde_json::json!({
            "safe-name": {"package": "foo", "bin": "dangerous"}
        });
        let prep = UpgradePrep {
            name: "foo".into(),
            current_version: "1.0.0".into(),
            new_version: Version::parse("2.0.0").unwrap(),
            new_saved_spec: "^2".into(),
            new_integrity: "sha512-new".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            prior_active_row_json,
            prior_aliases_json,
        };

        // Seed the pending row so commit_upgrade_locked can flip it.
        let mut manifest_with_pending = manifest.clone();
        manifest_with_pending.pending.insert(
            "foo".into(),
            lpm_global::PendingEntry {
                saved_spec: prep.new_saved_spec.clone(),
                resolved: prep.new_version.to_string(),
                integrity: prep.new_integrity.clone(),
                source: prep.source,
                started_at: chrono::Utc::now(),
                root: "installs/foo@2.0.0".into(),
                commands: Vec::new(),
                replaces_version: Some("1.0.0".into()),
            },
        );
        lpm_global::write_for(&root, &manifest_with_pending).unwrap();

        let staged = StagedUpgrade {
            tx_id: "tx-upgrade".into(),
            install_root: new_root.clone(),
            install_root_relative: "installs/foo@2.0.0".into(),
        };

        let out = commit_upgrade_locked(&root, &prep, &staged).unwrap();
        // The output's `commands` is the post-resolution direct-bin list.
        // `dangerous` is aliased-away, so the upgrade output exposes nothing
        // under that name directly.
        assert!(
            !out.commands.contains(&"dangerous".to_string()),
            "post-fix: aliased-away bin must not appear as a direct command \
             in upgrade output; got {:?}",
            out.commands
        );

        let final_manifest = lpm_global::read_for(&root).unwrap();
        let foo = final_manifest.packages.get("foo").expect("foo row");
        assert_eq!(foo.resolved, "2.0.0");
        assert!(
            !foo.commands.contains(&"dangerous".to_string()),
            "PackageEntry.commands must not include aliased-away bins: {:?}",
            foo.commands
        );
        assert!(
            final_manifest.aliases.contains_key("safe-name"),
            "alias row must be preserved through upgrade"
        );

        // Shim invariant: `safe-name` shim now points at the NEW install
        // root's `dangerous` bin; `dangerous` shim does NOT exist.
        let safe_target = std::fs::read_link(root.bin_dir().join("safe-name")).unwrap();
        let expected = new_root.join("node_modules").join(".bin").join("dangerous");
        assert_eq!(
            safe_target, expected,
            "alias shim must be re-pointed at the new install root"
        );
        assert!(
            std::fs::symlink_metadata(root.bin_dir().join("dangerous")).is_err(),
            "aliased-away bin must NOT be exposed as a direct shim on PATH"
        );
    }

    /// Upgrade refuses when the new version drops a bin targeted by a prior alias.
    #[test]
    #[cfg(unix)]
    fn upgrade_refuses_when_prior_alias_bin_dropped_from_new_version() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());

        let prior_root = root.install_root_for("foo", "1.0.0");
        std::fs::create_dir_all(&prior_root).unwrap();
        make_complete_install_root(&prior_root, &["dangerous"]);

        let manifest = pre_upgrade_manifest_with_alias(
            "installs/foo@1.0.0",
            &["dangerous"],
            "safe-name",
            "dangerous",
        );

        // New version drops `dangerous` and exposes `something-else`
        // instead — `safe-name -> dangerous` would dangle.
        let new_root = root.install_root_for("foo", "2.0.0");
        std::fs::create_dir_all(&new_root).unwrap();
        make_complete_install_root(&new_root, &["something-else"]);

        let active = manifest.packages.get("foo").unwrap();
        let prior_active_row_json = serde_json::json!({
            "saved_spec": active.saved_spec,
            "resolved": active.resolved,
            "integrity": active.integrity,
            "source": serde_json::to_value(active.source).unwrap(),
            "installed_at": active.installed_at.to_rfc3339(),
            "root": active.root,
            "commands": active.commands,
        });
        let prior_aliases_json = serde_json::json!({
            "safe-name": {"package": "foo", "bin": "dangerous"}
        });
        let prep = UpgradePrep {
            name: "foo".into(),
            current_version: "1.0.0".into(),
            new_version: Version::parse("2.0.0").unwrap(),
            new_saved_spec: "^2".into(),
            new_integrity: "sha512-new".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            prior_active_row_json,
            prior_aliases_json,
        };

        let mut manifest_with_pending = manifest.clone();
        manifest_with_pending.pending.insert(
            "foo".into(),
            lpm_global::PendingEntry {
                saved_spec: prep.new_saved_spec.clone(),
                resolved: prep.new_version.to_string(),
                integrity: prep.new_integrity.clone(),
                source: prep.source,
                started_at: chrono::Utc::now(),
                root: "installs/foo@2.0.0".into(),
                commands: Vec::new(),
                replaces_version: Some("1.0.0".into()),
            },
        );
        lpm_global::write_for(&root, &manifest_with_pending).unwrap();

        let staged = StagedUpgrade {
            tx_id: "tx-drop".into(),
            install_root: new_root,
            install_root_relative: "installs/foo@2.0.0".into(),
        };

        let err = commit_upgrade_locked(&root, &prep, &staged).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("safe-name -> dangerous"),
            "error must name the affected alias: {msg}"
        );
        assert!(
            msg.contains("Uninstall and reinstall"),
            "error must point user at the resolution path: {msg}"
        );

        // Rollback: pending row dropped, manifest active row unchanged.
        let final_manifest = lpm_global::read_for(&root).unwrap();
        assert!(!final_manifest.pending.contains_key("foo"));
        assert_eq!(
            final_manifest.packages.get("foo").unwrap().resolved,
            "1.0.0",
            "pre-upgrade active row stays after refusal"
        );
    }
}
