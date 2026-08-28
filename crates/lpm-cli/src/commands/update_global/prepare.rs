use chrono::Utc;
use lpm_common::{GlobalInstallsDirectory, LpmError, LpmRoot};
use lpm_global::{
    GlobalManifest, IntentPayload, PackageEntry, PackageSource, PendingEntry, TxKind, WalRecord,
    WalWriter, read_for, write_for,
};
use lpm_semver::Version;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(super) struct UpgradePrep {
    pub(super) name: String,
    pub(super) current_version: String,
    pub(super) new_version: Version,
    pub(super) new_saved_spec: String,
    pub(super) new_integrity: String,
    pub(super) source: PackageSource,
    /// Snapshot of the existing `[packages.<name>]` row, taken at
    /// planning time. Lands in the WAL Intent's `prior_active_row_json`
    /// so recovery's `roll_back` can restore it on failure.
    pub(super) prior_active_row_json: serde_json::Value,
    /// Snapshot of `[aliases]` rows owned by this package. Recovery
    /// uses `prior_command_ownership_json.aliases` to restore the
    /// pre-upgrade alias state.
    pub(super) prior_aliases_json: serde_json::Value,
}

#[derive(Debug, Clone)]
pub(super) struct StagedUpgrade {
    pub(super) tx_id: String,
    pub(super) install_root: PathBuf,
    pub(super) install_root_relative: String,
}

pub(super) fn prepare_upgrade_locked(
    root: &LpmRoot,
    prep: &UpgradePrep,
    tx_id: String,
) -> Result<StagedUpgrade, LpmError> {
    let mut manifest = read_for(root)?;
    let (staged, record) = prepare_upgrade_in_manifest(root, &mut manifest, prep, tx_id)?;
    let mut wal = WalWriter::open(root.global_wal())?;
    wal.append(&record)?;
    write_for(root, &manifest)?;
    Ok(staged)
}

pub(super) fn prepare_upgrade_batch_locked(
    root: &LpmRoot,
    upgrades: &[(&UpgradePrep, String)],
) -> Result<Vec<Result<StagedUpgrade, LpmError>>, LpmError> {
    let mut manifest = read_for(root)?;
    let mut records = Vec::with_capacity(upgrades.len());
    let mut results = Vec::with_capacity(upgrades.len());
    for &(prep, ref tx_id) in upgrades {
        match prepare_upgrade_in_manifest(root, &mut manifest, prep, tx_id.clone()) {
            Ok((staged, record)) => {
                records.push(record);
                results.push(Ok(staged));
            }
            Err(error) => results.push(Err(error)),
        }
    }
    if !records.is_empty() {
        let mut wal = WalWriter::open(root.global_wal())?;
        wal.append_many(records.iter())?;
        write_for(root, &manifest)?;
    }
    Ok(results)
}

fn prepare_upgrade_in_manifest(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    prep: &UpgradePrep,
    tx_id: String,
) -> Result<(StagedUpgrade, WalRecord), LpmError> {
    // Re-check active state under the lock (prior fetch was outside).
    let active = manifest.packages.get(&prep.name).ok_or_else(|| {
        LpmError::Script(format!(
            "'{}' is no longer installed (someone else uninstalled it). Aborting upgrade.",
            prep.name
        ))
    })?;
    if manifest.pending.contains_key(&prep.name) {
        return Err(LpmError::Script(format!(
            "'{}' has another in-flight transaction. Wait for it to finish.",
            prep.name
        )));
    }
    // The plan we built outside the lock captured a snapshot of the active row
    // (`prep.prior_active_row_json`). Between then and now another
    // process may have committed its own upgrade of the same package.
    // If we proceed with the stale snapshot, our commit would tombstone
    // *the wrong prior root* and overwrite their active row with our
    // older planned version. Refuse to proceed; tell the user to
    // re-plan against the current state.
    if let Err(diff) = active_matches_planned_snapshot(active, &prep.prior_active_row_json) {
        return Err(LpmError::Script(format!(
            "'{}' was modified by another process between planning and commit ({diff}). \
             Re-run `lpm global update {}` (or whatever spec you used) to plan against the \
             current state.",
            prep.name, prep.name
        )));
    }

    let install_root = root.install_root_for(&prep.name, &prep.new_version.to_string());
    let install_root_relative = format!(
        "installs/{}",
        install_root.file_name().unwrap().to_string_lossy()
    );

    // pre-install path-budget guard. Same rationale
    // as install_global::prepare_locked — fail fast with an actionable
    // LPM_HOME hint rather than mid-extraction with cryptic platform
    // errors when the new install root would push us over the
    // 247-char budget.
    lpm_common::check_install_path_budget(&install_root)?;
    let install_leaf = install_root.file_name().ok_or_else(|| {
        LpmError::Script(format!(
            "global install root has no final path component: {}",
            install_root.display()
        ))
    })?;
    GlobalInstallsDirectory::open_or_create(root)?.open_or_create_install(install_leaf)?;

    let new_row_json = serde_json::json!({
        "saved_spec": prep.new_saved_spec,
        "resolved": prep.new_version.to_string(),
        "integrity": prep.new_integrity,
        "source": serde_json::to_value(prep.source).unwrap(),
        "started_at": Utc::now().to_rfc3339(),
        "root": install_root_relative,
        // commands: discovered post-extract (marker-as-authority).
        "commands": Vec::<String>::new(),
        "replaces_version": prep.current_version,
    });
    let record = WalRecord::Intent(Box::new(IntentPayload {
        tx_id: tx_id.clone(),
        kind: TxKind::Upgrade,
        package: prep.name.clone(),
        new_root_path: install_root.clone(),
        new_row_json,
        prior_active_row_json: Some(prep.prior_active_row_json.clone()),
        prior_command_ownership_json: serde_json::json!({
            "aliases": prep.prior_aliases_json,
        }),
        // Preserve every alias the prior version owned; recovery treats this
        // snapshot as the authoritative post-commit alias set.
        new_aliases_json: prep.prior_aliases_json.clone(),
        // Upgrades don't resolve collisions — they keep the same package
        // owning the same commands, so
        // `find_command_collisions` never triggers non-self hits.
        ownership_delta: Vec::new(),
        // Upgrade preserves trust (same package, same name@version semantics
        // through the existing trust-binding drift gate). No prune.
        uninstall_trust_prune: Vec::new(),
    }));

    manifest.pending.insert(
        prep.name.clone(),
        PendingEntry {
            saved_spec: prep.new_saved_spec.clone(),
            resolved: prep.new_version.to_string(),
            integrity: prep.new_integrity.clone(),
            source: prep.source,
            started_at: Utc::now(),
            root: install_root_relative.clone(),
            commands: Vec::new(),
            replaces_version: Some(prep.current_version.clone()),
        },
    );
    Ok((
        StagedUpgrade {
            tx_id,
            install_root,
            install_root_relative,
        },
        record,
    ))
}

/// Compare the current `[packages.<pkg>]` row against the snapshot
/// captured by `plan_upgrade` outside the lock. Returns `Ok(())` when
/// they match on the load-bearing fields (`saved_spec`, `resolved`,
/// `integrity`, `source`, `root`) and `Err(diff_description)` otherwise.
///
/// `installed_at` is intentionally excluded — recovery can rewrite the
/// timestamp, and the timestamp doesn't affect tombstone correctness or
/// `replaces_version` semantics. Same omission as `active_matches_intent`
/// in recover.rs.
pub(super) fn active_matches_planned_snapshot(
    active: &PackageEntry,
    snapshot: &serde_json::Value,
) -> Result<(), String> {
    let snap = snapshot.as_object().ok_or_else(|| {
        "planned snapshot is not a JSON object (corrupt prior_active_row_json)".to_string()
    })?;
    let str_field = |k: &str| snap.get(k).and_then(|v| v.as_str());

    if str_field("saved_spec") != Some(active.saved_spec.as_str()) {
        return Err(format!(
            "saved_spec changed: planned {:?}, current {:?}",
            str_field("saved_spec"),
            active.saved_spec
        ));
    }
    if str_field("resolved") != Some(active.resolved.as_str()) {
        return Err(format!(
            "resolved version changed: planned {:?}, current {:?}",
            str_field("resolved"),
            active.resolved
        ));
    }
    if str_field("integrity") != Some(active.integrity.as_str()) {
        return Err(format!(
            "integrity changed: planned {:?}, current {:?}",
            str_field("integrity"),
            active.integrity
        ));
    }
    if str_field("root") != Some(active.root.as_str()) {
        return Err(format!(
            "install root changed: planned {:?}, current {:?}",
            str_field("root"),
            active.root
        ));
    }
    let active_source = serde_json::to_value(active.source)
        .ok()
        .and_then(|v| v.as_str().map(String::from));
    if str_field("source") != active_source.as_deref() {
        return Err(format!(
            "source changed: planned {:?}, current {:?}",
            str_field("source"),
            active_source
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn prepare_upgrade_refuses_symlinked_install_root_before_writing_transaction_state() {
        use std::os::unix::fs::symlink;

        let home = tempfile::TempDir::new().unwrap();
        let victim = tempfile::TempDir::new().unwrap();
        let root = LpmRoot::from_dir(home.path());
        let active = PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-old".into(),
            source: PackageSource::LpmDev,
            installed_at: Utc::now(),
            root: "installs/pkg@1.0.0".into(),
            commands: vec![],
        };
        let snapshot = serde_json::json!({
            "saved_spec": active.saved_spec,
            "resolved": active.resolved,
            "integrity": active.integrity,
            "source": active.source,
            "root": active.root,
        });
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert("pkg".into(), active);
        write_for(&root, &manifest).unwrap();
        std::fs::create_dir_all(root.global_installs()).unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        symlink(victim.path(), root.install_root_for("pkg", "2.0.0")).unwrap();
        let prep = UpgradePrep {
            name: "pkg".into(),
            current_version: "1.0.0".into(),
            new_version: Version::parse("2.0.0").unwrap(),
            new_saved_spec: "^2".into(),
            new_integrity: "sha512-new".into(),
            source: PackageSource::LpmDev,
            prior_active_row_json: snapshot,
            prior_aliases_json: serde_json::json!({}),
        };

        let error = prepare_upgrade_locked(&root, &prep, "tx-test".into()).unwrap_err();

        assert!(error.to_string().contains("global install root"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
        assert!(read_for(&root).unwrap().pending.is_empty());
        assert!(!root.global_wal().exists());
    }

    /// Snapshot matching is strict on the load-bearing fields.
    #[test]
    fn active_matches_planned_snapshot_passes_when_load_bearing_fields_agree() {
        let active = lpm_global::PackageEntry {
            saved_spec: "^9".into(),
            resolved: "9.24.0".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/eslint@9.24.0".into(),
            commands: vec!["eslint".into()],
        };
        // Snapshot matches on every load-bearing field. installed_at
        // and commands are intentionally NOT part of the comparison.
        let snapshot = serde_json::json!({
            "saved_spec": "^9",
            "resolved": "9.24.0",
            "integrity": "sha512-x",
            "source": "upstream-npm",
            "installed_at": "T00:00:00Z",
            "root": "installs/eslint@9.24.0",
            "commands": ["DIFFERENT-COMMANDS-IGNORED"],
        });
        assert!(active_matches_planned_snapshot(&active, &snapshot).is_ok());
    }

    #[test]
    fn active_matches_planned_snapshot_detects_resolved_change() {
        let active = lpm_global::PackageEntry {
            saved_spec: "^9".into(),
            resolved: "9.25.0".into(),
            integrity: "sha512-newer".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/eslint@9.25.0".into(),
            commands: vec!["eslint".into()],
        };
        let snapshot = serde_json::json!({
            "saved_spec": "^9",
            "resolved": "9.24.0",
            "integrity": "sha512-x",
            "source": "upstream-npm",
            "installed_at": "T00:00:00Z",
            "root": "installs/eslint@9.24.0",
            "commands": ["eslint"],
        });
        let err = active_matches_planned_snapshot(&active, &snapshot).unwrap_err();
        assert!(err.contains("resolved version changed"));
        assert!(err.contains("9.24.0"));
        assert!(err.contains("9.25.0"));
    }

    #[test]
    fn active_matches_planned_snapshot_detects_source_change() {
        let active = lpm_global::PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/x@1.0.0".into(),
            commands: vec![],
        };
        let snapshot = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "installed_at": "T00:00:00Z",
            "root": "installs/x@1.0.0",
            "commands": [],
        });
        let err = active_matches_planned_snapshot(&active, &snapshot).unwrap_err();
        assert!(err.contains("source changed"));
    }
}
