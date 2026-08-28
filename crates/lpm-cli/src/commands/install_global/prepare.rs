use super::resolve::ResolvedSpec;
use chrono::Utc;
use lpm_common::{GlobalInstallsDirectory, LpmError, LpmRoot};
use lpm_global::{
    IntentPayload, PackageSource, PendingEntry, TxKind, WalRecord, WalWriter, read_for, write_for,
};
use lpm_semver::Version;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(super) struct PrepResult {
    pub(super) tx_id: String,
    pub(super) name: String,
    pub(super) version: Version,
    pub(super) saved_spec: String,
    pub(super) integrity: String,
    pub(super) source: PackageSource,
    pub(super) install_root: PathBuf,
    pub(super) install_root_relative: String,
}

pub(super) fn prepare_locked(
    root: &LpmRoot,
    resolved: &ResolvedSpec,
    tx_id: String,
) -> Result<PrepResult, LpmError> {
    let mut manifest = read_for(root)?;

    if manifest.packages.contains_key(&resolved.name) {
        return Err(LpmError::Script(format!(
            "'{}' is already installed globally. Use `lpm global update {}` to upgrade or \
             `lpm uninstall -g {}` first. (Use `lpm global update` to upgrade in-place.)",
            resolved.name, resolved.name, resolved.name
        )));
    }
    if manifest.pending.contains_key(&resolved.name) {
        return Err(LpmError::Script(format!(
            "'{}' is already being installed by another process. Wait for it to finish or \
             check `~/.lpm/global/.tx.lock.pid` for a stale lock.",
            resolved.name
        )));
    }

    let install_root = root.install_root_for(&resolved.name, &resolved.version.to_string());
    let install_root_relative = format!(
        "installs/{}",
        install_root.file_name().unwrap().to_string_lossy()
    );

    // pre-install path-budget guard. Reject the
    // install up front if the chosen install root would push us over the
    // 247-char budget — failing fast with an actionable LPM_HOME hint
    // beats failing mid-extraction with cryptic platform errors. No-op
    // on POSIX; load-bearing for Windows (and for any scenario where
    // third-party tooling does not honour `\\?\` long-path prefixes).
    lpm_common::check_install_path_budget(&install_root)?;
    let install_leaf = install_root.file_name().ok_or_else(|| {
        LpmError::Script(format!(
            "global install root has no final path component: {}",
            install_root.display()
        ))
    })?;
    GlobalInstallsDirectory::open_or_create(root)?.open_or_create_install(install_leaf)?;

    // Write Intent + pending atomically: Intent first (fsynced), then
    // pending row. Crash between the two = recovery sees Intent without
    // pending, treats it as orphan (Case C).
    let mut wal = WalWriter::open(root.global_wal())?;
    let new_row_json = serde_json::json!({
        "saved_spec": resolved.saved_spec,
        "resolved": resolved.version.to_string(),
        "integrity": resolved.integrity,
        "source": serde_json::to_value(resolved.source).unwrap(),
        "started_at": Utc::now().to_rfc3339(),
        "root": install_root_relative,
        // commands: discovered at step 2; the marker is authoritative.
        "commands": Vec::<String>::new(),
    });
    wal.append(&WalRecord::Intent(Box::new(IntentPayload {
        tx_id: tx_id.clone(),
        kind: TxKind::Install,
        package: resolved.name.clone(),
        new_root_path: install_root.clone(),
        new_row_json,
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        // Populated at commit-time if the user resolved collisions via
        // flags. prepare_locked runs before marker discovery, so
        // no collisions are known yet — empty delta here is correct.
        ownership_delta: Vec::new(),
        // Install never prunes trust, so the field stays empty and
        // serializes away via `skip_serializing_if`.
        uninstall_trust_prune: Vec::new(),
    })))?;

    manifest.pending.insert(
        resolved.name.clone(),
        PendingEntry {
            saved_spec: resolved.saved_spec.clone(),
            resolved: resolved.version.to_string(),
            integrity: resolved.integrity.clone(),
            source: resolved.source,
            started_at: Utc::now(),
            root: install_root_relative.clone(),
            commands: Vec::new(),
            replaces_version: None,
        },
    );
    write_for(root, &manifest)?;

    Ok(PrepResult {
        tx_id,
        name: resolved.name.clone(),
        version: resolved.version.clone(),
        saved_spec: resolved.saved_spec.clone(),
        integrity: resolved.integrity.clone(),
        source: resolved.source,
        install_root,
        install_root_relative,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn prepare_refuses_symlinked_install_root_before_writing_transaction_state() {
        let home = TempDir::new().unwrap();
        let victim = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(home.path());
        std::fs::create_dir_all(root.global_installs()).unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        symlink(victim.path(), root.install_root_for("pkg", "1.0.0")).unwrap();
        let resolved = ResolvedSpec {
            name: "pkg".into(),
            version: Version::parse("1.0.0").unwrap(),
            integrity: "sha512-test".into(),
            source: PackageSource::LpmDev,
            saved_spec: "^1.0.0".into(),
        };

        let error = prepare_locked(&root, &resolved, "tx-test".into()).unwrap_err();

        assert!(error.to_string().contains("global install root"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
        assert!(read_for(&root).unwrap().pending.is_empty());
        assert!(!root.global_wal().exists());
    }
}
