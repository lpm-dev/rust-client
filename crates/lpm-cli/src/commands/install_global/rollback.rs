use super::prepare::PrepResult;
use chrono::Utc;
use lpm_common::{LpmError, LpmRoot, sanitize_for_terminal, with_exclusive_lock};
use lpm_global::{WalRecord, WalWriter, read_for, remove_shim, write_for};

pub(super) fn rollback_after_install_failure(
    root: &LpmRoot,
    prep: &PrepResult,
    reason: &str,
) -> Result<(), LpmError> {
    with_exclusive_lock(root.global_tx_lock(), || {
        let mut manifest = read_for(root)?;
        rollback_aborted_commit(root, &mut manifest, prep, reason, &[])
    })
}

/// Roll back a transaction that reached commit_locked but failed
/// validation (collision, future failure modes). Mirrors recover.rs's
/// roll_back semantics from the user-facing call site so the on-disk
/// state stays clean and the next recovery has nothing to reconcile.
///
/// Order of operations:
///   0. Sweep emitted shims. If a shim is locked and we cannot remove
///      it, return Err WITHOUT writing manifest or WAL Abort so
///      recovery picks up the half-rolled-back transaction on the next
///      `lpm` invocation.
///   1. Drop the install root (or tombstone if locked).
///   2. Remove `[pending.<pkg>]` row.
///   3. Persist manifest.
///   4. Append WAL Abort.
pub(super) fn rollback_aborted_commit(
    root: &LpmRoot,
    manifest: &mut lpm_global::GlobalManifest,
    prep: &PrepResult,
    reason: &str,
    emitted_shims: &[String],
) -> Result<(), LpmError> {
    let bin_dir = root.bin_dir();
    let mut shim_failures: Vec<String> = Vec::new();
    for shim_name in emitted_shims {
        if let Err(e) = remove_shim(&bin_dir, shim_name) {
            shim_failures.push(format!(
                "{}: {}",
                sanitize_for_terminal(shim_name),
                sanitize_for_terminal(&e.to_string())
            ));
        }
    }
    if !shim_failures.is_empty() {
        let name_safe = sanitize_for_terminal(&prep.name);
        let reason = format!(
            "could not clear {} emitted shim(s) for '{}': {}. Re-run `lpm` so recovery can \
             retry the rollback (the pending transaction is preserved in the manifest).",
            shim_failures.len(),
            name_safe,
            shim_failures.join("; ")
        );
        tracing::warn!("install -g rollback: deferring '{}': {reason}", prep.name);
        return Err(LpmError::Script(reason));
    }

    let install_root_ext = lpm_common::as_extended_path(&prep.install_root);
    let root_is_referenced = manifest
        .install_root_is_referenced_excluding_pending(&prep.install_root_relative, &prep.name);
    if !root_is_referenced
        && install_root_ext.exists()
        && let Err(e) = std::fs::remove_dir_all(&install_root_ext)
    {
        tracing::debug!(
            "install -g rollback: deferring install-root cleanup via tombstone: {}",
            e
        );
        manifest.tombstones.push(prep.install_root_relative.clone());
    }
    manifest.pending.remove(&prep.name);
    write_for(root, manifest)?;
    let mut wal = WalWriter::open(root.global_wal())?;
    wal.append(&WalRecord::Abort {
        tx_id: prep.tx_id.clone(),
        reason: format!("commit-time validation failed: {reason}"),
        aborted_at: Utc::now(),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rollback_aborted_commit` must leave the manifest with no
    /// pending row, the install root removed or tombstoned, and a WAL
    /// Abort appended. Without this, the next recovery would commit the
    /// rejected install.
    #[test]
    fn rollback_aborted_commit_leaves_no_residual_state() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::write(install_root.join("package.json"), "{}").unwrap();

        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.pending.insert(
            "pkg".into(),
            lpm_global::PendingEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::LpmDev,
                started_at: chrono::Utc::now(),
                root: "installs/pkg@1.0.0".into(),
                commands: vec![],
                replaces_version: None,
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let prep = PrepResult {
            tx_id: "tx1".into(),
            name: "pkg".into(),
            version: lpm_semver::Version::parse("1.0.0").unwrap(),
            saved_spec: "^1".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::LpmDev,
            install_root: install_root.clone(),
            install_root_relative: "installs/pkg@1.0.0".into(),
        };

        rollback_aborted_commit(&root, &mut manifest, &prep, "test reason", &[]).unwrap();

        // Manifest pending row gone.
        let read_back = lpm_global::read_for(&root).unwrap();
        assert!(!read_back.pending.contains_key("pkg"));
        // Install root removed.
        assert!(!install_root.exists());
        // WAL has the Abort record.
        let scan = lpm_global::WalReader::at(root.global_wal()).scan().unwrap();
        let has_abort = scan
            .records
            .iter()
            .any(|r| matches!(r, lpm_global::WalRecord::Abort { tx_id, .. } if tx_id == "tx1"));
        assert!(has_abort, "Abort record must be appended");
    }

    #[test]
    fn rollback_aborted_commit_preserves_root_referenced_by_active_package() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::write(install_root.join("package.json"), "{}").unwrap();

        let relative = "installs/pkg@1.0.0";
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.pending.insert(
            "pkg".into(),
            lpm_global::PendingEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-pending".into(),
                source: lpm_global::PackageSource::LpmDev,
                started_at: chrono::Utc::now(),
                root: relative.into(),
                commands: Vec::new(),
                replaces_version: None,
            },
        );
        manifest.packages.insert(
            "current-owner".into(),
            lpm_global::PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-current".into(),
                source: lpm_global::PackageSource::LpmDev,
                installed_at: chrono::Utc::now(),
                root: relative.into(),
                commands: Vec::new(),
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let prep = PrepResult {
            tx_id: "tx-shared".into(),
            name: "pkg".into(),
            version: lpm_semver::Version::parse("1.0.0").unwrap(),
            saved_spec: "^1".into(),
            integrity: "sha512-pending".into(),
            source: lpm_global::PackageSource::LpmDev,
            install_root: install_root.clone(),
            install_root_relative: relative.into(),
        };

        rollback_aborted_commit(&root, &mut manifest, &prep, "test reason", &[]).unwrap();

        assert!(
            install_root.exists(),
            "rollback must preserve a root still referenced by an active package"
        );
    }

    /// When `rollback_aborted_commit` is handed emitted shim names, it
    /// must remove each one so no PATH entry survives pointing at the
    /// about-to-be-deleted install root.
    #[test]
    #[cfg(unix)]
    fn rollback_aborted_commit_sweeps_emitted_shims() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(install_root.join("node_modules").join(".bin")).unwrap();
        let bin_target = install_root.join("node_modules").join(".bin").join("pkg");
        std::fs::write(&bin_target, b"#!/bin/sh\necho ok\n").unwrap();

        // Pre-rollback: simulate that commit_locked emitted two shims
        // before failing. They point at this install root.
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink(&bin_target, root.bin_dir().join("pkg")).unwrap();
        std::os::unix::fs::symlink(&bin_target, root.bin_dir().join("pkg-alias")).unwrap();
        assert!(std::fs::symlink_metadata(root.bin_dir().join("pkg")).is_ok());
        assert!(std::fs::symlink_metadata(root.bin_dir().join("pkg-alias")).is_ok());

        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.pending.insert(
            "pkg".into(),
            lpm_global::PendingEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::LpmDev,
                started_at: chrono::Utc::now(),
                root: "installs/pkg@1.0.0".into(),
                commands: vec![],
                replaces_version: None,
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let prep = PrepResult {
            tx_id: "tx-shim".into(),
            name: "pkg".into(),
            version: lpm_semver::Version::parse("1.0.0").unwrap(),
            saved_spec: "^1".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::LpmDev,
            install_root: install_root.clone(),
            install_root_relative: "installs/pkg@1.0.0".into(),
        };

        rollback_aborted_commit(
            &root,
            &mut manifest,
            &prep,
            "test reason",
            &["pkg".to_string(), "pkg-alias".to_string()],
        )
        .unwrap();

        assert!(
            std::fs::symlink_metadata(root.bin_dir().join("pkg")).is_err(),
            "emitted direct-bin shim must be removed by rollback"
        );
        assert!(
            std::fs::symlink_metadata(root.bin_dir().join("pkg-alias")).is_err(),
            "emitted alias shim must be removed by rollback"
        );
        assert!(!install_root.exists());
    }
}
