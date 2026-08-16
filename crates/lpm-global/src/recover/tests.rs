use super::manifest_ops::{replay_ownership_change, revert_ownership_change};
use super::{ReconciliationOutcome, recover};
use crate::install_root::{InstallReadyMarker, write_marker};
use crate::manifest::{
    AliasEntry, GlobalManifest, PackageEntry, PackageSource, PendingEntry, read_for, write_for,
};
#[cfg(unix)]
use crate::wal::WalReader;
use crate::wal::{IntentPayload, OwnershipChange, TrustPruneEntry, TxKind, WalRecord, WalWriter};
use chrono::Utc;
use lpm_common::LpmRoot;
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
    std::fs::write(
        install_root.join("lpm.lock"),
        crate::install_root::MINIMAL_VALID_LOCKFILE_TOML,
    )
    .unwrap();
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
        uninstall_trust_prune: Vec::new(),
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

#[test]
fn rollback_does_not_delete_install_root_referenced_by_an_active_package() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());
    let install_root = root.install_root_for("pkg", "1.0.0");
    std::fs::create_dir_all(install_root.join("node_modules").join(".bin")).unwrap();
    std::fs::write(install_root.join("lpm.lock"), b"x").unwrap();

    let relative = "installs/pkg@1.0.0";
    let mut manifest = GlobalManifest::default();
    manifest
        .pending
        .insert("pkg".into(), pending_install("pkg", relative, &["pkg"]));
    manifest.packages.insert(
        "current-owner".into(),
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-current".into(),
            source: PackageSource::LpmDev,
            installed_at: Utc::now(),
            root: relative.into(),
            commands: vec!["current-owner".into()],
        },
    );
    write_for(&root, &manifest).unwrap();

    let mut wal = WalWriter::open(root.global_wal()).unwrap();
    wal.append(&intent_install("tx1", "pkg", &install_root, &["pkg"]))
        .unwrap();

    let report = recover(&root).unwrap();

    assert!(matches!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::RolledBack { .. }
    ));
    assert!(
        install_root.exists(),
        "rollback must preserve a root still referenced by an active package"
    );
}

#[test]
fn rollback_does_not_delete_install_root_referenced_by_another_pending_package() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());
    let install_root = root.install_root_for("pkg", "1.0.0");
    std::fs::create_dir_all(install_root.join("node_modules").join(".bin")).unwrap();
    std::fs::write(install_root.join("lpm.lock"), b"x").unwrap();

    let relative = "installs/pkg@1.0.0";
    let mut manifest = GlobalManifest::default();
    manifest
        .pending
        .insert("pkg".into(), pending_install("pkg", relative, &["pkg"]));
    manifest.pending.insert(
        "other".into(),
        pending_install("other", relative, &["other"]),
    );
    write_for(&root, &manifest).unwrap();

    let mut wal = WalWriter::open(root.global_wal()).unwrap();
    wal.append(&intent_install("tx1", "pkg", &install_root, &["pkg"]))
        .unwrap();

    let report = recover(&root).unwrap();

    assert!(matches!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::RolledBack { .. }
    ));
    assert!(
        install_root.exists(),
        "rollback must preserve a root still referenced by another pending package"
    );
}

#[test]
fn recovery_defers_partial_install_while_inflight_tx_lock_is_held() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    let tx_id = "tx-live";
    let install_root = root.install_root_for("pkg", "1.0.0");
    std::fs::create_dir_all(install_root.join("node_modules").join(".bin")).unwrap();
    std::fs::write(install_root.join("package.json"), "{}").unwrap();
    std::fs::write(install_root.join("lpm.lock"), b"x").unwrap();

    let mut manifest = GlobalManifest::default();
    manifest.pending.insert(
        "pkg".into(),
        pending_install("pkg", "installs/pkg@1.0.0", &["pkg"]),
    );
    write_for(&root, &manifest).unwrap();

    let mut w = WalWriter::open(root.global_wal()).unwrap();
    w.append(&intent_install(tx_id, "pkg", &install_root, &["pkg"]))
        .unwrap();
    drop(w);

    let lock_path = crate::inflight_tx_lock(&root, tx_id);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel::<()>();
    let lock_thread = std::thread::spawn(move || {
        lpm_common::with_exclusive_lock(&lock_path, || {
            acquired_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok::<(), lpm_common::LpmError>(())
        })
    });
    acquired_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("inflight lock was not acquired");

    let report = recover(&root).unwrap();

    release_tx.send(()).unwrap();
    lock_thread.join().unwrap().unwrap();

    assert_eq!(report.reconciled.len(), 1);
    assert!(matches!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::InFlight { .. }
    ));

    let final_manifest = read_for(&root).unwrap();
    assert!(final_manifest.pending.contains_key("pkg"));
    assert!(
        install_root.exists(),
        "recovery must not delete a partial root owned by a live install"
    );
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
    #[cfg(unix)]
    assert!(std::fs::symlink_metadata(root.bin_dir().join("pkg")).is_ok());
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

// ─── Recovery regressions ─────────────────────────────────

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
        uninstall_trust_prune: Vec::new(),
    }))
}

/// When the manifest already reflects the committed state
/// (Case A — crash between manifest persist and
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

    // WAL has the INTENT but no COMMIT: the committed manifest state
    // must be recognized as already complete.
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

    // The install root must still exist because it is the active root.
    assert!(
        install_root.exists(),
        "active install root must not be deleted in Case A"
    );
    // [packages.pkg] still present and unchanged.
    let final_manifest = read_for(&root).unwrap();
    assert!(final_manifest.packages.contains_key("pkg"));
}

/// `active_matches_intent` must accept the flow where the Intent records
/// `commands == []` because commands are discovered from the marker
/// post-extract, while the committed active row carries the marker-derived
/// list.
/// Subset semantics: Intent's commands must be a SUBSET of the
/// active row's commands.
#[test]
fn case_a_matches_when_intent_commands_empty_and_active_has_marker_discovered_commands() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    // Stage the post-commit state: install root complete, manifest
    // has the active row with marker-derived commands, no pending
    // row. Simulates the "manifest persisted, WAL append
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

    // Intent records commands=[] (bin entries are unknown until
    // post-extract from the marker).
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
        uninstall_trust_prune: Vec::new(),
    }));
    let mut w = WalWriter::open(root.global_wal()).unwrap();
    w.append(&intent).unwrap();

    let report = recover(&root).unwrap();
    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::AlreadyCommitted,
        "commands-discovered-from-marker pattern must be Case A, NOT Case C"
    );
    assert!(
        install_root.exists(),
        "live install root must NOT be deleted"
    );
}

/// Even with subset semantics, an Intent that explicitly lists a
/// command the active row doesn't own is still a real mismatch —
/// strict subset, not arbitrary acceptance.
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
        new_root_path: install_root,
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
        uninstall_trust_prune: Vec::new(),
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

/// `active_matches_intent` must compare `source`, not just
/// spec/version/integrity/root/commands. Otherwise a Case-A match could
/// fire for the wrong source value, silently changing future
/// `lpm global update` resolution behavior.
#[test]
fn case_a_does_not_match_when_only_source_differs() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    let install_root = root.install_root_for("pkg", "1.0.0");
    std::fs::create_dir_all(&install_root).unwrap();
    make_complete_install_root(&install_root, &["pkg"]);

    // Active row says LpmDev. Intent's new_row says upstream-npm.
    // Every other field matches; source is the only reason this must
    // not be classified as Case A.
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
        new_root_path: install_root,
        new_row_json: new_row,
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        ownership_delta: Vec::new(),
        uninstall_trust_prune: Vec::new(),
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

/// Recovery must not silently roll forward a pending install whose
/// marker commands would collide with an existing package's
/// commands. The commit path should prevent this state from ever
/// existing, but if it ever does (older binary, manual tampering),
/// recovery refuses to commit it and rolls back instead.
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

    // Pending install of a DIFFERENT package whose marker also exposes
    // `eslint`; recovery must not roll this forward and overwrite the
    // existing eslint shim.
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

// ─── uninstall recovery ──────────────────────────────────

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
        uninstall_trust_prune: Vec::new(),
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

/// When a shim cannot be removed, recovery must not propagate as an
/// error because that would wedge every subsequent global-state command.
/// Instead it returns `Deferred` so the Intent stays in the WAL for the
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

#[test]
fn recovery_uninstall_preserves_install_root_referenced_by_another_package() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());
    let install_root = root.install_root_for("pkg", "1.0.0");
    std::fs::create_dir_all(&install_root).unwrap();

    let shared_root = "installs/pkg@1.0.0";
    let mut manifest = GlobalManifest::default();
    for package in ["pkg", "other"] {
        manifest.packages.insert(
            package.into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: format!("sha512-{package}"),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: shared_root.into(),
                commands: Vec::new(),
            },
        );
    }
    write_for(&root, &manifest).unwrap();

    let mut wal = WalWriter::open(root.global_wal()).unwrap();
    wal.append(&intent_uninstall("tx", "pkg", &install_root, &[], &[]))
        .unwrap();

    let report = recover(&root).unwrap();

    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::RolledForward
    );
    assert!(
        install_root.exists(),
        "uninstall recovery must preserve a root still referenced by another package"
    );
    assert!(read_for(&root).unwrap().tombstones.is_empty());
}

/// A colliding install may have already emitted a shim before crashing.
/// Fresh installs can have empty `pending.commands`, so rollback must
/// use marker-derived commands to clean the leaked shim and restore the
/// original owner's shim.
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

/// Recovery's collision check must honour `ownership_delta`. A crash
/// after the second Intent is durable but before WAL Commit leaves a
/// pending row whose collisions the user explicitly resolved via
/// `--replace-bin`; recovery must apply the `DirectTransfer` from the
/// delta to a working view and roll forward as the user approved.
#[test]
#[cfg(unix)]
fn recovery_rolls_forward_when_collision_resolved_by_replace_bin_in_delta() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    // Displaced owner: http-server@1 owns `serve`.
    let http_server_root = root.install_root_for("http-server", "1.0.0");
    std::fs::create_dir_all(&http_server_root).unwrap();
    make_complete_install_root(&http_server_root, &["serve"]);

    // Incoming install: foo@1 also declares a `serve` bin and the
    // user resolved the collision with `--replace-bin serve`.
    let foo_root = root.install_root_for("foo", "1.0.0");
    std::fs::create_dir_all(&foo_root).unwrap();
    make_complete_install_root(&foo_root, &["serve"]);

    let displaced_row = serde_json::json!({
        "saved_spec": "^1",
        "resolved": "1.0.0",
        "integrity": "sha512-old",
        "source": "upstream-npm",
        "installed_at": "2026-04-15T00:00:00Z",
        "root": "installs/http-server@1.0.0",
        "commands": ["serve"],
    });

    let mut manifest = GlobalManifest::default();
    manifest.packages.insert(
        "http-server".into(),
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-old".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: "installs/http-server@1.0.0".into(),
            commands: vec!["serve".into()],
        },
    );
    manifest.pending.insert(
        "foo".into(),
        pending_install("foo", "installs/foo@1.0.0", &[]),
    );
    write_for(&root, &manifest).unwrap();

    let new_row = serde_json::json!({
        "saved_spec": "^1",
        "resolved": "1.0.0",
        "integrity": "sha512-x",
        "source": "lpm-dev",
        "installed_at": "2026-04-15T00:00:00Z",
        "root": "installs/foo@1.0.0",
        "commands": ["serve"],
    });
    let intent = WalRecord::Intent(Box::new(IntentPayload {
        tx_id: "tx-resolved".into(),
        kind: TxKind::Install,
        package: "foo".into(),
        new_root_path: foo_root.clone(),
        new_row_json: new_row,
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        ownership_delta: vec![OwnershipChange::DirectTransfer {
            command: "serve".into(),
            from_package: "http-server".into(),
            from_row_snapshot: displaced_row,
        }],
        uninstall_trust_prune: Vec::new(),
    }));
    let mut w = WalWriter::open(root.global_wal()).unwrap();
    w.append(&intent).unwrap();

    let report = recover(&root).unwrap();
    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::RolledForward,
        "user-resolved DirectTransfer must roll forward, not back"
    );

    let final_manifest = read_for(&root).unwrap();
    assert!(final_manifest.packages.contains_key("foo"));
    assert!(
        !final_manifest.packages["http-server"]
            .commands
            .contains(&"serve".to_string()),
        "displaced owner must lose `serve` per the delta"
    );
    let bin_target = std::fs::read_link(root.bin_dir().join("serve")).unwrap();
    let expected = foo_root.join("node_modules").join(".bin").join("serve");
    assert_eq!(
        bin_target, expected,
        "`serve` shim must point at the new owner"
    );
}

/// The same collision-resolution rule applies to `--alias`: the new bin
/// lands under a fresh PATH name, the original collision name is filtered
/// out of the post-resolution check, and the new alias key is checked
/// against the working view.
#[test]
#[cfg(unix)]
fn recovery_rolls_forward_when_collision_resolved_by_alias_in_delta() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    let http_server_root = root.install_root_for("http-server", "1.0.0");
    std::fs::create_dir_all(&http_server_root).unwrap();
    make_complete_install_root(&http_server_root, &["serve"]);

    let foo_root = root.install_root_for("foo", "1.0.0");
    std::fs::create_dir_all(&foo_root).unwrap();
    make_complete_install_root(&foo_root, &["serve"]);

    let mut manifest = GlobalManifest::default();
    manifest.packages.insert(
        "http-server".into(),
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-old".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: "installs/http-server@1.0.0".into(),
            commands: vec!["serve".into()],
        },
    );
    manifest.pending.insert(
        "foo".into(),
        pending_install("foo", "installs/foo@1.0.0", &[]),
    );
    write_for(&root, &manifest).unwrap();

    // `--alias serve=foo-serve`: marker still lists `serve` (the
    // declared bin), the post-resolution exposure is `foo-serve`.
    // The original `serve` is filtered out and only `foo-serve` is
    // checked against the working view, where nobody owns it yet.
    let new_row = serde_json::json!({
        "saved_spec": "^1",
        "resolved": "1.0.0",
        "integrity": "sha512-x",
        "source": "lpm-dev",
        "installed_at": "2026-04-15T00:00:00Z",
        "root": "installs/foo@1.0.0",
        "commands": [],
    });
    let intent = WalRecord::Intent(Box::new(IntentPayload {
        tx_id: "tx-aliased".into(),
        kind: TxKind::Install,
        package: "foo".into(),
        new_root_path: foo_root,
        new_row_json: new_row,
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({
            "foo-serve": {"package": "foo", "bin": "serve"}
        }),
        ownership_delta: vec![OwnershipChange::AliasInstall {
            alias_name: "foo-serve".into(),
            package: "foo".into(),
            bin: "serve".into(),
        }],
        uninstall_trust_prune: Vec::new(),
    }));
    let mut w = WalWriter::open(root.global_wal()).unwrap();
    w.append(&intent).unwrap();

    let report = recover(&root).unwrap();
    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::RolledForward,
        "user-resolved AliasInstall must roll forward — the original name was filtered out"
    );

    let final_manifest = read_for(&root).unwrap();
    assert!(final_manifest.packages.contains_key("foo"));
    assert!(
        final_manifest
            .packages
            .get("http-server")
            .is_some_and(|e| e.commands.contains(&"serve".to_string())),
        "displaced owner keeps `serve` when the new install only aliases"
    );
    assert!(
        final_manifest.aliases.contains_key("foo-serve"),
        "new alias row must land in manifest"
    );
}

/// When a collision exists for a PATH name not covered by
/// `ownership_delta`, recovery still rolls back. This proves the
/// acceptance path is limited to user-resolved collisions and does not
/// blanket-disable collision checking.
#[test]
#[cfg(unix)]
fn recovery_still_rolls_back_when_collision_not_covered_by_delta() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    let http_server_root = root.install_root_for("http-server", "1.0.0");
    std::fs::create_dir_all(&http_server_root).unwrap();
    make_complete_install_root(&http_server_root, &["serve"]);

    // foo declares BOTH `serve` (resolved by replace-bin) AND
    // `lint` (unresolved — no delta entry for it).
    let foo_root = root.install_root_for("foo", "1.0.0");
    std::fs::create_dir_all(&foo_root).unwrap();
    make_complete_install_root(&foo_root, &["serve", "lint"]);

    let displaced_row = serde_json::json!({
        "saved_spec": "^1",
        "resolved": "1.0.0",
        "integrity": "sha512-old",
        "source": "upstream-npm",
        "installed_at": "2026-04-15T00:00:00Z",
        "root": "installs/http-server@1.0.0",
        "commands": ["serve"],
    });

    let mut manifest = GlobalManifest::default();
    manifest.packages.insert(
        "http-server".into(),
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-old".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: "installs/http-server@1.0.0".into(),
            commands: vec!["serve".into()],
        },
    );
    // Third-party owner of `lint` — incoming install has no
    // resolution for this collision.
    manifest.packages.insert(
        "eslint".into(),
        PackageEntry {
            saved_spec: "^9".into(),
            resolved: "9.0.0".into(),
            integrity: "sha512-z".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: "installs/eslint@9.0.0".into(),
            commands: vec!["lint".into()],
        },
    );
    manifest.pending.insert(
        "foo".into(),
        pending_install("foo", "installs/foo@1.0.0", &[]),
    );
    write_for(&root, &manifest).unwrap();

    let new_row = serde_json::json!({
        "saved_spec": "^1",
        "resolved": "1.0.0",
        "integrity": "sha512-x",
        "source": "lpm-dev",
        "installed_at": "2026-04-15T00:00:00Z",
        "root": "installs/foo@1.0.0",
        "commands": ["serve", "lint"],
    });
    let intent = WalRecord::Intent(Box::new(IntentPayload {
        tx_id: "tx-partial".into(),
        kind: TxKind::Install,
        package: "foo".into(),
        new_root_path: foo_root,
        new_row_json: new_row,
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        // Only `serve` is in the delta — `lint` is not.
        ownership_delta: vec![OwnershipChange::DirectTransfer {
            command: "serve".into(),
            from_package: "http-server".into(),
            from_row_snapshot: displaced_row,
        }],
        uninstall_trust_prune: Vec::new(),
    }));
    let mut w = WalWriter::open(root.global_wal()).unwrap();
    w.append(&intent).unwrap();

    let report = recover(&root).unwrap();
    assert!(
        matches!(
            report.reconciled[0].outcome,
            ReconciliationOutcome::RolledBack { .. }
        ),
        "unresolved collision on `lint` must still roll back, got {:?}",
        report.reconciled[0].outcome
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

#[test]
#[cfg(unix)]
fn orphan_recovery_rejects_non_native_separator_in_absolute_wal_root() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());
    let non_native_root = root.global_root().join(r"installs\pkg@1.0.0");
    std::fs::create_dir_all(&non_native_root).unwrap();

    let mut wal = WalWriter::open(root.global_wal()).unwrap();
    wal.append(&intent_install(
        "tx-non-native-separator",
        "pkg",
        &non_native_root,
        &[],
    ))
    .unwrap();

    let report = recover(&root).unwrap();

    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::NothingToDo
    );
    assert!(
        non_native_root.exists(),
        "recovery must not delete a different path than the absolute validator authorized"
    );
}

#[test]
fn orphan_recovery_does_not_delete_root_referenced_by_mismatched_active_row() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());
    let install_root = root.install_root_for("pkg", "1.0.0");
    std::fs::create_dir_all(&install_root).unwrap();
    std::fs::write(install_root.join("active"), b"current").unwrap();

    let mut manifest = GlobalManifest::default();
    manifest.packages.insert(
        "pkg".into(),
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-current".into(),
            source: PackageSource::LpmDev,
            installed_at: Utc::now(),
            root: "installs/pkg@1.0.0".into(),
            commands: vec!["pkg".into()],
        },
    );
    write_for(&root, &manifest).unwrap();

    let mut wal = WalWriter::open(root.global_wal()).unwrap();
    wal.append(&intent_with_new_row("tx1", "pkg", &install_root, &["pkg"]))
        .unwrap();

    let report = recover(&root).unwrap();

    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::NothingToDo
    );
    assert!(
        install_root.exists(),
        "orphan reconciliation must preserve a root still referenced by the active manifest"
    );
}

/// When Case-C cleanup fails, the orphan path must be queued as a
/// tombstone so `store gc` or the next recovery pass can retry instead
/// of leaving permanent debris.
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
        new_root_path: install_root,
        new_row_json: new_row,
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        ownership_delta: Vec::new(),
        uninstall_trust_prune: Vec::new(),
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

/// Roll-forward must remove obsolete aliases that the new snapshot doesn't claim, including their
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

/// When `remove_shim` fails during recovery rollback, the transaction
/// must defer rather than write WAL Abort with leaked shims surviving.
#[test]
#[cfg(unix)]
fn recovery_rollback_defers_when_shim_removal_fails() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    // Pending install with a partial root → roll_back.
    let install_root = root.install_root_for("pkg", "1.0.0");
    std::fs::create_dir_all(install_root.join("node_modules").join(".bin")).unwrap();
    std::fs::write(install_root.join("lpm.lock"), b"x").unwrap();

    let mut manifest = GlobalManifest::default();
    manifest.pending.insert(
        "pkg".into(),
        pending_install("pkg", "installs/pkg@1.0.0", &["pkg"]),
    );
    write_for(&root, &manifest).unwrap();

    // Plant a shim file that cleanup will try to remove.
    std::fs::create_dir_all(root.bin_dir()).unwrap();
    std::os::unix::fs::symlink("/dev/null", root.bin_dir().join("pkg")).unwrap();

    // Drop write perm on bin_dir so remove_shim fails (POSIX
    // requires write on a directory to unlink children).
    let original_perms = std::fs::metadata(root.bin_dir()).unwrap().permissions();
    std::fs::set_permissions(root.bin_dir(), std::fs::Permissions::from_mode(0o555)).unwrap();

    let mut w = WalWriter::open(root.global_wal()).unwrap();
    w.append(&intent_install("tx-locked", "pkg", &install_root, &["pkg"]))
        .unwrap();

    let report = recover(&root);

    // Restore perms before any assertion-driven panic.
    std::fs::set_permissions(root.bin_dir(), original_perms).unwrap();

    let report = report.unwrap();
    match &report.reconciled[0].outcome {
        ReconciliationOutcome::Deferred { reason } => {
            assert!(
                reason.contains("could not clear"),
                "deferred reason must name shim-clear failure: {reason}"
            );
            assert!(reason.contains("pkg"));
        }
        other => panic!("expected Deferred when remove_shim fails; got {other:?}"),
    }

    // WAL must NOT have an Abort record — the rollback didn't
    // complete and the next pass should retry.
    let scan = WalReader::at(root.global_wal()).scan().unwrap();
    let has_abort = scan
        .records
        .iter()
        .any(|r| matches!(r, WalRecord::Abort { tx_id, .. } if tx_id == "tx-locked"));
    assert!(
        !has_abort,
        "Abort must not be written when shim cleanup deferred the rollback"
    );
}

/// Roll-forward of an upgrade Intent whose `new_aliases_json` preserves
/// the prior install's aliases must not emit a direct shim for the
/// aliased-away bin, and must keep the alias row in manifest pointing at
/// the new install root.
#[test]
fn recovery_upgrade_does_not_tombstone_prior_root_referenced_by_another_package() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());
    let prior_root = root.install_root_for("foo", "1.0.0");
    std::fs::create_dir_all(&prior_root).unwrap();
    make_complete_install_root(&prior_root, &[]);
    let new_root = root.install_root_for("foo", "2.0.0");
    std::fs::create_dir_all(&new_root).unwrap();
    make_complete_install_root(&new_root, &[]);

    let prior_relative = "installs/foo@1.0.0";
    let prior_entry = PackageEntry {
        saved_spec: "^1".into(),
        resolved: "1.0.0".into(),
        integrity: "sha512-old".into(),
        source: PackageSource::UpstreamNpm,
        installed_at: Utc::now(),
        root: prior_relative.into(),
        commands: Vec::new(),
    };
    let mut manifest = GlobalManifest::default();
    manifest.packages.insert("foo".into(), prior_entry.clone());
    manifest
        .packages
        .insert("other".into(), prior_entry.clone());
    manifest.pending.insert(
        "foo".into(),
        PendingEntry {
            saved_spec: "^2".into(),
            resolved: "2.0.0".into(),
            integrity: "sha512-new".into(),
            source: PackageSource::UpstreamNpm,
            started_at: Utc::now(),
            root: "installs/foo@2.0.0".into(),
            commands: Vec::new(),
            replaces_version: Some("1.0.0".into()),
        },
    );
    write_for(&root, &manifest).unwrap();

    let intent = WalRecord::Intent(Box::new(IntentPayload {
        tx_id: "tx-shared-prior".into(),
        kind: TxKind::Upgrade,
        package: "foo".into(),
        new_root_path: new_root,
        new_row_json: serde_json::json!({
            "saved_spec": "^2",
            "resolved": "2.0.0",
            "integrity": "sha512-new",
            "source": "upstream-npm",
            "root": "installs/foo@2.0.0",
            "commands": [],
            "replaces_version": "1.0.0",
        }),
        prior_active_row_json: Some(serde_json::to_value(prior_entry).unwrap()),
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        ownership_delta: Vec::new(),
        uninstall_trust_prune: Vec::new(),
    }));
    let mut wal = WalWriter::open(root.global_wal()).unwrap();
    wal.append(&intent).unwrap();

    let report = recover(&root).unwrap();

    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::RolledForward
    );
    assert!(
        !read_for(&root)
            .unwrap()
            .tombstones
            .contains(&prior_relative.to_string()),
        "a prior root still referenced by another package must not be tombstoned"
    );
}

#[test]
#[cfg(unix)]
fn roll_forward_upgrade_with_preserved_aliases_omits_aliased_away_direct_shim() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    // Prior install root exists (recovery doesn't care; tombstoning
    // happens in step 4 of roll_forward).
    let prior_root = root.install_root_for("foo", "1.0.0");
    std::fs::create_dir_all(&prior_root).unwrap();
    make_complete_install_root(&prior_root, &["dangerous"]);

    // New install root has the same `dangerous` bin (we're upgrading
    // the version, not changing the declared bins).
    let new_root = root.install_root_for("foo", "2.0.0");
    std::fs::create_dir_all(&new_root).unwrap();
    make_complete_install_root(&new_root, &["dangerous"]);

    // Manifest state pre-recovery: active row at 1.0.0, alias
    // row preserved, pending row staged for 2.0.0.
    let mut manifest = GlobalManifest::default();
    manifest.packages.insert(
        "foo".into(),
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-old".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: "installs/foo@1.0.0".into(),
            commands: vec![],
        },
    );
    manifest.aliases.insert(
        "safe-name".into(),
        AliasEntry {
            package: "foo".into(),
            bin: "dangerous".into(),
        },
    );
    manifest.pending.insert(
        "foo".into(),
        PendingEntry {
            saved_spec: "^2".into(),
            resolved: "2.0.0".into(),
            integrity: "sha512-new".into(),
            source: PackageSource::UpstreamNpm,
            started_at: Utc::now(),
            root: "installs/foo@2.0.0".into(),
            commands: vec![],
            replaces_version: Some("1.0.0".into()),
        },
    );
    write_for(&root, &manifest).unwrap();

    // Existing alias shim pointing at PRIOR install root.
    std::fs::create_dir_all(root.bin_dir()).unwrap();
    std::os::unix::fs::symlink(
        prior_root.join("node_modules/.bin/dangerous"),
        root.bin_dir().join("safe-name"),
    )
    .unwrap();

    // Upgrade Intent with new_aliases_json populated to preserve aliases.
    let new_row = serde_json::json!({
        "saved_spec": "^2",
        "resolved": "2.0.0",
        "integrity": "sha512-new",
        "source": "upstream-npm",
        "installed_at": "2026-05-17T00:00:00Z",
        "root": "installs/foo@2.0.0",
        "commands": [],
        "replaces_version": "1.0.0",
    });
    let prior_row = serde_json::json!({
        "saved_spec": "^1",
        "resolved": "1.0.0",
        "integrity": "sha512-old",
        "source": "upstream-npm",
        "installed_at": "2026-05-15T00:00:00Z",
        "root": "installs/foo@1.0.0",
        "commands": [],
    });
    let intent = WalRecord::Intent(Box::new(IntentPayload {
        tx_id: "tx-upgrade-alias".into(),
        kind: TxKind::Upgrade,
        package: "foo".into(),
        new_root_path: new_root.clone(),
        new_row_json: new_row,
        prior_active_row_json: Some(prior_row),
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({
            "safe-name": {"package": "foo", "bin": "dangerous"}
        }),
        ownership_delta: Vec::new(),
        uninstall_trust_prune: Vec::new(),
    }));
    let mut w = WalWriter::open(root.global_wal()).unwrap();
    w.append(&intent).unwrap();

    let report = recover(&root).unwrap();
    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::RolledForward
    );

    let final_manifest = read_for(&root).unwrap();
    assert!(
        final_manifest.aliases.contains_key("safe-name"),
        "alias row must survive upgrade roll-forward"
    );
    let safe_target = std::fs::read_link(root.bin_dir().join("safe-name")).unwrap();
    let expected = new_root.join("node_modules").join(".bin").join("dangerous");
    assert_eq!(
        safe_target, expected,
        "alias shim must be re-pointed at the new install root"
    );
    assert!(
        std::fs::symlink_metadata(root.bin_dir().join("dangerous")).is_err(),
        "aliased-away bin MUST NOT appear as a direct shim post-recovery"
    );
}

/// Rollback must remove alias shims the new install would have owned
/// and restore alias shims for the prior version.
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
        new_root_path: new_root,
        new_row_json: new_row,
        prior_active_row_json: Some(prior_row),
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({
            "pkg2": {"package": "pkg", "bin": "pkg"}
        }),
        ownership_delta: Vec::new(),
        uninstall_trust_prune: Vec::new(),
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

// ─── ownership_delta replay + revert ─────────────────────────────
//
// Replace-ownership and recovery are
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
/// Case: crash between Intent and Commit
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
/// EXPOSED name (alias key).
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
        uninstall_trust_prune: Vec::new(),
    };
    let json = serde_json::to_vec(&payload).unwrap();
    let parsed: IntentPayload = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed, payload);
}

/// Older WAL entries without `ownership_delta` must still deserialize
/// cleanly. `#[serde(default)]` on the field guarantees this; pin it so
/// a future refactor doesn't drop the attribute.
#[test]
fn legacy_intent_payload_without_ownership_delta_still_deserializes() {
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

// ─── compound-delta end-to-end ────────────────────────────────────

/// Replay a compound delta with all three OwnershipChange variants
/// in one Intent. Pins the interaction between variants — the
/// final manifest state must reflect every mutation.
#[test]
fn replay_compound_delta_applies_all_three_variants_consistently() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());
    let mut m = GlobalManifest::default();

    seed_displaced_owner(&mut m, "http-server", &["serve", "http"]);
    seed_displaced_owner(&mut m, "other-pkg", &["server"]);
    m.aliases.insert(
        "srv".into(),
        AliasEntry {
            package: "other-pkg".into(),
            bin: "server".into(),
        },
    );

    let delta = vec![
        OwnershipChange::DirectTransfer {
            command: "serve".into(),
            from_package: "http-server".into(),
            from_row_snapshot: serde_json::Value::Null,
        },
        OwnershipChange::AliasOwnerRemove {
            alias_name: "srv".into(),
            entry_snapshot: serde_json::json!({"package":"other-pkg","bin":"server"}),
        },
        OwnershipChange::AliasInstall {
            alias_name: "foo-lint".into(),
            package: "foo".into(),
            bin: "lint".into(),
        },
    ];

    for change in &delta {
        replay_ownership_change(&mut m, &root.bin_dir(), change);
    }

    assert_eq!(
        m.packages["http-server"].commands,
        vec!["http"],
        "DirectTransfer must drop `serve` from http-server"
    );
    assert!(
        !m.aliases.contains_key("srv"),
        "AliasOwnerRemove must drop the alias row"
    );
    let foo_lint = m
        .aliases
        .get("foo-lint")
        .expect("AliasInstall must write the new alias row");
    assert_eq!(foo_lint.package, "foo");
    assert_eq!(foo_lint.bin, "lint");
}

/// replay(delta) then revert(delta.reverse()) converges back to the
/// original state. This is the round-trip invariant — it's what
/// lets a crash between Intent and Commit recover correctly
/// regardless of which crash window fired.
#[test]
fn replay_then_revert_round_trips_manifest_state() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    let mut original = GlobalManifest::default();
    seed_displaced_owner(&mut original, "http-server", &["serve", "http"]);
    seed_displaced_owner(&mut original, "other-pkg", &["server"]);
    original.aliases.insert(
        "srv".into(),
        AliasEntry {
            package: "other-pkg".into(),
            bin: "server".into(),
        },
    );
    let before = original.clone();

    let http_server_snapshot = serde_json::to_value(&original.packages["http-server"]).unwrap();
    let delta = vec![
        OwnershipChange::DirectTransfer {
            command: "serve".into(),
            from_package: "http-server".into(),
            from_row_snapshot: http_server_snapshot,
        },
        OwnershipChange::AliasOwnerRemove {
            alias_name: "srv".into(),
            entry_snapshot: serde_json::json!({"package":"other-pkg","bin":"server"}),
        },
        OwnershipChange::AliasInstall {
            alias_name: "foo-lint".into(),
            package: "foo".into(),
            bin: "lint".into(),
        },
    ];

    let mut m = original;
    for change in &delta {
        replay_ownership_change(&mut m, &root.bin_dir(), change);
    }
    for change in delta.iter().rev() {
        revert_ownership_change(&mut m, &root.bin_dir(), change, &root);
    }

    assert_eq!(
        m.packages["http-server"].commands,
        before.packages["http-server"].commands
    );
    assert_eq!(m.aliases.get("srv"), before.aliases.get("srv"));
    assert!(!m.aliases.contains_key("foo-lint"));
}

// ── Roll-forward replays the host-global trust prune ──────────────

/// Crash recovery for an uninstall transaction must replay the
/// `uninstall_trust_prune` entries that were planned at uninstall
/// time. Seed the WAL with an Intent carrying a populated prune
/// set + a trust file containing those entries, then run recovery
/// and assert the entries are gone, the manifest is at the post-
/// uninstall state, and a Commit was appended.
///
/// The trust prune is part of the recovery contract: a crash between
/// in-transaction prune planning and the WAL Commit must not leave a
/// stale trust entry behind on the next `lpm` invocation.
#[test]
fn roll_forward_uninstall_replays_trust_prune() {
    let tmp = TempDir::new().unwrap();
    let root = LpmRoot::from_dir(tmp.path());

    // Seed: package "pkga" present in manifest, install root
    // on disk, trust file contains lodash@4.17.21.
    let install_root = root.install_root_for("pkga", "1.0.0");
    std::fs::create_dir_all(&install_root).unwrap();
    let mut manifest = GlobalManifest::default();
    manifest.packages.insert(
        "pkga".into(),
        crate::PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-x".into(),
            source: crate::PackageSource::LpmDev,
            installed_at: Utc::now(),
            root: "installs/pkga@1.0.0".into(),
            commands: vec![],
        },
    );
    write_for(&root, &manifest).unwrap();
    let mut trust = crate::trusted_deps::GlobalTrustedDependencies::default();
    trust.insert_strict(
        "lodash",
        "4.17.21",
        Some("sha512-l".into()),
        Some("sha256-s".into()),
    );
    crate::trusted_deps::write_for(&root, &trust).unwrap();

    // Write an Uninstall Intent WITHOUT a Commit — simulates a
    // crash after Intent and before the prune+manifest steps.
    let mut wal = WalWriter::open(root.global_wal()).unwrap();
    wal.append(&WalRecord::Intent(Box::new(IntentPayload {
        tx_id: "tx-m76-recover".into(),
        kind: TxKind::Uninstall,
        package: "pkga".into(),
        new_root_path: install_root,
        new_row_json: serde_json::Value::Null,
        prior_active_row_json: Some(serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "installed_at": "2026-04-22T00:00:00Z",
            "root": "installs/pkga@1.0.0",
            "commands": [],
        })),
        prior_command_ownership_json: serde_json::json!({"aliases": {}}),
        new_aliases_json: serde_json::Value::Null,
        ownership_delta: Vec::new(),
        uninstall_trust_prune: vec![TrustPruneEntry {
            name: "lodash".into(),
            version: "4.17.21".into(),
        }],
    })))
    .unwrap();
    drop(wal);

    let report = recover(&root).unwrap();
    assert_eq!(report.reconciled.len(), 1);
    assert_eq!(
        report.reconciled[0].outcome,
        ReconciliationOutcome::RolledForward,
        "uninstall Intent must roll forward"
    );

    // Trust file is pruned.
    let trust_after = crate::trusted_deps::read_for(&root).unwrap();
    assert!(
        !trust_after.trusted.contains_key("lodash@4.17.21"),
        "recovery must replay the trust prune; got {:?}",
        trust_after.trusted
    );

    // Manifest at post-uninstall state.
    let manifest_after = read_for(&root).unwrap();
    assert!(!manifest_after.packages.contains_key("pkga"));
    assert!(
        manifest_after
            .tombstones
            .iter()
            .any(|t| t == "installs/pkga@1.0.0"),
        "tombstone must be queued"
    );

    // After recovery, the WAL is compacted (every tx is resolved),
    // so the file is truncated. `wal_compacted` reports that.
    // Either way: the Intent is no longer uncompleted — running
    // recovery a second time produces zero new reconciliations.
    assert!(
        report.wal_compacted,
        "WAL must be compacted after the only Intent was rolled forward"
    );
    let second = recover(&root).unwrap();
    assert!(
        second.reconciled.is_empty(),
        "second recovery pass must find no uncompleted Intents"
    );
}
