//! End-to-end rotation tests against the test trust-store backend.
//!
//! Each test runs in its own process (one test binary per file), so HOME and the
//! trust-store / audit / projects-index env vars can be mutated without racing
//! other tests.

use lpm_cert::{audit, cert, paths, projects, rotate, trust};
use std::path::{Path, PathBuf};

/// All tests in this binary share process-wide env (`HOME`, etc.), so they
/// must serialize. Each test calls `let _g = serial_guard();` at entry.
fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn setup_home() -> (tempfile::TempDir, std::sync::MutexGuard<'static, ()>) {
    let guard = serial_guard();
    let tmp = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("HOME", tmp.path());
        std::env::set_var(
            "LPM_CERT_TEST_TRUST_STORE_DIR",
            tmp.path().join("trust-store"),
        );
        std::env::set_var("LPM_CERT_AUDIT_DIR", tmp.path().join("audit"));
        std::env::set_var(
            "LPM_CERT_PROJECTS_INDEX",
            tmp.path().join("cert-projects.json"),
        );
        std::env::set_var("LPM_CERT_GRACE_FILE", tmp.path().join("cert-grace.json"));
    }
    (tmp, guard)
}

fn seed_root_ca() -> (PathBuf, PathBuf) {
    let cert_path = paths::ca_cert_path().unwrap();
    let key_path = paths::ca_key_path().unwrap();
    lpm_cert::create_dir_secure(cert_path.parent().unwrap()).unwrap();
    let (cert_pem, key_pem) = lpm_cert::ca::generate_ca().unwrap();
    std::fs::write(&cert_path, &cert_pem).unwrap();
    lpm_cert::write_key_file(&key_path, key_pem.as_bytes()).unwrap();
    trust::install_ca(&cert_path).unwrap();
    (cert_path, key_path)
}

fn seed_project_leaf(project_dir: &Path) -> PathBuf {
    seed_project_leaf_with_extras(project_dir, &[])
}

fn seed_project_leaf_with_extras(project_dir: &Path, extras: &[String]) -> PathBuf {
    let leaf_dir = project_dir.join(".lpm").join("certs");
    std::fs::create_dir_all(&leaf_dir).unwrap();
    let ca_cert = std::fs::read_to_string(paths::ca_cert_path().unwrap()).unwrap();
    let ca_key = std::fs::read_to_string(paths::ca_key_path().unwrap()).unwrap();
    let (cert_pem, key_pem) = cert::generate_project_cert(&ca_cert, &ca_key, extras).unwrap();
    let leaf_path = leaf_dir.join("cert.pem");
    std::fs::write(&leaf_path, &cert_pem).unwrap();
    std::fs::write(leaf_dir.join("key.pem"), &key_pem).unwrap();
    projects::record(project_dir).unwrap();
    leaf_path
}

fn read_audit_actions(audit_dir: &Path) -> Vec<String> {
    let log = audit_dir.join("cert.jsonl");
    if !log.exists() {
        return Vec::new();
    }
    let s = std::fs::read_to_string(&log).unwrap_or_default();
    s.lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["action"].as_str().unwrap().to_string()
        })
        .collect()
}

#[test]
fn rotate_replaces_root_and_reissues_indexed_leaves() {
    let (tmp, _g) = setup_home();
    let (active_cert, _active_key) = seed_root_ca();
    let project_a = tmp.path().join("proj-a");
    let leaf_a = seed_project_leaf(&project_a);

    let old_fp = cert::fingerprint_sha256(&active_cert).unwrap();

    let result = rotate::rotate(rotate::RotateOptions::default()).unwrap();

    assert!(result.success);
    assert!(result.ca_rotated);
    assert_eq!(result.mode, "hard_cutover");
    assert!(result.old_ca_uninstalled);
    assert!(result.old_ca_removal_scheduled.is_none());
    assert_eq!(result.reissued_leaves.len(), 1);

    let new_fp = cert::fingerprint_sha256(&active_cert).unwrap();
    assert_ne!(old_fp, new_fp);

    assert!(cert::leaf_signed_by(&leaf_a, &active_cert).unwrap());
    assert!(trust::is_ca_installed(&active_cert).unwrap());

    let actions = read_audit_actions(&tmp.path().join("audit"));
    assert!(actions.contains(&"ca.rotate.begin".to_string()));
    assert!(actions.contains(&"ca.generate".to_string()));
    assert!(actions.contains(&"ca.trust_install".to_string()));
    assert!(actions.contains(&"cert.reissue".to_string()));
    assert!(actions.contains(&"ca.rotate.promote".to_string()));
    assert!(actions.contains(&"ca.trust_uninstall".to_string()));
    assert!(actions.contains(&"ca.rotate.complete".to_string()));
}

#[test]
fn rotate_skips_missing_project_dir_in_index_by_default() {
    let (tmp, _g) = setup_home();
    let (_active_cert, _active_key) = seed_root_ca();
    let project_real = tmp.path().join("proj-real");
    seed_project_leaf(&project_real);

    let project_gone = tmp.path().join("proj-gone");
    std::fs::create_dir_all(&project_gone).unwrap();
    seed_project_leaf(&project_gone);
    std::fs::remove_dir_all(&project_gone).unwrap();

    let result = rotate::rotate(rotate::RotateOptions::default()).unwrap();
    assert!(result.success);
    assert_eq!(result.reissued_leaves.len(), 1);
    assert_eq!(result.skipped_missing.len(), 1);
    assert!(result.skipped_missing[0].contains("proj-gone"));
}

#[test]
fn rotate_fails_on_missing_when_flag_set() {
    let (tmp, _g) = setup_home();
    let (_active_cert, _active_key) = seed_root_ca();
    let project_gone = tmp.path().join("proj-gone");
    std::fs::create_dir_all(&project_gone).unwrap();
    seed_project_leaf(&project_gone);
    std::fs::remove_dir_all(&project_gone).unwrap();

    let result = rotate::rotate(rotate::RotateOptions {
        skip_missing: false,
        ..Default::default()
    });
    assert!(result.is_err());
}

#[test]
fn rotate_grace_window_defers_old_ca_uninstall_and_records_schedule() {
    let (tmp, _g) = setup_home();
    let (active_cert, _) = seed_root_ca();
    let project_a = tmp.path().join("proj-a");
    seed_project_leaf(&project_a);

    let old_fp = cert::fingerprint_sha256(&active_cert).unwrap();
    let old_fp_hex = cert::fingerprint_hex(&old_fp);

    let result = rotate::rotate(rotate::RotateOptions {
        keep_old_trusted_days: Some(14),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(result.mode, "grace_window");
    assert!(!result.old_ca_uninstalled);
    assert!(result.old_ca_removal_scheduled.is_some());

    let entries = rotate::read_grace_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].fingerprint, old_fp_hex);

    let actions = read_audit_actions(&tmp.path().join("audit"));
    assert!(actions.contains(&"ca.grace_scheduled".to_string()));
}

#[test]
fn rotate_grace_window_rejects_over_max_days() {
    let (_tmp, _g) = setup_home();
    let (_active_cert, _) = seed_root_ca();

    let err = rotate::rotate(rotate::RotateOptions {
        keep_old_trusted_days: Some(180),
        ..Default::default()
    });
    assert!(err.is_err());
}

#[test]
fn reconcile_removes_grace_entry_when_time_has_passed() {
    let (tmp, _g) = setup_home();
    let (active_cert, _) = seed_root_ca();
    let project_a = tmp.path().join("proj-a");
    seed_project_leaf(&project_a);
    let _ = rotate::rotate(rotate::RotateOptions {
        keep_old_trusted_days: Some(14),
        ..Default::default()
    })
    .unwrap();

    let grace_path = tmp.path().join("cert-grace.json");
    let json = std::fs::read_to_string(&grace_path).unwrap();
    let past = json.replace(
        &json
            .lines()
            .find(|l| l.contains("removes_at"))
            .unwrap()
            .to_string(),
        "      \"removes_at\": \"2020-01-01T00:00:00Z\"",
    );
    std::fs::write(&grace_path, past).unwrap();

    let result =
        lpm_cert::reconcile::reconcile(lpm_cert::reconcile::ReconcileOptions::default()).unwrap();
    assert!(result.success);
    assert_eq!(result.grace_removed.len(), 1, "expected one grace removal");
    assert!(result.grace_pending.is_empty());

    let active_fp = cert::fingerprint_sha256(&active_cert).unwrap();
    assert!(trust::is_ca_installed(&active_cert).unwrap());
    let _ = active_fp;
}

#[test]
fn reconcile_keeps_grace_entry_when_time_in_future() {
    let (tmp, _g) = setup_home();
    let (_active_cert, _) = seed_root_ca();
    let project_a = tmp.path().join("proj-a");
    seed_project_leaf(&project_a);
    let _ = rotate::rotate(rotate::RotateOptions {
        keep_old_trusted_days: Some(14),
        ..Default::default()
    })
    .unwrap();

    let result =
        lpm_cert::reconcile::reconcile(lpm_cert::reconcile::ReconcileOptions::default()).unwrap();
    assert!(result.grace_removed.is_empty());
    assert_eq!(result.grace_pending.len(), 1);
}

#[test]
fn ensure_https_reissues_leaf_when_chain_breaks() {
    let (tmp, _g) = setup_home();
    let (active_cert, active_key) = seed_root_ca();
    let project = tmp.path().join("proj-orphan");
    std::fs::create_dir_all(&project).unwrap();
    let leaf_path = seed_project_leaf(&project);
    let original_fp = cert::fingerprint_sha256(&leaf_path).unwrap();

    let (new_pem, new_key_pem) = lpm_cert::ca::generate_ca().unwrap();
    std::fs::write(&active_cert, &new_pem).unwrap();
    lpm_cert::write_key_file(&active_key, new_key_pem.as_bytes()).unwrap();
    trust::install_ca(&active_cert).unwrap();

    let _setup = lpm_cert::ensure_https(&project, &[]).unwrap();
    let new_fp = cert::fingerprint_sha256(&leaf_path).unwrap();
    assert_ne!(
        original_fp, new_fp,
        "ensure_https must regenerate the project leaf when issuer mismatches"
    );
    assert!(cert::leaf_signed_by(&leaf_path, &active_cert).unwrap());
}

#[cfg(unix)]
#[test]
fn ensure_https_refuses_to_sign_with_world_readable_key() {
    use std::os::unix::fs::PermissionsExt;

    let (tmp, _g) = setup_home();
    let (_active_cert, active_key) = seed_root_ca();
    let project = tmp.path().join("proj-leaky-key");
    std::fs::create_dir_all(&project).unwrap();
    seed_project_leaf(&project);

    std::fs::set_permissions(&active_key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let err = lpm_cert::ensure_https(&project, &[]);
    assert!(err.is_err(), "expected ensure_https to refuse signing");
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("0o644"), "expected mode in message, got {msg}");
    assert!(msg.contains("chmod 600"), "expected chmod hint, got {msg}");
}

#[cfg(unix)]
#[test]
fn audit_cert_permissions_reports_drift_on_loose_dir() {
    use std::os::unix::fs::PermissionsExt;

    let (_tmp, _g) = setup_home();
    let (_active_cert, _) = seed_root_ca();
    let ca_dir = paths::ca_dir().unwrap();
    std::fs::set_permissions(&ca_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let drifts = lpm_cert::audit_cert_permissions().unwrap();
    assert!(
        drifts.iter().any(|d| d.role == "cert dir"),
        "expected cert-dir drift, got {drifts:?}"
    );
}

#[test]
fn ca_days_until_expiry_returns_positive_for_fresh_ca() {
    let (tmp, _g) = setup_home();
    let (active_cert, _) = seed_root_ca();
    let days = lpm_cert::ca_days_until_expiry(&active_cert).unwrap();
    assert!(days > 800 && days < 830, "expected ~825 days, got {days}");

    drop(audit::AuditAction::CaGenerate {
        fingerprint: "x".into(),
        validity_days: 0,
        name_constraints: false,
    });
    drop(tmp);
}

#[test]
fn rotate_preserves_custom_dns_and_ip_sans_through_reissue() {
    let (tmp, _g) = setup_home();
    let (_active_cert, _active_key) = seed_root_ca();
    let project = tmp.path().join("proj-custom-sans");
    let extras = vec!["myapp.local".to_string(), "192.168.1.42".to_string()];
    let leaf_before = seed_project_leaf_with_extras(&project, &extras);

    let before_sans = cert::read_san_entries(&leaf_before).unwrap();
    assert!(
        before_sans
            .iter()
            .any(|s| matches!(s, cert::SanEntry::Dns(d) if d == "myapp.local")),
        "fixture must seed `myapp.local` as a DNS SAN"
    );
    assert!(
        before_sans
            .iter()
            .any(|s| matches!(s, cert::SanEntry::Ip(ip) if ip.to_string() == "192.168.1.42")),
        "fixture must seed `192.168.1.42` as an IP SAN"
    );

    let result = rotate::rotate(rotate::RotateOptions::default()).unwrap();
    assert!(result.success);
    assert_eq!(result.reissued_leaves.len(), 1);

    let after_sans = cert::read_san_entries(&leaf_before).unwrap();
    assert!(
        after_sans
            .iter()
            .any(|s| matches!(s, cert::SanEntry::Dns(d) if d == "myapp.local")),
        "rotation must preserve custom DNS SAN, got {after_sans:?}"
    );
    assert!(
        after_sans
            .iter()
            .any(|s| matches!(s, cert::SanEntry::Ip(ip) if ip.to_string() == "192.168.1.42")),
        "rotation must preserve custom IP SAN, got {after_sans:?}"
    );
}

#[test]
fn reconcile_retries_uninstall_for_unresolved_reconcile_required() {
    let (tmp, _g) = setup_home();
    // Simulate the state just BEFORE the failed step-6 uninstall: trust store
    // holds the old CA, and `.previous` is on disk pointing at it. The test
    // trust store backend models a single trusted CA, so we pin that to the
    // old root (not the new one) — `is_ca_installed(&prev_cert)` should be true.
    let (active_cert, _active_key) = seed_root_ca();
    let _ = seed_project_leaf(&tmp.path().join("proj"));

    let old_fp = cert::fingerprint_sha256(&active_cert).unwrap();
    let old_fp_hex = cert::fingerprint_hex(&old_fp);

    let ca_dir = paths::ca_dir().unwrap();
    let prev_cert_path = ca_dir.join("rootCA.pem.previous");
    let prev_key_path = ca_dir.join("rootCA-key.pem.previous");
    std::fs::copy(&active_cert, &prev_cert_path).unwrap();
    std::fs::copy(paths::ca_key_path().unwrap(), &prev_key_path).unwrap();

    audit::append(audit::AuditAction::CaReconcileRequired {
        old_fingerprint: old_fp_hex.clone(),
        new_fingerprint: "FUTURE".into(),
    })
    .unwrap();

    assert!(trust::is_ca_installed(&prev_cert_path).unwrap());

    let result =
        lpm_cert::reconcile::reconcile(lpm_cert::reconcile::ReconcileOptions::default()).unwrap();

    assert!(result.success);
    assert!(
        result.resolved_old_fingerprints.contains(&old_fp_hex),
        "reconcile should resolve the unresolved marker, got resolved={:?}",
        result.resolved_old_fingerprints
    );
    assert!(result.reconcile_required_cleared);
    assert!(
        !trust::is_ca_installed(&prev_cert_path).unwrap(),
        "reconcile should have uninstalled the old CA via the .previous bytes"
    );
}

#[test]
fn reconcile_preserves_previous_files_when_marker_unresolved_and_backup_missing() {
    let (tmp, _g) = setup_home();
    let (_active_cert, _) = seed_root_ca();
    let _ = seed_project_leaf(&tmp.path().join("proj"));

    let ca_dir = paths::ca_dir().unwrap();
    let prev_cert_path = ca_dir.join("rootCA.pem.previous");
    let prev_key_path = ca_dir.join("rootCA-key.pem.previous");

    // No .previous on disk and an unresolved reconcile_required event: reconcile
    // surfaces the pending marker; it does not delete the (missing) backup, and
    // does not pretend success.
    audit::append(audit::AuditAction::CaReconcileRequired {
        old_fingerprint: "AA:BB:CC".into(),
        new_fingerprint: "11:22:33".into(),
    })
    .unwrap();

    let result =
        lpm_cert::reconcile::reconcile(lpm_cert::reconcile::ReconcileOptions::default()).unwrap();
    assert!(
        result
            .pending_old_fingerprints
            .contains(&"AA:BB:CC".to_string()),
        "missing backup should leave the marker pending"
    );
    assert!(!result.reconcile_required_cleared);
    assert!(!prev_cert_path.exists());
    assert!(!prev_key_path.exists());
}

#[test]
fn rotate_refuses_to_overwrite_previous_while_reconcile_required_unresolved() {
    let (tmp, _g) = setup_home();
    let (active_cert, _) = seed_root_ca();
    seed_project_leaf(&tmp.path().join("proj"));

    let old_fp_hex = cert::fingerprint_hex(&cert::fingerprint_sha256(&active_cert).unwrap());

    // Simulate the post-promote, uninstall-failed state from a previous rotation:
    // .previous on disk + an unresolved ca.reconcile_required marker.
    let ca_dir = paths::ca_dir().unwrap();
    let prev_cert_path = ca_dir.join("rootCA.pem.previous");
    let prev_key_path = ca_dir.join("rootCA-key.pem.previous");
    std::fs::copy(&active_cert, &prev_cert_path).unwrap();
    std::fs::copy(paths::ca_key_path().unwrap(), &prev_key_path).unwrap();
    audit::append(audit::AuditAction::CaReconcileRequired {
        old_fingerprint: old_fp_hex.clone(),
        new_fingerprint: "FUTURE".into(),
    })
    .unwrap();

    let prev_cert_before = std::fs::read(&prev_cert_path).unwrap();

    let err = rotate::rotate(rotate::RotateOptions::default()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("reconcile_required"),
        "refusal must name the conflict, got {msg}"
    );
    assert!(
        msg.contains("lpm cert reconcile"),
        "refusal must point at `lpm cert reconcile`, got {msg}"
    );

    let prev_cert_after = std::fs::read(&prev_cert_path).unwrap();
    assert_eq!(
        prev_cert_before, prev_cert_after,
        "rotate must not have overwritten rootCA.pem.previous"
    );
}

#[test]
fn rotate_refuses_to_overwrite_previous_while_grace_window_open() {
    let (tmp, _g) = setup_home();
    let (_active_cert, _) = seed_root_ca();
    seed_project_leaf(&tmp.path().join("proj"));

    // First rotation in grace-window mode. After this the active CA is new,
    // .previous holds the old root, and a grace entry is on disk.
    rotate::rotate(rotate::RotateOptions {
        keep_old_trusted_days: Some(14),
        ..Default::default()
    })
    .unwrap();
    assert!(
        paths::ca_dir()
            .unwrap()
            .join("rootCA.pem.previous")
            .exists()
    );

    let err = rotate::rotate(rotate::RotateOptions::default()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("grace-window") || msg.contains("grace"),
        "refusal must name grace conflict, got {msg}"
    );
}

#[test]
fn rotate_preserves_custom_loopback_alias_ip_san() {
    use std::net::{IpAddr, Ipv4Addr};

    let (tmp, _g) = setup_home();
    let (_active_cert, _) = seed_root_ca();
    let project = tmp.path().join("proj-loopback-alias");
    let extras = vec!["127.0.0.2".to_string()];
    let leaf = seed_project_leaf_with_extras(&project, &extras);

    let before = cert::read_san_entries(&leaf).unwrap();
    assert!(
        before.iter().any(|s| matches!(
            s,
            cert::SanEntry::Ip(IpAddr::V4(ip)) if *ip == Ipv4Addr::new(127, 0, 0, 2)
        )),
        "fixture must seed 127.0.0.2 as an IP SAN"
    );

    rotate::rotate(rotate::RotateOptions::default()).unwrap();

    let after = cert::read_san_entries(&leaf).unwrap();
    assert!(
        after.iter().any(|s| matches!(
            s,
            cert::SanEntry::Ip(IpAddr::V4(ip)) if *ip == Ipv4Addr::new(127, 0, 0, 2)
        )),
        "rotation must preserve 127.0.0.2 — only the literal 127.0.0.1 / ::1 / localhost are defaults; loopback aliases must round-trip, got {after:?}"
    );
}
