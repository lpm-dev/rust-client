//! End-to-end rotation tests against the test trust-store backend.
//!
//! Each test runs in its own process (one test binary per file), so HOME and the
//! trust-store / audit / projects-index env vars can be mutated without racing
//! other tests.

#![cfg(debug_assertions)]

use lpm_cert::{audit, cert, paths, projects, rotate, trust};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::path::{Path, PathBuf};

const CONCURRENCY_ACTION_ENV: &str = "LPM_CERT_CONCURRENCY_ACTION";
const CONCURRENCY_PROJECT_ENV: &str = "LPM_CERT_CONCURRENCY_PROJECT";
const CONCURRENCY_BARRIER_ENV: &str = "LPM_CERT_CONCURRENCY_BARRIER";

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

fn seed_legacy_path_len_zero_root_ca() -> (PathBuf, PathBuf) {
    let cert_path = paths::ca_cert_path().unwrap();
    let key_path = paths::ca_key_path().unwrap();
    lpm_cert::create_dir_secure(cert_path.parent().unwrap()).unwrap();

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Legacy LPM Local Development CA");
    dn.push(DnType::OrganizationName, "LPM");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    std::fs::write(&cert_path, cert.pem()).unwrap();
    lpm_cert::write_key_file(&key_path, key_pair.serialize_pem().as_bytes()).unwrap();
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
fn certificate_concurrency_helper() {
    let Some(action) = std::env::var_os(CONCURRENCY_ACTION_ENV) else {
        return;
    };
    let project = PathBuf::from(std::env::var_os(CONCURRENCY_PROJECT_ENV).unwrap());
    if let Some(barrier) = std::env::var_os(CONCURRENCY_BARRIER_ENV) {
        let barrier = PathBuf::from(barrier);
        let ready = barrier.join(format!("{}.ready", std::process::id()));
        std::fs::write(&ready, b"ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !barrier.join("go").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "certificate concurrency barrier was never released"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    match action.to_string_lossy().as_ref() {
        "ensure" => {
            lpm_cert::ensure_https_with_consent(
                &project,
                &[],
                lpm_cert::TrustStoreConsent::Decline,
            )
            .unwrap();
        }
        "record" => projects::record(&project).unwrap(),
        "trust" => {
            lpm_cert::trust_ca().unwrap();
        }
        "audit" => audit::append(audit::AuditAction::CaGenerate {
            fingerprint: project.to_string_lossy().into_owned(),
            validity_days: 1,
            name_constraints: false,
        })
        .unwrap(),
        action => panic!("unknown certificate concurrency helper action: {action}"),
    }
}

fn spawn_concurrency_helpers(
    root: &Path,
    action: &str,
    projects: &[PathBuf],
) -> Vec<std::process::Child> {
    let executable = std::env::current_exe().unwrap();
    let barrier = root.join(format!("barrier-{}", std::process::id()));
    std::fs::create_dir_all(&barrier).unwrap();
    let children: Vec<_> = projects
        .iter()
        .map(|project| {
            std::process::Command::new(&executable)
                .args(["--exact", "certificate_concurrency_helper"])
                .env("HOME", root)
                .env("LPM_CERT_AUDIT_DIR", root.join("audit"))
                .env("LPM_CERT_PROJECTS_INDEX", root.join("cert-projects.json"))
                .env("LPM_CERT_TEST_TRUST_STORE_DIR", root.join("trust-store"))
                .env(CONCURRENCY_ACTION_ENV, action)
                .env(CONCURRENCY_PROJECT_ENV, project)
                .env(CONCURRENCY_BARRIER_ENV, &barrier)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::fs::read_dir(&barrier)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "ready")
        })
        .count()
        != children.len()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "certificate concurrency helpers did not reach the start barrier"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    std::fs::write(barrier.join("go"), b"go").unwrap();
    children
}

fn wait_for_concurrency_helpers(children: Vec<std::process::Child>) {
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "certificate concurrency helper failed with {}:\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn concurrent_ca_bootstrap_keeps_one_valid_pair_and_every_project_leaf() {
    let (tmp, _guard) = setup_home();
    let projects: Vec<_> = (0..8)
        .map(|index| {
            let project = tmp.path().join(format!("project-{index}"));
            std::fs::create_dir_all(&project).unwrap();
            project
        })
        .collect();

    wait_for_concurrency_helpers(spawn_concurrency_helpers(tmp.path(), "ensure", &projects));

    let ca_cert_path = paths::ca_cert_path().unwrap();
    let ca_cert = std::fs::read_to_string(&ca_cert_path).unwrap();
    let ca_key = std::fs::read_to_string(paths::ca_key_path().unwrap()).unwrap();
    assert!(cert::generate_project_cert(&ca_cert, &ca_key, &[]).is_ok());
    for project in &projects {
        let leaf = project.join(".lpm/certs/cert.pem");
        assert!(cert::project_cert_chains_to_root(&leaf, &ca_cert_path).unwrap());
    }
    assert_eq!(projects::list().unwrap().len(), projects.len());
}

#[test]
fn concurrent_trust_commands_keep_one_valid_root_pair() {
    let (tmp, _guard) = setup_home();
    let markers: Vec<_> = (0..8)
        .map(|index| tmp.path().join(format!("trust-{index}")))
        .collect();

    wait_for_concurrency_helpers(spawn_concurrency_helpers(tmp.path(), "trust", &markers));

    let ca_cert = std::fs::read_to_string(paths::ca_cert_path().unwrap()).unwrap();
    let ca_key = std::fs::read_to_string(paths::ca_key_path().unwrap()).unwrap();
    assert!(cert::validate_ca_key_pair(&ca_cert, &ca_key).is_ok());
}

#[test]
fn uninstall_active_ca_records_the_removed_fingerprint_inside_the_operation() {
    let (tmp, _guard) = setup_home();
    let (cert_path, _) = seed_root_ca();
    let fingerprint = cert::fingerprint_hex(&cert::fingerprint_sha256(&cert_path).unwrap());

    lpm_cert::uninstall_active_ca().unwrap();

    let audit_log = std::fs::read_to_string(tmp.path().join("audit/cert.jsonl")).unwrap();
    let event = audit_log
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["action"] == "ca.trust_uninstall")
        .expect("certificate uninstall did not append an audit event");
    assert_eq!(event["fingerprint"], fingerprint);
    assert_eq!(event["status"], "ok");
}

#[test]
fn hard_rotation_preserves_an_active_tls_certificate_generation() {
    let (_tmp, _guard) = setup_home();
    let (root_path, _) = seed_root_ca();
    let project = root_path.parent().unwrap().join("active-runtime-project");
    std::fs::create_dir_all(&project).unwrap();
    let setup = lpm_cert::ensure_https_with_consent(
        &project,
        &["app.localhost".to_string()],
        lpm_cert::TrustStoreConsent::Decline,
    )
    .unwrap();
    let original_root = std::fs::read(&root_path).unwrap();

    let error = rotate::rotate(rotate::RotateOptions::default()).unwrap_err();

    assert!(error.to_string().contains("active TLS runtime"), "{error}");
    assert_eq!(std::fs::read(&root_path).unwrap(), original_root);
    assert!(trust::is_ca_installed(&root_path).unwrap());

    drop(setup);
    let result = rotate::rotate(rotate::RotateOptions::default()).unwrap();
    assert!(result.success);
    assert_ne!(std::fs::read(&root_path).unwrap(), original_root);
}

#[test]
fn concurrent_project_index_updates_preserve_every_project() {
    let (tmp, _guard) = setup_home();
    let projects: Vec<_> = (0..16)
        .map(|index| {
            let project = tmp.path().join(format!("record-{index}"));
            std::fs::create_dir_all(&project).unwrap();
            project
        })
        .collect();

    wait_for_concurrency_helpers(spawn_concurrency_helpers(tmp.path(), "record", &projects));

    assert_eq!(projects::list().unwrap().len(), projects.len());
}

#[test]
fn concurrent_audit_appends_preserve_complete_json_lines() {
    let (tmp, _guard) = setup_home();
    let markers: Vec<_> = (0..16)
        .map(|index| tmp.path().join(format!("audit-{index}")))
        .collect();

    wait_for_concurrency_helpers(spawn_concurrency_helpers(tmp.path(), "audit", &markers));

    let log = std::fs::read_to_string(tmp.path().join("audit/cert.jsonl")).unwrap();
    let lines: Vec<_> = log.lines().collect();
    assert_eq!(lines.len(), markers.len());
    assert!(
        lines
            .iter()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
    );
}

#[cfg(unix)]
#[test]
fn ensure_https_rejects_a_project_certificate_directory_symlink() {
    use std::os::unix::fs::symlink;

    let (tmp, _guard) = setup_home();
    seed_root_ca();
    let project = tmp.path().join("project");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(project.join(".lpm")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, project.join(".lpm/certs")).unwrap();

    let result =
        lpm_cert::ensure_https_with_consent(&project, &[], lpm_cert::TrustStoreConsent::Decline);

    assert!(
        result.is_err(),
        "symlinked project cert directory was accepted"
    );
    assert!(!outside.join("cert.pem").exists());
    assert!(!outside.join("key.pem").exists());
}

#[cfg(unix)]
#[test]
fn ensure_https_rejects_a_project_certificate_file_symlink() {
    use std::os::unix::fs::symlink;

    let (tmp, _guard) = setup_home();
    seed_root_ca();
    let project = tmp.path().join("project");
    let cert_dir = project.join(".lpm/certs");
    let outside = tmp.path().join("outside.pem");
    std::fs::create_dir_all(&cert_dir).unwrap();
    std::fs::write(&outside, "sentinel").unwrap();
    symlink(&outside, cert_dir.join("cert.pem")).unwrap();

    let result =
        lpm_cert::ensure_https_with_consent(&project, &[], lpm_cert::TrustStoreConsent::Decline);

    assert!(
        result.is_err(),
        "symlinked project certificate was accepted"
    );
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "sentinel");
    assert!(!cert_dir.join("key.pem").exists());
}

#[cfg(unix)]
#[test]
fn ensure_https_rejects_a_project_private_key_symlink() {
    use std::os::unix::fs::symlink;

    let (tmp, _g) = setup_home();
    seed_root_ca();
    let project = tmp.path().join("proj-key-link");
    let cert_dir = project.join(".lpm/certs");
    std::fs::create_dir_all(&cert_dir).unwrap();
    let outside = tmp.path().join("outside-key.pem");
    std::fs::write(&outside, b"sentinel").unwrap();
    symlink(&outside, cert_dir.join("key.pem")).unwrap();

    let result =
        lpm_cert::ensure_https_with_consent(&project, &[], lpm_cert::TrustStoreConsent::Decline);

    assert!(
        result.is_err(),
        "symlinked project private key was accepted"
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"sentinel");
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

#[cfg(unix)]
#[test]
fn rotation_failure_on_a_later_project_restores_every_earlier_leaf() {
    use std::os::unix::fs::symlink;

    let (tmp, _guard) = setup_home();
    let (active_cert, _) = seed_root_ca();
    let project_a = tmp.path().join("a-project");
    let project_z = tmp.path().join("z-project");
    let leaf_a = seed_project_leaf(&project_a);
    seed_project_leaf(&project_z);
    let old_leaf_a = std::fs::read(&leaf_a).unwrap();
    let old_key_a = std::fs::read(project_a.join(".lpm/certs/key.pem")).unwrap();

    let unsafe_cert_dir = project_z.join(".lpm/certs");
    std::fs::remove_dir_all(&unsafe_cert_dir).unwrap();
    symlink(tmp.path(), &unsafe_cert_dir).unwrap();

    let error = rotate::rotate(rotate::RotateOptions::default()).unwrap_err();

    assert!(error.to_string().contains("without following links"));
    assert_eq!(std::fs::read(&leaf_a).unwrap(), old_leaf_a);
    assert_eq!(
        std::fs::read(project_a.join(".lpm/certs/key.pem")).unwrap(),
        old_key_a
    );
    assert!(cert::project_cert_chains_to_root(&leaf_a, &active_cert).unwrap());
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
fn expired_grace_generation_stays_pending_only_while_its_tls_runtime_is_active() {
    let (tmp, _guard) = setup_home();
    seed_root_ca();
    let project = tmp.path().join("leased-grace-project");
    std::fs::create_dir_all(&project).unwrap();
    let old_setup = lpm_cert::ensure_https_with_consent(
        &project,
        &["app.localhost".to_string()],
        lpm_cert::TrustStoreConsent::Decline,
    )
    .unwrap();
    rotate::rotate(rotate::RotateOptions {
        keep_old_trusted_days: Some(0),
        ..Default::default()
    })
    .unwrap();
    let grace_path = tmp.path().join("cert-grace.json");
    let json = std::fs::read_to_string(&grace_path).unwrap();
    std::fs::write(
        &grace_path,
        json.replace(
            &json
                .lines()
                .find(|line| line.contains("removes_at"))
                .unwrap()
                .to_string(),
            "      \"removes_at\": \"2020-01-01T00:00:00Z\"",
        ),
    )
    .unwrap();
    let new_setup = lpm_cert::ensure_https_with_consent(
        &project,
        &["app.localhost".to_string()],
        lpm_cert::TrustStoreConsent::Decline,
    )
    .unwrap();

    let pending =
        lpm_cert::reconcile::reconcile(lpm_cert::reconcile::ReconcileOptions::default()).unwrap();
    assert!(pending.grace_removed.is_empty());
    assert_eq!(pending.grace_pending.len(), 1);

    drop(old_setup);
    let removed =
        lpm_cert::reconcile::reconcile(lpm_cert::reconcile::ReconcileOptions::default()).unwrap();
    assert_eq!(removed.grace_removed.len(), 1);
    assert!(removed.grace_pending.is_empty());
    drop(new_setup);
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

#[test]
fn ensure_https_reissues_leaf_when_private_key_does_not_match() {
    let (tmp, _g) = setup_home();
    seed_root_ca();
    let project = tmp.path().join("proj-mismatched-leaf");
    std::fs::create_dir_all(&project).unwrap();
    let leaf_path = seed_project_leaf(&project);
    let original_fp = cert::fingerprint_sha256(&leaf_path).unwrap();

    let ca_cert = std::fs::read_to_string(paths::ca_cert_path().unwrap()).unwrap();
    let ca_key = std::fs::read_to_string(paths::ca_key_path().unwrap()).unwrap();
    let (_, unrelated_key) = cert::generate_project_cert(&ca_cert, &ca_key, &[]).unwrap();
    lpm_cert::write_key_file(
        &project.join(".lpm/certs/key.pem"),
        unrelated_key.as_bytes(),
    )
    .unwrap();

    let setup = lpm_cert::ensure_https(&project, &[]).unwrap();
    assert!(
        setup.cert_freshly_generated,
        "ensure_https must regenerate a project leaf whose private key does not match"
    );
    assert_ne!(
        original_fp,
        cert::fingerprint_sha256(&leaf_path).unwrap(),
        "the mismatched project certificate must be replaced"
    );
}

#[test]
fn ensure_https_writes_constrained_intermediate_chain_for_custom_hostnames() {
    let (_tmp, _g) = setup_home();
    let (active_cert, _active_key) = seed_root_ca();
    let project = tempfile::tempdir().unwrap();
    let extra = vec!["web.app.localhost".to_string()];

    let setup = lpm_cert::ensure_https(project.path(), &extra).unwrap();
    let cert_path = PathBuf::from(&setup.cert_path);

    assert!(cert::project_cert_has_intermediate(&cert_path).unwrap());
    assert!(cert::project_cert_chains_to_root(&cert_path, &active_cert).unwrap());
}

#[test]
fn ensure_https_writes_extra_permitted_dns_to_project_intermediate() {
    let (_tmp, _g) = setup_home();
    seed_root_ca();
    let project = tempfile::tempdir().unwrap();
    let extra_permitted_dns = vec!["myapp.local".to_string(), ".myapp.local".to_string()];

    let setup = lpm_cert::ensure_https_with_consent_and_permitted_dns(
        project.path(),
        &[],
        &extra_permitted_dns,
        lpm_cert::TrustStoreConsent::PreApproved,
    )
    .unwrap();
    let cert_path = PathBuf::from(&setup.cert_path);

    assert!(cert::project_cert_has_intermediate(&cert_path).unwrap());
    assert!(
        cert::project_cert_constraints_cover_dns(&cert_path, &[], &extra_permitted_dns).unwrap()
    );
}

#[test]
fn ensure_https_rejects_legacy_root_when_custom_hostnames_need_intermediate() {
    let (_tmp, _g) = setup_home();
    seed_legacy_path_len_zero_root_ca();
    let project = tempfile::tempdir().unwrap();
    let extra = vec!["web.app.localhost".to_string()];

    let err = lpm_cert::ensure_https(project.path(), &extra).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("pathLenConstraint is 0") && msg.contains("lpm cert rotate"),
        "expected rotate guidance for legacy root, got {msg}"
    );
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
fn rotate_preserves_project_intermediate_extra_dns_constraints() {
    let (tmp, _g) = setup_home();
    let (_active_cert, _active_key) = seed_root_ca();
    let project = tmp.path().join("proj-extra-constraints");
    std::fs::create_dir_all(&project).unwrap();
    let extras = vec!["web.myapp.local".to_string()];
    let extra_constraints = vec!["myapp.local".to_string(), ".myapp.local".to_string()];
    let setup = lpm_cert::ensure_https_with_consent_and_permitted_dns(
        &project,
        &extras,
        &extra_constraints,
        lpm_cert::TrustStoreConsent::PreApproved,
    )
    .unwrap();
    let leaf = PathBuf::from(&setup.cert_path);
    drop(setup);

    rotate::rotate(rotate::RotateOptions::default()).unwrap();

    let constraints = cert::read_project_dns_constraints(&leaf).unwrap();
    assert!(
        constraints.contains(&".myapp.local".to_string()),
        "rotation must preserve configured DNS suffix constraints, got {constraints:?}"
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
fn reconcile_refuses_to_resolve_marker_when_previous_fingerprint_mismatches() {
    let (tmp, _g) = setup_home();
    // Stage the "corrupted from a pre-fix branch build" state: a marker for
    // fp_A but `.previous` actually contains fp_B (a later root that was
    // installed by a since-broken successive rotation). Reconcile must NOT
    // record `ca.reconcile.resolved` for fp_A — fp_A is still trusted, and
    // uninstalling fp_B's bytes would remove the wrong cert.
    let (_active_cert, _) = seed_root_ca();
    seed_project_leaf(&tmp.path().join("proj"));

    // `.previous` here gets a brand-new CA's bytes — its fingerprint is fp_B,
    // unrelated to any audit event.
    let (b_cert_pem, b_key_pem) = lpm_cert::ca::generate_ca().unwrap();
    let ca_dir = paths::ca_dir().unwrap();
    let prev_cert_path = ca_dir.join("rootCA.pem.previous");
    let prev_key_path = ca_dir.join("rootCA-key.pem.previous");
    std::fs::write(&prev_cert_path, &b_cert_pem).unwrap();
    std::fs::write(&prev_key_path, &b_key_pem).unwrap();
    let prev_fp_b = cert::fingerprint_hex(&cert::fingerprint_sha256(&prev_cert_path).unwrap());

    let fp_a = "AA:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55".to_string();
    assert_ne!(fp_a, prev_fp_b);
    audit::append(audit::AuditAction::CaReconcileRequired {
        old_fingerprint: fp_a.clone(),
        new_fingerprint: "ZZ".into(),
    })
    .unwrap();

    let prev_bytes_before = std::fs::read(&prev_cert_path).unwrap();

    let result =
        lpm_cert::reconcile::reconcile(lpm_cert::reconcile::ReconcileOptions::default()).unwrap();

    assert!(
        result.pending_old_fingerprints.contains(&fp_a),
        "marker for fp_A must remain pending, got resolved={:?} pending={:?}",
        result.resolved_old_fingerprints,
        result.pending_old_fingerprints
    );
    assert!(
        !result.resolved_old_fingerprints.contains(&fp_a),
        "marker for fp_A must NOT be recorded as resolved when .previous holds a different fingerprint"
    );
    assert!(!result.reconcile_required_cleared);

    let actions = read_audit_actions(&tmp.path().join("audit"));
    assert!(
        !actions
            .iter()
            .any(|a| a == "ca.reconcile.resolved" || a == "ca.trust_uninstall"),
        "no false resolved/uninstall events may be appended, got actions={actions:?}"
    );
    assert_eq!(
        prev_bytes_before,
        std::fs::read(&prev_cert_path).unwrap(),
        ".previous bytes must not be touched"
    );
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
        old_fingerprint: old_fp_hex,
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
