use super::prelude::*;
use super::test_support::{guarded_attempts, with_test_env};
use super::*;
use tempfile::tempdir;

fn with_file_secret_env<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    with_test_env(dir, || {
        unsafe {
            std::env::remove_var(TEST_SECRET_ENV);
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }
        f()
    })
}

fn with_lpm_home<T>(home: &Path, f: impl FnOnce() -> T) -> T {
    struct RestoreLpmHome(Option<std::ffi::OsString>);

    impl Drop for RestoreLpmHome {
        fn drop(&mut self) {
            unsafe {
                match self.0.as_ref() {
                    Some(value) => std::env::set_var("LPM_HOME", value),
                    None => std::env::remove_var("LPM_HOME"),
                }
            }
        }
    }

    let _restore = RestoreLpmHome(std::env::var_os("LPM_HOME"));
    unsafe {
        std::env::set_var("LPM_HOME", home);
    }
    f()
}

fn without_test_native_auth<T>(f: impl FnOnce() -> T) -> T {
    struct RestoreTestAuth(Option<std::ffi::OsString>);

    impl Drop for RestoreTestAuth {
        fn drop(&mut self) {
            unsafe {
                match self.0.as_ref() {
                    Some(value) => std::env::set_var(TEST_AUTH_RESULT_ENV, value),
                    None => std::env::remove_var(TEST_AUTH_RESULT_ENV),
                }
            }
        }
    }

    let _restore = RestoreTestAuth(std::env::var_os(TEST_AUTH_RESULT_ENV));
    unsafe {
        std::env::remove_var(TEST_AUTH_RESULT_ENV);
    }
    f()
}

fn write_managed_policy(dir: &Path, body: &str) {
    let policy_path = dir.join("managed-security-policy.toml");
    std::fs::write(policy_path, body).unwrap();
}

fn firewall_global_config(mode: &str) -> crate::commands::config::GlobalConfig {
    let mut firewall = toml::map::Map::new();
    firewall.insert(
        crate::npm_firewall_config::FIREWALL_CONFIG_MODE_KEY.to_string(),
        toml::Value::String(mode.to_string()),
    );
    let mut table = toml::map::Map::new();
    table.insert(
        crate::npm_firewall_config::FIREWALL_CONFIG_SECTION.to_string(),
        toml::Value::Table(firewall),
    );
    crate::commands::config::GlobalConfig::from_table(table)
}

fn firewall_policy_global_config(
    mode: &str,
    policies: &[(&str, &str)],
) -> crate::commands::config::GlobalConfig {
    let mut config = firewall_global_config(mode);
    let mut policy_table = toml::map::Map::new();
    for (key, action) in policies {
        policy_table.insert(
            (*key).to_string(),
            toml::Value::String((*action).to_string()),
        );
    }
    let mut npm = toml::map::Map::new();
    npm.insert(
        crate::npm_firewall_config::FIREWALL_NPM_POLICIES_CONFIG_SECTION.to_string(),
        toml::Value::Table(policy_table),
    );
    config
        .table_mut()
        .get_mut(crate::npm_firewall_config::FIREWALL_CONFIG_SECTION)
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .insert(
            crate::npm_firewall_config::FIREWALL_NPM_CONFIG_SECTION.to_string(),
            toml::Value::Table(npm),
        );
    config
}

fn approve_enforced_firewall(policies: &[(&str, &str)]) {
    persist_authorized_posture(&AuthorizedPosture {
        firewall_mode: crate::npm_firewall_config::NpmFirewallMode::Enforce
            .as_str()
            .to_string(),
        firewall_policies: policies
            .iter()
            .map(|(key, action)| ((*key).to_string(), (*action).to_string()))
            .collect(),
        ..AuthorizedPosture::default()
    })
    .unwrap();
}

#[test]
fn authorized_posture_round_trips_through_signed_store() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let posture = AuthorizedPosture {
            script_policy: "allow".into(),
            minimum_release_age_secs: 0,
            sandbox_mode: "none".into(),
            ..AuthorizedPosture::default()
        };
        persist_authorized_posture(&posture).unwrap();
        let loaded = load_authorized_posture().unwrap();
        assert_eq!(loaded.script_policy(), ScriptPolicy::Allow);
        assert_eq!(loaded.minimum_release_age_secs(), 0);
        assert_eq!(loaded.sandbox_mode(), ResolvedSandboxMode::None);
    });
}

#[test]
fn authorized_posture_disables_install_time_source_analysis_by_default() {
    assert!(!AuthorizedPosture::default().install_time_source_analysis());
}

#[test]
fn persistent_source_analysis_disable_is_signed_and_reenable_strengthens_without_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        authorize_persistent_install_time_source_analysis(
            false,
            false,
            "lpm config source-analysis --set false",
        )
        .unwrap();
        assert!(
            !load_authorized_posture()
                .unwrap()
                .install_time_source_analysis()
        );

        without_test_native_auth(|| {
            authorize_persistent_install_time_source_analysis(
                true,
                true,
                "lpm config source-analysis --set true",
            )
        })
        .unwrap();
        assert!(
            load_authorized_posture()
                .unwrap()
                .install_time_source_analysis()
        );
    });
}

#[test]
fn runtime_source_analysis_disable_requires_project_unlock_when_posture_is_enabled() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        persist_authorized_posture(&AuthorizedPosture {
            install_time_source_analysis: true,
            ..AuthorizedPosture::default()
        })
        .unwrap();
        let error = ensure_runtime_install_time_source_analysis_authorized(&project, true, false)
            .unwrap_err();

        assert_eq!(error.error_code(), "security_approval_required");
        assert!(matches!(
            error,
            LpmError::SecurityApprovalRequired(ref approval)
                if approval.requested_scopes == ["source-analysis-disable"]
        ));
    });
}

#[test]
fn managed_source_analysis_policy_blocks_persistent_disable() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(temp.path(), "install-time-source-analysis = true\n");

        let error = authorize_persistent_install_time_source_analysis(
            false,
            false,
            "lpm config source-analysis --set false",
        )
        .unwrap_err();

        assert_eq!(error.error_code(), "security_floor");
        assert!(error.to_string().contains("install-time-source-analysis"));
    });
}

#[test]
fn load_authorized_posture_does_not_create_secret_when_existing_file_cannot_verify() {
    let temp = tempdir().unwrap();
    with_file_secret_env(temp.path(), || {
        let path = approved_posture_path().unwrap();
        let posture = AuthorizedPosture::default();
        let envelope = SignedEnvelope {
            payload: posture,
            signature: "00".repeat(32),
        };
        std::fs::write(&path, serde_json::to_string_pretty(&envelope).unwrap()).unwrap();

        let err = load_authorized_posture().unwrap_err();

        assert_eq!(err.error_code(), "security_approval_store");
        assert!(
            err.to_string().contains("signature") || err.to_string().contains("signing secret"),
            "unexpected error: {err}",
        );
        assert!(
            !signing_secret_path().unwrap().exists(),
            "verification must not create a replacement signing secret",
        );
    });
}

#[test]
fn persist_authorized_posture_creates_secret_for_new_signed_state() {
    let temp = tempdir().unwrap();
    with_file_secret_env(temp.path(), || {
        assert!(!signing_secret_path().unwrap().exists());

        persist_authorized_posture(&AuthorizedPosture::default()).unwrap();

        assert!(
            signing_secret_path().unwrap().exists(),
            "signing new state must create the signing secret",
        );
        load_authorized_posture().unwrap();
    });
}

#[test]
fn repair_security_state_quarantines_existing_state_when_secret_is_missing() {
    let temp = tempdir().unwrap();
    with_file_secret_env(temp.path(), || {
        let path = approved_posture_path().unwrap();
        let posture = AuthorizedPosture::default();
        let envelope = SignedEnvelope {
            payload: posture,
            signature: "00".repeat(32),
        };
        std::fs::write(&path, serde_json::to_string_pretty(&envelope).unwrap()).unwrap();

        let report = repair_security_state().unwrap();

        assert_eq!(report.quarantined.len(), 1);
        assert_eq!(
            report.quarantined[0].original_path,
            path.display().to_string()
        );
        assert_eq!(report.quarantined[0].reason, "signing secret missing");
        assert!(!path.exists());
        assert!(Path::new(&report.quarantined[0].quarantine_path).exists());
        assert!(
            !signing_secret_path().unwrap().exists(),
            "repair must not create a replacement signing secret",
        );
    });
}

#[test]
fn repair_security_state_quarantines_audit_log_when_secret_is_missing() {
    let temp = tempdir().unwrap();
    with_file_secret_env(temp.path(), || {
        let path = audit_log_path().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{}\n").unwrap();

        let report = repair_security_state().unwrap();

        assert_eq!(report.quarantined.len(), 1);
        assert_eq!(
            report.quarantined[0].original_path,
            path.display().to_string()
        );
        assert_eq!(report.quarantined[0].reason, "signing secret missing");
        assert!(!path.exists());
        assert!(Path::new(&report.quarantined[0].quarantine_path).exists());
    });
}

#[test]
fn unlock_grant_round_trips_and_matches_project_scope() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    with_test_env(temp.path(), || {
        let grant = create_unlock_grant(
            ApprovalScope::SandboxNone,
            &project,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &[],
        );
        persist_unlock_grant(&grant).unwrap();
        assert!(
            has_active_project_unlock(ApprovalScope::SandboxNone, &project, None, &[]).unwrap()
        );
    });
}

#[test]
fn unlock_duration_formats_compact_units() {
    assert_eq!(format_unlock_duration(600), "10m");
    assert_eq!(format_unlock_duration(3_600), "1h");
    assert_eq!(format_unlock_duration(365 * 24 * 60 * 60), "365d");
    assert_eq!(format_unlock_duration(45), "45s");
}

#[test]
fn default_unlock_bundle_excludes_trust_capability_and_floor_scopes() {
    let scopes = ApprovalScope::default_unlock_scopes();
    assert!(scopes.contains(&ApprovalScope::CooldownBypass));
    assert!(scopes.contains(&ApprovalScope::SandboxNone));
    assert!(scopes.contains(&ApprovalScope::SourceAnalysisDisable));
    assert!(!scopes.contains(&ApprovalScope::TrustBulkApprove));
    assert!(!scopes.contains(&ApprovalScope::TrustScopeWiden));
    assert!(!scopes.contains(&ApprovalScope::CapabilityWiden));
    assert!(!scopes.contains(&ApprovalScope::FloorEdit));
}

#[test]
fn unlock_scopes_command_accepts_year_long_ttl() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        let grant = unlock_scopes_command(
            "default",
            ApprovalScope::default_unlock_scopes(),
            &project,
            MAX_UNLOCK_TTL_SECS,
            false,
            None,
            &[],
        )
        .unwrap();

        assert_eq!(grant.scopes, ApprovalScope::default_unlock_scopes());
        assert_eq!(
            (grant.expires_at - grant.issued_at).whole_seconds(),
            MAX_UNLOCK_TTL_SECS as i64
        );
    });
}

#[test]
fn lock_global_scopes_command_revokes_only_requested_scopes() {
    let temp = tempdir().unwrap();

    with_test_env(temp.path(), || {
        let grant = create_global_unlock_grant_for_scopes(
            &[
                ApprovalScope::CooldownBypass,
                ApprovalScope::TrustBulkApprove,
            ],
            DEFAULT_UNLOCK_TTL_SECS,
            &[],
        );
        persist_unlock_grant(&grant).unwrap();

        let revocations =
            lock_global_scopes_command("default", ApprovalScope::default_unlock_scopes(), &[])
                .unwrap();

        assert_eq!(revocations.len(), 1);
        assert_eq!(
            revocations[0].revoked_scopes,
            vec![ApprovalScope::CooldownBypass]
        );
        assert_eq!(
            revocations[0].remaining_scopes,
            vec![ApprovalScope::TrustBulkApprove]
        );

        let grants = list_active_global_unlocks().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, grant.id);
        assert_eq!(grants[0].scopes, vec![ApprovalScope::TrustBulkApprove]);
    });
}

#[test]
fn lock_project_scopes_command_matches_exact_package_sets() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        let grant = create_unlock_grant_for_scopes(
            &[ApprovalScope::ProvenanceUnverified],
            &project,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &["esbuild".to_string(), "sharp".to_string()],
        );
        persist_unlock_grant(&grant).unwrap();

        let revocations = lock_project_scopes_command(
            "provenance-unverified",
            &[ApprovalScope::ProvenanceUnverified],
            &project,
            &["esbuild".to_string()],
        )
        .unwrap();

        assert!(revocations.is_empty());
        assert!(
            has_active_project_unlock(
                ApprovalScope::ProvenanceUnverified,
                &project,
                None,
                &["esbuild".to_string(), "sharp".to_string()],
            )
            .unwrap()
        );
    });
}

#[test]
fn managed_policy_overrides_selected_floor_controls() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let posture = AuthorizedPosture {
            script_policy: "deny".into(),
            minimum_release_age_secs: DEFAULT_MIN_RELEASE_AGE_SECS,
            sandbox_mode: "default".into(),
            sandbox_allow_degraded: false,
            sigstore_verify: "deny".into(),
            ..AuthorizedPosture::default()
        };
        persist_authorized_posture(&posture).unwrap();
        write_managed_policy(
            temp.path(),
            r#"
script-policy = "allow"
minimum-release-age-secs = "0"

[policy]
name = "ci"
source = "test"
"#,
        );

        let effective = load_effective_authorized_posture().unwrap();
        assert_eq!(effective.posture.script_policy(), ScriptPolicy::Allow);
        assert_eq!(effective.posture.minimum_release_age_secs(), 0);
        assert_eq!(
            effective.sources.script_policy,
            PostureSourceKind::ManagedPolicy
        );
        assert_eq!(
            effective.sources.minimum_release_age_secs,
            PostureSourceKind::ManagedPolicy
        );
        assert_eq!(
            effective.sources.sandbox_mode,
            PostureSourceKind::ApprovedStore
        );
        assert_eq!(
            effective
                .managed_policy
                .as_ref()
                .and_then(|policy| policy.name.as_deref()),
            Some("ci")
        );
    });
}

#[test]
fn managed_policy_rejects_non_table_firewall_section() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
firewall = "enforce"

[policy]
name = "ci"
source = "test"
"#,
        );

        let err = load_effective_authorized_posture().unwrap_err();

        assert!(
            err.to_string()
                .contains("must set `[firewall]` to a TOML table"),
            "unexpected error: {err}"
        );
    });
}

#[test]
fn runtime_firewall_mode_uses_managed_policy_floor_when_config_is_absent() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"
"#,
        );
        let mode = crate::npm_firewall_config::resolve_runtime_firewall(
            &crate::commands::config::GlobalConfig::empty(),
            &project,
            true,
            crate::npm_firewall_config::BypassRuleScope::GlobalOnly,
        )
        .unwrap()
        .mode;

        assert_eq!(mode, crate::npm_firewall_config::NpmFirewallMode::Enforce);
    });
}

#[test]
fn runtime_firewall_mode_rejects_explicit_config_below_managed_policy_floor() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"
"#,
        );
        let err = crate::npm_firewall_config::resolve_runtime_firewall(
            &firewall_global_config("off"),
            &project,
            true,
            crate::npm_firewall_config::BypassRuleScope::GlobalOnly,
        )
        .unwrap_err();

        assert_eq!(err.error_code(), "security_floor");
    });
}

#[test]
fn managed_firewall_protection_enforces_floor_when_lpm_home_changes() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let report = install_managed_firewall_protection(
            crate::npm_firewall_config::NpmFirewallMode::Enforce,
        )
        .unwrap();

        assert_eq!(report.change, ManagedProtectionChange::Enabled);
        assert_eq!(report.status.firewall_mode.as_deref(), Some("enforce"));
        let alternate_home = temp.path().join("alternate-lpm-home");
        with_lpm_home(&alternate_home, || {
            let effective = load_effective_authorized_posture().unwrap();
            assert_eq!(
                effective.posture.firewall_mode(),
                crate::npm_firewall_config::NpmFirewallMode::Enforce
            );
            assert_eq!(
                effective.sources.firewall_mode,
                PostureSourceKind::ManagedPolicy
            );
        });
    });
}

#[test]
fn managed_firewall_protection_enable_preserves_other_managed_controls() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
script-policy = "deny"
"#,
        );

        let report = install_managed_firewall_protection(
            crate::npm_firewall_config::NpmFirewallMode::Monitor,
        )
        .unwrap();

        assert_eq!(report.change, ManagedProtectionChange::Enabled);
        let effective = load_effective_authorized_posture().unwrap();
        assert_eq!(effective.posture.script_policy(), ScriptPolicy::Deny);
        assert_eq!(
            effective.sources.script_policy,
            PostureSourceKind::ManagedPolicy
        );
        assert_eq!(
            effective.posture.firewall_mode(),
            crate::npm_firewall_config::NpmFirewallMode::Monitor
        );
        assert_eq!(
            effective.sources.firewall_mode,
            PostureSourceKind::ManagedPolicy
        );
    });
}

#[test]
fn managed_firewall_protection_disable_preserves_other_managed_controls() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
script-policy = "deny"

[firewall]
mode = "enforce"
"#,
        );

        let report = remove_managed_firewall_protection().unwrap();

        assert_eq!(report.change, ManagedProtectionChange::Disabled);
        assert!(!report.status.active);
        let effective = load_effective_authorized_posture().unwrap();
        assert_eq!(effective.posture.script_policy(), ScriptPolicy::Deny);
        assert_eq!(
            effective.sources.script_policy,
            PostureSourceKind::ManagedPolicy
        );
        assert_eq!(
            effective.sources.firewall_mode,
            PostureSourceKind::BuiltinDefault
        );
    });
}

#[test]
fn managed_firewall_protection_disable_refuses_while_the_policy_sets_a_firewall_profile() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"

[firewall.npm.policies]
lpm_ai_agent_control_surface = "block"
"#,
        );

        let err = remove_managed_firewall_protection().unwrap_err();

        assert!(err.to_string().contains("[firewall.npm.policies]"), "{err}");
        let effective = load_effective_authorized_posture().unwrap();
        assert_eq!(
            effective.sources.firewall_mode,
            PostureSourceKind::ManagedPolicy
        );
    });
}

#[test]
fn security_status_does_not_report_absent_firewall_config_as_runtime_override() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"
"#,
        );
        let status = load_security_status(Some(&project), false).unwrap();

        assert!(status.active_runtime_overrides.is_empty());
    });
}

#[test]
fn persistent_weakening_rejects_when_managed_policy_owns_that_floor() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
script-policy = "deny"
"#,
        );

        let err = authorize_persistent_script_policy(
            ScriptPolicy::Allow,
            true,
            "lpm config scripts --set allow",
        )
        .unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
        assert!(err.to_string().contains("managed security policy"));
    });
}

#[test]
fn persistent_strict_sigstore_write_from_builtin_default_skips_signed_store() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let posture_path = approved_posture_path().unwrap();
        assert!(!posture_path.exists());

        authorize_persistent_sigstore(EnforceMode::Deny, true, "lpm config sigstore --set deny")
            .unwrap();

        assert!(
            !posture_path.exists(),
            "strict/equal writes from the builtin floor must not require native secure storage",
        );
    });
}

#[test]
fn persistent_strict_sigstore_write_revokes_existing_weaker_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let posture = AuthorizedPosture {
            sigstore_verify: "off".into(),
            ..AuthorizedPosture::default()
        };
        persist_authorized_posture(&posture).unwrap();

        authorize_persistent_sigstore(EnforceMode::Deny, true, "lpm config sigstore --set deny")
            .unwrap();

        let loaded = load_authorized_posture().unwrap();
        assert_eq!(loaded.sigstore_verify(), EnforceMode::Deny);
    });
}

#[test]
fn persistent_default_release_age_from_builtin_default_skips_signed_store() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let posture_path = approved_posture_path().unwrap();
        assert!(!posture_path.exists());

        authorize_persistent_release_age(
            DEFAULT_MIN_RELEASE_AGE_SECS,
            true,
            "lpm config release-age --set default",
        )
        .unwrap();

        assert!(
            !posture_path.exists(),
            "default release-age writes must not create a signed posture record",
        );
    });
}

#[test]
fn security_status_filters_unlocks_to_the_requested_project() {
    let temp = tempdir().unwrap();
    let project_a = temp.path().join("project-a");
    let project_b = temp.path().join("project-b");
    std::fs::create_dir_all(&project_a).unwrap();
    std::fs::create_dir_all(&project_b).unwrap();
    with_test_env(temp.path(), || {
        persist_unlock_grant(&create_unlock_grant(
            ApprovalScope::SandboxNone,
            &project_a,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &[],
        ))
        .unwrap();
        persist_unlock_grant(&create_unlock_grant(
            ApprovalScope::CooldownBypass,
            &project_b,
            DEFAULT_UNLOCK_TTL_SECS,
            Some(0),
            &[],
        ))
        .unwrap();

        let status = load_security_status(Some(&project_a), false).unwrap();
        let expected_root = canonical_project_root(&project_a);
        assert_eq!(status.target, UnlockTargetKind::Project);
        assert_eq!(status.project_root.as_deref(), Some(expected_root.as_str()));
        assert_eq!(status.active_unlocks.len(), 1);
        assert_eq!(
            status.active_unlocks[0].scopes,
            vec![ApprovalScope::SandboxNone]
        );
    });
}

#[test]
fn automation_mode_includes_json() {
    let automation = {
        let _env = crate::test_env::ScopedEnv::update([(TEST_AUTH_RESULT_ENV, None)]);
        is_automation(true)
    };
    assert!(automation);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_local_auth_reason_formats_prompt_as_action_phrase() {
    assert_eq!(
        super::native_auth::macos_local_auth_reason(
            "Approve cooldown-bypass for this project for 10m?"
        ),
        "approve cooldown-bypass for this project for 10m"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_local_auth_reason_uses_default_when_prompt_is_empty() {
    assert_eq!(
        super::native_auth::macos_local_auth_reason(" ? "),
        "approve this LPM security action"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_local_auth_allows_biometrics_or_password() {
    assert_eq!(
        super::native_auth::macos_local_auth_policy(),
        objc2_local_authentication::LAPolicy::DeviceOwnerAuthentication
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_local_auth_uses_default_password_fallback_title() {
    assert_eq!(super::native_auth::macos_local_auth_fallback_title(), None);
}

#[test]
fn windows_hello_availability_uses_native_prompt_when_available() {
    assert_eq!(
        super::native_auth::windows_hello_availability_action(0),
        super::native_auth::WindowsHelloAvailabilityAction::UseWindowsHello
    );
}

#[test]
fn windows_hello_availability_fails_closed_when_pin_is_not_configured() {
    assert_eq!(
        super::native_auth::windows_hello_availability_action(2),
        super::native_auth::WindowsHelloAvailabilityAction::FailClosed(
            "Windows Hello or PIN is not configured for this user"
        )
    );
}

#[test]
fn windows_hello_availability_fails_closed_when_policy_disables_verification() {
    assert_eq!(
        super::native_auth::windows_hello_availability_action(3),
        super::native_auth::WindowsHelloAvailabilityAction::FailClosed(
            "Windows Hello or PIN verification is disabled by policy"
        )
    );
}

#[test]
fn windows_hello_verification_approves_when_user_is_verified() {
    assert_eq!(
        super::native_auth::windows_hello_verification_action(0),
        super::native_auth::WindowsHelloVerificationAction::Approved
    );
}

#[test]
fn windows_hello_verification_denies_when_user_cancels() {
    assert_eq!(
        super::native_auth::windows_hello_verification_action(6),
        super::native_auth::WindowsHelloVerificationAction::Denied
    );
}

#[test]
fn project_trust_widening_requires_approval_at_runtime() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "lpm": {
    "trustedDependencies": {
      "esbuild@0.25.1": {
        "integrity": "sha512-demo",
        "scriptHash": "sha256-demo"
      }
    }
  }
}"#,
    )
    .unwrap();

    with_test_env(temp.path(), || {
        let err = ensure_project_policy_authorized(&project, true, ApprovalSource::ProjectConfig)
            .unwrap_err();
        assert_eq!(err.error_code(), "security_approval_required");
        assert!(
            err.to_string()
                .contains("project trust or capability state changed")
        );
    });
}

#[test]
fn project_trusted_scope_widening_requires_approval_at_runtime() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "lpm": {
    "scripts": {
      "trustedScopes": ["@myorg/*"]
    }
  }
}"#,
    )
    .unwrap();

    with_test_env(temp.path(), || {
        let err = ensure_project_policy_authorized(&project, true, ApprovalSource::ProjectConfig)
            .unwrap_err();
        assert_eq!(err.error_code(), "security_approval_required");
        assert!(
            err.to_string()
                .contains("project trust or capability state changed")
        );
    });
}

#[test]
fn project_capability_widening_requires_approval_at_runtime() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "lpm": {
    "scripts": {
      "readProject": "full",
      "passEnv": ["SSH_AUTH_SOCK"]
    }
  }
}"#,
    )
    .unwrap();

    with_test_env(temp.path(), || {
        let err = ensure_project_policy_authorized(&project, true, ApprovalSource::ProjectConfig)
            .unwrap_err();
        assert_eq!(err.error_code(), "security_approval_required");
        assert!(
            err.to_string()
                .contains("project trust or capability state changed")
        );
    });
}

#[test]
fn blocked_runtime_attempt_is_written_to_audit_log() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "lpm": {
    "scripts": {
      "trustedScopes": ["@myorg/*"]
    }
  }
}"#,
    )
    .unwrap();

    with_test_env(temp.path(), || {
        let err = ensure_project_policy_authorized(&project, true, ApprovalSource::ProjectConfig)
            .unwrap_err();
        assert_eq!(err.error_code(), "security_approval_required");

        let audit_path = audit_log_path().unwrap();
        let content = std::fs::read_to_string(audit_path).unwrap();
        let envelope: SignedAuditEnvelope = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(envelope.payload.event, "guarded-attempt");
        assert!(
            envelope
                .payload
                .scopes
                .iter()
                .any(|scope| scope == "trust-scope-widen")
        );
        // Compared parsed: JSON escapes the backslashes of a Windows path.
        assert_eq!(
            envelope.payload.project_root.as_deref(),
            Some(canonical_project_root(&project).as_str())
        );
    });
}

#[test]
fn cli_trust_authorization_persists_candidate_state() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"demo","version":"1.0.0"}"#,
    )
    .unwrap();

    with_test_env(temp.path(), || {
        let mut bindings = std::collections::HashMap::new();
        bindings.insert(
            "esbuild@0.25.1".to_string(),
            lpm_workspace::TrustedDependencyBinding {
                integrity: Some("sha512-demo".to_string()),
                script_hash: Some("sha256-demo".to_string()),
                ..Default::default()
            },
        );
        let trusted = lpm_workspace::TrustedDependencies::Rich(bindings);
        ensure_project_trust_candidate_authorized(
            &project,
            &trusted,
            false,
            ApprovalSource::CliFlag,
        )
        .unwrap();

        let approved = load_approved_project_policy_state(&project).unwrap();
        assert!(approved.trusted_dependencies.contains_key("esbuild@0.25.1"));
    });
}

#[test]
fn managed_approval_flow_persists_project_trust_without_unlock() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"demo","version":"1.0.0"}"#,
    )
    .unwrap();

    with_test_env(temp.path(), || {
        let mut bindings = std::collections::HashMap::new();
        bindings.insert(
            "esbuild@0.25.1".to_string(),
            lpm_workspace::TrustedDependencyBinding {
                integrity: Some("sha512-demo".to_string()),
                script_hash: Some("sha256-demo".to_string()),
                ..Default::default()
            },
        );
        let trusted = lpm_workspace::TrustedDependencies::Rich(bindings);

        record_project_trust_candidate_authorized_from_managed_flow(
            &project,
            &trusted,
            ApprovalSource::ApproveScripts,
        )
        .unwrap();

        let approved = load_approved_project_policy_state(&project).unwrap();
        assert!(approved.trusted_dependencies.contains_key("esbuild@0.25.1"));
        assert!(
            !read_active_unlocks()
                .unwrap()
                .iter()
                .any(|grant| { grant.scopes.contains(&ApprovalScope::TrustBulkApprove) })
        );
    });
}

#[test]
fn package_scoped_unlock_only_matches_granted_packages() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        let grant = create_unlock_grant(
            ApprovalScope::ProvenanceUnverified,
            &project,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &["esbuild".to_string()],
        );
        persist_unlock_grant(&grant).unwrap();
        assert!(
            has_active_project_unlock(
                ApprovalScope::ProvenanceUnverified,
                &project,
                None,
                &["esbuild".to_string()],
            )
            .unwrap()
        );
        assert!(
            !has_active_project_unlock(
                ApprovalScope::ProvenanceUnverified,
                &project,
                None,
                &["sharp".to_string()],
            )
            .unwrap()
        );
        assert!(
            !has_active_project_unlock(ApprovalScope::ProvenanceUnverified, &project, None, &[],)
                .unwrap()
        );
    });
}

#[test]
fn security_status_reports_runtime_sigstore_env_override() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        let original = std::env::var_os("LPM_PROVENANCE_ENFORCE");
        unsafe {
            std::env::set_var("LPM_PROVENANCE_ENFORCE", "warn");
        }
        let status = load_security_status(Some(&project), false).unwrap();
        assert_eq!(status.active_runtime_overrides.len(), 1);
        assert_eq!(
            status.active_runtime_overrides[0].control,
            "sigstore.verify"
        );
        assert_eq!(status.active_runtime_overrides[0].value, "warn");
        match original {
            Some(value) => unsafe { std::env::set_var("LPM_PROVENANCE_ENFORCE", value) },
            None => unsafe { std::env::remove_var("LPM_PROVENANCE_ENFORCE") },
        }
    });
}

#[test]
fn global_status_only_lists_global_unlocks() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        persist_unlock_grant(&create_unlock_grant(
            ApprovalScope::SandboxNone,
            &project,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &[],
        ))
        .unwrap();
        persist_unlock_grant(&create_global_unlock_grant(
            ApprovalScope::TrustBulkApprove,
            DEFAULT_UNLOCK_TTL_SECS,
            &[],
        ))
        .unwrap();

        let status = load_security_status(None, true).unwrap();
        assert_eq!(status.target, UnlockTargetKind::Global);
        assert_eq!(status.active_unlocks.len(), 1);
        assert_eq!(status.active_unlocks[0].target, UnlockTargetKind::Global);
    });
}

#[test]
fn runtime_sigstore_config_downgrade_requires_project_unlock() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        let err = ensure_runtime_sigstore_posture(
            &project,
            true,
            EnforceMode::Warn,
            crate::provenance_fetch::EnforceModeSource::Config,
        )
        .unwrap_err();
        assert_eq!(err.error_code(), "security_approval_required");
        assert!(err.to_string().contains("provenance-unverified"));
    });
}

#[test]
fn runtime_sigstore_config_downgrade_uses_active_project_unlock() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        let grant = create_unlock_grant(
            ApprovalScope::ProvenanceUnverified,
            &project,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &[],
        );
        persist_unlock_grant(&grant).unwrap();
        ensure_runtime_sigstore_posture(
            &project,
            true,
            EnforceMode::Warn,
            crate::provenance_fetch::EnforceModeSource::Config,
        )
        .unwrap();
    });
}

#[test]
fn runtime_firewall_config_downgrade_requires_project_unlock() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        persist_authorized_posture(&AuthorizedPosture {
            firewall_mode: crate::npm_firewall_config::NpmFirewallMode::Enforce
                .as_str()
                .to_string(),
            ..AuthorizedPosture::default()
        })
        .unwrap();

        let err = ensure_runtime_npm_firewall_config_authorized(
            &project,
            true,
            crate::npm_firewall_config::NpmFirewallMode::Off,
        )
        .unwrap_err();

        assert_eq!(err.error_code(), "security_approval_required");
        assert!(matches!(
            err,
            LpmError::SecurityApprovalRequired(ref approval)
                if approval.requested_scopes == ["firewall-disable"]
        ));
    });
}

#[test]
fn runtime_firewall_config_downgrade_uses_active_project_unlock() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        persist_authorized_posture(&AuthorizedPosture {
            firewall_mode: crate::npm_firewall_config::NpmFirewallMode::Enforce
                .as_str()
                .to_string(),
            ..AuthorizedPosture::default()
        })
        .unwrap();
        persist_unlock_grant(&create_unlock_grant(
            ApprovalScope::FirewallDisable,
            &project,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &[],
        ))
        .unwrap();

        ensure_runtime_npm_firewall_config_authorized(
            &project,
            true,
            crate::npm_firewall_config::NpmFirewallMode::Off,
        )
        .unwrap();
    });
}

#[test]
fn runtime_firewall_env_downgrade_records_env_source() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        persist_authorized_posture(&AuthorizedPosture {
            firewall_mode: crate::npm_firewall_config::NpmFirewallMode::Enforce
                .as_str()
                .to_string(),
            ..AuthorizedPosture::default()
        })
        .unwrap();
        let effective = load_effective_authorized_posture().unwrap();

        let err = without_test_native_auth(|| {
            ensure_runtime_npm_firewall_config_authorized_with_effective(
                &effective,
                &project,
                true,
                Some(
                    crate::npm_firewall_config::NpmFirewallModeRequest::from_env(
                        crate::npm_firewall_config::NpmFirewallMode::Off,
                    ),
                ),
                None,
            )
        })
        .unwrap_err();

        assert_eq!(err.error_code(), "security_approval_required");
        let content = std::fs::read_to_string(audit_log_path().unwrap()).unwrap();
        let envelope: SignedAuditEnvelope = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(envelope.payload.source.as_deref(), Some("env-var"));
        assert_eq!(
            envelope.payload.detail.as_deref(),
            Some(
                "The environment npm firewall setting weakens npm firewall checks for this project."
            )
        );
    });
}

#[test]
fn runtime_cli_approval_does_not_persist_signed_unlock_state() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_file_secret_env(temp.path(), || {
        approve_project_runtime_override(
            ApprovalScope::CooldownBypass,
            &project,
            false,
            ApprovalSource::CliFlag,
            "This install bypasses the minimum release age for this project.",
            &[],
        )
        .unwrap();

        assert!(!signing_secret_path().unwrap().exists());
        assert!(!audit_head_path().unwrap().exists());
        assert!(!audit_log_path().unwrap().exists());
        assert!(!unlocks_dir().unwrap().exists());
    });
}

#[test]
fn runtime_cli_approval_respects_managed_policy_without_signed_state() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_file_secret_env(temp.path(), || {
        write_managed_policy(temp.path(), "minimum-release-age-secs = 86400\n");

        let err = approve_project_runtime_override(
            ApprovalScope::CooldownBypass,
            &project,
            false,
            ApprovalSource::CliFlag,
            "This install bypasses the minimum release age for this project.",
            &[],
        )
        .unwrap_err();

        assert_eq!(err.error_code(), "security_floor");
        assert!(!signing_secret_path().unwrap().exists());
    });
}

#[test]
fn runtime_cli_approval_for_global_install_suggests_global_unlock() {
    let temp = tempdir().unwrap();

    with_file_secret_env(temp.path(), || {
        let lpm_home = temp.path().join("lpm-home");
        with_lpm_home(&lpm_home, || {
            without_test_native_auth(|| {
                let project = lpm_common::LpmRoot::from_env()
                    .unwrap()
                    .global_installs()
                    .join("fresh-tool");
                std::fs::create_dir_all(&project).unwrap();

                let err = approve_project_runtime_override(
                    ApprovalScope::CooldownBypass,
                    &project,
                    true,
                    ApprovalSource::CliFlag,
                    "This install bypasses the minimum release age for this project.",
                    &[],
                )
                .unwrap_err();

                match err {
                    LpmError::SecurityApprovalRequired(approval) => {
                        assert_eq!(approval.project_root, None);
                        assert_eq!(
                            approval.suggested_command.as_deref(),
                            Some("lpm security unlock cooldown-bypass --global --ttl 10m")
                        );
                    }
                    other => panic!("expected security approval error, got {other:?}"),
                }
                assert!(!signing_secret_path().unwrap().exists());
            });
        });
    });
}

#[test]
fn persistent_automation_refusal_is_written_to_audit_log() {
    let temp = tempdir().unwrap();

    with_test_env(temp.path(), || {
        let original_auth = std::env::var_os(TEST_AUTH_RESULT_ENV);
        unsafe {
            std::env::remove_var(TEST_AUTH_RESULT_ENV);
        }
        let err = authorize_persistent_script_policy(
            ScriptPolicy::Allow,
            true,
            "lpm config scripts --set allow",
        )
        .unwrap_err();
        match original_auth {
            Some(value) => unsafe { std::env::set_var(TEST_AUTH_RESULT_ENV, value) },
            None => unsafe { std::env::remove_var(TEST_AUTH_RESULT_ENV) },
        }
        assert_eq!(err.error_code(), "security_approval_required");

        let content = std::fs::read_to_string(audit_log_path().unwrap()).unwrap();
        assert!(content.contains("\"event\":\"persistent-guarded-attempt\""));
        assert!(content.contains("\"allowed\":false"));
        assert!(content.contains("scripts-allow"));
    });
}

#[test]
fn audit_log_truncation_is_detected_by_signed_head() {
    let temp = tempdir().unwrap();

    with_test_env(temp.path(), || {
        let event = AuditEvent {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            occurred_at: Timestamp::now(),
            event: "guarded-attempt".into(),
            allowed: false,
            scopes: vec![ApprovalScope::SandboxNone.as_str().to_string()],
            project_root: None,
            packages: Vec::new(),
            source: Some(ApprovalSource::CliFlag.as_str().to_string()),
            unlock_id: None,
            detail: Some("test".into()),
        };
        append_audit_event(&event).unwrap();
        std::fs::write(audit_log_path().unwrap(), "").unwrap();

        let err = append_audit_event(&event).unwrap_err();
        assert!(err.to_string().contains("signed audit head"));
    });
}

#[test]
fn audit_event_persists_signed_audit_head_file() {
    let temp = tempdir().unwrap();

    with_test_env(temp.path(), || {
        let event = AuditEvent {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            occurred_at: Timestamp::now(),
            event: "unlock-granted".into(),
            allowed: true,
            scopes: vec![ApprovalScope::CooldownBypass.as_str().to_string()],
            project_root: None,
            packages: Vec::new(),
            source: Some(ApprovalSource::CliFlag.as_str().to_string()),
            unlock_id: Some("unl_test".into()),
            detail: Some("test".into()),
        };

        append_audit_event(&event).unwrap();

        let head = read_signed_json::<AuditHead>(&audit_head_path().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(head.entry_count, 1);
    });
}

#[test]
fn audit_log_concurrent_appends_preserve_jsonl_and_hash_chain() {
    let temp = tempdir().unwrap();

    with_test_env(temp.path(), || {
        const WRITERS: usize = 32;
        let start = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
        let mut handles = Vec::with_capacity(WRITERS);

        for index in 0..WRITERS {
            let start = std::sync::Arc::clone(&start);
            handles.push(std::thread::spawn(move || {
                let event = AuditEvent {
                    schema_version: AUDIT_EVENT_SCHEMA_VERSION,
                    occurred_at: Timestamp::now(),
                    event: "guarded-attempt".into(),
                    allowed: false,
                    scopes: vec![ApprovalScope::CooldownBypass.as_str().to_string()],
                    project_root: None,
                    packages: Vec::new(),
                    source: Some(ApprovalSource::CliFlag.as_str().to_string()),
                    unlock_id: None,
                    detail: Some(format!("concurrent append {index}")),
                };
                start.wait();
                append_audit_event(&event)
            }));
        }

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        let log_path = audit_log_path().unwrap();
        let (_tail, count) = read_audit_log_tail(&log_path).unwrap();
        assert_eq!(count, WRITERS as u64);
    });
}

#[test]
fn audit_log_appends_after_unsigned_legacy_entries() {
    let temp = tempdir().unwrap();

    with_test_env(temp.path(), || {
        let event = AuditEvent {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            occurred_at: Timestamp::now(),
            event: "guarded-attempt".into(),
            allowed: false,
            scopes: vec![ApprovalScope::TrustBulkApprove.as_str().to_string()],
            project_root: None,
            packages: Vec::new(),
            source: Some(ApprovalSource::CliFlag.as_str().to_string()),
            unlock_id: None,
            detail: Some("legacy unsigned".into()),
        };
        let log_path = audit_log_path().unwrap();
        std::fs::write(
            &log_path,
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();

        append_audit_event(&event).unwrap();

        let (tail, count) = read_audit_log_tail(&log_path).unwrap();
        assert!(tail.is_some());
        assert_eq!(count, 2);
    });
}

#[test]
fn audit_log_appends_after_legacy_signed_entries() {
    let temp = tempdir().unwrap();

    with_test_env(temp.path(), || {
        let event = AuditEvent {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            occurred_at: Timestamp::now(),
            event: "guarded-attempt".into(),
            allowed: false,
            scopes: vec![ApprovalScope::SandboxNone.as_str().to_string()],
            project_root: None,
            packages: Vec::new(),
            source: Some(ApprovalSource::CliFlag.as_str().to_string()),
            unlock_id: None,
            detail: Some("legacy".into()),
        };
        let payload = serde_json::to_value(&event).unwrap();
        let legacy = SignedEnvelope {
            payload: event.clone(),
            signature: sign_payload_value(&payload).unwrap(),
        };
        let legacy_value = serde_json::to_value(&legacy).unwrap();
        let legacy_hash = hash_json_value(&legacy_value).unwrap();
        let log_path = audit_log_path().unwrap();
        std::fs::write(
            &log_path,
            format!("{}\n", serde_json::to_string(&legacy).unwrap()),
        )
        .unwrap();

        append_audit_event(&event).unwrap();

        let (tail, count) = read_audit_log_tail(&log_path).unwrap();
        assert!(tail.is_some());
        assert_eq!(count, 2);
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains(&legacy_hash));
    });
}

#[test]
fn unavailable_windows_hello_never_approves_through_terminal_confirmation() {
    for code in [1, 2] {
        assert!(matches!(
            super::native_auth::windows_hello_availability_action(code),
            super::native_auth::WindowsHelloAvailabilityAction::FailClosed(_)
        ));
        assert!(matches!(
            super::native_auth::windows_hello_verification_action(code),
            super::native_auth::WindowsHelloVerificationAction::FailClosed(_)
        ));
    }
}

#[test]
fn diagnostic_sigstore_posture_honors_unlocks_and_managed_policy_without_mutation() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    with_test_env(temp.path(), || {
        assert!(check_runtime_sigstore_posture(&project, EnforceMode::Off).is_err());
        assert!(!super::paths::unlocks_lock_path().unwrap().exists());
        assert!(!audit_log_path().unwrap().exists());
        let mut expired = create_unlock_grant(
            ApprovalScope::ProvenanceUnverified,
            &project,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &[],
        );
        expired.expires_at = Timestamp::now() - lpm_common::timestamp::Duration::seconds(1);
        persist_unlock_grant(&expired).unwrap();
        let expired_path = unlocks_dir().unwrap().join(format!("{}.json", expired.id));
        assert!(check_runtime_sigstore_posture(&project, EnforceMode::Off).is_err());
        assert!(
            expired_path.exists(),
            "diagnostics must retain expired grants"
        );
        let active = create_unlock_grant(
            ApprovalScope::ProvenanceUnverified,
            &project,
            DEFAULT_UNLOCK_TTL_SECS,
            None,
            &[],
        );
        persist_unlock_grant(&active).unwrap();
        assert!(check_runtime_sigstore_posture(&project, EnforceMode::Off).is_ok());
        write_managed_policy(temp.path(), "[sigstore]\nverify = \"deny\"\n");
        let error = check_runtime_sigstore_posture(&project, EnforceMode::Off).unwrap_err();
        assert!(
            error.to_string().contains("managed security policy"),
            "{error}"
        );
        assert!(expired_path.exists());
        assert!(!audit_log_path().unwrap().exists());
    });
}

fn with_test_native_auth_result<T>(result: &str, f: impl FnOnce() -> T) -> T {
    struct RestoreTestAuth(Option<std::ffi::OsString>);

    impl Drop for RestoreTestAuth {
        fn drop(&mut self) {
            unsafe {
                match self.0.as_ref() {
                    Some(value) => std::env::set_var(TEST_AUTH_RESULT_ENV, value),
                    None => std::env::remove_var(TEST_AUTH_RESULT_ENV),
                }
            }
        }
    }

    let _restore = RestoreTestAuth(std::env::var_os(TEST_AUTH_RESULT_ENV));
    unsafe {
        std::env::set_var(TEST_AUTH_RESULT_ENV, result);
    }
    f()
}

fn resolve_firewall(
    config: &crate::commands::config::GlobalConfig,
    project: &Path,
) -> Result<crate::npm_firewall_config::RuntimeFirewall, LpmError> {
    crate::npm_firewall_config::resolve_runtime_firewall(
        config,
        project,
        true,
        crate::npm_firewall_config::BypassRuleScope::GlobalOnly,
    )
}

#[test]
fn runtime_firewall_requires_approval_for_config_policy_that_allows_approved_blocks() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let config = firewall_policy_global_config(
            "enforce",
            &[(
                crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
                "allow",
            )],
        );

        let err = without_test_native_auth(|| resolve_firewall(&config, &project)).unwrap_err();

        let LpmError::SecurityApprovalRequired(context) = &err else {
            panic!("expected an approval error, got {err}");
        };
        assert!(
            context
                .message
                .contains("lpm_ai_confirmed_malware = allow (approved: block)"),
            "{}",
            context.message
        );
        assert_eq!(
            context.suggested_command.as_deref(),
            Some("lpm config firewall")
        );
        assert_eq!(
            context.requested_scopes,
            vec!["firewall-disable".to_string()]
        );
    });
}

#[test]
fn runtime_firewall_uses_config_policy_the_signed_posture_approved() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[(
            crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
            "allow",
        )]);
        let config = firewall_policy_global_config(
            "enforce",
            &[(
                crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
                "allow",
            )],
        );

        let firewall = without_test_native_auth(|| resolve_firewall(&config, &project)).unwrap();

        assert_eq!(
            firewall.policy_profile.lpm_ai_confirmed_malware,
            lpm_registry::client::NpmFirewallPolicyAction::Allow
        );
    });
}

#[test]
fn runtime_firewall_accepts_stricter_config_policy_without_approval() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let config = firewall_policy_global_config(
            "enforce",
            &[(
                crate::npm_firewall_config::LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY,
                "block",
            )],
        );

        let firewall = without_test_native_auth(|| resolve_firewall(&config, &project)).unwrap();

        assert_eq!(
            firewall.policy_profile.lpm_ai_agent_control_surface,
            lpm_registry::client::NpmFirewallPolicyAction::Block
        );
    });
}

#[test]
fn runtime_firewall_policy_needs_no_approval_where_the_approved_firewall_is_off() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        let config = firewall_policy_global_config(
            "enforce",
            &[(
                crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
                "allow",
            )],
        );

        let firewall = without_test_native_auth(|| resolve_firewall(&config, &project)).unwrap();

        assert_eq!(
            firewall.mode,
            crate::npm_firewall_config::NpmFirewallMode::Enforce
        );
        assert_eq!(
            firewall.policy_profile.lpm_ai_confirmed_malware,
            lpm_registry::client::NpmFirewallPolicyAction::Allow
        );
    });
}

#[test]
fn runtime_firewall_uses_approved_policies_when_config_has_no_policy_table() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[(
            crate::npm_firewall_config::CRITICAL_VULNERABILITY_POLICY_KEY,
            "block",
        )]);

        let firewall = resolve_firewall(&firewall_global_config("enforce"), &project).unwrap();

        assert_eq!(
            firewall.policy_profile.critical_vulnerability,
            lpm_registry::client::NpmFirewallPolicyAction::Block
        );
    });
}

#[test]
fn runtime_firewall_refuses_policy_loosening_under_managed_firewall_mode() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"
"#,
        );
        let config = firewall_policy_global_config(
            "enforce",
            &[(
                crate::npm_firewall_config::TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY,
                "warn",
            )],
        );

        let err = resolve_firewall(&config, &project).unwrap_err();

        assert_eq!(err.error_code(), "security_floor");
        assert!(err.to_string().contains("[firewall.npm.policies]"), "{err}");
    });
}

#[test]
fn managed_policy_firewall_policies_set_the_effective_profile() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"

[firewall.npm.policies]
lpm_ai_agent_control_surface = "block"
"#,
        );

        let effective = load_effective_authorized_posture().unwrap();

        assert_eq!(
            effective
                .posture
                .firewall_policy_profile()
                .lpm_ai_agent_control_surface,
            lpm_registry::client::NpmFirewallPolicyAction::Block
        );
        assert_eq!(
            effective.sources.firewall_policies,
            PostureSourceKind::ManagedPolicy
        );
        assert!(
            effective
                .managed_policy
                .unwrap()
                .enforced_controls
                .contains(&"firewall.npm.policies".to_string())
        );
    });
}

#[test]
fn managed_policy_rejects_firewall_policies_without_a_firewall_mode() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall.npm.policies]
lpm_ai_agent_control_surface = "block"
"#,
        );

        let err = load_effective_authorized_posture().unwrap_err();

        assert!(
            err.to_string()
                .contains("must set `[firewall].mode` when it sets `[firewall.npm.policies]`"),
            "{err}"
        );
    });
}

#[test]
fn managed_policy_rejects_invalid_firewall_policy_action() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"

[firewall.npm.policies]
lpm_ai_confirmed_malware = "ignore"
"#,
        );

        let err = load_effective_authorized_posture().unwrap_err();

        assert!(
            err.to_string().contains(
                "invalid `[firewall.npm.policies].lpm_ai_confirmed_malware` value `ignore`"
            ),
            "{err}"
        );
    });
}

#[test]
fn persistent_firewall_policy_loosening_is_signed_after_native_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_confirmed_malware: lpm_registry::client::NpmFirewallPolicyAction::Allow,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        with_test_native_auth_result("approve", || {
            authorize_persistent_npm_firewall_policies(&requested, false, "lpm config firewall")
        })
        .unwrap();

        let posture = load_authorized_posture().unwrap();
        assert_eq!(posture.firewall_policy_profile(), requested);
        assert_eq!(
            posture.firewall_mode(),
            crate::npm_firewall_config::NpmFirewallMode::Enforce
        );
    });
}

#[test]
fn persistent_firewall_policy_loosening_is_refused_when_native_approval_is_denied() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_dependency_script_policy: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let err = with_test_native_auth_result("deny", || {
            authorize_persistent_npm_firewall_policies(&requested, false, "lpm config firewall")
        })
        .unwrap_err();

        assert_eq!(err.error_code(), "security_approval_required");
        assert_eq!(
            load_authorized_posture().unwrap().firewall_policy_profile(),
            lpm_registry::client::NpmFirewallPolicyProfile::default()
        );
    });
}

#[test]
fn persistent_firewall_policy_tightening_needs_no_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_telemetry: lpm_registry::client::NpmFirewallPolicyAction::Block,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        without_test_native_auth(|| {
            authorize_persistent_npm_firewall_policies(&requested, true, "lpm config firewall")
        })
        .unwrap();

        assert_eq!(
            load_authorized_posture().unwrap().firewall_policy_profile(),
            requested
        );
    });
}

#[test]
fn persistent_firewall_policy_loosening_is_refused_under_managed_firewall_mode() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"
"#,
        );
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_confirmed_malware: lpm_registry::client::NpmFirewallPolicyAction::Allow,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let err = with_test_native_auth_result("approve", || {
            authorize_persistent_npm_firewall_policies(&requested, false, "lpm config firewall")
        })
        .unwrap_err();

        assert_eq!(err.error_code(), "security_floor");
        assert!(
            err.to_string()
                .contains("[firewall.npm.policies].lpm_ai_confirmed_malware"),
            "{err}"
        );
    });
}

#[test]
fn security_status_reports_config_policy_that_differs_from_the_effective_profile() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let config_dir = temp.path().join("lpm-home");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            "[firewall]\nmode = \"enforce\"\n\n[firewall.npm.policies]\nlpm_ai_confirmed_malware = \"allow\"\n",
        )
        .unwrap();

        let status = load_security_status(None, true).unwrap();

        let override_entry = status
            .active_runtime_overrides
            .iter()
            .find(|entry| entry.control == "[firewall.npm.policies]")
            .expect("policy override is reported");
        assert_eq!(override_entry.value, "lpm_ai_confirmed_malware=allow");
        assert_eq!(
            status.effective_floor.firewall_policies["lpm_ai_confirmed_malware"],
            "block"
        );
    });
}

fn bypass_rule(raw: &str) -> crate::firewall_bypass::FirewallBypassRule {
    crate::firewall_bypass::FirewallBypassRule::new(
        &crate::firewall_bypass::FirewallBypassSpec::parse(raw).unwrap(),
        crate::firewall_bypass::FirewallBypassScope::Global,
        None,
        false,
        Timestamp::now(),
    )
}

fn add_bypass(
    rules: Vec<crate::firewall_bypass::FirewallBypassRule>,
    json_output: bool,
) -> Result<FirewallBypassAdded, LpmError> {
    add_firewall_bypass_rules(FirewallBypassApproval {
        rules,
        prompt: "Allow foldrun@32.8.2 past LPM Firewall in every project",
        command_hint: Some("lpm firewall bypass add \"foldrun@32.8.2\""),
        json_output,
    })
}

#[test]
fn approved_firewall_bypass_is_saved_in_the_signed_store() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let added = with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap();

        assert_eq!(added.added.len(), 1);
        let saved = load_local_firewall_bypass_rules().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].spec, "foldrun@32.8.2");
        let audit = std::fs::read_to_string(audit_log_path().unwrap()).unwrap();
        assert!(audit.contains("firewall-bypass-added"), "{audit}");
    });
}

#[test]
fn declined_firewall_bypass_saves_nothing() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let err = with_test_native_auth_result("deny", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap_err();

        assert_eq!(err.error_code(), "security_approval_required");
        assert!(load_local_firewall_bypass_rules().unwrap().is_empty());
    });
}

#[test]
fn firewall_bypass_in_automation_asks_a_person_to_run_the_command() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let err =
            without_test_native_auth(|| add_bypass(vec![bypass_rule("foldrun@32.8.2")], true))
                .unwrap_err();

        let LpmError::SecurityApprovalRequired(context) = &err else {
            panic!("expected an approval error, got {err}");
        };
        assert_eq!(
            context.suggested_command.as_deref(),
            Some("lpm firewall bypass add \"foldrun@32.8.2\"")
        );
        assert!(load_local_firewall_bypass_rules().unwrap().is_empty());
    });
}

#[test]
fn adding_a_saved_firewall_bypass_again_asks_for_nothing() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap();

        let again =
            without_test_native_auth(|| add_bypass(vec![bypass_rule("foldrun@32.8.2")], true))
                .unwrap();

        assert!(again.added.is_empty());
        assert_eq!(again.unchanged.len(), 1);
    });
}

#[test]
fn firewall_bypass_is_refused_where_a_managed_policy_owns_the_firewall() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
mode = "enforce"
"#,
        );

        let err = with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap_err();

        assert_eq!(err.error_code(), "security_floor");
        assert!(err.to_string().contains("[firewall].bypass"), "{err}");
        assert!(load_local_firewall_bypass_rules().unwrap().is_empty());
    });
}

#[test]
fn removing_firewall_bypass_rules_needs_no_approval_and_empties_the_store() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        with_test_native_auth_result("approve", || {
            add_bypass(
                vec![bypass_rule("foldrun@32.8.2"), bypass_rule("left-pad")],
                false,
            )
        })
        .unwrap();

        let (removed, remaining) = without_test_native_auth(|| {
            remove_firewall_bypass_rules(|rule| rule.spec == "left-pad", "firewall-bypass-removed")
        })
        .unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(remaining, 1);
        assert_eq!(load_local_firewall_bypass_rules().unwrap().len(), 1);

        let (cleared, remaining) = without_test_native_auth(|| {
            remove_firewall_bypass_rules(|_| true, "firewall-bypass-cleared")
        })
        .unwrap();
        assert_eq!(cleared.len(), 1);
        assert_eq!(remaining, 0);
        assert!(!firewall_bypass_file_exists().unwrap());
    });
}

#[test]
fn tampered_firewall_bypass_store_is_rejected_and_repair_quarantines_it() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap();
        let path = firewall_bypass_path().unwrap();
        let tampered = std::fs::read_to_string(&path)
            .unwrap()
            .replace("foldrun@32.8.2", "foldrun@32.8.3");
        std::fs::write(&path, tampered).unwrap();

        assert!(load_local_firewall_bypass_rules().is_err());
        let status = load_security_status(None, true).unwrap();
        assert!(status.firewall_bypass.error.is_some());
        assert!(status.firewall_bypass.rules.is_empty());

        let report = repair_security_state().unwrap();
        assert!(
            report
                .quarantined
                .iter()
                .any(|entry| entry.original_path.ends_with("firewall-bypass.json")),
            "{report:?}"
        );
        assert!(load_local_firewall_bypass_rules().unwrap().is_empty());
    });
}

#[test]
fn firewall_bypass_store_from_a_newer_lpm_applies_no_rules() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_signed_json(
            &firewall_bypass_path().unwrap(),
            &serde_json::json!({
                "kind": "firewall-bypass",
                "schema_version": 2,
                "rules": [],
            }),
        )
        .unwrap();

        let err = load_local_firewall_bypass_rules().unwrap_err();

        assert!(err.to_string().contains("newer LPM CLI"), "{err}");
    });
}

#[test]
fn signed_json_of_another_kind_is_not_read_as_firewall_bypass_rules() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_signed_json(
            &firewall_bypass_path().unwrap(),
            &serde_json::json!({ "kind": "approved-posture", "schema_version": 1, "rules": [] }),
        )
        .unwrap();

        let err = load_local_firewall_bypass_rules().unwrap_err();

        assert!(
            err.to_string()
                .contains("is not an LPM Firewall bypass rule file"),
            "{err}"
        );
    });
}

#[test]
fn repair_quarantines_a_verified_bypass_file_this_cli_cannot_use() {
    for payload in [
        serde_json::json!({ "kind": "approved-posture", "schema_version": 1, "rules": [] }),
        serde_json::json!({ "kind": "firewall-bypass", "schema_version": 0, "rules": [] }),
        serde_json::json!({ "kind": "firewall-bypass", "schema_version": 1, "rules": [{ "spec": 1 }] }),
    ] {
        let temp = tempdir().unwrap();
        with_test_env(temp.path(), || {
            write_signed_json(&firewall_bypass_path().unwrap(), &payload).unwrap();
            assert!(load_local_firewall_bypass_rules().is_err(), "{payload}");

            let report = repair_security_state().unwrap();

            assert!(
                report
                    .quarantined
                    .iter()
                    .any(|entry| entry.original_path.ends_with("firewall-bypass.json")),
                "{payload}: {report:?}"
            );
            assert!(load_local_firewall_bypass_rules().unwrap().is_empty());
        });
    }
}

#[test]
fn repair_keeps_a_bypass_file_from_a_newer_cli() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_signed_json(
            &firewall_bypass_path().unwrap(),
            &serde_json::json!({ "kind": "firewall-bypass", "schema_version": 2, "rules": [] }),
        )
        .unwrap();

        let report = repair_security_state().unwrap();

        assert!(report.quarantined.is_empty(), "{report:?}");
        assert!(firewall_bypass_file_exists().unwrap());
    });
}

#[test]
fn security_status_for_a_project_lists_only_the_rules_that_apply_there() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("app");
    let other = temp.path().join("other");
    for dir in [&project, &other] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    }
    with_test_env(temp.path(), || {
        let project_rule = |dir: &Path, raw: &str| {
            crate::firewall_bypass::FirewallBypassRule::new(
                &crate::firewall_bypass::FirewallBypassSpec::parse(raw).unwrap(),
                crate::firewall_bypass::FirewallBypassScope::Project,
                Some(crate::firewall_bypass::project_policy_root_text(dir).unwrap()),
                false,
                Timestamp::now(),
            )
        };
        with_test_native_auth_result("approve", || {
            add_bypass(
                vec![
                    bypass_rule("everywhere@1.0.0"),
                    project_rule(&project, "here@1.0.0"),
                    project_rule(&other, "elsewhere@1.0.0"),
                ],
                false,
            )
        })
        .unwrap();
        let specs = |status: SecurityStatus| {
            let mut specs: Vec<String> = status
                .firewall_bypass
                .rules
                .into_iter()
                .map(|rule| rule.spec)
                .collect();
            specs.sort();
            specs
        };

        assert_eq!(
            specs(load_security_status(Some(&project), false).unwrap()),
            ["everywhere@1.0.0", "here@1.0.0"]
        );
        assert_eq!(
            specs(load_security_status(None, true).unwrap()),
            ["everywhere@1.0.0"]
        );
    });
}

#[test]
fn security_status_reports_active_firewall_bypass_rules_and_managed_entries() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap();
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
bypass = ["left-pad@^1.0.0"]
bypass-malware = ["evil@1.0.0"]
"#,
        );

        let status = load_security_status(None, true).unwrap();

        assert!(status.firewall_bypass.local_rules_apply);
        assert_eq!(status.firewall_bypass.rules[0].spec, "foldrun@32.8.2");
        assert_eq!(
            status.firewall_bypass.managed_rules,
            vec![
                ManagedFirewallBypass {
                    spec: "left-pad@^1.0.0".into(),
                    covers_malware: false,
                },
                ManagedFirewallBypass {
                    spec: "evil@1.0.0".into(),
                    covers_malware: true,
                },
            ]
        );
    });
}

#[test]
fn managed_bypass_malware_entries_must_name_exact_versions() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(
            temp.path(),
            r#"
[firewall]
bypass-malware = ["evil"]
"#,
        );

        let err = load_effective_authorized_posture().unwrap_err();

        assert!(
            err.to_string().contains("must name an exact version"),
            "{err}"
        );
    });
}

#[test]
fn security_status_blames_config_only_for_the_policy_groups_its_table_names() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[(
            crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
            "allow",
        )]);
        let config_dir = temp.path().join("lpm-home");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            "[firewall]\nmode = \"enforce\"\n\n[firewall.npm.policies]\nlpm_ai_telemetry = \"warn\"\n",
        )
        .unwrap();

        let status = load_security_status(None, true).unwrap();

        assert!(
            !status
                .active_runtime_overrides
                .iter()
                .any(|entry| entry.control == "[firewall.npm.policies]"),
            "{:?}",
            status.active_runtime_overrides
        );
    });
}

#[test]
fn security_status_lists_no_override_for_a_table_asking_for_the_approved_action() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[(
            crate::npm_firewall_config::LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY,
            "warn",
        )]);
        let config_dir = temp.path().join("lpm-home");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            "[firewall]\nmode = \"enforce\"\n\n[firewall.npm.policies]\nlpm_ai_dependency_script_policy = \"warn\"\nlpm_ai_confirmed_malware = \"warn\"\n",
        )
        .unwrap();

        let status = load_security_status(None, true).unwrap();

        let policies: Vec<&str> = status
            .active_runtime_overrides
            .iter()
            .filter(|entry| entry.control == "[firewall.npm.policies]")
            .map(|entry| entry.value.as_str())
            .collect();
        assert_eq!(policies, ["lpm_ai_confirmed_malware=warn"]);
    });
}

#[test]
fn forced_floor_measures_a_write_against_what_installs_run_not_an_unapproved_table() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let mut config = firewall_policy_global_config(
            "enforce",
            &[(
                crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
                "allow",
            )],
        );
        config.table_mut().insert(
            "force-security-floor".to_string(),
            toml::Value::Boolean(true),
        );
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_confirmed_malware: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let err = crate::security_floor::reject_looser_firewall_policy_write(&config, &requested)
            .unwrap_err();

        assert!(
            err.to_string().contains("lpm_ai_confirmed_malware"),
            "{err}"
        );
    });
}

const MANAGED_LOOSER_SCRIPT_POLICY: &str = "[firewall]\nmode = \"enforce\"\n\n[firewall.npm.policies]\nlpm_ai_dependency_script_policy = \"warn\"\n";

#[test]
fn an_editor_save_that_loosens_the_local_posture_under_a_looser_managed_profile_asks_first() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        write_managed_policy(temp.path(), MANAGED_LOOSER_SCRIPT_POLICY);
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_dependency_script_policy: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let err = with_test_native_auth_result("deny", || {
            authorize_persistent_npm_firewall_policies(&requested, false, "lpm config firewall")
        })
        .unwrap_err();

        assert_eq!(err.error_code(), "security_approval_required", "{err}");
        assert_eq!(
            load_authorized_posture()
                .unwrap()
                .firewall_policy_profile()
                .lpm_ai_dependency_script_policy,
            lpm_registry::client::NpmFirewallPolicyAction::Block
        );
    });
}

#[test]
fn forced_floor_holds_an_editor_save_at_the_local_posture_under_a_looser_managed_profile() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        write_managed_policy(temp.path(), MANAGED_LOOSER_SCRIPT_POLICY);
        let mut config = firewall_policy_global_config("enforce", &[]);
        config.table_mut().insert(
            "force-security-floor".to_string(),
            toml::Value::Boolean(true),
        );
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_dependency_script_policy: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let err = crate::security_floor::reject_looser_firewall_policy_write(&config, &requested)
            .unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("lpm_ai_dependency_script_policy"),
            "{message}"
        );
        assert!(message.contains("force-security-floor"), "{message}");
        assert!(!message.contains("config.toml"), "{message}");
    });
}

fn forced_floor_config(mode: &str) -> crate::commands::config::GlobalConfig {
    let mut config = firewall_policy_global_config(mode, &[]);
    config.table_mut().insert(
        "force-security-floor".to_string(),
        toml::Value::Boolean(true),
    );
    config
}

fn approve_firewall_mode(mode: crate::npm_firewall_config::NpmFirewallMode) {
    persist_authorized_posture(&AuthorizedPosture {
        firewall_mode: mode.as_str().to_string(),
        ..AuthorizedPosture::default()
    })
    .unwrap();
}

#[test]
fn forced_floor_lets_an_editor_save_raise_monitor_to_enforce_with_an_action_monitor_treats_alike() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_firewall_mode(crate::npm_firewall_config::NpmFirewallMode::Monitor);
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_dependency_script_policy: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        crate::security_floor::reject_looser_firewall_policy_write(
            &forced_floor_config("monitor"),
            &requested,
        )
        .unwrap();
    });
}

#[test]
fn forced_floor_lets_an_editor_save_turn_the_firewall_on_with_a_custom_profile() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_telemetry: lpm_registry::client::NpmFirewallPolicyAction::Allow,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        crate::security_floor::reject_looser_firewall_policy_write(
            &forced_floor_config("off"),
            &requested,
        )
        .unwrap();
    });
}

#[test]
fn forced_floor_names_one_action_that_passes_every_floor_an_editor_save_meets() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[(
            crate::npm_firewall_config::LPM_AI_SUSPICIOUS_POLICY_KEY,
            "block",
        )]);
        write_managed_policy(
            temp.path(),
            "[firewall]\nmode = \"enforce\"\n\n[firewall.npm.policies]\nlpm_ai_suspicious = \"warn\"\n",
        );
        let config = forced_floor_config("enforce");

        for requested_action in [
            lpm_registry::client::NpmFirewallPolicyAction::Allow,
            lpm_registry::client::NpmFirewallPolicyAction::Warn,
        ] {
            let requested = lpm_registry::client::NpmFirewallPolicyProfile {
                lpm_ai_suspicious: requested_action,
                ..lpm_registry::client::NpmFirewallPolicyProfile::default()
            };

            let message =
                crate::security_floor::reject_looser_firewall_policy_write(&config, &requested)
                    .unwrap_err()
                    .to_string();

            assert!(
                message.contains("would loosen the `block` your approved posture holds"),
                "{message}"
            );
            assert!(
                message.contains("Keep it at `block` or stricter"),
                "{message}"
            );
        }
    });
}

/// An editor save under `managed_policy` and `force-security-floor = true` at
/// `config_mode`, loosening telemetry to each of `requested_actions`, is
/// refused by the managed check, which names `refused_group` and records each
/// try.
fn assert_managed_check_refuses_first(
    managed_policy: &str,
    config_mode: &str,
    extra: lpm_registry::client::NpmFirewallPolicyProfile,
    requested_actions: &[lpm_registry::client::NpmFirewallPolicyAction],
    refused_group: &str,
) {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(temp.path(), managed_policy);
        let config = forced_floor_config(config_mode);

        for requested_action in requested_actions {
            let requested = lpm_registry::client::NpmFirewallPolicyProfile {
                lpm_ai_telemetry: *requested_action,
                ..extra
            };

            let message = crate::security_floor::reject_firewall_policy_save(&config, &requested)
                .unwrap_err()
                .to_string();

            assert!(
                message.contains(&format!(
                    "keeps `[firewall.npm.policies].{refused_group}` at `block`"
                )),
                "{message}"
            );
            assert!(!message.contains("force-security-floor"), "{message}");
        }
        assert_eq!(guarded_attempts(), requested_actions.len());
    });
}

#[test]
fn an_editor_save_meets_the_managed_check_before_the_forced_floor() {
    let telemetry_block =
        "[firewall]\nmode = \"{mode}\"\n\n[firewall.npm.policies]\nlpm_ai_telemetry = \"block\"\n";
    let looser = [
        lpm_registry::client::NpmFirewallPolicyAction::Allow,
        lpm_registry::client::NpmFirewallPolicyAction::Warn,
    ];
    // Installs run at monitor, where the managed `block` alone holds the group.
    assert_managed_check_refuses_first(
        &telemetry_block.replace("{mode}", "monitor"),
        "monitor",
        lpm_registry::client::NpmFirewallPolicyProfile::default(),
        &looser,
        "lpm_ai_telemetry",
    );
    // Installs run at enforce, where what they enforce ties the managed floor.
    assert_managed_check_refuses_first(
        &telemetry_block.replace("{mode}", "enforce"),
        "enforce",
        lpm_registry::client::NpmFirewallPolicyProfile::default(),
        &looser,
        "lpm_ai_telemetry",
    );
    // A save that loosens several groups the policy holds is refused on the
    // first, still by the managed check.
    assert_managed_check_refuses_first(
        &telemetry_block.replace("{mode}", "enforce"),
        "enforce",
        lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_confirmed_malware: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        },
        &[lpm_registry::client::NpmFirewallPolicyAction::Allow],
        "lpm_ai_confirmed_malware",
    );
}

#[test]
fn a_managed_mode_alone_names_the_loosest_action_its_mode_accepts() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        write_managed_policy(temp.path(), "[firewall]\nmode = \"monitor\"\n");
        let config = forced_floor_config("monitor");
        let dependency_scripts = |action| lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_dependency_script_policy: action,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let message = crate::security_floor::reject_firewall_policy_save(
            &config,
            &dependency_scripts(lpm_registry::client::NpmFirewallPolicyAction::Allow),
        )
        .unwrap_err()
        .to_string();

        assert!(
            message.contains("holds the npm firewall at `monitor` mode or stricter"),
            "{message}"
        );
        assert!(
            message.contains(&format!(
                "at `monitor` `[firewall.npm.policies].{}` can't be looser than `warn`",
                crate::npm_firewall_config::LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY
            )),
            "{message}"
        );
        assert!(!message.contains("`block`"), "{message}");
        assert_eq!(guarded_attempts(), 1);
        // Monitor reports `warn` and `block` alike, so the action it names passes.
        crate::security_floor::reject_firewall_policy_save(
            &config,
            &dependency_scripts(lpm_registry::client::NpmFirewallPolicyAction::Warn),
        )
        .unwrap();
        assert_eq!(guarded_attempts(), 1);
    });
}

#[test]
fn forced_floor_refuses_an_editor_save_that_would_sign_a_group_left_loose_by_hand() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let mut config = firewall_policy_global_config(
            "enforce",
            &[(
                crate::npm_firewall_config::LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY,
                "warn",
            )],
        );
        config.table_mut().insert(
            "force-security-floor".to_string(),
            toml::Value::Boolean(true),
        );
        let repairs_another_group = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_dependency_script_policy: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            lpm_ai_agent_control_surface: lpm_registry::client::NpmFirewallPolicyAction::Block,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let err = crate::security_floor::reject_looser_firewall_policy_write(
            &config,
            &repairs_another_group,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("lpm_ai_dependency_script_policy"),
            "{err}"
        );
    });
}

#[test]
fn forced_floor_measures_a_delete_at_the_mode_installs_run() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_firewall_mode(crate::npm_firewall_config::NpmFirewallMode::Monitor);
        let mut config = firewall_policy_global_config(
            "monitor",
            &[(
                crate::npm_firewall_config::LPM_AI_SUSPICIOUS_POLICY_KEY,
                "block",
            )],
        );
        config.table_mut().insert(
            "force-security-floor".to_string(),
            toml::Value::Boolean(true),
        );
        let after_delete = |action| lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_suspicious: action,
            lpm_ai_telemetry: action,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let reports_as_much = crate::security_floor::reject_looser_firewall_policy_delete(
            &config,
            &after_delete(lpm_registry::client::NpmFirewallPolicyAction::Warn),
        );
        let reports_less = crate::security_floor::reject_looser_firewall_policy_delete(
            &config,
            &after_delete(lpm_registry::client::NpmFirewallPolicyAction::Allow),
        );

        assert!(reports_as_much.is_ok(), "{reports_as_much:?}");
        assert_eq!(reports_less.unwrap_err().error_code(), "security_floor");
    });
}

#[test]
fn forced_floor_judges_a_delete_only_by_the_groups_it_changes() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let mut config = firewall_policy_global_config(
            "enforce",
            &[
                (
                    crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
                    "warn",
                ),
                (
                    crate::npm_firewall_config::LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY,
                    "warn",
                ),
            ],
        );
        config.table_mut().insert(
            "force-security-floor".to_string(),
            toml::Value::Boolean(true),
        );
        let restores_malware = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_dependency_script_policy: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };
        let loosens_scripts = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_confirmed_malware: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            lpm_ai_dependency_script_policy: lpm_registry::client::NpmFirewallPolicyAction::Allow,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let restored =
            crate::security_floor::reject_looser_firewall_policy_delete(&config, &restores_malware);
        let loosened =
            crate::security_floor::reject_looser_firewall_policy_delete(&config, &loosens_scripts)
                .unwrap_err();

        assert!(restored.is_ok(), "{restored:?}");
        assert!(
            loosened
                .to_string()
                .contains("lpm_ai_dependency_script_policy"),
            "{loosened}"
        );
    });
}

#[test]
fn runtime_firewall_reports_a_looser_mode_without_listing_unchanged_policies() {
    let temp = tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[]);
        let config = firewall_policy_global_config(
            "monitor",
            &[(
                crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
                "block",
            )],
        );

        let err = without_test_native_auth(|| resolve_firewall(&config, &project)).unwrap_err();

        let LpmError::SecurityApprovalRequired(context) = &err else {
            panic!("expected an approval error, got {err}");
        };
        assert!(
            !context.message.contains("[firewall.npm.policies]"),
            "{}",
            context.message
        );
        assert_ne!(
            context.suggested_command.as_deref(),
            Some("lpm config firewall")
        );
    });
}

#[test]
fn tightening_the_approved_profile_restores_defaults_without_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[
            (
                crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
                "allow",
            ),
            (
                crate::npm_firewall_config::LPM_AI_TELEMETRY_POLICY_KEY,
                "block",
            ),
        ]);

        without_test_native_auth(|| {
            tighten_persistent_npm_firewall_policies(
                &lpm_registry::client::NpmFirewallPolicyProfile::default(),
            )
        })
        .unwrap();

        let profile = load_authorized_posture().unwrap().firewall_policy_profile();
        assert_eq!(
            profile.lpm_ai_confirmed_malware,
            lpm_registry::client::NpmFirewallPolicyAction::Block
        );
        assert_eq!(
            profile.lpm_ai_telemetry,
            lpm_registry::client::NpmFirewallPolicyAction::Block,
            "tightening never loosens a stricter approved group"
        );
    });
}

#[test]
fn a_floor_edit_unlock_does_not_stand_in_for_firewall_bypass_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        with_test_native_auth_result("approve", || {
            unlock_global_scopes_command("floor-edit", &[ApprovalScope::FloorEdit], 600, false, &[])
        })
        .unwrap();

        let err = with_test_native_auth_result("deny", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap_err();

        assert_eq!(err.error_code(), "security_approval_required");
        assert!(load_local_firewall_bypass_rules().unwrap().is_empty());
    });
}

fn bypass_rule_expiring_in(raw: &str, minutes: i64) -> crate::firewall_bypass::FirewallBypassRule {
    let mut rule = bypass_rule(raw);
    rule.expires_at = Some(Timestamp::now() + time::Duration::minutes(minutes));
    rule
}

#[test]
fn re_adding_a_saved_rule_with_a_sooner_expiry_shortens_it_without_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap();
        let shorter = bypass_rule_expiring_in("foldrun@32.8.2", 30);

        let again = without_test_native_auth(|| add_bypass(vec![shorter.clone()], true)).unwrap();

        assert_eq!(again.narrowed[0].expires_at, shorter.expires_at);
        assert_eq!(
            load_local_firewall_bypass_rules().unwrap()[0].expires_at,
            shorter.expires_at
        );
    });
}

#[test]
fn re_adding_a_saved_rule_for_longer_needs_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let short = bypass_rule_expiring_in("foldrun@32.8.2", 30);
        with_test_native_auth_result("approve", || add_bypass(vec![short.clone()], false)).unwrap();

        let err =
            without_test_native_auth(|| add_bypass(vec![bypass_rule("foldrun@32.8.2")], true))
                .unwrap_err();
        assert_eq!(err.error_code(), "security_approval_required");
        assert_eq!(
            load_local_firewall_bypass_rules().unwrap()[0].expires_at,
            short.expires_at
        );

        let extended = with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap();
        assert_eq!(extended.extended.len(), 1);
        assert_eq!(
            load_local_firewall_bypass_rules().unwrap()[0].expires_at,
            None
        );
    });
}

#[test]
fn re_adding_a_saved_rule_unchanged_reports_the_saved_rule() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let mut saved = bypass_rule("foldrun@32.8.2");
        saved.reason = Some("reviewed the report".to_string());
        with_test_native_auth_result("approve", || add_bypass(vec![saved], false)).unwrap();

        let again =
            without_test_native_auth(|| add_bypass(vec![bypass_rule("foldrun@32.8.2")], true))
                .unwrap();

        assert!(again.added.is_empty() && again.narrowed.is_empty());
        assert_eq!(
            again.unchanged[0].reason.as_deref(),
            Some("reviewed the report")
        );
    });
}

#[test]
fn json_mode_never_prompts_even_where_native_approval_would_pass() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        let err = with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], true)
        })
        .unwrap_err();

        assert_eq!(err.error_code(), "security_approval_required");
        assert!(load_local_firewall_bypass_rules().unwrap().is_empty());
    });
}

#[test]
fn a_narrowing_judged_before_a_concurrent_remove_is_not_saved_without_approval() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap();
        let sorted =
            sort_firewall_bypass_requests(vec![bypass_rule_expiring_in("foldrun@32.8.2", 30)])
                .unwrap();
        assert_eq!(sorted.narrowed.len(), 1);
        remove_firewall_bypass_rules(|_| true, "firewall-bypass-cleared").unwrap();

        let saved = save_narrowed_firewall_bypass_rules(&sorted.narrowed).unwrap();

        assert!(saved.narrowed.is_empty());
        assert_eq!(saved.needs_approval.len(), 1);
        assert!(load_local_firewall_bypass_rules().unwrap().is_empty());
    });
}

#[test]
fn a_narrowing_judged_before_a_shorter_expiry_never_lengthens_the_rule() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        with_test_native_auth_result("approve", || {
            add_bypass(vec![bypass_rule("foldrun@32.8.2")], false)
        })
        .unwrap();
        let sorted =
            sort_firewall_bypass_requests(vec![bypass_rule_expiring_in("foldrun@32.8.2", 30)])
                .unwrap();
        let shortest = bypass_rule_expiring_in("foldrun@32.8.2", 10);
        save_narrowed_firewall_bypass_rules(std::slice::from_ref(&shortest)).unwrap();

        let saved = save_narrowed_firewall_bypass_rules(&sorted.narrowed).unwrap();

        assert!(saved.narrowed.is_empty());
        assert_eq!(
            load_local_firewall_bypass_rules().unwrap()[0].expires_at,
            shortest.expires_at
        );
    });
}

#[test]
fn forced_floor_holds_an_approved_group_a_partial_table_leaves_out() {
    let temp = tempdir().unwrap();
    with_test_env(temp.path(), || {
        approve_enforced_firewall(&[(
            crate::npm_firewall_config::LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY,
            "block",
        )]);
        let mut config = firewall_policy_global_config(
            "enforce",
            &[(
                crate::npm_firewall_config::LPM_AI_TELEMETRY_POLICY_KEY,
                "block",
            )],
        );
        config.table_mut().insert(
            "force-security-floor".to_string(),
            toml::Value::Boolean(true),
        );
        let requested = lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_telemetry: lpm_registry::client::NpmFirewallPolicyAction::Block,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        };

        let err = crate::security_floor::reject_looser_firewall_policy_write(&config, &requested)
            .unwrap_err();

        assert!(
            err.to_string().contains("lpm_ai_agent_control_surface"),
            "{err}"
        );
    });
}
