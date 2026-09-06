use super::prelude::*;
use super::*;
use tempfile::tempdir;

fn with_test_env<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    let policy_path = dir.join("managed-security-policy.toml");
    let lpm_home = dir.join("lpm-home");
    let _env = crate::test_env::ScopedEnv::update([
        ("LPM_HOME", Some(lpm_home.as_os_str().to_owned())),
        (SECURITY_DIR_ENV, Some(dir.as_os_str().to_owned())),
        (
            SECURITY_POLICY_PATH_ENV,
            Some(policy_path.as_os_str().to_owned()),
        ),
        (
            TEST_SECRET_ENV,
            Some(std::ffi::OsString::from(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
        ),
        (
            TEST_AUTH_RESULT_ENV,
            Some(std::ffi::OsString::from("approve")),
        ),
        ("LPM_NPM_FIREWALL", None),
        ("LPM_EXPERIMENT_NPM_FIREWALL", None),
        ("LPM_PROVENANCE_ENFORCE", None),
        ("LPM_FORCE_FILE_VAULT", None),
    ]);
    f()
}

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
            LpmError::SecurityApprovalRequired {
                ref requested_scopes,
                ..
            } if requested_scopes == &["source-analysis-disable"]
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
            (grant.expires_at - grant.issued_at).num_seconds(),
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
        let mode = crate::npm_firewall_config::resolve_runtime_mode(
            &crate::commands::config::GlobalConfig::empty(),
            &project,
            true,
        )
        .unwrap();

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
        let err = crate::npm_firewall_config::resolve_runtime_mode(
            &firewall_global_config("off"),
            &project,
            true,
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
    let original_auth = std::env::var_os(TEST_AUTH_RESULT_ENV);
    unsafe {
        std::env::remove_var(TEST_AUTH_RESULT_ENV);
    }
    let automation = is_automation(true);
    match original_auth {
        Some(value) => unsafe { std::env::set_var(TEST_AUTH_RESULT_ENV, value) },
        None => unsafe { std::env::remove_var(TEST_AUTH_RESULT_ENV) },
    }
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
fn windows_hello_availability_falls_back_when_pin_is_not_configured() {
    assert_eq!(
        super::native_auth::windows_hello_availability_action(2),
        super::native_auth::WindowsHelloAvailabilityAction::TerminalFallback(
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
        assert!(content.contains("\"event\":\"guarded-attempt\""));
        assert!(content.contains("trust-scope-widen"));
        assert!(content.contains(&canonical_project_root(&project)));
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
            LpmError::SecurityApprovalRequired {
                ref requested_scopes,
                ..
            } if requested_scopes == &["firewall-disable"]
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
                crate::npm_firewall_config::NpmFirewallModeRequest::from_env(
                    crate::npm_firewall_config::NpmFirewallMode::Off,
                ),
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
                    LpmError::SecurityApprovalRequired {
                        project_root,
                        suggested_command,
                        ..
                    } => {
                        assert_eq!(project_root, None);
                        assert_eq!(
                            suggested_command.as_deref(),
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
            occurred_at: Utc::now(),
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
            occurred_at: Utc::now(),
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
                    occurred_at: Utc::now(),
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
            occurred_at: Utc::now(),
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
            occurred_at: Utc::now(),
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
