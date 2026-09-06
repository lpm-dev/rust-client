use super::wizards::{
    CAUTIOUS_RELEASE_AGE_SECS, FIREWALL_ENFORCE_HINT, FIREWALL_MONITOR_HINT, FIREWALL_OFF_HINT,
    FIREWALL_WIZARD_PROMPT, INTEGRITY_SOURCE_HINT, INTEGRITY_TREE_HINT, INTEGRITY_WIZARD_PROMPT,
    ReleaseAgeSelection, persist_firewall_policy_profile_in_config_value,
    persist_release_age_selection, persist_script_policy, read_firewall_mode,
    read_integrity_policy, read_release_age_override, read_sandbox_mode,
    read_sigstore_availability, read_sigstore_scope, read_sigstore_verify,
    read_typosquat_guard_override, release_age_initial_choice,
};
use super::*;
use crate::npm_firewall_config::{FIREWALL_CONFIG_MODE_KEY, FIREWALL_CONFIG_PATH};
use tempfile::TempDir;

fn tmp_config() -> (TempDir, std::path::PathBuf, crate::test_env::ScopedEnv) {
    let dir = TempDir::new().expect("tempdir");
    let security_dir = dir.path().join("security");
    let env = crate::test_env::ScopedEnv::set([
        ("LPM_SECURITY_DIR", security_dir.as_os_str().to_owned()),
        (
            "LPM_SECURITY_POLICY_PATH",
            dir.path()
                .join("absent-managed-security-policy.toml")
                .as_os_str()
                .to_owned(),
        ),
        (
            "LPM_TEST_SECURITY_SECRET_HEX",
            std::ffi::OsString::from(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ),
    ]);
    let posture = crate::security_approval::AuthorizedPosture {
        script_policy: "allow".to_string(),
        minimum_release_age_secs: 0,
        sandbox_mode: "none".to_string(),
        sigstore_verify: "off".to_string(),
        typosquat_guard: "off".to_string(),
        ..crate::security_approval::AuthorizedPosture::default()
    };
    crate::security_approval::persist_authorized_posture(&posture).unwrap();
    let path = dir.path().join("config.toml");
    (dir, path, env)
}

fn global_config(contents: &str) -> GlobalConfig {
    GlobalConfig::from_value(toml::from_str(contents).unwrap()).unwrap()
}

#[test]
fn generic_set_target_routes_supported_nested_sections() {
    assert_eq!(
        [
            generic_set_target("sandbox"),
            generic_set_target("sigstore"),
            generic_set_target("firewall"),
        ],
        [
            GenericSetTarget::Sandbox,
            GenericSetTarget::Sigstore,
            GenericSetTarget::Firewall,
        ]
    );
}

#[test]
fn generic_set_target_rejects_nested_sections_without_scalar_meaning() {
    assert_eq!(
        [generic_set_target("policy"), generic_set_target("tunnel")],
        [
            GenericSetTarget::UnsupportedNested,
            GenericSetTarget::UnsupportedNested,
        ]
    );
}

#[test]
fn generic_set_target_rejects_dotted_paths_for_nested_sections() {
    for key in [
        "sandbox.mode",
        "sigstore.verify",
        "firewall.mode",
        "policy.extensions",
        "tunnel.relay-url",
    ] {
        assert_eq!(
            generic_set_target(key),
            GenericSetTarget::UnsupportedNested,
            "{key} must not become a quoted top-level key"
        );
    }
}

#[test]
fn firewall_wizard_copy_uses_npm_package_language() {
    assert_eq!(
        (
            FIREWALL_GUIDED_MENU_LABEL,
            FIREWALL_WIZARD_PROMPT,
            FIREWALL_OFF_HINT,
            FIREWALL_MONITOR_HINT,
            FIREWALL_ENFORCE_HINT,
        ),
        (
            "Firewall for npm",
            "How should LPM CLI handle LPM Firewall verdicts for npm packages?",
            "default; use direct npm metadata and tarballs only",
            "show what would be blocked without stopping install",
            "review recommended policy profile before saving",
        )
    );
}

#[test]
fn integrity_wizard_copy_uses_store_object_language() {
    assert_eq!(
        (
            INTEGRITY_GUIDED_MENU_LABEL,
            INTEGRITY_WIZARD_PROMPT,
            INTEGRITY_SOURCE_HINT,
            INTEGRITY_TREE_HINT,
        ),
        (
            "Store integrity",
            "How should LPM verify reused package store objects?",
            "default; verify source identity without rehashing expanded files",
            "stricter; rehash expanded files to detect local store tampering/corruption",
        )
    );
}

#[test]
fn release_age_guided_menu_uses_the_grouped_configuration_label() {
    assert_eq!(RELEASE_AGE_GUIDED_MENU_LABEL, "Release age configuration");
}

#[test]
fn guided_config_summary_uses_product_defaults_when_unset() {
    let (_dir, path, _env) = tmp_config();

    let summary = read_guided_config_summary(&path).unwrap();

    assert_eq!(
        summary,
        GuidedConfigSummary {
            script_policy: "deny".to_string(),
            triage_advisor: "none".to_string(),
            sandbox_mode: "default".to_string(),
            sigstore_verify: "deny".to_string(),
            sigstore_scope: "approved".to_string(),
            sigstore_availability: "best-effort".to_string(),
            signatures: "disabled",
            trust_policy: "off".to_string(),
            typosquat_guard: "default (disabled)".to_string(),
            firewall_mode: "off".to_string(),
            integrity_mode: "source".to_string(),
            release_age: "default (off)".to_string(),
            release_age_policy: "direct".to_string(),
            source_analysis: "disabled",
            lpm_skills: "enabled (default)",
            lpm_insights: "enabled",
        }
    );
}

#[test]
fn guided_config_summary_reflects_persisted_settings() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        r#"
script-policy = "triage"
triage-advisor = "codex"
signatures = true
trust-policy = "no-downgrade"
typosquat-guard = "off"
integrity = "tree"
minimum-release-age-secs = "259200"
release-age-policy = "strict"
auto-install-lpm-skills = false
fetch-lpm-security-insights = false
install-time-source-analysis = false

[sandbox]
mode = "strict"

[sigstore]
verify = "warn"
scope = "all"
availability = "strict"

[firewall]
mode = "enforce"
"#,
    )
    .unwrap();

    let summary = read_guided_config_summary(&path).unwrap();

    assert_eq!(
        summary,
        GuidedConfigSummary {
            script_policy: "triage".to_string(),
            triage_advisor: "codex".to_string(),
            sandbox_mode: "strict".to_string(),
            sigstore_verify: "warn".to_string(),
            sigstore_scope: "all".to_string(),
            sigstore_availability: "strict".to_string(),
            signatures: "enabled",
            trust_policy: "no-downgrade".to_string(),
            typosquat_guard: "off".to_string(),
            firewall_mode: "enforce".to_string(),
            integrity_mode: "tree".to_string(),
            release_age: "3d".to_string(),
            release_age_policy: "strict".to_string(),
            source_analysis: "disabled",
            lpm_skills: "disabled",
            lpm_insights: "disabled",
        }
    );
}

#[tokio::test]
async fn scripts_wizard_set_persists_valid_value() {
    let (_dir, path, _env) = tmp_config();
    run_scripts_wizard(&path, Some("triage"), true)
        .await
        .unwrap();
    let v = read_string_value(&path, SCRIPT_POLICY_KEY).unwrap();
    assert_eq!(v.as_deref(), Some("triage"));
}

#[tokio::test]
async fn scripts_wizard_set_rejects_invalid_value() {
    let (_dir, path, _env) = tmp_config();
    let err = run_scripts_wizard(&path, Some("yolo"), true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid script-policy 'yolo'"), "got: {msg}");
    // Nothing persisted on validation failure.
    let v = read_string_value(&path, SCRIPT_POLICY_KEY).unwrap();
    assert!(v.is_none());
}

#[tokio::test]
async fn scripts_wizard_set_rejects_looser_value_when_force_floor_enabled() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "force-security-floor = true\nscript-policy = \"triage\"\n",
    )
    .unwrap();
    let err = run_scripts_wizard(&path, Some("allow"), true)
        .await
        .unwrap_err();
    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains("script-policy"));
}

#[tokio::test]
async fn persist_script_policy_rejects_triage_when_force_floor_requires_deny() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "force-security-floor = true\nscript-policy = \"deny\"\n",
    )
    .unwrap();

    let err = persist_script_policy(&path, "triage", true)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains("script-policy"));
    assert_eq!(
        read_string_value(&path, SCRIPT_POLICY_KEY)
            .unwrap()
            .as_deref(),
        Some("deny")
    );
}

#[tokio::test]
async fn triage_wizard_set_persists_valid_provider() {
    let (_dir, path, _env) = tmp_config();
    run_triage_wizard(&path, Some("claude-cli"), true)
        .await
        .unwrap();
    let v = read_string_value(&path, TRIAGE_ADVISOR_KEY).unwrap();
    assert_eq!(v.as_deref(), Some("claude-cli"));
}

#[tokio::test]
async fn triage_wizard_set_accepts_none_as_first_class() {
    let (_dir, path, _env) = tmp_config();
    // Seed something first to confirm "none" can overwrite a prior choice.
    run_triage_wizard(&path, Some("claude-cli"), true)
        .await
        .unwrap();
    run_triage_wizard(&path, Some("none"), true).await.unwrap();
    let v = read_string_value(&path, TRIAGE_ADVISOR_KEY).unwrap();
    assert_eq!(v.as_deref(), Some("none"));
}

#[tokio::test]
async fn triage_wizard_set_rejects_unknown_provider() {
    let (_dir, path, _env) = tmp_config();
    let err = run_triage_wizard(&path, Some("anthropic-api"), true)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("invalid triage-advisor 'anthropic-api'"),
        "got: {err}",
    );
}

#[tokio::test]
async fn wizards_do_not_clobber_unrelated_keys() {
    let (_dir, path, _env) = tmp_config();
    // Pre-populate an unrelated key.
    std::fs::write(&path, "unrelated = \"keep-me\"\n").unwrap();
    run_scripts_wizard(&path, Some("deny"), true).await.unwrap();
    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    assert_eq!(
        table.get("unrelated").and_then(|v| v.as_str()),
        Some("keep-me")
    );
    assert_eq!(
        table.get(SCRIPT_POLICY_KEY).and_then(|v| v.as_str()),
        Some("deny")
    );
}

#[tokio::test]
async fn typosquat_wizard_set_persists_explicit_on_and_off_values() {
    for value in ["on", "off"] {
        let (_dir, path, _env) = tmp_config();

        run_typosquat_wizard(&path, Some(value), true)
            .await
            .unwrap();

        assert_eq!(
            read_typosquat_guard_override(&path).unwrap(),
            Some(parse_typosquat_guard_selection(value).unwrap()),
            "typosquat guard value '{value}' must persist",
        );
        let cfg = read_config(&path).unwrap();
        assert_eq!(
            cfg.get(TYPOSQUAT_GUARD_KEY).and_then(|v| v.as_str()),
            Some(value),
        );
    }
}

#[tokio::test]
async fn typosquat_wizard_set_default_deletes_existing_override() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "script-policy = \"triage\"\ntyposquat-guard = \"on\"\n",
    )
    .unwrap();

    run_typosquat_wizard(&path, Some("default"), true)
        .await
        .unwrap();

    assert_eq!(read_typosquat_guard_override(&path).unwrap(), None);
    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    assert_eq!(
        table.get("script-policy").and_then(|v| v.as_str()),
        Some("triage"),
        "default must preserve unrelated config keys",
    );
    assert!(
        !table.contains_key(TYPOSQUAT_GUARD_KEY),
        "default must remove the explicit typosquat-guard override",
    );
}

#[tokio::test]
async fn typosquat_wizard_set_persists_canonical_values_for_bool_aliases() {
    for (input, expected) in [("enabled", "on"), ("disabled", "off"), ("false", "off")] {
        let (_dir, path, _env) = tmp_config();

        run_typosquat_wizard(&path, Some(input), true)
            .await
            .unwrap();

        let cfg = read_config(&path).unwrap();
        assert_eq!(
            cfg.get(TYPOSQUAT_GUARD_KEY).and_then(|v| v.as_str()),
            Some(expected),
            "input '{input}' must persist canonical typosquat-guard value '{expected}'",
        );
    }
}

#[tokio::test]
async fn typosquat_wizard_set_rejects_invalid_value_without_persisting() {
    let (_dir, path, _env) = tmp_config();

    let err = run_typosquat_wizard(&path, Some("yolo"), true)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(msg.contains("invalid typosquat-guard 'yolo'"), "got: {msg}");
    assert!(
        read_typosquat_guard_override(&path).unwrap().is_none(),
        "invalid typosquat guard value must not create config.toml",
    );
}

#[tokio::test]
async fn typosquat_wizard_preserves_unrelated_keys() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "script-policy = \"triage\"\n").unwrap();

    run_typosquat_wizard(&path, Some("off"), true)
        .await
        .unwrap();

    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    assert_eq!(
        table.get("script-policy").and_then(|v| v.as_str()),
        Some("triage"),
    );
    assert_eq!(
        table.get(TYPOSQUAT_GUARD_KEY).and_then(|v| v.as_str()),
        Some("off"),
    );
}

#[tokio::test]
async fn typosquat_wizard_rejects_off_when_force_floor_keeps_guard_enabled() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "force-security-floor = true\ntyposquat-guard = \"on\"\n",
    )
    .unwrap();

    let err = run_typosquat_wizard(&path, Some("off"), true)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains(TYPOSQUAT_GUARD_KEY));
    assert_eq!(
        read_typosquat_guard_override(&path).unwrap(),
        Some(TyposquatGuardSelection::On)
    );
}

#[test]
fn global_config_get_typosquat_guard_mode_accepts_canonical_values() {
    let mut table = toml::map::Map::new();
    table.insert(
        TYPOSQUAT_GUARD_KEY.to_string(),
        toml::Value::String("off".to_string()),
    );
    let cfg = GlobalConfig { table };

    assert_eq!(
        cfg.get_typosquat_guard_mode(),
        Some(TyposquatGuardSelection::Off),
    );
}

#[tokio::test]
async fn firewall_wizard_set_persists_each_valid_mode() {
    for mode in ["off", "monitor", "enforce", "report"] {
        let (_dir, path, _env) = tmp_config();

        run_firewall_wizard(&path, Some(mode), true).await.unwrap();

        assert_eq!(
            read_firewall_mode(&path).unwrap(),
            Some(parse_firewall_mode_selection(mode).unwrap()),
            "firewall mode '{mode}' must persist",
        );
    }
}

#[tokio::test]
async fn firewall_wizard_set_writes_nested_firewall_table() {
    let (_dir, path, _env) = tmp_config();

    run_firewall_wizard(&path, Some("enforce"), true)
        .await
        .unwrap();

    let cfg = read_config(&path).unwrap();
    assert_eq!(
        cfg.get(FIREWALL_CONFIG_SECTION)
            .and_then(|v| v.as_table())
            .and_then(|t| t.get(FIREWALL_CONFIG_MODE_KEY))
            .and_then(|v| v.as_str()),
        Some("enforce")
    );
}

#[tokio::test]
async fn firewall_wizard_set_rejects_invalid_mode_without_persisting() {
    let (_dir, path, _env) = tmp_config();

    let err = run_firewall_wizard(&path, Some("observe"), true)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("invalid firewall mode 'observe'"),
        "got: {msg}"
    );
    assert!(read_firewall_mode(&path).unwrap().is_none());
}

#[tokio::test]
async fn firewall_wizard_set_records_enabled_mode_as_approved_posture() {
    let (_dir, path, _env) = tmp_config();

    run_firewall_wizard(&path, Some("enforce"), true)
        .await
        .unwrap();

    let posture = crate::security_approval::load_authorized_posture().unwrap();
    assert_eq!(posture.firewall_mode(), NpmFirewallMode::Enforce);
}

#[tokio::test]
async fn firewall_wizard_set_rejects_disable_when_approved_posture_requires_enforce() {
    let (_dir, path, _env) = tmp_config();
    run_firewall_wizard(&path, Some("enforce"), true)
        .await
        .unwrap();

    let err = run_firewall_wizard(&path, Some("off"), true)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), "security_approval_required");
    assert!(matches!(
        err,
        LpmError::SecurityApprovalRequired {
            ref requested_scopes,
            ..
        } if requested_scopes == &["firewall-disable"]
    ));
    assert_eq!(
        read_firewall_mode(&path).unwrap(),
        Some(NpmFirewallMode::Enforce)
    );
}

#[tokio::test]
async fn firewall_wizard_set_rejects_looser_mode_when_force_floor_enabled() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "force-security-floor = true\n[firewall]\nmode = \"enforce\"\n",
    )
    .unwrap();

    let err = run_firewall_wizard(&path, Some("monitor"), true)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains(FIREWALL_CONFIG_PATH));
    assert_eq!(
        read_firewall_mode(&path).unwrap(),
        Some(NpmFirewallMode::Enforce)
    );
}

#[tokio::test]
async fn firewall_wizard_preserves_sibling_keys() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "script-policy = \"triage\"\n[firewall]\nnote = \"keep-me\"\n",
    )
    .unwrap();

    run_firewall_wizard(&path, Some("monitor"), true)
        .await
        .unwrap();

    let cfg = read_config(&path).unwrap();
    let top = cfg.as_table().unwrap();
    assert_eq!(
        top.get("script-policy").and_then(|v| v.as_str()),
        Some("triage")
    );
    let firewall = top
        .get(FIREWALL_CONFIG_SECTION)
        .and_then(|v| v.as_table())
        .unwrap();
    assert_eq!(
        firewall
            .get(FIREWALL_CONFIG_MODE_KEY)
            .and_then(|v| v.as_str()),
        Some("monitor")
    );
    assert_eq!(
        firewall.get("note").and_then(|v| v.as_str()),
        Some("keep-me")
    );
}

#[test]
fn firewall_policy_profile_persistence_writes_nested_policy_table() {
    let mut cfg = GlobalConfig::empty();

    persist_firewall_policy_profile_in_config_value(
        &mut cfg,
        lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_agent_control_surface: lpm_registry::client::NpmFirewallPolicyAction::Warn,
            lpm_ai_suspicious: lpm_registry::client::NpmFirewallPolicyAction::Allow,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        },
    )
    .unwrap();

    let policies = cfg
        .get_value(FIREWALL_CONFIG_SECTION)
        .and_then(|value| value.as_table())
        .and_then(|table| table.get(crate::npm_firewall_config::FIREWALL_NPM_CONFIG_SECTION))
        .and_then(|value| value.as_table())
        .and_then(|table| {
            table.get(crate::npm_firewall_config::FIREWALL_NPM_POLICIES_CONFIG_SECTION)
        })
        .and_then(|value| value.as_table())
        .unwrap();
    assert_eq!(
        policies
            .get(crate::npm_firewall_config::LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY)
            .and_then(|value| value.as_str()),
        Some("warn")
    );
    assert_eq!(
        policies
            .get(crate::npm_firewall_config::LPM_AI_SUSPICIOUS_POLICY_KEY)
            .and_then(|value| value.as_str()),
        Some("allow")
    );
    assert!(
        !policies
            .contains_key(crate::npm_firewall_config::LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY)
    );
}

#[tokio::test]
async fn integrity_wizard_set_persists_each_valid_mode() {
    for mode in ["source", "tree"] {
        let (_dir, path, _env) = tmp_config();

        run_integrity_wizard(&path, Some(mode), true).await.unwrap();

        assert_eq!(
            read_integrity_policy(&path).unwrap(),
            Some(parse_integrity_policy_selection(mode).unwrap()),
            "integrity mode '{mode}' must persist",
        );
    }
}

#[tokio::test]
async fn integrity_wizard_set_rejects_invalid_mode_without_persisting() {
    let (_dir, path, _env) = tmp_config();

    let err = run_integrity_wizard(&path, Some("expanded"), true)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("invalid integrity mode 'expanded'; must be one of: source | tree"),
        "got: {msg}"
    );
    assert!(read_integrity_policy(&path).unwrap().is_none());
}

#[test]
fn resolve_object_integrity_policy_defaults_to_source() {
    let _env = crate::test_env::ScopedEnv::update([(
        lpm_store::v2::ENV_V2_OBJECT_INTEGRITY,
        None::<std::ffi::OsString>,
    )]);
    let cfg = GlobalConfig {
        table: toml::map::Map::new(),
    };

    assert_eq!(
        resolve_object_integrity_policy(&cfg).unwrap(),
        lpm_store::v2::ObjectIntegrityPolicy::Source,
    );
}

#[test]
fn resolve_object_integrity_policy_reads_config_tree() {
    let _env = crate::test_env::ScopedEnv::update([(
        lpm_store::v2::ENV_V2_OBJECT_INTEGRITY,
        None::<std::ffi::OsString>,
    )]);
    let mut table = toml::map::Map::new();
    table.insert(
        INTEGRITY_KEY.to_string(),
        toml::Value::String("tree".to_string()),
    );
    let cfg = GlobalConfig { table };

    assert_eq!(
        resolve_object_integrity_policy(&cfg).unwrap(),
        lpm_store::v2::ObjectIntegrityPolicy::Tree,
    );
}

#[test]
fn resolve_object_integrity_policy_prefers_env_override_over_config() {
    let _env = crate::test_env::ScopedEnv::update([(
        lpm_store::v2::ENV_V2_OBJECT_INTEGRITY,
        Some(std::ffi::OsString::from("source")),
    )]);
    let mut table = toml::map::Map::new();
    table.insert(
        INTEGRITY_KEY.to_string(),
        toml::Value::String("tree".to_string()),
    );
    let cfg = GlobalConfig { table };

    assert_eq!(
        resolve_object_integrity_policy(&cfg).unwrap(),
        lpm_store::v2::ObjectIntegrityPolicy::Source,
    );
}

// ── release-age wizard (--set path) ────────────────────────

#[tokio::test]
async fn release_age_wizard_set_persists_canonical_seconds_for_human_durations() {
    let (_dir, path, _env) = tmp_config();
    run_release_age_wizard(&path, Some("3d"), true)
        .await
        .unwrap();

    assert_eq!(read_release_age_override(&path).unwrap(), Some(259200));
    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    assert_eq!(
        table.get(RELEASE_AGE_KEY).and_then(|v| v.as_str()),
        Some("259200"),
        "release-age wizard should persist canonical seconds, not the raw duration string",
    );
}

#[tokio::test]
async fn release_age_wizard_set_accepts_off_alias_and_zero() {
    for value in ["off", "0"] {
        let (_dir, path, _env) = tmp_config();
        run_release_age_wizard(&path, Some(value), true)
            .await
            .unwrap();
        assert_eq!(
            read_release_age_override(&path).unwrap(),
            Some(0),
            "value '{value}' must persist as zero seconds",
        );
    }
}

#[tokio::test]
async fn release_age_wizard_set_default_deletes_existing_override() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "minimum-release-age-secs = \"259200\"\n").unwrap();

    run_release_age_wizard(&path, Some("default"), true)
        .await
        .unwrap();

    assert_eq!(read_release_age_override(&path).unwrap(), None);
    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    assert!(
        !table.contains_key(RELEASE_AGE_KEY),
        "default must remove the explicit global override",
    );
}

#[tokio::test]
async fn release_age_wizard_set_rejects_invalid_value() {
    let (_dir, path, _env) = tmp_config();
    let err = run_release_age_wizard(&path, Some("1w"), true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unsupported unit"), "got: {msg}");
    assert!(read_release_age_override(&path).unwrap().is_none());
}

#[tokio::test]
async fn release_age_wizard_set_rejects_lower_value_when_force_floor_enabled() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "force-security-floor = true\nminimum-release-age-secs = \"259200\"\n",
    )
    .unwrap();
    let err = run_release_age_wizard(&path, Some("0"), true)
        .await
        .unwrap_err();
    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains("minimum-release-age-secs"));
}

#[tokio::test]
async fn release_age_wizard_preserves_unrelated_keys() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "script-policy = \"triage\"\n").unwrap();

    run_release_age_wizard(&path, Some("12h"), true)
        .await
        .unwrap();

    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    assert_eq!(
        table.get("script-policy").and_then(|v| v.as_str()),
        Some("triage"),
    );
    assert_eq!(
        table.get(RELEASE_AGE_KEY).and_then(|v| v.as_str()),
        Some("43200"),
    );
}

#[tokio::test]
async fn grouped_release_age_save_persists_scope_and_minimum_age_together() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "registry = \"https://example.test\"\n").unwrap();

    persist_release_age_selection(
        &path,
        ReleaseAgeSelection::Seconds(CAUTIOUS_RELEASE_AGE_SECS),
        Some(crate::release_age_config::ReleaseAgePolicy::Strict),
        false,
        "lpm config release-age --set 3d",
    )
    .await
    .unwrap();

    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    assert_eq!(
        (
            table.get(RELEASE_AGE_KEY).and_then(toml::Value::as_str),
            table
                .get(RELEASE_AGE_POLICY_KEY)
                .and_then(toml::Value::as_str),
            table.get("registry").and_then(toml::Value::as_str),
        ),
        (Some("259200"), Some("strict"), Some("https://example.test"),)
    );
}

#[tokio::test]
async fn release_age_policy_wizard_set_persists_canonical_value() {
    let (_dir, path, _env) = tmp_config();

    run_release_age_policy_wizard(&path, Some("default"), true)
        .await
        .unwrap();

    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    assert_eq!(
        table.get(RELEASE_AGE_POLICY_KEY).and_then(|v| v.as_str()),
        Some("direct")
    );
}

#[tokio::test]
async fn release_age_policy_wizard_rejects_unknown_value() {
    let (_dir, path, _env) = tmp_config();

    let err = run_release_age_policy_wizard(&path, Some("transitive"), true)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(msg.contains("release-age-policy"), "got: {msg}");
    assert!(msg.contains("direct | strict"), "got: {msg}");
    assert!(!path.exists(), "invalid policy must not create config.toml");
}

#[tokio::test]
async fn release_age_policy_wizard_rejects_lower_value_when_force_floor_enabled() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "force-security-floor = true\nrelease-age-policy = \"strict\"\n",
    )
    .unwrap();

    let err = run_release_age_policy_wizard(&path, Some("direct"), true)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains("release-age-policy"));
}

#[test]
fn release_age_wizard_initial_choice_treats_explicit_one_day_as_custom() {
    assert_eq!(release_age_initial_choice(None), "default");
    assert_eq!(release_age_initial_choice(Some(0)), "off");
    assert_eq!(
        release_age_initial_choice(Some(CAUTIOUS_RELEASE_AGE_SECS)),
        "cautious"
    );
    assert_eq!(
        release_age_initial_choice(Some(86_400)),
        "custom",
        "explicit 1d override must stay distinguishable from true default",
    );
}

// ── sandbox wizard (rework) ─────────────────────────

#[tokio::test]
async fn sandbox_wizard_set_persists_each_valid_mode() {
    for mode in &["default", "strict", "none"] {
        let (_dir, path, _env) = tmp_config();
        run_sandbox_wizard(&path, Some(mode), true).await.unwrap();
        let v = read_sandbox_mode(&path).unwrap();
        assert_eq!(
            v.as_deref(),
            Some(*mode),
            "sandbox mode '{mode}' must persist",
        );
    }
}

#[tokio::test]
async fn sandbox_wizard_set_rejects_unknown_mode() {
    let (_dir, path, _env) = tmp_config();
    let err = run_sandbox_wizard(&path, Some("paranoid"), true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid sandbox mode 'paranoid'"),
        "got: {msg}",
    );
    // No persistence on validation failure.
    assert!(read_sandbox_mode(&path).unwrap().is_none());
}

#[tokio::test]
async fn sandbox_wizard_set_rejects_looser_mode_when_force_floor_enabled() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "force-security-floor = true\n[sandbox]\nmode = \"strict\"\n",
    )
    .unwrap();
    let err = run_sandbox_wizard(&path, Some("default"), true)
        .await
        .unwrap_err();
    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains("[sandbox].mode"));
}

#[tokio::test]
async fn sandbox_wizard_preserves_sibling_keys() {
    // The wizard writes `[sandbox] mode`; an existing
    // `[sandbox] allow-degraded` must survive.
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "unrelated = \"keep-me\"\n[sandbox]\nallow-degraded = true\n",
    )
    .unwrap();

    run_sandbox_wizard(&path, Some("strict"), true)
        .await
        .unwrap();

    let cfg = read_config(&path).unwrap();
    let top = cfg.as_table().unwrap();
    assert_eq!(
        top.get("unrelated").and_then(|v| v.as_str()),
        Some("keep-me"),
        "top-level sibling must survive",
    );
    let sandbox = top.get("sandbox").and_then(|v| v.as_table()).unwrap();
    assert_eq!(
        sandbox.get("mode").and_then(|v| v.as_str()),
        Some("strict"),
        "mode must be written",
    );
    assert_eq!(
        sandbox.get("allow-degraded").and_then(|v| v.as_bool()),
        Some(true),
        "sibling `allow-degraded` must survive — wizard must not clobber it",
    );
}

#[tokio::test]
async fn sandbox_wizard_refuses_to_clobber_non_table_sandbox_key() {
    // Defensive: if the user has somehow written `sandbox = "foo"` as
    // a top-level string, refuse rather than clobbering it into a
    // table. Honest error > silent migration on a typed config knob.
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "sandbox = \"not-a-table\"\n").unwrap();
    let posture_before = crate::security_approval::load_authorized_posture().unwrap();
    let err = run_sandbox_wizard(&path, Some("strict"), true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not a TOML table"), "got: {msg}");
    assert_eq!(
        crate::security_approval::load_authorized_posture().unwrap(),
        posture_before,
        "a failed config mutation must not change approved posture"
    );
}

#[tokio::test]
async fn sandbox_wizard_overwrites_existing_mode() {
    let (_dir, path, _env) = tmp_config();
    run_sandbox_wizard(&path, Some("default"), true)
        .await
        .unwrap();
    run_sandbox_wizard(&path, Some("strict"), true)
        .await
        .unwrap();
    assert_eq!(read_sandbox_mode(&path).unwrap().as_deref(), Some("strict"));
}

// ── GlobalConfig::get_sigstore_verify ──────────────────────

/// `[sigstore].verify` resolves to the right string. Pin both
/// the table layout (nested, not flat `sigstore-verify`) and the
/// returned value so a future wizard wired to a different key
/// path fails this test loudly. (Wizard write path + config
/// reader MUST agree on the nested-table key shape — if either
/// drifts, the wizard appears to succeed but installs ignore
/// the persisted value.)
#[test]
fn global_config_get_sigstore_verify_returns_string_when_present() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "[sigstore]\nverify = \"warn\"\n").unwrap();
    let toml_val = read_config(&path).unwrap();
    let table = match toml_val {
        toml::Value::Table(t) => t,
        _ => panic!("expected top-level table"),
    };
    let cfg = GlobalConfig { table };
    assert_eq!(cfg.get_sigstore_verify().as_deref(), Some("warn"));
}

/// Absent table → `None`. Distinguishes "operator hasn't set it"
/// from "operator set it to a known bad value" so the precedence
/// chain in `EnforceMode::resolve_from_chain` can fall through.
#[test]
fn global_config_get_sigstore_verify_returns_none_when_absent() {
    let cfg = GlobalConfig::empty();
    assert!(cfg.get_sigstore_verify().is_none());
}

/// Non-string (e.g. accidentally wrote a bool) → `None`. The
/// `EnforceMode` parser handles unknown strings with a
/// tracing::warn; this layer just signals "no usable value".
#[test]
fn global_config_get_sigstore_verify_returns_none_for_non_string_value() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "[sigstore]\nverify = true\n").unwrap();
    let toml_val = read_config(&path).unwrap();
    let table = match toml_val {
        toml::Value::Table(t) => t,
        _ => panic!("expected top-level table"),
    };
    let cfg = GlobalConfig { table };
    assert!(cfg.get_sigstore_verify().is_none());
}

#[test]
fn global_config_load_checked_rejects_malformed_config() {
    let dir = TempDir::new().expect("tempdir");
    let _env = crate::test_env::ScopedEnv::set([("LPM_HOME", dir.path().as_os_str().to_owned())]);
    std::fs::write(
        dir.path().join("config.toml"),
        "[firewall\nmode = \"enforce\"\n",
    )
    .unwrap();

    let Err(err) = GlobalConfig::load_checked() else {
        panic!("malformed config must fail checked load");
    };

    assert!(
        err.to_string().contains("config parse error"),
        "unexpected error: {err}"
    );
}

// ── lpm config sigstore wizard (--set path) ────────────────

/// `--set deny|warn|off` persists into `[sigstore] verify` and
/// round-trips through `read_sigstore_verify`. Three values, one
/// test — keeps the persistence-shape contract pinned in one
/// place.
#[tokio::test]
async fn sigstore_wizard_set_persists_each_valid_value() {
    for v in ["deny", "warn", "off"] {
        let (_dir, path, _env) = tmp_config();
        run_sigstore_wizard(&path, Some(v), true).await.unwrap();
        assert_eq!(
            read_sigstore_verify(&path).unwrap().as_deref(),
            Some(v),
            "value '{v}' must round-trip through [sigstore] verify",
        );
    }
}

#[tokio::test]
async fn sigstore_wizard_set_persists_scope_and_availability() {
    let (_dir, path, _env) = tmp_config();

    run_sigstore_wizard(&path, Some("scope=all"), true)
        .await
        .unwrap();
    run_sigstore_wizard(&path, Some("availability=strict"), true)
        .await
        .unwrap();

    assert_eq!(read_sigstore_scope(&path).unwrap().as_deref(), Some("all"));
    assert_eq!(
        read_sigstore_availability(&path).unwrap().as_deref(),
        Some("strict")
    );
    assert!(
        read_sigstore_verify(&path).unwrap().is_none(),
        "setting opt-in scope and availability must not materialize or change verify"
    );
}

#[tokio::test]
async fn sigstore_wizard_set_rejects_invalid_scope_without_mutating_config() {
    let (_dir, path, _env) = tmp_config();

    let error = run_sigstore_wizard(&path, Some("scope=trusted-ish"), true)
        .await
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("invalid sigstore scope mode 'trusted-ish'")
    );
    assert!(read_sigstore_scope(&path).unwrap().is_none());
}

/// `--set <unknown>` errors with a message that lists the three
/// valid values so the operator can self-correct without
/// consulting docs.
#[tokio::test]
async fn sigstore_wizard_set_rejects_invalid_value() {
    let (_dir, path, _env) = tmp_config();
    let err = run_sigstore_wizard(&path, Some("yolo"), true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid sigstore verify mode 'yolo'"),
        "got: {msg}"
    );
    assert!(
        msg.contains("deny"),
        "error must list 'deny' as a valid value: {msg}"
    );
    assert!(
        msg.contains("warn"),
        "error must list 'warn' as a valid value: {msg}"
    );
    assert!(
        msg.contains("off"),
        "error must list 'off' as a valid value: {msg}"
    );
    // Nothing persisted on validation failure.
    assert!(read_sigstore_verify(&path).unwrap().is_none());
}

#[tokio::test]
async fn sigstore_wizard_set_rejects_looser_value_when_force_floor_enabled() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
        &path,
        "force-security-floor = true\n[sigstore]\nverify = \"deny\"\n",
    )
    .unwrap();
    let err = run_sigstore_wizard(&path, Some("warn"), true)
        .await
        .unwrap_err();
    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains("[sigstore].verify"));
}

#[test]
fn guard_generic_set_rejects_disabling_force_floor_when_enabled() {
    let config = global_config("force-security-floor = true\n");
    let err = guard_generic_set_against_force_floor(&config, "force-security-floor", "false")
        .unwrap_err();
    assert_eq!(err.error_code(), "security_floor");
}

#[test]
fn guard_generic_set_rejects_case_insensitive_source_analysis_disable_under_force_floor() {
    let config =
        global_config("force-security-floor = true\ninstall-time-source-analysis = true\n");
    let err =
        guard_generic_set_against_force_floor(&config, INSTALL_TIME_SOURCE_ANALYSIS_KEY, " FALSE ")
            .unwrap_err();

    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains(INSTALL_TIME_SOURCE_ANALYSIS_KEY));
}

#[test]
fn guard_generic_delete_rejects_lowering_release_age_to_default() {
    let config =
        global_config("force-security-floor = true\nminimum-release-age-secs = \"259200\"\n");
    let err = guard_generic_delete_against_force_floor(&config, RELEASE_AGE_KEY).unwrap_err();
    assert_eq!(err.error_code(), "security_floor");
}

#[test]
fn guard_generic_delete_rejects_unsetting_force_floor_when_enabled() {
    let config = global_config("force-security-floor = true\n");
    let err =
        guard_generic_delete_against_force_floor(&config, "force-security-floor").unwrap_err();
    assert_eq!(err.error_code(), "security_floor");
}

#[test]
fn guard_generic_delete_rejects_unsetting_enabled_typosquat_guard_under_force_floor() {
    let config = global_config("force-security-floor = true\ntyposquat-guard = \"on\"\n");

    let err = guard_generic_delete_against_force_floor(&config, TYPOSQUAT_GUARD_KEY).unwrap_err();

    assert_eq!(err.error_code(), "security_floor");
    assert!(err.to_string().contains(TYPOSQUAT_GUARD_KEY));
}

#[test]
fn guard_generic_delete_allows_removing_disabled_typosquat_guard_under_force_floor() {
    let config = global_config("force-security-floor = true\ntyposquat-guard = \"off\"\n");

    guard_generic_delete_against_force_floor(&config, TYPOSQUAT_GUARD_KEY).unwrap();
}

/// JSON envelope shape for the announce-set path — mirrors the
/// sandbox / scripts wizards so agents can branch on the same
/// `{success, sigstore: {verify}}` field structure.
#[tokio::test]
async fn sigstore_wizard_json_envelope_shape() {
    let (_dir, path, _env) = tmp_config();
    // Capturing stdout cleanly in a unit test is awkward; this test
    // pins that `--set` + json_output returns Ok and the
    // persistence still happens. The envelope shape itself is
    // pinned by hand-inspection of `announce_sigstore_set`.
    run_sigstore_wizard(&path, Some("warn"), true)
        .await
        .expect("--set with json_output=true must not error");
    assert_eq!(
        read_sigstore_verify(&path).unwrap().as_deref(),
        Some("warn"),
        "JSON path must still persist before announcing",
    );
}

/// Persisting sigstore.verify must not clobber sibling keys
/// under `[sigstore]` (room for future trust-root overrides, etc.)
/// nor unrelated top-level entries. This is the same defensive
/// guarantee the sandbox wizard pins.
#[tokio::test]
async fn sigstore_wizard_preserves_other_keys() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(
            &path,
            "script-policy = \"triage\"\n\n[sandbox]\nmode = \"strict\"\n\n[sigstore]\ntrust-root-override = \"/path/to/custom-root.json\"\n",
        )
        .unwrap();
    run_sigstore_wizard(&path, Some("off"), true).await.unwrap();

    let cfg = read_config(&path).unwrap();
    let table = cfg.as_table().unwrap();
    // Sigstore verify landed.
    assert_eq!(
        table
            .get("sigstore")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("verify"))
            .and_then(|v| v.as_str()),
        Some("off"),
    );
    // Sibling [sigstore].trust-root-override preserved.
    assert_eq!(
        table
            .get("sigstore")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("trust-root-override"))
            .and_then(|v| v.as_str()),
        Some("/path/to/custom-root.json"),
        "sibling [sigstore] keys must survive — wizard must not clobber them",
    );
    // Unrelated top-level keys preserved.
    assert_eq!(
        table.get("script-policy").and_then(|v| v.as_str()),
        Some("triage"),
    );
    assert_eq!(
        table
            .get("sandbox")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("mode"))
            .and_then(|v| v.as_str()),
        Some("strict"),
    );
}

/// Defensive: refuse to clobber a non-table `sigstore` top-level
/// value (operator wrote `sigstore = "foo"`). Honest error >
/// silent migration on a typed config knob. Mirrors the
/// sandbox wizard's equivalent guard.
#[tokio::test]
async fn sigstore_wizard_refuses_to_clobber_non_table_sigstore_key() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "sigstore = \"not-a-table\"\n").unwrap();
    let posture_before = crate::security_approval::load_authorized_posture().unwrap();
    let err = run_sigstore_wizard(&path, Some("warn"), true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not a TOML table"), "got: {msg}");
    assert_eq!(
        crate::security_approval::load_authorized_posture().unwrap(),
        posture_before,
        "a failed config mutation must not change approved posture"
    );
}

#[tokio::test]
async fn firewall_setter_refuses_non_table_without_changing_approved_posture() {
    let (_dir, path, _env) = tmp_config();
    std::fs::write(&path, "firewall = \"not-a-table\"\n").unwrap();
    let posture_before = crate::security_approval::load_authorized_posture().unwrap();

    let err = apply_firewall_mode(
        &path,
        NpmFirewallMode::Enforce,
        true,
        "lpm config firewall --set enforce",
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("not a TOML table"));
    assert_eq!(
        crate::security_approval::load_authorized_posture().unwrap(),
        posture_before,
        "a failed config mutation must not change approved posture"
    );
}

#[tokio::test]
async fn failed_oversized_config_write_does_not_change_approved_posture() {
    let (_dir, path, _env) = tmp_config();
    let suffix = "\"\n[sandbox]\nmode = \"none\"\n";
    let prefix = "payload = \"";
    let payload_len = lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize - prefix.len() - suffix.len();
    let content = format!("{prefix}{}{suffix}", "x".repeat(payload_len));
    assert_eq!(content.len() as u64, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES);
    std::fs::write(&path, &content).unwrap();
    let posture_before = crate::security_approval::load_authorized_posture().unwrap();

    let err = apply_sandbox_mode(&path, "strict", true, "lpm config sandbox --set strict")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exceed"), "got: {err}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
    assert_eq!(
        crate::security_approval::load_authorized_posture().unwrap(),
        posture_before,
        "a rejected config write must roll back approved posture"
    );
}

/// Overwrite path: setting twice must end on the second value.
/// Pins idempotent re-runs.
#[tokio::test]
async fn sigstore_wizard_overwrites_existing_value() {
    let (_dir, path, _env) = tmp_config();
    run_sigstore_wizard(&path, Some("warn"), true)
        .await
        .unwrap();
    run_sigstore_wizard(&path, Some("deny"), true)
        .await
        .unwrap();
    assert_eq!(
        read_sigstore_verify(&path).unwrap().as_deref(),
        Some("deny"),
    );
}
