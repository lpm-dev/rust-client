use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use lpm_common::LpmError;

use super::GlobalConfig;
use crate::commands::install::policy_extensions::load_policy_extension_configs;
use crate::precedence::{PolicyTier, PurePolicyKnob};
use crate::security_approval::{EffectiveAuthorizedPosture, PostureSourceKind};

const DEFAULT_SOURCE: &str = "built-in default";
const USER_SOURCE: &str = "~/.lpm/config.toml";
const PROJECT_TOML_SOURCE: &str = "lpm.toml";
const PACKAGE_JSON_SOURCE: &str = "package.json > lpm";

const GROUP_SAVE: &str = "Dependency saving";
const GROUP_SCRIPTS: &str = "Lifecycle scripts";
const GROUP_SECURITY: &str = "Supply-chain security";
const GROUP_INSTALL: &str = "Installation";
const GROUP_WORKSPACE: &str = "Workspaces";
const GROUP_NETWORK: &str = "Network";
const GROUP_EXTENSIONS: &str = "Local policy extensions";
const GROUP_ADDITIONAL: &str = "Additional saved values";

const STATIC_CONFIG_ENTRY_COUNT: usize = 34;
const LEGACY_CONFIG_PATHS: &[&str] = &["firewall.npm.policies.static_only_suspicious", "noSkills"];

#[derive(Debug)]
pub(super) struct EffectiveConfig {
    entries: Vec<EffectiveConfigEntry>,
}

#[derive(Debug)]
struct EffectiveConfigEntry {
    key: String,
    value: serde_json::Value,
    source: String,
    group: &'static str,
}

impl EffectiveConfigEntry {
    fn new(
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
        source: impl Into<String>,
        group: &'static str,
    ) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            source: source.into(),
            group,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "group": self.group,
        })
    }
}

impl EffectiveConfig {
    pub(super) fn load(current_dir: &Path) -> Result<Self, LpmError> {
        let project_dir = lpm_workspace::find_project_root(current_dir)
            .unwrap_or_else(|| current_dir.to_path_buf());
        let global = GlobalConfig::load_checked()?;
        let project_toml = read_optional_toml_table(&project_dir.join("lpm.toml"))?;
        let (package_json, package_json_value) = read_package_json(&project_dir)?;
        let script_config =
            crate::script_policy_config::ScriptPolicyConfig::try_from_package_json(&project_dir)?;
        if let Some(invalid) = script_config.policy_parse_error.as_deref() {
            return Err(LpmError::Registry(format!(
                "invalid package.json > lpm > scriptPolicy value `{invalid}`"
            )));
        }
        let posture = crate::security_approval::load_effective_authorized_posture()?;
        let workspace = lpm_workspace::discover_workspace(&project_dir)
            .map_err(|error| LpmError::Workspace(error.to_string()))?;
        let workspace_root = workspace
            .as_ref()
            .map_or(project_dir.as_path(), |workspace| workspace.root.as_path());
        let root_package = workspace
            .as_ref()
            .map_or(&package_json, |workspace| &workspace.root_package);

        let mut entries = Vec::with_capacity(STATIC_CONFIG_ENTRY_COUNT + 8);
        add_save_entries(&mut entries, &project_dir, &project_toml, &global)?;
        add_script_entries(
            &mut entries,
            &project_dir,
            &project_toml,
            &package_json_value,
            &script_config,
            &global,
            &posture,
        )?;
        add_security_entries(
            &mut entries,
            &package_json,
            &package_json_value,
            &global,
            &posture,
        )?;
        add_install_entries(
            &mut entries,
            &project_dir,
            &package_json,
            root_package,
            &global,
        )?;
        add_workspace_entry(&mut entries, workspace_root, &global)?;
        add_network_entry(&mut entries, &global);
        add_policy_extension_entries(&mut entries, &global)?;
        add_unknown_saved_entries(&mut entries, &global);

        Ok(Self { entries })
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        let entries: Vec<_> = self
            .entries
            .iter()
            .map(EffectiveConfigEntry::to_json)
            .collect();
        serde_json::json!({
            "success": true,
            "action": "list",
            "count": entries.len(),
            "entries": entries,
        })
    }

    pub(super) fn print_human(&self) {
        let mut current_group = None;
        for entry in &self.entries {
            if current_group != Some(entry.group) {
                if current_group.is_some() {
                    println!();
                }
                println!("{}", crate::install_ui::bold(entry.group));
                println!("  {:<58} {:<24} SOURCE", "KEY", "VALUE");
                current_group = Some(entry.group);
            }
            let key = lpm_common::sanitize_terminal_inline(&entry.key);
            let display_value = display_json_value(&entry.value);
            let value = lpm_common::sanitize_terminal_inline(&display_value);
            let source = lpm_common::sanitize_terminal_inline(&entry.source);
            println!("  {key:<58} {value:<24} {source}");
        }
    }
}

fn add_save_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    project_dir: &Path,
    project: &toml::map::Map<String, toml::Value>,
    global: &GlobalConfig,
) -> Result<(), LpmError> {
    let config = crate::save_config::SaveConfigLoader::load_for_project(project_dir)?;
    let prefix = config
        .save_prefix
        .unwrap_or(crate::save_spec::SavePrefix::Caret)
        .as_str();
    entries.push(EffectiveConfigEntry::new(
        "save-prefix",
        prefix,
        first_source(
            project.contains_key("save-prefix"),
            global.get_value("save-prefix").is_some(),
        ),
        GROUP_SAVE,
    ));
    entries.push(EffectiveConfigEntry::new(
        "save-exact",
        config.save_exact,
        first_source(
            project.contains_key("save-exact"),
            global.get_value("save-exact").is_some(),
        ),
        GROUP_SAVE,
    ));
    Ok(())
}

fn add_script_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    project_dir: &Path,
    project: &toml::map::Map<String, toml::Value>,
    package_json: &serde_json::Value,
    script_config: &crate::script_policy_config::ScriptPolicyConfig,
    global: &GlobalConfig,
    posture: &EffectiveAuthorizedPosture,
) -> Result<(), LpmError> {
    if let Some(value) = global.get_value("script-policy") {
        let raw = value.as_str().ok_or_else(|| {
            LpmError::Registry("`script-policy` in ~/.lpm/config.toml must be a string".to_string())
        })?;
        crate::script_policy_config::ScriptPolicy::parse(raw)
            .map_err(|error| LpmError::Registry(error.to_string()))?;
    }
    let resolution = crate::script_policy_config::resolve_script_policy_raw(None, script_config);
    let candidate_source = policy_source(resolution.effective_source);
    let (script_policy, script_source) = select_security_value(
        resolution.effective,
        candidate_source,
        posture.posture.script_policy(),
        posture.sources.script_policy,
        |candidate, floor| candidate.loosens(floor),
    );
    entries.push(EffectiveConfigEntry::new(
        "script-policy",
        script_policy.as_str(),
        script_source,
        GROUP_SCRIPTS,
    ));

    let (advisor, advisor_source) = if let Some(value) = script_config.triage_advisor.as_deref() {
        (value, PACKAGE_JSON_SOURCE)
    } else if let Some(value) = global.get_str("triage-advisor") {
        (value, USER_SOURCE)
    } else {
        ("none", DEFAULT_SOURCE)
    };
    entries.push(EffectiveConfigEntry::new(
        "triage-advisor",
        advisor,
        advisor_source,
        GROUP_SCRIPTS,
    ));

    let (sandbox_options, sandbox_mode) =
        crate::sandbox_config::load_sandbox_options_with_mode(project_dir)?;
    let env_strict = env_bool("LPM_STRICT_SANDBOX") == Some(true);
    let candidate_mode = if env_strict {
        crate::sandbox_config::ResolvedSandboxMode::Strict
    } else {
        sandbox_mode
    };
    let candidate_mode_source = if env_strict {
        "LPM_STRICT_SANDBOX"
    } else {
        nested_source(project, &global.table, &["sandbox", "mode"])
    };
    let (sandbox_mode, sandbox_mode_source) = select_security_value(
        candidate_mode,
        candidate_mode_source,
        posture.posture.sandbox_mode(),
        posture.sources.sandbox_mode,
        |candidate, floor| candidate.loosens(floor),
    );
    entries.push(EffectiveConfigEntry::new(
        "sandbox.mode",
        sandbox_mode.as_str(),
        sandbox_mode_source,
        GROUP_SCRIPTS,
    ));

    let allow_degraded_source =
        nested_source(project, &global.table, &["sandbox", "allow-degraded"]);
    let (allow_degraded, allow_degraded_source) = select_security_value(
        sandbox_options.allow_degraded,
        allow_degraded_source,
        posture.posture.sandbox_allow_degraded(),
        posture.sources.sandbox_allow_degraded,
        |candidate, floor| candidate && !floor,
    );
    entries.push(EffectiveConfigEntry::new(
        "sandbox.allow-degraded",
        allow_degraded,
        allow_degraded_source,
        GROUP_SCRIPTS,
    ));

    let user_read_allow = read_string_array(global, "script-read-allow")?;
    let project_read_allow = package_json
        .pointer("/lpm/scripts/sandboxReadAllow")
        .map(|value| json_string_array(value, "package.json > lpm > scripts > sandboxReadAllow"))
        .transpose()?
        .unwrap_or_default();
    lpm_sandbox::load_sandbox_read_allow(
        &project_dir.join("package.json"),
        project_dir,
        &user_read_allow,
    )
    .map_err(|error| LpmError::Registry(error.to_string()))?;
    let read_allow = merge_unique(project_read_allow, user_read_allow);
    let read_allow_source = merged_source([
        package_json
            .pointer("/lpm/scripts/sandboxReadAllow")
            .is_some()
            .then_some(PACKAGE_JSON_SOURCE),
        global
            .get_value("script-read-allow")
            .is_some()
            .then_some(USER_SOURCE),
    ]);
    entries.push(EffectiveConfigEntry::new(
        "script-read-allow",
        serde_json::json!(read_allow),
        read_allow_source,
        GROUP_SCRIPTS,
    ));

    let max_write_roots = effective_max_write_roots(global)?;
    entries.push(EffectiveConfigEntry::new(
        "max-sandbox-write-roots",
        serde_json::json!(max_write_roots),
        if global.get_value("max-sandbox-write-roots").is_some() {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        GROUP_SCRIPTS,
    ));
    Ok(())
}

fn add_security_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    package: &lpm_workspace::PackageJson,
    package_json: &serde_json::Value,
    global: &GlobalConfig,
    posture: &EffectiveAuthorizedPosture,
) -> Result<(), LpmError> {
    let lpm = package.lpm.as_ref();
    let global_release_age = read_optional_u64(global, "minimum-release-age-secs")?;
    let (candidate_age, candidate_age_source) =
        if let Some(value) = lpm.and_then(|lpm| lpm.minimum_release_age) {
            (value, PACKAGE_JSON_SOURCE)
        } else if let Some(value) = global_release_age {
            (value, USER_SOURCE)
        } else {
            (
                crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS,
                DEFAULT_SOURCE,
            )
        };
    let (release_age, release_age_source) = select_security_value(
        candidate_age,
        candidate_age_source,
        posture.posture.minimum_release_age_secs(),
        posture.sources.minimum_release_age_secs,
        |candidate, floor| candidate < floor,
    );
    entries.push(EffectiveConfigEntry::new(
        "minimum-release-age-secs",
        release_age,
        release_age_source,
        GROUP_SECURITY,
    ));

    let project_policy = lpm
        .and_then(|lpm| lpm.minimum_release_age_policy.as_deref())
        .map(|raw| {
            crate::release_age_config::ReleaseAgePolicy::parse(
                "package.json > lpm > minimumReleaseAgePolicy",
                raw,
            )
        })
        .transpose()?;
    let global_policy = global
        .get_value(crate::release_age_config::GLOBAL_POLICY_KEY)
        .map(|value| {
            value.as_str().ok_or_else(|| {
                LpmError::Registry(
                    "`release-age-policy` in ~/.lpm/config.toml must be a string".to_string(),
                )
            })
        })
        .transpose()?
        .map(|raw| {
            crate::release_age_config::ReleaseAgePolicy::parse(
                "~/.lpm/config.toml > release-age-policy",
                raw,
            )
        })
        .transpose()?;
    let (candidate_policy, candidate_policy_source) = if let Some(value) = project_policy {
        (value, PACKAGE_JSON_SOURCE)
    } else if let Some(value) = global_policy {
        (value, USER_SOURCE)
    } else {
        (
            crate::release_age_config::ReleaseAgePolicy::Direct,
            DEFAULT_SOURCE,
        )
    };
    let (release_policy, release_policy_source) = select_security_value(
        candidate_policy,
        candidate_policy_source,
        posture.posture.release_age_policy(),
        posture.sources.release_age_policy,
        |candidate, floor| candidate.loosens(floor),
    );
    entries.push(EffectiveConfigEntry::new(
        "release-age-policy",
        release_policy.as_str(),
        release_policy_source,
        GROUP_SECURITY,
    ));

    let project_excludes = lpm
        .map(|lpm| lpm.minimum_release_age_exclude.clone())
        .unwrap_or_default();
    let global_excludes = read_string_array(global, "minimum-release-age-exclude")?;
    let project_excludes = crate::release_age_config::validate_release_age_excludes(
        "package.json > lpm > minimumReleaseAgeExclude",
        &project_excludes,
    )?;
    let global_excludes = crate::release_age_config::validate_release_age_excludes(
        "~/.lpm/config.toml > minimum-release-age-exclude",
        &global_excludes,
    )?;
    let excludes = merge_unique(project_excludes, global_excludes);
    let excludes_source = merged_source([
        package_json
            .pointer("/lpm/minimumReleaseAgeExclude")
            .is_some()
            .then_some(PACKAGE_JSON_SOURCE),
        global
            .get_value("minimum-release-age-exclude")
            .is_some()
            .then_some(USER_SOURCE),
    ]);
    entries.push(EffectiveConfigEntry::new(
        "minimum-release-age-exclude",
        serde_json::json!(excludes),
        excludes_source,
        GROUP_SECURITY,
    ));

    let env_sigstore = std::env::var("LPM_PROVENANCE_ENFORCE").ok();
    validate_sigstore_verify(global)?;
    let (candidate_sigstore, sigstore_source_kind) =
        crate::provenance_fetch::EnforceMode::resolve_from_chain(env_sigstore.as_deref(), || {
            global.get_sigstore_verify()
        });
    let candidate_sigstore_source = match sigstore_source_kind {
        crate::provenance_fetch::EnforceModeSource::Env => "LPM_PROVENANCE_ENFORCE",
        crate::provenance_fetch::EnforceModeSource::Config => USER_SOURCE,
        crate::provenance_fetch::EnforceModeSource::Default => DEFAULT_SOURCE,
    };
    let (sigstore, sigstore_source) = select_security_value(
        candidate_sigstore,
        candidate_sigstore_source,
        posture.posture.sigstore_verify(),
        posture.sources.sigstore_verify,
        crate::security_floor::sigstore_loosens,
    );
    entries.push(EffectiveConfigEntry::new(
        "sigstore.verify",
        crate::security_floor::sigstore_mode_name(sigstore),
        sigstore_source,
        GROUP_SECURITY,
    ));

    let sigstore_scope = crate::provenance_fetch::VerificationScope::from_config(
        global.get_sigstore_scope().as_deref(),
    )?;
    entries.push(EffectiveConfigEntry::new(
        "sigstore.scope",
        if sigstore_scope.verifies_all() {
            "all"
        } else {
            "approved"
        },
        nested_source(
            &toml::map::Map::new(),
            &global.table,
            &["sigstore", "scope"],
        ),
        GROUP_SECURITY,
    ));
    let sigstore_availability = crate::provenance_fetch::AvailabilityMode::from_config(
        global.get_sigstore_availability().as_deref(),
    )?;
    entries.push(EffectiveConfigEntry::new(
        "sigstore.availability",
        if sigstore_availability.is_strict() {
            "strict"
        } else {
            "best-effort"
        },
        nested_source(
            &toml::map::Map::new(),
            &global.table,
            &["sigstore", "availability"],
        ),
        GROUP_SECURITY,
    ));

    let signatures_env = std::env::var("LPM_VERIFY_REGISTRY_SIGNATURES").ok();
    let signatures = signatures_env.as_deref().map_or_else(
        || global.get_bool("signatures").unwrap_or(false),
        |value| parse_bool_text(value).unwrap_or(false),
    );
    let signatures_source = if signatures_env.is_some() {
        "LPM_VERIFY_REGISTRY_SIGNATURES"
    } else if global.get_bool("signatures").is_some() {
        USER_SOURCE
    } else {
        DEFAULT_SOURCE
    };
    entries.push(EffectiveConfigEntry::new(
        "signatures",
        signatures,
        signatures_source,
        GROUP_SECURITY,
    ));

    let configured_trust_policy = global.get_trust_policy();
    let trust_policy_source = if configured_trust_policy.is_some() {
        USER_SOURCE
    } else {
        DEFAULT_SOURCE
    };
    let trust_policy = configured_trust_policy.unwrap_or_else(|| "off".to_string());
    entries.push(EffectiveConfigEntry::new(
        "trust-policy",
        trust_policy,
        trust_policy_source,
        GROUP_SECURITY,
    ));

    let config_typosquat = global.get_typosquat_guard_mode();
    let env_typosquat_off = env_bool("LPM_TYPOSQUAT_GUARD") == Some(false);
    let (typosquat, typosquat_source) = if let Some(candidate) = config_typosquat {
        select_security_value(
            candidate,
            USER_SOURCE,
            posture.posture.typosquat_guard(),
            posture.sources.typosquat_guard,
            |candidate, floor| candidate.loosens(floor),
        )
    } else if env_typosquat_off
        && !crate::security_floor::force_security_floor_enabled(global)
        && !matches!(
            posture.sources.typosquat_guard,
            PostureSourceKind::ManagedPolicy
        )
    {
        (
            crate::commands::config::TyposquatGuardSelection::Off,
            "LPM_TYPOSQUAT_GUARD".to_string(),
        )
    } else if !matches!(
        posture.sources.typosquat_guard,
        PostureSourceKind::BuiltinDefault
    ) {
        (
            posture.posture.typosquat_guard(),
            posture_source(posture.sources.typosquat_guard).to_string(),
        )
    } else {
        (
            crate::commands::config::TyposquatGuardSelection::Default,
            DEFAULT_SOURCE.to_string(),
        )
    };
    entries.push(EffectiveConfigEntry::new(
        "typosquat-guard",
        typosquat.as_str(),
        typosquat_source,
        GROUP_SECURITY,
    ));

    let config_firewall = crate::npm_firewall_config::config_mode(global)?;
    let env_firewall = crate::npm_firewall_config::env_mode()?;
    let firewall_env_source = if std::env::var_os("LPM_NPM_FIREWALL").is_some() {
        "LPM_NPM_FIREWALL"
    } else {
        "LPM_EXPERIMENT_NPM_FIREWALL"
    };
    let combined_firewall_source = format!("{USER_SOURCE} + {firewall_env_source}");
    let (candidate_firewall, candidate_firewall_source) = match (config_firewall, env_firewall) {
        (Some(config), Some(env)) => (config.stricter(env), combined_firewall_source.as_str()),
        (Some(config), None) => (config, USER_SOURCE),
        (None, Some(env)) => (env, firewall_env_source),
        (None, None) => (
            posture.posture.firewall_mode(),
            posture_source(posture.sources.firewall_mode),
        ),
    };
    let (firewall, firewall_source) = select_security_value(
        candidate_firewall,
        candidate_firewall_source,
        posture.posture.firewall_mode(),
        posture.sources.firewall_mode,
        |candidate, floor| candidate.loosens(floor),
    );
    entries.push(EffectiveConfigEntry::new(
        "firewall.mode",
        firewall.as_str(),
        firewall_source,
        GROUP_SECURITY,
    ));
    add_firewall_policy_entries(entries, global)?;

    let integrity = crate::commands::config::resolve_object_integrity_policy(global)?;
    entries.push(EffectiveConfigEntry::new(
        "integrity",
        integrity.as_str(),
        if std::env::var_os(lpm_store::v2::ENV_V2_OBJECT_INTEGRITY).is_some() {
            lpm_store::v2::ENV_V2_OBJECT_INTEGRITY
        } else if global.get_value("integrity").is_some() {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        GROUP_SECURITY,
    ));

    let source_analysis = crate::source_analysis_config::read_install_time_source_analysis(global)?;
    let (source_analysis, source_analysis_source) = select_security_value(
        source_analysis,
        if global
            .get_value(crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY)
            .is_some()
        {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        posture.posture.install_time_source_analysis(),
        posture.sources.install_time_source_analysis,
        |candidate, floor| !candidate && floor,
    );
    entries.push(EffectiveConfigEntry::new(
        crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY,
        source_analysis,
        source_analysis_source,
        GROUP_SECURITY,
    ));
    let insights = crate::lpm_insights_config::read_fetch_lpm_security_insights(global)?;
    entries.push(EffectiveConfigEntry::new(
        crate::lpm_insights_config::FETCH_LPM_SECURITY_INSIGHTS_KEY,
        insights,
        if global
            .get_value(crate::lpm_insights_config::FETCH_LPM_SECURITY_INSIGHTS_KEY)
            .is_some()
        {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        GROUP_SECURITY,
    ));
    Ok(())
}

fn add_firewall_policy_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    global: &GlobalConfig,
) -> Result<(), LpmError> {
    let profile = crate::npm_firewall_config::config_policy_profile(global)?;
    let policies = global
        .get_table("firewall")
        .and_then(|table| table.get("npm"))
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("policies"))
        .and_then(toml::Value::as_table);
    let policy_source = |key: &str| {
        if policies.is_some_and(|policies| policies.contains_key(key)) {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        }
    };
    let values = [
        (
            "trusted_public_malicious_advisories",
            profile.trusted_public_malicious_advisories,
        ),
        ("lpm_ai_confirmed_malware", profile.lpm_ai_confirmed_malware),
        (
            "lpm_ai_agent_control_surface",
            profile.lpm_ai_agent_control_surface,
        ),
        ("critical_vulnerability", profile.critical_vulnerability),
        ("lpm_ai_suspicious", profile.lpm_ai_suspicious),
    ];
    for (key, value) in values {
        let source = if key == "lpm_ai_suspicious"
            && policies.is_some_and(|policies| {
                policies.contains_key(
                    crate::npm_firewall_config::LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY,
                )
            }) {
            USER_SOURCE
        } else {
            policy_source(key)
        };
        entries.push(EffectiveConfigEntry::new(
            format!("firewall.npm.policies.{key}"),
            value.as_str(),
            source,
            GROUP_SECURITY,
        ));
    }
    Ok(())
}

fn add_install_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    project_dir: &Path,
    package: &lpm_workspace::PackageJson,
    root_package: &lpm_workspace::PackageJson,
    global: &GlobalConfig,
) -> Result<(), LpmError> {
    let root_lpm = root_package.lpm.as_ref();
    let engine_strict = crate::engine_strict_config::resolve_for_root(false, root_package);
    entries.push(EffectiveConfigEntry::new(
        "engine-strict",
        engine_strict,
        if root_lpm.and_then(|lpm| lpm.engine_strict).is_some() {
            PACKAGE_JSON_SOURCE
        } else if global.get_bool("engine-strict").is_some() {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        GROUP_INSTALL,
    ));

    let lpm = package.lpm.as_ref();
    let strict_peers = lpm
        .and_then(|lpm| lpm.strict_peer_dependencies)
        .or_else(|| global.get_bool("strict-peer-dependencies"))
        .unwrap_or(false);
    entries.push(EffectiveConfigEntry::new(
        "strict-peer-dependencies",
        strict_peers,
        if lpm.and_then(|lpm| lpm.strict_peer_dependencies).is_some() {
            PACKAGE_JSON_SOURCE
        } else if global.get_bool("strict-peer-dependencies").is_some() {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        GROUP_INSTALL,
    ));
    let auto_peers = lpm
        .and_then(|lpm| lpm.auto_install_peers)
        .or_else(|| global.get_bool("auto-install-peers"))
        .unwrap_or(true);
    entries.push(EffectiveConfigEntry::new(
        "auto-install-peers",
        auto_peers,
        if lpm.and_then(|lpm| lpm.auto_install_peers).is_some() {
            PACKAGE_JSON_SOURCE
        } else if global.get_bool("auto-install-peers").is_some() {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        GROUP_INSTALL,
    ));

    let skills = crate::lpm_skills_config::LpmSkillsPreference::Config.resolve(global)?;
    let skills_source = if global
        .get_value(crate::lpm_skills_config::AUTO_INSTALL_LPM_SKILLS_KEY)
        .is_some()
    {
        USER_SOURCE
    } else if global
        .get_bool(crate::lpm_skills_config::LEGACY_NO_SKILLS_KEY)
        .is_some()
    {
        "~/.lpm/config.toml (legacy noSkills)"
    } else {
        DEFAULT_SOURCE
    };
    entries.push(EffectiveConfigEntry::new(
        crate::lpm_skills_config::AUTO_INSTALL_LPM_SKILLS_KEY,
        skills,
        skills_source,
        GROUP_INSTALL,
    ));

    let audit_env = std::env::var("LPM_AUDIT_AFTER_INSTALL").ok();
    let audit_env_value = audit_env.as_deref().and_then(parse_bool_text);
    let audit = audit_env_value
        .or_else(|| global.get_bool("audit-after-install"))
        .unwrap_or(false);
    entries.push(EffectiveConfigEntry::new(
        "audit-after-install",
        audit,
        if audit_env_value.is_some() {
            "LPM_AUDIT_AFTER_INSTALL"
        } else if global.get_bool("audit-after-install").is_some() {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        GROUP_INSTALL,
    ));

    let (linker, linker_source) = crate::linker_config::resolve_effective_linker_with_source(
        None,
        package,
        global,
        project_dir,
    )
    .map_err(LpmError::Script)?;
    entries.push(EffectiveConfigEntry::new(
        "linker",
        linker.as_str(),
        match linker_source {
            crate::linker_config::LinkerModeSource::CliFlag => "--linker",
            crate::linker_config::LinkerModeSource::GlobalConfig => USER_SOURCE,
            crate::linker_config::LinkerModeSource::EnvVar => "LPM_LINKER",
            crate::linker_config::LinkerModeSource::PackageJson => PACKAGE_JSON_SOURCE,
            crate::linker_config::LinkerModeSource::WorkspaceAutoDetected => {
                "workspace auto-detection"
            }
            crate::linker_config::LinkerModeSource::Default => DEFAULT_SOURCE,
        },
        GROUP_INSTALL,
    ));
    Ok(())
}

fn add_workspace_entry(
    entries: &mut Vec<EffectiveConfigEntry>,
    workspace_root: &Path,
    global: &GlobalConfig,
) -> Result<(), LpmError> {
    let concurrency =
        crate::workspace_concurrency_config::resolve_workspace_concurrency(workspace_root, None)?;
    let workspace_config = read_optional_toml_table(&workspace_root.join("lpm.toml"))?;
    entries.push(EffectiveConfigEntry::new(
        "workspace-concurrency",
        concurrency.get(),
        if nested_value(&workspace_config, &["workspace", "concurrency"]).is_some() {
            PROJECT_TOML_SOURCE
        } else if global.get_value("workspace-concurrency").is_some() {
            USER_SOURCE
        } else {
            DEFAULT_SOURCE
        },
        GROUP_WORKSPACE,
    ));
    Ok(())
}

fn add_network_entry(entries: &mut Vec<EffectiveConfigEntry>, global: &GlobalConfig) {
    let relay = lpm_tunnel::resolve_relay_url();
    let env_relay = std::env::var("LPM_TUNNEL_RELAY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let config_relay = global
        .get_table("tunnel")
        .and_then(|table| table.get("relay-url"))
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let source = if env_relay.as_deref() == Some(relay.as_str()) {
        "LPM_TUNNEL_RELAY"
    } else if config_relay == Some(relay.as_str()) {
        USER_SOURCE
    } else {
        DEFAULT_SOURCE
    };
    entries.push(EffectiveConfigEntry::new(
        "tunnel.relay-url",
        relay,
        source,
        GROUP_NETWORK,
    ));
}

fn add_policy_extension_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    global: &GlobalConfig,
) -> Result<(), LpmError> {
    let mut active: BTreeMap<_, _> = load_policy_extension_configs(global)?
        .into_iter()
        .map(|config| (config.name().to_string(), config))
        .collect();
    let Some(extensions) = global
        .get_table("policy")
        .and_then(|table| table.get("extensions"))
        .and_then(toml::Value::as_table)
    else {
        return Ok(());
    };
    let mut names: Vec<_> = extensions.keys().collect();
    names.sort_unstable();
    for name in names {
        let Some(table) = extensions.get(name).and_then(toml::Value::as_table) else {
            continue;
        };
        let base = format!("policy.extensions.{name}");
        if table.get("enabled").and_then(toml::Value::as_bool) == Some(false) {
            entries.push(EffectiveConfigEntry::new(
                format!("{base}.enabled"),
                false,
                USER_SOURCE,
                GROUP_EXTENSIONS,
            ));
            continue;
        }
        let config = active.remove(name).ok_or_else(|| {
            LpmError::Registry(format!(
                "active policy extension `{name}` did not resolve to an effective configuration"
            ))
        })?;
        let field_source = |field: &str| {
            if table.contains_key(field) {
                USER_SOURCE
            } else {
                DEFAULT_SOURCE
            }
        };
        entries.push(EffectiveConfigEntry::new(
            format!("{base}.enabled"),
            true,
            field_source("enabled"),
            GROUP_EXTENSIONS,
        ));
        entries.push(EffectiveConfigEntry::new(
            format!("{base}.command"),
            serde_json::json!(config.command()),
            field_source("command"),
            GROUP_EXTENSIONS,
        ));
        entries.push(EffectiveConfigEntry::new(
            format!("{base}.mode"),
            config.mode().as_str(),
            field_source("mode"),
            GROUP_EXTENSIONS,
        ));
        entries.push(EffectiveConfigEntry::new(
            format!("{base}.on-error"),
            config.on_error().as_str(),
            field_source("on-error"),
            GROUP_EXTENSIONS,
        ));
        entries.push(EffectiveConfigEntry::new(
            format!("{base}.timeout-ms"),
            config.timeout_ms() as u64,
            field_source("timeout-ms"),
            GROUP_EXTENSIONS,
        ));
        entries.push(EffectiveConfigEntry::new(
            format!("{base}.events"),
            serde_json::json!(["package.candidate"]),
            field_source("events"),
            GROUP_EXTENSIONS,
        ));
    }
    Ok(())
}

fn add_unknown_saved_entries(entries: &mut Vec<EffectiveConfigEntry>, global: &GlobalConfig) {
    let known: HashSet<&str> = entries
        .iter()
        .map(|entry| entry.key.as_str())
        .chain(LEGACY_CONFIG_PATHS.iter().copied())
        .collect();
    let mut unknown = Vec::new();
    flatten_unknown_values("", &global.table, &known, &mut unknown);
    drop(known);
    unknown.sort_by(|left, right| left.0.cmp(&right.0));
    entries.extend(unknown.into_iter().map(|(key, value)| {
        EffectiveConfigEntry::new(
            key,
            super::config_value_to_json(&value),
            USER_SOURCE,
            GROUP_ADDITIONAL,
        )
    }));
}

fn flatten_unknown_values(
    prefix: &str,
    table: &toml::map::Map<String, toml::Value>,
    known: &HashSet<&str>,
    output: &mut Vec<(String, toml::Value)>,
) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if known.contains(path.as_str()) || path.starts_with("policy.extensions.") {
            continue;
        }
        if let Some(nested) = value.as_table() {
            flatten_unknown_values(&path, nested, known, output);
        } else {
            output.push((path, value.clone()));
        }
    }
}

fn read_package_json(
    project_dir: &Path,
) -> Result<(lpm_workspace::PackageJson, serde_json::Value), LpmError> {
    let path = project_dir.join("package.json");
    let content =
        match lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => {
                return Ok((lpm_workspace::PackageJson::default(), serde_json::json!({})));
            }
            Err(error) => return Err(LpmError::Registry(error.to_string())),
        };
    let package = serde_json::from_str(&content).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    let value = serde_json::from_str(&content).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    Ok((package, value))
}

fn read_optional_toml_table(path: &Path) -> Result<toml::map::Map<String, toml::Value>, LpmError> {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(toml::map::Map::new()),
            Err(error) => return Err(LpmError::Registry(error.to_string())),
        };
    let parsed: toml::Value = toml::from_str(&content).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    parsed
        .as_table()
        .cloned()
        .ok_or_else(|| LpmError::Registry(format!("{} must contain a TOML table", path.display())))
}

fn validate_sigstore_verify(global: &GlobalConfig) -> Result<(), LpmError> {
    let Some(value) = global
        .get_table("sigstore")
        .and_then(|table| table.get("verify"))
    else {
        return Ok(());
    };
    let raw = value
        .as_str()
        .ok_or_else(|| LpmError::Registry("`[sigstore].verify` must be a string".to_string()))?;
    if matches!(raw, "deny" | "warn" | "off") {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "invalid `[sigstore].verify` value `{raw}`; must be deny | warn | off"
        )))
    }
}

fn read_optional_u64(global: &GlobalConfig, key: &str) -> Result<Option<u64>, LpmError> {
    let Some(_) = global.get_value(key) else {
        return Ok(None);
    };
    global.get_u64(key).map(Some).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `{key}` in ~/.lpm/config.toml; must be a non-negative integer"
        ))
    })
}

fn read_string_array(global: &GlobalConfig, key: &str) -> Result<Vec<String>, LpmError> {
    let Some(value) = global.get_value(key) else {
        return Ok(Vec::new());
    };
    let array = value.as_array().ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `{key}` in ~/.lpm/config.toml; must be an array of strings"
        ))
    })?;
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                LpmError::Registry(format!(
                    "invalid `{key}[{index}]` in ~/.lpm/config.toml; must be a string"
                ))
            })
        })
        .collect()
}

fn effective_max_write_roots(global: &GlobalConfig) -> Result<Vec<String>, LpmError> {
    let home = dirs::home_dir();
    Ok(read_string_array(global, "max-sandbox-write-roots")?
        .into_iter()
        .filter_map(|value| {
            if let Some(rest) = value.strip_prefix("~/") {
                home.as_ref()
                    .map(|home| home.join(rest).display().to_string())
            } else if value == "~" {
                home.as_ref().map(|home| home.display().to_string())
            } else {
                let path = std::path::PathBuf::from(&value);
                path.is_absolute().then_some(value)
            }
        })
        .collect())
}

fn json_string_array(value: &serde_json::Value, source: &str) -> Result<Vec<String>, LpmError> {
    let array = value
        .as_array()
        .ok_or_else(|| LpmError::Registry(format!("{source} must be an array of strings")))?;
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| LpmError::Registry(format!("{source}[{index}] must be a string")))
        })
        .collect()
}

fn first_source(project: bool, user: bool) -> &'static str {
    if project {
        PROJECT_TOML_SOURCE
    } else if user {
        USER_SOURCE
    } else {
        DEFAULT_SOURCE
    }
}

fn nested_source(
    project: &toml::map::Map<String, toml::Value>,
    global: &toml::map::Map<String, toml::Value>,
    path: &[&str],
) -> &'static str {
    if nested_value(project, path).is_some() {
        PROJECT_TOML_SOURCE
    } else if nested_value(global, path).is_some() {
        USER_SOURCE
    } else {
        DEFAULT_SOURCE
    }
}

fn nested_value<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    path: &[&str],
) -> Option<&'a toml::Value> {
    let (first, rest) = path.split_first()?;
    let mut value = table.get(*first)?;
    for segment in rest {
        value = value.as_table()?.get(*segment)?;
    }
    Some(value)
}

fn policy_source(source: PolicyTier) -> &'static str {
    match source {
        PolicyTier::Cli => "CLI flag",
        PolicyTier::Project => PACKAGE_JSON_SOURCE,
        PolicyTier::User => USER_SOURCE,
        PolicyTier::Default => DEFAULT_SOURCE,
    }
}

fn posture_source(source: PostureSourceKind) -> &'static str {
    match source {
        PostureSourceKind::BuiltinDefault => DEFAULT_SOURCE,
        PostureSourceKind::ApprovedStore => "approved security posture",
        PostureSourceKind::ManagedPolicy => "managed security policy",
    }
}

fn select_security_value<T: Copy + Eq>(
    candidate: T,
    candidate_source: &str,
    floor: T,
    floor_source: PostureSourceKind,
    loosens: impl Fn(T, T) -> bool,
) -> (T, String) {
    let candidate_loosens = loosens(candidate, floor);
    let floor_is_authoritative = matches!(floor_source, PostureSourceKind::ManagedPolicy)
        && (candidate == floor || candidate_loosens);
    let default_defers_to_floor = candidate_source == DEFAULT_SOURCE
        && !matches!(floor_source, PostureSourceKind::BuiltinDefault);
    if floor_is_authoritative || default_defers_to_floor || candidate_loosens {
        (floor, posture_source(floor_source).to_string())
    } else {
        (candidate, candidate_source.to_string())
    }
}

fn merged_source<const N: usize>(sources: [Option<&str>; N]) -> String {
    let sources: Vec<_> = sources.into_iter().flatten().collect();
    if sources.is_empty() {
        DEFAULT_SOURCE.to_string()
    } else {
        sources.join(" + ")
    }
}

fn merge_unique(first: Vec<String>, second: Vec<String>) -> Vec<String> {
    let mut merged = Vec::with_capacity(first.len() + second.len());
    let mut seen = HashSet::with_capacity(merged.capacity());
    for value in first.into_iter().chain(second) {
        if seen.insert(value.clone()) {
            merged.push(value);
        }
    }
    merged
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .as_deref()
        .and_then(parse_bool_text)
}

fn parse_bool_text(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "enabled" => Some(true),
        "0" | "false" | "no" | "off" | "disabled" => Some(false),
        _ => None,
    }
}

fn display_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".to_string()),
    }
}
