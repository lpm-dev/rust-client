use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use lpm_common::LpmError;

use super::GlobalConfig;
use crate::commands::install::policy_extensions::load_policy_extension_configs;
use crate::precedence::{PolicyTier, PurePolicyKnob};
use crate::security_approval::{EffectiveAuthorizedPosture, PostureSourceKind};

const DEFAULT_SOURCE: &str = "built-in default";
const DEFAULT_USER_SOURCE: &str = "~/.lpm/config.toml";
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

#[derive(Debug, serde::Serialize)]
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
        let key = key.into();
        Self {
            value: super::redact_config_json_value(&key, value.into()),
            key,
            source: source.into(),
            group,
        }
    }
}

#[derive(serde::Serialize)]
struct EffectiveConfigJson<'a> {
    success: bool,
    action: &'static str,
    count: usize,
    entries: &'a [EffectiveConfigEntry],
}

impl EffectiveConfig {
    pub(super) fn load(current_dir: &Path) -> Result<Self, LpmError> {
        let project_dir = lpm_workspace::find_project_root(current_dir)
            .unwrap_or_else(|| current_dir.to_path_buf());
        let global_path = lpm_common::LpmRoot::from_env()?.root().join("config.toml");
        let user_source = global_source_label();
        let global = GlobalConfig::from_value(super::read_config(&global_path)?)?;
        let project_toml_path = project_dir.join("lpm.toml");
        let project_toml = read_optional_toml_table(&project_toml_path)?;
        let (package_json, package_json_value) = read_package_json(&project_dir)?;
        let script_config =
            crate::script_policy_config::ScriptPolicyConfig::from_package_json_value(
                &package_json_value,
            );
        if let Some(invalid) = script_config.policy_parse_error.as_deref() {
            return Err(LpmError::Registry(format!(
                "invalid package.json > lpm > scriptPolicy value `{invalid}`"
            )));
        }
        let posture = crate::security_approval::load_effective_authorized_posture()?;
        let workspace_root = lpm_workspace::find_workspace_root(&project_dir)
            .map_err(|error| LpmError::Workspace(error.to_string()))?;
        let workspace_detected = workspace_root.is_some();
        let workspace_root = workspace_root.as_deref().unwrap_or(project_dir.as_path());
        let root_package_storage;
        let root_package = if workspace_root == project_dir {
            &package_json
        } else {
            root_package_storage = lpm_workspace::read_workspace_root_package(workspace_root)
                .map_err(|error| LpmError::Workspace(error.to_string()))?;
            &root_package_storage
        };
        let workspace_toml_path = workspace_root.join("lpm.toml");
        let workspace_toml_storage;
        let workspace_toml = if workspace_root == project_dir {
            &project_toml
        } else {
            workspace_toml_storage = read_optional_toml_table(&workspace_toml_path)?;
            &workspace_toml_storage
        };

        let mut entries = Vec::with_capacity(STATIC_CONFIG_ENTRY_COUNT + 8);
        add_save_entries(
            &mut entries,
            &project_toml,
            &project_toml_path,
            &global,
            &global_path,
            &user_source,
        )?;
        add_script_entries(
            &mut entries,
            ScriptEntryContext {
                project_dir: &project_dir,
                project: &project_toml,
                package_json: &package_json_value,
                script_config: &script_config,
                global: &global,
                global_path: &global_path,
                user_source: &user_source,
                posture: &posture,
            },
        )?;
        add_security_entries(
            &mut entries,
            &package_json,
            &package_json_value,
            &global,
            &global_path,
            &user_source,
            &posture,
        )?;
        add_install_entries(
            &mut entries,
            &package_json,
            root_package,
            &global,
            &global_path,
            &user_source,
            workspace_detected,
        )?;
        add_workspace_entry(
            &mut entries,
            workspace_toml,
            &workspace_toml_path,
            &global,
            &global_path,
            &user_source,
        )?;
        add_network_entry(&mut entries, &global, &global_path, &user_source)?;
        add_policy_extension_entries(&mut entries, &global, &user_source)?;
        add_unknown_saved_entries(&mut entries, global.into_table(), &user_source);

        Ok(Self { entries })
    }

    pub(super) fn print_json(&self) -> Result<(), LpmError> {
        use std::io::Write as _;

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        serde_json::to_writer_pretty(
            &mut output,
            &EffectiveConfigJson {
                success: true,
                action: "list",
                count: self.entries.len(),
                entries: &self.entries,
            },
        )?;
        writeln!(output)?;
        Ok(())
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
    project: &toml::map::Map<String, toml::Value>,
    project_path: &Path,
    global: &GlobalConfig,
    global_path: &Path,
    user_source: &str,
) -> Result<(), LpmError> {
    let project_prefix = read_save_prefix(project, project_path)?;
    let global_prefix = read_save_prefix(global.table(), global_path)?;
    let prefix = project_prefix
        .or(global_prefix)
        .unwrap_or(crate::save_spec::SavePrefix::Caret)
        .as_str();
    let project_exact = read_optional_bool_from_table(project, "save-exact", project_path)?;
    let global_exact = read_optional_bool(global, "save-exact", global_path)?;
    let save_exact = project_exact.or(global_exact).unwrap_or(false);
    entries.push(EffectiveConfigEntry::new(
        "save-prefix",
        prefix,
        first_source(
            project.contains_key("save-prefix"),
            global.get_value("save-prefix").is_some(),
            user_source,
        ),
        GROUP_SAVE,
    ));
    entries.push(EffectiveConfigEntry::new(
        "save-exact",
        save_exact,
        first_source(
            project.contains_key("save-exact"),
            global.get_value("save-exact").is_some(),
            user_source,
        ),
        GROUP_SAVE,
    ));
    Ok(())
}

struct ScriptEntryContext<'a> {
    project_dir: &'a Path,
    project: &'a toml::map::Map<String, toml::Value>,
    package_json: &'a serde_json::Value,
    script_config: &'a crate::script_policy_config::ScriptPolicyConfig,
    global: &'a GlobalConfig,
    global_path: &'a Path,
    user_source: &'a str,
    posture: &'a EffectiveAuthorizedPosture,
}

fn add_script_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    context: ScriptEntryContext<'_>,
) -> Result<(), LpmError> {
    let ScriptEntryContext {
        project_dir,
        project,
        package_json,
        script_config,
        global,
        global_path,
        user_source,
        posture,
    } = context;
    if let Some(value) = global.get_value("script-policy") {
        let raw = value.as_str().ok_or_else(|| {
            LpmError::Registry(format!(
                "`script-policy` in {} must be a string",
                global_path.display()
            ))
        })?;
        crate::script_policy_config::ScriptPolicy::parse(raw)
            .map_err(|error| LpmError::Registry(error.to_string()))?;
    }
    let resolution = crate::script_policy_config::resolve_script_policy_raw_with_global(
        None,
        script_config,
        global,
    );
    let candidate_source = policy_source(resolution.effective_source, user_source);
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

    let global_advisor = read_optional_string_choice(
        global,
        "triage-advisor",
        global_path,
        &["none", "claude-cli", "codex", "ollama"],
    )?;
    if let Some(value) = script_config.triage_advisor.as_deref()
        && !["none", "claude-cli", "codex", "ollama"].contains(&value)
    {
        return Err(LpmError::Registry(format!(
            "invalid package.json > lpm > triageAdvisor value `{value}`; must be none | claude-cli | codex | ollama"
        )));
    }
    let (advisor, advisor_source) = if let Some(value) = script_config.triage_advisor.as_deref() {
        (value, PACKAGE_JSON_SOURCE)
    } else if let Some(value) = global_advisor {
        (value, user_source)
    } else {
        ("none", DEFAULT_SOURCE)
    };
    entries.push(EffectiveConfigEntry::new(
        "triage-advisor",
        advisor,
        advisor_source,
        GROUP_SCRIPTS,
    ));

    let (sandbox_options, sandbox_mode) = crate::sandbox_config::load_sandbox_options_from_tables(
        project,
        global,
        &project_dir.join("lpm.toml").display().to_string(),
        &global_path.display().to_string(),
    )?;
    let env_strict = env_bool("LPM_STRICT_SANDBOX") == Some(true);
    let candidate_mode = if env_strict {
        crate::sandbox_config::ResolvedSandboxMode::Strict
    } else {
        sandbox_mode
    };
    let candidate_mode_source = if env_strict {
        "LPM_STRICT_SANDBOX"
    } else {
        nested_source(project, global.table(), &["sandbox", "mode"], user_source)
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

    let allow_degraded_source = nested_source(
        project,
        global.table(),
        &["sandbox", "allow-degraded"],
        user_source,
    );
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

    let user_read_allow = read_string_array(global, "script-read-allow", global_path)?;
    let project_read_allow = package_json
        .pointer("/lpm/scripts/sandboxReadAllow")
        .map(|value| json_string_array(value, "package.json > lpm > scripts > sandboxReadAllow"))
        .transpose()?
        .unwrap_or_default();
    lpm_sandbox::resolve_sandbox_read_allow(project_dir, &project_read_allow, &user_read_allow)
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
            .then_some(user_source),
    ]);
    entries.push(EffectiveConfigEntry::new(
        "script-read-allow",
        serde_json::json!(read_allow),
        read_allow_source,
        GROUP_SCRIPTS,
    ));

    let max_write_roots = effective_max_write_roots(global, global_path)?;
    entries.push(EffectiveConfigEntry::new(
        "max-sandbox-write-roots",
        serde_json::json!(max_write_roots),
        if global.get_value("max-sandbox-write-roots").is_some() {
            user_source
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
    global_path: &Path,
    user_source: &str,
    posture: &EffectiveAuthorizedPosture,
) -> Result<(), LpmError> {
    let lpm = package.lpm.as_ref();
    let global_release_age = read_optional_u64(global, "minimum-release-age-secs", global_path)?;
    let (candidate_age, candidate_age_source) =
        if let Some(value) = lpm.and_then(|lpm| lpm.minimum_release_age) {
            (value, PACKAGE_JSON_SOURCE)
        } else if let Some(value) = global_release_age {
            (value, user_source)
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
                LpmError::Registry(format!(
                    "`release-age-policy` in {} must be a string",
                    global_path.display()
                ))
            })
        })
        .transpose()?
        .map(|raw| {
            crate::release_age_config::ReleaseAgePolicy::parse(
                &format!("{} > release-age-policy", global_path.display()),
                raw,
            )
        })
        .transpose()?;
    let (candidate_policy, candidate_policy_source) = if let Some(value) = project_policy {
        (value, PACKAGE_JSON_SOURCE)
    } else if let Some(value) = global_policy {
        (value, user_source)
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
    let global_excludes = read_string_array(global, "minimum-release-age-exclude", global_path)?;
    let project_excludes = crate::release_age_config::validate_release_age_excludes(
        "package.json > lpm > minimumReleaseAgeExclude",
        &project_excludes,
    )?;
    let global_excludes = crate::release_age_config::validate_release_age_excludes(
        &format!("{} > minimum-release-age-exclude", global_path.display()),
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
            .then_some(user_source),
    ]);
    entries.push(EffectiveConfigEntry::new(
        "minimum-release-age-exclude",
        serde_json::json!(excludes),
        excludes_source,
        GROUP_SECURITY,
    ));

    let env_sigstore = std::env::var("LPM_PROVENANCE_ENFORCE").ok();
    let sigstore_verify_raw = read_nested_optional_string_choice(
        global,
        &["sigstore", "verify"],
        global_path,
        &["deny", "warn", "off"],
    )?;
    let (candidate_sigstore, sigstore_source_kind) =
        crate::provenance_fetch::EnforceMode::resolve_from_chain(env_sigstore.as_deref(), || {
            sigstore_verify_raw.map(str::to_string)
        });
    let candidate_sigstore_source = match sigstore_source_kind {
        crate::provenance_fetch::EnforceModeSource::Env => "LPM_PROVENANCE_ENFORCE",
        crate::provenance_fetch::EnforceModeSource::Config => user_source,
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

    let sigstore_scope_raw = read_nested_optional_string_choice(
        global,
        &["sigstore", "scope"],
        global_path,
        &["approved", "all"],
    )?;
    let sigstore_scope =
        crate::provenance_fetch::VerificationScope::from_config(sigstore_scope_raw)?;
    entries.push(EffectiveConfigEntry::new(
        "sigstore.scope",
        if sigstore_scope.verifies_all() {
            "all"
        } else {
            "approved"
        },
        nested_source(
            &toml::map::Map::new(),
            global.table(),
            &["sigstore", "scope"],
            user_source,
        ),
        GROUP_SECURITY,
    ));
    let sigstore_availability_raw = read_nested_optional_string_choice(
        global,
        &["sigstore", "availability"],
        global_path,
        &["best-effort", "strict"],
    )?;
    let sigstore_availability =
        crate::provenance_fetch::AvailabilityMode::from_config(sigstore_availability_raw)?;
    entries.push(EffectiveConfigEntry::new(
        "sigstore.availability",
        if sigstore_availability.is_strict() {
            "strict"
        } else {
            "best-effort"
        },
        nested_source(
            &toml::map::Map::new(),
            global.table(),
            &["sigstore", "availability"],
            user_source,
        ),
        GROUP_SECURITY,
    ));

    let signatures_env = std::env::var("LPM_VERIFY_REGISTRY_SIGNATURES").ok();
    let configured_signatures = read_optional_bool(global, "signatures", global_path)?;
    let signatures = signatures_env.as_deref().map_or_else(
        || configured_signatures.unwrap_or(false),
        |value| parse_bool_text(value).unwrap_or(false),
    );
    let signatures_source = if signatures_env.is_some() {
        "LPM_VERIFY_REGISTRY_SIGNATURES"
    } else if configured_signatures.is_some() {
        user_source
    } else {
        DEFAULT_SOURCE
    };
    entries.push(EffectiveConfigEntry::new(
        "signatures",
        signatures,
        signatures_source,
        GROUP_SECURITY,
    ));

    let configured_trust_policy = read_optional_string_choice(
        global,
        "trust-policy",
        global_path,
        &["off", "no-downgrade"],
    )?;
    let trust_policy_source = if configured_trust_policy.is_some() {
        user_source
    } else {
        DEFAULT_SOURCE
    };
    let trust_policy = configured_trust_policy.unwrap_or("off");
    entries.push(EffectiveConfigEntry::new(
        "trust-policy",
        trust_policy,
        trust_policy_source,
        GROUP_SECURITY,
    ));

    let config_typosquat = match global.get_value("typosquat-guard") {
        Some(value) => {
            let raw = value.as_str().ok_or_else(|| {
                invalid_global_value(global_path, "typosquat-guard", "default | on | off")
            })?;
            Some(
                crate::commands::config::TyposquatGuardSelection::parse(raw).ok_or_else(|| {
                    invalid_global_value(global_path, "typosquat-guard", "default | on | off")
                })?,
            )
        }
        None => None,
    };
    let env_typosquat_off = env_bool("LPM_TYPOSQUAT_GUARD") == Some(false);
    let (typosquat, typosquat_source) = if let Some(candidate) = config_typosquat {
        select_security_value(
            candidate,
            user_source,
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
    let combined_firewall_source = format!("{user_source} + {firewall_env_source}");
    let (candidate_firewall, candidate_firewall_source) = match (config_firewall, env_firewall) {
        (Some(config), Some(env)) => (config.stricter(env), combined_firewall_source.as_str()),
        (Some(config), None) => (config, user_source),
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
    add_firewall_policy_entries(entries, global, user_source)?;

    let integrity = crate::commands::config::resolve_object_integrity_policy(global)?;
    entries.push(EffectiveConfigEntry::new(
        "integrity",
        integrity.as_str(),
        if std::env::var_os(lpm_store::v2::ENV_V2_OBJECT_INTEGRITY).is_some() {
            lpm_store::v2::ENV_V2_OBJECT_INTEGRITY
        } else if global.get_value("integrity").is_some() {
            user_source
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
            user_source
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
            user_source
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
    user_source: &str,
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
            user_source
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
            user_source
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
    package: &lpm_workspace::PackageJson,
    root_package: &lpm_workspace::PackageJson,
    global: &GlobalConfig,
    global_path: &Path,
    user_source: &str,
    workspace_detected: bool,
) -> Result<(), LpmError> {
    let root_lpm = root_package.lpm.as_ref();
    let global_engine_strict = read_optional_bool(global, "engine-strict", global_path)?;
    let engine_strict =
        crate::engine_strict_config::resolve_for_root_with_global(false, root_package, global);
    entries.push(EffectiveConfigEntry::new(
        "engine-strict",
        engine_strict,
        if root_lpm.and_then(|lpm| lpm.engine_strict).is_some() {
            PACKAGE_JSON_SOURCE
        } else if global_engine_strict.is_some() {
            user_source
        } else {
            DEFAULT_SOURCE
        },
        GROUP_INSTALL,
    ));

    let lpm = package.lpm.as_ref();
    let global_strict_peers = read_optional_bool(global, "strict-peer-dependencies", global_path)?;
    let strict_peers = lpm
        .and_then(|lpm| lpm.strict_peer_dependencies)
        .or(global_strict_peers)
        .unwrap_or(false);
    entries.push(EffectiveConfigEntry::new(
        "strict-peer-dependencies",
        strict_peers,
        if lpm.and_then(|lpm| lpm.strict_peer_dependencies).is_some() {
            PACKAGE_JSON_SOURCE
        } else if global_strict_peers.is_some() {
            user_source
        } else {
            DEFAULT_SOURCE
        },
        GROUP_INSTALL,
    ));
    let global_auto_peers = read_optional_bool(global, "auto-install-peers", global_path)?;
    let auto_peers = lpm
        .and_then(|lpm| lpm.auto_install_peers)
        .or(global_auto_peers)
        .unwrap_or(true);
    entries.push(EffectiveConfigEntry::new(
        "auto-install-peers",
        auto_peers,
        if lpm.and_then(|lpm| lpm.auto_install_peers).is_some() {
            PACKAGE_JSON_SOURCE
        } else if global_auto_peers.is_some() {
            user_source
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
        user_source.to_string()
    } else if read_optional_bool(
        global,
        crate::lpm_skills_config::LEGACY_NO_SKILLS_KEY,
        global_path,
    )?
    .is_some()
    {
        format!("{user_source} (legacy noSkills)")
    } else {
        DEFAULT_SOURCE.to_string()
    };
    entries.push(EffectiveConfigEntry::new(
        crate::lpm_skills_config::AUTO_INSTALL_LPM_SKILLS_KEY,
        skills,
        skills_source,
        GROUP_INSTALL,
    ));

    let audit_env = std::env::var("LPM_AUDIT_AFTER_INSTALL").ok();
    let audit_env_value = audit_env.as_deref().and_then(parse_bool_text);
    let configured_audit = read_optional_bool(global, "audit-after-install", global_path)?;
    let audit = audit_env_value.or(configured_audit).unwrap_or(false);
    entries.push(EffectiveConfigEntry::new(
        "audit-after-install",
        audit,
        if audit_env_value.is_some() {
            "LPM_AUDIT_AFTER_INSTALL"
        } else if configured_audit.is_some() {
            user_source
        } else {
            DEFAULT_SOURCE
        },
        GROUP_INSTALL,
    ));

    if global.get_value("linker").is_some() && global.get_str("linker").is_none() {
        return Err(invalid_global_value(
            global_path,
            "linker",
            "isolated | hoisted",
        ));
    }
    let (linker, linker_source) =
        crate::linker_config::resolve_effective_linker_with_source_and_workspace(
            None,
            package,
            global,
            workspace_detected,
        )
        .map_err(LpmError::Script)?;
    entries.push(EffectiveConfigEntry::new(
        "linker",
        linker.as_str(),
        match linker_source {
            crate::linker_config::LinkerModeSource::CliFlag => "--linker",
            crate::linker_config::LinkerModeSource::GlobalConfig => user_source,
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
    workspace_config: &toml::map::Map<String, toml::Value>,
    workspace_config_path: &Path,
    global: &GlobalConfig,
    global_path: &Path,
    user_source: &str,
) -> Result<(), LpmError> {
    let concurrency =
        crate::workspace_concurrency_config::resolve_workspace_concurrency_from_tables(
            workspace_config,
            global,
            workspace_config_path,
            global_path,
        )?;
    entries.push(EffectiveConfigEntry::new(
        "workspace-concurrency",
        concurrency.get(),
        if nested_value(workspace_config, &["workspace", "concurrency"]).is_some() {
            PROJECT_TOML_SOURCE
        } else if global.get_value("workspace-concurrency").is_some() {
            user_source
        } else {
            DEFAULT_SOURCE
        },
        GROUP_WORKSPACE,
    ));
    Ok(())
}

fn add_network_entry(
    entries: &mut Vec<EffectiveConfigEntry>,
    global: &GlobalConfig,
    global_path: &Path,
    user_source: &str,
) -> Result<(), LpmError> {
    let config_relay = read_nested_optional_string(global, &["tunnel", "relay-url"], global_path)?
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let relay = lpm_tunnel::resolve_relay_url_from_config_value(config_relay);
    let env_relay = std::env::var("LPM_TUNNEL_RELAY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let source = if env_relay.as_deref() == Some(relay.as_str()) {
        "LPM_TUNNEL_RELAY"
    } else if config_relay == Some(relay.as_str()) {
        user_source
    } else {
        DEFAULT_SOURCE
    };
    entries.push(EffectiveConfigEntry::new(
        "tunnel.relay-url",
        relay,
        source,
        GROUP_NETWORK,
    ));
    Ok(())
}

fn add_policy_extension_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    global: &GlobalConfig,
    user_source: &str,
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
                user_source,
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
                user_source
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

fn add_unknown_saved_entries(
    entries: &mut Vec<EffectiveConfigEntry>,
    global: toml::map::Map<String, toml::Value>,
    user_source: &str,
) {
    let known: HashSet<&str> = entries
        .iter()
        .map(|entry| entry.key.as_str())
        .chain(LEGACY_CONFIG_PATHS.iter().copied())
        .collect();
    let mut unknown = Vec::new();
    flatten_unknown_values("", global, &known, &mut unknown);
    drop(known);
    unknown.sort_by(|left, right| left.0.cmp(&right.0));
    entries.extend(unknown.into_iter().map(|(key, value)| {
        EffectiveConfigEntry::new(
            key,
            super::config_value_to_json(&value),
            user_source,
            GROUP_ADDITIONAL,
        )
    }));
}

fn flatten_unknown_values(
    prefix: &str,
    table: toml::map::Map<String, toml::Value>,
    known: &HashSet<&str>,
    output: &mut Vec<(String, toml::Value)>,
) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key
        } else {
            format!("{prefix}.{key}")
        };
        if known.contains(path.as_str()) || path.starts_with("policy.extensions.") {
            continue;
        }
        match value {
            toml::Value::Table(nested) => {
                flatten_unknown_values(&path, nested, known, output);
            }
            value => output.push((path, value)),
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
    let value: serde_json::Value = serde_json::from_str(lpm_common::strip_utf8_bom_str(&content))
        .map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    let package = lpm_workspace::package_json_from_value(&value).map_err(|error| {
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

fn global_source_label() -> String {
    let Some(configured) = std::env::var_os("LPM_HOME").filter(|value| !value.is_empty()) else {
        return DEFAULT_USER_SOURCE.to_string();
    };
    if dirs::home_dir()
        .as_ref()
        .is_some_and(|home| std::path::Path::new(&configured) == home.join(".lpm"))
    {
        DEFAULT_USER_SOURCE.to_string()
    } else {
        "$LPM_HOME/config.toml".to_string()
    }
}

fn invalid_global_value(path: &Path, key: &str, expected: &str) -> LpmError {
    LpmError::Registry(format!(
        "invalid `{key}` in {}; must be {expected}",
        path.display()
    ))
}

fn read_optional_bool(
    global: &GlobalConfig,
    key: &str,
    path: &Path,
) -> Result<Option<bool>, LpmError> {
    let Some(_) = global.get_value(key) else {
        return Ok(None);
    };
    global
        .get_bool(key)
        .map(Some)
        .ok_or_else(|| invalid_global_value(path, key, "true or false"))
}

fn read_optional_bool_from_table(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    path: &Path,
) -> Result<Option<bool>, LpmError> {
    let Some(value) = table.get(key) else {
        return Ok(None);
    };
    match value {
        toml::Value::Boolean(value) => Ok(Some(*value)),
        toml::Value::String(value) => parse_bool_text(value)
            .map(Some)
            .ok_or_else(|| invalid_global_value(path, key, "true or false")),
        _ => Err(invalid_global_value(path, key, "true or false")),
    }
}

fn read_save_prefix(
    table: &toml::map::Map<String, toml::Value>,
    path: &Path,
) -> Result<Option<crate::save_spec::SavePrefix>, LpmError> {
    let Some(value) = table.get("save-prefix") else {
        return Ok(None);
    };
    let raw = value
        .as_str()
        .ok_or_else(|| invalid_global_value(path, "save-prefix", "\"^\", \"~\", or \"\""))?;
    crate::save_spec::SavePrefix::parse(raw)
        .map(Some)
        .map_err(|error| LpmError::Registry(format!("{}: {error}", path.display())))
}

fn read_optional_string_choice<'a>(
    global: &'a GlobalConfig,
    key: &str,
    path: &Path,
    choices: &[&str],
) -> Result<Option<&'a str>, LpmError> {
    let Some(value) = global.get_value(key) else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| {
        invalid_global_value(path, key, &format!("one of: {}", choices.join(" | ")))
    })?;
    if choices.contains(&raw) {
        Ok(Some(raw))
    } else {
        Err(invalid_global_value(
            path,
            key,
            &format!("one of: {}", choices.join(" | ")),
        ))
    }
}

fn read_nested_optional_string<'a>(
    global: &'a GlobalConfig,
    path: &[&str],
    global_path: &Path,
) -> Result<Option<&'a str>, LpmError> {
    let Some(value) = nested_value(global.table(), path) else {
        if path
            .first()
            .and_then(|section| global.get_value(section))
            .is_some_and(|section| !section.is_table())
        {
            return Err(invalid_global_value(global_path, path[0], "a TOML table"));
        }
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| invalid_global_value(global_path, &path.join("."), "a string"))
}

fn read_nested_optional_string_choice<'a>(
    global: &'a GlobalConfig,
    path: &[&str],
    global_path: &Path,
    choices: &[&str],
) -> Result<Option<&'a str>, LpmError> {
    let Some(raw) = read_nested_optional_string(global, path, global_path)? else {
        return Ok(None);
    };
    if choices.contains(&raw) {
        Ok(Some(raw))
    } else {
        Err(invalid_global_value(
            global_path,
            &path.join("."),
            &format!("one of: {}", choices.join(" | ")),
        ))
    }
}

fn read_optional_u64(
    global: &GlobalConfig,
    key: &str,
    global_path: &Path,
) -> Result<Option<u64>, LpmError> {
    let Some(_) = global.get_value(key) else {
        return Ok(None);
    };
    global.get_u64(key).map(Some).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `{key}` in {}; must be a non-negative integer",
            global_path.display()
        ))
    })
}

fn read_string_array(
    global: &GlobalConfig,
    key: &str,
    global_path: &Path,
) -> Result<Vec<String>, LpmError> {
    let Some(value) = global.get_value(key) else {
        return Ok(Vec::new());
    };
    let array = value.as_array().ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `{key}` in {}; must be an array of strings",
            global_path.display()
        ))
    })?;
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                LpmError::Registry(format!(
                    "invalid `{key}[{index}]` in {}; must be a string",
                    global_path.display()
                ))
            })
        })
        .collect()
}

fn effective_max_write_roots(
    global: &GlobalConfig,
    global_path: &Path,
) -> Result<Vec<String>, LpmError> {
    let home = dirs::home_dir();
    Ok(
        read_string_array(global, "max-sandbox-write-roots", global_path)?
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
            .collect(),
    )
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

fn first_source(project: bool, user: bool, user_source: &str) -> &str {
    if project {
        PROJECT_TOML_SOURCE
    } else if user {
        user_source
    } else {
        DEFAULT_SOURCE
    }
}

fn nested_source<'a>(
    project: &toml::map::Map<String, toml::Value>,
    global: &toml::map::Map<String, toml::Value>,
    path: &[&str],
    user_source: &'a str,
) -> &'a str {
    if nested_value(project, path).is_some() {
        PROJECT_TOML_SOURCE
    } else if nested_value(global, path).is_some() {
        user_source
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

fn policy_source(source: PolicyTier, user_source: &str) -> &str {
    match source {
        PolicyTier::Cli => "CLI flag",
        PolicyTier::Project => PACKAGE_JSON_SOURCE,
        PolicyTier::User => user_source,
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
