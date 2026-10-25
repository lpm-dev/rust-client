//! Native `.env` file parser.
//!
//! Parses `.env` files into key-value pairs. Supports:
//! - `KEY=VALUE` basic assignment
//! - `KEY="value with spaces"` double-quoted values (strips quotes)
//! - `KEY='literal value'` single-quoted values (strips quotes)
//! - `KEY="multiline\nvalue"` double-quoted values spanning multiple lines
//! - `# comments` and empty lines (ignored)
//! - `export KEY=VALUE` (strips `export` prefix)
//!
//! Does NOT expand `$VAR` references — values are taken literally.

use crate::lpm_json;
use lpm_common::{BoundedReadError, CONFIG_FILE_SIZE_CAP_BYTES, LpmError, read_text_file_capped};
use lpm_env::{EnvName, is_denied_env_var};
pub use lpm_vault::PersonalOverrides;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Whether a load applies this machine's personal overrides. Every entry
/// point takes one explicitly: running, showing and checking a project
/// apply them; anything that sends or copies values elsewhere excludes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverridePolicy {
    Apply,
    Exclude,
}

/// Load the fully-resolved environment for a project.
///
/// Resolution order, later layers winning per key:
/// 1. `.env` files (via inheritance chain if `environments` is configured, else standard cascade)
/// 2. Team vault values (the selected environment, or `default` when it has none of its own)
/// 3. Static service values, for callers that select a service
/// 4. Personal overrides on this machine, under [`OverridePolicy::Apply`]
/// 5. LPM's runtime values, added by the caller
///
/// Then dangerous names are removed, code-owned trusted values are inserted,
/// and the schema is evaluated.
pub fn load_project_env(
    project_dir: &Path,
    env_name: Option<&str>,
    policy: OverridePolicy,
) -> Result<HashMap<String, String>, LpmError> {
    load_project_env_with_schema_validation(
        project_dir,
        env_name,
        !crate::script::should_skip_env_validation(),
        policy,
    )
}

/// Load the project environment with an explicit schema-validation setting.
pub fn load_project_env_with_schema_validation(
    project_dir: &Path,
    env_name: Option<&str>,
    validate_schema: bool,
    policy: OverridePolicy,
) -> Result<HashMap<String, String>, LpmError> {
    let lpm_config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::EnvValidation)?;
    load_project_env_from_snapshot(
        project_dir,
        env_name,
        lpm_config.as_ref(),
        validate_schema,
        policy,
    )
}

/// Load the project environment using a configuration that the caller already parsed.
pub fn load_project_env_with_config(
    project_dir: &Path,
    env_name: Option<&str>,
    lpm_config: Option<&lpm_json::LpmJsonConfig>,
    policy: OverridePolicy,
) -> Result<HashMap<String, String>, LpmError> {
    load_project_env_from_snapshot(
        project_dir,
        env_name,
        lpm_config,
        !crate::script::should_skip_env_validation(),
        policy,
    )
}

fn load_project_env_from_snapshot(
    project_dir: &Path,
    env_name: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
    validate_schema: bool,
    policy: OverridePolicy,
) -> Result<HashMap<String, String>, LpmError> {
    let resolved = resolve_project_environment(env_name, config)?;
    let composed = load_project_env_layers_for_resolved(project_dir, &resolved, config, policy)?
        .compose(None, None)?;
    let mut vars = composed.vars;
    if validate_schema {
        let validator = config
            .and_then(|config| config.env_schema.as_ref())
            .map(lpm_env::EnvValidator::new);
        let errors = evaluate_project_env(
            &mut vars,
            validator.as_ref(),
            lpm_env::EvalContext {
                environment: &resolved.canonical,
                ..Default::default()
            },
        )?;
        validation_result(errors, &vars, &composed.overrides)?;
        remove_dangerous_env_vars(&mut vars, "project env");
    }
    Ok(vars)
}

/// Load and validate a scoped environment from one configuration snapshot.
pub fn load_project_env_with_config_and_context(
    project_dir: &Path,
    env_name: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
    stage: lpm_env::EnvStage,
    service: Option<&str>,
    policy: OverridePolicy,
) -> Result<ComposedProjectEnv, LpmError> {
    let resolved = resolve_project_environment(env_name, config)?;
    let mut composed =
        load_project_env_layers_for_resolved(project_dir, &resolved, config, policy)?
            .compose(config, service)?;
    let validator = config
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let errors = evaluate_project_env(
        &mut composed.vars,
        validator.as_ref(),
        lpm_env::EvalContext {
            environment: &resolved.canonical,
            stage,
            service,
        },
    )?;
    validation_result(errors, &composed.vars, &composed.overrides)?;
    remove_dangerous_env_vars(&mut composed.vars, "project env");
    Ok(composed)
}

/// Load a previously resolved identity without interpreting its canonical name as an alias.
pub fn load_project_env_for_resolved_with_config(
    project_dir: &Path,
    resolved: &lpm_env::ResolvedEnv,
    config: Option<&lpm_json::LpmJsonConfig>,
    policy: OverridePolicy,
) -> Result<HashMap<String, String>, LpmError> {
    let composed = load_project_env_layers_for_resolved(project_dir, resolved, config, policy)?
        .compose(None, None)?;
    let mut vars = composed.vars;
    let validator = config
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let errors = evaluate_project_env(
        &mut vars,
        validator.as_ref(),
        lpm_env::EvalContext {
            environment: &resolved.canonical,
            ..Default::default()
        },
    )?;
    validation_result(errors, &vars, &composed.overrides)?;
    remove_dangerous_env_vars(&mut vars, "project env");
    Ok(vars)
}

/// Layers 1 and 2 of a project's environment, with layer 4, the personal
/// overrides, kept apart until any service values are merged.
#[derive(Debug, Default)]
pub struct ProjectEnvLayers {
    vars: HashMap<String, String>,
    overrides: PersonalOverrides,
    overrides_applied: bool,
    vault_count: usize,
}

/// A project's environment through layer 4, with the overrides it applied,
/// which validation needs to attribute failures to them.
#[derive(Debug, Default)]
pub struct ComposedProjectEnv {
    pub vars: HashMap<String, String>,
    pub overrides: PersonalOverrides,
}

impl ProjectEnvLayers {
    /// Layers a caller already composed, kept with the overrides they applied.
    pub(crate) fn already_composed(composed: ComposedProjectEnv, vault_count: usize) -> Self {
        Self {
            vars: composed.vars,
            overrides: composed.overrides,
            overrides_applied: true,
            vault_count,
        }
    }

    /// How many names the personal overrides set or unset.
    pub fn override_count(&self) -> usize {
        self.overrides.len()
    }

    pub fn overrides(&self) -> &PersonalOverrides {
        &self.overrides
    }

    pub(crate) fn vault_count(&self) -> usize {
        self.vault_count
    }

    /// The environment of a child without service values, layers 1, 2 and 4,
    /// moved out. The overrides stay, for attributing validation failures.
    pub(crate) fn take_child_env(&mut self) -> Result<HashMap<String, String>, LpmError> {
        let vault_count = self.vault_count;
        let composed = std::mem::take(self).compose(None, None)?;
        *self = Self::already_composed(
            ComposedProjectEnv {
                vars: HashMap::new(),
                overrides: composed.overrides,
            },
            vault_count,
        );
        Ok(composed.vars)
    }

    /// Layers 3 and 4: `service`'s static values, then the personal
    /// overrides. A single child takes the layers by value.
    pub fn compose(
        self,
        config: Option<&lpm_json::LpmJsonConfig>,
        service: Option<&str>,
    ) -> Result<ComposedProjectEnv, LpmError> {
        let mut vars = self.vars;
        if self.overrides_applied {
            if service.is_some() {
                return Err(LpmError::EnvValidation(
                    "service values can't follow personal overrides".to_owned(),
                ));
            }
        } else {
            merge_configured_service_env(&mut vars, config, service)?;
            apply_personal_overrides(&mut vars, &self.overrides);
        }
        Ok(ComposedProjectEnv {
            vars,
            overrides: self.overrides,
        })
    }

    /// [`Self::compose`] for one of several children that share the layers,
    /// such as the services of `lpm dev`, given the service's static values.
    pub(crate) fn compose_service(
        &self,
        service_env: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>, LpmError> {
        if self.overrides_applied {
            return Err(LpmError::EnvValidation(
                "service values can't follow personal overrides".to_owned(),
            ));
        }
        let mut vars = self.vars.clone();
        merge_project_env(&mut vars, service_env)?;
        remove_dangerous_env_vars(&mut vars, "service env");
        apply_personal_overrides(&mut vars, &self.overrides);
        Ok(vars)
    }
}

/// Layer 4: set and unset this machine's personal overrides, in one pass
/// over `vars`. Where the host ignores case, a name matches without case.
pub fn apply_personal_overrides(vars: &mut HashMap<String, String>, overrides: &PersonalOverrides) {
    apply_overrides_with_case_policy(vars, overrides, cfg!(windows));
}

/// An ASCII name compared and hashed without case, without allocating.
#[derive(Clone, Copy)]
struct CaselessAscii<'name>(&'name str);

impl PartialEq for CaselessAscii<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for CaselessAscii<'_> {}

impl std::hash::Hash for CaselessAscii<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            state.write_u8(byte.to_ascii_uppercase());
        }
        state.write_u8(0xff);
    }
}

fn apply_overrides_with_case_policy(
    vars: &mut HashMap<String, String>,
    overrides: &PersonalOverrides,
    case_insensitive: bool,
) {
    if overrides.is_empty() {
        return;
    }
    if case_insensitive {
        // Override names are validated ASCII, so an ASCII name matches by
        // ASCII case folding; only a non-ASCII name needs the host's rule.
        let names: HashSet<CaselessAscii<'_>> = overrides
            .set
            .keys()
            .chain(&overrides.unset)
            .map(|name| CaselessAscii(name))
            .collect();
        let mut host_names: Option<Vec<EnvName>> = None;
        vars.retain(|existing, _| {
            if existing.is_ascii() {
                return !names.contains(&CaselessAscii(existing));
            }
            let host_names = host_names
                .get_or_insert_with(|| names.iter().map(|name| EnvName::new(name.0)).collect());
            let existing = EnvName::new(existing);
            !host_names.contains(&existing)
        });
    } else {
        for name in &overrides.unset {
            vars.remove(name);
        }
    }
    vars.extend(
        overrides
            .set
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
}

/// The line `lpm` prints once per command when personal overrides apply:
/// a count only, so the names stay out of shared terminals and logs.
pub fn personal_override_notice(count: usize, environment: &str) -> Option<String> {
    (count > 0).then(|| {
        format!(
            "{count} personal override{} on this Mac appl{} to {}",
            if count == 1 { "" } else { "s" },
            if count == 1 { "ies" } else { "y" },
            lpm_common::sanitize_terminal_inline(environment)
        )
    })
}

/// Log the overridden names at debug level, which `--verbose` shows.
pub fn log_personal_override_names(overrides: &PersonalOverrides) {
    if overrides.is_empty() {
        return;
    }
    let mut names: Vec<&str> = overrides
        .set
        .keys()
        .chain(&overrides.unset)
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    tracing::debug!("personal overrides apply to: {}", names.join(", "));
}

/// Recover a stored canonical identity from configured inventory without alias resolution.
pub fn resolve_stored_project_environment(
    canonical: &str,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<lpm_env::ResolvedEnv, LpmError> {
    lpm_env::resolver::validate_env_name(canonical).map_err(LpmError::EnvValidation)?;
    let empty = HashMap::new();
    let inventory = lpm_env::resolver::list_all_from_vault_names(
        config.map_or(&empty, |config| &config.env),
        config.and_then(|config| config.environments.as_ref()),
        std::iter::empty(),
    );
    Ok(inventory
        .into_iter()
        .find(|environment| environment.canonical == canonical && !environment.implicit_default)
        .unwrap_or_else(|| lpm_env::resolver::resolve(canonical, &empty, None)))
}

/// Steps 6–8 for a child: remove dangerous names from layers 1–5, insert the
/// trusted `PATH`, then evaluate the schema. `overrides` are the personal
/// overrides layer 4 applied, for attributing failures to them.
pub(crate) fn validate_child_env(
    vars: &mut HashMap<String, String>,
    validator: Option<&lpm_env::EnvValidator<'_>>,
    context: lpm_env::EvalContext<'_>,
    path: &str,
    validate_schema: bool,
    overrides: &PersonalOverrides,
) -> Result<(), LpmError> {
    validate_child_env_with_trusted(
        vars,
        validator,
        context,
        path,
        validate_schema,
        &[],
        overrides,
    )
}

/// [`validate_child_env`] with code-owned trusted values, such as the exec
/// plan's controlled `NODE_OPTIONS`, inserted after the filter and before
/// `PATH`, so they're never filtered and never overridable.
pub(crate) fn validate_child_env_with_trusted(
    vars: &mut HashMap<String, String>,
    validator: Option<&lpm_env::EnvValidator<'_>>,
    context: lpm_env::EvalContext<'_>,
    path: &str,
    validate_schema: bool,
    trusted: &[(String, String)],
    overrides: &PersonalOverrides,
) -> Result<(), LpmError> {
    remove_dangerous_env_vars(vars, "child env");
    for (key, value) in trusted {
        insert_project_env(vars, key.clone(), value.clone());
    }
    insert_project_env(vars, "PATH".into(), path.into());
    let errors = evaluate_project_env(
        vars,
        if validate_schema { validator } else { None },
        context,
    )?;
    validation_result(errors, vars, overrides)
}

/// Apply the configured static service values before scoped CLI evaluation.
pub fn merge_configured_service_env(
    vars: &mut HashMap<String, String>,
    config: Option<&lpm_json::LpmJsonConfig>,
    service: Option<&str>,
) -> Result<(), LpmError> {
    if let (Some(name), Some(config)) = (service, config)
        && !config.services.is_empty()
        && !config.services.contains_key(name)
    {
        return Err(LpmError::EnvValidation(format!(
            "unknown service '{name}'; select a configured service"
        )));
    }
    if let Some(service) =
        service.and_then(|name| config.and_then(|config| config.services.get(name)))
    {
        merge_project_env(vars, &service.env)?;
    }
    remove_dangerous_env_vars(vars, "service env");
    Ok(())
}

/// Read layers 1, 2 and 4 of `env_name`, leaving layer 4 apart.
pub(crate) fn load_project_env_layers(
    project_dir: &Path,
    env_name: Option<&str>,
    configured_file_path: Option<&str>,
    lpm_config: Option<&lpm_json::LpmJsonConfig>,
    policy: OverridePolicy,
) -> Result<ProjectEnvLayers, LpmError> {
    if let Some(snapshot) = lpm_config.and_then(|config| config.env_schema_resolution.as_ref()) {
        snapshot
            .verify_dependencies()
            .map_err(|error| LpmError::EnvValidation(error.to_string()))?;
    }
    if let Some(env_name) = env_name {
        lpm_env::resolver::validate_env_name(env_name).map_err(LpmError::EnvValidation)?;
    }

    let mut loaded = load_project_env_files_with_config(
        project_dir,
        env_name,
        configured_file_path,
        lpm_config,
    )?;

    if !loaded.is_empty() {
        tracing::debug!(
            "loaded {} env var(s) from .env files{}",
            loaded.len(),
            env_name.map(|m| format!(" (env: {m})")).unwrap_or_default()
        );
    }

    let (vault_vars, overrides) = crate::env_access::read(|| match policy {
        OverridePolicy::Apply => lpm_vault::try_get_run_environment(project_dir, env_name)
            .map(|run| (run.values, run.overrides)),
        OverridePolicy::Exclude => match env_name {
            Some(env_name) => {
                lpm_vault::try_get_all_env_with_default_fallback(project_dir, env_name)
            }
            None => lpm_vault::try_get_all(project_dir),
        }
        .map(|values| (values, PersonalOverrides::default())),
    })
    .map_err(LpmError::EnvValidation)?;

    let vault_count = vault_vars.len();
    if vault_count > 0 {
        tracing::debug!("loaded {vault_count} env var(s) from vault");
        merge_project_env(&mut loaded, &vault_vars)?;
    }

    remove_dangerous_env_vars(&mut loaded, "project env");

    Ok(ProjectEnvLayers {
        vars: loaded,
        overrides,
        overrides_applied: false,
        vault_count,
    })
}

/// Load only project files using an already resolved environment and configuration.
pub fn load_project_env_files_with_config(
    project_dir: &Path,
    env_name: Option<&str>,
    configured_file_path: Option<&str>,
    lpm_config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<HashMap<String, String>, LpmError> {
    // Load .env files — use inheritance chain if `environments` is configured
    let loaded = if let Some(env_name) = env_name
        && let Some(config) = lpm_config
        && let Some(envs_config) = &config.environments
    {
        match lpm_env::resolve_chain(envs_config, env_name) {
            Ok(chain) => {
                tracing::debug!("resolved env chain for '{env_name}': {}", chain.join(" → "));
                load_env_from_chain(project_dir, &chain)?
            }
            Err(_) if !envs_config.envs.contains_key(env_name) => {
                // An undeclared environment must preserve an explicit file mapping.
                tracing::debug!(
                    "env '{env_name}' not in environments config, using file mapping or standard loading"
                );
                match configured_file_path {
                    Some(path) => load_env_from_configured_path(project_dir, path)?,
                    None => load_env_files(project_dir, Some(env_name))?,
                }
            }
            Err(e) => {
                // Cycle or other structural error — hard fail
                return Err(LpmError::EnvValidation(e));
            }
        }
    } else if let Some(file_path) = configured_file_path {
        load_env_from_configured_path(project_dir, file_path)?
    } else {
        // Standard loading (no environments config or no env name)
        load_env_files(project_dir, env_name)?
    };

    Ok(loaded)
}

/// Merge stored values using the runner's process-safety and casing policy.
pub fn merge_stored_project_env(
    target: &mut HashMap<String, String>,
    values: &HashMap<String, String>,
) -> Result<(), LpmError> {
    merge_project_env(target, values)?;
    remove_dangerous_env_vars(target, "project env");
    Ok(())
}

/// Resolve an explicit selection or the configured default from one snapshot.
pub fn resolve_project_environment(
    env_name: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<lpm_env::ResolvedEnv, LpmError> {
    let empty = HashMap::new();
    let mut resolved = lpm_env::resolver::resolve_checked(
        env_name.unwrap_or("default"),
        config.map_or(&empty, |config| &config.env),
        config.and_then(|config| config.environments.as_ref()),
    )
    .map_err(LpmError::EnvValidation)?;
    resolved.implicit_default = env_name.is_none() && resolved.source == lpm_env::EnvSource::Vault;
    Ok(resolved)
}

/// Load values without schema validation using an existing configuration
/// snapshot: layers 1, 2 and 4, without service values.
pub fn load_project_env_unvalidated_with_config(
    project_dir: &Path,
    env_name: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
    policy: OverridePolicy,
) -> Result<ComposedProjectEnv, LpmError> {
    let resolved = resolve_project_environment(env_name, config)?;
    load_project_env_layers_for_resolved(project_dir, &resolved, config, policy)?
        .compose(None, None)
}

/// Load an inventory or command identity without reinterpreting its storage
/// key as an alias: layers 1, 2 and 4, without service values.
pub fn load_project_env_unvalidated_for_resolved(
    project_dir: &Path,
    resolved: &lpm_env::ResolvedEnv,
    config: Option<&lpm_json::LpmJsonConfig>,
    policy: OverridePolicy,
) -> Result<ComposedProjectEnv, LpmError> {
    load_project_env_layers_for_resolved(project_dir, resolved, config, policy)?.compose(None, None)
}

/// Layers 1, 2 and 4 of a resolved identity, for a caller that merges
/// service values before the personal overrides.
pub fn load_project_env_layers_for_resolved(
    project_dir: &Path,
    resolved: &lpm_env::ResolvedEnv,
    config: Option<&lpm_json::LpmJsonConfig>,
    policy: OverridePolicy,
) -> Result<ProjectEnvLayers, LpmError> {
    load_project_env_layers(
        project_dir,
        resolved_load_mode(resolved),
        resolved.file_path.as_deref(),
        config,
        policy,
    )
}

pub(crate) fn resolved_load_mode(resolved: &lpm_env::ResolvedEnv) -> Option<&str> {
    if resolved.implicit_default {
        None
    } else {
        Some(&resolved.storage_key)
    }
}

#[cfg(test)]
pub(crate) fn validate_project_env(
    vars: &mut HashMap<String, String>,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<(), LpmError> {
    validate_project_env_with_case_policy(vars, config, cfg!(windows))
}

#[cfg(test)]
fn validate_project_env_with_case_policy(
    vars: &mut HashMap<String, String>,
    config: Option<&lpm_json::LpmJsonConfig>,
    case_insensitive: bool,
) -> Result<(), LpmError> {
    let validator = config
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let errors = evaluate_project_env_with_case_policy(
        vars,
        validator.as_ref(),
        lpm_env::EvalContext::default(),
        case_insensitive,
    )?;
    validation_result(errors, vars, &PersonalOverrides::default())?;
    remove_dangerous_env_vars(vars, "project env");
    Ok(())
}

/// Validate effective values without converting inherited values into project overrides.
pub fn evaluate_project_env(
    vars: &mut HashMap<String, String>,
    validator: Option<&lpm_env::EnvValidator<'_>>,
    context: lpm_env::EvalContext<'_>,
) -> Result<Vec<lpm_env::ValidationError>, LpmError> {
    evaluate_project_env_with_case_policy(vars, validator, context, cfg!(windows))
}

fn evaluate_project_env_with_case_policy(
    vars: &mut HashMap<String, String>,
    validator: Option<&lpm_env::EnvValidator<'_>>,
    context: lpm_env::EvalContext<'_>,
    case_insensitive: bool,
) -> Result<Vec<lpm_env::ValidationError>, LpmError> {
    validate_process_values(vars)?;
    if let Some(validator) = validator {
        let schema = validator.schema();
        let schema_names = if case_insensitive {
            lpm_env::align_declared_casing(vars, schema)
                .map_err(|conflict| LpmError::EnvValidation(conflict.to_string()))?
        } else {
            std::collections::BTreeMap::new()
        };
        let mut inherited_values = Vec::with_capacity(schema.vars.len().min(32));
        let eligible =
            |key: &str| !vars.contains_key(key) && !crate::shell::inherited_env_is_stripped(key);
        if schema
            .vars
            .keys()
            .filter(|key| eligible(key))
            .take(32)
            .count()
            == 32
        {
            for (name, value) in std::env::vars_os() {
                let Some(name) = name.to_str() else { continue };
                let key = if case_insensitive {
                    schema_names.get(&EnvName::new(name)).copied()
                } else {
                    schema.vars.get_key_value(name).map(|(key, _)| key.as_str())
                };
                let Some(key) = key else { continue };
                if vars.contains_key(key) || crate::shell::inherited_env_is_stripped(key) {
                    continue;
                }
                let value = value.into_string().map_err(|_| {
                    LpmError::EnvValidation(format!(
                        "{key}: inherited declared values must be UTF-8"
                    ))
                })?;
                inherited_values.push((key, value.is_empty()));
                vars.insert(key.to_string(), value);
            }
        } else {
            for key in schema.vars.keys() {
                if !vars.contains_key(key) && !crate::shell::inherited_env_is_stripped(key) {
                    match std::env::var(key) {
                        Ok(value) => {
                            inherited_values.push((key.as_str(), value.is_empty()));
                            vars.insert(key.clone(), value);
                        }
                        Err(std::env::VarError::NotPresent) => {}
                        Err(std::env::VarError::NotUnicode(_)) => {
                            return Err(LpmError::EnvValidation(format!(
                                "{key}: inherited declared values must be UTF-8"
                            )));
                        }
                    }
                }
            }
        }
        let errors =
            validator.validate_with_default_policy(vars, context, |key| !is_denied_env_var(key));
        // Keep defaults replacing inherited empties, while preserving cacheEnv provenance.
        for (key, was_empty) in inherited_values {
            if !was_empty || vars.get(key).is_none_or(String::is_empty) {
                vars.remove(key);
            }
        }
        return Ok(errors);
    }
    Ok(Vec::new())
}

pub(crate) fn validate_project_env_with_plan(
    vars: &mut HashMap<String, String>,
    validator: Option<&lpm_env::EnvValidator<'_>>,
    context: lpm_env::EvalContext<'_>,
    overrides: &PersonalOverrides,
) -> Result<(), LpmError> {
    let errors = evaluate_project_env(vars, validator, context)?;
    validation_result(errors, vars, overrides)?;
    remove_dangerous_env_vars(vars, "project env");
    Ok(())
}

/// Fail with every validation error, saying which ones a personal override
/// caused: the override is the key's final origin, or its `unset` left the
/// key missing. A later layer that replaced the override takes the blame
/// back. Messages never include values.
fn validation_result(
    errors: Vec<lpm_env::ValidationError>,
    vars: &HashMap<String, String>,
    overrides: &PersonalOverrides,
) -> Result<(), LpmError> {
    if errors.is_empty() {
        return Ok(());
    }
    Err(LpmError::EnvValidation(
        errors
            .iter()
            .map(|error| {
                if is_caused_by_personal_override(&error.key, vars, overrides) {
                    format!("  {error} (from a personal override on this Mac)")
                } else {
                    format!("  {error}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
    ))
}

/// Whether a personal override caused `key`'s validation failure: the
/// override is its final origin, or its `unset` left it missing.
pub fn is_caused_by_personal_override(
    key: &str,
    vars: &HashMap<String, String>,
    overrides: &PersonalOverrides,
) -> bool {
    match overrides.set.get(key) {
        Some(value) => vars.get(key) == Some(value),
        None => overrides.unset.iter().any(|name| name == key) && !vars.contains_key(key),
    }
}

pub(crate) fn merge_project_env(
    target: &mut HashMap<String, String>,
    values: &HashMap<String, String>,
) -> Result<(), LpmError> {
    merge_env_with_case_policy(target, values, cfg!(windows))
}

fn merge_env_with_case_policy(
    target: &mut HashMap<String, String>,
    values: &HashMap<String, String>,
    case_insensitive: bool,
) -> Result<(), LpmError> {
    validate_process_values(values)?;
    if case_insensitive {
        let mut names = std::collections::BTreeSet::new();
        for key in values.keys() {
            if !names.insert(EnvName::new(key)) {
                return Err(LpmError::EnvValidation(format!(
                    "ambiguous environment variable casing for '{key}'"
                )));
            }
        }
        target.retain(|existing, _| !names.contains(&EnvName::new(existing)));
    }
    target.extend(
        values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    Ok(())
}

fn validate_process_values(values: &HashMap<String, String>) -> Result<(), LpmError> {
    if let Some(key) = values
        .keys()
        .filter(|key| key.is_empty() || key.as_bytes().contains(&0) || key.contains('='))
        .min()
    {
        return Err(LpmError::EnvValidation(format!(
            "{}: process environment keys must be nonempty and cannot contain NUL or '='",
            key.escape_debug()
        )));
    }
    if let Some((key, _)) = values
        .iter()
        .filter(|(_, value)| value.as_bytes().contains(&0))
        .min_by_key(|(key, _)| *key)
    {
        return Err(LpmError::EnvValidation(format!(
            "{}: values cannot contain NUL bytes",
            key.escape_debug()
        )));
    }
    Ok(())
}

pub(crate) fn insert_project_env(target: &mut HashMap<String, String>, key: String, value: String) {
    insert_env_with_case_policy(target, key, value, cfg!(windows));
}

fn insert_env_with_case_policy(
    target: &mut HashMap<String, String>,
    key: String,
    value: String,
    case_insensitive: bool,
) {
    if case_insensitive {
        let name = EnvName::new(&key);
        target.retain(|existing, _| EnvName::new(existing) != name);
    }
    target.insert(key, value);
}

fn retain_project_env_value(key: &str) -> bool {
    crate::shell::inherited_env_is_stripped(key) || std::env::var_os(key).is_none()
}

/// Parse a `.env` file into a key-value map.
///
/// Returns an empty map if the file doesn't exist (not an error).
pub fn parse_env_file(path: &Path) -> Result<HashMap<String, String>, BoundedReadError> {
    let content = match read_text_file_capped(path, CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok(c) => c,
        Err(BoundedReadError::NotFound { .. }) => return Ok(HashMap::new()),
        Err(error) => return Err(error),
    };
    Ok(parse_env_str(&content))
}

/// Parse `.env` content string into a key-value map.
///
/// Supports multiline values enclosed in double quotes:
/// ```text
/// MY_CERT="-----BEGIN CERTIFICATE-----
/// MIIBkTCB...
/// -----END CERTIFICATE-----"
/// ```
pub fn parse_env_str(content: &str) -> HashMap<String, String> {
    parse_env_str_with_case_policy(content, cfg!(windows))
}

fn parse_env_str_with_case_policy(
    content: &str,
    case_insensitive: bool,
) -> HashMap<String, String> {
    // Strip UTF-8 BOM if present — editors like Notepad prepend it, corrupting the first key
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);

    let mut vars = HashMap::new();
    let mut names = std::collections::BTreeMap::new();
    let mut lines = content.lines();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Strip optional `export ` prefix
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        // Find the first `=` separator
        let eq_pos = match trimmed.find('=') {
            Some(pos) => pos,
            None => continue,
        };

        let key = trimmed[..eq_pos].trim().to_string();
        if key.is_empty() {
            continue;
        }
        if case_insensitive && let Some(previous) = names.insert(EnvName::new(&key), key.clone()) {
            vars.remove(&previous);
        }

        let raw_value = trimmed[eq_pos + 1..].trim();

        if let Some(rest) = raw_value.strip_prefix('"') {
            let value = lpm_vault::parse_double_quoted_env_value(rest, &mut lines);
            vars.insert(key, value);
        } else {
            let value = unquote(raw_value);
            vars.insert(key, value);
        }
    }

    vars
}

/// Remove surrounding quotes from a value.
///
/// - `"hello world"` → `hello world`
/// - `'hello world'` → `hello world`
/// - `hello world` → `hello world` (no change)
fn unquote(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let mut value = String::with_capacity(s.len() - 2);
        let mut chars = s[1..s.len() - 1].chars();
        while let Some(character) = chars.next() {
            if character != '\\' {
                value.push(character);
                continue;
            }
            match chars.next() {
                Some('n') => value.push('\n'),
                Some('r') => value.push('\r'),
                Some('t') => value.push('\t'),
                Some('"') => value.push('"'),
                Some('\\') => value.push('\\'),
                Some(other) => {
                    value.push('\\');
                    value.push(other);
                }
                None => value.push('\\'),
            }
        }
        return value;
    }
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

/// Load environment variables from a sequence of `.env` files.
///
/// Files are loaded in order — later files override earlier ones.
/// Only sets variables that are NOT already present in the process environment
/// (process env takes precedence over `.env` files).
///
/// Standard loading order:
/// 1. `.env` — default values (checked into git)
/// 2. `.env.local` — local overrides (gitignored)
/// 3. `.env.{mode}` — mode-specific (e.g., `.env.staging`)
/// 4. `.env.{mode}.local` — mode-specific local overrides
pub fn load_env_files(
    project_dir: &Path,
    mode: Option<&str>,
) -> Result<HashMap<String, String>, LpmError> {
    let mut merged = HashMap::new();

    // 1. .env
    merge_env_file(&mut merged, &contained_env_file_path(project_dir, ".env")?)?;

    // 2. .env.local
    merge_env_file(
        &mut merged,
        &contained_env_file_path(project_dir, ".env.local")?,
    )?;

    // 3 & 4. Mode-specific files
    if let Some(mode) = mode {
        merge_env_file(
            &mut merged,
            &contained_env_file_path(project_dir, &format!(".env.{mode}"))?,
        )?;
        merge_env_file(
            &mut merged,
            &contained_env_file_path(project_dir, &format!(".env.{mode}.local"))?,
        )?;
    }

    // Only inherited values retained by the child take precedence.
    merged.retain(|key, _| retain_project_env_value(key));

    remove_dangerous_env_vars(&mut merged, ".env file");

    Ok(merged)
}

/// Load environment variables from an inheritance chain of file paths.
///
/// Each file in the chain is loaded in order (base first, most specific last).
/// Later files override earlier ones. `.local` variants are loaded after each
/// file for local overrides.
///
/// Same security filtering as `load_env_files`: process env takes precedence,
/// dangerous vars are blocked.
pub fn load_env_from_chain(
    project_dir: &Path,
    file_chain: &[String],
) -> Result<HashMap<String, String>, LpmError> {
    let mut merged = HashMap::new();

    for file_path in file_chain {
        let full_path = contained_env_file_path(project_dir, file_path)?;
        merge_env_file(&mut merged, &full_path)?;

        // Also load the .local variant for each file in the chain
        // e.g., .env.staging → .env.staging.local
        let local_path = contained_env_file_path(project_dir, &format!("{file_path}.local"))?;
        merge_env_file(&mut merged, &local_path)?;
    }

    // Only inherited values retained by the child take precedence.
    merged.retain(|key, _| retain_project_env_value(key));

    remove_dangerous_env_vars(&mut merged, ".env file");

    Ok(merged)
}

fn load_env_from_configured_path(
    project_dir: &Path,
    file_path: &str,
) -> Result<HashMap<String, String>, LpmError> {
    let mut merged = HashMap::new();
    for path in [
        ".env".to_string(),
        ".env.local".to_string(),
        file_path.to_string(),
        format!("{file_path}.local"),
    ] {
        merge_env_file(&mut merged, &contained_env_file_path(project_dir, &path)?)?;
    }
    merged.retain(|key, _| retain_project_env_value(key));
    remove_dangerous_env_vars(&mut merged, ".env file");
    Ok(merged)
}

fn contained_env_file_path(project_dir: &Path, file_path: &str) -> Result<PathBuf, LpmError> {
    let path = project_dir.join(file_path);
    if !path.exists() {
        return Ok(path);
    }
    let project_root = project_dir.canonicalize().map_err(|error| {
        LpmError::EnvValidation(format!(
            "could not resolve project directory '{}': {error}",
            project_dir.display()
        ))
    })?;
    let canonical_path = path.canonicalize().map_err(|error| {
        LpmError::EnvValidation(format!(
            "could not resolve environment file '{}': {error}",
            path.display()
        ))
    })?;
    if !canonical_path.starts_with(&project_root) {
        return Err(LpmError::EnvValidation(format!(
            "environment file '{}' resolves outside the project directory",
            path.display()
        )));
    }
    Ok(canonical_path)
}

pub(crate) fn remove_dangerous_env_vars(vars: &mut HashMap<String, String>, source: &str) {
    let denied_keys: Vec<String> = vars
        .keys()
        .filter(|key| is_denied_env_var(key))
        .cloned()
        .collect();

    for denied in denied_keys {
        if vars.remove(&denied).is_some() {
            tracing::warn!(
                "ignored dangerous env var '{denied}' from {source} — this variable cannot be set via LPM project env"
            );
        }
    }
}

/// Merge a single `.env` file into an existing map (overwriting existing keys).
fn merge_env_file(target: &mut HashMap<String, String>, path: &Path) -> Result<(), LpmError> {
    let vars = parse_env_file(path).map_err(|error| LpmError::EnvValidation(error.to_string()))?;
    merge_project_env(target, &vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    mod overrides;

    #[test]
    fn stored_explicit_default_retains_named_file_selection() {
        let resolved = resolve_stored_project_environment("default", None).unwrap();
        assert!(!resolved.implicit_default);
        assert_eq!(resolved_load_mode(&resolved), Some("default"));
        assert_eq!(resolved.file_path, None);
    }

    #[cfg(windows)]
    #[test]
    fn project_hook_filter_matches_windows_process_names() {
        for alias in ["node_options", "NODE_OPTıONS", "NODE_OPTIONſ"] {
            let mut command = std::process::Command::new("unused");
            command.env("NODE_OPTIONS", "first").env(alias, "last");
            if command.get_envs().count() == 1 {
                let mut vars =
                    HashMap::from([(alias.to_string(), "--require=untrusted.cjs".to_string())]);
                remove_dangerous_env_vars(&mut vars, "regression fixture");
                assert!(vars.is_empty(), "Windows hook alias survived: {alias}");
            }
        }
    }

    #[test]
    fn case_insensitive_env_merge_applies_the_last_layer_once() {
        let mut vars = HashMap::from([("port".to_string(), "invalid".to_string())]);
        let managed = HashMap::from([("PORT".to_string(), "4000".to_string())]);
        merge_env_with_case_policy(&mut vars, &managed, true).unwrap();
        assert_eq!(vars, managed);
    }

    #[test]
    fn case_insensitive_schema_checks_the_explicit_mixed_case_value() {
        let config = lpm_json::parse_lpm_json(
            r#"{"envSchema":{"vars":{"LPM_SCHEMA_CASE_PORT":{"format":"port"}}}}"#,
        )
        .unwrap();
        let mut vars = HashMap::from([("lpm_schema_case_port".to_string(), "invalid".to_string())]);
        assert!(validate_project_env_with_case_policy(&mut vars, Some(&config), true).is_err());
    }

    #[test]
    fn case_sensitive_env_merge_preserves_distinct_names() {
        let mut vars = HashMap::from([("port".to_string(), "invalid".to_string())]);
        let managed = HashMap::from([("PORT".to_string(), "4000".to_string())]);
        merge_env_with_case_policy(&mut vars, &managed, false).unwrap();
        assert_eq!(vars.get("port").unwrap(), "invalid");
        assert_eq!(vars.get("PORT").unwrap(), "4000");
    }

    #[test]
    fn case_insensitive_schema_rejects_conflicting_names_before_defaults() {
        for rule in [r#"{"default":"3000"}"#, r#"{"required":true}"#] {
            let config = lpm_json::parse_lpm_json(&format!(
                r#"{{"envSchema":{{"vars":{{"APPLICATION_PORT":{rule},"application_port":{{"default":"4000"}}}}}}}}"#
            )).unwrap();
            let mut vars = HashMap::new();
            let error = validate_project_env_with_case_policy(&mut vars, Some(&config), true)
                .expect_err("case-insensitive schema names must be unique");
            assert!(error.to_string().contains("ambiguous"), "{error}");
            assert!(vars.is_empty(), "invalid schema applied defaults");
        }
    }

    #[test]
    fn case_insensitive_merge_applies_unicode_name_precedence() {
        let mut vars = HashMap::from([("É_VAR".to_string(), "old".to_string())]);
        let overrides = HashMap::from([("é_var".to_string(), "new".to_string())]);
        merge_env_with_case_policy(&mut vars, &overrides, true).unwrap();
        assert_eq!(vars, overrides);
    }

    #[test]
    fn insensitive_parser_preserves_the_last_spelling_and_multiline_value() {
        let source = "É_VAR=old\né_var=\"first\nsecond\"\n";
        assert_eq!(
            parse_env_str_with_case_policy(source, true),
            HashMap::from([("é_var".to_string(), "first\nsecond".to_string())])
        );
        assert_eq!(parse_env_str_with_case_policy(source, false).len(), 2);
    }

    #[test]
    fn case_sensitive_schema_keeps_distinct_defaults() {
        let config = lpm_json::parse_lpm_json(
            r#"{"envSchema":{"vars":{"APPLICATION_PORT":{"default":"3000"},"application_port":{"default":"4000"}}}}"#,
        ).unwrap();
        let mut vars = HashMap::new();
        validate_project_env_with_case_policy(&mut vars, Some(&config), false).unwrap();
        assert_eq!(vars.get("APPLICATION_PORT").unwrap(), "3000");
        assert_eq!(vars.get("application_port").unwrap(), "4000");
    }

    #[test]
    fn case_insensitive_env_merge_rejects_ambiguous_names_before_mutation() {
        let mut vars = HashMap::from([("PORT".to_string(), "3000".to_string())]);
        let original = vars.clone();
        let overrides = HashMap::from([
            ("PORT".to_string(), "4000".to_string()),
            ("port".to_string(), "5000".to_string()),
        ]);
        assert!(merge_env_with_case_policy(&mut vars, &overrides, true).is_err());
        assert_eq!(vars, original);
    }

    #[test]
    fn env_file_layers_follow_platform_name_matching() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env.local");
        fs::write(&path, "port=4000\n").unwrap();
        let mut vars = HashMap::from([("PORT".to_string(), "3000".to_string())]);
        merge_env_file(&mut vars, &path).unwrap();
        assert_eq!(vars.get("port").unwrap(), "4000");
        assert_eq!(vars.contains_key("PORT"), !cfg!(windows));
    }

    #[test]
    fn parse_basic_env() {
        let vars = parse_env_str("KEY=value\nOTHER=123");
        assert_eq!(vars.get("KEY").unwrap(), "value");
        assert_eq!(vars.get("OTHER").unwrap(), "123");
    }

    #[test]
    fn parse_double_quoted() {
        let vars = parse_env_str(r#"KEY="hello world""#);
        assert_eq!(vars.get("KEY").unwrap(), "hello world");
    }

    #[test]
    fn parse_double_quoted_value_decodes_canonical_escapes() {
        let vars = parse_env_str(r#"KEY="tab\tcr\rlf\nquote\"slash\\unknown\q""#);

        assert_eq!(
            vars.get("KEY").unwrap(),
            "tab\tcr\rlf\nquote\"slash\\unknown\\q"
        );
    }

    #[test]
    fn parse_single_quoted() {
        let vars = parse_env_str("KEY='hello world'");
        assert_eq!(vars.get("KEY").unwrap(), "hello world");
    }

    #[test]
    fn parse_export_prefix() {
        let vars = parse_env_str("export API_KEY=abc123");
        assert_eq!(vars.get("API_KEY").unwrap(), "abc123");
    }

    #[test]
    fn parse_comments_and_blanks() {
        let vars =
            parse_env_str("# This is a comment\n\nKEY=value\n  # Another comment\n\nOTHER=123");
        assert_eq!(vars.len(), 2);
        assert_eq!(vars.get("KEY").unwrap(), "value");
    }

    #[test]
    fn parse_value_with_equals() {
        let vars = parse_env_str("URL=https://example.com?a=1&b=2");
        assert_eq!(vars.get("URL").unwrap(), "https://example.com?a=1&b=2");
    }

    #[test]
    fn parse_empty_value() {
        let vars = parse_env_str("EMPTY=\nBLANK=''");
        assert_eq!(vars.get("EMPTY").unwrap(), "");
        assert_eq!(vars.get("BLANK").unwrap(), "");
    }

    #[test]
    fn parse_whitespace_around_equals() {
        let vars = parse_env_str("KEY = value");
        assert_eq!(vars.get("KEY").unwrap(), "value");
    }

    #[test]
    fn parse_no_equals_line_skipped() {
        let vars = parse_env_str("NOEQUALS\nKEY=value");
        assert_eq!(vars.len(), 1);
        assert_eq!(vars.get("KEY").unwrap(), "value");
    }

    #[test]
    fn load_env_file_missing_ok() {
        let vars = parse_env_file(Path::new("/nonexistent/.env")).unwrap();
        assert!(vars.is_empty());
    }

    #[test]
    fn load_env_files_merge_order() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "A=from-env\nB=from-env").unwrap();
        fs::write(dir.path().join(".env.local"), "B=from-local").unwrap();

        let vars = load_env_files(dir.path(), None).unwrap();
        assert_eq!(vars.get("A").unwrap(), "from-env");
        assert_eq!(vars.get("B").unwrap(), "from-local");
    }

    #[test]
    fn load_env_files_with_mode() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "A=default\nB=default").unwrap();
        fs::write(dir.path().join(".env.staging"), "B=staging").unwrap();

        let vars = load_env_files(dir.path(), Some("staging")).unwrap();
        assert_eq!(vars.get("A").unwrap(), "default");
        assert_eq!(vars.get("B").unwrap(), "staging");
    }

    #[test]
    fn process_env_takes_precedence() {
        let dir = tempfile::tempdir().unwrap();

        // HOME is always set in the process env
        fs::write(
            dir.path().join(".env"),
            "HOME=/fake/path\nLPM_TEST_UNIQUE_12345=from-dotenv",
        )
        .unwrap();

        let vars = load_env_files(dir.path(), None).unwrap();
        // HOME should be filtered out (process env wins)
        assert!(!vars.contains_key("HOME"));
        // Our unique key should be present (not in process env)
        assert_eq!(vars.get("LPM_TEST_UNIQUE_12345").unwrap(), "from-dotenv");
    }

    #[test]
    fn parse_multiline_double_quoted_value() {
        let input =
            "MY_CERT=\"-----BEGIN CERTIFICATE-----\nMIIBkTCB...\n-----END CERTIFICATE-----\"";
        let vars = parse_env_str(input);
        assert_eq!(
            vars.get("MY_CERT").unwrap(),
            "-----BEGIN CERTIFICATE-----\nMIIBkTCB...\n-----END CERTIFICATE-----"
        );
    }

    #[test]
    fn parse_multiline_mixed_with_single_line() {
        let input = "SIMPLE=hello\nMULTI=\"line1\nline2\nline3\"\nAFTER=world";
        let vars = parse_env_str(input);
        assert_eq!(vars.get("SIMPLE").unwrap(), "hello");
        assert_eq!(vars.get("MULTI").unwrap(), "line1\nline2\nline3");
        assert_eq!(vars.get("AFTER").unwrap(), "world");
    }

    #[test]
    fn parse_multiline_single_quoted_not_supported() {
        // Single-quoted multiline is intentionally not supported (matches docker/dotenv behavior)
        // Each line is treated independently
        let input = "KEY='line1\nline2'";
        let vars = parse_env_str(input);
        // Should parse as two separate lines: KEY='line1 and line2' (broken)
        // This is acceptable — multiline is only supported with double quotes
        assert!(vars.contains_key("KEY"));
    }

    #[test]
    fn bom_stripped_from_first_key() {
        let vars = parse_env_str("\u{feff}API_KEY=value\nOTHER=123");
        assert_eq!(
            vars.get("API_KEY").unwrap(),
            "value",
            "BOM should not corrupt the first key name"
        );
        assert!(
            !vars.contains_key("\u{feff}API_KEY"),
            "key should not contain BOM prefix"
        );
        assert_eq!(vars.get("OTHER").unwrap(), "123");
    }

    #[test]
    fn denied_env_vars_filtered_from_dotenv() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(
			dir.path().join(".env"),
			"LD_PRELOAD=/evil.so\nLD_AUDIT=/audit.so\nDYLD_INSERT_LIBRARIES=/evil.dylib\nNODE_OPTIONS=--require=evil\nBASH_ENV=./bad-shell-env\nNORMAL_VAR=ok\nPATH=/malicious\nHOME=/fake",
		)
		.unwrap();

        let vars = load_env_files(dir.path(), None).unwrap();
        assert!(
            !vars.contains_key("LD_PRELOAD"),
            "LD_PRELOAD should be denied"
        );
        assert!(
            !vars.contains_key("DYLD_INSERT_LIBRARIES"),
            "DYLD_INSERT_LIBRARIES should be denied"
        );
        assert!(
            !vars.contains_key("NODE_OPTIONS"),
            "NODE_OPTIONS should be denied"
        );
        assert!(!vars.contains_key("LD_AUDIT"), "LD_AUDIT should be denied");
        assert!(!vars.contains_key("BASH_ENV"), "BASH_ENV should be denied");
        assert!(!vars.contains_key("PATH"), "PATH should be denied");
        assert!(!vars.contains_key("HOME"), "HOME should be denied");
        assert_eq!(
            vars.get("NORMAL_VAR").unwrap(),
            "ok",
            "normal vars should pass through"
        );
    }

    #[test]
    fn parse_multiline_unterminated_quote_takes_rest() {
        // Unterminated double-quote consumes everything until EOF
        let input = "KEY=\"unterminated\nrest of file";
        let vars = parse_env_str(input);
        assert_eq!(vars.get("KEY").unwrap(), "unterminated\nrest of file");
    }

    #[test]
    fn inline_comment_included_in_unquoted_value() {
        // Matches Node.js `dotenv` behavior: inline comments are NOT stripped
        // from unquoted values. This is intentional — values like URLs often
        // contain `#` (fragment identifiers).
        let vars = parse_env_str("KEY=value # this is a comment");
        assert_eq!(
            vars.get("KEY").unwrap(),
            "value # this is a comment",
            "inline comment should be part of the value (matches dotenv convention)"
        );
    }

    #[test]
    fn inline_comment_stripped_from_quoted_value() {
        // Inside quotes, everything is literal including # signs
        let vars = parse_env_str(r#"KEY="value with # hash""#);
        assert_eq!(vars.get("KEY").unwrap(), "value with # hash");
    }

    #[test]
    fn value_with_hash_fragment_url() {
        // Real-world case: URLs with fragment identifiers
        let vars = parse_env_str("URL=https://example.com/page#section");
        assert_eq!(vars.get("URL").unwrap(), "https://example.com/page#section");
    }

    #[test]
    fn denied_env_vars_filtered_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "ld_preload=/lib.so\nnode_options=--require=evil\nLPM_TEST_CS_42=ok",
        )
        .unwrap();

        let vars = load_env_files(dir.path(), None).unwrap();
        assert!(
            !vars.contains_key("ld_preload"),
            "lowercase ld_preload should be denied"
        );
        assert!(
            !vars.contains_key("node_options"),
            "lowercase node_options should be denied"
        );
        assert!(vars.contains_key("LPM_TEST_CS_42"));
    }

    #[test]
    fn mode_specific_local_overrides_mode() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env.staging"), "DB=staging-db").unwrap();
        fs::write(dir.path().join(".env.staging.local"), "DB=local-override").unwrap();

        let vars = load_env_files(dir.path(), Some("staging")).unwrap();
        assert_eq!(
            vars.get("DB").unwrap(),
            "local-override",
            ".env.staging.local should override .env.staging"
        );
    }

    #[test]
    fn parse_value_with_spaces_unquoted() {
        // Unquoted value with spaces — should be trimmed at the start but kept otherwise
        let vars = parse_env_str("KEY=  hello world  ");
        // trim() is applied to raw_value, so leading spaces are stripped
        assert_eq!(vars.get("KEY").unwrap(), "hello world");
    }

    /// Regression: undeclared env with `environments` config falls back to standard loading.
    ///
    /// When lpm.json has `environments: { staging: ... }` but we request "preview",
    /// the loader should fall back to `.env.preview` via `load_env_files` instead of
    /// failing with "environment 'preview' not found".
    #[test]
    fn load_project_env_undeclared_env_falls_back_to_standard_loading() {
        let dir = tempfile::tempdir().unwrap();

        // lpm.json with environments config that does NOT include "preview"
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "environments": {
                    "base": ".env",
                    "staging": { "extends": "base", "file": ".env.staging" }
                }
            }"#,
        )
        .unwrap();

        fs::write(dir.path().join(".env"), "BASE=from-base").unwrap();
        fs::write(
            dir.path().join(".env.preview"),
            "PREVIEW_KEY=from-preview-file",
        )
        .unwrap();

        // Skip schema validation for this test
        crate::script::set_skip_env_validation(true);
        let result = load_project_env(dir.path(), Some("preview"), OverridePolicy::Exclude);
        crate::script::set_skip_env_validation(false);

        let vars = result.expect("should fall back to standard loading, not error");
        assert_eq!(
            vars.get("PREVIEW_KEY").unwrap(),
            "from-preview-file",
            ".env.preview should be loaded via standard fallback"
        );
        // .env (base) should also be loaded in the standard cascade
        assert_eq!(
            vars.get("BASE").unwrap(),
            "from-base",
            ".env should be loaded as part of the standard cascade"
        );
    }

    /// Regression: inheritance cycle still hard-fails even with the fallback.
    ///
    /// The "not found" fallback must NOT suppress real inheritance errors
    /// like cycles or broken parent references.
    #[test]
    fn load_project_env_cycle_still_errors() {
        let dir = tempfile::tempdir().unwrap();

        // Circular: a extends b, b extends a
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "environments": {
                    "a": { "extends": "b", "file": ".env.a" },
                    "b": { "extends": "a", "file": ".env.b" }
                }
            }"#,
        )
        .unwrap();

        fs::write(dir.path().join(".env.a"), "A=1").unwrap();
        fs::write(dir.path().join(".env.b"), "B=2").unwrap();

        crate::script::set_skip_env_validation(true);
        let result = load_project_env(dir.path(), Some("a"), OverridePolicy::Exclude);
        crate::script::set_skip_env_validation(false);

        assert!(
            result.is_err(),
            "circular inheritance should still hard-fail"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("circular"),
            "error should mention circular: {err}"
        );
    }
    #[test]
    fn undeclared_nul_values_are_rejected_without_a_schema() {
        let mut values = HashMap::from([("UNDECLARED".into(), "private\0fixture".into())]);
        let error = validate_project_env(&mut values, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("UNDECLARED"));
        assert!(error.contains("NUL"));
        assert!(!error.contains("private"));
    }
    #[test]
    fn dotenv_format_preserves_unicode_whitespace_in_values() {
        for value in ["\u{00a0}hello\u{00a0}", "\u{2003}hello\u{2003}"] {
            let vars = HashMap::from([("VALUE".into(), value.into())]);
            let text =
                lpm_env::format_env(&vars, lpm_env::PrintFormat::Dotenv, &Default::default());
            assert_eq!(parse_env_str(&text), vars);
        }
    }

    #[test]
    fn undeclared_nul_keys_are_rejected_without_retaining_values() {
        for key in ["BAD\0NAME", "BAD=NAME", ""] {
            let mut values = HashMap::from([(key.into(), "private-fixture-value".into())]);
            let error = validate_project_env(&mut values, None)
                .unwrap_err()
                .to_string();
            assert!(error.contains("NUL"));
            assert!(!error.contains("private-fixture-value"));
        }
    }
}
