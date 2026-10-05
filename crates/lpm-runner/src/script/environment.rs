use super::{mark_script_child_env, should_skip_env_validation};
use crate::npm_context::NpmScriptContext;
use crate::{dotenv, lpm_json};
use lpm_common::color::Painted;
use lpm_common::{LpmError, sanitize_terminal_inline};
use std::collections::HashMap;
use std::path::Path;

/// Print a one-line environment context before script execution.
///
/// Example output:
///   Env: development (via lpm.json "dev") · 5 vault secrets
pub(super) fn print_env_context(loaded: &LoadedEnv) {
    let env_label = sanitize_terminal_inline(loaded.env_name.as_deref().unwrap_or("default"));

    let via = match (loaded.source, &loaded.alias) {
        ("--env flag", _) => format!("via {}", "--env".dimmed()),
        ("lpm.json task", _) => "via lpm.json task".to_string(),
        ("lpm.json", Some(alias)) => {
            format!(
                "via lpm.json \"{}\"",
                sanitize_terminal_inline(alias).dimmed()
            )
        }
        _ => String::new(),
    };

    let vault_str = if loaded.vault_count > 0 {
        format!(
            "{} vault secret{}",
            loaded.vault_count,
            if loaded.vault_count == 1 { "" } else { "s" }
        )
    } else {
        String::new()
    };

    // Build parts and join with " · "
    let mut parts = Vec::new();
    if !via.is_empty() {
        parts.push(via);
    }
    if !vault_str.is_empty() {
        parts.push(vault_str);
    }

    if parts.is_empty() {
        eprintln!("  {} {}", "Env:".dimmed(), env_label.bold());
    } else {
        eprintln!(
            "  {} {} ({})",
            "Env:".dimmed(),
            env_label.bold(),
            parts.join(" · ").dimmed()
        );
    }
}

/// Result of environment resolution + loading, including display metadata.
pub(crate) struct LoadedEnv {
    /// The loaded environment variables to inject into the child process.
    pub(crate) vars: HashMap<String, String>,
    /// The canonical environment name (e.g., "development", "production").
    /// `None` if no env was resolved (just .env + .env.local).
    pub(crate) env_name: Option<String>,
    /// The alias that resolved to this env (e.g., "dev" → "development").
    alias: Option<String>,
    /// How the env was determined.
    source: &'static str,
    /// Number of vault secrets loaded for this env.
    vault_count: usize,
}

/// Resolve the env mode and load environment variables.
///
/// Loading order (later sources override earlier):
/// 1. `.env` → `.env.local` → `.env.{mode}` → `.env.{mode}.local`
/// 2. **LPM Vault** (Keychain-backed secrets) — highest priority
///
/// Priority for determining the mode:
/// 1. Explicit `--env=staging` flag (highest priority)
/// 2. `lpm.json` `env` mapping for this script name
/// 3. No mode (load just `.env` and `.env.local`)
pub(super) fn resolve_and_load_env(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
) -> Result<LoadedEnv, LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::EnvValidation)?;
    resolve_and_load_env_with_config(project_dir, script_name, explicit_mode, config.as_ref())
}

pub(super) fn resolve_and_load_env_with_config(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<LoadedEnv, LpmError> {
    resolve_and_load_env_with_schema_validation(
        project_dir,
        script_name,
        explicit_mode,
        config,
        !should_skip_env_validation(),
    )
}

pub(crate) fn resolve_and_load_env_with_schema_validation(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
    validate_schema: bool,
) -> Result<LoadedEnv, LpmError> {
    // Determine the canonical env name via the resolver.
    // Priority: 1. explicit --env flag  2. lpm.json script mapping  3. None
    let (resolved, source) = if let Some(m) = explicit_mode {
        let resolved = match config {
            Some(c) => lpm_env::resolver::resolve_checked(m, &c.env, c.environments.as_ref())
                .map_err(LpmError::EnvValidation)?,
            None => lpm_env::resolver::resolve_checked(m, &Default::default(), None)
                .map_err(LpmError::EnvValidation)?,
        };
        (Some(resolved), "--env flag")
    } else if let Some(task_mode) = config
        .and_then(|config| config.tasks.get(script_name))
        .and_then(|task| task.env.as_deref())
    {
        let config = config.expect("task mode requires lpm.json");
        let resolved = lpm_env::resolver::resolve_checked(
            task_mode,
            &config.env,
            config.environments.as_ref(),
        )
        .map_err(LpmError::EnvValidation)?;
        (Some(resolved), "lpm.json task")
    } else {
        match config.and_then(|c| {
            lpm_env::resolver::resolve_from_script(script_name, &c.env, c.environments.as_ref())
        }) {
            Some(resolved) => (Some(resolved), "lpm.json"),
            None => (
                Some(dotenv::resolve_project_environment(None, config)?),
                "default",
            ),
        }
    };
    if let Some(resolved) = &resolved {
        lpm_env::resolver::validate_env_name(&resolved.canonical)
            .map_err(LpmError::EnvValidation)?;
    }
    let env_name = resolved.as_ref().map(|env| env.canonical.as_str());
    let load_mode = resolved.as_ref().and_then(dotenv::resolved_load_mode);
    let file_path = resolved.as_ref().and_then(|env| env.file_path.as_deref());
    let mut loaded = dotenv::load_project_env_details_with_config_and_schema_validation(
        project_dir,
        load_mode,
        file_path,
        config,
        false,
    )?;
    if validate_schema {
        let validator = config
            .and_then(|config| config.env_schema.as_ref())
            .map(lpm_env::EnvValidator::new);
        dotenv::validate_project_env_with_plan(
            &mut loaded.vars,
            validator.as_ref(),
            lpm_env::EvalContext {
                environment: env_name.unwrap_or("default"),
                stage: lpm_env::EnvStage::for_script(script_name),
                service: None,
            },
        )?;
    }

    Ok(LoadedEnv {
        vars: loaded.vars,
        env_name: env_name.map(str::to_string),
        alias: resolved.and_then(|env| env.alias),
        source,
        vault_count: loaded.vault_count,
    })
}

/// Load the exact environment that a named script or task receives.
///
/// This applies the same precedence as script execution: an explicit mode,
/// then `tasks.<name>.env`, then the `lpm.json` script mapping, then the
/// default environment.
pub fn load_script_env(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
) -> Result<HashMap<String, String>, LpmError> {
    Ok(resolve_and_load_env(project_dir, script_name, explicit_mode)?.vars)
}

/// Load a script environment using a configuration that the caller already parsed.
pub fn load_script_env_with_config(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<HashMap<String, String>, LpmError> {
    Ok(resolve_and_load_env_with_config(project_dir, script_name, explicit_mode, config)?.vars)
}

/// Load the validated final script environment for task-cache fingerprinting.
pub fn load_script_child_env_with_config(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
    path: &str,
    command: &str,
    context: &NpmScriptContext,
) -> Result<HashMap<String, String>, LpmError> {
    let loaded = resolve_and_load_env_with_schema_validation(
        project_dir,
        script_name,
        explicit_mode,
        config,
        false,
    )?;
    let mut vars = loaded.vars;
    mark_script_child_env(&mut vars);
    context.apply(&mut vars, script_name, command);
    let validate_schema = !should_skip_env_validation();
    let validator = config
        .filter(|_| validate_schema)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    dotenv::validate_child_env(
        &mut vars,
        validator.as_ref(),
        lpm_env::EvalContext {
            environment: loaded.env_name.as_deref().unwrap_or("default"),
            stage: lpm_env::EnvStage::for_script(script_name),
            service: None,
        },
        path,
        validate_schema,
    )?;
    Ok(vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn script_env_mapping_loads_the_exact_configured_file_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("config")).unwrap();
        fs::write(
            dir.path().join("config/dev.env"),
            "LPM_EXACT_ENV_MAPPING_TEST=from-configured-path\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(".env.dev"),
            "LPM_EXACT_ENV_MAPPING_TEST=from-derived-path\n",
        )
        .unwrap();
        let config = lpm_json::parse_lpm_json(r#"{"env":{"dev":"config/dev.env"}}"#).unwrap();

        let loaded = load_script_env_with_config(dir.path(), "dev", None, Some(&config)).unwrap();

        assert_eq!(
            loaded.get("LPM_EXACT_ENV_MAPPING_TEST").map(String::as_str),
            Some("from-configured-path")
        );
    }
}
