//! Environment inheritance resolution.
//!
//! Resolves environment file chains from `lpm.json` `environments` config.
//! Each environment can extend another, forming an inheritance chain.
//!
//! Example:
//! ```json
//! {
//!   "environments": {
//!     "base": ".env",
//!     "development": { "extends": "base", "file": ".env.development" },
//!     "staging": { "extends": "base", "file": ".env.staging" },
//!     "preview": { "extends": "staging" },
//!     "production": { "extends": "base", "file": ".env.production" }
//!   }
//! }
//! ```
//!
//! Resolution for `preview`: base (.env) → staging (.env.staging) → preview (no file, inherits all)

use serde::Deserialize;
use std::collections::HashMap;

/// Named environment definitions with optional inheritance.
///
/// Deserialized from `lpm.json`:
/// ```json
/// { "environments": { "staging": { "extends": "base", "file": ".env.staging" } } }
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnvironmentsConfig {
    #[serde(flatten)]
    pub envs: HashMap<String, EnvDefinition>,
}

/// A single environment definition — either a file path string or a structured object.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EnvDefinition {
    /// Simple: just a file path (e.g., `"base": ".env"`)
    File(String),
    /// Structured: with optional extends and file
    Structured {
        /// Parent environment to inherit from.
        #[serde(default)]
        extends: Option<String>,
        /// The .env file for this environment (optional — may inherit everything).
        #[serde(default)]
        file: Option<String>,
    },
}

impl EnvDefinition {
    /// Get the file path for this environment (if any).
    pub fn file(&self) -> Option<&str> {
        match self {
            EnvDefinition::File(f) => Some(f.as_str()),
            EnvDefinition::Structured { file, .. } => file.as_deref(),
        }
    }

    /// Get the parent environment name (if any).
    pub fn extends(&self) -> Option<&str> {
        match self {
            EnvDefinition::File(_) => None,
            EnvDefinition::Structured { extends, .. } => extends.as_deref(),
        }
    }
}

/// Resolve the inheritance chain for a named environment.
///
/// Returns a list of `.env` file paths to load, in order (base first, most specific last).
/// Later files override earlier ones.
///
/// # Errors
///
/// Returns `Err` if:
/// - The environment name is not found in the config
/// - A circular inheritance chain is detected
/// - An `extends` references a non-existent environment
pub fn resolve_chain(config: &EnvironmentsConfig, env_name: &str) -> Result<Vec<String>, String> {
    let mut chain = Vec::new();
    let mut visited = Vec::new();
    collect_chain(config, env_name, &mut chain, &mut visited)?;
    Ok(chain)
}

/// Recursively collect the file chain, base-first.
fn collect_chain(
    config: &EnvironmentsConfig,
    env_name: &str,
    chain: &mut Vec<String>,
    visited: &mut Vec<String>,
) -> Result<(), String> {
    // Cycle detection
    if visited.contains(&env_name.to_string()) {
        return Err(format!(
            "circular environment inheritance: {} → {env_name}",
            visited.join(" → ")
        ));
    }

    let def = config
        .envs
        .get(env_name)
        .ok_or_else(|| format!("environment '{env_name}' not found in lpm.json environments"))?;

    visited.push(env_name.to_string());

    // Recurse into parent first (base-first ordering)
    if let Some(parent) = def.extends() {
        collect_chain(config, parent, chain, visited)?;
    }

    // Add this environment's file (if it has one)
    if let Some(file) = def.file() {
        chain.push(file.to_string());
    }

    Ok(())
}

/// List all environment names defined in the config.
pub fn list_environments(config: &EnvironmentsConfig) -> Vec<&str> {
    let mut names: Vec<&str> = config.envs.keys().map(|k| k.as_str()).collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from_json(json: &str) -> EnvironmentsConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn simple_file_definition() {
        let config = config_from_json(r#"{"base": ".env"}"#);
        let chain = resolve_chain(&config, "base").unwrap();
        assert_eq!(chain, vec![".env"]);
    }

    #[test]
    fn structured_definition_with_file() {
        let config =
            config_from_json(r#"{"development": {"extends": null, "file": ".env.development"}}"#);
        let chain = resolve_chain(&config, "development").unwrap();
        assert_eq!(chain, vec![".env.development"]);
    }

    #[test]
    fn single_level_inheritance() {
        let config = config_from_json(
            r#"{
                "base": ".env",
                "development": {"extends": "base", "file": ".env.development"}
            }"#,
        );
        let chain = resolve_chain(&config, "development").unwrap();
        assert_eq!(chain, vec![".env", ".env.development"]);
    }

    #[test]
    fn multi_level_inheritance() {
        let config = config_from_json(
            r#"{
                "base": ".env",
                "staging": {"extends": "base", "file": ".env.staging"},
                "preview": {"extends": "staging"}
            }"#,
        );
        let chain = resolve_chain(&config, "preview").unwrap();
        // base (.env) → staging (.env.staging) → preview (no file)
        assert_eq!(chain, vec![".env", ".env.staging"]);
    }

    #[test]
    fn full_example_from_spec() {
        let config = config_from_json(
            r#"{
                "base": ".env",
                "development": {"extends": "base", "file": ".env.development"},
                "staging": {"extends": "base", "file": ".env.staging"},
                "preview": {"extends": "staging"},
                "production": {"extends": "base", "file": ".env.production"}
            }"#,
        );

        // development: base → development
        assert_eq!(
            resolve_chain(&config, "development").unwrap(),
            vec![".env", ".env.development"]
        );

        // staging: base → staging
        assert_eq!(
            resolve_chain(&config, "staging").unwrap(),
            vec![".env", ".env.staging"]
        );

        // preview: base → staging → (preview has no file)
        assert_eq!(
            resolve_chain(&config, "preview").unwrap(),
            vec![".env", ".env.staging"]
        );

        // production: base → production
        assert_eq!(
            resolve_chain(&config, "production").unwrap(),
            vec![".env", ".env.production"]
        );

        // base: just .env
        assert_eq!(resolve_chain(&config, "base").unwrap(), vec![".env"]);
    }

    #[test]
    fn circular_inheritance_detected() {
        let config = config_from_json(
            r#"{
                "a": {"extends": "b"},
                "b": {"extends": "a"}
            }"#,
        );
        let err = resolve_chain(&config, "a").unwrap_err();
        assert!(err.contains("circular"), "error: {err}");
    }

    #[test]
    fn self_referencing_detected() {
        let config = config_from_json(r#"{"loop": {"extends": "loop"}}"#);
        let err = resolve_chain(&config, "loop").unwrap_err();
        assert!(err.contains("circular"), "error: {err}");
    }

    #[test]
    fn missing_parent_detected() {
        let config =
            config_from_json(r#"{"child": {"extends": "nonexistent", "file": ".env.child"}}"#);
        let err = resolve_chain(&config, "child").unwrap_err();
        assert!(err.contains("not found"), "error: {err}");
    }

    #[test]
    fn missing_environment_detected() {
        let config = config_from_json(r#"{"base": ".env"}"#);
        let err = resolve_chain(&config, "nonexistent").unwrap_err();
        assert!(err.contains("not found"), "error: {err}");
    }

    #[test]
    fn three_level_chain() {
        let config = config_from_json(
            r#"{
                "base": ".env",
                "mid": {"extends": "base", "file": ".env.mid"},
                "leaf": {"extends": "mid", "file": ".env.leaf"}
            }"#,
        );
        let chain = resolve_chain(&config, "leaf").unwrap();
        assert_eq!(chain, vec![".env", ".env.mid", ".env.leaf"]);
    }

    #[test]
    fn list_environments_sorted() {
        let config = config_from_json(
            r#"{"production": ".env.prod", "base": ".env", "staging": ".env.staging"}"#,
        );
        let names = list_environments(&config);
        assert_eq!(names, vec!["base", "production", "staging"]);
    }

    #[test]
    fn structured_without_file_or_extends() {
        let config = config_from_json(r#"{"empty": {"extends": null}}"#);
        let chain = resolve_chain(&config, "empty").unwrap();
        assert!(chain.is_empty(), "no files in chain");
    }

    #[test]
    fn env_definition_accessors() {
        let file_def: EnvDefinition = serde_json::from_str(r#"".env""#).unwrap();
        assert_eq!(file_def.file(), Some(".env"));
        assert_eq!(file_def.extends(), None);

        let struct_def: EnvDefinition =
            serde_json::from_str(r#"{"extends": "base", "file": ".env.dev"}"#).unwrap();
        assert_eq!(struct_def.file(), Some(".env.dev"));
        assert_eq!(struct_def.extends(), Some("base"));

        let no_file: EnvDefinition = serde_json::from_str(r#"{"extends": "staging"}"#).unwrap();
        assert_eq!(no_file.file(), None);
        assert_eq!(no_file.extends(), Some("staging"));
    }
}
