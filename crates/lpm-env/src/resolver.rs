//! Canonical environment identity resolution.
//!
//! Every environment in LPM has a **canonical name** — the single key used in
//! vault storage, cloud sync, dashboard tabs, and platform push. This module
//! provides the single resolver that all code paths consume.
//!
//! The resolver accepts extracted fields from `lpm.json` (not `LpmJsonConfig`
//! directly) to keep `lpm-env` as a leaf crate with no internal dependencies.
//!
//! # Resolution Order
//!
//! 1. If input matches a canonical name in `environments` config → use directly
//! 2. If input matches a script alias in `env` config → resolve to extracted mode
//! 3. If input is an extracted mode that an alias maps to → use directly
//! 4. Otherwise → use input as-is (custom environment)

use crate::EnvironmentsConfig;
use std::collections::{HashMap, HashSet};

/// A resolved environment identity used consistently across CLI, vault, runner, and sync.
#[derive(Debug, Clone)]
pub struct ResolvedEnv {
    /// The canonical name — the intended identity for this environment.
    /// Derived from config or, for legacy/unknown keys, identical to `storage_key`.
    pub canonical: String,

    /// The actual key used in vault storage. Usually equals `canonical`,
    /// but differs for legacy entries (e.g., vault has `"dev"` while canonical
    /// is `"development"`).
    pub storage_key: String,

    /// The user-facing alias from `lpm.json` `env` keys, if any.
    pub alias: Option<String>,

    /// The `.env` file path, if configured.
    pub file_path: Option<String>,

    /// Where this entry was discovered from.
    pub source: EnvSource,

    /// Whether this env is marked sensitive (requires extra auth in dashboard).
    pub sensitive: bool,
}

/// Where an environment entry was discovered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvSource {
    /// From `lpm.json` `env` or `environments` config.
    Config,
    /// From vault storage, matching a known canonical name.
    Vault,
    /// From vault storage, NOT matching any canonical name from config.
    /// These are legacy keys that should be migrated.
    Legacy,
}

/// Extract the env mode from a `.env.{mode}` filename.
///
/// ```text
/// .env.development → Some("development")
/// .env.staging     → Some("staging")
/// .env             → None
/// ```
pub fn extract_mode_from_env_path(env_path: &str) -> Option<&str> {
    env_path.strip_prefix(".env.")
}

/// Validate an environment name for use as a vault key.
///
/// Rejects empty, too-long, path-traversal, and reserved names.
pub fn validate_env_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("environment name cannot be empty".into());
    }
    if name.len() > 64 {
        return Err("environment name too long (max 64 chars)".into());
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") || name.contains('\0') {
        return Err("environment name contains invalid characters".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(
            "environment name may only contain a-z, 0-9, hyphens, underscores, and dots".into(),
        );
    }
    if name == "__index__" {
        return Err("'__index__' is a reserved name".into());
    }
    Ok(())
}

/// Resolve a user-provided env name to a canonical identity.
///
/// This is **infallible** — read paths (list, get, print, diff, check) never
/// fail on env name. Use [`resolve_checked`] at write boundaries.
///
/// Takes extracted fields from `lpm.json`, NOT `LpmJsonConfig` directly,
/// to keep `lpm-env` as a leaf crate (no dependency on `lpm-runner`).
pub fn resolve(
    input: &str,
    env_map: &HashMap<String, String>,
    environments: Option<&EnvironmentsConfig>,
) -> ResolvedEnv {
    // 1. Check `environments` config (inheritance-based)
    if let Some(envs) = environments
        && envs.envs.contains_key(input)
    {
        return ResolvedEnv {
            canonical: input.to_string(),
            storage_key: input.to_string(),
            alias: find_alias_for_mode(env_map, input),
            file_path: envs
                .envs
                .get(input)
                .and_then(|d| d.file().map(String::from)),
            source: EnvSource::Config,
            sensitive: is_sensitive_by_name(input),
        };
    }

    // 2. Check `env` script alias mapping (e.g., "dev" → ".env.development" → "development")
    if let Some(file_path) = env_map.get(input) {
        let mode = extract_mode_from_env_path(file_path)
            .unwrap_or(input)
            .to_string();
        return ResolvedEnv {
            canonical: mode.clone(),
            storage_key: mode.clone(),
            alias: Some(input.to_string()),
            file_path: Some(file_path.clone()),
            source: EnvSource::Config,
            sensitive: is_sensitive_by_name(&mode),
        };
    }

    // 3. Check if input is an extracted mode that an alias maps to
    for (alias, file_path) in env_map {
        if let Some(mode) = extract_mode_from_env_path(file_path)
            && mode == input
        {
            return ResolvedEnv {
                canonical: input.to_string(),
                storage_key: input.to_string(),
                alias: Some(alias.clone()),
                file_path: Some(file_path.clone()),
                source: EnvSource::Config,
                sensitive: is_sensitive_by_name(input),
            };
        }
    }

    // 4. Fallback: use input as-is (custom or unknown environment)
    ResolvedEnv {
        canonical: input.to_string(),
        storage_key: input.to_string(),
        alias: None,
        file_path: None,
        source: EnvSource::Vault,
        sensitive: is_sensitive_by_name(input),
    }
}

/// Resolve + validate. Use at **write boundaries** (set, delete, import, create).
///
/// Returns `Err` if the resolved canonical name fails validation.
pub fn resolve_checked(
    input: &str,
    env_map: &HashMap<String, String>,
    environments: Option<&EnvironmentsConfig>,
) -> Result<ResolvedEnv, String> {
    let resolved = resolve(input, env_map, environments);
    validate_env_name(&resolved.canonical)?;
    Ok(resolved)
}

/// Resolve from a script name (e.g., `lpm run dev` → script\_name=`"dev"`).
///
/// Delegates to [`resolve`] so precedence rules are shared — if `environments`
/// has a key matching the script name, that takes priority over the `env` alias
/// mapping. Returns `None` only if neither `environments` nor `env` has the name.
pub fn resolve_from_script(
    script_name: &str,
    env_map: &HashMap<String, String>,
    environments: Option<&EnvironmentsConfig>,
) -> Option<ResolvedEnv> {
    // Check if the script name resolves to anything via the shared resolver.
    let resolved = resolve(script_name, env_map, environments);

    // resolve() always returns *something* (fallback). Only return Some if
    // it actually matched config — not if it fell through to the Vault fallback.
    if resolved.source == EnvSource::Config {
        Some(resolved)
    } else {
        None
    }
}

/// List all known environments from config + vault.
///
/// Vault keys that match a known canonical name are merged (`source: Vault`).
/// Vault keys that DON'T match any canonical are surfaced as separate entries
/// with `source: Legacy`. These represent stored secrets under a raw key
/// that the resolver doesn't recognize. They are **never** collapsed or hidden.
pub fn list_all(
    env_map: &HashMap<String, String>,
    environments: Option<&EnvironmentsConfig>,
    vault_envs: &HashMap<String, HashMap<String, String>>,
) -> Vec<ResolvedEnv> {
    let mut canonical_names = HashSet::new();
    let mut result = Vec::new();

    // Always include "default" first
    canonical_names.insert("default".to_string());
    result.push(ResolvedEnv {
        canonical: "default".to_string(),
        storage_key: "default".to_string(),
        alias: None,
        file_path: Some(".env".to_string()),
        source: EnvSource::Config,
        sensitive: false,
    });

    // From lpm.json `env` mapping (canonical = extracted mode)
    let mut sorted_env: Vec<_> = env_map.iter().collect();
    sorted_env.sort_by_key(|(alias, _)| alias.as_str());
    for (_, file_path) in &sorted_env {
        if let Some(mode) = extract_mode_from_env_path(file_path)
            && canonical_names.insert(mode.to_string())
        {
            result.push(resolve(mode, env_map, environments));
        }
    }

    // From `environments` config
    if let Some(envs) = environments {
        let mut sorted_names: Vec<_> = envs.envs.keys().collect();
        sorted_names.sort();
        for name in sorted_names {
            if canonical_names.insert(name.clone()) {
                result.push(resolve(name, env_map, environments));
            }
        }
    }

    // From vault — check each key against the canonical set.
    // DON'T call resolve() for unrecognized keys — that would canonicalize
    // "dev" → "development" and hide the legacy storage key.
    let mut sorted_vault: Vec<_> = vault_envs.keys().collect();
    sorted_vault.sort();
    for vault_key in sorted_vault {
        if canonical_names.contains(vault_key) {
            // Already listed from config. Mark source as Vault.
            if let Some(entry) = result.iter_mut().find(|e| e.canonical == *vault_key)
                && entry.source == EnvSource::Config
            {
                entry.source = EnvSource::Vault;
            }
        } else {
            // Vault key doesn't match any canonical name — surface as Legacy.
            canonical_names.insert(vault_key.clone());
            result.push(ResolvedEnv {
                canonical: vault_key.clone(),
                storage_key: vault_key.clone(),
                alias: None,
                file_path: None,
                source: EnvSource::Legacy,
                sensitive: is_sensitive_by_name(vault_key),
            });
        }
    }

    result
}

fn find_alias_for_mode(env_map: &HashMap<String, String>, mode: &str) -> Option<String> {
    for (alias, file_path) in env_map {
        if extract_mode_from_env_path(file_path) == Some(mode) {
            return Some(alias.clone());
        }
    }
    None
}

fn is_sensitive_by_name(name: &str) -> bool {
    name.contains("prod") || name.contains("live")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_env_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("dev".into(), ".env.development".into());
        m.insert("staging".into(), ".env.staging".into());
        m.insert("prod".into(), ".env.production".into());
        m
    }

    // -- extract_mode_from_env_path --

    #[test]
    fn extract_mode_development() {
        assert_eq!(
            extract_mode_from_env_path(".env.development"),
            Some("development")
        );
    }

    #[test]
    fn extract_mode_staging() {
        assert_eq!(extract_mode_from_env_path(".env.staging"), Some("staging"));
    }

    #[test]
    fn extract_mode_bare_env() {
        assert_eq!(extract_mode_from_env_path(".env"), None);
    }

    // -- validate_env_name --

    #[test]
    fn validate_valid_names() {
        assert!(validate_env_name("default").is_ok());
        assert!(validate_env_name("production").is_ok());
        assert!(validate_env_name("staging.eu").is_ok());
        assert!(validate_env_name("my-env_1").is_ok());
    }

    #[test]
    fn validate_empty() {
        assert!(validate_env_name("").is_err());
    }

    #[test]
    fn validate_too_long() {
        let long = "a".repeat(65);
        assert!(validate_env_name(&long).is_err());
    }

    #[test]
    fn validate_path_traversal() {
        assert!(validate_env_name("../etc").is_err());
        assert!(validate_env_name("foo/bar").is_err());
        assert!(validate_env_name("foo\\bar").is_err());
    }

    #[test]
    fn validate_reserved() {
        assert!(validate_env_name("__index__").is_err());
    }

    #[test]
    fn validate_invalid_chars() {
        assert!(validate_env_name("env name").is_err());
        assert!(validate_env_name("env@name").is_err());
    }

    // -- resolve --

    #[test]
    fn resolve_alias_to_canonical() {
        let env_map = make_env_map();
        let r = resolve("dev", &env_map, None);
        assert_eq!(r.canonical, "development");
        assert_eq!(r.storage_key, "development");
        assert_eq!(r.alias, Some("dev".into()));
        assert_eq!(r.file_path, Some(".env.development".into()));
        assert_eq!(r.source, EnvSource::Config);
    }

    #[test]
    fn resolve_canonical_name_directly() {
        let env_map = make_env_map();
        let r = resolve("development", &env_map, None);
        assert_eq!(r.canonical, "development");
        assert_eq!(r.alias, Some("dev".into()));
        assert_eq!(r.source, EnvSource::Config);
    }

    #[test]
    fn resolve_production() {
        let env_map = make_env_map();
        let r = resolve("production", &env_map, None);
        assert_eq!(r.canonical, "production");
        assert_eq!(r.alias, Some("prod".into()));
        assert!(r.sensitive);
    }

    #[test]
    fn resolve_custom_unknown() {
        let env_map = make_env_map();
        let r = resolve("custom", &env_map, None);
        assert_eq!(r.canonical, "custom");
        assert_eq!(r.alias, None);
        assert_eq!(r.source, EnvSource::Vault);
    }

    #[test]
    fn resolve_no_config() {
        let empty = HashMap::new();
        let r = resolve("dev", &empty, None);
        assert_eq!(r.canonical, "dev");
        assert_eq!(r.alias, None);
    }

    // -- resolve_checked --

    #[test]
    fn resolve_checked_valid() {
        let env_map = make_env_map();
        let r = resolve_checked("dev", &env_map, None);
        assert!(r.is_ok());
        assert_eq!(r.unwrap().canonical, "development");
    }

    #[test]
    fn resolve_checked_invalid_rejects() {
        let empty = HashMap::new();
        let r = resolve_checked("../etc", &empty, None);
        assert!(r.is_err());
    }

    // -- resolve_from_script --

    #[test]
    fn resolve_from_script_found() {
        let env_map = make_env_map();
        let r = resolve_from_script("dev", &env_map, None).unwrap();
        assert_eq!(r.canonical, "development");
        assert_eq!(r.alias, Some("dev".into()));
    }

    #[test]
    fn resolve_from_script_not_found() {
        let env_map = make_env_map();
        assert!(resolve_from_script("unknown", &env_map, None).is_none());
    }

    #[test]
    fn resolve_from_script_environments_takes_priority_over_alias() {
        // Config collision: env.dev = ".env.development" AND environments.dev = { file: ".env.dev" }
        // environments should win in both resolve() and resolve_from_script()
        let mut env_map = HashMap::new();
        env_map.insert("dev".into(), ".env.development".into());

        let mut envs_map = HashMap::new();
        envs_map.insert("dev".into(), crate::EnvDefinition::File(".env.dev".into()));
        let envs = EnvironmentsConfig { envs: envs_map };

        let from_resolve = resolve("dev", &env_map, Some(&envs));
        let from_script = resolve_from_script("dev", &env_map, Some(&envs)).unwrap();

        // Both must agree: environments wins, canonical = "dev" (not "development")
        assert_eq!(from_resolve.canonical, "dev");
        assert_eq!(from_script.canonical, "dev");
        assert_eq!(from_resolve.canonical, from_script.canonical);
    }

    #[test]
    fn sensitive_derived_from_canonical_not_alias() {
        // "release" alias maps to .env.production → canonical "production"
        // sensitive should be true (from "production"), not false (from "release")
        let mut env_map = HashMap::new();
        env_map.insert("release".into(), ".env.production".into());

        let r = resolve("release", &env_map, None);
        assert_eq!(r.canonical, "production");
        assert_eq!(r.alias, Some("release".into()));
        assert!(
            r.sensitive,
            "sensitive should derive from canonical 'production', not alias 'release'"
        );

        let r2 = resolve_from_script("release", &env_map, None).unwrap();
        assert_eq!(r2.canonical, "production");
        assert!(r2.sensitive);
    }

    // -- list_all --

    #[test]
    fn list_all_config_only() {
        let env_map = make_env_map();
        let vault = HashMap::new();
        let list = list_all(&env_map, None, &vault);

        let names: Vec<&str> = list.iter().map(|e| e.canonical.as_str()).collect();
        assert_eq!(names, &["default", "development", "production", "staging"]);

        // All from config
        for entry in &list {
            assert_eq!(entry.source, EnvSource::Config);
        }
    }

    #[test]
    fn list_all_vault_matches_canonical() {
        let env_map = make_env_map();
        let mut vault = HashMap::new();
        vault.insert("development".into(), HashMap::new());
        vault.insert("staging".into(), HashMap::new());

        let list = list_all(&env_map, None, &vault);

        // "development" and "staging" should be Vault source (exists in both)
        let dev = list.iter().find(|e| e.canonical == "development").unwrap();
        assert_eq!(dev.source, EnvSource::Vault);
        let stg = list.iter().find(|e| e.canonical == "staging").unwrap();
        assert_eq!(stg.source, EnvSource::Vault);
        // "production" still Config (not in vault)
        let prod = list.iter().find(|e| e.canonical == "production").unwrap();
        assert_eq!(prod.source, EnvSource::Config);
    }

    #[test]
    fn list_all_legacy_vault_key_surfaces_separately() {
        let env_map = make_env_map();
        let mut vault = HashMap::new();
        // "dev" is a legacy key — config maps "dev" alias → canonical "development"
        vault.insert("dev".into(), HashMap::new());
        vault.insert("development".into(), HashMap::new());

        let list = list_all(&env_map, None, &vault);

        let names: Vec<&str> = list.iter().map(|e| e.canonical.as_str()).collect();
        // Should have both "development" (canonical) and "dev" (legacy)
        assert!(names.contains(&"development"));
        assert!(names.contains(&"dev"));

        let legacy = list.iter().find(|e| e.storage_key == "dev").unwrap();
        assert_eq!(legacy.source, EnvSource::Legacy);

        let canonical = list.iter().find(|e| e.canonical == "development").unwrap();
        assert_eq!(canonical.source, EnvSource::Vault);
    }

    #[test]
    fn list_all_deduplicates_matching_vault_key() {
        let env_map = make_env_map();
        let mut vault = HashMap::new();
        vault.insert("development".into(), HashMap::new());

        let list = list_all(&env_map, None, &vault);

        // Only one "development" entry, not two
        let dev_count = list.iter().filter(|e| e.canonical == "development").count();
        assert_eq!(dev_count, 1);
    }

    #[test]
    fn list_all_sensitive_detection() {
        let env_map = make_env_map();
        let vault = HashMap::new();
        let list = list_all(&env_map, None, &vault);

        let prod = list.iter().find(|e| e.canonical == "production").unwrap();
        assert!(prod.sensitive);
        let dev = list.iter().find(|e| e.canonical == "development").unwrap();
        assert!(!dev.sensitive);
    }
}
