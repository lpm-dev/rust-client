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
use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::Path;

/// Load the fully-resolved environment for a project.
///
/// This is the **single entry point** for all env loading in LPM. Used by
/// `lpm run`, `lpm dev`, `lpm exec`, `lpm use vars print`, and `lpm use vars check`.
///
/// Resolution order:
/// 1. `.env` files (via inheritance chain if `environments` is configured, else standard cascade)
/// 2. Vault secrets (environment-specific if available, else default)
/// 3. Schema validation + default injection (if `envSchema` is configured)
///
/// # Arguments
/// * `project_dir` — project root
/// * `env_name` — optional environment name (from `--env` flag or lpm.json mapping)
pub fn load_project_env(
    project_dir: &Path,
    env_name: Option<&str>,
) -> Result<HashMap<String, String>, LpmError> {
    let lpm_config = lpm_json::read_lpm_json(project_dir).ok().flatten();

    // Validate env name to prevent path traversal
    let env_name = env_name.filter(|m| {
        if !m.is_empty()
            && !m.contains('/')
            && !m.contains('\\')
            && !m.contains("..")
            && !m.contains('\0')
        {
            true
        } else {
            tracing::warn!(
                "ignoring invalid env mode '{m}' — must not contain path separators, '..', or null bytes"
            );
            false
        }
    });

    // Load .env files — use inheritance chain if `environments` is configured
    let mut loaded = if let Some(env_name) = env_name
        && let Some(config) = &lpm_config
        && let Some(envs_config) = &config.environments
    {
        // Resolve the inheritance chain — hard error on cycle or missing parent
        let chain =
            lpm_env::resolve_chain(envs_config, env_name).map_err(LpmError::EnvValidation)?;

        tracing::debug!("resolved env chain for '{env_name}': {}", chain.join(" → "));
        load_env_from_chain(project_dir, &chain)
    } else {
        // Standard loading (no environments config or no env name)
        load_env_files(project_dir, env_name)
    };

    if !loaded.is_empty() {
        tracing::debug!(
            "loaded {} env var(s) from .env files{}",
            loaded.len(),
            env_name.map(|m| format!(" (env: {m})")).unwrap_or_default()
        );
    }

    // Load vault secrets — use environment-specific vault if available
    let vault_vars = if let Some(env_name) = env_name {
        let env_vars = lpm_vault::get_all_env(project_dir, env_name);
        if env_vars.is_empty() {
            lpm_vault::get_all(project_dir)
        } else {
            env_vars
        }
    } else {
        lpm_vault::get_all(project_dir)
    };

    if !vault_vars.is_empty() {
        tracing::debug!("loaded {} env var(s) from vault", vault_vars.len());
        loaded.extend(vault_vars);
    }

    // Validate against env schema (if defined in lpm.json)
    if !crate::script::should_skip_env_validation()
        && let Some(config) = &lpm_config
        && let Some(schema) = &config.env_schema
        && !schema.is_empty()
    {
        let errors = lpm_env::validate(schema, &mut loaded);
        if !errors.is_empty() {
            let lines: Vec<String> = errors.iter().map(|e| format!("  {e}")).collect();
            return Err(LpmError::EnvValidation(lines.join("\n")));
        }
        tracing::debug!("env schema validation passed ({} vars)", schema.len());
    }

    Ok(loaded)
}

/// Parse a `.env` file into a key-value map.
///
/// Returns an empty map if the file doesn't exist (not an error).
pub fn parse_env_file(path: &Path) -> HashMap<String, String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };
    parse_env_str(&content)
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
    // Strip UTF-8 BOM if present — editors like Notepad prepend it, corrupting the first key
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);

    let mut vars = HashMap::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }

        // Strip optional `export ` prefix
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        // Find the first `=` separator
        let eq_pos = match trimmed.find('=') {
            Some(pos) => pos,
            None => {
                i += 1;
                continue;
            }
        };

        let key = trimmed[..eq_pos].trim().to_string();
        if key.is_empty() {
            i += 1;
            continue;
        }

        let raw_value = trimmed[eq_pos + 1..].trim();

        // Check for multiline double-quoted value: starts with `"` but doesn't end with `"`
        if raw_value.starts_with('"') && !(raw_value.len() >= 2 && raw_value.ends_with('"')) {
            // Multiline: collect lines until we find a closing `"`
            let mut parts = vec![&raw_value[1..]]; // Strip leading quote
            i += 1;
            while i < lines.len() {
                let line = lines[i];
                if let Some(stripped) = line.strip_suffix('"') {
                    parts.push(stripped);
                    i += 1;
                    break;
                }
                parts.push(line);
                i += 1;
            }
            // If we hit EOF without closing quote, join everything we have
            vars.insert(key, parts.join("\n"));
        } else {
            let value = unquote(raw_value);
            vars.insert(key, value);
            i += 1;
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
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
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
pub fn load_env_files(project_dir: &Path, mode: Option<&str>) -> HashMap<String, String> {
    let mut merged = HashMap::new();

    // 1. .env
    merge_env_file(&mut merged, &project_dir.join(".env"));

    // 2. .env.local
    merge_env_file(&mut merged, &project_dir.join(".env.local"));

    // 3 & 4. Mode-specific files
    if let Some(mode) = mode {
        merge_env_file(&mut merged, &project_dir.join(format!(".env.{mode}")));
        merge_env_file(&mut merged, &project_dir.join(format!(".env.{mode}.local")));
    }

    // Filter out vars that already exist in process environment
    // (process env takes precedence)
    merged.retain(|key, _| std::env::var(key).is_err());

    // Remove dangerous env vars that should never come from .env files.
    // These can be exploited to inject shared libraries, alter runtime behavior,
    // or hijack PATH resolution even when the process env doesn't already set them.
    const DENIED_ENV_VARS: &[&str] = &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "NODE_OPTIONS",
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "TERM",
    ];
    for &denied in DENIED_ENV_VARS {
        if merged.remove(denied).is_some() {
            tracing::warn!(
                "ignored dangerous env var '{denied}' from .env file — this variable cannot be set via .env"
            );
        }
    }

    merged
}

/// Load environment variables from an inheritance chain of file paths.
///
/// Each file in the chain is loaded in order (base first, most specific last).
/// Later files override earlier ones. `.local` variants are loaded after each
/// file for local overrides.
///
/// Same security filtering as `load_env_files`: process env takes precedence,
/// dangerous vars are blocked.
pub fn load_env_from_chain(project_dir: &Path, file_chain: &[String]) -> HashMap<String, String> {
    let mut merged = HashMap::new();

    for file_path in file_chain {
        let full_path = project_dir.join(file_path);
        merge_env_file(&mut merged, &full_path);

        // Also load the .local variant for each file in the chain
        // e.g., .env.staging → .env.staging.local
        let local_path = project_dir.join(format!("{file_path}.local"));
        merge_env_file(&mut merged, &local_path);
    }

    // Filter out vars that already exist in process environment
    merged.retain(|key, _| std::env::var(key).is_err());

    // Remove dangerous env vars
    const DENIED_ENV_VARS: &[&str] = &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "NODE_OPTIONS",
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "TERM",
    ];
    for &denied in DENIED_ENV_VARS {
        if merged.remove(denied).is_some() {
            tracing::warn!(
                "ignored dangerous env var '{denied}' from .env file — this variable cannot be set via .env"
            );
        }
    }

    merged
}

/// Merge a single `.env` file into an existing map (overwriting existing keys).
fn merge_env_file(target: &mut HashMap<String, String>, path: &Path) {
    let vars = parse_env_file(path);
    for (k, v) in vars {
        target.insert(k, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        let vars = parse_env_file(Path::new("/nonexistent/.env"));
        assert!(vars.is_empty());
    }

    #[test]
    fn load_env_files_merge_order() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "A=from-env\nB=from-env").unwrap();
        fs::write(dir.path().join(".env.local"), "B=from-local").unwrap();

        let vars = load_env_files(dir.path(), None);
        assert_eq!(vars.get("A").unwrap(), "from-env");
        assert_eq!(vars.get("B").unwrap(), "from-local");
    }

    #[test]
    fn load_env_files_with_mode() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "A=default\nB=default").unwrap();
        fs::write(dir.path().join(".env.staging"), "B=staging").unwrap();

        let vars = load_env_files(dir.path(), Some("staging"));
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

        let vars = load_env_files(dir.path(), None);
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
			"LD_PRELOAD=/evil.so\nDYLD_INSERT_LIBRARIES=/evil.dylib\nNODE_OPTIONS=--require=evil\nNORMAL_VAR=ok\nPATH=/malicious\nHOME=/fake",
		)
		.unwrap();

        let vars = load_env_files(dir.path(), None);
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
    fn denied_vars_case_sensitive() {
        // Denylist should be case-sensitive — ld_preload (lowercase) should pass
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "ld_preload=/lib.so\nLPM_TEST_CS_42=ok",
        )
        .unwrap();

        let vars = load_env_files(dir.path(), None);
        // lowercase variant is NOT in the denylist
        assert!(
            vars.contains_key("ld_preload"),
            "lowercase variant should pass through"
        );
        assert!(vars.contains_key("LPM_TEST_CS_42"));
    }

    #[test]
    fn mode_specific_local_overrides_mode() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env.staging"), "DB=staging-db").unwrap();
        fs::write(dir.path().join(".env.staging.local"), "DB=local-override").unwrap();

        let vars = load_env_files(dir.path(), Some("staging"));
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
}
