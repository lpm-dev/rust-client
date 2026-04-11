//! LPM Vault — Keychain-backed secret storage for project environment variables.
//!
//! Provides a secure, per-project secret store that integrates with `lpm run`
//! for automatic env var injection. Secrets are stored in the macOS Keychain
//! on macOS, with an encrypted file fallback on other platforms.
//!
//! ## Keychain Contract (shared with SwiftUI Vault app)
//!
//! Both the CLI and the native macOS Vault app read/write the same Keychain items:
//! - Service: `dev.lpm.vault`
//! - Index item (account: `__index__`): JSON array of project metadata
//! - Data items (account: `{vault-id}`): JSON dict of secrets
//!
//! ## Usage
//!
//! ```ignore
//! // Store a secret
//! lpm_vault::set(&project_dir, &[("DB_HOST", "localhost")])?;
//!
//! // Get all secrets (for lpm run injection)
//! let secrets = lpm_vault::get_all(&project_dir);
//! ```

pub mod crypto;
mod fallback;
pub mod sync;
pub mod vault_id;

#[cfg(target_os = "macos")]
pub mod keychain;

use std::collections::HashMap;
use std::path::Path;

fn force_file_vault_backend() -> bool {
    matches!(
        std::env::var("LPM_FORCE_FILE_VAULT").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

/// Get a single secret value by key (from "default" environment).
pub fn get(project_dir: &Path, key: &str) -> Option<String> {
    let secrets = get_all(project_dir);
    secrets.get(key).cloned()
}

/// Get all vault secrets for the project (from "default" environment).
///
/// Returns an empty HashMap if no vault exists (backwards compatible).
pub fn get_all(project_dir: &Path) -> HashMap<String, String> {
    get_all_env(project_dir, "default")
}

/// Get all environments with their secrets.
///
/// Returns `{"default": {"KEY": "VALUE"}, "live": {"KEY": "VALUE"}}`.
/// Empty map if no vault exists.
pub fn get_all_environments(project_dir: &Path) -> HashMap<String, HashMap<String, String>> {
    let vault_id = match vault_id::read_vault_id(project_dir) {
        Some(id) => id,
        None => return HashMap::new(),
    };

    if force_file_vault_backend() {
        return fallback::read_all_environments(&vault_id).unwrap_or_default();
    }

    #[cfg(target_os = "macos")]
    {
        keychain::read_all_environments(&vault_id).unwrap_or_default()
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback::read_all_environments(&vault_id).unwrap_or_default()
    }
}

/// Get all vault secrets for a specific environment.
pub fn get_all_env(project_dir: &Path, env: &str) -> HashMap<String, String> {
    let vault_id = match vault_id::read_vault_id(project_dir) {
        Some(id) => id,
        None => return HashMap::new(),
    };

    read_secrets_env(&vault_id, env).unwrap_or_default()
}

/// Set one or more secrets in the vault.
///
/// Creates the vault (and vault ID in lpm.json) if it doesn't exist.
pub fn set(project_dir: &Path, pairs: &[(&str, &str)]) -> Result<(), String> {
    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let mut secrets = read_secrets(&vault_id).unwrap_or_default();

    for (key, value) in pairs {
        secrets.insert(key.to_string(), value.to_string());
    }

    write_secrets(&vault_id, &project_name, &project_path, &secrets)
}

/// Set secrets for a specific environment.
pub fn set_env(project_dir: &Path, env: &str, pairs: &[(&str, &str)]) -> Result<(), String> {
    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let mut secrets = read_secrets_env(&vault_id, env).unwrap_or_default();

    for (key, value) in pairs {
        secrets.insert(key.to_string(), value.to_string());
    }

    write_secrets_env(&vault_id, &project_name, &project_path, env, &secrets)
}

pub fn replace_all_environments(
    project_dir: &Path,
    environments: &HashMap<String, HashMap<String, String>>,
) -> Result<(), String> {
    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    write_all_environments(&vault_id, &project_name, &project_path, environments)
}

/// Delete one or more secrets from the vault.
pub fn delete(project_dir: &Path, keys: &[&str]) -> Result<(), String> {
    let vault_id = match vault_id::read_vault_id(project_dir) {
        Some(id) => id,
        None => return Err("no vault configured for this project".to_string()),
    };

    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let mut secrets = read_secrets(&vault_id).unwrap_or_default();

    for key in keys {
        secrets.remove(*key);
    }

    write_secrets(&vault_id, &project_name, &project_path, &secrets)
}

/// Get a single secret from a specific environment.
pub fn get_env(project_dir: &Path, env: &str, key: &str) -> Option<String> {
    get_all_env(project_dir, env).get(key).cloned()
}

/// Delete secrets from a specific environment.
pub fn delete_env(project_dir: &Path, env: &str, keys: &[&str]) -> Result<(), String> {
    let vault_id = match vault_id::read_vault_id(project_dir) {
        Some(id) => id,
        None => return Err("no vault configured for this project".to_string()),
    };

    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let mut secrets = read_secrets_env(&vault_id, env).unwrap_or_default();
    for key in keys {
        secrets.remove(*key);
    }
    write_secrets_env(&vault_id, &project_name, &project_path, env, &secrets)
}

/// List all secret keys (without values) for the project.
pub fn list_keys(project_dir: &Path) -> Vec<String> {
    let secrets = get_all(project_dir);
    let mut keys: Vec<String> = secrets.into_keys().collect();
    keys.sort();
    keys
}

/// Import secrets from a .env file into the vault.
///
/// Returns the number of imported secrets.
pub fn import_env_file(
    project_dir: &Path,
    env_path: &Path,
    overwrite: bool,
) -> Result<usize, String> {
    let content = std::fs::read_to_string(env_path)
        .map_err(|e| format!("failed to read {}: {e}", env_path.display()))?;

    let parsed = parse_env_content(&content);
    if parsed.is_empty() {
        return Ok(0);
    }

    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let mut secrets = read_secrets(&vault_id).unwrap_or_default();
    let mut imported = 0;

    for (key, value) in &parsed {
        if overwrite || !secrets.contains_key(key) {
            secrets.insert(key.clone(), value.clone());
            imported += 1;
        }
    }

    write_secrets(&vault_id, &project_name, &project_path, &secrets)?;

    // Auto-add the .env file to .gitignore
    add_to_gitignore(project_dir, env_path);

    Ok(imported)
}

/// Import secrets from a .env file into a specific environment.
///
/// Returns the number of imported secrets.
pub fn import_env_file_to_env(
    project_dir: &Path,
    env: &str,
    env_path: &Path,
    overwrite: bool,
) -> Result<usize, String> {
    let content = std::fs::read_to_string(env_path)
        .map_err(|e| format!("failed to read {}: {e}", env_path.display()))?;

    let parsed = parse_env_content(&content);
    if parsed.is_empty() {
        return Ok(0);
    }

    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let mut secrets = read_secrets_env(&vault_id, env).unwrap_or_default();
    let mut imported = 0;

    for (key, value) in &parsed {
        if overwrite || !secrets.contains_key(key) {
            secrets.insert(key.clone(), value.clone());
            imported += 1;
        }
    }

    write_secrets_env(&vault_id, &project_name, &project_path, env, &secrets)?;
    add_to_gitignore(project_dir, env_path);

    Ok(imported)
}

/// Export secrets from a specific environment to a .env file.
///
/// Returns the number of exported secrets.
pub fn export_env_file_from_env(
    project_dir: &Path,
    env: &str,
    output_path: &Path,
) -> Result<usize, String> {
    let secrets = get_all_env(project_dir, env);
    if secrets.is_empty() {
        return Ok(0);
    }

    let mut lines: Vec<String> = secrets
        .iter()
        .map(|(k, v)| {
            if v.contains(' ') || v.contains('"') || v.contains('\'') || v.contains('\n') {
                format!("{k}=\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                format!("{k}={v}")
            }
        })
        .collect();
    lines.sort();

    let content = lines.join("\n") + "\n";
    std::fs::write(output_path, content)
        .map_err(|e| format!("failed to write {}: {e}", output_path.display()))?;

    add_to_gitignore(project_dir, output_path);

    Ok(secrets.len())
}

/// Export vault secrets to a .env file.
///
/// Returns the number of exported secrets.
pub fn export_env_file(project_dir: &Path, output_path: &Path) -> Result<usize, String> {
    let secrets = get_all(project_dir);
    if secrets.is_empty() {
        return Ok(0);
    }

    let mut lines: Vec<String> = secrets
        .iter()
        .map(|(k, v)| {
            if v.contains(' ') || v.contains('"') || v.contains('\'') || v.contains('\n') {
                format!("{k}=\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                format!("{k}={v}")
            }
        })
        .collect();
    lines.sort();

    let content = lines.join("\n") + "\n";
    std::fs::write(output_path, content)
        .map_err(|e| format!("failed to write {}: {e}", output_path.display()))?;

    // Auto-add the output file to .gitignore
    add_to_gitignore(project_dir, output_path);

    Ok(secrets.len())
}

// ─── Platform dispatch ─────────────────────────────────────────────

fn read_secrets(vault_id: &str) -> Option<HashMap<String, String>> {
    read_secrets_env(vault_id, "default")
}

fn read_secrets_env(vault_id: &str, env: &str) -> Option<HashMap<String, String>> {
    if force_file_vault_backend() {
        return fallback::read_vault_file_env(vault_id, env);
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(secrets) = keychain::read_vault_env(vault_id, env) {
            return Some(secrets);
        }
    }

    // Fallback now supports environments
    fallback::read_vault_file_env(vault_id, env)
}

fn write_secrets(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    secrets: &HashMap<String, String>,
) -> Result<(), String> {
    if force_file_vault_backend() {
        return fallback::write_vault_file(vault_id, secrets);
    }

    #[cfg(target_os = "macos")]
    {
        keychain::write_vault(vault_id, project_name, project_path, secrets)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (project_name, project_path); // unused on non-macOS
        fallback::write_vault_file(vault_id, secrets)
    }
}

fn write_secrets_env(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    env: &str,
    secrets: &HashMap<String, String>,
) -> Result<(), String> {
    if force_file_vault_backend() {
        return fallback::write_vault_file_env(vault_id, env, secrets);
    }

    #[cfg(target_os = "macos")]
    {
        keychain::write_vault_env(vault_id, project_name, project_path, env, secrets)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (project_name, project_path);
        fallback::write_vault_file_env(vault_id, env, secrets)
    }
}

fn write_all_environments(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &HashMap<String, HashMap<String, String>>,
) -> Result<(), String> {
    if force_file_vault_backend() {
        return fallback::write_all_environments(vault_id, environments);
    }

    #[cfg(target_os = "macos")]
    {
        keychain::write_all_environments(vault_id, project_name, project_path, environments)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (project_name, project_path);
        fallback::write_all_environments(vault_id, environments)
    }
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Parse a .env file content into key-value pairs.
///
/// Public so callers like `vars init` can count variables before importing.
pub fn parse_env_content(content: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    let mut lines = content.lines();

    while let Some(line) = lines.next() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip optional `export ` prefix
        let line = line.strip_prefix("export ").unwrap_or(line);

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = parse_env_value(value.trim_start(), &mut lines);

            if !key.is_empty() {
                vars.insert(key, value);
            }
        }
    }

    vars
}

fn parse_env_value(value: &str, lines: &mut std::str::Lines<'_>) -> String {
    if let Some(rest) = value.strip_prefix('"') {
        return parse_quoted_env_value(rest, '"', lines);
    }

    if let Some(rest) = value.strip_prefix('\'') {
        return parse_quoted_env_value(rest, '\'', lines);
    }

    value.trim().to_string()
}

fn parse_quoted_env_value(value: &str, quote: char, lines: &mut std::str::Lines<'_>) -> String {
    let mut collected = String::new();
    let mut fragment = value;

    loop {
        if let Some(close_idx) = find_closing_quote(fragment, quote) {
            collected.push_str(&fragment[..close_idx]);
            return if quote == '"' {
                unescape_double_quoted(&collected)
            } else {
                collected
            };
        }

        collected.push_str(fragment);

        match lines.next() {
            Some(next_line) => {
                collected.push('\n');
                fragment = next_line;
            }
            None => {
                return if quote == '"' {
                    unescape_double_quoted(&collected)
                } else {
                    collected
                };
            }
        }
    }
}

fn find_closing_quote(value: &str, quote: char) -> Option<usize> {
    if quote == '\'' {
        return value.find(quote);
    }

    let mut escaped = false;
    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == quote {
            return Some(idx);
        }
    }

    None
}

fn unescape_double_quoted(value: &str) -> String {
    let mut unescaped = String::new();
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            unescaped.push(ch);
            continue;
        }

        match chars.next() {
            Some('n') => unescaped.push('\n'),
            Some('r') => unescaped.push('\r'),
            Some('t') => unescaped.push('\t'),
            Some('"') => unescaped.push('"'),
            Some('\\') => unescaped.push('\\'),
            Some(other) => {
                unescaped.push('\\');
                unescaped.push(other);
            }
            None => unescaped.push('\\'),
        }
    }

    unescaped
}

/// Add a file path to .gitignore if not already present.
fn add_to_gitignore(project_dir: &Path, file_path: &Path) {
    let gitignore_path = project_dir.join(".gitignore");

    let relative = file_path
        .strip_prefix(project_dir)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| file_path.display().to_string());

    let existing = std::fs::read_to_string(&gitignore_path).unwrap_or_default();

    // Check if already in .gitignore
    for line in existing.lines() {
        let line = line.trim();
        if line == relative || line == format!("/{relative}") {
            return;
        }
    }

    // Append to .gitignore
    let entry = if existing.ends_with('\n') || existing.is_empty() {
        format!("{relative}\n")
    } else {
        format!("\n{relative}\n")
    };

    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gitignore_path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(entry.as_bytes())
        })
    {
        tracing::debug!("failed to update .gitignore: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keychain-touching tests must be serialized — they share the `__index__` item.
    static KEYCHAIN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Clean up Keychain items created by a test (prevents Keychain pollution).
    fn cleanup_vault(project_dir: &Path) {
        if let Some(vault_id) = vault_id::read_vault_id(project_dir) {
            #[cfg(target_os = "macos")]
            {
                let _ = keychain::delete_vault(&vault_id);
            }
            let _ = fallback::delete_vault_file(&vault_id);
        }
    }

    #[test]
    fn parse_env_basic() {
        let content = "DB_HOST=localhost\nAPI_KEY=sk-123\nPORT=3000";
        let vars = parse_env_content(content);
        assert_eq!(vars["DB_HOST"], "localhost");
        assert_eq!(vars["API_KEY"], "sk-123");
        assert_eq!(vars["PORT"], "3000");
    }

    #[test]
    fn parse_env_with_quotes() {
        let content = r#"KEY1="value with spaces"
KEY2='literal value'
KEY3=no-quotes"#;
        let vars = parse_env_content(content);
        assert_eq!(vars["KEY1"], "value with spaces");
        assert_eq!(vars["KEY2"], "literal value");
        assert_eq!(vars["KEY3"], "no-quotes");
    }

    #[test]
    fn parse_env_skips_comments_and_empty() {
        let content = "# comment\n\nKEY=value\n  # another comment\n";
        let vars = parse_env_content(content);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars["KEY"], "value");
    }

    #[test]
    fn parse_env_export_prefix() {
        let content = "export DB_HOST=localhost\nexport API_KEY=sk-123";
        let vars = parse_env_content(content);
        assert_eq!(vars["DB_HOST"], "localhost");
        assert_eq!(vars["API_KEY"], "sk-123");
    }

    #[test]
    fn parse_env_value_with_equals() {
        let content = "DATABASE_URL=postgres://user:pass@host:5432/db?ssl=true";
        let vars = parse_env_content(content);
        assert_eq!(
            vars["DATABASE_URL"],
            "postgres://user:pass@host:5432/db?ssl=true"
        );
    }

    #[test]
    fn parse_env_multiline_double_quoted_value_round_trips_export_format() {
        let content = "PRIVATE_KEY=\"line one\nline two \\\"quoted\\\" \\\\ path\"\nNEXT=value\n";
        let vars = parse_env_content(content);

        assert_eq!(vars["PRIVATE_KEY"], "line one\nline two \"quoted\" \\ path");
        assert_eq!(vars["NEXT"], "value");
    }

    #[test]
    fn add_to_gitignore_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env.local");

        add_to_gitignore(dir.path(), &env_path);

        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(content.contains(".env.local"));
    }

    #[test]
    fn add_to_gitignore_skips_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), ".env.local\n").unwrap();

        let env_path = dir.path().join(".env.local");
        add_to_gitignore(dir.path(), &env_path);

        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(content.matches(".env.local").count(), 1);
    }

    #[test]
    fn set_and_get_all_round_trip() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();

        set(
            dir.path(),
            &[("DB_HOST", "localhost"), ("API_KEY", "sk-123")],
        )
        .unwrap();

        let secrets = get_all(dir.path());
        assert_eq!(secrets["DB_HOST"], "localhost");
        assert_eq!(secrets["API_KEY"], "sk-123");

        let vault_id = vault_id::read_vault_id(dir.path());
        assert!(vault_id.is_some());

        cleanup_vault(dir.path());
    }

    #[test]
    fn delete_secrets() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();

        set(dir.path(), &[("A", "1"), ("B", "2"), ("C", "3")]).unwrap();
        delete(dir.path(), &["B"]).unwrap();

        let secrets = get_all(dir.path());
        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains_key("A"));
        assert!(!secrets.contains_key("B"));
        assert!(secrets.contains_key("C"));

        cleanup_vault(dir.path());
    }

    #[test]
    fn list_keys_sorted() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();

        set(
            dir.path(),
            &[("ZEBRA", "z"), ("APPLE", "a"), ("MANGO", "m")],
        )
        .unwrap();

        let keys = list_keys(dir.path());
        assert_eq!(keys, vec!["APPLE", "MANGO", "ZEBRA"]);

        cleanup_vault(dir.path());
    }

    #[test]
    fn get_all_returns_empty_without_vault() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = get_all(dir.path());
        assert!(secrets.is_empty());
    }

    #[test]
    fn import_and_export_round_trip() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env.import-test");
        std::fs::write(&env_file, "DB=localhost\nPORT=3000\n").unwrap();

        let imported = import_env_file(dir.path(), &env_file, false).unwrap();
        assert_eq!(imported, 2);

        let export_file = dir.path().join(".env.exported");
        let exported = export_env_file(dir.path(), &export_file).unwrap();
        assert_eq!(exported, 2);

        let content = std::fs::read_to_string(&export_file).unwrap();
        assert!(content.contains("DB=localhost"));
        assert!(content.contains("PORT=3000"));

        cleanup_vault(dir.path());
    }

    #[test]
    fn import_and_export_round_trip_multiline_secret() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env.multiline");
        std::fs::write(
            &env_file,
            "PRIVATE_KEY=\"line one\nline two \\\"quoted\\\" \\\\ path\"\nPLAIN=value\n",
        )
        .unwrap();

        let imported = import_env_file(dir.path(), &env_file, false).unwrap();
        assert_eq!(imported, 2);

        let secrets = get_all(dir.path());
        assert_eq!(
            secrets["PRIVATE_KEY"],
            "line one\nline two \"quoted\" \\ path"
        );
        assert_eq!(secrets["PLAIN"], "value");

        let export_file = dir.path().join(".env.multiline.exported");
        let exported = export_env_file(dir.path(), &export_file).unwrap();
        assert_eq!(exported, 2);

        let reparsed = parse_env_content(&std::fs::read_to_string(&export_file).unwrap());
        assert_eq!(
            reparsed["PRIVATE_KEY"],
            "line one\nline two \"quoted\" \\ path"
        );
        assert_eq!(reparsed["PLAIN"], "value");

        cleanup_vault(dir.path());
    }

    #[test]
    fn import_no_overwrite() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();

        set(dir.path(), &[("KEY", "original")]).unwrap();

        let env_file = dir.path().join(".env.test");
        std::fs::write(&env_file, "KEY=overwritten\nNEW=added").unwrap();

        let imported = import_env_file(dir.path(), &env_file, false).unwrap();
        assert_eq!(imported, 1);

        let secrets = get_all(dir.path());
        assert_eq!(secrets["KEY"], "original");
        assert_eq!(secrets["NEW"], "added");

        cleanup_vault(dir.path());
    }

    #[test]
    fn import_with_overwrite() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();

        set(dir.path(), &[("KEY", "original")]).unwrap();

        let env_file = dir.path().join(".env.test");
        std::fs::write(&env_file, "KEY=overwritten").unwrap();

        let imported = import_env_file(dir.path(), &env_file, true).unwrap();
        assert_eq!(imported, 1);

        let secrets = get_all(dir.path());
        assert_eq!(secrets["KEY"], "overwritten");

        cleanup_vault(dir.path());
    }

    #[test]
    fn import_adds_to_gitignore() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();

        let env_file = dir.path().join(".env.local");
        std::fs::write(&env_file, "KEY=val").unwrap();

        import_env_file(dir.path(), &env_file, false).unwrap();

        let gitignore = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(gitignore.contains(".env.local"));

        cleanup_vault(dir.path());
    }

    /// Regression: `replace_all_environments` must wipe local-only environments
    /// AND replace (not merge) per-environment secrets, so a `vars pull` after a
    /// stale local edit ends up byte-identical to the cloud snapshot.
    ///
    /// Mirrors `tests/workflows/tests/env_vault.rs::
    /// use_vars_pull_overwrites_local_state_with_remote_environments` at the
    /// storage layer (no subprocess, no mock registry).
    #[test]
    fn replace_all_environments_drops_local_only_envs_and_overwrites_each_env() {
        let _lock = KEYCHAIN_LOCK.lock().unwrap();

        let temp_home = tempfile::tempdir().expect("create temp HOME");
        let original_home = std::env::var_os("HOME");
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");
        let original_fast_scrypt = std::env::var_os("LPM_TEST_FAST_SCRYPT");

        unsafe {
            std::env::set_var("HOME", temp_home.path());
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            std::env::set_var("LPM_TEST_FAST_SCRYPT", "1");
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let project = tempfile::tempdir().expect("create temp project dir");

            // Seed: stale `default` (with a key the cloud no longer has) plus a
            // local-only `preview` environment that the cloud doesn't know about.
            set_env(
                project.path(),
                "default",
                &[
                    ("STALE_DEFAULT", "old-default"),
                    ("REMOVE_ME", "local-only"),
                ],
            )
            .expect("seed default env");
            set_env(
                project.path(),
                "preview",
                &[
                    ("PREVIEW_ONLY", "stale-preview"),
                    ("SHARED_ENV", "stale-preview"),
                ],
            )
            .expect("seed preview env");

            // Pre-condition sanity: both environments are populated.
            let pre = get_all_environments(project.path());
            assert_eq!(pre.len(), 2, "both seeded envs should be present");
            assert!(
                pre.get("default")
                    .is_some_and(|env| env.contains_key("STALE_DEFAULT"))
            );
            assert!(
                pre.get("preview")
                    .is_some_and(|env| env.contains_key("PREVIEW_ONLY"))
            );

            // Pull payload: brand-new `default` keys + a brand-new `live` env.
            // `preview` is intentionally absent — the bug fix must drop it.
            let mut remote = HashMap::new();
            remote.insert(
                "default".to_string(),
                HashMap::from([
                    ("API_URL".to_string(), "https://api.example.com".to_string()),
                    ("SHARED_ENV".to_string(), "remote-default".to_string()),
                ]),
            );
            remote.insert(
                "live".to_string(),
                HashMap::from([("LIVE_ONLY".to_string(), "remote-live".to_string())]),
            );

            replace_all_environments(project.path(), &remote)
                .expect("replace_all_environments should succeed on file backend");

            // Post-condition: vault is byte-identical to the remote snapshot.
            let post_default = get_all_env(project.path(), "default");
            assert_eq!(
                post_default.len(),
                2,
                "default should contain only the remote keys"
            );
            assert_eq!(
                post_default.get("API_URL").map(String::as_str),
                Some("https://api.example.com")
            );
            assert_eq!(
                post_default.get("SHARED_ENV").map(String::as_str),
                Some("remote-default")
            );
            assert!(
                !post_default.contains_key("STALE_DEFAULT"),
                "stale local key must be removed, not merged"
            );
            assert!(
                !post_default.contains_key("REMOVE_ME"),
                "stale local key must be removed, not merged"
            );

            let post_live = get_all_env(project.path(), "live");
            assert_eq!(post_live.len(), 1);
            assert_eq!(
                post_live.get("LIVE_ONLY").map(String::as_str),
                Some("remote-live")
            );

            let post_preview = get_all_env(project.path(), "preview");
            assert!(
                post_preview.is_empty(),
                "local-only environments must be wiped during pull overwrite, got: {post_preview:?}"
            );

            let post_all = get_all_environments(project.path());
            assert_eq!(post_all.len(), 2, "exactly the remote envs should remain");
            assert!(post_all.contains_key("default"));
            assert!(post_all.contains_key("live"));
            assert!(!post_all.contains_key("preview"));

            cleanup_vault(project.path());
        }));

        unsafe {
            match original_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match original_force_file_vault {
                Some(value) => std::env::set_var("LPM_FORCE_FILE_VAULT", value),
                None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
            }
            match original_fast_scrypt {
                Some(value) => std::env::set_var("LPM_TEST_FAST_SCRYPT", value),
                None => std::env::remove_var("LPM_TEST_FAST_SCRYPT"),
            }
        }

        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}
