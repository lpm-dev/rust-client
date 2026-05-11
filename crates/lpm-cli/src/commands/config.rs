use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::io::{BufRead, IsTerminal, Write};

/// CLI configuration management.
///
/// Stores config in ~/.lpm/config.toml (user/machine config).
/// Project config lives in package.json under "lpm" key.
///
/// Beyond `get`/`set`/`delete`/`list`, two focused wizards live here:
/// - `lpm config scripts` owns `script-policy = deny | triage | allow`.
/// - `lpm config triage` owns `triage-advisor = none | claude-cli | codex | ollama`.
///
/// Both default to interactive in a TTY; `--set <value>` is the
/// non-interactive setter required for CI / scripted setup.
pub async fn run(
    action: &str,
    key: Option<&str>,
    value: Option<&str>,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let config_path = dirs::home_dir()
        .ok_or_else(|| LpmError::Registry("could not determine home dir".into()))?
        .join(".lpm")
        .join("config.toml");

    if action == "scripts" {
        return run_scripts_wizard(&config_path, set, json_output).await;
    }
    if action == "triage" {
        return run_triage_wizard(&config_path, set, json_output).await;
    }

    match action {
        "get" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let config = read_config(&config_path)?;
            if let Some(val) = config.get(key).and_then(|v| v.as_str()) {
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "success": true, key: val })
                        )
                        .unwrap()
                    );
                } else {
                    println!("{val}");
                }
            } else if !json_output {
                output::info(&format!("{key} is not set"));
            }
        }
        "set" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let value = value.ok_or_else(|| LpmError::Registry("missing value".into()))?;
            let mut config = read_config(&config_path)?;
            if let Some(table) = config.as_table_mut() {
                table.insert(key.to_string(), toml::Value::String(value.to_string()));
            }
            write_config(&config_path, &config)?;
            if !json_output {
                output::success(&format!("Set {} = {}", key.bold(), value));
            }
        }
        "delete" | "unset" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let mut config = read_config(&config_path)?;
            if let Some(table) = config.as_table_mut() {
                table.remove(key);
            }
            write_config(&config_path, &config)?;
            if !json_output {
                output::success(&format!("Deleted {}", key.bold()));
            }
        }
        "list" | "ls" => {
            let config = read_config(&config_path)?;
            if json_output {
                let mut json = serde_json::to_value(&config).unwrap_or(serde_json::json!({}));
                if let Some(obj) = json.as_object_mut() {
                    obj.insert("success".to_string(), serde_json::Value::Bool(true));
                }
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                if let Some(table) = config.as_table() {
                    if table.is_empty() {
                        output::info("No configuration set");
                    } else {
                        for (k, v) in table {
                            output::field(k, &v.to_string());
                        }
                    }
                }
            }
        }
        _ => {
            return Err(LpmError::Registry(format!(
                "unknown config action: {action}. Use: get, set, delete, list"
            )));
        }
    }

    Ok(())
}

fn read_config(path: &std::path::Path) -> Result<toml::Value, LpmError> {
    if !path.exists() {
        return Ok(toml::Value::Table(toml::map::Map::new()));
    }
    let content = std::fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|e| LpmError::Registry(format!("config parse error: {e}")))
}

fn write_config(path: &std::path::Path, config: &toml::Value) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(config)
        .map_err(|e| LpmError::Registry(format!("config serialize error: {e}")))?;
    std::fs::write(path, content)?;
    Ok(())
}

// ── Global config reader (used by other commands) ───────────────────

/// Read the global config file (~/.lpm/config.toml) once and provide
/// typed accessors. Cheap to construct (one file read, cached in struct).
pub struct GlobalConfig {
    table: toml::map::Map<String, toml::Value>,
}

impl GlobalConfig {
    /// Load from ~/.lpm/config.toml. Returns empty config if missing or unreadable.
    pub fn load() -> Self {
        let table = dirs::home_dir()
            .map(|h| h.join(".lpm").join("config.toml"))
            .and_then(|p| read_config(&p).ok())
            .and_then(|v| match v {
                toml::Value::Table(t) => Some(t),
                _ => None,
            })
            .unwrap_or_default();
        Self { table }
    }

    /// Construct an empty config — used by in-crate tests that need a
    /// deterministic "no overrides" baseline without touching
    /// `~/.lpm/config.toml`. `pub(crate)` because no external caller
    /// has a legitimate use; `#[cfg(test)]` because no production code
    /// path constructs an empty config — `load()` is the production
    /// path and a missing file already produces an empty table.
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            table: toml::map::Map::new(),
        }
    }

    /// Get a string value.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.table.get(key)?.as_str()
    }

    /// Get a boolean value. Accepts "true"/"false" strings or native bools.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.table.get(key)? {
            toml::Value::Boolean(b) => Some(*b),
            toml::Value::String(s) => match s.as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    /// Get a top-level table value, returning a reference to the
    /// underlying `toml::Table` for nested-key walks.
    ///
    /// Used by the Phase 48 `UserBound` reader to navigate into
    /// `[sandbox.limits]` without adding a bespoke per-section
    /// accessor to this struct. Callers chain through the returned
    /// table's own `get(...)` / `as_*` methods.
    ///
    /// Returns `None` for absent keys, dotted-key paths that don't
    /// resolve to a table, and any non-table value at this key.
    pub fn get_table(&self, key: &str) -> Option<&toml::value::Table> {
        self.table.get(key)?.as_table()
    }

    /// Get a value that should be an array of strings, returning the
    /// entries as owned `Vec<String>`. Accepts:
    /// - A native TOML array of strings: `foo = ["a", "b"]` → `vec!["a", "b"]`.
    /// - A generic `lpm config set foo "a,b"`-style comma-separated
    ///   string is NOT auto-split here (to avoid silently accepting
    ///   comma-containing paths as two separate entries). A user who
    ///   wants multiple values must write a native TOML array.
    /// - Any other shape (integer, bool, single string, etc.) returns
    ///   `None` — callers treat that as "key absent" per the
    ///   Phase 48 P0 slice 5 `max-sandbox-write-roots` contract where
    ///   empty/unset means "no constraint".
    ///
    /// Used by the `max-sandbox-write-roots` reader on the sandbox
    /// write-root enforcement path; a generic accessor is cheaper to
    /// maintain than one bespoke config reader per key.
    pub fn get_str_array(&self, key: &str) -> Option<Vec<String>> {
        let arr = self.table.get(key)?.as_array()?;
        let mut out = Vec::with_capacity(arr.len());
        for entry in arr {
            // Skip non-string entries rather than erroring — config
            // readers on this path are advisory (absent-or-malformed
            // means default behavior). A caller that needs strict
            // validation should read the TOML directly.
            if let Some(s) = entry.as_str() {
                out.push(s.to_string());
            }
        }
        Some(out)
    }

    /// Get a non-negative integer value. Accepts `toml::Value::Integer`
    /// natively AND string-coerced values (the generic `lpm config set`
    /// command serializes every value as a string — Finding A in
    /// [`crate::save_config`]). Returns `None` for absent keys, negative
    /// integers, or strings that don't parse as `u64`.
    ///
    /// This is a convenience reader for callers that don't need
    /// file-pathed error surfacing. For strict config loaders, read the
    /// file directly (see `release_age_config::read_global_min_age_from_file`
    /// for the path-aware pattern).
    ///
    /// String coercion routes through
    /// [`crate::release_age_config::parse_strict_u64_string`] so the
    /// rule "no sign prefix" stays uniform across the CLI flag, the
    /// global-TOML loader, and this convenience accessor. Without that
    /// shared helper, `"+5"` would parse as `5` on this path while the
    /// CLI flag rejects `+5h` — an inconsistency that would silently
    /// let persistent config accept inputs the CLI rejects.
    ///
    /// Note: no production caller uses this today (the `release_age`
    /// loader reads `~/.lpm/config.toml` with a path-aware fallible
    /// helper instead). `#[allow(dead_code)]` is retained for the one
    /// behavioural unit test; remove alongside if a caller lands.
    #[allow(dead_code)]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.table.get(key)? {
            toml::Value::Integer(i) => u64::try_from(*i).ok(),
            toml::Value::String(s) => crate::release_age_config::parse_strict_u64_string(s),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// `lpm config scripts`  /  `lpm config triage`  wizards (Phase 46 B3)
// ─────────────────────────────────────────────────────────────────────
//
// Two narrow product surfaces, deliberately split:
//   - `scripts` owns ONLY `script-policy` (deny | triage | allow).
//   - `triage`  owns ONLY `triage-advisor` (none | <provider>).
//
// `triage-advisor` is stored independently of `script-policy`; it stays
// configured while policy is deny or allow, just inert. Triage means
// the same thing on every machine; the advisor is an OPTIONAL uplift.
//
// Default persistence: user scope (`~/.lpm/config.toml`). Project
// scope must be explicit and is not handled by these wizards.
//
// Non-TTY without `--set` is a hard error — installs read existing
// config; the wizards are the interactive setup surface.

const SCRIPT_POLICY_KEY: &str = "script-policy";
const TRIAGE_ADVISOR_KEY: &str = "triage-advisor";

const SCRIPT_POLICY_VALUES: &[&str] = &["deny", "triage", "allow"];
const TRIAGE_ADVISOR_VALUES: &[&str] = &["none", "claude-cli", "codex", "ollama"];

/// Privacy one-liner shown when a cloud advisor is the chosen path.
/// Locked wording: short, accurate, not a consent wall.
const PRIVACY_LINE: &str = "Choosing a cloud advisor sends the package's lifecycle script text for review; \
     local advisors keep review on this machine.";

async fn run_scripts_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(v) = set {
        if !SCRIPT_POLICY_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid script-policy '{v}'; must be one of: {}",
                SCRIPT_POLICY_VALUES.join(" | ")
            )));
        }
        persist_string(config_path, SCRIPT_POLICY_KEY, v)?;
        announce_set(SCRIPT_POLICY_KEY, v, json_output);
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config scripts requires a TTY; use `--set deny|triage|allow` instead".to_string(),
        ));
    }

    let current =
        read_string_value(config_path, SCRIPT_POLICY_KEY)?.unwrap_or_else(|| "deny".to_string());
    println!();
    println!(
        "{}",
        "How should lpm treat package lifecycle scripts?".bold()
    );
    println!("  current: {}", current.cyan());
    println!();
    println!("  1) deny    — never auto-run lifecycle scripts (default; most restrictive)");
    println!("  2) triage  — Layers 1-3 always; advisor only if explicitly configured");
    println!("  3) allow   — run every script (npm-classic; least restrictive)");
    println!();
    let chosen = prompt_choice("Pick 1, 2, or 3", &["1", "2", "3"])?;
    let new_value = match chosen.as_str() {
        "1" => "deny",
        "2" => "triage",
        "3" => "allow",
        _ => unreachable!(),
    };
    persist_string(config_path, SCRIPT_POLICY_KEY, new_value)?;
    announce_set(SCRIPT_POLICY_KEY, new_value, json_output);

    if new_value == "triage" {
        println!();
        println!(
            "  {}: triage uses Layers 1-3 by default. To configure an \
             optional advisor (claude-cli / codex / ollama) for amber \
             cases, run `lpm config triage`.",
            "tip".cyan()
        );
    }
    Ok(())
}

async fn run_triage_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(v) = set {
        if !TRIAGE_ADVISOR_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid triage-advisor '{v}'; must be one of: {}",
                TRIAGE_ADVISOR_VALUES.join(" | ")
            )));
        }
        persist_string(config_path, TRIAGE_ADVISOR_KEY, v)?;
        announce_set(TRIAGE_ADVISOR_KEY, v, json_output);
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config triage requires a TTY; use `--set none|claude-cli|codex|ollama` instead"
                .to_string(),
        ));
    }

    // Cross-prompt: triage-advisor is inert unless script-policy = triage.
    let current_policy =
        read_string_value(config_path, SCRIPT_POLICY_KEY)?.unwrap_or_else(|| "deny".to_string());
    if current_policy != "triage" {
        println!();
        println!(
            "  {}: triage advisor only applies when script-policy = \"triage\". \
             Current policy: {}.",
            "note".cyan(),
            current_policy.yellow()
        );
        let switch = prompt_choice(
            "Switch script-policy to \"triage\" now? [y/N]",
            &["y", "n", ""],
        )?;
        if matches!(switch.as_str(), "y" | "Y") {
            persist_string(config_path, SCRIPT_POLICY_KEY, "triage")?;
            output::success(&format!("Set {} = {}", SCRIPT_POLICY_KEY.bold(), "triage"));
        } else {
            println!(
                "  Leaving script-policy at {}. The triage-advisor value will be saved \
                 but stay inert until you switch policy.",
                current_policy.yellow()
            );
        }
    }

    // Detect available providers in parallel. Strict for Ollama
    // (binary + HTTP probe); `which`-style for the CLI providers.
    let reports = lpm_triage_advisor::probe_all().await;
    let detected: Vec<&lpm_triage_advisor::ProbeReport> =
        reports.iter().filter(|r| r.is_available()).collect();

    println!();
    println!("{}", "Pick a triage advisor for amber-tier scripts:".bold());
    println!("  {PRIVACY_LINE}");
    println!();
    if detected.is_empty() {
        println!(
            "  {}: no advisors detected on this machine (`claude` / `codex` / `ollama` \
             not on PATH or ollama daemon not running). You can still pick \"none\".",
            "note".cyan()
        );
        println!();
    }
    // Build menu: detected first, then "none". Unavailable providers
    // are deliberately not listed (t3code's pattern — don't show
    // options the user can't pick).
    let mut options: Vec<&str> = Vec::new();
    for r in &detected {
        let label = match r.provider {
            lpm_triage_advisor::Provider::Ollama => "ollama (local, no cloud egress)",
            lpm_triage_advisor::Provider::ClaudeCli => "claude-cli (cloud)",
            lpm_triage_advisor::Provider::Codex => "codex (cloud)",
        };
        let slug = r.provider.slug();
        options.push(slug);
        println!("  {}) {}", options.len(), label);
    }
    options.push("none");
    println!(
        "  {}) none — Layers 1-3 only (portable triage)",
        options.len()
    );
    println!();
    let choices: Vec<String> = (1..=options.len()).map(|i| i.to_string()).collect();
    let choice_refs: Vec<&str> = choices.iter().map(String::as_str).collect();
    let idx = prompt_choice("Pick a number", &choice_refs)?;
    let chosen_slug = options[idx.parse::<usize>().unwrap() - 1];

    // Test-invoke when a real provider is chosen. Distinguish
    // EnvironmentNotReady (recoverable → save anyway) from
    // IntegrationFailure (block save per the locked contract).
    if let Some(provider) = lpm_triage_advisor::Provider::from_slug(chosen_slug) {
        match test_invoke_provider(provider).await {
            Ok(_) => println!("  {} test invoke OK", provider.slug().green()),
            Err(lpm_triage_advisor::AdvisorFailure::EnvironmentNotReady(msg)) => {
                println!(
                    "  {}: the advisor binary is present but didn't return a verdict ({msg})",
                    "environment not ready".yellow(),
                );
                let save = prompt_choice(
                    "Save this choice anyway? Install will degrade to advisor=none until the environment is fixed. [y/N]",
                    &["y", "n", "", "Y", "N"],
                )?;
                if !matches!(save.as_str(), "y" | "Y") {
                    println!("  Aborted. No config change.");
                    return Ok(());
                }
            }
            Err(lpm_triage_advisor::AdvisorFailure::IntegrationFailure(msg)) => {
                return Err(LpmError::Registry(format!(
                    "advisor integration failure (no save): {msg}"
                )));
            }
        }
    }

    persist_string(config_path, TRIAGE_ADVISOR_KEY, chosen_slug)?;
    announce_set(TRIAGE_ADVISOR_KEY, chosen_slug, json_output);
    Ok(())
}

async fn test_invoke_provider(
    provider: lpm_triage_advisor::Provider,
) -> Result<lpm_triage_advisor::AdvisorVerdict, lpm_triage_advisor::AdvisorFailure> {
    use lpm_triage_advisor::{Advisor, ClaudeCliAdapter, CodexAdapter, OllamaAdapter};
    let adapter: Box<dyn Advisor> = match provider {
        lpm_triage_advisor::Provider::ClaudeCli => Box::new(ClaudeCliAdapter),
        lpm_triage_advisor::Provider::Codex => Box::new(CodexAdapter),
        lpm_triage_advisor::Provider::Ollama => Box::new(OllamaAdapter::default()),
    };
    adapter.test_invoke().await
}

/// Stdin-line prompt with a small allowed-answer set. Re-asks on
/// invalid input. Empty string is treated as the default ("" must be
/// in the allowed set to accept).
fn prompt_choice(prompt: &str, allowed: &[&str]) -> Result<String, LpmError> {
    loop {
        print!("> {prompt}: ");
        std::io::stdout()
            .flush()
            .map_err(|e| LpmError::Registry(format!("stdout flush: {e}")))?;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| LpmError::Registry(format!("stdin read: {e}")))?;
        let trimmed = line.trim().to_string();
        if allowed.contains(&trimmed.as_str()) {
            return Ok(trimmed);
        }
        println!("  invalid; pick one of: {}", allowed.join(" / "));
    }
}

fn read_string_value(config_path: &std::path::Path, key: &str) -> Result<Option<String>, LpmError> {
    let cfg = read_config(config_path)?;
    Ok(cfg.get(key).and_then(|v| v.as_str()).map(String::from))
}

fn persist_string(config_path: &std::path::Path, key: &str, value: &str) -> Result<(), LpmError> {
    let mut cfg = read_config(config_path)?;
    if let Some(table) = cfg.as_table_mut() {
        table.insert(key.to_string(), toml::Value::String(value.to_string()));
    }
    write_config(config_path, &cfg)
}

fn announce_set(key: &str, value: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                key: value,
            }))
            .unwrap()
        );
    } else {
        output::success(&format!("Set {} = {}", key.bold(), value));
    }
}

#[cfg(test)]
mod wizard_tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_config() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("config.toml");
        (dir, path)
    }

    #[tokio::test]
    async fn scripts_wizard_set_persists_valid_value() {
        let (_dir, path) = tmp_config();
        run_scripts_wizard(&path, Some("triage"), true)
            .await
            .unwrap();
        let v = read_string_value(&path, SCRIPT_POLICY_KEY).unwrap();
        assert_eq!(v.as_deref(), Some("triage"));
    }

    #[tokio::test]
    async fn scripts_wizard_set_rejects_invalid_value() {
        let (_dir, path) = tmp_config();
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
    async fn triage_wizard_set_persists_valid_provider() {
        let (_dir, path) = tmp_config();
        run_triage_wizard(&path, Some("claude-cli"), true)
            .await
            .unwrap();
        let v = read_string_value(&path, TRIAGE_ADVISOR_KEY).unwrap();
        assert_eq!(v.as_deref(), Some("claude-cli"));
    }

    #[tokio::test]
    async fn triage_wizard_set_accepts_none_as_first_class() {
        let (_dir, path) = tmp_config();
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
        let (_dir, path) = tmp_config();
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
        let (_dir, path) = tmp_config();
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
}
