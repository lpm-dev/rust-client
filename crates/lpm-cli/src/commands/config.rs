use crate::output;
use crate::prompt::prompt_err;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::io::IsTerminal;

/// CLI configuration management.
///
/// Stores config in ~/.lpm/config.toml (user/machine config).
/// Project config lives in package.json under "lpm" key.
///
/// Beyond `get`/`set`/`delete`/`list`, three focused wizards live here:
/// - `lpm config scripts` owns `script-policy = deny | triage | allow`.
/// - `lpm config triage` owns `triage-advisor = none | claude-cli | codex | ollama`.
/// - `lpm config sandbox` owns `[sandbox] mode = default | strict | none`.
///
/// All three default to interactive in a TTY; `--set <value>` is the
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
    if action == "sandbox" {
        return run_sandbox_wizard(&config_path, set, json_output).await;
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
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "action": "set",
                        "key": key,
                        "value": value,
                    })
                );
            } else {
                output::success(&format!("Set {} = {}", key.bold(), value));
            }
        }
        "delete" | "unset" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let mut config = read_config(&config_path)?;
            let existed = config.as_table_mut().and_then(|t| t.remove(key)).is_some();
            write_config(&config_path, &config)?;
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "action": "delete",
                        "key": key,
                        "existed": existed,
                    })
                );
            } else {
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
    /// Used by the `UserBound` reader to navigate into
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
    ///   slice 5 `max-sandbox-write-roots` contract where
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
// `lpm config scripts`  /  `lpm config triage`  wizards
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
        if v == "triage" {
            print_triage_policy_followup(json_output);
        }
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
    println!("  current: {}", current.cyan());
    let new_value: &str = cliclack::select("How should lpm treat package lifecycle scripts?")
        .item(
            "deny",
            "deny — never auto-run lifecycle scripts",
            "default; most restrictive",
        )
        .item(
            "triage",
            "triage — Layers 1-3 always; advisor only if configured",
            "recommended",
        )
        .item(
            "allow",
            "allow — run every script",
            "npm-classic; least restrictive",
        )
        .initial_value(current.as_str())
        .interact()
        .map_err(prompt_err)?;
    persist_string(config_path, SCRIPT_POLICY_KEY, new_value)?;
    announce_set(SCRIPT_POLICY_KEY, new_value, json_output);

    if new_value == "triage" {
        print_triage_policy_followup(json_output);
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
        print_triage_advisor_followup(json_output);
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
        let switch = cliclack::confirm(r#"Switch script-policy to "triage" now?"#)
            .initial_value(false)
            .interact()
            .map_err(prompt_err)?;
        if switch {
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
    println!("  {PRIVACY_LINE}");
    if detected.is_empty() {
        println!();
        println!(
            "  {}: no advisors detected on this machine (`claude` / `codex` / `ollama` \
             not on PATH or ollama daemon not running). You can still pick \"none\".",
            "note".cyan()
        );
    }

    // Build menu: detected first, then "none". Unavailable providers
    // are deliberately not listed (t3code's pattern — don't show
    // options the user can't pick).
    let mut sel = cliclack::select("Pick a triage advisor for amber-tier scripts:");
    for r in &detected {
        let (label, hint) = match r.provider {
            lpm_triage_advisor::Provider::Ollama => ("ollama", "local, no cloud egress"),
            lpm_triage_advisor::Provider::ClaudeCli => ("claude-cli", "cloud"),
            lpm_triage_advisor::Provider::Codex => ("codex", "cloud"),
        };
        sel = sel.item(r.provider.slug(), label, hint);
    }
    sel = sel.item("none", "none", "Layers 1-3 only (portable triage)");
    // Default to the first detected provider when available, else "none".
    let initial = detected
        .first()
        .map(|r| r.provider.slug())
        .unwrap_or("none");
    let chosen_slug: &str = sel.initial_value(initial).interact().map_err(prompt_err)?;

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
                let save = cliclack::confirm(
                    "Save this choice anyway? `lpm install` will degrade to no-advisor \
                     for any run where this provider isn't ready and print one warning; \
                     install never fails because the advisor failed.",
                )
                .initial_value(false)
                .interact()
                .map_err(prompt_err)?;
                if !save {
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
    print_triage_advisor_followup(json_output);
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

/// Disclosure printed after `script-policy = triage` is persisted (via
/// either `--set` or interactive). After slice 1 the wizard
/// now describes the actual install-time degrade-and-warn contract:
/// triage uses Layers 1-3 always, an optional advisor uplift kicks
/// in if configured + available, and a configured-but-unavailable
/// advisor degrades cleanly with a one-line warning per install run.
fn print_triage_policy_followup(json_output: bool) {
    if json_output {
        return;
    }
    println!();
    println!(
        "  {}: triage runs Layers 1-3 on every install. Run `lpm config \
         triage` to pick an optional advisor (claude-cli / codex / \
         ollama) that can promote some amber packages to auto-run \
         this install. The advisor is consulted only for amber; \
         green and hard-blocked paths are unchanged.",
        "tip".cyan()
    );
}

// ─────────────────────────────────────────────────────────────────────
// `lpm config sandbox`  wizard  (rework)
// ─────────────────────────────────────────────────────────────────────
//
// Persists `[sandbox] mode = "default" | "strict" | "none"` into
// `~/.lpm/config.toml`. Mirror of `run_scripts_wizard` /
// `run_triage_wizard`:
//   - interactive (TTY): cliclack `select` with the current value
//     pre-selected, plus an extra confirmation prompt when the user
//     picks `none` (because that turns the install-time sandbox off
//     wholesale).
//   - `--set <value>`: non-interactive setter for CI / image bake
//     dotfiles automation. Trusts the operator — no confirmation
//     prompt even on `--set none`.
//
// The wizard ONLY touches `~/.lpm/config.toml`. The project-tier
// `./lpm.toml > [sandbox] mode` is committed-by-the-team and intended
// to be edited directly; the wizard's user-tier scope matches the
// other two wizards.

const SANDBOX_MODE_VALUES: &[&str] = &["default", "strict", "none"];

async fn run_sandbox_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(v) = set {
        if !SANDBOX_MODE_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid sandbox mode '{v}'; must be one of: {}",
                SANDBOX_MODE_VALUES.join(" | ")
            )));
        }
        persist_sandbox_mode(config_path, v)?;
        announce_sandbox_set(v, json_output);
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config sandbox requires a TTY; use `--set default|strict|none` instead"
                .to_string(),
        ));
    }

    let current = read_sandbox_mode(config_path)?.unwrap_or_else(|| "default".to_string());
    println!();
    println!("  current: {}", current.cyan());
    let new_value: &str = cliclack::select("How strict should the install-time sandbox be?")
        .item(
            "default",
            "default — filesystem + env containment, outbound network allowed",
            "recommended",
        )
        .item(
            "strict",
            "strict  — + outbound network denied",
            "paranoid / CI / enterprise",
        )
        .item(
            "none",
            "none    — sandbox off",
            "NOT recommended — full host access for every script",
        )
        .initial_value(current.as_str())
        .interact()
        .map_err(prompt_err)?;

    // DX redline: confirm when the user picks `none` in
    // the interactive wizard. The `--set none` form trusts the
    // operator (no TTY check); only the wizard prompts.
    if new_value == "none" {
        println!();
        println!(
            "  {}: setting sandbox mode to {} means every lifecycle script that runs \
             gets full host access — filesystem open, full env (credentials), network. \
             This is the npm-default shape; LPM does not recommend it as a persistent \
             posture.",
            "warning".yellow(),
            "none".yellow().bold()
        );
        let confirmed = cliclack::confirm(
            "Are you sure you want sandbox = none for every install on this machine?",
        )
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
        if !confirmed {
            println!("  Aborted. No config change.");
            return Ok(());
        }
    }

    persist_sandbox_mode(config_path, new_value)?;
    announce_sandbox_set(new_value, json_output);
    Ok(())
}

/// Read the `[sandbox] mode` value from `~/.lpm/config.toml`. Returns
/// `None` for missing file, missing section, or missing key.
fn read_sandbox_mode(config_path: &std::path::Path) -> Result<Option<String>, LpmError> {
    let cfg = read_config(config_path)?;
    Ok(cfg
        .get("sandbox")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("mode"))
        .and_then(|v| v.as_str())
        .map(String::from))
}

/// Persist the resolved sandbox mode into `[sandbox] mode` in the
/// config file. Creates the `[sandbox]` table if absent; preserves
/// any sibling keys (e.g. `allow-degraded`) untouched.
fn persist_sandbox_mode(config_path: &std::path::Path, value: &str) -> Result<(), LpmError> {
    let mut cfg = read_config(config_path)?;
    let top = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    let sandbox_section = top
        .entry("sandbox".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let sandbox_table = sandbox_section.as_table_mut().ok_or_else(|| {
        LpmError::Registry(format!(
            "{}: `[sandbox]` is not a TOML table — refusing to clobber",
            config_path.display(),
        ))
    })?;
    sandbox_table.insert("mode".to_string(), toml::Value::String(value.to_string()));
    write_config(config_path, &cfg)
}

fn announce_sandbox_set(value: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "sandbox": { "mode": value },
            }))
            .unwrap()
        );
    } else {
        output::success(&format!("Set [sandbox] mode = {}", value.bold()));
    }
}

/// Disclosure printed after `triage-advisor = <value>` is persisted
/// (via either `--set` or interactive). After slice 1 this describes
/// the actual install-time contract:
///   - `lpm install` preflights the advisor once per run.
///   - If detect or test-invoke fails, the run degrades to
///     `triage-advisor = "none"` semantics and prints one warning;
///     the install never fails because the advisor failed.
///   - The advisor only converts `Approve` verdicts into auto-run
///     for amber packages this run; the approval is ephemeral and
///     is NOT written to `trustedDependencies`.
fn print_triage_advisor_followup(json_output: bool) {
    if json_output {
        return;
    }
    println!(
        "  {}: `lpm install` preflights the advisor once per run. If it's \
         unavailable, the install degrades to no-advisor with one warning \
         and never fails on the advisor. The advisor only promotes amber \
         packages it returns Approve for, and the approval is ephemeral \
         (no persistent trust entry).",
        "note".cyan()
    );
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

    // ── sandbox wizard (rework) ─────────────────────────

    #[tokio::test]
    async fn sandbox_wizard_set_persists_each_valid_mode() {
        for mode in &["default", "strict", "none"] {
            let (_dir, path) = tmp_config();
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
        let (_dir, path) = tmp_config();
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
    async fn sandbox_wizard_preserves_sibling_keys() {
        // The wizard writes `[sandbox] mode`; an existing
        // `[sandbox] allow-degraded` must survive.
        let (_dir, path) = tmp_config();
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
        let (_dir, path) = tmp_config();
        std::fs::write(&path, "sandbox = \"not-a-table\"\n").unwrap();
        let err = run_sandbox_wizard(&path, Some("strict"), true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not a TOML table"), "got: {msg}");
    }

    #[tokio::test]
    async fn sandbox_wizard_overwrites_existing_mode() {
        let (_dir, path) = tmp_config();
        run_sandbox_wizard(&path, Some("strict"), true)
            .await
            .unwrap();
        run_sandbox_wizard(&path, Some("default"), true)
            .await
            .unwrap();
        assert_eq!(
            read_sandbox_mode(&path).unwrap().as_deref(),
            Some("default")
        );
    }
}
