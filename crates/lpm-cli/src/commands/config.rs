use crate::install_ui;
use crate::prompt::prompt_err;
use crate::provenance_fetch::EnforceMode;
use crate::sandbox_config::ResolvedSandboxMode;
use lpm_common::color::Painted;
use lpm_common::{LpmError, LpmRoot};
use std::io::IsTerminal;

/// CLI configuration management.
///
/// Stores config in ~/.lpm/config.toml (user/machine config).
/// Project config lives in package.json under "lpm" key.
///
/// Beyond `get`/`set`/`delete`/`list`, seven focused wizards live here:
/// - `lpm config scripts` owns `script-policy = deny | triage | allow`.
/// - `lpm config triage` owns `triage-advisor = none | claude-cli | codex | ollama`.
/// - `lpm config sandbox` owns `[sandbox] mode = default | strict | none`.
/// - `lpm config sigstore` owns `[sigstore] verify = deny | warn | off`
///   (operator persistent toggle for Sigstore provenance verification).
/// - `lpm config signatures` owns `signatures = true | false`
///   (operator persistent toggle for npm registry package signatures).
/// - `lpm config trust-policy` owns `trust-policy = off | no-downgrade`
///   (operator persistent toggle for npm publisher/provenance downgrade checks).
/// - `lpm config release-age` owns `minimum-release-age-secs = <seconds>`
///   via human-friendly duration inputs.
///
/// All seven default to interactive in a TTY; `--set <value>` is the
/// non-interactive setter required for CI / scripted setup.
pub async fn run(
    action: &str,
    key: Option<&str>,
    value: Option<&str>,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let config_path = LpmRoot::from_env()?.root().join("config.toml");

    if action == "scripts" {
        return run_scripts_wizard(&config_path, set, json_output).await;
    }
    if action == "triage" {
        return run_triage_wizard(&config_path, set, json_output).await;
    }
    if action == "sandbox" {
        return run_sandbox_wizard(&config_path, set, json_output).await;
    }
    if action == "sigstore" {
        return run_sigstore_wizard(&config_path, set, json_output).await;
    }
    if action == "signatures" {
        return run_signatures_wizard(&config_path, set, json_output).await;
    }
    if action == "trust-policy" {
        return run_trust_policy_wizard(&config_path, set, json_output).await;
    }
    if action == "release-age" {
        return run_release_age_wizard(&config_path, set, json_output).await;
    }

    match action {
        "get" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let config = read_config(&config_path)?;
            if let Some(val) = config.get(key) {
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "success": true,
                            key: config_value_to_json(val),
                        }))
                        .unwrap()
                    );
                } else if let Some(raw) = val.as_str() {
                    println!("{raw}");
                } else {
                    println!("{}", config_value_for_display(val));
                }
            } else if !json_output {
                install_ui::warn(&format!("{key} is not set"));
            }
        }
        "set" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let value = value.ok_or_else(|| LpmError::Registry("missing value".into()))?;
            let mut config = read_config(&config_path)?;
            guard_generic_set_against_force_floor(&config, key, value)?;
            match key {
                SCRIPT_POLICY_KEY => {
                    let requested = crate::script_policy_config::ScriptPolicy::parse(value)
                        .map_err(|e| LpmError::Registry(e.to_string()))?;
                    crate::security_approval::authorize_persistent_script_policy(
                        requested,
                        json_output,
                        &format!("lpm config set {key} {value}"),
                    )?;
                }
                RELEASE_AGE_KEY => {
                    let requested_secs = crate::release_age_config::parse_strict_u64_string(value)
                        .ok_or_else(|| {
                            LpmError::Registry(format!(
                                "`{RELEASE_AGE_KEY}` must be a non-negative integer second count"
                            ))
                        })?;
                    crate::security_approval::authorize_persistent_release_age(
                        requested_secs,
                        json_output,
                        &format!("lpm config set {key} {value}"),
                    )?;
                }
                SIGNATURES_KEY => {
                    parse_config_bool(value).map_err(|message| {
                        LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}"))
                    })?;
                }
                TRUST_POLICY_KEY => validate_trust_policy_value(value)?,
                _ => {}
            }
            if let Some(table) = config.as_table_mut() {
                let value = if key == SIGNATURES_KEY {
                    toml::Value::Boolean(parse_config_bool(value).map_err(|message| {
                        LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}"))
                    })?)
                } else {
                    toml::Value::String(value.to_string())
                };
                table.insert(key.to_string(), value);
            }
            write_config(&config_path, &config)?;
            if json_output {
                let value = if key == SIGNATURES_KEY {
                    serde_json::Value::Bool(parse_config_bool(value).map_err(|message| {
                        LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}"))
                    })?)
                } else {
                    serde_json::Value::String(value.to_string())
                };
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
                install_ui::done(&format!(
                    "Done · {key} = {}",
                    install_ui::section(&format!("\"{value}\""))
                ));
            }
        }
        "delete" | "unset" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let mut config = read_config(&config_path)?;
            guard_generic_delete_against_force_floor(&config, key)?;
            match key {
                SCRIPT_POLICY_KEY => crate::security_approval::authorize_persistent_script_policy(
                    crate::script_policy_config::ScriptPolicy::Deny,
                    json_output,
                    &format!("lpm config delete {key}"),
                )?,
                RELEASE_AGE_KEY => crate::security_approval::authorize_persistent_release_age(
                    crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS,
                    json_output,
                    &format!("lpm config delete {key}"),
                )?,
                "sandbox" => crate::security_approval::authorize_persistent_sandbox_mode(
                    ResolvedSandboxMode::Default,
                    json_output,
                    "lpm config delete sandbox",
                )?,
                _ => {}
            }
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
                install_ui::done(&format!("Deleted {}", key.bold()));
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
                        install_ui::warn("No configuration set");
                    } else {
                        for (k, v) in table {
                            println!("  {k:<24} {v}");
                        }
                    }
                }
            }
        }
        _ => {
            return Err(LpmError::Registry(format!(
                "unknown config action: {action}. \
                 Use: get, set, delete (alias: unset), list (alias: ls), \
                 scripts, triage, sandbox, sigstore, signatures, trust-policy, release-age"
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

fn config_value_to_json(value: &toml::Value) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

fn config_value_for_display(value: &toml::Value) -> String {
    match value {
        toml::Value::Boolean(value) => value.to_string(),
        toml::Value::Integer(value) => value.to_string(),
        toml::Value::Float(value) => value.to_string(),
        toml::Value::Datetime(value) => value.to_string(),
        _ => value.to_string(),
    }
}

fn global_config_view_from_value(config: &toml::Value) -> GlobalConfig {
    let table = match config {
        toml::Value::Table(t) => t.clone(),
        _ => toml::map::Map::new(),
    };
    GlobalConfig { table }
}

fn guard_generic_set_against_force_floor(
    config: &toml::Value,
    key: &str,
    value: &str,
) -> Result<(), LpmError> {
    let global = global_config_view_from_value(config);
    match key {
        "force-security-floor"
            if crate::security_floor::force_security_floor_enabled(&global)
                && !matches!(value, "true" | "1" | "yes") =>
        {
            return Err(crate::security_floor::security_floor_write_error(
                "force-security-floor",
                value,
                "true",
            ));
        }
        SCRIPT_POLICY_KEY => {
            if let Ok(requested) = crate::script_policy_config::ScriptPolicy::parse(value) {
                crate::security_floor::reject_looser_script_policy_write(&global, requested)?;
            }
        }
        RELEASE_AGE_KEY => {
            if let Some(requested_secs) = crate::release_age_config::parse_strict_u64_string(value)
            {
                crate::security_floor::reject_looser_release_age_write(&global, requested_secs)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn guard_generic_delete_against_force_floor(
    config: &toml::Value,
    key: &str,
) -> Result<(), LpmError> {
    let global = global_config_view_from_value(config);
    match key {
        RELEASE_AGE_KEY => crate::security_floor::reject_looser_release_age_write(
            &global,
            crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS,
        )?,
        "sandbox" => crate::security_floor::reject_looser_sandbox_mode_write(
            &global,
            ResolvedSandboxMode::Default,
        )?,
        "force-security-floor" if crate::security_floor::force_security_floor_enabled(&global) => {
            return Err(crate::security_floor::security_floor_write_error(
                "force-security-floor",
                "unset",
                "true",
            ));
        }
        _ => {}
    }
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

    #[cfg(test)]
    pub(crate) fn from_table(table: toml::map::Map<String, toml::Value>) -> Self {
        Self { table }
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
                "true" | "1" | "yes" | "on" | "enabled" => Some(true),
                "false" | "0" | "no" | "off" | "disabled" => Some(false),
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

    /// Read `[sigstore] verify`. Returns the raw string (`"deny"`
    /// / `"warn"` / `"off"`) if present, or `None` for absent /
    /// non-table / non-string / unknown values. The parse happens
    /// at the consumer ([`crate::provenance_fetch::EnforceMode::resolve_from_chain`])
    /// so unknown values fall back to the next tier in the
    /// precedence chain with a `tracing::debug` — the gap is
    /// diagnosable without crashing the install.
    ///
    /// The nested-table key path (`[sigstore].verify`, not flat
    /// `sigstore-verify = "..."`) matches the
    /// `[sandbox] mode = "..."` precedent; leaves room for future
    /// sigstore-scoped knobs (trust-root override path, custom
    /// Rekor URL) without polluting the top-level table.
    pub fn get_sigstore_verify(&self) -> Option<String> {
        let raw = self
            .get_table("sigstore")?
            .get("verify")?
            .as_str()
            .map(String::from)?;
        match raw.as_str() {
            "deny" | "warn" | "off" => Some(raw),
            _ => None,
        }
    }

    pub fn get_trust_policy(&self) -> Option<String> {
        let raw = self.get_str(TRUST_POLICY_KEY)?.to_string();
        match raw.as_str() {
            "off" | "no-downgrade" => Some(raw),
            _ => None,
        }
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
    ///   `max-sandbox-write-roots` contract where
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
// `lpm config release-age` wizard
// ─────────────────────────────────────────────────────────────────────
//
// Persists the existing global `minimum-release-age-secs` override,
// but exposes a human-friendly command surface:
//   - interactive (TTY): presets for Default / Cautious / Off plus a
//     Custom duration prompt.
//   - `--set <value>`: accepts `default`, `off`, or the same duration
//     grammar as `lpm install --min-release-age` (`12h`, `3d`, `0`).
//
// Deliberate contract: `default` removes the global override rather
// than persisting `86400`, so users stay on the product default if it
// changes later.

const RELEASE_AGE_KEY: &str = "minimum-release-age-secs";
const DEFAULT_RELEASE_AGE_SECS: u64 = crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS;
const CAUTIOUS_RELEASE_AGE_SECS: u64 = 3 * DEFAULT_RELEASE_AGE_SECS;

#[derive(Clone, Copy)]
enum ReleaseAgeSelection {
    Default,
    Seconds(u64),
}

async fn run_release_age_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let existing_cfg = read_config(config_path)?;
    let global = global_config_view_from_value(&existing_cfg);
    let selection = if let Some(value) = set {
        parse_release_age_selection(value)?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config release-age requires a TTY; use `--set default|off|0|<N>h|<N>d` instead"
                    .to_string(),
            ));
        }

        let current = read_release_age_override(config_path)?;
        println!();
        println!("  current: {}", format_current_release_age(current).cyan());
        let preset: &str =
            cliclack::select("How long should LPM wait before allowing newly published packages?")
                .item("default", "Default (1 day)", "recommended")
                .item("cautious", "Cautious (3 days)", "stricter")
                .item("off", "Off", "NOT recommended — disables the cooldown")
                .item("custom", "Custom", "enter 12h / 7d / 0")
                .initial_value(release_age_initial_choice(current))
                .interact()
                .map_err(prompt_err)?;

        match preset {
            "default" => ReleaseAgeSelection::Default,
            "cautious" => ReleaseAgeSelection::Seconds(CAUTIOUS_RELEASE_AGE_SECS),
            "off" => ReleaseAgeSelection::Seconds(0),
            "custom" => {
                let default_input =
                    current.map_or_else(|| "1d".to_string(), format_release_age_cli_value);
                let duration: String = cliclack::input("Minimum release age")
                    .default_input(&default_input)
                    .placeholder("1d, 12h, 0")
                    .validate(|input: &String| {
                        crate::release_age_config::parse_duration(input)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    })
                    .interact()
                    .map_err(prompt_err)?;
                ReleaseAgeSelection::Seconds(crate::release_age_config::parse_duration(&duration)?)
            }
            _ => unreachable!("release-age select returned unexpected preset"),
        }
    };

    let requested_secs = match selection {
        ReleaseAgeSelection::Default => DEFAULT_RELEASE_AGE_SECS,
        ReleaseAgeSelection::Seconds(secs) => secs,
    };
    crate::security_floor::reject_looser_release_age_write(&global, requested_secs)?;
    let command_hint = match selection {
        ReleaseAgeSelection::Default => "lpm config release-age --set default".to_string(),
        ReleaseAgeSelection::Seconds(0) => "lpm config release-age --set 0".to_string(),
        ReleaseAgeSelection::Seconds(secs) => {
            format!(
                "lpm config release-age --set {}",
                format_release_age_cli_value(secs)
            )
        }
    };
    crate::security_approval::authorize_persistent_release_age(
        requested_secs,
        json_output,
        &command_hint,
    )?;

    let persisted = persist_release_age_selection(config_path, selection)?;
    announce_release_age_set(persisted, json_output);
    Ok(())
}

fn parse_release_age_selection(input: &str) -> Result<ReleaseAgeSelection, LpmError> {
    match input {
        "default" => Ok(ReleaseAgeSelection::Default),
        "off" => Ok(ReleaseAgeSelection::Seconds(0)),
        other => crate::release_age_config::parse_duration(other).map(ReleaseAgeSelection::Seconds),
    }
}

fn read_release_age_override(config_path: &std::path::Path) -> Result<Option<u64>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    Ok(GlobalConfig { table }.get_u64(RELEASE_AGE_KEY))
}

fn persist_release_age_selection(
    config_path: &std::path::Path,
    selection: ReleaseAgeSelection,
) -> Result<Option<u64>, LpmError> {
    let mut cfg = read_config(config_path)?;
    let top = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;

    let persisted = match selection {
        ReleaseAgeSelection::Default => {
            top.remove(RELEASE_AGE_KEY);
            None
        }
        ReleaseAgeSelection::Seconds(secs) => {
            top.insert(
                RELEASE_AGE_KEY.to_string(),
                toml::Value::String(secs.to_string()),
            );
            Some(secs)
        }
    };

    write_config(config_path, &cfg)?;
    Ok(persisted)
}

fn format_release_age_cli_value(secs: u64) -> String {
    if secs == 0 {
        return "0".to_string();
    }
    if secs.is_multiple_of(86400) {
        return format!("{}d", secs / 86400);
    }
    if secs.is_multiple_of(3600) {
        return format!("{}h", secs / 3600);
    }
    secs.to_string()
}

fn format_current_release_age(current: Option<u64>) -> String {
    match current {
        None => "default (1d)".to_string(),
        Some(0) => "off".to_string(),
        Some(secs) if secs == DEFAULT_RELEASE_AGE_SECS => "1d (explicit override)".to_string(),
        Some(secs) => format_release_age_cli_value(secs),
    }
}

fn release_age_initial_choice(current: Option<u64>) -> &'static str {
    match current {
        None => "default",
        Some(0) => "off",
        Some(secs) if secs == CAUTIOUS_RELEASE_AGE_SECS => "cautious",
        Some(_) => "custom",
    }
}

fn announce_release_age_set(value: Option<u64>, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                RELEASE_AGE_KEY: value,
            }))
            .unwrap()
        );
        return;
    }

    match value {
        None => install_ui::done("Using default minimum release age (1d)"),
        Some(0) => install_ui::done("Set minimum release age = off"),
        Some(secs) => install_ui::done(&format!(
            "Set minimum release age = {}",
            format_release_age_cli_value(secs).bold()
        )),
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
const SIGNATURES_KEY: &str = "signatures";
pub(crate) const TRUST_POLICY_KEY: &str = "trust-policy";

const SCRIPT_POLICY_VALUES: &[&str] = &["deny", "triage", "allow"];
const TRIAGE_ADVISOR_VALUES: &[&str] = &["none", "claude-cli", "codex", "ollama"];
const TRUST_POLICY_VALUES: &[&str] = &["off", "no-downgrade"];

/// Privacy one-liner shown when a cloud advisor is the chosen path.
/// Locked wording: short, accurate, not a consent wall.
const PRIVACY_LINE: &str = "Choosing a cloud advisor sends the package's lifecycle script text for review; \
     local advisors keep review on this machine.";

async fn run_signatures_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let enabled = if let Some(value) = set {
        parse_config_bool(value)
            .map_err(|message| LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}")))?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config signatures requires a TTY; use `--set true|false` instead".to_string(),
            ));
        }

        let current = read_bool_value(config_path, SIGNATURES_KEY)?.unwrap_or(false);
        println!();
        println!("  current: {}", format_bool_enabled(current).cyan());
        let new_value: &str =
            cliclack::select("Verify npm registry package signatures during install?")
                .item(
                    "true",
                    "enabled",
                    "fail install when registry signatures cannot verify",
                )
                .item(
                    "false",
                    "disabled",
                    "default; use `lpm audit signatures` on demand",
                )
                .initial_value(if current { "true" } else { "false" })
                .interact()
                .map_err(prompt_err)?;
        parse_config_bool(new_value)
            .map_err(|message| LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}")))?
    };

    persist_bool(config_path, SIGNATURES_KEY, enabled)?;
    announce_bool_set(SIGNATURES_KEY, enabled, json_output);
    Ok(())
}

async fn run_trust_policy_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let value = if let Some(value) = set {
        validate_trust_policy_value(value)?;
        value.to_string()
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config trust-policy requires a TTY; use `--set off|no-downgrade` instead"
                    .to_string(),
            ));
        }

        let current = read_string_value(config_path, TRUST_POLICY_KEY)?
            .filter(|v| TRUST_POLICY_VALUES.contains(&v.as_str()))
            .unwrap_or_else(|| "off".to_string());
        println!();
        println!("  current: {}", current.cyan());
        cliclack::select("How should LPM handle npm trust downgrades?")
            .item("off", "off", "default")
            .item(
                "no-downgrade",
                "no-downgrade",
                "block versions that drop publisher/provenance trust",
            )
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?
            .to_string()
    };

    persist_string(config_path, TRUST_POLICY_KEY, &value)?;
    announce_trust_policy_set(&value, json_output);
    Ok(())
}

fn validate_trust_policy_value(value: &str) -> Result<(), LpmError> {
    if TRUST_POLICY_VALUES.contains(&value) {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "invalid trust-policy '{value}'; must be one of: {}",
            TRUST_POLICY_VALUES.join(" | ")
        )))
    }
}

fn parse_config_bool(input: &str) -> Result<bool, &'static str> {
    match input.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" | "enabled" => Ok(true),
        "false" | "0" | "no" | "off" | "disabled" => Ok(false),
        _ => Err("must be true or false"),
    }
}

fn read_bool_value(config_path: &std::path::Path, key: &str) -> Result<Option<bool>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    Ok(GlobalConfig { table }.get_bool(key))
}

fn persist_bool(config_path: &std::path::Path, key: &str, value: bool) -> Result<(), LpmError> {
    let mut cfg = read_config(config_path)?;
    let table = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    table.insert(key.to_string(), toml::Value::Boolean(value));
    write_config(config_path, &cfg)
}

fn format_bool_enabled(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

fn announce_bool_set(key: &str, value: bool, json_output: bool) {
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
        install_ui::done(&format!(
            "Set {key} = {}",
            format_bool_enabled(value).bold()
        ));
    }
}

fn announce_trust_policy_set(value: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                TRUST_POLICY_KEY: value,
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!("Set trust-policy = {}", value.bold()));
    }
}

async fn run_scripts_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let existing_cfg = read_config(config_path)?;
    let global = global_config_view_from_value(&existing_cfg);
    if let Some(v) = set {
        if !SCRIPT_POLICY_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid script-policy '{v}'; must be one of: {}",
                SCRIPT_POLICY_VALUES.join(" | ")
            )));
        }
        let requested = crate::script_policy_config::ScriptPolicy::parse(v)
            .map_err(|e| LpmError::Registry(e.to_string()))?;
        crate::security_floor::reject_looser_script_policy_write(&global, requested)?;
        crate::security_approval::authorize_persistent_script_policy(
            requested,
            json_output,
            &format!("lpm config scripts --set {v}"),
        )?;
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
    let requested = crate::script_policy_config::ScriptPolicy::parse(new_value)
        .map_err(|e| LpmError::Registry(e.to_string()))?;
    crate::security_floor::reject_looser_script_policy_write(&global, requested)?;
    crate::security_approval::authorize_persistent_script_policy(
        requested,
        json_output,
        &format!("lpm config scripts --set {new_value}"),
    )?;
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
            install_ui::done(&format!(
                "Done · {SCRIPT_POLICY_KEY} = {}",
                install_ui::section("\"triage\"")
            ));
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
    let initial = detected.first().map_or("none", |r| r.provider.slug());
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
        install_ui::done(&format!(
            "Done · {key} = {}",
            install_ui::section(&format!("\"{value}\""))
        ));
    }
}

/// Disclosure printed after `script-policy = triage` is persisted (via
/// either `--set` or interactive). The wizard describes the
/// actual install-time degrade-and-warn contract:
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
    let existing_cfg = read_config(config_path)?;
    let global = global_config_view_from_value(&existing_cfg);
    if let Some(v) = set {
        if !SANDBOX_MODE_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid sandbox mode '{v}'; must be one of: {}",
                SANDBOX_MODE_VALUES.join(" | ")
            )));
        }
        let requested = ResolvedSandboxMode::parse_for_security_floor(v)
            .ok_or_else(|| LpmError::Registry(format!("invalid sandbox mode '{v}'")))?;
        crate::security_floor::reject_looser_sandbox_mode_write(&global, requested)?;
        crate::security_approval::authorize_persistent_sandbox_mode(
            requested,
            json_output,
            &format!("lpm config sandbox --set {v}"),
        )?;
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

    let requested = ResolvedSandboxMode::parse_for_security_floor(new_value)
        .ok_or_else(|| LpmError::Registry(format!("invalid sandbox mode '{new_value}'")))?;
    crate::security_floor::reject_looser_sandbox_mode_write(&global, requested)?;
    crate::security_approval::authorize_persistent_sandbox_mode(
        requested,
        json_output,
        &format!("lpm config sandbox --set {new_value}"),
    )?;
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
        install_ui::done(&format!("Set [sandbox] mode = {}", value.bold()));
    }
}

// ─────────────────────────────────────────────────────────────────────
// `lpm config sigstore` wizard
// ─────────────────────────────────────────────────────────────────────
//
// Persists `[sigstore] verify = "deny" | "warn" | "off"` into
// `~/.lpm/config.toml`. Mirror of the sandbox wizard above:
//   - interactive (TTY): `cliclack::select` with the current value
//     pre-selected, plus an extra confirmation prompt when the user
//     picks `off` (because that turns the Sigstore verifier off
//     fleet-wide — every attestation will be ignored).
//   - `--set <value>`: non-interactive setter for CI / image bake
//     dotfiles automation. Trusts the operator — no confirmation
//     prompt even on `--set off`.
//
// The wizard ONLY touches `~/.lpm/config.toml`. There is no
// project-tier sigstore knob (unlike `[sandbox] mode`); per-invocation
// opt-out lives on the install CLI (`--unverified-provenance[-all]`).

const SIGSTORE_VERIFY_VALUES: &[&str] = &["deny", "warn", "off"];

async fn run_sigstore_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let existing_cfg = read_config(config_path)?;
    let global = global_config_view_from_value(&existing_cfg);
    if let Some(v) = set {
        if !SIGSTORE_VERIFY_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid sigstore verify mode '{v}'; must be one of: {}",
                SIGSTORE_VERIFY_VALUES.join(" | ")
            )));
        }
        let requested = parse_sigstore_enforce_mode(v)?;
        crate::security_floor::reject_looser_sigstore_write(&global, requested)?;
        crate::security_approval::authorize_persistent_sigstore(
            requested,
            json_output,
            &format!("lpm config sigstore --set {v}"),
        )?;
        persist_sigstore_verify(config_path, v)?;
        announce_sigstore_set(v, json_output);
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config sigstore requires a TTY; use `--set deny|warn|off` instead".to_string(),
        ));
    }

    let current = read_sigstore_verify(config_path)?.unwrap_or_else(|| "deny".to_string());
    println!();
    println!("  current: {}", current.cyan());
    let new_value: &str =
        cliclack::select("How should LPM handle Sigstore provenance verification?")
            .item(
                "deny",
                "deny — verify every attestation, fail-closed on errors",
                "recommended",
            )
            .item("warn", "warn — verify, but only log on failure", "degraded")
            .item(
                "off",
                "off  — skip verification entirely",
                "NOT recommended",
            )
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?;

    // Confirm when the user picks `off` in the interactive wizard.
    // The `--set off` form trusts the operator (no TTY check); only
    // the wizard prompts. Matches the sandbox=none confirm shape.
    if new_value == "off" {
        println!();
        println!(
            "  {}: setting sigstore.verify = {} means every Sigstore attestation \
             your registry ships will be IGNORED. Provenance drift detection \
             still runs against unverified identity data, but a malicious or \
             compromised registry can lie about who built a package and the \
             install will accept it. LPM does not recommend disabled verification \
             as a persistent setting.",
            "warning".yellow(),
            "off".yellow().bold(),
        );
        let confirmed = cliclack::confirm(
            "Are you sure you want sigstore.verify = off for every install on this machine?",
        )
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
        if !confirmed {
            println!("  Aborted. No config change.");
            return Ok(());
        }
    }

    let requested = parse_sigstore_enforce_mode(new_value)?;
    crate::security_floor::reject_looser_sigstore_write(&global, requested)?;
    crate::security_approval::authorize_persistent_sigstore(
        requested,
        json_output,
        &format!("lpm config sigstore --set {new_value}"),
    )?;
    persist_sigstore_verify(config_path, new_value)?;
    announce_sigstore_set(new_value, json_output);
    Ok(())
}

fn parse_sigstore_enforce_mode(raw: &str) -> Result<EnforceMode, LpmError> {
    match raw {
        "deny" => Ok(EnforceMode::Deny),
        "warn" => Ok(EnforceMode::Warn),
        "off" => Ok(EnforceMode::Off),
        other => Err(LpmError::Registry(format!(
            "invalid sigstore verify mode '{other}'"
        ))),
    }
}

/// Read the `[sigstore] verify` value from `~/.lpm/config.toml`.
/// Returns `None` for missing file, missing section, or missing key.
/// Mirrors [`read_sandbox_mode`] in shape.
fn read_sigstore_verify(config_path: &std::path::Path) -> Result<Option<String>, LpmError> {
    let cfg = read_config(config_path)?;
    Ok(cfg
        .get("sigstore")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("verify"))
        .and_then(|v| v.as_str())
        .map(String::from))
}

/// Persist the resolved sigstore verify mode into `[sigstore] verify`
/// in the config file. Creates the `[sigstore]` table if absent;
/// preserves any sibling keys (future trust-root override path, etc.)
/// untouched. Mirrors [`persist_sandbox_mode`] in shape.
fn persist_sigstore_verify(config_path: &std::path::Path, value: &str) -> Result<(), LpmError> {
    let mut cfg = read_config(config_path)?;
    let top = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    let sigstore_section = top
        .entry("sigstore".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let sigstore_table = sigstore_section.as_table_mut().ok_or_else(|| {
        LpmError::Registry(format!(
            "{}: `[sigstore]` is not a TOML table — refusing to clobber",
            config_path.display(),
        ))
    })?;
    sigstore_table.insert("verify".to_string(), toml::Value::String(value.to_string()));
    write_config(config_path, &cfg)
}

fn announce_sigstore_set(value: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "sigstore": { "verify": value },
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!("Set [sigstore] verify = {}", value.bold()));
    }
}

/// Disclosure printed after `triage-advisor = <value>` is persisted
/// (via either `--set` or interactive). This describes the
/// actual install-time contract:
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

    fn tmp_config() -> (TempDir, std::path::PathBuf, crate::test_env::ScopedEnv) {
        let dir = TempDir::new().expect("tempdir");
        let security_dir = dir.path().join("security");
        let env = crate::test_env::ScopedEnv::set([
            ("LPM_SECURITY_DIR", security_dir.as_os_str().to_owned()),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                std::ffi::OsString::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
            ),
        ]);
        let posture = crate::security_approval::AuthorizedPosture {
            script_policy: "allow".to_string(),
            minimum_release_age_secs: 0,
            sandbox_mode: "none".to_string(),
            sigstore_verify: "off".to_string(),
            ..crate::security_approval::AuthorizedPosture::default()
        };
        crate::security_approval::persist_authorized_posture(&posture).unwrap();
        let path = dir.path().join("config.toml");
        (dir, path, env)
    }

    #[tokio::test]
    async fn scripts_wizard_set_persists_valid_value() {
        let (_dir, path, _env) = tmp_config();
        run_scripts_wizard(&path, Some("triage"), true)
            .await
            .unwrap();
        let v = read_string_value(&path, SCRIPT_POLICY_KEY).unwrap();
        assert_eq!(v.as_deref(), Some("triage"));
    }

    #[tokio::test]
    async fn scripts_wizard_set_rejects_invalid_value() {
        let (_dir, path, _env) = tmp_config();
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
    async fn scripts_wizard_set_rejects_looser_value_when_force_floor_enabled() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(
            &path,
            "force-security-floor = true\nscript-policy = \"triage\"\n",
        )
        .unwrap();
        let err = run_scripts_wizard(&path, Some("allow"), true)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
        assert!(err.to_string().contains("script-policy"));
    }

    #[tokio::test]
    async fn triage_wizard_set_persists_valid_provider() {
        let (_dir, path, _env) = tmp_config();
        run_triage_wizard(&path, Some("claude-cli"), true)
            .await
            .unwrap();
        let v = read_string_value(&path, TRIAGE_ADVISOR_KEY).unwrap();
        assert_eq!(v.as_deref(), Some("claude-cli"));
    }

    #[tokio::test]
    async fn triage_wizard_set_accepts_none_as_first_class() {
        let (_dir, path, _env) = tmp_config();
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
        let (_dir, path, _env) = tmp_config();
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
        let (_dir, path, _env) = tmp_config();
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

    // ── release-age wizard (--set path) ────────────────────────

    #[tokio::test]
    async fn release_age_wizard_set_persists_canonical_seconds_for_human_durations() {
        let (_dir, path, _env) = tmp_config();
        run_release_age_wizard(&path, Some("3d"), true)
            .await
            .unwrap();

        assert_eq!(read_release_age_override(&path).unwrap(), Some(259200));
        let cfg = read_config(&path).unwrap();
        let table = cfg.as_table().unwrap();
        assert_eq!(
            table.get(RELEASE_AGE_KEY).and_then(|v| v.as_str()),
            Some("259200"),
            "release-age wizard should persist canonical seconds, not the raw duration string",
        );
    }

    #[tokio::test]
    async fn release_age_wizard_set_accepts_off_alias_and_zero() {
        for value in ["off", "0"] {
            let (_dir, path, _env) = tmp_config();
            run_release_age_wizard(&path, Some(value), true)
                .await
                .unwrap();
            assert_eq!(
                read_release_age_override(&path).unwrap(),
                Some(0),
                "value '{value}' must persist as zero seconds",
            );
        }
    }

    #[tokio::test]
    async fn release_age_wizard_set_default_deletes_existing_override() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(&path, "minimum-release-age-secs = \"259200\"\n").unwrap();

        run_release_age_wizard(&path, Some("default"), true)
            .await
            .unwrap();

        assert_eq!(read_release_age_override(&path).unwrap(), None);
        let cfg = read_config(&path).unwrap();
        let table = cfg.as_table().unwrap();
        assert!(
            !table.contains_key(RELEASE_AGE_KEY),
            "default must remove the explicit global override",
        );
    }

    #[tokio::test]
    async fn release_age_wizard_set_rejects_invalid_value() {
        let (_dir, path, _env) = tmp_config();
        let err = run_release_age_wizard(&path, Some("1w"), true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported unit"), "got: {msg}");
        assert!(read_release_age_override(&path).unwrap().is_none());
    }

    #[tokio::test]
    async fn release_age_wizard_set_rejects_lower_value_when_force_floor_enabled() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(
            &path,
            "force-security-floor = true\nminimum-release-age-secs = \"259200\"\n",
        )
        .unwrap();
        let err = run_release_age_wizard(&path, Some("0"), true)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
        assert!(err.to_string().contains("minimum-release-age-secs"));
    }

    #[tokio::test]
    async fn release_age_wizard_preserves_unrelated_keys() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(&path, "script-policy = \"triage\"\n").unwrap();

        run_release_age_wizard(&path, Some("12h"), true)
            .await
            .unwrap();

        let cfg = read_config(&path).unwrap();
        let table = cfg.as_table().unwrap();
        assert_eq!(
            table.get("script-policy").and_then(|v| v.as_str()),
            Some("triage"),
        );
        assert_eq!(
            table.get(RELEASE_AGE_KEY).and_then(|v| v.as_str()),
            Some("43200"),
        );
    }

    #[test]
    fn release_age_wizard_initial_choice_treats_explicit_one_day_as_custom() {
        assert_eq!(release_age_initial_choice(None), "default");
        assert_eq!(release_age_initial_choice(Some(0)), "off");
        assert_eq!(
            release_age_initial_choice(Some(CAUTIOUS_RELEASE_AGE_SECS)),
            "cautious"
        );
        assert_eq!(
            release_age_initial_choice(Some(DEFAULT_RELEASE_AGE_SECS)),
            "custom",
            "explicit 1d override must stay distinguishable from true default",
        );
    }

    // ── sandbox wizard (rework) ─────────────────────────

    #[tokio::test]
    async fn sandbox_wizard_set_persists_each_valid_mode() {
        for mode in &["default", "strict", "none"] {
            let (_dir, path, _env) = tmp_config();
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
        let (_dir, path, _env) = tmp_config();
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
    async fn sandbox_wizard_set_rejects_looser_mode_when_force_floor_enabled() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(
            &path,
            "force-security-floor = true\n[sandbox]\nmode = \"strict\"\n",
        )
        .unwrap();
        let err = run_sandbox_wizard(&path, Some("default"), true)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
        assert!(err.to_string().contains("[sandbox].mode"));
    }

    #[tokio::test]
    async fn sandbox_wizard_preserves_sibling_keys() {
        // The wizard writes `[sandbox] mode`; an existing
        // `[sandbox] allow-degraded` must survive.
        let (_dir, path, _env) = tmp_config();
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
        let (_dir, path, _env) = tmp_config();
        std::fs::write(&path, "sandbox = \"not-a-table\"\n").unwrap();
        let err = run_sandbox_wizard(&path, Some("strict"), true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not a TOML table"), "got: {msg}");
    }

    #[tokio::test]
    async fn sandbox_wizard_overwrites_existing_mode() {
        let (_dir, path, _env) = tmp_config();
        run_sandbox_wizard(&path, Some("default"), true)
            .await
            .unwrap();
        run_sandbox_wizard(&path, Some("strict"), true)
            .await
            .unwrap();
        assert_eq!(read_sandbox_mode(&path).unwrap().as_deref(), Some("strict"));
    }

    // ── GlobalConfig::get_sigstore_verify ──────────────────────

    /// `[sigstore].verify` resolves to the right string. Pin both
    /// the table layout (nested, not flat `sigstore-verify`) and the
    /// returned value so a future wizard wired to a different key
    /// path fails this test loudly. (Wizard write path + config
    /// reader MUST agree on the nested-table key shape — if either
    /// drifts, the wizard appears to succeed but installs ignore
    /// the persisted value.)
    #[test]
    fn global_config_get_sigstore_verify_returns_string_when_present() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(&path, "[sigstore]\nverify = \"warn\"\n").unwrap();
        let toml_val = read_config(&path).unwrap();
        let table = match toml_val {
            toml::Value::Table(t) => t,
            _ => panic!("expected top-level table"),
        };
        let cfg = GlobalConfig { table };
        assert_eq!(cfg.get_sigstore_verify().as_deref(), Some("warn"));
    }

    /// Absent table → `None`. Distinguishes "operator hasn't set it"
    /// from "operator set it to a known bad value" so the precedence
    /// chain in `EnforceMode::resolve_from_chain` can fall through.
    #[test]
    fn global_config_get_sigstore_verify_returns_none_when_absent() {
        let cfg = GlobalConfig::empty();
        assert!(cfg.get_sigstore_verify().is_none());
    }

    /// Non-string (e.g. accidentally wrote a bool) → `None`. The
    /// `EnforceMode` parser handles unknown strings with a
    /// tracing::warn; this layer just signals "no usable value".
    #[test]
    fn global_config_get_sigstore_verify_returns_none_for_non_string_value() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(&path, "[sigstore]\nverify = true\n").unwrap();
        let toml_val = read_config(&path).unwrap();
        let table = match toml_val {
            toml::Value::Table(t) => t,
            _ => panic!("expected top-level table"),
        };
        let cfg = GlobalConfig { table };
        assert!(cfg.get_sigstore_verify().is_none());
    }

    // ── lpm config sigstore wizard (--set path) ────────────────

    /// `--set deny|warn|off` persists into `[sigstore] verify` and
    /// round-trips through `read_sigstore_verify`. Three values, one
    /// test — keeps the persistence-shape contract pinned in one
    /// place.
    #[tokio::test]
    async fn sigstore_wizard_set_persists_each_valid_value() {
        for v in ["deny", "warn", "off"] {
            let (_dir, path, _env) = tmp_config();
            run_sigstore_wizard(&path, Some(v), true).await.unwrap();
            assert_eq!(
                read_sigstore_verify(&path).unwrap().as_deref(),
                Some(v),
                "value '{v}' must round-trip through [sigstore] verify",
            );
        }
    }

    /// `--set <unknown>` errors with a message that lists the three
    /// valid values so the operator can self-correct without
    /// consulting docs.
    #[tokio::test]
    async fn sigstore_wizard_set_rejects_invalid_value() {
        let (_dir, path, _env) = tmp_config();
        let err = run_sigstore_wizard(&path, Some("yolo"), true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid sigstore verify mode 'yolo'"),
            "got: {msg}"
        );
        assert!(
            msg.contains("deny"),
            "error must list 'deny' as a valid value: {msg}"
        );
        assert!(
            msg.contains("warn"),
            "error must list 'warn' as a valid value: {msg}"
        );
        assert!(
            msg.contains("off"),
            "error must list 'off' as a valid value: {msg}"
        );
        // Nothing persisted on validation failure.
        assert!(read_sigstore_verify(&path).unwrap().is_none());
    }

    #[tokio::test]
    async fn sigstore_wizard_set_rejects_looser_value_when_force_floor_enabled() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(
            &path,
            "force-security-floor = true\n[sigstore]\nverify = \"deny\"\n",
        )
        .unwrap();
        let err = run_sigstore_wizard(&path, Some("warn"), true)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
        assert!(err.to_string().contains("[sigstore].verify"));
    }

    #[test]
    fn guard_generic_set_rejects_disabling_force_floor_when_enabled() {
        let config: toml::Value = toml::from_str("force-security-floor = true\n").unwrap();
        let err = guard_generic_set_against_force_floor(&config, "force-security-floor", "false")
            .unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
    }

    #[test]
    fn guard_generic_delete_rejects_lowering_release_age_to_default() {
        let config: toml::Value =
            toml::from_str("force-security-floor = true\nminimum-release-age-secs = \"259200\"\n")
                .unwrap();
        let err = guard_generic_delete_against_force_floor(&config, RELEASE_AGE_KEY).unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
    }

    #[test]
    fn guard_generic_delete_rejects_unsetting_force_floor_when_enabled() {
        let config: toml::Value = toml::from_str("force-security-floor = true\n").unwrap();
        let err =
            guard_generic_delete_against_force_floor(&config, "force-security-floor").unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
    }

    /// JSON envelope shape for the announce-set path — mirrors the
    /// sandbox / scripts wizards so agents can branch on the same
    /// `{success, sigstore: {verify}}` field structure.
    #[tokio::test]
    async fn sigstore_wizard_json_envelope_shape() {
        let (_dir, path, _env) = tmp_config();
        // Capturing stdout cleanly in a unit test is awkward; this test
        // pins that `--set` + json_output returns Ok and the
        // persistence still happens. The envelope shape itself is
        // pinned by hand-inspection of `announce_sigstore_set`.
        run_sigstore_wizard(&path, Some("warn"), true)
            .await
            .expect("--set with json_output=true must not error");
        assert_eq!(
            read_sigstore_verify(&path).unwrap().as_deref(),
            Some("warn"),
            "JSON path must still persist before announcing",
        );
    }

    /// Persisting sigstore.verify must not clobber sibling keys
    /// under `[sigstore]` (room for future trust-root overrides, etc.)
    /// nor unrelated top-level entries. This is the same defensive
    /// guarantee the sandbox wizard pins.
    #[tokio::test]
    async fn sigstore_wizard_preserves_other_keys() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(
            &path,
            "script-policy = \"triage\"\n\n[sandbox]\nmode = \"strict\"\n\n[sigstore]\ntrust-root-override = \"/path/to/custom-root.json\"\n",
        )
        .unwrap();
        run_sigstore_wizard(&path, Some("off"), true).await.unwrap();

        let cfg = read_config(&path).unwrap();
        let table = cfg.as_table().unwrap();
        // Sigstore verify landed.
        assert_eq!(
            table
                .get("sigstore")
                .and_then(|v| v.as_table())
                .and_then(|t| t.get("verify"))
                .and_then(|v| v.as_str()),
            Some("off"),
        );
        // Sibling [sigstore].trust-root-override preserved.
        assert_eq!(
            table
                .get("sigstore")
                .and_then(|v| v.as_table())
                .and_then(|t| t.get("trust-root-override"))
                .and_then(|v| v.as_str()),
            Some("/path/to/custom-root.json"),
            "sibling [sigstore] keys must survive — wizard must not clobber them",
        );
        // Unrelated top-level keys preserved.
        assert_eq!(
            table.get("script-policy").and_then(|v| v.as_str()),
            Some("triage"),
        );
        assert_eq!(
            table
                .get("sandbox")
                .and_then(|v| v.as_table())
                .and_then(|t| t.get("mode"))
                .and_then(|v| v.as_str()),
            Some("strict"),
        );
    }

    /// Defensive: refuse to clobber a non-table `sigstore` top-level
    /// value (operator wrote `sigstore = "foo"`). Honest error >
    /// silent migration on a typed config knob. Mirrors the
    /// sandbox wizard's equivalent guard.
    #[tokio::test]
    async fn sigstore_wizard_refuses_to_clobber_non_table_sigstore_key() {
        let (_dir, path, _env) = tmp_config();
        std::fs::write(&path, "sigstore = \"not-a-table\"\n").unwrap();
        let err = run_sigstore_wizard(&path, Some("warn"), true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not a TOML table"), "got: {msg}");
    }

    /// Overwrite path: setting twice must end on the second value.
    /// Pins idempotent re-runs.
    #[tokio::test]
    async fn sigstore_wizard_overwrites_existing_value() {
        let (_dir, path, _env) = tmp_config();
        run_sigstore_wizard(&path, Some("warn"), true)
            .await
            .unwrap();
        run_sigstore_wizard(&path, Some("deny"), true)
            .await
            .unwrap();
        assert_eq!(
            read_sigstore_verify(&path).unwrap().as_deref(),
            Some("deny"),
        );
    }
}
