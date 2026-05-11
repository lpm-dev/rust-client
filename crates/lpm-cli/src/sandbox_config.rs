//! Phase 46.1 sandbox-config loader.
//!
//! Resolves the [`lpm_sandbox::SandboxOptions`] the install / rebuild
//! pipelines pass through to [`lpm_sandbox::new_for_platform_with_options`].
//! Reads the `[sandbox]` table from two TOML files in precedence
//! order:
//!
//! 1. **Project config**: `<project_dir>/lpm.toml`. Highest
//!    precedence — a project that wants strict containment in every
//!    contributor's environment sets `allow-degraded = false` (or
//!    leaves it absent — the default).
//! 2. **Global config**: `~/.lpm/config.toml`. Per-user opt-in to the
//!    degraded posture on a specific machine (RHEL 9 / Ubuntu 22.04
//!    / Debian 12 / Amazon Linux 2023 boxes that knowingly accept
//!    the trade-off of running without kernel-level outbound network
//!    denial).
//! 3. **Built-in default**: `allow-degraded = false` — the strict
//!    posture, honest about what the kernel can deliver.
//!
//! Per-project values win over per-user values. The
//! `[sandbox] allow-degraded` knob is read by both the
//! `lpm install` / `lpm rebuild` lifecycle-script pipelines and by
//! `lpm doctor` (so the doctor surface reflects the same opt-in
//! that the install will actually use).
//!
//! ## File format
//!
//! ```toml
//! [sandbox]
//! allow-degraded = false   # bool; true falls back to V1 on kernels < 6.7
//! ```
//!
//! Per CLAUDE.md and the design-note locked decisions, the
//! `[sandbox] allow-degraded` opt-in is persistent (not a flag-only
//! escape) — it lives in lpm.toml / ~/.lpm/config.toml so a machine's
//! degraded posture is a property of that machine, not a one-off
//! invocation.
//!
//! ## Why not under `package.json > lpm`?
//!
//! The opt-in is a per-environment (machine / kernel / distro)
//! trade-off, not a publishable package metadata trait. A project
//! whose contributors include both 6.7+ and < 6.7 hosts gets the
//! best of both worlds: contributors on capable kernels get strict
//! containment; contributors on older kernels opt in to degraded.
//! Putting the toggle in `package.json` would force the project to
//! pick one posture for every contributor — exactly the wrong
//! design lever.

use lpm_common::LpmError;
use lpm_sandbox::{SandboxMode, SandboxOptions};
use std::path::Path;

/// Read the Phase 46.1 sandbox knobs from `<project_dir>/lpm.toml`
/// + `~/.lpm/config.toml` and resolve them to a [`SandboxOptions`].
///
/// Missing files / missing keys fall through to defaults.
///
/// Returns `Err(LpmError::Registry)` only if a file exists but is
/// malformed (invalid TOML, non-bool `allow-degraded` value,
/// unknown `mode` string). The error names the offending file
/// path so the user sees which side needs editing.
///
/// **Phase 46.1 rework note:** this loader reports the
/// CONFIG-ONLY view (project lpm.toml + user config.toml). CLI
/// flags (`--strict-sandbox` / `--paranoid` / `--no-sandbox`) and
/// the `LPM_STRICT_SANDBOX` env var sit at HIGHER priority and are
/// applied by [`resolve_sandbox_mode_from_chain`] — call sites
/// that have CLI / env signals should use that wrapper instead of
/// this raw loader.
#[allow(dead_code)]
pub fn load_sandbox_options(project_dir: &Path) -> Result<SandboxOptions, LpmError> {
    let (options, _) = load_sandbox_options_with_mode(project_dir)?;
    Ok(options)
}

/// Same as [`load_sandbox_options`] but also returns the resolved
/// user-facing sandbox mode (`default` / `strict` / `none`) for
/// callers that need to short-circuit to `SandboxMode::Disabled`
/// when the mode is `None`.
pub fn load_sandbox_options_with_mode(
    project_dir: &Path,
) -> Result<(SandboxOptions, ResolvedSandboxMode), LpmError> {
    let project_path = project_dir.join("lpm.toml");
    let project = read_sandbox_keys_from_file(&project_path)?;

    let global_path = dirs::home_dir().map(|h| h.join(".lpm").join("config.toml"));
    let global = match global_path {
        Some(ref p) => read_sandbox_keys_from_file(p)?,
        None => RawSandboxKeys::default(),
    };

    Ok(merge(project, global))
}

/// Phase 46.1 rework: resolve the FULL precedence chain into a
/// concrete sandbox mode. Highest priority first:
///
/// 1. CLI flag (`no_sandbox_flag` / `strict_sandbox_flag`). Caller
///    passes the parsed boolean from clap. Conflicting flags
///    (`--no-sandbox` + `--strict-sandbox`) are clap-rejected at
///    arg parse so this resolver never sees both true.
/// 2. `LPM_STRICT_SANDBOX=1` env var (CI / one-shot).
/// 3. `./lpm.toml > [sandbox] mode` (project, committed to git).
/// 4. `~/.lpm/config.toml > [sandbox] mode` (user, not committed).
/// 5. Default: [`ResolvedSandboxMode::Default`].
///
/// Returns the resolved mode + a [`SandboxOptions`] with
/// `deny_outbound_network` aligned to the resolved mode. Callers
/// then pick `SandboxMode::Enforce` (for Default + Strict) or
/// `SandboxMode::Disabled` (for None) at the constructor call
/// site.
pub fn resolve_sandbox_mode_from_chain(
    project_dir: &Path,
    no_sandbox_flag: bool,
    strict_sandbox_flag: bool,
) -> Result<(SandboxOptions, ResolvedSandboxMode), LpmError> {
    if no_sandbox_flag {
        // `--no-sandbox` always wins. No env/config consultation —
        // the user explicitly said "no sandbox for this command."
        return Ok((SandboxOptions::default(), ResolvedSandboxMode::None));
    }
    if strict_sandbox_flag {
        let (options, _) = load_sandbox_options_with_mode(project_dir)?;
        return Ok((
            SandboxOptions {
                deny_outbound_network: true,
                ..options
            },
            ResolvedSandboxMode::Strict,
        ));
    }
    if env_strict_sandbox_set() {
        let (options, _) = load_sandbox_options_with_mode(project_dir)?;
        return Ok((
            SandboxOptions {
                deny_outbound_network: true,
                ..options
            },
            ResolvedSandboxMode::Strict,
        ));
    }
    load_sandbox_options_with_mode(project_dir)
}

/// `true` when `LPM_STRICT_SANDBOX` is set to a value the user
/// intended as "on" (`"1"`, `"true"`, `"yes"`, case-insensitively).
/// Empty / unset / `"0"` / `"false"` / `"no"` are off. Any other
/// value is treated as off too — magic-by-malformed-env is the
/// kind of "what the user configured wins" violation the Q4
/// redline rejected.
fn env_strict_sandbox_set() -> bool {
    match std::env::var("LPM_STRICT_SANDBOX") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Raw key snapshot from a single TOML file. `None` means the key is
/// absent (fall through to the next tier); `Some` means the file
/// explicitly set it.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
struct RawSandboxKeys {
    allow_degraded: Option<bool>,
    /// Phase 46.1 rework: `[sandbox] mode = "default" | "strict" |
    /// "none"`. The wizard (`lpm config sandbox`) writes this key;
    /// the install pipeline reads it and resolves the precedence
    /// chain (CLI flag > env > project lpm.toml > user
    /// config.toml > default). `None` means absent; resolution
    /// falls through to the next tier or to the default.
    ///
    /// The value is normalised at parse time. Unknown strings
    /// error out with a named-file diagnostic so the user knows
    /// which file needs editing.
    mode: Option<SandboxModeKey>,
}

/// Internal normalised representation of the `[sandbox] mode` TOML
/// key. The CLI surface uses string-typed values for the wizard;
/// this enum is what flows through the precedence chain.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum SandboxModeKey {
    Default,
    Strict,
    None,
}

impl SandboxModeKey {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "default" => Some(Self::Default),
            "strict" => Some(Self::Strict),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Read the Phase 46.1 sandbox keys from a single TOML file. Missing
/// file → empty `RawSandboxKeys`. Malformed file or invalid value →
/// error with the file path baked in for diagnostics.
fn read_sandbox_keys_from_file(path: &Path) -> Result<RawSandboxKeys, LpmError> {
    if !path.exists() {
        return Ok(RawSandboxKeys::default());
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| LpmError::Registry(format!("failed to read {}: {e}", path.display())))?;

    let parsed: toml::Value = toml::from_str(&raw)
        .map_err(|e| LpmError::Registry(format!("failed to parse {}: {e}", path.display())))?;

    let table = match parsed {
        toml::Value::Table(t) => t,
        _ => {
            return Err(LpmError::Registry(format!(
                "{} must be a TOML table at the top level",
                path.display()
            )));
        }
    };

    let mut keys = RawSandboxKeys::default();

    // The Phase 46.1 surface lives under `[sandbox]`. A bare
    // top-level `allow-degraded = …` is NOT honored — pinning the
    // namespace prevents accidental key-name collisions with other
    // top-level config keys (e.g. `save-prefix`, `script-policy`).
    if let Some(sandbox_section) = table.get("sandbox") {
        let sb_table = sandbox_section.as_table().ok_or_else(|| {
            LpmError::Registry(format!(
                "{}: `[sandbox]` must be a TOML table, got {sandbox_section}",
                path.display(),
            ))
        })?;

        if let Some(value) = sb_table.get("allow-degraded") {
            keys.allow_degraded = Some(coerce_bool(value).ok_or_else(|| {
                LpmError::Registry(format!(
                    "{}: `[sandbox] allow-degraded` must be a boolean (`true`, `false`) or one \
                     of the string aliases (\"true\", \"false\", \"1\", \"0\", \"yes\", \"no\"), \
                     got {value}",
                    path.display(),
                ))
            })?);
        }

        // Phase 46.1 rework: `[sandbox] mode = "default" | "strict"
        // | "none"`. Reject unknown strings explicitly — silently
        // ignoring would mask a typo and the user would never
        // know why strict mode wasn't engaging.
        if let Some(value) = sb_table.get("mode") {
            let raw = value.as_str().ok_or_else(|| {
                LpmError::Registry(format!(
                    "{}: `[sandbox] mode` must be a string, got {value}",
                    path.display(),
                ))
            })?;
            let parsed = SandboxModeKey::parse(raw).ok_or_else(|| {
                LpmError::Registry(format!(
                    "{}: `[sandbox] mode` must be one of \"default\", \"strict\", \"none\", \
                     got {raw:?}",
                    path.display(),
                ))
            })?;
            keys.mode = Some(parsed);
        }
    }

    Ok(keys)
}

/// Merge project + global raw keys into the final [`SandboxOptions`].
/// Project values win over global; both fall through to defaults.
///
/// Phase 46.1 rework: emits `(SandboxOptions, ResolvedSandboxMode)`
/// so the install pipeline knows BOTH the `deny_outbound_network`
/// the constructor consumes AND whether the user picked `none`
/// (in which case the caller switches `SandboxMode` to `Disabled`
/// and skips the constructor entirely).
fn merge(project: RawSandboxKeys, global: RawSandboxKeys) -> (SandboxOptions, ResolvedSandboxMode) {
    let mode = project
        .mode
        .or(global.mode)
        .unwrap_or(SandboxModeKey::Default);
    let deny_outbound_network = matches!(mode, SandboxModeKey::Strict);
    let resolved = match mode {
        SandboxModeKey::Default => ResolvedSandboxMode::Default,
        SandboxModeKey::Strict => ResolvedSandboxMode::Strict,
        SandboxModeKey::None => ResolvedSandboxMode::None,
    };
    let options = SandboxOptions {
        allow_degraded: project
            .allow_degraded
            .or(global.allow_degraded)
            .unwrap_or(false),
        deny_outbound_network,
    };
    (options, resolved)
}

/// Phase 46.1 rework: the user-facing sandbox mode resolved from the
/// precedence chain. The CLI surface speaks this enum; the
/// constructor accepts the `(SandboxMode, SandboxOptions)` pair.
///
/// - `Default` → `SandboxMode::Enforce` + `deny_outbound_network = false`.
/// - `Strict`  → `SandboxMode::Enforce` + `deny_outbound_network = true`.
/// - `None`    → `SandboxMode::Disabled` (caller short-circuits to
///   `NoopSandbox` and skips env scrubbing too — Phase 46.1 rework
///   collapsed `--unsafe-full-env` into `--no-sandbox` per Q6 of
///   the DX redline).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ResolvedSandboxMode {
    Default,
    Strict,
    None,
}

impl ResolvedSandboxMode {
    /// User-visible name for diagnostic output (doctor, install
    /// banner, debug logs).
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Strict => "strict",
            Self::None => "none",
        }
    }
}

/// Phase 46.1 rework runtime collapse: turn the resolved sandbox
/// mode + per-command CLI overrides into the `(SandboxMode, env_scrub)`
/// pair the install/rebuild pipelines actually consume.
///
/// Centralised because the previous version of `rebuild::run_under_store_lock`
/// computed `SandboxMode` from `no_sandbox` alone and discarded the
/// resolved mode — so persistent `[sandbox] mode = "none"` (config /
/// wizard) silently fell back to the enforced default. This helper
/// + its unit tests pin the contract so a regression rebuilds the bug.
///
/// Precedence (CLI > config / env):
///
/// 1. `no_sandbox_flag` (CLI `--no-sandbox`) → [`SandboxMode::Disabled`]
///    plus `env_scrub = false`. The legacy `--unsafe-full-env`
///    partner was collapsed per Q6 of the DX redline.
/// 2. `sandbox_log_flag` (CLI `--sandbox-log`) → [`SandboxMode::LogOnly`]
///    plus `env_scrub = true`. Diagnostic intent on the CLI wins
///    over a persistent `mode = "none"` so the user can observe
///    behaviour without changing their default posture.
/// 3. Resolved [`ResolvedSandboxMode::None`] (from `[sandbox] mode = "none"`
///    in `./lpm.toml` or `~/.lpm/config.toml`) → [`SandboxMode::Disabled`]
///    plus `env_scrub = false`. Same shape as the CLI escape, just
///    persistent — what `lpm config sandbox --set none` promises.
/// 4. Resolved [`ResolvedSandboxMode::Default`] or
///    [`ResolvedSandboxMode::Strict`] → [`SandboxMode::Enforce`]
///    plus `env_scrub = true`. Strict is distinguished from default
///    at the `SandboxOptions` layer (via `deny_outbound_network`),
///    not here.
///
/// `env_scrub = true` means the install pipeline runs
/// [`build_sanitized_env`](crate::commands::rebuild::build_sanitized_env)
/// (strip credential env vars); `false` means pass the full
/// `std::env::vars()` through.
pub fn decide_runtime_sandbox_mode(
    no_sandbox_flag: bool,
    sandbox_log_flag: bool,
    resolved: ResolvedSandboxMode,
) -> (SandboxMode, bool) {
    if no_sandbox_flag {
        // CLI `--no-sandbox` is the per-command escape hatch.
        // Single-flag drop of containment AND env scrubbing — the
        // Phase 46.1 Q6 collapse.
        return (SandboxMode::Disabled, false);
    }
    if sandbox_log_flag {
        // Diagnostic-only override on the CLI. The clap layer
        // rejects `--sandbox-log` paired with `--no-sandbox`, so
        // this branch never co-occurs with the prior one.
        return (SandboxMode::LogOnly, true);
    }
    if matches!(resolved, ResolvedSandboxMode::None) {
        // Persistent `[sandbox] mode = "none"` — the wizard's
        // off-mode shape. Same runtime behaviour as the CLI
        // `--no-sandbox` escape so the contract is symmetric.
        return (SandboxMode::Disabled, false);
    }
    // Default / Strict: containment is on. Strict's deny-outbound-
    // network bit is carried separately on `SandboxOptions`.
    (SandboxMode::Enforce, true)
}

/// Coerce a TOML value into a `bool` using the same string-alias rules
/// that the global config reader uses for legacy string-coerced
/// values. Native `Boolean(b)` is the preferred form; the string
/// aliases exist because the generic `lpm config set <key> <value>`
/// command writes every value as a TOML string regardless of the
/// key's intended type (Finding A in [`crate::save_config`]) — without
/// the alias set, the documented persistent-config path would fail
/// for users who set the knob via that command.
fn coerce_bool(value: &toml::Value) -> Option<bool> {
    match value {
        toml::Value::Boolean(b) => Some(*b),
        toml::Value::String(s) => match s.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct Env {
        _tmp: TempDir,
        project: std::path::PathBuf,
    }

    fn fixture(lpm_toml_body: Option<&str>) -> Env {
        let tmp = tempfile::tempdir().expect("tempdir");
        let project = tmp.path().to_path_buf();
        if let Some(body) = lpm_toml_body {
            fs::write(project.join("lpm.toml"), body).expect("write lpm.toml");
        }
        Env { _tmp: tmp, project }
    }

    /// Convenience: read the project-side only (ignore the global
    /// `~/.lpm/config.toml`). The full chain is exercised separately
    /// via `load_sandbox_options` against a controlled HOME.
    fn read_project_only(env: &Env) -> Result<RawSandboxKeys, LpmError> {
        read_sandbox_keys_from_file(&env.project.join("lpm.toml"))
    }

    #[test]
    fn missing_lpm_toml_yields_default_options() {
        let env = fixture(None);
        let r = read_project_only(&env).unwrap();
        assert_eq!(r, RawSandboxKeys::default());
    }

    #[test]
    fn lpm_toml_without_sandbox_section_yields_default() {
        let env = fixture(Some(r#"save-prefix = "^""#));
        let r = read_project_only(&env).unwrap();
        assert_eq!(r, RawSandboxKeys::default());
    }

    #[test]
    fn lpm_toml_with_sandbox_section_but_no_allow_degraded_yields_default() {
        let env = fixture(Some(
            r#"
[sandbox]
"#,
        ));
        let r = read_project_only(&env).unwrap();
        assert_eq!(r, RawSandboxKeys::default());
    }

    #[test]
    fn lpm_toml_native_bool_true_sets_allow_degraded() {
        let env = fixture(Some(
            r#"
[sandbox]
allow-degraded = true
"#,
        ));
        let r = read_project_only(&env).unwrap();
        assert_eq!(r.allow_degraded, Some(true));
    }

    #[test]
    fn lpm_toml_native_bool_false_sets_allow_degraded() {
        let env = fixture(Some(
            r#"
[sandbox]
allow-degraded = false
"#,
        ));
        let r = read_project_only(&env).unwrap();
        assert_eq!(r.allow_degraded, Some(false));
    }

    #[test]
    fn lpm_toml_string_aliases_coerce_to_bool() {
        for (raw, expected) in &[
            (r#""true""#, true),
            (r#""1""#, true),
            (r#""yes""#, true),
            (r#""false""#, false),
            (r#""0""#, false),
            (r#""no""#, false),
        ] {
            let body = format!(
                r#"
[sandbox]
allow-degraded = {raw}
"#,
            );
            let env = fixture(Some(&body));
            let r = read_project_only(&env).unwrap();
            assert_eq!(
                r.allow_degraded,
                Some(*expected),
                "string alias {raw} must coerce to {expected}",
            );
        }
    }

    #[test]
    fn lpm_toml_invalid_value_errors_with_actionable_message() {
        let env = fixture(Some(
            r#"
[sandbox]
allow-degraded = "maybe"
"#,
        ));
        match read_project_only(&env) {
            Err(LpmError::Registry(msg)) => {
                assert!(msg.contains("allow-degraded"));
                assert!(msg.contains("boolean"));
            }
            other => panic!("expected Registry error, got {other:?}"),
        }
    }

    #[test]
    fn lpm_toml_non_table_sandbox_errors() {
        let env = fixture(Some(r#"sandbox = "not-a-table""#));
        match read_project_only(&env) {
            Err(LpmError::Registry(msg)) => {
                assert!(msg.contains("`[sandbox]`"));
                assert!(msg.contains("table"));
            }
            other => panic!("expected Registry error, got {other:?}"),
        }
    }

    #[test]
    fn lpm_toml_malformed_toml_errors_with_filepath() {
        let env = fixture(Some(r#"[sandbox INVALID"#));
        match read_project_only(&env) {
            Err(LpmError::Registry(msg)) => {
                assert!(msg.contains("parse"));
                assert!(msg.contains("lpm.toml"), "must name the source file: {msg}");
            }
            other => panic!("expected Registry error, got {other:?}"),
        }
    }

    // ── merge() ──

    #[test]
    fn merge_default_is_default_when_both_tiers_absent() {
        // Phase 46.1 rework: when neither tier sets a value, the
        // user is on the relaxed default — sandbox active, network
        // allowed.
        let (options, mode) = merge(RawSandboxKeys::default(), RawSandboxKeys::default());
        assert!(!options.allow_degraded);
        assert!(!options.deny_outbound_network);
        assert_eq!(mode, ResolvedSandboxMode::Default);
    }

    #[test]
    fn merge_global_supplies_allow_degraded_when_project_silent() {
        let global = RawSandboxKeys {
            allow_degraded: Some(true),
            mode: None,
        };
        let (options, mode) = merge(RawSandboxKeys::default(), global);
        assert!(options.allow_degraded);
        // `allow_degraded` only matters under strict; the resolved
        // mode is still Default unless `[sandbox] mode = "strict"`
        // is set.
        assert_eq!(mode, ResolvedSandboxMode::Default);
    }

    #[test]
    fn merge_project_allow_degraded_wins_over_global() {
        // Project explicitly disables degrade — a team can pin
        // strict-no-fallback in lpm.toml and any user who has
        // globally enabled allow-degraded still gets the strict
        // default.
        let project = RawSandboxKeys {
            allow_degraded: Some(false),
            mode: None,
        };
        let global = RawSandboxKeys {
            allow_degraded: Some(true),
            mode: None,
        };
        let (options, _) = merge(project, global);
        assert!(
            !options.allow_degraded,
            "project allow-degraded=false MUST override global allow-degraded=true",
        );
    }

    #[test]
    fn merge_project_allow_degraded_opt_in_wins_over_global() {
        // Symmetric: a project that needs degraded posture can
        // opt in regardless of global config.
        let project = RawSandboxKeys {
            allow_degraded: Some(true),
            mode: None,
        };
        let global = RawSandboxKeys {
            allow_degraded: Some(false),
            mode: None,
        };
        let (options, _) = merge(project, global);
        assert!(
            options.allow_degraded,
            "project allow-degraded=true MUST override global allow-degraded=false",
        );
    }

    #[test]
    fn merge_project_mode_strict_sets_deny_outbound_network() {
        let project = RawSandboxKeys {
            allow_degraded: None,
            mode: Some(SandboxModeKey::Strict),
        };
        let (options, mode) = merge(project, RawSandboxKeys::default());
        assert!(options.deny_outbound_network);
        assert_eq!(mode, ResolvedSandboxMode::Strict);
    }

    #[test]
    fn merge_project_mode_none_propagates_to_resolved() {
        let project = RawSandboxKeys {
            allow_degraded: None,
            mode: Some(SandboxModeKey::None),
        };
        let (options, mode) = merge(project, RawSandboxKeys::default());
        assert!(!options.deny_outbound_network);
        assert_eq!(mode, ResolvedSandboxMode::None);
    }

    #[test]
    fn merge_project_mode_wins_over_global_mode() {
        let project = RawSandboxKeys {
            allow_degraded: None,
            mode: Some(SandboxModeKey::Default),
        };
        let global = RawSandboxKeys {
            allow_degraded: None,
            mode: Some(SandboxModeKey::Strict),
        };
        let (options, mode) = merge(project, global);
        assert!(!options.deny_outbound_network);
        assert_eq!(mode, ResolvedSandboxMode::Default);
    }

    #[test]
    fn merge_global_mode_supplies_when_project_silent() {
        let global = RawSandboxKeys {
            allow_degraded: None,
            mode: Some(SandboxModeKey::Strict),
        };
        let (options, mode) = merge(RawSandboxKeys::default(), global);
        assert!(options.deny_outbound_network);
        assert_eq!(mode, ResolvedSandboxMode::Strict);
    }

    // ── SandboxModeKey::parse ──

    #[test]
    fn parse_sandbox_mode_key_accepts_known_values() {
        assert_eq!(
            SandboxModeKey::parse("default"),
            Some(SandboxModeKey::Default)
        );
        assert_eq!(
            SandboxModeKey::parse("strict"),
            Some(SandboxModeKey::Strict)
        );
        assert_eq!(SandboxModeKey::parse("none"), Some(SandboxModeKey::None));
    }

    #[test]
    fn parse_sandbox_mode_key_rejects_unknown() {
        assert_eq!(SandboxModeKey::parse("paranoid"), None);
        assert_eq!(SandboxModeKey::parse(""), None);
        assert_eq!(SandboxModeKey::parse("Default"), None); // case-sensitive
    }

    // ── decide_runtime_sandbox_mode (Phase 46.1 rework follow-up) ──
    //
    // GPT-5 audit (2026-05-11) caught a real bug: the previous version
    // of `rebuild::run_under_store_lock` computed `SandboxMode` from
    // the CLI `no_sandbox` flag alone and discarded the resolved
    // mode, so persistent `[sandbox] mode = "none"` from the wizard
    // / config files silently fell back to the enforced default.
    // These tests pin the contract a future regression would break.

    #[test]
    fn decide_runtime_no_flags_default_mode_yields_enforce_with_scrub() {
        // The 90% case: user hasn't touched any sandbox knob, install
        // runs under filesystem-write containment + env scrubbing.
        let (mode, scrub) = decide_runtime_sandbox_mode(false, false, ResolvedSandboxMode::Default);
        assert_eq!(mode, SandboxMode::Enforce);
        assert!(scrub, "env scrubbing on under the default posture");
    }

    #[test]
    fn decide_runtime_no_flags_strict_mode_yields_enforce_with_scrub() {
        // Strict is distinguished at the SandboxOptions layer (the
        // `deny_outbound_network` bit), not at `SandboxMode`. The
        // runtime mode is the same Enforce as default; only the
        // ruleset narrows.
        let (mode, scrub) = decide_runtime_sandbox_mode(false, false, ResolvedSandboxMode::Strict);
        assert_eq!(mode, SandboxMode::Enforce);
        assert!(scrub, "env scrubbing on under strict posture");
    }

    #[test]
    fn decide_runtime_no_flags_config_none_yields_disabled_no_scrub() {
        // The bug GPT-5 caught: `[sandbox] mode = "none"` from
        // config / the wizard MUST produce a fully-disabled runtime,
        // not silently fall back to Enforce. Symmetric with the CLI
        // `--no-sandbox` escape — same on-disk shape persisted via
        // `lpm config sandbox --set none`.
        let (mode, scrub) = decide_runtime_sandbox_mode(false, false, ResolvedSandboxMode::None);
        assert_eq!(
            mode,
            SandboxMode::Disabled,
            "config mode = 'none' MUST disable the sandbox (matches CLI --no-sandbox semantics)"
        );
        assert!(
            !scrub,
            "config mode = 'none' MUST drop env scrubbing (matches CLI --no-sandbox semantics)"
        );
    }

    #[test]
    fn decide_runtime_cli_no_sandbox_wins_over_strict_resolved() {
        // CLI escape always trumps any persistent state. Even when
        // config says strict, `--no-sandbox` for this command means
        // both containment and env scrub drop.
        let (mode, scrub) = decide_runtime_sandbox_mode(true, false, ResolvedSandboxMode::Strict);
        assert_eq!(mode, SandboxMode::Disabled);
        assert!(!scrub);
    }

    #[test]
    fn decide_runtime_cli_no_sandbox_wins_over_default_resolved() {
        let (mode, scrub) = decide_runtime_sandbox_mode(true, false, ResolvedSandboxMode::Default);
        assert_eq!(mode, SandboxMode::Disabled);
        assert!(!scrub);
    }

    #[test]
    fn decide_runtime_cli_no_sandbox_with_config_none_is_idempotent() {
        // Belt and braces: if the user passes `--no-sandbox` on top
        // of a `mode = "none"` config (no-op but legal), the result
        // is unchanged. Tests that no_sandbox + None doesn't
        // accidentally double-flip anything.
        let (mode, scrub) = decide_runtime_sandbox_mode(true, false, ResolvedSandboxMode::None);
        assert_eq!(mode, SandboxMode::Disabled);
        assert!(!scrub);
    }

    #[test]
    fn decide_runtime_cli_sandbox_log_overrides_default_resolved() {
        // `--sandbox-log` is the macOS Seatbelt diagnostic flag.
        // When set on the CLI, even a `default` config gets LogOnly
        // for this run.
        let (mode, scrub) = decide_runtime_sandbox_mode(false, true, ResolvedSandboxMode::Default);
        assert_eq!(mode, SandboxMode::LogOnly);
        assert!(scrub, "LogOnly is sandbox-active, env scrub stays on");
    }

    #[test]
    fn decide_runtime_cli_sandbox_log_overrides_config_none() {
        // Edge case: user has `mode = "none"` in config but passes
        // `--sandbox-log` for one run. The CLI diagnostic intent
        // wins over the persistent off-mode — sandbox engages in
        // LogOnly so the user can observe what would have been
        // denied.
        let (mode, scrub) = decide_runtime_sandbox_mode(false, true, ResolvedSandboxMode::None);
        assert_eq!(
            mode,
            SandboxMode::LogOnly,
            "CLI --sandbox-log (diagnostic intent) overrides persistent mode = 'none'"
        );
        assert!(scrub);
    }

    #[test]
    fn decide_runtime_cli_no_sandbox_wins_over_sandbox_log() {
        // Clap-layer mutex forbids this pair, but defense-in-depth:
        // if both somehow arrive true, the hard escape wins. A
        // `Disabled` sandbox can't usefully LogOnly anything.
        let (mode, scrub) = decide_runtime_sandbox_mode(true, true, ResolvedSandboxMode::Default);
        assert_eq!(mode, SandboxMode::Disabled);
        assert!(!scrub);
    }
}
