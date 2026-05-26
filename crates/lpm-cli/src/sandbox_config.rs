//! sandbox-config loader.
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

/// Read the sandbox knobs from `<project_dir>/lpm.toml`
/// + `~/.lpm/config.toml` and resolve them to a [`SandboxOptions`].
///
/// Missing files / missing keys fall through to defaults.
///
/// Returns `Err(LpmError::Registry)` only if a file exists but is
/// malformed (invalid TOML, non-bool `allow-degraded` value,
/// unknown `mode` string). The error names the offending file
/// path so the user sees which side needs editing.
///
/// rework this loader reports the
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

/// resolve the FULL precedence chain into a
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
    json_output: bool,
) -> Result<(SandboxOptions, ResolvedSandboxMode), LpmError> {
    let project_path = project_dir.join("lpm.toml");
    let mut project = read_sandbox_keys_from_file(&project_path)?;

    let global_path = dirs::home_dir().map(|h| h.join(".lpm").join("config.toml"));
    let global = match global_path {
        Some(ref p) => read_sandbox_keys_from_file(p)?,
        None => RawSandboxKeys::default(),
    };

    let force_security_floor = crate::security_floor::force_security_floor_enabled(
        &crate::commands::config::GlobalConfig::load(),
    );
    let mut effective_no_sandbox_flag = no_sandbox_flag;
    if force_security_floor {
        let floor_mode = global.mode.unwrap_or(SandboxModeKey::Default);
        let floor_allow_degraded = global.allow_degraded.unwrap_or(false);

        if effective_no_sandbox_flag && !matches!(floor_mode, SandboxModeKey::None) {
            crate::security_floor::record_suppression(
                crate::security_floor::SuppressionRecord::new(
                    crate::security_floor::GuardedControl::SandboxMode,
                    crate::security_floor::SuppressionSource::Cli,
                    "none",
                    sandbox_mode_key_name(floor_mode),
                ),
                json_output,
            );
            effective_no_sandbox_flag = false;
        }

        if let Some(mode) = project.mode
            && mode.loosens(floor_mode)
        {
            crate::security_floor::record_suppression(
                crate::security_floor::SuppressionRecord::new(
                    crate::security_floor::GuardedControl::SandboxMode,
                    crate::security_floor::SuppressionSource::Project,
                    sandbox_mode_key_name(mode),
                    sandbox_mode_key_name(floor_mode),
                ),
                json_output,
            );
            project.mode = None;
        }

        if project.allow_degraded == Some(true) && !floor_allow_degraded {
            crate::security_floor::record_suppression(
                crate::security_floor::SuppressionRecord::new(
                    crate::security_floor::GuardedControl::SandboxAllowDegraded,
                    crate::security_floor::SuppressionSource::Project,
                    "true",
                    "false",
                ),
                json_output,
            );
            project.allow_degraded = None;
        }
    }

    if effective_no_sandbox_flag {
        // `--no-sandbox` always wins. No env/config consultation —
        // the user explicitly said "no sandbox for this command."
        return Ok((SandboxOptions::default(), ResolvedSandboxMode::None));
    }
    if strict_sandbox_flag {
        let (options, _) = merge(project.clone(), global.clone());
        return Ok((
            SandboxOptions {
                deny_outbound_network: true,
                ..options
            },
            ResolvedSandboxMode::Strict,
        ));
    }
    if env_strict_sandbox_set() {
        let (options, _) = merge(project.clone(), global.clone());
        return Ok((
            SandboxOptions {
                deny_outbound_network: true,
                ..options
            },
            ResolvedSandboxMode::Strict,
        ));
    }
    Ok(merge(project, global))
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
    /// `[sandbox] mode = "default" | "strict" |
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

    fn loosens(self, floor: Self) -> bool {
        self.rank() < floor.rank()
    }

    fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Default => 1,
            Self::Strict => 2,
        }
    }
}

fn sandbox_mode_key_name(mode: SandboxModeKey) -> &'static str {
    match mode {
        SandboxModeKey::Default => "default",
        SandboxModeKey::Strict => "strict",
        SandboxModeKey::None => "none",
    }
}

/// Read the sandbox keys from a single TOML file. Missing
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

    // The surface lives under `[sandbox]`. A bare
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

        // `[sandbox] mode = "default" | "strict"
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
/// emits `(SandboxOptions, ResolvedSandboxMode)`
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

/// the user-facing sandbox mode resolved from the
/// precedence chain. The CLI surface speaks this enum; the
/// constructor accepts the `(SandboxMode, SandboxOptions)` pair.
///
/// - `Default` → `SandboxMode::Enforce` + `deny_outbound_network = false`.
/// - `Strict`  → `SandboxMode::Enforce` + `deny_outbound_network = true`.
/// - `None`    → `SandboxMode::Disabled` (caller short-circuits to
///   `NoopSandbox` and skips env scrubbing too — rework
///   collapsed `--unsafe-full-env` into `--no-sandbox` of
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

    pub(crate) fn as_str(&self) -> &'static str {
        self.name()
    }

    pub(crate) fn parse_for_security_floor(raw: &str) -> Option<Self> {
        match raw {
            "default" => Some(Self::Default),
            "strict" => Some(Self::Strict),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub(crate) fn loosens(self, floor: Self) -> bool {
        self.rank() < floor.rank()
    }

    fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Default => 1,
            Self::Strict => 2,
        }
    }
}

/// rework runtime collapse: turn the resolved sandbox
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
///    partner was collapsed.
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
        //
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

/// The per-install stderr banner that announces strict mode is in
/// effect, or `None` when no banner is needed. Returned as a static
/// string so the install pipeline only has the decision to make,
/// not the prose to template.
///
/// caught that the previous version only
/// fired this banner when `--strict-sandbox` / `--paranoid` arrived
/// on the CLI — config-set (`[sandbox] mode = "strict"`) and env-set
/// (`LPM_STRICT_SANDBOX=1`) users got the kernel-level network
/// denial silently. The DX-doc walkthroughs / / all show
/// the same banner regardless of source, so the gating must be on
/// the resolved mode, not on which tier supplied it.
///
/// follow-up (same day, second pass): the banner must
/// ALSO gate on the final [`SandboxMode`], not just the resolved
/// tier. `--sandbox-log` (macOS Seatbelt diagnostic) wins over
/// resolved Strict in [`decide_runtime_sandbox_mode`] and produces
/// [`SandboxMode::LogOnly`] — observed-but-not-enforced. Emitting
/// "outbound network will be denied" alongside the existing
/// "logged but NOT enforced" sandbox-log banner is a lie about
/// the runtime contract. Under LogOnly the rules are loaded but
/// not enforced, so the strict banner must suppress itself.
/// Similarly under [`SandboxMode::Disabled`] — containment is off,
/// so claiming any enforcement is wrong (the disabled-sandbox
/// banner at the env-scrub site already covers that case).
///
/// Wording is intentionally neutral (no `--strict-sandbox` prefix)
/// because the banner runs the same for config / env / CLI sources;
/// claiming a source the install can't actually attribute would be
/// the inverse of the first bug GPT-5 caught. The provenance
/// ("which tier set strict") belongs on `lpm doctor`, which DOES
/// have the resolver result available and a stable surface for it.
pub fn strict_banner_for_runtime(
    sandbox_mode: SandboxMode,
    resolved: ResolvedSandboxMode,
) -> Option<&'static str> {
    // Truthfulness gate: only announce "will be denied" when the
    // runtime is actually going to enforce. LogOnly / Disabled
    // produce contradictory UX without this.
    if !matches!(sandbox_mode, SandboxMode::Enforce) {
        return None;
    }
    match resolved {
        ResolvedSandboxMode::Strict => Some(
            "strict-sandbox: outbound network will be denied for every lifecycle script in \
             this run (filesystem + env containment also active).",
        ),
        ResolvedSandboxMode::Default | ResolvedSandboxMode::None => None,
    }
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

    struct ScopedHomeDir {
        dir: TempDir,
        _env: crate::test_env::ScopedEnv,
    }

    impl ScopedHomeDir {
        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    fn fixture(lpm_toml_body: Option<&str>) -> Env {
        let tmp = tempfile::tempdir().expect("tempdir");
        let project = tmp.path().to_path_buf();
        if let Some(body) = lpm_toml_body {
            fs::write(project.join("lpm.toml"), body).expect("write lpm.toml");
        }
        Env { _tmp: tmp, project }
    }

    fn scoped_home_dir() -> ScopedHomeDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = crate::test_env::ScopedEnv::set([("HOME", dir.path().as_os_str().to_owned())]);
        ScopedHomeDir { dir, _env: env }
    }

    fn write_global_config(home: &Path, body: &str) {
        let path = home.join(".lpm").join("config.toml");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create .lpm");
        }
        fs::write(path, body).expect("write config.toml");
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
        // when neither tier sets a value, the
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

    // ── decide_runtime_sandbox_mode  ──
    //
    // caught a real bug: the previous version
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
        // The bug `[sandbox] mode = "none"` from
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

    // ── strict_banner_for_runtime (follow-up) ──
    //
    // caught two related bugs here, both fixed by gating
    // on the (final SandboxMode, resolved tier) pair:
    //
    // Round 1 (Low): the banner only fired for `--strict-sandbox` /
    // `--paranoid` on the CLI. Config-set / env-set strict was
    // silent, contradicting DX-doc walkthroughs / /.
    //
    // Round 2 (Medium): once the banner fired for all resolved-Strict
    // sources, it ALSO fired when `--sandbox-log` was passed together
    // with strict — but `decide_runtime_sandbox_mode` collapses to
    // [`SandboxMode::LogOnly`] in that case, so the resulting UX was
    // contradictory ("network will be denied" immediately followed
    // by "logged but NOT enforced"). The clap layer doesn't reject
    // `--strict-sandbox --sandbox-log` (and can't reject the
    // env/config tier strict + CLI `--sandbox-log` combinations at
    // all). The decision-layer gate must catch it.
    //
    // These tests pin the corrected contract.

    #[test]
    fn strict_banner_fires_for_enforce_plus_resolved_strict() {
        // The 90% strict-mode case: backend will Enforce + resolved
        // is Strict. Banner announces outbound network will be
        // denied, regardless of which tier supplied Strict.
        let banner = strict_banner_for_runtime(SandboxMode::Enforce, ResolvedSandboxMode::Strict);
        let line = banner.expect(
            "strict mode under Enforce MUST emit a runtime banner — DX-doc walkthroughs / / \
             all require it regardless of source. This was the GPT-5 audit Low finding (round 1).",
        );
        assert!(
            line.contains("outbound network"),
            "banner must name what strict actually does — outbound network denial. got: {line}",
        );
        assert!(
            line.contains("strict-sandbox"),
            "banner must label itself as the strict-sandbox notice so users can grep for it. \
             got: {line}",
        );
        // Pre-fix regression pin: the banner used to start with
        // `--strict-sandbox:` (double-dash CLI-flag prefix), which
        // claimed a source the install pipeline can no longer
        // attribute correctly under env/config-tier strict.
        assert!(
            !line.starts_with("--"),
            "banner must NOT prefix `--` — that would falsely claim CLI-flag source when \
             strict can also come from `[sandbox] mode = \"strict\"` or `LPM_STRICT_SANDBOX=1`. \
             got: {line}",
        );
    }

    #[test]
    fn strict_banner_does_not_fire_under_default_or_none_resolved() {
        // Symmetric: no banner when there's nothing to announce.
        // Default is the relaxed posture (no network denial); None
        // is fully off and gets its own different banner up at the
        // env-scrub site.
        assert!(
            strict_banner_for_runtime(SandboxMode::Enforce, ResolvedSandboxMode::Default).is_none(),
            "no banner under the default posture — there's no behaviour change to announce",
        );
        assert!(
            strict_banner_for_runtime(SandboxMode::Enforce, ResolvedSandboxMode::None).is_none(),
            "no strict banner under `mode = \"none\"` — the disabled-sandbox banner at the \
             env-scrub site already covers it",
        );
    }

    #[test]
    fn strict_banner_suppressed_under_logonly_runtime_even_when_resolved_strict() {
        // round 2 (Medium): the failure mode.
        //
        // `lpm rebuild --strict-sandbox --sandbox-log` (or env/config
        // strict + CLI `--sandbox-log`) collapses to LogOnly in
        // `decide_runtime_sandbox_mode` — the user wants to OBSERVE,
        // not enforce. Under LogOnly the rules are loaded but rule
        // triggers are reported, not blocked — so "outbound network
        // will be denied" is a lie.
        //
        // The existing `--sandbox-log: diagnostic mode only. Rule
        // triggers are logged but NOT enforced…` banner downstream
        // is the right surface for this run; the strict banner must
        // suppress itself.
        let banner = strict_banner_for_runtime(SandboxMode::LogOnly, ResolvedSandboxMode::Strict);
        assert!(
            banner.is_none(),
            "strict banner MUST suppress itself under LogOnly — saying `outbound network \
             will be denied` while the next line says `logged but NOT enforced` is \
             contradictory UX. GPT-5 audit round 2 finding. got: {banner:?}",
        );
    }

    #[test]
    fn strict_banner_suppressed_under_disabled_runtime() {
        // Defense-in-depth: SandboxMode::Disabled means containment
        // is off entirely. Even if the resolved tier somehow holds
        // Strict (it can't via the resolver — `no_sandbox=true`
        // returns `(SandboxOptions::default(), None)` — but a future
        // refactor could break that invariant), the banner must
        // suppress itself because enforcement isn't happening.
        // Under the current chain the disabled-sandbox banner at the
        // env-scrub site already covers the user-visible message.
        for resolved in [
            ResolvedSandboxMode::Strict,
            ResolvedSandboxMode::Default,
            ResolvedSandboxMode::None,
        ] {
            assert!(
                strict_banner_for_runtime(SandboxMode::Disabled, resolved).is_none(),
                "no strict banner under Disabled regardless of resolved tier (resolved={resolved:?})",
            );
        }
    }

    #[test]
    fn strict_banner_logonly_default_and_none_also_suppressed() {
        // Symmetric: LogOnly with non-strict resolved doesn't fire
        // the banner either. Pinned so a future refactor that
        // changes the gate order doesn't accidentally widen the
        // banner.
        assert!(
            strict_banner_for_runtime(SandboxMode::LogOnly, ResolvedSandboxMode::Default).is_none(),
        );
        assert!(
            strict_banner_for_runtime(SandboxMode::LogOnly, ResolvedSandboxMode::None).is_none(),
        );
    }

    #[test]
    fn resolve_sandbox_mode_force_floor_suppresses_cli_no_sandbox() {
        let env = fixture(None);
        let home = scoped_home_dir();
        write_global_config(
            home.path(),
            "force-security-floor = true\n[sandbox]\nmode = \"strict\"\n",
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();

        let (_, resolved) =
            resolve_sandbox_mode_from_chain(&env.project, true, false, true).unwrap();

        assert_eq!(resolved, ResolvedSandboxMode::Strict);
        let suppressions = crate::security_floor::recorded_suppressions();
        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].control,
            crate::security_floor::GuardedControl::SandboxMode
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();
    }

    #[test]
    fn resolve_sandbox_mode_force_floor_suppresses_looser_project_mode() {
        let env = fixture(Some(
            r#"
[sandbox]
mode = "none"
"#,
        ));
        let home = scoped_home_dir();
        write_global_config(
            home.path(),
            "force-security-floor = true\n[sandbox]\nmode = \"strict\"\n",
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();

        let (_, resolved) =
            resolve_sandbox_mode_from_chain(&env.project, false, false, true).unwrap();

        assert_eq!(resolved, ResolvedSandboxMode::Strict);
        let suppressions = crate::security_floor::recorded_suppressions();
        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].source,
            crate::security_floor::SuppressionSource::Project
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();
    }
}
