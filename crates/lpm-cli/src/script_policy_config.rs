//! — `script-policy` config loader and [`ScriptPolicy`] enum.
//!
//! Consolidates the pre-existing ad-hoc script-related readers
//! ([`crate::commands::install::read_auto_build_config`] in install.rs
//! and the `read_deny_all_config` helper in build.rs) into a single
//! typed loader so the new `scriptPolicy` key doesn't spawn a
//! third ad-hoc reader. Each call returns a [`ScriptPolicyConfig`]
//! with all four `package.json > lpm > scripts` keys and the
//! `scriptPolicy` key, parsed once.
//!
//! ## Precedence (highest wins)
//!
//! 1. CLI flag on the install / build command:
//!    `--policy=deny|allow|triage` (canonical) or
//!    `--yolo` (alias for `--policy=allow`) or
//!    `--triage` (alias for `--policy=triage`).
//!    Mutually-exclusive validation is enforced at the clap layer.
//! 2. `package.json > lpm > scriptPolicy` (per-project, team-shared).
//! 3. `~/.lpm/config.toml` key `script-policy` (per-user, this machine).
//! 4. Default: [`ScriptPolicy::Deny`].
//!
//! ## String coercion policy (precedent)
//!
//! `lpm config set script-policy triage` writes the value as a string
//! under the hood (see [`crate::commands::config`]'s generic `set`
//! handler). The reader therefore accepts both native TOML strings and
//! the canonical kebab-case form. Invalid values produce a clear
//! error pointing at the offending source (file path or CLI flag) so
//! the user can fix it without reading code.

use crate::commands::config::GlobalConfig;
use crate::precedence::PurePolicyKnob;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Which gate to apply to lifecycle scripts during `lpm rebuild` /
/// autoBuild flows.
///
/// See
/// for the user-facing description of each mode.
///
/// Wire/config format is kebab-case: `"deny"` | `"allow"` | `"triage"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptPolicy {
    /// **Default.** Every lifecycle script is blocked at install time
    /// and requires explicit `lpm approve-scripts`. Equivalent to the
    /// pre-existing behavior.
    #[default]
    Deny,
    /// Every package trusted. Install-time auto-build and `lpm rebuild`
    /// run lifecycle scripts without the triage gate.
    Allow,
    /// Four-layer tiered gate. Greens become eligible for auto-
    /// execution in the sandbox (P6); ambers flow to layers 2/3/4
    /// (trust manifest, provenance + cooldown, optional LLM triage);
    /// reds block unconditionally and never reach the LLM.
    Triage,
}

impl ScriptPolicy {
    /// Parse a kebab-case string. Accepts the exact wire forms
    /// (`deny` | `allow` | `triage`); anything else errors.
    pub fn parse(s: &str) -> Result<Self, ScriptPolicyParseError> {
        match s {
            "deny" => Ok(Self::Deny),
            "allow" => Ok(Self::Allow),
            "triage" => Ok(Self::Triage),
            other => Err(ScriptPolicyParseError {
                input: other.to_string(),
            }),
        }
    }

    /// Canonical kebab-case string form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Triage => "triage",
        }
    }
}

/// Error from [`ScriptPolicy::parse`].
///
/// Carries the offending input so the caller can include it in a
/// source-specific message (`"in package.json: got 'foo'"` vs.
/// `"in --policy flag: got 'foo'"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptPolicyParseError {
    pub input: String,
}

impl std::fmt::Display for ScriptPolicyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid script-policy value '{}' (expected one of: deny, allow, triage)",
            self.input,
        )
    }
}

impl std::error::Error for ScriptPolicyParseError {}

/// Consolidated read of `package.json > lpm > {scriptPolicy, scripts}`.
///
/// Single source of truth for install.rs, build.rs, and any future
/// consumer. Replaces the previous two separate ad-hoc readers
/// (`read_auto_build_config`, `read_deny_all_config`) — each of those
/// callers migrates to this struct's accessors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptPolicyConfig {
    /// `package.json > lpm > scriptPolicy`, if explicitly set AND
    /// parsed successfully. `None` means "fall through to
    /// `~/.lpm/config.toml` then default". A deliberate `"deny"`
    /// value parses to `Some(ScriptPolicy::Deny)` so users can lock
    /// the default against a teammate's global override.
    ///
    pub policy: Option<ScriptPolicy>,
    /// `package.json > lpm > scripts.autoBuild`. Defaults to `false`.
    pub auto_build: bool,
    /// `package.json > lpm > scripts.denyAll`. Kill-switch: when
    /// `true`, scripts never run regardless of `policy`. Defaults to
    /// `false`.
    pub deny_all: bool,
    /// `package.json > lpm > scripts.trustedScopes`. Glob patterns
    /// like `@myorg/*` that auto-approve by scope. Defaults to empty.
    pub trusted_scopes: Vec<String>,
    /// `package.json > lpm > triageAdvisor`,
    /// if set. The string is stored verbatim (not parsed into a
    /// `Provider` here) so the resolver layer can normalise + warn
    /// once on unknown slugs at the install-time call site rather
    /// than every read. `None` means "fall through to
    /// `~/.lpm/config.toml` then default `none`."
    pub triage_advisor: Option<String>,
}

impl ScriptPolicyConfig {
    #[cfg(test)]
    pub fn from_package_json(project_dir: &Path) -> Self {
        Self::try_from_package_json(project_dir).expect("valid test script configuration")
    }

    /// Read project script policy while preserving configuration I/O failures.
    pub fn try_from_package_json(project_dir: &Path) -> Result<Self, lpm_common::LpmError> {
        let pkg_json_path = project_dir.join("package.json");
        let content = match lpm_common::read_text_file_capped(
            &pkg_json_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let parsed =
            serde_json::from_str::<serde_json::Value>(lpm_common::strip_utf8_bom_str(&content))
                .map_err(|error| {
                    lpm_common::LpmError::Script(format!("{}: {error}", pkg_json_path.display()))
                })?;
        Self::from_package_json_value(&parsed)
    }

    pub(crate) fn from_package_json_value(
        parsed: &serde_json::Value,
    ) -> Result<Self, lpm_common::LpmError> {
        let Some(lpm) = parsed.get("lpm") else {
            return Ok(Self::default());
        };
        let lpm = lpm.as_object().ok_or_else(|| {
            lpm_common::LpmError::Script("package.json > lpm must be an object".into())
        })?;
        let policy = script_config_field::<ScriptPolicy>(lpm, "scriptPolicy", "lpm")?;
        let scripts = lpm
            .get("scripts")
            .map(|value| {
                value.as_object().ok_or_else(|| {
                    lpm_common::LpmError::Script(
                        "package.json > lpm > scripts must be an object".into(),
                    )
                })
            })
            .transpose()?;
        let mut config = Self {
            policy,
            triage_advisor: script_config_field(lpm, "triageAdvisor", "lpm")?,
            ..Self::default()
        };
        if let Some(scripts) = scripts {
            config.auto_build =
                script_config_field(scripts, "autoBuild", "lpm > scripts")?.unwrap_or(false);
            config.deny_all =
                script_config_field(scripts, "denyAll", "lpm > scripts")?.unwrap_or(false);
            config.trusted_scopes =
                script_config_field(scripts, "trustedScopes", "lpm > scripts")?.unwrap_or_default();
        }
        Ok(config)
    }
}

fn script_config_field<T: serde::de::DeserializeOwned>(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    parent: &str,
) -> Result<Option<T>, lpm_common::LpmError> {
    object
        .get(key)
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                lpm_common::LpmError::Script(format!("package.json > {parent} > {key}: {error}"))
            })
        })
        .transpose()
}

/// Collapse the three clap-layer flags (`--policy=<val>`, `--yolo`,
/// `--triage`) into a single `Option<ScriptPolicy>` for the precedence
/// chain.
///
/// Clap enforces mutual exclusion via `conflicts_with_all` on each
/// flag, so at most one is set per invocation. This helper therefore
/// trusts the single-value invariant and only validates the value of
/// the canonical `--policy` flag (where a bad string can still reach
/// us, e.g. `--policy=yolo`).
///
/// Returns `Ok(None)` when none of the three flags is set (the caller
/// falls through to project / global / default). Returns
/// `Err(String)` when `--policy`'s value is not a known variant, with
/// a user-facing message that names both the offending input and the
/// accepted values.
pub fn collapse_policy_flags(
    policy: Option<&str>,
    yolo: bool,
    triage_alias: bool,
) -> Result<Option<ScriptPolicy>, String> {
    // Clap's `conflicts_with_all` guarantees at most one is set. Honor
    // the aliases first (they're booleans — no parse step needed).
    if yolo {
        return Ok(Some(ScriptPolicy::Allow));
    }
    if triage_alias {
        return Ok(Some(ScriptPolicy::Triage));
    }
    match policy {
        None => Ok(None),
        Some(s) => ScriptPolicy::parse(s)
            .map(Some)
            .map_err(|e| format!("--policy: {e}")),
    }
}

/// Resolve the effective [`ScriptPolicy`] through the full precedence
/// chain.
///
/// this function delegates to
/// [`crate::precedence::resolve_pure_policy`], which ships the unified
/// three-layer containment model. `scriptPolicy` is a pure-policy knob
/// of kind [`crate::precedence::PolicyKind::Legacy`] — /// project-over-user precedence is preserved by default, but the
/// resolver now also honors the `force-security-floor` user-global
/// kill-switch (`force-security-floor = true` in `~/.lpm/config.toml`).
/// When the flag is set, user becomes the floor, CLI loosening flags
/// are suppressed, and project-config loosening values are dropped.
/// See the precedence module for the canonical semantics.
///
/// Any dropped candidates produce
/// [`crate::precedence::Rejection`]s that this shim routes to
/// [`crate::migration_warnings::emit_rejections`] — the boundary where
/// pure resolver output becomes user-facing stderr notices. See the
/// migration_warnings module for the three distinct wordings
/// (one per [`crate::precedence::RejectionReason`] variant).
///
/// `cli_override` is `Some(policy)` iff the user passed exactly one of
/// `--policy=<value>` / `--yolo` / `--triage` on this invocation. The
/// mutual-exclusion enforcement happens at the clap layer via
/// `conflicts_with_all`; this function trusts the single-value
/// guarantee.
///
/// `project_config` is a pre-loaded [`ScriptPolicyConfig`] (see
/// [`ScriptPolicyConfig::try_from_package_json`]). Taking the loaded
/// config rather than a path avoids reading the manifest again during resolution.
pub fn resolve_script_policy(
    cli_override: Option<ScriptPolicy>,
    project_config: &ScriptPolicyConfig,
) -> ScriptPolicy {
    let resolution = resolve_script_policy_raw(cli_override, project_config);
    crate::migration_warnings::emit_rejections(&resolution);
    resolution.effective
}

/// JSON/reporting-aware shim for command paths that need the same
/// effective policy plus a structured suppression trace.
#[allow(dead_code)]
pub fn resolve_script_policy_with_reporting(
    cli_override: Option<ScriptPolicy>,
    project_config: &ScriptPolicyConfig,
) -> ScriptPolicy {
    let resolution = resolve_script_policy_raw(cli_override, project_config);
    crate::migration_warnings::emit_rejections(&resolution);
    record_force_floor_rejections(&resolution);
    resolution.effective
}

pub(crate) fn approval_scope_for_policy(
    policy: ScriptPolicy,
) -> crate::security_approval::ApprovalScope {
    match policy {
        ScriptPolicy::Deny => crate::security_approval::ApprovalScope::ScriptsTriage,
        ScriptPolicy::Triage => crate::security_approval::ApprovalScope::ScriptsTriage,
        ScriptPolicy::Allow => crate::security_approval::ApprovalScope::ScriptsAllow,
    }
}

/// Security-aware variant that treats raw config values as proposals
/// unless they are covered by the approved machine posture or an
/// active project unlock.
pub fn resolve_script_policy_with_security(
    project_dir: &Path,
    cli_override: Option<ScriptPolicy>,
    project_config: &ScriptPolicyConfig,
    json_output: bool,
) -> Result<ScriptPolicy, lpm_common::LpmError> {
    resolve_script_policy_with_security_for_packages(
        project_dir,
        cli_override,
        project_config,
        json_output,
        &[],
    )
}

pub(crate) fn resolve_script_policy_with_security_for_packages(
    project_dir: &Path,
    cli_override: Option<ScriptPolicy>,
    project_config: &ScriptPolicyConfig,
    json_output: bool,
    packages: &[String],
) -> Result<ScriptPolicy, lpm_common::LpmError> {
    let global = GlobalConfig::load_checked()?;
    let user = global
        .get_str("script-policy")
        .and_then(|s| ScriptPolicy::parse(s).ok());
    let authorized = crate::security_approval::load_effective_authorized_posture()?.posture;
    let authorized_floor = authorized.script_policy();

    if let Some(requested) = cli_override
        && requested.loosens(authorized_floor)
    {
        crate::security_approval::ensure_project_unlock(
            approval_scope_for_policy(requested),
            project_dir,
            json_output,
            crate::security_approval::ApprovalSource::CliFlag,
            &format!(
                "This command requests `script-policy = {}` for this project.",
                requested.as_str()
            ),
            None,
            packages,
        )?;
    } else if cli_override.is_none()
        && let Some(requested) = project_config.policy
        && requested.loosens(authorized_floor)
    {
        crate::security_approval::ensure_project_unlock(
            approval_scope_for_policy(requested),
            project_dir,
            json_output,
            crate::security_approval::ApprovalSource::ProjectConfig,
            "package.json requests a weaker script-policy than this machine has approved.",
            None,
            &[],
        )?;
    }

    if cli_override.is_none()
        && project_config.policy.is_none()
        && let Some(user_policy) = user
        && user_policy.loosens(authorized_floor)
    {
        return Err(crate::security_approval::approval_required_error(
            "the persisted global script-policy value is weaker than this machine has approved",
            vec![approval_scope_for_policy(user_policy).as_str().to_string()],
            None,
            Some(format!("lpm config scripts --set {}", user_policy.as_str())),
        ));
    }

    let override_authorized = if let Some(requested) = cli_override {
        requested.loosens(authorized_floor)
    } else if let Some(requested) = project_config.policy {
        requested.loosens(authorized_floor)
    } else {
        false
    };
    let force_security_floor =
        global.get_bool("force-security-floor").unwrap_or(false) && !override_authorized;
    let resolution = crate::precedence::resolve_pure_policy(crate::precedence::PolicyInputs {
        cli: cli_override,
        project: project_config.policy,
        user,
        default: ScriptPolicy::default(),
        force_security_floor,
    });
    crate::migration_warnings::emit_rejections(&resolution);
    record_force_floor_rejections(&resolution);
    Ok(resolution.effective)
}

/// Pure variant of [`resolve_script_policy`] that returns the full
/// [`crate::precedence::Resolution`] without emitting stderr
/// warnings.
///
/// Use this when you need to inspect the rejection list directly
/// (tests, or call sites that want custom warning routing). The
/// [`resolve_script_policy`] shim above is a thin wrapper that
/// extracts `.effective` after emitting warnings via
/// [`crate::migration_warnings::emit_rejections`].
///
/// This function does NOT touch stderr. It DOES read
/// `~/.lpm/config.toml` via [`GlobalConfig::load`]; tests that
/// want isolation from the host's global config should inject a
/// synthetic resolution through [`crate::precedence::resolve_pure_policy`]
/// directly rather than calling this shim.
pub fn resolve_script_policy_raw(
    cli_override: Option<ScriptPolicy>,
    project_config: &ScriptPolicyConfig,
) -> crate::precedence::Resolution<ScriptPolicy> {
    let global = GlobalConfig::load();
    resolve_script_policy_raw_with_global(cli_override, project_config, &global)
}

pub(crate) fn resolve_script_policy_raw_with_global(
    cli_override: Option<ScriptPolicy>,
    project_config: &ScriptPolicyConfig,
    global: &GlobalConfig,
) -> crate::precedence::Resolution<ScriptPolicy> {
    let user = global
        .get_str("script-policy")
        .and_then(|s| ScriptPolicy::parse(s).ok());
    let force_security_floor = global.get_bool("force-security-floor").unwrap_or(false);
    crate::precedence::resolve_pure_policy(crate::precedence::PolicyInputs {
        cli: cli_override,
        project: project_config.policy,
        user,
        default: ScriptPolicy::default(),
        force_security_floor,
    })
}

fn record_force_floor_rejections(resolution: &crate::precedence::Resolution<ScriptPolicy>) {
    for rejection in &resolution.rejections {
        let source = match rejection.source {
            crate::precedence::PolicyTier::Cli => crate::security_floor::SuppressionSource::Cli,
            crate::precedence::PolicyTier::Project => {
                crate::security_floor::SuppressionSource::Project
            }
            crate::precedence::PolicyTier::User | crate::precedence::PolicyTier::Default => {
                continue;
            }
        };
        match rejection.reason {
            crate::precedence::RejectionReason::ForceFlagSuppressesCli
            | crate::precedence::RejectionReason::ForceFlagRejectsProject => {
                crate::security_floor::record_suppression(
                    crate::security_floor::SuppressionRecord::new(
                        crate::security_floor::GuardedControl::ScriptPolicy,
                        source,
                        rejection.rejected_value.as_str(),
                        resolution.effective.as_str(),
                    ),
                    true,
                );
            }
            crate::precedence::RejectionReason::NewKnobProjectLoosens => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_pkg_json(dir: &Path, content: &str) {
        std::fs::write(dir.join("package.json"), content).unwrap();
    }

    fn scoped_home_with_security(dir: &Path) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::set([
            ("HOME", std::ffi::OsString::from(dir.to_str().unwrap())),
            (
                "LPM_SECURITY_DIR",
                dir.join("security").as_os_str().to_owned(),
            ),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                std::ffi::OsString::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
            ),
        ])
    }

    // ── ScriptPolicy parsing ──────────────────────────────────────

    #[test]
    fn parse_accepts_canonical_kebab_forms() {
        assert_eq!(ScriptPolicy::parse("deny").unwrap(), ScriptPolicy::Deny);
        assert_eq!(ScriptPolicy::parse("allow").unwrap(), ScriptPolicy::Allow);
        assert_eq!(ScriptPolicy::parse("triage").unwrap(), ScriptPolicy::Triage,);
    }

    #[test]
    fn parse_rejects_unknown_variants() {
        assert!(ScriptPolicy::parse("yolo").is_err());
        assert!(ScriptPolicy::parse("safe").is_err());
        assert!(ScriptPolicy::parse("").is_err());
        assert!(ScriptPolicy::parse("DENY").is_err(), "case-sensitive");
    }

    #[test]
    fn as_str_roundtrips_through_parse() {
        for p in [
            ScriptPolicy::Deny,
            ScriptPolicy::Allow,
            ScriptPolicy::Triage,
        ] {
            assert_eq!(ScriptPolicy::parse(p.as_str()).unwrap(), p);
        }
    }

    #[test]
    fn default_is_deny() {
        assert_eq!(ScriptPolicy::default(), ScriptPolicy::Deny);
    }

    // ── ScriptPolicyConfig loader ─────────────────────────────────

    #[test]
    fn from_package_json_missing_file_returns_defaults() {
        let dir = tempdir().unwrap();
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg, ScriptPolicyConfig::default());
        assert_eq!(cfg.policy, None);
        assert!(!cfg.auto_build);
        assert!(!cfg.deny_all);
        assert!(cfg.trusted_scopes.is_empty());
    }

    #[test]
    fn from_package_json_empty_lpm_block_returns_defaults() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"name":"test","lpm":{}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg, ScriptPolicyConfig::default());
    }

    #[test]
    fn from_package_json_reads_all_four_keys() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            r#"{
                "name": "test",
                "lpm": {
                    "scriptPolicy": "triage",
                    "scripts": {
                        "autoBuild": true,
                        "denyAll": false,
                        "trustedScopes": ["@myorg/*", "@internal/*"]
                    }
                }
            }"#,
        );
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.policy, Some(ScriptPolicy::Triage));
        assert!(cfg.auto_build);
        assert!(!cfg.deny_all);
        assert_eq!(
            cfg.trusted_scopes,
            vec!["@myorg/*".to_string(), "@internal/*".to_string()]
        );
    }

    #[test]
    fn from_package_json_script_policy_deny_is_explicit_not_none() {
        // A user who writes `"scriptPolicy": "deny"` explicitly is
        // locking the default against a teammate's global override.
        // Distinguishing `Some(Deny)` from `None` is load-bearing.
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "deny"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(
            cfg.policy,
            Some(ScriptPolicy::Deny),
            "explicit deny must not be indistinguishable from unset"
        );
    }

    #[test]
    fn from_package_json_invalid_script_policy_fails() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "invalid"}}"#);
        let error = ScriptPolicyConfig::try_from_package_json(dir.path()).unwrap_err();
        assert!(error.to_string().contains("scriptPolicy"));
    }

    #[test]
    fn from_package_json_absent_script_policy_is_none() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {}}"#);
        assert_eq!(
            ScriptPolicyConfig::from_package_json(dir.path()).policy,
            None
        );
    }

    #[test]
    fn from_package_json_malformed_json_fails() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), "{not valid json");
        assert!(ScriptPolicyConfig::try_from_package_json(dir.path()).is_err());
    }

    #[test]
    fn from_package_json_empty_trusted_scopes_array_yields_empty_vec() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scripts": {"trustedScopes": []}}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert!(cfg.trusted_scopes.is_empty());
    }

    #[test]
    fn from_package_json_rejects_non_string_trusted_scopes() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"lpm":{"scripts":{"trustedScopes":["@ok/*",42,null]}}}"#,
        );
        let error = ScriptPolicyConfig::try_from_package_json(dir.path()).unwrap_err();
        assert!(error.to_string().contains("trustedScopes"));
    }

    // ── triage_advisor reader ──────────────────────────────
    //
    // The reader stores the value verbatim; resolution + slug
    // validation happens later at the install-time call site
    // (`triage_advisor_session::AdvisorSession::preflight`). These
    // tests pin the read contract: correct key spelling, absence
    // vs presence distinguishable, type-safety on non-strings.

    #[test]
    fn from_package_json_reads_triage_advisor_string() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"triageAdvisor": "claude-cli"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.triage_advisor.as_deref(), Some("claude-cli"));
    }

    #[test]
    fn from_package_json_triage_advisor_absent_is_none() {
        // No `triageAdvisor` key → `None` so the resolver falls
        // through to `~/.lpm/config.toml` then default. Distinct
        // from `Some("none")` which is an explicit per-project
        // opt-out (the resolver short-circuits on it).
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.triage_advisor, None);
    }

    #[test]
    fn from_package_json_explicit_none_preserved_as_string() {
        // `"triageAdvisor": "none"` is an explicit project-level
        // opt-out the resolver must respect (it short-circuits in
        // preflight rather than falling through to global config).
        // Reader's job: round-trip the literal string; semantics
        // belong to the resolver.
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"triageAdvisor": "none"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.triage_advisor.as_deref(), Some("none"));
    }

    #[test]
    fn from_package_json_non_string_triage_advisor_fails() {
        for value in [
            serde_json::json!(["none"]),
            serde_json::json!(42),
            serde_json::json!(true),
            serde_json::Value::Null,
            serde_json::json!({"provider":"none"}),
        ] {
            let dir = tempdir().unwrap();
            write_pkg_json(
                dir.path(),
                &serde_json::json!({"lpm":{"triageAdvisor":value}}).to_string(),
            );
            let error = ScriptPolicyConfig::try_from_package_json(dir.path()).unwrap_err();
            assert!(error.to_string().contains("triageAdvisor"));
        }
    }

    #[test]
    fn from_package_json_triage_advisor_does_not_clobber_other_keys() {
        // Single-pass reader: a populated `triageAdvisor` must NOT
        // affect adjacent keys' parsing (scriptPolicy, autoBuild,
        // trustedScopes). Catches an accidental mutually-exclusive
        // branch if the parser ever moves to a match-tree shape.
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            r#"{
                "lpm": {
                    "scriptPolicy": "triage",
                    "triageAdvisor": "ollama",
                    "scripts": {
                        "autoBuild": true,
                        "trustedScopes": ["@me/*"]
                    }
                }
            }"#,
        );
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.policy, Some(ScriptPolicy::Triage));
        assert_eq!(cfg.triage_advisor.as_deref(), Some("ollama"));
        assert!(cfg.auto_build);
        assert_eq!(cfg.trusted_scopes, vec!["@me/*".to_string()]);
    }

    // ── resolve_script_policy precedence ──────────────────────────

    #[test]
    fn resolve_cli_override_wins() {
        let dir = tempdir().unwrap();
        // Project says triage; CLI forces allow; CLI must win.
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "triage"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(dir.path().to_str().unwrap()),
        )]);
        let resolved = resolve_script_policy(Some(ScriptPolicy::Allow), &cfg);
        assert_eq!(resolved, ScriptPolicy::Allow);
    }

    #[test]
    fn resolve_project_wins_over_global() {
        // Setting `HOME` to a temp dir isolates the global-config read;
        // without a global config there, the project-level value must
        // win on its own.
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "triage"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        // Clear HOME so GlobalConfig::load finds nothing.
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(dir.path().to_str().unwrap()),
        )]);
        let resolved = resolve_script_policy(None, &cfg);
        assert_eq!(resolved, ScriptPolicy::Triage);
    }

    #[test]
    fn resolve_default_when_nothing_set() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        // Isolate HOME so any developer's real ~/.lpm/config.toml
        // doesn't leak into this test.
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(dir.path().to_str().unwrap()),
        )]);
        let resolved = resolve_script_policy(None, &cfg);
        assert_eq!(resolved, ScriptPolicy::Deny);
    }

    #[test]
    fn resolve_with_security_rejects_unapproved_project_allow() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "allow"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        let _env = scoped_home_with_security(dir.path());

        let err = resolve_script_policy_with_security(dir.path(), None, &cfg, true).unwrap_err();
        assert_eq!(err.error_code(), "security_approval_required");
        assert!(err.to_string().contains("security approval required"));
    }

    #[test]
    fn resolve_with_security_allows_project_allow_when_authorized() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "allow"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        let _env = scoped_home_with_security(dir.path());
        let posture = crate::security_approval::AuthorizedPosture {
            script_policy: "allow".to_string(),
            ..crate::security_approval::AuthorizedPosture::default()
        };
        crate::security_approval::persist_authorized_posture(&posture).unwrap();

        let resolved = resolve_script_policy_with_security(dir.path(), None, &cfg, true).unwrap();
        assert_eq!(resolved, ScriptPolicy::Allow);
    }
}
