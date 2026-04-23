//! Phase 46 P1 — `script-policy` config loader and [`ScriptPolicy`] enum.
//!
//! Consolidates the pre-existing ad-hoc script-related readers
//! ([`crate::commands::install::read_auto_build_config`] in install.rs
//! and the `read_deny_all_config` helper in build.rs) into a single
//! typed loader so Phase 46's new `scriptPolicy` key doesn't spawn a
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
//! ## String coercion policy (Phase 33 precedent)
//!
//! `lpm config set script-policy triage` writes the value as a string
//! under the hood (see [`crate::commands::config`]'s generic `set`
//! handler). The reader therefore accepts both native TOML strings and
//! the canonical kebab-case form. Invalid values produce a clear
//! error pointing at the offending source (file path or CLI flag) so
//! the user can fix it without reading code.

use crate::commands::config::GlobalConfig;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Which gate to apply to lifecycle scripts during `lpm build` /
/// autoBuild flows.
///
/// See [§5 of the Phase 46 plan](../DOCS/new-features/37-rust-client-RUNNER-VISION-phase46.md)
/// for the user-facing description of each mode.
///
/// Wire/config format is kebab-case: `"deny"` | `"allow"` | `"triage"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptPolicy {
    /// **Default.** Every lifecycle script is blocked at install time
    /// and requires explicit `lpm approve-scripts`. Equivalent to the
    /// pre-Phase-46 behavior.
    #[default]
    Deny,
    /// Every package trusted. `lpm build` runs every lifecycle script
    /// without the triage gate, via the existing two-phase pipeline.
    /// Scripts still execute at `lpm build` time (or autoBuild-
    /// triggered), never at install.
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
    /// **Invalid values**: when `scriptPolicy` is present as a string
    /// but doesn't parse (typo, wrong case, etc.), this field is
    /// `None` AND [`Self::policy_parse_error`] holds the offending
    /// input. Loader callers are expected to surface the error (via
    /// [`crate::output::warn`] in non-JSON mode) so a shared-repo
    /// typo doesn't silently produce per-developer policy divergence.
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
    /// The offending input when `scriptPolicy` was present as a string
    /// but failed to parse. `None` when `scriptPolicy` was absent,
    /// non-string, or parsed successfully. Callers surface this to the
    /// user; the field is not consumed by the precedence resolver (an
    /// unparseable value remains "unset" for precedence purposes,
    /// matching the `policy: None` path).
    ///
    /// Separated from `policy` so consumers who only care about the
    /// resolved value can ignore errors, while consumers responsible
    /// for user-facing output can surface them.
    pub policy_parse_error: Option<String>,
}

impl ScriptPolicyConfig {
    /// Read from `<project_dir>/package.json`. Missing file or
    /// unreadable content yields [`Self::default`] (all keys absent or
    /// at their defaults) — the install pipeline's own missing-manifest
    /// handling surfaces the real error earlier; here we must return
    /// something rather than panicking.
    pub fn from_package_json(project_dir: &Path) -> Self {
        let pkg_json_path = project_dir.join("package.json");
        let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
            return Self::default();
        };
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) else {
            return Self::default();
        };

        let lpm = parsed.get("lpm");
        let scripts = lpm.and_then(|l| l.get("scripts"));

        // Policy is the one key where "present but invalid" is
        // meaningfully different from "absent": a typo in a team-
        // shared package.json otherwise produces silent per-developer
        // divergence. Capture the offending input in
        // `policy_parse_error` so callers can warn.
        let raw_policy = lpm
            .and_then(|l| l.get("scriptPolicy"))
            .and_then(|v| v.as_str());
        let (policy, policy_parse_error) = match raw_policy {
            None => (None, None),
            Some(s) => match ScriptPolicy::parse(s) {
                Ok(p) => (Some(p), None),
                Err(e) => (None, Some(e.input)),
            },
        };

        let auto_build = scripts
            .and_then(|s| s.get("autoBuild"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let deny_all = scripts
            .and_then(|s| s.get("denyAll"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let trusted_scopes = scripts
            .and_then(|s| s.get("trustedScopes"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            policy,
            auto_build,
            deny_all,
            trusted_scopes,
            policy_parse_error,
        }
    }
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
/// **Phase 48 P0:** this function delegates to
/// [`crate::precedence::resolve_pure_policy`], which ships the unified
/// three-layer containment model. `scriptPolicy` is a pure-policy knob
/// of kind [`crate::precedence::PolicyKind::Legacy`] — Phase 46
/// project-over-user precedence is preserved by default, but the
/// resolver now also honors the `force-security-floor` user-global
/// kill-switch (`force-security-floor = true` in `~/.lpm/config.toml`).
/// When the flag is set, user becomes the floor, CLI loosening flags
/// are suppressed, and project-config loosening values are dropped.
/// See the precedence module for the canonical semantics.
///
/// `cli_override` is `Some(policy)` iff the user passed exactly one of
/// `--policy=<value>` / `--yolo` / `--triage` on this invocation. The
/// mutual-exclusion enforcement happens at the clap layer via
/// `conflicts_with_all`; this function trusts the single-value
/// guarantee.
///
/// `project_config` is a pre-loaded [`ScriptPolicyConfig`] (see
/// [`ScriptPolicyConfig::from_package_json`]). Taking the loaded
/// config rather than a path lets the caller inspect
/// [`ScriptPolicyConfig::policy_parse_error`] and surface the typo via
/// [`crate::output::warn`] before resolving — so a team-shared
/// typo in `package.json > lpm > scriptPolicy` doesn't silently
/// produce per-developer policy divergence.
///
/// # Dropped rejections
///
/// The pure-policy resolver returns a
/// [`crate::precedence::Resolution`] carrying both the effective value
/// and a list of [`crate::precedence::Rejection`]s for values that
/// were dropped along the way (CLI `--yolo` suppressed by the force
/// flag, project value rejected for loosening, etc.). This shim
/// silently drops the rejections because the slice that wires them
/// into stderr warnings lands separately — see phase48.md §7 P0
/// "Migration path" for the three distinct warning wordings. Until
/// that slice lands, the force-flag kill-switch still provides the
/// correct *behavior* (loosening values are dropped from the effective
/// value), just without the user-facing notice naming which source
/// got dropped.
pub fn resolve_script_policy(
    cli_override: Option<ScriptPolicy>,
    project_config: &ScriptPolicyConfig,
) -> ScriptPolicy {
    let global = GlobalConfig::load();
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
    .effective
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_pkg_json(dir: &Path, content: &str) {
        std::fs::write(dir.join("package.json"), content).unwrap();
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
    fn from_package_json_invalid_script_policy_surfaces_parse_error() {
        // v2.3 post-audit behavior change: a team-shared
        // `package.json` with a typo in `scriptPolicy` must NOT
        // silently fall through to per-developer global config.
        // `policy` stays `None` (precedence falls through), but
        // `policy_parse_error` carries the offending input so
        // install.rs / build.rs can warn the user via
        // `output::warn`.
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "invalid"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.policy, None);
        assert_eq!(
            cfg.policy_parse_error.as_deref(),
            Some("invalid"),
            "invalid scriptPolicy value must be captured for user warning"
        );
    }

    #[test]
    fn from_package_json_valid_script_policy_has_no_parse_error() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "triage"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.policy, Some(ScriptPolicy::Triage));
        assert_eq!(cfg.policy_parse_error, None);
    }

    #[test]
    fn from_package_json_absent_script_policy_has_no_parse_error() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.policy, None);
        assert_eq!(
            cfg.policy_parse_error, None,
            "absence must not look like a parse error"
        );
    }

    #[test]
    fn from_package_json_malformed_json_returns_defaults() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), "{not valid json");
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg, ScriptPolicyConfig::default());
    }

    #[test]
    fn from_package_json_empty_trusted_scopes_array_yields_empty_vec() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scripts": {"trustedScopes": []}}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert!(cfg.trusted_scopes.is_empty());
    }

    #[test]
    fn from_package_json_ignores_non_string_trusted_scopes() {
        // Defensive: if someone writes `["ok", 42, null, "fine"]`,
        // the non-strings are dropped rather than failing the whole load.
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"lpm": {"scripts": {"trustedScopes": ["@ok/*", 42, null, "@fine/*"]}}}"#,
        );
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(
            cfg.trusted_scopes,
            vec!["@ok/*".to_string(), "@fine/*".to_string()]
        );
    }

    // ── resolve_script_policy precedence ──────────────────────────

    #[test]
    fn resolve_cli_override_wins() {
        let dir = tempdir().unwrap();
        // Project says triage; CLI forces allow; CLI must win.
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "triage"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
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
    fn resolve_ignores_parse_error_uses_fallthrough() {
        // When package.json has an invalid `scriptPolicy`, the
        // resolver treats it as "unset" and falls through to global /
        // default. The error surfacing is a caller concern
        // (install.rs / build.rs emit `output::warn`). This test pins
        // the resolver contract: parse-error does NOT block
        // resolution, just prevents the value from winning.
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "junk"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert!(cfg.policy_parse_error.is_some());
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(dir.path().to_str().unwrap()),
        )]);
        let resolved = resolve_script_policy(None, &cfg);
        assert_eq!(
            resolved,
            ScriptPolicy::Deny,
            "parse-error scriptPolicy falls through to default",
        );
    }
}
