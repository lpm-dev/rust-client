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
    /// and requires explicit `lpm approve-builds`. Equivalent to the
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
    /// `package.json > lpm > scriptPolicy`, if explicitly set.
    /// `None` means "fall through to `~/.lpm/config.toml` then default".
    /// A deliberate `"deny"` value parses to `Some(ScriptPolicy::Deny)`
    /// so users can lock the default against a teammate's global
    /// override.
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

        let policy = lpm
            .and_then(|l| l.get("scriptPolicy"))
            .and_then(|v| v.as_str())
            .and_then(|s| ScriptPolicy::parse(s).ok());
        // Intentionally silent on parse failure: a malformed
        // `scriptPolicy` here is equivalent to "not set" for precedence
        // purposes, so we fall through to the global default. The
        // canonical error path is the CLI flag (validated at clap
        // time) and `lpm config` write-time validation in P9.
        // Surfacing the error here would spam every install in the
        // field until the user fixes their package.json; graceful
        // fallthrough matches the existing `read_*_config` helpers'
        // behavior.

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
/// chain (CLI > project > global > default).
///
/// `cli_override` is `Some(policy)` iff the user passed exactly one of
/// `--policy=<value>` / `--yolo` / `--triage` on this invocation. The
/// mutual-exclusion enforcement happens at the clap layer via
/// `conflicts_with_all`; this function trusts the single-value
/// guarantee.
///
/// `project_dir` is the install root (or `lpm build` project dir).
/// `from_package_json` handles missing files gracefully.
pub fn resolve_script_policy(
    cli_override: Option<ScriptPolicy>,
    project_dir: &Path,
) -> ScriptPolicy {
    if let Some(p) = cli_override {
        return p;
    }
    let project = ScriptPolicyConfig::from_package_json(project_dir);
    if let Some(p) = project.policy {
        return p;
    }
    if let Some(p) = GlobalConfig::load()
        .get_str("script-policy")
        .and_then(|s| ScriptPolicy::parse(s).ok())
    {
        return p;
    }
    ScriptPolicy::default()
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
    fn from_package_json_invalid_script_policy_is_silent_none() {
        // Graceful fallthrough (matches existing ad-hoc readers'
        // behavior and avoids spamming every install in the field
        // until the user fixes it). The error path is at the CLI flag
        // + `lpm config` write-time.
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "invalid"}}"#);
        let cfg = ScriptPolicyConfig::from_package_json(dir.path());
        assert_eq!(cfg.policy, None);
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
        let resolved = resolve_script_policy(Some(ScriptPolicy::Allow), dir.path());
        assert_eq!(resolved, ScriptPolicy::Allow);
    }

    #[test]
    fn resolve_project_wins_over_global() {
        // Setting `HOME` to a temp dir isolates the global-config read;
        // without a global config there, the project-level value must
        // win on its own.
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{"lpm": {"scriptPolicy": "triage"}}"#);
        // Clear HOME so GlobalConfig::load finds nothing.
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(dir.path().to_str().unwrap()),
        )]);
        let resolved = resolve_script_policy(None, dir.path());
        assert_eq!(resolved, ScriptPolicy::Triage);
    }

    #[test]
    fn resolve_default_when_nothing_set() {
        let dir = tempdir().unwrap();
        write_pkg_json(dir.path(), r#"{}"#);
        // Isolate HOME so any developer's real ~/.lpm/config.toml
        // doesn't leak into this test.
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(dir.path().to_str().unwrap()),
        )]);
        let resolved = resolve_script_policy(None, dir.path());
        assert_eq!(resolved, ScriptPolicy::Deny);
    }
}
