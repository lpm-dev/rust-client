//! Save-spec decision logic for `lpm install` (Phase 33).
//!
//! When `lpm install <pkg>` mutates `package.json`, this module decides what
//! string lands in the manifest. The decision is a pure function of:
//!
//! - **What the user typed.** `lpm install zod` is treated very differently
//!   from `lpm install zod@4.3.6` or `lpm install zod@^4.3.0`. See
//!   [`UserSaveIntent`].
//! - **The resolved version.** The full install pipeline resolves the spec
//!   against the registry and lockfile; we feed the resolved
//!   [`lpm_semver::Version`] back into the helper after resolution so the
//!   `^resolvedVersion` default has a real number to work with. This is
//!   load-bearing for Phase 33's "no `*` default" rule.
//! - **CLI flags.** `--exact`, `--tilde`, and `--save-prefix` override the
//!   default for the current invocation. See [`SaveFlags`].
//! - **User config.** `save-prefix` and `save-exact` from
//!   `~/.lpm/config.toml` (or `./lpm.toml` for project-level overrides) seed
//!   the defaults for bare installs. See [`SaveConfig`].
//!
//! ## Precedence (highest wins)
//!
//! 1. **Explicit user spec** in the `pkg@spec` argument
//!    ([`UserSaveIntent::Exact`], [`UserSaveIntent::Range`],
//!    [`UserSaveIntent::Wildcard`], [`UserSaveIntent::Workspace`]) — preserved
//!    verbatim, never reinterpreted.
//! 2. **CLI flag override** (`--exact`, `--tilde`, `--save-prefix`).
//! 3. **Prerelease-exact safety.** If the resolved version is a prerelease
//!    and no CLI flag forced something else, save the exact resolved version.
//!    Phase 33's "Prerelease Policy" — prereleases should not auto-widen
//!    under a forgotten `save-prefix` config setting.
//! 4. **Config.** `save-exact = true`, then `save-prefix = "^|~|"`.
//! 5. **Default.** `^resolvedVersion`.
//!
//! See `DOCS/new-features/37-rust-client-RUNNER-VISION-phase33.md` for the
//! full policy table and rationale.

use lpm_common::LpmError;
use lpm_semver::{Version, VersionReq};

// ─── Public API ─────────────────────────────────────────────────────

/// What the user typed when they ran `lpm install <spec>`.
///
/// Distinguishes "user provided no version, pick a sensible default" (`Bare`)
/// from "user provided an explicit version or range, preserve it" (every
/// other variant).
///
/// Constructed by [`parse_user_save_intent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserSaveIntent {
    /// `lpm install zod` — no version token at all. Save policy decides.
    Bare,
    /// `lpm install zod@4.3.6` — concrete version. Preserved verbatim.
    Exact(String),
    /// `lpm install zod@^4.3.0`, `~4.3.6`, `>=1.2`, `1.x`, etc.
    /// Any non-exact, non-wildcard, non-workspace range. Preserved verbatim.
    Range(String),
    /// `lpm install zod@latest` / `@beta` / `@next` — a dist-tag, not a
    /// version. The save spec is decided by the resolved version's stability
    /// (stable → caret default, prerelease → exact).
    DistTag(String),
    /// `lpm install zod@*` — explicit wildcard. Preserved as `*`.
    /// Phase 33: `*` is **only** allowed when the user asked for it.
    Wildcard,
    /// `workspace:*`, `workspace:^`, `workspace:~`, or `workspace:<range>`.
    /// Always preserved verbatim. Phase 33 does not change workspace
    /// protocol semantics.
    Workspace(String),
}

/// Per-command CLI flag overrides for the save policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct SaveFlags {
    /// `--exact`: write the exact resolved version with no prefix.
    pub exact: bool,
    /// `--tilde`: write `~resolvedVersion`.
    pub tilde: bool,
    /// `--save-prefix '<p>'`: write `<p>resolvedVersion`. Mutually exclusive
    /// with `--exact` and `--tilde`; clap enforces this at parse time.
    pub save_prefix: Option<SavePrefix>,
}

impl SaveFlags {
    /// Whether any of the per-command flags is set. Used by the stage step
    /// to decide whether to rewrite an existing dep entry: bare reinstalls
    /// (no flags) leave existing entries alone, but explicit flag overrides
    /// always force a rewrite per the Phase 33 "do rewrite when" rule.
    pub fn forces_rewrite(&self) -> bool {
        self.exact || self.tilde || self.save_prefix.is_some()
    }
}

/// Persistent save-policy config (loaded from `~/.lpm/config.toml` and/or
/// `./lpm.toml`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SaveConfig {
    pub save_prefix: Option<SavePrefix>,
    pub save_exact: bool,
}

/// The valid save prefixes — never `*`. `Empty` means "exact, no prefix".
//
// Phase 33: variants are constructed by `SavePrefix::parse` (called by the
// CLI flag parser in Step 5 and the config loader in Step 6). Until those
// steps land, the helper is exercised only by tests, so the dead-code lint
// flags the variants as unused. Safe to remove the allow once `--save-prefix`
// is wired through clap.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavePrefix {
    Caret,
    Tilde,
    Empty,
}

impl SavePrefix {
    /// Parse from a config / CLI string. Accepts `^`, `~`, and `""` only.
    /// Rejects `*` — wildcards are an explicit-per-package opt-in, not a
    /// default save policy.
    #[allow(dead_code)] // Wired in Step 5 (CLI flag) + Step 6 (config loader).
    pub fn parse(s: &str) -> Result<Self, LpmError> {
        match s {
			"^" => Ok(SavePrefix::Caret),
			"~" => Ok(SavePrefix::Tilde),
			"" => Ok(SavePrefix::Empty),
			"*" => Err(LpmError::Registry(
				"save-prefix '*' is not allowed: wildcards must be requested per-package via `pkg@*`".into(),
			)),
			other => Err(LpmError::Registry(format!(
				"invalid save-prefix '{other}': expected '^', '~', or empty"
			))),
		}
    }

    fn render(self, resolved: &Version) -> String {
        match self {
            SavePrefix::Caret => format!("^{resolved}"),
            SavePrefix::Tilde => format!("~{resolved}"),
            SavePrefix::Empty => resolved.to_string(),
        }
    }
}

/// Why a particular spec was chosen. Used for debug logging and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveSpecReason {
    /// User typed an exact version, preserved verbatim.
    PreservedUserExact,
    /// User typed a range, preserved verbatim.
    PreservedUserRange,
    /// User typed `@*`, preserved verbatim.
    PreservedUserWildcard,
    /// `workspace:*` etc — preserved verbatim, never reinterpreted.
    PreservedWorkspace,
    /// Bare or dist-tag, resolved to a stable version, default `^resolved`.
    DefaultCaret,
    /// Bare or dist-tag resolved to a prerelease — saved exact for safety.
    PrereleaseExactSafety,
    /// `--exact` flag.
    FlagExact,
    /// `--tilde` flag.
    FlagTilde,
    /// `--save-prefix` flag.
    FlagSavePrefix,
    /// `save-exact = true` from config.
    ConfigSaveExact,
    /// `save-prefix` from config.
    ConfigSavePrefix,
}

/// The result of [`decide_saved_dependency_spec`].
//
// `reason` is used by tests and is intended for `--verbose` install output
// (Step 9 docs/UX). Until that lands the production callers in install.rs
// only consume `spec_to_write`, so dead-code flags `reason` as unread.
#[derive(Debug, Clone)]
pub struct SaveSpecDecision {
    pub spec_to_write: String,
    #[allow(dead_code)]
    pub reason: SaveSpecReason,
}

/// Parse a CLI install spec into `(name, intent)`.
///
/// Recognises:
/// - `zod` → `("zod", Bare)`
/// - `zod@4.3.6` → `("zod", Exact("4.3.6"))`
/// - `zod@^4.3.0` → `("zod", Range("^4.3.0"))`
/// - `zod@~4.3.6` → `("zod", Range("~4.3.6"))`
/// - `zod@1.x` → `("zod", Range("1.x"))`
/// - `zod@latest` → `("zod", DistTag("latest"))`
/// - `zod@*` → `("zod", Wildcard)`
/// - `@scope/name` → `("@scope/name", Bare)`
/// - `@scope/name@1.2.3` → `("@scope/name", Exact("1.2.3"))`
/// - `@scope/name@workspace:*` → `("@scope/name", Workspace("workspace:*"))`
///
/// Classification rule for the version token:
/// 1. `*` → [`UserSaveIntent::Wildcard`]
/// 2. `workspace:...` → [`UserSaveIntent::Workspace`]
/// 3. Parses as [`Version`] → [`UserSaveIntent::Exact`]
/// 4. Parses as [`lpm_semver::VersionReq`] → [`UserSaveIntent::Range`]
/// 5. Otherwise → [`UserSaveIntent::DistTag`] (npm allows arbitrary tag names)
pub fn parse_user_save_intent(spec: &str) -> (String, UserSaveIntent) {
    let (name, version_token) = split_name_and_version_token(spec);
    let intent = match version_token {
        None => UserSaveIntent::Bare,
        Some(token) => classify_version_token(token),
    };
    (name, intent)
}

/// Split a CLI install argument into `(name, Some(version_token))` or
/// `(name, None)` for the bare case.
///
/// Handles scoped packages (`@scope/name[@token]`) and unscoped
/// (`name[@token]`). For scoped packages the leading `@` is part of the
/// name, so the version separator is the *second* `@`.
fn split_name_and_version_token(spec: &str) -> (String, Option<&str>) {
    if let Some(rest) = spec.strip_prefix('@') {
        // Scoped: the first `@` is the scope marker; find the next `@` (if any)
        // for the version separator.
        match rest.find('@') {
            Some(at_pos) => {
                let split = at_pos + 1; // adjust back for the stripped '@'
                (spec[..split].to_string(), Some(&spec[split + 1..]))
            }
            None => (spec.to_string(), None),
        }
    } else {
        match spec.find('@') {
            Some(at_pos) => (spec[..at_pos].to_string(), Some(&spec[at_pos + 1..])),
            None => (spec.to_string(), None),
        }
    }
}

/// Classify a non-empty version token (the part after `@`) into a
/// `UserSaveIntent` variant.
///
/// The order matters: workspace + wildcard short-circuit, then exact-version
/// parse, then range parse, with dist-tag as the fallback for anything that
/// doesn't parse as semver. This mirrors npm's CLI semantics — `latest`,
/// `next`, `beta`, etc. are tags, never versions.
fn classify_version_token(token: &str) -> UserSaveIntent {
    // Empty token after `@` (e.g. `zod@`) — treat as bare. This is a
    // degenerate user input but a valid one to recover from.
    if token.is_empty() {
        return UserSaveIntent::Bare;
    }
    if token == "*" {
        return UserSaveIntent::Wildcard;
    }
    if token.starts_with("workspace:") {
        return UserSaveIntent::Workspace(token.to_string());
    }
    if Version::parse(token).is_ok() {
        return UserSaveIntent::Exact(token.to_string());
    }
    if VersionReq::parse(token).is_ok() {
        return UserSaveIntent::Range(token.to_string());
    }
    UserSaveIntent::DistTag(token.to_string())
}

/// Compute the spec to write into `package.json` for a single dependency.
///
/// `intent` is what the user typed; `resolved` is what the resolver picked.
/// The full precedence chain (and why prerelease-exact safety sits between
/// flags and config) is documented in the module-level comment.
pub fn decide_saved_dependency_spec(
    intent: &UserSaveIntent,
    resolved: &Version,
    flags: SaveFlags,
    config: SaveConfig,
) -> Result<SaveSpecDecision, LpmError> {
    // ── Tier 1: explicit user input wins everything. ─────────────
    // Wildcard, Workspace, Exact, and Range are all things the user
    // concretely typed at the command line; per Phase 33's "preserve
    // explicit user intent" rule we never reinterpret them, regardless
    // of flags or config.
    match intent {
        UserSaveIntent::Wildcard => {
            return Ok(SaveSpecDecision {
                spec_to_write: "*".to_string(),
                reason: SaveSpecReason::PreservedUserWildcard,
            });
        }
        UserSaveIntent::Workspace(s) => {
            return Ok(SaveSpecDecision {
                spec_to_write: s.clone(),
                reason: SaveSpecReason::PreservedWorkspace,
            });
        }
        UserSaveIntent::Exact(s) => {
            return Ok(SaveSpecDecision {
                spec_to_write: s.clone(),
                reason: SaveSpecReason::PreservedUserExact,
            });
        }
        UserSaveIntent::Range(s) => {
            return Ok(SaveSpecDecision {
                spec_to_write: s.clone(),
                reason: SaveSpecReason::PreservedUserRange,
            });
        }
        UserSaveIntent::Bare | UserSaveIntent::DistTag(_) => {
            // Fall through to the policy chain.
        }
    }

    // ── Tier 2: per-command CLI flags. ───────────────────────────
    // `--exact`, `--tilde`, `--save-prefix` are explicit per-invocation
    // opt-ins. They beat both safety defaults (prerelease) and config,
    // because the user just typed them — they unambiguously want this
    // behavior right now.
    if flags.exact {
        return Ok(SaveSpecDecision {
            spec_to_write: resolved.to_string(),
            reason: SaveSpecReason::FlagExact,
        });
    }
    if flags.tilde {
        return Ok(SaveSpecDecision {
            spec_to_write: format!("~{resolved}"),
            reason: SaveSpecReason::FlagTilde,
        });
    }
    if let Some(prefix) = flags.save_prefix {
        return Ok(SaveSpecDecision {
            spec_to_write: prefix.render(resolved),
            reason: SaveSpecReason::FlagSavePrefix,
        });
    }

    // ── Tier 3: prerelease-exact safety. ─────────────────────────
    // Prereleases are inherently less stable; saving `^4.4.0-beta.2`
    // invites surprise upgrades across unstable releases. Phase 33's
    // "Prerelease Policy" makes this exact-by-default. Sits ABOVE
    // config so a forgotten `save-prefix = "^"` does not silently
    // widen prereleases.
    if resolved.is_prerelease() {
        return Ok(SaveSpecDecision {
            spec_to_write: resolved.to_string(),
            reason: SaveSpecReason::PrereleaseExactSafety,
        });
    }

    // ── Tier 4: persistent user config. ──────────────────────────
    // `save-exact = true` wins over `save-prefix` per the Phase 33
    // "Config interaction rule".
    if config.save_exact {
        return Ok(SaveSpecDecision {
            spec_to_write: resolved.to_string(),
            reason: SaveSpecReason::ConfigSaveExact,
        });
    }
    if let Some(prefix) = config.save_prefix {
        return Ok(SaveSpecDecision {
            spec_to_write: prefix.render(resolved),
            reason: SaveSpecReason::ConfigSavePrefix,
        });
    }

    // ── Tier 5: built-in default. ────────────────────────────────
    // `^resolvedVersion` — Phase 33's load-bearing change. Replaces
    // the legacy `*` default.
    Ok(SaveSpecDecision {
        spec_to_write: format!("^{resolved}"),
        reason: SaveSpecReason::DefaultCaret,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|e| panic!("test fixture: bad version {s}: {e}"))
    }

    // ─── parse_user_save_intent ─────────────────────────────────

    #[test]
    fn parse_unscoped_bare() {
        let (name, intent) = parse_user_save_intent("zod");
        assert_eq!(name, "zod");
        assert_eq!(intent, UserSaveIntent::Bare);
    }

    #[test]
    fn parse_unscoped_exact() {
        let (name, intent) = parse_user_save_intent("zod@4.3.6");
        assert_eq!(name, "zod");
        assert_eq!(intent, UserSaveIntent::Exact("4.3.6".into()));
    }

    #[test]
    fn parse_unscoped_caret_range() {
        let (name, intent) = parse_user_save_intent("zod@^4.3.0");
        assert_eq!(name, "zod");
        assert_eq!(intent, UserSaveIntent::Range("^4.3.0".into()));
    }

    #[test]
    fn parse_unscoped_tilde_range() {
        let (name, intent) = parse_user_save_intent("zod@~4.3.6");
        assert_eq!(name, "zod");
        assert_eq!(intent, UserSaveIntent::Range("~4.3.6".into()));
    }

    #[test]
    fn parse_unscoped_x_range() {
        let (name, intent) = parse_user_save_intent("zod@1.x");
        assert_eq!(name, "zod");
        assert_eq!(intent, UserSaveIntent::Range("1.x".into()));
    }

    #[test]
    fn parse_unscoped_dist_tag_latest() {
        let (name, intent) = parse_user_save_intent("zod@latest");
        assert_eq!(name, "zod");
        assert_eq!(intent, UserSaveIntent::DistTag("latest".into()));
    }

    #[test]
    fn parse_unscoped_dist_tag_beta() {
        let (name, intent) = parse_user_save_intent("react@beta");
        assert_eq!(name, "react");
        assert_eq!(intent, UserSaveIntent::DistTag("beta".into()));
    }

    #[test]
    fn parse_unscoped_explicit_wildcard() {
        let (name, intent) = parse_user_save_intent("zod@*");
        assert_eq!(name, "zod");
        assert_eq!(intent, UserSaveIntent::Wildcard);
    }

    #[test]
    fn parse_scoped_bare() {
        let (name, intent) = parse_user_save_intent("@lpm.dev/owner.pkg");
        assert_eq!(name, "@lpm.dev/owner.pkg");
        assert_eq!(intent, UserSaveIntent::Bare);
    }

    #[test]
    fn parse_scoped_exact() {
        let (name, intent) = parse_user_save_intent("@lpm.dev/owner.pkg@1.2.3");
        assert_eq!(name, "@lpm.dev/owner.pkg");
        assert_eq!(intent, UserSaveIntent::Exact("1.2.3".into()));
    }

    #[test]
    fn parse_scoped_caret_range() {
        let (name, intent) = parse_user_save_intent("@scope/foo@^1.0.0");
        assert_eq!(name, "@scope/foo");
        assert_eq!(intent, UserSaveIntent::Range("^1.0.0".into()));
    }

    #[test]
    fn parse_scoped_workspace_star() {
        let (name, intent) = parse_user_save_intent("@scope/foo@workspace:*");
        assert_eq!(name, "@scope/foo");
        assert_eq!(intent, UserSaveIntent::Workspace("workspace:*".into()));
    }

    #[test]
    fn parse_scoped_workspace_caret() {
        let (name, intent) = parse_user_save_intent("@scope/foo@workspace:^");
        assert_eq!(name, "@scope/foo");
        assert_eq!(intent, UserSaveIntent::Workspace("workspace:^".into()));
    }

    #[test]
    fn parse_unscoped_workspace_exact_range() {
        let (name, intent) = parse_user_save_intent("foo@workspace:1.2.3");
        assert_eq!(name, "foo");
        assert_eq!(intent, UserSaveIntent::Workspace("workspace:1.2.3".into()));
    }

    // ─── decide_saved_dependency_spec — matrix rows 1-11, 13 ────

    /// Row 1: bare install of a stable version → caret default.
    #[test]
    fn row1_bare_stable_default_caret() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("4.3.6"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "^4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::DefaultCaret);
    }

    /// Row 2: explicit exact version → preserved verbatim.
    #[test]
    fn row2_exact_user_input_preserved() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Exact("4.3.6".into()),
            &v("4.3.6"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::PreservedUserExact);
    }

    /// Row 3: explicit caret range → preserved (NOT normalized to ^4.3.6).
    #[test]
    fn row3_caret_range_preserved_not_normalized() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Range("^4.3.0".into()),
            &v("4.3.6"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(
            decision.spec_to_write, "^4.3.0",
            "explicit ^4.3.0 must NOT be rewritten to ^4.3.6"
        );
        assert_eq!(decision.reason, SaveSpecReason::PreservedUserRange);
    }

    /// Row 4: explicit tilde range → preserved (NOT normalized to ^).
    #[test]
    fn row4_tilde_range_preserved() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Range("~4.3.6".into()),
            &v("4.3.6"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "~4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::PreservedUserRange);
    }

    /// Row 5: dist-tag `@latest` → resolved is stable → caret default.
    #[test]
    fn row5_dist_tag_latest_stable_caret_default() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::DistTag("latest".into()),
            &v("4.3.6"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "^4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::DefaultCaret);
    }

    /// Row 6a: bare install resolving to a prerelease → exact (safety).
    #[test]
    fn row6_bare_prerelease_resolves_exact() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("19.0.0-rc.1"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "19.0.0-rc.1");
        assert_eq!(decision.reason, SaveSpecReason::PrereleaseExactSafety);
    }

    /// Row 6b: dist-tag `@beta` resolves to a prerelease → exact.
    #[test]
    fn row6_dist_tag_beta_prerelease_exact() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::DistTag("beta".into()),
            &v("4.4.0-beta.2"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "4.4.0-beta.2");
        assert_eq!(decision.reason, SaveSpecReason::PrereleaseExactSafety);
    }

    /// Row 7: `--exact` flag on a bare install → exact resolved.
    #[test]
    fn row7_flag_exact_bare() {
        let flags = SaveFlags {
            exact: true,
            ..Default::default()
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("4.3.6"),
            flags,
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::FlagExact);
    }

    /// Row 8: `--tilde` flag on a bare install → tilde resolved.
    #[test]
    fn row8_flag_tilde_bare() {
        let flags = SaveFlags {
            tilde: true,
            ..Default::default()
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("4.3.6"),
            flags,
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "~4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::FlagTilde);
    }

    /// Row 9: config `save-prefix='^'` is honored on bare installs.
    /// (Tilde here distinguishes config-driven from default-driven, since
    /// the default also produces caret.)
    #[test]
    fn row9_config_save_prefix_tilde_honored_on_bare() {
        let config = SaveConfig {
            save_prefix: Some(SavePrefix::Tilde),
            save_exact: false,
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("4.3.6"),
            SaveFlags::default(),
            config,
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "~4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::ConfigSavePrefix);
    }

    /// Row 10: config `save-exact=true` overrides the default caret.
    #[test]
    fn row10_config_save_exact_overrides_default() {
        let config = SaveConfig {
            save_prefix: None,
            save_exact: true,
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("4.3.6"),
            SaveFlags::default(),
            config,
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::ConfigSaveExact);
    }

    /// Row 11: explicit user spec beats config and flags.
    /// `lpm install zod@^4.3.0 --exact` with `save-exact=true` config →
    /// still saves `^4.3.0` because the explicit user spec wins everything.
    #[test]
    fn row11_explicit_spec_beats_flags_and_config() {
        let flags = SaveFlags {
            exact: true,
            ..Default::default()
        };
        let config = SaveConfig {
            save_prefix: Some(SavePrefix::Caret),
            save_exact: true,
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Range("^4.3.0".into()),
            &v("4.3.6"),
            flags,
            config,
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "^4.3.0");
        assert_eq!(decision.reason, SaveSpecReason::PreservedUserRange);
    }

    /// Row 13: `0.x` bare install still gets a caret prefix.
    /// Phase 33 explicitly does NOT diverge from the npm/pnpm convention here.
    #[test]
    fn row13_zerox_bare_caret() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("0.12.29"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "^0.12.29");
        assert_eq!(decision.reason, SaveSpecReason::DefaultCaret);
    }

    // ─── Precedence tests ───────────────────────────────────────

    /// `--exact` flag beats `--save-prefix` config (CLI > config).
    #[test]
    fn flag_exact_beats_config_save_prefix() {
        let flags = SaveFlags {
            exact: true,
            ..Default::default()
        };
        let config = SaveConfig {
            save_prefix: Some(SavePrefix::Caret),
            save_exact: false,
        };
        let decision =
            decide_saved_dependency_spec(&UserSaveIntent::Bare, &v("4.3.6"), flags, config)
                .unwrap();
        assert_eq!(decision.spec_to_write, "4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::FlagExact);
    }

    /// `--tilde` flag beats `save-exact=true` config.
    #[test]
    fn flag_tilde_beats_config_save_exact() {
        let flags = SaveFlags {
            tilde: true,
            ..Default::default()
        };
        let config = SaveConfig {
            save_prefix: None,
            save_exact: true,
        };
        let decision =
            decide_saved_dependency_spec(&UserSaveIntent::Bare, &v("4.3.6"), flags, config)
                .unwrap();
        assert_eq!(decision.spec_to_write, "~4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::FlagTilde);
    }

    /// `--save-prefix '~'` flag works for bare installs.
    #[test]
    fn flag_save_prefix_tilde_bare() {
        let flags = SaveFlags {
            save_prefix: Some(SavePrefix::Tilde),
            ..Default::default()
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("4.3.6"),
            flags,
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "~4.3.6");
        assert_eq!(decision.reason, SaveSpecReason::FlagSavePrefix);
    }

    /// Prerelease-exact safety sits ABOVE config: a forgotten
    /// `save-prefix = "^"` config must NOT auto-widen a prerelease.
    #[test]
    fn prerelease_exact_safety_overrides_config_save_prefix() {
        let config = SaveConfig {
            save_prefix: Some(SavePrefix::Caret),
            save_exact: false,
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("19.0.0-rc.1"),
            SaveFlags::default(),
            config,
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "19.0.0-rc.1");
        assert_eq!(decision.reason, SaveSpecReason::PrereleaseExactSafety);
    }

    /// Explicit `--tilde` flag wins over the prerelease-exact default,
    /// because per-command flags are higher precedence than safety defaults.
    /// The user explicitly opted in to widening for THIS install.
    #[test]
    fn flag_tilde_overrides_prerelease_exact_safety() {
        let flags = SaveFlags {
            tilde: true,
            ..Default::default()
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Bare,
            &v("19.0.0-rc.1"),
            flags,
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "~19.0.0-rc.1");
        assert_eq!(decision.reason, SaveSpecReason::FlagTilde);
    }

    // ─── Wildcard + workspace short-circuits ────────────────────

    /// Explicit `@*` is preserved verbatim regardless of resolved/flags/config.
    #[test]
    fn explicit_wildcard_preserved_verbatim() {
        let flags = SaveFlags {
            exact: true,
            ..Default::default()
        };
        let config = SaveConfig {
            save_prefix: Some(SavePrefix::Caret),
            save_exact: true,
        };
        let decision =
            decide_saved_dependency_spec(&UserSaveIntent::Wildcard, &v("4.3.6"), flags, config)
                .unwrap();
        assert_eq!(decision.spec_to_write, "*");
        assert_eq!(decision.reason, SaveSpecReason::PreservedUserWildcard);
    }

    /// Workspace protocol is preserved verbatim, regardless of everything.
    #[test]
    fn workspace_protocol_preserved_verbatim() {
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Workspace("workspace:^".into()),
            &v("1.5.0"),
            SaveFlags::default(),
            SaveConfig::default(),
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "workspace:^");
        assert_eq!(decision.reason, SaveSpecReason::PreservedWorkspace);
    }

    /// Even with `--exact` and config overrides, workspace deps are preserved.
    #[test]
    fn workspace_protocol_ignores_flags_and_config() {
        let flags = SaveFlags {
            exact: true,
            ..Default::default()
        };
        let config = SaveConfig {
            save_prefix: Some(SavePrefix::Caret),
            save_exact: true,
        };
        let decision = decide_saved_dependency_spec(
            &UserSaveIntent::Workspace("workspace:*".into()),
            &v("1.5.0"),
            flags,
            config,
        )
        .unwrap();
        assert_eq!(decision.spec_to_write, "workspace:*");
        assert_eq!(decision.reason, SaveSpecReason::PreservedWorkspace);
    }

    // ─── SavePrefix::parse ──────────────────────────────────────

    #[test]
    fn save_prefix_parse_caret() {
        assert_eq!(SavePrefix::parse("^").unwrap(), SavePrefix::Caret);
    }

    #[test]
    fn save_prefix_parse_tilde() {
        assert_eq!(SavePrefix::parse("~").unwrap(), SavePrefix::Tilde);
    }

    #[test]
    fn save_prefix_parse_empty() {
        assert_eq!(SavePrefix::parse("").unwrap(), SavePrefix::Empty);
    }

    #[test]
    fn save_prefix_parse_rejects_wildcard() {
        let err = SavePrefix::parse("*").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not allowed") || msg.contains("'*'"),
            "expected wildcard rejection message, got: {msg}"
        );
    }

    #[test]
    fn save_prefix_parse_rejects_other_garbage() {
        assert!(SavePrefix::parse(">=").is_err());
        assert!(SavePrefix::parse("foo").is_err());
    }
}
