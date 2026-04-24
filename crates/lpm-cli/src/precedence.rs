//! Generic precedence resolver for Phase 48 containment knobs.
//!
//! Implements the three-layer containment model from
//! [Phase 48 §6](../../../../../../a-package-manager/DOCS/new-features/37-rust-client-RUNNER-VISION-phase48.md).
//! The resolver is the single source of truth for "given these inputs,
//! what's the effective policy, and what got rejected along the way."
//!
//! # Scope for Phase 48 P0
//!
//! This module ships the **pure-policy** side of the three-layer model
//! first — the `resolve_pure_policy` function below handles
//! `scriptPolicy` (legacy), `network-policy` (new), and
//! `install-policy.strict-behavioral` (new) precedence. Per-package
//! capability knobs (`passEnv`, `sandboxLimits`, `readProject`) land
//! in a sibling resolver in subsequent P0 commits — their shape is
//! similar but the approval-tuple binding is a distinct concern.
//!
//! # Pure-policy rule (phase48.md §6 "Pure-policy knobs — single semantic")
//!
//! A project value that matches the user floor or tightens below it is
//! honored. A project value that would loosen beyond the floor is
//! **rejected at load time with a named-source warning**. There is no
//! approval path for pure-policy knobs; "loosen" strictly means
//! "project declaration → drop, surface warning."
//!
//! Legacy Phase 46 knobs keep project > user precedence as long as
//! `force-security-floor = false` — this is the Phase 46 back-compat
//! contract. When `force-security-floor = true`, legacy and new knobs
//! behave identically: user is floor for both, CLI loosening flags
//! suppressed, project loosening rejected.
//!
//! # Force-security-floor interactions (§6 "Gap 4 kill-switch")
//!
//! When the flag is set:
//! - A CLI value that loosens the floor is dropped (`Rejection` with
//!   `ForceFlagSuppressesCli`), callers route the user to
//!   `lpm config unset force-security-floor` to loosen intentionally.
//! - A project value that loosens is dropped (`Rejection` with
//!   `ForceFlagRejectsProject`) regardless of whether the knob is
//!   legacy or new.
//! - Tightening CLI / project values ARE still honored — the flag is
//!   "no loosening below the floor," not "nothing moves."
//!
//! Approval suspension is a separate concern handled by the approval
//! record layer, not this resolver.

use std::fmt;

// ── Public types ──────────────────────────────────────────────────

/// Whether a knob is subject to Phase 46 back-compat precedence.
///
/// [`PolicyKind::Legacy`] knobs (`scriptPolicy`, `sandboxWriteDirs`
/// — the latter handled by a separate resolver) retain the Phase 46
/// project > user order when `force-security-floor = false`. The
/// default flip for legacy knobs is scheduled for Phase 5 (Phase 49),
/// not P0.
///
/// [`PolicyKind::New`] knobs (`network-policy`,
/// `install-policy.strict-behavioral`) always use user-is-floor, with
/// project values that loosen below the floor rejected at load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    /// Shipped before Phase 48; project > user by default unless
    /// `force-security-floor` is set.
    Legacy,
    /// Introduced in Phase 48; user is always the floor.
    New,
}

/// Source tier of a policy value.
///
/// Used both to attribute the effective value in [`Resolution`] and
/// to label entries in the [`Rejection`] list so user-facing warnings
/// can name both source files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTier {
    /// Command-line flag on the current invocation.
    Cli,
    /// `package.json > lpm > *` for the project being installed.
    Project,
    /// `~/.lpm/config.toml` on the user's machine.
    User,
    /// Built-in default when no other tier supplied a value.
    Default,
}

impl fmt::Display for PolicyTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyTier::Cli => f.write_str("CLI flag"),
            PolicyTier::Project => f.write_str("project package.json"),
            PolicyTier::User => f.write_str("~/.lpm/config.toml"),
            PolicyTier::Default => f.write_str("built-in default"),
        }
    }
}

/// Why a candidate value was rejected during resolution.
///
/// These map 1:1 to the three distinct warning triggers listed in
/// [Phase 48 P0's migration-path bullet](../../../../../../a-package-manager/DOCS/new-features/37-rust-client-RUNNER-VISION-phase48.md):
/// callers choose wording per variant so users can tell which kind
/// of containment action just happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectionReason {
    /// `force-security-floor = true` suppressed a CLI loosening flag.
    /// Remediation surface: `lpm config unset force-security-floor`.
    ForceFlagSuppressesCli,
    /// `force-security-floor = true` rejected a project-config
    /// loosening value. Applies to both legacy and new knobs.
    ForceFlagRejectsProject,
    /// New Phase 48 knob: project value rejected because it would
    /// loosen below the user floor. Does NOT require the force flag
    /// — new-knob precedence is user-is-floor by default.
    NewKnobProjectLoosens,
}

/// A single rejection emitted during resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection<T> {
    /// The value that got dropped.
    pub rejected_value: T,
    /// Which tier that value came from.
    pub source: PolicyTier,
    /// Why it was dropped.
    pub reason: RejectionReason,
}

/// Result of a pure-policy resolution.
///
/// The effective value is what callers should actually apply. The
/// rejection list is non-empty only when the resolver dropped a
/// candidate; callers render each rejection into a stderr warning
/// naming both the dropped source and the floor source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution<T> {
    pub effective: T,
    pub effective_source: PolicyTier,
    pub rejections: Vec<Rejection<T>>,
}

/// Inputs to the pure-policy resolver.
///
/// All four tiers are materialised by the caller: CLI from
/// `collapse_policy_flags`-style helpers, project from a per-knob
/// `from_package_json` loader, user from `GlobalConfig`, default from
/// the knob's `Default` impl. The resolver is a pure function of
/// these inputs — no I/O — so it's trivially testable and no hidden
/// state can slip in.
#[derive(Debug, Clone)]
pub struct PolicyInputs<T> {
    pub cli: Option<T>,
    pub project: Option<T>,
    pub user: Option<T>,
    pub default: T,
    pub force_security_floor: bool,
}

/// Per-knob customisation for the pure-policy resolver.
///
/// Types that implement this trait can flow through
/// [`resolve_pure_policy`]. The one non-trivial method is
/// [`PurePolicyKnob::loosens`] — the resolver uses it to decide
/// whether a candidate value would widen the attack surface beyond
/// the floor.
pub trait PurePolicyKnob: Copy + PartialEq + Eq {
    /// Canonical name for user-facing messages (kebab-case).
    const NAME: &'static str;

    /// Whether the knob follows Phase 46 legacy precedence or the
    /// new-knob user-is-floor rule.
    const KIND: PolicyKind;

    /// Returns `true` if `self` is strictly more permissive than
    /// `floor` — i.e., applying `self` over `floor` would widen the
    /// attack surface.
    ///
    /// For `scriptPolicy`: `Allow` loosens `Triage` loosens `Deny`.
    /// For `network-policy`: `Allow` loosens `Fenced`.
    ///
    /// Must be strict (`self != floor` implies at most one of
    /// `self.loosens(floor)` and `floor.loosens(self)` is true).
    fn loosens(self, floor: Self) -> bool;
}

// ── Resolver ──────────────────────────────────────────────────────

/// Resolve a pure-policy knob through the full precedence chain.
///
/// See the module-level doc for the contract. The function is pure
/// and side-effect-free; callers are responsible for translating the
/// resulting rejections into stderr warnings and for respecting the
/// `effective` value when applying policy.
pub fn resolve_pure_policy<T: PurePolicyKnob>(inputs: PolicyInputs<T>) -> Resolution<T> {
    // The floor is the user's explicit value if set, otherwise the
    // knob's default. This is what "loosens" is measured against for
    // rejection decisions.
    let (floor, floor_source) = match inputs.user {
        Some(u) => (u, PolicyTier::User),
        None => (inputs.default, PolicyTier::Default),
    };

    let mut rejections = Vec::new();

    // ── Branch 1: force-security-floor is on ──
    //
    // Both legacy and new knobs behave identically here: any CLI or
    // project value that loosens past the floor is rejected. Tighter
    // CLI / project values are still honored.
    if inputs.force_security_floor {
        let cli_keep = match inputs.cli {
            Some(c) if c.loosens(floor) => {
                rejections.push(Rejection {
                    rejected_value: c,
                    source: PolicyTier::Cli,
                    reason: RejectionReason::ForceFlagSuppressesCli,
                });
                None
            }
            other => other,
        };
        let project_keep = match inputs.project {
            Some(p) if p.loosens(floor) => {
                rejections.push(Rejection {
                    rejected_value: p,
                    source: PolicyTier::Project,
                    reason: RejectionReason::ForceFlagRejectsProject,
                });
                None
            }
            other => other,
        };

        let (effective, effective_source) = if let Some(c) = cli_keep {
            (c, PolicyTier::Cli)
        } else if let Some(p) = project_keep {
            (p, PolicyTier::Project)
        } else {
            (floor, floor_source)
        };
        return Resolution {
            effective,
            effective_source,
            rejections,
        };
    }

    // ── Branch 2: no force flag, legacy knob ──
    //
    // Phase 46 order preserved: CLI > project > user > default, no
    // loosening checks. This is the Phase 46 back-compat contract
    // documented in §6 "Gap 4 default for legacy knobs — honest
    // framing"; the default flip for legacy knobs is Phase 5 (Phase
    // 49), not P0.
    if matches!(T::KIND, PolicyKind::Legacy) {
        let (effective, effective_source) = if let Some(c) = inputs.cli {
            (c, PolicyTier::Cli)
        } else if let Some(p) = inputs.project {
            (p, PolicyTier::Project)
        } else {
            (floor, floor_source)
        };
        return Resolution {
            effective,
            effective_source,
            rejections,
        };
    }

    // ── Branch 3: no force flag, new knob ──
    //
    // User-is-floor default. CLI still wins if present (CLI is a
    // live user action); project is rejected if it would loosen the
    // user floor. This is the rule that Phase 48 gets to apply
    // without a back-compat carve-out because these knobs are new.
    let project_keep = match inputs.project {
        Some(p) if p.loosens(floor) => {
            rejections.push(Rejection {
                rejected_value: p,
                source: PolicyTier::Project,
                reason: RejectionReason::NewKnobProjectLoosens,
            });
            None
        }
        other => other,
    };

    let (effective, effective_source) = if let Some(c) = inputs.cli {
        (c, PolicyTier::Cli)
    } else if let Some(p) = project_keep {
        (p, PolicyTier::Project)
    } else {
        (floor, floor_source)
    };

    Resolution {
        effective,
        effective_source,
        rejections,
    }
}

// ── Impl: ScriptPolicy (legacy knob) ──────────────────────────────

impl PurePolicyKnob for crate::script_policy_config::ScriptPolicy {
    const NAME: &'static str = "script-policy";
    const KIND: PolicyKind = PolicyKind::Legacy;

    fn loosens(self, floor: Self) -> bool {
        use crate::script_policy_config::ScriptPolicy::*;
        // Strictness order: Deny (tightest) < Triage < Allow (loosest).
        let rank = |p: Self| match p {
            Deny => 0,
            Triage => 1,
            Allow => 2,
        };
        rank(self) > rank(floor)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script_policy_config::ScriptPolicy;

    /// Test-only stand-in for a Phase 48 new-knob policy.
    ///
    /// Real `network-policy` lands in P3 with the backend wiring;
    /// the resolver only needs a representative enum to exercise
    /// the [`PolicyKind::New`] code path under P0, so we ship this
    /// as a local test type rather than publishing a half-built
    /// public API.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NetworkPolicy {
        Fenced,
        Allow,
    }

    impl PurePolicyKnob for NetworkPolicy {
        const NAME: &'static str = "network-policy";
        const KIND: PolicyKind = PolicyKind::New;

        fn loosens(self, floor: Self) -> bool {
            matches!((self, floor), (Self::Allow, Self::Fenced))
        }
    }

    // ── loosens ordering ──────────────────────────────────────────

    #[test]
    fn script_policy_loosens_order_is_deny_triage_allow() {
        assert!(!ScriptPolicy::Deny.loosens(ScriptPolicy::Deny));
        assert!(!ScriptPolicy::Deny.loosens(ScriptPolicy::Triage));
        assert!(!ScriptPolicy::Deny.loosens(ScriptPolicy::Allow));
        assert!(ScriptPolicy::Triage.loosens(ScriptPolicy::Deny));
        assert!(!ScriptPolicy::Triage.loosens(ScriptPolicy::Triage));
        assert!(!ScriptPolicy::Triage.loosens(ScriptPolicy::Allow));
        assert!(ScriptPolicy::Allow.loosens(ScriptPolicy::Deny));
        assert!(ScriptPolicy::Allow.loosens(ScriptPolicy::Triage));
        assert!(!ScriptPolicy::Allow.loosens(ScriptPolicy::Allow));
    }

    #[test]
    fn network_policy_loosens_order_is_fenced_allow() {
        assert!(!NetworkPolicy::Fenced.loosens(NetworkPolicy::Fenced));
        assert!(!NetworkPolicy::Fenced.loosens(NetworkPolicy::Allow));
        assert!(NetworkPolicy::Allow.loosens(NetworkPolicy::Fenced));
        assert!(!NetworkPolicy::Allow.loosens(NetworkPolicy::Allow));
    }

    // ── Phase 48 P0 Exit Criterion #1: force flag rejects CLI + project loosening ──

    /// §7 P0 exit criterion 1.
    ///
    /// `force-security-floor = true` + project `scriptPolicy = "allow"`
    /// + `--yolo` (CLI = `allow`) → effective is `deny` (user default
    /// floor); CLI rejected with `ForceFlagSuppressesCli`, project
    /// rejected with `ForceFlagRejectsProject`. User isn't set so
    /// floor defaults to `deny`.
    #[test]
    fn force_flag_rejects_cli_yolo_and_project_loosening() {
        let inputs = PolicyInputs::<ScriptPolicy> {
            cli: Some(ScriptPolicy::Allow),
            project: Some(ScriptPolicy::Allow),
            user: None,
            default: ScriptPolicy::Deny,
            force_security_floor: true,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(
            resolution.effective,
            ScriptPolicy::Deny,
            "force-security-floor + no user value → default floor (deny) prevails"
        );
        assert_eq!(resolution.effective_source, PolicyTier::Default);

        // Both loosening paths rejected, one rejection each.
        assert_eq!(
            resolution.rejections.len(),
            2,
            "CLI and project rejections both fired: {:?}",
            resolution.rejections
        );
        assert!(
            resolution
                .rejections
                .iter()
                .any(|r| r.source == PolicyTier::Cli
                    && r.reason == RejectionReason::ForceFlagSuppressesCli
                    && r.rejected_value == ScriptPolicy::Allow),
            "CLI --yolo rejection present: {:?}",
            resolution.rejections
        );
        assert!(
            resolution
                .rejections
                .iter()
                .any(|r| r.source == PolicyTier::Project
                    && r.reason == RejectionReason::ForceFlagRejectsProject
                    && r.rejected_value == ScriptPolicy::Allow),
            "project scriptPolicy rejection present: {:?}",
            resolution.rejections
        );
    }

    // ── Phase 48 P0 Exit Criterion #2: legacy back-compat preserved ──

    /// §7 P0 exit criterion 2.
    ///
    /// `force-security-floor = false` + project `scriptPolicy = "allow"`
    /// (user unset) → effective is `allow`. Phase 46 project > user
    /// order preserved for the legacy knob; the default flip is
    /// Phase 5's job, not P0's.
    #[test]
    fn legacy_knob_without_force_flag_preserves_phase46_order() {
        let inputs = PolicyInputs::<ScriptPolicy> {
            cli: None,
            project: Some(ScriptPolicy::Allow),
            user: None,
            default: ScriptPolicy::Deny,
            force_security_floor: false,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(
            resolution.effective,
            ScriptPolicy::Allow,
            "Phase 46 back-compat: project scriptPolicy wins without force flag"
        );
        assert_eq!(resolution.effective_source, PolicyTier::Project);
        assert!(
            resolution.rejections.is_empty(),
            "no rejections under legacy back-compat: {:?}",
            resolution.rejections
        );
    }

    /// Sibling to exit criterion 2: user-set value still loses to
    /// project under legacy back-compat. Pins the "no force flag
    /// means Phase 46 order, period" contract.
    #[test]
    fn legacy_knob_without_force_flag_project_beats_user_even_when_explicit() {
        let inputs = PolicyInputs::<ScriptPolicy> {
            cli: None,
            project: Some(ScriptPolicy::Allow),
            user: Some(ScriptPolicy::Deny),
            default: ScriptPolicy::Deny,
            force_security_floor: false,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(resolution.effective, ScriptPolicy::Allow);
        assert_eq!(resolution.effective_source, PolicyTier::Project);
        assert!(resolution.rejections.is_empty());
    }

    // ── Phase 48 P0 Exit Criterion #3: new-knob user-is-floor default ──

    /// §7 P0 exit criterion 3.
    ///
    /// `force-security-floor = false` + project `network-policy = "allow"`
    /// + user `network-policy = "fenced"` → effective is `fenced`,
    /// project value rejected at load with `NewKnobProjectLoosens`.
    /// New-knob rule applies WITHOUT the force flag.
    ///
    /// Pins the rule from the test side: no entry should show up
    /// in any approval UI for this rejection. The resolver's
    /// contract is "rejected at load, no request flow" — if a
    /// future refactor routes rejections through approval, this
    /// test guards the canonical semantic.
    #[test]
    fn new_knob_without_force_flag_rejects_project_loosening() {
        let inputs = PolicyInputs::<NetworkPolicy> {
            cli: None,
            project: Some(NetworkPolicy::Allow),
            user: Some(NetworkPolicy::Fenced),
            default: NetworkPolicy::Fenced,
            force_security_floor: false,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(
            resolution.effective,
            NetworkPolicy::Fenced,
            "new-knob: user floor prevails without force flag"
        );
        assert_eq!(resolution.effective_source, PolicyTier::User);
        assert_eq!(
            resolution.rejections.len(),
            1,
            "exactly one rejection (project loosening): {:?}",
            resolution.rejections
        );
        let rej = &resolution.rejections[0];
        assert_eq!(rej.source, PolicyTier::Project);
        assert_eq!(rej.reason, RejectionReason::NewKnobProjectLoosens);
        assert_eq!(rej.rejected_value, NetworkPolicy::Allow);
    }

    // ── Additional coverage: non-regression cases from the contract ──

    /// Force flag + project TIGHTENING → project value honored
    /// (tighter-than-floor is always fine, see §6 "Gap 4 kill-switch").
    #[test]
    fn force_flag_honors_project_tightening() {
        let inputs = PolicyInputs::<ScriptPolicy> {
            cli: None,
            project: Some(ScriptPolicy::Deny),
            user: Some(ScriptPolicy::Allow),
            default: ScriptPolicy::Deny,
            force_security_floor: true,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(resolution.effective, ScriptPolicy::Deny);
        assert_eq!(resolution.effective_source, PolicyTier::Project);
        assert!(resolution.rejections.is_empty());
    }

    /// Force flag + CLI TIGHTENING → CLI honored. Same rationale
    /// as the project-tightening case; the flag blocks loosening,
    /// not movement.
    #[test]
    fn force_flag_honors_cli_tightening() {
        let inputs = PolicyInputs::<ScriptPolicy> {
            cli: Some(ScriptPolicy::Deny),
            project: Some(ScriptPolicy::Allow),
            user: Some(ScriptPolicy::Triage),
            default: ScriptPolicy::Deny,
            force_security_floor: true,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(resolution.effective, ScriptPolicy::Deny);
        assert_eq!(resolution.effective_source, PolicyTier::Cli);
        // Project's `Allow` loosens `Triage`, so it IS rejected.
        assert_eq!(resolution.rejections.len(), 1);
        assert_eq!(resolution.rejections[0].source, PolicyTier::Project);
        assert_eq!(
            resolution.rejections[0].reason,
            RejectionReason::ForceFlagRejectsProject,
        );
    }

    /// New-knob + CLI loosening WITHOUT force flag → CLI still wins
    /// (a live user-typed flag is a legitimate user action; only
    /// project auto-loosening is blocked by the new-knob rule).
    /// The force flag is the only thing that fences CLI.
    #[test]
    fn new_knob_without_force_flag_cli_loosening_honored() {
        let inputs = PolicyInputs::<NetworkPolicy> {
            cli: Some(NetworkPolicy::Allow),
            project: None,
            user: Some(NetworkPolicy::Fenced),
            default: NetworkPolicy::Fenced,
            force_security_floor: false,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(resolution.effective, NetworkPolicy::Allow);
        assert_eq!(resolution.effective_source, PolicyTier::Cli);
        assert!(resolution.rejections.is_empty());
    }

    /// New-knob + project TIGHTENING (project says `fenced` when
    /// user is `allow`) → project value honored (tightening is
    /// always welcome regardless of knob kind).
    #[test]
    fn new_knob_without_force_flag_honors_project_tightening() {
        let inputs = PolicyInputs::<NetworkPolicy> {
            cli: None,
            project: Some(NetworkPolicy::Fenced),
            user: Some(NetworkPolicy::Allow),
            default: NetworkPolicy::Fenced,
            force_security_floor: false,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(resolution.effective, NetworkPolicy::Fenced);
        assert_eq!(resolution.effective_source, PolicyTier::Project);
        assert!(resolution.rejections.is_empty());
    }

    /// Empty inputs: nothing set except default. Legacy and new
    /// behave identically here (no candidates to reject or honor).
    #[test]
    fn defaults_fall_through_when_all_tiers_absent() {
        let inputs = PolicyInputs::<ScriptPolicy> {
            cli: None,
            project: None,
            user: None,
            default: ScriptPolicy::Deny,
            force_security_floor: false,
        };

        let resolution = resolve_pure_policy(inputs);

        assert_eq!(resolution.effective, ScriptPolicy::Deny);
        assert_eq!(resolution.effective_source, PolicyTier::Default);
        assert!(resolution.rejections.is_empty());
    }

    /// PolicyTier renders a human-facing string for stderr warnings;
    /// callers depend on these exact phrasings, pinned here so
    /// a message-string refactor can't silently break them.
    #[test]
    fn policy_tier_display_matches_user_facing_phrasings() {
        assert_eq!(PolicyTier::Cli.to_string(), "CLI flag");
        assert_eq!(PolicyTier::Project.to_string(), "project package.json");
        assert_eq!(PolicyTier::User.to_string(), "~/.lpm/config.toml");
        assert_eq!(PolicyTier::Default.to_string(), "built-in default");
    }
}
