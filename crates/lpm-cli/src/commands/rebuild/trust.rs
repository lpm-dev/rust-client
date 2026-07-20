use crate::script_policy_config::ScriptPolicy;
use lpm_security::script_hash::compute_script_hash;
use lpm_security::triage::StaticTier;
use lpm_security::{SecurityPolicy, TrustMatch};
use std::collections::HashMap;
use std::path::Path;

pub(super) fn is_scope_trusted(package_name: &str, project_dir: &Path) -> bool {
    let scopes = parse_trusted_scopes(project_dir);
    name_matches_trusted_scope(package_name, &scopes)
}

/// Read `project_dir/package.json` ONCE and return the
/// `lpm.scripts.trustedScopes` list. Returns an empty vec if the file
/// is missing, malformed, or the field is absent — matching the
/// fail-closed posture of [`is_scope_trusted`].
///
/// Exposed for hot per-N call sites that previously paid an O(N) tax
/// for re-parsing the same manifest in a loop.
pub(super) fn parse_trusted_scopes(project_dir: &Path) -> Vec<String> {
    let pkg_json_path = project_dir.join("package.json");
    let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    parsed
        .get("lpm")
        .and_then(|l| l.get("scripts"))
        .and_then(|s| s.get("trustedScopes"))
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Pure helper: match a package name against a precomputed list of
/// `trustedScopes` glob patterns. Same semantics as the original
/// `is_scope_trusted` body — kept identical so behavior under all
/// existing tests is preserved.
pub(super) fn name_matches_trusted_scope(package_name: &str, scopes: &[String]) -> bool {
    for pattern in scopes {
        // Simple glob matching: `@myorg/*` matches `@myorg/anything`.
        //
        // previously used `starts_with(prefix)` which also matched
        // `@myorg-evil/pkg` against `@myorg` — a lookalike-scope
        // bypass of the lifecycle approval gate. Require the prefix
        // to be followed by exactly `/` so only members of `@myorg`
        // itself qualify, never a `@myorg<suffix>` scope.
        if let Some(prefix) = pattern.strip_suffix("/*") {
            if let Some(rest) = package_name.strip_prefix(prefix)
                && let Some(after_sep) = rest.strip_prefix('/')
                && !after_sep.is_empty()
            {
                return true;
            }
        } else if pattern == package_name {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustReason {
    /// Rich strict binding whose exact source/content identity and script hash
    /// match an approved entry.
    StrictBinding,
    /// Pre-legacy bare-name `trustedDependencies: ["name"]`
    /// entry. Matched via `TrustMatch::LegacyNameOnly`. Callers
    /// still emit a soft deprecation warning so users migrate to
    /// the rich form.
    LegacyName,
    /// `lpm.scripts.trustedScopes` glob match (e.g., `@myorg/*`).
    ScopedGlob,
    /// `script-policy = "triage"` + worst-wins classification of
    /// the package's lifecycle phases is [`StaticTier::Green`]. This
    /// is the auto-trust path — the package carries no manifest
    /// binding, but its scripts match the hand-curated Layer 1
    /// allowlist (`node-gyp rebuild`, `tsc`, `prisma generate`,
    /// `husky install`, `electron-rebuild`, relative-path `node`
    /// calls). Only reachable under [`ScriptPolicy::Triage`].
    GreenTierUnderTriage,
    ///
    /// `script-policy = "triage"` + worst-wins classification is
    /// Amber/AmberLlm + an in-memory [`crate::triage_advisor_session::AdvisorSession`]
    /// returned `Approve` for this exact source/content/script identity
    /// during the current install. The approval is **ephemeral**: it lives
    /// only for the lifetime of the `AdvisorSession` (one install
    /// run), is never written to `trustedDependencies`, and is
    /// invisible to a later standalone `lpm rebuild` invocation
    /// that doesn't carry its own session.
    ///
    /// Reachable only when [`evaluate_trust`] is given a non-empty
    /// `advisor_approvals` set. Standalone `lpm rebuild` passes
    /// `None`, so this variant never fires outside the install path.
    AdvisorApprovedThisRun,
    /// Strict binding exists but its stored `scriptHash` no longer
    /// matches the on-disk body. Triage does NOT auto-recover this:
    /// the user previously approved a specific script and the script
    /// changed, so a re-review is required. Matches `rebuild::run`'s
    /// previous semantics exactly.
    BindingDrift,
    /// The user set
    /// `force-security-floor = true` in `~/.lpm/config.toml`. What
    /// would otherwise be a trust-granting result (`StrictBinding`,
    /// `LegacyName`, `ScopedGlob`, or `GreenTierUnderTriage`) is
    /// suspended for the duration the flag is set. No persisted state
    /// changes — approvals in `package.json > lpm > trustedDependencies`
    /// remain intact. Unsetting the flag reactivates them on the next
    /// `lpm rebuild` / `lpm install` invocation without re-review.
    ///
    /// Distinct from [`Self::Untrusted`]: `Untrusted` means "no
    /// approval exists"; `SuspendedByForceFloor` means "an approval
    /// exists but is paused." `lpm doctor` surfaces the count of
    /// suspended approvals so users can see what the kill-switch is
    /// holding back.
    SuspendedByForceFloor,
    /// The package's requested
    /// [`crate::capability::CapabilitySet`] widens beyond the
    /// user's [`crate::capability::UserBound`], AND no approval
    /// record in `package.json > lpm > trustedDependencies` has a
    /// `capabilityHash` matching the requested set.
    ///
    /// Two concrete sub-cases collapse into this reason:
    /// - The package has an approval (binding exists) but its
    ///   `capability_hash` is `None` (legacy approval) or doesn't
    ///   match the current request — approval is for a different
    ///   capability surface than what's being asked for now.
    /// - The package has an approval whose `capability_hash` was
    ///   never set (approval predates capability hashing) — any
    ///   package that widens via the capability model falls into
    ///   this state even if the user ran `lpm approve-scripts`.
    ///   Widening becomes enforceable before it becomes grantable
    ///   through normal UX.
    ///
    /// Not trusted — the script doesn't run. UX
    /// distinguishes this from `StrictBinding` /
    /// `SuspendedByForceFloor` via the approve-scripts delta
    /// display, but at the enforcement layer this is just "no."
    CapabilityNotApproved,
    /// No trust basis found.
    Untrusted,
}

impl TrustReason {
    /// Single point where the helper's output gets collapsed to the
    /// build pipeline's boolean `is_trusted`. Kept on the enum so both
    /// call sites (`rebuild::run` and `all_scripted_packages_trusted`)
    /// can never drift on which reasons count as trusted.
    pub(crate) fn is_trusted(self) -> bool {
        matches!(
            self,
            Self::StrictBinding
                | Self::LegacyName
                | Self::ScopedGlob
                | Self::GreenTierUnderTriage
                | Self::AdvisorApprovedThisRun,
        )
    }
}

/// — shared trust decision.
///
/// Single source of truth for "is this package trusted to execute
/// lifecycle scripts under the current effective policy?" Consumed by
/// both [`run`] (via its `scriptable_packages` loop) and
/// [`all_scripted_packages_trusted`]  so the two
/// paths cannot disagree on trust the first time one gets tweaked.
///
/// Evaluation order — the first matching rule wins:
/// 1. **Strict gate** ([`SecurityPolicy::can_run_scripts_strict`]).
///    A rich binding that matches the full tuple yields
///    [`TrustReason::StrictBinding`]; a legacy bare-name entry yields
///    [`TrustReason::LegacyName`]; a rich binding whose `scriptHash`
///    drifted yields [`TrustReason::BindingDrift`] — terminal, never
///    overridden by later rules.
/// 2. **Scope glob** (`lpm.scripts.trustedScopes`). Glob match yields
///    [`TrustReason::ScopedGlob`].
/// 3. **Green-tier auto-trust**. Only when
///    `effective_policy == Triage`: classify every present lifecycle
///    phase via [`lpm_security::static_gate::classify`], reduce
///    worst-wins (same precedence `build_state.rs` uses at install
///    time), and if the result is [`StaticTier::Green`] yield
///    [`TrustReason::GreenTierUnderTriage`]. Amber / AmberLlm / Red
///    flow through to untrusted regardless of policy.
///
/// The classifier is the authoritative tier source — we do NOT read
/// back from `build-state.json`. That file is an install-time cache
/// and a user-facing artifact; calling `lpm rebuild` standalone (no
/// preceding install) must still yield the same decision. Strict
/// bindings remain authoritative when a script changes.
///
/// Drift is never auto-recovered under triage. A drifted rich binding
/// means the user previously approved a different script body; even
/// if the current on-disk script classifies green, the user still
/// needs to re-review the delta via `lpm approve-scripts`. This keeps
/// the security floor at "no execution without current user approval
/// intent".
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn evaluate_trust(
    package_dir: &Path,
    name: &str,
    version: &str,
    integrity: Option<&str>,
    scripts: &HashMap<String, String>,
    policy: &SecurityPolicy,
    project_dir: &Path,
    effective_policy: ScriptPolicy,
    // When `true`, any result that would
    // otherwise be trust-granting (`StrictBinding`, `LegacyName`,
    // `ScopedGlob`, `GreenTierUnderTriage`) is intercepted and
    // returned as [`TrustReason::SuspendedByForceFloor`]. Callers
    // read this from `GlobalConfig::load().get_bool("force-security-floor")`
    // once per invocation. `BindingDrift` is unaffected — drift already
    // represents a "not trusted" terminal state. `Untrusted` is also
    // unaffected — there's nothing to suspend when nothing was trusted.
    force_security_floor: bool,
    // The package's requested
    // capability set, parsed from `package.json > lpm > scripts >
    // {passEnv, readProject, sandboxLimits}`. Baseline default means
    // "no extras requested" and passes straight through — most
    // packages are at baseline.
    requested_capabilities: &crate::capability::CapabilitySet,
    // The user's configured bounds for capability widening, read
    // from `~/.lpm/config.toml`. Default means "no user ceilings
    // configured" — rlimit requests with no matching user ceiling
    // fail closed (trigger the approval gate).
    user_bound: &crate::capability::UserBound,
    // In-memory ephemeral approval set
    // populated by the install path's
    // [`crate::triage_advisor_session::AdvisorSession`]. A package
    // whose exact source/content/script identity appears here AND
    // classifies amber under triage yields
    // [`TrustReason::AdvisorApprovedThisRun`].
    // `None` (or empty) preserves portable L1-3 behaviour — the
    // standalone `lpm rebuild` path passes `None`.
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> TrustReason {
    evaluate_trust_for_identity(
        package_dir,
        name,
        version,
        None,
        integrity,
        scripts,
        policy,
        project_dir,
        effective_policy,
        force_security_floor,
        requested_capabilities,
        user_bound,
        advisor_approvals,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_trust_for_identity(
    package_dir: &Path,
    name: &str,
    version: &str,
    source: Option<&str>,
    integrity: Option<&str>,
    scripts: &HashMap<String, String>,
    policy: &SecurityPolicy,
    project_dir: &Path,
    effective_policy: ScriptPolicy,
    force_security_floor: bool,
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> TrustReason {
    let candidate = evaluate_trust_unsuspended(
        package_dir,
        name,
        version,
        source,
        integrity,
        scripts,
        policy,
        project_dir,
        effective_policy,
        advisor_approvals,
    );
    let after_force = if force_security_floor && candidate.is_trusted() {
        TrustReason::SuspendedByForceFloor
    } else {
        candidate
    };

    // Capability gate — applies only when the prior layer returned
    // a trust-granting reason. A non-trusted result (BindingDrift,
    // SuspendedByForceFloor, Untrusted) short-circuits: the script
    // won't run anyway, and letting it flow through unchanged
    // preserves the specific diagnostic reason (the capability
    // gate producing `CapabilityNotApproved` on top would clobber
    // the more actionable message).
    if !after_force.is_trusted() {
        return after_force;
    }

    // Trusted-so-far. Check whether the requested capability set
    // widens beyond the user bound — if not, the request is
    // self-approving (nothing beyond baseline / tighter-than-bound
    // needs explicit approval).
    if !requested_capabilities.loosens_beyond(user_bound) {
        return after_force;
    }

    // Widening request. Requires a matching capability-hash
    // approval on the binding. Legacy bindings (capability_hash =
    // None) and missing bindings both fail this check, collapsing
    // into CapabilityNotApproved — which 6d's UX surfaces as a
    // distinct reason from Untrusted.
    match policy.get_binding(name, version, source, integrity) {
        Some(binding) if requested_capabilities.is_approved_by(binding) => after_force,
        _ => TrustReason::CapabilityNotApproved,
    }
}

/// the original `evaluate_trust` body, extracted
/// so [`evaluate_trust`] can compose "raw match → suspension filter"
/// without duplicating the match logic. Returns every variant
/// [`TrustReason`] can take EXCEPT [`TrustReason::SuspendedByForceFloor`],
/// which is strictly a decorator applied by the outer function.
#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_trust_unsuspended(
    package_dir: &Path,
    name: &str,
    version: &str,
    source: Option<&str>,
    integrity: Option<&str>,
    scripts: &HashMap<String, String>,
    policy: &SecurityPolicy,
    project_dir: &Path,
    effective_policy: ScriptPolicy,
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> TrustReason {
    let script_hash = compute_script_hash(package_dir);
    let strict = policy.can_run_scripts_strict_for_identity(
        name,
        version,
        source,
        integrity,
        script_hash.as_deref(),
    );
    match strict {
        TrustMatch::Strict => return TrustReason::StrictBinding,
        TrustMatch::LegacyNameOnly => return TrustReason::LegacyName,
        TrustMatch::BindingDrift { .. } => return TrustReason::BindingDrift,
        TrustMatch::NotTrusted => {}
    }

    if is_scope_trusted(name, project_dir) {
        return TrustReason::ScopedGlob;
    }

    if effective_policy == ScriptPolicy::Triage {
        let tier = classify_package_worst_tier(scripts);
        if tier == Some(StaticTier::Green) && green_tier_can_auto_trust(scripts) {
            return TrustReason::GreenTierUnderTriage;
        }
        // Amber + advisor said Approve →
        // ephemeral trust for this run. Confined to triage policy
        // (deny / allow paths never reach here in a triage-meaningful
        // way) and to a non-empty in-memory approval set. Standalone
        // `lpm rebuild` passes `None`, so this short-circuit cannot
        // bypass the persistent trust manifest outside an active
        // install.
        if matches!(tier, Some(StaticTier::Amber) | Some(StaticTier::AmberLlm))
            && let Some(set) = advisor_approvals
        {
            // Classification is package-wide, so one source-qualified package
            // identity has one bundle verdict for this install session.
            let integrity_owned: Option<String> = integrity.map(str::to_string);
            if set.iter().any(|(n, v, s, i, _)| {
                n == name && v == version && s.as_deref() == source && *i == integrity_owned
            }) {
                return TrustReason::AdvisorApprovedThisRun;
            }
        }
    }

    TrustReason::Untrusted
}

/// Worst-wins classification across the lifecycle phases present in
/// `scripts`. Returns `None` when `scripts` is empty (caller has
/// already early-returned in practice, since the trust-decision call
/// sites only run after at least one lifecycle script was found).
///
/// Mirrors the reduction at `build_state.rs:418-421` exactly so the
/// install-time annotation and the `lpm rebuild` gate agree on tier
/// per-package without sharing cached state.
pub(super) fn classify_package_worst_tier(scripts: &HashMap<String, String>) -> Option<StaticTier> {
    scripts
        .values()
        .map(|body| lpm_security::static_gate::classify(body))
        .reduce(StaticTier::worse_of)
}

pub(super) fn green_tier_can_auto_trust(scripts: &HashMap<String, String>) -> bool {
    scripts
        .values()
        .all(|body| lpm_security::static_gate::extract_delegate_path(body).is_none())
}
