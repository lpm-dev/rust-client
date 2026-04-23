//! Phase 48 P0 — migration warnings for the pure-policy resolver.
//!
//! The [`crate::precedence`] module is pure (no I/O). When its
//! [`resolve_pure_policy`] function drops a candidate value, it
//! returns a [`Rejection`] describing what was dropped, from which
//! source, and why. This module is the boundary where those
//! rejections become user-facing output: a [`rejection_message`]
//! pure function turns a `Rejection` into a warning string, and
//! [`emit_rejection`] / [`emit_rejections`] route strings to stderr
//! with process-scoped dedup so the same (knob, reason) doesn't
//! spam across multiple resolver calls in one `lpm` invocation.
//!
//! # Three distinct wordings
//!
//! Per phase48.md §7 P0 "Migration path," the three [`RejectionReason`]
//! variants must have distinguishable user-facing strings. Each one
//! corresponds to a different user action:
//!
//! - [`RejectionReason::ForceFlagSuppressesCli`] → "you typed a
//!   loosening CLI flag, the user-global force flag suppressed it."
//!   Remediation: `lpm config unset force-security-floor`.
//! - [`RejectionReason::ForceFlagRejectsProject`] → "the project's
//!   `package.json` requested a looser policy, the user-global force
//!   flag rejected it at load time." Remediation: same as above.
//! - [`RejectionReason::NewKnobProjectLoosens`] → "the project's
//!   `package.json` requested a looser policy on a new Phase 48 knob,
//!   which the user-is-floor rule rejects even without the force
//!   flag." Remediation: set a looser value in
//!   `~/.lpm/config.toml` if intentional.
//!
//! Collapsing these into one wording would lose the user's ability
//! to tell which class of containment action just happened, so the
//! tests in this module pin the distinctions.
//!
//! # Dedup scope
//!
//! Dedup key = `(knob name, rejection reason)`. Scoped per process
//! (a single `lpm` invocation). Multiple call sites that all resolve
//! the same knob and hit the same rejection reason emit the warning
//! once. Different reasons on the same knob each emit once. A new
//! `lpm` invocation starts fresh.
//!
//! Per-`(project, knob, reason)` dedup is equivalent in practice
//! today because an `lpm install` operates on a single project;
//! revisit if batch commands ever span projects in one invocation.

use crate::precedence::{PurePolicyKnob, Rejection, RejectionReason, Resolution};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

// ── Pure wording function ─────────────────────────────────────────

/// Produce the user-facing warning string for a rejection.
///
/// Pure: no I/O, no dedup state. Callers route the result to stderr
/// via [`emit_rejection`] (which handles dedup) or directly.
///
/// Wording is load-bearing: tests in this module pin exact
/// substrings (knob name, remediation command, source-file names)
/// so a string refactor can't silently drop a clue the user needs.
pub fn rejection_message<T: PurePolicyKnob>(r: &Rejection<T>) -> String {
    match r.reason {
        RejectionReason::ForceFlagSuppressesCli => format!(
            "warning: CLI loosening flag for `{name}` ignored — \
             `force-security-floor = true` in ~/.lpm/config.toml \
             locks the machine to the user floor. \
             Run `lpm config unset force-security-floor` to loosen \
             intentionally for this session.",
            name = T::NAME,
        ),
        RejectionReason::ForceFlagRejectsProject => format!(
            "warning: project `{name}` in package.json ignored — \
             `force-security-floor = true` in ~/.lpm/config.toml \
             makes user settings the floor for all policies. \
             Run `lpm config unset force-security-floor` to let \
             project configs override.",
            name = T::NAME,
        ),
        RejectionReason::NewKnobProjectLoosens => format!(
            "warning: project `{name}` in package.json ignored — \
             would loosen below the user setting in \
             ~/.lpm/config.toml. Pure-policy knobs introduced in \
             Phase 48 use user-is-floor by default (no force flag \
             required). Set `{name}` in ~/.lpm/config.toml to the \
             looser value if you want it globally.",
            name = T::NAME,
        ),
    }
}

// ── Dedup cache + emit API ────────────────────────────────────────

/// Process-scoped dedup cache. Lazily initialised on first emit.
///
/// Key = `(knob name, rejection reason)`. Production callers never
/// need to reset this; tests use [`reset_dedup_cache_for_tests`].
fn dedup_cache() -> &'static Mutex<HashSet<(&'static str, RejectionReason)>> {
    static CACHE: OnceLock<Mutex<HashSet<(&'static str, RejectionReason)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Emit the warning for a single rejection to stderr, deduped per
/// `(knob name, reason)` for the current process.
///
/// Silently drops the warning if it's already been emitted in this
/// invocation. The dedup is intentional: multiple call sites resolve
/// the same knob, and users don't need the same warning three times
/// per `lpm install`.
pub fn emit_rejection<T: PurePolicyKnob>(r: &Rejection<T>) {
    let key = (T::NAME, r.reason);
    let mut cache = dedup_cache().lock().expect("dedup cache mutex poisoned");
    if cache.insert(key) {
        eprintln!("{}", rejection_message(r));
    }
}

/// Emit warnings for every rejection in a [`Resolution`], deduped.
///
/// Convenience wrapper — calls [`emit_rejection`] on each rejection
/// in order. Dedup is per-rejection, so multiple rejections in one
/// resolution (e.g., `force-security-floor = true` rejecting BOTH
/// CLI and project) each fire their own warning on the first call,
/// then suppress on subsequent calls across the same invocation.
pub fn emit_rejections<T: PurePolicyKnob>(resolution: &Resolution<T>) {
    for r in &resolution.rejections {
        emit_rejection(r);
    }
}

/// Test helper: clear the dedup cache so consecutive tests in the
/// same process don't mask each other's emit behavior.
///
/// Production code never calls this. Tests that care about dedup
/// semantics should use [`#[serial_test::serial]`] or similar to
/// avoid parallel-test interference if they also emit warnings.
#[cfg(test)]
pub fn reset_dedup_cache_for_tests() {
    dedup_cache()
        .lock()
        .expect("dedup cache mutex poisoned")
        .clear();
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precedence::PolicyTier;
    use crate::script_policy_config::ScriptPolicy;

    fn mk_rej(reason: RejectionReason, source: PolicyTier) -> Rejection<ScriptPolicy> {
        Rejection {
            rejected_value: ScriptPolicy::Allow,
            source,
            reason,
        }
    }

    // ── Wording pins — the three RejectionReason variants must
    //    produce distinguishable, load-bearing warnings ──

    #[test]
    fn force_flag_suppresses_cli_wording_names_knob_flag_and_remediation() {
        let msg = rejection_message(&mk_rej(
            RejectionReason::ForceFlagSuppressesCli,
            PolicyTier::Cli,
        ));
        assert!(
            msg.contains("script-policy"),
            "wording must name the knob: {msg}"
        );
        assert!(
            msg.contains("force-security-floor"),
            "wording must name the force flag so the user can find it: {msg}"
        );
        assert!(
            msg.contains("~/.lpm/config.toml"),
            "wording must name the config file so the user can find it: {msg}"
        );
        assert!(
            msg.contains("lpm config unset force-security-floor"),
            "wording must include the remediation command verbatim: {msg}"
        );
        assert!(
            msg.contains("CLI"),
            "wording must distinguish this from the project-rejected variant: {msg}"
        );
    }

    #[test]
    fn force_flag_rejects_project_wording_names_source_file_and_remediation() {
        let msg = rejection_message(&mk_rej(
            RejectionReason::ForceFlagRejectsProject,
            PolicyTier::Project,
        ));
        assert!(msg.contains("script-policy"), "names the knob: {msg}");
        assert!(msg.contains("package.json"), "names the source file: {msg}");
        assert!(
            msg.contains("force-security-floor"),
            "names the flag: {msg}"
        );
        assert!(
            msg.contains("lpm config unset force-security-floor"),
            "remediation command verbatim: {msg}"
        );
    }

    #[test]
    fn new_knob_project_loosens_wording_does_not_mention_force_flag() {
        let msg = rejection_message(&mk_rej(
            RejectionReason::NewKnobProjectLoosens,
            PolicyTier::Project,
        ));
        assert!(msg.contains("script-policy"), "names the knob: {msg}");
        assert!(
            msg.contains("package.json"),
            "names the project source: {msg}"
        );
        assert!(
            msg.contains("~/.lpm/config.toml"),
            "names the user config file: {msg}"
        );
        // Critical distinction from the force-flag variants: this
        // rejection fires without the force flag, so the wording
        // must not send the user chasing `lpm config unset
        // force-security-floor` — that wouldn't help. Pin the
        // absence explicitly.
        assert!(
            !msg.contains("force-security-floor"),
            "NewKnobProjectLoosens must NOT mention force flag \
             (it fires regardless of the flag): {msg}"
        );
        assert!(
            !msg.contains("lpm config unset"),
            "NewKnobProjectLoosens must not point at the force-flag \
             remediation (which doesn't apply): {msg}"
        );
    }

    #[test]
    fn all_three_wordings_are_pairwise_distinct() {
        let a = rejection_message(&mk_rej(
            RejectionReason::ForceFlagSuppressesCli,
            PolicyTier::Cli,
        ));
        let b = rejection_message(&mk_rej(
            RejectionReason::ForceFlagRejectsProject,
            PolicyTier::Project,
        ));
        let c = rejection_message(&mk_rej(
            RejectionReason::NewKnobProjectLoosens,
            PolicyTier::Project,
        ));
        assert_ne!(a, b, "ForceFlag{{Cli,Project}} must differ");
        assert_ne!(a, c, "ForceFlag(cli) vs NewKnob must differ");
        assert_ne!(b, c, "ForceFlag(project) vs NewKnob must differ");
    }

    #[test]
    fn every_wording_starts_with_warning_prefix() {
        // Consistent prefix means log grep / CI filter rules stay
        // predictable regardless of which variant fired.
        for reason in [
            RejectionReason::ForceFlagSuppressesCli,
            RejectionReason::ForceFlagRejectsProject,
            RejectionReason::NewKnobProjectLoosens,
        ] {
            let msg = rejection_message(&mk_rej(reason, PolicyTier::Cli));
            assert!(
                msg.starts_with("warning: "),
                "{reason:?} wording must start with `warning: ` prefix: {msg}"
            );
        }
    }

    // ── Dedup behavior ─────────────────────────────────────────────

    #[test]
    fn dedup_cache_is_process_scoped_and_resettable() {
        // Reset at start so prior tests in this binary don't skew.
        reset_dedup_cache_for_tests();
        let r = mk_rej(RejectionReason::ForceFlagSuppressesCli, PolicyTier::Cli);

        // First emit populates the cache. We can't capture stderr
        // here without intrusive test infra, but we can observe
        // cache state via a second insert attempt: if emit_rejection
        // deduped correctly, a direct cache insert of the same key
        // should return false (already present).
        emit_rejection(&r);
        let still_present = dedup_cache()
            .lock()
            .unwrap()
            .contains(&(ScriptPolicy::NAME, RejectionReason::ForceFlagSuppressesCli));
        assert!(still_present, "first emit should record in cache");

        // Reset clears it.
        reset_dedup_cache_for_tests();
        let after_reset = dedup_cache()
            .lock()
            .unwrap()
            .contains(&(ScriptPolicy::NAME, RejectionReason::ForceFlagSuppressesCli));
        assert!(!after_reset, "reset must clear the cache");
    }

    #[test]
    fn dedup_key_includes_reason_not_just_knob() {
        // Two rejections on the same knob with different reasons
        // should both populate the cache — the user needs to hear
        // about each distinct class of containment action.
        reset_dedup_cache_for_tests();
        let force_cli = mk_rej(RejectionReason::ForceFlagSuppressesCli, PolicyTier::Cli);
        let force_proj = mk_rej(
            RejectionReason::ForceFlagRejectsProject,
            PolicyTier::Project,
        );

        emit_rejection(&force_cli);
        emit_rejection(&force_proj);

        let cache = dedup_cache().lock().unwrap();
        assert!(cache.contains(&(ScriptPolicy::NAME, RejectionReason::ForceFlagSuppressesCli)));
        assert!(cache.contains(&(ScriptPolicy::NAME, RejectionReason::ForceFlagRejectsProject)));
        assert_eq!(cache.len(), 2, "both reasons recorded distinctly");
    }

    #[test]
    fn emit_rejections_on_empty_resolution_is_noop() {
        reset_dedup_cache_for_tests();
        let resolution: Resolution<ScriptPolicy> = Resolution {
            effective: ScriptPolicy::Deny,
            effective_source: PolicyTier::Default,
            rejections: Vec::new(),
        };
        emit_rejections(&resolution);
        let cache = dedup_cache().lock().unwrap();
        assert!(cache.is_empty(), "no rejections → no cache entries");
    }
}
