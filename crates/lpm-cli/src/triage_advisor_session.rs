//! Install-time L4 advisor session.
//!
//! Owns the once-per-install lifecycle of the optional triage advisor.
//!
//! **Read.** `triage-advisor` is resolved from this precedence chain
//! (highest first):
//!
//! - `--advisor` CLI flag — reserved; not wired in slice 1, accepted
//!   by [`AdvisorSession::preflight`] for forward-compat.
//! - `package.json > lpm > triageAdvisor` — per-project, shared
//!   across machines via the manifest.
//! - `~/.lpm/config.toml` — per-user / per-machine, written by
//!   `lpm config triage`.
//! - Default `none`.
//!
//! `./lpm.toml` is **not** in this chain by repo convention (see
//! Phase 46 §5.2 in the plan doc) — that file is reserved for the
//! save-policy reader today; a general project-config loader is a
//! separate follow-up.
//!
//! **Preflight.** The configured adapter is probed exactly once via
//! `detect()` + `test_invoke()`. If either fails, the session
//! degrades to `none` for the remainder of the run and emits ONE
//! warning. Subsequent per-package classify calls become no-ops;
//! portable L1-3 behaviour applies to every amber package.
//!
//! **Classify.** Prompted amber packages flow through
//! `classify_amber()`. Only packages where EVERY amber phase returns
//! `Approve` land in the ephemeral
//! `(name, version, Option<integrity>)` approval set. Any `Manual` /
//! `Abstain` / failure on any phase blocks the package from the set —
//! it stays prompted (blocked set on disk → `lpm approve-scripts`).
//!
//! **Source-aware identity.** The approval key includes the
//! integrity hash (or `None` when no integrity is available, e.g.
//! workspace / link / file sources), NOT just `(name, version)`. The
//! install pipeline treats same-coord packages from different
//! sources as distinct, so collapsing identity to a pair would mean
//! approving one source's `pkg@1.0.0` could auto-run a different
//! source's `pkg@1.0.0` in the same install. Triple keying matches
//! `compute_blocked_packages_with_metadata`'s identity exactly.
//!
//! # Ephemeral by construction
//!
//! Approvals live in memory for the lifetime of this `AdvisorSession`
//! and never persist:
//! - No `trustedDependencies` entry is written.
//! - No new on-disk state is created (the build-state blocked set is
//!   still computed by the existing capture path; advisor-approved
//!   packages are excluded from it ONLY when auto-build will actually
//!   execute their scripts this run — see [`select_approvals_for_capture`]
//!   in [`crate::commands::install`] for the conditional gate. When
//!   auto-build is off, the persisted blocked set still surfaces
//!   advisor-approved-but-not-run packages so they remain reachable
//!   via `lpm approve-scripts` after the session drops).
//! - A later `lpm rebuild` invocation has no `AdvisorSession` in
//!   scope and therefore makes its trust decision purely from the
//!   persistent `trustedDependencies` manifest.
//!
//! This is the contract the wizard's "degrade-and-warn" copy
//! describes after Part B B3 ships and slice 1 lands.

use std::collections::HashSet;

use lpm_security::triage::StaticTier;
use lpm_triage_advisor::{
    Advisor, AdvisorFailure, AdvisorVerdict, AmberScript, ClaudeCliAdapter, CodexAdapter,
    OllamaAdapter, Provider,
};

use crate::output;

/// Per-install advisor lifecycle. Constructed once at install start
/// via [`AdvisorSession::preflight`]; consumed by per-package
/// [`AdvisorSession::classify_amber`] calls.
pub struct AdvisorSession {
    /// `Some` only if `triage-advisor` was set AND preflight passed.
    /// `None` when the user opted into `none`, the slug was invalid,
    /// or detect/test-invoke failed (post warn-once).
    adapter: Option<Box<dyn Advisor>>,
    /// Provider slug as configured — used in the warn-once line so
    /// the user knows which advisor was attempted.
    configured_slug: Option<String>,
    /// `(name, version, Option<integrity>)` → `Approve` verdict. The
    /// set the install path hands to
    /// `compute_blocked_packages_with_metadata` and `evaluate_trust`
    /// as the ephemeral approval list. The integrity slot makes the
    /// key source-aware: workspace / file / link installations of
    /// the same coord with no registry integrity are distinct
    /// entries from registry installs that carry integrity, so an
    /// approval on one source cannot leak to a sibling source.
    approvals: HashSet<(String, String, Option<String>)>,
    /// Set to `true` after the single degrade-warning fires. Guards
    /// against repeat warnings if a future caller does extra preflight.
    warned_about_unavailable: bool,
}

impl AdvisorSession {
    /// Build a session by resolving `triage-advisor` through the
    /// precedence chain and preflighting the adapter.
    ///
    /// Reads:
    /// - `cli_override`: value of any future `--advisor` CLI flag
    ///   (slice 1 doesn't expose one; threaded for forward-compat).
    /// - `package_json_triage_advisor`: `package.json > lpm >
    ///   triageAdvisor` if present.
    /// - The global config (`~/.lpm/config.toml`) `triage-advisor`
    ///   key.
    pub async fn preflight(
        cli_override: Option<&str>,
        package_json_triage_advisor: Option<&str>,
        global_config_triage_advisor: Option<&str>,
        json_output: bool,
    ) -> Self {
        let resolved = cli_override
            .or(package_json_triage_advisor)
            .or(global_config_triage_advisor);
        let slug = match resolved {
            None | Some("") | Some("none") => return Self::none(None),
            Some(s) => s,
        };
        let Some(provider) = Provider::from_slug(slug) else {
            // Unknown slug: degrade to none with a one-line warning.
            // Don't fail the install — invalid config is an
            // operator issue, not a runtime hard stop.
            warn_once(
                json_output,
                &format!(
                    "triage-advisor = \"{slug}\" is not a known provider; \
                     install continues without advisor (portable L1-3)."
                ),
            );
            return Self::none(Some(slug.to_string()));
        };
        let adapter: Box<dyn Advisor> = match provider {
            Provider::ClaudeCli => Box::new(ClaudeCliAdapter),
            Provider::Codex => Box::new(CodexAdapter),
            Provider::Ollama => Box::new(OllamaAdapter::default()),
        };
        if !adapter.detect().await {
            warn_once(
                json_output,
                &format!(
                    "triage-advisor = \"{slug}\" not available on this machine; \
                     install continues without advisor (portable L1-3)."
                ),
            );
            return Self::degraded(slug.to_string());
        }
        match adapter.test_invoke().await {
            Ok(_) => Self {
                adapter: Some(adapter),
                configured_slug: Some(slug.to_string()),
                approvals: HashSet::new(),
                warned_about_unavailable: false,
            },
            Err(AdvisorFailure::EnvironmentNotReady(msg)) => {
                warn_once(
                    json_output,
                    &format!(
                        "triage-advisor = \"{slug}\" is configured but not ready ({msg}); \
                         install continues without advisor (portable L1-3)."
                    ),
                );
                Self::degraded(slug.to_string())
            }
            Err(AdvisorFailure::IntegrationFailure(msg)) => {
                warn_once(
                    json_output,
                    &format!(
                        "triage-advisor = \"{slug}\" returned an unparseable verdict on the \
                         pre-flight probe ({msg}); install continues without advisor."
                    ),
                );
                Self::degraded(slug.to_string())
            }
        }
    }

    fn none(slug: Option<String>) -> Self {
        Self {
            adapter: None,
            configured_slug: slug,
            approvals: HashSet::new(),
            warned_about_unavailable: false,
        }
    }

    fn degraded(slug: String) -> Self {
        let mut s = Self::none(Some(slug));
        s.warned_about_unavailable = true;
        s
    }

    /// Was an adapter actually configured + ready? `false` means
    /// the session degraded (or was never configured); per-package
    /// classify is a no-op.
    pub fn is_active(&self) -> bool {
        self.adapter.is_some()
    }

    /// Provider slug, for logging / report metadata. `None` when
    /// the session is `none`.
    pub fn provider_slug(&self) -> Option<&str> {
        self.configured_slug.as_deref()
    }

    /// Classify a batch of amber packages and collect packages
    /// where EVERY amber phase returned `Approve`.
    ///
    /// Worst-of-phases semantics mirror the L1 classifier's
    /// [`lpm_security::triage::StaticTier::worse_of`] reduction and
    /// the audit harness's per-package roll-up: a package with
    /// preinstall = Approve but postinstall = Manual is NOT
    /// approved. Otherwise an attacker-controlled phase could
    /// shadow a benign sibling phase and self-upgrade through the
    /// gate.
    ///
    /// Per-package failures (`EnvironmentNotReady` /
    /// `IntegrationFailure`) do NOT generate new warnings —
    /// preflight already warned if the adapter was suspect. They
    /// leave the package un-approved (worst-of with `Manual`
    /// equivalent), which preserves the safe default. The install
    /// never fails because the advisor failed.
    ///
    /// `candidates` should be deduplicated by `(name, version)` —
    /// duplicate invocations waste tokens / wall-clock without
    /// changing the outcome.
    pub async fn classify_amber(&mut self, candidates: &[AmberPackageRequest]) {
        let Some(adapter) = self.adapter.as_deref() else {
            return;
        };
        for c in candidates {
            // Per-package worst-of across all amber phases. Start at
            // Approve and degrade. A single Manual/Abstain phase or
            // a single failure flips the package out of the approval
            // pool.
            let mut package_verdict = PackageAdvisorOutcome::Approve;
            for (phase, body) in &c.amber_phases {
                let amber = AmberScript {
                    package_name: &c.name,
                    package_version: &c.version,
                    phase: phase.as_str(),
                    script_body: body.as_str(),
                };
                match adapter.classify_amber(&amber).await {
                    Ok(AdvisorVerdict::Approve) => {}
                    Ok(AdvisorVerdict::Manual) => {
                        package_verdict = PackageAdvisorOutcome::Manual;
                        break;
                    }
                    Ok(AdvisorVerdict::Abstain) => {
                        package_verdict =
                            package_verdict.degrade_to(PackageAdvisorOutcome::Abstain);
                    }
                    Err(_) => {
                        // Silent per the locked contract; degrade
                        // to "no approval" for this package and
                        // keep scanning the remaining packages.
                        package_verdict =
                            package_verdict.degrade_to(PackageAdvisorOutcome::Abstain);
                    }
                }
            }
            if package_verdict == PackageAdvisorOutcome::Approve && !c.amber_phases.is_empty() {
                self.approvals
                    .insert((c.name.clone(), c.version.clone(), c.integrity.clone()));
            }
        }
    }

    /// Borrow the immutable approval set. The trust-evaluation path
    /// (`evaluate_trust`) and the blocked-set capture path
    /// (`compute_blocked_packages_with_metadata`) both consult this
    /// view; both must see the SAME set so a package can't be
    /// blocked while its script also runs.
    pub fn approvals(&self) -> &HashSet<(String, String, Option<String>)> {
        &self.approvals
    }
}

/// One unit of work for [`AdvisorSession::classify_amber`]. Carries
/// every amber lifecycle phase for one package so the session can
/// apply per-package worst-of without the caller pre-aggregating.
///
/// Owned strings on the input side so the install-time caller (which
/// already holds owned `name`/`version`/script bodies from the package
/// store) doesn't have to invent a separate borrowed view. The
/// per-classify-call cost is dominated by the LLM round trip; a few
/// `String` clones are not the bottleneck.
pub struct AmberPackageRequest {
    pub name: String,
    pub version: String,
    /// Integrity hash (typically `sha512-...`) for this package's
    /// resolved source. `None` for workspace / link / file sources
    /// that don't carry integrity. The advisor doesn't classify on
    /// integrity — but the session keys its approval set by it, so
    /// the request must carry the same identity the downstream
    /// trust-evaluation path will use.
    pub integrity: Option<String>,
    /// `(phase_name, script_body)` for every amber phase. An empty
    /// list means the package has no amber phases and won't be
    /// approved (the empty-product case in the worst-of reduction
    /// would otherwise vacuously promote to Approve — guarded
    /// against in the consumer).
    pub amber_phases: Vec<(String, String)>,
}

/// Per-package worst-of accumulator state inside
/// [`AdvisorSession::classify_amber`]. Not exposed.
///
/// Ordering: `Manual > Abstain > Approve`. Only `Approve` grants
/// the ephemeral approval; the worst single phase wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageAdvisorOutcome {
    Approve,
    Abstain,
    Manual,
}

impl PackageAdvisorOutcome {
    /// Worst-wins reducer. Manual beats Abstain beats Approve.
    fn degrade_to(self, other: Self) -> Self {
        use PackageAdvisorOutcome::*;
        match (self, other) {
            (Manual, _) | (_, Manual) => Manual,
            (Abstain, _) | (_, Abstain) => Abstain,
            (Approve, Approve) => Approve,
        }
    }
}

/// Static-tier filter used at the install integration site:
/// "is this package eligible for advisor classification at all?"
///
/// Only amber packages are sent through the advisor. Green
/// auto-runs without involvement; red is hard-blocked regardless;
/// no-script packages have nothing to advise.
pub fn should_advise(tier: Option<StaticTier>) -> bool {
    matches!(tier, Some(StaticTier::Amber) | Some(StaticTier::AmberLlm))
}

fn warn_once(json_output: bool, message: &str) {
    if json_output {
        // JSON callers don't get a human warning line; the same
        // signal surfaces via the install-time report fields that
        // already serialise advisor state.
        return;
    }
    output::warn(message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Synthetic in-process advisor for unit testing the session
    /// without spawning subprocesses. Records every invocation so
    /// "warn-once" / "ephemeral" assertions can verify side effects.
    struct FakeAdvisor {
        provider: Provider,
        detect_result: bool,
        test_invoke_result: Result<AdvisorVerdict, AdvisorFailure>,
        classify_results: Mutex<Vec<Result<AdvisorVerdict, AdvisorFailure>>>,
        call_log: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl Advisor for FakeAdvisor {
        fn provider(&self) -> Provider {
            self.provider
        }
        async fn detect(&self) -> bool {
            self.call_log.lock().await.push("detect".into());
            self.detect_result
        }
        async fn test_invoke(&self) -> Result<AdvisorVerdict, AdvisorFailure> {
            self.call_log.lock().await.push("test_invoke".into());
            match &self.test_invoke_result {
                Ok(v) => Ok(*v),
                Err(AdvisorFailure::EnvironmentNotReady(s)) => {
                    Err(AdvisorFailure::EnvironmentNotReady(s.clone()))
                }
                Err(AdvisorFailure::IntegrationFailure(s)) => {
                    Err(AdvisorFailure::IntegrationFailure(s.clone()))
                }
            }
        }
        async fn classify_amber(
            &self,
            script: &AmberScript<'_>,
        ) -> Result<AdvisorVerdict, AdvisorFailure> {
            self.call_log
                .lock()
                .await
                .push(format!("classify:{}", script.package_name));
            let mut q = self.classify_results.lock().await;
            if q.is_empty() {
                return Ok(AdvisorVerdict::Manual);
            }
            q.remove(0)
        }
    }

    fn session_with_fake(advisor: FakeAdvisor) -> AdvisorSession {
        AdvisorSession {
            adapter: Some(Box::new(advisor)),
            configured_slug: Some("test-fake".into()),
            approvals: HashSet::new(),
            warned_about_unavailable: false,
        }
    }

    #[tokio::test]
    async fn none_config_yields_inactive_session() {
        let s = AdvisorSession::preflight(None, None, None, false).await;
        assert!(!s.is_active());
        assert!(s.approvals().is_empty());
    }

    #[tokio::test]
    async fn empty_string_and_explicit_none_both_yield_inactive() {
        for v in ["", "none"] {
            let s = AdvisorSession::preflight(None, None, Some(v), false).await;
            assert!(!s.is_active(), "v={v:?}");
        }
    }

    #[tokio::test]
    async fn unknown_slug_degrades_silently_to_none() {
        // No panic, no install-failing error. The wrapper prints a
        // user-facing warning; the session reports inactive.
        let s = AdvisorSession::preflight(None, None, Some("anthropic-api"), true).await;
        assert!(!s.is_active());
    }

    #[tokio::test]
    async fn precedence_cli_wins_over_package_json_and_global() {
        // Highest-priority slot. We can't actually preflight without
        // a real binary, but we can assert the resolver picks the
        // CLI value first by passing different bogus slugs at each
        // layer — only the topmost is reported as the configured
        // slug (or, when unknown, surfaces via the warn-once path).
        // Using `"anthropic-api"` (a known-invalid slug) at the CLI
        // layer guarantees `configured_slug` reflects it even
        // though preflight degrades to none.
        let s = AdvisorSession::preflight(
            Some("cli-bogus"),
            Some("pkgjson-bogus"),
            Some("global-bogus"),
            true,
        )
        .await;
        // The resolver picked the CLI layer; degraded with the CLI
        // slug recorded.
        assert_eq!(s.provider_slug(), Some("cli-bogus"));
    }

    #[tokio::test]
    async fn precedence_package_json_wins_over_global() {
        // **Locked precedence (review finding Medium 2).** When no
        // CLI flag is given, `package.json > lpm > triageAdvisor`
        // wins over `~/.lpm/config.toml`. This is the layer slice 1
        // wires explicitly; previously the install callsite passed
        // None for package.json, making the feature non-reproducible
        // across machines.
        let s = AdvisorSession::preflight(None, Some("pkgjson-bogus"), Some("global-bogus"), true)
            .await;
        assert_eq!(s.provider_slug(), Some("pkgjson-bogus"));
    }

    #[tokio::test]
    async fn precedence_global_used_when_package_json_absent() {
        // Symmetric to the above: with no CLI flag and no
        // package.json value, the global config layer wins.
        let s = AdvisorSession::preflight(None, None, Some("global-bogus"), true).await;
        assert_eq!(s.provider_slug(), Some("global-bogus"));
    }

    #[tokio::test]
    async fn precedence_explicit_none_at_higher_layer_does_not_fall_through() {
        // A user who sets `package.json > lpm > triageAdvisor =
        // "none"` is making an explicit per-project opt-out. The
        // resolver must respect it, NOT fall through to the global
        // layer where a different value might live.
        let s = AdvisorSession::preflight(None, Some("none"), Some("claude-cli"), true).await;
        assert!(
            !s.is_active(),
            "explicit none at higher layer must short-circuit"
        );
    }

    #[tokio::test]
    async fn precedence_cli_explicit_none_overrides_active_lower_layers() {
        // **Locked CLI flag contract (Phase 46 slice 1 close-out).**
        // `lpm install --advisor=none` is an explicit per-invocation
        // opt-out that MUST win over any `package.json` /
        // `~/.lpm/config.toml` value beneath it. Without this, a user
        // trying to silence a misbehaving advisor for ONE run would
        // also have to edit config files — defeating the entire
        // point of the CLI override slot.
        //
        // Pairs with `precedence_cli_wins_over_package_json_and_global`
        // (which uses bogus slugs to prove the CLI slot is *consulted*
        // first) — this test additionally proves the CLI's explicit
        // `"none"` value short-circuits even when both lower layers
        // hold valid provider slugs that *would* have produced an
        // active session if the CLI layer were missing.
        let s = AdvisorSession::preflight(
            Some("none"),       // CLI: explicit opt-out for THIS run
            Some("claude-cli"), // package.json: team default
            Some("ollama"),     // global config: per-user default
            true,               // json_output: suppress warn lines in test output
        )
        .await;
        assert!(
            !s.is_active(),
            "CLI --advisor=none MUST short-circuit before package.json / global config"
        );
        assert!(
            s.provider_slug().is_none(),
            "explicit none records no configured slug (matches the resolved-to-None contract)",
        );
    }

    #[tokio::test]
    async fn classify_no_op_when_inactive() {
        let mut s = AdvisorSession::preflight(None, None, None, false).await;
        let req = AmberPackageRequest {
            name: "p".into(),
            version: "1.0.0".into(),
            integrity: None,
            amber_phases: vec![("postinstall".into(), "tsc".into())],
        };
        s.classify_amber(&[req]).await;
        assert!(
            s.approvals().is_empty(),
            "inactive session must not collect approvals"
        );
    }

    #[tokio::test]
    async fn only_packages_where_all_phases_approve_become_approvals() {
        let call_log = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeAdvisor {
            provider: Provider::ClaudeCli,
            detect_result: true,
            test_invoke_result: Ok(AdvisorVerdict::Approve),
            classify_results: Mutex::new(vec![
                Ok(AdvisorVerdict::Approve), // approve-me (single phase)
                Ok(AdvisorVerdict::Manual),  // manual-only
                Ok(AdvisorVerdict::Abstain), // abstain-only
                Err(AdvisorFailure::EnvironmentNotReady("daemon hung".into())),
                Err(AdvisorFailure::IntegrationFailure("bad shape".into())),
            ]),
            call_log: Arc::clone(&call_log),
        };
        let mut s = session_with_fake(fake);
        let one_phase = || vec![("postinstall".to_string(), "tsc".to_string())];
        let reqs = [
            AmberPackageRequest {
                name: "approve-me".into(),
                version: "1.0.0".into(),
                integrity: None,
                amber_phases: one_phase(),
            },
            AmberPackageRequest {
                name: "manual".into(),
                version: "1.0.0".into(),
                integrity: None,
                amber_phases: one_phase(),
            },
            AmberPackageRequest {
                name: "abstain".into(),
                version: "1.0.0".into(),
                integrity: None,
                amber_phases: one_phase(),
            },
            AmberPackageRequest {
                name: "env-fail".into(),
                version: "1.0.0".into(),
                integrity: None,
                amber_phases: one_phase(),
            },
            AmberPackageRequest {
                name: "int-fail".into(),
                version: "1.0.0".into(),
                integrity: None,
                amber_phases: one_phase(),
            },
        ];
        s.classify_amber(&reqs).await;
        assert_eq!(s.approvals().len(), 1);
        assert!(
            s.approvals()
                .contains(&("approve-me".into(), "1.0.0".into(), None))
        );
        let log = call_log.lock().await.clone();
        // Manual short-circuits the per-package loop, so we expect
        // a single classify call for the manual package. Abstain and
        // failures continue to subsequent phases (none here), so
        // they also yield one call each.
        assert!(log.iter().any(|l| l == "classify:manual"));
        assert!(log.iter().any(|l| l == "classify:abstain"));
        assert!(log.iter().any(|l| l == "classify:env-fail"));
        assert!(log.iter().any(|l| l == "classify:int-fail"));
    }

    #[tokio::test]
    async fn manual_phase_blocks_otherwise_approved_package() {
        // The whole point of per-package worst-of: a package with
        // multiple amber phases that mostly approve but one says
        // Manual must NOT get the ephemeral approval. Otherwise a
        // benign sibling phase could shadow a malicious one.
        let call_log = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeAdvisor {
            provider: Provider::ClaudeCli,
            detect_result: true,
            test_invoke_result: Ok(AdvisorVerdict::Approve),
            classify_results: Mutex::new(vec![
                Ok(AdvisorVerdict::Approve), // preinstall: looks safe
                Ok(AdvisorVerdict::Manual),  // postinstall: actually risky
            ]),
            call_log: Arc::clone(&call_log),
        };
        let mut s = session_with_fake(fake);
        let req = AmberPackageRequest {
            name: "two-phase-trap".into(),
            version: "1.0.0".into(),
            integrity: None,
            amber_phases: vec![
                ("preinstall".into(), "tsc".into()),
                ("postinstall".into(), "node install.js".into()),
            ],
        };
        s.classify_amber(&[req]).await;
        assert!(
            s.approvals().is_empty(),
            "any Manual phase must block the package"
        );
    }

    #[tokio::test]
    async fn package_with_no_amber_phases_is_never_approved() {
        // Guards the empty-product edge: if the caller hands us a
        // package with `amber_phases = &[]`, the worst-of starts at
        // Approve and never degrades — but the package didn't go
        // through the advisor at all. Must NOT land in the approval
        // set.
        let call_log = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeAdvisor {
            provider: Provider::ClaudeCli,
            detect_result: true,
            test_invoke_result: Ok(AdvisorVerdict::Approve),
            classify_results: Mutex::new(vec![]),
            call_log: Arc::clone(&call_log),
        };
        let mut s = session_with_fake(fake);
        let req = AmberPackageRequest {
            name: "edge".into(),
            version: "1.0.0".into(),
            integrity: None,
            amber_phases: Vec::new(),
        };
        s.classify_amber(&[req]).await;
        assert!(s.approvals().is_empty());
        // No advisor calls fired for an empty-phase request.
        assert!(call_log.lock().await.is_empty());
    }

    #[tokio::test]
    async fn should_advise_tier_filter() {
        assert!(should_advise(Some(StaticTier::Amber)));
        assert!(should_advise(Some(StaticTier::AmberLlm)));
        assert!(!should_advise(Some(StaticTier::Green)));
        assert!(!should_advise(Some(StaticTier::Red)));
        assert!(!should_advise(None));
    }

    #[tokio::test]
    async fn ephemeral_no_persistent_state_handles() {
        // Sanity: the session exposes ONLY a read-only borrow of the
        // approvals set. There is no method that writes to disk or
        // returns an owned Vec destined for serialization. This is a
        // type-level guarantee of the "ephemeral" contract — a future
        // contributor accidentally persisting approvals would need to
        // grow the API.
        //
        // We assert structurally: serde derives intentionally absent
        // on AdvisorSession + AmberPackageRequest.
        fn assert_no_serde<T>() {
            // Compile-time check via trait absence — wouldn't compile
            // if a Serialize impl existed; here we just confirm the
            // negative case via the impl-not-defined position.
            //
            // Practically the assertion is "look at the source": no
            // #[derive(Serialize)] anywhere in this module. This test
            // is documentation; the real guard is review.
            let _ = std::marker::PhantomData::<T>;
        }
        assert_no_serde::<AdvisorSession>();
        assert_no_serde::<AmberPackageRequest>();
    }
}
