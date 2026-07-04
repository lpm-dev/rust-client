//! Install-time L4 advisor session.
//!
//! Owns the once-per-install lifecycle of the optional triage advisor.
//!
//! **Read.** `triage-advisor` is resolved from this precedence chain
//! (highest first):
//!
//! - `--advisor` CLI flag — per-run override, accepted
//!   by [`AdvisorSession::preflight`].
//! - `package.json > lpm > triageAdvisor` — per-project, shared
//!   across machines via the manifest.
//! - `~/.lpm/config.toml` — per-user / per-machine, written by
//!   `lpm config triage`.
//! - Default `none`.
//!
//! `./lpm.toml` is **not** in this chain by repo convention (see
//! in the plan doc) — that file is reserved for the
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
//! This is the contract the wizard's "degrade-and-warn" copy describes.

use std::collections::HashSet;
use std::sync::Arc;

use futures::StreamExt;
use lpm_security::triage::StaticTier;
use lpm_triage_advisor::{
    Advisor, AdvisorFailure, AdvisorVerdict, AmberScript, CacheKeyInputs, ClaudeCliAdapter,
    CodexAdapter, L4Cache, OllamaAdapter, Provider, build_cache_key, prompt_template_hash,
    provider_version,
};

use crate::output;

/// Type alias for the ephemeral advisor approval key.
///
/// M29: keyed on `(name, version, integrity, script_bundle_hash)`.
/// The script-bundle hash folds every `(phase, body)` pair the
/// advisor evaluated into a SHA-256 digest. Today the same digest
/// applies to every script of the package (whole-package
/// classification); if a future refactor moves to per-phase
/// classification, the key automatically distinguishes them. The
/// integrity slot keeps source-aware identity (so a workspace
/// `pkg@1` is distinct from a registry `pkg@1`); the bundle-hash
/// slot keeps script-aware identity (so an approval can't leak to
/// a sibling phase or to a different script body that happens to
/// share the same package coordinate).
pub type AdvisorApprovalKey = (String, String, Option<String>, String);

/// Hash an ordered `(phase, body)` slice into a hex SHA-256 digest.
/// Used to fold script bodies into [`AdvisorApprovalKey`].
///
/// Order is preserved (the caller passes phases in
/// `EXECUTED_INSTALL_PHASES` order, matching `compute_script_hash`'s
/// phase ordering). Distinct field separators (`0x1e` records,
/// `0x00` fields) prevent the `phase="ab" body="cd"` /
/// `phase="abc" body="d"` ambiguity that naive concatenation would
/// have.
pub fn compute_script_bundle_hash(amber_phases: &[(String, String)]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for (phase, body) in amber_phases {
        hasher.update(phase.as_bytes());
        hasher.update([0x00]);
        hasher.update(body.as_bytes());
        hasher.update([0x1e]);
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod bundle_hash_tests {
    use super::compute_script_bundle_hash;

    /// M29: identical phase lists hash identically.
    #[test]
    fn bundle_hash_is_deterministic_for_same_input() {
        let a = vec![("preinstall".into(), "echo a".into())];
        assert_eq!(
            compute_script_bundle_hash(&a),
            compute_script_bundle_hash(&a)
        );
    }

    /// M29: different script body → different bundle hash. Pins the
    /// per-script identity property the approval key is supposed to
    /// guarantee against a future per-phase refactor.
    #[test]
    fn bundle_hash_changes_when_body_changes() {
        let a = vec![("preinstall".into(), "echo a".into())];
        let b = vec![("preinstall".into(), "echo b".into())];
        assert_ne!(
            compute_script_bundle_hash(&a),
            compute_script_bundle_hash(&b)
        );
    }

    /// Different phase → different hash, even with identical body.
    #[test]
    fn bundle_hash_changes_when_phase_changes() {
        let a = vec![("preinstall".into(), "echo a".into())];
        let b = vec![("postinstall".into(), "echo a".into())];
        assert_ne!(
            compute_script_bundle_hash(&a),
            compute_script_bundle_hash(&b)
        );
    }

    /// Order matters — `[a, b]` and `[b, a]` hash differently.
    #[test]
    fn bundle_hash_changes_with_phase_order() {
        let a = vec![
            ("preinstall".into(), "echo one".into()),
            ("postinstall".into(), "echo two".into()),
        ];
        let b = vec![
            ("postinstall".into(), "echo two".into()),
            ("preinstall".into(), "echo one".into()),
        ];
        assert_ne!(
            compute_script_bundle_hash(&a),
            compute_script_bundle_hash(&b)
        );
    }

    /// Distinct field separators close the
    /// `phase="ab" body="cd"` vs `phase="abc" body="d"`
    /// concatenation-ambiguity gap.
    #[test]
    fn bundle_hash_disambiguates_field_boundaries() {
        let a = vec![("ab".into(), "cd".into())];
        let b = vec![("abc".into(), "d".into())];
        assert_ne!(
            compute_script_bundle_hash(&a),
            compute_script_bundle_hash(&b)
        );
    }

    /// Empty bundle still produces a stable hash (used as the
    /// "no amber phases" sentinel — `has_phases` filters them out at
    /// the call site, but the helper must still be total).
    #[test]
    fn bundle_hash_empty_input_is_stable() {
        let empty: Vec<(String, String)> = Vec::new();
        let h1 = compute_script_bundle_hash(&empty);
        let h2 = compute_script_bundle_hash(&empty);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "32-byte SHA-256 encoded as 64 hex chars");
    }
}

/// Max in-flight advisor classifications inside
/// [`AdvisorSession::classify_amber`]. parallelization
/// : pre-parallelization, packages were classified one
/// after another and a 10-amber install paid 10 × LLM round-trip.
/// Post-parallelization, we cap at this many in-flight calls so:
/// - local providers (Ollama) don't get queue-saturated (one
///   inference task per call already saturates a single GPU; running
///   more in parallel just stalls in the model server's queue),
/// - cloud providers stay comfortably below typical per-IP rate
///   limits (Claude / Codex / similar advisor endpoints all tolerate
///   single-digit concurrent requests),
/// - the install pipeline's progress UI keeps the wall-clock honest
///   (the dominant amber count on real installs is 1-5, so 8 covers
///   every workload-size we've seen without spinning extra futures).
///
/// Single-amber installs the DX benchmark are unchanged
/// by this concurrency — there's only one task to drive. The win
/// shows up at amber-count ≥ 2.
const CLASSIFY_CONCURRENCY: usize = 8;

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
    approvals: HashSet<AdvisorApprovalKey>,
    /// Set to `true` after the single degrade-warning fires. Guards
    /// against repeat warnings if a future caller does extra preflight.
    warned_about_unavailable: bool,
    /// — L4 verdict cache. Shared across the parallel
    /// classify tasks via [`Arc`]. `None` when the cache could not be
    /// opened (e.g. no resolvable HOME) — the session falls back to
    /// uncached classification with a one-line warning, never
    /// failing the install over a cache problem. Disabled-via-env
    /// shows up as `Some(cache_disabled)` rather than `None`; both
    /// short-circuit lookup/insert to no-ops.
    cache: Option<Arc<L4Cache>>,
    /// Cached prompt-template hash (computed once at preflight).
    /// Folded into every cache key so a template change auto-
    /// invalidates the prior verdicts.
    prompt_template_hash: String,
    /// Cached provider-version string (probed once at preflight via
    /// `provider_version`). Empty when the probe failed; the empty
    /// string still folds into the cache key, so a future successful
    /// probe with a real version will simply miss the prior entries
    /// rather than collide.
    model_version: String,
}

impl AdvisorSession {
    /// Build a session by resolving `triage-advisor` through the
    /// precedence chain and preflighting the adapter.
    ///
    /// Reads:
    /// - `cli_override`: value of the `--advisor` CLI flag
    ///   (threaded for forward-compat; `None` when not provided).
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
            Ok(_) => {
                // — open the L4 cache once at preflight.
                // Probe provider_version + prompt_template_hash here
                // so the per-package classify path doesn't repeat
                // them. Cache-open failure is non-fatal: the install
                // continues without a cache.
                let cache = open_cache_or_warn(json_output);
                let model_version = provider_version(provider).await.unwrap_or_default();
                let template_hash = prompt_template_hash();
                Self {
                    adapter: Some(adapter),
                    configured_slug: Some(slug.to_string()),
                    approvals: HashSet::new(),
                    warned_about_unavailable: false,
                    cache,
                    prompt_template_hash: template_hash,
                    model_version,
                }
            }
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
            cache: None,
            prompt_template_hash: String::new(),
            model_version: String::new(),
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

        // parallelization : fan out one task
        // per candidate package across the advisor concurrently. The
        // `Advisor` trait is `Send + Sync` and `classify_amber`
        // takes `&self`, so concurrent calls are safe; only the
        // per-package outcome accumulator mutates locals.
        //
        // Within a package, phases still iterate serially because
        // the `Manual` short-circuit (worst-of with early exit) is a
        // real win when phase 1 already disqualifies the package —
        // no point spending an LLM round-trip on phase 2 just to
        // discard the result. Phases per package are usually 1, so
        // the within-package serialization is a non-issue.
        //
        // Bounded concurrency: cap at [`CLASSIFY_CONCURRENCY`] so
        // local providers (Ollama) don't get queue-saturated and
        // cloud providers stay below typical rate limits. The
        // case (1 amber package) is unchanged; the win is on
        // installs with several amber-tier deps. Pre-parallelization
        // the cost was N × round-trip; post-parallelization it's
        // ceil(N / CONCURRENCY) × round-trip.
        //
        // L4 cache: lookup before the LLM call, insert
        // after. Cached hits skip the round-trip entirely; misses
        // pay the round-trip once and amortize on every later
        // install. The cache is `Arc`-shared across the `buffer_
        // unordered` tasks; lookup + insert hold the inner mutex
        // for a tiny critical section (no LLM call while holding).
        //
        // Outcomes flow back through the stream and the approval
        // insertions happen serially after collection — that keeps
        // `self.approvals` mutation single-threaded without locks.
        let provider_slug = self.configured_slug.clone().unwrap_or_default();
        let template_hash = self.prompt_template_hash.clone();
        let model_version = self.model_version.clone();
        let cache = self.cache.clone();

        let results: Vec<(
            String,
            String,
            Option<String>,
            String,
            PackageAdvisorOutcome,
            bool,
        )> = futures::stream::iter(candidates.iter().map(|c| {
            let cache = cache.clone();
            let provider_slug = provider_slug.clone();
            let template_hash = template_hash.clone();
            let model_version = model_version.clone();
            async move {
                let cache_key =
                    build_package_cache_key(c, &template_hash, &provider_slug, &model_version);

                // Fast path: cache hit. Map a single cached
                // verdict to the package-level outcome and skip
                // the LLM round-trip.
                if let Some(cache) = cache.as_deref()
                    && let Some(verdict) = cache.lookup(&cache_key)
                {
                    let outcome = match verdict {
                        AdvisorVerdict::Approve => PackageAdvisorOutcome::Approve,
                        AdvisorVerdict::Manual => PackageAdvisorOutcome::Manual,
                        AdvisorVerdict::Abstain => PackageAdvisorOutcome::Abstain,
                    };
                    return (
                        c.name.clone(),
                        c.version.clone(),
                        c.integrity.clone(),
                        compute_script_bundle_hash(&c.amber_phases),
                        outcome,
                        !c.amber_phases.is_empty(),
                    );
                }

                // Borrow the referenced-file content as a slice of
                // `ReferencedScript` so the prompt's "Referenced files"
                // section can render the embedded view.
                let referenced: Vec<lpm_triage_advisor::ReferencedScript<'_>> = c
                    .referenced_scripts
                    .iter()
                    .map(|(filename, content)| lpm_triage_advisor::ReferencedScript {
                        filename: filename.as_str(),
                        content: content.as_str(),
                    })
                    .collect();
                let mut package_verdict = PackageAdvisorOutcome::Approve;
                for (phase, body) in &c.amber_phases {
                    let amber = AmberScript {
                        package_name: &c.name,
                        package_version: &c.version,
                        phase: phase.as_str(),
                        script_body: body.as_str(),
                        repository: c.repository.as_deref(),
                        referenced_scripts: &referenced,
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
                            // Silent per the locked contract;
                            // degrade to "no approval" for this
                            // package and keep scanning the
                            // remaining packages. Per-package
                            // failures are NOT cached — a
                            // future re-install may succeed.
                            package_verdict =
                                package_verdict.degrade_to(PackageAdvisorOutcome::Abstain);
                            return (
                                c.name.clone(),
                                c.version.clone(),
                                c.integrity.clone(),
                                compute_script_bundle_hash(&c.amber_phases),
                                package_verdict,
                                !c.amber_phases.is_empty(),
                            );
                        }
                    }
                }

                // Persist this package's final verdict to the
                // cache (insert is cheap; persist happens once
                // at the end of the session). Map back to the
                // raw verdict for storage.
                if let Some(cache) = cache.as_deref() {
                    let stored = match package_verdict {
                        PackageAdvisorOutcome::Approve => AdvisorVerdict::Approve,
                        PackageAdvisorOutcome::Manual => AdvisorVerdict::Manual,
                        PackageAdvisorOutcome::Abstain => AdvisorVerdict::Abstain,
                    };
                    cache.insert(
                        cache_key,
                        stored,
                        &provider_slug,
                        &model_version,
                        &template_hash,
                    );
                }

                (
                    c.name.clone(),
                    c.version.clone(),
                    c.integrity.clone(),
                    compute_script_bundle_hash(&c.amber_phases),
                    package_verdict,
                    !c.amber_phases.is_empty(),
                )
            }
        }))
        .buffer_unordered(CLASSIFY_CONCURRENCY)
        .collect()
        .await;

        // Serial application of approvals — single-thread mutation,
        // no locks. Order doesn't matter because the approval set is
        // a `HashSet` keyed by
        // `(name, version, integrity, script_bundle_hash)`.
        for (name, version, integrity, script_bundle_hash, outcome, has_phases) in results {
            if outcome == PackageAdvisorOutcome::Approve && has_phases {
                self.approvals
                    .insert((name, version, integrity, script_bundle_hash));
            }
        }

        // — write the cache back to disk once per session.
        // Failure to persist is non-fatal: in-memory cache is still
        // populated, but next install starts cold.
        if let Some(cache) = self.cache.as_deref()
            && let Err(e) = cache.persist()
        {
            tracing::warn!(
                target: "lpm_cli::triage_advisor_session::cache",
                path = %cache.path().display(),
                error = %e,
                "could not persist l4 verdict cache; next install will start cold"
            );
        }
    }

    /// Borrow the immutable approval set. The trust-evaluation path
    /// (`evaluate_trust`) and the blocked-set capture path
    /// (`compute_blocked_packages_with_metadata`) both consult this
    /// view; both must see the SAME set so a package can't be
    /// blocked while its script also runs.
    pub fn approvals(&self) -> &HashSet<AdvisorApprovalKey> {
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
    /// `repository` URL from the package manifest (typically
    /// `package.json > repository.url` or the
    /// legacy shorthand string). Forwarded to the advisor prompt as
    /// the `Repository:` line; pairs with the "fetch IDENTITY"
    /// rule so the model can approve delegate-to-local-file
    /// installers when the repository host owns the package
    /// identity. `None` when the manifest doesn't declare one — the
    /// prompt renders `<none>` so the model knows the field is
    /// missing, not stripped.
    pub repository: Option<String>,
    /// `(phase_name, script_body)` for every amber phase. An empty
    /// list means the package has no amber phases and won't be
    /// approved (the empty-product case in the worst-of reduction
    /// would otherwise vacuously promote to Approve — guarded
    /// against in the consumer).
    pub amber_phases: Vec<(String, String)>,
    /// Files the script body delegates to, each as `(filename, content)`.
    /// The advisor prompt's
    /// "Referenced files" section embeds these so the model can
    /// evaluate the actual fetch / build / payload, not just the
    /// delegating one-liner. Empty when the body doesn't delegate
    /// or when caps (depth, size, binary detection, path safety)
    /// reject every candidate file. See
    /// `crate::build_state::collect_referenced_scripts` for the
    /// caller-side caps.
    pub referenced_scripts: Vec<(String, String)>,
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

/// — best-effort cache open for the install-pipeline
/// session. A failure (no resolvable HOME, IO error) emits a
/// one-line warning and degrades to "no cache" rather than failing
/// the install. The cache module's `LPM_L4_CACHE=0` env var disables
/// the cache via its own internal check — that path returns `Some`
/// with a no-op cache so callers don't need an extra branch.
fn open_cache_or_warn(json_output: bool) -> Option<Arc<L4Cache>> {
    match L4Cache::open_default() {
        Ok(cache) => Some(Arc::new(cache)),
        Err(e) => {
            warn_once(
                json_output,
                &format!(
                    "could not open l4 verdict cache ({e}); install continues without \
                     cache acceleration."
                ),
            );
            None
        }
    }
}

/// — build the L4-cache key for one [`AmberPackageRequest`].
/// Borrows the request's owned strings without copying. Folds in the
/// repository URL and the referenced-scripts content so a manifest
/// that adds, removes, or changes any of those produces a different
/// cache slot — the verdict can
/// legitimately differ on those axes.
fn build_package_cache_key(
    c: &AmberPackageRequest,
    prompt_template_hash: &str,
    provider_slug: &str,
    model_version: &str,
) -> String {
    let phases: Vec<(&str, &str)> = c
        .amber_phases
        .iter()
        .map(|(phase, body)| (phase.as_str(), body.as_str()))
        .collect();
    let refs: Vec<(&str, &str)> = c
        .referenced_scripts
        .iter()
        .map(|(filename, content)| (filename.as_str(), content.as_str()))
        .collect();
    build_cache_key(&CacheKeyInputs {
        package_name: &c.name,
        package_version: &c.version,
        amber_phases: &phases,
        repository: c.repository.as_deref(),
        referenced_scripts: &refs,
        prompt_template_hash,
        provider_slug,
        model_version,
    })
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
            // Tests don't exercise the cache; pass `None` so lookups
            // miss and inserts no-op. The cache-specific behavior is
            // tested in `lpm-triage-advisor::l4_cache` and in the
            // session-level cache tests below.
            cache: None,
            prompt_template_hash: String::new(),
            model_version: String::new(),
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
        // wins over `~/.lpm/config.toml`. Previously the install callsite passed
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
        // **Locked CLI flag contract.**
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
            repository: None,
            referenced_scripts: Vec::new(),
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
                repository: None,
                referenced_scripts: Vec::new(),
                amber_phases: one_phase(),
            },
            AmberPackageRequest {
                name: "manual".into(),
                version: "1.0.0".into(),
                integrity: None,
                repository: None,
                referenced_scripts: Vec::new(),
                amber_phases: one_phase(),
            },
            AmberPackageRequest {
                name: "abstain".into(),
                version: "1.0.0".into(),
                integrity: None,
                repository: None,
                referenced_scripts: Vec::new(),
                amber_phases: one_phase(),
            },
            AmberPackageRequest {
                name: "env-fail".into(),
                version: "1.0.0".into(),
                integrity: None,
                repository: None,
                referenced_scripts: Vec::new(),
                amber_phases: one_phase(),
            },
            AmberPackageRequest {
                name: "int-fail".into(),
                version: "1.0.0".into(),
                integrity: None,
                repository: None,
                referenced_scripts: Vec::new(),
                amber_phases: one_phase(),
            },
        ];
        s.classify_amber(&reqs).await;
        assert_eq!(s.approvals().len(), 1);
        // M29: approval key includes the script-bundle hash. Today
        // the bundle is `[("preinstall", "echo approve-me")]`; verify
        // the entry exists by matching on the first three fields.
        assert!(
            s.approvals()
                .iter()
                .any(|(n, v, i, _)| { n == "approve-me" && v == "1.0.0" && i.is_none() })
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
            repository: None,
            referenced_scripts: Vec::new(),
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
            repository: None,
            referenced_scripts: Vec::new(),
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

    /// Synthetic slow advisor for the parallelism test. Holds for
    /// `delay` on every `classify_amber` call so a serial-vs-parallel
    /// wall-clock difference is detectable. Always returns
    /// `Approve` so we don't need to coordinate a result queue
    /// across concurrent callers.
    struct SlowFakeAdvisor {
        delay: std::time::Duration,
        call_count: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Advisor for SlowFakeAdvisor {
        fn provider(&self) -> Provider {
            Provider::ClaudeCli
        }
        async fn detect(&self) -> bool {
            true
        }
        async fn test_invoke(&self) -> Result<AdvisorVerdict, AdvisorFailure> {
            Ok(AdvisorVerdict::Approve)
        }
        async fn classify_amber(
            &self,
            _: &AmberScript<'_>,
        ) -> Result<AdvisorVerdict, AdvisorFailure> {
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(AdvisorVerdict::Approve)
        }
    }

    #[tokio::test]
    async fn classify_amber_fans_out_in_parallel_across_packages() {
        // parallelization : pre-parallel the
        // outer per-package loop awaited each LLM round-trip
        // sequentially, so N amber packages cost N × round-trip wall
        // clock. The DX-doc walkthrough measured 2.1s on a single
        // amber install, dominated by ONE round-trip; a five-amber
        // install would have hit ~5–10s. Post-parallel, up to
        // [`CLASSIFY_CONCURRENCY`] calls are in flight at once.
        //
        // This test pins the wall-clock property at the integration
        // boundary. Using `tokio::time::sleep(50ms)` per call so the
        // measurement is robust against scheduler jitter without
        // making the test slow. With 6 packages and concurrency
        // ≥ 8, all 6 fire concurrently and total wall-clock is
        // ~50ms; the serial baseline would be 6 × 50 = 300ms. We
        // assert under 200ms — comfortably below 300ms but above any
        // realistic single-call overshoot from CI jitter.
        //
        // A future regression that re-introduces the serial loop
        // would push this test toward 300ms+ and fail.
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fake = SlowFakeAdvisor {
            delay: std::time::Duration::from_millis(50),
            call_count: Arc::clone(&call_count),
        };
        let mut s = AdvisorSession {
            adapter: Some(Box::new(fake)),
            configured_slug: Some("slow-fake".into()),
            approvals: HashSet::new(),
            warned_about_unavailable: false,
            cache: None,
            prompt_template_hash: String::new(),
            model_version: String::new(),
        };
        let reqs: Vec<AmberPackageRequest> = (0..6)
            .map(|i| AmberPackageRequest {
                name: format!("pkg-{i}"),
                version: "1.0.0".into(),
                integrity: None,
                repository: None,
                referenced_scripts: Vec::new(),
                amber_phases: vec![("postinstall".into(), "node install.js".into())],
            })
            .collect();

        let start = std::time::Instant::now();
        s.classify_amber(&reqs).await;
        let elapsed = start.elapsed();

        // All 6 calls fired (one per package, since each request has
        // exactly one phase).
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            6,
            "every package's amber phase must reach the advisor",
        );
        // All 6 approvals landed (every package returned Approve).
        assert_eq!(s.approvals().len(), 6);
        // Parallelism gate: wall-clock must be well under the serial
        // baseline of 6 × 50ms = 300ms. 200ms gives a generous
        // margin for scheduler / single-call overshoot while still
        // failing if the loop reverts to serial.
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "classify_amber must fan out concurrently across packages — elapsed {elapsed:?} is \
             close to or above the serial baseline (~300ms). A regression to the serial loop \
             would trip this assertion. concurrency = {CLASSIFY_CONCURRENCY}",
        );
    }

    #[tokio::test]
    async fn classify_amber_concurrency_cap_bounds_inflight_calls() {
        // Defense-in-depth: when the candidate set exceeds
        // [`CLASSIFY_CONCURRENCY`], the stream must NOT spawn every
        // task at once — that would defeat the rate-limit / queue-
        // saturation safety we cap for. We exercise this by:
        //   • Making each call sleep `delay` (50ms)
        //   • Sending `CLASSIFY_CONCURRENCY * 2` requests
        //   • Asserting wall-clock is ≥ delay × 2 (i.e., at least
        //     two waves must serialize), but well under
        //     `delay × CONCURRENCY * 2` (which would mean fully
        //     serial)
        //
        // The window between those bounds is wide enough to be
        // robust against jitter while still pinning that the cap
        // actually applies.
        let n = CLASSIFY_CONCURRENCY * 2;
        let delay_ms = 50u64;
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fake = SlowFakeAdvisor {
            delay: std::time::Duration::from_millis(delay_ms),
            call_count: Arc::clone(&call_count),
        };
        let mut s = AdvisorSession {
            adapter: Some(Box::new(fake)),
            configured_slug: Some("slow-fake".into()),
            approvals: HashSet::new(),
            warned_about_unavailable: false,
            cache: None,
            prompt_template_hash: String::new(),
            model_version: String::new(),
        };
        let reqs: Vec<AmberPackageRequest> = (0..n)
            .map(|i| AmberPackageRequest {
                name: format!("pkg-{i}"),
                version: "1.0.0".into(),
                integrity: None,
                repository: None,
                referenced_scripts: Vec::new(),
                amber_phases: vec![("postinstall".into(), "node install.js".into())],
            })
            .collect();

        let start = std::time::Instant::now();
        s.classify_amber(&reqs).await;
        let elapsed = start.elapsed();

        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            n,
            "every package must still reach the advisor — concurrency cap throttles, doesn't drop",
        );
        assert_eq!(s.approvals().len(), n);
        // Lower bound: at least 2 waves of `delay` each because the
        // cap forces serialization. Subtract a generous 20ms for
        // sleep/scheduling slack so the lower bound never fires on
        // hot machines.
        let lower = std::time::Duration::from_millis(delay_ms * 2 - 20);
        assert!(
            elapsed >= lower,
            "concurrency cap MUST throttle past `CLASSIFY_CONCURRENCY` requests — elapsed \
             {elapsed:?} is below the two-wave lower bound {lower:?}. If parallelism is \
             unbounded the cap is broken.",
        );
        // Upper bound: nowhere near fully serial. Serial would be
        // n × delay = 16 × 50 = 800ms. Cap with 2 waves should be
        // ~100ms. We allow up to 350ms — accommodates jitter while
        // catching a regression to serial.
        assert!(
            elapsed < std::time::Duration::from_millis(350),
            "concurrency cap parallelizes — elapsed {elapsed:?} is close to the serial \
             baseline of ~{} ms. Did the fan-out break? concurrency = {CLASSIFY_CONCURRENCY}",
            n as u64 * delay_ms,
        );
    }

    // ─────────────────────────────────────────────────────────────
    // — L4 cache behavioral contract
    // ─────────────────────────────────────────────────────────────

    fn session_with_cache(advisor: FakeAdvisor, cache: Arc<L4Cache>) -> AdvisorSession {
        AdvisorSession {
            adapter: Some(Box::new(advisor)),
            configured_slug: Some("test-fake".into()),
            approvals: HashSet::new(),
            warned_about_unavailable: false,
            cache: Some(cache),
            // Synthetic non-empty stamp so the cache key is stable
            // across the two phases of each test (the actual values
            // don't matter as long as both runs use the same ones).
            prompt_template_hash: "sha256-test-template".into(),
            model_version: "test-model-v1".into(),
        }
    }

    #[tokio::test]
    async fn cache_hit_skips_adapter_classify_call() {
        // First run: cache empty, advisor is called, verdict is
        // inserted into the cache. Second run with the SAME inputs:
        // adapter classify must NOT be called (cache fully covers
        // every request).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l4.json");
        unsafe {
            // Test must run with the cache enabled regardless of
            // the host env. Setting via env::set_var is unsafe in
            // multi-threaded contexts, but the cache disable check
            // only reads at open time and we control that here.
            std::env::set_var("LPM_L4_CACHE", "1");
            std::env::set_var("LPM_L4_CACHE_PATH", path.display().to_string());
        }
        let cache = Arc::new(L4Cache::open_at(path.clone(), DEFAULT_TTL_FOR_TEST).unwrap());

        // Cold run: adapter returns Approve, cache should miss then
        // insert.
        let call_log_cold = Arc::new(Mutex::new(Vec::new()));
        let fake_cold = FakeAdvisor {
            provider: Provider::ClaudeCli,
            detect_result: true,
            test_invoke_result: Ok(AdvisorVerdict::Approve),
            classify_results: Mutex::new(vec![Ok(AdvisorVerdict::Approve)]),
            call_log: Arc::clone(&call_log_cold),
        };
        let mut s = session_with_cache(fake_cold, Arc::clone(&cache));
        let req = AmberPackageRequest {
            name: "sharp".into(),
            version: "0.34.4".into(),
            integrity: Some("sha512-abc".into()),
            repository: None,
            referenced_scripts: Vec::new(),
            amber_phases: vec![("install".into(), "node install.js".into())],
        };
        s.classify_amber(&[req]).await;
        assert_eq!(
            s.approvals().len(),
            1,
            "cold run should approve via adapter"
        );
        let cold_log = call_log_cold.lock().await.clone();
        assert!(
            cold_log.iter().any(|l| l == "classify:sharp"),
            "cold run must call adapter.classify_amber: {cold_log:?}"
        );
        assert_eq!(cache.entry_count(), 1, "verdict should be cached");

        // Warm run with the SAME input. New fake whose classify_results
        // is empty — if the cache is consulted, the adapter never
        // fires. Otherwise the empty queue produces a Manual default
        // and the test fails because the package wouldn't be approved.
        let call_log_warm = Arc::new(Mutex::new(Vec::new()));
        let fake_warm = FakeAdvisor {
            provider: Provider::ClaudeCli,
            detect_result: true,
            test_invoke_result: Ok(AdvisorVerdict::Approve),
            classify_results: Mutex::new(vec![]),
            call_log: Arc::clone(&call_log_warm),
        };
        let mut s = session_with_cache(fake_warm, cache);
        let req = AmberPackageRequest {
            name: "sharp".into(),
            version: "0.34.4".into(),
            integrity: Some("sha512-abc".into()),
            repository: None,
            referenced_scripts: Vec::new(),
            amber_phases: vec![("install".into(), "node install.js".into())],
        };
        s.classify_amber(&[req]).await;
        assert_eq!(
            s.approvals().len(),
            1,
            "warm run must approve via cache, not adapter"
        );
        let warm_log = call_log_warm.lock().await.clone();
        assert!(
            warm_log.iter().all(|l| l != "classify:sharp"),
            "warm run must NOT call adapter.classify_amber (cache hit should skip): {warm_log:?}"
        );
    }

    /// Same default TTL as the production cache. Tests use this so a
    /// "freshly inserted" entry is always within the lookup window.
    /// Bringing the constant into scope here keeps the test
    /// self-contained even if the upstream default changes.
    const DEFAULT_TTL_FOR_TEST: std::time::Duration =
        std::time::Duration::from_secs(30 * 24 * 60 * 60);
}
