use std::sync::Arc;

use futures::StreamExt;
use indicatif::ProgressBar;
use lpm_security::triage::StaticTier;
use lpm_triage_advisor::{
    Advisor, AdvisorFailure, AdvisorVerdict as TriageVerdict, AmberScript as TriageAmberScript,
    CacheKeyInputs, ClaudeCliAdapter, CodexAdapter, L4Cache, OllamaAdapter,
    Provider as AdvisorProvider, binary_path, build_cache_key, prompt_template_hash,
    provider_version,
};

use crate::args::Args;
use crate::classify::scripted_phases;
use crate::types::{
    AdvisorOutcome, AdvisorStamp, BoxError, PackageAudit, PortableOutcome, ScriptAudit,
};
use crate::util::{emit_progress_milestone, progress_style};

/// Spawn the named advisor and invoke it on every `portable_outcome
/// = Prompt` package. Records the verdict on `advisor_outcome` and
/// recomputes the advisor-enhanced final outcome.
///
/// Failures are surfaced as records, not run aborts: an
/// `EnvironmentNotReady` for one package downgrades that package's
/// advisor outcome to whatever the portable outcome was (no uplift),
/// but the audit continues. An `IntegrationFailure` is the same — the
/// audit harness's job is to MEASURE, not to fix the advisor mid-run.
pub(crate) async fn enrich_advisor_in_place(
    name: &str,
    audits: &mut [PackageAudit],
    args: &Args,
) -> Result<Option<AdvisorStamp>, BoxError> {
    let provider = AdvisorProvider::from_slug(name)
        .ok_or_else(|| format!("unknown advisor '{name}'; valid: claude-cli / codex / ollama"))?;
    let (advisor, model): (Box<dyn Advisor>, Option<String>) = match provider {
        AdvisorProvider::ClaudeCli => (Box::new(ClaudeCliAdapter), None),
        AdvisorProvider::Codex => (Box::new(CodexAdapter), None),
        AdvisorProvider::Ollama => {
            let a = OllamaAdapter::default();
            let m = Some(a.model.clone());
            (Box::new(a), m)
        }
    };

    // Pre-flight: detect + test-invoke. If either fails we abort the
    // L4 phase entirely; running the audit with a broken adapter would
    // produce noise, not data.
    if !advisor.detect().await {
        return Err(format!(
            "advisor '{name}' not available on this machine (detect probe failed)"
        )
        .into());
    }
    match advisor.test_invoke().await {
        Ok(_v) => println!("L4 advisor '{name}': test invoke OK"),
        Err(AdvisorFailure::EnvironmentNotReady(msg)) => {
            return Err(format!("advisor '{name}' environment not ready: {msg}").into());
        }
        Err(AdvisorFailure::IntegrationFailure(msg)) => {
            return Err(format!("advisor '{name}' integration failure: {msg}").into());
        }
    }

    let targets: Vec<usize> = audits
        .iter()
        .enumerate()
        .filter(|(_, a)| a.portable_outcome == Some(PortableOutcome::Prompt))
        .map(|(i, _)| i)
        .collect();

    // Collect identity stamp regardless of how many prompted packages
    // exist — so re-running on an audit set with zero ambers still
    // captures "we tried, here's the advisor we'd use."
    let stamp = AdvisorStamp {
        provider: provider.slug().to_string(),
        binary_path: binary_path(provider).map(|p| p.display().to_string()),
        binary_version: provider_version(provider).await,
        model,
        prompt_template_hash: prompt_template_hash(),
        invoked_count: targets.len(),
    };

    if targets.is_empty() {
        println!("L4 advisor: no prompted packages — nothing to advise");
        return Ok(Some(stamp));
    }
    println!(
        "L4 advisor: classifying {} prompted package(s) via {name}",
        targets.len()
    );

    // Open the L4 cache when `--l4-cache` is set. Off by
    // default so a measurement run pays the honest cold-cache LLM
    // round-trip cost. The cache module's own `LPM_L4_CACHE=0`
    // env-var disable still applies; if both flag-on + env-off, we
    // surface that in a print line so a confused operator can spot
    // the env-var override.
    let cache: Option<Arc<L4Cache>> = if args.l4_cache {
        match L4Cache::open_default() {
            Ok(c) => {
                if c.is_disabled() {
                    println!(
                        "L4 cache: enabled by --l4-cache but disabled via env (LPM_L4_CACHE != 1); \
                         every advisor call will hit the LLM."
                    );
                } else {
                    println!(
                        "L4 cache: enabled, file = {} (existing entries: {})",
                        c.path().display(),
                        c.entry_count()
                    );
                }
                Some(Arc::new(c))
            }
            Err(e) => {
                eprintln!(
                    "warning: --l4-cache requested but L4Cache::open_default failed ({e}); \
                     running uncached"
                );
                None
            }
        }
    } else {
        None
    };
    let cache_template_hash = stamp.prompt_template_hash.clone();
    let cache_model_version = stamp
        .binary_version
        .clone()
        .unwrap_or_else(|| stamp.model.clone().unwrap_or_default());
    let cache_provider_slug = stamp.provider.clone();
    let cache_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cache_misses = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let pb = Arc::new(ProgressBar::new(targets.len() as u64));
    pb.set_style(progress_style("L4 advise"));

    // Fan out advisor calls in parallel.
    // Pre-parallelization the curated 123-amber run took ~7 min
    // wall-clock at ~3.4s/call serial. With concurrency = 8, that
    // drops to ~1 min. The `Advisor` trait is `Send + Sync` and
    // `classify_amber` takes `&self`, so concurrent calls are
    // safe; only the per-target `advisor_outcome` slot mutation
    // happens serially after collection — single-thread, no locks.
    //
    // Concurrency cap matches the install-pipeline session's cap
    // (`crates/lpm-cli/src/triage_advisor_session.rs::CLASSIFY_CONCURRENCY`)
    // so a future audit run that exhausts the user's provider's
    // rate limit fails the same way the live install would, not
    // earlier or later.
    //
    // Implementation note: snapshot each target's `PackageAudit`
    // BEFORE the stream so the futures don't borrow `audits` (the
    // serial-application phase below needs `&mut audits`). Per-
    // package clone cost is negligible relative to the LLM
    // round-trip cost; the snapshot also carries a one-line
    // tracing identity (name + rank) that the post-stream loop
    // uses for the verdict log line.
    const L4_CONCURRENCY: usize = 8;
    let provider_slug = provider.slug().to_string();
    let advisor_ref: &dyn Advisor = &*advisor;
    let pb_for_stream = Arc::clone(&pb);
    let outcomes: Vec<(usize, Option<&'static str>, AdvisorOutcome)> =
        futures::stream::iter(targets.iter().map(|&idx| (idx, audits[idx].clone())).map(
            |(idx, snapshot)| {
                let pb = Arc::clone(&pb_for_stream);
                let cache = cache.clone();
                let cache_template_hash = cache_template_hash.clone();
                let cache_model_version = cache_model_version.clone();
                let cache_provider_slug = cache_provider_slug.clone();
                let cache_hits = Arc::clone(&cache_hits);
                let cache_misses = Arc::clone(&cache_misses);
                async move {
                    let (verdict_label, advisor_outcome) = classify_one_with_advisor(
                        advisor_ref,
                        &snapshot,
                        cache.as_deref(),
                        &cache_provider_slug,
                        &cache_model_version,
                        &cache_template_hash,
                        &cache_hits,
                        &cache_misses,
                    )
                    .await;
                    pb.inc(1);
                    // Non-TTY-friendly stderr milestone every 25 advisor
                    // calls. The L4 phase is slower per-item than fetch
                    // (each call is an LLM round-trip), so the milestone
                    // interval is tighter than fetch's 100 to keep the
                    // user informed during a long run.
                    emit_progress_milestone("L4 advise", &pb, 25);
                    (idx, verdict_label, advisor_outcome)
                }
            },
        ))
        .buffer_unordered(L4_CONCURRENCY)
        .collect()
        .await;
    pb.finish_with_message("L4 advisor complete");

    for (idx, verdict_label, advisor_outcome) in outcomes {
        audits[idx].advisor_outcome = Some(advisor_outcome);
        audits[idx].advisor_provider = Some(provider_slug.clone());
        if let Some(l) = verdict_label {
            tracing::info!(target: "lpm_audit_corpus::advisor", rank = audits[idx].rank, name = %audits[idx].name, verdict = l, "advisor verdict");
        }
    }

    // Persist + summary. Persisting is best-effort
    // (failure surfaces as a warning, never an error). Summary line
    // fires when `--l4-cache` is set OR when `--l4-cache-stats` is
    // (the latter is for a future "show stats without changing the
    // cache" debug mode).
    if let Some(cache) = cache.as_deref() {
        match cache.persist() {
            Ok(()) => {
                let hits = cache_hits.load(std::sync::atomic::Ordering::Relaxed);
                let misses = cache_misses.load(std::sync::atomic::Ordering::Relaxed);
                println!(
                    "L4 cache: hits={hits} misses={misses} entries={} (persisted to {})",
                    cache.entry_count(),
                    cache.path().display(),
                );
            }
            Err(e) => {
                eprintln!(
                    "warning: L4 cache persist failed: {e} (in-memory entries lost; next \
                     run starts cold)",
                );
            }
        }
    } else if args.l4_cache_stats {
        println!(
            "L4 cache: stats requested but cache is disabled (hits/misses both 0; \
             pass --l4-cache to enable)"
        );
    }

    Ok(Some(stamp))
}

/// Run the advisor on a single package's amber script(s). Worst-of
/// across phases (matches the L1 worst-of-phases logic). Returns
/// `(verdict_label_for_logging, final_advisor_outcome)`.
///
/// When `cache` is `Some`, look up the (name, version,
/// amber-phase-bodies, prompt_template_hash, provider, model) key
/// before invoking the advisor. On a hit, the LLM call is skipped
/// entirely and the cached verdict is mapped straight back to an
/// `AdvisorOutcome`. On a miss, the advisor classifies as usual and
/// the resulting worst-of verdict is inserted into the cache so the
/// next run hits.
#[allow(clippy::too_many_arguments)]
async fn classify_one_with_advisor(
    advisor: &dyn Advisor,
    pkg: &PackageAudit,
    cache: Option<&L4Cache>,
    cache_provider_slug: &str,
    cache_model_version: &str,
    cache_template_hash: &str,
    cache_hits: &std::sync::atomic::AtomicUsize,
    cache_misses: &std::sync::atomic::AtomicUsize,
) -> (Option<&'static str>, AdvisorOutcome) {
    let phases = scripted_phases(pkg);
    let amber_phases: Vec<(&'static str, &ScriptAudit)> = phases
        .into_iter()
        .filter(|(_, s)| matches!(s.tier, StaticTier::Amber | StaticTier::AmberLlm))
        .collect();
    if amber_phases.is_empty() {
        return (None, AdvisorOutcome::Prompt);
    }

    let version = pkg.version.as_deref().unwrap_or("unknown");

    // Cache lookup. The cache key folds in every input
    // axis that affects the verdict: package identity (name +
    // version), every amber phase body, plus the advisor's prompt
    // template hash + provider slug + model version. A cache hit
    // means we've already classified an identical input and can
    // skip the LLM round-trip.
    let cache_phases: Vec<(&str, &str)> = amber_phases
        .iter()
        .map(|(phase, script)| (*phase, script.script.as_str()))
        .collect();
    let cache_refs: Vec<(&str, &str)> = pkg
        .referenced_scripts
        .iter()
        .map(|r| (r.filename.as_str(), r.content.as_str()))
        .collect();
    let cache_key = build_cache_key(&CacheKeyInputs {
        package_name: &pkg.name,
        package_version: version,
        amber_phases: &cache_phases,
        repository: pkg.repository.as_deref(),
        referenced_scripts: &cache_refs,
        prompt_template_hash: cache_template_hash,
        provider_slug: cache_provider_slug,
        model_version: cache_model_version,
    });
    if let Some(cache) = cache
        && let Some(cached_verdict) = cache.lookup(&cache_key)
    {
        cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let outcome = match cached_verdict {
            TriageVerdict::Approve => AdvisorOutcome::AutoRun,
            TriageVerdict::Manual => AdvisorOutcome::Prompt,
            TriageVerdict::Abstain => AdvisorOutcome::Prompt,
        };
        let label = match cached_verdict {
            TriageVerdict::Approve => "approve",
            TriageVerdict::Manual => "manual",
            TriageVerdict::Abstain => "abstain",
        };
        return (Some(label), outcome);
    }

    // borrow the referenced files as a slice
    // of `ReferencedScript` so the prompt's "Referenced files"
    // section can render the embedded view.
    let amber_refs: Vec<lpm_triage_advisor::ReferencedScript<'_>> = pkg
        .referenced_scripts
        .iter()
        .map(|r| lpm_triage_advisor::ReferencedScript {
            filename: r.filename.as_str(),
            content: r.content.as_str(),
        })
        .collect();
    let mut worst = TriageVerdict::Approve;
    let mut saw_failure = false;
    for (phase_name, script) in &amber_phases {
        let amber = TriageAmberScript {
            package_name: &pkg.name,
            package_version: version,
            phase: phase_name,
            script_body: &script.script,
            // forward the package's
            // `repository` URL so the prompt's `Repository:` line
            // pairs with the script body.
            repository: pkg.repository.as_deref(),
            // forward the embedded view of
            // referenced files so the prompt can apply the
            // fetch-IDENTITY rule one level deep.
            referenced_scripts: &amber_refs,
        };
        match advisor.classify_amber(&amber).await {
            Ok(v) => worst = combine_verdict(worst, v),
            Err(e) => {
                saw_failure = true;
                tracing::warn!(
                    target: "lpm_audit_corpus::advisor",
                    package = %pkg.name,
                    phase = phase_name,
                    error = %e,
                    "advisor classify failed; treating as no-uplift for this package"
                );
            }
        }
    }

    if saw_failure {
        // Per the contract: degrade to portable outcome for this
        // package, never block. Don't cache failures — the next run
        // may succeed.
        return (Some("failure"), AdvisorOutcome::Prompt);
    }

    // Insert the final verdict into the cache so the
    // next run with the same inputs hits.
    if cache.is_some() {
        cache_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(cache) = cache {
        cache.insert(
            cache_key,
            worst,
            cache_provider_slug,
            cache_model_version,
            cache_template_hash,
        );
    }

    let outcome = match worst {
        TriageVerdict::Approve => AdvisorOutcome::AutoRun,
        TriageVerdict::Manual => AdvisorOutcome::Prompt,
        TriageVerdict::Abstain => AdvisorOutcome::Prompt,
    };
    let label = match worst {
        TriageVerdict::Approve => "approve",
        TriageVerdict::Manual => "manual",
        TriageVerdict::Abstain => "abstain",
    };
    (Some(label), outcome)
}

/// Worst-of reducer over advisor verdicts: Manual > Abstain >
/// Approve. Mirrors the L1 `StaticTier::worse_of` discipline so a
/// single "manual" phase on a multi-phase package pulls the whole
/// package back into the prompt bucket.
fn combine_verdict(a: TriageVerdict, b: TriageVerdict) -> TriageVerdict {
    use TriageVerdict::*;
    match (a, b) {
        (Manual, _) | (_, Manual) => Manual,
        (Abstain, _) | (_, Abstain) => Abstain,
        (Approve, Approve) => Approve,
    }
}
