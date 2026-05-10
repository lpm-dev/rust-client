//! Top-N npm static-gate audit harness.
//!
//! Walks the npm registry search API to collect the top-N packages by
//! monthly download count, fetches each package's `latest` manifest, runs
//! every lifecycle script (`preinstall` / `install` / `postinstall`)
//! through [`lpm_security::static_gate::classify`], and emits:
//!
//! - a per-package JSON results file (one record per package),
//! - an aggregate Markdown report with tier distribution + amber-pattern
//!   frequency table + every red-classified package surfaced inline.
//!
//! Re-runnable: the top-N list is cached on disk, manifest fetches are
//! parallelised behind a configurable concurrency limit, and rerunning
//! after a `static_gate.rs` change re-uses the cached top-N list while
//! re-classifying.
//!
//! Run via:
//!   cargo run --release -p lpm-audit-corpus -- \
//!     --size 5000 \
//!     --top-n-cache /tmp/lpm-audit-top5000.json \
//!     --results /tmp/lpm-audit-results.json \
//!     --report /tmp/lpm-audit-report.md
//!
//! This crate is a tool, not a library. It is `publish = false` and is
//! intended for Phase 46 calibration runs (and future re-runs after
//! green-allowlist iterations).

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use lpm_security::SecurityPolicy;
use lpm_security::static_gate::classify;
use lpm_security::triage::StaticTier;
use serde::{Deserialize, Serialize};

type BoxError = Box<dyn Error + Send + Sync>;

const SEARCH_PAGE_SIZE: usize = 250;
const SEARCH_ENDPOINT: &str = "https://registry.npmjs.org/-/v1/search";
const REGISTRY_BASE: &str = "https://registry.npmjs.org";
const USER_AGENT: &str = "lpm-audit-corpus/0.1 (+https://lpm.dev)";

#[derive(Parser, Debug)]
#[command(name = "lpm-audit-corpus")]
#[command(about = "Run lpm-security static-gate over the top-N npm packages.")]
struct Args {
    /// Top-N to audit (paginates the npm search API in 250-package batches).
    #[arg(long, default_value_t = 5000)]
    size: usize,

    /// Cache file for the top-N list (reused across audit re-runs).
    #[arg(long, default_value = "/tmp/lpm-audit-top-n.json")]
    top_n_cache: PathBuf,

    /// Output: per-package audit results (JSON).
    #[arg(long, default_value = "/tmp/lpm-audit-results.json")]
    results: PathBuf,

    /// Output: human-readable Markdown summary.
    #[arg(long, default_value = "/tmp/lpm-audit-report.md")]
    report: PathBuf,

    /// Concurrent manifest fetches.
    #[arg(long, default_value_t = 32)]
    concurrency: usize,

    /// Force-refresh the top-N cache even if a valid one exists.
    #[arg(long, default_value_t = false)]
    refresh_top_n: bool,

    /// Per-request timeout (seconds).
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,

    /// Resume from a previous results file: keep records without
    /// `fetch_error`, retry only the ones that failed. Useful after a
    /// 429-heavy run.
    #[arg(long, default_value_t = false)]
    resume: bool,

    /// Re-classify the scripts recorded in `--results` without
    /// re-fetching manifests. Use after a `static_gate.rs` change to
    /// measure the new tier distribution against the cached dataset.
    /// `--top-n-cache` is still required (rank + downloads come from
    /// it) but no network calls are made.
    #[arg(long, default_value_t = false)]
    reclassify: bool,

    /// Backfill Layer 3 data (packument `time` + attestation
    /// presence) for scripted records in `--results` without
    /// re-running L1 classification. Useful after extending the
    /// existing cache with the L1-3 harness for the first time.
    /// Fetches only scripted packages (≪ 5000), so completes in
    /// seconds.
    #[arg(long, default_value_t = false)]
    enrich_l3_only: bool,

    /// Skip Layer 3 enrichment during a default audit run. Layer 3
    /// data is omitted; `portable_outcome` falls back to L1-only.
    /// Primarily for development; the production audit should always
    /// include L3 because the portable contract requires it.
    #[arg(long, default_value_t = false)]
    skip_l3: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TopNEntry {
    name: String,
    monthly_downloads: u64,
    rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackageAudit {
    name: String,
    rank: usize,
    monthly_downloads: u64,
    /// `Some(version)` if a manifest was successfully fetched, else `None`.
    version: Option<String>,
    /// Per-phase classification. `None` if the script was absent in the manifest.
    preinstall: Option<ScriptAudit>,
    install: Option<ScriptAudit>,
    postinstall: Option<ScriptAudit>,
    /// Worst-of of the three phases. `None` if none of the three scripts was set.
    tier: Option<StaticTier>,
    /// Layer 2 result. Always [`L2Outcome::Miss`] in a first-install
    /// audit (the audit user has no prior trust state).
    #[serde(default = "L2Outcome::default_miss")]
    l2_outcome: L2Outcome,
    /// Layer 3 result. `None` for packages with no scripts (L3 not
    /// applicable) and for runs that haven't enriched yet.
    #[serde(default)]
    l3_outcome: Option<L3Outcome>,
    /// Final outcome under the **portable** triage contract (script-policy
    /// = "triage", triage-advisor = "none"). Computed deterministically
    /// from L1+L2+L3; this is the decision-grade metric per the
    /// principle that triage must mean the same thing on every machine.
    #[serde(default)]
    portable_outcome: Option<PortableOutcome>,
    /// Reserved for Part B. Populated only when an advisor was
    /// invoked; otherwise `None` and the portable outcome is the
    /// authoritative answer for this run.
    #[serde(default)]
    advisor_outcome: Option<AdvisorOutcome>,
    /// Empty unless the manifest fetch errored.
    fetch_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScriptAudit {
    script: String,
    tier: StaticTier,
    first_token: Option<String>,
    /// Normalised shape bucket for reporting (replaces the lossy
    /// first-token grouping). Populated at classify time.
    #[serde(default)]
    shape: Option<ScriptShape>,
}

/// Layer 2 — trust-manifest outcome.
///
/// In a first-install audit (no prior `trustedDependencies` snapshot on
/// disk), Layer 2 always returns `Miss` because there's nothing to
/// strict-match against. The other variants are reserved for future
/// audits that simulate prior approval state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum L2Outcome {
    /// No prior strict binding matched — typical first-install case.
    Miss,
    /// (Future) the package matched the user's strict
    /// `{name,version,integrity,script_hash}` binding → would auto-run.
    StrictMatch,
    /// (Future) the package has a binding that drifted from prior
    /// approval (different integrity / script hash) → would block.
    Drift,
}

impl L2Outcome {
    fn default_miss() -> Self {
        L2Outcome::Miss
    }
}

/// Layer 3 — provenance drift + cooldown.
///
/// Two gates today: release-age cooldown (always relevant) and
/// provenance drift (relevant only when there's an approved-side
/// snapshot to compare against — never the case in a first-install
/// audit, so the audit records `provenance_drift = NoDrift` for every
/// scripted package).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct L3Outcome {
    /// ISO 8601 publish timestamp of the latest version (from the
    /// registry packument's `time[<version>]`). `None` when the
    /// registry didn't return a usable timestamp.
    #[serde(default)]
    published_at: Option<String>,
    /// Age of the release in seconds at the time of the audit run.
    /// `None` if `published_at` couldn't be parsed.
    #[serde(default)]
    age_secs: Option<u64>,
    /// Whether `cooldown_block` would have fired under the default
    /// `SecurityPolicy::DEFAULT_MIN_RELEASE_AGE` (24h). The audit uses
    /// the default explicitly to keep numbers reproducible — users
    /// who tighten via `lpm.minimumReleaseAge` see stricter blocks
    /// than these.
    cooldown_block: bool,
    /// Whether the latest version has Sigstore attestations published
    /// to the npm attestations endpoint. Captured for reporting; does
    /// NOT gate the portable outcome on its own (provenance drift
    /// requires an approved-side reference, which a first-install
    /// audit doesn't have).
    attestation_present: bool,
    /// Drift verdict for the audit's reference frame. Always
    /// `NoDrift` for first-install audits — surfaced as a field so
    /// future audits that simulate prior approvals can populate it
    /// without schema churn.
    provenance_drift: ProvenanceDriftSummary,
    /// Empty unless one of the L3 fetches errored. The other fields
    /// reflect best-effort partial data.
    #[serde(default)]
    l3_fetch_error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ProvenanceDriftSummary {
    NoDrift,
    ProvenanceDropped,
    IdentityChanged,
}

/// Final outcome under the **portable** triage contract (no advisor).
///
/// This is the decision-grade metric: triage must mean the same thing
/// on every machine. The advisor-enhanced number is a separate uplift
/// line and lives in [`AdvisorOutcome`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum PortableOutcome {
    /// No lifecycle scripts in the manifest — nothing for triage to do.
    NoScripts,
    /// L1 green ⇒ auto-run. (Or, in future audits, L2 strict-match.)
    AutoRun,
    /// L1 amber + L2 miss + L3 pass ⇒ user prompt required.
    Prompt,
    /// L1 red, or L1 amber + L3 cooldown/drift block ⇒ hard-block.
    HardBlock,
}

/// Reserved for Part B (advisor-enhanced triage). Same shape as
/// [`PortableOutcome`] but additionally accounts for an L4 advisor
/// promoting amber → auto-run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum AdvisorOutcome {
    NoScripts,
    AutoRun,
    Prompt,
    HardBlock,
}

/// Normalised shape bucket for reporting amber scripts. Replaces the
/// lossy first-token grouping that lumped softfail-wrappers, binary
/// fetchers, and helper scripts together under "node".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum ScriptShape {
    /// `node -e "<softfail wrapper>"` — recognised by the P0 regex.
    SoftfailWrapper,
    /// `node <reserved-basename>.{js,cjs,mjs}` — install/postinstall/
    /// preinstall convention; binary fetcher per D18.
    BinaryFetcher,
    /// Bare `node-gyp rebuild` / `node-gyp-build` / `node-gyp-build-
    /// optional-packages` — local-only native build helpers.
    NativeBuild,
    /// Pure no-op (`exit 0`, `:`, `echo …`).
    NoOp,
    /// `prebuild-install || node-gyp rebuild` and friends — compound
    /// of a prebuild fetch with a local fallback.
    PrebuildFallback,
    /// Compound command (multiple commands joined by `&&`/`||`/`;`/
    /// pipe/redirect) that isn't recognised above.
    Compound,
    /// `node <relative>.{js,cjs,mjs}` with a non-reserved basename —
    /// the script body lives in a JS file we can't statically read.
    NodeHelperScript,
    /// Anything else.
    Other,
}

/// What we read from `https://registry.npmjs.org/{pkg}/latest`. We deserialise
/// only the two fields we care about; everything else (deps, license, readme,
/// etc.) is skipped so the binary doesn't pay for parsing the entire manifest.
#[derive(Debug, Deserialize)]
struct LatestManifest {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    scripts: Option<BTreeMap<String, String>>,
}

/// Slice of the full registry packument we need for L3 enrichment.
/// `time[<version>]` carries the ISO 8601 publish timestamp; we don't
/// touch the rest. We fetch the whole packument because the
/// per-version `/{pkg}/{ver}` endpoint doesn't expose this.
#[derive(Debug, Deserialize)]
struct Packument {
    #[serde(default)]
    time: BTreeMap<String, String>,
}

/// Slice of the npm attestations API response. We only need presence
/// detection; the full bundle is much larger.
#[derive(Debug, Deserialize)]
struct AttestationsResponse {
    #[serde(default)]
    attestations: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    objects: Vec<SearchObject>,
}

#[derive(Debug, Deserialize)]
struct SearchObject {
    package: SearchPackage,
    downloads: SearchDownloads,
}

#[derive(Debug, Deserialize)]
struct SearchPackage {
    name: String,
}

#[derive(Debug, Deserialize)]
struct SearchDownloads {
    monthly: u64,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    if args.reclassify {
        return reclassify_from_cache(&args);
    }

    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(args.timeout_secs))
        .build()?;

    if args.enrich_l3_only {
        return enrich_l3_from_cache(&client, &args).await;
    }

    let top_n = load_or_fetch_top_n(&client, &args).await?;
    println!(
        "loaded top-{} packages (range: {} dl/mo … {} dl/mo)",
        top_n.len(),
        top_n.first().map(|e| e.monthly_downloads).unwrap_or(0),
        top_n.last().map(|e| e.monthly_downloads).unwrap_or(0),
    );

    let resume_records = if args.resume && args.results.exists() {
        let bytes = std::fs::read(&args.results)?;
        let recs: Vec<PackageAudit> = serde_json::from_slice(&bytes)?;
        let ok = recs.iter().filter(|r| r.fetch_error.is_none()).count();
        println!(
            "resume: {} prior records loaded, {} ok, {} to retry",
            recs.len(),
            ok,
            recs.len() - ok
        );
        Some(recs)
    } else {
        None
    };

    let mut audits = audit_top_n(&client, &top_n, args.concurrency, resume_records).await?;

    if !args.skip_l3 {
        enrich_l3_in_place(&client, &mut audits, args.concurrency).await;
    }
    finalize_outcomes(&mut audits);

    std::fs::write(&args.results, serde_json::to_vec_pretty(&audits)?)?;
    println!(
        "wrote {} audit records → {}",
        audits.len(),
        args.results.display()
    );

    let report = build_report(&audits);
    std::fs::write(&args.report, &report)?;
    println!("wrote markdown report → {}", args.report.display());

    print_summary(&audits);
    Ok(())
}

/// Enrich an audit set with L3 data (packument time + attestation
/// presence) for every scripted record that doesn't already have it.
/// Skips records without a tier (no scripts) and records whose
/// `l3_outcome` is already populated.
async fn enrich_l3_in_place(
    client: &reqwest::Client,
    audits: &mut [PackageAudit],
    concurrency: usize,
) {
    let targets: Vec<(usize, String, String)> = audits
        .iter()
        .enumerate()
        .filter(|(_, a)| a.tier.is_some() && a.l3_outcome.is_none() && a.fetch_error.is_none())
        .filter_map(|(i, a)| a.version.as_ref().map(|v| (i, a.name.clone(), v.clone())))
        .collect();

    if targets.is_empty() {
        println!("L3 enrichment: no scripted records need fetching");
        return;
    }
    println!(
        "L3 enrichment: fetching packument + attestation for {} scripted package(s)",
        targets.len()
    );

    let pb = Arc::new(ProgressBar::new(targets.len() as u64));
    pb.set_style(progress_style("L3 enrich"));

    let mut in_flight = FuturesUnordered::new();
    let mut iter = targets.into_iter();
    for (idx, name, ver) in iter.by_ref().take(concurrency) {
        let client = client.clone();
        let pb = Arc::clone(&pb);
        in_flight.push(tokio::spawn(async move {
            (idx, fetch_l3_one(&client, &name, &ver, pb).await)
        }));
    }
    while let Some(joined) = in_flight.next().await {
        let (idx, l3) = joined.expect("L3 fetch task panicked");
        audits[idx].l3_outcome = Some(l3);
        if let Some((next_idx, next_name, next_ver)) = iter.next() {
            let client = client.clone();
            let pb = Arc::clone(&pb);
            in_flight.push(tokio::spawn(async move {
                (
                    next_idx,
                    fetch_l3_one(&client, &next_name, &next_ver, pb).await,
                )
            }));
        }
    }
    pb.finish_with_message("L3 enrichment complete");
}

/// Populate `portable_outcome` on every record. Pure computation,
/// always safe to re-run after a change to the outcome logic.
fn finalize_outcomes(audits: &mut [PackageAudit]) {
    for a in audits.iter_mut() {
        a.portable_outcome = Some(compute_portable_outcome(a));
    }
}

/// Refresh the `shape` bucket on every recorded script body. Pure
/// re-computation against the cached script — does NOT change tier.
/// Called by the cache-only paths so older records (written before
/// the `shape` field existed) get bucketed properly.
fn refresh_shapes(audits: &mut [PackageAudit]) {
    for a in audits.iter_mut() {
        for phase in [&mut a.preinstall, &mut a.install, &mut a.postinstall]
            .into_iter()
            .flatten()
        {
            let tokens = shlex::split(&phase.script).unwrap_or_default();
            phase.shape = Some(classify_shape(&phase.script, &tokens, phase.tier));
        }
    }
}

/// Backfill mode: read cached results, fetch L3 for scripted records
/// that don't have it, compute outcomes, write back. Doesn't touch L1
/// tier classification (use `--reclassify` for that) — but DOES
/// refresh the `shape` bucket from the cached script body, since
/// older cached records pre-date the shape field and would all bucket
/// as `Other` otherwise.
async fn enrich_l3_from_cache(client: &reqwest::Client, args: &Args) -> Result<(), BoxError> {
    let bytes = std::fs::read(&args.results)
        .map_err(|e| format!("--enrich-l3-only requires {}: {e}", args.results.display()))?;
    let mut audits: Vec<PackageAudit> = serde_json::from_slice(&bytes)?;
    println!(
        "enrich-l3: loaded {} cached records from {}",
        audits.len(),
        args.results.display()
    );

    refresh_shapes(&mut audits);
    enrich_l3_in_place(client, &mut audits, args.concurrency).await;
    finalize_outcomes(&mut audits);

    std::fs::write(&args.results, serde_json::to_vec_pretty(&audits)?)?;
    let report = build_report(&audits);
    std::fs::write(&args.report, &report)?;
    println!(
        "wrote {} audit records → {}\nwrote markdown report → {}",
        audits.len(),
        args.results.display(),
        args.report.display()
    );

    print_summary(&audits);
    Ok(())
}

fn print_summary(audits: &[PackageAudit]) {
    let summary = summarise(audits);
    println!(
        "\nL1: green={} amber={} red={} no-scripts={} fetch-failed={}",
        summary.green, summary.amber, summary.red, summary.no_scripts, summary.fetch_failed,
    );
    if summary.scripted_total() > 0 {
        println!(
            "L1 green/(green+amber) over scripted = {:.1}%",
            summary.green_share_pct(),
        );
    }
    let portable = summarise_portable(audits);
    println!(
        "Portable (L1-3): auto-run={} prompt={} hard-block={} no-scripts={}",
        portable.auto_run, portable.prompt, portable.hard_block, portable.no_scripts
    );
    let total_scripted = portable.auto_run + portable.prompt + portable.hard_block;
    if total_scripted > 0 {
        println!(
            "Portable auto-run rate over scripted = {:.1}%",
            (portable.auto_run as f64) * 100.0 / total_scripted as f64,
        );
    }
}

/// Read the cached results JSON and re-run `classify()` on every
/// recorded script body. Manifests are NOT re-fetched. Output is the
/// same JSON + Markdown shape, with the new tier annotations.
///
/// This is the fast path for evaluating a `static_gate.rs` change
/// against the same 5000-package dataset the prior run captured.
fn reclassify_from_cache(args: &Args) -> Result<(), BoxError> {
    let bytes = std::fs::read(&args.results)
        .map_err(|e| format!("--reclassify requires {}: {e}", args.results.display()))?;
    let mut audits: Vec<PackageAudit> = serde_json::from_slice(&bytes)?;
    println!(
        "reclassify: loaded {} cached records from {}",
        audits.len(),
        args.results.display()
    );

    let mut changed = 0usize;
    for a in &mut audits {
        let prev_tier = a.tier;
        for phase in [&mut a.preinstall, &mut a.install, &mut a.postinstall]
            .into_iter()
            .flatten()
        {
            // Re-classify and re-bucket the shape from the cached
            // script body. `classify_script` recomputes both in one
            // call.
            *phase = classify_script(&phase.script);
        }
        a.tier = worst_of_phases(a);
        if a.tier != prev_tier {
            changed += 1;
        }
    }
    println!("reclassify: {changed} package tier(s) changed");

    finalize_outcomes(&mut audits);

    std::fs::write(&args.results, serde_json::to_vec_pretty(&audits)?)?;
    let report = build_report(&audits);
    std::fs::write(&args.report, &report)?;
    println!(
        "wrote {} audit records → {}\nwrote markdown report → {}",
        audits.len(),
        args.results.display(),
        args.report.display()
    );

    print_summary(&audits);
    Ok(())
}

async fn load_or_fetch_top_n(
    client: &reqwest::Client,
    args: &Args,
) -> Result<Vec<TopNEntry>, BoxError> {
    if !args.refresh_top_n && args.top_n_cache.exists() {
        let bytes = std::fs::read(&args.top_n_cache)?;
        let cached: Vec<TopNEntry> = serde_json::from_slice(&bytes)?;
        if cached.len() >= args.size {
            println!(
                "using cached top-N from {} ({} entries)",
                args.top_n_cache.display(),
                cached.len()
            );
            return Ok(cached.into_iter().take(args.size).collect());
        }
        println!(
            "cache at {} has {} entries (< requested {}); refreshing",
            args.top_n_cache.display(),
            cached.len(),
            args.size,
        );
    }

    println!("fetching top-{} from npm search API", args.size);
    let mut entries = Vec::with_capacity(args.size);
    let mut from = 0usize;
    let pb = ProgressBar::new(args.size as u64);
    pb.set_style(progress_style("fetch top-n"));
    while entries.len() < args.size {
        let want = (args.size - entries.len()).min(SEARCH_PAGE_SIZE);
        let url = format!(
            "{}?text=keywords:&size={}&from={}",
            SEARCH_ENDPOINT, want, from,
        );
        let resp = fetch_search_page_with_retry(client, &url).await?;
        if resp.objects.is_empty() {
            break;
        }
        for o in resp.objects {
            let rank = entries.len() + 1;
            entries.push(TopNEntry {
                name: o.package.name,
                monthly_downloads: o.downloads.monthly,
                rank,
            });
            if entries.len() >= args.size {
                break;
            }
        }
        pb.set_position(entries.len() as u64);
        from += want;
        // npm's `-/v1/search` endpoint is much more rate-limited than the
        // per-package registry endpoint. Sleep between pages to stay polite.
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
    pb.finish_with_message("top-n fetched");

    std::fs::write(&args.top_n_cache, serde_json::to_vec_pretty(&entries)?)?;
    Ok(entries)
}

async fn fetch_search_page_with_retry(
    client: &reqwest::Client,
    url: &str,
) -> Result<SearchResponse, BoxError> {
    // On 429 / 5xx, back off exponentially. Six attempts caps total wait at
    // ~63s which is well within npm's published rate-limit windows.
    let mut delay_ms = 1_000u64;
    for attempt in 1..=6u32 {
        let resp = client.get(url).send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp.json().await?);
        }
        if status.as_u16() == 429 || status.is_server_error() {
            eprintln!("search {url} returned {status}, attempt {attempt}/6, sleeping {delay_ms}ms");
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = delay_ms.saturating_mul(2);
            continue;
        }
        return Err(resp.error_for_status().unwrap_err().into());
    }
    Err(format!("exhausted retries fetching {url}").into())
}

async fn audit_top_n(
    client: &reqwest::Client,
    top_n: &[TopNEntry],
    concurrency: usize,
    resume: Option<Vec<PackageAudit>>,
) -> Result<Vec<PackageAudit>, BoxError> {
    // Build a name → prior-record lookup so we can skip successful entries.
    let prior: BTreeMap<String, PackageAudit> = resume
        .into_iter()
        .flatten()
        .map(|r| (r.name.clone(), r))
        .collect();

    let mut results: Vec<PackageAudit> = Vec::with_capacity(top_n.len());
    let mut to_fetch: Vec<TopNEntry> = Vec::new();
    for entry in top_n {
        match prior.get(&entry.name) {
            Some(r) if r.fetch_error.is_none() => results.push(r.clone()),
            _ => to_fetch.push(entry.clone()),
        }
    }
    if !prior.is_empty() {
        println!(
            "resume: {} carried over, {} to (re)fetch",
            results.len(),
            to_fetch.len()
        );
    }

    let pb = Arc::new(ProgressBar::new(to_fetch.len() as u64));
    pb.set_style(progress_style("audit"));

    let mut in_flight = FuturesUnordered::new();
    let mut iter = to_fetch.into_iter();
    for entry in iter.by_ref().take(concurrency) {
        let client = client.clone();
        let pb = Arc::clone(&pb);
        in_flight.push(tokio::spawn(
            async move { audit_one(&client, entry, pb).await },
        ));
    }
    while let Some(joined) = in_flight.next().await {
        let res = joined?;
        results.push(res);
        if let Some(entry) = iter.next() {
            let client = client.clone();
            let pb = Arc::clone(&pb);
            in_flight.push(tokio::spawn(
                async move { audit_one(&client, entry, pb).await },
            ));
        }
    }

    pb.finish_with_message("audit complete");
    results.sort_by_key(|r| r.rank);
    Ok(results)
}

async fn audit_one(
    client: &reqwest::Client,
    entry: TopNEntry,
    pb: Arc<ProgressBar>,
) -> PackageAudit {
    let manifest_url = format!("{}/{}/latest", REGISTRY_BASE, encode_pkg(&entry.name));
    // Retry on 429 / 5xx; bail with the error captured on the record otherwise
    // (most non-2xx for `/{pkg}/latest` are 404 = unpublished, which we want
    // recorded, not retried). Cap retries at ~64s total so a single stalled
    // record can't keep the whole audit alive.
    let mut delay_ms = 500u64;
    let result = loop {
        match client.get(&manifest_url).send().await {
            Err(e) => break Err::<LatestManifest, reqwest::Error>(e),
            Ok(r) => {
                let s = r.status();
                if s.is_success() {
                    break r.json::<LatestManifest>().await;
                }
                if (s.as_u16() == 429 || s.is_server_error()) && delay_ms <= 32_000 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = delay_ms.saturating_mul(2);
                    continue;
                }
                break Err(r.error_for_status().unwrap_err());
            }
        }
    };

    let mut audit = PackageAudit {
        name: entry.name.clone(),
        rank: entry.rank,
        monthly_downloads: entry.monthly_downloads,
        version: None,
        preinstall: None,
        install: None,
        postinstall: None,
        tier: None,
        l2_outcome: L2Outcome::Miss,
        l3_outcome: None,
        portable_outcome: None,
        advisor_outcome: None,
        fetch_error: None,
    };

    match result {
        Ok(manifest) => {
            audit.version = manifest.version;
            let scripts = manifest.scripts.unwrap_or_default();
            audit.preinstall = scripts.get("preinstall").map(|s| classify_script(s));
            audit.install = scripts.get("install").map(|s| classify_script(s));
            audit.postinstall = scripts.get("postinstall").map(|s| classify_script(s));
            audit.tier = worst_of_phases(&audit);
        }
        Err(e) => audit.fetch_error = Some(e.to_string()),
    }

    pb.inc(1);
    audit
}

fn classify_script(script: &str) -> ScriptAudit {
    let tier = classify(script);
    let tokens = shlex::split(script).unwrap_or_default();
    let first_token = tokens.first().map(|s| {
        // strip leading `./` or absolute path prefix to make grouping
        // stable across different relative-path styles.
        let trimmed = s.trim_start_matches("./");
        trimmed
            .split('/')
            .next_back()
            .unwrap_or(trimmed)
            .to_string()
    });
    let shape = Some(classify_shape(script, &tokens, tier));
    ScriptAudit {
        script: script.to_string(),
        tier,
        first_token,
        shape,
    }
}

/// Bucket a script into a stable normalised shape for reporting.
/// Replaces the lossy first-token grouping that previously lumped
/// softfail-wrappers, binary fetchers, and helper scripts under
/// `node`.
fn classify_shape(script: &str, tokens: &[String], tier: StaticTier) -> ScriptShape {
    let trimmed = script.trim();
    let bare = tokens.first().map(String::as_str).unwrap_or("");

    // `node -e "..."` style — captures both green and amber softfail
    // wrappers under one shape (tier disambiguates at report time).
    if bare == "node" && tokens.iter().skip(1).any(|t| t == "-e" || t == "--eval") {
        return ScriptShape::SoftfailWrapper;
    }

    // Bare native-build helpers (post-P0.5: bare `node-gyp-build` and
    // its `-optional-packages` sibling are green; bare `node-gyp` is
    // not on its own but the family clusters here for reporting).
    if matches!(
        bare,
        "node-gyp" | "node-gyp-build" | "node-gyp-build-optional-packages"
    ) {
        return ScriptShape::NativeBuild;
    }

    // No-op shapes (the @datadog/native-* family ships `exit 0`).
    if matches!(bare, "exit" | "true" | ":" | "echo") {
        return ScriptShape::NoOp;
    }

    // `prebuild-install || node-gyp rebuild` and friends — compound
    // with prebuild fetch on the left, local build on the right.
    if tokens.iter().any(|t| t == "prebuild-install")
        && tokens.iter().any(|t| t == "||" || t == "&&" || t == ";")
    {
        return ScriptShape::PrebuildFallback;
    }

    // `node <relative>` family — split by whether basename is in the
    // §4.1 reserved binary-fetcher set (mirrors the classifier's
    // `is_reserved_lifecycle_basename`, kept in sync here for
    // reporting only — the classifier remains the source of truth).
    if bare == "node" && tokens.len() >= 2 {
        let path = tokens[1].as_str();
        let basename = path.rsplit('/').next().unwrap_or(path);
        if matches!(
            basename,
            "install.js"
                | "install.cjs"
                | "install.mjs"
                | "postinstall.js"
                | "postinstall.cjs"
                | "postinstall.mjs"
                | "preinstall.js"
                | "preinstall.cjs"
                | "preinstall.mjs"
        ) {
            return ScriptShape::BinaryFetcher;
        }
        return ScriptShape::NodeHelperScript;
    }

    // Compound catch-all for amber scripts the classifier rejected on
    // operator grounds — not yet recognised by a more specific shape.
    if tier == StaticTier::Amber
        && (trimmed.contains("&&")
            || trimmed.contains("||")
            || trimmed.contains(';')
            || trimmed.contains('|')
            || trimmed.contains('>')
            || trimmed.contains('('))
    {
        return ScriptShape::Compound;
    }

    ScriptShape::Other
}

fn worst_of_phases(a: &PackageAudit) -> Option<StaticTier> {
    [&a.preinstall, &a.install, &a.postinstall]
        .into_iter()
        .flatten()
        .map(|s| s.tier)
        .reduce(StaticTier::worse_of)
}

// ─────────────────────────────────────────────────────────────────────
// Layer 3 enrichment + portable-outcome computation
// ─────────────────────────────────────────────────────────────────────

/// Fetch the registry packument and the attestations endpoint for one
/// version, derive an [`L3Outcome`]. Used by the post-L1 enrichment
/// phase. Skips fetching for packages with no scripts — L3 is only
/// meaningful for the scripted subset.
///
/// Best-effort: any fetch error is recorded on `l3_fetch_error` and the
/// remaining fields reflect partial data (defaulted), so the L3 record
/// is always emitted even when the network drops. That keeps the audit
/// resumable.
async fn fetch_l3_one(
    client: &reqwest::Client,
    name: &str,
    version: &str,
    pb: Arc<ProgressBar>,
) -> L3Outcome {
    let packument_url = format!("{}/{}", REGISTRY_BASE, encode_pkg(name));
    let attestations_url = format!(
        "{}/-/npm/v1/attestations/{}@{}",
        REGISTRY_BASE,
        encode_pkg(name),
        version
    );

    // Packument fetch (carries `time[<version>]`).
    let pack_res = fetch_packument_with_retry(client, &packument_url).await;
    let (published_at, packument_err) = match pack_res {
        Ok(p) => (p.time.get(version).cloned(), None),
        Err(e) => (None, Some(format!("packument: {e}"))),
    };

    // Attestations fetch — 404 means "no attestation", which is a
    // legitimate answer, NOT an error.
    let (attestation_present, attestation_err) =
        fetch_attestation_presence(client, &attestations_url).await;

    let age_secs = published_at.as_deref().and_then(parse_age_secs);
    let policy = SecurityPolicy::default_policy();
    let cooldown_block = policy.check_release_age(published_at.as_deref()).is_some();

    let l3_fetch_error = match (packument_err, attestation_err) {
        (Some(p), Some(a)) => Some(format!("{p}; {a}")),
        (Some(p), None) => Some(p),
        (None, Some(a)) => Some(a),
        (None, None) => None,
    };

    pb.inc(1);
    L3Outcome {
        published_at,
        age_secs,
        cooldown_block,
        attestation_present,
        // First-install audit always lands here — see ProvenanceDriftSummary
        // docs.
        provenance_drift: ProvenanceDriftSummary::NoDrift,
        l3_fetch_error,
    }
}

async fn fetch_packument_with_retry(
    client: &reqwest::Client,
    url: &str,
) -> Result<Packument, BoxError> {
    let mut delay_ms = 500u64;
    loop {
        match client.get(url).send().await {
            Err(e) => return Err(Box::new(e)),
            Ok(r) => {
                let s = r.status();
                if s.is_success() {
                    return Ok(r.json::<Packument>().await?);
                }
                if (s.as_u16() == 429 || s.is_server_error()) && delay_ms <= 32_000 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = delay_ms.saturating_mul(2);
                    continue;
                }
                return Err(Box::new(r.error_for_status().unwrap_err()));
            }
        }
    }
}

/// Attestations endpoint protocol: 200 with `attestations` array =>
/// present (we treat any non-empty array as present); 404 => absent
/// (legitimate — most packages don't have attestations); other errors
/// => `(false, Some(error))` so the report can distinguish "definitely
/// absent" from "network dropped". We never retry forever — three
/// attempts is enough to ride out a transient 429.
async fn fetch_attestation_presence(client: &reqwest::Client, url: &str) -> (bool, Option<String>) {
    let mut delay_ms = 500u64;
    for _ in 0..4 {
        match client.get(url).send().await {
            Err(e) => return (false, Some(format!("attestations: {e}"))),
            Ok(r) => {
                let s = r.status();
                if s.is_success() {
                    return match r.json::<AttestationsResponse>().await {
                        Ok(a) => (!a.attestations.is_empty(), None),
                        Err(e) => (false, Some(format!("attestations: {e}"))),
                    };
                }
                if s.as_u16() == 404 {
                    return (false, None);
                }
                if (s.as_u16() == 429 || s.is_server_error()) && delay_ms <= 8_000 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = delay_ms.saturating_mul(2);
                    continue;
                }
                return (
                    false,
                    Some(format!(
                        "attestations: {}",
                        r.error_for_status().unwrap_err()
                    )),
                );
            }
        }
    }
    (false, Some("attestations: retries exhausted".to_string()))
}

/// Parse an ISO 8601 timestamp string and return age in seconds vs.
/// the current epoch time. Returns `None` if parsing fails — same
/// fail-closed contract as `SecurityPolicy::check_release_age` (which
/// treats unparseable as "just published"), but the audit records the
/// failure rather than asserting an age.
fn parse_age_secs(iso8601: &str) -> Option<u64> {
    use time::format_description::well_known::Rfc3339;
    let t = time::OffsetDateTime::parse(iso8601, &Rfc3339).ok()?;
    let now = time::OffsetDateTime::now_utc();
    let secs = (now - t).whole_seconds();
    if secs < 0 { None } else { Some(secs as u64) }
}

/// Compute the portable-contract outcome from the L1+L2+L3 trace.
/// Deterministic, no I/O. The decision tree:
///
/// - no L1 tier (no scripts in manifest)        → NoScripts
/// - L1 = Red                                   → HardBlock
/// - L1 = Green + L2 ≠ Drift                    → AutoRun
/// - L1 = Amber + L2 = StrictMatch              → AutoRun
/// - L1 = Amber + L3 cooldown_block             → HardBlock
/// - L1 = Amber + L3 provenance_drift ≠ NoDrift → HardBlock
/// - L1 = Amber + L3 pass                       → Prompt
/// - L2 = Drift                                 → HardBlock
fn compute_portable_outcome(a: &PackageAudit) -> PortableOutcome {
    let Some(tier) = a.tier else {
        return PortableOutcome::NoScripts;
    };

    if a.l2_outcome == L2Outcome::Drift {
        return PortableOutcome::HardBlock;
    }

    match tier {
        StaticTier::Red => PortableOutcome::HardBlock,
        StaticTier::Green => PortableOutcome::AutoRun,
        StaticTier::Amber | StaticTier::AmberLlm => {
            if a.l2_outcome == L2Outcome::StrictMatch {
                return PortableOutcome::AutoRun;
            }
            if let Some(l3) = &a.l3_outcome
                && (l3.cooldown_block || l3.provenance_drift != ProvenanceDriftSummary::NoDrift)
            {
                return PortableOutcome::HardBlock;
            }
            PortableOutcome::Prompt
        }
    }
}

fn encode_pkg(name: &str) -> String {
    // Scoped packages (`@scope/name`) need the `@` and `/` URL-encoded for the
    // registry path. Everything else can be passed verbatim — registry names
    // are restricted to a small ASCII subset.
    if let Some(rest) = name.strip_prefix('@') {
        format!("@{}", rest.replace('/', "%2F"))
    } else {
        name.to_string()
    }
}

fn progress_style(prefix: &str) -> ProgressStyle {
    ProgressStyle::with_template(&format!(
        "{prefix} [{{elapsed_precise}}] [{{wide_bar:.cyan/blue}}] {{pos}}/{{len}} ({{eta}})"
    ))
    .unwrap()
    .progress_chars("█▉▊▋▌▍▎▏ ")
}

#[derive(Debug, Default)]
struct Summary {
    green: usize,
    amber: usize,
    red: usize,
    no_scripts: usize,
    fetch_failed: usize,
}

impl Summary {
    fn scripted_total(&self) -> usize {
        self.green + self.amber + self.red
    }
    fn green_share_pct(&self) -> f64 {
        let denom = (self.green + self.amber) as f64;
        if denom == 0.0 {
            0.0
        } else {
            (self.green as f64) * 100.0 / denom
        }
    }
}

fn summarise(audits: &[PackageAudit]) -> Summary {
    let mut s = Summary::default();
    for a in audits {
        if a.fetch_error.is_some() {
            s.fetch_failed += 1;
            continue;
        }
        match a.tier {
            Some(StaticTier::Green) => s.green += 1,
            Some(StaticTier::Amber) | Some(StaticTier::AmberLlm) => s.amber += 1,
            Some(StaticTier::Red) => s.red += 1,
            None => s.no_scripts += 1,
        }
    }
    s
}

/// Distribution over [`PortableOutcome`] — the decision-grade view.
#[derive(Debug, Default)]
struct PortableSummary {
    auto_run: usize,
    prompt: usize,
    hard_block: usize,
    no_scripts: usize,
}

fn summarise_portable(audits: &[PackageAudit]) -> PortableSummary {
    let mut s = PortableSummary::default();
    for a in audits {
        if a.fetch_error.is_some() {
            // Fetch failures aren't a portable outcome; exclude from
            // both numerator and denominator so the rate isn't
            // dilated by transient registry errors.
            continue;
        }
        match a.portable_outcome {
            Some(PortableOutcome::AutoRun) => s.auto_run += 1,
            Some(PortableOutcome::Prompt) => s.prompt += 1,
            Some(PortableOutcome::HardBlock) => s.hard_block += 1,
            Some(PortableOutcome::NoScripts) | None => s.no_scripts += 1,
        }
    }
    s
}

fn build_report(audits: &[PackageAudit]) -> String {
    let mut out = String::new();
    out.push_str("# Phase 46 — Top-N audit (L1-3, portable)\n\n");
    out.push_str(&format!("Total packages audited: **{}**\n\n", audits.len()));

    section_l1_tier_distribution(&mut out, audits);
    section_portable_outcome(&mut out, audits);
    section_l1_to_portable_transition(&mut out, audits);
    section_l3_detail(&mut out, audits);
    section_red_packages(&mut out, audits);
    section_amber_shape_buckets(&mut out, audits);
    section_advisor_baseline_placeholder(&mut out, audits);

    out
}

fn section_l1_tier_distribution(out: &mut String, audits: &[PackageAudit]) {
    let summary = summarise(audits);
    let total = audits.len() as f64;
    let scripted = summary.scripted_total() as f64;
    let pct_audited = |n: usize| {
        if total == 0.0 {
            0.0
        } else {
            n as f64 * 100.0 / total
        }
    };
    let pct_scripted = |n: usize| {
        if scripted == 0.0 {
            0.0
        } else {
            n as f64 * 100.0 / scripted
        }
    };

    out.push_str("## Layer 1 — static tier distribution\n\n");
    out.push_str("| Tier | Count | % of audited | % of scripted |\n");
    out.push_str("|------|------:|-------------:|-------------:|\n");
    out.push_str(&format!(
        "| green | {} | {:.2}% | {:.2}% |\n",
        summary.green,
        pct_audited(summary.green),
        pct_scripted(summary.green)
    ));
    out.push_str(&format!(
        "| amber | {} | {:.2}% | {:.2}% |\n",
        summary.amber,
        pct_audited(summary.amber),
        pct_scripted(summary.amber)
    ));
    out.push_str(&format!(
        "| red | {} | {:.2}% | {:.2}% |\n",
        summary.red,
        pct_audited(summary.red),
        pct_scripted(summary.red)
    ));
    out.push_str(&format!(
        "| no-scripts | {} | {:.2}% | — |\n",
        summary.no_scripts,
        pct_audited(summary.no_scripts)
    ));
    out.push_str(&format!(
        "| fetch-failed | {} | {:.2}% | — |\n\n",
        summary.fetch_failed,
        pct_audited(summary.fetch_failed)
    ));
    out.push_str(&format!(
        "L1 green / (green + amber) over scripted = **{:.2}%** (§4.1 corpus floor: ≥60% on the curated 500-entry corpus; live distribution is not gated by that floor).\n\n",
        summary.green_share_pct(),
    ));
}

fn section_portable_outcome(out: &mut String, audits: &[PackageAudit]) {
    let p = summarise_portable(audits);
    let scripted = p.auto_run + p.prompt + p.hard_block;
    let pct = |n: usize, denom: usize| {
        if denom == 0 {
            0.0
        } else {
            n as f64 * 100.0 / denom as f64
        }
    };

    out.push_str("## Portable baseline (L1-3, advisor=none) — decision-grade\n\n");
    out.push_str(
        "The portable contract is what `script-policy = \"triage\"` means on \
         a machine with `triage-advisor = \"none\"`. Triage must mean the \
         same thing on every machine, so this is the metric a future \
         default decision should be measured against.\n\n",
    );
    out.push_str("| Outcome | Count | % of scripted |\n");
    out.push_str("|---------|------:|-------------:|\n");
    out.push_str(&format!(
        "| auto-run | {} | {:.2}% |\n",
        p.auto_run,
        pct(p.auto_run, scripted)
    ));
    out.push_str(&format!(
        "| prompt | {} | {:.2}% |\n",
        p.prompt,
        pct(p.prompt, scripted)
    ));
    out.push_str(&format!(
        "| hard-block | {} | {:.2}% |\n",
        p.hard_block,
        pct(p.hard_block, scripted)
    ));
    out.push_str(&format!("| no-scripts | {} | — |\n\n", p.no_scripts,));
    out.push_str(&format!(
        "**Portable auto-run rate over scripted = {:.2}%.** \
         This is essentially the L1 green rate; L2 always misses in a \
         first-install audit and L3 only adds blocks, never approvals.\n\n",
        pct(p.auto_run, scripted),
    ));
}

fn section_l1_to_portable_transition(out: &mut String, audits: &[PackageAudit]) {
    let mut green_to: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut amber_to: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut red_to: BTreeMap<&'static str, usize> = BTreeMap::new();
    for a in audits {
        if a.fetch_error.is_some() {
            continue;
        }
        let bucket = match a.portable_outcome {
            Some(PortableOutcome::AutoRun) => "auto-run",
            Some(PortableOutcome::Prompt) => "prompt",
            Some(PortableOutcome::HardBlock) => "hard-block",
            _ => continue,
        };
        match a.tier {
            Some(StaticTier::Green) => *green_to.entry(bucket).or_default() += 1,
            Some(StaticTier::Amber) | Some(StaticTier::AmberLlm) => {
                *amber_to.entry(bucket).or_default() += 1
            }
            Some(StaticTier::Red) => *red_to.entry(bucket).or_default() += 1,
            None => {}
        }
    }
    out.push_str("## L1 → portable transition matrix\n\n");
    out.push_str("How L2+L3 reshape each L1 tier:\n\n");
    out.push_str(
        "| L1 tier → | auto-run | prompt | hard-block |\n\
         |-----------|---------:|-------:|-----------:|\n",
    );
    let cell = |m: &BTreeMap<&'static str, usize>, k: &'static str| {
        m.get(k).copied().unwrap_or(0).to_string()
    };
    out.push_str(&format!(
        "| green | {} | {} | {} |\n",
        cell(&green_to, "auto-run"),
        cell(&green_to, "prompt"),
        cell(&green_to, "hard-block")
    ));
    out.push_str(&format!(
        "| amber | {} | {} | {} |\n",
        cell(&amber_to, "auto-run"),
        cell(&amber_to, "prompt"),
        cell(&amber_to, "hard-block")
    ));
    out.push_str(&format!(
        "| red | {} | {} | {} |\n\n",
        cell(&red_to, "auto-run"),
        cell(&red_to, "prompt"),
        cell(&red_to, "hard-block")
    ));
}

fn section_l3_detail(out: &mut String, audits: &[PackageAudit]) {
    let scripted: Vec<&PackageAudit> = audits
        .iter()
        .filter(|a| a.tier.is_some() && a.fetch_error.is_none())
        .collect();
    let with_l3 = scripted.iter().filter(|a| a.l3_outcome.is_some()).count();
    let cooldown_blocks: Vec<&&PackageAudit> = scripted
        .iter()
        .filter(|a| a.l3_outcome.as_ref().is_some_and(|l| l.cooldown_block))
        .collect();
    let with_attestation: Vec<&&PackageAudit> = scripted
        .iter()
        .filter(|a| a.l3_outcome.as_ref().is_some_and(|l| l.attestation_present))
        .collect();

    out.push_str("## Layer 3 — cooldown + attestation detail\n\n");
    out.push_str(&format!(
        "- {} of {} scripted packages have L3 data populated.\n",
        with_l3,
        scripted.len()
    ));
    out.push_str(&format!(
        "- **Cooldown blocks**: {} package(s) with latest release published within 24h.\n",
        cooldown_blocks.len(),
    ));
    out.push_str(&format!(
        "- **Attestation present**: {} of {} scripted packages publish Sigstore provenance.\n\n",
        with_attestation.len(),
        scripted.len(),
    ));

    if !cooldown_blocks.is_empty() {
        out.push_str("### Scripted packages blocked by cooldown\n\n");
        out.push_str("| Rank | Package | Monthly DL | Published | Age (s) |\n");
        out.push_str("|-----:|---------|----------:|-----------|--------:|\n");
        let mut sorted = cooldown_blocks.clone();
        sorted.sort_by_key(|a| a.rank);
        for a in sorted {
            if let Some(l3) = &a.l3_outcome {
                out.push_str(&format!(
                    "| {} | `{}` | {} | {} | {} |\n",
                    a.rank,
                    a.name,
                    a.monthly_downloads,
                    l3.published_at.as_deref().unwrap_or("?"),
                    l3.age_secs
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                ));
            }
        }
        out.push('\n');
    }
}

fn section_red_packages(out: &mut String, audits: &[PackageAudit]) {
    out.push_str("## Red-classified packages (zero-FP-red gate)\n\n");
    let mut reds: Vec<&PackageAudit> = audits
        .iter()
        .filter(|a| a.tier == Some(StaticTier::Red))
        .collect();
    reds.sort_by_key(|a| a.rank);
    if reds.is_empty() {
        out.push_str("_None — zero-FP-red gate held on this run._\n\n");
        return;
    }
    out.push_str(&format!("Total: **{}**\n\n", reds.len()));
    out.push_str("| Rank | Package | Monthly DL | Phase | Script |\n");
    out.push_str("|-----:|---------|----------:|-------|--------|\n");
    for a in reds {
        for (phase, script) in red_phases(a) {
            out.push_str(&format!(
                "| {} | `{}` | {} | {} | `{}` |\n",
                a.rank,
                a.name,
                a.monthly_downloads,
                phase,
                escape_md(&script.script),
            ));
        }
    }
    out.push('\n');
}

fn section_amber_shape_buckets(out: &mut String, audits: &[PackageAudit]) {
    let mut buckets: BTreeMap<ScriptShape, AmberBucket> = BTreeMap::new();
    for a in audits {
        for (_phase, script) in scripted_phases(a) {
            if !matches!(script.tier, StaticTier::Amber | StaticTier::AmberLlm) {
                continue;
            }
            let shape = script.shape.unwrap_or(ScriptShape::Other);
            let bucket = buckets.entry(shape).or_default();
            bucket.count += 1;
            if bucket.examples.len() < 5 {
                bucket
                    .examples
                    .push((a.name.clone(), script.script.clone()));
            }
        }
    }
    let mut bucket_vec: Vec<(ScriptShape, AmberBucket)> = buckets.into_iter().collect();
    bucket_vec.sort_by(|a, b| b.1.count.cmp(&a.1.count));

    out.push_str("## Amber scripts grouped by normalised shape\n\n");
    out.push_str(
        "Replaces the lossy first-token bucketing. Each shape is a \
         green-allowlist-iteration candidate: if a shape clusters \
         packages we trust, that's a green-list expansion target.\n\n",
    );
    out.push_str("| Shape | Amber count | Sample packages → script |\n");
    out.push_str("|-------|-----------:|----|\n");
    for (shape, bucket) in bucket_vec.iter() {
        let samples = bucket
            .examples
            .iter()
            .map(|(pkg, s)| format!("`{pkg}` → `{}`", escape_md(s)))
            .collect::<Vec<_>>()
            .join("<br>");
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            shape_label(*shape),
            bucket.count,
            samples
        ));
    }
    out.push('\n');
}

fn shape_label(s: ScriptShape) -> &'static str {
    match s {
        ScriptShape::SoftfailWrapper => "softfail-wrapper",
        ScriptShape::BinaryFetcher => "binary-fetcher",
        ScriptShape::NativeBuild => "native-build",
        ScriptShape::NoOp => "no-op",
        ScriptShape::PrebuildFallback => "prebuild-fallback",
        ScriptShape::Compound => "compound",
        ScriptShape::NodeHelperScript => "node-helper-script",
        ScriptShape::Other => "other",
    }
}

fn section_advisor_baseline_placeholder(out: &mut String, audits: &[PackageAudit]) {
    let any_advisor = audits.iter().any(|a| a.advisor_outcome.is_some());
    out.push_str("## Advisor-enhanced baseline (L1-4)\n\n");
    if !any_advisor {
        out.push_str(
            "_No advisor configured (`triage-advisor = \"none\"`). \
             Portable baseline above is the authoritative outcome for \
             this run. Advisor uplift will appear here once Part B \
             lands._\n\n",
        );
    } else {
        // Reserved for Part B; not yet implemented in detail.
        out.push_str(
            "_Part B reporting placeholder — populate once advisor outcomes are recorded._\n\n",
        );
    }
}

#[derive(Debug, Default)]
struct AmberBucket {
    count: usize,
    examples: Vec<(String, String)>,
}

fn scripted_phases(a: &PackageAudit) -> Vec<(&'static str, &ScriptAudit)> {
    let mut v = Vec::new();
    if let Some(s) = a.preinstall.as_ref() {
        v.push(("preinstall", s));
    }
    if let Some(s) = a.install.as_ref() {
        v.push(("install", s));
    }
    if let Some(s) = a.postinstall.as_ref() {
        v.push(("postinstall", s));
    }
    v
}

fn red_phases(a: &PackageAudit) -> Vec<(&'static str, &ScriptAudit)> {
    scripted_phases(a)
        .into_iter()
        .filter(|(_p, s)| s.tier == StaticTier::Red)
        .collect()
}

fn escape_md(s: &str) -> String {
    // Markdown table cells need backticks/pipes/newlines neutralised so a
    // rogue script can't break the table layout.
    s.replace('|', "\\|").replace('\n', " ").replace('`', "\\`")
}
