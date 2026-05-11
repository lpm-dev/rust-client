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
use lpm_triage_advisor::{
    Advisor, AdvisorFailure, AdvisorVerdict as TriageVerdict, AmberScript as TriageAmberScript,
    ClaudeCliAdapter, CodexAdapter, OllamaAdapter, Provider as AdvisorProvider, binary_path,
    prompt_template_hash, provider_version,
};
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

    /// Invoke the named Layer 4 advisor on every package whose
    /// portable outcome is `Prompt`, recording the verdict on
    /// `advisor_outcome`. Reported as a separate uplift line, never
    /// blended with the portable baseline. Valid values:
    /// `claude-cli` / `codex` / `ollama`.
    #[arg(long)]
    advisor: Option<String>,

    /// Phase 69 — corpus selector. `live` (default) walks the npm
    /// search API and fetches manifests over the network; `hermetic`
    /// reads a frozen offline fixture set bundled with this crate
    /// and runs the SAME classifier / L3 / advisor pipeline against
    /// it without touching the network.
    ///
    /// Hermetic mode is for reproducible benchmark runs: classifier
    /// regressions show up as a delta against the frozen fixture's
    /// expected distribution. Live mode is for measuring the real
    /// top-N today.
    ///
    /// When `hermetic` is selected, the following flags are ignored:
    /// `--size`, `--top-n-cache`, `--refresh-top-n`, `--timeout-secs`,
    /// `--concurrency`, `--resume`, `--enrich-l3-only`, `--skip-l3`,
    /// `--reclassify`. `--advisor` still works (it's an opt-in
    /// uplift, orthogonal to corpus origin).
    #[arg(long, value_enum, default_value_t = CorpusKind::Live)]
    corpus: CorpusKind,
}

/// Origin of the audit corpus. See [`Args::corpus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum CorpusKind {
    /// Walk the npm registry search API + fetch manifests over the
    /// network. The default — preserves pre-Phase-69 behavior.
    Live,
    /// Read the bundled offline fixture set
    /// (`crates/lpm-audit-corpus/fixtures/hermetic/corpus.json`).
    /// No network calls; output shape is identical to live mode so
    /// the same Markdown report + standing-benchmark table fires.
    Hermetic,
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
    /// Populated only when an advisor was invoked on this package;
    /// otherwise `None` and the portable outcome is the authoritative
    /// answer for this run.
    #[serde(default)]
    advisor_outcome: Option<AdvisorOutcome>,
    /// Provider slug for the advisor that produced `advisor_outcome`
    /// (e.g. `"claude-cli"`). Lets the report name the advisor in
    /// its conclusion sentence without an out-of-band side channel.
    #[serde(default)]
    advisor_provider: Option<String>,
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

/// Per-run metadata stamp. Persisted to a sidecar file alongside the
/// audit results JSON so future comparative runs can attribute uplift
/// drift to advisor identity (provider, binary path, version) vs
/// prompt-template iteration (`prompt_template_hash`) vs everything
/// else. Without this, +1 today vs +2 tomorrow is muddy.
///
/// Stored in a SIDECAR (`<results>.meta.json`) rather than wrapped
/// into the records file so existing tooling that deserialises
/// `Vec<PackageAudit>` doesn't break. Schema-wise it's append-only:
/// all fields use `serde(default)` so older sidecars still parse.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AuditMetadata {
    /// Wall-clock timestamp the audit run finished (ISO 8601 UTC).
    #[serde(default)]
    run_completed_at: Option<String>,
    /// `--size` value that produced the audited population.
    #[serde(default)]
    audit_size: Option<usize>,
    /// L4 advisor stamp. `None` when the run had no `--advisor`.
    #[serde(default)]
    advisor: Option<AdvisorStamp>,
    /// Phase 69 — corpus origin: `"live"` for npm-walked, `"hermetic"`
    /// for the frozen offline fixture. Stamped so the report writer
    /// can pick the right interpretation for ambiguous metrics
    /// (e.g. zero-FP-red is a §4.1 ship gate on live but expected
    /// fixture coverage on hermetic). `None` on records written
    /// before this field existed; readers default to the live
    /// interpretation in that case.
    #[serde(default)]
    corpus: Option<String>,
}

/// Identity of the advisor that ran on this audit. Lets future
/// comparison runs explain "+1 vs +2 uplift" by showing whether the
/// binary version, prompt template, or model changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdvisorStamp {
    /// Provider slug (`claude-cli` / `codex` / `ollama`).
    provider: String,
    /// Absolute path of the binary that ran. `None` if the adapter
    /// invokes via HTTP only (Ollama) and the CLI isn't on PATH.
    #[serde(default)]
    binary_path: Option<String>,
    /// Output of `<binary> --version`. Best-effort: `None` if the
    /// binary doesn't support `--version` or the probe failed.
    #[serde(default)]
    binary_version: Option<String>,
    /// For Ollama only: the model name passed to `/api/generate`.
    /// `None` for CLI providers.
    #[serde(default)]
    model: Option<String>,
    /// SHA-256 of the canonical prompt rendering. Changes iff
    /// [`lpm_triage_advisor::build_prompt`] changes.
    prompt_template_hash: String,
    /// Count of packages the advisor was invoked on (== number of
    /// packages with `portable_outcome = Prompt` at invocation time).
    invoked_count: usize,
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

    if args.corpus == CorpusKind::Hermetic {
        // Phase 69 — offline mode. Skip every network code path, run
        // L1+L3+advisor against the bundled fixture, write the same
        // results + report + sidecar shape so downstream tooling
        // (incl. the standing-benchmark table writer) is unchanged.
        return run_hermetic(&args).await;
    }

    if args.reclassify {
        return reclassify_from_cache(&args).await;
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

    let mut metadata = AuditMetadata {
        run_completed_at: Some(now_rfc3339()),
        audit_size: Some(args.size),
        advisor: None,
        corpus: Some("live".to_string()),
    };

    if let Some(name) = &args.advisor {
        metadata.advisor = enrich_advisor_in_place(name, &mut audits).await?;
    }

    persist_audit(&args.results, &args.report, &audits, &metadata)?;
    print_summary(&audits);
    Ok(())
}

/// Persist the records JSON, the sidecar metadata JSON, and the
/// Markdown report in one go. All three are derived from the same
/// in-memory state, so a single helper keeps them in lockstep across
/// the audit / reclassify / enrich-l3-only paths.
fn persist_audit(
    results_path: &std::path::Path,
    report_path: &std::path::Path,
    audits: &[PackageAudit],
    metadata: &AuditMetadata,
) -> Result<(), BoxError> {
    std::fs::write(results_path, serde_json::to_vec_pretty(audits)?)?;
    let meta_path = sidecar_metadata_path(results_path);
    std::fs::write(&meta_path, serde_json::to_vec_pretty(metadata)?)?;
    let report = build_report(audits, metadata);
    std::fs::write(report_path, &report)?;
    println!(
        "wrote {} audit records → {}\nwrote metadata → {}\nwrote markdown report → {}",
        audits.len(),
        results_path.display(),
        meta_path.display(),
        report_path.display()
    );
    Ok(())
}

/// Sidecar metadata path: `<results>.meta.json`. Picked rather than
/// wrapping the records file so existing tooling that deserialises a
/// bare `Vec<PackageAudit>` keeps working.
fn sidecar_metadata_path(results_path: &std::path::Path) -> std::path::PathBuf {
    let mut s = results_path.as_os_str().to_owned();
    s.push(".meta.json");
    std::path::PathBuf::from(s)
}

/// Load the metadata sidecar if it exists, else default. Used by the
/// reclassify / enrich-l3-only paths so we preserve prior-run
/// metadata when the new pass doesn't itself invoke the advisor.
fn load_sidecar_metadata(results_path: &std::path::Path) -> AuditMetadata {
    let path = sidecar_metadata_path(results_path);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => AuditMetadata::default(),
    }
}

fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::now_utc();
    now.format(&Rfc3339).unwrap_or_else(|_| String::new())
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

    // Carry forward any prior metadata (cooldown of an earlier run is
    // still meaningful even if we didn't run an advisor this time),
    // but always refresh `run_completed_at` so the sidecar timestamp
    // reflects when this pass actually ran.
    let mut metadata = load_sidecar_metadata(&args.results);
    metadata.run_completed_at = Some(now_rfc3339());
    metadata.audit_size = metadata.audit_size.or(Some(args.size));

    if let Some(name) = &args.advisor {
        metadata.advisor = enrich_advisor_in_place(name, &mut audits).await?;
    }

    persist_audit(&args.results, &args.report, &audits, &metadata)?;
    print_summary(&audits);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Layer 4 enrichment: invoke an advisor over every prompted package.
// ─────────────────────────────────────────────────────────────────────
// Phase 69 — hermetic offline corpus mode
// ─────────────────────────────────────────────────────────────────────

/// One entry in `fixtures/hermetic/corpus.json`. A synthetic
/// "package" — name + version + lifecycle scripts + L3 inputs —
/// that the hermetic loader maps to a [`PackageAudit`] using the
/// same classifier / outcome logic the live path uses.
///
/// Format choice rationale: deliberately NOT a serialised
/// `PackageAudit`. The fixture's job is to lock the INPUTS (script
/// bodies, publish-age window, attestation presence) and let the
/// rest of the pipeline produce outputs the same way it would for a
/// live npm package. That way the standing-benchmark table is a
/// stable shape that re-runs with no network, and a classifier
/// regression shows up as an output delta rather than as a
/// fixture-edit conflict.
#[derive(Debug, Clone, Deserialize)]
struct HermeticEntry {
    name: String,
    rank: usize,
    monthly_downloads: u64,
    version: String,
    /// `{ "preinstall" | "install" | "postinstall": <body> }`. Empty
    /// map ⇒ no-script package (`PortableOutcome::NoScripts`).
    #[serde(default)]
    scripts: BTreeMap<String, String>,
    /// Hours-before-now the synthetic "publish" happened. Loader
    /// translates to a concrete ISO 8601 timestamp at run time so
    /// the cooldown gate's `now - published_at < min_release_age`
    /// math hits the same code path live uses. Values >> 24 are
    /// "old" (cooldown-pass); values < 24 fire the cooldown block.
    publish_age_hours: u64,
    /// Whether the fixture declares this package as having Sigstore
    /// attestations published. Plain bool — no fetch.
    attestation_present: bool,
}

const HERMETIC_CORPUS_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/hermetic/corpus.json");

/// Phase 69 — run the audit against the bundled offline corpus.
///
/// Identical control flow to the live path's `main()`:
/// `audit_top_n` equivalent → `enrich_l3_in_place` equivalent →
/// `finalize_outcomes` → optional `--advisor` enrichment →
/// `persist_audit` + `print_summary`. The only difference is that
/// the per-package data comes from the fixture instead of from
/// network calls.
async fn run_hermetic(args: &Args) -> Result<(), BoxError> {
    let bytes = std::fs::read(HERMETIC_CORPUS_PATH).map_err(|e| {
        format!(
            "hermetic corpus not readable at {HERMETIC_CORPUS_PATH}: {e} \
             (this file ships with the crate; a missing read means a \
             corrupted checkout or a stripped-down install — re-clone \
             the rust-client repo)"
        )
    })?;
    let entries: Vec<HermeticEntry> = serde_json::from_slice(&bytes)
        .map_err(|e| format!("hermetic corpus parse error at {HERMETIC_CORPUS_PATH}: {e}"))?;
    println!(
        "hermetic: loaded {} synthetic packages from {HERMETIC_CORPUS_PATH}",
        entries.len()
    );

    let mut audits: Vec<PackageAudit> = entries.into_iter().map(hermetic_entry_to_audit).collect();
    audits.sort_by_key(|r| r.rank);
    finalize_outcomes(&mut audits);

    // Audit-size in the sidecar reflects the FIXTURE size in
    // hermetic mode, not `--size` (which was ignored). Lets the
    // sidecar carry a meaningful number for downstream tooling that
    // expects `audit_size` to mean "how many records did we audit."
    let mut metadata = AuditMetadata {
        run_completed_at: Some(now_rfc3339()),
        audit_size: Some(audits.len()),
        advisor: None,
        corpus: Some("hermetic".to_string()),
    };

    if let Some(name) = &args.advisor {
        metadata.advisor = enrich_advisor_in_place(name, &mut audits).await?;
    }

    persist_audit(&args.results, &args.report, &audits, &metadata)?;
    print_summary(&audits);
    Ok(())
}

/// Map one fixture entry to a [`PackageAudit`]. Mirrors the
/// post-fetch construction at `audit_one` + the L3 derivation at
/// `fetch_l3_one`, but reads every field from the fixture instead of
/// the network.
fn hermetic_entry_to_audit(entry: HermeticEntry) -> PackageAudit {
    let preinstall = entry.scripts.get("preinstall").map(|s| classify_script(s));
    let install = entry.scripts.get("install").map(|s| classify_script(s));
    let postinstall = entry.scripts.get("postinstall").map(|s| classify_script(s));

    let mut audit = PackageAudit {
        name: entry.name.clone(),
        rank: entry.rank,
        monthly_downloads: entry.monthly_downloads,
        version: Some(entry.version.clone()),
        preinstall,
        install,
        postinstall,
        tier: None,
        l2_outcome: L2Outcome::Miss,
        l3_outcome: None,
        portable_outcome: None,
        advisor_outcome: None,
        advisor_provider: None,
        fetch_error: None,
    };
    audit.tier = worst_of_phases(&audit);

    // L3 is only meaningful for scripted packages — same gate the
    // live path applies inside `enrich_l3_in_place`.
    if audit.tier.is_some() {
        audit.l3_outcome = Some(hermetic_l3_outcome(
            entry.publish_age_hours,
            entry.attestation_present,
        ));
    }

    audit
}

/// Derive a fully-populated [`L3Outcome`] from the fixture's
/// `publish_age_hours` + `attestation_present`. Routes through the
/// SAME `SecurityPolicy::check_release_age` the live path uses so
/// the cooldown decision is byte-identical to what
/// `enrich_l3_in_place` would emit for an equivalently-aged real
/// package.
fn hermetic_l3_outcome(publish_age_hours: u64, attestation_present: bool) -> L3Outcome {
    use time::format_description::well_known::Rfc3339;
    // `publish_age_hours` is unbounded in theory; in practice the
    // fixture file only carries values in the [1, 8760] range
    // (1 hour … 1 year). Saturating math keeps the arithmetic
    // well-defined for any value a future fixture edit might
    // introduce without sneaking a panic into the audit binary.
    let age_secs = publish_age_hours.saturating_mul(3600);
    let now = time::OffsetDateTime::now_utc();
    let published_dt = now - time::Duration::seconds(age_secs as i64);
    let published_at = published_dt.format(&Rfc3339).ok().map(|s| s.to_string());

    let policy = SecurityPolicy::default_policy();
    let cooldown_block = policy.check_release_age(published_at.as_deref()).is_some();

    L3Outcome {
        published_at,
        age_secs: Some(age_secs),
        cooldown_block,
        attestation_present,
        // First-install audit always lands here — matches the live
        // path's invariant. A future audit that simulates prior
        // approval state would populate this differently.
        provenance_drift: ProvenanceDriftSummary::NoDrift,
        l3_fetch_error: None,
    }
}

// ─────────────────────────────────────────────────────────────────────

/// Spawn the named advisor and invoke it on every `portable_outcome
/// = Prompt` package. Records the verdict on `advisor_outcome` and
/// recomputes the advisor-enhanced final outcome.
///
/// Failures are surfaced as records, not run aborts: an
/// `EnvironmentNotReady` for one package downgrades that package's
/// advisor outcome to whatever the portable outcome was (no uplift),
/// but the audit continues. An `IntegrationFailure` is the same — the
/// audit harness's job is to MEASURE, not to fix the advisor mid-run.
async fn enrich_advisor_in_place(
    name: &str,
    audits: &mut [PackageAudit],
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

    let pb = Arc::new(ProgressBar::new(targets.len() as u64));
    pb.set_style(progress_style("L4 advise"));

    for idx in targets {
        let (verdict_label, advisor_outcome) =
            classify_one_with_advisor(&*advisor, &audits[idx]).await;
        audits[idx].advisor_outcome = Some(advisor_outcome);
        audits[idx].advisor_provider = Some(provider.slug().to_string());
        if let Some(l) = verdict_label {
            tracing::info!(target: "lpm_audit_corpus::advisor", rank = audits[idx].rank, name = %audits[idx].name, verdict = l, "advisor verdict");
        }
        pb.inc(1);
    }
    pb.finish_with_message("L4 advisor complete");

    Ok(Some(stamp))
}

/// Run the advisor on a single package's amber script(s). Worst-of
/// across phases (matches the L1 worst-of-phases logic). Returns
/// `(verdict_label_for_logging, final_advisor_outcome)`.
async fn classify_one_with_advisor(
    advisor: &dyn Advisor,
    pkg: &PackageAudit,
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
    let mut worst = TriageVerdict::Approve;
    let mut saw_failure = false;
    for (phase_name, script) in &amber_phases {
        let amber = TriageAmberScript {
            package_name: &pkg.name,
            package_version: version,
            phase: phase_name,
            script_body: &script.script,
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
        // package, never block.
        return (Some("failure"), AdvisorOutcome::Prompt);
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

    let advisor = summarise_advisor(audits);
    if advisor.invoked > 0 {
        println!(
            "Advisor-enhanced (L1-4): auto-run={} prompt={} hard-block={} (invoked on {} prompted)",
            advisor.auto_run, advisor.prompt, advisor.hard_block, advisor.invoked,
        );
        let total = advisor.auto_run + advisor.prompt + advisor.hard_block;
        if total > 0 {
            println!(
                "Advisor-enhanced auto-run rate over scripted = {:.1}% (uplift = +{:.1}pp)",
                (advisor.auto_run as f64) * 100.0 / total as f64,
                (advisor.auto_run as f64 - portable.auto_run as f64) * 100.0 / total as f64,
            );
        }
    }
}

/// Distribution over the advisor-enhanced outcome (`portable_outcome`
/// with prompted packages overridden by the L4 advisor's verdict).
/// `invoked` is the count of packages the advisor actually ran on;
/// the others retain their portable outcome verbatim.
#[derive(Debug, Default)]
struct AdvisorSummary {
    invoked: usize,
    auto_run: usize,
    prompt: usize,
    hard_block: usize,
}

fn summarise_advisor(audits: &[PackageAudit]) -> AdvisorSummary {
    let mut s = AdvisorSummary::default();
    for a in audits {
        if a.fetch_error.is_some() {
            continue;
        }
        // Effective outcome: advisor_outcome if set (the advisor ran),
        // otherwise the portable outcome cast to the same shape.
        let outcome = match (a.advisor_outcome, a.portable_outcome) {
            (Some(o), _) => {
                s.invoked += 1;
                o
            }
            (None, Some(PortableOutcome::AutoRun)) => AdvisorOutcome::AutoRun,
            (None, Some(PortableOutcome::Prompt)) => AdvisorOutcome::Prompt,
            (None, Some(PortableOutcome::HardBlock)) => AdvisorOutcome::HardBlock,
            (None, Some(PortableOutcome::NoScripts)) | (None, None) => continue,
        };
        match outcome {
            AdvisorOutcome::AutoRun => s.auto_run += 1,
            AdvisorOutcome::Prompt => s.prompt += 1,
            AdvisorOutcome::HardBlock => s.hard_block += 1,
            AdvisorOutcome::NoScripts => {}
        }
    }
    s
}

/// Read the cached results JSON and re-run `classify()` on every
/// recorded script body. Manifests are NOT re-fetched. Output is the
/// same JSON + Markdown shape, with the new tier annotations.
///
/// This is the fast path for evaluating a `static_gate.rs` change
/// against the same 5000-package dataset the prior run captured.
async fn reclassify_from_cache(args: &Args) -> Result<(), BoxError> {
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

    // Carry forward existing metadata; refresh timestamp; replace the
    // advisor stamp iff this pass invokes one.
    let mut metadata = load_sidecar_metadata(&args.results);
    metadata.run_completed_at = Some(now_rfc3339());
    metadata.audit_size = metadata.audit_size.or(Some(args.size));

    if let Some(name) = &args.advisor {
        // Clear stale advisor outcomes before re-running so a previous
        // run's verdicts don't bleed into this one's report.
        for a in &mut audits {
            a.advisor_outcome = None;
            a.advisor_provider = None;
        }
        metadata.advisor = enrich_advisor_in_place(name, &mut audits).await?;
    }

    persist_audit(&args.results, &args.report, &audits, &metadata)?;
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
        advisor_provider: None,
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
/// `prompt_tuneable` is `prompt` minus packages whose dominant
/// amber-script shape is policy-permanent — i.e. amber by §4.1
/// design (binary-fetcher / prebuild-fallback). The tuneable count is
/// the standing "how much classifier headroom is left" number.
#[derive(Debug, Default)]
struct PortableSummary {
    auto_run: usize,
    prompt: usize,
    /// Subset of `prompt` excluding policy-permanent shapes. Always
    /// `<= prompt`.
    prompt_tuneable: usize,
    hard_block: usize,
    no_scripts: usize,
    /// Hard ship-gate number — must always be 0 per §4.1.
    zero_fp_red_count: usize,
    /// L3 cooldown blocks broken out separately so the standing table
    /// can distinguish "blocked because L1 red" from "blocked because
    /// L3 said the release is too new".
    cooldown_blocks: usize,
    /// Attestation coverage over scripted packages.
    attestation_present: usize,
    scripted_total: usize,
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
            Some(PortableOutcome::Prompt) => {
                s.prompt += 1;
                if !package_is_policy_permanent_amber(a) {
                    s.prompt_tuneable += 1;
                }
            }
            Some(PortableOutcome::HardBlock) => s.hard_block += 1,
            Some(PortableOutcome::NoScripts) | None => s.no_scripts += 1,
        }
        if a.tier == Some(StaticTier::Red) {
            s.zero_fp_red_count += 1;
        }
        if a.tier.is_some() {
            s.scripted_total += 1;
            if let Some(l3) = &a.l3_outcome {
                if l3.cooldown_block {
                    s.cooldown_blocks += 1;
                }
                if l3.attestation_present {
                    s.attestation_present += 1;
                }
            }
        }
    }
    s
}

/// Is the dominant amber-tier script on this package classified under
/// a policy-permanent shape? Worst-tier-of-shapes wins (matches the
/// classifier's worst-of-phases logic). A `None` shape (older cached
/// records pre-dating the field) is treated as tunable, since we
/// can't prove permanence without re-bucketing.
fn package_is_policy_permanent_amber(a: &PackageAudit) -> bool {
    [&a.preinstall, &a.install, &a.postinstall]
        .into_iter()
        .flatten()
        .filter(|s| matches!(s.tier, StaticTier::Amber | StaticTier::AmberLlm))
        .filter_map(|s| s.shape)
        .any(is_policy_permanent_amber_shape)
}

fn build_report(audits: &[PackageAudit], metadata: &AuditMetadata) -> String {
    let mut out = String::new();
    out.push_str("# Phase 46 — Top-N audit (L1-3, portable)\n\n");
    out.push_str(&format!("Total packages audited: **{}**\n\n", audits.len()));

    section_run_metadata(&mut out, metadata);
    section_standing_benchmark(&mut out, audits, metadata);
    section_l1_tier_distribution(&mut out, audits);
    section_portable_outcome(&mut out, audits);
    section_l1_to_portable_transition(&mut out, audits);
    section_prompt_shape_breakdown(&mut out, audits);
    section_l3_detail(&mut out, audits);
    section_runtime_review_candidates(&mut out, audits);
    section_red_packages(&mut out, audits, metadata);
    section_advisor_baseline_placeholder(&mut out, audits, metadata);

    out
}

/// Pin run identity at the top of the report. Without this stamp,
/// "+1 today vs +2 tomorrow" is impossible to attribute — could be
/// the advisor's non-determinism, a binary upgrade, or a prompt-template
/// iteration. Surfacing all three lets future comparative studies say
/// exactly what changed.
fn section_run_metadata(out: &mut String, metadata: &AuditMetadata) {
    out.push_str("## Run identity\n\n");
    out.push_str("| Field | Value |\n|-------|-------|\n");
    if let Some(t) = &metadata.run_completed_at {
        out.push_str(&format!("| Run completed at | `{t}` |\n"));
    }
    if let Some(s) = metadata.audit_size {
        out.push_str(&format!("| Audit size | {s} |\n"));
    }
    if let Some(a) = &metadata.advisor {
        out.push_str(&format!("| Advisor provider | `{}` |\n", a.provider));
        if let Some(path) = &a.binary_path {
            out.push_str(&format!("| Advisor binary | `{path}` |\n"));
        }
        if let Some(v) = &a.binary_version {
            out.push_str(&format!(
                "| Advisor version | `{}` |\n",
                v.replace('\n', " ").trim()
            ));
        }
        if let Some(m) = &a.model {
            out.push_str(&format!("| Advisor model | `{m}` |\n"));
        }
        out.push_str(&format!(
            "| Prompt template hash | `{}` |\n",
            a.prompt_template_hash
        ));
        out.push_str(&format!("| Advisor invocations | {} |\n", a.invoked_count));
    } else {
        out.push_str("| Advisor provider | _none — portable baseline only_ |\n");
    }
    out.push('\n');
}

/// Locked standing benchmark per the Phase 46 audit Part A closeout.
/// These 7 numbers are the canonical comparison points for future
/// audit iterations.
///
/// `metadata.corpus` re-interprets one cell: on the live top-N
/// corpus, `zero-FP-red` is a §4.1 ship gate that MUST stay 0
/// because real npm is overwhelmingly benign; on the hermetic
/// fixture, intentional reds exercise classifier shape coverage,
/// so the "stay 0" framing is wrong and gets replaced with a
/// fixture-expected-count framing.
fn section_standing_benchmark(out: &mut String, audits: &[PackageAudit], metadata: &AuditMetadata) {
    let p = summarise_portable(audits);
    let pct_scripted = |n: usize| {
        if p.scripted_total == 0 {
            0.0
        } else {
            n as f64 * 100.0 / p.scripted_total as f64
        }
    };
    out.push_str("## Standing benchmark table\n\n");
    out.push_str(
        "Locked Part A closeout metrics. These are the canonical \
         comparison points for future audit iterations.\n\n",
    );
    out.push_str("| Metric | Value | Notes |\n");
    out.push_str("|--------|------:|-------|\n");
    out.push_str(&format!(
        "| auto-run | {} | L1 green + L2 strict-match (always 0 in first-install audit) |\n",
        p.auto_run
    ));
    out.push_str(&format!(
        "| prompt (total) | {} | L1 amber that passed L2 + L3 |\n",
        p.prompt
    ));
    out.push_str(&format!(
        "| prompt (tuneable) | {} | Excludes policy-permanent shapes (binary-fetcher, prebuild-fallback) — the standing \"classifier headroom\" number |\n",
        p.prompt_tuneable
    ));
    out.push_str(&format!(
        "| hard-block | {} | L1 red + L1 amber blocked by L3 |\n",
        p.hard_block
    ));
    out.push_str(&format!(
        "| no-scripts | {} | Manifest had no lifecycle scripts |\n",
        p.no_scripts
    ));
    // The zero-FP-red metric is named for its live-corpus role
    // (§4.1 ship gate: any red on real top-N is a suspected
    // false-positive). On the hermetic fixture the reds are
    // intentional shape coverage, so the "MUST stay 0" framing is
    // misleading — re-word that single cell.
    let zero_fp_red_note = match metadata.corpus.as_deref() {
        Some("hermetic") => {
            "Hermetic fixture: count reflects intentional red shape coverage, not a ship-gate failure. Compare to the prior run's value; a change signals a classifier drift on the fixed corpus."
        }
        _ => "**§4.1 ship gate — MUST stay 0**",
    };
    out.push_str(&format!(
        "| **zero-FP-red** | **{}** | {zero_fp_red_note} |\n",
        p.zero_fp_red_count
    ));
    out.push_str(&format!(
        "| cooldown-blocks | {} | L3 cooldown gate fires (release < 24h old) |\n",
        p.cooldown_blocks
    ));
    out.push_str(&format!(
        "| attestation-coverage | {}/{} ({:.1}%) | Forward indicator for future provenance-drift gating |\n\n",
        p.attestation_present,
        p.scripted_total,
        pct_scripted(p.attestation_present)
    ));
}

fn section_prompt_shape_breakdown(out: &mut String, audits: &[PackageAudit]) {
    let mut buckets: BTreeMap<ScriptShape, ShapeBucket> = BTreeMap::new();
    for a in audits {
        if a.portable_outcome != Some(PortableOutcome::Prompt) {
            continue;
        }
        for (_phase, s) in scripted_phases(a) {
            if matches!(s.tier, StaticTier::Amber | StaticTier::AmberLlm) {
                let shape = s.shape.unwrap_or(ScriptShape::Other);
                let bucket = buckets.entry(shape).or_default();
                bucket.count += 1;
                if bucket.examples.len() < 5 {
                    bucket.examples.push((a.name.clone(), s.script.clone()));
                }
            }
        }
    }
    let mut sorted: Vec<(ScriptShape, ShapeBucket)> = buckets.into_iter().collect();
    sorted.sort_by(|a, b| b.1.count.cmp(&a.1.count));
    out.push_str("## Prompt-shape breakdown\n\n");
    out.push_str(
        "Each prompted script categorised by normalised shape. The \
         `policy-permanent?` flag marks shapes that are amber by §4.1 \
         design (binary-fetcher / prebuild-fallback) — they should \
         NOT be treated as classifier-tuning candidates in future \
         iterations.\n\n",
    );
    out.push_str("| Shape | Count | Policy-permanent? | Sample packages → script |\n");
    out.push_str("|-------|------:|:------------------|----|\n");
    for (shape, bucket) in sorted {
        let perm = if is_policy_permanent_amber_shape(shape) {
            "**yes — §4.1 D18**"
        } else {
            "no"
        };
        let samples = bucket
            .examples
            .iter()
            .map(|(pkg, s)| format!("`{pkg}` → `{}`", escape_md(s)))
            .collect::<Vec<_>>()
            .join("<br>");
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            shape_label(shape),
            bucket.count,
            perm,
            samples
        ));
    }
    out.push('\n');
}

#[derive(Debug, Default)]
struct ShapeBucket {
    count: usize,
    examples: Vec<(String, String)>,
}

fn section_runtime_review_candidates(out: &mut String, audits: &[PackageAudit]) {
    let green_names: std::collections::HashSet<&str> = audits
        .iter()
        .filter(|a| a.portable_outcome == Some(PortableOutcome::AutoRun))
        .map(|a| a.name.as_str())
        .collect();

    let present: Vec<(&str, &str)> = RUNTIME_REVIEW_CANDIDATES
        .iter()
        .copied()
        .filter(|(name, _)| green_names.contains(name))
        .collect();

    out.push_str("## Runtime-review candidates\n\n");
    out.push_str(
        "Currently-green packages whose actual behaviour lives in a \
         JS file the static gate can't read. These are sandbox/runtime \
         concerns, **not classifier bugs** — surfacing them here keeps \
         the boundary explicit so future iterations don't try to \
         solve runtime-behavior questions with filename heuristics.\n\n",
    );
    if present.is_empty() {
        out.push_str(
            "_None of the curated runtime-review candidates appear \
             green in this run._\n\n",
        );
        return;
    }
    out.push_str("| Package | Runtime concern |\n");
    out.push_str("|---------|-----------------|\n");
    for (name, reason) in present {
        out.push_str(&format!("| `{name}` | {reason} |\n"));
    }
    out.push('\n');
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

fn section_red_packages(out: &mut String, audits: &[PackageAudit], metadata: &AuditMetadata) {
    let is_hermetic = matches!(metadata.corpus.as_deref(), Some("hermetic"));
    if is_hermetic {
        out.push_str("## Red-classified packages (hermetic fixture coverage)\n\n");
    } else {
        out.push_str("## Red-classified packages (zero-FP-red gate)\n\n");
    }
    let mut reds: Vec<&PackageAudit> = audits
        .iter()
        .filter(|a| a.tier == Some(StaticTier::Red))
        .collect();
    reds.sort_by_key(|a| a.rank);
    if reds.is_empty() {
        if is_hermetic {
            out.push_str("_None — no red shapes in the hermetic fixture this run._\n\n");
        } else {
            out.push_str("_None — zero-FP-red gate held on this run._\n\n");
        }
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

/// Whether a shape is **policy-permanent amber** — amber by explicit
/// §4.1 design (binary-fetcher / prebuild-fallback are D18 downloader
/// classes; widening them would erode the user-acknowledges-binary-
/// download contract). Used to compute `prompt-tuneable`: the subset
/// of prompts that classifier work could still plausibly reduce.
///
/// Shapes NOT marked permanent are tunable in principle, though the
/// individual packages within a shape may still be amber for
/// per-package reasons (e.g. softfail-wrappers with reserved
/// basenames). Per-package permanence requires inspecting the script
/// body, not just the shape; this coarser flag is the standing
/// reporting view.
fn is_policy_permanent_amber_shape(s: ScriptShape) -> bool {
    matches!(
        s,
        ScriptShape::BinaryFetcher | ScriptShape::PrebuildFallback
    )
}

/// Hand-curated list of currently-green packages whose actual runtime
/// behaviour lives in a JS file the classifier can't read. They are
/// **runtime-review candidates** — sandbox/runtime is the right gate,
/// not more filename heuristics. Surfacing them here keeps the
/// boundary explicit so future classifier work doesn't try to solve
/// runtime-behavior questions with filename rules.
///
/// Each entry is the package name as it appears in the registry.
/// Update this list when the green-list expands; the standing
/// runtime-review-candidate report section reflects whatever names
/// are in here that also appear in the audit's green set.
const RUNTIME_REVIEW_CANDIDATES: &[(&str, &str)] = &[
    (
        "@parcel/watcher",
        "build-from-source script may fetch source tarballs from a remote",
    ),
    (
        "prisma",
        "bootstraps the prisma engine binary download in the JS file",
    ),
    (
        "@scarf/scarf",
        "performs anonymous network telemetry on every install",
    ),
];

fn section_advisor_baseline_placeholder(
    out: &mut String,
    audits: &[PackageAudit],
    metadata: &AuditMetadata,
) {
    let any_advisor = audits.iter().any(|a| a.advisor_outcome.is_some());
    out.push_str("## Advisor-enhanced baseline (L1-4)\n\n");
    if !any_advisor {
        out.push_str(
            "_No advisor configured (`triage-advisor = \"none\"`). \
             Portable baseline above is the authoritative outcome for \
             this run. Re-run with `--advisor claude-cli` / `--advisor \
             codex` / `--advisor ollama` to populate this section._\n\n",
        );
        return;
    }

    let portable = summarise_portable(audits);
    let advisor = summarise_advisor(audits);
    let total_scripted = advisor.auto_run + advisor.prompt + advisor.hard_block;
    let pct = |n: usize, denom: usize| {
        if denom == 0 {
            0.0
        } else {
            n as f64 * 100.0 / denom as f64
        }
    };

    out.push_str(
        "Reported as a separate uplift line, **never blended** with the \
         portable baseline. The advisor only converts amber → auto-run; \
         the L1 red and L3 hard-blocks are unchanged.\n\n",
    );
    out.push_str("| Outcome | Portable (L1-3) | Advisor-enhanced (L1-4) | Δ |\n");
    out.push_str("|---------|----------------:|------------------------:|--:|\n");
    out.push_str(&format!(
        "| auto-run | {} ({:.1}%) | {} ({:.1}%) | +{} |\n",
        portable.auto_run,
        pct(portable.auto_run, total_scripted),
        advisor.auto_run,
        pct(advisor.auto_run, total_scripted),
        advisor.auto_run as i64 - portable.auto_run as i64,
    ));
    out.push_str(&format!(
        "| prompt | {} ({:.1}%) | {} ({:.1}%) | {} |\n",
        portable.prompt,
        pct(portable.prompt, total_scripted),
        advisor.prompt,
        pct(advisor.prompt, total_scripted),
        advisor.prompt as i64 - portable.prompt as i64,
    ));
    out.push_str(&format!(
        "| hard-block | {} | {} | {} |\n\n",
        portable.hard_block,
        advisor.hard_block,
        advisor.hard_block as i64 - portable.hard_block as i64,
    ));
    out.push_str(&format!(
        "Advisor invoked on **{} prompted package(s)**.\n\n",
        advisor.invoked
    ));

    // Per-verdict breakdown — which prompted packages did the advisor
    // approve / mark manual / abstain on? Visibility into the
    // per-package judgment is what makes the uplift number actionable.
    out.push_str("### Per-package advisor verdicts\n\n");
    out.push_str("| Rank | Package | Portable | Advisor outcome |\n");
    out.push_str("|-----:|---------|----------|-----------------|\n");
    let mut rows: Vec<&PackageAudit> = audits
        .iter()
        .filter(|a| a.advisor_outcome.is_some())
        .collect();
    rows.sort_by_key(|a| a.rank);
    for a in rows.iter().take(50) {
        let advisor_label = match a.advisor_outcome {
            Some(AdvisorOutcome::AutoRun) => "**auto-run** (approve)",
            Some(AdvisorOutcome::Prompt) => "prompt (manual/abstain/fail)",
            Some(AdvisorOutcome::HardBlock) => "hard-block",
            Some(AdvisorOutcome::NoScripts) => "no-scripts",
            None => "—",
        };
        let portable_label = match a.portable_outcome {
            Some(PortableOutcome::Prompt) => "prompt",
            Some(PortableOutcome::AutoRun) => "auto-run",
            Some(PortableOutcome::HardBlock) => "hard-block",
            Some(PortableOutcome::NoScripts) => "no-scripts",
            None => "—",
        };
        out.push_str(&format!(
            "| {} | `{}` | {} | {} |\n",
            a.rank, a.name, portable_label, advisor_label,
        ));
    }
    out.push('\n');

    // Explicit conclusion. Otherwise readers see "L4 complete" and
    // mentally inflate what the advisor actually bought. The numbers
    // in this sentence are derived from the same summaries used in
    // the table above so they can't drift out of sync.
    let uplift_packages = advisor.auto_run as i64 - portable.auto_run as i64;
    let uplift_pp = if total_scripted > 0 {
        (advisor.auto_run as f64 - portable.auto_run as f64) * 100.0 / total_scripted as f64
    } else {
        0.0
    };
    let unresolved = advisor.prompt;
    // Prefer the metadata stamp's provider — it's the most reliable
    // source. Fall back to per-record provider tag if the stamp isn't
    // present (older sidecars).
    let provider_label = metadata
        .advisor
        .as_ref()
        .map(|a| a.provider.clone())
        .or_else(|| advisor_provider_name(audits))
        .unwrap_or_else(|| "configured advisor".to_string());
    out.push_str(&format!(
        "**Conclusion.** Advisor-enhanced run with `{provider_label}` increased \
         auto-run by {uplift_packages} package(s) (+{uplift_pp:.1}pp over portable) \
         and left {unresolved} of {invoked} prompted packages unresolved. \
         Advisor uplift is real but modest; **portable L1-3 remains the \
         decision-grade baseline**.\n\n",
        invoked = advisor.invoked,
    ));
}

/// Best-effort: name the advisor provider the audit was run with,
/// for the conclusion sentence. Reads `advisor_provider` off any
/// record that was advised, since the harness attaches the slug
/// per-record during the L4 enrichment pass.
fn advisor_provider_name(audits: &[PackageAudit]) -> Option<String> {
    audits
        .iter()
        .filter_map(|a| a.advisor_provider.clone())
        .next()
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
