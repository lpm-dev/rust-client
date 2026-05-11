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
    /// Empty unless the manifest fetch errored.
    fetch_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScriptAudit {
    script: String,
    tier: StaticTier,
    first_token: Option<String>,
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

    let audits = audit_top_n(&client, &top_n, args.concurrency, resume_records).await?;
    std::fs::write(&args.results, serde_json::to_vec_pretty(&audits)?)?;
    println!(
        "wrote {} audit records → {}",
        audits.len(),
        args.results.display()
    );

    let report = build_report(&audits);
    std::fs::write(&args.report, &report)?;
    println!("wrote markdown report → {}", args.report.display());

    let summary = summarise(&audits);
    println!(
        "\nsummary: green={} amber={} red={} no-scripts={} fetch-failed={}",
        summary.green, summary.amber, summary.red, summary.no_scripts, summary.fetch_failed,
    );
    if summary.scripted_total() > 0 {
        println!(
            "green/(green+amber) over scripted = {:.1}% (target: ≥60%)",
            summary.green_share_pct(),
        );
    }

    Ok(())
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
            phase.tier = classify(&phase.script);
        }
        a.tier = worst_of_phases(a);
        if a.tier != prev_tier {
            changed += 1;
        }
    }
    println!("reclassify: {changed} package tier(s) changed");

    std::fs::write(&args.results, serde_json::to_vec_pretty(&audits)?)?;
    let report = build_report(&audits);
    std::fs::write(&args.report, &report)?;
    println!(
        "wrote {} audit records → {}\nwrote markdown report → {}",
        audits.len(),
        args.results.display(),
        args.report.display()
    );

    let summary = summarise(&audits);
    println!(
        "\nsummary: green={} amber={} red={} no-scripts={} fetch-failed={}",
        summary.green, summary.amber, summary.red, summary.no_scripts, summary.fetch_failed,
    );
    if summary.scripted_total() > 0 {
        println!(
            "green/(green+amber) over scripted = {:.1}%",
            summary.green_share_pct(),
        );
    }
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
    let first_token = shlex::split(script)
        .and_then(|toks| toks.into_iter().next())
        .map(|s| {
            // strip leading `./` or absolute path prefix to make grouping
            // stable across different relative-path styles.
            let trimmed = s.trim_start_matches("./");
            trimmed
                .split('/')
                .next_back()
                .unwrap_or(trimmed)
                .to_string()
        });
    ScriptAudit {
        script: script.to_string(),
        tier,
        first_token,
    }
}

fn worst_of_phases(a: &PackageAudit) -> Option<StaticTier> {
    [&a.preinstall, &a.install, &a.postinstall]
        .into_iter()
        .flatten()
        .map(|s| s.tier)
        .reduce(StaticTier::worse_of)
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

fn build_report(audits: &[PackageAudit]) -> String {
    let summary = summarise(audits);
    let mut out = String::new();

    out.push_str("# Phase 46 — Top-N static-gate audit\n\n");
    out.push_str(&format!("Total packages audited: **{}**\n\n", audits.len()));

    // 1. Tier distribution
    out.push_str("## Tier distribution\n\n");
    out.push_str("| Tier | Count | % of audited | % of scripted |\n");
    out.push_str("|------|------:|-------------:|-------------:|\n");
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
		"**green / (green + amber) over scripted = {:.2}%** (Phase 46 §4.1 floor: ≥60% on the 500-entry corpus).\n\n",
		summary.green_share_pct()
	));

    // 2. All red-classified packages — every red gets surfaced; if any of these
    //    are real (non-malicious) packages they are zero-FP-red violations and
    //    must be triaged against the §4.1 hard gate before any default flip.
    out.push_str("## Red-classified packages (zero-FP-red gate)\n\n");
    let mut reds: Vec<&PackageAudit> = audits
        .iter()
        .filter(|a| a.tier == Some(StaticTier::Red))
        .collect();
    reds.sort_by_key(|a| a.rank);
    if reds.is_empty() {
        out.push_str("_None — zero-FP-red gate held on this run._\n\n");
    } else {
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

    // 3. Top amber patterns by frequency, grouped by first-token of the script.
    out.push_str("## Top amber patterns (by first-token frequency)\n\n");
    let mut buckets: BTreeMap<String, AmberBucket> = BTreeMap::new();
    for a in audits {
        for (_phase, script) in scripted_phases(a) {
            if !matches!(script.tier, StaticTier::Amber | StaticTier::AmberLlm) {
                continue;
            }
            let key = script
                .first_token
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string());
            let bucket = buckets.entry(key).or_default();
            bucket.count += 1;
            if bucket.examples.len() < 5 {
                bucket
                    .examples
                    .push((a.name.clone(), script.script.clone()));
            }
        }
    }
    let mut bucket_vec: Vec<(String, AmberBucket)> = buckets.into_iter().collect();
    bucket_vec.sort_by(|a, b| b.1.count.cmp(&a.1.count));
    out.push_str("| First token | Amber count | Sample packages → script |\n");
    out.push_str("|-------------|-----------:|----|\n");
    for (token, bucket) in bucket_vec.iter().take(30) {
        let samples = bucket
            .examples
            .iter()
            .map(|(pkg, s)| format!("`{pkg}` → `{}`", escape_md(s)))
            .collect::<Vec<_>>()
            .join("<br>");
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            escape_md(token),
            bucket.count,
            samples
        ));
    }
    out.push('\n');

    out
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
