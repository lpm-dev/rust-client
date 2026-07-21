use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::ProgressBar;
use lpm_security::static_gate::ManifestContext;
use serde::Deserialize;

use crate::args::Args;
use crate::classify::{classify_script_with_context, finalize_outcomes, worst_of_phases};
use crate::io::{load_sidecar_metadata, persist_audit};
use crate::layers::l3::{enrich_l3_from_cache, enrich_l3_in_place};
use crate::layers::l4::enrich_advisor_in_place;
use crate::report::summary::print_summary;
use crate::types::{AuditMetadata, BoxError, L2Outcome, PackageAudit, TopNEntry};
use crate::util::{
    REGISTRY_BASE, USER_AGENT, emit_progress_milestone, encode_pkg, now_rfc3339, progress_style,
};

const SEARCH_PAGE_SIZE: usize = 250;
const SEARCH_ENDPOINT: &str = "https://registry.npmjs.org/-/v1/search";

/// What we read from `https://registry.npmjs.org/{pkg}/latest`. We deserialise
/// only the fields we care about; everything else (deps, license, readme,
/// etc.) is skipped so the binary doesn't pay for parsing the entire manifest.
///
/// `repository` carries either the legacy
/// shorthand string `"github.com/x/y"` or the modern object form
/// `{ "type": "git", "url": "git+https://..." }`. Both shapes
/// deserialize into the same `RepositoryField` enum, which the
/// audit harness flattens to a single URL string on its way to the
/// advisor.
#[derive(Debug, Deserialize)]
struct LatestManifest {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    repository: Option<RepositoryField>,
}

/// Repository declaration on a `package.json` — accepts both wire
/// shapes the npm registry serves.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RepositoryField {
    /// Shorthand: a bare URL string, e.g. `"github.com/lovell/sharp"`.
    String(String),
    /// Object form: `{ "type": "git", "url": "..." }`. Only the
    /// `url` field is consulted; `type` is ignored.
    Object {
        #[serde(default)]
        url: Option<String>,
    },
}

impl RepositoryField {
    /// Flatten to a single URL string. `None` when the object form
    /// has no `url`, or the string form is empty.
    fn into_url(self) -> Option<String> {
        match self {
            RepositoryField::String(s) if !s.is_empty() => Some(s),
            RepositoryField::Object { url: Some(u) } if !u.is_empty() => Some(u),
            _ => None,
        }
    }
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

pub(crate) async fn run(args: &Args) -> Result<(), BoxError> {
    if args.reclassify {
        return reclassify_from_cache(args).await;
    }

    let client = lpm_http::client_builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(args.timeout_secs))
        .build()?;

    if args.enrich_l3_only {
        return enrich_l3_from_cache(&client, args).await;
    }

    let top_n = load_or_fetch_top_n(&client, args).await?;
    println!(
        "loaded top-{} packages (range: {} dl/mo … {} dl/mo)",
        top_n.len(),
        top_n.first().map_or(0, |e| e.monthly_downloads),
        top_n.last().map_or(0, |e| e.monthly_downloads),
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
        metadata.advisor = enrich_advisor_in_place(name, &mut audits, args).await?;
    }

    persist_audit(&args.results, &args.report, &audits, &metadata)?;
    print_summary(&audits);
    Ok(())
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
        // `--reclassify` re-runs the L1
        // classifier with the manifest context the prior fetch
        // captured. `repository` is on the cached record; `bin`
        // isn't (audit-corpus never fetched it for older audits),
        // so passes through as empty.
        //
        // `--reclassify` doesn't have publish
        // ages in the cached record (the audit-corpus's PackageAudit
        // shape never persisted them). Pass `min_release_age_secs=0`
        // so the identity check fires on identity match — matches the prior
        // `--reclassify` behaviour for users iterating on
        // `static_gate.rs` changes. Production install pipeline
        // applies the proper cooldown defense; this is a measurement
        // tool tradeoff.
        let ctx = ManifestContext {
            package_name: &a.name,
            repository: a.repository.as_deref(),
            bin_names: &[],
            publish_age_secs: None,
            min_release_age_secs: 0,
        };
        for phase in [&mut a.preinstall, &mut a.install, &mut a.postinstall]
            .into_iter()
            .flatten()
        {
            // Re-classify and re-bucket the shape from the cached
            // script body. `classify_script_with_context` recomputes
            // both in one call.
            *phase = classify_script_with_context(&phase.script, Some(&ctx));
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
        metadata.advisor = enrich_advisor_in_place(name, &mut audits, args).await?;
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
        let resp =
            client.get(url).send().await.map_err(|error| -> BoxError {
                lpm_http::display_error(&error).to_string().into()
            })?;
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
    let result: Result<LatestManifest, String> = loop {
        match client.get(&manifest_url).send().await {
            Err(e) => break Err(lpm_http::display_error(&e).to_string()),
            Ok(r) => {
                let s = r.status();
                if s.is_success() {
                    break r
                        .json::<LatestManifest>()
                        .await
                        .map_err(|e| lpm_http::display_error(&e).to_string());
                }
                if (s.as_u16() == 429 || s.is_server_error()) && delay_ms <= 32_000 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = delay_ms.saturating_mul(2);
                    continue;
                }
                break Err(lpm_http::display_error(&r.error_for_status().unwrap_err()).to_string());
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
        repository: None,
        // live audit path does NOT fetch
        // tarballs (heavy + npm-rate-limit-sensitive). Referenced
        // scripts stay empty for live runs; fixture-based runs
        // populate them from the corpus / expectations. A future
        // extension could opt-in to tarball fetch behind an
        // explicit flag.
        referenced_scripts: Vec::new(),
        fetch_error: None,
    };

    match result {
        Ok(manifest) => {
            audit.version = manifest.version;
            // pull the `repository` URL from
            // the registry manifest (string or object shape).
            audit.repository = manifest.repository.and_then(RepositoryField::into_url);
            let scripts = manifest.scripts.unwrap_or_default();
            // pass identity context so
            // delegate-to-local-file shapes with matching repo
            // identity Green at L1, skipping L4.
            //
            // live audit doesn't compute publish
            // ages here (the cooldown gate runs separately in
            // `enrich_l3_in_place`). For audit-measurement purposes
            // we pass `min_release_age_secs=0` so the L1 classifier
            // reports the unconstrained tier; the report's L3
            // section still surfaces cooldown blocks separately, so
            // measurement fidelity is preserved.
            let ctx = ManifestContext {
                package_name: &audit.name,
                repository: audit.repository.as_deref(),
                bin_names: &[],
                publish_age_secs: None,
                min_release_age_secs: 0,
            };
            audit.preinstall = scripts
                .get("preinstall")
                .map(|s| classify_script_with_context(s, Some(&ctx)));
            audit.install = scripts
                .get("install")
                .map(|s| classify_script_with_context(s, Some(&ctx)));
            audit.postinstall = scripts
                .get("postinstall")
                .map(|s| classify_script_with_context(s, Some(&ctx)));
            audit.tier = worst_of_phases(&audit);
        }
        Err(e) => audit.fetch_error = Some(e),
    }

    pb.inc(1);
    // Emit a stderr milestone every 100 manifests so non-TTY runs
    // (piped through `tee`, CI capture, etc.) have visibility into
    // the fetch-phase progress that indicatif's visual bar silently
    // suppresses without a TTY.
    emit_progress_milestone("audit", &pb, 100);
    audit
}
