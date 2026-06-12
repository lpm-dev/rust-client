use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::ProgressBar;
use lpm_security::SecurityPolicy;
use serde::Deserialize;

use crate::args::Args;
use crate::classify::{finalize_outcomes, refresh_shapes};
use crate::io::{load_sidecar_metadata, persist_audit};
use crate::layers::l4::enrich_advisor_in_place;
use crate::report::summary::print_summary;
use crate::types::{BoxError, L3Outcome, PackageAudit, ProvenanceDriftSummary};
use crate::util::{
    REGISTRY_BASE, emit_progress_milestone, encode_pkg, now_rfc3339, progress_style,
};

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

/// Enrich an audit set with L3 data (packument time + attestation
/// presence) for every scripted record that doesn't already have it.
/// Skips records without a tier (no scripts) and records whose
/// `l3_outcome` is already populated.
pub(crate) async fn enrich_l3_in_place(
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

/// Backfill mode: read cached results, fetch L3 for scripted records
/// that don't have it, compute outcomes, write back. Doesn't touch L1
/// tier classification (use `--reclassify` for that) — but DOES
/// refresh the `shape` bucket from the cached script body, since
/// older cached records pre-date the shape field and would all bucket
/// as `Other` otherwise.
pub(crate) async fn enrich_l3_from_cache(
    client: &reqwest::Client,
    args: &Args,
) -> Result<(), BoxError> {
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
        metadata.advisor = enrich_advisor_in_place(name, &mut audits, args).await?;
    }

    persist_audit(&args.results, &args.report, &audits, &metadata)?;
    print_summary(&audits);
    Ok(())
}

/// Derive a fully-populated [`L3Outcome`] from the fixture's
/// `publish_age_hours` + `attestation_present`. Routes through the
/// SAME `SecurityPolicy::check_release_age` the live path uses so
/// the cooldown decision is byte-identical to what
/// `enrich_l3_in_place` would emit for an equivalently-aged real
/// package.
pub(crate) fn hermetic_l3_outcome(publish_age_hours: u64, attestation_present: bool) -> L3Outcome {
    use time::format_description::well_known::Rfc3339;
    // `publish_age_hours` is unbounded in theory; in practice the
    // fixture file only carries values in the [1, 8760] range
    // (1 hour … 1 year). Saturating math keeps the arithmetic
    // well-defined for any value a future fixture edit might
    // introduce without sneaking a panic into the audit binary.
    let age_secs = publish_age_hours.saturating_mul(3600);
    let now = time::OffsetDateTime::now_utc();
    let published_dt = now - time::Duration::seconds(age_secs as i64);
    let published_at = published_dt.format(&Rfc3339).ok();

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
    let outcome = L3Outcome {
        published_at,
        age_secs,
        cooldown_block,
        attestation_present,
        // First-install audit always lands here — see ProvenanceDriftSummary
        // docs.
        provenance_drift: ProvenanceDriftSummary::NoDrift,
        l3_fetch_error,
    };
    // L3 enrichment has a smaller working set than the manifest
    // fetch phase (only scripted packages need L3 enrichment, so
    // ~5-15% of audited count). Milestone every 50 items balances
    // signal against noise.
    emit_progress_milestone("L3 enrich", &pb, 50);
    outcome
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
