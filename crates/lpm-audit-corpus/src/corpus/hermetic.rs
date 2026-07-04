use std::collections::BTreeMap;

use lpm_security::static_gate::ManifestContext;
use serde::Deserialize;

use crate::args::Args;
use crate::classify::{classify_script_with_context, finalize_outcomes, worst_of_phases};
use crate::io::persist_audit;
use crate::layers::l3::hermetic_l3_outcome;
use crate::layers::l4::enrich_advisor_in_place;
use crate::report::summary::print_summary;
use crate::types::{
    AuditMetadata, BoxError, HermeticReferencedScript, L2Outcome, PackageAudit,
    ReferencedScriptEntry,
};
use crate::util::now_rfc3339;

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
    /// optional repository URL surfaced to the
    /// advisor prompt as the `Repository:` line. Defaults to `None`
    /// for older fixture entries so the field can be rolled out
    /// incrementally; new amber entries (especially delegate-
    /// to-local-file installers) should carry the URL so the L4
    /// advisor can apply the matching-identity APPROVE rule.
    #[serde(default)]
    repository: Option<String>,
    /// referenced file contents to embed in
    /// the advisor prompt's "Referenced files" section. Each entry
    /// is `{ "filename": "<rel path>", "content": "<inline body>" }`.
    /// Defaults to empty so existing fixtures don't need a rewrite.
    /// New delegate-to-local-file entries should supply realistic
    /// install.js content so the lever's effect can be measured.
    #[serde(default)]
    referenced_scripts: Vec<HermeticReferencedScript>,
}

const HERMETIC_CORPUS_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/hermetic/corpus.json");

/// Run the audit against the bundled offline corpus.
///
/// Identical control flow to the live path's `main()`:
/// `audit_top_n` equivalent → `enrich_l3_in_place` equivalent →
/// `finalize_outcomes` → optional `--advisor` enrichment →
/// `persist_audit` + `print_summary`. The only difference is that
/// the per-package data comes from the fixture instead of from
/// network calls.
pub(crate) async fn run(args: &Args) -> Result<(), BoxError> {
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
        metadata.advisor = enrich_advisor_in_place(name, &mut audits, args).await?;
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
    // thread identity into the L1 classifier so
    // hermetic delegate-to-local-file shapes with matching repo
    // names Green directly at L1 (no L4 round-trip).
    //
    // use the fixture's `publish_age_hours` to
    // exercise the cooldown defense-in-depth. The recent-publish
    // hermetic entry (`hermetic-amber-binary-fetcher-recent` with
    // `publish_age_hours: 1`) is the load-bearing test case: with
    // Under the 24h cooldown policy, that entry stays Amber even though its
    // repository identity matches, because the publish age is below
    // the cooldown threshold.
    let ctx = ManifestContext {
        package_name: &entry.name,
        repository: entry.repository.as_deref(),
        bin_names: &[],
        publish_age_secs: Some(entry.publish_age_hours.saturating_mul(3600)),
        min_release_age_secs: 24 * 60 * 60,
    };
    let preinstall = entry
        .scripts
        .get("preinstall")
        .map(|s| classify_script_with_context(s, Some(&ctx)));
    let install = entry
        .scripts
        .get("install")
        .map(|s| classify_script_with_context(s, Some(&ctx)));
    let postinstall = entry
        .scripts
        .get("postinstall")
        .map(|s| classify_script_with_context(s, Some(&ctx)));

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
        // hermetic fixtures may declare a
        // `repository` URL so the L4 advisor sees it in the prompt.
        // Existing fixtures may omit the field, so `serde(default)`
        // lets them load as `None` without a fixture rewrite.
        repository: entry.repository.clone(),
        // hermetic fixtures may declare
        // referenced file content so the L4 advisor sees it
        // embedded in the prompt. `serde(default)` keeps existing
        // fixtures load-clean as an empty list.
        referenced_scripts: entry
            .referenced_scripts
            .iter()
            .map(|r| ReferencedScriptEntry {
                filename: r.filename.clone(),
                content: r.content.clone(),
            })
            .collect(),
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
