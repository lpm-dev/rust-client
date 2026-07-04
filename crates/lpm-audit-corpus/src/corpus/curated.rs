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

/// Path to the curated static-gate corpus.
/// Sibling crate's tests directory; resolved at compile time from
/// `CARGO_MANIFEST_DIR` so a future workspace re-layout fails to
/// build instead of silently stop-reading. The fixture's
/// `expectations.json` + `scripts/<id>.txt` shape is owned by
/// `lpm-security`; if it moves, this constant is the failure site.
const CURATED_EXPECTATIONS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lpm-security/tests/fixtures/postinstall-scripts/expectations.json"
);
const CURATED_SCRIPTS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lpm-security/tests/fixtures/postinstall-scripts/scripts"
);

/// One entry from the curated fixture's `expectations.json`. The
/// `expected` field is hand-assigned; the audit harness uses it
/// only for the report's "expected vs classified" sanity check.
#[derive(Debug, Clone, Deserialize)]
struct CuratedExpectation {
    id: String,
    /// Hand-assigned expected tier. The harness reports a per-entry
    /// mismatch line when the L1 classifier disagrees; this is
    /// useful for spotting classifier drift but does NOT affect the
    /// audit's L1 output (the classifier is still the authority).
    #[serde(default)]
    #[allow(dead_code)]
    // retained for fixture schema compatibility with lpm-security expectations
    expected: Option<String>,
    /// optional repository URL the L4 advisor
    /// will see in its prompt. Defaults to `None` so older fixture
    /// entries don't need a rewrite; delegate-to-local-file entries
    /// should carry a plausible URL pointing at a recognizable host.
    #[serde(default)]
    repository: Option<String>,
    /// optional simulated package name. The
    /// entry `id` doubles as the audit identity by default, but the
    /// L1 widening's identity match keys off the package's base
    /// name. For fixture entries whose ID is a synthetic prefix
    /// (`amber-d18-013-sharp-install-js`), supplying `package_name:
    /// "sharp"` gives the advisor the same identity payload a real
    /// `sharp` manifest would carry. When absent, the entry ID is
    /// used for compatibility with older fixtures.
    #[serde(default)]
    package_name: Option<String>,
    /// referenced file contents to embed in
    /// the advisor prompt. Same shape as `HermeticEntry::
    /// referenced_scripts` — `{ "filename": "...", "content": "..." }`
    /// entries. Defaults to empty so existing fixtures don't need a
    /// rewrite.
    #[serde(default)]
    referenced_scripts: Vec<HermeticReferencedScript>,
}

/// Run the audit against the curated
/// static-gate fixture. Same control flow as [`run_hermetic`]; the
/// per-entry construction reads `scripts/<id>.txt` for the body and
/// synthesizes a single-postinstall PackageAudit (the fixture is
/// "one script body per entry", so we slot every body under
/// `postinstall` — the static-gate classifier doesn't distinguish
/// by phase name, so this is faithful to the L1 contract).
///
/// `--advisor` works identically to live/hermetic; the audit run
/// completes by writing the same results + report + sidecar shape.
pub(crate) async fn run(args: &Args) -> Result<(), BoxError> {
    let expectations_bytes = std::fs::read(CURATED_EXPECTATIONS_PATH).map_err(|e| {
        format!(
            "curated corpus expectations not readable at {CURATED_EXPECTATIONS_PATH}: {e} \
             (this fixture lives in lpm-security/tests/fixtures/postinstall-scripts/ — a \
             missing read usually means the rust-client workspace layout was edited)"
        )
    })?;
    let expectations: Vec<CuratedExpectation> = serde_json::from_slice(&expectations_bytes)
        .map_err(|e| {
            format!("curated corpus expectations parse error at {CURATED_EXPECTATIONS_PATH}: {e}")
        })?;

    let mut audits: Vec<PackageAudit> = Vec::with_capacity(expectations.len());
    let mut missing_bodies: Vec<String> = Vec::new();
    for (idx, entry) in expectations.iter().enumerate() {
        let body_path = format!("{CURATED_SCRIPTS_DIR}/{}.txt", entry.id);
        let body = match std::fs::read_to_string(&body_path) {
            Ok(b) => b,
            Err(_) => {
                // Record missing-body entries but keep going so a
                // single misnamed fixture doesn't kill the whole
                // measurement run. The harness surfaces the count
                // in the stdout summary below.
                missing_bodies.push(entry.id.clone());
                continue;
            }
        };
        let refs: Vec<ReferencedScriptEntry> = entry
            .referenced_scripts
            .iter()
            .map(|r| ReferencedScriptEntry {
                filename: r.filename.clone(),
                content: r.content.clone(),
            })
            .collect();
        audits.push(curated_entry_to_audit(
            &entry.id,
            idx + 1,
            body,
            entry.repository.clone(),
            entry.package_name.as_deref(),
            refs,
        ));
    }

    if !missing_bodies.is_empty() {
        eprintln!(
            "warning: {} curated entry/entries had no script body file: {}",
            missing_bodies.len(),
            missing_bodies.join(", "),
        );
    }

    println!(
        "curated: loaded {} entries from {CURATED_EXPECTATIONS_PATH}",
        audits.len(),
    );

    audits.sort_by_key(|r| r.rank);
    finalize_outcomes(&mut audits);

    let mut metadata = AuditMetadata {
        run_completed_at: Some(now_rfc3339()),
        audit_size: Some(audits.len()),
        advisor: None,
        corpus: Some("curated".to_string()),
    };

    if let Some(name) = &args.advisor {
        metadata.advisor = enrich_advisor_in_place(name, &mut audits, args).await?;
    }

    persist_audit(&args.results, &args.report, &audits, &metadata)?;
    print_summary(&audits);
    Ok(())
}

/// Map one curated-fixture entry to a [`PackageAudit`]. The script
/// body is treated as the package's `postinstall` body (the
/// static-gate classifier doesn't distinguish by phase name). L3
/// inputs aren't in the fixture, so every entry gets the
/// "old publish, no attestation" baseline — matches the hermetic
/// fixture's no-cooldown-no-attestation shape.
fn curated_entry_to_audit(
    id: &str,
    rank: usize,
    body: String,
    repository: Option<String>,
    simulated_package_name: Option<&str>,
    referenced_scripts: Vec<ReferencedScriptEntry>,
) -> PackageAudit {
    // pass identity context to the L1
    // classifier. For most entries the fixture's entry ID doubles
    // as the package name; for entries whose ID is a synthetic
    // prefix (e.g. `amber-d18-013-sharp-install-js`), an explicit
    // `package_name` (e.g. `"sharp"`) lets the lever match the
    // identity payload a real manifest would carry.
    //
    // curated entries default to "old publish"
    // (8760h = 1 year, matching `hermetic_l3_outcome(8760, false)`
    // below), under the standard 24h cooldown.
    // defense-in-depth thus fires the widening normally on curated.
    // A future curated entry that wants to exercise the recent-
    // publish path would supply its own `publish_age_hours` field.
    let identity_name = simulated_package_name.unwrap_or(id);
    let ctx = ManifestContext {
        package_name: identity_name,
        repository: repository.as_deref(),
        bin_names: &[],
        publish_age_secs: Some(365 * 24 * 60 * 60),
        min_release_age_secs: 24 * 60 * 60,
    };
    let postinstall = Some(classify_script_with_context(&body, Some(&ctx)));
    let mut audit = PackageAudit {
        // The fixture entries don't have real npm names; the entry
        // ID is the audit identity. Surface it verbatim so the
        // report's per-package lines stay greppable against
        // `expectations.json`.
        name: id.to_string(),
        rank,
        monthly_downloads: 0,
        version: Some("0.0.0".to_string()),
        preinstall: None,
        install: None,
        postinstall,
        tier: None,
        l2_outcome: L2Outcome::Miss,
        l3_outcome: None,
        portable_outcome: None,
        advisor_outcome: None,
        advisor_provider: None,
        // curated entries may carry a
        // repository URL on `expectations.json` so the L4 advisor
        // can apply the delegate-to-local-file APPROVE rule. Older
        // expectation entries without the field land as `None`.
        repository,
        // curated entries may carry an
        // embedded view of their delegated file so the L4 advisor
        // can apply the fetch-IDENTITY rule one level deep without
        // a tarball fetch.
        referenced_scripts,
        fetch_error: None,
    };
    audit.tier = worst_of_phases(&audit);
    // Treat every curated entry as if it were an "old" publish with
    // no attestation — same shape as `hermetic_l3_outcome` defaults
    // when the fixture doesn't carry per-entry L3 data.
    if audit.tier.is_some() {
        audit.l3_outcome = Some(hermetic_l3_outcome(8760, false));
    }
    audit
}
