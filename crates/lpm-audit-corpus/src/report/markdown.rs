use std::collections::BTreeMap;

use lpm_security::triage::StaticTier;

use crate::classify::{is_policy_permanent_amber_shape, red_phases, scripted_phases, shape_label};
use crate::report::summary::{summarise, summarise_advisor, summarise_portable};
use crate::types::{AdvisorOutcome, AuditMetadata, PackageAudit, PortableOutcome, ScriptShape};

pub(crate) fn build_report(audits: &[PackageAudit], metadata: &AuditMetadata) -> String {
    let mut out = String::new();
    out.push_str("# Top-N audit (L1-3, portable)\n\n");
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

/// Locked standing benchmark. These numbers are the canonical comparison
/// points for future
/// iterations.
///
/// `metadata.corpus` re-interprets one cell: on the live top-N
/// corpus, `zero-FP-red` is a ship gate that MUST stay 0
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
    // (Ship gate: any red on real top-N is a suspected
    // false-positive). On the hermetic fixture the reds are
    // intentional shape coverage, so the "MUST stay 0" framing is
    // misleading — re-word that single cell.
    let zero_fp_red_note = match metadata.corpus.as_deref() {
        Some("hermetic") => {
            "Hermetic fixture: count reflects intentional red shape coverage, not a ship-gate failure. Compare to the prior run's value; a change signals a classifier drift on the fixed corpus."
        }
        _ => "**Ship gate — MUST stay 0**",
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
    sorted.sort_by_key(|entry| std::cmp::Reverse(entry.1.count));
    out.push_str("## Prompt-shape breakdown\n\n");
    out.push_str(
        "Each prompted script categorised by normalised shape. The \
         `policy-permanent?` flag marks shapes that are amber by design \
         design (binary-fetcher / prebuild-fallback) — they should \
         NOT be treated as classifier-tuning candidates in future \
         iterations.\n\n",
    );
    out.push_str("| Shape | Count | Policy-permanent? | Sample packages → script |\n");
    out.push_str("|-------|------:|:------------------|----|\n");
    for (shape, bucket) in sorted {
        let perm = if is_policy_permanent_amber_shape(shape) {
            "**yes — D18 binary-fetcher**"
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
        "L1 green / (green + amber) over scripted = **{:.2}%** (corpus floor: ≥60% on the curated 500-entry corpus; live distribution is not gated by that floor).\n\n",
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
        scripted
            .iter()
            .filter(|a| a.l3_outcome.as_ref().is_some_and(|l| l.attestation_present))
            .count(),
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
                        .map_or_else(|| "?".to_string(), |s| s.to_string()),
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

fn escape_md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('`', "\\`")
}
