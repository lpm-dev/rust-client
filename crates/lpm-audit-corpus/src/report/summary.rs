use lpm_security::triage::StaticTier;

use crate::classify::package_is_policy_permanent_amber;
use crate::types::{AdvisorOutcome, PackageAudit, PortableOutcome};

pub(crate) fn print_summary(audits: &[PackageAudit]) {
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
pub(crate) struct AdvisorSummary {
    pub(crate) invoked: usize,
    pub(crate) auto_run: usize,
    pub(crate) prompt: usize,
    pub(crate) hard_block: usize,
}

pub(crate) fn summarise_advisor(audits: &[PackageAudit]) -> AdvisorSummary {
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

#[derive(Debug, Default)]
pub(crate) struct Summary {
    pub(crate) green: usize,
    pub(crate) amber: usize,
    pub(crate) red: usize,
    pub(crate) no_scripts: usize,
    pub(crate) fetch_failed: usize,
}

impl Summary {
    pub(crate) fn scripted_total(&self) -> usize {
        self.green + self.amber + self.red
    }
    pub(crate) fn green_share_pct(&self) -> f64 {
        let denom = (self.green + self.amber) as f64;
        if denom == 0.0 {
            0.0
        } else {
            (self.green as f64) * 100.0 / denom
        }
    }
}

pub(crate) fn summarise(audits: &[PackageAudit]) -> Summary {
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
/// amber-script shape is policy-permanent — i.e. amber by design
/// design (binary-fetcher / prebuild-fallback). The tuneable count is
/// the standing "how much classifier headroom is left" number.
#[derive(Debug, Default)]
pub(crate) struct PortableSummary {
    pub(crate) auto_run: usize,
    pub(crate) prompt: usize,
    /// Subset of `prompt` excluding policy-permanent shapes. Always
    /// `<= prompt`.
    pub(crate) prompt_tuneable: usize,
    pub(crate) hard_block: usize,
    pub(crate) no_scripts: usize,
    /// Hard ship-gate number — must always be 0 for real-corpus runs.
    pub(crate) zero_fp_red_count: usize,
    /// L3 cooldown blocks broken out separately so the standing table
    /// can distinguish "blocked because L1 red" from "blocked because
    /// L3 said the release is too new".
    pub(crate) cooldown_blocks: usize,
    /// Attestation coverage over scripted packages.
    pub(crate) attestation_present: usize,
    pub(crate) scripted_total: usize,
}

pub(crate) fn summarise_portable(audits: &[PackageAudit]) -> PortableSummary {
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
