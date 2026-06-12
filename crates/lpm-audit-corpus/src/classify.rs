use lpm_security::static_gate::{ManifestContext, classify_with_context};
use lpm_security::triage::StaticTier;

use crate::types::{
    L2Outcome, PackageAudit, PortableOutcome, ProvenanceDriftSummary, ScriptAudit, ScriptShape,
};

/// Populate `portable_outcome` on every record. Pure computation,
/// always safe to re-run after a change to the outcome logic.
pub(crate) fn finalize_outcomes(audits: &mut [PackageAudit]) {
    for a in audits.iter_mut() {
        a.portable_outcome = Some(compute_portable_outcome(a));
    }
}

/// Refresh the `shape` bucket on every recorded script body. Pure
/// re-computation against the cached script — does NOT change tier.
/// Called by the cache-only paths so older records (written before
/// the `shape` field existed) get bucketed properly.
pub(crate) fn refresh_shapes(audits: &mut [PackageAudit]) {
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

#[allow(dead_code)] // kept as the context-free shorthand; presently
// all in-crate callers pass `Some(ctx)` via
// `classify_script_with_context`, but downstream tooling
// (e.g. ad-hoc binaries linking the crate) may still want the bare
// form. Removing it would be a public-surface change.
pub(crate) fn classify_script(script: &str) -> ScriptAudit {
    classify_script_with_context(script, None)
}

/// classify with optional manifest context for
/// the `node install.js` + matching-identity widening. Callers that
/// have the package name + repository / bin available should prefer
/// this form so the L1 tier reflects the lever; legacy callers
/// (e.g. `--reclassify` over cached records without identity data)
/// fall back to context-free classification with `None`.
pub(crate) fn classify_script_with_context(
    script: &str,
    ctx: Option<&ManifestContext<'_>>,
) -> ScriptAudit {
    let tier = classify_with_context(script, ctx);
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
pub(crate) fn classify_shape(script: &str, tokens: &[String], tier: StaticTier) -> ScriptShape {
    let trimmed = script.trim();
    let bare = tokens.first().map_or("", String::as_str);

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
    // Binary-fetcher set (mirrors the classifier's
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

pub(crate) fn worst_of_phases(a: &PackageAudit) -> Option<StaticTier> {
    [&a.preinstall, &a.install, &a.postinstall]
        .into_iter()
        .flatten()
        .map(|s| s.tier)
        .reduce(StaticTier::worse_of)
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
pub(crate) fn compute_portable_outcome(a: &PackageAudit) -> PortableOutcome {
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

/// Is the dominant amber-tier script on this package classified under
/// a policy-permanent shape? Worst-tier-of-shapes wins (matches the
/// classifier's worst-of-phases logic). A `None` shape (older cached
/// records pre-dating the field) is treated as tunable, since we
/// can't prove permanence without re-bucketing.
pub(crate) fn package_is_policy_permanent_amber(a: &PackageAudit) -> bool {
    [&a.preinstall, &a.install, &a.postinstall]
        .into_iter()
        .flatten()
        .filter(|s| matches!(s.tier, StaticTier::Amber | StaticTier::AmberLlm))
        .filter_map(|s| s.shape)
        .any(is_policy_permanent_amber_shape)
}

pub(crate) fn shape_label(s: ScriptShape) -> &'static str {
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
/// design (binary-fetcher / prebuild-fallback are D18 downloader
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
pub(crate) fn is_policy_permanent_amber_shape(s: ScriptShape) -> bool {
    matches!(
        s,
        ScriptShape::BinaryFetcher | ScriptShape::PrebuildFallback
    )
}

pub(crate) fn scripted_phases(a: &PackageAudit) -> Vec<(&'static str, &ScriptAudit)> {
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

pub(crate) fn red_phases(a: &PackageAudit) -> Vec<(&'static str, &ScriptAudit)> {
    scripted_phases(a)
        .into_iter()
        .filter(|(_p, s)| s.tier == StaticTier::Red)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::L3Outcome;

    fn audit_with_tier(tier: Option<StaticTier>) -> PackageAudit {
        PackageAudit {
            name: "pkg".to_string(),
            rank: 1,
            monthly_downloads: 10,
            version: Some("1.0.0".to_string()),
            preinstall: tier.map(|tier| ScriptAudit {
                script: "node install.js".to_string(),
                tier,
                first_token: Some("node".to_string()),
                shape: Some(ScriptShape::BinaryFetcher),
            }),
            install: None,
            postinstall: None,
            tier,
            l2_outcome: L2Outcome::Miss,
            l3_outcome: None,
            portable_outcome: None,
            advisor_outcome: None,
            advisor_provider: None,
            repository: None,
            referenced_scripts: Vec::new(),
            fetch_error: None,
        }
    }

    #[test]
    fn compute_portable_outcome_hard_blocks_red_scripts() {
        assert_eq!(
            compute_portable_outcome(&audit_with_tier(Some(StaticTier::Red))),
            PortableOutcome::HardBlock
        );
    }

    #[test]
    fn compute_portable_outcome_prompts_amber_without_l3_block() {
        assert_eq!(
            compute_portable_outcome(&audit_with_tier(Some(StaticTier::Amber))),
            PortableOutcome::Prompt
        );
    }

    #[test]
    fn compute_portable_outcome_hard_blocks_amber_with_cooldown() {
        let mut audit = audit_with_tier(Some(StaticTier::Amber));
        audit.l3_outcome = Some(L3Outcome {
            published_at: None,
            age_secs: None,
            cooldown_block: true,
            attestation_present: false,
            provenance_drift: ProvenanceDriftSummary::NoDrift,
            l3_fetch_error: None,
        });
        assert_eq!(compute_portable_outcome(&audit), PortableOutcome::HardBlock);
    }
}
