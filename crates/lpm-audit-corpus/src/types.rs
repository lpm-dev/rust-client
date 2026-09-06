use lpm_security::triage::StaticTier;
use serde::{Deserialize, Serialize};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TopNEntry {
    pub(crate) name: String,
    pub(crate) monthly_downloads: u64,
    pub(crate) rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PackageAudit {
    pub(crate) name: String,
    pub(crate) rank: usize,
    pub(crate) monthly_downloads: u64,
    /// `Some(version)` if a manifest was successfully fetched, else `None`.
    pub(crate) version: Option<String>,
    /// Per-phase classification. `None` if the script was absent in the manifest.
    pub(crate) preinstall: Option<ScriptAudit>,
    pub(crate) install: Option<ScriptAudit>,
    pub(crate) postinstall: Option<ScriptAudit>,
    /// Worst-of of the three phases. `None` if none of the three scripts was set.
    pub(crate) tier: Option<StaticTier>,
    /// Layer 2 result. Always [`L2Outcome::Miss`] in a first-install
    /// audit (the audit user has no prior trust state).
    #[serde(default = "L2Outcome::default_miss")]
    pub(crate) l2_outcome: L2Outcome,
    /// Layer 3 result. `None` for packages with no scripts (L3 not
    /// applicable) and for runs that haven't enriched yet.
    #[serde(default)]
    pub(crate) l3_outcome: Option<L3Outcome>,
    /// Final outcome under the **portable** triage contract (script-policy
    /// = "triage", triage-advisor = "none"). Computed deterministically
    /// from L1+L2+L3; this is the decision-grade metric per the
    /// principle that triage must mean the same thing on every machine.
    #[serde(default)]
    pub(crate) portable_outcome: Option<PortableOutcome>,
    /// Populated only when an advisor was invoked on this package;
    /// otherwise `None` and the portable outcome is the authoritative
    /// answer for this run.
    #[serde(default)]
    pub(crate) advisor_outcome: Option<AdvisorOutcome>,
    /// Provider slug for the advisor that produced `advisor_outcome`
    /// (e.g. `"claude-cli"`). Lets the report name the advisor in
    /// its conclusion sentence without an out-of-band side channel.
    #[serde(default)]
    pub(crate) advisor_provider: Option<String>,
    /// `repository` URL pulled from the
    /// manifest's `repository` field. Forwarded to the advisor at
    /// classify time so the prompt can reason about package
    /// identity. Persisted on each record so a `--reclassify` (or
    /// future advisor re-run) doesn't need to re-fetch the manifest
    /// to recover the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) repository: Option<String>,
    /// files the script body delegates to,
    /// each as `(filename, content)`. The advisor prompt embeds
    /// these so the model can see one level deeper than the
    /// delegating one-liner. Hermetic / curated fixtures supply
    /// the content directly; the live-fetch path currently leaves
    /// this empty (tarball download is the heavy step the
    /// audit-corpus harness has deliberately not added — fixtures
    /// are the measurement vehicle).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) referenced_scripts: Vec<ReferencedScriptEntry>,
    /// Empty unless the manifest fetch errored.
    pub(crate) fetch_error: Option<String>,
}

/// one referenced file persisted on a
/// `PackageAudit` record. Storing the `(filename, content)` pair
/// inline lets `--reclassify` and `--advisor` re-runs use the
/// embedded view without re-fetching the tarball.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReferencedScriptEntry {
    pub(crate) filename: String,
    pub(crate) content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ScriptAudit {
    pub(crate) script: String,
    pub(crate) tier: StaticTier,
    pub(crate) first_token: Option<String>,
    /// Normalised shape bucket for reporting (replaces the lossy
    /// first-token grouping). Populated at classify time.
    #[serde(default)]
    pub(crate) shape: Option<ScriptShape>,
}

/// Layer 2 — trust-manifest outcome.
///
/// In a first-install audit (no prior `trustedDependencies` snapshot on
/// disk), Layer 2 always returns `Miss` because there's nothing to
/// strict-match against. The other variants are reserved for future
/// audits that simulate prior approval state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum L2Outcome {
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
    pub(crate) fn default_miss() -> Self {
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
pub(crate) struct L3Outcome {
    /// ISO 8601 publish timestamp of the latest version (from the
    /// registry packument's `time[<version>]`). `None` when the
    /// registry didn't return a usable timestamp.
    #[serde(default)]
    pub(crate) published_at: Option<String>,
    /// Age of the release in seconds at the time of the audit run.
    /// `None` if `published_at` couldn't be parsed.
    #[serde(default)]
    pub(crate) age_secs: Option<u64>,
    /// Whether `cooldown_block` would have fired under the default
    /// `SecurityPolicy::DEFAULT_MIN_RELEASE_AGE` (0, disabled). The audit uses
    /// the default explicitly to keep numbers reproducible — users
    /// who tighten via `lpm.minimumReleaseAge` see stricter blocks
    /// than these.
    pub(crate) cooldown_block: bool,
    /// Whether the latest version has Sigstore attestations published
    /// to the npm attestations endpoint. Captured for reporting; does
    /// NOT gate the portable outcome on its own (provenance drift
    /// requires an approved-side reference, which a first-install
    /// audit doesn't have).
    pub(crate) attestation_present: bool,
    /// Drift verdict for the audit's reference frame. Always
    /// `NoDrift` for first-install audits — surfaced as a field so
    /// future audits that simulate prior approvals can populate it
    /// without schema churn.
    pub(crate) provenance_drift: ProvenanceDriftSummary,
    /// Empty unless one of the L3 fetches errored. The other fields
    /// reflect best-effort partial data.
    #[serde(default)]
    pub(crate) l3_fetch_error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProvenanceDriftSummary {
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
pub(crate) enum PortableOutcome {
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
pub(crate) enum AdvisorOutcome {
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
pub(crate) struct AuditMetadata {
    /// Wall-clock timestamp the audit run finished (ISO 8601 UTC).
    #[serde(default)]
    pub(crate) run_completed_at: Option<String>,
    /// `--size` value that produced the audited population.
    #[serde(default)]
    pub(crate) audit_size: Option<usize>,
    /// L4 advisor stamp. `None` when the run had no `--advisor`.
    #[serde(default)]
    pub(crate) advisor: Option<AdvisorStamp>,
    /// Corpus origin: `"live"` for npm-walked, `"hermetic"`
    /// for the frozen offline fixture. Stamped so the report writer
    /// can pick the right interpretation for ambiguous metrics
    /// (e.g. zero-FP-red is a ship gate on live but expected
    /// fixture coverage on hermetic). `None` on records written
    /// before this field existed; readers default to the live
    /// interpretation in that case.
    #[serde(default)]
    pub(crate) corpus: Option<String>,
}

/// Identity of the advisor that ran on this audit. Lets future
/// comparison runs explain "+1 vs +2 uplift" by showing whether the
/// binary version, prompt template, or model changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AdvisorStamp {
    /// Provider slug (`claude-cli` / `codex` / `ollama`).
    pub(crate) provider: String,
    /// Absolute path of the binary that ran. `None` if the adapter
    /// invokes via HTTP only (Ollama) and the CLI isn't on PATH.
    #[serde(default)]
    pub(crate) binary_path: Option<String>,
    /// Output of `<binary> --version`. Best-effort: `None` if the
    /// binary doesn't support `--version` or the probe failed.
    #[serde(default)]
    pub(crate) binary_version: Option<String>,
    /// For Ollama only: the model name passed to `/api/generate`.
    /// `None` for CLI providers.
    #[serde(default)]
    pub(crate) model: Option<String>,
    /// SHA-256 of the canonical prompt rendering. Changes iff
    /// [`lpm_triage_advisor::build_prompt`] changes.
    pub(crate) prompt_template_hash: String,
    /// Count of packages the advisor was invoked on (== number of
    /// packages with `portable_outcome = Prompt` at invocation time).
    pub(crate) invoked_count: usize,
}

/// Normalised shape bucket for reporting amber scripts. Replaces the
/// lossy first-token grouping that lumped softfail-wrappers, binary
/// fetchers, and helper scripts together under "node".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ScriptShape {
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

/// one referenced file in a hermetic fixture
/// entry. Mirrors the prompt's `ReferencedScript` shape so the
/// fixture format is easy to author by hand.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HermeticReferencedScript {
    pub(crate) filename: String,
    pub(crate) content: String,
}
