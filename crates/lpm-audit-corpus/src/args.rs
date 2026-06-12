use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lpm-audit-corpus")]
#[command(about = "Run lpm-security static-gate over the top-N npm packages.")]
pub(crate) struct Args {
    /// Top-N to audit (paginates the npm search API in 250-package batches).
    #[arg(long, default_value_t = 5000)]
    pub(crate) size: usize,

    /// Cache file for the top-N list (reused across audit re-runs).
    #[arg(long, default_value = "/tmp/lpm-audit-top-n.json")]
    pub(crate) top_n_cache: PathBuf,

    /// Output: per-package audit results (JSON).
    #[arg(long, default_value = "/tmp/lpm-audit-results.json")]
    pub(crate) results: PathBuf,

    /// Output: human-readable Markdown summary.
    #[arg(long, default_value = "/tmp/lpm-audit-report.md")]
    pub(crate) report: PathBuf,

    /// Concurrent manifest fetches.
    #[arg(long, default_value_t = 32)]
    pub(crate) concurrency: usize,

    /// Force-refresh the top-N cache even if a valid one exists.
    #[arg(long, default_value_t = false)]
    pub(crate) refresh_top_n: bool,

    /// Per-request timeout (seconds).
    #[arg(long, default_value_t = 30)]
    pub(crate) timeout_secs: u64,

    /// Resume from a previous results file: keep records without
    /// `fetch_error`, retry only the ones that failed. Useful after a
    /// 429-heavy run.
    #[arg(long, default_value_t = false)]
    pub(crate) resume: bool,

    /// Re-classify the scripts recorded in `--results` without
    /// re-fetching manifests. Use after a `static_gate.rs` change to
    /// measure the new tier distribution against the cached dataset.
    /// `--top-n-cache` is still required (rank + downloads come from
    /// it) but no network calls are made.
    #[arg(long, default_value_t = false)]
    pub(crate) reclassify: bool,

    /// Backfill Layer 3 data (packument `time` + attestation
    /// presence) for scripted records in `--results` without
    /// re-running L1 classification. Useful after extending the
    /// existing cache with the L1-3 harness for the first time.
    /// Fetches only scripted packages (≪ 5000), so completes in
    /// seconds.
    #[arg(long, default_value_t = false)]
    pub(crate) enrich_l3_only: bool,

    /// Skip Layer 3 enrichment during a default audit run. Layer 3
    /// data is omitted; `portable_outcome` falls back to L1-only.
    /// Primarily for development; the production audit should always
    /// include L3 because the portable contract requires it.
    #[arg(long, default_value_t = false)]
    pub(crate) skip_l3: bool,

    /// Invoke the named Layer 4 advisor on every package whose
    /// portable outcome is `Prompt`, recording the verdict on
    /// `advisor_outcome`. Reported as a separate uplift line, never
    /// blended with the portable baseline. Valid values:
    /// `claude-cli` / `codex` / `ollama`.
    #[arg(long)]
    pub(crate) advisor: Option<String>,

    /// Opt-in to the L4 verdict cache.
    /// Off by default so a cold measurement run pays the full LLM
    /// round-trip cost (the honest "first install" comparison
    /// number). When set, the audit harness reads `~/.lpm/cache/
    /// l4-verdicts.json` (or `$LPM_L4_CACHE_PATH` if set) and uses
    /// the same cache the install pipeline does; a second run with
    /// `--l4-cache` should be nearly silent (every prior verdict
    /// served from cache, no LLM calls).
    ///
    /// The cache module's own `LPM_L4_CACHE=0` env-var disable still
    /// applies — setting both flag-on + env-off keeps the cache
    /// off (env wins). Useful for benchmark scripts that want one
    /// flag-driven run to deliberately bypass a populated cache.
    #[arg(long, default_value_t = false)]
    pub(crate) l4_cache: bool,

    /// Print one-line cache stats summary at the end
    /// of the L4 phase (`hits / misses / entries`). Implied by
    /// `--l4-cache`; the flag exists so a future cache-debugging
    /// run can request the summary without enabling the cache itself.
    #[arg(long, default_value_t = false)]
    pub(crate) l4_cache_stats: bool,

    /// Corpus selector. `live` (default) walks the npm
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
    pub(crate) corpus: CorpusKind,
}

/// Origin of the audit corpus. See [`Args::corpus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub(crate) enum CorpusKind {
    /// Walk the npm registry search API + fetch manifests over the
    /// network. The default — preserves legacy behavior.
    Live,
    /// Read the bundled offline fixture set
    /// (`crates/lpm-audit-corpus/fixtures/hermetic/corpus.json`).
    /// No network calls; output shape is identical to live mode so
    /// the same Markdown report + standing-benchmark table fires.
    Hermetic,
    /// Read the 523-entry curated static-gate corpus at
    /// `crates/lpm-security/tests/fixtures/postinstall-scripts/`
    /// (the same fixture `static_gate_corpus.rs` exercises). Each
    /// entry's expected tier from `expectations.json` becomes the
    /// L1 input; the script body comes from `scripts/<id>.txt`. No
    /// network calls. Designed for L4-advisor amber-shift
    /// measurements against hand-curated real-world script shapes
    /// — wider coverage than the 16-entry hermetic fixture.
    ///
    /// L3 inputs (publish age, attestation) aren't part of the
    /// fixture, so the curated path treats every entry as "old
    /// publish, no attestation" — same as the hermetic baseline.
    /// L1 is the load-bearing signal for this corpus.
    Curated,
}
