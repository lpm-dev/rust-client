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
//! intended for calibration runs (and future re-runs after
//! green-allowlist iterations).

mod args;
mod classify;
mod corpus;
mod io;
mod layers;
mod report;
mod types;
mod util;

use args::{Args, CorpusKind};
use clap::Parser;
use types::BoxError;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    match args.corpus {
        CorpusKind::Live => corpus::live::run(&args).await,
        CorpusKind::Hermetic => corpus::hermetic::run(&args).await,
        CorpusKind::Curated => corpus::curated::run(&args).await,
    }
}
