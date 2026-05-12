#!/usr/bin/env bash
set -euo pipefail

# ─── LPM Performance Measurement Suite ───────────────────────────────────────
#
# Two complementary tools:
#
#   criterion  — sub-millisecond resolver micro-benchmarks.
#                Measures pure resolver CPU (no network, no disk I/O).
#                Runs statistical analysis: 50 samples, reports min/median/max
#                and percent change vs the saved baseline.
#                Target: resolver algorithm trials (allocator, hasher, inline).
#
#   dhat       — exact heap allocation counts for a real install run.
#                Eliminates OS/network noise entirely. Tells you whether an
#                optimization actually reduced allocation count, not just
#                whether the wall clock happened to be faster today.
#                Target: mimalloc trial, PathBuf pool trial.
#
# Usage:
#   ./bench/run-perf.sh criterion        # run resolver criterion bench
#   ./bench/run-perf.sh dhat             # build + run dhat on fixture-large
#   ./bench/run-perf.sh dhat-save NAME   # save a named dhat snapshot
#   ./bench/run-perf.sh baseline         # save criterion baseline (before optimization)
#   ./bench/run-perf.sh compare NAME     # compare current criterion run to saved NAME
#
# ─────────────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$REPO_ROOT/bench/fixture-large"
RESULTS_DIR="$REPO_ROOT/bench/perf-results"
DHAT_BINARY="$REPO_ROOT/target/debug/lpm-rs"
# Separate target dir keeps perf builds from polluting the regular incremental cache
PERF_TARGET="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

mode="${1:-help}"

case "$mode" in

# ── criterion ────────────────────────────────────────────────────────────────
criterion)
    echo "▶ criterion: lpm-resolver greedy bench"
    echo "  corpus: n=50 / n=266 / n=500 / n=1000 synthetic packages"
    echo "  samples: 50 per corpus size"
    echo ""
    cargo bench -p lpm-resolver --bench greedy 2>&1 | tee "$RESULTS_DIR/criterion-latest.txt"
    echo ""
    echo "HTML report: $PERF_TARGET/criterion/greedy_resolver/report/index.html"
    ;;

# ── dhat build + run ─────────────────────────────────────────────────────────
dhat)
    echo "▶ dhat: building lpm-cli with heap instrumentation (debug profile)"
    cargo build -p lpm-cli --features dhat-heap 2>&1

    echo ""
    echo "▶ dhat: running on fixture-large (21 direct → ~266 transitive packages)"
    echo "  This is a real install run — network required for first-time run."
    echo "  Use a pre-warmed cache for noise-free counts:"
    echo "    lpm install          # populate ~/.lpm/cache/metadata first"
    echo "    rm -rf node_modules  # then measure link+extract only"
    echo ""
    cd "$FIXTURE"
    rm -rf node_modules
    "$DHAT_BINARY" install
    echo ""
    echo "▶ dhat output: $FIXTURE/dhat-heap.json"
    echo "  View at: https://nnethercote.github.io/dh_view/dh_view.html"
    echo "  Key metrics to note:"
    echo "    'Total bytes allocated'  — if this drops, the optimization works"
    echo "    'Total blocks allocated' — allocation count (noise-free signal)"
    echo "    'Peak bytes'             — RSS high-water mark"
    ;;

# ── dhat with named snapshot ──────────────────────────────────────────────────
dhat-save)
    name="${2:-unnamed}"
    "$0" dhat
    dest="$RESULTS_DIR/dhat-${name}.json"
    cp "$FIXTURE/dhat-heap.json" "$dest"
    echo ""
    echo "▶ Saved snapshot: $dest"
    echo "  Compare two snapshots side-by-side in dh_view by loading both."
    ;;

# ── criterion baseline save ───────────────────────────────────────────────────
baseline)
    echo "▶ criterion: saving baseline (run this BEFORE applying optimizations)"
    cargo bench -p lpm-resolver --bench greedy 2>&1 | tee "$RESULTS_DIR/criterion-baseline.txt"
    # criterion auto-saves JSON baselines in target/criterion/ — subsequent
    # runs compare against those automatically and report percent change.
    echo ""
    echo "Baseline saved. Apply your optimization, then run:"
    echo "  ./bench/run-perf.sh criterion"
    echo "to see the percent-change comparison."
    ;;

# ── compare named run ─────────────────────────────────────────────────────────
compare)
    name="${2:-baseline}"
    saved="$RESULTS_DIR/criterion-${name}.txt"
    if [[ ! -f "$saved" ]]; then
        echo "No saved run at $saved"
        echo "Run: ./bench/run-perf.sh baseline  first"
        exit 1
    fi
    echo "▶ Saved ($name):"
    grep "time:" "$saved" | head -20
    echo ""
    echo "▶ Current (running now):"
    cargo bench -p lpm-resolver --bench greedy 2>&1 | grep "time:\|change:" | head -40
    ;;

*)
    echo "Usage: $0 criterion | dhat | dhat-save NAME | baseline | compare NAME"
    echo ""
    echo "  criterion         Run resolver micro-benchmarks (statistical, no network)"
    echo "  dhat              Build dhat binary and run on fixture-large"
    echo "  dhat-save NAME    Same as dhat but saves the .json snapshot"
    echo "  baseline          Save criterion baseline before applying an optimization"
    echo "  compare NAME      Compare current criterion run to a saved run"
    ;;

esac
