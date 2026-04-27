#!/bin/bash
# Phase 56 W1 bench harness — 3 lpm arms + bun control on bench/fixture-large COLD.
#
# Cells (round-robin per outer iteration so each arm sees similar network state):
#   - pubgrub-stream  — control:   PubGrub resolver + streaming walker (today's default)
#   - greedy-stream   — baseline:  greedy resolver  + streaming walker (Phase 53 W2 ship)
#   - greedy-fusion   — NEW:       greedy resolver  + fused dispatcher (LPM_GREEDY_FUSION=1)
#
# Bun control: separate cold installs (default n=10).
#
# At W1 HEAD (no fusion code yet) the LPM_GREEDY_FUSION env var is unread, so the
# greedy-fusion arm collapses to "greedy with no walker env var" (default walker mode).
# That is intentional — the W1 ship-or-drop measurement is "all 4 lpm cells produce
# stable medians within ±200 ms across runs" (harness-validation), not a fusion-vs-
# walker delta. The fusion delta lands when W2 wires `resolve_greedy_fused`.
#
# Per Phase 56 pre-plan §5 the fixture path and clean targets match Phase 53 W5
# exactly so wall medians are directly comparable.
#
# Usage: $0 <n_iters> [<tag>]
#
set -euo pipefail

N="${1:-20}"
TAG="${2:-w1-validation}"
N_BUN="${N_BUN:-10}"

BIN="/tmp/lpm-rs-phase56-target/release/lpm-rs"
FIXTURE="/Users/tolga/Documents/Projects/lpm-dev/rust-client/bench/fixture-large"
RESULTS="/tmp/phase56-fusion-bench/${TAG}-results"
mkdir -p "$RESULTS"

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary missing at $BIN — wait for cargo build"; exit 1
fi
if ! command -v bun &>/dev/null; then
    echo "ERROR: bun not on PATH"; exit 1
fi

clean_lpm() {
    rm -rf "${HOME}/.lpm/cache" "${HOME}/.lpm/store"
    rm -rf "${FIXTURE}/node_modules" "${FIXTURE}/.lpm" \
           "${FIXTURE}/lpm.lock" "${FIXTURE}/lpm.lockb"
}
clean_bun() {
    rm -rf "${HOME}/.bun/install/cache"
    rm -rf "${FIXTURE}/node_modules" "${FIXTURE}/bun.lockb" "${FIXTURE}/bun.lock"
}
cd "$FIXTURE"

echo "[bench] phase56 ${TAG} — n=${N} per cell, n_bun=${N_BUN}"
date

for i in $(seq 1 "$N"); do
    for arm in pubgrub-stream greedy-stream greedy-fusion; do
        clean_lpm
        unset LPM_RESOLVER LPM_WALKER LPM_GREEDY_FUSION
        case $arm in
            pubgrub-stream)
                export LPM_WALKER=stream
                ;;
            greedy-stream)
                # W4: fusion is the default under LPM_RESOLVER=greedy,
                # so this cell pins to the legacy walker arm via
                # `LPM_GREEDY_FUSION=0` — explicit opt-out. Pre-W4 this
                # was unset; setting it to "0" preserves the cell's
                # walker-arm semantics regardless of repo HEAD.
                export LPM_RESOLVER=greedy
                export LPM_WALKER=stream
                export LPM_GREEDY_FUSION=0
                ;;
            greedy-fusion)
                # W4: `LPM_GREEDY_FUSION=1` is now redundant (fusion is
                # the default for LPM_RESOLVER=greedy), but kept here
                # explicitly so the cell self-documents its intent and
                # so the harness still works against pre-W4 HEADs for
                # comparison runs.
                export LPM_RESOLVER=greedy
                export LPM_GREEDY_FUSION=1
                export LPM_WALKER=stream
                ;;
        esac
        out="$RESULTS/iter-${i}-${arm}.json"
        err="$RESULTS/iter-${i}-${arm}.err"
        s=$(python3 -c 'import time;print(time.perf_counter_ns())')
        "$BIN" install --allow-new --json > "$out" 2> "$err" || true
        e=$(python3 -c 'import time;print(time.perf_counter_ns())')
        wall_ms=$(( (e-s)/1000000 ))
        echo "$wall_ms" > "$RESULTS/iter-${i}-${arm}.wall_ms"
        echo "  iter $i $arm = ${wall_ms} ms"
    done
done
unset LPM_RESOLVER LPM_WALKER LPM_GREEDY_FUSION

echo "[bun control] n=${N_BUN}"
for i in $(seq 1 "$N_BUN"); do
    clean_bun
    out="$RESULTS/iter-${i}-bun.out"
    err="$RESULTS/iter-${i}-bun.err"
    s=$(python3 -c 'import time;print(time.perf_counter_ns())')
    bun install --no-summary --force > "$out" 2> "$err" || true
    e=$(python3 -c 'import time;print(time.perf_counter_ns())')
    wall_ms=$(( (e-s)/1000000 ))
    echo "$wall_ms" > "$RESULTS/iter-${i}-bun.wall_ms"
    echo "  iter $i bun = ${wall_ms} ms"
done

echo "[done] $RESULTS"
date
echo "=== summary ==="
python3 /tmp/phase56-fusion-bench/summarize.py "$RESULTS"
