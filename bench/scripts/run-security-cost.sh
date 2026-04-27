#!/bin/bash
# Phase 57 measurement-sprint A — security-analyzer wall-cost on the
# fusion install hot path. Two cells, n=20 round-robin per outer iter.
#
#   fusion-baseline    — current default (security analyzer fused into extract)
#   fusion-no-security — LPM_SKIP_SECURITY=1 (predicate disabled, inspector
#                        no-op, finalize skipped — see lpm-store/src/lib.rs)
#
# Wall delta = empirical cost of behavioral analysis on bench/fixture-large.
# Compares against Gemini's "~300 ms wall-clock win from deferring the
# analyzer" claim, which assumed a serial post-extract pass. Phase 38 P2
# already folded analysis INTO the extract pass, so the empirical answer
# may differ substantially from the model.
#
# Usage: $0 <n_iters> [<tag>]
set -euo pipefail

N="${1:-20}"
TAG="${2:-security-cost}"
BIN="/tmp/lpm-rs-phase56-target/release/lpm-rs"
FIXTURE="/Users/tolga/Documents/Projects/lpm-dev/rust-client/bench/fixture-large"
RESULTS="/tmp/phase56-fusion-bench/${TAG}-results"
mkdir -p "$RESULTS"

[[ -x "$BIN" ]] || { echo "ERROR: binary missing at $BIN"; exit 1; }

clean_lpm() {
    rm -rf "${HOME}/.lpm/cache" "${HOME}/.lpm/store"
    rm -rf "${FIXTURE}/node_modules" "${FIXTURE}/.lpm" \
           "${FIXTURE}/lpm.lock" "${FIXTURE}/lpm.lockb"
}
cd "$FIXTURE"

echo "[bench] phase57-${TAG} — n=${N} per cell"
date

for i in $(seq 1 "$N"); do
    for arm in fusion-baseline fusion-no-security; do
        clean_lpm
        unset LPM_SKIP_SECURITY
        export LPM_RESOLVER=greedy
        export LPM_WALKER=stream  # explicit; redundant under W4 default-fusion
        case $arm in
            fusion-no-security)
                export LPM_SKIP_SECURITY=1
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
unset LPM_RESOLVER LPM_WALKER LPM_SKIP_SECURITY

echo "[done] $RESULTS"
date
echo "=== summary ==="
python3 - "$RESULTS" <<'PY'
import os, sys, glob, statistics, math, re
RES = sys.argv[1]
def load(arm):
    out = []
    for f in sorted(glob.glob(os.path.join(RES, f'iter-*-{arm}.wall_ms'))):
        try:
            v = int(open(f).read().strip())
            out.append((int(re.search(r'iter-(\d+)-', f).group(1)), v))
        except: pass
    return sorted(out)
loaded = {arm: load(arm) for arm in ['fusion-baseline', 'fusion-no-security']}
print(f"  {'arm':<22s} {'n':>4s} {'median':>8s} {'mean':>8s} {'stdev':>8s}")
for arm, data in loaded.items():
    if not data: continue
    vals = [v for _, v in data]
    print(f"  {arm:<22s} {len(vals):>4d} {statistics.median(vals):>8.0f} "
          f"{statistics.mean(vals):>8.0f} "
          f"{statistics.stdev(vals) if len(vals) > 1 else 0:>8.0f}")
a, b = loaded['fusion-baseline'], loaded['fusion-no-security']
common = sorted(set(i for i, _ in a) & set(i for i, _ in b))
if len(common) >= 5:
    da, db = dict(a), dict(b)
    diffs = [db[i] - da[i] for i in common]
    n = len(diffs)
    mean_d = sum(diffs) / n
    var_d = sum((d - mean_d)**2 for d in diffs) / (n - 1)
    se = math.sqrt(var_d / n)
    t = mean_d / se if se > 0 else float('nan')
    sig = '*' if abs(t) > 2.093 else ''
    print(f"\n[paired t]  baseline → no-security  n={n}  Δ={mean_d:+.0f} ms  "
          f"t={t:+.2f}  {sig}")
    print(f"[security cost] median delta = {statistics.median(diffs):+.0f} ms")
PY
