#!/bin/bash
# Phase 57 measurement-sprint B — script-policy benchmark methodology.
# Today's "lpm install" never runs scripts (Phase 46 two-phase model);
# `bun install` runs scripts by default. Headline "1.17× bun" therefore
# compares different workloads. This bench measures the delta both ways.
#
# Four cells, n=10 round-robin per outer iter:
#   lpm-default          — `lpm install` (deny, no scripts; today's bench)
#   lpm-yolo-autobuild   — `lpm install --yolo --auto-build` (runs scripts)
#   bun-default          — `bun install` (runs scripts)
#   bun-ignore-scripts   — `bun install --ignore-scripts`
#
# The two like-for-like comparisons:
#   lpm-default          ↔ bun-ignore-scripts   (both skip)
#   lpm-yolo-autobuild   ↔ bun-default          (both run)
#
# Usage: $0 <n_iters> [<tag>]
set -euo pipefail

N="${1:-10}"
TAG="${2:-script-policy}"
BIN="/tmp/lpm-rs-phase56-target/release/lpm-rs"
FIXTURE="/Users/tolga/Documents/Projects/lpm-dev/rust-client/bench/fixture-large"
RESULTS="/tmp/phase56-fusion-bench/${TAG}-results"
mkdir -p "$RESULTS"

[[ -x "$BIN" ]] || { echo "ERROR: binary missing at $BIN"; exit 1; }
command -v bun >/dev/null || { echo "ERROR: bun not on PATH"; exit 1; }

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

echo "[bench] phase57-${TAG} — n=${N} per cell"
date

for i in $(seq 1 "$N"); do
    for arm in lpm-default lpm-yolo-autobuild bun-default bun-ignore-scripts; do
        out="$RESULTS/iter-${i}-${arm}.out"
        err="$RESULTS/iter-${i}-${arm}.err"
        case $arm in
            lpm-default)
                clean_lpm
                export LPM_RESOLVER=greedy
                export LPM_WALKER=stream
                cmd="$BIN install --allow-new"
                ;;
            lpm-yolo-autobuild)
                clean_lpm
                export LPM_RESOLVER=greedy
                export LPM_WALKER=stream
                cmd="$BIN install --allow-new --yolo --auto-build"
                ;;
            bun-default)
                unset LPM_RESOLVER LPM_WALKER
                clean_bun
                cmd="bun install --no-summary --force"
                ;;
            bun-ignore-scripts)
                unset LPM_RESOLVER LPM_WALKER
                clean_bun
                cmd="bun install --no-summary --force --ignore-scripts"
                ;;
        esac
        s=$(python3 -c 'import time;print(time.perf_counter_ns())')
        $cmd > "$out" 2> "$err" || true
        e=$(python3 -c 'import time;print(time.perf_counter_ns())')
        wall_ms=$(( (e-s)/1000000 ))
        echo "$wall_ms" > "$RESULTS/iter-${i}-${arm}.wall_ms"
        echo "  iter $i $arm = ${wall_ms} ms"
    done
done
unset LPM_RESOLVER LPM_WALKER

echo "[done] $RESULTS"
date
echo "=== summary ==="
python3 - "$RESULTS" <<'PY'
import os, sys, glob, statistics, math, re
RES = sys.argv[1]
ARMS = ['lpm-default', 'lpm-yolo-autobuild', 'bun-default', 'bun-ignore-scripts']
def load(arm):
    out = []
    for f in sorted(glob.glob(os.path.join(RES, f'iter-*-{arm}.wall_ms'))):
        try:
            v = int(open(f).read().strip())
            out.append((int(re.search(r'iter-(\d+)-', f).group(1)), v))
        except: pass
    return sorted(out)
loaded = {arm: load(arm) for arm in ARMS}
print(f"  {'arm':<22s} {'n':>4s} {'median':>8s} {'mean':>8s} {'stdev':>8s}")
for arm in ARMS:
    data = loaded[arm]
    if not data: continue
    vals = [v for _, v in data]
    print(f"  {arm:<22s} {len(vals):>4d} {statistics.median(vals):>8.0f} "
          f"{statistics.mean(vals):>8.0f} "
          f"{statistics.stdev(vals) if len(vals) > 1 else 0:>8.0f}")

# Like-for-like comparisons
def paired(a_arm, b_arm):
    a = loaded.get(a_arm, [])
    b = loaded.get(b_arm, [])
    common = sorted(set(i for i, _ in a) & set(i for i, _ in b))
    if len(common) < 5: return None
    da, db = dict(a), dict(b)
    diffs = [db[i] - da[i] for i in common]
    n = len(diffs)
    mean_d = sum(diffs) / n
    var_d = sum((d - mean_d)**2 for d in diffs) / (n - 1)
    se = math.sqrt(var_d / n) if var_d > 0 else 0
    t = mean_d / se if se > 0 else float('nan')
    return n, mean_d, statistics.median(diffs), t

print("\n[like-for-like]  (script-policy controlled)")
for a, b in [('lpm-default', 'bun-ignore-scripts'),
             ('lpm-yolo-autobuild', 'bun-default')]:
    res = paired(a, b)
    if res is None:
        print(f"  {a:<22s} → {b:<22s}  insufficient data")
        continue
    n, mean_d, med_d, t = res
    sig = ' *' if abs(t) > 2.262 else ''  # n=10 critical t
    print(f"  {a:<22s} → {b:<22s}  n={n}  Δmed={med_d:+.0f}  Δmean={mean_d:+.0f}  t={t:+.2f}{sig}")

print("\n[script-policy delta]")
for tool, deny_arm, allow_arm in [
    ('lpm', 'lpm-default', 'lpm-yolo-autobuild'),
    ('bun', 'bun-ignore-scripts', 'bun-default'),
]:
    res = paired(deny_arm, allow_arm)
    if res is None: continue
    n, mean_d, med_d, t = res
    sig = ' *' if abs(t) > 2.262 else ''
    print(f"  {tool:<5s} default(deny) → allow(scripts run)  n={n}  Δmed={med_d:+.0f}  Δmean={mean_d:+.0f}  t={t:+.2f}{sig}")
PY
