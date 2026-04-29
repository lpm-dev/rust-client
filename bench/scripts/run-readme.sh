#!/bin/bash
# README bench harness — npm / pnpm / bun / greedy-fusion lpm, round-robin
# per outer iter.
#
# Round-robin matches the methodology of `run-5cell.sh` (Phase 56 W4): each
# outer iter runs all four arms back-to-back, so adjacent samples see the
# SAME network state. The per-arm sequential structure in `bench/run.sh`
# favors whichever arm runs last (gets warmest DNS / TLS / CDN — npm goes
# first, lpm goes last, so lpm benefits and bun is biased somewhere
# between). Round-robin removes that bias.
#
# Two modes per run:
#   - clean   (cold install, equal footing — wipes OUTSIDE timer)
#   - full    (cold install, full wipe loop — wipes INSIDE timer)
#
# Each tool wipes its own lockfile + cache per iter. CRITICAL: bun's
# wipe must include BOTH `bun.lock` (modern text format) and `bun.lockb`
# (legacy binary format). Pre-patch `bench/run.sh` only wiped the binary
# format, letting bun reuse the modern lockfile across iters and
# silently turning the median into a "warm-lockfile cold-cache"
# measurement.
#
# Usage:
#   ./bench/scripts/run-readme.sh <n_iters> [<tag>]

set -euo pipefail

N="${1:-20}"
TAG="${2:-readme}"

BIN="${LPM_BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release/lpm-rs}"
FIXTURE="${BENCH_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/bench/fixture-large}"
RESULTS="/tmp/lpm-bench-readme-roundrobin/${TAG}-results"
mkdir -p "$RESULTS"

if [[ ! -x "$BIN" ]]; then echo "ERROR: missing $BIN — build with cargo build --release"; exit 1; fi
if ! command -v bun &>/dev/null; then echo "ERROR: bun not on PATH"; exit 1; fi

# Use a fresh work dir, not the in-tree fixture itself, so the `node_modules`
# / lockfile churn doesn't pollute the committed fixture state.
WORK="/tmp/lpm-bench-readme-roundrobin/work"
rm -rf "$WORK" && mkdir -p "$WORK"
cp "$FIXTURE/package.json" "$WORK/"

clean_lpm() {
    rm -rf "${HOME}/.lpm/cache" "${HOME}/.lpm/store"
    rm -rf "${WORK}/node_modules" "${WORK}/.lpm" \
           "${WORK}/lpm.lock" "${WORK}/lpm.lockb"
}
clean_bun() {
    rm -rf "${HOME}/.bun/install/cache"
    rm -rf "${WORK}/node_modules" "${WORK}/bun.lock" "${WORK}/bun.lockb"
}
clean_npm() {
    npm cache clean --force > /dev/null 2>&1 || true
    rm -rf "${WORK}/node_modules" "${WORK}/package-lock.json"
}
clean_pnpm() {
    pnpm store prune > /dev/null 2>&1 || true
    rm -rf "$(pnpm store path 2>/dev/null)" 2>/dev/null || true
    rm -rf "${WORK}/node_modules" "${WORK}/pnpm-lock.yaml"
}

# Convert nanoseconds-since-process-start to wall-ms; tolerant of macOS BSD date.
now_ms() { python3 -c 'import time;print(int(time.perf_counter_ns()))'; }

run_arm() {
    local mode=$1 arm=$2
    case "$mode/$arm" in
        clean/lpm) clean_lpm; local s=$(now_ms); (cd "$WORK" && "$BIN" install --allow-new --json) > /dev/null 2>&1; local e=$(now_ms);;
        clean/bun) clean_bun; local s=$(now_ms); (cd "$WORK" && bun install --ignore-scripts) > /dev/null 2>&1; local e=$(now_ms);;
        clean/npm) clean_npm; local s=$(now_ms); (cd "$WORK" && npm install --ignore-scripts) > /dev/null 2>&1; local e=$(now_ms);;
        clean/pnpm) clean_pnpm; local s=$(now_ms); (cd "$WORK" && pnpm install --ignore-scripts) > /dev/null 2>&1; local e=$(now_ms);;
        full/lpm) local s=$(now_ms); (rm -rf "${HOME}/.lpm/cache" "${HOME}/.lpm/store" "${WORK}/node_modules" "${WORK}/.lpm" "${WORK}/lpm.lock" "${WORK}/lpm.lockb" 2>/dev/null; cd "$WORK" && "$BIN" install --allow-new --json) > /dev/null 2>&1; local e=$(now_ms);;
        full/bun) local s=$(now_ms); (rm -rf "${HOME}/.bun/install/cache" "${WORK}/node_modules" "${WORK}/bun.lock" "${WORK}/bun.lockb" 2>/dev/null; cd "$WORK" && bun install --ignore-scripts) > /dev/null 2>&1; local e=$(now_ms);;
        full/npm) local s=$(now_ms); (npm cache clean --force > /dev/null 2>&1 || true; rm -rf "${WORK}/node_modules" "${WORK}/package-lock.json" 2>/dev/null; cd "$WORK" && npm install --ignore-scripts) > /dev/null 2>&1; local e=$(now_ms);;
        full/pnpm) local s=$(now_ms); (pnpm store prune > /dev/null 2>&1 || true; rm -rf "$(pnpm store path 2>/dev/null)" 2>/dev/null; rm -rf "${WORK}/node_modules" "${WORK}/pnpm-lock.yaml" 2>/dev/null; cd "$WORK" && pnpm install --ignore-scripts) > /dev/null 2>&1; local e=$(now_ms);;
    esac
    local wall=$(( (e-s) / 1000000 ))
    echo "$wall" > "$RESULTS/${mode}-iter-${i}-${arm}.wall_ms"
    echo "  [${mode}] iter $i $arm = ${wall}ms"
}

echo "[bench] readme round-robin — n=${N} per arm, fixture: $(basename "$FIXTURE")"
echo "[bench] HEAD: $(cd "$(dirname "$0")/../.." && git rev-parse --short HEAD) ($(cd "$(dirname "$0")/../.." && git branch --show-current))"
date

# Methodology:
#   npm + pnpm   — sequential, n iters each. Their bun-lockfile-reuse
#                  bias is N/A; their absolute numbers are reference
#                  points, not the headline lpm-vs-bun comparison.
#   lpm + bun    — strict 2-arm round-robin alternating per outer iter.
#                  Iter 1 runs lpm-then-bun, iter 2 runs bun-then-lpm,
#                  etc. Across n iters each arm visits position-1
#                  (cold) and position-2 (warm-after-other) equally
#                  often, so both see the same mix of network state.
#                  This is the apples-to-apples like-for-like
#                  comparison the bench/scripts W4 baseline uses.

# Order matters. Running npm/pnpm BEFORE the lpm+bun round-robin
# would warm not just the local OS state (DNS, TCP keep-alives) but
# also the npm CDN edge — causing bun's median to drop from ~870ms
# to ~580ms relative to lpm. Run the lpm+bun headline FIRST while
# the CDN is cold, then npm+pnpm afterward.

# ── Cold install, equal footing (wipes OUTSIDE timer) ──────────────
echo "[clean] cold install, equal footing — wipes OUTSIDE timer"

# lpm + bun round-robin (alternating order per iter) — the apples-to-
# apples headline. Each arm visits position-1 and position-2 equally
# often across n iters, so both see the same warm/cold network mix.
for i in $(seq 1 "$N"); do
    if (( i % 2 == 1 )); then arm_order=(lpm bun); else arm_order=(bun lpm); fi
    for arm in "${arm_order[@]}"; do run_arm clean "$arm"; done
done

# npm + pnpm sequential — context numbers. Their ~1.5-7s install times
# dwarf any 200-300ms network-warmth bias, so methodology drift is N/A.
for i in $(seq 1 "$N"); do run_arm clean npm; done
for i in $(seq 1 "$N"); do run_arm clean pnpm; done

# ── Cold install, full wipe loop (wipes INSIDE timer) ──────────────
echo "[full] cold install, full wipe loop — wipes INSIDE timer"

for i in $(seq 1 "$N"); do
    if (( i % 2 == 1 )); then arm_order=(lpm bun); else arm_order=(bun lpm); fi
    for arm in "${arm_order[@]}"; do run_arm full "$arm"; done
done

for i in $(seq 1 "$N"); do run_arm full npm; done
for i in $(seq 1 "$N"); do run_arm full pnpm; done

# ── Summary ────────────────────────────────────────────────────────
echo
echo "=== summary (n=${N}) ==="
python3 - <<EOF
import os, glob, statistics
RES = "$RESULTS"
print(f"\n{'mode':<8} {'arm':<6} {'median':>8} {'mean':>8} {'tmean10':>9} {'stdev':>7}")
print("-" * 50)
def load(prefix, arm):
    files = sorted(glob.glob(os.path.join(RES, f"{prefix}-iter-*-{arm}.wall_ms")))
    return [int(open(f).read().strip()) for f in files]
for mode in ("clean", "full"):
    for arm in ("npm", "pnpm", "bun", "lpm"):
        v = load(mode, arm)
        if not v: continue
        s = sorted(v); n = len(v); trim = max(1, n//10)
        median = statistics.median(v); mean = statistics.mean(v)
        tmean = statistics.mean(s[trim:n-trim]) if n - 2*trim > 0 else mean
        stdev = statistics.stdev(v) if n > 1 else 0
        print(f"{mode:<8} {arm:<6} {int(median):>8} {int(mean):>8} {int(tmean):>9} {int(stdev):>7}")

print()
for mode in ("clean", "full"):
    lpm_v = load(mode, "lpm"); bun_v = load(mode, "bun")
    if lpm_v and bun_v:
        print(f"  [{mode:<5}] lpm/bun ratio = {statistics.median(lpm_v)/statistics.median(bun_v):.2f}x")
EOF

echo
echo "[done] $RESULTS"
date
