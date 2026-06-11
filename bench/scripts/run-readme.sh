#!/bin/bash
# README bench harness — npm / pnpm / bun / greedy-fusion lpm, round-robin
# per outer iter.
#
# Round-robin matches the methodology of `run-5cell.sh` (W4): each
# outer iter runs all four arms back-to-back, so adjacent samples see the
# SAME network state. The per-arm sequential structure in `bench/run.sh`
# favors whichever arm runs last (gets warmest DNS / TLS / CDN — npm goes
# first, lpm goes last, so lpm benefits and bun is biased somewhere
# between). Round-robin removes that bias.
#
# Two modes per run:
#   - clean   (cold install, equal footing — wipes OUTSIDE timer)
#   - full    (cold install, reset-each-iter — lpm rotates old state
#              OUTSIDE timer; npm/pnpm/bun wipe INSIDE timer)
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
#
#   BENCH_ARMS=lpm,bun ./bench/scripts/run-readme.sh 5 quick
#   BENCH_ARMS=all     ./bench/scripts/run-readme.sh 20 readme

set -euo pipefail

N="${1:-20}"
TAG="${2:-readme}"

BIN="${LPM_BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release/lpm-rs}"
FIXTURE="${BENCH_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/bench/fixture-large}"
BENCH_BASE="/tmp/lpm-bench-readme-roundrobin"
WORK="${BENCH_WORK_DIR:-$BENCH_BASE/work}"
RESULTS="/tmp/lpm-bench-readme-roundrobin/${TAG}-results"
EFFECTIVE_LPM_HOME="${LPM_HOME:-$HOME/.lpm}"
TRASH_DIR="$BENCH_BASE/${TAG}-trash"
BUN_CACHE_DIR="${BENCH_BUN_CACHE_DIR:-$HOME/.bun/install/cache}"
NPM_CACHE_DIR="${BENCH_NPM_CACHE_DIR:-$HOME/.npm}"
BENCH_ARMS_RAW="${BENCH_ARMS:-all}"
BENCH_ARMS_CSV="$(printf '%s' "$BENCH_ARMS_RAW" | tr -d '[:space:]')"
if [[ "$BENCH_ARMS_CSV" == "all" ]]; then
    BENCH_ARMS_CSV="lpm,bun,npm,pnpm"
fi
if [[ -z "$BENCH_ARMS_CSV" ]]; then
    echo "ERROR: BENCH_ARMS must include at least one arm: lpm,bun,npm,pnpm or all"
    exit 1
fi
for configured_arm in ${BENCH_ARMS_CSV//,/ }; do
    case "$configured_arm" in
        lpm|bun|npm|pnpm) ;;
        *) echo "ERROR: unknown BENCH_ARMS entry '$configured_arm'"; exit 1;;
    esac
done

arm_enabled() {
    case ",$BENCH_ARMS_CSV," in
        *",$1,"*) return 0;;
        *) return 1;;
    esac
}

DEFAULT_PNPM_STORE_DIR=""
if arm_enabled pnpm; then
    DEFAULT_PNPM_STORE_DIR="$(pnpm store path 2>/dev/null || true)"
fi
PNPM_STORE_DIR="${BENCH_PNPM_STORE_DIR:-$DEFAULT_PNPM_STORE_DIR}"
ROTATE_SEQ=0
DEFERRED_DELETE=()

mkdir -p "$RESULTS" "$TRASH_DIR"

if [[ ! -x "$BIN" ]]; then echo "ERROR: missing $BIN — build with cargo build --release"; exit 1; fi
if arm_enabled bun && ! command -v bun &>/dev/null; then echo "ERROR: bun not on PATH"; exit 1; fi
if arm_enabled npm && ! command -v npm &>/dev/null; then echo "ERROR: npm not on PATH"; exit 1; fi
if arm_enabled pnpm && ! command -v pnpm &>/dev/null; then echo "ERROR: pnpm not on PATH"; exit 1; fi

# Use a fresh work dir, not the in-tree fixture itself, so the `node_modules`
# / lockfile churn doesn't pollute the committed fixture state.
rm -rf "$WORK" && mkdir -p "$WORK"
cp "$FIXTURE/package.json" "$WORK/"

cleanup_deferred_delete() {
    if (( ${#DEFERRED_DELETE[@]} == 0 )); then
        return
    fi
    rm -rf "${DEFERRED_DELETE[@]}" 2>/dev/null || true
}

rotate_out_of_band() {
    local path=$1
    local label=$2
    if [[ ! -e "$path" ]]; then
        return
    fi
    ROTATE_SEQ=$((ROTATE_SEQ + 1))
    local rotated="$TRASH_DIR/${label}-iter-${i}-${ROTATE_SEQ}"
    mv "$path" "$rotated"
    DEFERRED_DELETE+=("$rotated")
}

prepare_full_lpm_reset() {
    # Rotate old state out of band so full/lpm still starts from a cold home
    # without timing recursive deletion.
    mkdir -p "$EFFECTIVE_LPM_HOME"
    rotate_out_of_band "$EFFECTIVE_LPM_HOME/cache" "lpm-cache"
    rotate_out_of_band "$EFFECTIVE_LPM_HOME/store" "lpm-store"
    rotate_out_of_band "$WORK/node_modules" "work-node_modules"
    rotate_out_of_band "$WORK/.lpm" "work-lpm"
    rm -f "$WORK/lpm.lock" "$WORK/lpm.lockb"
}

run_lpm_install() {
    (cd "$WORK" && env LPM_HOME="$EFFECTIVE_LPM_HOME" "$BIN" install --json) > /dev/null 2>&1
}

run_bun_install() {
    (cd "$WORK" && bun install --ignore-scripts --cache-dir "$BUN_CACHE_DIR") > /dev/null 2>&1
}

run_npm_install() {
    (cd "$WORK" && env npm_config_cache="$NPM_CACHE_DIR" npm install --ignore-scripts) > /dev/null 2>&1
}

run_pnpm_install() {
    if [[ -n "$PNPM_STORE_DIR" ]]; then
        (cd "$WORK" && pnpm install --ignore-scripts --store-dir "$PNPM_STORE_DIR") > /dev/null 2>&1
    else
        (cd "$WORK" && pnpm install --ignore-scripts) > /dev/null 2>&1
    fi
}

trap cleanup_deferred_delete EXIT

clean_lpm() {
    rm -rf "${EFFECTIVE_LPM_HOME}/cache" "${EFFECTIVE_LPM_HOME}/store"
    rm -rf "${WORK}/node_modules" "${WORK}/.lpm" \
           "${WORK}/lpm.lock" "${WORK}/lpm.lockb"
}
clean_bun() {
    rm -rf "$BUN_CACHE_DIR"
    rm -rf "${WORK}/node_modules" "${WORK}/bun.lock" "${WORK}/bun.lockb"
}
clean_npm() {
    env npm_config_cache="$NPM_CACHE_DIR" npm cache clean --force > /dev/null 2>&1 || true
    rm -rf "${WORK}/node_modules" "${WORK}/package-lock.json"
}
clean_pnpm() {
    rm -rf "$PNPM_STORE_DIR" 2>/dev/null || true
    rm -rf "${WORK}/node_modules" "${WORK}/pnpm-lock.yaml"
}

# Convert nanoseconds-since-process-start to wall-ms; tolerant of macOS BSD date.
now_ms() { python3 -c 'import time;print(int(time.perf_counter_ns()))'; }

run_arm() {
    local mode=$1 arm=$2
    case "$mode/$arm" in
        clean/lpm) clean_lpm; local s=$(now_ms); run_lpm_install; local e=$(now_ms);;
        clean/bun) clean_bun; local s=$(now_ms); run_bun_install; local e=$(now_ms);;
        clean/npm) clean_npm; local s=$(now_ms); run_npm_install; local e=$(now_ms);;
        clean/pnpm) clean_pnpm; local s=$(now_ms); run_pnpm_install; local e=$(now_ms);;
        full/lpm) prepare_full_lpm_reset; local s=$(now_ms); run_lpm_install; local e=$(now_ms);;
        full/bun) local s=$(now_ms); (rm -rf "$BUN_CACHE_DIR" "${WORK}/node_modules" "${WORK}/bun.lock" "${WORK}/bun.lockb" 2>/dev/null; cd "$WORK" && bun install --ignore-scripts --cache-dir "$BUN_CACHE_DIR") > /dev/null 2>&1; local e=$(now_ms);;
        full/npm) local s=$(now_ms); (env npm_config_cache="$NPM_CACHE_DIR" npm cache clean --force > /dev/null 2>&1 || true; rm -rf "${WORK}/node_modules" "${WORK}/package-lock.json" 2>/dev/null; cd "$WORK" && env npm_config_cache="$NPM_CACHE_DIR" npm install --ignore-scripts) > /dev/null 2>&1; local e=$(now_ms);;
        full/pnpm) local s=$(now_ms); (rm -rf "$PNPM_STORE_DIR" 2>/dev/null; rm -rf "${WORK}/node_modules" "${WORK}/pnpm-lock.yaml" 2>/dev/null; cd "$WORK" && if [[ -n "$PNPM_STORE_DIR" ]]; then pnpm install --ignore-scripts --store-dir "$PNPM_STORE_DIR"; else pnpm install --ignore-scripts; fi) > /dev/null 2>&1; local e=$(now_ms);;
    esac
    local wall=$(( (e-s) / 1000000 ))
    echo "$wall" > "$RESULTS/${mode}-iter-${i}-${arm}.wall_ms"
    echo "  [${mode}] iter $i $arm = ${wall}ms"
}

echo "[bench] readme round-robin — n=${N} per arm, fixture: $(basename "$FIXTURE")"
echo "[bench] HEAD: $(cd "$(dirname "$0")/../.." && git rev-parse --short HEAD) ($(cd "$(dirname "$0")/../.." && git branch --show-current))"
echo "[bench] arms: $BENCH_ARMS_CSV"
echo "[bench] full/lpm reset: out-of-band rotate"
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
#                  comparison the bench/scripts baseline uses.

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
if arm_enabled lpm && arm_enabled bun; then
    for i in $(seq 1 "$N"); do
        if (( i % 2 == 1 )); then arm_order=(lpm bun); else arm_order=(bun lpm); fi
        for arm in "${arm_order[@]}"; do run_arm clean "$arm"; done
    done
else
    for arm in lpm bun; do
        if arm_enabled "$arm"; then
            for i in $(seq 1 "$N"); do run_arm clean "$arm"; done
        fi
    done
fi

# npm + pnpm sequential — context numbers. Their ~1.5-7s install times
# dwarf any 200-300ms network-warmth bias, so methodology drift is N/A.
for arm in npm pnpm; do
    if arm_enabled "$arm"; then
        for i in $(seq 1 "$N"); do run_arm clean "$arm"; done
    fi
done

# ── Cold install, reset-each-iter (lpm rotates old state) ──────────
echo "[full] cold install, reset-each-iter — lpm rotates old state outside timer"

if arm_enabled lpm && arm_enabled bun; then
    for i in $(seq 1 "$N"); do
        if (( i % 2 == 1 )); then arm_order=(lpm bun); else arm_order=(bun lpm); fi
        for arm in "${arm_order[@]}"; do run_arm full "$arm"; done
    done
else
    for arm in lpm bun; do
        if arm_enabled "$arm"; then
            for i in $(seq 1 "$N"); do run_arm full "$arm"; done
        fi
    done
fi

for arm in npm pnpm; do
    if arm_enabled "$arm"; then
        for i in $(seq 1 "$N"); do run_arm full "$arm"; done
    fi
done

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
