#!/bin/bash
# README bench harness — npm / pnpm / bun / greedy-fusion lpm, round-robin
# per outer iter. Equal-footing cold install is the primary/default mode.
#
# Round-robin matches the methodology of `run-5cell.sh` (W4): each
# outer iter runs all four arms back-to-back, so adjacent samples see the
# SAME network state. The per-arm sequential structure in `bench/run.sh`
# favors whichever arm runs last (gets warmest DNS / TLS / CDN — npm goes
# first, lpm goes last, so lpm benefits and bun is biased somewhere
# between). Round-robin removes that bias.
#
# Modes:
#   - clean   (default; cold install, equal footing — wipes OUTSIDE timer)
#   - full    (opt-in; cold install, reset-each-iter — lpm rotates old
#              state OUTSIDE timer; npm/pnpm/bun wipe INSIDE timer)
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
#   BENCH_ARMS=npm,pnpm,bun,lpm,lpm-proxy-h3 ./bench/scripts/run-readme.sh 5 proxy-h3
#   BENCH_INCLUDE_RESET_EACH_ITER=1 ./bench/scripts/run-readme.sh 5 reset-check
#   BENCH_LPM_SECURITY_MODE=allow-new ./bench/scripts/run-readme.sh 5 speed-compare

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
BENCH_LPM_SECURITY_MODE="${BENCH_LPM_SECURITY_MODE:-default}"
LPM_INSTALL_SECURITY_ARG=""
case "$BENCH_LPM_SECURITY_MODE" in
    default|secure) BENCH_LPM_SECURITY_LABEL="default minimumReleaseAge";;
    allow-new|cooldown-bypass)
        BENCH_LPM_SECURITY_LABEL="--allow-new cooldown bypass"
        LPM_INSTALL_SECURITY_ARG="--allow-new"
        ;;
    *)
        echo "ERROR: BENCH_LPM_SECURITY_MODE must be default or allow-new"
        exit 1
        ;;
esac
if [[ "$BENCH_ARMS_CSV" == "all" ]]; then
    BENCH_ARMS_CSV="lpm,bun,npm,pnpm"
fi
if [[ -z "$BENCH_ARMS_CSV" ]]; then
    echo "ERROR: BENCH_ARMS must include at least one arm: lpm,bun,npm,pnpm,lpm-proxy-h3 or all"
    exit 1
fi
BENCH_ARM_LIST=()
for configured_arm in ${BENCH_ARMS_CSV//,/ }; do
    case "$configured_arm" in
        lpm|bun|npm|pnpm|lpm-proxy-h3) ;;
        *) echo "ERROR: unknown BENCH_ARMS entry '$configured_arm'"; exit 1;;
    esac
    BENCH_ARM_LIST+=("$configured_arm")
done

BENCH_INCLUDE_RESET_EACH_ITER="${BENCH_INCLUDE_RESET_EACH_ITER:-0}"
BENCH_MODES=(clean)
case "$BENCH_INCLUDE_RESET_EACH_ITER" in
    1|true|TRUE|yes|YES|on|ON) BENCH_MODES+=(full);;
    0|false|FALSE|no|NO|off|OFF|"") ;;
    *) echo "ERROR: BENCH_INCLUDE_RESET_EACH_ITER must be 0/1, true/false, yes/no, or on/off"; exit 1;;
esac
BENCH_MODES_CSV="$(IFS=,; printf '%s' "${BENCH_MODES[*]}")"
if (( ${#BENCH_ARM_LIST[@]} == 0 )); then
    echo "ERROR: BENCH_ARMS must include at least one arm"
    exit 1
fi

for required_tool in "${BENCH_ARM_LIST[@]}"; do
    case "$required_tool" in
        bun) if ! command -v bun &>/dev/null; then echo "ERROR: bun not on PATH"; exit 1; fi;;
        npm) if ! command -v npm &>/dev/null; then echo "ERROR: npm not on PATH"; exit 1; fi;;
        pnpm) if ! command -v pnpm &>/dev/null; then echo "ERROR: pnpm not on PATH"; exit 1; fi;;
        lpm|lpm-proxy-h3) ;;
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
    local out="$RESULTS/last-lpm-output.json"
    if [[ -n "$LPM_INSTALL_SECURITY_ARG" ]]; then
        (cd "$WORK" && env LPM_HOME="$EFFECTIVE_LPM_HOME" "$BIN" install "$LPM_INSTALL_SECURITY_ARG" --json) > "$out"
    else
        (cd "$WORK" && env LPM_HOME="$EFFECTIVE_LPM_HOME" "$BIN" install --json) > "$out"
    fi || { cat "$out" >&2; return 1; }
}

run_lpm_proxy_h3_install() {
    local out="$RESULTS/last-lpm-proxy-h3-output.json"
    if [[ -n "$LPM_INSTALL_SECURITY_ARG" ]]; then
        (cd "$WORK" && env LPM_HOME="$EFFECTIVE_LPM_HOME" LPM_NPM_ROUTE=proxy LPM_HTTP=h3-worker "$BIN" install "$LPM_INSTALL_SECURITY_ARG" --json) > "$out"
    else
        (cd "$WORK" && env LPM_HOME="$EFFECTIVE_LPM_HOME" LPM_NPM_ROUTE=proxy LPM_HTTP=h3-worker "$BIN" install --json) > "$out"
    fi || { cat "$out" >&2; return 1; }
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
        clean/lpm-proxy-h3) clean_lpm; local s=$(now_ms); run_lpm_proxy_h3_install; local e=$(now_ms);;
        clean/bun) clean_bun; local s=$(now_ms); run_bun_install; local e=$(now_ms);;
        clean/npm) clean_npm; local s=$(now_ms); run_npm_install; local e=$(now_ms);;
        clean/pnpm) clean_pnpm; local s=$(now_ms); run_pnpm_install; local e=$(now_ms);;
        full/lpm) prepare_full_lpm_reset; local s=$(now_ms); run_lpm_install; local e=$(now_ms);;
        full/lpm-proxy-h3) prepare_full_lpm_reset; local s=$(now_ms); run_lpm_proxy_h3_install; local e=$(now_ms);;
        full/bun) local s=$(now_ms); (rm -rf "$BUN_CACHE_DIR" "${WORK}/node_modules" "${WORK}/bun.lock" "${WORK}/bun.lockb" 2>/dev/null; cd "$WORK" && bun install --ignore-scripts --cache-dir "$BUN_CACHE_DIR") > /dev/null 2>&1; local e=$(now_ms);;
        full/npm) local s=$(now_ms); (env npm_config_cache="$NPM_CACHE_DIR" npm cache clean --force > /dev/null 2>&1 || true; rm -rf "${WORK}/node_modules" "${WORK}/package-lock.json" 2>/dev/null; cd "$WORK" && env npm_config_cache="$NPM_CACHE_DIR" npm install --ignore-scripts) > /dev/null 2>&1; local e=$(now_ms);;
        full/pnpm) local s=$(now_ms); (rm -rf "$PNPM_STORE_DIR" 2>/dev/null; rm -rf "${WORK}/node_modules" "${WORK}/pnpm-lock.yaml" 2>/dev/null; cd "$WORK" && if [[ -n "$PNPM_STORE_DIR" ]]; then pnpm install --ignore-scripts --store-dir "$PNPM_STORE_DIR"; else pnpm install --ignore-scripts; fi) > /dev/null 2>&1; local e=$(now_ms);;
    esac
    local wall=$(( (e-s) / 1000000 ))
    echo "$wall" > "$RESULTS/${mode}-iter-${i}-${arm}.wall_ms"
    echo "  [${mode}] iter $i $arm = ${wall}ms"
}

run_mode_round_robin() {
    local mode=$1 title=$2
    echo "[$mode] $title"
    local arm_count=${#BENCH_ARM_LIST[@]}
    for i in $(seq 1 "$N"); do
        local offset=$(( (i - 1) % arm_count ))
        for (( step = 0; step < arm_count; step++ )); do
            local arm="${BENCH_ARM_LIST[$(( (offset + step) % arm_count ))]}"
            run_arm "$mode" "$arm"
        done
    done
}

echo "[bench] readme round-robin — n=${N} per arm, fixture: $(basename "$FIXTURE")"
echo "[bench] HEAD: $(cd "$(dirname "$0")/../.." && git rev-parse --short HEAD) ($(cd "$(dirname "$0")/../.." && git branch --show-current))"
echo "[bench] arms: $BENCH_ARMS_CSV"
echo "[bench] modes: $BENCH_MODES_CSV"
echo "[bench] lpm security: $BENCH_LPM_SECURITY_LABEL"
if arm_enabled lpm-proxy-h3; then
    echo "[bench] lpm-proxy-h3: LPM_NPM_ROUTE=proxy LPM_HTTP=h3-worker"
fi
if [[ " $BENCH_MODES_CSV " == *full* ]]; then
    echo "[bench] full/lpm reset: out-of-band rotate"
fi
date

# Methodology:
#   All configured arms run in one round-robin per outer iter. Iter 1 starts
#   at arm 1, iter 2 starts at arm 2, and so on. Across enough iterations,
#   each arm sees the same mix of early/late CDN, DNS, TLS, and OS-cache
#   state while each tool's own cache/lockfile cleanup stays outside the
#   clean-mode timer.

# ── Cold install, equal footing (wipes OUTSIDE timer) ──────────────
run_mode_round_robin clean "cold install, equal footing — wipes OUTSIDE timer"

# ── Cold install, reset-each-iter (lpm rotates old state) ──────────
if [[ " $BENCH_MODES_CSV " == *full* ]]; then
    run_mode_round_robin full "cold install, reset-each-iter — lpm rotates old state outside timer"
fi

# ── Summary ────────────────────────────────────────────────────────
echo
echo "=== summary (n=${N}) ==="
python3 - <<EOF
import os, glob, statistics
RES = "$RESULTS"
MODES = "$BENCH_MODES_CSV".split(",")
ARMS = "$BENCH_ARMS_CSV".split(",")
arm_width = max([6] + [len(arm) for arm in ARMS])
print(f"\n{'mode':<8} {'arm':<{arm_width}} {'median':>8} {'mean':>8} {'tmean10':>9} {'stdev':>7}")
print("-" * (44 + arm_width))
def load(prefix, arm):
    files = sorted(glob.glob(os.path.join(RES, f"{prefix}-iter-*-{arm}.wall_ms")))
    return [int(open(f).read().strip()) for f in files]
for mode in MODES:
    for arm in ARMS:
        v = load(mode, arm)
        if not v: continue
        s = sorted(v); n = len(v); trim = max(1, n//10)
        median = statistics.median(v); mean = statistics.mean(v)
        tmean = statistics.mean(s[trim:n-trim]) if n - 2*trim > 0 else mean
        stdev = statistics.stdev(v) if n > 1 else 0
        print(f"{mode:<8} {arm:<{arm_width}} {int(median):>8} {int(mean):>8} {int(tmean):>9} {int(stdev):>7}")

print()
for mode in MODES:
    lpm_v = load(mode, "lpm"); bun_v = load(mode, "bun")
    if lpm_v and bun_v:
        print(f"  [{mode:<5}] lpm/bun ratio = {statistics.median(lpm_v)/statistics.median(bun_v):.2f}x")
    proxy_v = load(mode, "lpm-proxy-h3")
    if proxy_v and bun_v:
        print(f"  [{mode:<5}] lpm-proxy-h3/bun ratio = {statistics.median(proxy_v)/statistics.median(bun_v):.2f}x")
    if proxy_v and lpm_v:
        print(f"  [{mode:<5}] lpm-proxy-h3/lpm ratio = {statistics.median(proxy_v)/statistics.median(lpm_v):.2f}x")
EOF

echo
echo "[done] $RESULTS"
date
