#!/bin/bash
# Phase 66 Phase 4f dual-gate bench harness.
#
# Pairs warm-install measurements for the two `LinkerMode` candidates
# in the SAME outer iteration so the per-iter network/disk state is
# identical between cells. The flip-or-hold decision per preplan
# §Phase 4f rests on:
#
#   GATE 1 (absolute UX):       hoisted warm-install median ≤ 200 ms.
#   GATE 2 (no-everyday-regression): hoisted warm-install median is
#                                    no more than 30 ms slower than
#                                    isolated in the same paired run.
#
# Both must pass for the default flip to ship. Either failing → hold
# the flip and surface the bench data so the user can decide whether
# to investigate v2 perf gaps further or accept the current shape as
# the post-4f reality.
#
# ## Methodology (matches README footnote 3 + preplan §6.5)
#
#   - `rm -rf node_modules` only between iters.
#   - lpm.lock + lpm.lockb + ~/.lpm/store + ~/.lpm/cache + <project>/.lpm
#     ALL survive, so each iter measures pure project-side symlink
#     reconstruction against a populated v2 store.
#   - First-iter warm-up writes the lockfile + populates the store.
#     Discarded from the median.
#   - Round-robin per outer iter: each pair (isolated, hoisted) runs
#     back-to-back so adjacent samples see identical state.
#
# ## Usage
#
#   ./bench/scripts/run-4f-gate.sh <n_iters> [<tag>]
#
#   N defaults to 20 (matches preplan §6.5 acceptance n).
#
set -euo pipefail

N="${1:-20}"
TAG="${2:-4f-gate}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${LPM_BIN:-$REPO_ROOT/target/release/lpm-rs}"
FIXTURE="${BENCH_PROJECT_DIR:-$REPO_ROOT/bench/fixture-large}"
RESULTS="/tmp/lpm-bench-4f-gate/${TAG}-results"
mkdir -p "$RESULTS"

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary missing at $BIN — wait for cargo build --release"
    exit 1
fi

WORK="/tmp/lpm-bench-4f-gate/work"
rm -rf "$WORK" && mkdir -p "$WORK"
cp "$FIXTURE/package.json" "$WORK/"

echo "[bench] phase66 4f gate — n=${N} per cell"
echo "[bench] fixture: $FIXTURE"
echo "[bench] binary:  $BIN"
date

# Warm-up pass: cold install once per cell to populate the lockfile +
# the global v2 store. Both cells share the same store/cache so the
# second warm-up just reuses what the first one populated.
warm_up() {
    local linker="$1"
    rm -rf "$WORK/node_modules" "$WORK/lpm.lock" "$WORK/lpm.lockb" "$WORK/.lpm"
    cd "$WORK"
    LPM_LINKER="$linker" "$BIN" install --allow-new --no-skills > /dev/null 2>&1
}

# Drop just node_modules between iters; everything else (lockfile,
# `<project>/.lpm/`, `~/.lpm/store`, `~/.lpm/cache`) survives so each
# iter measures the warm-install path the README footnote 3 anchors on.
warm_iter_ms() {
    local linker="$1"
    rm -rf "$WORK/node_modules"
    local start_ns
    start_ns=$(date +%s%N)
    LPM_LINKER="$linker" "$BIN" install --allow-new --no-skills > /dev/null 2>&1
    local end_ns
    end_ns=$(date +%s%N)
    echo $(( (end_ns - start_ns) / 1000000 ))
}

declare -a ISOLATED_MS
declare -a HOISTED_MS

# Warm both linkers' starting state. Ordered isolated → hoisted so the
# hoisted warm-up writes its own lockfile shape if it differs (it
# shouldn't under v2 — both modes produce the same project node_modules
# symlinks pointing into the global store — but warming both is cheap
# and removes one source of first-iter noise).
warm_up isolated
warm_up hoisted

for i in $(seq 1 "$N"); do
    iso_ms=$(warm_iter_ms isolated)
    hoi_ms=$(warm_iter_ms hoisted)
    ISOLATED_MS+=("$iso_ms")
    HOISTED_MS+=("$hoi_ms")
    printf "  iter %2d: iso=%4dms  hoi=%4dms  delta=%+5dms\n" \
        "$i" "$iso_ms" "$hoi_ms" "$((hoi_ms - iso_ms))"
done

# Median helper — feed numbers space-separated.
median() {
    local nums=($(echo "$@" | tr ' ' '\n' | sort -n))
    local n=${#nums[@]}
    local mid=$((n / 2))
    if (( n % 2 == 1 )); then
        echo "${nums[$mid]}"
    else
        echo $(( (nums[mid-1] + nums[mid]) / 2 ))
    fi
}

ISOLATED_MED=$(median "${ISOLATED_MS[@]}")
HOISTED_MED=$(median "${HOISTED_MS[@]}")
DELTA=$((HOISTED_MED - ISOLATED_MED))

echo
echo "========================================"
echo " PHASE 66 PHASE 4F DUAL-GATE RESULTS"
echo "========================================"
printf " isolated median: %4d ms\n" "$ISOLATED_MED"
printf " hoisted  median: %4d ms\n" "$HOISTED_MED"
printf " hoisted - iso  : %+4d ms\n" "$DELTA"
echo

# Persist raw samples for triage.
{
    echo "iter,isolated_ms,hoisted_ms"
    for i in "${!ISOLATED_MS[@]}"; do
        echo "$((i+1)),${ISOLATED_MS[$i]},${HOISTED_MS[$i]}"
    done
} > "$RESULTS/samples.csv"
echo " raw samples → $RESULTS/samples.csv"
echo

GATE1_PASS="?"
GATE2_PASS="?"
if (( HOISTED_MED <= 200 )); then
    GATE1_PASS="✓"
else
    GATE1_PASS="✗"
fi
if (( DELTA <= 30 )); then
    GATE2_PASS="✓"
else
    GATE2_PASS="✗"
fi

echo " GATE 1 (hoisted ≤ 200 ms absolute):              $GATE1_PASS"
echo " GATE 2 (hoisted ≤ isolated + 30 ms paired):      $GATE2_PASS"
echo
if [[ "$GATE1_PASS" == "✓" && "$GATE2_PASS" == "✓" ]]; then
    echo " VERDICT: BOTH GATES PASS — flip the linker default to hoisted."
    exit 0
else
    echo " VERDICT: HOLD — at least one gate failed."
    exit 1
fi
