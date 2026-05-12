#!/bin/bash
# Phase 66 confidence-followup §1b — run the generated top-N fixtures
# in parallel and emit a consolidated summary. Wrapper around
# bench/audit-fixtures/run-audit.sh; reuses the existing single-fixture
# harness so the smoke contract stays consistent across audit + top-N
# tiers.
#
# Parallelism: defaults to 4 concurrent fixtures. Override with
# LPM_TOP_NPM_PARALLEL=N. Each parallel slot needs ~30 MB of network
# bandwidth + a fresh `~/.lpm/cache` / `~/.lpm/store` per install,
# which run-audit.sh resets between modes — meaning real-world
# parallelism can stomp on the shared cache. Per-slot work dirs come
# from RUNNER_TEMP / LPM_AUDIT_WORK_BASE; we set per-slot LPM_HOME via
# the SLOT_INDEX env so cache/store don't collide.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
DEST_ROOT="$HERE/../audit-fixtures/top-npm"
RESULTS_DIR="$HERE/../audit-fixtures/results"
PARALLEL="${LPM_TOP_NPM_PARALLEL:-4}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq not on PATH" >&2
    exit 2
fi

# Generate (idempotent — fast).
bash "$HERE/generate.sh"

# Optional substring filter: `./run-all.sh react` runs only fixtures
# whose name contains "react". Useful for CI debugging.
FILTER="${1:-}"

FIXTURES=()
while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    if [[ -n "$FILTER" && "$d" != *"$FILTER"* ]]; then
        continue
    fi
    FIXTURES+=("top-npm/$(basename "$d")")
done < <(find "$DEST_ROOT" -mindepth 1 -maxdepth 1 -type d | sort)

date
echo "[top-npm] running ${#FIXTURES[@]} fixture(s) with parallelism $PARALLEL"
echo

# Per-process LPM_HOME so concurrent installs don't stomp on each
# other's `~/.lpm/cache` / `~/.lpm/store` (run-audit.sh wipes those
# between modes). LPM honors `LPM_HOME` as the root for cache + store.
#
# Pre-fix this used a mod-PARALLEL slot index baked into the fixture
# line ("<idx> <fixture>", `idx = i % PARALLEL`) and assumed xargs
# would tie slot → worker process. It doesn't: xargs -P N -L 1 just
# spawns one process per line; line ordering is preserved, slot
# ordering isn't. When fixture i+PARALLEL's bash invocation started
# before fixture i's finished — easy whenever fixture i was slow
# (large tarball, slow npm metadata) — both ran concurrently with the
# same LPM_HOME, the late starter's `rm -rf "$slot_home"` wiped the
# early starter's in-progress store, and the early starter exited
# non-zero on the next store read. The collision manifests as
# nondeterministic asymmetric outcomes (~15-20 per CI run, set
# differs each run; same suite goes ASYMMETRIC: 0 under PARALLEL=1).
#
# Fix: drop the slot abstraction entirely and key the home off `$$`
# (the per-invocation PID). Every concurrent `run_one` call lands in
# a distinct directory by construction, regardless of how xargs
# schedules the workers. An EXIT trap removes the home so /tmp
# doesn't accumulate ~50 MB × N fixtures of store data across runs.
run_one() {
    local fixture="$1"
    local slot_home work_base
    slot_home="${LPM_AUDIT_WORK_BASE:-${RUNNER_TEMP:-/tmp}}/lpm-top-npm-home-$$"
    work_base="${LPM_AUDIT_WORK_BASE:-${RUNNER_TEMP:-/tmp}/lpm-top-npm-work-$$}"
    rm -rf "$slot_home" "$work_base"
    mkdir -p "$slot_home" "$work_base"
    # shellcheck disable=SC2064  # expansion at trap-install time is intentional
    trap "rm -rf '$slot_home' '$work_base'" EXIT

    LPM_HOME="$slot_home" \
    LPM_AUDIT_WORK_BASE="$work_base" \
    bash "$HERE/../audit-fixtures/run-audit.sh" "$fixture" \
        > "$slot_home/last.log" 2>&1 || true

    # Echo a one-line status to the parent.
    local fname
    fname="$(echo "$fixture" | tr '/' '-')"
    local iso hst
    iso=$(ls -t "$RESULTS_DIR/$fname-isolated-"*.json 2>/dev/null | head -1)
    hst=$(ls -t "$RESULTS_DIR/$fname-hoisted-"*.json 2>/dev/null | head -1)
    local iv hv
    iv=$([[ -f "$iso" ]] && python3 -c "import json;print(json.load(open('$iso'))['verdict'])" || echo "?")
    hv=$([[ -f "$hst" ]] && python3 -c "import json;print(json.load(open('$hst'))['verdict'])" || echo "?")
    printf "%-40s %s/%s\n" "$fixture" "$iv" "$hv"
}

export -f run_one
export HERE RESULTS_DIR

# One xargs line per fixture. Each `bash -c` invocation gets its own
# PID and therefore its own LPM_HOME / work base — see run_one.
printf '%s\n' "${FIXTURES[@]}" | xargs -P "$PARALLEL" -L 1 bash -c 'run_one "$0"'

echo
echo
echo "############################################"
echo "##  TOP-N NPM AUDIT SUMMARY"
echo "############################################"
printf "%-40s %s\n" "FIXTURE" "ISOLATED/HOISTED"
echo "------------------------------------------------------------------"
pass=0; mixed=0; sym_fail=0; unknown=0
asymmetric_list=()
for f in "${FIXTURES[@]}"; do
    fname="$(echo "$f" | tr '/' '-')"
    iso=$(ls -t "$RESULTS_DIR/$fname-isolated-"*.json 2>/dev/null | head -1)
    hst=$(ls -t "$RESULTS_DIR/$fname-hoisted-"*.json 2>/dev/null | head -1)
    iv=$([[ -f "$iso" ]] && python3 -c "import json;print(json.load(open('$iso'))['verdict'])" || echo "?")
    hv=$([[ -f "$hst" ]] && python3 -c "import json;print(json.load(open('$hst'))['verdict'])" || echo "?")
    printf "%-40s %s/%s\n" "$f" "$iv" "$hv"
    case "${iv}/${hv}" in
        "PASS/PASS") pass=$((pass+1)) ;;
        "FAIL/FAIL") sym_fail=$((sym_fail+1)) ;;
        "PASS/FAIL"|"FAIL/PASS") mixed=$((mixed+1)); asymmetric_list+=("$f: $iv/$hv") ;;
        *) unknown=$((unknown+1)) ;;
    esac
done
echo "------------------------------------------------------------------"
printf "PASS both: %d   ASYMMETRIC: %d   FAIL both: %d   unknown: %d   total: %d\n" \
    "$pass" "$mixed" "$sym_fail" "$unknown" "${#FIXTURES[@]}"

if [[ ${#asymmetric_list[@]} -gt 0 ]]; then
    echo
    echo "Asymmetric outcomes (isolated/hoisted, either direction is a regression):"
    for a in "${asymmetric_list[@]}"; do
        echo "  $a"
    done
fi

date

# CI gate: asymmetric outcomes are the regression signal.
if [[ $mixed -gt 0 ]]; then
    echo
    echo "FAIL: $mixed fixture(s) had asymmetric outcomes"
    exit 1
fi
exit 0
