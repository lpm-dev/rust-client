#!/bin/bash
# Run every real-world project in projects.json and emit a consolidated
# summary. CI-friendly: exits non-zero only on mode-asymmetric outcomes
# (PASS isolated / FAIL hoisted or vice versa) — symmetric failures are
# upstream/ecosystem incompat and don't gate the build.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq not on PATH (manifest reader)" >&2
    exit 2
fi

# Optional filter: only run projects matching a substring (`./run-all.sh next`)
FILTER="${1:-}"

# Read project names in manifest order. Avoid mapfile/readarray (not
# in macOS bash 3.2) — use a portable while-read loop instead.
PROJECT_NAMES=()
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ -z "$FILTER" || "$line" == *"$FILTER"* ]]; then
        PROJECT_NAMES+=("$line")
    fi
done < <(jq -r '.projects[].name' "$HERE/projects.json")

declare -a RESULTS=()
declare -a NAMES=()

date
echo "[realworld] running ${#PROJECT_NAMES[@]} project(s)"
echo

for name in "${PROJECT_NAMES[@]}"; do
    echo
    echo "=========================================="
    echo "  $name"
    echo "=========================================="
    set +e
    "$HERE/run-realworld.sh" "$name"
    set -e

    iso=$(ls -t "$HERE/results/$name-isolated-"*.json 2>/dev/null | head -1)
    hst=$(ls -t "$HERE/results/$name-hoisted-"*.json 2>/dev/null | head -1)
    iso_v=$([[ -f "$iso" ]] && python3 -c "import json;print(json.load(open('$iso'))['verdict'])" || echo "?")
    hst_v=$([[ -f "$hst" ]] && python3 -c "import json;print(json.load(open('$hst'))['verdict'])" || echo "?")
    NAMES+=("$name")
    RESULTS+=("${iso_v}/${hst_v}")
done

echo
echo
echo "############################################"
echo "##  REAL-WORLD AUDIT SUMMARY"
echo "############################################"
printf "%-32s %-20s\n" "PROJECT" "ISOLATED/HOISTED"
echo "------------------------------------------------------------------"
pass=0; fail=0; mixed=0
for i in "${!NAMES[@]}"; do
    printf "%-32s %-20s\n" "${NAMES[$i]}" "${RESULTS[$i]}"
    case "${RESULTS[$i]}" in
        "PASS/PASS") pass=$((pass+1)) ;;
        "PASS/FAIL"|"FAIL/PASS") mixed=$((mixed+1)) ;;
        *)           fail=$((fail+1)) ;;
    esac
done
echo "------------------------------------------------------------------"
printf "PASS both: %d   ASYMMETRIC: %d   FAIL both / unknown: %d   total: %d\n" \
    "$pass" "$mixed" "$fail" "${#NAMES[@]}"
echo

date

# Mode-asymmetric outcomes are regressions. Symmetric failures are
# adjacent issues (upstream incompat, lpm bug equally on both modes,
# fixture/network problem) — surface them but don't gate the build.
if [[ $mixed -gt 0 ]]; then
    echo
    echo "FAIL: $mixed project(s) had asymmetric outcomes (hoisted regressions)"
    exit 1
fi
exit 0
