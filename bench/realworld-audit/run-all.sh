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
printf "%-32s %-20s %s\n" "PROJECT" "ISOLATED/HOISTED" "CATEGORY"
echo "------------------------------------------------------------------"
pass=0; symmetric_non_pass=0; mixed=0
symmetric_issue_rows=()
for i in "${!NAMES[@]}"; do
    iso="$HERE/results/${NAMES[$i]}-isolated-*.json"
    hst="$HERE/results/${NAMES[$i]}-hoisted-*.json"
    iso_file=$(ls -t $iso 2>/dev/null | head -1)
    hst_file=$(ls -t $hst 2>/dev/null | head -1)
    iso_c=$([[ -f "$iso_file" ]] && python3 -c "import json;print(json.load(open('$iso_file')).get('classification','unclassified-failure'))" || echo "?")
    hst_c=$([[ -f "$hst_file" ]] && python3 -c "import json;print(json.load(open('$hst_file')).get('classification','unclassified-failure'))" || echo "?")
    if [[ "$iso_c" == "$hst_c" ]]; then
        category_summary="$iso_c"
    else
        category_summary="$iso_c/$hst_c"
    fi
    printf "%-32s %-20s %s\n" "${NAMES[$i]}" "${RESULTS[$i]}" "$category_summary"
    case "${RESULTS[$i]}" in
        "PASS/PASS") pass=$((pass+1)) ;;
        "PASS/FAIL"|"FAIL/PASS") mixed=$((mixed+1)) ;;
        *)
            symmetric_non_pass=$((symmetric_non_pass+1))
            symmetric_issue_rows+=("${NAMES[$i]}|$category_summary|${RESULTS[$i]}")
            ;;
    esac
done
echo "------------------------------------------------------------------"
printf "PASS both: %d   ASYMMETRIC: %d   SYMMETRIC NON-PASS: %d   total: %d\n" \
    "$pass" "$mixed" "$symmetric_non_pass" "${#NAMES[@]}"
echo

if [[ ${#symmetric_issue_rows[@]} -gt 0 ]]; then
    echo "Symmetric non-pass buckets:"
    python3 -c '
import collections
import sys

rows = [row.split("|", 2) for row in sys.argv[1:] if row]
by_category = collections.defaultdict(list)
for project, category, verdicts in rows:
    by_category[category].append((project, verdicts))

for category in sorted(by_category):
    entries = sorted(by_category[category])
    print(f"  {category}: {len(entries)}")
    for project, verdicts in entries:
        print(f"    {project} ({verdicts})")
' "${symmetric_issue_rows[@]}"
    echo
fi

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
