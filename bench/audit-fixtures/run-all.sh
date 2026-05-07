#!/bin/bash
# Run every audit fixture and emit a consolidated summary.
# Iteration order is stable so re-runs produce comparable output.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"

# All fixtures, deterministically ordered.
FIXTURES=(
    "peer-heavy/react-ssr"
    "peer-heavy/vite-react"
    "peer-heavy/nextjs-minimal"
    "peer-heavy/vue-3-ecosystem"
    "peer-heavy/apollo-graphql"
    "peer-heavy/nestjs-deep"
    "tooling/eslint-flat-config"
    "tooling/babel-presets"
    "tooling/rollup-plugins"
    "native/sharp-image"
    "native/esbuild-prebuilt"
    "native/better-sqlite3"
    "native/prisma-codegen"
    "workspace/monorepo-basic"
    "dogfood/realworld-app"
    "source-kind/file-protocol"
    "source-kind/link-protocol"
    "source-kind/postinstall-sibling-husky"
)

declare -a RESULTS=()
declare -a FIXTURE_NAMES=()

date
echo "[audit] running all ${#FIXTURES[@]} fixtures"
echo

for fixture in "${FIXTURES[@]}"; do
    echo
    echo "=========================================="
    echo "  $fixture"
    echo "=========================================="
    set +e
    output=$("$HERE/run-audit.sh" "$fixture" 2>&1)
    exit_code=$?
    set -e
    echo "$output"

    fixture_name="$(echo "$fixture" | tr '/' '-')"
    iso=$(ls -t "$HERE/results/$fixture_name-isolated-"*.json 2>/dev/null | head -1)
    hst=$(ls -t "$HERE/results/$fixture_name-hoisted-"*.json 2>/dev/null | head -1)
    iso_verdict=$([[ -f "$iso" ]] && python3 -c "import json;print(json.load(open('$iso'))['verdict'])" || echo "?")
    hst_verdict=$([[ -f "$hst" ]] && python3 -c "import json;print(json.load(open('$hst'))['verdict'])" || echo "?")
    FIXTURE_NAMES+=("$fixture")
    RESULTS+=("${iso_verdict}/${hst_verdict}")
done

# Consolidated summary
echo
echo
echo "############################################"
echo "##  CONSOLIDATED AUDIT SUMMARY"
echo "############################################"
printf "%-44s %-20s\n" "FIXTURE" "ISOLATED/HOISTED"
echo "------------------------------------------------------------------"
pass_count=0
fail_count=0
skip_count=0
for i in "${!FIXTURE_NAMES[@]}"; do
    printf "%-44s %-20s\n" "${FIXTURE_NAMES[$i]}" "${RESULTS[$i]}"
    case "${RESULTS[$i]}" in
        "PASS/PASS") pass_count=$((pass_count+1)) ;;
        "SKIP/SKIP") skip_count=$((skip_count+1)) ;;
        *)           fail_count=$((fail_count+1)) ;;
    esac
done
echo "------------------------------------------------------------------"
printf "PASS both: %d   SKIP: %d   FAIL or mixed: %d   total: %d\n" \
    "$pass_count" "$skip_count" "$fail_count" "${#FIXTURE_NAMES[@]}"
echo

# CI exit semantics: asymmetric outcomes (PASS/FAIL or FAIL/PASS) ARE
# regressions and exit non-zero. Symmetric outcomes (both PASS or both
# FAIL or both SKIP) are not — the audit's question is "does hoisted
# regress vs isolated," and equal-outcome failures across modes are
# adjacent bugs, not hoisting regressions.
asymmetric=0
for v in "${RESULTS[@]}"; do
    case "$v" in
        PASS/FAIL|FAIL/PASS|PASS/SKIP|SKIP/PASS|FAIL/SKIP|SKIP/FAIL)
            asymmetric=$((asymmetric+1))
            ;;
    esac
done

date

if [[ $asymmetric -gt 0 ]]; then
    echo
    echo "FAIL: $asymmetric fixture(s) had asymmetric outcomes (mode regressions)"
    exit 1
fi
exit 0
