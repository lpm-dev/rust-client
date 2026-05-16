#!/usr/bin/env bash
# sandbox-network-denial audit — whole-list runner +
# family classifier.
#
# Takes a newline-separated file of `name@version` entries and runs
# the single-package harness over each, collecting results and
# emitting:
#
#   results/<timestamp>/
#       raw/<pkgname>.json    — per-package outcome (see run.sh)
#       summary.json          — family-level rollup
#
# Usage:
#   run-all.sh <packages-file> [parallelism]
#
# Parallelism defaults to 4. Each per-package run isolates in its
# own tempdir, so collisions are not a concern; pick a value that
# matches your network capacity (npm metadata fetches can throttle
# under high parallelism).

set -u

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <packages-file> [parallelism]" >&2
    exit 2
fi

PACKAGES_FILE="$1"
PARALLELISM="${2:-4}"

if [[ ! -r "$PACKAGES_FILE" ]]; then
    echo "error: cannot read packages file '$PACKAGES_FILE'" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="$SCRIPT_DIR/results/$TIMESTAMP"
RAW_DIR="$RESULTS_DIR/raw"
mkdir -p "$RAW_DIR"

# Record the environment so the PR write-up can name kernel +
# lpm-rs version verbatim. Both are PR-description-load-bearing
# inputs (the audit's contract is "Linux kernel >= 6.7"); the
# reader needs to know if the run honored that.
KERNEL="$(uname -r 2>/dev/null || echo unknown)"
LPM_VERSION="$(lpm-rs --version 2>/dev/null | head -1 || echo unknown)"
PLATFORM="$(uname -s)"
echo "kernel: $KERNEL" >&2
echo "lpm: $LPM_VERSION" >&2
echo "platform: $PLATFORM" >&2

# Filter empty lines + lines starting with `#` so the packages file
# can carry comments.
mapfile -t PACKAGES < <(grep -vE '^\s*(#|$)' "$PACKAGES_FILE")
TOTAL="${#PACKAGES[@]}"
echo "auditing $TOTAL packages with parallelism=$PARALLELISM" >&2

# Run each package via the single-package harness, in parallel
# but throttled. `xargs -P` keeps memory bounded.
single_run() {
    local pkg="$1"
    local script_dir="$2"
    local raw_dir="$3"
    local safe
    safe="$(echo "$pkg" | tr '/' '_' | tr '@' '_')"
    local out="$raw_dir/${safe}.json"
    # Emit per-package JSON. The per-package script writes its
    # record on stdout; we redirect to a file under $raw_dir.
    "$script_dir/run.sh" "$pkg" > "$out" 2>>"$raw_dir/_runner-errors.log" || true
}
export -f single_run

printf '%s\n' "${PACKAGES[@]}" | \
    xargs -n1 -P "$PARALLELISM" -I{} bash -c 'single_run "$@"' _ "{}" "$SCRIPT_DIR" "$RAW_DIR"

# Collect into the family-level summary. The per-package records
# are already one-line JSON; concat through jq for the rollup.
# `group_by(.family)` does the family-count aggregation in one
# pass; the named-family-list approach with `$inputs` that an
# earlier iteration of this script tried is broken (the slurpfile
# binding doesn't exist at this scope) and is gone.
SUMMARY_FILE="$RESULTS_DIR/summary.json"
jq -s \
    --arg kernel "$KERNEL" \
    --arg lpm_version "$LPM_VERSION" \
    --arg platform "$PLATFORM" \
    --argjson total "$TOTAL" \
    '
    def remediation(f):
        if f == "prebuild-downloader" then "trustedDependencies, or package-own env opt-out (e.g. PUPPETEER_SKIP_DOWNLOAD=1)"
        elif f == "browser-fetcher" then "package-own env opt-out (PUPPETEER_SKIP_DOWNLOAD=1, PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1), or trustedDependencies"
        elif f == "native-bundler" then "trustedDependencies (postinstall builds against host toolchain)"
        elif f == "telemetry" then "if business-critical: trustedDependencies; otherwise let it fail silently — the install completes"
        else "case-by-case; most are no-op postinstalls or non-network failures unrelated to this phase"
        end;
    {
        kernel: $kernel,
        platform: $platform,
        lpm_version: $lpm_version,
        total: $total,
        observed: length,
        by_family: (
            group_by(.family) | map({
                key: .[0].family,
                value: {
                    count: length,
                    remediation: remediation(.[0].family)
                }
            }) | from_entries
        ),
        denied_in_sandbox: (map(select(.denial_signal_seen == true and .lpm_built_present == false)) | length),
        succeeded: (map(select(.lpm_built_present == true)) | length),
        marker_absent_no_denial_signal: (map(select(.lpm_built_present == false and .denial_signal_seen == false)) | length),
        dns_failure_observed: (map(select((.dns_failure_seen // false) == true)) | length)
    }
    ' \
    "$RAW_DIR"/*.json > "$SUMMARY_FILE"

echo >&2
echo "results: $RESULTS_DIR" >&2
echo "summary: $SUMMARY_FILE" >&2
cat "$SUMMARY_FILE" >&2
