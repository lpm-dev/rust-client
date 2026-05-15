#!/usr/bin/env bash
# sandbox-network-audit — input-list builder.
#
# Replaces the broken "top-500 by downloads" recipe from earlier
# drafts (npm no longer exposes a free per-package downloads
# ranking via its public API; see README.md "Producing the audit
# input list" for the history).
#
# Strategy:
#   1. Seed from `../top-npm-audit/top-100.txt` (popularity-curated
#      from ) PLUS `scripted-candidates.txt` (this
#      directory's family-by-family known-scripted list).
#   2. De-duplicate.
#   3. For each candidate, fetch
#      `https://registry.npmjs.org/<pkg>/latest`. Keep entries
#      whose `.scripts` carry `preinstall` / `install` /
#      `postinstall`. Pin to the resolved `latest` semver so the
#      audit input is stable across runs.
#
# Output: `name@version` lines on stdout, one per kept entry.
# Errors / 404s / non-scripted entries go to stderr as one-line
# diagnostics so the operator can reconcile the count.
#
# Parallelism is fixed at 8 (npm metadata fetches are cheap — the
# bottleneck is npm's per-IP rate limit, which kicks in well
# above 8 concurrent requests).
#
# Usage:
#   ./build-input-list.sh > /tmp/sandbox-network-audit-input.txt
#
# Requires: curl, jq, xargs.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOP_100="$SCRIPT_DIR/../top-npm-audit/top-100.txt"
CANDIDATES="$SCRIPT_DIR/scripted-candidates.txt"
PARALLELISM=8

if [[ ! -r "$TOP_100" ]]; then
    echo "error: missing seed list $TOP_100" >&2
    exit 2
fi
if [[ ! -r "$CANDIDATES" ]]; then
    echo "error: missing seed list $CANDIDATES" >&2
    exit 2
fi

# Combine + strip comments/blanks + trailing inline comments +
# trailing whitespace, then de-dup. The candidates file uses
# trailing `# annotation` for per-line notes; those must be
# stripped or the curl lookup sees the comment as part of the
# package name.
SEEDS="$(mktemp)"
trap 'rm -f "$SEEDS"' EXIT
{
    cat "$TOP_100"
    cat "$CANDIDATES"
} | sed -E 's/[[:space:]]*#.*$//; s/[[:space:]]+$//' \
  | grep -vE '^\s*$' \
  | sort -u > "$SEEDS"
SEED_COUNT="$(wc -l < "$SEEDS")"
echo "build-input-list: $SEED_COUNT seed candidates" >&2

# Per-package probe. Emits one `name@version` line on stdout if
# the package carries a lifecycle script on `latest`; emits one
# diagnostic on stderr otherwise.
probe_one() {
    local pkg="$1"
    local metadata
    # `-f` makes curl exit non-zero on HTTP errors; `-s` silences
    # progress; `-S` keeps real errors. Tolerate transient
    # failures by retrying once with a 1s pause.
    metadata="$(curl -fsSL --retry 1 --retry-delay 1 \
        "https://registry.npmjs.org/${pkg}/latest" 2>/dev/null)" || {
            echo "skip ${pkg}: registry fetch failed" >&2
            return 0
        }
    if [[ -z "$metadata" ]]; then
        echo "skip ${pkg}: empty registry response" >&2
        return 0
    fi
    # Use `// ""` (default to empty string, not `// empty` which
    # filters the entry out of the pipeline entirely and breaks
    # the downstream comparison). The OR fold is enough — any
    # one of the three lifecycle keys is sufficient to count as
    # scripted.
    local has_script
    has_script="$(echo "$metadata" | jq -r '
        (.scripts // {}) as $s
        | if (($s.preinstall // "") != ""
              or ($s.install // "") != ""
              or ($s.postinstall // "") != "")
          then "yes" else "no" end
    ' 2>/dev/null || echo "error")"
    if [[ "$has_script" == "yes" ]]; then
        local version
        version="$(echo "$metadata" | jq -r '.version // empty')"
        if [[ -n "$version" && "$version" != "null" ]]; then
            echo "${pkg}@${version}"
        else
            echo "skip ${pkg}: scripted but no .version field" >&2
        fi
    elif [[ "$has_script" == "no" ]]; then
        echo "drop ${pkg}: no lifecycle script on latest" >&2
    else
        echo "skip ${pkg}: jq parse failure" >&2
    fi
}
export -f probe_one

xargs -a "$SEEDS" -n1 -P "$PARALLELISM" -I{} \
    bash -c 'probe_one "$@"' _ "{}" | sort -u
