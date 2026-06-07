#!/bin/bash
# Real-world project audit harness — confidence-followup
#
# Clones a project pinned in projects.json, replaces its install with
# `lpm install --linker <mode>` for both isolated and hoisted, and runs
# the project's own smoke command (build / typecheck / equivalent). The
# audit signal is mode-asymmetric outcomes — same as the audit-fixtures
# suite. Symmetric failures (both modes fail) are upstream / ecosystem
# incompat and don't gate the audit.
#
# Usage:  ./run-realworld.sh <project-name>
# Example: ./run-realworld.sh next-blog-starter
set -euo pipefail

PROJECT_NAME="${1:?project name required, e.g. next-blog-starter}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
RESULTS_DIR="$HERE/results"
CACHE_DIR="${LPM_REALWORLD_CACHE:-$HERE/.cache}"
BIN="${LPM_BIN:-$REPO_ROOT/target/release/lpm-rs}"
WORK_BASE="${LPM_REALWORLD_WORK_BASE:-/tmp/lpm-realworld-work}"
MANIFEST="$HERE/projects.json"
source "$REPO_ROOT/bench/audit-install-args.sh"
# Per-smoke timeout (seconds). A real lpm bug surfaced as
# vitepress@1.5 hanging forever on `--version` after install — pre-fix
# that wedged a `run-all.sh` for 312 s before SIGKILL. Anything past
# this cap kills the smoke and reports `smoke_exit=124` (matches GNU
# `timeout`'s convention) so a single bad project can't stall a weekly
# or manual sweep. Override via LPM_REALWORLD_SMOKE_TIMEOUT_S.
SMOKE_TIMEOUT_S="${LPM_REALWORLD_SMOKE_TIMEOUT_S:-300}"

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: lpm binary not found or not executable: $BIN" >&2
    echo "       build with: cargo build --release -p lpm-cli" >&2
    exit 2
fi
if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: manifest not found: $MANIFEST" >&2
    exit 2
fi
if ! command -v node &>/dev/null; then
    echo "ERROR: node not on PATH" >&2
    exit 2
fi
if ! command -v git &>/dev/null; then
    echo "ERROR: git not on PATH" >&2
    exit 2
fi
if ! command -v jq &>/dev/null; then
    echo "ERROR: jq not on PATH (manifest reader)" >&2
    exit 2
fi
lpm_audit_prepare_install_args

# Pull the project's manifest entry.
ENTRY=$(jq -e --arg n "$PROJECT_NAME" '.projects[] | select(.name == $n)' "$MANIFEST" 2>/dev/null || true)
if [[ -z "$ENTRY" ]]; then
    echo "ERROR: project not in manifest: $PROJECT_NAME" >&2
    echo "       known projects:" >&2
    jq -r '.projects[].name' "$MANIFEST" | sed 's/^/         /' >&2
    exit 2
fi

GIT_URL=$(echo "$ENTRY" | jq -r '.git_url // ""')
GIT_REF=$(echo "$ENTRY" | jq -r '.git_ref // ""')
SUBPATH=$(echo "$ENTRY" | jq -r '.subpath // "."')
PRE_INSTALL=$(echo "$ENTRY" | jq -r '.pre_install // ""')
SMOKE=$(echo "$ENTRY" | jq -r .smoke)
CATEGORY=$(echo "$ENTRY" | jq -r '.category // "uncategorized"')
FROM_SCRATCH=$(echo "$ENTRY" | jq -r '.from_scratch // false')

TS="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR" "$CACHE_DIR"

now_ms() { python3 -c 'import time;print(int(time.perf_counter_ns()))'; }

json_string() {
    printf '%s' "$1" | python3 -c 'import json, sys; print(json.dumps(sys.stdin.read()))'
}

# Portable timeout wrapper. GNU `timeout` isn't on macOS by default
# (renames to `gtimeout` via coreutils); Windows Git Bash also lacks
# it. Perl is preinstalled on macOS, every CI Linux image, and Git
# Bash, so the harness can rely on it without a `requirements.sh`.
#
# Implementation:
#   - fork a child; child does setpgrp + exec — runs in its own
#     process group ($child_pid)
#   - parent installs ALRM handler that kills the child's group
#     (-$child_pid) WITHOUT killing itself
#   - on timeout: wait reap, exit 124 (matches GNU `timeout`'s
#     convention so callers can distinguish "killed by timeout" from
#     "smoke exited nonzero")
#   - on success: propagate child's exit code
run_with_timeout() {
    local secs="$1"; shift
    perl -e '
        my $t = shift;
        my $pid = fork();
        if ($pid == 0) {
            setpgrp(0, 0);
            exec @ARGV or exit 127;
        }
        $SIG{ALRM} = sub {
            kill -9, $pid;
            waitpid $pid, 0;
            exit 124;
        };
        alarm $t;
        waitpid $pid, 0;
        my $rc = $?;
        exit($rc == 0 ? 0 : ($rc >> 8 || 1));
    ' "$secs" "$@"
}

# Clone (or refresh) the source repo into a name-keyed cache. We clone
# at the pinned ref with --depth 1 so re-runs hit the cache. Different
# refs for the same name invalidate the cache directory.
clone_or_refresh() {
    local cache_key="$CACHE_DIR/$PROJECT_NAME"
    local stamp="$cache_key/.lpm-audit-ref"

    if [[ -f "$stamp" && "$(cat "$stamp")" == "$GIT_REF" ]]; then
        echo "[clone] cache hit: $cache_key @ $GIT_REF"
        return 0
    fi

    rm -rf "$cache_key"
    echo "[clone] $GIT_URL @ $GIT_REF -> $cache_key"
    # Path 1: tag or branch — `--depth 1 --branch` is the cheap path
    # (no blob filter; --depth 1 already minimizes data, and blob
    # filtering on top fights with later checkout).
    if git clone --depth 1 --branch "$GIT_REF" "$GIT_URL" "$cache_key" 2>/dev/null; then
        echo "$GIT_REF" > "$stamp"
        return 0
    fi

    # Path 2: arbitrary SHA — partial-init + targeted fetch. GitHub's
    # uploadpack.allowAnySHA1InWant is enabled, so a single-SHA fetch
    # works without a full clone. This avoids the multi-minute
    # full-clone path for repos with deep history.
    echo "[clone] tag/branch fetch failed, fetching SHA: $GIT_REF"
    rm -rf "$cache_key"
    mkdir -p "$cache_key"
    (
        cd "$cache_key"
        git init -q
        git remote add origin "$GIT_URL"
        if git fetch --depth=1 origin "$GIT_REF" 2>/dev/null; then
            git checkout -q FETCH_HEAD
        else
            # Path 3: SHA host doesn't allow single-SHA fetch (rare).
            # Full clone fallback.
            cd ..
            rm -rf "$cache_key"
            git clone "$GIT_URL" "$cache_key"
            cd "$cache_key"
            git checkout "$GIT_REF"
        fi
    )
    echo "$GIT_REF" > "$stamp"
}

# `from_scratch: true` projects skip the clone entirely — useful when
# the unit-under-test IS the install graph (e.g., "install all of
# vitepress's transitives") and the project's own source tree is
# irrelevant (or worse, has `workspace:*` references that need
# rewriting). pre_install then becomes the project authoring step.
if [[ "$FROM_SCRATCH" == "true" ]]; then
    echo "[clone] from_scratch: skipping git clone for $PROJECT_NAME"
else
    if [[ -z "$GIT_URL" || -z "$GIT_REF" ]]; then
        echo "ERROR: $PROJECT_NAME requires git_url + git_ref unless from_scratch=true" >&2
        exit 2
    fi
    clone_or_refresh
fi

run_mode() {
    local mode="$1"
    local work="$WORK_BASE/$PROJECT_NAME-$mode"
    local result="$RESULTS_DIR/$PROJECT_NAME-$mode-$TS.json"
    local effective_lpm_home="${LPM_HOME:-$WORK_BASE/$PROJECT_NAME-$mode-home}"

    echo "--- $PROJECT_NAME [$mode] ---"

    # Wipe everything for true cold install. Honor LPM_HOME (mirrors
    # the audit-fixtures runner — see that file for the full
    # rationale). Without this, callers that set LPM_HOME for
    # parallelism leak state from one mode to the next.
    if [[ -n "${LPM_HOME:-}" ]]; then
        rm -rf "$work" "$effective_lpm_home/cache" "$effective_lpm_home/store"
    else
        rm -rf "$work" "$effective_lpm_home"
    fi
    mkdir -p "$work" "$effective_lpm_home"

    if [[ "$FROM_SCRATCH" == "true" ]]; then
        # No clone — pre_install authors the project from scratch.
        :
    else
        # Copy the cached project into the work dir. Use rsync to skip
        # .git (large + irrelevant for the install).
        local src="$CACHE_DIR/$PROJECT_NAME/$SUBPATH"
        if [[ ! -d "$src" ]]; then
            echo "ERROR: subpath does not exist after clone: $src" >&2
            exit 2
        fi
        if command -v rsync &>/dev/null; then
            rsync -a --exclude='.git' "$src/" "$work/"
        else
            cp -R "$src/." "$work/"
            rm -rf "$work/.git"
        fi
    fi

    # Strip lockfiles so lpm runs a fresh resolution. Each mode gets the
    # same input regardless of which package manager the project ships.
    rm -f "$work/package-lock.json" "$work/yarn.lock" "$work/pnpm-lock.yaml" "$work/bun.lockb" "$work/lpm.lock" "$work/lpm.lockb"

    # Pre-install hook (e.g., normalize package.json so npm/lpm don't
    # reject a missing name field on a template fragment).
    if [[ -n "$PRE_INSTALL" ]]; then
        echo "[pre-install] $PRE_INSTALL"
        (cd "$work" && bash -c "$PRE_INSTALL")
    fi

    # Run install.
    local install_log="$work/.lpm-install.log"
    local install_json="$work/.lpm-install.json"
    local s=$(now_ms)
    set +e
    (cd "$work" && export LPM_HOME="$effective_lpm_home" && lpm_audit_run_install "$BIN" --linker "$mode" --json > "$install_json") 2> "$install_log"
    local install_exit=$?
    set -e
    local e=$(now_ms)
    local install_ms=$(( (e-s)/1000000 ))

    # Top-level node_modules count (sanity check).
    local top_count=0
    if [[ -d "$work/node_modules" ]]; then
        top_count=$(find "$work/node_modules" -mindepth 1 -maxdepth 1 \( -type d -o -type l \) -not -name '.bin' -not -name '.lpm*' 2>/dev/null | wc -l | tr -d ' ')
    fi

    # Smoke test. Wrapped in `run_with_timeout` so a hanging CLI
    # (vitepress@1.5 `--version` did this in pre-smoke) can't wedge
    # the suite. Timeout fires `kill 9 -$$` to take down the whole
    # process group — important for `npx`/`node` sub-processes.
    local smoke_log="$work/.lpm-smoke.log"
    local smoke_exit=0
    local smoke_ms=0
    if [[ $install_exit -eq 0 ]]; then
        local ss=$(now_ms)
        set +e
        (
            cd "$work" && \
            run_with_timeout "$SMOKE_TIMEOUT_S" bash -c "$SMOKE"
        ) > "$smoke_log" 2>&1
        smoke_exit=$?
        set -e
        local se=$(now_ms)
        smoke_ms=$(( (se-ss)/1000000 ))
        if [[ $smoke_exit -eq 124 ]]; then
            echo "(smoke killed: exceeded ${SMOKE_TIMEOUT_S}s)" >> "$smoke_log"
        fi
    else
        smoke_exit=99
        echo "(install failed; smoke skipped)" > "$smoke_log"
    fi

    # Verdict.
    local verdict="PASS"
    local fail_reason=""
    if [[ $install_exit -ne 0 ]]; then
        verdict="FAIL"; fail_reason="install exited $install_exit"
    elif [[ $smoke_exit -eq 124 ]]; then
        verdict="FAIL"; fail_reason="smoke timed out (${SMOKE_TIMEOUT_S}s)"
    elif [[ $smoke_exit -ne 0 ]]; then
        verdict="FAIL"; fail_reason="smoke exit $smoke_exit"
    fi

    # Snip the install log for the JSON (full log stays on disk).
    local install_log_snip=""
    if [[ -f "$install_log" ]]; then
        install_log_snip=$(tail -20 "$install_log" | tr -d '\r' | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
    else
        install_log_snip='""'
    fi
    local install_json_snip=""
    if [[ -f "$install_json" ]]; then
        install_json_snip=$(tail -20 "$install_json" | tr -d '\r' | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
    else
        install_json_snip='""'
    fi
    local smoke_log_snip=""
    if [[ -f "$smoke_log" ]]; then
        smoke_log_snip=$(tail -20 "$smoke_log" | tr -d '\r' | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
    else
        smoke_log_snip='""'
    fi

    local fail_reason_json
    fail_reason_json=$(json_string "$fail_reason")
    local classification_json
    classification_json=$(python3 "$REPO_ROOT/bench/audit-fixtures/classify_result.py" <<EOF
{
  "project": "$PROJECT_NAME",
  "mode": "$mode",
  "verdict": "$verdict",
  "fail_reason": $fail_reason_json,
  "install_exit": $install_exit,
  "smoke_exit": $smoke_exit,
    "install_json_tail": $install_json_snip,
  "install_log_tail": $install_log_snip,
  "smoke_log_tail": $smoke_log_snip
}
EOF
)
    local classification
    classification=$(printf '%s' "$classification_json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["classification"])')
    local classification_detail
    classification_detail=$(printf '%s' "$classification_json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["classification_detail"])')
    local classification_detail_json
    classification_detail_json=$(json_string "$classification_detail")

    python3 - <<EOF > "$result"
import json
print(json.dumps({
    "project": "$PROJECT_NAME",
    "category": "$CATEGORY",
    "git_ref": "$GIT_REF",
    "mode": "$mode",
    "timestamp": "$TS",
    "install_exit": $install_exit,
    "install_ms": $install_ms,
    "top_level_dep_count": $top_count,
    "smoke_exit": $smoke_exit,
    "smoke_ms": $smoke_ms,
    "verdict": "$verdict",
    "fail_reason": $fail_reason_json,
    "classification": "$classification",
    "classification_detail": $classification_detail_json,
    "install_json_tail": $install_json_snip,
    "install_log_tail": $install_log_snip,
    "smoke_log_tail": $smoke_log_snip,
}, indent=2))
EOF

    printf "  install: exit=%d, %dms, top-level deps=%d\n" \
        "$install_exit" "$install_ms" "$top_count"
    printf "  smoke:   exit=%d, %dms\n" "$smoke_exit" "$smoke_ms"
    if [[ "$verdict" != "PASS" ]]; then
        printf "  verdict: FAIL [%s] (%s)\n" "$classification" "$fail_reason"
        if [[ $install_exit -ne 0 ]]; then
            tail -10 "$install_log" 2>/dev/null | sed 's/^/    /'
        elif [[ $smoke_exit -ne 0 ]]; then
            tail -10 "$smoke_log" 2>/dev/null | sed 's/^/    /'
        fi
    else
        printf "  verdict: PASS\n"
    fi
    echo
}

echo "[realworld] $PROJECT_NAME ($CATEGORY) — HEAD $(cd "$REPO_ROOT" && git rev-parse --short HEAD)"
if [[ "$FROM_SCRATCH" == "true" ]]; then
    echo "            from_scratch (pre_install authors package.json)"
else
    echo "            $GIT_URL @ $GIT_REF/$SUBPATH"
fi
echo

run_mode isolated
run_mode hoisted

echo "==================================="
echo " $PROJECT_NAME — overall summary"
echo "==================================="
for mode in isolated hoisted; do
    current_result="$RESULTS_DIR/$PROJECT_NAME-$mode-$TS.json"
    if [[ -f "$current_result" ]]; then
        verdict=$(python3 -c "import json;print(json.load(open('$current_result'))['verdict'])")
        classification=$(python3 -c "import json;print(json.load(open('$current_result')).get('classification','unclassified-failure'))")
        reason=$(python3 -c "import json;print(json.load(open('$current_result')).get('fail_reason','') or '-')")
        printf "  %-10s %-5s %-22s %s\n" "$mode" "$verdict" "$classification" "$reason"
    fi
done
