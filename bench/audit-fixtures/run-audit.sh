#!/bin/bash
# Hoisted-mode compatibility audit harness.
#
# For a single fixture, runs `lpm install` in both isolated and hoisted modes
# and captures: install exit code, install_ms, top-level dep count,
# per-dep require() exit, smoke.sh exit + stderr.
#
# Usage:  ./run-audit.sh <fixture-path>
# Example: ./run-audit.sh peer-heavy/react-ssr
set -euo pipefail

FIXTURE_REL="${1:?fixture path required, e.g. peer-heavy/react-ssr}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
FIXTURE_DIR="$HERE/$FIXTURE_REL"
RESULTS_DIR="$HERE/results"

# Phase 66 confidence-followup §3b — Windows portability.
# On Git Bash (Windows-latest runner), the binary lands at
# `target/release/lpm-rs.exe` and `/tmp` resolves to the host's MSYS
# tmp dir (per-user, not shared) which is fine. Auto-append `.exe` and
# honor RUNNER_TEMP so cross-platform paths don't bake in.
IS_WINDOWS=0
case "${OSTYPE:-}" in
    msys*|cygwin*|win32*) IS_WINDOWS=1 ;;
esac
case "${OS:-}" in
    Windows_NT) IS_WINDOWS=1 ;;
esac

DEFAULT_BIN="$REPO_ROOT/target/release/lpm-rs"
if [[ $IS_WINDOWS -eq 1 && ! -e "$DEFAULT_BIN" && -e "${DEFAULT_BIN}.exe" ]]; then
    DEFAULT_BIN="${DEFAULT_BIN}.exe"
fi
BIN="${LPM_BIN:-$DEFAULT_BIN}"
# Work base: prefer RUNNER_TEMP on CI (windows-latest sets this);
# fall back to /tmp on Linux/macOS. Lets one harness handle all three.
WORK_BASE="${LPM_AUDIT_WORK_BASE:-${RUNNER_TEMP:-/tmp}/lpm-audit-work}"

if [[ ! -d "$FIXTURE_DIR" ]]; then
    echo "ERROR: fixture not found: $FIXTURE_DIR" >&2
    exit 2
fi
if [[ ! -f "$FIXTURE_DIR/package.json" ]]; then
    echo "ERROR: $FIXTURE_DIR/package.json missing" >&2
    exit 2
fi
if [[ ! -x "$BIN" ]]; then
    echo "ERROR: lpm binary not found or not executable: $BIN" >&2
    echo "       build with: cargo build --release -p lpm-cli" >&2
    exit 2
fi
if ! command -v node &>/dev/null; then
    echo "ERROR: node not on PATH" >&2
    exit 2
fi

FIXTURE_NAME="$(echo "$FIXTURE_REL" | tr '/' '-')"
TS="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Optional `requirements.sh` per fixture: if it exists and exits
# non-zero, the audit is SKIPPED (not failed) for this fixture.
# Used for env-conditional fixtures (better-sqlite3 needs node-gyp on
# PATH; without it the install can't compile). The reason is
# captured from the script's stderr.
if [[ -x "$FIXTURE_DIR/requirements.sh" ]]; then
    set +e
    skip_log="$(bash "$FIXTURE_DIR/requirements.sh" 2>&1)"
    skip_exit=$?
    set -e
    if [[ $skip_exit -ne 0 ]]; then
        echo "[audit] $FIXTURE_REL — SKIP (requirements not met)"
        printf "  %s\n" "$skip_log"
        # Write a SKIP result JSON so aggregators can distinguish skip-
        # from-fail.
        for mode in isolated hoisted; do
            python3 - <<EOF > "$RESULTS_DIR/$FIXTURE_NAME-$mode-$TS.json"
import json
print(json.dumps({
    "fixture": "$FIXTURE_REL",
    "mode": "$mode",
    "timestamp": "$TS",
    "verdict": "SKIP",
    "skip_reason": """$skip_log""",
}, indent=2))
EOF
        done
        exit 0
    fi
fi

now_ms() { python3 -c 'import time;print(int(time.perf_counter_ns()))'; }

# Read direct deps from the fixture's package.json (one per line).
# Only `dependencies` — devDependencies are typically CLI tools (vitest,
# prisma, eslint, etc.) where `require()` isn't the validation path
# (vitest is ESM-only, prisma's @prisma/client needs `prisma generate`
# first, etc.). The fixture's smoke.sh exercises devDeps as needed.
direct_deps() {
    python3 - <<EOF
import json, sys
with open("$FIXTURE_DIR/package.json") as f:
    pkg = json.load(f)
for k in (pkg.get("dependencies") or {}).keys():
    print(k)
EOF
}

run_mode() {
    local mode="$1"   # "isolated" | "hoisted"
    local work="$WORK_BASE/$FIXTURE_NAME-$mode"
    local result="$RESULTS_DIR/$FIXTURE_NAME-$mode-$TS.json"

    echo "--- $FIXTURE_REL [$mode] ---"

    # Wipe everything so we get a true cold install.
    rm -rf "$work" "$HOME/.lpm/cache" "$HOME/.lpm/store"
    mkdir -p "$work"
    # Copy every file in the fixture dir except readme/smoke (those
    # aren't part of the install input).
    for f in "$FIXTURE_DIR"/*; do
        local base="$(basename "$f")"
        case "$base" in
            README.md|smoke.sh|requirements.sh) continue ;;
            *) cp -R "$f" "$work/" ;;
        esac
    done

    # Run install. Capture exit code separately so set -e doesn't bail
    # us out on a fixture failure (the failure IS the data).
    local install_log="$work/install.log"
    local install_json="$work/install.json"
    local s=$(now_ms)
    set +e
    (cd "$work" && "$BIN" install --allow-new --linker "$mode" --json > "$install_json") 2> "$install_log"
    local install_exit=$?
    set -e
    local e=$(now_ms)
    local install_ms=$(( (e-s)/1000000 ))

    # Top-level dep count. Match dirs AND symlinks — isolated mode puts
    # symlinks at top level (pointing into the wrappers tree), hoisted
    # mode puts real dirs.
    local top_count=0
    if [[ -d "$work/node_modules" ]]; then
        top_count=$(find "$work/node_modules" -mindepth 1 -maxdepth 1 \( -type d -o -type l \) -not -name '.bin' -not -name '.lpm*' 2>/dev/null | wc -l | tr -d ' ')
    fi

    # Per-dep require() check.
    local require_results=""
    local require_pass=0
    local require_fail=0
    while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue
        set +e
        local req_stderr
        req_stderr=$(cd "$work" && node -e "require('$dep')" 2>&1)
        local req_exit=$?
        set -e
        if [[ $req_exit -eq 0 ]]; then
            require_pass=$((require_pass+1))
            require_results+="  ✓ $dep\n"
        else
            require_fail=$((require_fail+1))
            local err_first_line=$(echo "$req_stderr" | head -1 | tr -d '"' | tr '\n' ' ')
            require_results+="  ✗ $dep: $err_first_line\n"
        fi
    done < <(direct_deps)

    # Smoke test (if smoke.sh exists in fixture).
    local smoke_exit=0
    local smoke_log=""
    if [[ -x "$FIXTURE_DIR/smoke.sh" ]]; then
        set +e
        smoke_log=$(cd "$work" && bash "$FIXTURE_DIR/smoke.sh" 2>&1)
        smoke_exit=$?
        set -e
    fi

    # Verdict.
    local verdict="PASS"
    local fail_reason=""
    if [[ $install_exit -ne 0 ]]; then
        verdict="FAIL"; fail_reason="install exited $install_exit"
    elif [[ $require_fail -gt 0 ]]; then
        verdict="FAIL"; fail_reason="$require_fail of $((require_pass+require_fail)) requires failed"
    elif [[ $smoke_exit -ne 0 ]]; then
        verdict="FAIL"; fail_reason="smoke exit $smoke_exit"
    fi

    # Write detailed result JSON.
    python3 - <<EOF > "$result"
import json
print(json.dumps({
    "fixture": "$FIXTURE_REL",
    "mode": "$mode",
    "timestamp": "$TS",
    "install_exit": $install_exit,
    "install_ms": $install_ms,
    "top_level_dep_count": $top_count,
    "require_pass": $require_pass,
    "require_fail": $require_fail,
    "smoke_exit": $smoke_exit,
    "verdict": "$verdict",
    "fail_reason": "$fail_reason",
}, indent=2))
EOF

    # Stdout summary.
    printf "  install: exit=%d, %dms, top-level deps=%d\n" \
        "$install_exit" "$install_ms" "$top_count"
    printf "  require: %d pass, %d fail\n" "$require_pass" "$require_fail"
    if [[ $require_fail -gt 0 ]]; then
        printf "%b" "$require_results"
    fi
    if [[ -x "$FIXTURE_DIR/smoke.sh" ]]; then
        printf "  smoke: exit=%d\n" "$smoke_exit"
        if [[ $smoke_exit -ne 0 ]]; then
            echo "$smoke_log" | sed 's/^/    /' | head -10
        fi
    fi
    printf "  verdict: %s%s\n\n" "$verdict" \
        "$([[ -n "$fail_reason" ]] && echo " ($fail_reason)" || true)"
}

echo "[audit] $FIXTURE_REL — HEAD $(cd "$REPO_ROOT" && git rev-parse --short HEAD)"
echo

run_mode isolated
run_mode hoisted

# Final cross-mode summary.
echo "==================================="
echo " $FIXTURE_REL — overall summary"
echo "==================================="
for mode in isolated hoisted; do
    latest=$(ls -t "$RESULTS_DIR/$FIXTURE_NAME-$mode-"*.json 2>/dev/null | head -1)
    if [[ -n "$latest" ]]; then
        verdict=$(python3 -c "import json;print(json.load(open('$latest'))['verdict'])")
        reason=$(python3 -c "import json;print(json.load(open('$latest')).get('fail_reason','') or '-')")
        printf "  %-10s %-5s  %s\n" "$mode" "$verdict" "$reason"
    fi
done
