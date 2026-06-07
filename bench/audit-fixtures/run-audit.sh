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
source "$REPO_ROOT/bench/audit-install-args.sh"

# confidence-followup — Windows portability.
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

python_path() {
    if [[ $IS_WINDOWS -eq 1 ]] && command -v cygpath &>/dev/null; then
        cygpath -w "$1"
    else
        printf '%s\n' "$1"
    fi
}

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
lpm_audit_prepare_install_args

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
    PY_FIXTURE_PACKAGE="$(python_path "$FIXTURE_DIR/package.json")" python3 - <<'PY'
import json
import os

with open(os.environ["PY_FIXTURE_PACKAGE"]) as f:
    pkg = json.load(f)
for k in (pkg.get("dependencies") or {}).keys():
    print(k)
PY
}

json_string() {
    printf '%s' "$1" | python3 -c 'import json, sys; print(json.dumps(sys.stdin.read()))'
}

run_mode() {
    local mode="$1"   # "isolated" | "hoisted"
    local work="$WORK_BASE/$FIXTURE_NAME-$mode"
    local result="$RESULTS_DIR/$FIXTURE_NAME-$mode-$TS.json"
    local effective_lpm_home="${LPM_HOME:-$WORK_BASE/$FIXTURE_NAME-$mode-home}"
    local top_npm_smoke_authoritative=0
    if [[ "$FIXTURE_REL" == top-npm/* ]]; then
        top_npm_smoke_authoritative=1
    fi

    echo "--- $FIXTURE_REL [$mode] ---"

    # Wipe everything so we get a true cold install. Honor LPM_HOME if
    # set — `LpmRoot::from_env` uses `$LPM_HOME` as the root directly
    # (no `.lpm` suffix; see crates/lpm-common/src/paths.rs:86-103).
    # Pre-fix this only wiped `$HOME/.lpm`, so callers that set
    # LPM_HOME (top-npm-audit's per-slot homes) leaked state across
    # modes — hoisted reused the populated store from the prior
    # isolated pass, weakening 's cold-state signal.
    if [[ -n "${LPM_HOME:-}" ]]; then
        rm -rf "$work" "$effective_lpm_home/cache" "$effective_lpm_home/store"
    else
        rm -rf "$work" "$effective_lpm_home"
    fi
    mkdir -p "$work" "$effective_lpm_home"
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
    (cd "$work" && export LPM_HOME="$effective_lpm_home" && lpm_audit_run_install "$BIN" --linker "$mode" --json > "$install_json") 2> "$install_log"
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
    local require_failures_file="$work/require-failures.tsv"
    : > "$require_failures_file"
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
            printf '%s\t%s\n' "$dep" "$err_first_line" >> "$require_failures_file"
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

    local require_fail_overridden=0
    if [[ $top_npm_smoke_authoritative -eq 1 && $require_fail -gt 0 && $smoke_exit -eq 0 ]]; then
        require_fail_overridden=1
    fi

    local require_failures_json
    require_failures_json=$(PY_REQUIRE_FAILURES_FILE="$(python_path "$require_failures_file")" python3 - <<'PY'
import csv
import json
import os
from pathlib import Path

rows = []
path = Path(os.environ["PY_REQUIRE_FAILURES_FILE"])
if path.exists():
    with path.open(newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        for row in reader:
            if not row:
                continue
            dep = row[0]
            error = "\t".join(row[1:]) if len(row) > 1 else ""
            rows.append({"dep": dep, "error": error})

print(json.dumps(rows))
PY
)

    local package_surfaces_json
    package_surfaces_json=$(PY_FIXTURE_PACKAGE="$(python_path "$FIXTURE_DIR/package.json")" PY_WORK="$(python_path "$work")" python3 - <<'PY'
import json
import os


def has_root_runtime_entry(exports_value):
    if isinstance(exports_value, str):
        return True
    if isinstance(exports_value, list):
        return True
    if not isinstance(exports_value, dict):
        return False
    if "." in exports_value:
        return True
    return any(not str(key).startswith(".") for key in exports_value)


fixture_package_path = os.environ["PY_FIXTURE_PACKAGE"]
work_dir = os.environ["PY_WORK"]

with open(fixture_package_path) as fixture_handle:
    fixture_package = json.load(fixture_handle)

rows = []
for dep in (fixture_package.get("dependencies") or {}).keys():
    manifest_path = os.path.join(work_dir, "node_modules", *dep.split("/"), "package.json")
    surface = {
        "dep": dep,
        "manifest_found": os.path.exists(manifest_path),
        "surface_kind": "missing-manifest",
        "peer_dependencies": [],
    }
    if not os.path.exists(manifest_path):
        rows.append(surface)
        continue

    with open(manifest_path) as manifest_handle:
        package_manifest = json.load(manifest_handle)

    exports_value = package_manifest.get("exports")
    has_runtime_entry = bool(
        package_manifest.get("main")
        or package_manifest.get("module")
        or has_root_runtime_entry(exports_value)
    )
    has_types = bool(package_manifest.get("types") or package_manifest.get("typings"))
    has_bin = bool(package_manifest.get("bin"))

    if not has_runtime_entry and has_types and not has_bin:
        surface_kind = "types-only"
    elif not has_runtime_entry and has_bin and not has_types:
        surface_kind = "bin-only"
    elif not has_runtime_entry:
        surface_kind = "non-runtime"
    else:
        surface_kind = "runtime"

    surface.update(
        {
            "surface_kind": surface_kind,
            "peer_dependencies": sorted((package_manifest.get("peerDependencies") or {}).keys()),
            "has_runtime_entry": has_runtime_entry,
            "has_bin": has_bin,
            "has_types": has_types,
        }
    )
    rows.append(surface)

print(json.dumps(rows))
PY
)

    # Verdict.
    local verdict="PASS"
    local fail_reason=""
    if [[ $install_exit -ne 0 ]]; then
        verdict="FAIL"; fail_reason="install exited $install_exit"
    elif [[ $require_fail -gt 0 && $require_fail_overridden -eq 0 ]]; then
        verdict="FAIL"; fail_reason="$require_fail of $((require_pass+require_fail)) requires failed"
    elif [[ $smoke_exit -ne 0 ]]; then
        verdict="FAIL"; fail_reason="smoke exit $smoke_exit"
    fi

    local install_log_snip='""'
    if [[ -f "$install_log" ]]; then
        install_log_snip=$(tail -20 "$install_log" | tr -d '\r' | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
    fi

    local install_json_snip='""'
    if [[ -f "$install_json" ]]; then
        install_json_snip=$(tail -20 "$install_json" | tr -d '\r' | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
    fi

    local smoke_log_snip='""'
    if [[ -n "$smoke_log" ]]; then
        smoke_log_snip=$(printf '%s' "$smoke_log" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
    fi

    local fail_reason_json
    fail_reason_json=$(json_string "$fail_reason")

    local classification_json
    classification_json=$(python3 "$(python_path "$HERE/classify_result.py")" <<EOF
{
  "fixture": "$FIXTURE_REL",
  "mode": "$mode",
  "verdict": "$verdict",
  "fail_reason": $fail_reason_json,
  "install_exit": $install_exit,
  "require_pass": $require_pass,
  "require_fail": $require_fail,
  "smoke_exit": $smoke_exit,
    "install_json_tail": $install_json_snip,
  "install_log_tail": $install_log_snip,
  "smoke_log_tail": $smoke_log_snip,
  "require_failures": $require_failures_json,
  "package_surfaces": $package_surfaces_json
}
EOF
)
    local classification
    classification=$(printf '%s' "$classification_json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["classification"])')
    local classification_detail
    classification_detail=$(printf '%s' "$classification_json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["classification_detail"])')
    local classification_detail_json
    classification_detail_json=$(json_string "$classification_detail")

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
    "fail_reason": $fail_reason_json,
    "classification": "$classification",
    "classification_detail": $classification_detail_json,
    "require_failures": json.loads('''$require_failures_json'''),
    "package_surfaces": json.loads('''$package_surfaces_json'''),
    "install_json_tail": $install_json_snip,
    "install_log_tail": $install_log_snip,
    "smoke_log_tail": $smoke_log_snip,
}, indent=2))
EOF

    # Stdout summary.
    printf "  install: exit=%d, %dms, top-level deps=%d\n" \
        "$install_exit" "$install_ms" "$top_count"
    if [[ $require_fail_overridden -eq 1 ]]; then
        printf "  require: %d pass, %d fail (top-npm smoke passed; import-only or bin-only surface tolerated)\n" "$require_pass" "$require_fail"
    else
        printf "  require: %d pass, %d fail\n" "$require_pass" "$require_fail"
    fi
    if [[ $require_fail -gt 0 ]]; then
        printf "%b" "$require_results"
    fi
    if [[ -x "$FIXTURE_DIR/smoke.sh" ]]; then
        printf "  smoke: exit=%d\n" "$smoke_exit"
        if [[ $smoke_exit -ne 0 ]]; then
            echo "$smoke_log" | sed 's/^/    /' | head -10
        fi
    fi
    local verdict_suffix=""
    if [[ "$classification" != "pass" ]]; then
        verdict_suffix=" [$classification]"
    fi
    printf "  verdict: %s%s%s\n\n" "$verdict" "$verdict_suffix" \
        "$( [[ -n "$fail_reason" ]] && echo " ($fail_reason)" || true )"
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
    current_result="$RESULTS_DIR/$FIXTURE_NAME-$mode-$TS.json"
    if [[ -f "$current_result" ]]; then
        verdict=$(PY_JSON_FILE="$(python_path "$current_result")" python3 -c 'import json, os; print(json.load(open(os.environ["PY_JSON_FILE"]))["verdict"])')
        classification=$(PY_JSON_FILE="$(python_path "$current_result")" python3 -c 'import json, os; print(json.load(open(os.environ["PY_JSON_FILE"])).get("classification", "unclassified-failure"))')
        reason=$(PY_JSON_FILE="$(python_path "$current_result")" python3 -c 'import json, os; print(json.load(open(os.environ["PY_JSON_FILE"])).get("fail_reason", "") or "-")')
        printf "  %-10s %-5s %-22s %s\n" "$mode" "$verdict" "$classification" "$reason"
    fi
done
