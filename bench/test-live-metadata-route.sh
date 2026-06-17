#!/bin/bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_LPM="$TMP_DIR/fake-lpm"
ARGS_FILE="$TMP_DIR/args.txt"
ENV_FILE="$TMP_DIR/env.txt"
CWD_FILE="$TMP_DIR/cwd.txt"
mkdir -p "$TMP_DIR/work"

cat > "$FAKE_LPM" <<'SH'
#!/bin/bash
set -euo pipefail

printf '%s\n' "$*" >> "$LPM_TEST_ARGS_FILE"
printf 'HOME=%s\nLPM_HOME=%s\nLPM_NPM_ROUTE=%s\nLPM_STORE_VERSION=%s\n' \
  "$HOME" "$LPM_HOME" "$LPM_NPM_ROUTE" "$LPM_STORE_VERSION" >> "$LPM_TEST_ENV_FILE"
pwd >> "$LPM_TEST_CWD_FILE"
mkdir -p "$LPM_HOME/store/v2/objects/fake-$LPM_NPM_ROUTE"

case "$LPM_NPM_ROUTE" in
  direct)
    source='registry+https://registry.npmjs.org'
    http_2=58
    dispatcher_rpc=57
    ;;
  proxy)
    source='registry+https://lpm.dev'
    http_2=5
    dispatcher_rpc=4
    ;;
  *)
    echo "unexpected LPM_NPM_ROUTE=$LPM_NPM_ROUTE" >&2
    exit 1
    ;;
esac

cat <<JSON
{
  "success": true,
  "packages": [
    {
      "name": "fixture-root",
      "version": "1.0.0",
      "source": "$source",
      "direct": true
    }
  ],
  "count": 1,
  "downloaded": 0,
  "cached": 1,
  "linked": 0,
  "duration_ms": 10,
  "timing": {
    "resolve_ms": 7,
    "fetch_ms": 1,
    "link_ms": 1,
    "total_ms": 10,
    "resolve": {
      "initial_batch_ms": 0,
      "followup_rpc_count": $http_2,
      "walker_rpc_count": 0,
      "escape_hatch_rpc_count": 0,
      "parse_ndjson_ms": 0,
      "pubgrub_ms": 7,
      "metadata_http_versions": {
        "http_09": 0,
        "http_10": 0,
        "http_11": 0,
        "http_2": $http_2,
        "http_3": 0,
        "unknown": 0
      },
      "dispatcher": {
        "rpc_count": $dispatcher_rpc,
        "inflight_high_water": 1,
        "parked_max_depth": 1,
        "tarball_dispatched": 1,
        "peer_prefetch_count": 0
      },
      "streaming_bfs": {
        "levels": []
      }
    }
  }
}
JSON
SH
chmod +x "$FAKE_LPM"

export LPM_BIN="$FAKE_LPM"
export LPM_TEST_ARGS_FILE="$ARGS_FILE"
export LPM_TEST_ENV_FILE="$ENV_FILE"
export LPM_TEST_CWD_FILE="$CWD_FILE"

RUNS=2 \
BENCH_WORK_DIR="$TMP_DIR/work" \
LPM_LIVE_METADATA_KEEP_WORK=1 \
"$REPO_ROOT/bench/live-metadata-route.sh" > "$TMP_DIR/out.txt" 2> "$TMP_DIR/err.txt"

grep -Fq 'LPM Live Metadata Route Benchmark' "$TMP_DIR/out.txt"
grep -Fq 'mode: warm-store' "$TMP_DIR/out.txt"
grep -Fq '"route": "direct"' "$TMP_DIR/out.txt"
grep -Fq '"route": "proxy"' "$TMP_DIR/out.txt"
grep -Fq '"metadata_http_response_count_median": 58' "$TMP_DIR/out.txt"
grep -Fq '"metadata_http_response_count_median": 5' "$TMP_DIR/out.txt"
grep -Fq 'prewarm_route: direct' "$TMP_DIR/out.txt"

RESULTS_FILE="$(awk '/^results: / { print $2 }' "$TMP_DIR/out.txt")"
test -f "$RESULTS_FILE"

jq -s -e 'length == 4' "$RESULTS_FILE" >/dev/null
jq -s -e 'map(select(.route == "direct" and .metadata_http_response_count == 58)) | length == 2' "$RESULTS_FILE" >/dev/null
jq -s -e 'map(select(.route == "proxy" and .metadata_http_response_count == 5)) | length == 2' "$RESULTS_FILE" >/dev/null

grep -Fq -- 'install --json --no-security-summary --no-skills --no-editor-setup' "$ARGS_FILE"
grep -q '^LPM_NPM_ROUTE=direct$' "$ENV_FILE"
grep -q '^LPM_NPM_ROUTE=proxy$' "$ENV_FILE"
grep -q '^LPM_STORE_VERSION=v2$' "$ENV_FILE"
grep -Fq "HOME=$TMP_DIR/work/" "$ENV_FILE"
grep -Fq "LPM_HOME=$TMP_DIR/work/" "$ENV_FILE"
grep -Fq "$TMP_DIR/work/" "$CWD_FILE"
grep -Fq '/project' "$CWD_FILE"

if grep -Fxq "HOME=$HOME" "$ENV_FILE"; then
	echo "live metadata route bench leaked the real HOME" >&2
	exit 1
fi

echo "live metadata route bench helper tests passed"
