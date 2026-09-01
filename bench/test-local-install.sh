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
VALIDATOR_FILE="$TMP_DIR/validators.txt"
STALE_FILE="$TMP_DIR/stale.txt"

cat > "$FAKE_LPM" <<'SH'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$LPM_TEST_ARGS_FILE"
printf 'HOME=%s\nLPM_HOME=%s\nLPM_NPM_ROUTE=%s\nLPM_STORE_VERSION=%s\n' \
  "$HOME" "$LPM_HOME" "$LPM_NPM_ROUTE" "$LPM_STORE_VERSION" >> "$LPM_TEST_ENV_FILE"
pwd >> "$LPM_TEST_CWD_FILE"
cache_dir="$LPM_HOME/cache/metadata"
if [[ -d "$cache_dir" ]]; then
	for cache_entry in "$cache_dir"/*; do
		if [[ -f "$cache_entry" ]]; then
			sed -n '3p' "$cache_entry" >> "$LPM_TEST_VALIDATOR_FILE"
			if [[ "$(sed -n '3p' "$cache_entry")" == '"lpm-local-stale-bench"' ]]; then
				python3 - "$cache_entry" "$LPM_TEST_STALE_FILE" <<'PY'
import pathlib
import sys

if pathlib.Path(sys.argv[1]).stat().st_mtime < 978307200:
    pathlib.Path(sys.argv[2]).write_text("stale\n", encoding="utf-8")
PY
			fi
		fi
	done
fi
mkdir -p "$cache_dir"
if ! find "$cache_dir" -maxdepth 1 -type f | grep -q .; then
	printf 'LPM-MD-V4\n300\n"local-install-etag"\npayload' > "$cache_dir/entry"
fi
cat <<'JSON'
{
  "success": true,
  "timing": {
    "resolve_ms": 1,
    "fetch_ms": 2,
    "link_ms": 3,
    "total_ms": 4,
    "fetch_breakdown": {
      "task_count": 1,
      "queue_wait": { "sum_ms": 0, "max_ms": 0 },
      "download": { "sum_ms": 1, "max_ms": 1 },
      "integrity": { "sum_ms": 0, "max_ms": 0 },
      "extract": { "sum_ms": 1, "max_ms": 1 },
      "security": { "sum_ms": 0, "max_ms": 0 },
      "finalize": { "sum_ms": 0, "max_ms": 0 }
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
export LPM_TEST_VALIDATOR_FILE="$VALIDATOR_FILE"
export LPM_TEST_STALE_FILE="$STALE_FILE"

RUNS=1 \
BENCH_WORK_DIR="$TMP_DIR/work" \
LPM_LOCAL_BENCH_PACKAGES=4 \
LPM_LOCAL_BENCH_ROOTS=2 \
LPM_LOCAL_BENCH_VERSIONS=2 \
LPM_LOCAL_BENCH_TARBALL_KIB=1 \
"$REPO_ROOT/bench/local-install.sh" > "$TMP_DIR/out.txt"

grep -Fq 'LPM Local Install Benchmark' "$TMP_DIR/out.txt"
grep -Fq 'cold' "$TMP_DIR/out.txt"
grep -Fq 'warm' "$TMP_DIR/out.txt"
grep -Fq 'repeat' "$TMP_DIR/out.txt"
grep -Fq 'stale-304' "$TMP_DIR/out.txt"
grep -Fq 'stale-200' "$TMP_DIR/out.txt"
grep -Fq 'fetch' "$TMP_DIR/out.txt"

grep -Fq -- '--registry http://127.0.0.1:' "$ARGS_FILE"
grep -Fq -- '--insecure install --no-skills --json' "$ARGS_FILE"
grep -Fq -- '--force --json' "$ARGS_FILE"
grep -q '^LPM_NPM_ROUTE=proxy$' "$ENV_FILE"
grep -q '^LPM_STORE_VERSION=v2$' "$ENV_FILE"
grep -Fq "HOME=$TMP_DIR/work/" "$ENV_FILE"
grep -Fq "LPM_HOME=$TMP_DIR/work/" "$ENV_FILE"
grep -Fq "$TMP_DIR/work/" "$CWD_FILE"
grep -Fq '/project' "$CWD_FILE"
grep -Fxq '"lpm-local-stale-bench"' "$VALIDATOR_FILE"
grep -Fxq 'stale' "$STALE_FILE"

if grep -Fxq "HOME=$HOME" "$ENV_FILE"; then
	echo "local install bench leaked the real HOME" >&2
	exit 1
fi

echo "local install bench helper tests passed"
