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

cat > "$FAKE_LPM" <<'SH'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$LPM_TEST_ARGS_FILE"
printf 'HOME=%s\nLPM_HOME=%s\nLPM_NPM_ROUTE=%s\nLPM_STORE_VERSION=%s\n' \
  "$HOME" "$LPM_HOME" "$LPM_NPM_ROUTE" "$LPM_STORE_VERSION" >> "$LPM_TEST_ENV_FILE"
pwd >> "$LPM_TEST_CWD_FILE"
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

if grep -Fxq "HOME=$HOME" "$ENV_FILE"; then
	echo "local install bench leaked the real HOME" >&2
	exit 1
fi

echo "local install bench helper tests passed"
