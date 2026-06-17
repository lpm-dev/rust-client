#!/bin/bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TMP_DIR="$(mktemp -d)"
DEFAULT_TAG="run-readme-test-default-$$"
RESET_TAG="run-readme-test-reset-$$"
trap 'rm -rf "$TMP_DIR" "/tmp/lpm-bench-readme-roundrobin/${DEFAULT_TAG}-results" "/tmp/lpm-bench-readme-roundrobin/${DEFAULT_TAG}-trash" "/tmp/lpm-bench-readme-roundrobin/${RESET_TAG}-results" "/tmp/lpm-bench-readme-roundrobin/${RESET_TAG}-trash"' EXIT

mkdir -p "$TMP_DIR/bin" "$TMP_DIR/fixture"
printf '{"name":"run-readme-test","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}\n' > "$TMP_DIR/fixture/package.json"

cat > "$TMP_DIR/fake-lpm" <<'SH'
#!/bin/bash
set -euo pipefail

printf 'lpm route=%s http=%s args=%s cwd=%s\n' \
    "${LPM_NPM_ROUTE:-}" "${LPM_HTTP:-}" "$*" "$PWD" >> "$RUN_README_TEST_LOG"
mkdir -p "$LPM_HOME/cache" "$LPM_HOME/store" "$PWD/node_modules"
SH
chmod +x "$TMP_DIR/fake-lpm"

cat > "$TMP_DIR/bin/bun" <<'SH'
#!/bin/bash
set -euo pipefail

printf 'bun args=%s cwd=%s\n' "$*" "$PWD" >> "$RUN_README_TEST_LOG"
mkdir -p "$PWD/node_modules"
SH
chmod +x "$TMP_DIR/bin/bun"

cat > "$TMP_DIR/bin/npm" <<'SH'
#!/bin/bash
set -euo pipefail

printf 'npm args=%s cwd=%s\n' "$*" "$PWD" >> "$RUN_README_TEST_LOG"
if [[ "${1:-}" == "install" ]]; then
    mkdir -p "$PWD/node_modules"
fi
SH
chmod +x "$TMP_DIR/bin/npm"

cat > "$TMP_DIR/bin/pnpm" <<'SH'
#!/bin/bash
set -euo pipefail

if [[ "${1:-}" == "store" && "${2:-}" == "path" ]]; then
    printf '%s\n' "$RUN_README_PNPM_STORE"
    exit 0
fi
printf 'pnpm args=%s cwd=%s\n' "$*" "$PWD" >> "$RUN_README_TEST_LOG"
mkdir -p "$PWD/node_modules"
SH
chmod +x "$TMP_DIR/bin/pnpm"

run_readme_bench() {
    local tag=$1
    local out=$2
    shift 2

    env \
        PATH="$TMP_DIR/bin:$PATH" \
        LPM_BIN="$TMP_DIR/fake-lpm" \
        LPM_HOME="$TMP_DIR/lpm-home" \
        BENCH_WORK_DIR="$TMP_DIR/work" \
        BENCH_PROJECT_DIR="$TMP_DIR/fixture" \
        BENCH_BUN_CACHE_DIR="$TMP_DIR/bun-cache" \
        BENCH_NPM_CACHE_DIR="$TMP_DIR/npm-cache" \
        BENCH_PNPM_STORE_DIR="$TMP_DIR/pnpm-store" \
        RUN_README_PNPM_STORE="$TMP_DIR/pnpm-store" \
        RUN_README_TEST_LOG="$TMP_DIR/run.log" \
        "$@" \
        "$REPO_ROOT/bench/scripts/run-readme.sh" 1 "$tag" > "$out"
}

rm -f "$TMP_DIR/run.log"
run_readme_bench "$DEFAULT_TAG" "$TMP_DIR/default.out" \
    BENCH_ARMS=npm,pnpm,bun,lpm,lpm-proxy-h3

grep -Fq '[bench] modes: clean' "$TMP_DIR/default.out"
grep -Fq '[clean] cold install, equal footing' "$TMP_DIR/default.out"
grep -Fq 'lpm-proxy-h3: LPM_NPM_ROUTE=proxy LPM_HTTP=h3-worker' "$TMP_DIR/default.out"
grep -Fq 'clean    lpm-proxy-h3' "$TMP_DIR/default.out"
grep -Fq 'lpm route= http= args=install --json' "$TMP_DIR/run.log"
grep -Fq 'lpm route=proxy http=h3-worker args=install --json' "$TMP_DIR/run.log"

if grep -Fq '[full]' "$TMP_DIR/default.out"; then
    echo "run-readme default unexpectedly ran reset-each-iter mode" >&2
    exit 1
fi

if compgen -G "/tmp/lpm-bench-readme-roundrobin/${DEFAULT_TAG}-results/full-iter-*" > /dev/null; then
    echo "run-readme default wrote full-mode result files" >&2
    exit 1
fi

rm -f "$TMP_DIR/run.log"
run_readme_bench "$RESET_TAG" "$TMP_DIR/reset.out" \
    BENCH_ARMS=lpm \
    BENCH_INCLUDE_RESET_EACH_ITER=1

grep -Fq '[bench] modes: clean,full' "$TMP_DIR/reset.out"
grep -Fq '[full] cold install, reset-each-iter' "$TMP_DIR/reset.out"
test -f "/tmp/lpm-bench-readme-roundrobin/${RESET_TAG}-results/clean-iter-1-lpm.wall_ms"
test -f "/tmp/lpm-bench-readme-roundrobin/${RESET_TAG}-results/full-iter-1-lpm.wall_ms"

echo "run-readme bench helper tests passed"
