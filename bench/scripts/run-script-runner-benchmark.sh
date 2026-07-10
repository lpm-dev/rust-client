#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

: "${ITERATIONS:=30}"
: "${WARMUP_ITERATIONS:=2}"
: "${SCENARIOS:=^(noop|node-noop)$}"
: "${RUNNERS:=lpm-run,npm-run,pnpm-run,bun-run}"
: "${GROUPS:=script-runner}"
: "${OUT:=$ROOT/bench/perf-results/script-runner-$STAMP.md}"
: "${JSON_OUT:=${OUT%.md}.json}"

if [[ -z "${LPM_BIN:-}" ]]; then
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        LPM_BIN="$CARGO_TARGET_DIR/release/lpm-rs"
    else
        LPM_BIN="$ROOT/target/release/lpm-rs"
    fi
fi

if [[ ! -x "$LPM_BIN" ]]; then
    echo "[setup] building release lpm-rs at $LPM_BIN"
    (cd "$ROOT" && cargo build --release --locked -p lpm-cli --bin lpm-rs)
fi

export ITERATIONS
export WARMUP_ITERATIONS
export SCENARIOS
export RUNNERS
export GROUPS
export OUT
export JSON_OUT
export LPM_BIN

echo "[script-runner] scenarios: $SCENARIOS"
echo "[script-runner] runners: $RUNNERS"
echo "[script-runner] markdown: $OUT"
echo "[script-runner] json: $JSON_OUT"

exec node "$ROOT/bench/scripts/run-bin-benchmark.mjs"
