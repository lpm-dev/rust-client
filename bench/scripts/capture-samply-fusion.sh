#!/bin/bash
# Phase 57 measurement-sprint C — samply flamegraph on a single
# fusion install, bench/fixture-large COLD. Identifies the residual
# ~100 ms hot symbols below the ~900 ms total wall.

set -euo pipefail

BIN="/tmp/lpm-rs-phase56-target/release/lpm-rs"
FIXTURE="/Users/tolga/Documents/Projects/lpm-dev/rust-client/bench/fixture-large"
OUT_DIR="/tmp/phase56-fusion-bench/samply-fusion"
PROF="${OUT_DIR}/cold.json.gz"
mkdir -p "$OUT_DIR"

[[ -x "$BIN" ]] || { echo "ERROR: binary missing at $BIN"; exit 1; }
command -v samply >/dev/null || { echo "ERROR: samply not on PATH"; exit 1; }

echo "[clean] removing ~/.lpm/{cache,store} and fixture node_modules…"
rm -rf "${HOME}/.lpm/cache" "${HOME}/.lpm/store"
rm -rf "${FIXTURE}/node_modules" "${FIXTURE}/.lpm" \
       "${FIXTURE}/lpm.lock" "${FIXTURE}/lpm.lockb"

# Phase 56 W4: fusion is default for LPM_RESOLVER=greedy. LPM_WALKER stays
# stream as a no-op for symmetry with the bench harness.
export LPM_RESOLVER=greedy
export LPM_WALKER=stream

cd "$FIXTURE"

echo "[samply] recording cold fusion install → $PROF"
samply record \
    --unstable-presymbolicate \
    --save-only \
    --output "$PROF" \
    -- \
    "$BIN" install --allow-new --json \
    > "${OUT_DIR}/stdout.json" \
    2> "${OUT_DIR}/stderr.log"

echo "[done] profile: $PROF"
ls -lah "$PROF" "${PROF%.gz}.syms.json" 2>&1 | head -5
echo "[wall_ms / total_ms / resolve_ms / fetch_ms / pubgrub_ms]"
grep -oE '"(wall_ms|total_ms|resolve_ms|fetch_ms|pubgrub_ms)"[[:space:]]*:[[:space:]]*[0-9]+' "${OUT_DIR}/stdout.json" | head -10
