#!/usr/bin/env bash
# Phase 39 P4 — Profile-Guided Optimization build recipe.
#
# Two-pass build:
#   1. Instrumented build (emits `.profraw` files while running a
#      training workload).
#   2. Train: run `lpm install` against the benchmark fixture 3×
#      cold, which stresses resolve / fetch / extract / scan / link
#      hot paths (NDJSON parse, SHA-512, tar walk, behavioral scan,
#      symlink + clonefile loops).
#   3. Merge `.profraw` → `.profdata` via llvm-profdata.
#   4. Rebuild with `-Cprofile-use` applied on top of the existing
#      release profile (LTO + codegen-units=1 + opt-level=3 + strip).
#
# Prereqs:
#   rustup component add llvm-tools-preview
#
# Artifacts:
#   $OUT_DIR/pgo-profdata/merged.profdata    — training profile
#   $OUT_DIR/release/lpm-rs                  — PGO-optimized binary
#
# Usage:
#   ./scripts/pgo-build.sh                   # default OUT_DIR=/tmp/lpm-pgo
#   OUT_DIR=/path/to/dir ./scripts/pgo-build.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-/tmp/lpm-pgo}"
PROFRAW_DIR="$OUT_DIR/pgo-profraw"
PROFDATA_DIR="$OUT_DIR/pgo-profdata"
PROFDATA="$PROFDATA_DIR/merged.profdata"
BENCH_FIXTURE="$REPO_ROOT/bench/project/package.json"
TRAINING_WORKDIR="$OUT_DIR/pgo-train"

LLVM_PROFDATA="$(find "$HOME/.rustup" -name llvm-profdata 2>/dev/null | head -1 || true)"
if [[ -z "$LLVM_PROFDATA" ]]; then
	echo "error: llvm-profdata not found. Run:" >&2
	echo "  rustup component add llvm-tools-preview" >&2
	exit 1
fi

mkdir -p "$OUT_DIR" "$PROFRAW_DIR" "$PROFDATA_DIR" "$TRAINING_WORKDIR"

# ── Pass 1: instrumented build ───────────────────────────────────────
#
# Writing .profraw from a parallel workload overwrites itself unless
# `%p` (PID) + `%m` (module signature) are in the filename. The
# `LLVM_PROFILE_FILE` env var is consumed by the instrumented binary
# at runtime, NOT at compile time — set it before running, not here.
echo "▶ pass 1: instrumented build"
CARGO_TARGET_DIR="$OUT_DIR" \
	RUSTFLAGS="-Cprofile-generate=$PROFRAW_DIR" \
	cargo build --release -p lpm-cli

LPM_BIN="$OUT_DIR/release/lpm-rs"
if [[ ! -x "$LPM_BIN" ]]; then
	echo "error: instrumented binary missing at $LPM_BIN" >&2
	exit 1
fi

# ── Pass 2: training workload ────────────────────────────────────────
echo "▶ pass 2: training workload (3 cold installs on bench fixture)"
cp "$BENCH_FIXTURE" "$TRAINING_WORKDIR/"

for i in 1 2 3; do
	echo "  training run $i/3"
	# Cold: wipe project state + global store + metadata cache so the
	# instrumented binary exercises the full resolve → fetch → extract
	# → link critical path on each iteration.
	(cd "$TRAINING_WORKDIR" && rm -rf node_modules lpm.lock lpm.lockb)
	rm -rf "$HOME/.lpm/cache" "$HOME/.lpm/store" 2>/dev/null || true
	# `%p` per-PID filename keeps the 3 runs' .profraw distinct.
	(cd "$TRAINING_WORKDIR" && \
		LLVM_PROFILE_FILE="$PROFRAW_DIR/lpm-%p-%m.profraw" \
		"$LPM_BIN" install --allow-new >/dev/null 2>&1) || {
		echo "warning: training run $i failed; continuing" >&2
	}
done

RAW_COUNT=$(find "$PROFRAW_DIR" -name '*.profraw' | wc -l | tr -d ' ')
if [[ "$RAW_COUNT" -eq 0 ]]; then
	echo "error: no .profraw files written. Check RUSTFLAGS and training workload." >&2
	exit 1
fi
echo "  wrote $RAW_COUNT .profraw files"

# ── Pass 3: merge profiles ───────────────────────────────────────────
echo "▶ pass 3: merge .profraw → .profdata"
"$LLVM_PROFDATA" merge -o "$PROFDATA" "$PROFRAW_DIR"/*.profraw
PROFDATA_SIZE=$(wc -c < "$PROFDATA" | tr -d ' ')
echo "  merged profile: $PROFDATA ($PROFDATA_SIZE bytes)"

# ── Pass 4: PGO-optimized build ──────────────────────────────────────
#
# `-Cprofile-use` applied on top of the existing release profile
# (LTO + codegen-units=1 + strip from Cargo.toml [profile.release]).
# `-Cllvm-args=-pgo-warn-missing-function` surfaces hot functions the
# training didn't cover — useful for expanding the workload later.
echo "▶ pass 4: PGO build"
# Re-use the same CARGO_TARGET_DIR so incremental artefacts are kept;
# RUSTFLAGS differ from pass 1 so cargo will recompile anyway.
CARGO_TARGET_DIR="$OUT_DIR" \
	RUSTFLAGS="-Cprofile-use=$PROFDATA -Cllvm-args=-pgo-warn-missing-function" \
	cargo build --release -p lpm-cli

BINARY_SIZE=$(stat -f%z "$LPM_BIN" 2>/dev/null || stat -c%s "$LPM_BIN")
echo
echo "✓ PGO build complete: $LPM_BIN ($BINARY_SIZE bytes)"
echo "  profile: $PROFDATA"
echo
echo "Next: compare against a non-PGO build with the same flags via:"
echo "  LPM_BIN=$LPM_BIN bench/run.sh cold-install-clean"
