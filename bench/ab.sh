#!/usr/bin/env bash
#
# Phase 36 A/B benchmark: compare cold-install timing between two git refs.
#
# Builds both binaries up front, then interleaves N runs of each so network
# noise affects both sides equally. Reports per-side medians and the delta.
#
# Usage:
#   ./bench/ab.sh                                          # default: v0.16.0 vs HEAD
#   ./bench/ab.sh v0.16.0 phase-36-streaming-overlap       # explicit refs
#   RUNS=10 ./bench/ab.sh                                  # more samples
#   AB_INTERLEAVE=0 ./bench/ab.sh                          # all A then all B (not recommended)
#
# Each cold run uses an isolated $HOME (via mktemp -d) and runs with
# LPM_BENCH_ALLOW_WIPE=1, so each measurement starts from a clean ~/.lpm.
# The host's ~/.lpm is never touched.
#
# Env vars:
#   RUNS            — samples per side (default: 5)
#   AB_INTERLEAVE   — 1 (default): interleave A/B runs to spread network noise.
#                     0: run all A first, then all B (sensitive to network drift).
#   AB_KEEP_BINS    — 1: keep built binaries in /tmp/lpm-ab-{A,B} after the run.

set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$BENCH_DIR/.." && pwd)"
RUN_SH="$BENCH_DIR/run.sh"
RUNS="${RUNS:-5}"
INTERLEAVE="${AB_INTERLEAVE:-1}"
KEEP_BINS="${AB_KEEP_BINS:-0}"

REF_A="${1:-v0.16.0}"
REF_B="${2:-HEAD}"

bold="\033[1m"
dim="\033[2m"
reset="\033[0m"
red="\033[31m"
green="\033[32m"
yellow="\033[33m"
cyan="\033[36m"
bold_cyan="\033[1;36m"

step() { printf "\n${bold_cyan}▸ %s${reset}\n" "$1"; }
info() { printf "${dim}  %s${reset}\n" "$1"; }
warn() { printf "${yellow}⚠ %s${reset}\n" "$1"; }
fail() { printf "${red}✗ %s${reset}\n" "$1" >&2; exit 1; }

# ─── Sanity checks ──────────────────────────────────────────────────────────

cd "$REPO_DIR"

if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
	fail "working tree is dirty — commit or stash before running A/B"
fi

ORIG_REF="$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse HEAD)"

# Resolve refs to commit hashes for stable identity in output
SHA_A="$(git rev-parse --verify "$REF_A" 2>/dev/null)" || fail "cannot resolve REF_A: $REF_A"
SHA_B="$(git rev-parse --verify "$REF_B" 2>/dev/null)" || fail "cannot resolve REF_B: $REF_B"

if [[ "$SHA_A" == "$SHA_B" ]]; then
	warn "REF_A and REF_B resolve to the same commit ($SHA_A) — A/B will measure noise only"
fi

# ─── Build binaries ──────────────────────────────────────────────────────────

BIN_A_DIR="/tmp/lpm-ab-A"
BIN_B_DIR="/tmp/lpm-ab-B"
BIN_A="$BIN_A_DIR/lpm-rs"
BIN_B="$BIN_B_DIR/lpm-rs"

cleanup() {
	# Restore original ref
	git checkout --quiet "$ORIG_REF" 2>/dev/null || true
	if [[ "$KEEP_BINS" != "1" ]]; then
		rm -rf "$BIN_A_DIR" "$BIN_B_DIR" 2>/dev/null || true
	fi
}
trap cleanup EXIT

build_ref() {
	local ref="$1" sha="$2" out_bin="$3" target_dir="$4"

	step "Building $ref ($sha)"
	git checkout --quiet "$sha" || fail "git checkout $sha failed"

	mkdir -p "$(dirname "$out_bin")"
	CARGO_TARGET_DIR="$target_dir" cargo build --release --bin lpm-rs --quiet \
		|| fail "cargo build failed for $ref"

	cp "$target_dir/release/lpm-rs" "$out_bin"
	info "binary: $out_bin ($(stat -f%z "$out_bin" 2>/dev/null || stat -c%s "$out_bin") bytes)"
}

build_ref "$REF_A" "$SHA_A" "$BIN_A" "/tmp/lpm-ab-target-A"
build_ref "$REF_B" "$SHA_B" "$BIN_B" "/tmp/lpm-ab-target-B"

# Restore original ref so the harness reads bench/run.sh from a sensible state
git checkout --quiet "$ORIG_REF"

# ─── Benchmark loop ──────────────────────────────────────────────────────────

# Each iteration runs cold-install once with the given binary, captures the
# per-stage JSON, and prints the engine total.
#
# We use RUNS=1 inside run.sh (one sample per invocation) and aggregate here
# so we can interleave A/B sides cleanly.

run_one() {
	local binary="$1"
	local out
	# LPM_BENCH_ALLOW_WIPE=1 enables the cold scenario in lpm-stages.
	# RUNS=1 because we aggregate samples here (one cold per invocation).
	# Use isolated HOME so each side starts with empty ~/.lpm and pollutes
	# nothing on the host. The HOME is wiped between runs as well, since
	# each cold run inside lpm-stages also wipes ~/.lpm/cache + store.
	local isolated_home
	isolated_home="$(mktemp -d)"

	out="$(HOME="$isolated_home" LPM_BIN="$binary" LPM_BENCH_ALLOW_WIPE=1 RUNS=1 \
		"$RUN_SH" lpm-stages 2>&1)" || {
		rm -rf "$isolated_home"
		return 1
	}
	rm -rf "$isolated_home"

	# run.sh's lpm-stages output for the cold line looks like:
	#   cold         resolve 1068ms  fetch 682ms  link 113ms  total 1849ms
	# Strip ANSI escapes first so the regex matches reliably.
	local cold_line
	cold_line="$(echo "$out" \
		| sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
		| grep -E "^\s*cold\s" | head -1 || true)"

	if [[ -z "$cold_line" ]]; then
		echo "PARSE_FAIL"
		return 1
	fi

	local resolve fetch link total
	resolve="$(echo "$cold_line" | grep -oE "resolve [0-9]+" | grep -oE "[0-9]+" | head -1 || echo 0)"
	fetch="$(echo "$cold_line" | grep -oE "fetch [0-9]+" | grep -oE "[0-9]+" | head -1 || echo 0)"
	link="$(echo "$cold_line" | grep -oE "link [0-9]+" | grep -oE "[0-9]+" | head -1 || echo 0)"
	total="$(echo "$cold_line" | grep -oE "total [0-9]+" | grep -oE "[0-9]+" | head -1 || echo 0)"

	echo "$resolve $fetch $link $total"
}

declare -a A_RESOLVE A_FETCH A_LINK A_TOTAL
declare -a B_RESOLVE B_FETCH B_LINK B_TOTAL

step "Running $RUNS samples per side (interleave=$INTERLEAVE)"

if [[ "$INTERLEAVE" == "1" ]]; then
	for ((i = 1; i <= RUNS; i++)); do
		printf "${dim}  Run %d/%d: ${reset}" "$i" "$RUNS"

		# Randomize which side goes first to avoid systematic bias
		if (( RANDOM % 2 == 0 )); then
			order=("A" "B")
		else
			order=("B" "A")
		fi

		for side in "${order[@]}"; do
			if [[ "$side" == "A" ]]; then
				bin="$BIN_A"
			else
				bin="$BIN_B"
			fi

			result="$(run_one "$bin" "$side")" || { warn "run $i $side failed"; continue; }
			read -r r f l t <<<"$result"

			if [[ "$side" == "A" ]]; then
				A_RESOLVE+=("$r"); A_FETCH+=("$f"); A_LINK+=("$l"); A_TOTAL+=("$t")
				printf "A=%dms " "$t"
			else
				B_RESOLVE+=("$r"); B_FETCH+=("$f"); B_LINK+=("$l"); B_TOTAL+=("$t")
				printf "B=%dms " "$t"
			fi
		done
		printf "\n"
	done
else
	step "All A runs first"
	for ((i = 1; i <= RUNS; i++)); do
		printf "${dim}  A run %d/%d: ${reset}" "$i" "$RUNS"
		result="$(run_one "$BIN_A" "A")" || { warn "failed"; continue; }
		read -r r f l t <<<"$result"
		A_RESOLVE+=("$r"); A_FETCH+=("$f"); A_LINK+=("$l"); A_TOTAL+=("$t")
		printf "%dms\n" "$t"
	done

	step "All B runs"
	for ((i = 1; i <= RUNS; i++)); do
		printf "${dim}  B run %d/%d: ${reset}" "$i" "$RUNS"
		result="$(run_one "$BIN_B" "B")" || { warn "failed"; continue; }
		read -r r f l t <<<"$result"
		B_RESOLVE+=("$r"); B_FETCH+=("$f"); B_LINK+=("$l"); B_TOTAL+=("$t")
		printf "%dms\n" "$t"
	done
fi

# ─── Statistics ──────────────────────────────────────────────────────────────

median() {
	local -a sorted
	IFS=$'\n' sorted=($(sort -n <<<"$*"))
	unset IFS
	local n=${#sorted[@]}
	if (( n == 0 )); then echo 0; return; fi
	if (( n % 2 == 1 )); then
		echo "${sorted[$((n / 2))]}"
	else
		echo $(( (sorted[n / 2 - 1] + sorted[n / 2]) / 2 ))
	fi
}

min() {
	local -a sorted
	IFS=$'\n' sorted=($(sort -n <<<"$*"))
	unset IFS
	echo "${sorted[0]:-0}"
}

max() {
	local -a sorted
	IFS=$'\n' sorted=($(sort -nr <<<"$*"))
	unset IFS
	echo "${sorted[0]:-0}"
}

A_MED_R=$(median "${A_RESOLVE[@]}")
A_MED_F=$(median "${A_FETCH[@]}")
A_MED_L=$(median "${A_LINK[@]}")
A_MED_T=$(median "${A_TOTAL[@]}")

B_MED_R=$(median "${B_RESOLVE[@]}")
B_MED_F=$(median "${B_FETCH[@]}")
B_MED_L=$(median "${B_LINK[@]}")
B_MED_T=$(median "${B_TOTAL[@]}")

DELTA_R=$((B_MED_R - A_MED_R))
DELTA_F=$((B_MED_F - A_MED_F))
DELTA_L=$((B_MED_L - A_MED_L))
DELTA_T=$((B_MED_T - A_MED_T))

# Color delta: green if B faster (negative), red if B slower (positive)
fmt_delta() {
	local d="$1"
	if (( d < 0 )); then
		printf "${green}%+dms${reset}" "$d"
	elif (( d > 0 )); then
		printf "${red}%+dms${reset}" "$d"
	else
		printf "${dim}%+dms${reset}" "$d"
	fi
}

step "A/B Results — $RUNS samples per side"

printf "${bold}  %-10s %12s %12s %12s${reset}\n" "stage" "A median" "B median" "delta"
printf "${dim}  %-10s %12s %12s${reset}\n" "" "$REF_A" "$REF_B"
printf "  %-10s %10dms %10dms %20b\n" "resolve" "$A_MED_R" "$B_MED_R" "$(fmt_delta "$DELTA_R")"
printf "  %-10s %10dms %10dms %20b\n" "fetch"   "$A_MED_F" "$B_MED_F" "$(fmt_delta "$DELTA_F")"
printf "  %-10s %10dms %10dms %20b\n" "link"    "$A_MED_L" "$B_MED_L" "$(fmt_delta "$DELTA_L")"
printf "  ${bold}%-10s %10dms %10dms %20b${reset}\n" "total" "$A_MED_T" "$B_MED_T" "$(fmt_delta "$DELTA_T")"

# Spread (min/max) for noise context
printf "\n${dim}  Spread (min..max):${reset}\n"
printf "${dim}    A total: %d..%d (n=%d)${reset}\n" "$(min "${A_TOTAL[@]}")" "$(max "${A_TOTAL[@]}")" "${#A_TOTAL[@]}"
printf "${dim}    B total: %d..%d (n=%d)${reset}\n" "$(min "${B_TOTAL[@]}")" "$(max "${B_TOTAL[@]}")" "${#B_TOTAL[@]}"

# ─── Verdict ──────────────────────────────────────────────────────────────────

# Heuristic: |delta| must exceed the larger spread to be considered signal
A_SPREAD=$(( $(max "${A_TOTAL[@]}") - $(min "${A_TOTAL[@]}") ))
B_SPREAD=$(( $(max "${B_TOTAL[@]}") - $(min "${B_TOTAL[@]}") ))
LARGER_SPREAD=$(( A_SPREAD > B_SPREAD ? A_SPREAD : B_SPREAD ))
ABS_DELTA=$(( DELTA_T < 0 ? -DELTA_T : DELTA_T ))

printf "\n"
if (( ABS_DELTA < LARGER_SPREAD )); then
	printf "${yellow}⚠ Verdict: NOISE — |delta| (%dms) < larger spread (%dms). Need more samples.${reset}\n" "$ABS_DELTA" "$LARGER_SPREAD"
elif (( DELTA_T < 0 )); then
	printf "${green}✓ Verdict: B is faster by %dms (median total)${reset}\n" "$ABS_DELTA"
else
	printf "${red}✗ Verdict: B is SLOWER by %dms (median total)${reset}\n" "$ABS_DELTA"
fi

printf "\n"
info "REF_A: $REF_A ($SHA_A)"
info "REF_B: $REF_B ($SHA_B)"
info "Samples: $RUNS per side, interleave=$INTERLEAVE"
if [[ "$KEEP_BINS" == "1" ]]; then
	info "Binaries kept: $BIN_A, $BIN_B"
fi
