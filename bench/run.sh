#!/usr/bin/env bash
set -euo pipefail

# ─── LPM Benchmark Suite ─────────────────────────────────────────────────────
#
# Phase 34.3: benchmarks are organized into three measurement classes:
#
#   wall-clock    — command + shell + destructive setup. Includes rm -rf,
#                   cache wipes, and process overhead. Represents real user-
#                   visible latency including orchestration.
#
#   command-only  — binary invocation on an already-prepared fixture. No
#                   destructive cleanup in the timed region. Isolates the
#                   binary's own cost from harness overhead.
#
#   engine        — JSON per-stage timing from `lpm install --json`.
#                   Internal resolve/fetch/link/total. LPM-only.
#
# Usage:
#   ./bench/run.sh                     # Run all benchmarks
#   ./bench/run.sh cold-install        # Full-round cold (wipes INSIDE timer)
#   ./bench/run.sh cold-install-clean  # Equal-footing cold (wipes OUTSIDE)
#   ./bench/run.sh warm-install
#   ./bench/run.sh up-to-date
#   ./bench/run.sh command-only        # Phase 34.3: command-only class
#   ./bench/run.sh script-overhead
#   ./bench/run.sh builtin-tools
#   ./bench/run.sh lpm-stages          # Engine class
#   ./bench/run.sh fetch-breakdown     # Phase 38 P0: cold-fetch sub-stages

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$BENCH_DIR/project"

# ─── Helpers ──────────────────────────────────────────────────────────────────

bold="\033[1m"
dim="\033[2m"
reset="\033[0m"
green="\033[32m"
yellow="\033[33m"
cyan="\033[36m"

# Prefer the source tree binary over whatever `lpm` is on PATH.
# This prevents measuring an old installed version instead of the local build.
# Allow explicit override so the same harness can compare two binaries.
LOCAL_BIN="$BENCH_DIR/../target/release/lpm-rs"
if [[ -n "${LPM_BIN:-}" ]]; then
	printf "${dim}Using overridden binary: %s${reset}\n" "$LPM_BIN"
elif [[ -x "$LOCAL_BIN" ]]; then
	LPM_BIN="$LOCAL_BIN"
	printf "${dim}Using local binary: %s${reset}\n" "$LOCAL_BIN"
elif command -v lpm &>/dev/null; then
	LPM_BIN="lpm"
	printf "${yellow}⚠ Using PATH binary: $(which lpm) — build with 'cargo build --release' for local binary${reset}\n"
else
	LPM_BIN=""
fi
RUNS="${RUNS:-3}"

header() { printf "\n${bold}${cyan}▸ %s${reset}\n" "$1"; }
label()  { printf "  ${dim}%-15s${reset}" "$1"; }
result() { printf " ${bold}%s${reset}\n" "$1"; }

# Run a command N times, return median wall-clock ms
median_ms() {
	local cmd="$1"
	local times=()

	for i in $(seq 1 $RUNS); do
		local start=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
		eval "$cmd" > /dev/null 2>&1
		local end=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
		times+=($((end - start)))
	done

	# Sort and pick median
	IFS=$'\n' sorted=($(sort -n <<< "${times[*]}")); unset IFS
	echo "${sorted[$((RUNS / 2))]}"
}

# Like median_ms, but the setup step runs BEFORE each iteration OUTSIDE the
# timed region. Used by the "equal footing" cold-install-clean bench so that
# per-tool global cache/store wipes don't get charged to install speed.
median_ms_with_setup() {
	local setup="$1"  # per-iteration prep, NOT timed
	local cmd="$2"    # timed
	local times=()

	for i in $(seq 1 $RUNS); do
		eval "$setup" > /dev/null 2>&1
		local start=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
		eval "$cmd" > /dev/null 2>&1
		local end=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
		times+=($((end - start)))
	done

	IFS=$'\n' sorted=($(sort -n <<< "${times[*]}")); unset IFS
	echo "${sorted[$((RUNS / 2))]}"
}

# Paired A/B with interleaved run order. Per iteration, both commands run
# with the same setup-reset between them; the order alternates each
# iteration so neither gets a systematic CDN-warmth advantage. Returns
# two medians "median_a median_b" over RUNS samples each.
#
# Phase 39 P0 use case: compare `lpm install` in default mode vs with
# Phase-38-disabled mode (`LPM_STREAM_FETCH=0 LPM_SPEC_FETCH=0`) inside
# one bench invocation so CDN state can't confound the delta.
median_ms_ab_with_setup() {
	local setup="$1"
	local cmd_a="$2"
	local cmd_b="$3"
	local times_a=() times_b=()

	for i in $(seq 1 $RUNS); do
		local run_a_first=$(( i % 2 == 1 ))

		if (( run_a_first )); then
			eval "$setup" > /dev/null 2>&1
			local a_start=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
			eval "$cmd_a" > /dev/null 2>&1
			local a_end=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
			times_a+=($((a_end - a_start)))

			eval "$setup" > /dev/null 2>&1
			local b_start=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
			eval "$cmd_b" > /dev/null 2>&1
			local b_end=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
			times_b+=($((b_end - b_start)))
		else
			eval "$setup" > /dev/null 2>&1
			local b_start=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
			eval "$cmd_b" > /dev/null 2>&1
			local b_end=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
			times_b+=($((b_end - b_start)))

			eval "$setup" > /dev/null 2>&1
			local a_start=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
			eval "$cmd_a" > /dev/null 2>&1
			local a_end=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
			times_a+=($((a_end - a_start)))
		fi
	done

	local mid=$((RUNS / 2))
	local sorted_a sorted_b
	sorted_a=($(printf '%s\n' "${times_a[@]}" | sort -n))
	sorted_b=($(printf '%s\n' "${times_b[@]}" | sort -n))
	echo "${sorted_a[$mid]} ${sorted_b[$mid]}"
}

check_tool() {
	if ! command -v "$1" &>/dev/null; then
		printf "  ${yellow}⚠ %s not found, skipping${reset}\n" "$1"
		return 1
	fi
	return 0
}

# ─── Cold Install ─────────────────────────────────────────────────────────────

bench_cold_install() {
	header "Cold Install [wall-clock] (17 direct deps → 51 packages, no cache/lockfile)"

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work"
	cp "$PROJECT_DIR/package.json" "$work/"

	local ms

	# --- npm ---
	if check_tool npm; then
		cd "$work"
		rm -rf node_modules package-lock.json
		npm cache clean --force > /dev/null 2>&1
		ms=$(median_ms "cd $work && rm -rf node_modules package-lock.json && npm cache clean --force 2>/dev/null && npm install --ignore-scripts")
		label "npm"; result "${ms}ms"
	fi

	# --- pnpm ---
	if check_tool pnpm; then
		cd "$work"
		rm -rf node_modules pnpm-lock.yaml
		ms=$(median_ms "cd $work && rm -rf node_modules pnpm-lock.yaml && pnpm store prune 2>/dev/null && rm -rf \$(pnpm store path 2>/dev/null) 2>/dev/null && pnpm install --ignore-scripts")
		label "pnpm"; result "${ms}ms"
	fi

	# --- bun ---
	if check_tool bun; then
		cd "$work"
		rm -rf node_modules bun.lockb
		ms=$(median_ms "cd $work && rm -rf node_modules bun.lockb ~/.bun/install/cache 2>/dev/null && bun install --ignore-scripts")
		label "bun"; result "${ms}ms"
	fi

	# --- lpm ---
	if [[ -n "$LPM_BIN" ]]; then
		cd "$work"
		rm -rf node_modules lpm.lock lpm.lockb
		ms=$(median_ms "cd $work && rm -rf node_modules lpm.lock lpm.lockb ~/.lpm/cache ~/.lpm/store 2>/dev/null && $LPM_BIN install --allow-new")
		label "lpm"; result "${ms}ms"
	fi

	rm -rf "$work"
}

# ─── Cold Install (Clean / Equal Footing) ─────────────────────────────────────
#
# 2026-04-14: empirical measurement confirmed that the per-iteration `rm -rf`
# of each tool's global cache charges ~700ms of syscall time to that tool's
# "cold install" number. LPM wipes two paths (~/.lpm/cache + ~/.lpm/store);
# bun wipes one; npm/pnpm wipe their own equivalents. That asymmetric wipe
# cost was the dominant term in the lpm-vs-bun wall-clock gap, not engine
# speed. See 37-rust-client-RUNNER-VISION-phase-a-worker-batch.md Step 5
# commentary for the measurements.
#
# This benchmark runs the exact same tools + fixture as `cold-install`, but
# moves the wipe OUTSIDE the timed region. The result is a true
# "install-command-only wall-clock" that is apples-to-apples across tools.
#
# Keep `cold-install` too — it's the full round-trip number Phase 32
# guardrails point at, and some users genuinely care about the
# wipe+install loop (e.g. CI fresh-clone cold start).

bench_cold_install_clean() {
	header "Cold Install [wall-clock, equal-footing — wipes OUTSIDE timer] (17 direct deps → 51 packages)"

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work"
	cp "$PROJECT_DIR/package.json" "$work/"

	local ms

	# --- npm ---
	if check_tool npm; then
		ms=$(median_ms_with_setup \
			"cd $work && rm -rf node_modules package-lock.json && npm cache clean --force" \
			"cd $work && npm install --ignore-scripts")
		label "npm"; result "${ms}ms"
	fi

	# --- pnpm ---
	if check_tool pnpm; then
		ms=$(median_ms_with_setup \
			"cd $work && rm -rf node_modules pnpm-lock.yaml && pnpm store prune 2>/dev/null && rm -rf \$(pnpm store path 2>/dev/null)" \
			"cd $work && pnpm install --ignore-scripts")
		label "pnpm"; result "${ms}ms"
	fi

	# --- bun ---
	if check_tool bun; then
		ms=$(median_ms_with_setup \
			"cd $work && rm -rf node_modules bun.lockb ~/.bun/install/cache" \
			"cd $work && bun install --ignore-scripts")
		label "bun"; result "${ms}ms"
	fi

	# --- lpm ---
	#
	# Phase 39 P0: A/B legacy (Phase-38 paths disabled) vs default (Phase-38
	# paths on). Runs both in the same session with alternating order per
	# iteration so CDN state balances out. Without this, defaults-only
	# numbers can't be compared against historic pre-P38 baselines inside
	# one invocation.
	if [[ -n "$LPM_BIN" ]]; then
		read ms_default ms_legacy <<< "$(median_ms_ab_with_setup \
			"cd $work && rm -rf node_modules lpm.lock lpm.lockb ~/.lpm/cache ~/.lpm/store" \
			"cd $work && $LPM_BIN install --allow-new" \
			"cd $work && LPM_STREAM_FETCH=0 LPM_SPEC_FETCH=0 $LPM_BIN install --allow-new")"
		label "lpm (default)"; result "${ms_default}ms"
		label "lpm (legacy)";  result "${ms_legacy}ms"
	fi

	rm -rf "$work"
}

# ─── Warm Install ─────────────────────────────────────────────────────────────

bench_warm_install() {
	header "Warm Install [wall-clock] (17 direct deps → 51 packages, lockfile + cache)"

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work"
	cp "$PROJECT_DIR/package.json" "$work/"

	local ms

	# --- npm ---
	if check_tool npm; then
		cd "$work"
		rm -rf node_modules package-lock.json
		npm install --ignore-scripts > /dev/null 2>&1  # generate lockfile
		rm -rf node_modules
		ms=$(median_ms "cd $work && rm -rf node_modules && npm install --ignore-scripts")
		label "npm"; result "${ms}ms"
	fi

	# --- pnpm ---
	if check_tool pnpm; then
		cd "$work"
		rm -rf node_modules pnpm-lock.yaml
		pnpm install --ignore-scripts > /dev/null 2>&1
		rm -rf node_modules
		ms=$(median_ms "cd $work && rm -rf node_modules && pnpm install --ignore-scripts")
		label "pnpm"; result "${ms}ms"
	fi

	# --- bun ---
	if check_tool bun; then
		cd "$work"
		rm -rf node_modules bun.lockb
		bun install --ignore-scripts > /dev/null 2>&1
		rm -rf node_modules
		ms=$(median_ms "cd $work && rm -rf node_modules && bun install --ignore-scripts")
		label "bun"; result "${ms}ms"
	fi

	# --- lpm ---
	if [[ -n "$LPM_BIN" ]]; then
		cd "$work"
		rm -rf node_modules lpm.lock lpm.lockb
		$LPM_BIN install --allow-new > /dev/null 2>&1
		rm -rf node_modules
		ms=$(median_ms "cd $work && rm -rf node_modules && $LPM_BIN install --allow-new")
		label "lpm"; result "${ms}ms"
	fi

	rm -rf "$work"
}

# ─── Up-to-Date Install ──────────────────────────────────────────────────────

bench_up_to_date() {
	header "Up-to-Date Install [wall-clock] (17 direct deps → 51 packages, nothing changed)"

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work"
	cp "$PROJECT_DIR/package.json" "$work/"

	local ms

	# --- npm ---
	if check_tool npm; then
		cd "$work"
		rm -rf node_modules package-lock.json
		npm install --ignore-scripts > /dev/null 2>&1  # initial install
		ms=$(median_ms "cd $work && npm install --ignore-scripts")
		label "npm"; result "${ms}ms"
	fi

	# --- pnpm ---
	if check_tool pnpm; then
		cd "$work"
		rm -rf node_modules pnpm-lock.yaml
		pnpm install --ignore-scripts > /dev/null 2>&1
		ms=$(median_ms "cd $work && pnpm install --ignore-scripts")
		label "pnpm"; result "${ms}ms"
	fi

	# --- bun ---
	if check_tool bun; then
		cd "$work"
		rm -rf node_modules bun.lockb
		bun install --ignore-scripts > /dev/null 2>&1
		ms=$(median_ms "cd $work && bun install --ignore-scripts")
		label "bun"; result "${ms}ms"
	fi

	# --- lpm ---
	if [[ -n "$LPM_BIN" ]]; then
		cd "$work"
		rm -rf node_modules lpm.lock lpm.lockb
		$LPM_BIN install --allow-new > /dev/null 2>&1  # initial install
		ms=$(median_ms "cd $work && $LPM_BIN install --allow-new")
		label "lpm"; result "${ms}ms"
	fi

	rm -rf "$work"
}

# ─── Command-Only (Phase 34.3) ───────────────────────────────────────────────
#
# Measures binary invocation on an ALREADY-PREPARED fixture. No destructive
# cleanup inside the timed region. Isolates binary startup + install logic
# from shell orchestration overhead.
#
# Only measures LPM — cross-tool command-only comparison is out of scope
# because other PMs don't expose an equivalent "already installed" fast path
# with structured timing.

bench_command_only() {
	header "Command-Only [command-only] (prepared fixture, LPM only)"

	if [[ -z "$LPM_BIN" ]]; then
		printf "  ${yellow}⚠ no LPM binary, skipping${reset}\n"
		return
	fi

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work"
	cp "$PROJECT_DIR/package.json" "$work/"

	# Prepare fixture — fail closed if setup fails (no || true).
	(cd "$work" && rm -rf node_modules lpm.lock lpm.lockb && $LPM_BIN install --allow-new >/dev/null 2>&1)

	# Up-to-date: everything in place, binary does the hash check and exits.
	local ms
	ms=$(median_ms "cd $work && $LPM_BIN install")
	label "up-to-date"; result "${ms}ms"

	# Warm: lockfile + store intact, node_modules missing.
	# The rm -rf is done OUTSIDE the timed region (in setup), then
	# only `lpm install` is timed — true command-only semantics.
	# median_ms runs $RUNS iterations; each iteration needs node_modules
	# removed again, so we use a two-step approach: prepare once, then
	# time N individual runs with setup between them.
	local times=()
	for i in $(seq 1 $RUNS); do
		rm -rf "$work/node_modules"
		local start=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
		(cd "$work" && $LPM_BIN install --allow-new) > /dev/null 2>&1
		local end=$(($(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))') / 1000000))
		times+=($((end - start)))
	done
	IFS=$'\n' sorted=($(sort -n <<< "${times[*]}")); unset IFS
	ms="${sorted[$((RUNS / 2))]}"
	label "warm"; result "${ms}ms"

	rm -rf "$work"
}

# ─── Script Overhead ──────────────────────────────────────────────────────────

bench_script_overhead() {
	header "Script Overhead (run 'true' via each package manager)"

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work"
	cp "$PROJECT_DIR/package.json" "$work/"
	cd "$work"
	npm install --ignore-scripts > /dev/null 2>&1

	local ms

	if check_tool npm; then
		ms=$(median_ms "cd $work && npm run noop")
		label "npm"; result "${ms}ms"
	fi

	if check_tool pnpm; then
		ms=$(median_ms "cd $work && pnpm run noop")
		label "pnpm"; result "${ms}ms"
	fi

	if check_tool bun; then
		ms=$(median_ms "cd $work && bun run noop")
		label "bun"; result "${ms}ms"
	fi

	if [[ -n "$LPM_BIN" ]]; then
		ms=$(median_ms "cd $work && $LPM_BIN run noop")
		label "lpm"; result "${ms}ms"
	fi

	rm -rf "$work"
}

# ─── Built-in Tools ──────────────────────────────────────────────────────────

bench_builtin_tools() {
	header "Built-in Tools (lint + fmt on a real project)"

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work/src"
	cp "$PROJECT_DIR/package.json" "$work/"

	# Generate some JS files to lint/format
	for i in $(seq 1 20); do
		cat > "$work/src/module${i}.js" << 'JSEOF'
const express = require("express")
const app = express()
app.get("/", (req, res) => { res.json({ status: "ok", time: Date.now() }) })
const unused = 42
module.exports = app
JSEOF
	done

	cd "$work"
	npm install --ignore-scripts > /dev/null 2>&1

	local ms

	header "  lint (oxlint)"
	if [[ -n "$LPM_BIN" ]]; then
		ms=$(median_ms "cd $work && $LPM_BIN lint")
		label "lpm lint"; result "${ms}ms"
	fi
	if check_tool npx; then
		ms=$(median_ms "cd $work && npx oxlint src/")
		label "npx oxlint"; result "${ms}ms"
	fi

	header "  fmt (biome)"
	if [[ -n "$LPM_BIN" ]]; then
		ms=$(median_ms "cd $work && $LPM_BIN fmt")
		label "lpm fmt"; result "${ms}ms"
	fi
	if check_tool npx; then
		ms=$(median_ms "cd $work && npx @biomejs/biome format src/")
		label "npx biome"; result "${ms}ms"
	fi

	rm -rf "$work"
}

# ─── LPM Per-Stage Timings ───────────────────────────────────────────────────
#
# Cross-tool benchmarks above measure wall-clock only — that's the right
# methodology for comparing lpm vs npm vs pnpm vs bun. This section captures
# LPM's internal per-stage breakdown (resolve / fetch / link / total) by
# parsing `lpm install --json` output. Useful for tracking per-stage
# regressions inside LPM that wall-clock alone might hide.
#
# Phase 32 guardrail #3: install-path features must not regress these numbers.

# Run `lpm install --json` and extract timing.{resolve_ms,fetch_ms,link_ms,total_ms}.
# Outputs four space-separated integers: "resolve fetch link total"
#
# The JSON output is piped to Python via stdin (NOT interpolated into the Python
# source) so that arbitrary content in the JSON — including embedded quotes,
# triple-quotes, or backslash sequences — cannot break the parser. The Python
# program itself is a fixed single-quoted shell string with no expansion.
lpm_timing_capture() {
	local work="$1"
	local out
	out=$(cd "$work" && $LPM_BIN install --allow-new --json 2>/dev/null) || return 1
	# Use python for portable JSON parsing — jq isn't guaranteed to be installed.
	# `printf '%s'` avoids echo's backslash and leading-dash quirks.
	printf '%s' "$out" | python3 -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    t = data.get("timing", {})
    print(t.get("resolve_ms", 0), t.get("fetch_ms", 0), t.get("link_ms", 0), t.get("total_ms", 0))
except (json.JSONDecodeError, AttributeError):
    sys.exit(1)
' 2>/dev/null
}

# Median of N runs for each timing field. Outputs "resolve fetch link total" medians.
#
# Correctness note (2026-04-16): the previous implementation used
# `IFS=$'\n' s_r=($(sort -n <<< "${arr[*]}"))`, which does NOT actually
# sort. Empirically with `arr=(17 23 19 5 99)` it yields `[17 23 19 5 99]`
# unchanged — the prefix-IFS is not applied when `"${arr[*]}"` is expanded
# into the command line, so the herestring receives space-separated
# values on a single line and `sort -n` has nothing to reorder. All
# pre-Phase-38 `lpm-stages` numbers (including the Phase A 711 ms cold
# engine baseline) were therefore "middle-run-in-insertion-order", not
# true medians. For low-variance runs the difference is small; for anything
# noisy it was silently wrong. Fixed here ahead of Phase 38 P1 baseline
# capture so both the pre-P1 and post-P1 numbers use correct medians.
lpm_timing_median() {
	local work="$1"
	local setup="$2" # shell command to reset state between runs
	local resolves=() fetches=() links=() totals=()

	for i in $(seq 1 $RUNS); do
		eval "$setup" >/dev/null 2>&1
		local timing
		timing=$(lpm_timing_capture "$work") || return 1
		read -r r f l t <<< "$timing"
		resolves+=("$r")
		fetches+=("$f")
		links+=("$l")
		totals+=("$t")
	done

	# Sort each array and pick the middle element. `printf '%s\n'` feeds
	# one value per line so `sort -n` actually reorders.
	local mid=$((RUNS / 2))
	local s_r s_f s_l s_t
	s_r=($(printf '%s\n' "${resolves[@]}" | sort -n))
	s_f=($(printf '%s\n' "${fetches[@]}"  | sort -n))
	s_l=($(printf '%s\n' "${links[@]}"    | sort -n))
	s_t=($(printf '%s\n' "${totals[@]}"   | sort -n))

	echo "${s_r[$mid]} ${s_f[$mid]} ${s_l[$mid]} ${s_t[$mid]}"
}

bench_lpm_per_stage() {
	header "LPM Per-Stage Timings [engine] (resolve / fetch / link / total — milliseconds)"

	if [[ -z "$LPM_BIN" ]]; then
		printf "  ${yellow}⚠ no LPM binary, skipping${reset}\n"
		return
	fi

	if ! command -v python3 &>/dev/null; then
		printf "  ${yellow}⚠ python3 required for JSON parsing, skipping${reset}\n"
		return
	fi

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work"
	cp "$PROJECT_DIR/package.json" "$work/"

	local timings

	# --- Cold: wipe everything including global store ---
	# DESTRUCTIVE — wipes ~/.lpm/cache and ~/.lpm/store. Skipped unless
	# LPM_BENCH_ALLOW_WIPE=1 is set, to prevent accidental cache loss.
	if [[ "${LPM_BENCH_ALLOW_WIPE:-0}" == "1" ]]; then
		timings=$(lpm_timing_median "$work" \
			"cd $work && rm -rf node_modules lpm.lock lpm.lockb ~/.lpm/cache ~/.lpm/store 2>/dev/null")
		if [[ -n "$timings" ]]; then
			read -r r f l t <<< "$timings"
			label "cold"; printf " ${bold}resolve %sms  fetch %sms  link %sms  total %sms${reset}\n" "$r" "$f" "$l" "$t"
		fi
	else
		printf "  ${dim}cold${reset}        ${dim}skipped (set LPM_BENCH_ALLOW_WIPE=1 to enable — wipes ~/.lpm/cache and ~/.lpm/store)${reset}\n"
	fi

	# --- Warm: keep store + lockfile, wipe node_modules ---
	# Generate a lockfile first (one-time, not measured)
	(cd "$work" && rm -rf node_modules lpm.lock lpm.lockb && $LPM_BIN install --allow-new >/dev/null 2>&1) || true
	timings=$(lpm_timing_median "$work" "cd $work && rm -rf node_modules")
	if [[ -n "$timings" ]]; then
		read -r r f l t <<< "$timings"
		label "warm"; printf " ${bold}resolve %sms  fetch %sms  link %sms  total %sms${reset}\n" "$r" "$f" "$l" "$t"
	fi

	# --- Up-to-date: nothing changed, fast path ---
	timings=$(lpm_timing_median "$work" "true")
	if [[ -n "$timings" ]]; then
		read -r r f l t <<< "$timings"
		label "up-to-date"; printf " ${bold}resolve %sms  fetch %sms  link %sms  total %sms${reset}\n" "$r" "$f" "$l" "$t"
	fi

	rm -rf "$work"
}

# ─── LPM Fetch Breakdown (Phase 38 P0) ───────────────────────────────────────
#
# Splits the lumpy `fetch_ms` number into six real sub-stages so follow-up
# Phase 38 work has a principled ruler. Only meaningful COLD — warm/up-to-date
# never enter the download pool, so the breakdown is zero everywhere.
#
# Fields (all whole milliseconds, per the `FetchBreakdown` contract in
# `lpm-cli/src/commands/install.rs`):
#
#   task_count   number of non-cached packages downloaded
#   queue_wait   sum/max time tasks sat waiting for a semaphore permit
#   download     sum/max time in `fetch_tarball_to_file`
#   integrity    sum/max time in SRI compare + optional re-verify
#   extract      sum/max time in `extract_tarball_from_file`
#   security     sum/max time in `analyze_package` + `.lpm-security.json` write
#   finalize     sum/max time in `.integrity` write + atomic rename
#
# Sum = cumulative across all parallel tasks (useful for CPU/IO attribution).
# Max = single slowest package (useful for tail-latency analysis).
#
# DESTRUCTIVE: wipes ~/.lpm/cache and ~/.lpm/store between runs. Gated by
# LPM_BENCH_ALLOW_WIPE=1 to prevent accidental cache loss.

# Run `lpm install --json` and extract the `timing.fetch_breakdown` sub-fields.
# Outputs 13 space-separated integers in a fixed column order so shell can
# read them with a single `read`:
#
#   count qw_sum qw_max dl_sum dl_max in_sum in_max ex_sum ex_max se_sum se_max fi_sum fi_max
lpm_fetch_breakdown_capture() {
	local work="$1"
	local out
	out=$(cd "$work" && $LPM_BIN install --allow-new --json 2>/dev/null) || return 1
	printf '%s' "$out" | python3 -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    fb = data.get("timing", {}).get("fetch_breakdown", {})
    def pair(key):
        stage = fb.get(key, {}) or {}
        return stage.get("sum_ms", 0), stage.get("max_ms", 0)
    count = fb.get("task_count", 0)
    qw = pair("queue_wait")
    dl = pair("download")
    ig = pair("integrity")
    ex = pair("extract")
    se = pair("security")
    fi = pair("finalize")
    print(count,
          qw[0], qw[1], dl[0], dl[1], ig[0], ig[1],
          ex[0], ex[1], se[0], se[1], fi[0], fi[1])
except (json.JSONDecodeError, AttributeError):
    sys.exit(1)
' 2>/dev/null
}

# Median of N runs for every fetch_breakdown field. Outputs one line of 13
# space-separated medians in the same column order as `lpm_fetch_breakdown_capture`.
lpm_fetch_breakdown_median() {
	local work="$1"
	local setup="$2"
	# 13 parallel arrays — one per output column.
	local counts=() qw_s=() qw_m=() dl_s=() dl_m=() ig_s=() ig_m=()
	local ex_s=() ex_m=() se_s=() se_m=() fi_s=() fi_m=()

	for i in $(seq 1 $RUNS); do
		eval "$setup" >/dev/null 2>&1
		local line
		line=$(lpm_fetch_breakdown_capture "$work") || return 1
		# shellcheck disable=SC2162  # intentional: we want whitespace-split, not line
		read c qw1 qw2 dl1 dl2 ig1 ig2 ex1 ex2 se1 se2 fi1 fi2 <<< "$line"
		counts+=("$c")
		qw_s+=("$qw1"); qw_m+=("$qw2")
		dl_s+=("$dl1"); dl_m+=("$dl2")
		ig_s+=("$ig1"); ig_m+=("$ig2")
		ex_s+=("$ex1"); ex_m+=("$ex2")
		se_s+=("$se1"); se_m+=("$se2")
		fi_s+=("$fi1"); fi_m+=("$fi2")
	done

	local mid=$((RUNS / 2))
	# Correct median helper — puts one value per line via `printf '%s\n'`
	# so `sort -n` actually sorts. The `lpm_timing_median` pattern above
	# uses `<<< "${array[*]}"` which bash's herestring treats as a single
	# line regardless of IFS (preserves literal content, never interprets
	# `\n`), so the values never sort. See comment in `lpm_timing_median`
	# for the pre-existing bug flag.
	median_of() {
		local name=$1[@]
		local values=("${!name}")
		local sorted
		sorted=($(printf '%s\n' "${values[@]}" | sort -n))
		echo "${sorted[$mid]}"
	}

	echo "$(median_of counts) \
$(median_of qw_s) $(median_of qw_m) \
$(median_of dl_s) $(median_of dl_m) \
$(median_of ig_s) $(median_of ig_m) \
$(median_of ex_s) $(median_of ex_m) \
$(median_of se_s) $(median_of se_m) \
$(median_of fi_s) $(median_of fi_m)"
}

bench_lpm_fetch_breakdown() {
	header "LPM Fetch Breakdown [engine, cold only] (queue / download / integrity / extract / security / finalize — ms)"

	if [[ -z "$LPM_BIN" ]]; then
		printf "  ${yellow}⚠ no LPM binary, skipping${reset}\n"
		return
	fi

	if ! command -v python3 &>/dev/null; then
		printf "  ${yellow}⚠ python3 required for JSON parsing, skipping${reset}\n"
		return
	fi

	if [[ "${LPM_BENCH_ALLOW_WIPE:-0}" != "1" ]]; then
		printf "  ${dim}skipped — requires LPM_BENCH_ALLOW_WIPE=1 (wipes ~/.lpm/cache + ~/.lpm/store)${reset}\n"
		return
	fi

	local work="$BENCH_DIR/.work"
	rm -rf "$work"
	mkdir -p "$work"
	cp "$PROJECT_DIR/package.json" "$work/"

	local medians
	medians=$(lpm_fetch_breakdown_median "$work" \
		"cd $work && rm -rf node_modules lpm.lock lpm.lockb ~/.lpm/cache ~/.lpm/store 2>/dev/null")
	if [[ -z "$medians" ]]; then
		printf "  ${yellow}⚠ failed to capture fetch breakdown — is --json emitting fetch_breakdown?${reset}\n"
		rm -rf "$work"
		return
	fi

	# shellcheck disable=SC2162
	read count qw_s qw_m dl_s dl_m ig_s ig_m ex_s ex_m se_s se_m fi_s fi_m <<< "$medians"

	printf "  ${bold}task_count${reset}  ${count}\n"
	printf "  ${bold}%-10s${reset}  sum=%-6s  max=%-6s\n" "queue_wait" "${qw_s}ms" "${qw_m}ms"
	printf "  ${bold}%-10s${reset}  sum=%-6s  max=%-6s\n" "download"   "${dl_s}ms" "${dl_m}ms"
	printf "  ${bold}%-10s${reset}  sum=%-6s  max=%-6s\n" "integrity"  "${ig_s}ms" "${ig_m}ms"
	printf "  ${bold}%-10s${reset}  sum=%-6s  max=%-6s\n" "extract"    "${ex_s}ms" "${ex_m}ms"
	printf "  ${bold}%-10s${reset}  sum=%-6s  max=%-6s\n" "security"   "${se_s}ms" "${se_m}ms"
	printf "  ${bold}%-10s${reset}  sum=%-6s  max=%-6s\n" "finalize"   "${fi_s}ms" "${fi_m}ms"

	rm -rf "$work"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

printf "${bold}LPM Benchmark Suite${reset}\n"
printf "${dim}%s runs per benchmark, reporting median${reset}\n" "$RUNS"
printf "${dim}Machine: $(uname -m), $(uname -s) $(uname -r)${reset}\n"

target="${1:-all}"

case "$target" in
	cold-install)       bench_cold_install ;;
	cold-install-clean) bench_cold_install_clean ;;
	warm-install)       bench_warm_install ;;
	up-to-date)         bench_up_to_date ;;
	command-only)       bench_command_only ;;
	script-overhead)    bench_script_overhead ;;
	builtin-tools)      bench_builtin_tools ;;
	lpm-stages)         bench_lpm_per_stage ;;
	fetch-breakdown)    bench_lpm_fetch_breakdown ;;
	all)
		bench_cold_install
		bench_cold_install_clean
		bench_warm_install
		bench_up_to_date
		bench_command_only
		bench_script_overhead
		bench_builtin_tools
		bench_lpm_per_stage
		bench_lpm_fetch_breakdown
		;;
	*)
		echo "Unknown benchmark: $target"
		echo "Available: cold-install, cold-install-clean, warm-install, up-to-date, command-only, script-overhead, builtin-tools, lpm-stages, fetch-breakdown, all"
		exit 1
		;;
esac

printf "\n${dim}Done.${reset}\n"
