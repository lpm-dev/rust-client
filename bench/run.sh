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
label()  { printf "  ${dim}%-12s${reset}" "$1"; }
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
	if [[ -n "$LPM_BIN" ]]; then
		ms=$(median_ms_with_setup \
			"cd $work && rm -rf node_modules lpm.lock lpm.lockb ~/.lpm/cache ~/.lpm/store" \
			"cd $work && $LPM_BIN install --allow-new")
		label "lpm"; result "${ms}ms"
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

	# Sort each array and pick the middle element
	local mid=$((RUNS / 2))
	IFS=$'\n' s_r=($(sort -n <<< "${resolves[*]}")); unset IFS
	IFS=$'\n' s_f=($(sort -n <<< "${fetches[*]}")); unset IFS
	IFS=$'\n' s_l=($(sort -n <<< "${links[*]}")); unset IFS
	IFS=$'\n' s_t=($(sort -n <<< "${totals[*]}")); unset IFS

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
	all)
		bench_cold_install
		bench_cold_install_clean
		bench_warm_install
		bench_up_to_date
		bench_command_only
		bench_script_overhead
		bench_builtin_tools
		bench_lpm_per_stage
		;;
	*)
		echo "Unknown benchmark: $target"
		echo "Available: cold-install, cold-install-clean, warm-install, up-to-date, command-only, script-overhead, builtin-tools, lpm-stages, all"
		exit 1
		;;
esac

printf "\n${dim}Done.${reset}\n"
