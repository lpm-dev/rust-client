#!/usr/bin/env bash
set -euo pipefail

# ─── LPM Benchmark Suite ─────────────────────────────────────────────────────
#
# Usage:
#   ./bench/run.sh                  # Run all benchmarks
#   ./bench/run.sh cold-install     # Run specific benchmark
#   ./bench/run.sh warm-install
#   ./bench/run.sh script-overhead
#   ./bench/run.sh builtin-tools

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$BENCH_DIR/project"
RUNS=3

# ─── Helpers ──────────────────────────────────────────────────────────────────

bold="\033[1m"
dim="\033[2m"
reset="\033[0m"
green="\033[32m"
yellow="\033[33m"
cyan="\033[36m"

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

check_tool() {
	if ! command -v "$1" &>/dev/null; then
		printf "  ${yellow}⚠ %s not found, skipping${reset}\n" "$1"
		return 1
	fi
	return 0
}

# ─── Cold Install ─────────────────────────────────────────────────────────────

bench_cold_install() {
	header "Cold Install (17 direct deps → 51 packages, no cache/lockfile)"

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
	if check_tool lpm; then
		cd "$work"
		rm -rf node_modules lpm.lock lpm.lockb
		ms=$(median_ms "cd $work && rm -rf node_modules lpm.lock lpm.lockb ~/.lpm/cache ~/.lpm/store 2>/dev/null && lpm install --allow-new")
		label "lpm"; result "${ms}ms"
	fi

	rm -rf "$work"
}

# ─── Warm Install ─────────────────────────────────────────────────────────────

bench_warm_install() {
	header "Warm Install (17 direct deps → 51 packages, lockfile + cache)"

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
	if check_tool lpm; then
		cd "$work"
		rm -rf node_modules lpm.lock lpm.lockb
		lpm install --allow-new > /dev/null 2>&1
		rm -rf node_modules
		ms=$(median_ms "cd $work && rm -rf node_modules && lpm install --allow-new")
		label "lpm"; result "${ms}ms"
	fi

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

	if check_tool lpm; then
		ms=$(median_ms "cd $work && lpm run noop")
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
	if check_tool lpm; then
		ms=$(median_ms "cd $work && lpm lint")
		label "lpm lint"; result "${ms}ms"
	fi
	if check_tool npx; then
		ms=$(median_ms "cd $work && npx oxlint src/")
		label "npx oxlint"; result "${ms}ms"
	fi

	header "  fmt (biome)"
	if check_tool lpm; then
		ms=$(median_ms "cd $work && lpm fmt")
		label "lpm fmt"; result "${ms}ms"
	fi
	if check_tool npx; then
		ms=$(median_ms "cd $work && npx @biomejs/biome format src/")
		label "npx biome"; result "${ms}ms"
	fi

	rm -rf "$work"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

printf "${bold}LPM Benchmark Suite${reset}\n"
printf "${dim}%s runs per benchmark, reporting median${reset}\n" "$RUNS"
printf "${dim}Machine: $(uname -m), $(uname -s) $(uname -r)${reset}\n"

target="${1:-all}"

case "$target" in
	cold-install)    bench_cold_install ;;
	warm-install)    bench_warm_install ;;
	script-overhead) bench_script_overhead ;;
	builtin-tools)   bench_builtin_tools ;;
	all)
		bench_cold_install
		bench_warm_install
		bench_script_overhead
		bench_builtin_tools
		;;
	*)
		echo "Unknown benchmark: $target"
		echo "Available: cold-install, warm-install, script-overhead, builtin-tools, all"
		exit 1
		;;
esac

printf "\n${dim}Done.${reset}\n"
