#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY_SCRIPT="$REPO_ROOT/bench/local-install-registry.py"

RUNS="${RUNS:-3}"
PACKAGES="${LPM_LOCAL_BENCH_PACKAGES:-96}"
ROOTS="${LPM_LOCAL_BENCH_ROOTS:-16}"
VERSIONS="${LPM_LOCAL_BENCH_VERSIONS:-32}"
TARBALL_KIB="${LPM_LOCAL_BENCH_TARBALL_KIB:-512}"
ROUTE="${LPM_LOCAL_BENCH_ROUTE:-proxy}"
STORE_VERSION="${LPM_STORE_VERSION:-v2}"

LOCAL_BIN="$REPO_ROOT/target/release/lpm-rs"
if [[ -n "${LPM_BIN:-}" ]]; then
	BIN="$LPM_BIN"
elif [[ -x "$LOCAL_BIN" ]]; then
	BIN="$LOCAL_BIN"
else
	BIN="lpm"
fi

if ! command -v python3 >/dev/null 2>&1; then
	echo "python3 is required" >&2
	exit 1
fi

case "$ROUTE" in
	proxy|custom) ;;
	*)
		echo "LPM_LOCAL_BENCH_ROUTE must be 'proxy' or 'custom' (got '$ROUTE')" >&2
		exit 1
		;;
esac
if [[ "$ROUTE" == "proxy" ]]; then
	ROUTE_MODE="proxy"
else
	ROUTE_MODE="direct"
fi

if [[ "$RUNS" -lt 1 ]]; then
	echo "RUNS must be >= 1" >&2
	exit 1
fi

if [[ -n "${BENCH_WORK_DIR:-}" ]]; then
	mkdir -p "$BENCH_WORK_DIR"
	WORK_ROOT="$(mktemp -d "$BENCH_WORK_DIR/local-install.XXXXXX")"
else
	WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/lpm-local-install.XXXXXX")"
fi

REGISTRY_PID=""
cleanup() {
	if [[ -n "$REGISTRY_PID" ]] && kill -0 "$REGISTRY_PID" >/dev/null 2>&1; then
		kill "$REGISTRY_PID" >/dev/null 2>&1 || true
		wait "$REGISTRY_PID" 2>/dev/null || true
	fi
	if [[ "${LPM_LOCAL_BENCH_KEEP_WORK:-0}" != "1" ]]; then
		rm -rf "$WORK_ROOT"
	else
		echo "kept work dir: $WORK_ROOT" >&2
	fi
}
trap cleanup EXIT

READY_FILE="$WORK_ROOT/registry-ready.json"
REGISTRY_LOG="$WORK_ROOT/registry.log"
python3 "$REGISTRY_SCRIPT" \
	--packages "$PACKAGES" \
	--roots "$ROOTS" \
	--versions "$VERSIONS" \
	--tarball-kib "$TARBALL_KIB" \
	--ready-file "$READY_FILE" \
	>"$REGISTRY_LOG" 2>&1 &
REGISTRY_PID="$!"

for _ in $(seq 1 100); do
	if [[ -s "$READY_FILE" ]]; then
		break
	fi
	if ! kill -0 "$REGISTRY_PID" >/dev/null 2>&1; then
		echo "local registry exited before becoming ready" >&2
		cat "$REGISTRY_LOG" >&2 || true
		exit 1
	fi
	sleep 0.05
done

if [[ ! -s "$READY_FILE" ]]; then
	echo "local registry did not become ready" >&2
	cat "$REGISTRY_LOG" >&2 || true
	exit 1
fi

REGISTRY_URL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["url"])' "$READY_FILE")"
TEMPLATE_DIR="$WORK_ROOT/template"
PROJECT_DIR="$WORK_ROOT/project"
RESULTS_DIR="$WORK_ROOT/results"
HOME_DIR="$WORK_ROOT/home"
mkdir -p "$TEMPLATE_DIR" "$RESULTS_DIR" "$HOME_DIR/.lpm"
python3 "$REGISTRY_SCRIPT" --write-project "$TEMPLATE_DIR/package.json" --roots "$ROOTS"
printf 'minimum-release-age-secs = 0\n' > "$HOME_DIR/.lpm/security-policy.toml"
if [[ "$ROUTE" == "custom" ]]; then
	printf 'registry=%s/\n' "$REGISTRY_URL" > "$TEMPLATE_DIR/.npmrc"
fi

bold="\033[1m"
dim="\033[2m"
reset="\033[0m"
cyan="\033[36m"

now_ms() {
	python3 -c 'import time; print(time.perf_counter_ns() // 1_000_000)'
}

reset_project() {
	rm -rf "$PROJECT_DIR"
	mkdir -p "$PROJECT_DIR"
	cp "$TEMPLATE_DIR/package.json" "$PROJECT_DIR/package.json"
	if [[ -f "$TEMPLATE_DIR/.npmrc" ]]; then
		cp "$TEMPLATE_DIR/.npmrc" "$PROJECT_DIR/.npmrc"
	fi
}

reset_lpm_home() {
	rm -rf "$HOME_DIR/.lpm/cache" "$HOME_DIR/.lpm/store" "$HOME_DIR/.lpm/global"
	mkdir -p "$HOME_DIR/.lpm"
	printf 'minimum-release-age-secs = 0\n' > "$HOME_DIR/.lpm/security-policy.toml"
}

make_cache_stale() {
	find "$HOME_DIR/.lpm/cache" -type f -exec touch -t 200001010000 {} + 2>/dev/null || true
}

poison_metadata_etags() {
	python3 - "$HOME_DIR/.lpm/cache/metadata" <<'PY'
import pathlib
import os
import re
import sys

cache_dir = pathlib.Path(sys.argv[1])
if not cache_dir.exists():
    raise SystemExit(0)

for path in cache_dir.iterdir():
    if not path.is_file():
        continue
    content = path.read_bytes()
    magic_end = content.find(b"\n")
    if magic_end < 0:
        continue
    magic = content[:magic_end + 1]
    match = re.fullmatch(rb"LPM-MD-V([0-9]+)\n", magic)
    if match is None:
        continue
    rest = content[magic_end + 1:]
    if int(match.group(1)) >= 4:
        freshness_end = rest.find(b"\n")
        if freshness_end < 0:
            continue
        prefix = magic + rest[:freshness_end + 1]
        rest = rest[freshness_end + 1:]
    else:
        prefix = magic
    etag_end = rest.find(b"\n")
    if etag_end < 0:
        continue
    timestamps = path.stat()
    path.write_bytes(prefix + b'"lpm-local-stale-bench"\n' + rest[etag_end + 1:])
    os.utime(path, ns=(timestamps.st_atime_ns, timestamps.st_mtime_ns))
PY
}

run_lpm_json() {
	local output_file="$1"
	local stderr_file="$2"
	shift 2
	local start end
	start="$(now_ms)"
	if ! (
		cd "$PROJECT_DIR"
		env \
		HOME="$HOME_DIR" \
		LPM_HOME="$HOME_DIR/.lpm" \
		XDG_CONFIG_HOME="$HOME_DIR/.config" \
		XDG_DATA_HOME="$HOME_DIR/.local/share" \
		XDG_CACHE_HOME="$HOME_DIR/.cache" \
		LPM_SECURITY_POLICY_PATH="$HOME_DIR/.lpm/security-policy.toml" \
		LPM_FORCE_FILE_AUTH=1 \
		LPM_FORCE_FILE_VAULT=1 \
		LPM_TEST_FAST_SCRYPT=1 \
		LPM_DISABLE_HOST_CLI_AUTH=1 \
		LPM_NO_UPDATE_CHECK=1 \
		LPM_STORE_VERSION="$STORE_VERSION" \
		LPM_NPM_ROUTE="$ROUTE_MODE" \
		NO_COLOR=1 \
		"$BIN" --registry "$REGISTRY_URL" --insecure install "$@" --json \
			>"$output_file" 2>"$stderr_file"
	); then
		echo "lpm install failed; stderr:" >&2
		cat "$stderr_file" >&2 || true
		echo "stdout:" >&2
		cat "$output_file" >&2 || true
		exit 1
	fi
	end="$(now_ms)"
	echo $((end - start))
}

scenario() {
	local name="$1"
	local setup="$2"
	shift 2
	local walls=()
	local files=()
	for i in $(seq 1 "$RUNS"); do
		eval "$setup"
		local out="$RESULTS_DIR/$name-$i.json"
		local err="$RESULTS_DIR/$name-$i.err"
		local wall
		wall="$(run_lpm_json "$out" "$err" "$@")"
		walls+=("$wall")
		files+=("$out")
	done
	print_summary "$name" "${walls[*]}" "${files[@]}"
}

print_summary() {
	local name="$1"
	local walls="$2"
	shift 2
	python3 - "$name" "$walls" "$@" <<'PY'
import json
import statistics
import sys

name = sys.argv[1]
walls = [int(v) for v in sys.argv[2].split()]
docs = [json.load(open(path, encoding="utf-8")) for path in sys.argv[3:]]

def median(values):
    values = sorted(int(v) for v in values)
    return int(statistics.median(values)) if values else 0

def timing_field(field):
    return median(doc.get("timing", {}).get(field, 0) for doc in docs)

print(
    f"  {name:<12} wall {median(walls):>5}ms  "
    f"resolve {timing_field('resolve_ms'):>5}ms  "
    f"fetch {timing_field('fetch_ms'):>5}ms  "
    f"link {timing_field('link_ms'):>5}ms  "
    f"total {timing_field('total_ms'):>5}ms"
)

if name == "fetch":
    latest = docs[len(docs) // 2].get("timing", {}).get("fetch_breakdown", {})
    def pair(key):
        stage = latest.get(key, {}) or {}
        return stage.get("sum_ms", 0), stage.get("max_ms", 0)
    print(f"    task_count {latest.get('task_count', 0)}")
    for key in ("queue_wait", "download", "integrity", "extract", "security", "finalize"):
        s, m = pair(key)
        print(f"    {key:<10} sum={s}ms max={m}ms")
PY
}

printf "${bold}LPM Local Install Benchmark${reset}\n"
printf "${dim}%s run(s), route=%s, store=%s, packages=%s, roots=%s, versions=%s, tarball=%sKiB${reset}\n" \
	"$RUNS" "$ROUTE" "$STORE_VERSION" "$PACKAGES" "$ROOTS" "$VERSIONS" "$TARBALL_KIB"
printf "${dim}binary: %s${reset}\n" "$BIN"
printf "${dim}registry: %s${reset}\n" "$REGISTRY_URL"
printf "${cyan}scenarios${reset}\n"

scenario "cold" "reset_project; reset_lpm_home; rm -rf '$PROJECT_DIR/node_modules' '$PROJECT_DIR/lpm.lock' '$PROJECT_DIR/lpm.lockb'" --no-skills

reset_project
reset_lpm_home
run_lpm_json "$RESULTS_DIR/warm-prime.json" "$RESULTS_DIR/warm-prime.err" --no-skills >/dev/null
scenario "warm" "rm -rf '$PROJECT_DIR/node_modules'" --no-skills

scenario "repeat" "true" --no-skills

make_cache_stale
scenario "stale-304" "make_cache_stale; rm -rf '$PROJECT_DIR/node_modules'" --no-skills --force

make_cache_stale
scenario "stale-200" "make_cache_stale; poison_metadata_etags; rm -rf '$PROJECT_DIR/node_modules'" --no-skills --force

scenario "fetch" "reset_project; reset_lpm_home" --no-skills

printf "${dim}raw outputs were in %s during the run${reset}\n" "$RESULTS_DIR"
