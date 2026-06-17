#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RUNS="${RUNS:-5}"
MODE="${LPM_LIVE_METADATA_MODE:-warm-store}"
KEEP_WORK="${LPM_LIVE_METADATA_KEEP_WORK:-0}"
STORE_VERSION="${LPM_STORE_VERSION:-v2}"
PREWARM_ROUTE="${LPM_LIVE_METADATA_PREWARM_ROUTE:-direct}"

LOCAL_BIN="$REPO_ROOT/target/release/lpm-rs"
if [[ -n "${LPM_BIN:-}" ]]; then
	BIN="$LPM_BIN"
elif [[ -x "$LOCAL_BIN" ]]; then
	BIN="$LOCAL_BIN"
else
	BIN="lpm"
fi

usage() {
	cat <<'EOF'
Usage: bench/live-metadata-route.sh [--runs N] [--mode cold|warm-store] [--keep-work]

Runs an interleaved live install comparison for npm direct metadata versus
Worker-routed metadata. The warm-store mode pre-populates tarballs once, then
leaves the metadata cache empty for each measured sample.

Environment:
  RUNS                         samples per route (default: 5)
  LPM_BIN                      lpm binary to run (default: target/release/lpm-rs, then lpm)
  LPM_LIVE_METADATA_MODE       cold or warm-store (default: warm-store)
  LPM_LIVE_METADATA_KEEP_WORK  keep the temp work directory when set to 1
  LPM_LIVE_METADATA_PREWARM_ROUTE
                               direct or proxy prewarm route (default: direct)
  LPM_STORE_VERSION            store layout passed to lpm (default: v2)
  BENCH_WORK_DIR               parent directory for temp work
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--runs)
			RUNS="${2:?--runs requires a value}"
			shift 2
			;;
		--mode)
			MODE="${2:?--mode requires a value}"
			shift 2
			;;
		--keep-work)
			KEEP_WORK=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown argument: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

case "$RUNS" in
	''|*[!0-9]*)
		echo "RUNS must be a positive integer (got '$RUNS')" >&2
		exit 2
		;;
esac
if (( RUNS < 1 )); then
	echo "RUNS must be >= 1" >&2
	exit 2
fi

case "$MODE" in
	cold|warm-store) ;;
	*)
		echo "LPM_LIVE_METADATA_MODE must be 'cold' or 'warm-store' (got '$MODE')" >&2
		exit 2
		;;
esac

case "$PREWARM_ROUTE" in
	direct|proxy) ;;
	*)
		echo "LPM_LIVE_METADATA_PREWARM_ROUTE must be 'direct' or 'proxy' (got '$PREWARM_ROUTE')" >&2
		exit 2
		;;
esac

for cmd in jq python3; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		echo "$cmd is required" >&2
		exit 1
	fi
done

if [[ -n "${BENCH_WORK_DIR:-}" ]]; then
	mkdir -p "$BENCH_WORK_DIR"
	WORK_ROOT="$(mktemp -d "$BENCH_WORK_DIR/live-metadata-route.XXXXXX")"
else
	WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/lpm-live-metadata-route.XXXXXX")"
fi

RESULTS="$WORK_ROOT/results.ndjson"
: > "$RESULTS"
STORE_SRC=""
FAILURES=0

cleanup() {
	if [[ "$KEEP_WORK" != "1" ]]; then
		rm -rf "$WORK_ROOT"
	else
		echo "kept work dir: $WORK_ROOT" >&2
	fi
}
trap cleanup EXIT

now_ms() {
	python3 - <<'PY'
import time
print(time.perf_counter_ns() // 1_000_000)
PY
}

make_manifest() {
	local project_dir="$1"
	jq -n '{
		name: "live-metadata-web-lite",
		version: "1.0.0",
		dependencies: {
			axios: "1.7.9",
			chalk: "5.3.0",
			commander: "12.1.0",
			debug: "4.4.1",
			dayjs: "1.11.13",
			"fast-glob": "3.3.2",
			kleur: "4.1.5",
			lodash: "4.17.21",
			marked: "14.1.2",
			minimist: "1.2.8",
			nanoid: "5.0.7",
			picocolors: "1.1.1",
			semver: "7.6.3",
			zod: "3.23.8"
		}
	}' > "$project_dir/package.json"
}

run_lpm_json() {
	local route="$1"
	local project_dir="$2"
	local home_dir="$3"
	local output_file="$4"
	local stderr_file="$5"

	(
		cd "$project_dir"
		env \
			HOME="$home_dir" \
			LPM_HOME="$home_dir/.lpm" \
			XDG_CONFIG_HOME="$home_dir/.config" \
			XDG_DATA_HOME="$home_dir/.local/share" \
			XDG_CACHE_HOME="$home_dir/.cache" \
			LPM_FORCE_FILE_AUTH=1 \
			LPM_FORCE_FILE_VAULT=1 \
			LPM_TEST_FAST_SCRYPT=1 \
			LPM_DISABLE_HOST_CLI_AUTH=1 \
			LPM_NO_UPDATE_CHECK=1 \
			LPM_STORE_VERSION="$STORE_VERSION" \
			LPM_NPM_ROUTE="$route" \
			NO_COLOR=1 \
			"$BIN" install --json --no-security-summary --no-skills --no-editor-setup \
				>"$output_file" 2>"$stderr_file"
	)
}

append_failure() {
	local route="$1"
	local sample="$2"
	local wall_ms="$3"
	local rc="$4"
	local output_file="$5"
	local stderr_file="$6"

	jq -n \
		--arg route "$route" \
		--argjson sample "$sample" \
		--argjson wall_ms "$wall_ms" \
		--argjson rc "$rc" \
		--rawfile stdout "$output_file" \
		--rawfile stderr "$stderr_file" \
		'{
			route: $route,
			sample: $sample,
			wall_ms: $wall_ms,
			rc: $rc,
			stdout: $stdout,
			stderr: $stderr
		}' >> "$RESULTS"
}

append_success() {
	local route="$1"
	local sample="$2"
	local wall_ms="$3"
	local output_file="$4"

	jq \
		--arg route "$route" \
		--argjson sample "$sample" \
		--argjson wall_ms "$wall_ms" \
		'
		(.timing.resolve // {}) as $resolve
		| ($resolve.metadata_http_versions // {}) as $http
		| {
			route: $route,
			sample: $sample,
			wall_ms: $wall_ms,
			rc: 0,
			success: .success,
			count: .count,
			downloaded: .downloaded,
			cached: .cached,
			linked: .linked,
			duration_ms: .duration_ms,
			resolve_ms: .timing.resolve_ms,
			fetch_ms: .timing.fetch_ms,
			link_ms: .timing.link_ms,
			metadata_http_response_count: (
				($http.http_09 // 0) +
				($http.http_10 // 0) +
				($http.http_11 // 0) +
				($http.http_2 // 0) +
				($http.http_3 // 0) +
				($http.unknown // 0)
			),
			http_11: ($http.http_11 // 0),
			http_2: ($http.http_2 // 0),
			http_3: ($http.http_3 // 0),
			unknown_http: ($http.unknown // 0),
			initial_batch_ms: ($resolve.initial_batch_ms // null),
			followup_rpc_count: ($resolve.followup_rpc_count // null),
			dispatcher_rpc_count: ($resolve.dispatcher.rpc_count // null),
			dispatcher_inflight_high_water: ($resolve.dispatcher.inflight_high_water // null),
			parked_max_depth: ($resolve.dispatcher.parked_max_depth // null),
			tarball_dispatched: ($resolve.dispatcher.tarball_dispatched // null),
			walker_rpc_count: ($resolve.walker_rpc_count // null),
			escape_hatch_rpc_count: ($resolve.escape_hatch_rpc_count // null),
			pubgrub_ms: ($resolve.pubgrub_ms // null),
			parse_ndjson_ms: ($resolve.parse_ndjson_ms // null),
			streaming_bfs_level_count: (($resolve.streaming_bfs.levels // []) | length),
			sources: ([.packages[].source] | unique)
		}
		' "$output_file" >> "$RESULTS"
}

prewarm_store() {
	local dir="$WORK_ROOT/prewarm"
	local project_dir="$dir/project"
	local home_dir="$dir/home"
	local output_file="$dir/stdout.json"
	local stderr_file="$dir/stderr.txt"
	mkdir -p "$project_dir" "$home_dir"
	make_manifest "$project_dir"

	if ! run_lpm_json "$PREWARM_ROUTE" "$project_dir" "$home_dir" "$output_file" "$stderr_file"; then
		echo "prewarm install failed; stderr:" >&2
		cat "$stderr_file" >&2 || true
		echo "stdout:" >&2
		cat "$output_file" >&2 || true
		exit 1
	fi

	STORE_SRC="$home_dir/.lpm/store"
	if [[ ! -d "$STORE_SRC" ]]; then
		echo "prewarm install did not create $STORE_SRC" >&2
		exit 1
	fi
}

prepare_sample_home() {
	local home_dir="$1"
	mkdir -p "$home_dir/.lpm"
	if [[ "$MODE" == "warm-store" ]]; then
		cp -a "$STORE_SRC" "$home_dir/.lpm/store"
	fi
}

run_one() {
	local route="$1"
	local sample="$2"
	local dir="$WORK_ROOT/sample-$sample-$route"
	local project_dir="$dir/project"
	local home_dir="$dir/home"
	local output_file="$dir/stdout.json"
	local stderr_file="$dir/stderr.txt"
	mkdir -p "$project_dir" "$home_dir"
	make_manifest "$project_dir"
	prepare_sample_home "$home_dir"

	local start end wall_ms rc
	start="$(now_ms)"
	set +e
	run_lpm_json "$route" "$project_dir" "$home_dir" "$output_file" "$stderr_file"
	rc=$?
	set -e
	end="$(now_ms)"
	wall_ms=$((end - start))

	if [[ "$rc" -ne 0 ]]; then
		FAILURES=$((FAILURES + 1))
		append_failure "$route" "$sample" "$wall_ms" "$rc" "$output_file" "$stderr_file"
		printf 'sample=%s route=%s rc=%s wall_ms=%s FAILED\n' "$sample" "$route" "$rc" "$wall_ms" >&2
		sed -n '1,20p' "$stderr_file" >&2 || true
		sed -n '1,20p' "$output_file" >&2 || true
		return
	fi

	append_success "$route" "$sample" "$wall_ms" "$output_file"
	printf 'sample=%s route=%s wall_ms=%s resolve_ms=%s metadata_http=%s\n' \
		"$sample" \
		"$route" \
		"$wall_ms" \
		"$(jq -r '.timing.resolve_ms' "$output_file")" \
		"$(jq -r '(.timing.resolve.metadata_http_versions // {}) as $h | (($h.http_09 // 0)+($h.http_10 // 0)+($h.http_11 // 0)+($h.http_2 // 0)+($h.http_3 // 0)+($h.unknown // 0))' "$output_file")" \
		>&2
}

print_summary() {
	jq -s '
		def median:
			sort
			| if length == 0 then null
			  elif (length % 2) == 1 then .[length / 2 | floor]
			  else ((.[length / 2 - 1] + .[length / 2]) / 2)
			  end;
		def ok: map(select(.rc == 0));
		(group_by(.route) | map({
			route: .[0].route,
			samples: length,
			failures: (map(select(.rc != 0)) | length),
			wall_ms_median: (ok | map(.wall_ms) | median),
			duration_ms_median: (ok | map(.duration_ms) | median),
			resolve_ms_median: (ok | map(.resolve_ms) | median),
			fetch_ms_median: (ok | map(.fetch_ms) | median),
			link_ms_median: (ok | map(.link_ms) | median),
			metadata_http_response_count_median: (ok | map(.metadata_http_response_count) | median),
			dispatcher_rpc_count_median: (ok | map(.dispatcher_rpc_count) | median),
			followup_rpc_count_median: (ok | map(.followup_rpc_count) | median),
			initial_batch_ms_median: (ok | map(.initial_batch_ms) | median),
			http_2_total: (ok | map(.http_2) | add),
			http_3_total: (ok | map(.http_3) | add),
			downloaded_median: (ok | map(.downloaded) | median),
			cached_median: (ok | map(.cached) | median),
			package_count_median: (ok | map(.count) | median),
			sources_seen: (ok | map(.sources[]) | unique)
		}))
	' "$RESULTS"
}

printf 'LPM Live Metadata Route Benchmark\n'
printf 'runs: %s\n' "$RUNS"
printf 'mode: %s\n' "$MODE"
printf 'binary: %s\n' "$BIN"
printf 'work_root: %s\n' "$WORK_ROOT"

if [[ "$MODE" == "warm-store" ]]; then
	prewarm_store
	printf 'prewarm_route: %s\n' "$PREWARM_ROUTE"
	printf 'prewarm_store_files: %s\n' "$(find "$STORE_SRC" -type f | wc -l | tr -d ' ')"
fi

for sample in $(seq 1 "$RUNS"); do
	if (( sample % 2 == 1 )); then
		run_one direct "$sample"
		run_one proxy "$sample"
	else
		run_one proxy "$sample"
		run_one direct "$sample"
	fi
done

printf 'results: %s\n' "$RESULTS"
printf 'summary:\n'
print_summary

if [[ "$FAILURES" -ne 0 ]]; then
	exit 1
fi
