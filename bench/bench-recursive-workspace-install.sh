#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/target/release/lpm-rs}"
output="${2:-$repo_root/bench/perf-results/recursive-workspace-install-latest.json}"
mode="${LPM_RECURSIVE_BENCH_MODE:-default}"
runs="${LPM_BENCH_RUNS:-20}"
warmup="${LPM_BENCH_WARMUP:-3}"

if ! command -v hyperfine >/dev/null 2>&1; then
  echo "hyperfine is required" >&2
  exit 1
fi
if [[ ! -x "$binary" ]]; then
  echo "release binary not found or not executable: $binary" >&2
  echo "run: cargo build --release --locked -p lpm-cli" >&2
  exit 1
fi
binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"
case "$mode" in
  default | explicit | legacy) ;;
  *)
    echo "LPM_RECURSIVE_BENCH_MODE must be default, explicit, or legacy" >&2
    exit 1
    ;;
esac

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/lpm-recursive-workspace.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT
mkdir -p "$fixture_root/lpm-home" "$(dirname "$output")"

install_flags=(
  --no-security-summary
  --no-skills
  --no-editor-setup
  --no-audit-after-install
)
hyperfine_args=()

for count in 15 30 60 120 240; do
  workspace="$fixture_root/$count"
  mkdir -p "$workspace/packages"
  printf '{"name":"workspace-%d","private":true,"workspaces":["packages/*"]}\n' \
    "$count" >"$workspace/package.json"

  for ((index = 0; index < count; index++)); do
    printf -v member 'm%03d' "$index"
    mkdir -p "$workspace/packages/$member"
    printf '{"name":"@bench/%s","version":"1.0.0","private":true}\n' \
      "$member" >"$workspace/packages/$member/package.json"
  done

  case "$mode" in
    default)
      printf -v command 'cd %q && LPM_HOME=%q %q install %s >/dev/null' \
        "$workspace" "$fixture_root/lpm-home" "$binary" "${install_flags[*]}"
      ;;
    explicit)
      printf -v command 'cd %q && LPM_HOME=%q %q install --recursive %s >/dev/null' \
        "$workspace" "$fixture_root/lpm-home" "$binary" "${install_flags[*]}"
      ;;
    legacy)
      printf -v command \
        'for project in %q/packages/* %q; do (cd "$project" && LPM_HOME=%q %q install --no-recursive %s >/dev/null); done' \
        "$workspace" "$workspace" "$fixture_root/lpm-home" "$binary" "${install_flags[*]}"
      ;;
  esac
  hyperfine_args+=(--command-name "$mode-$count" "$command")
done

hyperfine \
  --warmup "$warmup" \
  --runs "$runs" \
  --export-json "$output" \
  "${hyperfine_args[@]}"
