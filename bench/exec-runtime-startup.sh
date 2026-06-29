#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LPM_BIN="${LPM_BIN:-"$ROOT/target/release/lpm-rs"}"
ITERATIONS="${ITERATIONS:-20}"
OUT="${OUT:-"$ROOT/bench/perf-results/exec-runtime-startup-$(date -u +%Y%m%dT%H%M%SZ).md"}"
REAL_NODE="$(command -v node || true)"
LOCAL_TSX_BIN="${LOCAL_TSX_BIN:-$(command -v tsx || true)}"

if [[ ! -x "$LPM_BIN" ]]; then
  cargo build --release --locked -p lpm-cli --bin lpm-rs
fi

PROJECT="$(mktemp -d)"
cleanup() {
  rm -rf "$PROJECT"
}
trap cleanup EXIT

mkdir -p "$PROJECT/scripts" "$(dirname "$OUT")"
cat > "$PROJECT/package.json" <<'JSON'
{"name":"lpm-exec-bench","version":"0.0.0"}
JSON
cat > "$PROJECT/scripts/noop.js" <<'JS'
console.log("js");
JS
cat > "$PROJECT/scripts/noop.ts" <<'TS'
const message: string = "ts";
console.log(message);
TS
cat > "$PROJECT/scripts/noop.tsx" <<'TSX'
const view = <main>tsx</main>;
console.log(view.type);
TSX

measure_case() {
  local name="$1"
  shift
  local total_ns=0
  local min_ns=0
  local max_ns=0
  local status=0

  for ((i = 1; i <= ITERATIONS; i++)); do
    local start end elapsed
    start="$(date +%s%N)"
    if ! (cd "$PROJECT" && "$LPM_BIN" "$@" >/dev/null 2>&1); then
      status=1
      break
    fi
    end="$(date +%s%N)"
    elapsed=$((end - start))
    total_ns=$((total_ns + elapsed))
    if [[ "$min_ns" -eq 0 || "$elapsed" -lt "$min_ns" ]]; then
      min_ns="$elapsed"
    fi
    if [[ "$elapsed" -gt "$max_ns" ]]; then
      max_ns="$elapsed"
    fi
  done

  if [[ "$status" -ne 0 ]]; then
    printf '| %s | failed | - | - | - |\n' "$name" >> "$OUT"
    return
  fi

  local avg_ms min_ms max_ms
  avg_ms="$(awk -v ns="$total_ns" -v n="$ITERATIONS" 'BEGIN { printf "%.2f", ns / n / 1000000 }')"
  min_ms="$(awk -v ns="$min_ns" 'BEGIN { printf "%.2f", ns / 1000000 }')"
  max_ms="$(awk -v ns="$max_ns" 'BEGIN { printf "%.2f", ns / 1000000 }')"
  printf '| %s | pass | %s | %s | %s |\n' "$name" "$avg_ms" "$min_ms" "$max_ms" >> "$OUT"
}

{
  printf '# lpm exec runtime startup\n\n'
  printf '%s\n' "- Date: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`"
  printf '%s\n' "- Iterations: \`$ITERATIONS\`"
  printf '%s\n' "- Binary: \`$LPM_BIN\`"
  printf '%s\n\n' "- Node: \`$(node --version 2>/dev/null || printf unavailable)\`"
  printf '| Case | Status | Avg ms | Min ms | Max ms |\n'
  printf '| --- | --- | ---: | ---: | ---: |\n'
} > "$OUT"

measure_case "js exec startup" exec scripts/noop.js
measure_case "ts lpm runtime startup" exec scripts/noop.ts
measure_case "tsx lpm runtime startup" exec scripts/noop.tsx

if [[ -n "$LOCAL_TSX_BIN" && -x "$LOCAL_TSX_BIN" && -n "$REAL_NODE" ]]; then
  mkdir -p "$PROJECT/node_modules/.bin"
  ln -sf "$LOCAL_TSX_BIN" "$PROJECT/node_modules/.bin/tsx"
  cat > "$PROJECT/node_modules/.bin/node" <<SH
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then
  printf 'v20.5.0\\n'
  exit 0
fi
exec "$REAL_NODE" "\$@"
SH
  chmod +x "$PROJECT/node_modules/.bin/node"
  measure_case "local tsx fallback startup" exec scripts/noop.tsx
else
  printf '| local tsx fallback startup | skipped: no local tsx binary available | - | - | - |\n' >> "$OUT"
fi

printf 'Wrote %s\n' "$OUT"
