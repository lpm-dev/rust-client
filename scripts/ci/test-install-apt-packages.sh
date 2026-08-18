#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/install-apt-packages.sh"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_file_equals() {
  local expected="$1"
  local path="$2"
  local actual
  actual="$(cat "$path" 2>/dev/null || true)"
  [[ "$actual" == "$expected" ]] || fail "expected $path to contain '$expected', got '$actual'"
}

make_fake_tools() {
  local directory="$1"
  mkdir -p "$directory/bin" "$directory/state"

  cat >"$directory/bin/timeout" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'timeout' >>"$LPM_APT_TEST_LOG"
printf ' <%s>' "$@" >>"$LPM_APT_TEST_LOG"
printf '\n' >>"$LPM_APT_TEST_LOG"

count_file="$LPM_APT_TEST_STATE/timeout.count"
count=0
if [[ -f "$count_file" ]]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$count_file"
if ((count <= ${LPM_APT_TEST_TIMEOUT_FAILURES:-0})); then
  exit 124
fi

shift 3
exec "$@"
EOF

  cat >"$directory/bin/sleep" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'sleep <%s>\n' "$*" >>"$LPM_APT_TEST_LOG"
EOF

  cat >"$directory/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'apt-get' >>"$LPM_APT_TEST_LOG"
printf ' <%s>' "$@" >>"$LPM_APT_TEST_LOG"
printf '\n' >>"$LPM_APT_TEST_LOG"

action=""
for argument in "$@"; do
  case "$argument" in
    update|install)
      action="$argument"
      break
      ;;
  esac
done
[[ -n "$action" ]] || exit 90

count_file="$LPM_APT_TEST_STATE/$action.count"
count=0
if [[ -f "$count_file" ]]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$count_file"

case "$action" in
  update)
    if ((count <= ${LPM_APT_TEST_FAIL_UPDATE_COUNT:-0})); then
      exit 42
    fi
    ;;
  install)
    if ((count <= ${LPM_APT_TEST_FAIL_INSTALL_COUNT:-0})); then
      exit 43
    fi
    ;;
esac
EOF

  chmod +x "$directory/bin/apt-get" "$directory/bin/sleep" "$directory/bin/timeout"
}

run_helper() {
  local directory="$1"
  shift
  PATH="$directory/bin:$PATH" \
    LPM_CI_APT_NO_SUDO=1 \
    LPM_CI_APT_ATTEMPTS=3 \
    LPM_CI_APT_TIMEOUT_SECONDS=17 \
    LPM_CI_APT_RETRY_DELAY_SECONDS=1 \
    LPM_APT_TEST_LOG="$directory/invocations.log" \
    LPM_APT_TEST_STATE="$directory/state" \
    LPM_APT_TEST_TIMEOUT_FAILURES="${LPM_APT_TEST_TIMEOUT_FAILURES:-0}" \
    LPM_APT_TEST_FAIL_UPDATE_COUNT="${LPM_APT_TEST_FAIL_UPDATE_COUNT:-0}" \
    LPM_APT_TEST_FAIL_INSTALL_COUNT="${LPM_APT_TEST_FAIL_INSTALL_COUNT:-0}" \
    bash "$HELPER" "$@"
}

[[ -f "$HELPER" ]] || fail "missing helper: $HELPER"

update_retry="$FIXTURE_ROOT/update-retry"
make_fake_tools "$update_retry"
LPM_APT_TEST_FAIL_UPDATE_COUNT=2 run_helper "$update_retry" pkg-config libdbus-1-dev
assert_file_equals 3 "$update_retry/state/update.count"
assert_file_equals 1 "$update_retry/state/install.count"

timeout_retry="$FIXTURE_ROOT/timeout-retry"
make_fake_tools "$timeout_retry"
LPM_APT_TEST_TIMEOUT_FAILURES=2 run_helper "$timeout_retry" pkg-config
assert_file_equals 4 "$timeout_retry/state/timeout.count"
assert_file_equals 1 "$timeout_retry/state/update.count"
assert_file_equals 1 "$timeout_retry/state/install.count"

install_retry="$FIXTURE_ROOT/install-retry"
make_fake_tools "$install_retry"
LPM_APT_TEST_FAIL_INSTALL_COUNT=2 run_helper "$install_retry" jq
assert_file_equals 1 "$install_retry/state/update.count"
assert_file_equals 3 "$install_retry/state/install.count"

exhausted="$FIXTURE_ROOT/exhausted"
make_fake_tools "$exhausted"
if LPM_APT_TEST_FAIL_UPDATE_COUNT=9 run_helper "$exhausted" musl-tools=1.2.4-2; then
  fail "helper succeeded after exhausting the update attempts"
fi
assert_file_equals 3 "$exhausted/state/update.count"
[[ ! -e "$exhausted/state/install.count" ]] || fail "install ran after update exhausted its attempts"

grep -Fq \
  'timeout <--signal=TERM> <--kill-after=10s> <17s> <apt-get> <-o> <Acquire::Retries=2> <-o> <Acquire::http::Timeout=20> <-o> <Acquire::https::Timeout=20> <update>' \
  "$update_retry/invocations.log" || fail "update did not use the bounded APT policy"
grep -Fq \
  'apt-get <-o> <Acquire::Retries=2> <-o> <Acquire::http::Timeout=20> <-o> <Acquire::https::Timeout=20> <install> <-y> <pkg-config> <libdbus-1-dev>' \
  "$update_retry/invocations.log" || fail "install did not preserve package arguments or APT options"

echo "install-apt-packages helper tests passed"
