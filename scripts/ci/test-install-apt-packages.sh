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
    LPM_CI_APT_UPDATE_TIMEOUT_SECONDS="${LPM_CI_APT_UPDATE_TIMEOUT_SECONDS:-17}" \
    LPM_CI_APT_INSTALL_TIMEOUT_SECONDS="${LPM_CI_APT_INSTALL_TIMEOUT_SECONDS:-17}" \
    LPM_CI_APT_RETRY_DELAY_SECONDS="${LPM_CI_APT_RETRY_DELAY_SECONDS:-1}" \
    LPM_CI_APT_RETRY_JITTER_SECONDS="${LPM_CI_APT_RETRY_JITTER_SECONDS:-0}" \
    LPM_CI_APT_MIRROR_FILE="${LPM_CI_APT_MIRROR_FILE:-$directory/state/missing-apt-mirrors.txt}" \
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
grep -Fxq 'sleep <1>' "$update_retry/invocations.log" || fail "first retry did not use the base delay"
grep -Fxq 'sleep <2>' "$update_retry/invocations.log" || fail "second retry did not use bounded backoff"

separate_timeouts="$FIXTURE_ROOT/separate-timeouts"
make_fake_tools "$separate_timeouts"
LPM_CI_APT_UPDATE_TIMEOUT_SECONDS=23 \
  LPM_CI_APT_INSTALL_TIMEOUT_SECONDS=31 \
  run_helper "$separate_timeouts" pkg-config
grep -Fq \
  'timeout <--signal=TERM> <--kill-after=10s> <23s> <apt-get> <-o> <Acquire::Retries=2> <-o> <Acquire::http::Timeout=20> <-o> <Acquire::https::Timeout=20> <update>' \
  "$separate_timeouts/invocations.log" || fail "index refresh did not use its independent timeout"
grep -Fq \
  'timeout <--signal=TERM> <--kill-after=10s> <31s> <apt-get> <-o> <Acquire::Retries=2> <-o> <Acquire::http::Timeout=20> <-o> <Acquire::https::Timeout=20> <install> <-y> <pkg-config>' \
  "$separate_timeouts/invocations.log" || fail "package installation did not use its independent timeout"

timeout_retry="$FIXTURE_ROOT/timeout-retry"
make_fake_tools "$timeout_retry"
LPM_APT_TEST_TIMEOUT_FAILURES=2 run_helper "$timeout_retry" pkg-config
assert_file_equals 4 "$timeout_retry/state/timeout.count"
assert_file_equals 1 "$timeout_retry/state/update.count"
assert_file_equals 1 "$timeout_retry/state/install.count"

mirror_failover="$FIXTURE_ROOT/mirror-failover"
make_fake_tools "$mirror_failover"
mirror_file="$mirror_failover/apt-mirrors.txt"
cat >"$mirror_file" <<'EOF'
# GitHub-hosted runner mirror policy
http://azure.archive.ubuntu.com/ubuntu/	priority:1
https://archive.ubuntu.com/ubuntu/	priority:2
https://security.ubuntu.com/ubuntu/	priority:3
EOF
LPM_APT_TEST_TIMEOUT_FAILURES=1 \
  LPM_CI_APT_MIRROR_FILE="$mirror_file" \
  run_helper "$mirror_failover" pkg-config
assert_file_equals \
  $'# GitHub-hosted runner mirror policy\nhttp://azure.archive.ubuntu.com/ubuntu/\tpriority:3\nhttps://archive.ubuntu.com/ubuntu/\tpriority:1\nhttps://security.ubuntu.com/ubuntu/\tpriority:2' \
  "$mirror_file"

non_timeout_mirror="$FIXTURE_ROOT/non-timeout-mirror"
make_fake_tools "$non_timeout_mirror"
non_timeout_mirror_file="$non_timeout_mirror/apt-mirrors.txt"
cat >"$non_timeout_mirror_file" <<'EOF'
http://azure.archive.ubuntu.com/ubuntu/	priority:1
https://archive.ubuntu.com/ubuntu/	priority:2
https://security.ubuntu.com/ubuntu/	priority:3
EOF
LPM_APT_TEST_FAIL_UPDATE_COUNT=1 \
  LPM_CI_APT_MIRROR_FILE="$non_timeout_mirror_file" \
  run_helper "$non_timeout_mirror" pkg-config
assert_file_equals \
  $'http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\nhttps://archive.ubuntu.com/ubuntu/\tpriority:2\nhttps://security.ubuntu.com/ubuntu/\tpriority:3' \
  "$non_timeout_mirror_file"

nonstandard_mirror="$FIXTURE_ROOT/nonstandard-mirror"
make_fake_tools "$nonstandard_mirror"
nonstandard_mirror_file="$nonstandard_mirror/apt-mirrors.txt"
printf '%s\n' 'https://mirror.example.test/ubuntu/ priority:1' >"$nonstandard_mirror_file"
LPM_APT_TEST_TIMEOUT_FAILURES=1 \
  LPM_CI_APT_MIRROR_FILE="$nonstandard_mirror_file" \
  run_helper "$nonstandard_mirror" pkg-config
assert_file_equals 'https://mirror.example.test/ubuntu/ priority:1' "$nonstandard_mirror_file"

symlink_mirror="$FIXTURE_ROOT/symlink-mirror"
make_fake_tools "$symlink_mirror"
symlink_mirror_target="$symlink_mirror/real-apt-mirrors.txt"
cat >"$symlink_mirror_target" <<'EOF'
http://azure.archive.ubuntu.com/ubuntu/	priority:1
https://archive.ubuntu.com/ubuntu/	priority:2
https://security.ubuntu.com/ubuntu/	priority:3
EOF
ln -s "$symlink_mirror_target" "$symlink_mirror/apt-mirrors.txt"
LPM_APT_TEST_TIMEOUT_FAILURES=1 \
  LPM_CI_APT_MIRROR_FILE="$symlink_mirror/apt-mirrors.txt" \
  run_helper "$symlink_mirror" pkg-config
assert_file_equals \
  $'http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\nhttps://archive.ubuntu.com/ubuntu/\tpriority:2\nhttps://security.ubuntu.com/ubuntu/\tpriority:3' \
  "$symlink_mirror_target"

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
