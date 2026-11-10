#!/bin/bash

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
helper="$repo_root/scripts/ci/with-unlocked-gnome-keyring.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# Every fake appends one line to $LPM_TEST_LOG. The fake dbus-send reports the
# Secret Service as registered from poll number $LPM_TEST_REGISTERED_FROM on.
cat > "$fixture/bin/dbus-run-session" <<'EOF'
#!/bin/bash
set -euo pipefail
mode=$(stat -c %a "$XDG_RUNTIME_DIR" 2>/dev/null || stat -f %Lp "$XDG_RUNTIME_DIR")
echo "dbus-run-session runtime_dir=$XDG_RUNTIME_DIR mode=$mode" >> "$LPM_TEST_LOG"
[ "$1" = -- ] || { echo "fake dbus-run-session: expected --" >&2; exit 64; }
shift
DBUS_SESSION_BUS_ADDRESS=unix:path=/fake/bus exec "$@"
EOF

cat > "$fixture/bin/gnome-keyring-daemon" <<'EOF'
#!/bin/bash
set -euo pipefail
line="gnome-keyring-daemon $* runtime_dir=$XDG_RUNTIME_DIR"
if [ "$1" = --unlock ]; then
  line="$line password=$(cat)"
fi
echo "$line" >> "$LPM_TEST_LOG"
EOF

cat > "$fixture/bin/dbus-send" <<'EOF'
#!/bin/bash
set -euo pipefail
polls=$(( $(cat "$LPM_TEST_POLLS" 2>/dev/null || echo 0) + 1 ))
echo "$polls" > "$LPM_TEST_POLLS"
[ "$DBUS_SESSION_BUS_ADDRESS" = unix:path=/fake/bus ] || exit 1
if [ "$LPM_TEST_REGISTERED_FROM" != never ] && [ "$polls" -ge "$LPM_TEST_REGISTERED_FROM" ]; then
  echo '   boolean true'
else
  echo '   boolean false'
fi
EOF

cat > "$fixture/bin/sleep" <<'EOF'
#!/bin/bash
EOF
chmod +x "$fixture/bin/"*

export PATH="$fixture/bin:$PATH"
export LPM_TEST_LOG="$fixture/log"
export LPM_TEST_POLLS="$fixture/polls"

reset() {
  rm -f "$LPM_TEST_LOG" "$LPM_TEST_POLLS"
  : > "$LPM_TEST_LOG"
}

runtime_dir_from_log() {
  sed -n 's/^dbus-run-session runtime_dir=\([^ ]*\) .*/\1/p' "$LPM_TEST_LOG"
}

# The command runs once the Secret Service is registered, in the private
# runtime dir and session bus, and its exit status is the helper's.
reset
status=0
# shellcheck disable=SC2016
LPM_TEST_REGISTERED_FROM=3 "$helper" bash -c \
  'echo "command runtime_dir=$XDG_RUNTIME_DIR bus=$DBUS_SESSION_BUS_ADDRESS" >> "$LPM_TEST_LOG"; exit 7' || status=$?
[ "$status" -eq 7 ] || fail "the command's exit status 7 came back as $status"
runtime_dir=$(runtime_dir_from_log)
case "$runtime_dir" in
  /run/user/*|'') fail "the keyring did not get a private runtime dir: '$runtime_dir'" ;;
esac
grep -qx "dbus-run-session runtime_dir=$runtime_dir mode=700" "$LPM_TEST_LOG" ||
  fail "the private runtime dir is not owner-only: $(head -1 "$LPM_TEST_LOG")"
[ ! -e "$runtime_dir" ] || fail "the private runtime dir was left behind: $runtime_dir"
expected="dbus-run-session runtime_dir=$runtime_dir mode=700
gnome-keyring-daemon --unlock --components=secrets runtime_dir=$runtime_dir password=lpm-ci
gnome-keyring-daemon --start --components=secrets runtime_dir=$runtime_dir
command runtime_dir=$runtime_dir bus=unix:path=/fake/bus"
[ "$(cat "$LPM_TEST_LOG")" = "$expected" ] ||
  fail "unexpected call sequence:
$(cat "$LPM_TEST_LOG")"
[ "$(cat "$LPM_TEST_POLLS")" -eq 3 ] || fail "expected 3 registration polls, got $(cat "$LPM_TEST_POLLS")"

# When the Secret Service never registers, the helper fails with a clear error
# after the wait and never runs the command.
reset
status=0
# shellcheck disable=SC2016
output=$(LPM_TEST_REGISTERED_FROM=never LPM_CI_KEYRING_WAIT_SECONDS=2 "$helper" \
  bash -c 'echo "command ran" >> "$LPM_TEST_LOG"' 2>&1) || status=$?
[ "$status" -eq 1 ] || fail "an unregistered Secret Service exited $status, not 1"
grep -q 'did not register org.freedesktop.secrets on the session bus within 2s' <<<"$output" ||
  fail "missing registration error, got: $output"
! grep -q 'command ran' "$LPM_TEST_LOG" || fail "the command ran without a Secret Service"
[ "$(cat "$LPM_TEST_POLLS")" -eq 20 ] || fail "expected 20 polls in 2s, got $(cat "$LPM_TEST_POLLS")"
runtime_dir=$(runtime_dir_from_log)
[ -n "$runtime_dir" ] && [ ! -e "$runtime_dir" ] || fail "the private runtime dir was left behind after a failure: '$runtime_dir'"

# With no command, it prints usage and starts nothing.
reset
status=0
output=$("$helper" 2>&1) || status=$?
[ "$status" -eq 2 ] || fail "no command exited $status, not 2"
grep -q '^usage: ' <<<"$output" || fail "missing usage, got: $output"
[ ! -s "$LPM_TEST_LOG" ] || fail "started a session without a command: $(cat "$LPM_TEST_LOG")"

echo "with-unlocked-gnome-keyring tests passed"
