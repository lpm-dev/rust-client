#!/bin/bash

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
helper="$repo_root/scripts/ci/with-apple-service-retry.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# Each fake run consumes the next outcome from $LPM_TEST_OUTCOMES and appends
# its shell-quoted argv as one line of $LPM_TEST_CALLS.
cat > "$fixture/bin/codesign" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%q ' "$@" >> "$LPM_TEST_CALLS"
printf '\n' >> "$LPM_TEST_CALLS"
count=$(wc -l < "$LPM_TEST_CALLS" | tr -d ' ')
outcome=$(printf '%s\n' $LPM_TEST_OUTCOMES | sed -n "${count}p")
bundle=${*: -1}
case "$outcome" in
  ok) echo "$bundle: signed app bundle with Mach-O thin (x86_64) [dev.lpm.cli]" >&2 ;;
  timestamp-missing)
    echo "$bundle: A timestamp was expected but was not found." >&2
    exit 1
    ;;
  timestamp-unavailable)
    echo "$bundle: The timestamp service is not available." >&2
    exit 1
    ;;
  identity)
    echo "error: The specified item could not be found in the keychain." >&2
    exit 1
    ;;
  *) exit 99 ;;
esac
EOF

cat > "$fixture/bin/xcrun" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%q ' "$@" >> "$LPM_TEST_CALLS"
printf '\n' >> "$LPM_TEST_CALLS"
count=$(wc -l < "$LPM_TEST_CALLS" | tr -d ' ')
status=$(printf '%s\n' $LPM_TEST_OUTCOMES | sed -n "${count}p")
echo "Processing: $3"
case "$status" in
  0) echo "The $2 action worked!" ;;
  *) echo "The $2 action failed! Error $status." ;;
esac
exit "$status"
EOF
chmod +x "$fixture/bin/codesign" "$fixture/bin/xcrun"

export LPM_APPLE_SERVICE_CODESIGN="$fixture/bin/codesign"
export LPM_APPLE_SERVICE_XCRUN="$fixture/bin/xcrun"
export LPM_APPLE_SERVICE_BACKOFF_SECONDS=0
export LPM_TEST_CALLS="$fixture/calls"
bundle="$fixture/signed bundle/LPM CLI.app"
identity="Developer ID Application: Example (TEAMID1234)"

run_helper() {
  outcomes=$1
  shift
  : > "$LPM_TEST_CALLS"
  status=0
  LPM_TEST_OUTCOMES="$outcomes" "$helper" "$@" \
    > "$fixture/stdout" 2> "$fixture/stderr" || status=$?
  calls=$(wc -l < "$LPM_TEST_CALLS" | tr -d ' ')
}

assert_every_call_was() {
  expected=$(printf '%q ' "$@")
  while IFS= read -r call; do
    [ "$call" = "$expected" ] || fail "tool received different arguments: $call"
  done < "$LPM_TEST_CALLS"
}

codesign_arguments=(
  --force --timestamp --options runtime
  --entitlements macos/lpm.entitlements
  --sign "$identity"
  "$bundle"
)

run_helper "timestamp-missing timestamp-unavailable ok" codesign "${codesign_arguments[@]}"
[ "$status" -eq 0 ] || fail "codesign recovering from timestamp failures exited $status"
[ "$calls" -eq 3 ] || fail "codesign recovering from timestamp failures ran $calls times"
assert_every_call_was "${codesign_arguments[@]}"
grep -Fq "$bundle: A timestamp was expected but was not found." "$fixture/stderr" \
  || fail "codesign's own timestamp failure was not passed through"
[ "$(grep -c '^::warning::codesign hit a transient Apple service failure' "$fixture/stderr")" -eq 2 ] \
  || fail "each codesign retry must be announced"
echo "PASS: codesign retries timestamp-authority failures with its arguments intact"

run_helper "identity ok" codesign "${codesign_arguments[@]}"
[ "$status" -eq 1 ] || fail "codesign identity failure exited $status"
[ "$calls" -eq 1 ] || fail "codesign identity failure was retried ($calls runs)"
grep -Fq "could not be found in the keychain" "$fixture/stderr" \
  || fail "codesign's identity failure was not passed through"
echo "PASS: codesign fails at once on a signing failure unrelated to the timestamp"

LPM_APPLE_SERVICE_MAX_ATTEMPTS=3 run_helper \
  "timestamp-missing timestamp-missing timestamp-missing ok" codesign "${codesign_arguments[@]}"
[ "$status" -eq 1 ] || fail "lasting timestamp outage exited $status"
[ "$calls" -eq 3 ] || fail "lasting timestamp outage ran codesign $calls times, expected 3"
grep -Fq "::error::codesign still failed after 3 attempts" "$fixture/stderr" \
  || fail "lasting timestamp outage was not reported"
echo "PASS: codesign gives up with its own status after the attempt budget"

run_helper "68 68 0" stapler validate "$bundle"
[ "$status" -eq 0 ] || fail "stapler validate recovering from CloudKit exited $status"
[ "$calls" -eq 3 ] || fail "stapler validate recovering from CloudKit ran $calls times"
assert_every_call_was stapler validate "$bundle"
grep -Fq "The validate action failed! Error 68." "$fixture/stdout" \
  || fail "stapler's stdout report was not passed through"
grep -Fq "The validate action worked!" "$fixture/stdout" \
  || fail "stapler's final success was not passed through"
echo "PASS: stapler validate retries while the ticketing service does not answer"

run_helper "68 0" stapler staple "$bundle"
[ "$status" -eq 0 ] || fail "stapler staple recovering from CloudKit exited $status"
[ "$calls" -eq 2 ] || fail "stapler staple recovering from CloudKit ran $calls times"
assert_every_call_was stapler staple "$bundle"
echo "PASS: stapler staple retries while the ticketing service does not answer"

for status_code in 65 66 67; do
  run_helper "$status_code 0" stapler validate "$bundle"
  [ "$status" -eq "$status_code" ] || fail "stapler status $status_code became $status"
  [ "$calls" -eq 1 ] || fail "stapler status $status_code was retried ($calls runs)"
done
echo "PASS: stapler fails at once on a missing, invalid, or revoked ticket"

LPM_APPLE_SERVICE_MAX_ATTEMPTS=3 run_helper "68 68 68 0" stapler validate "$bundle"
[ "$status" -eq 68 ] || fail "lasting CloudKit outage exited $status"
[ "$calls" -eq 3 ] || fail "lasting CloudKit outage ran stapler $calls times, expected 3"
grep -Fq "::error::stapler validate still failed after 3 attempts" "$fixture/stderr" \
  || fail "lasting CloudKit outage was not reported"
echo "PASS: stapler gives up with its own status after the attempt budget"

for arguments in "notarytool submit" "codesign" "stapler" "stapler validate" \
  "stapler verify /tmp/lpm.app" "stapler validate /tmp/lpm.app extra"; do
  status=0
  # shellcheck disable=SC2086
  "$helper" $arguments > /dev/null 2>&1 || status=$?
  [ "$status" -eq 2 ] || fail "'$arguments' should be a usage error, got $status"
done
echo "PASS: unsupported invocations are usage errors"
