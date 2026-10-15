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

# Each fake run consumes the next line of $LPM_TEST_OUTCOMES and appends its
# shell-quoted argv as one line of $LPM_TEST_CALLS. A codesign outcome other
# than "ok" is the error it reports for its last argument.
cat > "$fixture/bin/codesign" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%q ' "$@" >> "$LPM_TEST_CALLS"
printf '\n' >> "$LPM_TEST_CALLS"
count=$(wc -l < "$LPM_TEST_CALLS" | tr -d ' ')
outcome=$(printf '%s\n' "$LPM_TEST_OUTCOMES" | sed -n "${count}p")
target=${*: -1}
if [ "$outcome" = ok ]; then
  echo "$target: signed app bundle with Mach-O thin (x86_64) [dev.lpm.cli]" >&2
  exit 0
fi
echo "$target: $outcome" >&2
exit 1
EOF

cat > "$fixture/bin/xcrun" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%q ' "$@" >> "$LPM_TEST_CALLS"
printf '\n' >> "$LPM_TEST_CALLS"
count=$(wc -l < "$LPM_TEST_CALLS" | tr -d ' ')
status=$(printf '%s\n' "$LPM_TEST_OUTCOMES" | sed -n "${count}p")
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

lines() {
  printf '%s\n' "$@"
}

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

transient_timestamp_failures=(
  "A timestamp was expected but was not found."
  "The timestamp service is not available."
  "The time source for the Timestamp Authority is not available."
  "The timestamp request cannot be handled due to system failure."
  "A timestamp transaction is waiting."
  "A timestamp transaction was rejected."
)
LPM_APPLE_SERVICE_MAX_ATTEMPTS=7 run_helper \
  "$(lines "${transient_timestamp_failures[@]}" ok)" codesign "${codesign_arguments[@]}"
[ "$status" -eq 0 ] || fail "codesign recovering from timestamp failures exited $status"
[ "$calls" -eq 7 ] || fail "codesign recovering from timestamp failures ran $calls times"
assert_every_call_was "${codesign_arguments[@]}"
grep -Fq "$bundle: A timestamp was expected but was not found." "$fixture/stderr" \
  || fail "codesign's own timestamp failure was not passed through"
[ "$(grep -c '^::warning::codesign hit a transient Apple service failure' "$fixture/stderr")" -eq 6 ] \
  || fail "each codesign retry must be announced"
echo "PASS: codesign retries timestamp-authority outages with its arguments intact"

permanent_failures=(
  "no identity found"
  "The requested policy is not supported by the Timestamp Authority."
  "An unrecognized or unsupported Algorithm Identifier in timestamp."
  "The timestamp was not trusted."
  "The timestamp was not valid."
)
for failure in "${permanent_failures[@]}"; do
  run_helper "$(lines "$failure" ok)" codesign "${codesign_arguments[@]}"
  [ "$status" -eq 1 ] || fail "codesign failure '$failure' exited $status"
  [ "$calls" -eq 1 ] || fail "codesign failure '$failure' was retried ($calls runs)"
  grep -Fq "$bundle: $failure" "$fixture/stderr" \
    || fail "codesign's failure '$failure' was not passed through"
done
echo "PASS: codesign fails at once when signing or the timestamp request cannot succeed"

missing_bundle="$fixture/timestamp-input/Missing.app"
run_helper "$(lines "No such file or directory" ok)" codesign --force --timestamp "$missing_bundle"
[ "$status" -eq 1 ] || fail "codesign of a missing bundle exited $status"
[ "$calls" -eq 1 ] || fail "a path naming the timestamp made codesign retry ($calls runs)"
echo "PASS: codesign does not mistake a path naming the timestamp for an outage"

LPM_APPLE_SERVICE_MAX_ATTEMPTS=3 run_helper \
  "$(lines "${transient_timestamp_failures[0]}" "${transient_timestamp_failures[0]}" "${transient_timestamp_failures[0]}" ok)" \
  codesign "${codesign_arguments[@]}"
[ "$status" -eq 1 ] || fail "lasting timestamp outage exited $status"
[ "$calls" -eq 3 ] || fail "lasting timestamp outage ran codesign $calls times, expected 3"
grep -Fq "::error::codesign still failed after 3 attempts" "$fixture/stderr" \
  || fail "lasting timestamp outage was not reported"
echo "PASS: codesign gives up with its own status after the attempt budget"

run_helper "$(lines 68 68 0)" stapler validate "$bundle"
[ "$status" -eq 0 ] || fail "stapler validate recovering from CloudKit exited $status"
[ "$calls" -eq 3 ] || fail "stapler validate recovering from CloudKit ran $calls times"
assert_every_call_was stapler validate "$bundle"
grep -Fq "The validate action failed! Error 68." "$fixture/stdout" \
  || fail "stapler's stdout report was not passed through"
grep -Fq "The validate action worked!" "$fixture/stdout" \
  || fail "stapler's final success was not passed through"
echo "PASS: stapler validate retries while the ticketing service does not answer"

run_helper "$(lines 68 0)" stapler staple "$bundle"
[ "$status" -eq 0 ] || fail "stapler staple recovering from CloudKit exited $status"
[ "$calls" -eq 2 ] || fail "stapler staple recovering from CloudKit ran $calls times"
assert_every_call_was stapler staple "$bundle"
echo "PASS: stapler staple retries while the ticketing service does not answer"

for status_code in 65 66 73 77; do
  run_helper "$(lines "$status_code" 0)" stapler validate "$bundle"
  [ "$status" -eq "$status_code" ] || fail "stapler status $status_code became $status"
  [ "$calls" -eq 1 ] || fail "stapler status $status_code was retried ($calls runs)"
done
echo "PASS: stapler fails at once on a missing, invalid, unwritable, or revoked ticket"

LPM_APPLE_SERVICE_MAX_ATTEMPTS=3 run_helper "$(lines 68 68 68 0)" stapler validate "$bundle"
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
