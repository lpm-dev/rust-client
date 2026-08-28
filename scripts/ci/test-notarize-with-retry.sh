#!/bin/bash

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin"
touch "$fixture/release.zip"

cat > "$fixture/bin/xcrun" <<'EOF'
#!/bin/bash
set -euo pipefail
test "$1" = notarytool
operation=$2
case "$operation" in
  submit)
    count=$(cat "$LPM_TEST_SUBMIT_COUNT" 2>/dev/null || echo 0)
    count=$((count + 1))
    echo "$count" > "$LPM_TEST_SUBMIT_COUNT"
    if [ "$count" -eq 1 ]; then
      echo 'Error: No network route' >&2
      exit 1
    fi
    printf '{"id":"11111111-2222-3333-4444-555555555555"}\n'
    ;;
  info)
    count=$(cat "$LPM_TEST_INFO_COUNT" 2>/dev/null || echo 0)
    count=$((count + 1))
    echo "$count" > "$LPM_TEST_INFO_COUNT"
    if [ "$count" -eq 1 ]; then
      echo 'temporary 503' >&2
      exit 1
    fi
    if [ "$count" -eq 2 ]; then
      printf '{"status":"In Progress"}\n'
    else
      printf '{"status":"Accepted"}\n'
    fi
    ;;
  *) exit 99 ;;
esac
EOF
chmod +x "$fixture/bin/xcrun"

export PATH="$fixture/bin:$PATH"
export LPM_TEST_SUBMIT_COUNT="$fixture/submit-count"
export LPM_TEST_INFO_COUNT="$fixture/info-count"
export LPM_NOTARY_MAX_SUBMIT_ATTEMPTS=3
export LPM_NOTARY_MAX_INFO_ATTEMPTS=4
export LPM_NOTARY_POLL_SECONDS=0
export LPM_NOTARY_STATE_PATH="$fixture/submission-id"

bash "$repo_root/scripts/ci/notarize-with-retry.sh" "$fixture/release.zip" --key "$fixture/key.p8"
test "$(cat "$LPM_TEST_SUBMIT_COUNT")" = 2
test "$(cat "$LPM_TEST_INFO_COUNT")" = 3
test ! -e "$LPM_NOTARY_STATE_PATH"

rm -f "$LPM_TEST_SUBMIT_COUNT" "$LPM_TEST_INFO_COUNT"
LPM_NOTARY_MODE=submit bash "$repo_root/scripts/ci/notarize-with-retry.sh" \
  "$fixture/release.zip" --key "$fixture/key.p8"
test "$(cat "$LPM_TEST_SUBMIT_COUNT")" = 2
test ! -e "$LPM_TEST_INFO_COUNT"
test -f "$LPM_NOTARY_STATE_PATH"
LPM_NOTARY_MODE=poll bash "$repo_root/scripts/ci/notarize-with-retry.sh" \
  "$fixture/release.zip" --key "$fixture/key.p8"
test "$(cat "$LPM_TEST_SUBMIT_COUNT")" = 2
test "$(cat "$LPM_TEST_INFO_COUNT")" = 3
test ! -e "$LPM_NOTARY_STATE_PATH"

archive_sha256=$(shasum -a 256 "$fixture/release.zip" | awk '{print $1}')
jq -n \
  --arg archiveSha256 "$archive_sha256" \
  --arg submissionId '11111111-2222-3333-4444-555555555555' \
  '{archiveSha256: $archiveSha256, submissionId: $submissionId}' > "$LPM_NOTARY_STATE_PATH"
: > "$LPM_TEST_INFO_COUNT"
bash "$repo_root/scripts/ci/notarize-with-retry.sh" "$fixture/release.zip" --key "$fixture/key.p8"
test "$(cat "$LPM_TEST_SUBMIT_COUNT")" = 2
