#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
HELPER="$SCRIPT_DIR/macos-keychain-search-list.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
WORKFLOW="$REPO_ROOT/.github/workflows/release.yml"

if [ ! -x "$HELPER" ]; then
	echo "missing executable Keychain search-list helper: $HELPER" >&2
	exit 1
fi

TEST_ROOT="$(mktemp -d)"
cleanup() {
	rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

FAKE_BIN="$TEST_ROOT/bin"
CURRENT_LIST="$TEST_ROOT/current-list"
CALL_LOG="$TEST_ROOT/calls"
STATE_FILE="$TEST_ROOT/original-list"
EXPECTED_STATE="$TEST_ROOT/expected-list"
mkdir -p "$FAKE_BIN"

cat >"$FAKE_BIN/security" <<'EOF'
#!/bin/bash
set -euo pipefail

printf '%s\0' "$@" >>"$FAKE_SECURITY_CALL_LOG"
printf '\n' >>"$FAKE_SECURITY_CALL_LOG"

if [ "$#" -ge 3 ] && [ "$1" = "list-keychains" ] && [ "$2" = "-d" ] && [ "$3" = "user" ]; then
	shift 3
	if [ "$#" -eq 0 ]; then
		while IFS= read -r keychain; do
			printf '    "%s"\n' "$keychain"
		done <"$FAKE_SECURITY_CURRENT_LIST"
		exit 0
	fi

	if [ "$1" = "-s" ]; then
		shift
		if [ "${FAKE_SECURITY_FAIL_SET:-0}" = "1" ]; then
			exit 70
		fi
		: >"$FAKE_SECURITY_CURRENT_LIST"
		if [ "$#" -gt 0 ]; then
			printf '%s\n' "$@" >"$FAKE_SECURITY_CURRENT_LIST"
		fi
		exit 0
	fi
fi

echo "unexpected security invocation" >&2
exit 64
EOF
chmod +x "$FAKE_BIN/security"

LOGIN_KEYCHAIN="/Users/release/Library/Keychains/login.keychain-db"
SPACED_KEYCHAIN="/Users/release/Library/Keychains/Release Signing Backup.keychain-db"
SIGNING_KEYCHAIN="$TEST_ROOT/LPM Release Signing.keychain-db"
printf '%s\n%s\n' "$LOGIN_KEYCHAIN" "$SPACED_KEYCHAIN" >"$CURRENT_LIST"
printf '%s\0%s\0' "$LOGIN_KEYCHAIN" "$SPACED_KEYCHAIN" >"$EXPECTED_STATE"

FAKE_SECURITY_CURRENT_LIST="$CURRENT_LIST" \
	FAKE_SECURITY_CALL_LOG="$CALL_LOG" \
	SECURITY_BIN="$FAKE_BIN/security" \
	"$HELPER" add "$SIGNING_KEYCHAIN" "$STATE_FILE"

cmp "$EXPECTED_STATE" "$STATE_FILE"
case "$(uname -s)" in
Darwin)
	test "$(stat -f '%Lp' "$STATE_FILE")" = "600"
	;;
*)
	test "$(stat -c '%a' "$STATE_FILE")" = "600"
	;;
esac
EXPECTED_ADDED="$TEST_ROOT/expected-added"
printf '%s\n%s\n%s\n' "$LOGIN_KEYCHAIN" "$SPACED_KEYCHAIN" "$SIGNING_KEYCHAIN" >"$EXPECTED_ADDED"
cmp "$EXPECTED_ADDED" "$CURRENT_LIST"

FAKE_SECURITY_CURRENT_LIST="$CURRENT_LIST" \
	FAKE_SECURITY_CALL_LOG="$CALL_LOG" \
	SECURITY_BIN="$FAKE_BIN/security" \
	"$HELPER" restore "$STATE_FILE"

EXPECTED_RESTORED="$TEST_ROOT/expected-restored"
printf '%s\n%s\n' "$LOGIN_KEYCHAIN" "$SPACED_KEYCHAIN" >"$EXPECTED_RESTORED"
cmp "$EXPECTED_RESTORED" "$CURRENT_LIST"
test ! -e "$STATE_FILE"

printf '%s\n' "$LOGIN_KEYCHAIN" >"$CURRENT_LIST"
printf '%s\n' "$LOGIN_KEYCHAIN" >"$EXPECTED_RESTORED"
FAKE_SECURITY_CURRENT_LIST="$CURRENT_LIST" \
	FAKE_SECURITY_CALL_LOG="$CALL_LOG" \
	SECURITY_BIN="$FAKE_BIN/security" \
	"$HELPER" add "$LOGIN_KEYCHAIN" "$STATE_FILE"
cmp "$EXPECTED_RESTORED" "$CURRENT_LIST"

if FAKE_SECURITY_CURRENT_LIST="$CURRENT_LIST" \
	FAKE_SECURITY_CALL_LOG="$CALL_LOG" \
	FAKE_SECURITY_FAIL_SET=1 \
	SECURITY_BIN="$FAKE_BIN/security" \
	"$HELPER" restore "$STATE_FILE"; then
	echo "restore unexpectedly succeeded when security rejected the update" >&2
	exit 1
fi
test -f "$STATE_FILE"

FAKE_SECURITY_CURRENT_LIST="$CURRENT_LIST" \
	FAKE_SECURITY_CALL_LOG="$CALL_LOG" \
	SECURITY_BIN="$FAKE_BIN/security" \
	"$HELPER" restore "$STATE_FILE"
test ! -e "$STATE_FILE"

: >"$CURRENT_LIST"
FAKE_SECURITY_CURRENT_LIST="$CURRENT_LIST" \
	FAKE_SECURITY_CALL_LOG="$CALL_LOG" \
	SECURITY_BIN="$FAKE_BIN/security" \
	"$HELPER" add "$SIGNING_KEYCHAIN" "$STATE_FILE"
test "$(wc -c <"$STATE_FILE" | tr -d ' ')" = "0"
printf '%s\n' "$SIGNING_KEYCHAIN" >"$EXPECTED_ADDED"
cmp "$EXPECTED_ADDED" "$CURRENT_LIST"
FAKE_SECURITY_CURRENT_LIST="$CURRENT_LIST" \
	FAKE_SECURITY_CALL_LOG="$CALL_LOG" \
	SECURITY_BIN="$FAKE_BIN/security" \
	"$HELPER" restore "$STATE_FILE"
test ! -s "$CURRENT_LIST"

grep -Fq "macos-keychain-search-list.sh\" add \"\$KEYCHAIN_PATH\" \"\$KEYCHAIN_SEARCH_LIST_STATE\"" "$WORKFLOW"
grep -Fq "macos-keychain-search-list.sh\" restore \"\$APPLE_KEYCHAIN_SEARCH_LIST_STATE\"" "$WORKFLOW"
grep -Fq "if [ -e \"\$APPLE_SIGNING_KEYCHAIN\" ]; then" "$WORKFLOW"

echo "macOS Keychain search-list tests passed"
