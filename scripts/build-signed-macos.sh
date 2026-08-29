#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
ENTITLEMENTS="$REPO_ROOT/macos/lpm.entitlements"
APP_ASSEMBLER="$REPO_ROOT/scripts/assemble-macos-app.sh"
SIGNING_IDENTITY="${LPM_SIGNING_IDENTITY:-Developer ID Application: Tolga Ergin (823S8YKMRW)}"
PROVISIONING_PROFILE="${LPM_CLI_PROVISIONING_PROFILE:-}"
EXPECTED_TEAM_ID="823S8YKMRW"
EXPECTED_ACCESS_GROUP="$EXPECTED_TEAM_ID.dev.lpm.vault.shared"
EXPECTED_APPLICATION_ID="$EXPECTED_TEAM_ID.dev.lpm.cli"
EXPECTED_PROFILE_ACCESS_GROUP="$EXPECTED_TEAM_ID.*"
PROFILE="debug"
TARGET_TRIPLE=""
RUN_ARGS=()

if [ "$(uname -s)" != "Darwin" ]; then
	echo "error: signed Keychain development builds require macOS" >&2
	exit 1
fi

while [ "$#" -gt 0 ]; do
	case "$1" in
	--release)
		PROFILE="release"
		shift
		;;
	--target)
		if [ "$#" -lt 2 ]; then
			echo "error: --target requires a Rust target triple" >&2
			exit 1
		fi
		TARGET_TRIPLE="$2"
		shift 2
		;;
	--)
		shift
		RUN_ARGS=("$@")
		break
		;;
	*)
		echo "error: unknown option: $1" >&2
		exit 1
		;;
	esac
done

TIMESTAMP_ARGUMENT="--timestamp=none"
if [ "$PROFILE" = "release" ]; then
	TIMESTAMP_ARGUMENT="--timestamp"
fi

if ! security find-identity -v -p codesigning | grep -Fq -- "\"$SIGNING_IDENTITY\""; then
	echo "error: signing identity is unavailable: $SIGNING_IDENTITY" >&2
	exit 1
fi

if [ -z "$PROVISIONING_PROFILE" ] || [ ! -f "$PROVISIONING_PROFILE" ]; then
	echo "error: set LPM_CLI_PROVISIONING_PROFILE to the Developer ID provisioning profile for dev.lpm.cli" >&2
	exit 1
fi

PROFILE_PLIST="$(mktemp)"
SIGNED_ENTITLEMENTS="$(mktemp)"
STAGING_DIR=""
cleanup() {
	rm -f "$PROFILE_PLIST" "$SIGNED_ENTITLEMENTS"
	if [ -n "$STAGING_DIR" ] && [ -d "$STAGING_DIR" ]; then
		rm -rf -- "$STAGING_DIR"
	fi
}
trap cleanup EXIT

security cms -D -i "$PROVISIONING_PROFILE" >"$PROFILE_PLIST"
PROFILE_TEAM_ID="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$PROFILE_PLIST")"
PROFILE_APPLICATION_ID="$(
	/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$PROFILE_PLIST" 2>/dev/null ||
		/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$PROFILE_PLIST"
)"
PROFILE_ACCESS_GROUPS="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:keychain-access-groups' "$PROFILE_PLIST")"
if [ "$PROFILE_TEAM_ID" != "$EXPECTED_TEAM_ID" ] || \
	[ "$PROFILE_APPLICATION_ID" != "$EXPECTED_APPLICATION_ID" ] || \
	! printf '%s\n' "$PROFILE_ACCESS_GROUPS" | awk \
		-v exact="$EXPECTED_ACCESS_GROUP" \
		-v wildcard="$EXPECTED_PROFILE_ACCESS_GROUP" \
		'{ value = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); if (value == exact || value == wildcard) found = 1 } END { exit(found ? 0 : 1) }'; then
	echo "error: provisioning profile does not authorize the LPM CLI shared Keychain contract" >&2
	exit 1
fi

ACCESS_GROUP="$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$ENTITLEMENTS")"
if [ "$ACCESS_GROUP" != "$EXPECTED_ACCESS_GROUP" ]; then
	echo "error: unexpected Keychain access group: $ACCESS_GROUP" >&2
	exit 1
fi

TARGET_ROOT="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
BUILD_ARGS=(build --locked -p lpm-cli --bin lpm-rs)
if [ "$PROFILE" = "release" ]; then
	BUILD_ARGS+=(--release)
fi
if [ -n "$TARGET_TRIPLE" ]; then
	BUILD_ARGS+=(--target "$TARGET_TRIPLE")
fi

cd "$REPO_ROOT"
cargo "${BUILD_ARGS[@]}"

TARGET_PROFILE_ROOT="$TARGET_ROOT/$PROFILE"
if [ -n "$TARGET_TRIPLE" ]; then
	TARGET_PROFILE_ROOT="$TARGET_ROOT/$TARGET_TRIPLE/$PROFILE"
fi
BINARY="$TARGET_PROFILE_ROOT/lpm-rs"
APP_BUNDLE="$TARGET_PROFILE_ROOT/LPM CLI.app"
STAGING_DIR="$(mktemp -d "$TARGET_PROFILE_ROOT/.lpm-cli-app.XXXXXX")"
"$APP_ASSEMBLER" "$BINARY" "$STAGING_DIR" "$PROVISIONING_PROFILE"

codesign --force --options runtime "$TIMESTAMP_ARGUMENT" \
	--entitlements "$ENTITLEMENTS" \
	--sign "$SIGNING_IDENTITY" \
	"$STAGING_DIR"
codesign --verify --strict --verbose=2 "$STAGING_DIR"

codesign -d --entitlements :- "$STAGING_DIR" >"$SIGNED_ENTITLEMENTS" 2>/dev/null
SIGNED_ACCESS_GROUP="$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$SIGNED_ENTITLEMENTS")"
if [ "$SIGNED_ACCESS_GROUP" != "$EXPECTED_ACCESS_GROUP" ]; then
	echo "error: signed binary is missing the shared Keychain access group" >&2
	exit 1
fi

SIGNED_TEAM_ID="$(codesign -dvv "$STAGING_DIR" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2}')"
if [ "$SIGNED_TEAM_ID" != "$EXPECTED_TEAM_ID" ]; then
	echo "error: signed binary has unexpected team identifier: $SIGNED_TEAM_ID" >&2
	exit 1
fi

rm -rf -- "$APP_BUNDLE"
mv "$STAGING_DIR" "$APP_BUNDLE"
STAGING_DIR=""

SIGNED_BINARY="$APP_BUNDLE/Contents/MacOS/lpm-rs"
echo "Signed LPM CLI: $SIGNED_BINARY"
if [ "${#RUN_ARGS[@]}" -gt 0 ]; then
	exec "$SIGNED_BINARY" "${RUN_ARGS[@]}"
fi
