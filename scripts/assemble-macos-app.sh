#!/bin/bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
	echo "usage: $0 <executable> <app-bundle> <provisioning-profile>" >&2
	exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
EXECUTABLE="$1"
APP_BUNDLE="$2"
PROVISIONING_PROFILE="$3"
INFO_PLIST="$REPO_ROOT/macos/LPMCLI-Info.plist"
ICON="$REPO_ROOT/macos/LPMCLI.icns"

if [ "$(uname -s)" != "Darwin" ]; then
	echo "error: macOS app assembly requires macOS" >&2
	exit 1
fi

for source_file in "$EXECUTABLE" "$PROVISIONING_PROFILE" "$INFO_PLIST" "$ICON"; do
	if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
		echo "error: required app source is not a regular file: $source_file" >&2
		exit 1
	fi
done

if [ -e "$APP_BUNDLE" ] || [ -L "$APP_BUNDLE" ]; then
	if [ ! -d "$APP_BUNDLE" ] || [ -L "$APP_BUNDLE" ] || [ -n "$(find "$APP_BUNDLE" -mindepth 1 -print -quit)" ]; then
		echo "error: app destination must be absent or an empty real directory: $APP_BUNDLE" >&2
		exit 1
	fi
else
	mkdir -p "$APP_BUNDLE"
fi

"$SCRIPT_DIR/validate-macos-icon.sh" >/dev/null
bundle_executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$INFO_PLIST")"
if [ "$bundle_executable" != "lpm-rs" ]; then
	echo "error: CFBundleExecutable must be lpm-rs" >&2
	exit 1
fi

mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
cp "$INFO_PLIST" "$APP_BUNDLE/Contents/Info.plist"
cp "$ICON" "$APP_BUNDLE/Contents/Resources/LPMCLI.icns"
cp "$EXECUTABLE" "$APP_BUNDLE/Contents/MacOS/lpm-rs"
cp "$PROVISIONING_PROFILE" "$APP_BUNDLE/Contents/embedded.provisionprofile"
chmod 644 \
	"$APP_BUNDLE/Contents/Info.plist" \
	"$APP_BUNDLE/Contents/Resources/LPMCLI.icns" \
	"$APP_BUNDLE/Contents/embedded.provisionprofile"
chmod 755 "$APP_BUNDLE/Contents/MacOS/lpm-rs"

unexpected_entries="$(
	cd "$APP_BUNDLE"
	find . -print | grep -Ev '^(\.|\./Contents|\./Contents/Info\.plist|\./Contents/embedded\.provisionprofile|\./Contents/MacOS|\./Contents/MacOS/lpm-rs|\./Contents/Resources|\./Contents/Resources/LPMCLI\.icns)$' || true
)"
if [ -n "$unexpected_entries" ]; then
	echo "error: unsigned app assembly produced unexpected entries:" >&2
	printf '%s\n' "$unexpected_entries" >&2
	exit 1
fi

echo "Assembled $APP_BUNDLE"
