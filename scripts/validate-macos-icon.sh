#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
INFO_PLIST="$REPO_ROOT/macos/LPMCLI-Info.plist"
ICON="$REPO_ROOT/macos/LPMCLI.icns"

if [ "$(uname -s)" != "Darwin" ]; then
	echo "error: macOS icon validation requires macOS" >&2
	exit 1
fi

if [ ! -f "$ICON" ] || [ -L "$ICON" ]; then
	echo "error: macOS icon is not a regular file: $ICON" >&2
	exit 1
fi

plutil -lint "$INFO_PLIST" >/dev/null
declared_icon="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIconFile' "$INFO_PLIST")"
if [ "$declared_icon" != "LPMCLI.icns" ]; then
	echo "error: CFBundleIconFile must be LPMCLI.icns" >&2
	exit 1
fi

working_dir="$(mktemp -d "${TMPDIR:-/tmp}/lpm-macos-icon-check.XXXXXX")"
cleanup() {
	rm -rf -- "$working_dir"
}
trap cleanup EXIT

iconset_dir="$working_dir/LPMCLI.iconset"
iconutil --convert iconset --output "$iconset_dir" "$ICON"

entry_count="$(find "$iconset_dir" -type f | wc -l | tr -d '[:space:]')"
if [ "$entry_count" != "10" ]; then
	echo "error: LPMCLI.icns must contain exactly 10 icon representations" >&2
	exit 1
fi

validate_size() {
	icon_path="$1"
	expected_size="$2"
	if [ ! -f "$icon_path" ]; then
		echo "error: missing icon representation: $icon_path" >&2
		exit 1
	fi
	width="$(sips -g pixelWidth "$icon_path" | awk '/pixelWidth/{print $2}')"
	height="$(sips -g pixelHeight "$icon_path" | awk '/pixelHeight/{print $2}')"
	if [ "$width" != "$expected_size" ] || [ "$height" != "$expected_size" ]; then
		echo "error: $icon_path is ${width}x${height}; expected ${expected_size}x${expected_size}" >&2
		exit 1
	fi
}

for size in 16 32 128 256 512; do
	double_size=$((size * 2))
	validate_size "$iconset_dir/icon_${size}x${size}.png" "$size"
	validate_size "$iconset_dir/icon_${size}x${size}@2x.png" "$double_size"
done

echo "Validated $ICON"
