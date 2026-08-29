#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
SOURCE_ICON="$REPO_ROOT/assets/lpm-icon.svg"
OUTPUT_ICON="$REPO_ROOT/macos/LPMCLI.icns"

if [ "$(uname -s)" != "Darwin" ]; then
	echo "error: macOS icon generation requires macOS" >&2
	exit 1
fi

working_dir="$(mktemp -d "${TMPDIR:-/tmp}/lpm-macos-icon.XXXXXX")"
cleanup() {
	rm -rf -- "$working_dir"
}
trap cleanup EXIT

iconset_dir="$working_dir/LPMCLI.iconset"
mkdir "$iconset_dir"

# Quick Look renders the SVG onto the white canvas used by the approved CLI icon.
qlmanage -t -s 1024 -o "$working_dir" "$SOURCE_ICON" >/dev/null 2>&1
rendered_icon="$working_dir/$(basename "$SOURCE_ICON").png"
if [ ! -f "$rendered_icon" ]; then
	echo "error: Quick Look did not render $SOURCE_ICON" >&2
	exit 1
fi

for size in 16 32 128 256 512; do
	double_size=$((size * 2))
	sips -z "$size" "$size" "$rendered_icon" \
		--out "$iconset_dir/icon_${size}x${size}.png" >/dev/null
	sips -z "$double_size" "$double_size" "$rendered_icon" \
		--out "$iconset_dir/icon_${size}x${size}@2x.png" >/dev/null
done

generated_icon="$working_dir/LPMCLI.icns"
iconutil --convert icns --output "$generated_icon" "$iconset_dir"
cp "$generated_icon" "$OUTPUT_ICON"
chmod 644 "$OUTPUT_ICON"
echo "Generated $OUTPUT_ICON"
