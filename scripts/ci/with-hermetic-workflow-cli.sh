#!/bin/bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
	echo "usage: $0 <command> [args...]" >&2
	exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

cd "$REPO_ROOT"
cargo build --locked -p lpm-cli --bin lpm-rs --features internal-test-sigstore-mock

target_root="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
if [[ "$target_root" != /* ]]; then
	target_root="$REPO_ROOT/$target_root"
fi
target_root="$(cd "$target_root" && pwd -P)"

profile_root="$target_root/debug"
if [ -n "${CARGO_BUILD_TARGET:-}" ]; then
	if [[ "$CARGO_BUILD_TARGET" == */* || "$CARGO_BUILD_TARGET" == *..* ]]; then
		echo "error: CARGO_BUILD_TARGET must be a target triple" >&2
		exit 1
	fi
	profile_root="$target_root/$CARGO_BUILD_TARGET/debug"
fi

source_binary="$profile_root/lpm-rs"
binary_name="lpm-rs"
if [ ! -f "$source_binary" ] && [ -f "$source_binary.exe" ]; then
	source_binary="$source_binary.exe"
	binary_name="lpm-rs.exe"
fi
if [ ! -f "$source_binary" ] || [ -L "$source_binary" ] || [ ! -x "$source_binary" ]; then
	echo "error: feature-built lpm-rs binary is unavailable: $source_binary" >&2
	exit 1
fi

temp_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
staging_dir="$(mktemp -d "$temp_root/lpm-hermetic-workflow-cli.XXXXXX")"
cleanup() {
	case "$staging_dir" in
	"$temp_root"/lpm-hermetic-workflow-cli.*)
		if [ -d "$staging_dir" ] && [ ! -L "$staging_dir" ]; then
			rm -rf -- "$staging_dir"
		fi
		;;
	*)
		echo "error: refusing to remove unexpected staging path: $staging_dir" >&2
		;;
	esac
}
trap cleanup EXIT

staged_binary="$staging_dir/$binary_name"
cp "$source_binary" "$staged_binary"
chmod 500 "$staged_binary"

env "CARGO_BIN_EXE_lpm-rs=$staged_binary" "$@"
