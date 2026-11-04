#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
WRAPPER="$SCRIPT_DIR/with-hermetic-workflow-cli.sh"
TEST_ROOT="$(mktemp -d)"

cleanup() {
	rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/target/debug"

cat >"$TEST_ROOT/bin/cargo" <<'STUB'
#!/bin/bash
set -euo pipefail

if [ "$*" != "build --locked -p lpm-cli --bin lpm-rs --features internal-test-sigstore-mock" ]; then
	echo "unexpected cargo invocation: $*" >&2
	exit 1
fi

mkdir -p "$CARGO_TARGET_DIR/debug"
fixture_binary="$CARGO_TARGET_DIR/debug/lpm-rs${FIXTURE_SUFFIX:-}"
cat >"$fixture_binary" <<'BINARY'
#!/bin/bash
printf 'feature-built\n'
BINARY
chmod +x "$fixture_binary"
STUB
chmod +x "$TEST_ROOT/bin/cargo"

cat >"$TEST_ROOT/exercise-copy" <<'COMMAND'
#!/bin/bash
set -euo pipefail

selected_binary="$(printenv 'CARGO_BIN_EXE_lpm-rs')"
printf '%s\n' "$selected_binary" >"$SELECTED_BINARY_RECORD"
cat >"$CARGO_TARGET_DIR/debug/lpm-rs" <<'STALE'
#!/bin/bash
printf 'overwritten-default-build\n'
STALE
chmod +x "$CARGO_TARGET_DIR/debug/lpm-rs"
"$selected_binary"
COMMAND
chmod +x "$TEST_ROOT/exercise-copy"

selected_binary_record="$TEST_ROOT/selected-binary"
output="$({
	PATH="$TEST_ROOT/bin:$PATH" \
		CARGO_TARGET_DIR="$TEST_ROOT/target" \
		SELECTED_BINARY_RECORD="$selected_binary_record" \
		"$WRAPPER" "$TEST_ROOT/exercise-copy"
} 2>&1)"

if [ "$output" != "feature-built" ]; then
	echo "expected immutable feature binary, got: $output" >&2
	exit 1
fi

selected_binary="$(cat "$selected_binary_record")"
if [ -e "$selected_binary" ]; then
	echo "temporary feature binary was not removed: $selected_binary" >&2
	exit 1
fi

output="$({
    PATH="$TEST_ROOT/bin:$PATH" \
        CARGO_TARGET_DIR="$TEST_ROOT/target" \
        FIXTURE_SUFFIX=".exe" \
        SELECTED_BINARY_RECORD="$selected_binary_record" \
        "$WRAPPER" "$TEST_ROOT/exercise-copy"
} 2>&1)"
if [ "$output" != "feature-built" ] || [[ "$(cat "$selected_binary_record")" != *.exe ]]; then
    echo "expected Windows executable path, got: $output" >&2
    exit 1
fi
if [ -e "$(cat "$selected_binary_record")" ]; then
    echo "temporary Windows binary was not removed" >&2
    exit 1
fi

mkdir -p "$TEST_ROOT/prebuilt/debug"
cat >"$TEST_ROOT/prebuilt/debug/lpm-rs" <<'BINARY'
#!/bin/bash
printf 'prebuilt\n'
BINARY
chmod +x "$TEST_ROOT/prebuilt/debug/lpm-rs"

if ! output="$({
	PATH="$TEST_ROOT/bin:$PATH" \
		CARGO_TARGET_DIR="$TEST_ROOT/prebuilt" \
		SELECTED_BINARY_RECORD="$selected_binary_record" \
		"$WRAPPER" --prebuilt "$TEST_ROOT/exercise-copy"
} 2>&1)" || [ "$output" != "prebuilt" ]; then
	echo "expected --prebuilt to stage the existing binary without building, got: $output" >&2
	exit 1
fi
if [ -e "$(cat "$selected_binary_record")" ]; then
	echo "temporary prebuilt binary was not removed" >&2
	exit 1
fi

mkdir -p "$TEST_ROOT/unbuilt/debug"
if output="$(PATH="$TEST_ROOT/bin:$PATH" CARGO_TARGET_DIR="$TEST_ROOT/unbuilt" "$WRAPPER" --prebuilt true 2>&1)"; then
	echo "expected --prebuilt to fail when no binary was built" >&2
	exit 1
fi
if [[ "$output" != *"--prebuilt"* ]]; then
	echo "expected the missing-binary error to name --prebuilt, got: $output" >&2
	exit 1
fi

status=0
"$WRAPPER" --prebuilt >/dev/null 2>&1 || status=$?
if [ "$status" -ne 2 ]; then
	echo "expected usage exit 2 for --prebuilt without a command, got: $status" >&2
	exit 1
fi

echo "hermetic workflow CLI wrapper tests passed"
