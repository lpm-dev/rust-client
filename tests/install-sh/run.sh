#!/bin/sh
# Test harness for install.sh.
#
# Two cases run automatically:
#   1. Syntax check (`sh -n`) — catches malformed scripts on every CI run.
#   2. Fail-closed exit when neither sha256sum nor shasum is on PATH and
#      LPM_INSTALL_INSECURE is unset — pins the integrity-gate contract.
#
# Full HTTP-mock coverage (manifest 404, SHA mismatch, cosign verify,
# happy-path) lives in `MANUAL_TESTS.md`; the Rust-side wiremock suite
# in `crates/lpm-cli/src/commands/self_update.rs::tests` already pins
# the verifier semantics from the producer side.
#
# Run from anywhere: `sh tests/install-sh/run.sh`.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SH="$SCRIPT_DIR/../../install.sh"

if [ ! -f "$INSTALL_SH" ]; then
  echo "FAIL: install.sh not found at $INSTALL_SH" >&2
  exit 1
fi

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

# ── Case 1: syntax check ─────────────────────────────────────────
sh -n "$INSTALL_SH" || fail "install.sh has shell syntax errors"
pass "install.sh shell syntax"

# ── Case 2: fail-closed when sha256sum/shasum are missing ──────
# Drive install.sh under an empty PATH so neither sha256sum nor
# shasum resolves. install.sh must:
#   - exit non-zero
#   - print a message naming the missing tool
#   - NOT proceed to curl the binary
#
# We seed the empty PATH with the basic utilities install.sh's
# pre-SHA-check block uses (uname, sh, mktemp, rm, basename). The
# real shell builtins (`command`, `[`, `case`) come from the
# invoking shell itself and don't need to be symlinked.
EMPTY_BIN="$(mktemp -d)"
trap 'rm -rf "$EMPTY_BIN"' EXIT
for tool in sh uname mktemp rm basename grep awk curl sed; do
  src="$(command -v "$tool" 2>/dev/null || true)"
  if [ -n "$src" ]; then
    ln -s "$src" "$EMPTY_BIN/$tool"
  fi
done

actual_exit=0
out="$(PATH="$EMPTY_BIN" LPM_INSTALL_INSECURE="" sh "$INSTALL_SH" 2>&1)" || actual_exit=$?

if [ "$actual_exit" -eq 0 ]; then
  echo "$out"
  fail "install.sh exited 0 when neither sha256sum nor shasum is on PATH; expected non-zero"
fi
if ! echo "$out" | grep -q "neither 'sha256sum' nor 'shasum'"; then
  echo "$out"
  fail "install.sh did not print the expected 'neither sha256sum nor shasum' message"
fi
if ! echo "$out" | grep -q "LPM_INSTALL_INSECURE=1"; then
  echo "$out"
  fail "install.sh did not surface the LPM_INSTALL_INSECURE=1 escape valve"
fi
pass "fail-closed when SHA tools are missing"

echo
echo "All install.sh smoke tests passed."
