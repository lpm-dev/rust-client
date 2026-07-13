#!/bin/sh
# Test harness for install.sh.
#
# Covers:
#   - syntax check (`sh -n`)
#   - fail-closed when SHA tools missing (no LPM_INSTALL_INSECURE)
#   - LPM_INSTALL_INSECURE=1 opt-out succeeds without integrity gate
#   - LPM_INSTALL_TEST_API_URL / _DOWNLOAD_BASE loopback enforcement
#   - happy path (manifest + binary match, no cosign on PATH)
#   - explicit LPM_INSTALL_VERSION path (no latest-release API fetch)
#   - manifest 404 (release predates signed-install gate)
#   - bundle 404 (manifest present, bundle missing → fail-closed)
#   - SHA mismatch (manifest declares one SHA, binary has another)
#   - missing platform entry in manifest
#   - insecure opt-out bypasses missing-manifest gate
#
# Drives install.sh against a `serve.py` http.server on 127.0.0.1, with
# the LPM_INSTALL_TEST_API_URL and LPM_INSTALL_TEST_DOWNLOAD_BASE env
# vars steering all production endpoints at the local fixture server.
#
# Cosign is detected by install.sh via `command -v cosign`. These tests
# do NOT install cosign — the cosign branch in install.sh is opportunistic
# and a missing-cosign happy path is the realistic CI shape. Tests that
# need the cosign branch plant a stub binary onto PATH.
#
# Run from anywhere: `sh tests/install-sh/run.sh`.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/install.sh"
SERVE_PY="$SCRIPT_DIR/serve.py"
FIXTURE_VERSION="v0.43.1-test"

if [ ! -f "$INSTALL_SH" ]; then
  echo "FAIL: install.sh not found at $INSTALL_SH" >&2
  exit 1
fi

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

# ── Platform detection — match what install.sh detects on this host ──
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64|aarch64) PLATFORM="lpm-darwin-arm64" ;;
      x86_64) PLATFORM="lpm-darwin-x64" ;;
      *) fail "unsupported macOS arch $(uname -m) — extend the harness" ;;
    esac ;;
  Linux)
    case "$(uname -m)" in
      aarch64|arm64) PLATFORM="lpm-linux-arm64" ;;
      x86_64)
        if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
          PLATFORM="lpm-linux-x64-musl"
        else
          PLATFORM="lpm-linux-x64"
        fi
        ;;
      *) fail "unsupported Linux arch $(uname -m) — extend the harness" ;;
    esac ;;
  *) fail "unsupported OS $(uname -s) — install.sh tests run on macOS/Linux only" ;;
esac

# ── SHA hasher — same selection install.sh would make ──
if command -v sha256sum >/dev/null 2>&1; then SHA_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHA_TOOL="shasum -a 256"
else fail "neither sha256sum nor shasum is available on the harness runner"
fi

# ── Helpers ─────────────────────────────────────────────────────────

# Pick a free localhost port. Uses python so we don't depend on any
# specific netstat / ss flag set.
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# Start serve.py against a fixture dir. Sets globals SERVER_PID and
# SERVER_PORT. The caller is expected to call stop_server in a trap or
# at end of the test case.
start_server() {
  fixture_dir="$1"
  SERVER_PORT="$(free_port)"
  python3 "$SERVE_PY" "$fixture_dir" "$SERVER_PORT" >/dev/null 2>&1 &
  SERVER_PID=$!
  # Poll for the server. A 404 on `/__nope__` is the success signal
  # because it means the listener is accepting TCP connections and
  # speaking HTTP. We curl -o /dev/null with everything silenced and
  # let `curl --head` return 0 on any HTTP response (success OR 404),
  # which is exactly what we want here.
  i=0
  while [ $i -lt 30 ]; do
    if curl -s -o /dev/null --head -m 1 "http://127.0.0.1:$SERVER_PORT/__nope__" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
    i=$((i + 1))
  done
  fail "server on :$SERVER_PORT did not come up in 3s"
}

stop_server() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}

# Build the canonical happy-path fixture: a placeholder binary, its
# SHA-256, and a SHA256SUMS.txt + dummy bundle. Returns the fixture
# dir via FIXTURE_DIR.
make_happy_fixture() {
  FIXTURE_DIR="$(mktemp -d)"
  # API response — install.sh extracts `tag_name` via grep+sed.
  printf '{"tag_name": "%s"}\n' "$FIXTURE_VERSION" > "$FIXTURE_DIR/api.json"
  # Placeholder binary at the path install.sh expects after the
  # `$VERSION` is substituted. install.sh's $BASE_URL is the override,
  # so the path is `<base>/$PLATFORM` (NO $VERSION segment).
  printf 'happy-fixture-binary-bytes' > "$FIXTURE_DIR/$PLATFORM"
  bin_sha="$($SHA_TOOL "$FIXTURE_DIR/$PLATFORM" | awk '{print $1}')"
  printf '%s  %s\n' "$bin_sha" "$PLATFORM" > "$FIXTURE_DIR/SHA256SUMS.txt"
  # Dummy bundle. cosign isn't on PATH during these tests; the file's
  # presence just exercises the bundle-fetch step.
  printf 'dummy-sigstore-bundle' > "$FIXTURE_DIR/SHA256SUMS.txt.sigstore"
}

# Build a controlled PATH that has the essentials install.sh needs
# (sh, curl, sha256sum / shasum, etc.) but excludes cosign — every
# harness case below is the "no cosign on PATH" scenario per the
# top-of-file note. Setting CLEAN_PATH to a prepared dir of symlinks
# avoids inheriting the dev machine's cosign / brew layout.
build_clean_path() {
  CLEAN_PATH_DIR="$(mktemp -d)"
  # Tools install.sh shells out to during the integrity flow.
  for tool in sh uname mktemp rm basename grep awk curl sed cat tr chmod mv mkdir ln; do
    src="$(command -v "$tool" 2>/dev/null || true)"
    if [ -n "$src" ]; then
      ln -s "$src" "$CLEAN_PATH_DIR/$tool"
    fi
  done
  # Hasher — both shapes accepted; install.sh detects whichever it finds.
  if command -v sha256sum >/dev/null 2>&1; then
    ln -s "$(command -v sha256sum)" "$CLEAN_PATH_DIR/sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    ln -s "$(command -v shasum)" "$CLEAN_PATH_DIR/shasum"
  fi
}

# Run install.sh against the running server with a clean install dir.
# Sets RUN_OUT (combined stdout+stderr) and RUN_RC (exit code).
run_install_sh() {
  install_root="$(mktemp -d)"
  set +e
  RUN_OUT="$(
    PATH="$CLEAN_PATH_DIR" \
    LPM_INSTALL_TEST_API_URL="http://127.0.0.1:$SERVER_PORT/api.json" \
    LPM_INSTALL_TEST_DOWNLOAD_BASE="http://127.0.0.1:$SERVER_PORT" \
    HOME="$install_root" \
    LPM_INSTALL_INSECURE="${LPM_INSTALL_INSECURE:-}" \
    LPM_INSTALL_VERSION="${LPM_INSTALL_VERSION:-}" \
    sh "$INSTALL_SH" 2>&1
  )"
  RUN_RC=$?
  set -e
  RUN_INSTALL_DIR="$install_root/.lpm/bin"
}

build_clean_path

# ── Case 1: syntax check ─────────────────────────────────────────
sh -n "$INSTALL_SH" || fail "install.sh has shell syntax errors"
pass "install.sh shell syntax"

# ── Case 2: Linux x64 musl selects the musl artifact ──────────
rm -f "$CLEAN_PATH_DIR/uname"
printf '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n' > "$CLEAN_PATH_DIR/uname"
chmod +x "$CLEAN_PATH_DIR/uname"
printf '#!/bin/sh\necho "musl libc (x86_64)" >&2\nexit 1\n' > "$CLEAN_PATH_DIR/ldd"
chmod +x "$CLEAN_PATH_DIR/ldd"
fdir="$(mktemp -d)"
printf '{"tag_name": "%s"}\n' "$FIXTURE_VERSION" > "$fdir/api.json"
printf 'musl-binary-bytes' > "$fdir/lpm-linux-x64-musl"
sha="$($SHA_TOOL "$fdir/lpm-linux-x64-musl" | awk '{print $1}')"
printf '%s  %s\n' "$sha" "lpm-linux-x64-musl" > "$fdir/SHA256SUMS.txt"
printf 'dummy-sigstore-bundle' > "$fdir/SHA256SUMS.txt.sigstore"
trap 'stop_server' EXIT
start_server "$fdir"
run_install_sh
stop_server
trap - EXIT
[ "$RUN_RC" -eq 0 ] || fail "musl platform install failed with exit $RUN_RC; out: $RUN_OUT"
echo "$RUN_OUT" | grep -q "manifest does not enumerate" \
  && fail "musl platform selected the wrong manifest entry: $RUN_OUT"
[ -x "$RUN_INSTALL_DIR/lpm" ] || fail "musl platform did not install an executable"
rm -rf "$fdir" "$CLEAN_PATH_DIR"
build_clean_path
pass "Linux x64 musl selects the musl artifact"

# ── Case 3: Linux ARM64 musl fails instead of selecting GNU ────
rm -f "$CLEAN_PATH_DIR/uname"
printf '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo aarch64 ;; esac\n' > "$CLEAN_PATH_DIR/uname"
chmod +x "$CLEAN_PATH_DIR/uname"
printf '#!/bin/sh\necho "musl libc (aarch64)" >&2\nexit 1\n' > "$CLEAN_PATH_DIR/ldd"
chmod +x "$CLEAN_PATH_DIR/ldd"
actual_exit=0
out="$(PATH="$CLEAN_PATH_DIR" HOME="$(mktemp -d)" sh "$INSTALL_SH" 2>&1)" || actual_exit=$?
[ "$actual_exit" -ne 0 ] || fail "Linux ARM64 musl should fail without an official artifact"
echo "$out" | grep -q "Linux musl ARM64" \
  || fail "Linux ARM64 musl failure did not explain the unsupported target: $out"
rm -rf "$CLEAN_PATH_DIR"
build_clean_path
pass "Linux ARM64 musl does not select the GNU artifact"

# ── Case 4: fail-closed when sha256sum/shasum missing ──────────
empty_bin="$(mktemp -d)"
for tool in sh uname mktemp rm basename grep awk curl sed cat tr; do
  src="$(command -v "$tool" 2>/dev/null || true)"
  if [ -n "$src" ]; then
    ln -s "$src" "$empty_bin/$tool"
  fi
done
actual_exit=0
out="$(PATH="$empty_bin" LPM_INSTALL_INSECURE="" sh "$INSTALL_SH" 2>&1)" || actual_exit=$?
[ "$actual_exit" -ne 0 ] || fail "install.sh exited 0 when SHA tools missing; expected non-zero"
echo "$out" | grep -q "neither 'sha256sum' nor 'shasum'" \
  || fail "install.sh did not name the missing tool: $out"
echo "$out" | grep -q "LPM_INSTALL_INSECURE=1" \
  || fail "install.sh did not surface the LPM_INSTALL_INSECURE=1 escape valve: $out"
rm -rf "$empty_bin"
pass "fail-closed when SHA tools missing"

# ── Case 4: loopback enforcement on test override env vars ────
actual_exit=0
out="$(LPM_INSTALL_TEST_API_URL="http://attacker.example/x" sh "$INSTALL_SH" 2>&1)" || actual_exit=$?
[ "$actual_exit" -ne 0 ] || fail "non-loopback API URL should fail-closed; got exit 0"
echo "$out" | grep -q "127.0.0.1" || fail "expected loopback-only error: $out"
actual_exit=0
out="$(LPM_INSTALL_TEST_DOWNLOAD_BASE="http://attacker.example/x" sh "$INSTALL_SH" 2>&1)" || actual_exit=$?
[ "$actual_exit" -ne 0 ] || fail "non-loopback DOWNLOAD_BASE should fail-closed; got exit 0"
echo "$out" | grep -q "127.0.0.1" || fail "expected loopback-only error: $out"
pass "test-override env vars are loopback-gated"

# ── Case 5: happy path ─────────────────────────────────────────
make_happy_fixture
trap 'stop_server' EXIT
start_server "$FIXTURE_DIR"
run_install_sh
stop_server
trap - EXIT
[ "$RUN_RC" -eq 0 ] || fail "happy-path exit code was $RUN_RC; out: $RUN_OUT"
echo "$RUN_OUT" | grep -q "Verified SHA-256:" \
  || fail "happy-path did not log SHA verification: $RUN_OUT"
[ -x "$RUN_INSTALL_DIR/lpm" ] \
  || fail "happy-path did not produce executable at $RUN_INSTALL_DIR/lpm"
# Bytes installed must match the fixture binary's bytes exactly —
# guards against a future regression that "verifies" but installs
# different bytes.
installed_sha="$($SHA_TOOL "$RUN_INSTALL_DIR/lpm" | awk '{print $1}')"
fixture_sha="$($SHA_TOOL "$FIXTURE_DIR/$PLATFORM" | awk '{print $1}')"
[ "$installed_sha" = "$fixture_sha" ] \
  || fail "happy-path installed bytes differ from fixture (installed=$installed_sha fixture=$fixture_sha)"
rm -rf "$FIXTURE_DIR"
pass "happy path installs the verified binary"

# ── Case 6: explicit version skips the latest-release API ──────
fdir="$(mktemp -d)"
printf 'explicit-version-binary-bytes' > "$fdir/$PLATFORM"
sha="$($SHA_TOOL "$fdir/$PLATFORM" | awk '{print $1}')"
printf '%s  %s\n' "$sha" "$PLATFORM" > "$fdir/SHA256SUMS.txt"
printf 'dummy-sigstore-bundle' > "$fdir/SHA256SUMS.txt.sigstore"
# Deliberately omit api.json. If install.sh still fetches the latest
# release API while LPM_INSTALL_VERSION is set, this case fails closed.
trap 'stop_server' EXIT
start_server "$fdir"
LPM_INSTALL_VERSION="$FIXTURE_VERSION" run_install_sh
unset LPM_INSTALL_VERSION
stop_server
trap - EXIT
[ "$RUN_RC" -eq 0 ] || fail "explicit-version path failed with exit $RUN_RC; out: $RUN_OUT"
echo "$RUN_OUT" | grep -q "Using requested version $FIXTURE_VERSION" \
  || fail "explicit-version path did not acknowledge requested version: $RUN_OUT"
[ -x "$RUN_INSTALL_DIR/lpm" ] \
  || fail "explicit-version path did not produce executable at $RUN_INSTALL_DIR/lpm"
rm -rf "$fdir"
pass "explicit version installs without latest-release API"

# ── Case 7: manifest 404 fails closed ─────────────────────────
fdir="$(mktemp -d)"
printf '{"tag_name": "%s"}\n' "$FIXTURE_VERSION" > "$fdir/api.json"
printf 'placeholder' > "$fdir/$PLATFORM"
printf 'bundle' > "$fdir/SHA256SUMS.txt.sigstore"
# Deliberately omit SHA256SUMS.txt — server returns 404.
trap 'stop_server' EXIT
start_server "$fdir"
run_install_sh
stop_server
trap - EXIT
[ "$RUN_RC" -ne 0 ] || fail "missing-manifest must fail-closed; got exit 0 with out: $RUN_OUT"
echo "$RUN_OUT" | grep -q "does not ship a signed checksums manifest" \
  || fail "expected 'does not ship a signed checksums manifest': $RUN_OUT"
[ ! -e "$RUN_INSTALL_DIR/lpm" ] || fail "missing-manifest must not install anything"
rm -rf "$fdir"
pass "manifest 404 fails closed"

# ── Case 8: bundle 404 fails closed ───────────────────────────
fdir="$(mktemp -d)"
printf '{"tag_name": "%s"}\n' "$FIXTURE_VERSION" > "$fdir/api.json"
printf 'placeholder' > "$fdir/$PLATFORM"
sha="$($SHA_TOOL "$fdir/$PLATFORM" | awk '{print $1}')"
printf '%s  %s\n' "$sha" "$PLATFORM" > "$fdir/SHA256SUMS.txt"
# Bundle file omitted — 404.
trap 'stop_server' EXIT
start_server "$fdir"
run_install_sh
stop_server
trap - EXIT
# install.sh treats bundle 404 as a soft skip (cosign branch can't run);
# SHA gate still runs and passes against the matching manifest. This
# encodes the "bundle is opportunistic, manifest is the floor" contract.
[ "$RUN_RC" -eq 0 ] || fail "bundle-404 should still install via SHA-only path; got exit $RUN_RC: $RUN_OUT"
echo "$RUN_OUT" | grep -q "Verified SHA-256:" \
  || fail "bundle-404 SHA-only path did not run: $RUN_OUT"
echo "$RUN_OUT" | grep -q "Verified Sigstore" \
  && fail "bundle-404 should NOT claim Sigstore verification: $RUN_OUT"
[ -x "$RUN_INSTALL_DIR/lpm" ] || fail "bundle-404 SHA path did not install"
rm -rf "$fdir"
pass "bundle 404 falls back to SHA-only floor"

# ── Case 9: SHA mismatch fails closed ─────────────────────────
fdir="$(mktemp -d)"
printf '{"tag_name": "%s"}\n' "$FIXTURE_VERSION" > "$fdir/api.json"
printf 'real-bytes' > "$fdir/$PLATFORM"
# Manifest lists a wrong SHA (all zeros) for the platform.
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" "$PLATFORM" \
  > "$fdir/SHA256SUMS.txt"
printf 'bundle' > "$fdir/SHA256SUMS.txt.sigstore"
trap 'stop_server' EXIT
start_server "$fdir"
run_install_sh
stop_server
trap - EXIT
[ "$RUN_RC" -ne 0 ] || fail "SHA mismatch must fail-closed; got exit 0: $RUN_OUT"
echo "$RUN_OUT" | grep -q "SHA-256 mismatch" \
  || fail "expected 'SHA-256 mismatch': $RUN_OUT"
[ ! -e "$RUN_INSTALL_DIR/lpm" ] || fail "SHA mismatch must not install"
rm -rf "$fdir"
pass "SHA mismatch fails closed"

# ── Case 10: missing platform entry in manifest ──────────────
fdir="$(mktemp -d)"
printf '{"tag_name": "%s"}\n' "$FIXTURE_VERSION" > "$fdir/api.json"
printf 'real-bytes' > "$fdir/$PLATFORM"
# Manifest enumerates SOME other platform but not the running one.
printf '0000000000000000000000000000000000000000000000000000000000000000  lpm-some-other-platform\n' \
  > "$fdir/SHA256SUMS.txt"
printf 'bundle' > "$fdir/SHA256SUMS.txt.sigstore"
trap 'stop_server' EXIT
start_server "$fdir"
run_install_sh
stop_server
trap - EXIT
[ "$RUN_RC" -ne 0 ] || fail "missing-platform-entry must fail-closed; got exit 0: $RUN_OUT"
echo "$RUN_OUT" | grep -q "manifest does not enumerate" \
  || fail "expected 'manifest does not enumerate': $RUN_OUT"
[ ! -e "$RUN_INSTALL_DIR/lpm" ] || fail "missing-platform-entry must not install"
rm -rf "$fdir"
pass "missing platform entry fails closed"

# ── Case 11: LPM_INSTALL_INSECURE=1 bypasses missing manifest ─
fdir="$(mktemp -d)"
printf '{"tag_name": "%s"}\n' "$FIXTURE_VERSION" > "$fdir/api.json"
printf 'unsigned-bytes' > "$fdir/$PLATFORM"
# Deliberately no manifest.
trap 'stop_server' EXIT
start_server "$fdir"
LPM_INSTALL_INSECURE=1 run_install_sh
stop_server
trap - EXIT
unset LPM_INSTALL_INSECURE
[ "$RUN_RC" -eq 0 ] || fail "LPM_INSTALL_INSECURE=1 must succeed despite missing manifest; exit $RUN_RC: $RUN_OUT"
echo "$RUN_OUT" | grep -q "LPM_INSTALL_INSECURE=1" \
  || fail "expected loud WARN line referencing LPM_INSTALL_INSECURE=1: $RUN_OUT"
[ -x "$RUN_INSTALL_DIR/lpm" ] || fail "insecure opt-out should install"
rm -rf "$fdir"
pass "LPM_INSTALL_INSECURE=1 bypasses missing-manifest gate"

echo
echo "All install.sh harness tests passed."
