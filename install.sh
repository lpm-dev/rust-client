#!/bin/sh
# LPM CLI installer
# Usage: curl -fsSL https://raw.githubusercontent.com/lpm-dev/rust-client/main/install.sh | sh
#
# Installs the latest (or requested) LPM CLI binary to ~/.lpm/bin and adds it to PATH.
# Every downloaded byte is verified against a signed SHA256SUMS.txt
# manifest before chmod +x; cosign verify-blob runs opportunistically
# when a cosign binary is on PATH. Set LPM_INSTALL_INSECURE=1 to skip
# all integrity checks (NOT recommended; emergency-recovery only).
# Set LPM_INSTALL_CHANNEL=nightly to install the latest nightly.
# Set LPM_INSTALL_VERSION=vX.Y.Z to install a specific release tag.

set -e

if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  echo "LPM CLI does not support installation through sudo." >&2
  echo "Run the installer without sudo. It installs into your user home directory." >&2
  exit 1
fi

REPO="lpm-dev/rust-client"
INSTALL_DIR="$HOME/.lpm/bin"
LIBEXEC_DIR="$HOME/.lpm/libexec"
BINARY_NAME="lpm"
ALIAS_NAME="lpx"
EXPECTED_APP_NAME="LPM CLI.app"
EXPECTED_BUNDLE_ID="dev.lpm.cli"
EXPECTED_TEAM_ID="823S8YKMRW"
EXPECTED_ACCESS_GROUP="$EXPECTED_TEAM_ID.dev.lpm.vault.shared"
EXPECTED_PROFILE_ACCESS_GROUP="$EXPECTED_TEAM_ID.*"
MACOS_BUNDLE=0
LEGACY_MACOS=0

plist_array_contains_exact() {
  plist_values_="$1"
  expected_value_="$2"
  printf '%s\n' "$plist_values_" | awk -v expected="$expected_value_" '
    {
      value = $0
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (value == expected) found = 1
    }
    END { exit(found ? 0 : 1) }
  '
}

# Minimum version this installer is willing to deliver. Bumped manually
# alongside each release that fixes a security-relevant gap. The floor
# is a downgrade-resistance gate: an attacker who controls the GitHub
# API response (or a downstream mirror) cannot point a fresh installer
# at an old, known-vulnerable release — even one with a valid SHA-256
# manifest and Sigstore signature (the old release IS authentically
# signed; the floor refuses to install it anyway).
#
# Override only as documented recovery; sets the same signal as
# LPM_INSTALL_INSECURE but scoped to the floor check.
MIN_VERSION="v0.43.0"

# Strict POSIX vX.Y.Z[-prerelease] comparator. Pre-release suffixes are
# trimmed before comparison: `v0.43.0-rc1 < v0.43.0` per the relaxed
# pre-release-equals-stable convention we ship in this installer.
# Returns 0 (true) if $1 < $2, non-zero otherwise.
version_lt() {
  v1_=${1#v}; v1_=${v1_%%-*}
  v2_=${2#v}; v2_=${v2_%%-*}
  a1_=$(echo "$v1_" | cut -d. -f1); b1_=$(echo "$v1_" | cut -d. -f2); c1_=$(echo "$v1_" | cut -d. -f3)
  a2_=$(echo "$v2_" | cut -d. -f1); b2_=$(echo "$v2_" | cut -d. -f2); c2_=$(echo "$v2_" | cut -d. -f3)
  a1_=${a1_:-0}; b1_=${b1_:-0}; c1_=${c1_:-0}
  a2_=${a2_:-0}; b2_=${b2_:-0}; c2_=${c2_:-0}
  if [ "$a1_" -lt "$a2_" ]; then return 0; fi
  if [ "$a1_" -gt "$a2_" ]; then return 1; fi
  if [ "$b1_" -lt "$b2_" ]; then return 0; fi
  if [ "$b1_" -gt "$b2_" ]; then return 1; fi
  [ "$c1_" -lt "$c2_" ]
}

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

linux_libc() {
  if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    echo musl
    return
  fi
  case "$1" in
    x86_64) loader_="/lib/ld-musl-x86_64.so.1" ;;
    aarch64|arm64) loader_="/lib/ld-musl-aarch64.so.1" ;;
    *) loader_="" ;;
  esac
  if [ -n "$loader_" ] && [ -e "$loader_" ]; then
    echo musl
  else
    echo glibc
  fi
}

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64|aarch64) PLATFORM="lpm-darwin-arm64" ;;
      x86_64)        PLATFORM="lpm-darwin-x64" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    MACOS_BUNDLE=1
    ;;
  Linux)
    case "$ARCH" in
      aarch64|arm64)
        if [ "$(linux_libc "$ARCH")" = "musl" ]; then
          echo "Unsupported platform: Linux musl ARM64"
          echo "Official musl releases currently support x86_64. Build from source on ARM64."
          exit 1
        fi
        PLATFORM="lpm-linux-arm64"
        ;;
      x86_64)
        if [ "$(linux_libc "$ARCH")" = "musl" ]; then
          PLATFORM="lpm-linux-x64-musl"
        else
          PLATFORM="lpm-linux-x64"
        fi
        ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS"
    echo "For Windows, use: npm install -g @lpm-registry/cli"
    exit 1
    ;;
esac

# Resolve a SHA-256 hasher. macOS ships `shasum -a 256`, Linux ships
# `sha256sum`. Both produce `<hex>  <name>`. Fail-closed when neither
# is available; LPM_INSTALL_INSECURE=1 is the documented escape valve.
if command -v sha256sum >/dev/null 2>&1; then
  SHA_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_TOOL="shasum -a 256"
else
  if [ "${LPM_INSTALL_INSECURE:-0}" = "1" ]; then
    echo "WARN: no sha256sum/shasum on PATH; LPM_INSTALL_INSECURE=1 set, proceeding without integrity check"
    SHA_TOOL=""
  else
    echo "ERROR: neither 'sha256sum' nor 'shasum' is available on PATH"
    echo "       (apt-get install coreutils / brew install coreutils)"
    echo "Cannot verify the LPM download integrity without one of them."
    echo "Emergency workaround: LPM_INSTALL_INSECURE=1 sh install.sh"
    echo "                      (NOT recommended; skips ALL integrity checks)"
    exit 1
  fi
fi

# Resolve the API + download endpoints. Tests point both at a local
# http.server on 127.0.0.1; production always uses GitHub. Test overrides
# are loopback-gated — a non-loopback value triggers a hard fail rather
# than silently steering the install at an attacker-controlled host.
# Both env vars are validated UP FRONT (before any curl) so a single
# malicious value is rejected even when the other is unset.
is_loopback_http() {
  case "$1" in
    http://*) loopback_authority=${1#http://} ;;
    *) return 1 ;;
  esac
  loopback_authority=${loopback_authority%%/*}
  case "$loopback_authority" in
    127.0.0.1|localhost|'[::1]') return 0 ;;
    127.0.0.1:*|localhost:*|'[::1]':*)
      loopback_port=${loopback_authority##*:}
      case "$loopback_port" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

if [ -n "${LPM_INSTALL_TEST_API_URL:-}" ] && ! is_loopback_http "$LPM_INSTALL_TEST_API_URL"; then
  echo "ERROR: LPM_INSTALL_TEST_API_URL must point at 127.0.0.1 / localhost / [::1] over http"
  exit 1
fi
if [ -n "${LPM_INSTALL_TEST_DOWNLOAD_BASE:-}" ] && ! is_loopback_http "$LPM_INSTALL_TEST_DOWNLOAD_BASE"; then
  echo "ERROR: LPM_INSTALL_TEST_DOWNLOAD_BASE must point at 127.0.0.1 / localhost / [::1] over http"
  exit 1
fi
if [ -n "${LPM_INSTALL_TEST_INTERRUPT_AFTER:-}" ] && { \
   [ -z "${LPM_INSTALL_TEST_API_URL:-}" ] || \
   [ -z "${LPM_INSTALL_TEST_DOWNLOAD_BASE:-}" ]; \
}; then
  echo "ERROR: installer interruption hooks require both loopback test endpoints"
  exit 1
fi

MACOS_CODESIGN_TOOL="/usr/bin/codesign"
MACOS_SECURITY_TOOL="/usr/bin/security"
MACOS_SPCTL_TOOL="/usr/sbin/spctl"
MACOS_XCRUN_TOOL="/usr/bin/xcrun"
MACOS_DITTO_TOOL="/usr/bin/ditto"
MACOS_UNZIP_TOOL="/usr/bin/unzip"

if [ -n "${LPM_INSTALL_TEST_CODESIGN:-}${LPM_INSTALL_TEST_SECURITY:-}${LPM_INSTALL_TEST_SPCTL:-}${LPM_INSTALL_TEST_XCRUN:-}" ]; then
  if [ "$OS" != "Darwin" ] || \
     [ -z "${LPM_INSTALL_TEST_API_URL:-}" ] || \
     [ -z "${LPM_INSTALL_TEST_DOWNLOAD_BASE:-}" ]; then
    echo "ERROR: macOS tool overrides require both loopback test endpoints on macOS"
    exit 1
  fi
  MACOS_CODESIGN_TOOL="${LPM_INSTALL_TEST_CODESIGN:-$MACOS_CODESIGN_TOOL}"
  MACOS_SECURITY_TOOL="${LPM_INSTALL_TEST_SECURITY:-$MACOS_SECURITY_TOOL}"
  MACOS_SPCTL_TOOL="${LPM_INSTALL_TEST_SPCTL:-$MACOS_SPCTL_TOOL}"
  MACOS_XCRUN_TOOL="${LPM_INSTALL_TEST_XCRUN:-$MACOS_XCRUN_TOOL}"
fi

REQUESTED_VERSION="${LPM_INSTALL_VERSION:-}"
INSTALL_CHANNEL="${LPM_INSTALL_CHANNEL:-stable}"

case "$INSTALL_CHANNEL" in
  stable|nightly) ;;
  *)
    echo "ERROR: LPM_INSTALL_CHANNEL must be 'stable' or 'nightly' (got '$INSTALL_CHANNEL')"
    exit 1
    ;;
esac

if [ -n "$REQUESTED_VERSION" ]; then
  VERSION="$REQUESTED_VERSION"
  echo "Using requested version $VERSION..."
else
  if [ "$INSTALL_CHANNEL" = "nightly" ]; then
    API_URL="${LPM_INSTALL_TEST_API_URL:-https://registry.npmjs.org/@lpm-registry/cli/nightly}"
    echo "Detecting latest nightly version..."
  else
    API_URL="${LPM_INSTALL_TEST_API_URL:-https://api.github.com/repos/$REPO/releases/latest}"
    echo "Detecting latest stable version..."
  fi
  API_RESPONSE="$(curl -fsSL --max-time 30 "$API_URL")" || {
    echo "Failed to detect latest $INSTALL_CHANNEL version. Check https://github.com/$REPO/releases"
    exit 1
  }
  if [ "$INSTALL_CHANNEL" = "nightly" ]; then
    VERSION=$(printf '%s\n' "$API_RESPONSE" | grep -m 1 '"version"' | sed -E 's/.*"version": *"([^"]+)".*/v\1/')
  else
    VERSION=$(printf '%s\n' "$API_RESPONSE" | grep -m 1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  fi
fi

if [ -z "$VERSION" ]; then
  echo "Failed to detect latest $INSTALL_CHANNEL version. Check https://github.com/$REPO/releases"
  exit 1
fi

if ! printf '%s\n' "$VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'; then
  echo "ERROR: detected version '$VERSION' does not match expected vX.Y.Z[-prerelease] format"
  echo "       This is a strong tampering signal — the release registry or a"
  echo "       downstream mirror returned an unexpected version. Refusing to install."
  exit 1
fi

if [ -z "$REQUESTED_VERSION" ]; then
  if [ "$INSTALL_CHANNEL" = "stable" ] && printf '%s\n' "$VERSION" | grep -q -- '-'; then
    echo "ERROR: stable channel returned prerelease version '$VERSION'; refusing to install."
    exit 1
  fi
  if [ "$INSTALL_CHANNEL" = "nightly" ] && ! printf '%s\n' "$VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-nightly\.[0-9]{8}\.(0|[1-9][0-9]*)\.([0-9a-f]{7,40}|g0[0-9]{6})$'; then
    echo "ERROR: nightly channel returned non-nightly version '$VERSION'; refusing to install."
    exit 1
  fi
fi

RESOLVED_CHANNEL="$INSTALL_CHANNEL"
if [ -n "$REQUESTED_VERSION" ]; then
  case "$VERSION" in
    *-nightly.*) RESOLVED_CHANNEL="nightly" ;;
    *) RESOLVED_CHANNEL="stable" ;;
  esac
fi

# Downgrade gate. An attacker who controls the API response can point
# the installer at an old release that still carries valid SHA-256
# and Sigstore signatures (it IS an authentic release) but predates
# a fix the user is implicitly relying on. The floor refuses anything
# below MIN_VERSION unless the user opts out by name.
if version_lt "$VERSION" "$MIN_VERSION"; then
  if [ "${LPM_INSTALL_MIN_VERSION_OVERRIDE:-0}" = "1" ]; then
    echo "WARN: $VERSION is below the configured minimum $MIN_VERSION."
    echo "      LPM_INSTALL_MIN_VERSION_OVERRIDE=1 set — proceeding anyway."
  else
    echo "ERROR: detected version $VERSION is below the minimum supported $MIN_VERSION."
    echo ""
    echo "This installer refuses to deliver releases older than $MIN_VERSION because"
    echo "they predate at least one security fix that would otherwise be silently"
    echo "downgraded. If you are recovering from a release-pipeline incident and need"
    echo "an older release on purpose, set LPM_INSTALL_MIN_VERSION_OVERRIDE=1 to bypass"
    echo "(NOT recommended; downloads will still be SHA-256 + Sigstore verified)."
    echo ""
    echo "If you did NOT expect to land on an old release, treat this as an attack"
    echo "signal and check https://github.com/$REPO/releases directly."
    exit 1
  fi
fi

echo "Installing LPM CLI $VERSION ($RESOLVED_CHANNEL channel) for $OS/$ARCH..."

BASE_URL="${LPM_INSTALL_TEST_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download/$VERSION}"

MANIFEST_URL="$BASE_URL/SHA256SUMS.txt"
BUNDLE_URL="$BASE_URL/SHA256SUMS.txt.sigstore"

# Stage downloads into a temp dir so a failed verification never
# leaves a half-installed binary in $INSTALL_DIR. Cleanup runs on
# any exit shape (success, error, SIGINT) so we don't accumulate
# stragglers when integrity gates trip.
mkdir -p "$INSTALL_DIR"
STAGE_DIR="$(mktemp -d)"
BUNDLE_STAGE_ROOT=""
BUNDLE_TRANSACTION_ACTIVE=0
BUNDLE_ROLLBACK_INCOMPLETE=0
BUNDLE_MOVED_APP=0
BUNDLE_MOVED_LPM=0
BUNDLE_MOVED_LPX=0
BUNDLE_INSTALLED_APP=0
BUNDLE_INSTALLED_LPM=0
BUNDLE_INSTALLED_LPX=0
BUNDLE_STAGED_APP=""
BUNDLE_PREVIOUS_APP=""
BUNDLE_PREVIOUS_LPM=""
BUNDLE_PREVIOUS_LPX=""
BUNDLE_FINAL_APP=""
BUNDLE_FINAL_LPM="$INSTALL_DIR/$BINARY_NAME"
BUNDLE_FINAL_LPX="$INSTALL_DIR/$ALIAS_NAME"

rollback_macos_bundle_transaction() {
  [ "$BUNDLE_TRANSACTION_ACTIVE" = "1" ] || return 0

  # Rollback is single-shot. The EXIT trap must never repeat successful
  # inverse operations after a later inverse fails.
  BUNDLE_TRANSACTION_ACTIVE=0
  rollback_ok=1
  if [ "$BUNDLE_INSTALLED_LPM" = "1" ]; then
    if { [ ! -e "$BUNDLE_FINAL_LPM" ] && [ ! -L "$BUNDLE_FINAL_LPM" ]; } || \
       rm -f "$BUNDLE_FINAL_LPM"; then
      BUNDLE_INSTALLED_LPM=0
    else
      rollback_ok=0
    fi
  fi
  if [ "$BUNDLE_INSTALLED_LPX" = "1" ]; then
    if { [ ! -e "$BUNDLE_FINAL_LPX" ] && [ ! -L "$BUNDLE_FINAL_LPX" ]; } || \
       rm -f "$BUNDLE_FINAL_LPX"; then
      BUNDLE_INSTALLED_LPX=0
    else
      rollback_ok=0
    fi
  fi
  if [ "$BUNDLE_INSTALLED_APP" = "1" ]; then
    if [ ! -e "$BUNDLE_FINAL_APP" ] && [ ! -L "$BUNDLE_FINAL_APP" ]; then
      BUNDLE_INSTALLED_APP=0
    elif { [ -e "$BUNDLE_STAGED_APP" ] || [ -L "$BUNDLE_STAGED_APP" ]; }; then
      rollback_ok=0
    elif mv "$BUNDLE_FINAL_APP" "$BUNDLE_STAGED_APP"; then
      BUNDLE_INSTALLED_APP=0
    else
      rollback_ok=0
    fi
  fi

  if [ "$BUNDLE_MOVED_APP" = "1" ]; then
    if { [ ! -e "$BUNDLE_PREVIOUS_APP" ] && [ ! -L "$BUNDLE_PREVIOUS_APP" ]; } || \
       { [ -e "$BUNDLE_FINAL_APP" ] || [ -L "$BUNDLE_FINAL_APP" ]; }; then
      rollback_ok=0
    elif mv "$BUNDLE_PREVIOUS_APP" "$BUNDLE_FINAL_APP"; then
      BUNDLE_MOVED_APP=0
    else
      rollback_ok=0
    fi
  fi
  if [ "$BUNDLE_MOVED_LPM" = "1" ]; then
    if { [ ! -e "$BUNDLE_PREVIOUS_LPM" ] && [ ! -L "$BUNDLE_PREVIOUS_LPM" ]; } || \
       { [ -e "$BUNDLE_FINAL_LPM" ] || [ -L "$BUNDLE_FINAL_LPM" ]; }; then
      rollback_ok=0
    elif mv "$BUNDLE_PREVIOUS_LPM" "$BUNDLE_FINAL_LPM"; then
      BUNDLE_MOVED_LPM=0
    else
      rollback_ok=0
    fi
  fi
  if [ "$BUNDLE_MOVED_LPX" = "1" ]; then
    if { [ ! -e "$BUNDLE_PREVIOUS_LPX" ] && [ ! -L "$BUNDLE_PREVIOUS_LPX" ]; } || \
       { [ -e "$BUNDLE_FINAL_LPX" ] || [ -L "$BUNDLE_FINAL_LPX" ]; }; then
      rollback_ok=0
    elif mv "$BUNDLE_PREVIOUS_LPX" "$BUNDLE_FINAL_LPX"; then
      BUNDLE_MOVED_LPX=0
    else
      rollback_ok=0
    fi
  fi

  if [ "$rollback_ok" = "1" ]; then
    return 0
  fi

  BUNDLE_ROLLBACK_INCOMPLETE=1
  echo "ERROR: macOS installation rollback was incomplete." >&2
  echo "Rollback data was retained at $BUNDLE_STAGE_ROOT" >&2
  return 1
}

cleanup() {
  rm -rf "$STAGE_DIR"
  if [ -n "$BUNDLE_STAGE_ROOT" ] && [ "$BUNDLE_ROLLBACK_INCOMPLETE" != "1" ]; then
    rm -rf "$BUNDLE_STAGE_ROOT"
  fi
}

on_exit() {
  exit_status=$?
  trap - 0 HUP INT TERM
  if [ "$BUNDLE_TRANSACTION_ACTIVE" = "1" ]; then
    echo "ERROR: macOS installation was interrupted; restoring the previous installation." >&2
    if ! rollback_macos_bundle_transaction; then exit_status=1; fi
  fi
  cleanup
  exit "$exit_status"
}

interrupt_install_test_after() {
  [ "${LPM_INSTALL_TEST_INTERRUPT_AFTER:-}" = "$1" ] || return 0
  kill -TERM "$$"
  exit 1
}

trap on_exit 0
trap 'exit 1' HUP INT TERM
MANIFEST_TMP="$STAGE_DIR/SHA256SUMS.txt"
BUNDLE_TMP="$STAGE_DIR/SHA256SUMS.txt.sigstore"

if [ "${LPM_INSTALL_INSECURE:-0}" = "1" ]; then
  echo "WARN: LPM_INSTALL_INSECURE=1 — skipping ALL integrity checks"
elif [ -n "$SHA_TOOL" ]; then
  echo "Fetching signed checksums manifest..."
  if ! curl -fsSL --max-time 30 "$MANIFEST_URL" -o "$MANIFEST_TMP"; then
    echo "ERROR: release $VERSION does not ship a signed checksums manifest"
    echo "       ($MANIFEST_URL is missing)."
    echo "This release predates LPM's signed-install gate. Install manually:"
    echo "  https://github.com/$REPO/releases/$VERSION"
    echo "Or set LPM_INSTALL_INSECURE=1 to skip integrity verification (NOT recommended)."
    exit 1
  fi
  # Bundle is opportunistic — cosign verify only fires when both the
  # bundle AND cosign are present. Bundle 404 is not an attack signal
  # by itself (the SHA gate still runs), but missing-cosign means we
  # cannot make a stronger claim, so we degrade quietly.
  curl -fsSL --max-time 30 "$BUNDLE_URL" -o "$BUNDLE_TMP" 2>/dev/null || rm -f "$BUNDLE_TMP"
fi

RELEASE_ASSET="$PLATFORM"
if [ "$MACOS_BUNDLE" = "1" ]; then
  RELEASE_ASSET="$PLATFORM.zip"
  if [ "${LPM_INSTALL_INSECURE:-0}" != "1" ] && [ -n "$SHA_TOOL" ]; then
    if ! awk -v p="$RELEASE_ASSET" '$2 == p { found=1 } END { exit !found }' "$MANIFEST_TMP"; then
      # Only the final pre-bundle release may use the historical raw asset.
      if [ "$VERSION" = "v0.75.0" ] && \
         awk -v p="$PLATFORM" '$2 == p { found=1 } END { exit !found }' "$MANIFEST_TMP"; then
        RELEASE_ASSET="$PLATFORM"
        LEGACY_MACOS=1
      else
        echo "ERROR: manifest does not enumerate the required $PLATFORM.zip bundle; cannot verify download."
        exit 1
      fi
    fi
  fi
fi

URL="$BASE_URL/$RELEASE_ASSET"
DOWNLOAD_TMP="$STAGE_DIR/$RELEASE_ASSET"
if ! curl -fsSL --max-time 300 "$URL" -o "$DOWNLOAD_TMP"; then
  if [ "$MACOS_BUNDLE" = "1" ] && \
     [ "${LPM_INSTALL_INSECURE:-0}" = "1" ] && \
     [ "$VERSION" = "v0.75.0" ]; then
    RELEASE_ASSET="$PLATFORM"
    LEGACY_MACOS=1
    URL="$BASE_URL/$RELEASE_ASSET"
    DOWNLOAD_TMP="$STAGE_DIR/$RELEASE_ASSET"
    curl -fsSL --max-time 300 "$URL" -o "$DOWNLOAD_TMP"
  else
    exit 1
  fi
fi

if [ "${LPM_INSTALL_INSECURE:-0}" = "1" ]; then
  : # already warned above
elif [ -n "$SHA_TOOL" ]; then
  ACTUAL_SHA=$($SHA_TOOL "$DOWNLOAD_TMP" | awk '{print $1}')
  EXPECTED_SHA=$(awk -v p="$RELEASE_ASSET" '$2 == p { print $1; count++ } END { if (count != 1) exit 1 }' "$MANIFEST_TMP") || EXPECTED_SHA=""
  if [ -z "$EXPECTED_SHA" ]; then
    echo "ERROR: manifest must enumerate $RELEASE_ASSET exactly once; cannot verify download."
    echo "       This is a release-pipeline bug. Report at https://github.com/$REPO/issues"
    exit 1
  fi
  if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    echo "ERROR: SHA-256 mismatch for $RELEASE_ASSET"
    echo "  expected: $EXPECTED_SHA  (from signed manifest)"
    echo "  actual:   $ACTUAL_SHA"
    echo "Refusing to install — this is a strong tampering signal."
    exit 1
  fi
  echo "Verified SHA-256: $ACTUAL_SHA"

  # Opportunistic Sigstore. `cosign` present + bundle present →
  # fail-closed on rejection. `cosign` absent → SHA-only floor.
  if command -v cosign >/dev/null 2>&1 && [ -s "$BUNDLE_TMP" ]; then
    echo "cosign detected; verifying manifest signature..."
    cosign verify-blob \
      --bundle "$BUNDLE_TMP" \
      --certificate-identity-regexp "^https://github\\.com/lpm-dev/rust-client/\\.github/workflows/release\\.yml@.+" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "$MANIFEST_TMP" >/dev/null 2>&1 \
      || {
        echo "ERROR: cosign refused the signature on SHA256SUMS.txt — manifest is not authentically from $REPO release.yml"
        exit 1
      }
    echo "Verified Sigstore signature on manifest (identity-pinned to release.yml)"
  fi
fi

validate_macos_bundle() {
  app_bundle="$1"
  app_label="$2"
  app_contents="$app_bundle/Contents"
  app_executable="$app_contents/MacOS/lpm-rs"
  app_profile="$app_contents/embedded.provisionprofile"
  app_signature="$app_contents/_CodeSignature/CodeResources"
  app_ticket="$app_contents/CodeResources"

  for required_file in \
    "$app_contents/Info.plist" \
    "$app_ticket" \
    "$app_executable" \
    "$app_profile" \
    "$app_signature"
  do
    if [ ! -f "$required_file" ] || [ -L "$required_file" ]; then
      echo "ERROR: $app_label is missing a required regular file: $required_file"
      return 1
    fi
  done

  unexpected_entries=$(
    cd "$app_bundle" &&
      find . -print | grep -Ev '^(\.|\./Contents|\./Contents/Info\.plist|\./Contents/CodeResources|\./Contents/embedded\.provisionprofile|\./Contents/MacOS|\./Contents/MacOS/lpm-rs|\./Contents/_CodeSignature|\./Contents/_CodeSignature/CodeResources)$' || true
  )
  if [ -n "$unexpected_entries" ]; then
    echo "ERROR: $app_label contains unexpected entries:"
    printf '%s\n' "$unexpected_entries"
    return 1
  fi
  if find "$app_bundle" -type l -print | grep -q .; then
    echo "ERROR: $app_label contains a symbolic link."
    return 1
  fi
  if find "$app_bundle" ! -type d ! -type f -print | grep -q .; then
    echo "ERROR: $app_label contains an unsupported file type."
    return 1
  fi

  if ! "$MACOS_CODESIGN_TOOL" --verify --strict --verbose=4 "$app_bundle"; then
    echo "ERROR: $app_label failed code-signature validation."
    return 1
  fi
  signature_details=$("$MACOS_CODESIGN_TOOL" -dvv "$app_bundle" 2>&1) || return 1
  signed_team=$(printf '%s\n' "$signature_details" | awk -F= '/^TeamIdentifier=/{print $2}')
  signed_identifier=$(printf '%s\n' "$signature_details" | awk -F= '/^Identifier=/{print $2}')
  if [ "$signed_team" != "$EXPECTED_TEAM_ID" ] || [ "$signed_identifier" != "$EXPECTED_BUNDLE_ID" ]; then
    echo "ERROR: $app_label has an unexpected signing identity."
    return 1
  fi

  signed_entitlements="$STAGE_DIR/signed-entitlements.plist"
  if ! "$MACOS_CODESIGN_TOOL" -d --entitlements :- "$app_bundle" > "$signed_entitlements" 2>/dev/null; then
    echo "ERROR: $app_label has no readable signed entitlements."
    return 1
  fi
  signed_access_groups=$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups' "$signed_entitlements" 2>/dev/null) || return 1
  if ! plist_array_contains_exact "$signed_access_groups" "$EXPECTED_ACCESS_GROUP"; then
    echo "ERROR: $app_label does not have the LPM Vault shared Keychain access group."
    return 1
  fi

  profile_plist="$STAGE_DIR/profile.plist"
  if ! "$MACOS_SECURITY_TOOL" cms -D -i "$app_profile" > "$profile_plist"; then
    echo "ERROR: $app_label has an unreadable provisioning profile."
    return 1
  fi
  profile_team=$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$profile_plist" 2>/dev/null) || return 1
  profile_application=$(
    /usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$profile_plist" 2>/dev/null ||
      /usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$profile_plist" 2>/dev/null
  ) || return 1
  profile_access_groups=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:keychain-access-groups' "$profile_plist" 2>/dev/null) || return 1
  if [ "$profile_team" != "$EXPECTED_TEAM_ID" ] || \
     [ "$profile_application" != "$EXPECTED_TEAM_ID.$EXPECTED_BUNDLE_ID" ] || \
     { ! plist_array_contains_exact "$profile_access_groups" "$EXPECTED_ACCESS_GROUP" && \
       ! plist_array_contains_exact "$profile_access_groups" "$EXPECTED_PROFILE_ACCESS_GROUP"; }; then
    echo "ERROR: $app_label provisioning profile does not authorize the shared Keychain contract."
    return 1
  fi

  if ! "$MACOS_XCRUN_TOOL" stapler validate "$app_bundle"; then
    echo "ERROR: $app_label does not contain a valid notarization ticket."
    return 1
  fi
  if ! "$MACOS_SPCTL_TOOL" --assess --type execute --verbose=4 "$app_bundle"; then
    echo "ERROR: Gatekeeper rejected $app_label."
    return 1
  fi
}

install_macos_bundle() {
  archive="$1"
  archive_entries=$("$MACOS_UNZIP_TOOL" -Z1 "$archive") || {
    echo "ERROR: cannot read the macOS app archive."
    return 1
  }
  if [ -z "$archive_entries" ] || \
     printf '%s\n' "$archive_entries" | grep -Eq '(^/|(^|/)\.\.(/|$)|\\|[[:cntrl:]])'; then
    echo "ERROR: macOS app archive contains an unsafe path."
    return 1
  fi
  if printf '%s\n' "$archive_entries" | grep -Ev '^LPM CLI\.app(/|$)' >/dev/null; then
    echo "ERROR: macOS app archive must contain only $EXPECTED_APP_NAME."
    return 1
  fi

  extracted_root="$STAGE_DIR/extracted"
  mkdir "$extracted_root"
  "$MACOS_DITTO_TOOL" -x -k "$archive" "$extracted_root"
  extracted_app="$extracted_root/$EXPECTED_APP_NAME"
  validate_macos_bundle "$extracted_app" "downloaded $EXPECTED_APP_NAME"

  mkdir -p "$LIBEXEC_DIR"
  BUNDLE_STAGE_ROOT=$(mktemp -d "$LIBEXEC_DIR/.lpm-install.XXXXXX")
  BUNDLE_STAGED_APP="$BUNDLE_STAGE_ROOT/$EXPECTED_APP_NAME"
  BUNDLE_PREVIOUS_APP="$BUNDLE_STAGE_ROOT/previous-$EXPECTED_APP_NAME"
  BUNDLE_PREVIOUS_LPM="$BUNDLE_STAGE_ROOT/previous-lpm"
  BUNDLE_PREVIOUS_LPX="$BUNDLE_STAGE_ROOT/previous-lpx"
  BUNDLE_FINAL_APP="$LIBEXEC_DIR/$EXPECTED_APP_NAME"
  link_target="../libexec/$EXPECTED_APP_NAME/Contents/MacOS/lpm-rs"
  new_lpm="$BUNDLE_STAGE_ROOT/new-lpm"
  new_lpx="$BUNDLE_STAGE_ROOT/new-lpx"

  "$MACOS_DITTO_TOOL" "$extracted_app" "$BUNDLE_STAGED_APP"
  validate_macos_bundle "$BUNDLE_STAGED_APP" "staged $EXPECTED_APP_NAME"
  ln -s "$link_target" "$new_lpm"
  ln -s "$link_target" "$new_lpx"

  if [ -d "$INSTALL_DIR/$BINARY_NAME" ] && [ ! -L "$INSTALL_DIR/$BINARY_NAME" ]; then
    echo "ERROR: $INSTALL_DIR/$BINARY_NAME is a directory; refusing to replace it."
    return 1
  fi
  if [ -d "$INSTALL_DIR/$ALIAS_NAME" ] && [ ! -L "$INSTALL_DIR/$ALIAS_NAME" ]; then
    echo "ERROR: $INSTALL_DIR/$ALIAS_NAME is a directory; refusing to replace it."
    return 1
  fi

  BUNDLE_MOVED_APP=0
  BUNDLE_MOVED_LPM=0
  BUNDLE_MOVED_LPX=0
  BUNDLE_INSTALLED_APP=0
  BUNDLE_INSTALLED_LPM=0
  BUNDLE_INSTALLED_LPX=0
  install_ok=1
  BUNDLE_TRANSACTION_ACTIVE=1

  if [ -e "$BUNDLE_FINAL_APP" ] || [ -L "$BUNDLE_FINAL_APP" ]; then
    BUNDLE_MOVED_APP=1
    if mv "$BUNDLE_FINAL_APP" "$BUNDLE_PREVIOUS_APP"; then
      interrupt_install_test_after moved-app
    else
      BUNDLE_MOVED_APP=0
      install_ok=0
    fi
  fi
  if [ "$install_ok" = "1" ] && { [ -e "$INSTALL_DIR/$BINARY_NAME" ] || [ -L "$INSTALL_DIR/$BINARY_NAME" ]; }; then
    BUNDLE_MOVED_LPM=1
    if mv "$BUNDLE_FINAL_LPM" "$BUNDLE_PREVIOUS_LPM"; then
      interrupt_install_test_after moved-lpm
    else
      BUNDLE_MOVED_LPM=0
      install_ok=0
    fi
  fi
  if [ "$install_ok" = "1" ] && { [ -e "$INSTALL_DIR/$ALIAS_NAME" ] || [ -L "$INSTALL_DIR/$ALIAS_NAME" ]; }; then
    BUNDLE_MOVED_LPX=1
    if mv "$BUNDLE_FINAL_LPX" "$BUNDLE_PREVIOUS_LPX"; then
      interrupt_install_test_after moved-lpx
    else
      BUNDLE_MOVED_LPX=0
      install_ok=0
    fi
  fi
  if [ "$install_ok" = "1" ]; then
    BUNDLE_INSTALLED_APP=1
    if mv "$BUNDLE_STAGED_APP" "$BUNDLE_FINAL_APP"; then
      interrupt_install_test_after installed-app
    else
      BUNDLE_INSTALLED_APP=0
      install_ok=0
    fi
  fi
  if [ "$install_ok" = "1" ]; then
    BUNDLE_INSTALLED_LPM=1
    if mv "$new_lpm" "$BUNDLE_FINAL_LPM"; then
      interrupt_install_test_after installed-lpm
    else
      BUNDLE_INSTALLED_LPM=0
      install_ok=0
    fi
  fi
  if [ "$install_ok" = "1" ]; then
    BUNDLE_INSTALLED_LPX=1
    if mv "$new_lpx" "$BUNDLE_FINAL_LPX"; then
      interrupt_install_test_after installed-lpx
    else
      BUNDLE_INSTALLED_LPX=0
      install_ok=0
    fi
  fi
  if [ "$install_ok" = "1" ]; then
    BUNDLE_TRANSACTION_ACTIVE=0
    return 0
  fi

  echo "ERROR: macOS installation failed; restoring the previous installation."
  rollback_macos_bundle_transaction || true
  return 1
}

if [ "$MACOS_BUNDLE" = "1" ] && [ "$LEGACY_MACOS" != "1" ]; then
  install_macos_bundle "$DOWNLOAD_TMP"
else
  mv "$DOWNLOAD_TMP" "$INSTALL_DIR/$BINARY_NAME"
  chmod +x "$INSTALL_DIR/$BINARY_NAME"
  ln -sf "$BINARY_NAME" "$INSTALL_DIR/$ALIAS_NAME"
fi

echo "Installed to $INSTALL_DIR/$BINARY_NAME"
echo "Alias installed to $INSTALL_DIR/$ALIAS_NAME"

# Check PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    SHELL_NAME="$(basename "$SHELL")"
    case "$SHELL_NAME" in
      zsh)  RC="$HOME/.zshrc" ;;
      bash) RC="$HOME/.bashrc" ;;
      fish) RC="$HOME/.config/fish/config.fish" ;;
      *)    RC="" ;;
    esac

    if [ -n "$RC" ]; then
      if [ "$SHELL_NAME" = "fish" ]; then
        echo "fish_add_path $INSTALL_DIR" >> "$RC"
      else
        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$RC"
      fi
      echo "Added $INSTALL_DIR to PATH in $RC"
      echo "Run: source $RC (or open a new terminal)"
    else
      echo "Add $INSTALL_DIR to your PATH manually."
    fi
    ;;
esac

echo ""
echo "Done! Run 'lpm --help' to get started."
echo "Login: lpm login"
