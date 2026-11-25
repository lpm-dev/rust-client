#!/bin/sh
# LPM CLI installer
# Usage: curl -fsSL https://raw.githubusercontent.com/lpm-dev/rust-client/main/install.sh | sh
#
# Installs the latest (or requested) LPM CLI binary to ~/.lpm/bin and adds it to PATH.
# Every downloaded byte is verified against a signed SHA256SUMS.txt
# manifest before chmod +x; cosign verify-blob runs opportunistically
# when a cosign binary is on PATH. Set LPM_INSTALL_REQUIRE_SIGSTORE=1 to
# refuse to install unless cosign verifies who published the release.
# Set LPM_INSTALL_INSECURE=1 to skip all integrity checks (NOT
# recommended; emergency-recovery only).
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
# A Developer ID Application signature of LPM's team, and code Apple
# notarized. The system confirms `notarized` from the stapled ticket, its
# ticket cache or Apple's service, so only the ticket-record comparison below
# proves which ticket the app carries.
MACOS_CODE_REQUIREMENT="anchor apple generic and identifier \"$EXPECTED_BUNDLE_ID\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$EXPECTED_TEAM_ID\" and notarized"
# v0.76.5 is the last signed app bundle that does not declare an icon.
MACOS_ICON_FIRST_VERSION="v0.76.6"
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

# Minimum version this installer is willing to deliver. Raise it after
# each stable release that fixes a security-relevant gap is published,
# never before: a floor above the latest release refuses every install.
# The floor is a downgrade-resistance gate: an attacker who controls the
# GitHub API response (or a downstream mirror) cannot point a fresh
# installer at an old, known-vulnerable release — even one with a valid
# SHA-256 manifest and Sigstore signature (the old release IS
# authentically signed; the floor refuses to install it anyway). It
# can't go below v0.85.0, the first release that can update itself to
# the releases signed from main.
#
# Override only as documented recovery; sets the same signal as
# LPM_INSTALL_INSECURE but scoped to the floor check.
MIN_VERSION="v0.87.0"

# POSIX vX.Y.Z[-prerelease] comparator. As in semver, a prerelease sorts
# before its release, so `v0.87.0-nightly.… < v0.87.0`: a nightly of the
# floor version was built before that release. Two prereleases of the same
# version compare equal. Returns 0 (true) if $1 < $2, non-zero otherwise.
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
  if [ "$c1_" -lt "$c2_" ]; then return 0; fi
  if [ "$c1_" -gt "$c2_" ]; then return 1; fi
  case "$1" in
    *-*) case "$2" in *-*) return 1 ;; *) return 0 ;; esac ;;
  esac
  return 1
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

REQUIRE_SIGSTORE="${LPM_INSTALL_REQUIRE_SIGSTORE:-0}"
case "$REQUIRE_SIGSTORE" in
  0|1) ;;
  *)
    echo "ERROR: LPM_INSTALL_REQUIRE_SIGSTORE must be 0 or 1 (got '$REQUIRE_SIGSTORE')"
    exit 1
    ;;
esac
if [ "$REQUIRE_SIGSTORE" = "1" ]; then
  if [ "${LPM_INSTALL_INSECURE:-0}" = "1" ]; then
    echo "ERROR: LPM_INSTALL_REQUIRE_SIGSTORE=1 asks for the signature check that LPM_INSTALL_INSECURE=1 skips."
    echo "       Unset one of them."
    exit 1
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    echo "ERROR: LPM_INSTALL_REQUIRE_SIGSTORE=1 needs cosign on PATH to verify who published the release."
    echo "       Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/"
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
  # Only the exact host, then an optional all-digit port: anything else, a
  # user-info `@` among it, would let curl reach another host.
  case "$loopback_authority" in
    127.0.0.1*) loopback_port=${loopback_authority#127.0.0.1} ;;
    localhost*) loopback_port=${loopback_authority#localhost} ;;
    '[::1]'*) loopback_port=${loopback_authority#'[::1]'} ;;
    *) return 1 ;;
  esac
  case "$loopback_port" in
    '') return 0 ;;
    :*) loopback_port=${loopback_port#:} ;;
    *) return 1 ;;
  esac
  case "$loopback_port" in
    ''|*[!0123456789]*) return 1 ;;
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

# Every macOS tool below ships with macOS. None may be an xcrun shim such as
# /usr/bin/stapler, which fails on a Mac without Xcode or the Command Line
# Tools.
MACOS_BASE64_TOOL="/usr/bin/base64"
MACOS_CODESIGN_TOOL="/usr/bin/codesign"
MACOS_DITTO_TOOL="/usr/bin/ditto"
MACOS_OPENSSL_TOOL="/usr/bin/openssl"
MACOS_PLISTBUDDY_TOOL="/usr/libexec/PlistBuddy"
MACOS_PLUTIL_TOOL="/usr/bin/plutil"
MACOS_SPCTL_TOOL="/usr/sbin/spctl"
MACOS_UNZIP_TOOL="/usr/bin/unzip"

# Apple publishes the ticket it issues for each notarized code directory as a
# record in a public CloudKit database, named after the code-directory hash.
# `stapler validate` compares that record with the ticket stapled to the app;
# the installer does the same with curl.
NOTARIZATION_TICKET_LOOKUP_URL="https://api.apple-cloudkit.com/database/1/com.apple.gk.ticket-delivery/production/public/records/lookup"

if [ -n "${LPM_INSTALL_TEST_CODESIGN:-}${LPM_INSTALL_TEST_OPENSSL:-}${LPM_INSTALL_TEST_SPCTL:-}${LPM_INSTALL_TEST_TICKET_LOOKUP_URL:-}" ]; then
  if [ "$OS" != "Darwin" ] || \
     [ -z "${LPM_INSTALL_TEST_API_URL:-}" ] || \
     [ -z "${LPM_INSTALL_TEST_DOWNLOAD_BASE:-}" ]; then
    echo "ERROR: macOS tool overrides require both loopback test endpoints on macOS"
    exit 1
  fi
  if [ -n "${LPM_INSTALL_TEST_TICKET_LOOKUP_URL:-}" ] && ! is_loopback_http "$LPM_INSTALL_TEST_TICKET_LOOKUP_URL"; then
    echo "ERROR: LPM_INSTALL_TEST_TICKET_LOOKUP_URL must point at 127.0.0.1 / localhost / [::1] over http"
    exit 1
  fi
  MACOS_CODESIGN_TOOL="${LPM_INSTALL_TEST_CODESIGN:-$MACOS_CODESIGN_TOOL}"
  MACOS_OPENSSL_TOOL="${LPM_INSTALL_TEST_OPENSSL:-$MACOS_OPENSSL_TOOL}"
  MACOS_SPCTL_TOOL="${LPM_INSTALL_TEST_SPCTL:-$MACOS_SPCTL_TOOL}"
  NOTARIZATION_TICKET_LOOKUP_URL="${LPM_INSTALL_TEST_TICKET_LOOKUP_URL:-$NOTARIZATION_TICKET_LOOKUP_URL}"
fi

REQUESTED_VERSION="${LPM_INSTALL_VERSION:-}"
RELEASE_COMMIT=""
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
    # The commit the release was published from; cosign binds the
    # signature to it below.
    RELEASE_COMMIT=$(printf '%s\n' "$API_RESPONSE" | grep -m 1 '"target_commitish"' | sed -E 's/.*"target_commitish": *"([0-9a-f]{40})".*/\1/')
  fi
fi
case "$RELEASE_COMMIT" in
  *[!0-9a-f]*|"") RELEASE_COMMIT="" ;;
esac
[ "${#RELEASE_COMMIT}" -eq 40 ] || RELEASE_COMMIT=""

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
  elif [ -z "$REQUESTED_VERSION" ] && [ "$INSTALL_CHANNEL" = "nightly" ]; then
    echo "ERROR: The latest nightly, $VERSION, was built before $MIN_VERSION,"
    echo "       the oldest release this installer delivers."
    echo "Install the stable release instead, or try again once the next nightly is published."
    exit 1
  else
    echo "ERROR: detected version $VERSION is below the minimum supported $MIN_VERSION."
    echo ""
    echo "This installer refuses to deliver releases older than $MIN_VERSION because"
    echo "they predate at least one security fix that would otherwise be silently"
    echo "downgraded. If you are recovering from a release-pipeline incident and need"
    echo "an older release on purpose, set LPM_INSTALL_MIN_VERSION_OVERRIDE=1 to bypass"
    echo "(NOT recommended; the download is still verified as usual)."
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
STAGED_BINARY=""

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
  if [ -n "$STAGED_BINARY" ]; then
    rm -f "$STAGED_BINARY"
  fi
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
  # Without cosign the SHA gate still runs, and the installer says that it
  # couldn't verify who published the release; LPM_INSTALL_REQUIRE_SIGSTORE=1
  # refuses that case instead. With cosign, every release at or above the
  # floor has a bundle to verify.
  bundle_status=$(curl -sSL --max-time 30 -o "$BUNDLE_TMP" -w '%{http_code}' "$BUNDLE_URL" 2>/dev/null) \
    || bundle_status="no response"
  [ "$bundle_status" = "200" ] || rm -f "$BUNDLE_TMP"
  if [ ! -s "$BUNDLE_TMP" ] && { [ "$REQUIRE_SIGSTORE" = "1" ] || command -v cosign >/dev/null 2>&1; }; then
    if [ "$bundle_status" = "404" ] || [ "$bundle_status" = "200" ]; then
      echo "ERROR: release $VERSION has no Sigstore bundle ($BUNDLE_URL),"
      echo "       so cosign can't verify who published it. Refusing to install."
    else
      echo "ERROR: couldn't download the Sigstore bundle of release $VERSION ($bundle_status)."
      echo "       cosign can't verify who published it without it. Try again."
    fi
    exit 1
  fi
fi

# The identities releases are signed with: release.yml in this repository,
# run from main by hand for a stable release, and by the schedule or by hand
# for a nightly. Most stable releases before v0.77.0 were signed from their
# own tag by a tag push, and v0.60.0, v0.61.0 and v0.68.0 from main by hand.
# When the installer looks up the latest stable release itself, the
# signature must also be for the commit that release records. An explicit
# version isn't bound to a commit: a build the release workflow signed for
# that version passes, and the staged check below confirms the version.
verify_manifest_signer() {
  if [ "$RESOLVED_CHANNEL" = "stable" ] && version_lt "$VERSION" "v0.77.0"; then
    signers="refs/tags/$VERSION@push refs/heads/main@workflow_dispatch"
  elif [ "$RESOLVED_CHANNEL" = "stable" ]; then
    signers="refs/heads/main@workflow_dispatch"
  else
    signers="refs/heads/main@schedule refs/heads/main@workflow_dispatch"
  fi
  for signer in $signers; do
    signing_ref=${signer%@*}
    signing_trigger=${signer##*@}
    set -- \
      --bundle "$BUNDLE_TMP" \
      --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@$signing_ref" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      --certificate-github-workflow-repository "$REPO" \
      --certificate-github-workflow-ref "$signing_ref" \
      --certificate-github-workflow-trigger "$signing_trigger"
    if [ -n "$RELEASE_COMMIT" ]; then
      set -- "$@" --certificate-github-workflow-sha "$RELEASE_COMMIT"
    fi
    if cosign verify-blob "$@" "$MANIFEST_TMP" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

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
    if [ -z "$REQUESTED_VERSION" ] && [ "$RESOLVED_CHANNEL" = "stable" ] && [ -z "$RELEASE_COMMIT" ]; then
      echo "ERROR: the latest-release lookup doesn't name the commit $VERSION was published from,"
      echo "       so its signature can't be bound to that release. Refusing to install."
      exit 1
    fi
    verify_manifest_signer || {
      echo "ERROR: cosign refused the signature on SHA256SUMS.txt — manifest is not authentically from $REPO release.yml"
      exit 1
    }
    echo "Verified Sigstore signature on manifest (identity-pinned to release.yml)"
  elif [ "$MACOS_BUNDLE" != "1" ] || [ "$LEGACY_MACOS" = "1" ]; then
    # On macOS the Developer ID signature and notarization checks below
    # verify the publisher of an app bundle independently of GitHub.
    echo "Note: the publisher of this release wasn't verified, because cosign isn't installed."
    echo "      The download matches the checksums published with the release."
    echo "      Install cosign to verify the publisher, or set LPM_INSTALL_REQUIRE_SIGSTORE=1"
    echo "      to refuse to install without that check."
  fi
fi

# A release's binary must report the version the installer asked for. Its
# first line of --version names the version; an update notice can follow,
# so the check asks for none and reads only that line. The binary runs from
# the install directory, since the temporary directory may be mounted noexec.
require_reported_version() {
  [ "${LPM_INSTALL_INSECURE:-0}" = "1" ] && return 0
  expected_version_line="lpm ${VERSION#v}"
  version_errors="$STAGE_DIR/version-check.err"
  if ! version_output=$(LPM_NO_UPDATE_CHECK=1 "$1" --version 2>"$version_errors") || [ -z "$version_output" ]; then
    echo "ERROR: couldn't run the downloaded binary to check its version:"
    sed -n '1,5s/^/  /p' "$version_errors"
    echo "This can mean the binary doesn't suit this system, or that $2 doesn't allow running programs."
    return 1
  fi
  reported_version_line=$(printf '%s\n' "$version_output" | sed -n 1p)
  if [ "$reported_version_line" != "$expected_version_line" ]; then
    echo "ERROR: the downloaded binary reports '$reported_version_line', but the release is $VERSION."
    echo "Refusing to install a binary from another release."
    return 1
  fi
}

# Record errors Apple's ticket service reports for load or outages.
NOTARIZATION_TICKET_TRANSIENT_ERRORS=" THROTTLED TRY_AGAIN_LATER SERVICE_UNAVAILABLE INTERNAL_ERROR ZONE_BUSY "
# A ticket record is under 4 KiB; anything far larger isn't one.
NOTARIZATION_TICKET_RESPONSE_MAX_BYTES=65536

# Prints the lookup answer's value at key path $1, in plutil's format $2.
# Each value is extracted on its own, so a JSON null elsewhere in the answer,
# which a plist can't hold, doesn't hide the ones the check reads.
notarization_ticket_extract() {
  "$MACOS_PLUTIL_TOOL" -extract "$1" "$2" -o - "$ticket_response" 2>/dev/null
}

# Prints the root element of the value at key path $1: the line after
# `<plist version="1.0">` in its one-value XML plist.
notarization_ticket_root() {
  notarization_ticket_extract "$1" xml1 | sed -n '/^<plist version="1.0">$/{n;p;q;}'
}

# Prints the string at key path $1. Returns 1 when the answer has no such
# value and 2 when it isn't a string.
notarization_ticket_string() {
  ticket_field_root=$(notarization_ticket_root "$1")
  case "$ticket_field_root" in
    '') return 1 ;;
    '<string/>'|'<string></string>') return 0 ;;
    '<string>'*'</string>') ;;
    *) return 2 ;;
  esac
  printf '%s\n' "$ticket_field_root" | sed -n 's:^<string>\(.*\)</string>$:\1:p'
}

# Looks up the ticket record named $ticket_record. Sets ticket_lookup to
# issued (Apple's ticket is in $ticket_issued), not-issued (no ticket, or a
# revoked one), refused (an error asking again won't change) or unavailable,
# and ticket_lookup_detail to what the service said. The user's ~/.curlrc
# still applies, for its proxy settings, so redirects are refused and the
# status is read from the response headers rather than curl's exit status.
lookup_notarization_ticket() {
  ticket_lookup="unavailable"
  ticket_lookup_detail="no answer"
  rm -f "$ticket_response" "$ticket_headers" "$ticket_issued" "$ticket_transfer"
  {
    ticket_transfer_status=0
    curl -sS --max-time 30 --max-redirs 0 -D "$ticket_headers" -o - \
      -H 'Content-Type: application/json' \
      --data "{\"records\":[{\"recordName\":\"$ticket_record\"}]}" \
      "$NOTARIZATION_TICKET_LOOKUP_URL" || ticket_transfer_status=$?
    printf '%s\n' "$ticket_transfer_status" > "$ticket_transfer"
  } | head -c "$((NOTARIZATION_TICKET_RESPONSE_MAX_BYTES + 1))" > "$ticket_response" || true
  ticket_http_status=$(awk '/^HTTP\//{sub(/\r$/, ""); status=$2} END{print status}' "$ticket_headers" 2>/dev/null || true)
  case "$ticket_http_status" in
    [0123456789][0123456789][0123456789]) ;;
    *) ticket_http_status="" ;;
  esac
  case "$ticket_http_status" in
    200) ;;
    '') return 0 ;;
    1[0-9][0-9]|408|429|5[0-9][0-9]) ticket_lookup_detail="HTTP $ticket_http_status"; return 0 ;;
    *) ticket_lookup="refused"; ticket_lookup_detail="HTTP $ticket_http_status"; return 0 ;;
  esac
  if [ "$(wc -c < "$ticket_response")" -gt "$NOTARIZATION_TICKET_RESPONSE_MAX_BYTES" ]; then
    ticket_lookup_detail="an oversized answer"
    return 0
  fi
  if [ "$(cat "$ticket_transfer" 2>/dev/null)" != 0 ]; then
    if [ -s "$ticket_response" ]; then
      ticket_lookup_detail="an incomplete answer"
    fi
    return 0
  fi
  # `records` must be an array of objects, and hold only one: plutil writes
  # it as `[`, that record and `]`, whatever the record's key order.
  ticket_records_json=$(notarization_ticket_extract records json || true)
  if [ "$ticket_records_json" = "[]" ]; then
    ticket_lookup_detail="an answer about another record"
    return 0
  fi
  ticket_record_json=$(notarization_ticket_extract records.0 json || true)
  case "$ticket_records_json:$ticket_record_json" in
    '['*']:{'*'}') ;;
    *) ticket_lookup_detail="an unreadable answer"; return 0 ;;
  esac
  ticket_field_status=0
  ticket_answered_record=$(notarization_ticket_string records.0.recordName) || ticket_field_status=$?
  if [ "$ticket_field_status" -ne 0 ]; then
    ticket_lookup_detail="an unreadable answer"
    return 0
  fi
  if [ "${#ticket_records_json}" -ne "$((${#ticket_record_json} + 2))" ] || \
     [ "$ticket_answered_record" != "$ticket_record" ]; then
    ticket_lookup_detail="an answer about another record"
    return 0
  fi
  # Every field must have its JSON type before any decides, as self-update's
  # parser requires.
  ticket_error_status=0
  ticket_server_error=$(notarization_ticket_string records.0.serverErrorCode) || ticket_error_status=$?
  ticket_value_status=0
  ticket_value=$(notarization_ticket_string records.0.fields.signedTicket.value) || ticket_value_status=$?
  ticket_deleted=$(notarization_ticket_root records.0.deleted)
  case "$ticket_error_status:$ticket_value_status:$ticket_deleted" in
    2:*|*:2:*|*:*:'<false/>'|*:*:'<true/>'|*:*:) ;;
    *) ticket_error_status=2 ;;
  esac
  case "$ticket_error_status:$ticket_value_status:$ticket_deleted" in
    2:*|*:2:*) ticket_lookup_detail="an unreadable answer"; return 0 ;;
  esac
  if [ "$ticket_error_status" -eq 0 ]; then
    case "$ticket_server_error" in
      NOT_FOUND) ticket_lookup="not-issued"; return 0 ;;
      ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZ_]*) ticket_server_error="" ;;
    esac
    if [ -z "$ticket_server_error" ] || [ "${#ticket_server_error}" -gt 40 ]; then
      ticket_lookup="refused"
      ticket_lookup_detail="an unrecognized error"
      return 0
    fi
    ticket_lookup_detail="$ticket_server_error"
    case "$NOTARIZATION_TICKET_TRANSIENT_ERRORS" in
      *" $ticket_server_error "*) ;;
      *) ticket_lookup="refused" ;;
    esac
    return 0
  fi
  if [ "$ticket_deleted" = '<true/>' ]; then
    ticket_lookup="not-issued"
    return 0
  fi
  if [ "$ticket_value_status" -eq 1 ]; then
    ticket_lookup_detail="an answer without a ticket"
    return 0
  fi
  # Standard padded base64 only, as self-update's decoder requires: base64 -D
  # would skip characters outside the alphabet.
  case "$ticket_value" in
    *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]*) ticket_value="" ;;
  esac
  if [ -z "$ticket_value" ] || [ $((${#ticket_value} % 4)) -ne 0 ] || \
     ! printf '%s' "$ticket_value" | "$MACOS_BASE64_TOOL" -D > "$ticket_issued" 2>/dev/null || \
     [ ! -s "$ticket_issued" ]; then
    ticket_lookup_detail="an unreadable ticket"
    return 0
  fi
  ticket_lookup="issued"
}

# Confirms that Apple's ticket database holds exactly the ticket stapled to an
# app bundle, for the code directory whose SHA-256 hash is $3. The service has
# kept failing for over 20 s at a time, so the lookups spread over about two
# minutes before giving up.
confirm_notarization_ticket() {
  ticket_bundle="$1"
  ticket_label="$2"
  ticket_record="2/2/$3"
  ticket_response="$STAGE_DIR/notarization-ticket.json"
  ticket_headers="$STAGE_DIR/notarization-ticket.headers"
  ticket_transfer="$STAGE_DIR/notarization-ticket.transfer"
  ticket_issued="$STAGE_DIR/notarization-ticket"
  for ticket_retry_delay in 2 5 15 30 60 ""; do
    lookup_notarization_ticket
    case "$ticket_lookup" in
      issued)
        if cmp -s "$ticket_issued" "$ticket_bundle/Contents/CodeResources"; then
          return 0
        fi
        echo "ERROR: the notarization ticket stapled to $ticket_label is not the one Apple issued for its code."
        return 1
        ;;
      not-issued)
        echo "ERROR: Apple has not issued a notarization ticket for $ticket_label, or has revoked it."
        return 1
        ;;
      refused)
        echo "ERROR: Apple's notarization service refused to look up the ticket of $ticket_label ($ticket_lookup_detail)."
        return 1
        ;;
    esac
    if [ -z "$ticket_retry_delay" ]; then
      echo "ERROR: Apple's notarization service did not answer while checking $ticket_label ($ticket_lookup_detail). Try again in a few minutes."
      return 1
    fi
    echo "Apple's notarization service did not answer ($ticket_lookup_detail); checking the notarization ticket again in ${ticket_retry_delay}s..."
    sleep "$ticket_retry_delay"
  done
}

# Validates an app bundle and sets app_cdhash to its code-directory hash. Given
# a bundle Apple already confirmed and that bundle's hash, the bundle is a copy
# of it: instead of asking Apple again, it must carry the same code and the
# same stapled ticket.
validate_macos_bundle() {
  app_bundle="$1"
  app_label="$2"
  confirmed_bundle="${3:-}"
  confirmed_cdhash="${4:-}"
  app_contents="$app_bundle/Contents"
  app_executable="$app_contents/MacOS/lpm-rs"
  app_icon="$app_contents/Resources/LPMCLI.icns"
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

  declared_icon=$("$MACOS_PLISTBUDDY_TOOL" -c 'Print :CFBundleIconFile' "$app_contents/Info.plist" 2>/dev/null || true)
  icon_required=0
  if ! version_lt "$VERSION" "$MACOS_ICON_FIRST_VERSION"; then
    icon_required=1
  fi
  if [ "$icon_required" = "1" ] || [ -n "$declared_icon" ] || [ -e "$app_icon" ] || [ -L "$app_icon" ]; then
    if [ "$declared_icon" != "LPMCLI.icns" ]; then
      echo "ERROR: $app_label must declare LPMCLI.icns as its application icon."
      return 1
    fi
    if [ ! -f "$app_icon" ] || [ -L "$app_icon" ]; then
      echo "ERROR: $app_label is missing its declared regular icon file: $app_icon"
      return 1
    fi
  fi

  unexpected_entries=$(
    cd "$app_bundle" &&
      find . -print | grep -Ev '^(\.|\./Contents|\./Contents/Info\.plist|\./Contents/CodeResources|\./Contents/embedded\.provisionprofile|\./Contents/MacOS|\./Contents/MacOS/lpm-rs|\./Contents/Resources|\./Contents/Resources/LPMCLI\.icns|\./Contents/_CodeSignature|\./Contents/_CodeSignature/CodeResources)$' || true
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

  if ! "$MACOS_CODESIGN_TOOL" --verify --strict --verbose=4 -R "=$MACOS_CODE_REQUIREMENT" "$app_bundle"; then
    echo "ERROR: $app_label failed code-signature and notarization validation."
    return 1
  fi
  signature_details=$("$MACOS_CODESIGN_TOOL" -dvvv "$app_bundle" 2>&1) || return 1
  signed_team=$(printf '%s\n' "$signature_details" | sed -n 's/^TeamIdentifier=//p')
  signed_identifier=$(printf '%s\n' "$signature_details" | sed -n 's/^Identifier=//p')
  if [ "$signed_team" != "$EXPECTED_TEAM_ID" ] || [ "$signed_identifier" != "$EXPECTED_BUNDLE_ID" ]; then
    echo "ERROR: $app_label has an unexpected signing identity."
    return 1
  fi
  signed_hash_type=$(printf '%s\n' "$signature_details" | sed -n 's/^Hash type=\([^ ]*\).*/\1/p')
  if [ "$signed_hash_type" != "sha256" ]; then
    echo "ERROR: $app_label is not signed with a SHA-256 code directory."
    return 1
  fi
  app_cdhash=$(printf '%s\n' "$signature_details" | sed -n 's/^CDHash=//p')
  case "$app_cdhash" in
    *[!0123456789abcdef]*|'')
      echo "ERROR: $app_label has no well-formed code-directory hash."
      return 1
      ;;
  esac
  if [ "${#app_cdhash}" -ne 40 ]; then
    echo "ERROR: $app_label has no well-formed code-directory hash."
    return 1
  fi

  signed_entitlements="$STAGE_DIR/signed-entitlements.plist"
  if ! "$MACOS_CODESIGN_TOOL" -d --entitlements :- "$app_bundle" > "$signed_entitlements" 2>/dev/null; then
    echo "ERROR: $app_label has no readable signed entitlements."
    return 1
  fi
  signed_access_groups=$("$MACOS_PLISTBUDDY_TOOL" -c 'Print :keychain-access-groups' "$signed_entitlements" 2>/dev/null) || return 1
  if ! plist_array_contains_exact "$signed_access_groups" "$EXPECTED_ACCESS_GROUP"; then
    echo "ERROR: $app_label does not have the LPM Vault shared Keychain access group."
    return 1
  fi

  # security cms -D would import the profile's certificates into the default
  # keychain, and fails for an account without one. The profile is a sealed
  # resource of the code signature verified above, so it only needs decoding.
  profile_plist="$STAGE_DIR/profile.plist"
  if ! "$MACOS_OPENSSL_TOOL" smime -verify -noverify -nosigs -inform DER -in "$app_profile" -out "$profile_plist" 2>/dev/null; then
    echo "ERROR: $app_label has an unreadable provisioning profile."
    return 1
  fi
  profile_team=$("$MACOS_PLISTBUDDY_TOOL" -c 'Print :TeamIdentifier:0' "$profile_plist" 2>/dev/null) || return 1
  profile_application=$(
    "$MACOS_PLISTBUDDY_TOOL" -c 'Print :Entitlements:com.apple.application-identifier' "$profile_plist" 2>/dev/null ||
      "$MACOS_PLISTBUDDY_TOOL" -c 'Print :Entitlements:application-identifier' "$profile_plist" 2>/dev/null
  ) || return 1
  profile_access_groups=$("$MACOS_PLISTBUDDY_TOOL" -c 'Print :Entitlements:keychain-access-groups' "$profile_plist" 2>/dev/null) || return 1
  if [ "$profile_team" != "$EXPECTED_TEAM_ID" ] || \
     [ "$profile_application" != "$EXPECTED_TEAM_ID.$EXPECTED_BUNDLE_ID" ] || \
     { ! plist_array_contains_exact "$profile_access_groups" "$EXPECTED_ACCESS_GROUP" && \
       ! plist_array_contains_exact "$profile_access_groups" "$EXPECTED_PROFILE_ACCESS_GROUP"; }; then
    echo "ERROR: $app_label provisioning profile does not authorize the shared Keychain contract."
    return 1
  fi

  if [ -z "$confirmed_bundle" ]; then
    confirm_notarization_ticket "$app_bundle" "$app_label" "$app_cdhash" || return 1
  elif [ "$app_cdhash" != "$confirmed_cdhash" ] || \
       ! cmp -s "$confirmed_bundle/Contents/CodeResources" "$app_ticket"; then
    echo "ERROR: $app_label differs from the downloaded bundle whose notarization ticket Apple confirmed."
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
  downloaded_cdhash=$app_cdhash

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
  validate_macos_bundle "$BUNDLE_STAGED_APP" "staged $EXPECTED_APP_NAME" \
    "$extracted_app" "$downloaded_cdhash"
  require_reported_version "$BUNDLE_STAGED_APP/Contents/MacOS/lpm-rs" "$LIBEXEC_DIR" || return 1
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
  STAGED_BINARY=$(mktemp "$INSTALL_DIR/.$BINARY_NAME.new.XXXXXX")
  mv "$DOWNLOAD_TMP" "$STAGED_BINARY"
  chmod +x "$STAGED_BINARY"
  require_reported_version "$STAGED_BINARY" "$INSTALL_DIR" || exit 1
  mv "$STAGED_BINARY" "$INSTALL_DIR/$BINARY_NAME"
  STAGED_BINARY=""
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
        QUOTED_INSTALL_DIR="$(printf '%s' "$INSTALL_DIR" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g")"
        PATH_LINE="fish_add_path -- '$QUOTED_INSTALL_DIR'"
      else
        QUOTED_INSTALL_DIR="$(printf '%s' "$INSTALL_DIR" | sed "s/'/'\\\\''/g")"
        PATH_LINE="export PATH='$QUOTED_INSTALL_DIR':\"\$PATH\""
      fi
      mkdir -p "$(dirname "$RC")"
      if [ ! -f "$RC" ] || ! grep -Fqx -- "$PATH_LINE" "$RC"; then
        printf '\n%s\n' "$PATH_LINE" >> "$RC"
        echo "Added $INSTALL_DIR to PATH in $RC"
      else
        echo "PATH is already configured in $RC"
      fi
      echo "Open a new terminal to use lpm."
    else
      echo "Add $INSTALL_DIR to your PATH manually."
    fi
    ;;
esac

echo ""
echo "Done! Run 'lpm --help' to get started."
echo "Login: lpm login"
