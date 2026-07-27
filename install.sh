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

REPO="lpm-dev/rust-client"
INSTALL_DIR="$HOME/.lpm/bin"
BINARY_NAME="lpm"
ALIAS_NAME="lpx"

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
    http://127.0.0.1*|http://127.0.0.1:*|http://localhost*|http://localhost:*|http://\[::1\]*)
      return 0 ;;
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

URL="$BASE_URL/$PLATFORM"
MANIFEST_URL="$BASE_URL/SHA256SUMS.txt"
BUNDLE_URL="$BASE_URL/SHA256SUMS.txt.sigstore"

# Stage downloads into a temp dir so a failed verification never
# leaves a half-installed binary in $INSTALL_DIR. Cleanup runs on
# any exit shape (success, error, SIGINT) so we don't accumulate
# stragglers when integrity gates trip.
mkdir -p "$INSTALL_DIR"
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT
MANIFEST_TMP="$STAGE_DIR/SHA256SUMS.txt"
BUNDLE_TMP="$STAGE_DIR/SHA256SUMS.txt.sigstore"
BIN_TMP="$STAGE_DIR/$PLATFORM"

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

curl -fsSL --max-time 300 "$URL" -o "$BIN_TMP"

if [ "${LPM_INSTALL_INSECURE:-0}" = "1" ]; then
  : # already warned above
elif [ -n "$SHA_TOOL" ]; then
  ACTUAL_SHA=$($SHA_TOOL "$BIN_TMP" | awk '{print $1}')
  EXPECTED_SHA=$(awk -v p="$PLATFORM" '$2 == p { print $1; exit }' "$MANIFEST_TMP")
  if [ -z "$EXPECTED_SHA" ]; then
    echo "ERROR: manifest does not enumerate $PLATFORM; cannot verify download."
    echo "       This is a release-pipeline bug. Report at https://github.com/$REPO/issues"
    exit 1
  fi
  if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    echo "ERROR: SHA-256 mismatch for $PLATFORM"
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

mv "$BIN_TMP" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"
ln -sf "$BINARY_NAME" "$INSTALL_DIR/$ALIAS_NAME"

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
