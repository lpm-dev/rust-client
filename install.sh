#!/bin/sh
# LPM CLI installer
# Usage: curl -fsSL https://raw.githubusercontent.com/lpm-dev/rust-client/main/install.sh | sh
#
# Installs the latest LPM CLI binary to ~/.lpm/bin and adds it to PATH.
# Every downloaded byte is verified against a signed SHA256SUMS.txt
# manifest before chmod +x; cosign verify-blob runs opportunistically
# when a cosign binary is on PATH. Set LPM_INSTALL_INSECURE=1 to skip
# all integrity checks (NOT recommended; emergency-recovery only).

set -e

REPO="lpm-dev/rust-client"
INSTALL_DIR="$HOME/.lpm/bin"
BINARY_NAME="lpm"

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

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
      aarch64|arm64) PLATFORM="lpm-linux-arm64" ;;
      x86_64)        PLATFORM="lpm-linux-x64" ;;
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

API_URL="${LPM_INSTALL_TEST_API_URL:-https://api.github.com/repos/$REPO/releases/latest}"

echo "Detecting latest version..."
VERSION=$(curl -fsSL "$API_URL" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "Failed to detect latest version. Check https://github.com/$REPO/releases"
  exit 1
fi

echo "Installing LPM CLI $VERSION for $OS/$ARCH..."

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

echo "Installed to $INSTALL_DIR/$BINARY_NAME"

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
