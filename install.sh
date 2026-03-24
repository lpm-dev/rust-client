#!/bin/sh
# LPM CLI installer
# Usage: curl -fsSL https://raw.githubusercontent.com/lpm-dev/rust-client/main/install.sh | sh
#
# Installs the latest LPM CLI binary to ~/.lpm/bin and adds it to PATH.

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

# Get latest version from GitHub API
echo "Detecting latest version..."
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "Failed to detect latest version. Check https://github.com/$REPO/releases"
  exit 1
fi

echo "Installing LPM CLI $VERSION for $OS/$ARCH..."

# Download
URL="https://github.com/$REPO/releases/download/$VERSION/$PLATFORM"
mkdir -p "$INSTALL_DIR"
curl -fsSL "$URL" -o "$INSTALL_DIR/$BINARY_NAME"
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
