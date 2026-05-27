#!/bin/bash
set -euo pipefail

if [[ "${1:-}" == "--help" ]]; then
    cat <<'EOF'
Ensure a user-local Node 22 install exists for Linux audit parity with CI.

Installs the requested Node 22 tarball under ~/.local/lpm-bench by default and
prints the bin directory when called with --print-bin-dir.

Environment overrides:
  LPM_BENCH_NODE_VERSION   Node version tag to install (default: v22.22.1)
  LPM_BENCH_NODE_ROOT      Install root (default: ~/.local/lpm-bench)
EOF
    exit 0
fi

MODE="ensure"
case "${1:-}" in
    "" ) ;;
    --print-bin-dir) MODE="print-bin-dir" ;;
    *)
        echo "ERROR: unknown argument: ${1}" >&2
        exit 1
        ;;
esac

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: ensure-node-22-linux.sh only supports Linux hosts" >&2
    exit 1
fi

NODE_VERSION="${LPM_BENCH_NODE_VERSION:-v22.22.1}"
INSTALL_ROOT="${LPM_BENCH_NODE_ROOT:-$HOME/.local/lpm-bench}"

case "$(uname -m)" in
    aarch64|arm64) NODE_ARCH="arm64" ;;
    x86_64|amd64) NODE_ARCH="x64" ;;
    *)
        echo "ERROR: unsupported Linux architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

INSTALL_DIR="$INSTALL_ROOT/node-${NODE_VERSION}-linux-${NODE_ARCH}"
BIN_DIR="$INSTALL_DIR/bin"
ARCHIVE_NAME="node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
DOWNLOAD_URL="https://nodejs.org/dist/${NODE_VERSION}/${ARCHIVE_NAME}"

if [[ ! -x "$BIN_DIR/node" ]]; then
    install -d -m 0755 "$INSTALL_ROOT"
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lpm-node22.XXXXXX")"
    cleanup() {
        rm -rf "$TMP_DIR"
    }
    trap cleanup EXIT

    curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ARCHIVE_NAME"
    tar -xJf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"
    rm -rf "$INSTALL_DIR"
    mv "$TMP_DIR/node-${NODE_VERSION}-linux-${NODE_ARCH}" "$INSTALL_DIR"
    trap - EXIT
    cleanup
fi

NODE_ACTUAL_VERSION="$($BIN_DIR/node -v)"
if [[ "$NODE_ACTUAL_VERSION" != v22.* ]]; then
    echo "ERROR: expected Node 22 but found $NODE_ACTUAL_VERSION at $BIN_DIR/node" >&2
    exit 1
fi

if [[ "$MODE" == "print-bin-dir" ]]; then
    printf '%s\n' "$BIN_DIR"
    exit 0
fi

echo "Node available at $BIN_DIR"
echo "node: $NODE_ACTUAL_VERSION"
echo "npm: $($BIN_DIR/npm -v)"