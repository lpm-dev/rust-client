#!/bin/bash
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
POLICY_PATH="/etc/lpm/security-policy.toml"

if [[ "${1:-}" == "--help" ]]; then
    cat <<'EOF'
Install the machine-level audit security policy required by the bench harnesses.

Writes /etc/lpm/security-policy.toml with minimum-release-age-secs = 0 so
headless audit runs can exercise fresh-package install graphs without per-project
interactive unlocks.
EOF
    exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null; then
        exec sudo "$SCRIPT_PATH" "$@"
    fi
    echo "ERROR: installing the audit security policy requires root or sudo" >&2
    exit 1
fi

install -d -m 0755 /etc/lpm
cat > "$POLICY_PATH" <<'EOF'
minimum-release-age-secs = 0

[policy]
name = "audit-harness"
source = "rust-client bench harness"
EOF
chmod 0644 "$POLICY_PATH"

if command -v chown >/dev/null; then
    chown root:root "$POLICY_PATH" 2>/dev/null || chown 0:0 "$POLICY_PATH"
fi

echo "Installed audit security policy at $POLICY_PATH"