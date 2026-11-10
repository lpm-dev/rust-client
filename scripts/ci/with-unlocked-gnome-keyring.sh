#!/bin/bash
# Runs a command on its own D-Bus session bus, against a Secret Service backed
# by an unlocked gnome-keyring login collection.
#
#   scripts/ci/with-unlocked-gnome-keyring.sh cargo test -p lpm-keyring ...
#
# Needs gnome-keyring and dbus-daemon installed.

set -euo pipefail

usage() {
  echo "usage: $0 command [args...]" >&2
  exit 2
}

wait_seconds=${LPM_CI_KEYRING_WAIT_SECONDS:-10}

if [ "${1:-}" != "--in-session" ]; then
  [ $# -gt 0 ] || usage
  # gnome-keyring finds a running daemon through $XDG_RUNTIME_DIR/keyring/control.
  # On a runner, /run/user/<uid>/keyring can also be served by the user's systemd
  # session once the package enables its socket unit, and the unlock then lands in
  # a daemon this bus never sees. A private runtime dir keeps both off that path.
  runtime_dir=$(mktemp -d)
  trap 'rm -rf "$runtime_dir"' EXIT
  status=0
  XDG_RUNTIME_DIR=$runtime_dir dbus-run-session -- "$BASH" "$0" --in-session "$@" || status=$?
  exit "$status"
fi
shift
[ $# -gt 0 ] || usage

printf lpm-ci | gnome-keyring-daemon --unlock --components=secrets >/dev/null
# The unlocked daemon joins the bus in the background. Without --start, a client
# that arrives first makes D-Bus activate a second daemon instead.
gnome-keyring-daemon --start --components=secrets >/dev/null

secret_service_is_registered() {
  dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets 2>/dev/null |
    grep -q 'boolean true'
}

attempts=$((wait_seconds * 10))
for ((attempt = 0; attempt < attempts; attempt++)); do
  if secret_service_is_registered; then
    exec "$@"
  fi
  sleep 0.1
done

echo "error: gnome-keyring did not register org.freedesktop.secrets on the session bus within ${wait_seconds}s" >&2
ls -la "$XDG_RUNTIME_DIR/keyring" >&2 || true
exit 1
