#!/usr/bin/env bash
set -euo pipefail

ATTEMPTS="${LPM_CI_APT_ATTEMPTS:-3}"
LEGACY_TIMEOUT_SECONDS="${LPM_CI_APT_TIMEOUT_SECONDS:-}"
UPDATE_TIMEOUT_SECONDS="${LPM_CI_APT_UPDATE_TIMEOUT_SECONDS:-${LEGACY_TIMEOUT_SECONDS:-120}}"
INSTALL_TIMEOUT_SECONDS="${LPM_CI_APT_INSTALL_TIMEOUT_SECONDS:-${LEGACY_TIMEOUT_SECONDS:-60}}"
RETRY_DELAY_SECONDS="${LPM_CI_APT_RETRY_DELAY_SECONDS:-5}"
RETRY_JITTER_SECONDS="${LPM_CI_APT_RETRY_JITTER_SECONDS:-5}"
APT_GET_COMMAND="${LPM_CI_APT_GET_COMMAND:-apt-get}"
TIMEOUT_COMMAND="${LPM_CI_TIMEOUT_COMMAND:-timeout}"
SLEEP_COMMAND="${LPM_CI_SLEEP_COMMAND:-sleep}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || fail "$name must be a positive integer"
}

require_nonnegative_integer() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || fail "$name must be a nonnegative integer"
}

require_positive_integer LPM_CI_APT_ATTEMPTS "$ATTEMPTS"
require_positive_integer LPM_CI_APT_UPDATE_TIMEOUT_SECONDS "$UPDATE_TIMEOUT_SECONDS"
require_positive_integer LPM_CI_APT_INSTALL_TIMEOUT_SECONDS "$INSTALL_TIMEOUT_SECONDS"
require_nonnegative_integer LPM_CI_APT_RETRY_DELAY_SECONDS "$RETRY_DELAY_SECONDS"
require_nonnegative_integer LPM_CI_APT_RETRY_JITTER_SECONDS "$RETRY_JITTER_SECONDS"
[[ "$#" -gt 0 ]] || fail "usage: $0 PACKAGE [PACKAGE ...]"
command -v "$APT_GET_COMMAND" >/dev/null || fail "apt-get command not found: $APT_GET_COMMAND"
command -v "$TIMEOUT_COMMAND" >/dev/null || fail "timeout command not found: $TIMEOUT_COMMAND"
command -v "$SLEEP_COMMAND" >/dev/null || fail "sleep command not found: $SLEEP_COMMAND"
command -v awk >/dev/null || fail "awk is required for APT mirror failover"
command -v install >/dev/null || fail "install is required for APT mirror failover"
command -v mktemp >/dev/null || fail "mktemp is required for APT mirror failover"

APT_OPTIONS=(
  -o Acquire::Retries=2
  -o Acquire::http::Timeout=20
  -o Acquire::https::Timeout=20
)
EXECUTION_PREFIX=(env DEBIAN_FRONTEND=noninteractive)
if [[ "${LPM_CI_APT_NO_SUDO:-0}" != "1" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  command -v sudo >/dev/null || fail "sudo is required to install APT packages"
  EXECUTION_PREFIX=(sudo --non-interactive env DEBIAN_FRONTEND=noninteractive)
fi

APT_MIRROR_FILE="/etc/apt/apt-mirrors.txt"
if [[ -n "${LPM_CI_APT_MIRROR_FILE:-}" ]]; then
  [[ "${LPM_CI_APT_NO_SUDO:-0}" == "1" ]] || fail "LPM_CI_APT_MIRROR_FILE requires LPM_CI_APT_NO_SUDO=1"
  [[ "$LPM_CI_APT_MIRROR_FILE" == /* ]] || fail "LPM_CI_APT_MIRROR_FILE must be an absolute path"
  APT_MIRROR_FILE="$LPM_CI_APT_MIRROR_FILE"
fi
MIRROR_PROMOTED=0

promote_github_archive_mirror() {
  ((MIRROR_PROMOTED == 0)) || return 0
  [[ -f "$APT_MIRROR_FILE" && ! -L "$APT_MIRROR_FILE" ]] || return 1
  grep -Eq '^http://azure\.archive\.ubuntu\.com/ubuntu/[[:space:]]+priority:1$' "$APT_MIRROR_FILE" || return 1
  grep -Eq '^https://archive\.ubuntu\.com/ubuntu/[[:space:]]+priority:2$' "$APT_MIRROR_FILE" || return 1
  grep -Eq '^https://security\.ubuntu\.com/ubuntu/[[:space:]]+priority:3$' "$APT_MIRROR_FILE" || return 1

  local rewritten_file
  local staged_file
  rewritten_file="$(mktemp)" || return 1
  if ! awk '
    $1 == "http://azure.archive.ubuntu.com/ubuntu/" {
      printf "%s\tpriority:3\n", $1
      next
    }
    $1 == "https://archive.ubuntu.com/ubuntu/" {
      printf "%s\tpriority:1\n", $1
      next
    }
    $1 == "https://security.ubuntu.com/ubuntu/" {
      printf "%s\tpriority:2\n", $1
      next
    }
    { print }
  ' "$APT_MIRROR_FILE" >"$rewritten_file"; then
    rm -f "$rewritten_file"
    return 1
  fi

  if ! staged_file="$("${EXECUTION_PREFIX[@]}" mktemp "${APT_MIRROR_FILE}.lpm.XXXXXX")"; then
    rm -f "$rewritten_file"
    return 1
  fi
  if ! "${EXECUTION_PREFIX[@]}" install -m 0644 "$rewritten_file" "$staged_file" ||
    ! "${EXECUTION_PREFIX[@]}" mv -f "$staged_file" "$APT_MIRROR_FILE"; then
    "${EXECUTION_PREFIX[@]}" rm -f "$staged_file" || true
    rm -f "$rewritten_file"
    return 1
  fi
  rm -f "$rewritten_file"
  MIRROR_PROMOTED=1
  echo "APT timed out on the Azure mirror; promoted the Ubuntu archive fallback"
}

run_with_retries() {
  local description="$1"
  local timeout_seconds="$2"
  shift 2
  local attempt
  local retry_delay
  local status

  for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
    echo "$description (attempt $attempt/$ATTEMPTS)"
    if "${EXECUTION_PREFIX[@]}" \
      "$TIMEOUT_COMMAND" \
      --signal=TERM \
      --kill-after=10s \
      "${timeout_seconds}s" \
      "$APT_GET_COMMAND" \
      "${APT_OPTIONS[@]}" \
      "$@"; then
      return 0
    else
      status=$?
    fi

    if ((status == 124)); then
      promote_github_archive_mirror || true
    fi

    if ((attempt == ATTEMPTS)); then
      echo "ERROR: $description failed after $ATTEMPTS attempts (last status: $status)" >&2
      return "$status"
    fi
    retry_delay=$((RETRY_DELAY_SECONDS * attempt))
    if ((RETRY_JITTER_SECONDS > 0)); then
      retry_delay=$((retry_delay + RANDOM % (RETRY_JITTER_SECONDS + 1)))
    fi
    echo "WARNING: $description failed with status $status; retrying in ${retry_delay}s" >&2
    "$SLEEP_COMMAND" "$retry_delay"
  done
}

run_with_retries "Refresh APT indexes" "$UPDATE_TIMEOUT_SECONDS" update
run_with_retries "Install APT packages" "$INSTALL_TIMEOUT_SECONDS" install -y "$@"
