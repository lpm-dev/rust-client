#!/usr/bin/env bash
set -euo pipefail

ATTEMPTS="${LPM_CI_APT_ATTEMPTS:-3}"
TIMEOUT_SECONDS="${LPM_CI_APT_TIMEOUT_SECONDS:-60}"
RETRY_DELAY_SECONDS="${LPM_CI_APT_RETRY_DELAY_SECONDS:-5}"
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
require_positive_integer LPM_CI_APT_TIMEOUT_SECONDS "$TIMEOUT_SECONDS"
require_nonnegative_integer LPM_CI_APT_RETRY_DELAY_SECONDS "$RETRY_DELAY_SECONDS"
[[ "$#" -gt 0 ]] || fail "usage: $0 PACKAGE [PACKAGE ...]"
command -v "$APT_GET_COMMAND" >/dev/null || fail "apt-get command not found: $APT_GET_COMMAND"
command -v "$TIMEOUT_COMMAND" >/dev/null || fail "timeout command not found: $TIMEOUT_COMMAND"
command -v "$SLEEP_COMMAND" >/dev/null || fail "sleep command not found: $SLEEP_COMMAND"

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

run_with_retries() {
  local description="$1"
  shift
  local attempt
  local status

  for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
    echo "$description (attempt $attempt/$ATTEMPTS)"
    if "${EXECUTION_PREFIX[@]}" \
      "$TIMEOUT_COMMAND" \
      --signal=TERM \
      --kill-after=10s \
      "${TIMEOUT_SECONDS}s" \
      "$APT_GET_COMMAND" \
      "${APT_OPTIONS[@]}" \
      "$@"; then
      return 0
    else
      status=$?
    fi

    if ((attempt == ATTEMPTS)); then
      echo "ERROR: $description failed after $ATTEMPTS attempts (last status: $status)" >&2
      return "$status"
    fi
    echo "WARNING: $description failed with status $status; retrying in ${RETRY_DELAY_SECONDS}s" >&2
    "$SLEEP_COMMAND" "$RETRY_DELAY_SECONDS"
  done
}

run_with_retries "Refresh APT indexes" update
run_with_retries "Install APT packages" install -y "$@"
