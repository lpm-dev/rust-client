#!/bin/bash

# Runs a macOS signing tool that depends on an Apple network service, running
# it again while that service fails transiently. Any other failure fails at
# once with the tool's own exit status.
#
#   codesign <arguments...>          retries when the timestamp authority fails
#   stapler <staple|validate> <path> retries while the ticketing service
#                                    doesn't answer

set -euo pipefail

usage() {
  echo "usage: $0 codesign <codesign-arguments...>" >&2
  echo "       $0 stapler <staple|validate> <path>" >&2
  exit 2
}

[ "$#" -ge 2 ] || usage
service=$1
shift

MAX_ATTEMPTS=${LPM_APPLE_SERVICE_MAX_ATTEMPTS:-5}
BACKOFF_SECONDS=${LPM_APPLE_SERVICE_BACKOFF_SECONDS:-5}
CODESIGN=${LPM_APPLE_SERVICE_CODESIGN:-/usr/bin/codesign}
XCRUN=${LPM_APPLE_SERVICE_XCRUN:-/usr/bin/xcrun}

# stapler exits with EX_NOHOST when CloudKit doesn't answer the ticket lookup,
# and when staple runs before a just-accepted ticket has propagated.
STAPLER_TICKETING_SERVICE_UNAVAILABLE=68

case "$service" in
  codesign)
    command=("$CODESIGN" "$@")
    description=codesign
    ;;
  stapler)
    [ "$#" -eq 2 ] || usage
    case "$1" in
      staple | validate) ;;
      *) usage ;;
    esac
    command=("$XCRUN" stapler "$1" "$2")
    description="stapler $1"
    ;;
  *) usage ;;
esac

output_dir=$(mktemp -d)
trap 'rm -rf "$output_dir"' EXIT
stdout_path="$output_dir/stdout"
stderr_path="$output_dir/stderr"

# codesign exits 1 for every signing failure, so its message is the only
# signal. These Security framework errors mean the timestamp authority didn't
# deliver; its other timestamp errors, such as an untrusted timestamp, persist.
# The Security framework reports every RFC 3161 rejection with one message,
# whatever its failInfo, so the authority's temporary systemFailure and
# timeNotAvailable rejections are only retried by retrying all of them.
codesign_timestamp_authority_unavailable() {
  grep -qF \
    -e "A timestamp was expected but was not found." \
    -e "The timestamp service is not available." \
    -e "The time source for the Timestamp Authority is not available." \
    -e "The timestamp request cannot be handled due to system failure." \
    -e "A timestamp transaction is waiting." \
    -e "A timestamp transaction was rejected." \
    "$stdout_path" "$stderr_path"
}

is_transient() {
  case "$service" in
    codesign) codesign_timestamp_authority_unavailable ;;
    stapler) [ "$1" -eq "$STAPLER_TICKETING_SERVICE_UNAVAILABLE" ] ;;
  esac
}

attempt=1
while :; do
  status=0
  "${command[@]}" >"$stdout_path" 2>"$stderr_path" || status=$?
  cat "$stdout_path"
  cat "$stderr_path" >&2
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  if ! is_transient "$status"; then
    exit "$status"
  fi
  if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
    echo "::error::$description still failed after $MAX_ATTEMPTS attempts; Apple's service did not recover." >&2
    exit "$status"
  fi
  delay=$((attempt * attempt * BACKOFF_SECONDS))
  echo "::warning::$description hit a transient Apple service failure (attempt $attempt of $MAX_ATTEMPTS); retrying in ${delay}s." >&2
  sleep "$delay"
  attempt=$((attempt + 1))
done
