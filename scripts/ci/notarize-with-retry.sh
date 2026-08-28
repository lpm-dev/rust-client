#!/bin/bash

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <archive> <notarytool-auth-arguments...>" >&2
  exit 2
fi

archive=$1
shift
if [ ! -f "$archive" ]; then
  echo "notarization archive does not exist: $archive" >&2
  exit 2
fi

MAX_SUBMIT_ATTEMPTS=${LPM_NOTARY_MAX_SUBMIT_ATTEMPTS:-4}
MAX_INFO_ATTEMPTS=${LPM_NOTARY_MAX_INFO_ATTEMPTS:-120}
POLL_SECONDS=${LPM_NOTARY_POLL_SECONDS:-15}
state_path=${LPM_NOTARY_STATE_PATH:-"${archive}.submission-id"}
mode=${LPM_NOTARY_MODE:-all}
submission_id=
archive_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')

if [ "$mode" != all ] && [ "$mode" != submit ] && [ "$mode" != poll ]; then
  echo "LPM_NOTARY_MODE must be all, submit, or poll" >&2
  exit 2
fi

if [ -f "$state_path" ]; then
  state_archive_sha256=$(jq -r '.archiveSha256 // empty' "$state_path" 2>/dev/null || true)
  submission_id=$(jq -r '.submissionId // empty' "$state_path" 2>/dev/null || true)
  if [ "$state_archive_sha256" != "$archive_sha256" ]; then
    echo "notarization state does not belong to the current archive" >&2
    exit 1
  fi
  if [[ ! "$submission_id" =~ ^[0-9A-Fa-f-]{36}$ ]]; then
    echo "invalid notarization submission ID in $state_path" >&2
    exit 1
  fi
  echo "Resuming notarization submission $submission_id"
fi

if [ "$mode" = poll ] && [ -z "$submission_id" ]; then
  echo "notarization polling requires a persisted submission state file" >&2
  exit 1
fi

submit_attempt=1
while [ -z "$submission_id" ] && [ "$submit_attempt" -le "$MAX_SUBMIT_ATTEMPTS" ]; do
  response=$(mktemp)
  if xcrun notarytool submit "$archive" "$@" --output-format json >"$response" 2>&1; then
    :
  fi
  parsed_id=$(jq -r '.id // empty' "$response" 2>/dev/null || true)
  if [[ "$parsed_id" =~ ^[0-9A-Fa-f-]{36}$ ]]; then
    submission_id=$parsed_id
    umask 077
    state_temp="${state_path}.tmp"
    jq -n \
      --arg archiveSha256 "$archive_sha256" \
      --arg submissionId "$submission_id" \
      '{archiveSha256: $archiveSha256, submissionId: $submissionId}' > "$state_temp"
    mv "$state_temp" "$state_path"
    rm -f "$response"
    break
  fi

  echo "Notarization submit attempt $submit_attempt did not return a submission ID." >&2
  sed -E 's/(password|key)[^[:space:]]*/[redacted]/Ig' "$response" >&2
  rm -f "$response"
  if [ "$submit_attempt" -eq "$MAX_SUBMIT_ATTEMPTS" ]; then
    echo "Notarization submission failed after $MAX_SUBMIT_ATTEMPTS attempts." >&2
    exit 1
  fi
  sleep $((submit_attempt * submit_attempt * 5))
  submit_attempt=$((submit_attempt + 1))
done

if [ "$mode" = submit ]; then
  echo "Notarization submitted: $submission_id"
  exit 0
fi

info_attempt=1
while [ "$info_attempt" -le "$MAX_INFO_ATTEMPTS" ]; do
  response=$(mktemp)
  if xcrun notarytool info "$submission_id" "$@" --output-format json >"$response" 2>&1; then
    status=$(jq -r '.status // empty' "$response" 2>/dev/null || true)
    case "$status" in
      Accepted)
        rm -f "$response" "$state_path"
        echo "Notarization accepted: $submission_id"
        exit 0
        ;;
      Invalid | Rejected)
        cat "$response" >&2
        rm -f "$response"
        xcrun notarytool log "$submission_id" "$@" || true
        exit 1
        ;;
      "In Progress" | Uploaded | Processing | "") ;;
      *)
        echo "Unexpected notarization status: $status" >&2
        cat "$response" >&2
        rm -f "$response"
        exit 1
        ;;
    esac
  else
    echo "Transient notarization status failure for $submission_id (attempt $info_attempt)." >&2
  fi
  rm -f "$response"
  if [ "$info_attempt" -lt "$MAX_INFO_ATTEMPTS" ]; then sleep "$POLL_SECONDS"; fi
  info_attempt=$((info_attempt + 1))
done

echo "Timed out waiting for notarization submission $submission_id; resume polling with the persisted state file." >&2
exit 1
