#!/bin/bash

set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <repository> <artifact-id> <sha256:digest> <output-directory>" >&2
  exit 2
fi

repository=$1
artifact_id=$2
expected_digest=$3
output_directory=$4

if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
   [[ ! "$artifact_id" =~ ^[1-9][0-9]*$ ]] ||
   [[ ! "$expected_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "invalid verified-artifact identity" >&2
  exit 2
fi
if [ -e "$output_directory" ]; then
  echo "artifact output directory already exists: $output_directory" >&2
  exit 2
fi

archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
gh api "repos/${repository}/actions/artifacts/${artifact_id}/zip" > "$archive"
actual_digest="sha256:$(sha256sum "$archive" | awk '{print $1}')"
if [ "$actual_digest" != "$expected_digest" ]; then
  echo "artifact digest mismatch: expected $expected_digest, got $actual_digest" >&2
  exit 1
fi

entries=$(zipinfo -1 "$archive")
if printf '%s\n' "$entries" | grep -Eq '(^/|(^|/)\.\.(/|$)|\\)'; then
  echo "artifact contains an unsafe archive path" >&2
  exit 1
fi
duplicates=$(printf '%s\n' "$entries" | sort | uniq -d)
if [ -n "$duplicates" ]; then
  echo "artifact contains duplicate archive paths" >&2
  exit 1
fi

mkdir "$output_directory"
unzip -q "$archive" -d "$output_directory"
