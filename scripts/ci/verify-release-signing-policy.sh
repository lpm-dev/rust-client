#!/bin/bash
# Verifies a signed SHA256SUMS.txt with the self-update signing policy compiled
# into the LPM binary being released. The release workflow runs it on each fresh
# attestation, so a signing identity that installed clients would refuse fails
# before any draft or published release exists, and again on the published
# assets with the release's recorded publication time and target commit.

set -euo pipefail

if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
  echo "usage: $0 <lpm-binary> <version> <SHA256SUMS.txt> <SHA256SUMS.txt.sigstore> <release-commit> [published-at]" >&2
  exit 2
fi

binary=$1
version=$2
manifest=$3
bundle=$4
release_commit=$5
published_at=${6:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}

if [[ ! "$release_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "release commit must be a 40-character lowercase Git object ID: $release_commit" >&2
  exit 2
fi

# Run a private executable copy under a throwaway HOME so the staged release
# tree is never modified and the gate cannot read or write runner state.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$binary" "$work/lpm"
chmod 0755 "$work/lpm"
mkdir "$work/home"

HOME="$work/home" "$work/lpm" internal-verify-release "$version" \
  --manifest "$manifest" \
  --bundle "$bundle" \
  --published-at "$published_at" \
  --release-commit "$release_commit"
