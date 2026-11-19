#!/bin/bash
# Verifies with cosign that a stable release's SHA256SUMS.txt was signed by the
# one identity stable releases come from: release.yml in lpm-dev/rust-client,
# run by hand on main at the release's source commit. The release workflow uses
# it wherever it checks a stable release's signature, so every check holds the
# same identity, and none accepts another ref, repository, commit or trigger.

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <SHA256SUMS.txt> <SHA256SUMS.txt.sigstore> <source-commit>" >&2
  exit 2
fi

manifest=$1
bundle=$2
source_commit=$3

if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "source commit must be a 40-character lowercase Git object ID: $source_commit" >&2
  exit 2
fi

cosign verify-blob \
  --bundle "$bundle" \
  --certificate-identity 'https://github.com/lpm-dev/rust-client/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate-github-workflow-repository lpm-dev/rust-client \
  --certificate-github-workflow-ref refs/heads/main \
  --certificate-github-workflow-sha "$source_commit" \
  --certificate-github-workflow-trigger workflow_dispatch \
  "$manifest"
