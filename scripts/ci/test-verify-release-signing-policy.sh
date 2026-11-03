#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <lpm-binary>" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
binary=$1
gate="$repo_root/scripts/ci/verify-release-signing-policy.sh"
fixtures="$repo_root/crates/lpm-cli/tests/fixtures"
manifest="$fixtures/release_manifests/lpm-v0.84.0-SHA256SUMS.txt"
bundle="$fixtures/sigstore_bundles/21-real-lpm-release-v0.84.0.json"
source_commit=35edeab28d25a6851519629e99e478c3cd810c3a
published_at=2026-11-02T04:06:07Z

expect_failure() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "$description was accepted" >&2
    exit 1
  fi
}

bash "$gate" "$binary" 0.84.0 "$manifest" "$bundle" "$source_commit" "$published_at"

expect_failure "a release targeting another commit" \
  bash "$gate" "$binary" 0.84.0 "$manifest" "$bundle" \
  1e98fb8efbcc00f620678fc8091b512ed503768f "$published_at"
expect_failure "an attestation outside the replay window" \
  bash "$gate" "$binary" 0.84.0 "$manifest" "$bundle" "$source_commit" 2026-11-04T04:06:07Z
expect_failure "a non-hexadecimal release commit" \
  bash "$gate" "$binary" 0.84.0 "$manifest" "$bundle" main "$published_at"
expect_failure "a missing release commit" \
  bash "$gate" "$binary" 0.84.0 "$manifest" "$bundle"

echo "release signing-policy gate tests passed"
