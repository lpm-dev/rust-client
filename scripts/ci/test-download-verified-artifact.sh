#!/bin/bash

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/payload"
printf '%s\n' verified > "$fixture/payload/value.txt"
(cd "$fixture/payload" && zip -q "$fixture/artifact.zip" value.txt)

cat > "$fixture/bin/gh" <<'EOF'
#!/bin/bash
set -euo pipefail
test "$1" = api
cat "$LPM_TEST_ARTIFACT_ARCHIVE"
EOF
chmod +x "$fixture/bin/gh"
export PATH="$fixture/bin:$PATH"
export LPM_TEST_ARTIFACT_ARCHIVE="$fixture/artifact.zip"
digest="sha256:$(sha256sum "$fixture/artifact.zip" | awk '{print $1}')"

bash "$repo_root/scripts/ci/download-verified-artifact.sh" \
  lpm-dev/rust-client 42 "$digest" "$fixture/output"
test "$(cat "$fixture/output/value.txt")" = verified

if bash "$repo_root/scripts/ci/download-verified-artifact.sh" \
  lpm-dev/rust-client 42 "sha256:$(printf '0%.0s' {1..64})" "$fixture/mismatch"; then
  echo "digest mismatch was accepted" >&2
  exit 1
fi
