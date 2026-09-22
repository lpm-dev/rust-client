#!/usr/bin/env bash
set -euo pipefail

version=${1:?release version is required}
tag=${2:?npm dist-tag is required}
propagation_timeout_seconds=900
deadline=$((SECONDS + propagation_timeout_seconds))
attempt=0
backoff=5
attempt_root=

cleanup_attempt() {
  if [ -n "$attempt_root" ]; then
    rm -rf "$attempt_root"
  fi
  attempt_root=
}
trap cleanup_attempt EXIT

run_before_deadline() {
  local remaining=$((deadline - SECONDS))
  [ "$remaining" -gt 0 ] || return 1
  timeout --signal=TERM --kill-after=5s "${remaining}s" "$@"
}

verify_attempt() {
  local prefix="$attempt_root/prefix"
  local cache="$attempt_root/cache"
  local installed_version tagged_version
  local npm_options=(
    --registry=https://registry.npmjs.org
    --cache "$cache" --prefer-online
    --fetch-retries=0 --fetch-timeout=30000
  )

  run_before_deadline npm install -g --prefix "$prefix" \
    "${npm_options[@]}" --include=optional --ignore-scripts=false --no-audit --no-fund \
    "@lpm-registry/cli@$version" || return 1
  installed_version=$(run_before_deadline "$prefix/bin/lpm" --version) || return 1
  if [ "$installed_version" != "lpm $version" ]; then
    echo "Expected lpm $version, received: $installed_version" >&2
    return 1
  fi
  run_before_deadline "$prefix/bin/lpx" --help || return 1
  tagged_version=$(run_before_deadline npm view @lpm-registry/cli "dist-tags.$tag" \
    "${npm_options[@]}") || return 1
  if [ "$tagged_version" != "$version" ]; then
    echo "Expected dist-tags.$tag=$version, received: $tagged_version" >&2
    return 1
  fi
  [ "$SECONDS" -lt "$deadline" ]
}

while [ "$SECONDS" -lt "$deadline" ]; do
  attempt=$((attempt + 1))
  attempt_root=$(mktemp -d)
  echo "Verifying published wrapper $version (attempt $attempt, $((deadline - SECONDS))s remaining)"
  if verify_attempt >"$attempt_root/verify.log" 2>&1; then
    echo "Verified published wrapper $version and dist-tags.$tag"
    exit 0
  fi
  cat "$attempt_root/verify.log" >&2
  cleanup_attempt

  remaining=$((deadline - SECONDS))
  if [ "$remaining" -le 0 ]; then break; fi
  if [ "$backoff" -gt "$remaining" ]; then backoff=$remaining; fi
  sleep "$backoff"
  backoff=$((backoff * 2))
  if [ "$backoff" -gt 30 ]; then backoff=30; fi
done

echo "::error::Published wrapper $version install/launch or dist-tags.$tag verification failed after ${propagation_timeout_seconds}s registry-propagation window" >&2
exit 1
