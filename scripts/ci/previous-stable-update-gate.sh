#!/bin/bash
# Updates the latest published stable LPM to a release served from this
# machine, through that stable's own `lpm self-update`.
#
# Every installed copy updates with the code it shipped, and that code can't
# change afterwards. A release whose signature, manifest or macOS bundle an
# installed updater would refuse strands those users, so the release workflow
# runs this on each candidate before promoting it, and the release trust
# monitor runs it daily on the newest nightly.
#
# The release directory holds the release's GitHub assets: SHA256SUMS.txt,
# SHA256SUMS.txt.sigstore and the platform assets.

set -euo pipefail

usage() {
  echo "usage: $0 <release-dir> <version> <source-commit> <stable|nightly> [previous-stable-version]" >&2
  exit 2
}

[ "$#" -ge 4 ] && [ "$#" -le 5 ] || usage

release_dir=$(cd "$1" && pwd)
version=$2
source_commit=$3
channel=$4
previous=${5:-}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)

# The first stable whose updater needs neither Xcode nor the Command Line
# Tools on macOS. Earlier ones run /usr/bin/stapler, which only Xcode
# provides.
first_version_without_developer_tools=0.89.0

case "$channel" in
  stable|nightly) ;;
  *) usage ;;
esac
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "source commit must be a 40-character lowercase Git object ID: $source_commit" >&2
  exit 2
fi
for asset in SHA256SUMS.txt SHA256SUMS.txt.sigstore; do
  if [ ! -f "$release_dir/$asset" ]; then
    echo "$release_dir has no $asset" >&2
    exit 2
  fi
done

if [ -z "$previous" ]; then
  previous=$(curl -fsSL --retry 3 https://registry.npmjs.org/@lpm-registry/cli/latest |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["version"])')
fi
newer=$(python3 - "$version" "$previous" <<'PY'
import re, sys

def key(version):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-(.+))?", version)
    if not match:
        sys.exit(f"not a release version: {version}")
    major, minor, patch, pre = match.groups()
    return (int(major), int(minor), int(patch), pre is None, pre or "")

print("yes" if key(sys.argv[1]) > key(sys.argv[2]) else "no")
PY
)
if [ "$newer" != yes ]; then
  echo "$version is not newer than the latest stable, $previous; nothing to update from" >&2
  exit 0
fi

work=$(mktemp -d)
server_pid=
developer_tools_hidden=
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
  fi
  if [ -n "$developer_tools_hidden" ]; then
    bash "$repo_root/scripts/ci/macos-developer-tools.sh" restore "$work/developer-tools" || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

home="$work/home"
serve="$work/serve"
mkdir -p "$home" "$serve/download/$version" "$serve/release"
cp -p "$release_dir"/* "$serve/download/$version/"

# The updater checks that the release was published close to when Rekor
# recorded its signature, and from the commit the signature names.
integrated_time=$(python3 - "$release_dir/SHA256SUMS.txt.sigstore" <<'PY'
import json, sys

def find(value):
    if isinstance(value, dict):
        if "integratedTime" in value:
            return value["integratedTime"]
        values = value.values()
    elif isinstance(value, list):
        values = value
    else:
        return None
    for item in values:
        found = find(item)
        if found is not None:
            return found
    return None

print(int(find(json.load(open(sys.argv[1])))))
PY
)
published_at=$(python3 -c 'import datetime, sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$integrated_time")
printf '{"name":"@lpm-registry/cli","version":"%s"}\n' "$version" > "$serve/npm.json"
printf '{"tag_name":"v%s","published_at":"%s","target_commitish":"%s"}\n' \
  "$version" "$published_at" "$source_commit" > "$serve/release/$version.json"

port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$serve" \
  >"$work/server.log" 2>&1 &
server_pid=$!
base="http://127.0.0.1:$port"
for attempt in $(seq 1 50); do
  if curl -fsS -o /dev/null "$base/npm.json" 2>/dev/null; then
    break
  fi
  if [ "$attempt" -eq 50 ]; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.1
done

run_isolated() {
  env -u LPM_HOME -u LPM_INSTALL_DOWNLOAD_BASE -u LPM_INSTALL_TEST_DOWNLOAD_BASE \
    HOME="$home" LPM_NO_UPDATE_CHECK=1 "$@"
}

echo "Installing LPM $previous through the official installer"
run_isolated LPM_INSTALL_VERSION="v$previous" LPM_INSTALL_CHANNEL=stable sh "$repo_root/install.sh"
lpm="$home/.lpm/bin/lpm"
actual=$(run_isolated "$lpm" --version)
if [ "$actual" != "lpm $previous" ]; then
  echo "the installer installed '$actual', not lpm $previous" >&2
  exit 1
fi

if [ "$(uname -s)" = Darwin ] &&
  [ "$(printf '%s\n%s\n' "$first_version_without_developer_tools" "$previous" | sort -V | head -n 1)" = "$first_version_without_developer_tools" ]; then
  # Most users' Macs have neither Xcode nor the Command Line Tools.
  bash "$repo_root/scripts/ci/macos-developer-tools.sh" hide none "$work/developer-tools"
  developer_tools_hidden=1
fi

echo "Updating LPM $previous to $version through its own updater"
update_status=0
run_isolated \
  LPM_NPM_REGISTRY_URL_OVERRIDE="$base/npm.json" \
  LPM_NPM_NIGHTLY_REGISTRY_URL_OVERRIDE="$base/npm.json" \
  LPM_GITHUB_RELEASES_URL_OVERRIDE="$base/no-release-list" \
  LPM_GITHUB_NIGHTLY_RELEASES_URL_OVERRIDE="$base/no-release-list" \
  LPM_GITHUB_RELEASE_BY_TAG_URL_OVERRIDE="$base/release/{tag}.json" \
  LPM_GITHUB_RELEASE_DOWNLOAD_URL_OVERRIDE="$base/download/{tag}/{file}" \
  "$lpm" self-update --channel "$channel" --refresh || update_status=$?

if [ -n "$developer_tools_hidden" ]; then
  bash "$repo_root/scripts/ci/macos-developer-tools.sh" restore "$work/developer-tools"
  developer_tools_hidden=
fi
if [ "$update_status" -ne 0 ]; then
  echo "::error::LPM $previous refused to update to $version (exit $update_status). Installed copies would be stranded on $previous." >&2
  exit 1
fi

actual=$(run_isolated "$lpm" --version)
if [ "$actual" != "lpm $version" ]; then
  echo "::error::LPM $previous reported success, but lpm --version says '$actual', not lpm $version" >&2
  exit 1
fi
echo "LPM $previous updated itself to $version"
