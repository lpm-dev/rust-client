#!/bin/bash
# Updates a published stable LPM to a release served from this machine,
# through that stable's own `lpm self-update`.
#
# Every installed copy updates with the code it shipped, and that code can't
# change afterwards. A release whose signature, manifest or macOS bundle an
# installed updater would refuse strands those users, so the release workflow
# runs this on each candidate before promoting it, and the release trust
# monitor runs it daily on the newest release.
#
# The release directory holds the release's GitHub assets: SHA256SUMS.txt,
# SHA256SUMS.txt.sigstore and the platform assets.
#
# --previous names the stable to update from; the default is npm's latest.
# --published-at gives a published release's real publication time; an
# unpublished candidate is served as published when Rekor recorded its
# signature.
#
# The updater finds the account's home directory from the system, not from
# $HOME, and on macOS updates only an app in that home. So this runs only on
# a disposable CI runner, where it sets the account's ~/.lpm aside and puts
# it back afterwards. Sigstore's trust root is fetched as installed copies
# fetch it.

set -euo pipefail

usage() {
  echo "usage: $0 [--previous VERSION] [--published-at RFC3339] <release-dir> <version> <source-commit> <stable|nightly>" >&2
  exit 2
}

previous=
published_at=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --previous)
      [ "$#" -ge 2 ] || usage
      previous=$2
      shift 2
      ;;
    --published-at)
      [ "$#" -ge 2 ] || usage
      published_at=$2
      shift 2
      ;;
    --*) usage ;;
    *) break ;;
  esac
done
[ "$#" -eq 4 ] || usage

if [ "${GITHUB_ACTIONS:-}" != true ]; then
  echo "$0 replaces this account's ~/.lpm while it runs, so it runs only in GitHub Actions" >&2
  exit 2
fi

release_dir=$(cd "$1" && pwd)
version=$2
source_commit=$3
channel=$4
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

newer_than() {
  python3 -I "$repo_root/scripts/ci/semver-newer.py" "$1" "$2"
}

if [ -z "$previous" ]; then
  previous=$(curl -fsSL --retry 3 https://registry.npmjs.org/@lpm-registry/cli/latest |
    python3 -I -c 'import json, sys; print(json.load(sys.stdin)["version"])')
fi
if [ "$(newer_than "$version" "$previous")" != yes ]; then
  echo "::error::$version is not newer than $previous, so LPM $previous has nothing to update to" >&2
  exit 1
fi

account_home=$(python3 -I -c 'import os, pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)')
account_lpm="$account_home/.lpm"
work=$(mktemp -d)
# Beside ~/.lpm, so setting it aside is a rename on the same volume.
set_aside="$account_home/.lpm-set-aside-by-update-gate"
# Under RUNNER_TEMP, so a workflow step can restore the developer tools even
# if this script is killed.
developer_tools="${RUNNER_TEMP:-$work}/previous-stable-gate-developer-tools"
server_pid=
account_lpm_claimed=
developer_tools_hidden=
cleanup() {
  local status=$?
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
  fi
  if [ -n "$developer_tools_hidden" ] &&
    ! bash "$repo_root/scripts/ci/macos-developer-tools.sh" restore "$developer_tools"; then
    echo "::error::developer tools could not be restored; they remain under $developer_tools" >&2
    status=1
  fi
  if [ -n "$account_lpm_claimed" ]; then
    rm -rf "$account_lpm"
    if [ -e "$set_aside" ] && ! mv "$set_aside" "$account_lpm"; then
      echo "::error::could not put the account's ~/.lpm back; it is at $set_aside" >&2
      status=1
    fi
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ -e "$set_aside" ]; then
  echo "$set_aside already exists: an earlier run didn't put the account's ~/.lpm back" >&2
  exit 1
fi
if [ -e "$account_lpm" ]; then
  mv "$account_lpm" "$set_aside"
fi
account_lpm_claimed=1

serve="$work/serve"
mkdir -p "$serve/download/$version" "$serve/release"
cp -p "$release_dir"/* "$serve/download/$version/"

# The updater checks that the release was published close to when Rekor
# recorded its signature, and from the commit the signature names.
if [ -z "$published_at" ]; then
  published_at=$(python3 -I - "$release_dir/SHA256SUMS.txt.sigstore" <<'PY'
import datetime, json, sys

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

integrated = int(find(json.load(open(sys.argv[1]))))
print(datetime.datetime.fromtimestamp(integrated, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)
fi
printf '{"name":"@lpm-registry/cli","version":"%s"}\n' "$version" > "$serve/npm.json"
printf '{"tag_name":"v%s","published_at":"%s","target_commitish":"%s"}\n' \
  "$version" "$published_at" "$source_commit" > "$serve/release/$version.json"

if [ "$(uname -s)" = Darwin ]; then
  # The server keeps running while the developer tools are hidden.
  python_prefix=$(python3 -I -c 'import sys; print(sys.base_prefix)')
  case "$python_prefix" in
    /Library/Developer/*|/Applications/Xcode*)
      echo "::error::python3 comes from developer tools ($python_prefix), which this gate hides" >&2
      exit 1
      ;;
  esac
fi
python3 -I -u -m http.server 0 --bind 127.0.0.1 --directory "$serve" \
  >"$work/server.log" 2>&1 &
server_pid=$!
port=
for attempt in $(seq 1 50); do
  port=$(sed -n 's/.* port \([0-9][0-9]*\) .*/\1/p' "$work/server.log" | head -n 1)
  if [ -n "$port" ] && curl -fsS -o /dev/null "http://127.0.0.1:$port/npm.json" 2>/dev/null; then
    break
  fi
  if [ "$attempt" -eq 50 ]; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.1
done
base="http://127.0.0.1:$port"

run_isolated() {
  env -u LPM_HOME -u LPM_INSTALL_DOWNLOAD_BASE -u LPM_INSTALL_TEST_DOWNLOAD_BASE -u DEVELOPER_DIR \
    HOME="$account_home" LPM_NO_UPDATE_CHECK=1 "$@"
}

echo "Installing LPM $previous through the official installer"
run_isolated LPM_INSTALL_VERSION="v$previous" LPM_INSTALL_CHANNEL=stable sh "$repo_root/install.sh"
lpm="$account_lpm/bin/lpm"
actual=$(run_isolated "$lpm" --version)
if [ "$actual" != "lpm $previous" ]; then
  echo "the installer installed '$actual', not lpm $previous" >&2
  exit 1
fi

if [ "$(uname -s)" = Darwin ] &&
  [ "$(newer_than "$first_version_without_developer_tools" "$previous")" = no ]; then
  # Most users' Macs have neither Xcode nor the Command Line Tools. Set
  # before hiding, so a hide that fails partway is still undone.
  developer_tools_hidden=1
  bash "$repo_root/scripts/ci/macos-developer-tools.sh" hide none "$developer_tools"
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
  bash "$repo_root/scripts/ci/macos-developer-tools.sh" restore "$developer_tools"
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
