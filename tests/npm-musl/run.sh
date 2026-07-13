#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "usage: $0 /path/to/lpm-linux-x64-musl" >&2
  exit 2
fi

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

cp -R "$repo_root/npm/cli" "$work_dir/cli"
cp -R "$repo_root/npm/cli-linux-x64-musl" "$work_dir/cli-linux-x64-musl"
cp "$1" "$work_dir/cli-linux-x64-musl/lpm"
cp "$1" "$work_dir/cli-linux-x64-musl/lpx"
chmod +x "$work_dir/cli-linux-x64-musl/lpm" "$work_dir/cli-linux-x64-musl/lpx"

platform_package=$(cd "$work_dir/cli-linux-x64-musl" && npm pack --silent --pack-destination "$work_dir")
wrapper_package=$(cd "$work_dir/cli" && npm pack --silent --pack-destination "$work_dir")

mkdir "$work_dir/project"
cd "$work_dir/project"
npm install --offline --no-audit --no-fund --no-package-lock \
  "$work_dir/$platform_package" \
  "$work_dir/$wrapper_package"

test "$(node -p "require('./node_modules/@lpm-registry/cli-linux-x64-musl/package.json').libc[0]")" = "musl"
./node_modules/.bin/lpm --version
./node_modules/.bin/lpx --help >/dev/null
