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
cp -R "$repo_root/npm/cli-linux-x64" "$work_dir/cli-linux-x64"
cp -R "$repo_root/npm/cli-linux-x64-musl" "$work_dir/cli-linux-x64-musl"
cp "$1" "$work_dir/cli-linux-x64/lpm"
cp "$1" "$work_dir/cli-linux-x64/lpx"
cp "$1" "$work_dir/cli-linux-x64-musl/lpm"
cp "$1" "$work_dir/cli-linux-x64-musl/lpx"
chmod +x \
  "$work_dir/cli-linux-x64/lpm" \
  "$work_dir/cli-linux-x64/lpx" \
  "$work_dir/cli-linux-x64-musl/lpm" \
  "$work_dir/cli-linux-x64-musl/lpx"

glibc_package=$(cd "$work_dir/cli-linux-x64" && npm pack --silent --pack-destination "$work_dir")
musl_package=$(cd "$work_dir/cli-linux-x64-musl" && npm pack --silent --pack-destination "$work_dir")

node - "$work_dir/cli/package.json" "$work_dir/$glibc_package" "$work_dir/$musl_package" <<'NODE'
const fs = require("node:fs");
const [manifestPath, glibcPackage, muslPackage] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
manifest.optionalDependencies = {
  "@lpm-registry/cli-linux-x64": `file:${glibcPackage}`,
  "@lpm-registry/cli-linux-x64-musl": `file:${muslPackage}`,
};
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
NODE

wrapper_package=$(cd "$work_dir/cli" && npm pack --silent --pack-destination "$work_dir")

mkdir "$work_dir/project"
cd "$work_dir/project"
npm install --offline --no-audit --no-fund --no-package-lock \
  "$work_dir/$wrapper_package"

test -d node_modules/@lpm-registry/cli-linux-x64-musl
test ! -e node_modules/@lpm-registry/cli-linux-x64
test "$(node -p "require('./node_modules/@lpm-registry/cli-linux-x64-musl/package.json').libc[0]")" = musl
./node_modules/.bin/lpm --version
./node_modules/.bin/lpx --help >/dev/null
