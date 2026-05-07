#!/bin/bash
# husky: validate the package loaded + the bin is on PATH. Note: husky
# only writes .husky/ to the project root when invoked as the
# `prepare` script in a git repo; this audit doesn't initialize git,
# so we only test the package-load path. The sibling-write
# capability is exercised in real-world adoption — lpm's sandbox
# either permits it or surfaces the policy error.
set -e
node -e "
const husky = require('husky');
// husky exports a single function (install).
if (typeof husky !== 'function' && typeof husky.default !== 'function') {
    console.error('husky main export is not callable:', typeof husky);
    process.exit(2);
}
"
# Bin should be linked.
if [[ ! -e node_modules/.bin/husky ]]; then
    echo "node_modules/.bin/husky missing"
    exit 3
fi
