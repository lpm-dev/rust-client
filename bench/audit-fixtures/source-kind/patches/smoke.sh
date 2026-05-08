#!/bin/bash
# patches smoke. Verifies that ms's installed copy carries the
# patched-in `lpmPatchProof` export. The patch (`patches/ms@2.1.3.patch`)
# appends a sentinel function to ms's index.js; the contract is that
# `apply_patches_for_install` mutates EVERY materialized destination
# of ms@2.1.3 — under hoisted that's `node_modules/ms/`, under
# isolated that's the wrappers segment that contains ms — and from
# the project root `require('ms').lpmPatchProof()` returns the
# sentinel string regardless of mode.
set -e

# 1. Layout-level: ms is present + the patch file is intact in the
# project (the harness copies fixture files into the work dir).
if [[ ! -e node_modules/ms/package.json ]]; then
    echo "ms not installed at top level"
    exit 2
fi
if [[ ! -f patches/ms@2.1.3.patch ]]; then
    echo "patch file missing in work dir"
    exit 3
fi

# 2. Functional: require ms and call the patched-in function.
node -e "
const ms = require('ms');
if (typeof ms.lpmPatchProof !== 'function') {
    console.error('ms.lpmPatchProof is not a function — patch not applied');
    console.error('available exports:', Object.keys(ms));
    process.exit(4);
}
const proof = ms.lpmPatchProof();
if (proof !== 'patched-by-lpm-fixture-2f') {
    console.error('lpmPatchProof returned wrong value:', proof);
    process.exit(5);
}
"
