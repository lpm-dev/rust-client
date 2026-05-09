#!/bin/bash
# npm-aliases smoke. Each alias must resolve to its target's contents.
# We assert that:
#   1. node_modules/<alias>/package.json carries the TARGET's name field
#      (e.g. node_modules/lodash-a/package.json → "name": "lodash"),
#   2. require('<alias>') exposes the TARGET's runtime surface,
#   3. all three lodash aliases AND the unaliased lodash are visible
#      simultaneously without clobbering each other,
#   4. the scoped-target alias (@types/node aliased to a non-scoped name)
#      installs and is at least filesystem-resolvable.
set -e

# 1. Filesystem identity: each alias dir's package.json names the
# target, not the alias.
check_alias_identity() {
    local alias="$1" target="$2"
    local pj="node_modules/$alias/package.json"
    if [[ ! -f "$pj" ]]; then
        echo "missing alias dir: $pj"
        exit 2
    fi
    local found
    found=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$pj','utf8')).name)")
    if [[ "$found" != "$target" ]]; then
        echo "alias $alias resolves to wrong package: name=$found, expected $target"
        exit 3
    fi
}

check_alias_identity "lodash" "lodash"
check_alias_identity "lodash-a" "lodash"
check_alias_identity "lodash-b" "lodash"
check_alias_identity "lodash-c" "lodash"
check_alias_identity "code-frame-alias" "@babel/code-frame"

# Functional check for the scoped-target alias too — proves the
# LAST-`@`-split path (alias `code-frame-alias` → target `@babel/code-frame`)
# resolves to a runtime-loadable module, not just a name-equivalent.
node -e "
const cf = require('code-frame-alias');
if (typeof cf.codeFrameColumns !== 'function') {
    console.error('code-frame-alias missing codeFrameColumns export');
    process.exit(6);
}
"

# 2. Functional: each lodash-shaped require returns lodash's surface.
# We assert on a stable named export (`toArray`) and that all four
# entries return the SAME function (they're aliases of the same
# package — should be one underlying copy via lpm's content-
# addressable store).
node -e "
const direct = require('lodash');
const a = require('lodash-a');
const b = require('lodash-b');
const c = require('lodash-c');
for (const [name, lib] of [['lodash', direct], ['lodash-a', a], ['lodash-b', b], ['lodash-c', c]]) {
    if (typeof lib.toArray !== 'function') {
        console.error('alias', name, 'does not expose lodash.toArray');
        process.exit(4);
    }
    if (lib.toArray('xy').join('') !== 'xy') {
        console.error('alias', name, 'lodash.toArray returned wrong value');
        process.exit(5);
    }
}
// All four point at the same content-addressed package — toArray
// should be reference-equal across aliases. If not, lpm has a
// duplicate-extraction bug for aliased deps (still a pass, just a
// store inefficiency); flag it without failing the smoke.
if (direct.toArray !== a.toArray || direct.toArray !== b.toArray || direct.toArray !== c.toArray) {
    console.error('NOTE: lodash aliases are not reference-equal — same target was extracted multiple times');
}
"
