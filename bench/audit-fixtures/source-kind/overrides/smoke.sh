#!/bin/bash
# lpm.overrides application smoke. Without the override, lodash@^4.0.0
# resolves to 4.17.21 (newest in 4.x). With `lpm.overrides.lodash =
# "4.17.20"`, the resolver MUST install 4.17.20.
set -e

if [[ ! -f node_modules/lodash/package.json ]]; then
    echo "missing node_modules/lodash/package.json — install layout broken"
    exit 2
fi

actual=$(node -e "console.log(JSON.parse(require('fs').readFileSync('node_modules/lodash/package.json','utf8')).version)")
if [[ "$actual" != "4.17.20" ]]; then
    echo "lpm.overrides did not apply — expected 4.17.20, got $actual"
    exit 3
fi

# Functional check: pinned 4.17.20 still loads + merge works.
node -e "
const _ = require('lodash');
if (typeof _.merge !== 'function') {
    console.error('lodash export shape unexpected: _.merge missing');
    process.exit(4);
}
const out = _.merge({a: 1}, {b: 2}, {c: {d: 3}});
if (out.a !== 1 || out.b !== 2 || out.c.d !== 3) {
    console.error('lodash merge produced unexpected output:', out);
    process.exit(5);
}
"
