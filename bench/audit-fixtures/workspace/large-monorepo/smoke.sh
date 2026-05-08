#!/bin/bash
# Large-monorepo smoke. Verify (1) every workspace member symlink
# exists at root level, (2) the full transitive chain from m10 reaches
# every leaf via cross-member requires, (3) externals (lodash, chalk)
# resolve from a deep workspace member via Node walk-up to the root
# hoist.
set -e

# 1. All 10 member symlinks present at the root.
for n in m01 m02 m03 m04 m05 m06 m07 m08 m09 m10; do
    if [[ ! -e "node_modules/audit-large-$n/package.json" ]]; then
        echo "missing root-level workspace symlink: node_modules/audit-large-$n"
        exit 2
    fi
done

# 2. Transitive chain via the top of the DAG. m10's info().chain
# pushes itself first, then ...m09.chain, then ...m03.chain. Because
# nodes appear multiple times in the DAG (e.g. m05 is visited via m09
# AND via m03), we don't assert the exact ordering — only that every
# leaf shows up at least once and the chain length matches the
# expected count of visits in this DAG.
node -e "
const m10 = require('audit-large-m10');
const chain = m10.info().chain;

// DAG visit counts via depth-first traversal of m10's chain:
//   m10 → m09 + m03
//   m09 → m08 + m06
//   m08 → m07 + m05
//   m07 → m01 + m04
//   m05 → m03 + m04
//   m03 → m01 + m02
//   m06 → m02 + m05
// Visit counts (inlined; do NOT recompute via an alternate algo —
// the audit's value is asserting the layout produces the exact same
// observed graph in both modes): m01:4, m02:4, m03:3, m04:3, m05:2,
// m06:1, m07:1, m08:1, m09:1, m10:1. Total: 21.
if (chain.length !== 21) {
    console.error('expected chain length 21, got', chain.length, chain);
    process.exit(3);
}
const expectedCounts = { m01:4, m02:4, m03:3, m04:3, m05:2, m06:1, m07:1, m08:1, m09:1, m10:1 };
for (const [name, count] of Object.entries(expectedCounts)) {
    const got = chain.filter(x => x === name).length;
    if (got !== count) {
        console.error('member', name, 'visited', got, 'times, expected', count);
        process.exit(4);
    }
}
"

# 3. Externals from a deep member. Run from packages/m08 — its require
# walks up packages/m08/node_modules → packages/node_modules → root
# node_modules. lodash + chalk should resolve at the root hoist.
(cd packages/m08 && node -e "
const _ = require('lodash');
const chalk = require('chalk');
if (typeof _.toArray !== 'function') {
    console.error('lodash did not load from deep member');
    process.exit(5);
}
if (typeof chalk.red !== 'function') {
    console.error('chalk did not load from deep member');
    process.exit(6);
}
")
