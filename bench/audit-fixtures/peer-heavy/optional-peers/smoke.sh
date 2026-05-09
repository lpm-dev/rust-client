#!/bin/bash
# optional-peers smoke. Verifies react-redux loads cleanly with two
# of its peers (`redux`, `@types/react`) absent — both flagged in
# `peerDependenciesMeta` as optional. Exercises the canonical
# react-redux export surface so a partial-load failure (e.g. an
# inline `require('redux')` at module top) trips on a real export
# being undefined rather than just on the import line.
set -e

# Confirm optional peers are NOT in node_modules. If lpm "helpfully"
# installed them, the test wouldn't actually exercise the optional
# branch.
for absent in redux @types/react; do
    if [[ -e "node_modules/$absent" ]]; then
        echo "expected optional peer $absent to be ABSENT, but it was installed"
        exit 2
    fi
done

# Confirm react-redux loaded its full named-export surface even
# without redux installed. Optional-peer loading bugs typically
# present as a missing export (the offending top-level require()
# tripped a try/catch and the module exited early).
node -e "
const RR = require('react-redux');
const required = ['Provider', 'useSelector', 'useDispatch', 'useStore', 'connect', 'createSelectorHook'];
for (const k of required) {
    if (typeof RR[k] === 'undefined') {
        console.error('react-redux missing export:', k);
        process.exit(3);
    }
}
"
