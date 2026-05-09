#!/bin/bash
# Phase 66 R2.2 — eager peer auto-install smoke.
#
# Contract: declaring `react-redux` (which has a required peer on
# `react@^18 || ^19`) without listing react in `dependencies` MUST
# still produce a working node_modules/ tree. The resolver's R2.2
# peer-drain pass synthesizes an ambient root-scoped install for
# react; the linker materializes node_modules/react alongside
# node_modules/react-redux.
#
# Pre-R2.2 signal: node_modules/react missing → require('react-redux')
# fails with "Cannot find module 'react'" because react-redux's
# CJS entrypoint top-level-requires react.
set -e

# Step 1 — react-redux itself materialized (basic install sanity).
if [[ ! -f node_modules/react-redux/package.json ]]; then
    echo "missing node_modules/react-redux/package.json — install layout broken"
    exit 2
fi

# Step 2 — R2.2 contract: react was auto-installed even though it
# wasn't declared in `dependencies`.
if [[ ! -f node_modules/react/package.json ]]; then
    echo "R2.2 auto-install regression: node_modules/react/ missing"
    echo "react-redux declares a required peer on react; the resolver"
    echo "should have synthesized an ambient install."
    exit 3
fi

# Step 3 — version matches the peer constraint. react-redux@9
# declares peer `react@^18.0 || ^19.0`; the auto-install must pick a
# version satisfying that range. We do a coarse "starts with 18 or 19"
# check rather than full semver intersection because:
#   - The exact version drifts as react publishes patches; pinning
#     would force fixture maintenance on every react patch release.
#   - Both 18.x and 19.x are valid post-R2.2 outcomes — the resolver
#     picks the newest in the peer range, which depends on
#     react-redux's currently-published peer constraint.
react_version=$(node -e "console.log(JSON.parse(require('fs').readFileSync('node_modules/react/package.json','utf8')).version)")
case "$react_version" in
    18.*|19.*) ;;
    *)
        echo "auto-installed react@$react_version doesn't match react-redux's peer constraint (^18 || ^19)"
        exit 4
        ;;
esac

# Step 4 — runtime load. Without react in node_modules, this is the
# hard-fail point pre-R2.2: `require('react-redux')` walks up to its
# own CJS entrypoint, which top-level-requires react, which throws
# `Cannot find module 'react'`. Post-R2.2 it loads cleanly.
node -e "
const RR = require('react-redux');
const required = ['Provider', 'useSelector', 'useDispatch', 'useStore', 'connect'];
for (const k of required) {
    if (typeof RR[k] === 'undefined') {
        console.error('react-redux loaded but missing export:', k);
        process.exit(5);
    }
}
"
