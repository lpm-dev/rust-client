#!/bin/bash
# Rollup: bin resolves + plugins instantiate.
set -e
node_modules/.bin/rollup --version > /dev/null 2>&1
node -e "
const nodeResolve = require('@rollup/plugin-node-resolve');
const commonjs = require('@rollup/plugin-commonjs');
const nrf = nodeResolve.nodeResolve || nodeResolve.default || nodeResolve;
const cjf = commonjs.default || commonjs;
const p1 = nrf();
const p2 = cjf();
if (!p1 || !p1.name) { console.error('node-resolve plugin malformed'); process.exit(2); }
if (!p2 || !p2.name) { console.error('commonjs plugin malformed'); process.exit(3); }
"
