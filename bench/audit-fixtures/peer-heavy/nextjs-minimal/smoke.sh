#!/bin/bash
# Smoke: Next CLI resolves + React loads through Next's bundled paths.
set -e
node_modules/.bin/next --version > /dev/null 2>&1
# Confirm Next + React can be required side-by-side at runtime without
# multi-instance React errors (the highest-risk hoisting failure mode
# for Next's deep peer-dep chain).
node -e "
const next = require('next');
const React = require('react');
const ReactDOM = require('react-dom');
if (typeof next !== 'function') { console.error('next did not export a callable'); process.exit(2); }
if (!React.version) { console.error('React did not load'); process.exit(3); }
if (!ReactDOM.version) { console.error('ReactDOM did not load'); process.exit(4); }
"
