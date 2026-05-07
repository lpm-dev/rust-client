#!/bin/bash
# Smoke: Next CLI resolves + ESLint config loads.
set -e
node_modules/.bin/next --version > /dev/null 2>&1
# eslint-config-next is loaded via require — fails on phantom-dep collapse.
node -e "
const cfg = require('eslint-config-next');
if (!cfg) { console.error('config did not export'); process.exit(2); }
"
