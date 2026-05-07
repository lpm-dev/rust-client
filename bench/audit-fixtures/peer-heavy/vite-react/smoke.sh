#!/bin/bash
# Vite plugin loads correctly + the bin runs.
set -e
node_modules/.bin/vite --version > /dev/null 2>&1
# Verify the React plugin imports without runtime error.
node -e "
const plugin = require('@vitejs/plugin-react');
const factory = typeof plugin === 'function' ? plugin : plugin.default;
if (typeof factory !== 'function') {
    console.error('plugin export is not callable');
    process.exit(2);
}
const inst = factory();
if (!Array.isArray(inst) && typeof inst !== 'object') {
    console.error('plugin factory returned wrong shape');
    process.exit(3);
}
" 2>&1
