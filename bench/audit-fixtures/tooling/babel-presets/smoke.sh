#!/bin/bash
# Babel: load the API + transform a tiny snippet using both presets.
set -e
node -e "
const babel = require('@babel/core');
const out = babel.transformSync('const x: number = 1;', {
    presets: ['@babel/preset-env', '@babel/preset-typescript'],
    filename: 'test.ts',
});
if (!out || !out.code) {
    console.error('babel produced no output');
    process.exit(2);
}
if (out.code.includes(': number')) {
    console.error('preset-typescript did not strip type annotation');
    process.exit(3);
}
"
