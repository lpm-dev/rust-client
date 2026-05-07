#!/bin/bash
# esbuild: load + actual transform. Validates platform-specific binary
# was correctly installed, postinstall wiring is intact, and the
# native call works end-to-end.
set -e
node -e "
const esbuild = require('esbuild');
const out = esbuild.transformSync('const x: number = 1', {
    loader: 'ts',
    target: 'es2020',
});
if (!out || !out.code || !out.code.includes('const x = 1')) {
    console.error('esbuild transform produced unexpected output:', out);
    process.exit(2);
}
"
