#!/bin/bash
# Cyclic-deps smoke: load both members from the project root and verify
# both directions of the cycle work — direct exports AND lazy
# cross-calls. If hoisted's flat node_modules wires the workspace
# symlinks differently than isolated's wrappers, Node's module cache
# lookup might mismatch the two physical paths and break the cycle's
# partial-export semantics.
set -e

node -e "
const a = require('audit-cycle-a');
const b = require('audit-cycle-b');

if (a.helloFromA() !== 'hello-from-a') {
    console.error('a.helloFromA returned wrong value');
    process.exit(2);
}
if (b.helloFromB() !== 'hello-from-b') {
    console.error('b.helloFromB returned wrong value');
    process.exit(3);
}
if (a.aTouchesB() !== 'hello-from-b/from-a') {
    console.error('a→b cross-call returned wrong value:', a.aTouchesB());
    process.exit(4);
}
if (b.bTouchesA() !== 'hello-from-a/from-b') {
    console.error('b→a cross-call returned wrong value:', b.bTouchesA());
    process.exit(5);
}
"
