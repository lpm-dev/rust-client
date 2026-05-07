#!/bin/bash
# file: protocol smoke. The local-greeter package is sourced from
# ./local/greeter/ via "file:./local/greeter" in the manifest. After
# install, requiring it must hit the local code (not a registry copy).
set -e
node -e "
const greeter = require('local-greeter');
const got = greeter.hello('audit');
if (got !== 'hello from local-greeter, audit') {
    console.error('local-greeter resolved to wrong code:', got);
    process.exit(2);
}
// External (lodash) must coexist.
const _ = require('lodash');
if (_.toUpper('hi') !== 'HI') {
    console.error('lodash broken under file: source');
    process.exit(3);
}
"
