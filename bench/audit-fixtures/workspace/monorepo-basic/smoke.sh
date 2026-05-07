#!/bin/bash
# Workspace smoke: verify cross-member resolution from each consumer.
# Each member must be able to require its declared workspace deps;
# external deps (lodash) must resolve consistently across members.
# Validates lpm's workspace semantics under both linker modes.
set -e

# 1. Verify root has workspace member symlinks (they're declared as
# workspace:* in the root, so they should exist at root-level).
for member in audit-utility audit-core audit-consumer; do
    if [[ ! -e "node_modules/$member/package.json" ]]; then
        echo "missing root-level workspace symlink: node_modules/$member"
        exit 2
    fi
done

# 2. Verify each member can resolve its own internal + external deps
# from its OWN node_modules (where lpm/npm/yarn place per-member deps).
(cd packages/consumer && node -e "
const consumer = require('audit-consumer');
const result = consumer.run();
if (result.direct !== 'hello, consumer') {
    console.error('utility direct call returned wrong value:', JSON.stringify(result));
    process.exit(3);
}
if (result.throughCore !== 'HELLO, WORLD') {
    console.error('core+utility+lodash chain returned wrong value:', JSON.stringify(result));
    process.exit(4);
}
")
