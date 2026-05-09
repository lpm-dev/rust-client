#!/bin/bash
# Self-reference smoke. Verifies `node_modules/<self_pkg_name>` exists
# as a symlink and that requiring the package by its own name from
# inside its own source resolves correctly to its own files. The
# entrypoint at src/run.js does the actual asserts.
set -e

# 1. Layout sanity — the self-ref symlink should exist regardless of
# linker mode. Both modes wire it through lib.rs Phase 3.5
# `create_self_ref`.
if [[ ! -e node_modules/audit-fixture-self-ref-pkg ]]; then
    echo "missing self-ref symlink: node_modules/audit-fixture-self-ref-pkg"
    exit 2
fi

# 2. Functional check — require self by name + by sub-path.
node src/run.js
