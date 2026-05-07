#!/bin/bash
# Smoke test for eslint-flat-config fixture.
#
# Runs ESLint against test-file.js with the flat config that imports two
# popular plugins. ESLint exit codes: 0 = no problems, 1 = lint warnings/
# errors found, 2 = config/plugin load failure.
#
# This smoke ASSERTS exit < 2 (loaded config successfully + executed
# against the file). Lint findings (exit 1) are acceptable — we're
# testing config + plugin discovery, not lint correctness.
set +e
node_modules/.bin/eslint --config ./eslint.config.js test-file.js > /tmp/eslint-smoke-$$.log 2>&1
exit_code=$?
set -e

if [[ $exit_code -ge 2 ]]; then
    echo "ESLint failed to load config (exit $exit_code):"
    cat /tmp/eslint-smoke-$$.log
    rm -f /tmp/eslint-smoke-$$.log
    exit 1
fi

rm -f /tmp/eslint-smoke-$$.log
exit 0
