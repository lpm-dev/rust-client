#!/bin/bash
# Smoke test for react-ssr fixture. Runs renderToString through ReactDOM
# and verifies the output is the expected HTML string. Fails if React and
# ReactDOM resolve to different module instances (the dispatcher invariant
# trips with a clear error in dev mode).
set -e

OUTPUT=$(node -e "
const React = require('react');
const ReactDOMServer = require('react-dom/server');
const el = React.createElement('div', { id: 'audit' }, 'hoisted-mode-audit');
const html = ReactDOMServer.renderToString(el);
if (html !== '<div id=\"audit\">hoisted-mode-audit</div>') {
    console.error('UNEXPECTED OUTPUT:', html);
    process.exit(2);
}
console.log('OK');
")

if [[ "$OUTPUT" != "OK" ]]; then
    echo "smoke output: $OUTPUT"
    exit 1
fi
exit 0
