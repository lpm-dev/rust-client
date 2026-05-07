#!/bin/bash
# Real-world dogfood smoke: exercises a representative sampling of the
# 21-direct-dep graph at runtime — load + actually call a function on
# each. The audit harness already require()s every direct dep on its
# own; this smoke goes further and validates that the loaded modules
# actually WORK (some packages can `require` without their native bits
# wired up correctly, then fail on first call).
set -e
node -e "
// Loaders (just require; harness covers this too, but redundancy is cheap)
const lodash = require('lodash');
const dayjs = require('dayjs');
const semver = require('semver');
const { z } = require('zod');
const { v4: uuidv4 } = require('uuid');
const { nanoid } = require('nanoid');
const { Command } = require('commander');
const yaml = require('yaml');
const chalk = require('chalk');
const React = require('react');
const ReactDOMServer = require('react-dom/server');

// Functional checks — actually call something on each.
if (lodash.toUpper('hi') !== 'HI') { console.error('lodash broken'); process.exit(2); }
if (!dayjs().format('YYYY')) { console.error('dayjs broken'); process.exit(3); }
if (!semver.satisfies('1.2.3', '^1.0.0')) { console.error('semver broken'); process.exit(4); }
const schema = z.object({ x: z.number() });
if (!schema.parse({ x: 1 }).x) { console.error('zod broken'); process.exit(5); }
if (typeof uuidv4() !== 'string') { console.error('uuid broken'); process.exit(6); }
if (typeof nanoid() !== 'string') { console.error('nanoid broken'); process.exit(7); }
if (typeof new Command() !== 'object') { console.error('commander broken'); process.exit(8); }
if (yaml.parse('a: 1').a !== 1) { console.error('yaml broken'); process.exit(9); }
// chalk has dual API (default export vs named); check it's callable.
const chalkImpl = chalk.default || chalk;
if (typeof chalkImpl !== 'function' && typeof chalkImpl.bold !== 'function') {
    console.error('chalk broken'); process.exit(10);
}
// React + ReactDOM — instance invariant check (the highest-risk
// hoisting scenario). They must agree on the module instance.
const html = ReactDOMServer.renderToString(React.createElement('div', { id: 'x' }, 'ok'));
if (html !== '<div id=\"x\">ok</div>') { console.error('react-dom mismatch:', html); process.exit(11); }
"
