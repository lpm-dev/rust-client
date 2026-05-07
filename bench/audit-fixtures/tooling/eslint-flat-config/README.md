# eslint-flat-config — tooling compat fixture

**Tests:** ESLint 9 plugin discovery and peer-dep resolution under both
linker modes.

**Risk:** ESLint plugins import the host ESLint via a peer-dep relationship.
`@typescript-eslint/eslint-plugin` declares `eslint` as a peer.
`eslint-plugin-react-hooks` does the same. Under hoisted layout, all
plugins + ESLint are at top level — peer resolution is a sibling lookup.
Under isolated layout, plugins live in their wrapper directories and
must walk up to find ESLint.

The flat-config-style import (`import tsPlugin from "@typescript-eslint/eslint-plugin"`)
is more sensitive than legacy plugin discovery (which scans `node_modules`
for `eslint-plugin-*` names). Flat config requires the package to be
explicitly importable from the project root.

**Smoke test:** runs `eslint test-file.js` with the flat config that
imports two plugins. Asserts exit code < 2 (0 = no findings, 1 = lint
findings, both acceptable; 2+ = config/plugin load failure).

**Expected today:** both modes should pass. ESLint flat config has been
shipping for over a year and works under both layouts on npm/yarn/pnpm.
A failure here would indicate either a plugin's package.json is wrong
about its peer, or our hoisting/isolation is misplacing something.
