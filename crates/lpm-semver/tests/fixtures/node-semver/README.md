# node-semver fixture corpus

These JSON fixtures are derived from npm's `node-semver` test corpus:

- Source repository: <https://github.com/npm/node-semver>
- Source commit: `8640bd68f1653e504b53e9be4030eccdfe4c307a`
- Source files:
  - `test/fixtures/range-include.js`
  - `test/fixtures/range-exclude.js`
  - `test/fixtures/comparisons.js`

Regenerate with:

```bash
node crates/lpm-semver/scripts/vendor-node-semver-fixtures.mjs
```

The generated `skipped` arrays preserve upstream cases that require
node-semver options LPM does not expose, such as `loose` and
`includePrerelease`, plus npm's empty-range wildcard behavior. The Rust tests
execute every generated `cases` row.
