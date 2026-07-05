# postinstall-introspects-layout — postinstall walker compat fixture

**Tests:** packages whose postinstall walks `node_modules/` looking
for siblings (e.g., `@grpc/grpc-js`, react-native native-binding
loaders) under both linker modes.

**Risk:** hoisted's flat layout means the walker finds different siblings
than under isolated. A real postinstall script runs from inside its own
package dir; `process.cwd()` is the package's resolved real path, and `..`
is whichever node_modules parent the linker planted (top-level
`node_modules/` under hoisted, or a wrappers tree segment under isolated).
The walker observes different *counts* of siblings between modes, but the
runtime contract — each declared sibling reachable via `require()` — must
hold the same.

**Why simulate, not run the postinstall:** the audit runs with
`script-policy=deny` (the default), which blocks every package's
postinstall. The husky and prisma-codegen fixtures use the same
shape: have smoke.sh run the equivalent script manually. The
introspection logic is what matters, not the launch site.

**Smoke test (`introspect.js`)** covers two walker patterns:

**Walker A — from project root (`INIT_CWD`-style).** Most common
shape; what `npm ls`-equivalents and consumer-targeted postinstalls
do.
1. `fs.readdirSync('node_modules')` shows all three direct deps
   (`chalk`, `lodash`, `ms`).
2. Each direct dep has a real package.json with the expected
   `name` field (catches a layout where lpm planted the wrong
   symlink target).

**Walker B — from inside the package's resolved cwd.** The shape a
real postinstall script gets when it runs (lifecycle scripts run
with `cwd = the package's installed dir`).
3. Sibling-list sanity: `fs.readdirSync(path.dirname(chalkReal))`
   contains chalk itself.
4. Functional cross-resolution: spawn a child `node -e "require('<dep>')"`
   with `cwd = chalkReal`. **chalk's *declared* deps** (`ansi-styles`,
   `supports-color`) must resolve from chalk's own cwd. This is the
   contract real walkers depend on — under hoisted, Node walks up
   to root node_modules; under isolated, Node walks up to the
   wrappers segment containing chalk's deps. Both must produce a
   loaded module.
5. Same exercise for `lodash` (a zero-transitive-dep leaf): its
   sibling-list must contain itself. Catches a layout that
   over-trims a leaf's neighborhood.

**What we deliberately do NOT test:** a package requiring an arbitrary
sibling that isn't its declared dep, or a package requiring its own
*transitive* deps from its own cwd. Both are non-contracts in
content-addressed storage models (lpm v2, pnpm, yarn berry pnp) —
each package's resolved location only exposes its *own declared
deps* via Node's walk-up, and asserting otherwise would fail on every
content-addressed package manager.

**Why these three deps specifically:** chalk has transitive deps
(color-convert, supports-color) that surface as wrappers segments
under isolated and as top-level entries under hoisted — its
introspection point sees a different "shape" per mode. lodash and ms
have zero transitive deps; their introspection points are tighter,
covering the leaf-package case. The mix gives one parent and two
leaves to exercise both shapes in the same fixture.

**Expected today:** both isolated and hoisted should pass. Asymmetric
failure means a real linker-mode bug in how postinstall walkers
resolve siblings. Symmetric failure on the require()-resolution
checks means lpm's wrappers tree is too narrow under isolated, or
hoisted's hoisting decisions dropped a sibling — file as adjacent.
