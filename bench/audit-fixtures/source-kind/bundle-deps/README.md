# bundle-deps — bundleDependencies compat fixture

**Tests:** the `bundleDependencies` field semantic — packages that
vendor their deps inside the published tarball's `node_modules/` dir
must have that subtree preserved through extraction + linking.

**Real-world example:** `npm@11` ships 65 vendored deps. Anyone
installing the npm CLI as a dep depends on this surviving — npm's
own runtime `require()` walks into its bundled subtree to find its
internal helpers.

**Risk:** hoisted layout might overwrite vendored deps if the same
package name appears at top level via another transitive path. More
fundamentally: lpm has no explicit
bundleDependencies handling (verified via `grep bundleDep crates/`),
so we're testing the implicit invariant — the extractor preserves
tarball-internal `node_modules/` as part of the package source, and
the linker doesn't strip or shadow it.

**Smoke test:**
1. Top-level: `node_modules/npm/` and `node_modules/lodash/` are
   both present (npm via direct dep, lodash as unrelated direct dep
   to ensure non-bundled siblings coexist).
2. **Layout survival.** `realpath node_modules/npm` resolves through
   whichever symlink layer the active mode uses; under it, the
   `node_modules/` directory exists and contains at least 30
   subdirectories (npm bundles 65, but the floor leaves room for
   patch-release variation).
3. **Bundled-dep identity.** Eight known-bundled deps from npm@11.14.0's
   list (abbrev, archy, cacache, chalk, ci-info, fastest-levenshtein,
   ini, proc-log) each have a real `package.json` reporting their own
   `name` and a non-empty `version`. Names verified by inspecting the
   actual installed `node_modules/npm/package.json > bundleDependencies`
   array. If hoisting somehow displaced the bundled copies, this
   trips a missing-file failure with a specific name rather than a
   generic "wrong layout."
4. **Sanity:** `node_modules/npm/package.json` reports an 11.x version
   AND lists ≥30 entries in its `bundleDependencies` array — proves
   the package itself extracted correctly and the manifest's
   bundleDependencies metadata round-tripped through lpm's tarball
   handling intact.

**Why npm specifically:** of all real-world packages surveyed, npm is
the only one with active bundleDependencies usage. npm's heavy install
(~30MB) is acceptable for an audit fixture: existing fixtures like
apollo-graphql and nestjs-deep are similar order of magnitude, and
the audit is correctness, not perf.

**Expected today:** both isolated and hoisted should pass. Symmetric
failure means lpm's extractor strips tarball-internal `node_modules/`
(file as adjacent issue — would affect every bundleDependencies user
equally regardless of linker mode). Asymmetric failure is a real
linker-mode bug where one mode shadows the bundled subtree.
