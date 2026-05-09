# npm-aliases — alias resolution compat fixture

**Tests:** the `npm:<target>@<range>` alias syntax (Phase 40 P2 in
lpm) under both linker modes, with three aliases of the same target +
one alias of a scoped target + an unaliased install of the same
target running side-by-side.

**Risk:** the followup doc's §2c — "hoisted's same-name handling
might confuse the alias-target relationship. Three+ aliases of the
same target stress the wrapper-segment handling." Each alias is its
own dependency identity at the layout level (a unique
`node_modules/<alias>` entry) but resolves to the SAME target tarball
in the content-addressed store. Both modes have to thread that
identity-vs-content distinction:

- **isolated:** four lodash-shaped surfaces means four wrapper
  segments under `.lpm/wrappers/`, each pointing at the same store
  tarball. Bug shape: a wrapper segment that picks the wrong target
  (e.g. tries to install a literally-named `lodash-a` from npm, which
  doesn't exist, and the install fails).
- **hoisted:** four root-level entries in the flat layout, one per
  alias name. Bug shape: same-name collision logic accidentally
  drops one of the alias slots, or hoists the unaliased lodash and
  routes one of the aliases through it (which still works for `lodash-a`
  but breaks if the aliased target ever differs from the unaliased
  install).

**Smoke test:**
1. **Identity check.** For each alias, `node_modules/<alias>/package.json`
   must carry the TARGET's `name` field — e.g. `node_modules/lodash-a/package.json`
   has `"name": "lodash"`. If lpm tried to install a literal package
   named `lodash-a` from npm (which doesn't exist), the install would
   fail before this check runs; if it installed the alias as the alias
   name (skipping the alias resolution), the name field would be
   `"lodash-a"` instead of `"lodash"`.
2. **Functional check.** `require('<alias>')` returns lodash's runtime
   surface — `toArray()` works and produces the expected output.
3. **Side-by-side check.** All four lodash-shaped entries
   (lodash + lodash-a/b/c) coexist; require()-ing each from the same
   process resolves cleanly.
4. **Reference-equal note (informational).** Aliases of the same
   target SHOULD share the underlying file via lpm's content-
   addressable store, so `lodash.toArray === lodash-a.toArray`.
   Non-equality is a duplicate-extraction inefficiency, not a
   correctness bug, so the smoke logs but does not fail.
5. **Scoped-target alias.** `code-frame-alias: npm:@babel/code-frame@^7`
   covers the LAST-`@`-split convention in the alias parser
   ([`specifier.rs:208-220`](../../../crates/lpm-resolver/src/specifier.rs#L208-L220)).
   The target is a runtime-loadable scoped package (small, dep-free
   in the relevant releases) so the smoke can exercise `require()`
   on the alias rather than just filesystem-checking the dir.

**Expected today:** both isolated and hoisted should pass. Symmetric
failure means lpm's alias parser or installer has a bug independent
of linker mode (file as adjacent issue). Asymmetric failure is a
linker-mode bug in alias placement.
