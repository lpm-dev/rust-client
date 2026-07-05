# large-monorepo — workspace scale fixture

**Tests:** workspace correctness at 10 members (3.3× `monorepo-basic`)
with a multi-level internal cross-dep DAG, plus shared externals.

**Risk model:** O(N²) hoisting decisions might surface at scale, and
large workspace symlink counts might trip path-walk limits.
`monorepo-basic` covers the 3-member happy path; this fixture is the
same shape but pushed to where mode-specific asymmetric behavior is more
likely to materialize (more wrappers under isolated, more top-level
entries under hoisted, denser symlink graph either way). Externals
(lodash, chalk) sit at the root and must resolve from inside a deep
workspace member via Node's walk-up, which exercises the layout's ability
to keep externals reachable from workspace consumers under both linker
modes simultaneously with the internal DAG.

**DAG shape:**

```
m10 ─┬─ m09 ─┬─ m08 ─┬─ m07 ─┬─ m01
     │      │       │      └─ m04
     │      │       └─ m05 ─┬─ m03 ─┬─ m01
     │      │              └─ m04   └─ m02
     │      └─ m06 ─┬─ m02
     │             └─ m05 (revisit)
     └─ m03 (revisit)

leaves: m01, m02, m04
```

Per-member visit counts via DFS of m10's chain: m01:4, m02:4, m03:3,
m04:3, m05:2, m06:1, m07:1, m08:1, m09:1, m10:1 — total 21. The smoke
pins both the exact total length AND the per-member visit counts so a
bug that produces a slightly different observed graph (e.g. a duplicate
package surface, a missing cross-symlink dropping a member from one
path) trips a specific assertion rather than a generic "wrong output".

**Smoke test:**
1. Layout-level: all 10 `node_modules/audit-large-mNN/package.json`
   files exist (root-level workspace symlinks present).
2. Functional: `m10.info().chain` matches expected length 18 AND
   per-member visit counts. Asserting both length and per-member
   counts means a bug that adds an extra visit (e.g. m04 appears 4×
   instead of 3×) fails distinctly from a bug that drops a visit.
3. Externals from depth: `packages/m08/` requires lodash + chalk;
   verifies Node's walk-up reaches the root hoist from a workspace
   member.

**Why m08 specifically for externals:** m08 is two levels deep from
m10 and pulls in two distinct sub-trees. Any external-resolution bug
that's specific to deep workspace members (rather than top-level
workspace members) trips here without needing a third nesting level.

**Expected today:** both isolated and hoisted should pass. An
asymmetric failure here is a real linker scaling regression. A
symmetric failure (e.g. m08 can't find lodash) is a workspace-resolver
adjacent issue and gets filed separately.
