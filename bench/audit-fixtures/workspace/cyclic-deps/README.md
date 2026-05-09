# cyclic-deps — workspace-cycle compat fixture

**Tests:** A↔B cyclic require chain across two workspace members under
both linker modes.

**Risk:** Node's CommonJS handles cycles via partial-export semantics —
when module A is mid-load and triggers `require('B')`, B's
`require('A')` returns A's `module.exports` as-of-that-instant
(possibly empty `{}`). The semantic depends on Node's module cache
keying off the *resolved physical path*, which means each linker mode
must produce the same canonical path for `audit-cycle-a` no matter who
requires it. If hoisted's top-level symlink and isolated's wrappers
tree resolve to different physical files for the same logical name,
the cache misses, the module is loaded twice, and the cycle either
deadlocks or yields stale exports.

**Smoke test:** loads both `audit-cycle-a` and `audit-cycle-b` from the
project root, then exercises four functions: each member's direct
export (must match a literal) and each member's cross-call into the
other (must yield the concatenated cycle output). Lazy bodies — the
cross-calls run *after* both modules have finished loading, so a
healthy cycle returns the final exports; a broken cycle returns a
function-from-an-empty-object and crashes with `TypeError:
b.helloFromB is not a function`.

**Why workspace-shaped:** lpm's v1 resolver does not recurse into
workspace member dependencies (same shape as `monorepo-basic`), so
both members are also declared at the root as `workspace:*`. The
cycle is in the runtime require graph, not the resolver graph — which
is exactly what the partial-export semantic exercises.

**Expected today:** both isolated and hoisted should pass. The cycle
is small and synthetic; if either mode fails this, the failure mode
is "wrong physical-path resolution for workspace members," which is a
real linker bug.
