# self-referential — self-ref symlink compat fixture

**Tests:** lpm-linker's self-reference symlink
(`node_modules/<self_pkg_name>` → project root) under both linker
modes. A package can `require('itself')` and `require('itself/sub/path')`
from its own source — npm/Node both support this and apps lean on it
for cleaner internal imports than `'../../../lib/util'` chains.

**Risk:** hoisted creates `node_modules/<self_name>/` as a symlink to
the project root; if hoisting puts a different package at the same name
slot first, self-ref is lost. This fixture uses a synthetic project name
(`audit-fixture-self-ref-pkg`) that no published dep can collide with,
so the test exercises the *positive* path: with at least one external
sibling (lodash) hoisted next to the self-ref slot, the symlink survives
and resolution still walks through it from a project sub-directory.

**Smoke test:**
1. Layout-level: `node_modules/audit-fixture-self-ref-pkg` exists
   (file or symlink). Failing this means the linker silently dropped
   the self-ref step.
2. Functional: `src/run.js` does `require('audit-fixture-self-ref-pkg')`
   *and* `require('audit-fixture-self-ref-pkg/lib/util')`. Each round
   trips through the symlink and back into a real file inside the
   project, asserting concrete return values for the root entry's
   greeting + function and the sub-path util's exports. A subtle bug
   where the symlink points somewhere wrong (e.g., the wrappers tree
   instead of project root) shows up here as a `MODULE_NOT_FOUND` for
   `lib/util` even though the top-level require would still succeed.

**Why a sub-path require is load-bearing:** `require('self')` could
satisfy via Node's native self-reference (when `exports` is set in
package.json) without going through any symlink. This fixture has no
`exports` field — both requires MUST traverse the symlink. The
sub-path form (`'self/lib/util'`) is the one Node's
exports-self-reference doesn't cover, so it specifically exercises
lpm's symlink wiring.

**Expected today:** both isolated and hoisted should pass. lpm's
self-ref logic is shared between modes (lib.rs `link_packages` calls
`create_self_ref` regardless of layout strategy), so an asymmetric
failure here is a real linker-mode bug.
