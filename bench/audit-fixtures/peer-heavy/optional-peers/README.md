# optional-peers — peerDependenciesMeta compat fixture

**Tests:** packages with optional peers via
`peerDependenciesMeta.<peer>.optional = true` install and load when
those optional peers are NOT present.

**Real-world example:** react-redux v9 declares `redux` and
`@types/react` as optional via meta. A working install layout must
(a) not fail the install on missing optional peer, (b) not crash
react-redux's module load, and (c) keep all of react-redux's runtime
exports available — Provider, useSelector, useDispatch, etc.

**Risk:** hoisted's conflict-nesting algorithm decides where to place
peers based on the consumer chain. If the algorithm treats optional
peers as required for placement decisions, an unmet optional could
trigger a misplacement that loads a different peer instance (or no
instance at all) for one mode but not the other. The synthetic shape
of optional peers — declared but absent — is exactly the input the
algorithm has to handle distinctly from "unmet required peer."

**Smoke test:**
1. Layout-level: confirm `redux` and `@types/react` are NOT in
   `node_modules/`. If they're auto-installed (because the resolver
   ignored the optional flag), the rest of the test wouldn't actually
   exercise the optional branch — fail fast.
2. Functional: require react-redux and assert six of its named
   exports are functions. The most common failure shape for
   "module's optional peer crashed its load" is one or more named
   exports landing as `undefined` (the body that defined them was
   skipped after a top-level `try { require('redux') } catch`
   exited early).

**Why react-redux specifically:** its peerDependenciesMeta surface is
small (2 optional peers) and the package is tested daily in the
ecosystem with optional peers absent (anyone using react-redux via
@reduxjs/toolkit doesn't necessarily have a separate `redux` install
— RTK ships its own redux). So a passing smoke here mirrors a real,
common usage pattern rather than an exotic edge case.

**Expected today:** both isolated and hoisted should pass. Symmetric
failure means lpm's resolver doesn't honor `meta.optional: true` (file
as adjacent issue, mode-agnostic). Asymmetric failure would be a real
linker-mode bug in optional-peer handling.
