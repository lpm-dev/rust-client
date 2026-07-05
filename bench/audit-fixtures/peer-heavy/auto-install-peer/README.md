# auto-install-peer — eager peer fixture

**Tests:** the resolver's peer-drain pass auto-installs a
required peer that was absent from the project's `dependencies`.

**Risk:** before eager peer installation, the greedy/fused resolver
collected peer declarations only for the post-resolve `check_unmet_peers`
warning pass. A user installing `react-redux` without manually adding
`react` to `dependencies` got:

1. The install completed silently (peer-warnings are not errors).
2. `node_modules/react/` was missing.
3. The first `require('react-redux')` at runtime threw `Cannot find
   module 'react'` — react-redux's CJS entrypoint top-level-requires
   react.

That's the package-manager-as-paperwork failure mode the user explicitly
chose to design out. Eager peer installation makes peers a first-class input
to the resolver: any required peer not satisfied by the resolved tree triggers
a root-scoped ambient install through the same dispatcher machinery as regular
deps. The package author's peer declaration becomes a real install obligation,
not just documentation.

**Smoke contract:**

1. `node_modules/react-redux/package.json` exists (install sanity).
2. `node_modules/react/package.json` exists — the ambient install
   landed react despite the project's `dependencies` listing only
   `react-redux`.
3. The auto-installed react version satisfies react-redux's peer
   range (`^18 || ^19`). The smoke does a coarse "starts with 18
   or 19" check rather than a full semver intersection because both
   majors are currently valid eager-install outcomes — react-redux's
   published peer range determines the upper bound, and pinning
   here would force fixture maintenance on every patch.
4. `require('react-redux')` returns a module with the canonical
   public API (`Provider`, `useSelector`, etc.). This is the runtime
   shape the user actually consumes; loading is the load-bearing
   assertion that the auto-install integrated with the linker
   correctly.

**Architectural note:** eager peer installation deliberately routes the
ambient install through `parent = 0` (root-scope) rather than as a child edge
of the consumer (react-redux). The consumer's
`ResolvedPackage.peers` field still records the relationship, but
its `dependencies` field stays unchanged. This separation is
load-bearing for the v2 store's graph-key derivation
(`install.rs:4620-4686`) — peer pinning is folded into the v2 link-
entry key so two projects with the same dep tree but different peer
ranges produce distinct `links/<key>/` entries. Smuggling peers
into `consumer.children` would silently break that isolation.

**Expected outcomes:**

- **Current behavior:** PASS / PASS in both linker modes.
- **Without eager peer installation:** FAIL / FAIL — react-redux loads abort
  on the missing react require. Symmetric failure because the
  resolver bug was upstream of the linker; both modes inherited the
  empty react slot.

**Why react-redux:** it has a single, well-defined required peer
(react), no other "auto-install candidate" peers, and a hard
top-level require chain that turns a missing peer into a
deterministic load failure. The optional-peers fixture (sibling
directory) tests the inverse: that
`peerDependenciesMeta.optional = true` peers are NOT auto-installed
even under the eager default.

**Why not pin a specific react version:** the auto-install picks
"newest in the peer range," which is a moving target as react
publishes patches. Pinning would either force manual fixture
updates per release or lie about the contract (the contract is
"some version satisfying the peer," not "this exact version").
