# nextjs-minimal — peer-heavy compat fixture

**Tests:** Next.js full ecosystem (React + plugin chains + ESLint config).

Next's dependency tree is the deepest peer-dep chain in mainstream JS.
Many transitive plugins assume specific phantom-dep access patterns
(picking up Next's bundled modules). If hoisted layout dedupes too
aggressively or nests something the wrong direction, Next's runtime
init or eslint-config-next's plugin chain fails.

**Smoke test:** `next --version` + `require('eslint-config-next')` —
both touch the high-risk surfaces without launching a build.
