# nextjs-minimal — peer-heavy compat fixture

**Tests:** Next.js + React peer-dep chain under both linker modes.

Next's dependency tree is the deepest peer-dep chain in mainstream JS.
The risk we're testing: Next imports React internally, the user
imports React directly — both must resolve to the same instance, or
React's hooks dispatcher (module-scoped global state) misbehaves at
runtime.

**Smoke test:** `next --version` (CLI bin resolves) +
`require('next')` + `require('react')` + `require('react-dom')`
side-by-side. Confirms the peer chain is consistent.

**Why no eslint-config-next:** the original fixture pulled
`eslint-config-next` for plugin-chain coverage, but it depends on
`@rushstack/eslint-patch` which doesn't support ESLint 9
(`Failed to patch ESLint because the calling module was not
recognized.`). That's a fixture-ecosystem incompatibility with the
ESLint version, not an lpm bug — both linker modes failed identically
on the original fixture (2026-05-07 audit). Plugin-chain coverage is
already provided by `tooling/eslint-flat-config`, which uses ESLint 9
directly.
