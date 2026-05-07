# react-ssr — peer-heavy compat fixture

**Tests:** ReactDOM's React peer-dep invariant under hoisted layout.

**Risk:** ReactDOM declares `react` as a peer. Hoisted-mode layout has one
canonical React copy at top level — fine when both packages resolve to it.
If hoisted ever conflict-nests React under one consumer (e.g. due to a
sibling dep with a different React range), ReactDOM and the user's
`require('react')` would resolve to different module instances. React's
hooks dispatcher is module-scoped global state; cross-instance use crashes
loudly with "Invalid hook call" or silently produces wrong output.

**Smoke test:** `React.createElement` + `ReactDOMServer.renderToString`.
Output is asserted to be the literal string `<div id="audit">hoisted-mode-audit</div>`.
A hoisting-induced instance split fails the assertion (or trips React's
own runtime invariant warnings).

**Why minimal:** two direct deps. We're testing the peer-dep mechanism,
not testing React's API surface. A bigger fixture (Next, Vite-React) is a
later test in the same bucket.

**Expected today:** both isolated and hoisted should pass — fixture-large
already has React + ReactDOM and both modes were correctness-checked in
the bench pre-test (2026-05-07). This fixture confirms the SSR path
specifically, which the bench's `node -e require('react')` smoke didn't
exercise.
