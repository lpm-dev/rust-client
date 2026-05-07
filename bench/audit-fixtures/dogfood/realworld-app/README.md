# dogfood/realworld-app — large-graph compat fixture

**Tests:** correctness on a realistic real-world Node.js dep graph
(~21 direct deps → ~266 transitive packages — the same shape as
`bench/fixture-large` which the perf benchmarks use).

**Why this duplicates fixture-large's package.json deliberately:** the
bench harness times this graph but doesn't validate correctness.
Mirroring the same graph here means any correctness regression that
slips through the bench is caught by the audit.

**Smoke test:** for each common dep, load it AND call a representative
function. Some packages can be `require()`d without their internal
state wired correctly (especially native bindings or peer-dep-coupled
modules); the functional check catches that.

The hoisting risk this fixture surfaces: 21 direct deps + ~245
transitives is enough for at least a handful of version conflicts to
show up. The eslint-flat-config bug we caught (brace-expansion v1 vs
v5 nested under the wrong consumer) was found in this same graph
shape — at the time it surfaced via a separate ESLint-focused
fixture, but a real-world graph this size catches the symptom directly.

If hoisted ever drifts back into a misplacement bug, this fixture's
React+ReactDOM instance-invariant check is a strong canary.
