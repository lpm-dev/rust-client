# overrides — `lpm.overrides` application fixture

**Tests:** user-declared `lpm.overrides` (and the legacy
`package.json > overrides`) actually take effect on the default
greedy resolver path.

**Risk:** the followup doc's R1 — pre-fix, both resolver arms parsed
`OverrideSet` from package.json but only the pubgrub arm's
`LpmDependencyProvider::choose_version` (provider.rs:1185-1207)
applied overrides. The default greedy/fused arm accepted
`_overrides` (underscored = unused) and shipped
`applied_overrides: Vec::new()`. Every user-declared override —
version pins, selective downgrades, `package.json > overrides` —
silently dropped on the default path.

The contract is asymmetric in a different sense than the rest of
this audit: pre-R1, both linker modes failed equally because both
ran the same resolver. The signal is **symmetric FAIL**, which the
audit harness catches as "missing 4.17.20 → 4.17.21 in both modes."
The cross-cutting note in the followup doc explicitly calls this
out: symmetric FAILs are still useful when they encode a contract
the user expects to hold.

**Smoke test:**
1. With `dependencies.lodash = "^4.0.0"` and `lpm.overrides.lodash =
   "4.17.20"`, `node_modules/lodash/package.json > version` MUST be
   `4.17.20` — not `4.17.21` (newest in 4.x). A 4.17.21 result is the
   pre-R1 silent-drop signature.
2. Functional check: 4.17.20 still loads, `_.merge` is callable, and
   produces correct nested output. Pins that the override-forced
   pin didn't break the package's runtime API.

**Expected today:** PASS / PASS post-R1. Pre-R1, FAIL / FAIL
(asymmetric only with `LPM_RESOLVER=pubgrub`, which the audit
harness doesn't toggle).

**Why lodash 4.17.20:** dramatic-enough version delta that 4.17.21
(the pre-R1 silent-drop value) is unambiguously distinguishable. Two
adjacent patches (e.g., `2.1.2` vs `2.1.3`) would also work but the
reader has to remember which side is "newest in range" and which is
"override target" — `4.17.20` vs `4.17.21` keeps the override
effect visually obvious. lodash itself is a 67 KB unscoped package
with zero deps, so the install footprint is tiny.
