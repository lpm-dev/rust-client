# patches — lpm patch system compat fixture

**Tests:** `lpm.patchedDependencies` (Phase 32 P6) under both linker
modes. The contract: when `package.json > lpm.patchedDependencies`
declares a patch, the install pipeline applies it to every physical
destination of the target package and the patched bytes survive
through to runtime require.

**Risk:** the followup doc's §2f — "hoisted's materialized-package
list is computed differently than isolated's; patches that worked in
isolated might not find their target in hoisted's flat layout." The
[`apply_patches_for_install` function in `install.rs`](../../../crates/lpm-cli/src/commands/install.rs#L1022)
filters `link_result.materialized` to find each location of the
target package. The linker reports every shape (isolated wrapper,
hoisted root, hoisted-nested fallback at `<project>/.lpm/hoisted/nested/`),
so `apply_patches_for_install` should be mode-agnostic — but the
audit verifies that empirically.

**Patch contents:** `patches/ms@2.1.3.patch` is a unified diff that
appends a sentinel function (`lpmPatchProof`) to ms@2.1.3's
`index.js`. The function returns a literal string
(`patched-by-lpm-fixture-2f`) so the smoke can assert on a
known-bytes signature rather than guessing whether some upstream-ms
behavior changed.

**`originalIntegrity`:** `sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==`
— this is ms@2.1.3's published tarball SRI. patch_engine's
`verify_original_integrity` reads it from the store's `.integrity`
file and refuses to apply if it differs (drift detection).

**Smoke test:**
1. Layout-level: `node_modules/ms/package.json` exists; the patch
   file `patches/ms@2.1.3.patch` is present in the work dir.
2. Functional: `require('ms').lpmPatchProof()` returns the literal
   sentinel string. A patch that didn't apply at all → the function
   doesn't exist → fail with "patch not applied" + a diagnostic
   listing of ms's exports. A partial-application bug where the
   patch landed somewhere but not the loaded copy → wrong sentinel
   value, distinct exit code.

**Adjacent issue (current state, 2026-05-08):** lpm's
`patch_engine::apply_patch` reads the original baseline from
`PackageStore::package_dir(name, version)` which is hardcoded to the
v1 layout (`~/.lpm/store/v1/<key>/`). With v2 store now active by
default on main, the patch baseline lookup fails because v2 stores
content at `~/.lpm/store/v2/links/<graph-key>/node_modules/<name>/`
instead. Both modes will FAIL symmetric until lpm's patch system is
updated to v2. The fixture is written ready-state — once the gap is
fixed it validates without modification.

**Expected today:** symmetric FAIL (mode-agnostic patch+v2 gap).
Asymmetric FAIL would be a hoisting-specific patch-targeting bug —
file as a real linker-mode regression.
