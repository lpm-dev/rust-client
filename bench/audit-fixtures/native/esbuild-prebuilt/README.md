# esbuild-prebuilt — native compat fixture (always-runnable)

**Tests:** optional+platform-specific dep + postinstall script + native
binary load + actual native call.

esbuild is the canonical case of a JS package that ships per-platform
native binaries via `optionalDependencies` (`@esbuild/darwin-arm64`,
`@esbuild/linux-x64`, `@esbuild/win32-x64`, etc.). The platform-matching
subpackage is automatically installed; the others are optional and
skipped. esbuild's main package's postinstall verifies the right
binary is reachable and exits cleanly.

**Why this is the always-runnable native fixture:** unlike sharp
(which downloads libvips at postinstall — relies on network + file
permissions in `~/.npm`) and better-sqlite3 (compile-on-install via
node-gyp — relies on Python + C++ toolchain on the host), esbuild
needs nothing beyond a working Node + npm. The platform-specific
binary is just a regular npm package install.

**Smoke test:** `esbuild.transformSync` on a TypeScript snippet. Exits
0 on the expected JS output; non-zero on any failure (binary not
found, transform error, wrong output).

**Comparison to other native fixtures:**
- `sharp-image` — exercises the prebuild-install flow + postinstall
  binary download + native binding load.
- `better-sqlite3` — env-conditional (needs node-gyp); exercises
  compile-on-install. Skipped automatically when node-gyp is missing.
- `esbuild-prebuilt` (this fixture) — pure-JS install path with
  optional+platform-specific deps. Always runnable.
