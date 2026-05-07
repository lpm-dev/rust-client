# better-sqlite3 — native compat fixture

**Tests:** node-gyp compile-on-install + runtime native binding load.

Different model than sharp — better-sqlite3 compiles a `.node` binary
locally during postinstall (node-gyp) rather than downloading a
prebuilt. Compilation tooling (`node-gyp`, `python`, system C++
toolchain) must resolve correctly for postinstall to succeed.

**Smoke test:** open `:memory:` DB, run a trivial query, verify
result. Validates the compiled binding loads and runs.
