# rollup-plugins — tooling compat fixture

**Tests:** Rollup plugin loading under both layouts.

Rollup plugins are typically loaded as user-imported modules; the
plugin's own deps must be resolvable from where the plugin sits. With
hoisted layout, plugin deps may be hoisted to top level; isolated
gives each plugin its own wrapper.

**Smoke test:** `rollup --version` + instantiating both plugins via
`require()`. Confirms the plugin packages load AND their constructor
factories return the expected `{ name, ... }` plugin shape.
