# babel-presets — tooling compat fixture

**Tests:** Babel preset resolution under both layouts.

Babel resolves preset names by walking `node_modules`. Hoisted layout
should expose all preset packages at top level; isolated puts them
behind wrappers. A real transformation (TypeScript → JavaScript) is
the smoke test — a successful transform proves the preset chain loaded.
