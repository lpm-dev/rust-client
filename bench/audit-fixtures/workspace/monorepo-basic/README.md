# workspace/monorepo-basic — workspace compat fixture

**Tests:** lpm's workspace handling under both linker modes.

The audit had no workspace coverage before this fixture, despite
workspaces being a first-class lpm feature. Real risk: hoisting +
workspaces interact in ways isolated mode doesn't (workspace member
symlinks vs hoisted package symlinks at the root, internal cross-deps
via `workspace:*`, external deps shared across members).

**Setup:** three-member monorepo:

```
packages/
  utility/     (no deps)
  core/        (workspace:* utility, ^4.17.21 lodash)
  consumer/    (workspace:* core, workspace:* utility, ^4.17.21 lodash)
```

**Smoke test:**
1. Confirm workspace member symlinks exist at `node_modules/<member>/package.json`.
2. Exercise the full chain — `require('audit-consumer').run()` triggers
   `consumer → core → utility` (internal) plus a `lodash.toUpper` call
   (external, must hoist correctly so all three members see the same
   instance).

A failure here would be either:
- Workspace symlinks missing → `lpm install` doesn't materialize the
  members at the project root.
- Internal `require` returns "Cannot find module" → workspace:*
  resolution didn't wire the internal symlinks within each member's
  `node_modules`.
- External `lodash` instance mismatch → hoisting issue specific to the
  workspace layout.
