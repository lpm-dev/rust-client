# Deferred surfaces

Capabilities that LPM advertises a stance on (typically by emitting a
"not supported yet" / "isn't supported yet" / "doesn't extend to
globals yet" message) but doesn't actually implement. Each entry names
the user-facing surface, the source-of-truth string the user sees, the
intended behavior we'll grow into, and the workaround today.

This is engineering tracking. Doc pages must NEVER reference phase
numbers; this file uses concrete capability names instead. Keep it
updated whenever a new "not supported yet" string lands, and prune
entries the moment they're implemented.

---

## `lpm patch` — range-selector keys

**Surface:** `lpm patch react@^18.0.0` / `react@4.x` / `lodash@latest`
**Status:** Rejected at parse time. Only exact-version pins like
`react@18.0.0` are accepted.
**Source string:** [`patch_engine.rs::is_range_version`](crates/lpm-cli/src/patch_engine.rs)
emits "Range selectors are not supported yet."
**Why deferred:** Range patches need a per-store-entry application
strategy (which versions match? all of them? newest only?) that we
haven't designed yet.
**Workaround:** Pin to an exact version. If multiple versions in the
tree need the same patch, list each one separately.

## `lpm patch` — file renames

**Surface:** patch chunks that rename a file (e.g., `lib/foo.js` →
`lib/foo.cjs`) inside a generated diff.
**Status:** Rejected at `lpm patch-commit` time.
**Source string:** [`patch_engine.rs:521`](crates/lpm-cli/src/patch_engine.rs)
emits "patch chunk renames X → Y; renames are not supported yet."
**Why deferred:** Renames need integrity binding to BOTH the
old-content store entry and the new-content store entry, plus a
re-application strategy that survives store re-extraction. Modify-
only patches are integrity-bound to one entry, which is much
simpler.
**Workaround:** Edit the file in place; don't rename.

## Sandbox enforcement on Windows

**Surface:** `lpm install` / `lpm rebuild` lifecycle scripts under
`script-policy = "triage"` or `"allow"` on Windows.
**Status:** No filesystem containment. The platform has no LPM
sandbox backend.
**Source string:** [`lpm-sandbox::unsupported_remediation`](crates/lpm-sandbox/src/lib.rs)
returns "sandbox enforcement isn't supported on Windows yet."
**Why deferred:** Need a Windows backend (likely AppContainer or Job
Object). macOS uses Seatbelt and Linux uses Landlock; Windows is the
gap.
**Workaround:** Re-run with `--unsafe-full-env --no-sandbox` to
execute scripts without containment, or set `script-policy = "deny"`
to block them entirely.

## Global-scope cooldown overrides

**Surface:** `lpm install -g <pkg> --min-release-age=<DUR>` /
`--allow-new`.
**Status:** Both flags are rejected when combined with `-g`. The
24-hour default cooldown still fires via the
`package.json > lpm > minimumReleaseAge` /
`~/.lpm/config.toml > minimum-release-age-secs` chain.
**Source string:** [`main.rs::validate_global_install_project_scoped_flags`](crates/lpm-cli/src/main.rs)
emits "`--min-release-age` is not supported on `lpm install -g` yet
— global-scope cooldown overrides aren't wired up." and
"`--allow-new` is not supported on `lpm install -g` yet —
global-scope cooldown bypass isn't wired up."
**Why deferred:** The `-g` install path doesn't have a global-scope
slot for per-invocation cooldown policy overrides or bypasses.
**Workaround:** Drop either flag and rely on the chain default.

## Global-scope provenance-drift overrides

**Surface:** `lpm install -g <pkg> --ignore-provenance-drift <pkg>` /
`--ignore-provenance-drift-all`.
**Status:** Rejected when combined with `-g`.
**Source string:** [`main.rs::validate_global_install_project_scoped_flags`](crates/lpm-cli/src/main.rs)
emits "`--ignore-provenance-drift` ... not supported on `lpm install
-g` yet — the global trust store doesn't accept per-package drift
overrides."
**Why deferred:** The global trust store schema has no slot for
per-package drift exceptions.
**Workaround:** Drop the flag for global installs.

## Global-scope script policy + sandbox parity

**Surface:** `lpm install -g <pkg>` running lifecycle scripts under
the tiered triage gate or filesystem sandbox.
**Status:** Globals use a separate trust store at
`~/.lpm/global/trusted-dependencies.json`; the triage gate and
sandbox containment don't extend to that path yet.
**Source string:** [`doctor.rs::scope_boundary_note_if_globals_present`](crates/lpm-cli/src/commands/doctor.rs)
emits "project installs only — global installs use a separate trust
store ... The tiered gate and sandbox containment don't extend to
globals yet."
**Why deferred:** Global-scope triage needs the trust-store schema
extended to carry per-package script-policy state, and the install
pipeline rewired to call into the gate from the global path.
**Workaround:** Use `lpm install` (project scope) when triage /
sandbox containment matters.

## LLM triage layer (Layer 4)

**Surface:** `lpm install --policy=triage` / `--triage` /
`script-policy = "triage"`.
**Status:** Three of the four triage layers ship today (allowlist
greens, blocklist reds, manual-review ambers). The fourth — LLM-
based per-package triage — isn't built yet.
**Source string:** [`main.rs:366`](crates/lpm-cli/src/main.rs)
clap doc on `--policy=triage`: "The LLM triage layer is not
available yet."
**Why deferred:** Needs a vetted prompt pipeline + cost guardrails

- per-package determinism story. None of those are designed.
  **Workaround:** Triage works without the LLM layer — ambers and
  reds simply route to manual review via `lpm approve-scripts`.

## mTLS client certs / per-origin TLS via `.npmrc`

**Surface:** global `.npmrc` keys `certfile` / `keyfile`, plus
per-origin `//host/:cafile=` / `:certfile=` / `:keyfile=`.
**Status:** Global `cafile=` / `ca=` are already wired and do feed
the HTTP client's extra root store. The deferred pieces are mTLS
client certs and per-origin TLS overrides: they parse, warn, and the
request falls back to the process-wide TLS config.
**Source string:** [`npmrc.rs`](crates/lpm-registry/src/npmrc.rs)
emits "per-origin '`certfile`' is not supported yet ..." and "`certfile`
(mTLS client cert) is not supported yet."
**Why deferred:** Per-origin TLS contexts need a routed reqwest
client builder; today reqwest is constructed once at process start.
mTLS client certs need PKCS#12 / PEM loading + key-passphrase prompt
support.
**Workaround:** Use global `cafile=` / `ca=` when you only need extra
root CAs. For mTLS or host-specific TLS, configure it at the system /
network proxy level, or use a registry that doesn't require client
certs.

## Workspace deploy: local-package injection

**Surface:** `lpm deploy --filter <member>` for a workspace whose
internal members aren't published to a registry.
**Status:** `workspace:*` deps in the deploy output must already be
published. The deploy resolver has no path for inlining local-only
copies.
**Source string:** [`workspaces.mdx:163`](../rust-client-docs/content/docs/packages/workspaces.mdx#L163)
and [`monorepo-setup.mdx`](../rust-client-docs/content/docs/guides/monorepo-setup.mdx)
say "Local-package injection into deploy outputs is not supported
yet — publish internal members first."
**Why deferred:** Needs a deploy-time bundler that can rewrite
`workspace:*` references to relative paths (or vendor copies) inside
the production-closure tarball. Non-trivial.
**Workaround:** Pre-deploy step that publishes internal members to
the LPM registry first, then runs `lpm deploy`.

## `lpm migrate -y` (interactive flag)

**Surface:** `lpm migrate -y` / `--yes`.
**Status:** Reserved. The migrate flow is fully non-interactive
today, so the flag is a no-op. It does NOT imply `--force` (decoupled
in this tranche to remove the destructive widening).
**Source string:** [`main.rs:1765`](crates/lpm-cli/src/main.rs)
clap doc spells out the no-op contract.
**Why deferred:** Future interactive prompts (e.g., "we found N
peer-dep conflicts; pick a resolution") would re-enable the flag's
purpose.
**Workaround:** Pass `--force` to overwrite existing `lpm.lock`.

---

## How to update this file

Whenever you land a new "not supported yet" / "isn't supported yet" /
"doesn't extend to X yet" string:

1. Add a section here naming the surface, the source string, why it's
   deferred, and the workaround.
2. Whenever a deferred surface ships, delete its section and search
   the codebase for the source string to remove.

A test-side helper at
[`tests/workflows/tests/behavioral_tag_catalog_drift.rs`](tests/workflows/tests/behavioral_tag_catalog_drift.rs)
shows the cross-repo doc-drift pattern. Similar parity tests for the
deferred-surface strings would be a reasonable future addition if
they start drifting between source and docs.
