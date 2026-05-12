# Sandbox network-denial breakage audit (Phase 46.1)

Closes Phase 46.1 deliverable #5 — a **curated scripted-slice
impact sample** measuring the effect of the Phase 46.1
outbound-network-deny default on real npm packages with
lifecycle scripts. Where `bench/realworld-audit` tests whole
projects end-to-end and `bench/audit-fixtures` tests isolated
dep-graph shapes, this suite samples ecosystem-level breakage
across the family classifier's named buckets (prebuild-downloader,
browser-fetcher, native-bundler, telemetry, other).

Earlier drafts of the design note framed this as "live top-500
by weekly downloads." The data source for that framing (npm's
per-package downloads ranking API) is no longer publicly
available; see ["Producing the audit input list"](#producing-the-audit-input-list)
for the curated-sample approach that replaces it. The sample is
not exhaustive — it is family-distributed coverage at point of
release.

The audit is a one-shot, **pre-merge** run on the implementation
branch. The raw per-package ledger is meant to live as a PR artifact
+ release-prep artifact — **not** committed to the repo. A
family-level summary may be committed to release notes if useful.

## When this is run

Once, by the implementer / release operator, before merging Phase
46.1 to `main`. The output is attached to the PR description.

This is **not** a recurring CI gate. The durable in-tree regression
gate is `tests/workflows/tests/sandbox_network_denial.rs` (the
primary + loopback-target workflow cases). The audit sample
measures ecosystem impact at a point in time; the workflow test
pins the contract going forward.

## Requirements

- **Linux kernel ≥ 6.7**, with landlock V4 enabled
  (`CONFIG_SECURITY_LANDLOCK=y`). The design note's locked floor.
  On older kernels the strict default refuses the install and the
  audit's family-classification step has nothing to measure beyond
  "refused".
- **Network connectivity** for fetching package metadata + tarballs
  from npmjs.org. The sandbox denies network INSIDE postinstall —
  it does not deny the registry fetch that the install pipeline
  performs.
- **`lpm-rs` built from the implementation branch**, available on
  `$PATH`:
  ```bash
  cargo build --release -p lpm-cli
  export PATH="$PWD/target/release:$PATH"
  ```
- **Node.js** on `$PATH` — most npm postinstall scripts invoke
  node directly.

## Layout

```
bench/sandbox-network-audit/
├── README.md                # this file
├── run.sh                   # single-package runner
├── run-all.sh               # whole-list runner + family classifier
├── starter-packages.txt     # small validation slice (~10 well-known
│                              scripted packages) for smoke-testing
│                              the harness before the full run
├── .cache/    (gitignored)  # per-package staging area
└── results/   (gitignored)  # raw per-package JSON + family summary
```

## Producing the audit input list

The harness takes a newline-separated file of `name@version` (or
just `name`) entries. The design note framed this as a "live
top-500 by weekly downloads" slice, but **npm no longer exposes a
free per-package downloads ranking via its public API**:

- `https://api.npmjs.org/downloads/range/last-week/all` returns
  aggregated daily totals only — no `.packages[].name` field, the
  recipe that earlier drafts of this README relied on can't be
  reconstructed against today's endpoint shape.
- The community datasets earlier iterations pointed at
  (`anvaka/npm-rank`, `cheeaun/top-npm-libraries`, similar) are
  either 404 or stale beyond usefulness.
- `https://registry.npmjs.org/-/v1/search` works but is text-query
  scoped — there's no "give me top-N by downloads" mode.

The replacement approach is a **curated impact sample** assembled
from sources we control:

1. **Seed list.** Start from
   [`../top-npm-audit/top-100.txt`](../top-npm-audit/top-100.txt)
   (popularity-curated from Phase 66 §1b work) plus the
   family-by-family list of known-scripted packages we maintain
   in [`scripted-candidates.txt`](./scripted-candidates.txt) (this
   file is committed and tracks the packages we want this audit
   to keep covering as the ecosystem moves).
2. **Filter to scripted.** For each candidate, fetch
   `https://registry.npmjs.org/<pkg>/latest`, keep entries whose
   `.scripts` object carries any of `preinstall`, `install`,
   `postinstall`. The lookup is parallelizable; see
   [`build-input-list.sh`](./build-input-list.sh).

```bash
./bench/sandbox-network-audit/build-input-list.sh \
    > /tmp/sandbox-network-audit-input.txt
```

The output is a curated impact sample (typically 60-150
packages), not a literal "top-500 by downloads." The PR write-up
must say so — calling it the latter would be misleading given
the data-source gap.

If/when a working per-package downloads ranking becomes available
again, swap the seed-list step for it and keep the rest of the
pipeline (filter-to-scripted + harness invocation) unchanged.

## Running the harness

```bash
# Whole curated sample (generated by build-input-list.sh above)
./bench/sandbox-network-audit/run-all.sh /tmp/sandbox-network-audit-input.txt

# Smoke-test the harness against the small validation slice
./bench/sandbox-network-audit/run-all.sh \
    ./bench/sandbox-network-audit/starter-packages.txt

# Single package
./bench/sandbox-network-audit/run.sh prisma@5.22.0
```

## Output

Each run produces, under `results/<timestamp>/`:

- `raw/<package-name>.json` — per-package outcome:
  ```json
  {
      "package": "prisma@5.22.0",
      "name": "prisma",
      "requested_version": "5.22.0",
      "resolved_version": "5.22.0",
      "exit_code": 1,
      "lpm_built_present": false,
      "denial_signal_seen": true,
      "stderr_tail": "... EACCES ...",
      "family": "prebuild-downloader",
      "recommendation": "trustedDependencies OR PRISMA_SKIP_POSTINSTALL_GENERATE=1"
  }
  ```

  The `requested_version` and `resolved_version` fields diverge
  for bare-name inputs: `requested_version` carries `"latest"`
  while `resolved_version` is the concrete semver the install
  pipeline materialized in `node_modules`. The `.lpm-built`
  marker path is keyed off the resolved semver, not the input
  string, so both fields are reported for traceability.
- `summary.json` — family-level rollup:
  ```json
  {
      "kernel": "6.7.0-1-amd64",
      "lpm_version": "v0.39.0",
      "total": 500,
      "by_family": {
          "prebuild-downloader": { "count": 132, "remediation": "trustedDependencies, package-own env opt-out (e.g. PUPPETEER_SKIP_DOWNLOAD=1)" },
          "browser-fetcher":     { "count":  28, "remediation": "package-own env opt-out (e.g. PUPPETEER_SKIP_DOWNLOAD=1), trustedDependencies" },
          "native-bundler":      { "count":  47, "remediation": "trustedDependencies (postinstall builds against host toolchain)" },
          "telemetry":           { "count":   9, "remediation": "trustedDependencies if business-critical, otherwise let it fail silently — install completes" },
          "other":               { "count": 284, "remediation": "case-by-case; most are no-op or non-network postinstalls" }
      }
  }
  ```

## Family classification

The classifier in `run-all.sh` tags each package by:

1. **`prebuild-downloader`** — package name in the known
   prebuild-downloader list (esbuild, @swc/*, @biomejs/biome,
   sharp, bcrypt, node-sass, sqlite3, canvas, …) OR stderr matches
   `/downloading prebuilt/i`.
2. **`browser-fetcher`** — package name matches `^puppeteer`,
   `^playwright`, `^cypress`, `^electron` OR stderr matches
   `/downloading (chromium|firefox|webkit|browser)/i`.
3. **`native-bundler`** — package name matches a known native
   build (prisma, esbuild, @swc/*, oxc, lightningcss, biome,
   tree-sitter, node-gyp consumers) AND the package isn't already
   tagged as a prebuild-downloader.
4. **`telemetry`** — postinstall script body contains a known
   telemetry endpoint (sentry.io, segment.io, posthog, opencollective,
   `analytics.` hostnames) OR matches a "phone home" heuristic.
5. **`other`** — everything else. Most of these are no-op
   postinstalls (husky setup that fails silently, doc generators
   with no network dep, etc.).

Each family carries a default recommendation column in `summary.json`.
The PR description should re-classify any high-impact `other` cases
into the named families if the heuristic misses them.

## Posting results

```bash
# Attach raw + summary to the PR as a single zip
zip -r sandbox-network-audit-results.zip results/<timestamp>/
gh pr upload <PR> sandbox-network-audit-results.zip

# In the PR description, paste the summary section + a paragraph
# interpreting the family counts. Call it a curated impact sample,
# not "top-500 by downloads" — see the data-source caveat above:
#
#   "Across N curated scripted packages spanning all family
#    buckets, X cleanly succeeded, Y were denied_in_sandbox via
#    the kernel-level signal, Z landed in
#    marker_absent_no_denial_signal (decompose by reading the
#    per-package stderr_tail). The dns_failure_observed soft
#    count is <count> — re-classify host-config-bound resolver
#    behavior case-by-case."
```

## What the per-package outcome means

Each per-package record carries three load-bearing booleans —
`lpm_built_present`, `denial_signal_seen`, and the implicit
"install pipeline exit" recorded as `exit_code`. The
`summary.json` rollup buckets them into three non-overlapping
counts:

- **`succeeded`** — `lpm_built_present == true`. The package's
  lifecycle script ran, completed, and the build pipeline minted
  the marker.
- **`denied_in_sandbox`** — `denial_signal_seen == true` AND
  `lpm_built_present == false`. The kernel-level OS signal
  (`EACCES` / `EPERM` / `EHOSTUNREACH` / `ENETUNREACH` /
  `operation not permitted` / `permission denied`) from
  `connect(2)` / `bind(2)` reached stderr, and the marker is
  absent. The clean Phase 46.1 denial case — landlock V4's
  `ConnectTcp` / `BindTcp` deny ruleset surfaced an
  unambiguous refusal that the lifecycle script's caller
  emitted to stderr.
- **`marker_absent_no_denial_signal`** — `lpm_built_present == false`
  AND `denial_signal_seen == false`. Catches three distinct
  cases: (a) packages whose postinstall is a no-op or has no
  lifecycle scripts (the marker is absent because nothing
  needed to be built); (b) packages whose postinstall failed
  for a non-network reason (missing toolchain, syntax error);
  (c) **wrapped-error denials** — packages whose postinstall
  caught the network failure and re-threw a higher-level error
  (e.g. puppeteer's "Failed to set up chrome v131..."), so the
  OS-level denial token never reached stderr in plain form. The
  PR write-up should re-classify (c) cases manually by reading
  the per-package stderr.

The `exit_code` recorded per package is the **install pipeline's**
exit, not the lifecycle script's. Phase 69 locked the soft-fail
contract where the install pipeline returns 0 even when a
lifecycle script fails under the sandbox — so a non-zero
`exit_code` here almost always means the install never started
(metadata fetch failure, OS-incompat package). The marker +
denial-signal pair is the load-bearing signal for sandbox
behavior; `exit_code` is mostly diagnostic.

### Soft heuristic: `dns_failure_seen` and `dns_failure_observed`

Each per-package record also carries a `dns_failure_seen`
boolean (true when stderr contains `EAI_AGAIN` / `EAI_NODATA` /
`EAI_NONAME` / `EAI_FAIL` / the literal `getaddrinfo` token).
The summary aggregates this into a separate `dns_failure_observed`
count, **deliberately not folded into `denied_in_sandbox`**.

**Why it's a separate axis.** Phase 46.1's shipped contract on
Linux is "outbound TCP denied" (see
[`crates/lpm-sandbox/src/lib.rs`](../../crates/lpm-sandbox/src/lib.rs)
module doc and the
[Phase 46.1.1 follow-up](../../DOCS/new-features/37-rust-client-RUNNER-VISION-phase46.1.1-seccomp-udp-denial.md)
that ships UDP / DNS-via-UDP denial via seccomp-bpf). DNS lookups
in the Phase 46.1 sandbox may or may not fail, depending on the
host resolver stack:

- A glibc resolver that falls back to TCP-port-53 for AAAA records,
  truncated UDP responses, or DNSSEC validation will hit landlock
  V4's `ConnectTcp`-deny and surface `EAI_AGAIN`.
- A glibc resolver that successfully uses UDP throughout (the
  expected common case) will resolve DNS cleanly under Phase 46.1
  alone; the subsequent TCP `connect(2)` is what gets denied.
- Musl, network-namespace setups, alternative resolvers (`unbound`,
  `dnsmasq`, etc.), and host-specific NSS configurations all behave
  differently.

So **`dns_failure_seen` is a host-dependent observation, not a
contract claim.** Treating it as the same axis as `denial_signal_seen`
would (a) overstate the product contract by implying Phase 46.1
already seals external DNS — it doesn't, that's 46.1.1's job; (b)
misbucket ordinary resolver failures (a flaky DNS server, an
unreachable nscd, a real network outage) as sandbox denials. The
PR write-up should use `dns_failure_observed` to identify
candidate packages for case-by-case re-classification, but should
not claim the count as Phase 46.1's measured impact.

## Not committed to the repo

- `.cache/` — staging trees, gitignored.
- `results/` — raw per-package JSON, gitignored. **Goes to the PR
  artifact**, not into version control.

A stable family-level summary may be committed to release notes
if useful.
