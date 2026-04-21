# Static-gate fixture corpus

Phase 46 P2 Chunk 2 — starter set of lifecycle-script bodies with
hand-assigned expected tiers. Consumed by
`crates/lpm-security/tests/static_gate_corpus.rs`.

## Layout

- `expectations.json` — array of `{id, expected, notes?}`. Category
  is encoded in the `id` prefix (see naming below), so there is no
  explicit `category` field.
- `scripts/<id>.txt` — one file per entry, containing the exact raw
  script body. Separate files (instead of an inline JSON field) so
  that:
  1. Diffs are per-script and readable.
  2. Unicode adversarial inputs (RTL overrides, zero-width joiners,
     BOM) are preserved byte-for-byte without JSON escaping.
  3. The expected tier and the raw body can be reviewed side-by-side.

## Naming

`<category>-<NNN>-<short-descriptor>` — category groups logically
related entries so diffs during tuning stay scoped:

- `green-NNN-*` — pure local build steps that should tier Green.
- `amber-d18-NNN-*` — D18 network binary downloaders (playwright,
  puppeteer, node install.js, etc.) that tier Amber by design.
- `amber-compound-NNN-*` — compounds of otherwise-green commands.
- `amber-novel-NNN-*` — commands outside the allowlist and outside
  the red blocklist.
- `amber-node-escape-NNN-*` — `node <path>` where the path would
  escape the package directory.
- `amber-parse-fail-NNN-*` — malformed input (unbalanced quotes,
  etc.) that tokenizes fail-closed to Amber.
- `red-pipe-NNN-*` — pipe-to-shell patterns.
- `red-eval-NNN-*` — `eval`, `node -e`, `node --eval`.
- `red-nested-pm-NNN-*` — nested package-manager installs.
- `red-rm-NNN-*` — `rm -rf` on dangerous targets.
- `red-chmod-NNN-*` — `chmod` outside the package tree.
- `red-redirect-NNN-*` — redirects into user dotfiles or `/etc`.
- `red-nc-NNN-*` — `nc` / `netcat` / `ncat` reverse-shell shapes.
- `adversarial-NNN-*` — Unicode obfuscation, PowerShell literals,
  no-space operator attacks (the §12.2 adversarial set).

## Ship criteria (from the plan doc, §4.1)

- Zero false-positive reds (asserted in Chunk 2 harness).
- Every expectation must match the classifier's output (asserted in
  Chunk 2 harness).
- ≥60% green-rate across the full 500-script corpus — the starter
  set is deliberately biased toward amber/red for coverage, so its
  green-rate starts lower and grows in Chunk 6. The rate is printed
  every run; the hard `≥60%` assertion flips on in Chunk 6.

## Regeneration

Add a new fixture by:

1. Pick an id following the naming convention above.
2. Write the raw body to `scripts/<id>.txt`.
3. Append the entry to `expectations.json` with the expected tier.
4. Run `cargo test -p lpm-security --test static_gate_corpus` — it
   will report a mismatch if your expectation disagrees with the
   classifier, or success plus an updated green-rate stat line.
