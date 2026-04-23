# Static-gate fixture corpus

Phase 46 P2 — 500-script fixture set of lifecycle-script bodies with
hand-assigned expected tiers, consumed by
`crates/lpm-security/tests/static_gate_corpus.rs`.

## Layout

- `expectations.json` — array of `{id, expected}`. Category is
  encoded in the `id` prefix (see naming below). The manifest is
  machine-regenerable from the `scripts/` filesystem and should be
  regenerated whenever a fixture is added or removed (see below).
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

All three are hard-asserted in the Chunk 2 harness as of Chunk 6:

- **Zero false-positive reds.** The classifier MUST NOT flag any
  non-red expectation as red. Red rules never relax to chase the
  green-rate threshold — if a regression drops the rate, grow the
  corpus or (with explicit justification) widen a green rule.
- **Every expectation matches classifier output.** Any diff between
  declared `expected` and actual tier fails the test with a full
  listing.
- **≥60% green-rate** over the non-adversarial subset, measured as
  `green / (green + amber)`. Denominator definition is pinned in
  the plan §4.1. Current measured rate: see harness stats.

## Regeneration

Add a new fixture:

1. Pick an id following the naming convention above.
2. Write the raw body to `scripts/<id>.txt`.
3. Regenerate `expectations.json` from the filesystem:
   ```bash
   cd scripts/
   python3 -c "
   import os
   ids = sorted(f[:-4] for f in os.listdir('.') if f.endswith('.txt'))
   print('[')
   for i, id in enumerate(ids):
       if id.startswith('adversarial-') or id.startswith('red-'):
           exp = 'red'
       elif id.startswith('green-'):
           exp = 'green'
       elif id.startswith('amber-'):
           exp = 'amber'
       comma = ',' if i < len(ids)-1 else ''
       print(f'  {{ \"id\": \"{id}\", \"expected\": \"{exp}\" }}{comma}')
   print(']')
   " > ../expectations.json
   ```
4. Run `cargo test -p lpm-security --test static_gate_corpus` — it
   will report a mismatch if your expectation (derived from the id
   prefix) disagrees with the classifier, or success plus an
   updated green-rate stat line.
