# Provenance hardening performance audit

- Date: 2026-07-24
- Platform: macOS arm64
- Baseline: `origin/main` at `30c3cdd120edb00a65fe5759c449cc7cce977bbe`
- Candidate branch: `codex/provenance-hardening`
- Default configuration was not changed before or after measurement.

The candidate keeps these defaults:

```toml
trust-policy = "off"

[sigstore]
verify = "deny"
scope = "approved"
availability = "best-effort"
```

`scope = "all"`, strict provenance availability, and verified-history
no-downgrade remain explicit opt-ins.

## Default-path release A/B

The default-path comparison used interleaved baseline/candidate runs against
the deterministic localhost registry fixture with 96 packages. Each scenario
used isolated project and LPM home state appropriate to cold, warm, frozen,
or repeat-frozen replay.

| Scenario | Baseline median | Candidate median | Delta |
| --- | ---: | ---: | ---: |
| Cold | 435 ms | 441 ms | +6 ms (+1.4%) |
| Warm | 26 ms | 27 ms | +1 ms (+3.8%) |
| Frozen | 24 ms | 25 ms | +1 ms (+4.2%) |
| Repeat frozen | 23 ms | 23 ms | 0 ms |

The TOML lockfile was 41,937 bytes in both arms. Importer snapshots made this
graph TOML-only, so neither arm emitted `lpm.lockb`.

The measured release binaries were pinned at:

- Baseline SHA-256:
  `fbf2e48f4f8f91700d9ff2b837d9a645bf65cf1b8c728faf4e824ea491c650f4`
- Candidate SHA-256:
  `5e8537d5f14913f421a22a62635fcf6779291a451c1ef9ace53eefefcdacbae6`

The candidate binary preceded the final linear-time provenance table
validation cleanup. That cleanup is inactive when the provenance table is
empty and only removes repeated package scans when evidence is present, so
the default-path comparison remains representative and the opt-in path result
is conservative.

## Universal verification opt-in

Real npm measurements used axios 1.14.0 and its 26-package graph, with nine
interleaved runs per cold arm.

| Mode | Wall median | Internal median |
| --- | ---: | ---: |
| Defaults | 202 ms | 185 ms |
| `scope = "all"` | 250 ms | 233 ms |

Universal cold verification added 48 ms. The median provenance policy gate was
36 ms: 31 ms for the attestation HTTP request and 1 ms for cryptographic
verification. The result is network-bound, which is why universal
verification remains opt-in.

The verified TOML lockfile was 15,342 bytes versus 14,615 bytes by default.
The one evidence record added 727 bytes.

### Re-verifying cache hit

| Mode | Wall | Internal |
| --- | ---: | ---: |
| Defaults | 30 ms | 16 ms |
| `scope = "all"` | 33 ms | 19 ms |

The provenance cache hit took 1 ms and included complete certificate,
transparency-log, identity, npm subject, and tarball digest verification of
the original cached bundle bytes. It made no attestation HTTP request.

## Binary lockfile structural cost

Binary wire format v3 keeps the v2 package entry at 36 bytes and adds a sparse
provenance section:

- No provenance evidence: one 8-byte `PRV3` footer.
- Each verified package: one 68-byte evidence record plus its eight unique
  strings.

Packages without evidence have no per-package size penalty.

## `dhat` frozen replay

The exact heap comparison used the 21-direct-dependency
`bench/fixture-large` manifest. Both arms resolved byte-identical 302-package
lockfiles apart from `lockfile-version = 6` versus `7`, installed 256
host-compatible packages, warmed isolated stores, removed `node_modules`, and
then ran with `CI=1` so the existing lockfile automatically selected frozen
replay.

| Metric | Baseline | Candidate | Delta |
| --- | ---: | ---: | ---: |
| Total bytes allocated | 47,661,732 | 47,775,506 | +113,774 (+0.24%) |
| Total blocks allocated | 210,761 | 210,886 | +125 (+0.06%) |
| Peak live bytes | 2,896,994 | 2,900,122 | +3,128 (+0.11%) |
| Peak live blocks | 22,201 | 22,192 | -9 (-0.04%) |
| Bytes live at exit | 402,627 | 402,627 | 0 |
| Blocks live at exit | 800 | 800 | 0 |

The default frozen path has no meaningful heap regression.

Instrumented binary SHA-256:

- Baseline:
  `87a62249367cc91e05ba69925026a6a9c33eb65eac066406a1a6a36fdb2b4811`
- Candidate:
  `c26e1156b85bf1db24e39753f43bafa8bef010c48a37ecd06ebfad86cb022856`

## Tracy

Release builds with the `tracy` feature produced valid cold-install captures
for both arms. Each trace contained the same 197 instrumented zones, including
the existing extractor and linker spans. The one-shot profiled wall samples
were intentionally not used as the A/B timing result; Tracy changes runtime
shape and a single localhost sample is noisier than the interleaved medians
above.

Instrumented binary SHA-256:

- Baseline:
  `7a23fb1f761a710620c98483b780b48a145b715f251c0afe2f399b5fbed6d702`
- Candidate:
  `e9370e188af8549c29a94acfdb81831d0fb2163dd4737684bdb68a9130ed4b4a`

## Decision

Keep the configurable defaults unchanged. The default path is effectively
flat in wall time and heap use, while `scope = "all"` has a measurable
48 ms cold cost dominated by attestation network latency. Users who prefer
universal verification can enable it explicitly; strict availability and
verified-history no-downgrade remain independent opt-ins.
