# Rewritten publish archive retention benchmark

- Date: 2026-08-20
- Host: Apple M5 Pro, macOS 26.5.2, arm64, 48 GiB RAM
- Toolchain: Rust 1.94.0
- Build profile: release with LTO
- Samples: seven alternating AB/BA pairs after one warm gate per binary
- Peak RSS source: `/usr/bin/time -lp`

## Scope

The fixture contains one 180 MiB incompressible package payload and four publish
targets with distinct package names. The command is
`lpm publish --check --lpm --npm --github --gitlab --allow-secrets --no-provenance`,
so it builds one base archive and four renamed archives without network
activity.

The high-entropy payload keeps every compressed rewrite close to the source
size. It therefore exposes the cost of retaining all rewritten archives for
the full publish command.

## Binaries

| Revision | Commit | SHA-256 |
| --- | --- | --- |
| In-memory rewrite baseline | `b03f9603` | `1a59871bf643d218dfeffb820523d4d756298804de5a702263489bcc943410c2` |
| File-backed rewrite candidate | `52b0c46d` | `abca5d7116ac9ab992100bf917d5d8a3d8e198539e4897b1280393e1157969d7` |

No compiler process ran during a measured sample. Both binaries used the same
fixture, environment, toolchain, and release profile.

## Results

| Metric | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Peak RSS | 1,575.09 MiB | 854.63 MiB | -45.74% |
| Wall time | 10,464.43 ms | 10,656.89 ms | +1.84% |

The candidate saves 720.47 MiB of median peak RSS. The file-backed design adds
a small wall-time cost because each rewrite is written to temporary storage
instead of an in-memory vector. Check mode never reloads those bytes, so this
benchmark isolates archive preparation and retained-memory behavior.

## Implementation result

Renamed archives are written to owner-held temporary files while their hashes
are computed in the same pass. Publish planning retains only each temporary
file, its length, hashes, manifest size, and secret-scan result. It does not
retain any rewritten archive bytes.

The base archive remains shared in memory. A rewritten archive is validated
against its recorded length and loaded immediately before its corresponding
upload. Provenance precomputation uses hashes and metadata without loading the
archive, and check or dry-run paths never load rewritten bytes.

## Conclusion

The candidate removes simultaneous retention of all rewritten publish
archives. The 45.74% peak-RSS reduction confirms that the retained archives
were material on the four-target stress fixture. The 1.84% median wall-time
increase is the measured cost of the file-backed lifetime boundary.

Raw artifacts:

- `/tmp/lpm-area3-rewrite-retention-results.json`
- `/tmp/lpm-rewrite-retention-benchmark.mjs`
- `/tmp/lpm-rewrite-retention-fixture.t8bLbd`
