# Publish tar/gzip buffer overlap benchmark

- Date: 2026-08-20
- Host: Apple M5 Pro, macOS 26.5.2, arm64, 48 GiB RAM
- Toolchain: Rust 1.94.0
- Build profile: release with LTO
- Samples: seven alternating AB/BA pairs after one warm gate per binary
- Peak RSS source: `/usr/bin/time -lp`

## Scope

The fixture contains one 180 MiB incompressible package payload. The command is
`lpm publish --check --npm --allow-secrets --no-provenance`, so it exercises
publish file collection, tar construction, gzip encoding, hashing, and local
validation without network activity.

The high-entropy payload keeps the compressed and uncompressed archive sizes
close. It therefore exposes whole-buffer overlap near its practical maximum.

## Binaries

| Revision | Commit | SHA-256 |
| --- | --- | --- |
| Bounded archive baseline | `439e287d` | `3db75bc5554f0598ea85681104362b9bb1701a3fe76e42e1a8d8d9ae3e03fb3d` |
| Streaming tar/gzip candidate | `5111ff22` | `1a59871bf643d218dfeffb820523d4d756298804de5a702263489bcc943410c2` |

No compiler process ran during a measured sample. Both binaries used the same
fixture, environment, toolchain, and release profile.

## Results

| Metric | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Peak RSS | 923.70 MiB | 634.31 MiB | -31.33% |
| Wall time | 2,194.02 ms | 2,100.29 ms | -4.27% |

Candidate peak RSS stayed between 634.14 MiB and 634.36 MiB across all seven
samples. Baseline peak RSS stayed between 907.72 MiB and 923.73 MiB. The first
pair was slower for both binaries; alternating order and the median exclude
that shared warm-state movement from the result.

## Implementation result

Publish packing now writes tar bytes directly through gzip instead of retaining
a complete uncompressed tar beside the compressed result. Name and workspace
rewrites stream from gzip decoding through bounded tar rebuilding into gzip.
Compressed and uncompressed outputs have independent 500 MiB limits.

Buffered extraction also retains its aggregate allocation reservation until the
decoded buffer is dropped, and the reservation includes both compressed input
bytes and decoded-output capacity.

## Conclusion

The candidate removes the measured whole-tar/gzip overlap. It reduces peak RSS
by 289.39 MiB on the stress fixture and does not regress median wall time.

Raw artifacts:

- `/tmp/lpm-area2-publish-buffer-results.json`
- `/tmp/lpm-publish-buffer-benchmark.mjs`
- `/tmp/lpm-publish-buffer-fixture.IQQLGG`
