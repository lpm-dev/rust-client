# Release transaction memory benchmark

- Date: 2026-08-17
- Host: Apple M5 Pro, macOS 26.5.2, arm64, 48 GiB RAM
- Toolchain: Rust 1.94.0
- Build profile: release, LTO, `internal-test-sigstore-mock`
- Samples: seven alternating AB/BA pairs for each final scenario
- Peak RSS source: `/usr/bin/time -lp`

## Scope

This benchmark measures release apply and interrupted transaction recovery.
The fixture contains 47 workspace manifests.
Each manifest contains 1,048,000 description bytes.
The fixture has 46.97 MiB of manifest source text.

This fixture is near the 48 MiB transaction limit.
It does not represent a typical workspace.

## Binaries

| Revision | Commit | SHA-256 |
| --- | --- | --- |
| Before durable recovery | `bd07d9fb` | `6f556e8e89201c17e6c0adec2def8458fb3974f48d8ccf6fffc1bd017e863907` |
| Durable recovery | `5598f9a4` | `3366bfacf2a575a34bd9bc5e5d598c87ea751293b04c1921bed84275b6b55b99` |
| Bounded and streamed candidate | `59efc582` | `2e133e99187af6533d63665b66fde64f334aa6e0db0cfbc922c7ee3e5f81dc1c` |

The harness built all binaries with the same toolchain, features, and target directory.
No compiler process ran during a measured sample.

## Correctness gates

Each apply sample had to update all 47 versions from `1.0.0` to `1.0.1`.
Each recovery seed aborted after the 24th durable manifest write.
The harness required exactly 24 updated manifests and a durable journal before each timed retry.

Each retry had to update all 47 manifests.
Each retry also had to remove the recovery journal.
The harness stopped without a result if a correctness gate failed.

## Durable recovery context

The first run compared the direct parent commits before and after durable recovery.

| Scenario | Before recovery | Durable recovery | Change |
| --- | ---: | ---: | ---: |
| Apply median peak RSS | 230.55 MiB | 397.78 MiB | +72.54% |
| Apply median time | 67.96 ms | 614.67 ms | +804.45% |
| Recovery median peak RSS | not supported | 434.06 MiB | - |
| Recovery median time | not supported | 890.38 ms | - |

Durable recovery adds file synchronization, backup encoding, journal persistence, and recovery validation.
The parent binary does not provide the same crash-recovery contract.
Therefore, this table gives context and is not the final regression gate.

## Final paired results

The final run alternated the durable recovery binary and the streamed candidate.

| Scenario | Durable recovery | Candidate | Change |
| --- | ---: | ---: | ---: |
| Apply median peak RSS | 397.83 MiB | 335.73 MiB | -15.61% |
| Apply median time | 606.78 ms | 596.71 ms | -1.66% |
| Interrupted recovery median peak RSS | 434.06 MiB | 374.20 MiB | -13.79% |
| Interrupted recovery median time | 896.28 ms | 888.50 ms | -0.87% |

The candidate serializes one encoded backup at a time.
It does not retain all encoded backups and the raw journal at the same time.
The serialized journal remains byte-compatible with the recovery parser and commit receipt.

The candidate also stops pretty serialization at 16 MiB for one manifest.
It stops all retained manifest updates at 48 MiB for one transaction.
The transaction boundary repeats the aggregate check before journal creation or manifest mutation.

## Conclusion

The final candidate reduces peak RSS without a latency regression.
The results support streamed journal encoding for the durable recovery path.
The fixed limits also remove unbounded updated-manifest retention.

This change does not affect dependency installation or runtime acquisition.
Therefore, the install-readiness benchmark is not part of this gate.

Raw artifacts:

- `/private/tmp/lpm-release-memory-before.json`
- `/private/tmp/lpm-release-memory-final-paired.json`
- `/private/tmp/lpm-release-memory-benchmark.mjs`
