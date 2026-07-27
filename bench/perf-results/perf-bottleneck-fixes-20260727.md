# Profiled bottleneck fixes — 2026-07-27

This pass started from `origin/main` at `e651b2ea33f05c35ec80952b1824fb9d6f2512d9`.
Measurements below were captured on macOS/aarch64 with release builds unless
noted otherwise. The profiling branch was used only as reference.

## Measured results

| Path | Before | After | Change |
| --- | ---: | ---: | ---: |
| Behavioral scan, 4.3 MiB non-ASCII corpus | 12.54 ms | 4.91 ms | 2.55× faster |
| SHA-256, one-shot | 444.8 MiB/s | 3,122.2 MiB/s | 7.02× throughput |
| SHA-256, 64 KiB updates | 430.7 MiB/s | 3,143.2 MiB/s | 7.30× throughput |
| SHA-512, one-shot | 650.5 MiB/s | 1,781.3 MiB/s | 2.74× throughput |
| Warm state check, 1,000-package lockfile, 100 iterations | 161.922 ms | 6.930 ms | 23.4× faster |
| Four serial 10 ms lifecycle children | 417.999875 ms | 63.953208 ms | 6.54× faster |

The behavioral result keeps Unicode `\b` semantics. The optimized
implementation uses individual `Regex::is_match` calls rather than changing
word-boundary behavior to ASCII. The harness verifies identical match vectors
between the old `RegexSet` and the individual regexes on its corpus.

The warm-state comparison uses the same optimized binary and project state for
both arms. The legacy arm removes only the new binary-sidecar expectation line,
forcing the prior full TOML validation path. The marker arm records that the
completed install intentionally has no binary sidecar.

The SHA assembly backend is enabled on non-Windows product builds. Windows
retains the portable software backend because `sha2-asm` does not support
MSVC's assembler.

After converting the lifecycle timing check into an ignored manual benchmark
so CI scheduling cannot fail correctness tests, a verification rerun measured
70.088750 ms for the same four children (5.96× faster than the 417.999875 ms
polling baseline). The product implementation is unchanged from the 63.953208
ms result in the table.

For the profiled 811-package add case, registry metadata candidates fall from
811 packages to the 9 packages that contain lifecycle scripts: 802 fewer
metadata lookups (98.9%). A unit test pins the candidate rules for scripted,
script-free, and local-source packages. V2 installs resolve those candidates
through the same project-scoped baseline index used by blocked-set capture, and
reuse that index for any post-build recapture. The workflow regression covers
cold metadata enrichment plus a warm reinstall after the registry disappears.

## Allocation reductions

- Removing the unused `BufReader` in the 64 KiB tree-hash loop eliminates the
  6,338 allocations of 8,192 bytes attributed by the original dhat profile
  (49.5 MiB of cumulative allocation).
- Moving the speculative HTTP `Bytes` value into the extraction task removes
  one full compressed-body copy per dispatched speculative extraction.
- Individual supply-chain regexes remove the large Unicode-overlap automaton
  state observed in the original heap profile.

These allocation changes were not assigned standalone wall-clock claims; the
hash and behavioral end-to-end harnesses above include their relevant paths.

## Reproduction

```bash
cargo run --release -p lpm-security --example behavioral_hotpath
cargo run --release -p lpm-store --example hash_backend
cargo test -p lpm-cli --bin lpm-rs \
  wait_with_timeout_manual_benchmark_for_four_short_lived_children \
  -- --ignored --nocapture --test-threads=1
```

The warm-state comparison was a temporary release-mode unit harness so it could
call the private install-state predicate directly. It constructed one
1,000-package lockfile, ran 100 checks with `b:not-required`, removed only that
line, and ran 100 checks through the legacy fallback. The timing-only harness
was removed after measurement; permanent tests cover required, not-required,
and malformed/legacy marker behavior.

## Deliberately not changed

- Binary lockfiles remain generated validation companions, not authoritative
  install inputs. Reviving binary reads would change the code-review security
  contract and would not help current importer-bearing lockfiles.
- Tree snapshots retain `ctime`. Dropping it would weaken tamper detection;
  hardware SHA acceleration instead reduces the unavoidable content-hash
  fallback after archive restore.
- Recursive workspace install was not added because it is a new command
  behavior, not a transparent optimization.
- Resolver metadata was not made lazy in this pass; that requires a larger
  ownership and cache-format redesign. The avoidable speculative body copy and
  tree-hash allocation were removed now.
- Lifecycle scripts remain serial and dependency ordered.
- macOS continues to use the supported `/usr/bin/sandbox-exec` boundary.
  Replacing it with private Seatbelt APIs would change the security mechanism
  and introduce unsafe post-fork work.
