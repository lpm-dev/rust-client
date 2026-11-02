# SHA-2 backends after sha2 0.11 — 2026-11-02

sha2 0.11 removes the `asm` feature that `lpm-common`'s `asm-sha2` feature
enabled for the CLI on every platform except Windows. It selects hardware
backends at run time instead: the AArch64 `sha2` and `sha3` extensions, and x86
SHA-NI and AVX2, with the portable code as the fallback. sha2 0.10 without
`asm` used the portable code on AArch64, which is the 7× gap that
`perf-bottleneck-fixes-20260727.md` measured.

## Measured results

Apple M5 Pro, macOS 27, Rust 1.99.1, `opt-level = 3`, fat LTO, one codegen
unit. One binary links `sha2 = "=0.10.9"` with `asm` and `sha2 = "=0.11.1"` with
default features, and checks that both produce the same digest. Each case hashes
the same 64 MiB of generated data: two warm runs per side, then eleven
alternating rounds, reporting the median.

| Case | sha2 0.10.9 + `asm` | sha2 0.11.1 | Change |
| --- | ---: | ---: | ---: |
| SHA-256, one-shot | 3,374.9 MiB/s | 3,374.0 MiB/s | 1.00× |
| SHA-256, 64 KiB updates | 3,375.8 MiB/s | 3,375.5 MiB/s | 1.00× |
| SHA-512, one-shot | 1,837.7 MiB/s | 1,854.9 MiB/s | 1.01× |
| SHA-512, 64 KiB updates | 1,839.9 MiB/s | 1,864.2 MiB/s | 1.01× |

## Consequences

- The `asm-sha2` feature and the C and assembly build it needed are removed.
- Windows builds, which never had `asm`, now use SHA-NI and AVX2 where the CPU
  has them.
- The env engine LPM Vault bundles kept `asm` off so its object code would not
  depend on the local C compiler. It now gets the hardware backends from Rust
  code alone.
