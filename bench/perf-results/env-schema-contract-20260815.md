# Environment schema contract benchmark

## Scope

This benchmark measures `lpm env check` with valid schema defaults. It compares the `main` baseline with the regex-contract candidate and verifies the final resource limits.

- Platform: macOS arm64
- Baseline commit: `edf0e9d5f8a1fdd624215051bb0a9b47df948748`
- Baseline binary SHA-256: `542d236410c756f36746892f05e6a417f50b861ae17e5fd240b926b66c72fd05`
- Initial grouped candidate SHA-256: `ebd31503adf062d37991d78dc5c223144b024fba5ea7e76301d952c1c009f09b`
- Final bounded candidate SHA-256: `b28a1a9058c16477270ebb4c3d91faa71b05c1823776c2bd2abc9d1fda305eea`
- Method: three warm-ups, alternating A/B order, isolated project and LPM home
- Wall time: 31 or 51 samples per binary
- Peak RSS: seven `/usr/bin/time -l` samples per binary

The fixtures use patterns that both the old wildcard matcher and the regex engine accept. This keeps the performance comparison independent of the corrected match semantics.

## Final grouped validator

| Variables | Pattern set | Main median | Candidate median | Delta | Main peak RSS | Candidate peak RSS |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 10 | unique | 4.93 ms | 5.09 ms | +0.16 ms | — | — |
| 100 | unique | 5.03 ms | 5.40 ms | +0.36 ms | — | — |
| 1,000 | duplicate | 6.08 ms | 6.35 ms | +0.28 ms | 18.28 MiB | 19.09 MiB |
| 1,000 | unique | 6.21 ms | 9.02 ms | +2.80 ms | 18.33 MiB | 20.55 MiB |

The final validator deduplicates patterns, compiles unique patterns in bounded groups of 64, disables capture state, and reuses one match bitmap. Normal project sizes remain within process-startup noise. The 1,000-unique-pattern case adds 2.80 ms and 2.22 MiB while providing the documented regex contract.

## Resource-bound follow-up

The final candidate uses these exact fixture formulas:

```python
matching = {
    f"PATTERN_{index:03}": {
        "pattern": f"^value_{index}$",
        "default": f"value_{index}",
    }
    for index in range(count)
}
invalid_split = matching_variables(65)
invalid_split["PATTERN_032"]["pattern"] = "("
budget = {
    f"PATTERN_{index:03}": {
        "pattern": f"^(?:a?){{1024}}{index}$",
        "default": "a" * 1024 + str(index),
    }
    for index in range(256)
}
```

The multi-environment fixtures use 1,000 unique matching rules. The four-environment fixture adds three empty named environment files to the default environment.

Each timing sample runs this command with output discarded:

```bash
HOME="$isolated_home" LPM_NO_UPDATE_CHECK=1 NO_COLOR=1 \
  "$candidate" env check
```

Peak RSS uses the same environment and command:

```bash
/usr/bin/time -l -o "$sample" "$candidate" env check
```

The 64/65 and one/four-environment pairs use three warm-ups and 31 alternating samples. The invalid-split/budget pair uses three warm-ups and 15 alternating samples. Each peak-RSS result is the maximum of seven samples.

| Fixture | Median | Peak RSS | Result |
| --- | ---: | ---: | --- |
| 64 unique patterns | 6.79 ms | 16.88 MiB | Exit 0 |
| 65 unique patterns | 6.86 ms | 16.88 MiB | Exit 0 |
| 65 patterns, one invalid | 6.00 ms | 16.77 MiB | Exit 1; 64 valid and one isolated compiler error |
| 256 adversarial patterns | 17.57 ms | 38.89 MiB | Exit 1; all 256 report the 8 MiB budget error |
| 1,000 unique patterns, one environment | 8.17 ms | 20.17 MiB | Exit 0 |
| 1,000 unique patterns, four environments | 9.98 ms | 20.56 MiB | Exit 0 |

The 64-to-65 boundary adds 0.07 ms and no measurable peak RSS. Three more environments add 1.81 ms and 0.39 MiB because the command compiles the schema once and reuses the validator.

Before the aggregate guard, the adversarial fixture retained 25,292,640 bytes of compiled regex state. The final validator caps retained regex and cache memory at 8 MiB. If compilation crosses the limit, it clears all compiled batches and returns the same truthful budget error for every affected rule. The final retained compiled-regex memory is zero for this rejected fixture.

The 38.89 MiB process peak includes the CLI, the fixture, and transient compilation of one candidate batch. The retained state stays bounded after rejection, and transient compilation does not grow with the total pattern count.

## Rejected implementation

The first implementation retained one compiled regex per variable. It was rejected before commit.

| Variables | Pattern set | Main median | Candidate median | Main peak RSS | Candidate peak RSS |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1,000 | duplicate | 6.45 ms | 21.70 ms | 18.19 MiB | 28.55 MiB |
| 1,000 | unique | 6.07 ms | 29.53 ms | 18.33 MiB | 32.27 MiB |

The grouped validator removes 70% of the rejected unique-pattern latency and 84% of its added peak memory. It also removes almost all duplicate-pattern overhead.
