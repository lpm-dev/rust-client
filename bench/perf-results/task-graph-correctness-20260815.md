# Task-graph correctness benchmark

- Date: 2026-08-15
- Host: macOS arm64
- Samples: 10 adjacent AB/BA pairs for each scenario
- Warmups: one run for each binary and scenario

The benchmark used two prebuilt release binaries. The harness did not build a
binary during the benchmark.

- Main commit: `226f5767297ff843c999d06076baec0be7c40f7d`
- Main binary SHA-256: `c811c14541df73e2ebf5bf78172e415ac87ee096fafd4cc7f8b92e70ca9d6be1`
- Candidate binary SHA-256: `f853d49bdcb4068cd1e1ccbd8156edaf1f0bd07b689a6fa48a5481697a328285`

Each fixture contains one real Node subprocess. Meta-tasks form the remaining
deep or wide graph. The subprocess stays active for 300 ms so the harness can
sample process-tree peak RSS.

| Scenario | Main wall median / p95 | Candidate wall median / p95 | Wall median change | Main tree RSS median / p95 | Candidate tree RSS median / p95 | RSS median change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Deep, 10 tasks | 335.18 / 350.62 ms | 335.18 / 343.27 ms | 0.00% | 55.23 / 55.92 MiB | 55.23 / 55.28 MiB | -0.01% |
| Deep, 100 tasks | 334.22 / 356.14 ms | 334.47 / 346.74 ms | +0.07% | 55.27 / 55.31 MiB | 55.28 / 55.49 MiB | +0.01% |
| Deep, 1,000 tasks | 337.58 / 369.98 ms | 339.00 / 362.07 ms | +0.42% | 58.23 / 58.72 MiB | 58.14 / 58.54 MiB | -0.15% |
| Wide, 10 tasks | 334.76 / 362.61 ms | 334.30 / 354.54 ms | -0.14% | 55.23 / 55.32 MiB | 55.28 / 55.37 MiB | +0.10% |
| Wide, 100 tasks | 337.75 / 358.60 ms | 335.49 / 357.54 ms | -0.67% | 55.50 / 55.73 MiB | 55.45 / 55.51 MiB | -0.10% |
| Wide, 1,000 tasks | 349.76 / 353.69 ms | 349.33 / 355.33 ms | -0.12% | 59.36 / 59.83 MiB | 59.41 / 59.67 MiB | +0.09% |

All 60 candidate runs passed the correctness contract. No wall-time or peak-RSS
metric crossed its regression limit. File-descriptor and thread metrics were
advisory because these short runs did not contain two detailed samples.

The benchmark command was:

```bash
node bench/scripts/run-runtime-readiness.mjs \
  --lpm-binary main=/private/tmp/lpm-task-baseline-226f5767-lpm-rs \
  --lpm-binary candidate=/private/tmp/lpm-task-candidate-final-20260815-lpm-rs \
  --compare main,candidate \
  --profile full \
  --scenarios task/deep-10,task/wide-10,task/deep-100,task/wide-100,task/deep-1000,task/wide-1000 \
  --samples 10 \
  --warmups 1
```

Raw artifacts: `/var/folders/p2/32lgcl857ds0wkcnkg0qk51h0000gn/T/lpm-runtime-readiness-20260815T103133621Z-2696`
