# Native lifecycle-build cache benchmark

- Platform: macOS arm64
- Node: v22.22.1
- Fixture: `bench/audit-fixtures/native/esbuild-prebuilt`
- Release-build samples per scenario: 10
- Build artifact size: 134,444 bytes

| Scenario | Median wall | p95 wall | Median RSS | User CPU | System CPU | Result |
|---|---:|---:|---:|---:|---:|---:|
| Cache disabled | 112.35 ms | 423.22 ms | 52,264,960 B | 40 ms | 10 ms | baseline |
| Cache miss | 137.53 ms | 147.84 ms | 52,264,960 B | 50 ms | 20 ms | 10 misses |
| Local artifact hit | 29.66 ms | 31.39 ms | 41,517,056 B | 10 ms | 0 ms | 3.79×; 73.60% lower wall time |
| Fresh-project warm-store hit | 29.19 ms | 30.51 ms | 41,533,440 B | 10 ms | 0 ms | 3.85×; 74.02% lower wall time |

The disabled and miss scenarios rematerialized pristine dependencies before
every sample. Local-hit samples rematerialized the same project. CI-like hit
samples created a fresh project while retaining the warm LPM store. Across ten
hits, the artifact metadata recorded 1,046 ms of lifecycle execution avoided.

The cache miss adds about 25.2 ms over the disabled median for keying,
pristine rematerialization, integrity validation, and atomic publication. This
fixture has a short lifecycle command; native compilation workloads should
have a substantially larger absolute hit benefit.
