# Native lifecycle-build cache benchmark

- Platform: macOS arm64
- Node: v22.22.1
- Fixture: `bench/audit-fixtures/native/esbuild-prebuilt`
- Release-build samples per scenario: 10
- Build artifact size: 134,444 bytes

| Scenario | Median wall | p95 wall | Median RSS | User CPU | System CPU | Result |
|---|---:|---:|---:|---:|---:|---:|
| Cache disabled | 114.99 ms | 417.43 ms | 52,248,576 B | 40 ms | 10 ms | baseline |
| Cache miss | 134.58 ms | 148.42 ms | 52,264,960 B | 50 ms | 20 ms | 10 misses |
| Local artifact hit | 29.45 ms | 51.91 ms | 41,500,672 B | 10 ms | 0 ms | 3.90×; 74.39% lower wall time |
| Fresh-project warm-store hit | 29.19 ms | 31.29 ms | 41,566,208 B | 10 ms | 0 ms | 3.94×; 74.62% lower wall time |

The disabled and miss scenarios rematerialized pristine dependencies before
every sample. Local-hit samples rematerialized the same project. CI-like hit
samples created a fresh project while retaining the warm LPM store. Across ten
hits, the artifact metadata recorded 1,028 ms of lifecycle execution avoided.

The cache miss adds about 19.6 ms over the disabled median for keying,
pristine rematerialization, integrity validation, and atomic publication. This
fixture has a short lifecycle command; native compilation workloads should
have a substantially larger absolute hit benefit.
