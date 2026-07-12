# Native lifecycle-build cache benchmark

- Platform: macOS arm64
- Node: v22.22.1
- Fixture: `bench/audit-fixtures/native/esbuild-prebuilt`
- Release-build samples per scenario: 10
- Median build artifact size: 134,444 bytes

| Scenario | Median wall | p95 wall | Median RSS | User CPU | System CPU | Result |
|---|---:|---:|---:|---:|---:|---:|
| Strict cache miss | 138.03 ms | 449.94 ms | 52,248,576 B | 50 ms | 20 ms | 10 misses |
| Local artifact hit | 32.33 ms | 37.27 ms | 41,467,904 B | 10 ms | 10 ms | 4.27×; 76.58% lower wall time |
| Stable-path CI warm-store hit | 29.50 ms | 30.12 ms | 41,418,752 B | 10 ms | 10 ms | 4.68×; 78.63% lower wall time |

Every measured scenario used the same strict sandbox. Miss and local-hit
samples rematerialized the same project. CI-like samples deleted and recreated
a checkout at one stable path while retaining the warm LPM store; observable
lifecycle paths are part of the cache key, so moving a checkout intentionally
invalidates the artifact.

Across ten local hits, artifact metadata recorded 1,356 ms of lifecycle
execution avoided. Across ten stable-path CI hits, it recorded 1,053 ms
avoided. This fixture has a short lifecycle command; native compilation
workloads should have a substantially larger absolute hit benefit.
