# Native lifecycle-build cache benchmark — NativeToolchain

- Platform: macOS arm64
- Node: v22.22.1
- Fixture: `bench/audit-fixtures/native/sharp-image`
- Release-build samples per scenario: 10
- Median build artifact size: 503,469 bytes

| Scenario | Median wall | p95 wall | Median RSS | User CPU | System CPU | Result |
|---|---:|---:|---:|---:|---:|---:|
| Strict cache miss | 229.99 ms | 444.35 ms | 47,104,000 B | 120 ms | 170 ms | 10 misses |
| Local artifact hit | 122.88 ms | 131.98 ms | 41,631,744 B | 100 ms | 160 ms | 1.87×; 46.57% lower wall time |
| Stable-path CI warm-store hit | 125.39 ms | 135.02 ms | 41,615,360 B | 100 ms | 160 ms | 1.83×; 45.48% lower wall time |

Every measured scenario used the same strict sandbox. Sharp follows the
`NativeToolchain` cache path, so every hit includes trusted compiler, SDK,
package-database, pkg-config, Homebrew receipt, and Node-header fingerprinting.
Miss and local-hit samples rematerialized the same project. CI-like samples
deleted and recreated a checkout at one stable path while retaining the warm
LPM store.

Across ten local hits, artifact metadata recorded 1,072 ms of lifecycle
execution avoided. Across ten stable-path CI hits, it recorded 1,073 ms
avoided. The measured hit remains beneficial after paying the complete native
toolchain key cost.
