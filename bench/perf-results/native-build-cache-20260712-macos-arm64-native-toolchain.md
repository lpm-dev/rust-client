# Native lifecycle-build cache benchmark — NativeToolchain

- Platform: macOS arm64
- Node: v22.22.1
- Fixture: `bench/audit-fixtures/native/sharp-image`
- Release-build samples per scenario: 10
- Median build artifact size: 503,469 bytes

| Scenario | Median wall | p95 wall | Median RSS | User CPU | System CPU | Result |
|---|---:|---:|---:|---:|---:|---:|
| Strict cache miss | 245.04 ms | 319.67 ms | 47,136,768 B | 70 ms | 60 ms | 10 misses |
| Local artifact hit | 132.80 ms | 156.10 ms | 41,566,208 B | 50 ms | 50 ms | 1.85×; 45.8% lower wall time |
| Stable-path CI warm-store hit | 134.28 ms | 140.65 ms | 41,549,824 B | 50 ms | 50 ms | 1.82×; 45.2% lower wall time |

Every measured scenario used the same strict sandbox. Sharp follows the
`NativeToolchain` cache path, so every hit includes trusted compiler, SDK,
package-database, pkg-config, Homebrew receipt, and Node-header fingerprinting.
Miss and local-hit samples rematerialized the same project. CI-like samples
deleted and recreated a checkout at one stable path while retaining the warm
LPM store.

Across ten local hits, artifact metadata recorded 1,048 ms of lifecycle
execution avoided. Across ten stable-path CI hits, it recorded 1,053 ms
avoided. The measured hit remains beneficial after paying the complete native
toolchain key cost.
