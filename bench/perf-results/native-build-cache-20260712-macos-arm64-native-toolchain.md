# Native lifecycle-build cache benchmark — NativeToolchain

- Platform: macOS arm64
- Node: v22.22.1
- Fixture: `bench/audit-fixtures/native/sharp-image`
- Release-build samples per scenario: 10
- Median build artifact size: 503,469 bytes

| Scenario | Median wall | p95 wall | Median RSS | User CPU | System CPU | Result |
|---|---:|---:|---:|---:|---:|---:|
| Strict cache miss | 173.10 ms | 280.00 ms | 47,169,536 B | 40 ms | 20 ms | 10 misses |
| Local artifact hit | 59.07 ms | 72.25 ms | 41,631,744 B | 20 ms | 10 ms | 2.93×; 65.88% lower wall time |
| Stable-path CI warm-store hit | 58.49 ms | 61.69 ms | 41,615,360 B | 10 ms | 10 ms | 2.96×; 66.21% lower wall time |

Every measured scenario used the same strict sandbox. Sharp follows the
`NativeToolchain` cache path, so every hit validates the persisted compiler,
SDK, package-database, pkg-config, Homebrew receipt, and Node-header snapshot.
The first measured miss computed the complete host fingerprint in 126 ms;
subsequent unchanged-host key derivations took 15–24 ms.
Miss and local-hit samples rematerialized the same project. CI-like samples
deleted and recreated a checkout at one stable path while retaining the warm
LPM store.

Across ten local hits, artifact metadata recorded 1,049 ms of lifecycle
execution avoided. Across ten stable-path CI hits, it recorded 1,051 ms
avoided. The measured hit remains beneficial after paying the conservative
host-snapshot validation cost.
