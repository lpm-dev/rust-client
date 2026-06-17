# HTTP/3 Transport Compare

Standalone benchmark helper for comparing the existing reqwest HTTP/3 experiment
with a Cloudflare `tokio-quiche` HTTP/3 client against the LPM Worker metadata
batch endpoint.

This helper is intentionally outside the main Cargo workspace so the shipped
client does not inherit `tokio-quiche`, BoringSSL, or native build prerequisites.
Each sample opens a fresh client/QUIC connection for both transports, matching
the live install benchmark's separate-process samples more closely than a pooled
client loop would.

Requirements:

- `cmake` on `PATH` for `tokio-quiche`/BoringSSL
- `RUSTFLAGS='--cfg reqwest_unstable'` for reqwest's experimental HTTP/3 API

Example:

```bash
RUSTFLAGS='--cfg reqwest_unstable' \
  cargo run --release --manifest-path bench/http3-transport-compare/Cargo.toml -- \
  --runs 5 \
  --packages axios,react,zod,debug \
  --timeout-ms 30000
```

The existing live metadata benchmark can run this helper after the install route
comparison:

```bash
RUNS=5 bench/live-metadata-route.sh --transport-compare
```
