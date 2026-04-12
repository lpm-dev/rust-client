# Cold Resolve Profiling — Phase 34.4

**Date:** 2026-04-12 (revision 3: corrected for split-pass attribution and cold-path measurement)
**Machine:** macOS arm64, Apple Silicon, Darwin 25.3.0
**Fixture:** bench/project (17 direct deps → 51 resolved packages, triggers 1 split on `is-unicode-supported`)
**Binary:** `target/release/lpm-rs` (LTO enabled)
**Methodology:**
- `crate::profile` — `AtomicU64` accumulators with drop guards. Counters are global (not thread-local) so `spawn_blocking` writes accumulate correctly. `reset_all()` called once before any resolver pass; `summary()` read once after all passes complete.
- `Instant` timers around `batch_metadata_deep`, `parse_ndjson_batch` JSON parse loop, and `write_metadata_cache` calls inside NDJSON parsing.
- `RUST_LOG=lpm=debug` for trace output.
- Cold = `~/.lpm/cache` + `~/.lpm/store` wiped before run.

---

## Timing (Release Binary)

### Cold install (cache + store wiped)

| Stage | Time |
|-------|------|
| resolve | 2322ms |
| fetch | 1269ms |
| link | 75ms |
| **total** | **3673ms** |

### Warm-cache install (metadata on disk, no lockfile, no node_modules)

| Stage | Time |
|-------|------|
| resolve | 25ms |
| fetch | 0ms |
| link | 50ms |
| **total** | **85ms** |

Note: cold numbers vary with network (Wi-Fi). Warm-cache numbers isolate local compute.

---

## Measured Function-Level Breakdown (Both Resolver Passes)

### Cold install — resolver profile (AtomicU64 accumulators, Phase 1 + Phase 2 combined)

| Function | Calls | Total time | Notes |
|----------|------:|----------:|-------|
| `get_dependencies` | 63 | 168.59ms | Includes nested `ensure_cached` + `to_pubgrub_ranges` |
| `ensure_cached` | 52 | 166.84ms | 52 calls across both passes. Includes disk cache reads (warm hits) + 3 individual HTTP fetches |
| `to_pubgrub_ranges` | 89 | 0.67ms | O(n²) union loop, 89 calls total across both passes |
| `available_versions` | 89 | 0.13ms | Vec clone |
| `choose_version` | 61 | 0.05ms | PubGrub callback |

### Warm-cache install — resolver profile (Phase 1 + Phase 2 combined)

| Function | Calls | Total time | Notes |
|----------|------:|----------:|-------|
| `get_dependencies` | 63 | 25.32ms | All cache hits, no network |
| `ensure_cached` | 52 | 24.42ms | Pure disk I/O: file read + HMAC verify + MessagePack deser |
| `to_pubgrub_ranges` | 89 | 0.42ms | Same call count, compute-only |
| `available_versions` | 89 | 0.07ms | Same |
| `choose_version` | 61 | 0.02ms | Same |

### NDJSON parse and cache write (cold install, measured inside `parse_ndjson_batch`)

| Operation | Time | Packages |
|-----------|------|----------|
| JSON parsing (`serde_json::from_str` + `from_value` per line) | **53.20ms** | 48 |
| Cache writing (MessagePack serialize + HMAC + `fs::write` per package) | **27.92ms** | 48 |
| **Client-side total** | **81.12ms** | |

### Batch prefetch total (cold install)

| Operation | Time |
|-----------|------|
| `batch_metadata_deep` end-to-end (HTTP + parse + cache write) | **2147ms** |

---

## Analysis: Where the time actually goes

### Cold resolve: 2322ms breakdown

| Component | Time | % | Source |
|-----------|------|---|--------|
| `batch_metadata_deep` — network wait (HTTP round-trip + server resolve) | ~2066ms | 89% | 2147ms total - 81ms client work |
| `batch_metadata_deep` — client JSON parse | 53ms | 2% | Measured |
| `batch_metadata_deep` — client cache write | 28ms | 1% | Measured |
| `ensure_cached` during resolution (3 individual fetches + disk reads) | 167ms | 7% | Measured |
| Resolver compute (`to_pubgrub_ranges` + PubGrub SAT) | ~1ms | <1% | Measured |
| Unaccounted (Phase 1→2 transition, format_solution, framework) | ~8ms | <1% | Difference |

### Warm-cache resolve: 25ms breakdown

| Component | Time | % | Source |
|-----------|------|---|--------|
| `ensure_cached` (52 disk cache reads: HMAC + MessagePack deser) | 24ms | 96% | Measured |
| Resolver compute (`to_pubgrub_ranges` + PubGrub) | ~0.5ms | 2% | Measured |
| Unaccounted | ~0.5ms | 2% | Difference |

### Cold-path client work: 81ms is measurable but not dominant

The NDJSON JSON parse (53ms) + cache write (28ms) = 81ms is **3.5% of the 2322ms cold resolve**. This is not negligible — it's more than the entire warm-cache resolve — but network wait at ~2066ms (89%) is still 25x larger. Optimizing the parse/write path (e.g., eliminating the `meta_value.clone()` double-parse, using direct MessagePack from the wire) could save ~20-40ms, but won't materially change the cold install experience.

---

## Metadata Flow

| Step | Count | Description |
|------|-------|-------------|
| Batch prefetch (deep) | 1 request | POST to `/api/registry/batch-metadata`, 48 packages via NDJSON |
| Cache hits during resolution | 47 | Batch-warmed metadata from disk |
| Individual HTTP fetches during resolution | 3 | `emoji-regex`, `@isaacs/fs-minipass`, `@pinojs/redact` |

## Version Distribution (Top 10)

| Package | Versions Parsed |
|---------|----------------|
| pino | 316 |
| zod | 286 |
| undici | 247 |
| ws | 167 |
| tar | 144 |
| dayjs | 129 |
| nanoid | 114 |
| lodash | 113 |
| semver | 111 |
| commander | 102 |

**Total versions across 50 packages:** 2,810

---

## Phase 34.5 Optimization Recommendations

Based on **measured** data:

### 1. Reduce `ensure_cached` disk I/O — warm resolve bottleneck (24ms of 25ms)

The batch prefetch writes metadata to disk, then during resolution `ensure_cached` reads it back from disk for every package. The in-memory cache (`phase1_cache`) partially helps in Phase 2 (split), but Phase 1 still reads from disk for all 48+ packages.

**Fix:** Keep the batch prefetch results in an in-memory HashMap and pass them to the resolver. The resolver's `ensure_cached` checks the in-memory map before falling back to disk. This eliminates 52 file reads + HMAC verifications + MessagePack deserializations.

**Expected improvement:** warm resolve from 25ms → ~1-3ms. Cold resolve saves ~167ms (the `ensure_cached` portion).

### 2. Fix `to_pubgrub_ranges` O(n²) — scaling concern

At 89 calls and 0.67ms total, this is NOT the current bottleneck. But at 500+ packages with larger version sets, the quadratic cost will scale badly. Fix for correctness.

**Expected improvement at current scale:** <1ms.

### 3. Eliminate NDJSON double-parse — cold-path client optimization (potential ~20ms)

`parse_ndjson_batch` calls `serde_json::from_value(meta_value.clone())` which clones the `Value` then deserializes it. Parsing directly from the line bytes into `PackageMetadata` (skipping the intermediate `Value`) would eliminate one clone + one parse.

**Expected improvement:** ~20-25ms off the cold-path 53ms parse cost.

### 4. Carry publish_time from resolver — ~5-10ms win

Eliminates post-resolution `minimumReleaseAge` metadata re-fetch.

---

## What Phase 34.5 Should NOT Do

- **Overlap/streaming architecture** — Cold resolve is 89% network. Overlap saves nothing on the client side.
- **Custom allocator** — Warm resolve compute is <1ms.
- **`available_versions` clone elimination** — 0.07ms. Not worth the refactoring.
