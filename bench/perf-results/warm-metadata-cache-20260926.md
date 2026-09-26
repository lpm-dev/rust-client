# Warm metadata cache: stored resolver projections

A warm resolve decoded every cached package history in full and then parsed it again into the resolver's tables. For vite-react that took about 40 ms of CPU across 110 packages, with react, react-dom, react-refresh, vite and scheduler (750–3,000 versions each) on the critical path. The resolver now stores its parsed tables beside each cached history and reads them back directly. In the frozen-registry harness, vite-react fresh checkouts with a warm cache take 49.3 ms instead of 59.5 ms, and T3's take 85.4 ms instead of 89.9 ms. When the cache has expired, complete histories are now revalidated instead of downloaded again, and a 304 answers from the stored tables: against the live registry, vite-react's install takes 225–327 ms instead of 393–442 ms.

## Where the time went

Profiles and timing traces of vite-react fresh checkouts with the cache inside its 5-minute freshness window showed:

- **Decoding and parsing, not waiting.** Each cache hit decoded the full MessagePack history (27 ms of CPU per install) and then projected it into the resolver's tables (11.5 ms). Read on its own, react-dom took 4.2 ms to decode and 2.4 ms to project.
- **The network limit was not binding.** Cache hits do take the same 16 metadata permits as network requests, and their waits add up to about 31 ms per install. Raising the limit to 256 left resolve time unchanged at 23.5 ms: the waits overlapped other work.

## The change

**Stored projections.** The resolver's parsed tables for one package history are written to `<entry>.projection` beside the cached document. A warm read validates them and loads them without touching the document. On vite-react's cache, decoding projections for all 110 packages sequentially took 2.4 ms against 41 ms for reading, decoding and projecting the documents, and react-dom's took 0.45 ms against 6.6 ms.

A projection is used only while it describes the exact document on disk:

- **Content ID.** Every metadata cache write now records a random 128-bit content ID in its header (cache format V7), and a projection is bound to that ID. Rewriting the document orphans the projection. A 304 revalidation only moves the entry's expiry, so its projection stays valid.
- **Format.** Projections carry a format name that includes the crate version, so a release that changes how metadata is parsed never reads tables an older parser derived.
- **Validation.** Loading checks every string ID, record span, UTF-8 boundary and sort order before the tables reach accessors that index without checks. Damaged or foreign projections fall back to decoding the document.
- **Lifecycle.** Invalidating an entry removes its projection. `lpm cache clean` removes the whole directory.

The registry chooses between a cached history, a latest document and the network exactly as before; projections only replace decoding. The decisions that need the document's contents (whether a partial history covers the requested range) use two facts stored in the projection header: whether the history is complete, and its `latest` tag.

**Faster version parsing.** Loading a projection parses each version string again. A dedicated parser for the canonical `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` form, identical to node-semver on the inputs it accepts and deferring to it on all others, cut react's 2,957 versions from 0.44 ms to 0.22 ms. It also speeds up the resolver's projection of downloaded documents.

**Stale complete histories are revalidated.** When a range excluded the `latest` tag, the preferred path stored the complete history under a separate cache key, but a stale lookup only read the ETag of the partial entry. Complete histories were therefore downloaded in full every time they expired: 18.3 MB for vite-react. The lookup now falls back to the complete entry's ETag, and a 304 reuses that entry and its projection.

**The Node probe no longer blocks a runtime worker.** The first engine check of a dependency runs `node --version`, which takes about 13 ms. Three dispatcher tasks made that check on a tokio worker, and every task queued behind that worker waited with it. Once projections made resolution fast, T3's timelines showed cache reads that had finished at 5 ms not resuming until 17 ms. The dispatchers now call `block_in_place` before the first probe, so the runtime hands the worker's other tasks to another thread.

## Results

### Frozen-registry harness

The harness replays a frozen HTTPS capture of the registry locally, with balanced ordering and 16 samples per variant. Values are median / nearest-rank p95 in ms; the paired difference is the median over the same samples.

Fresh checkout with a warm cache (the state this change targets):

| Project | #893 | This change | Paired |
|---|---:|---:|---:|
| vite-react | 59.5 / 62.1 | 49.3 / 53.1 | −9.6 (16/16) |
| T3 | 89.9 / 100.5 | 85.4 / 91.2 | −4.2 (15/16) |
| nest | 40.7 / 43.3 | 39.4 / 41.6 | −1.3 (13/16) |
| native-sharp | 30.1 / 31.2 | 29.8 / 33.3 | −0.3 (12/16) |

An earlier round, built before the last code cleanup, measured −9.6 (16/16), −4.0 (13/16), −1.3 (14/16) and −0.2 ms (9/16).

Cold states, to check that writing projections costs nothing measurable:

| Project, state | #893 | This change | Paired |
|---|---:|---:|---:|
| T3, first install | 1,488.8 / 1,906.3 | 1,492.3 / 1,611.3 | +2.8 (7/16) |
| T3, CI cold | 1,389.9 / 1,631.9 | 1,384.6 / 1,448.7 | −5.5 (8/16) |
| vite-react, first install | 285.0 / 291.5 | 287.0 / 295.3 | +0.7 (5/16) |
| vite-react, CI cold | 223.3 / 236.2 | 225.4 / 323.8 | +1.6 (8/16) |

Earlier rounds with the build before the last cleanup measured −1.1 and −2.4 ms for T3, and +3.2 / −5.0 then −1.2 / −0.2 ms for vite-react's first install / CI cold. No state moves consistently in either direction.

### Expired cache, live registry

The replay proxy does not answer conditional requests, so the stale state was measured against registry.npmjs.org. Before each run, a seeded cache was restored and every entry expired; the lockfile, `node_modules` and `.lpm` were removed. Two sets of eight paired runs, median total install time in ms:

| Project | #893 | This change | Paired |
|---|---:|---:|---:|
| vite-react, final build | 393.0 | 224.5 | −157.5 (8/8) |
| vite-react, earlier build | 441.5 | 326.5 | −140.0 (6/8) |
| T3, final build | 810.5 | 672.5 | −112.5 (6/8) |
| T3, earlier build | 749.5 | 640.0 | −45.5 (6/8) |

In the traced vite-react run, #893 downloaded 18.3 MB (82 revalidations). This change revalidated 109 entries, downloaded 4.4 KB and answered 58 packages from projections.

### Local warm-cache runs

Against the live registry with the cache inside its freshness window, 24 paired runs: vite-react resolves in 5 ms instead of 22.5 ms (total 31.0 against 41.0 ms, 24/24 faster), and T3 in 16 ms instead of 20 ms (total 65.0 against 69.0 ms, 21/24 faster). Before the Node probe fix, vite-react resolved in 14 ms.

## Measured and not adopted

**Cache hits skipping the network limit.** With projections, raising the metadata permit limit from 16 to 256 changed nothing in warm states: vite-react 0.0 ms (3/24 faster) and T3 0.0 ms (12/24). With a mix of hits and network misses (vite-react plus three new dependencies against the live registry), permit waits added up to 1.1–1.3 s per install at 16 permits and 25–38 ms at 256, yet resolve differed by −11 ms (7/10), inside network noise of ±100 ms. Letting hits bypass the limit would need a second scheduling lane in the resolver, so it stays out.

## Costs

- **One-time cache miss.** The V7 header changes cache file names, so the first install after upgrading downloads metadata again instead of revalidating it. Old V6 files stay until `lpm cache clean`.
- **Disk.** Projections add 30–48% to the metadata cache: 7.2 MB beside 15.2 MB of documents for vite-react, 4.2 MB beside 13.9 MB for T3.

## Remaining costs found along the way

- **Node probe latency.** A fresh checkout with engine constraints still waits for `node --version` once. The probe starts when the first constrained package arrives, and resolution cannot finish handing selected packages to the fetch dispatcher until it returns. With a stub `node` answering in about 3 ms, T3 resolves in 8–11 ms instead of 16 ms.
- **Exact-version histories over the size cap.** Exact versions are selected from the package's full history when it fits in 4 MiB. Ten of T3's (`@next/swc-*`, `@next/env`, `@tailwindcss/oxide`) have 4.8–7.7 MB histories, so each attempt reads 4 MiB (0.5–0.9 MB over the wire), fails and falls back to the 2–3 KB version document. That is about 42 MB decoded on every cold or expired T3 install, in #893 as well.

## Limitations

The harness replays locally over TLS and does not model internet latency or bandwidth; the stale-cache and mixed-state measurements used the live registry and vary by ±100 ms. All runs used one Apple Silicon machine (18 cores).

## Artifacts

The adjacent `-summary.json` holds the numbers in this report. The `-tools.tar.gz` archive contains the harness drivers and rows, the A/B and trace scripts, the timeline and profile analysis scripts, and the spawn-stall probe.
