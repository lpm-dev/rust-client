# Registry connection lanes

Installs sent every registry request, metadata and tarballs alike, through one HTTP/2 connection per origin. This change spreads requests across eight connections. On T3 first installs it saves 0.4 s at 20 ms round-trip time, 2.5 s at 50 ms and 5.6 s at 100 ms. Against the live registry at 7 ms it is 71 ms faster.

## Method

Two Linux containers on a Docker network ran every harness measurement. The client ran a linux-arm64 release build of `lpm-rs`. The server replayed a frozen capture of registry.npmjs.org through the benchmark HTTPS proxy: 349 responses, of which 95 were tarballs totaling 124 MB. The proxy was the unpaced replay proxy, extended to listen across containers and to count bytes per connection. Netem on both interfaces added half the round-trip time in each direction at 1 Gbit/s, or 100 Mbit/s in one cell. The queue held about twice the bandwidth-delay product, and segmentation offloads were off.

The client's TCP receive buffer was capped at 4 MiB, the macOS default, or 6 MiB, the Linux default. The server used one of three socket profiles:

- **Large buffer:** a 64 MiB send buffer.
- **CDN-like:** the same buffer with `tcp_notsent_lowat` at 128 KiB.
- **Default:** kernel defaults.

Every sample was a first install of the T3 fixture into an empty home, cache and store. Variants alternated in balanced order, with 10 to 16 samples per variant. Times are nearest-rank median and p95 milliseconds, and paired deltas are medians over the same samples.

The proxy relay does not cap a connection. At 0 ms, one connection downloaded the 42 MB `next` tarball at 113–116 MB/s on the 1 Gbit/s link. At 100 ms one warm connection reached about 19 MB/s, while four connections together reached 50 MB/s.

Live measurements ran on this Mac against registry.npmjs.org, with about 7 ms TCP connect time and about 100 MB/s on a single download.

## One connection carried every byte

An install opened about 34 connections, but one carried 100% of the 158 MB. Every retryable request goes out through the redirect-disabled client provider, whatever client built it, and that provider held one client. The other connections came from the startup burst: concurrent requests each open a connection before any TLS handshake has settled on HTTP/2, and only one connection then stays in use.

The timing waterfall located the cost. With 50 ms of latency, resolution took 4.7 of 6.1 s. Resolution waits on metadata, which queued behind tarball data on that connection, and the connection moved at most its flow-control window and the receive buffer per round trip.

## Moving tarballs alone was inconsistent

A first matrix used the large-buffer profile, with variants selected by an experiment switch (`experiment.patch`), 12 samples each. Paired deltas against the shared connection:

| Round trip, client buffer | Shared | Tarballs on 1 lane | Tarballs over 4 lanes | Tarballs ≥ 8 MiB on 1 lane | HTTP/1.1 pool |
|---|---:|---:|---:|---:|---:|
| 0 ms, 4 MiB | 2,479 | −239 | −316 | −156 | −502 |
| 20 ms, 4 MiB | 3,360 | −151 | −89 | +188 | −991 |
| 50 ms, 4 MiB | 5,748 | −407 | −1,328 | −523 | −2,188 |
| 100 ms, 4 MiB | 12,439 | −302 | −4,627 | −1,078 | −6,392 |
| 50 ms, 6 MiB | 5,125 | −363 | +1,036 | −45 | −1,707 |
| 100 ms, 6 MiB | 8,487 | +207 | −453 | +434 | −3,396 |
| 50 ms, 100 Mbit/s | 14,870 | +204 | +48 | −143 | −1,341 |

The first column is the shared connection's median; the rest are paired deltas. Moving tarballs mainly shifted time from resolution to fetching, and with a 6 MiB buffer the tarball lanes were neutral or slower. A dedicated lane for large tarballs is not worth adding.

## Spreading every request

Spreading all requests, metadata included, shortened resolution itself. At 50 ms with a 4 MiB buffer, 10 samples per variant:

| Server profile | Shared | 4 lanes | 8 lanes | HTTP/1.1 pool |
|---|---:|---:|---:|---:|
| Large buffer | 6,058 | −1,097 (9/10) | −2,435 (10/10) | −2,580 (10/10) |
| CDN-like | 6,981 | −2,481 (10/10) | −2,687 (10/10) | −3,616 (10/10) |
| Default | 5,783 | −1,965 (9/10) | −2,262 (10/10) | −2,690 (10/10) |

With eight lanes, resolution fell from 4.7 to 1.9 s, and the result held across all three server profiles. Sixteen or thirty-two lanes added nothing measurable: at 20, 50 and 100 ms, 16 lanes were within the noise of 8.

## HTTP/1.1 pooling did not hold up live

The HTTP/1.1 pool (`LPM_HTTP=h1-pool`) was fastest in the harness. It opened 125 to 170 connections per install, and capping metadata concurrency did not reduce that. The latest-document race abandons the history request of every range its latest document answers, up to 69 per T3 install, and under HTTP/1.1 each abandoned response closes its connection.

Live at 7 ms, 12 rounds each:

| Variant | Median | p95 | Paired |
|---|---:|---:|---:|
| Shared connection | 2,222 | 2,494 | |
| All requests over 8 lanes | 2,023 | 2,691 | −123 (10/12) |
| HTTP/1.1 pool | 2,188 | 2,549 | +11 (6/12) |

Its new TLS handshakes to the real CDN cancel the gain, which matches the earlier measurement that led to HTTP/2 being the default. The existing `LPM_HTTP=h1-pool` opt-in keeps a single lane.

## The change

Each client set builds eight redirect-disabled request lanes with their own connection pools, and successive requests rotate across them. The dedicated policy-metadata connection is unchanged. The #889 head against this change, CDN-like server, 4 MiB buffer, 16 samples each:

| Round trip | #889 | This change | Paired | Resolution | Busy connections |
|---|---:|---:|---:|---:|---:|
| 0 ms | 2,521 / 3,097 | 2,459 / 2,911 | −60 (8/16) | 1,232 → 968 | 1 → 8 |
| 20 ms | 3,062 / 3,937 | 2,651 / 3,056 | −441 (15/16) | 1,918 → 1,146 | 1 → 8 |
| 50 ms | 6,166 / 8,126 | 3,594 / 5,813 | −2,494 (16/16) | 4,640 → 1,909 | 1 → 8 |
| 100 ms | 11,227 / 15,134 | 5,883 / 8,237 | −5,637 (16/16) | 9,653 → 3,553 | 1 → 8 |

Live at 7 ms, 16 rounds each: #889 took 1,868 / 2,169 and this change 1,818 / 2,095, a paired −71 (12/16).

Building the extra clients does not slow command startup. Up-to-date installs, which return without network work, took 24.5 ms with and without eight extra clients over 30 paired runs.

Server retransmissions per install fell with lanes at 50 and 100 ms, from 64.5 to 46 and from 60 to 52.5. At 20 ms they were unchanged, and at 0 ms they rose from 10 to 56.5 without a time cost. The number of connections opened stayed at about 34, because the startup burst already opened that many.

## Limitations

The replay server is Node's HTTP/2 implementation, not the registry CDN's, and netem models latency, bandwidth and one queue rather than an internet path. The harness measured first installs of one fixture. The live check covers only this Mac's low-latency path, since adding latency to it would need root access.

## Artifacts

The adjacent `-summary.json` holds every measurement in this report. The `-tools.tar.gz` archive contains:

- the harness: server and proxy, drivers, runners, netem script, analysis scripts, calibration and live scripts;
- the experiment switch as `experiment.patch`;
- the raw rows.

Generated TLS material and captured registry bodies are not included. Absolute paths in the scripts identify this run.
