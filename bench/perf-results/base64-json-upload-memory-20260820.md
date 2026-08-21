# Base64 JSON publish upload memory benchmark

- Date: 2026-08-20–21
- Host: Apple M5 Pro, macOS 26.5.2, arm64, 48 GiB RAM
- Toolchain: Rust 1.94.0
- Build profile: release with LTO
- Samples: seven alternating AB/BA pairs after one warm gate per binary
- Peak RSS source: `/usr/bin/time -lp`

## Scope

The fixture contains one 180 MiB incompressible package payload. The command is
`lpm stage publish --yes --allow-secrets --no-provenance` against a loopback npm
stage endpoint that drains the complete request body before responding.

The baseline constructs a full Base64 string and then serializes the complete
JSON request while retaining the compressed archive. The candidate retains one
shared archive and streams its Base64 representation in 192 KiB input chunks
between small, pre-serialized JSON prefix and suffix buffers. A fresh stream is
constructed for every retry.

## Binaries

| Revision | Source state | SHA-256 |
| --- | --- | --- |
| Serialized JSON baseline | `52b0c46d` | `abca5d7116ac9ab992100bf917d5d8a3d8e198539e4897b1280393e1157969d7` |
| Discarded file-backed request trial | Uncommitted trial | `a4f61bf60cdb57dca954eb23418d202b18925624070f91354b278707c0587d14` |
| Pre-closeout direct-stream candidate | Uncommitted review candidate | `077802ceed0cee06c9a58eaaad1f28c8ffa04d682d1b6d1246966f056e40b83d` |
| Direct-stream request candidate | Uncommitted closeout candidate | `5abf8605096f34fe090481d00fbdeed1e89836856a6ecefcae870aa17ab829b1` |

No compiler process ran during a measured sample. Every comparison used the
same fixture, environment, toolchain, release profile, loopback server, and
alternating execution order.

## Final direct-stream results

| Metric | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Peak RSS | 1,432.25 MiB | 855.91 MiB | -40.24% |
| Wall time | 4,582.92 ms | 4,453.14 ms | -2.83% |

The direct-stream candidate saves 576.34 MiB of median peak RSS while improving
median wall time by 2.83% on this fixture. Six of seven pairs were faster; the
median paired change was -3.01%, and one candidate sample was 5.13% slower.

## Near-limit escape-heavy provenance

The provenance path was measured independently because the main fixture uses
`--no-provenance`. The exact
`npm_publish_payload_streams_near_limit_escape_heavy_provenance` test builds a
10 MiB string composed entirely of JSON escape characters, so eager JSON
serialization would produce a separate 20 MiB encoded value. After one warm
run, seven `/usr/bin/time -lp` samples all reported 36.86 MiB peak RSS. Seven
control runs of a small test in the same test binary reported 12.67 MiB, leaving
24.19 MiB of incremental peak RSS for the 10 MiB raw value, its construction,
and the replayable body. Median peak memory footprint increased by 20.00 MiB
(6.55 MiB to 26.55 MiB).

The replayable body itself retains less than 128 KiB of already-encoded JSON
segments and shares the raw provenance through `Arc<str>`. JSON escaping is
emitted in chunks capped at 256 KiB plus the final closing quote when the
request stream is consumed, so the complete 20 MiB escaped value is never
resident.

## Discarded file-backed trial

The first implementation wrote the complete JSON request to an owner-held
temporary file and reopened it for each attempt. It reduced median peak RSS
from 1,432 MiB to 856 MiB (-40.22%), but increased median wall time from
4,484.57 ms to 5,137.92 ms (+14.57%) across the same seven-pair method. That
runtime regression was material, so the trial was discarded.

Direct streaming preserves essentially the same memory reduction without the
full request write/read cycle. It also avoids pathname races and temporary-file
lifetime concerns at the HTTP boundary.

## Correctness result

Chunk-boundary tests compare the emitted bytes with standard whole-buffer
Base64 and JSON-string encoding. Wire-level tests verify that npm web-auth
retries, LPM gateway retries, and body-preserving redirects send byte-identical
JSON bodies with the exact content length. Cross-origin redirects strip bearer,
cookie, proxy, and OTP credentials, reselect the target origin's TLS client,
refuse HTTPS downgrades and non-loopback cleartext targets, redact redirected
request URLs from errors, and share one timeout budget across client selection
and network work. LPM, npm provenance, and staged npm workflow uploads accept
and decode the streamed payload.

## Conclusion

Streaming the Base64 attachment directly into the HTTP body removes the two
archive-sized text allocations responsible for upload amplification. The
40.24% peak-RSS reduction confirms that those values were material, while the
final design avoids the discarded file-backed trial's wall-time regression.

Raw artifacts:

- `/tmp/lpm-area4-upload-memory-results.json`
- `/tmp/lpm-area4-post-closeout-upload-memory-results.json`
- `/tmp/lpm-upload-memory-benchmark.mjs`
- `/tmp/lpm-rewrite-retention-fixture.t8bLbd`
