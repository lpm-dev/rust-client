# Self-update download memory benchmark

- Date: 2026-08-17
- Host: Apple M5 Pro, macOS 26.5.2, arm64, 48 GiB RAM
- Toolchain: Rust 1.94.0
- Build profile: test, unoptimized with debug information
- Samples: seven per mode in alternating AB/BA order
- Peak RSS source: `getrusage(RUSAGE_SELF)` in a fresh test process

## Scope

The fixture serves a deterministic 64 MiB response from a local TCP server.
The server writes one 64 KiB buffer repeatedly, so it does not retain the response body.

The buffered control reproduces the old pipeline:

1. Download the complete body into a `Vec<u8>`.
2. Hash the buffer.
3. Write it to a same-directory temporary file while retaining the buffer.

The streaming candidate hashes each response chunk while writing it directly to the temporary file.
Both modes use the same compiled test binary and run in separate processes.

## Results

| Metric | Buffered control | Streaming candidate | Change |
| --- | ---: | ---: | ---: |
| Median peak RSS delta | 68.05 MiB | 3.94 MiB | -94.21% |
| Median elapsed time | 444 ms | 447 ms | +0.68% |
| Elapsed range | 443-464 ms | 437-469 ms | within run noise |

The candidate stays below the 32 MiB regression bound.
The buffered control stays above that bound, which confirms that the probe can detect full-body retention.

## Correctness gates

Each sample verifies the 64 MiB byte count and staged file size.
The buffered control and streaming candidate both compute SHA-256 during the measured interval.

Separate active tests verify that the streaming path:

- creates the staged file beside the destination executable;
- produces the expected SHA-256;
- enforces the cap when `Content-Length` is absent;
- removes a partial staged file after a cap failure.

## Conclusion

Streaming removes approximately 64 MiB of retained memory for a 64 MiB asset.
The measured 0.68% median latency difference is smaller than the run-to-run range and is not a supported regression signal.

This change affects only standalone self-update downloads.
It does not affect dependency installation or runtime acquisition, so the install-readiness benchmark is not part of this gate.
