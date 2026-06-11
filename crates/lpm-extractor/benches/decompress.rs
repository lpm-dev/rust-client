//! Isolated decompression-speed benchmark comparing libdeflate (the
//! install-hot-path decoder) against flate2 with the `zlib-rs` backend.
//!
//! Three fixture sizes mirror the npm tarball size distribution:
//!   - small  (~100 KB compressed) — typical leaf utility (lodash.get etc.)
//!   - medium (~500 KB compressed) — typical mid-tree dep (react, axios)
//!   - large  (~2 MB compressed)   — typical heavyweight (typescript-ish)
//!
//! Each fixture is a synthetic tarball with realistic JS-source-like content
//! so the gzip codec sees representative entropy.

use criterion::{Criterion, criterion_group, criterion_main};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::{Read as _, Write as _};

/// Build a gzip-compressed tarball whose uncompressed payload is roughly
/// `target_uncompressed_bytes`. Content is JS-like to give the codec
/// realistic entropy.
fn make_fixture(target_uncompressed_bytes: usize) -> Vec<u8> {
    // Repetitive but not pathological — JS source patterns repeat a lot of
    // identifiers, but no two files are identical.
    let line_template = b"function fn_NN(arg) { return arg.value + 42 * Math.random(); }\n";
    let header_template = b"// generated benchmark fixture line NN -- do not edit\n";

    let mut payload = Vec::with_capacity(target_uncompressed_bytes);
    let mut n: u32 = 0;
    while payload.len() < target_uncompressed_bytes {
        let suffix = format!("{:08x}", n);
        let mut line = line_template.to_vec();
        // Replace "NN" with a hex-encoded counter so each line is unique.
        if let Some(pos) = line.windows(2).position(|w| w == b"NN") {
            line[pos..pos + 2].copy_from_slice(&suffix.as_bytes()[..2]);
        }
        payload.extend_from_slice(&line);
        let mut hdr = header_template.to_vec();
        if let Some(pos) = hdr.windows(2).position(|w| w == b"NN") {
            hdr[pos..pos + 2].copy_from_slice(&suffix.as_bytes()[..2]);
        }
        payload.extend_from_slice(&hdr);
        n += 1;
    }
    payload.truncate(target_uncompressed_bytes);

    // Wrap in a single-file tar archive so callers see realistic tarball
    // framing (gzip-of-tar, not gzip-of-raw).
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        let mut header = tar::Header::new_gnu();
        header.set_path("package/bench-payload.js").unwrap();
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder.append(&header, payload.as_slice()).unwrap();
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

const MAX_BUFFERED_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

/// Mirror of `decompress_gzip_libdeflate` in lib.rs — copied here because
/// the helper is private. The bench measures the same buffered decode shape
/// (ISIZE hint + bounded retry-on-grow loop) so the comparison is apples-to-apples.
fn libdeflate_decompress(compressed: &[u8]) -> Vec<u8> {
    let isize_bytes = &compressed[compressed.len() - 4..];
    let isize_hint = u32::from_le_bytes([
        isize_bytes[0],
        isize_bytes[1],
        isize_bytes[2],
        isize_bytes[3],
    ]) as usize;
    assert!(
        isize_hint <= MAX_BUFFERED_DECOMPRESSED_SIZE,
        "benchmark fixture exceeds buffered decompression cap"
    );
    let mut capacity = if isize_hint == 0 {
        compressed.len().clamp(1, MAX_BUFFERED_DECOMPRESSED_SIZE)
    } else {
        isize_hint
    };
    let mut decompressor = libdeflater::Decompressor::new();
    loop {
        let mut output = vec![0u8; capacity];
        match decompressor.gzip_decompress(compressed, &mut output) {
            Ok(actual) => {
                output.truncate(actual);
                return output;
            }
            Err(libdeflater::DecompressionError::InsufficientSpace) => {
                assert!(
                    capacity < MAX_BUFFERED_DECOMPRESSED_SIZE,
                    "benchmark fixture exceeded buffered decompression cap"
                );
                capacity = capacity
                    .saturating_mul(2)
                    .min(MAX_BUFFERED_DECOMPRESSED_SIZE);
            }
            Err(e) => panic!("decompress failed: {e:?}"),
        }
    }
}

fn flate2_decompress(compressed: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(compressed);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).unwrap();
    out
}

fn bench_decompress(c: &mut Criterion) {
    let sizes = [
        ("small_100KB", 100 * 1024),
        ("medium_500KB", 500 * 1024),
        ("large_2MB", 2 * 1024 * 1024),
    ];

    for (label, target) in sizes {
        let compressed = make_fixture(target);
        let mut group = c.benchmark_group(format!("decompress/{label}"));
        group.throughput(criterion::Throughput::Bytes(compressed.len() as u64));

        group.bench_function("libdeflate", |b| {
            b.iter(|| {
                let out = libdeflate_decompress(std::hint::black_box(&compressed));
                std::hint::black_box(out);
            })
        });

        group.bench_function("flate2_zlib_rs", |b| {
            b.iter(|| {
                let out = flate2_decompress(std::hint::black_box(&compressed));
                std::hint::black_box(out);
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_decompress);
criterion_main!(benches);
