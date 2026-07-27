//! Reports the hash throughput used by the store hot paths.
//!
//! Run with:
//! `cargo run --release -p lpm-store --example hash_backend`

use sha2::Digest;
use std::time::Instant;

const SAMPLE_BYTES: usize = 64 * 1024 * 1024;
const TREE_HASH_CHUNK: usize = 64 * 1024;

fn pseudo_random(len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; len];
    let mut state: u32 = 0x1234_5678;
    for byte in &mut out {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (state >> 24) as u8;
    }
    out
}

fn throughput(label: &str, data: &[u8], mut hash: impl FnMut(&[u8])) -> f64 {
    hash(&data[..data.len().min(1024)]);
    let start = Instant::now();
    hash(data);
    let mib_per_second = (data.len() as f64 / 1_048_576.0) / start.elapsed().as_secs_f64();
    println!("{label:<38} {mib_per_second:>8.1} MiB/s");
    mib_per_second
}

fn main() {
    let data = pseudo_random(SAMPLE_BYTES);
    println!(
        "architecture={} sample={}MiB",
        std::env::consts::ARCH,
        SAMPLE_BYTES / 1_048_576
    );

    let sha256 = throughput("SHA-256 one-shot", &data, |bytes| {
        std::hint::black_box(sha2::Sha256::digest(bytes));
    });
    throughput("SHA-256 in 64KiB chunks", &data, |bytes| {
        let mut hasher = sha2::Sha256::new();
        for chunk in bytes.chunks(TREE_HASH_CHUNK) {
            hasher.update(chunk);
        }
        std::hint::black_box(hasher.finalize());
    });
    let sha512 = throughput("SHA-512 one-shot", &data, |bytes| {
        std::hint::black_box(sha2::Sha512::digest(bytes));
    });
    let blake3 = throughput("BLAKE3 one-shot", &data, |bytes| {
        std::hint::black_box(blake3::hash(bytes));
    });

    println!("sha512/sha256={:.2}", sha512 / sha256);
    println!("blake3/sha256={:.2}", blake3 / sha256);
}
