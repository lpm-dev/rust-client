//! Trial 5 (2026-05-13) — store path-helper microbench.
//!
//! Measures the per-call allocation cost of `StoreV2Paths::object_dir`
//! and `StoreV2Paths::link_package_dir`, the two paths the linker
//! hot loop calls 153× each per install (51-package fixture).

use criterion::{Criterion, criterion_group, criterion_main};
use lpm_store::v2::{GraphKey, LinkerModeTag, PlatformTuple, StoreV2Paths};
use std::collections::HashMap;
use std::hint::black_box;

fn make_graph_key() -> GraphKey {
    GraphKey::derive_raw(
        "@scope/example-package",
        "1.2.3",
        &PlatformTuple::current(),
        LinkerModeTag::Isolated,
        &[("dep-a".to_string(), "^1.0.0".to_string())],
        &HashMap::new(),
        &[],
        None,
        None,
        None,
    )
}

fn bench_paths(c: &mut Criterion) {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StoreV2Paths::at(tmp.path().to_path_buf());
    let key = make_graph_key();
    // Realistic SRI (base64-encoded SHA-512), matching the shape the
    // npm registry returns. 64 bytes of "hash" → 88-char base64.
    let sri = "sha512-PnQj4nKhAGgQ7yEUS5JlNGYpemoCx5gqL8sUebNqgWKYWFp64g4nNFstUNbgKb3khA34iCExmgIBjxNzwzL2fOiYAxwSOJrMxA==";

    let mut group = c.benchmark_group("store_paths");
    group.bench_function("link_package_dir", |b| {
        b.iter(|| {
            let p = paths.link_package_dir(black_box(&key));
            black_box(p);
        })
    });
    group.bench_function("link_node_modules_dir", |b| {
        b.iter(|| {
            let p = paths.link_node_modules_dir(black_box(&key));
            black_box(p);
        })
    });
    group.bench_function("object_dir", |b| {
        b.iter(|| {
            let p = paths.object_dir(black_box(sri)).unwrap();
            black_box(p);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_paths);
criterion_main!(benches);
