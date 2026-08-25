//! Local-only metadata hydration benchmarks.
//!
//! Run after the machine is on stable power and low-background-load conditions:
//!
//!   cargo bench -p lpm-resolver --features bench-internals --bench metadata_hydration
//!
//! The fixture is generated in memory and never hits the network. It separates
//! packument JSON hydration from resolver projection and speculation projection
//! so cache/parser work can be compared without CDN or filesystem noise.

use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use lpm_registry::PackageMetadata;
use lpm_resolver::{
    SpeculativePackageMetadata, benchmark_merge_cached_package_info,
    benchmark_parse_full_metadata_to_cache_info, benchmark_parse_metadata_to_cache_info,
    benchmark_parse_owned_full_metadata_to_cache_info,
    benchmark_parse_owned_metadata_to_cache_info,
    benchmark_parse_owned_partial_metadata_to_cache_info,
};
use serde_json::{Map, Value};
use std::sync::Arc;

#[derive(Clone, Copy)]
enum DependencyShape {
    EveryVersion,
    LatestOnly,
}

fn synthetic_packument(
    version_count: usize,
    include_time: bool,
    dependency_shape: DependencyShape,
) -> (Vec<u8>, PackageMetadata) {
    let mut versions = Map::new();
    let mut time = Map::new();

    for idx in 0..version_count {
        let patch = version_count - idx;
        let version = format!("1.0.{patch}");
        let is_latest = idx == 0;
        let include_deps = matches!(dependency_shape, DependencyShape::EveryVersion) || is_latest;
        let mut dependencies = Map::new();
        if include_deps {
            for dep_idx in 0..3 {
                dependencies.insert(
                    format!("dep-{idx}-{dep_idx}"),
                    Value::String(format!("^{}.0.0", dep_idx + 1)),
                );
            }
        }

        let mut version_obj = Map::new();
        version_obj.insert(
            "name".to_string(),
            Value::String("synthetic-packument".to_string()),
        );
        version_obj.insert("version".to_string(), Value::String(version.clone()));
        version_obj.insert("dependencies".to_string(), Value::Object(dependencies));
        if include_deps {
            version_obj.insert(
                "peerDependencies".to_string(),
                serde_json::json!({ "react": "^18.0.0" }),
            );
            version_obj.insert(
                "optionalDependencies".to_string(),
                serde_json::json!({ "fsevents": "^2.3.3" }),
            );
        }
        version_obj.insert(
            "dist".to_string(),
            serde_json::json!({
                "tarball": format!("https://registry.example/synthetic-packument-{patch}.tgz"),
                "integrity": format!("sha512-{patch:064x}")
            }),
        );

        versions.insert(version.clone(), Value::Object(version_obj));

        if include_time {
            time.insert(
                version,
                Value::String(format!("2026-01-{:02}T00:00:00.000Z", (idx % 28) + 1)),
            );
        }
    }

    let body = serde_json::json!({
        "name": "synthetic-packument",
        "modified": "2026-02-01T00:00:00.000Z",
        "dist-tags": {
            "latest": format!("1.0.{version_count}")
        },
        "versions": versions,
        "time": time
    });

    let bytes = serde_json::to_vec(&body).expect("synthetic packument should serialize");
    let metadata = serde_json::from_slice(&bytes).expect("synthetic packument should deserialize");
    (bytes, metadata)
}

fn bench_metadata_hydration(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_hydration");
    group.sample_size(30);

    for version_count in [64usize, 512, 2048] {
        let (abbreviated_bytes, abbreviated_metadata) =
            synthetic_packument(version_count, false, DependencyShape::EveryVersion);
        let (full_bytes, full_metadata) =
            synthetic_packument(version_count, true, DependencyShape::EveryVersion);
        let (_, sparse_abbreviated_metadata) =
            synthetic_packument(version_count, false, DependencyShape::LatestOnly);
        let speculation_info = Arc::new(benchmark_parse_metadata_to_cache_info(
            &abbreviated_metadata,
        ));
        let speculation_input = (&abbreviated_metadata, speculation_info);

        group.bench_with_input(
            BenchmarkId::new("json_deserialize_abbreviated", version_count),
            &abbreviated_bytes,
            |b, bytes| {
                b.iter(|| {
                    black_box(
                        serde_json::from_slice::<PackageMetadata>(black_box(bytes))
                            .expect("fixture should parse"),
                    )
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("resolver_projection_abbreviated", version_count),
            &abbreviated_metadata,
            |b, metadata| {
                b.iter(|| black_box(benchmark_parse_metadata_to_cache_info(black_box(metadata))));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("resolver_projection_owned_abbreviated", version_count),
            &abbreviated_metadata,
            |b, metadata| {
                b.iter_batched(
                    || metadata.clone(),
                    |metadata| black_box(benchmark_parse_owned_metadata_to_cache_info(metadata)),
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("resolver_projection_owned_partial", version_count),
            &abbreviated_metadata,
            |b, metadata| {
                b.iter_batched(
                    || metadata.clone(),
                    |metadata| {
                        black_box(benchmark_parse_owned_partial_metadata_to_cache_info(
                            metadata,
                        ))
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new(
                "resolver_projection_abbreviated_latest_deps_only",
                version_count,
            ),
            &sparse_abbreviated_metadata,
            |b, metadata| {
                b.iter(|| black_box(benchmark_parse_metadata_to_cache_info(black_box(metadata))));
            },
        );

        group.bench_with_input(
            BenchmarkId::new(
                "resolver_projection_owned_abbreviated_latest_deps_only",
                version_count,
            ),
            &sparse_abbreviated_metadata,
            |b, metadata| {
                b.iter_batched(
                    || metadata.clone(),
                    |metadata| black_box(benchmark_parse_owned_metadata_to_cache_info(metadata)),
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("json_deserialize_full", version_count),
            &full_bytes,
            |b, bytes| {
                b.iter(|| {
                    black_box(
                        serde_json::from_slice::<PackageMetadata>(black_box(bytes))
                            .expect("fixture should parse"),
                    )
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("resolver_projection_full", version_count),
            &full_metadata,
            |b, metadata| {
                b.iter(|| {
                    black_box(benchmark_parse_full_metadata_to_cache_info(black_box(
                        metadata,
                    )))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("resolver_projection_owned_full", version_count),
            &full_metadata,
            |b, metadata| {
                b.iter_batched(
                    || metadata.clone(),
                    |metadata| {
                        black_box(benchmark_parse_owned_full_metadata_to_cache_info(metadata))
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("speculation_projection", version_count),
            &speculation_input,
            |b, (metadata, info)| {
                b.iter(|| {
                    black_box(SpeculativePackageMetadata::from_dist_tags_and_info(
                        metadata.dist_tags.clone(),
                        info.clone(),
                    ))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("resolver_plus_speculation_projection", version_count),
            &abbreviated_metadata,
            |b, metadata| {
                b.iter_batched(
                    || metadata.clone(),
                    |metadata| {
                        let info = Arc::new(benchmark_parse_metadata_to_cache_info(&metadata));
                        let speculation = SpeculativePackageMetadata::from_dist_tags_and_info(
                            metadata.dist_tags,
                            info.clone(),
                        );
                        black_box((info, speculation))
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();

    let (_, metadata) = synthetic_packument(32, false, DependencyShape::EveryVersion);
    let mut version_names = metadata.versions.keys().cloned().collect::<Vec<_>>();
    version_names.sort();
    let fragments = version_names
        .into_iter()
        .map(|selected| {
            let mut fragment = metadata.clone();
            fragment.versions.retain(|version, _| version == &selected);
            benchmark_parse_owned_partial_metadata_to_cache_info(fragment)
        })
        .collect::<Vec<_>>();
    let mut merge_group = c.benchmark_group("metadata_fragment_merge");
    merge_group.sample_size(30);
    for fragment_count in [1usize, 8, 32] {
        merge_group.bench_with_input(
            BenchmarkId::new("sequential_exact_fragments", fragment_count),
            &fragment_count,
            |b, &fragment_count| {
                b.iter(|| {
                    let mut merged = fragments[0].clone();
                    for fragment in &fragments[1..fragment_count] {
                        merged = benchmark_merge_cached_package_info(&merged, fragment);
                    }
                    black_box(merged)
                });
            },
        );
    }
    merge_group.finish();
}

criterion_group!(benches, bench_metadata_hydration);
criterion_main!(benches);
