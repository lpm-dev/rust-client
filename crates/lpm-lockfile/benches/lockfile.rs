use criterion::{Criterion, black_box, criterion_group, criterion_main};
use lpm_lockfile::{ImporterSnapshot, LockedPackage, Lockfile, ValidatedLockfile, binary};

fn make_lockfile(n: usize) -> Lockfile {
    let mut lf = Lockfile::new();
    for i in 0..n {
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: format!("pkg-{i:05}"),
            version: format!("{i}.0.0"),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-abcdef1234567890".to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: if i > 0 {
                vec![format!("pkg-{:05}@{}.0.0", i - 1, i - 1)]
            } else {
                vec![]
            },
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
    }
    lf
}

fn make_workspace_union(
    importer_count: usize,
    unique_package_count: usize,
    packages_per_importer: usize,
) -> (String, Vec<String>) {
    let packages = make_lockfile(unique_package_count).packages;
    let mut union = Lockfile::new();
    let mut importers = Vec::with_capacity(importer_count);
    for importer_index in 0..importer_count {
        let importer = format!("packages/member-{importer_index:03}");
        let mut package_indices = (0..packages_per_importer)
            .map(|offset| (importer_index * 53 + offset * 11) % unique_package_count)
            .collect::<Vec<_>>();
        package_indices.sort_unstable();
        package_indices.dedup();
        let mut standalone = Lockfile::new();
        standalone.importers.insert(
            ".".to_string(),
            ImporterSnapshot {
                dependencies: [(format!("direct-{importer_index:03}"), "^1.0.0".to_string())]
                    .into(),
                ..ImporterSnapshot::default()
            },
        );
        standalone.packages = package_indices
            .into_iter()
            .map(|index| packages[index].clone())
            .collect();
        union.absorb_importer(&importer, standalone).unwrap();
        importers.push(importer);
    }
    (union.to_toml().unwrap(), importers)
}

fn bench_binary_write(c: &mut Criterion) {
    let lf_100 = make_lockfile(100);
    let lf_1000 = make_lockfile(1000);
    let lf_10000 = make_lockfile(10000);

    let mut group = c.benchmark_group("binary_write");
    group.bench_function("100_packages", |b| {
        b.iter(|| binary::to_binary(black_box(&lf_100)).unwrap())
    });
    group.bench_function("1000_packages", |b| {
        b.iter(|| binary::to_binary(black_box(&lf_1000)).unwrap())
    });
    group.bench_function("10000_packages", |b| {
        b.iter(|| binary::to_binary(black_box(&lf_10000)).unwrap())
    });
    group.finish();
}

fn bench_binary_read(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();

    for &n in &[100, 1000, 10000] {
        let lf = make_lockfile(n);
        let path = dir.path().join(format!("lpm-{n}.lockb"));
        binary::write_binary(&lf, &path).unwrap();
    }

    let mut group = c.benchmark_group("binary_read");
    for &n in &[100, 1000, 10000] {
        let path = dir.path().join(format!("lpm-{n}.lockb"));
        group.bench_function(format!("{n}_packages"), |b| {
            b.iter(|| {
                let reader = binary::BinaryLockfileReader::open(black_box(&path))
                    .unwrap()
                    .unwrap();
                black_box(reader.to_lockfile().unwrap());
            })
        });
    }
    group.finish();
}

fn bench_toml_read(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();

    for &n in &[100, 1000, 10000] {
        let lf = make_lockfile(n);
        let path = dir.path().join(format!("lpm-{n}.lock"));
        lf.write_to_file(&path).unwrap();
    }

    let mut group = c.benchmark_group("toml_read");
    for &n in &[100, 1000, 10000] {
        let path = dir.path().join(format!("lpm-{n}.lock"));
        group.bench_function(format!("{n}_packages"), |b| {
            b.iter(|| {
                let lf = Lockfile::read_from_file(black_box(&path)).unwrap();
                black_box(lf);
            })
        });
    }
    group.finish();
}

fn bench_find_package(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();

    for &n in &[100, 1000, 10000] {
        let lf = make_lockfile(n);
        let path = dir.path().join(format!("lpm-{n}.lockb"));
        binary::write_binary(&lf, &path).unwrap();
    }

    let mut group = c.benchmark_group("find_package");
    for &n in &[100, 1000, 10000] {
        let path = dir.path().join(format!("lpm-{n}.lockb"));
        let reader = binary::BinaryLockfileReader::open(&path).unwrap().unwrap();
        // Search for a package in the middle
        let target = format!("pkg-{:05}", n / 2);
        group.bench_function(format!("binary_{n}_packages"), |b| {
            b.iter(|| {
                let result = reader.find_package(black_box(&target));
                black_box(result);
            })
        });
    }

    // Compare with TOML find_package (linear scan via binary_search on sorted vec)
    for &n in &[100, 1000, 10000] {
        let lf = make_lockfile(n);
        let target = format!("pkg-{:05}", n / 2);
        group.bench_function(format!("toml_{n}_packages"), |b| {
            b.iter(|| {
                let result = lf.find_package(black_box(&target));
                black_box(result);
            })
        });
    }
    group.finish();
}

fn bench_read_fast(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();

    for &n in &[100, 1000] {
        let lf = make_lockfile(n);
        let toml_path = dir.path().join(format!("lpm-{n}.lock"));
        let bin_path = dir.path().join(format!("lpm-{n}.lockb"));
        lf.write_to_file(&toml_path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        binary::write_binary(&lf, &bin_path).unwrap();
    }

    let mut group = c.benchmark_group("read_fast");
    for &n in &[100, 1000] {
        let toml_path = dir.path().join(format!("lpm-{n}.lock"));
        group.bench_function(format!("{n}_packages"), |b| {
            b.iter(|| {
                let lf = Lockfile::read_fast(black_box(&toml_path)).unwrap();
                black_box(lf);
            })
        });
    }
    group.finish();
}

fn bench_workspace_union(c: &mut Criterion) {
    let (encoded, importers) = make_workspace_union(78, 4_570, 400);
    let validated = ValidatedLockfile::from_toml(&encoded).unwrap();
    let mut group = c.benchmark_group("workspace_union_78_importers");
    group.sample_size(10);
    group.bench_function("parse_and_validate_4570_unique_packages", |b| {
        b.iter(|| {
            let lockfile = ValidatedLockfile::from_toml(black_box(&encoded)).unwrap();
            black_box(lockfile);
        })
    });
    group.bench_function("borrow_31200_importer_package_rows", |b| {
        b.iter(|| {
            for importer in &importers {
                let metadata = validated
                    .project_importer_metadata(black_box(importer))
                    .unwrap();
                let packages = validated.importer_packages(black_box(importer)).unwrap();
                black_box((metadata, packages));
            }
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_binary_write,
    bench_binary_read,
    bench_toml_read,
    bench_find_package,
    bench_read_fast,
    bench_workspace_union,
);
criterion_main!(benches);
