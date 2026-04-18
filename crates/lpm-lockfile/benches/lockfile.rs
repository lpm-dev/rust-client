use criterion::{Criterion, black_box, criterion_group, criterion_main};
use lpm_lockfile::{LockedPackage, Lockfile, binary};

fn make_lockfile(n: usize) -> Lockfile {
    let mut lf = Lockfile::new();
    for i in 0..n {
        lf.add_package(LockedPackage {
            name: format!("pkg-{i:05}"),
            version: format!("{i}.0.0"),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-abcdef1234567890".to_string()),
            dependencies: if i > 0 {
                vec![format!("pkg-{:05}@{}.0.0", i - 1, i - 1)]
            } else {
                vec![]
            },
            alias_dependencies: vec![],
            tarball: None,
        });
    }
    lf
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
                black_box(reader.to_lockfile());
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

criterion_group!(
    benches,
    bench_binary_write,
    bench_binary_read,
    bench_toml_read,
    bench_find_package,
    bench_read_fast,
);
criterion_main!(benches);
